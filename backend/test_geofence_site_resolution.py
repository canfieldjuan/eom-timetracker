"""Contract tests for dormant C3 customer-site resolution (#215)."""

from __future__ import annotations

import bcrypt
import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import calendar_import_store
import db
import time_tracker_api as api
from conftest import _raw_conn


PREFIX = "C3_SITE_RESOLUTION_TEST"
LATITUDE = 39.5100000
LONGITUDE = -88.8100000


def _clean_rows() -> None:
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM plain_time_action_receipts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_visit_assignments WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM shifts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_visit_assignments WHERE planned_visit_id IN "
            "(SELECT id FROM planned_service_visits WHERE source_calendar_id LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_service_visits WHERE source_calendar_id LIKE %s",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM google_calendar_connections WHERE google_account_email LIKE %s",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM locations WHERE address LIKE %s",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM customers WHERE name LIKE %s",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM employees WHERE name LIKE %s",
            (f"{PREFIX}%",),
        )
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def isolate_c3_data(setup_db):
    _clean_rows()
    yield
    _clean_rows()


def _create_employee(client, suffix: str) -> tuple[int, dict[str, str]]:
    name = f"{PREFIX} {suffix}"
    password = "c3-site-resolution-password"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode()
    row = db.query_one(
        """
        INSERT INTO employees (name, password_hash, role, hourly_rate)
        VALUES (%s, %s, 'employee', 18.25)
        RETURNING id
        """,
        (name, password_hash),
    )
    assert row
    response = client.post("/api/auth/login", json={"name": name, "password": password})
    assert response.status_code == 200, response.text
    return int(row["id"]), {"Authorization": f"Bearer {response.json()['token']}"}


def _create_site(
    suffix: str,
    *,
    latitude: float | None = LATITUDE,
    longitude: float | None = LONGITUDE,
    address: str | None = None,
    geofence_radius_m: int | None = None,
    location_type: str | None = "Residential",
    customer_active: bool = True,
    customer_archived: bool = False,
    linked: bool = True,
) -> int:
    customer_id = None
    customer_name = f"{PREFIX} Customer {suffix}"
    if linked:
        customer = db.query_one(
            """
            INSERT INTO customers (name, active, archived_at)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                customer_name,
                customer_active,
                datetime.now(timezone.utc) if customer_archived else None,
            ),
        )
        assert customer
        customer_id = int(customer["id"])
    site = db.query_one(
        """
        INSERT INTO locations (
            customer_id, address, customer_name, location_type, lat, lng,
            geofence_radius_m, rate, rate_type, expected_hours
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, 100, 'per_visit', 2)
        RETURNING id
        """,
        (
            customer_id,
            address or f"{PREFIX} {suffix}",
            customer_name,
            location_type,
            latitude,
            longitude,
            geofence_radius_m,
        ),
    )
    assert site
    return int(site["id"])


def _assign_planned_visit(employee_id: int, location_id: int, suffix: str) -> int:
    now = datetime.now(timezone.utc)
    source_key = hashlib.sha256(f"{PREFIX}:source:{suffix}".encode()).hexdigest()
    fingerprint = hashlib.sha256(f"{PREFIX}:fingerprint:{suffix}".encode()).hexdigest()
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO google_calendar_connections (
                    google_account_email, granted_scopes, revoked_at
                ) VALUES (%s, ARRAY['calendar.readonly'], NOW())
                RETURNING id
                """,
                (f"{PREFIX}-{suffix}@example.test",),
            )
            connection_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO planned_service_visits (
                    connection_id, source_calendar_id, source_event_id,
                    source_series_id, source_occurrence_id, source_key,
                    source_fingerprint, title, location_id,
                    approximate_start, approximate_end, source_timezone
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'America/Chicago')
                RETURNING id
                """,
                (
                    connection_id,
                    f"{PREFIX}-{suffix}",
                    f"event-{suffix}",
                    f"series-{suffix}",
                    f"occurrence-{suffix}",
                    source_key,
                    fingerprint,
                    f"Planned {suffix}",
                    location_id,
                    now - timedelta(hours=1),
                    now + timedelta(hours=2),
                ),
            )
            planned_visit_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO planned_visit_assignments (planned_visit_id, employee_id)
                VALUES (%s, %s)
                """,
                (planned_visit_id, employee_id),
            )
    return planned_visit_id


def _resolve(client, employee_auth: dict[str, str], **payload):
    return client.post(
        "/api/timesheet/site-resolution",
        headers=employee_auth,
        json={
            "action": "arrive",
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            **payload,
        },
    )


def test_c3_is_dormant_by_default_and_advertises_that_capability(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "dormant")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    status = client.get("/api/timesheet/current-status", headers=employee_auth)
    assert status.status_code == 200, status.text
    assert status.json()["siteResolutionEnabled"] is False
    resolution = _resolve(client, employee_auth)
    assert resolution.status_code == 200, resolution.text
    assert resolution.json() == {"success": True, "enabled": False}


def test_clock_radius_env_default_is_independent_of_shared_rollout(monkeypatch):
    monkeypatch.setenv("GEOFENCE_PER_SITE_RADIUS_ENABLED", "true")
    monkeypatch.delenv(
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        raising=False,
    )
    assert api._clock_boundary_per_site_radius_enabled_from_env() is False

    monkeypatch.setenv("GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", "true")
    assert api._clock_boundary_per_site_radius_enabled_from_env() is True


def test_c3_resolves_eligible_sites_and_uses_schedule_only_for_overlap_ties(
    client,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "resolver")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)

    no_inside = _resolve(client, employee_auth, latitude=LATITUDE + 1)
    assert no_inside.status_code == 200, no_inside.text
    assert no_inside.json()["resolution"] == {
        "state": "unresolved",
        "reason": "no_eligible_inside_site",
    }

    first_site_id = _create_site("first eligible")
    inactive_parent_site_id = _create_site("inactive parent", customer_active=False)

    single = _resolve(client, employee_auth)
    assert single.status_code == 200, single.text
    assert single.json()["resolution"] == {
        "state": "customer_site",
        "source": "single_inside",
        "site": {
            "locationId": first_site_id,
            "address": f"{PREFIX} first eligible",
            "customerName": f"{PREFIX} Customer first eligible",
            "locationType": "Residential",
            "legacyUnlinked": False,
        },
    }

    rejected_explicit = _resolve(client, employee_auth, locationId=inactive_parent_site_id)
    assert rejected_explicit.status_code == 200, rejected_explicit.text
    assert rejected_explicit.json()["resolution"] == {
        "state": "unresolved",
        "reason": "selected_site_ineligible",
    }

    second_site_id = _create_site("second eligible")
    ambiguous = _resolve(client, employee_auth)
    assert ambiguous.status_code == 200, ambiguous.text
    assert ambiguous.json()["resolution"]["state"] == "selection_required"
    assert ambiguous.json()["resolution"]["reason"] == "multiple_inside_sites"
    assert {
        candidate["locationId"]
        for candidate in ambiguous.json()["resolution"]["candidates"]
    } == {first_site_id, second_site_id}

    explicit = _resolve(client, employee_auth, locationId=second_site_id)
    assert explicit.status_code == 200, explicit.text
    assert explicit.json()["resolution"]["state"] == "customer_site"
    assert explicit.json()["resolution"]["source"] == "explicit"
    assert explicit.json()["resolution"]["site"]["locationId"] == second_site_id

    _assign_planned_visit(employee_id, first_site_id, "tie-break")
    scheduled = _resolve(client, employee_auth)
    assert scheduled.status_code == 200, scheduled.text
    assert scheduled.json()["resolution"]["state"] == "customer_site"
    assert scheduled.json()["resolution"]["source"] == "planned_tiebreak"
    assert scheduled.json()["resolution"]["site"]["locationId"] == first_site_id

    # Exercise the write-transaction schedule query too: the planned visit
    # may break an overlap tie, but the final write must lock and re-check it.
    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["siteResolution"]["source"] == "planned_tiebreak"
    assert clock_in.json()["entry"]["locationId"] == first_site_id

    unlinked_site_id = _create_site(
        "unlinked legacy",
        latitude=LATITUDE + 0.01,
        linked=False,
    )
    unlinked = _resolve(client, employee_auth, latitude=LATITUDE + 0.01)
    assert unlinked.status_code == 200, unlinked.text
    assert unlinked.json()["resolution"]["site"]["locationId"] == unlinked_site_id
    assert unlinked.json()["resolution"]["site"]["legacyUnlinked"] is True


def test_c3_keeps_unready_sites_eligible_but_rejects_ineligible_sites(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(client, "eligibility")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    unpinned_site_id = _create_site("unpinned", latitude=None, longitude=None)
    archived_site_id = _create_site("archived", latitude=LATITUDE + 0.01)
    type_less_site_id = _create_site(
        "type less",
        latitude=LATITUDE + 0.02,
        location_type=None,
    )
    inactive_parent_site_id = _create_site(
        "inactive parent",
        latitude=LATITUDE + 0.03,
        customer_active=False,
    )
    db.execute("UPDATE locations SET archived_at = NOW() WHERE id = %s", (archived_site_id,))

    unpinned = _resolve(client, employee_auth, locationId=unpinned_site_id)
    assert unpinned.status_code == 200, unpinned.text
    assert unpinned.json()["resolution"] == {
        "state": "unresolved",
        "reason": "selected_site_not_inside",
    }

    for location_id in (archived_site_id, type_less_site_id, inactive_parent_site_id):
        rejected = _resolve(client, employee_auth, locationId=location_id)
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["resolution"] == {
            "state": "unresolved",
            "reason": "selected_site_ineligible",
        }

    # Geometry is not part of the derived eligibility predicate: a malformed
    # legacy pin remains eligible-but-unready, never a new authorization.
    malformed = {
        "active": True,
        "archived_at": None,
        "location_type": "Residential",
        "customer_id": None,
        "lat": float("nan"),
        "lng": LONGITUDE,
        "geofence_radius_m": None,
    }
    assert api._location_business_eligible(malformed) is True
    assert api._c3_site_geofence(
        malformed,
        api.SiteResolutionRequest(
            action="arrive",
            latitude=LATITUDE,
            longitude=LONGITUDE,
            accuracy=5,
        ),
    )["status"] != "inside"


def test_c3_associates_clock_in_and_arrival_without_creating_legacy_evidence(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(client, "actions")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    clock_site_id = _create_site("clock site")
    arrival_latitude = LATITUDE + 0.01
    arrival_site_id = _create_site("arrival site", latitude=arrival_latitude)

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert clock_in.status_code == 200, clock_in.text
    clock_entry = clock_in.json()["entry"]
    assert clock_in.json()["siteResolution"]["state"] == "customer_site"
    assert clock_entry["locationId"] == clock_site_id
    assert db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s", (clock_entry["id"],)
    ) == {"location_id": clock_site_id}

    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": arrival_site_id,
            "latitude": arrival_latitude,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text
    assert arrival.json()["siteResolution"]["state"] == "customer_site"
    assert "visit" in arrival.json(), arrival.json()
    assert arrival.json()["visit"]["locationId"] == arrival_site_id
    assert db.query_one(
        "SELECT location_id FROM visits WHERE id = %s",
        (arrival.json()["visit"]["id"],),
    ) == {"location_id": arrival_site_id}
    assert db.query_one("SELECT COUNT(*) AS count FROM visit_evidence_events") == {
        "count": 0
    }


def test_c3_uses_site_identity_when_a_site_address_is_reused(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "reused-address arrivals")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    shared_address = f"{PREFIX} shared address"
    first_site_id = _create_site("reused address first", address=shared_address)

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": first_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert clock_in.status_code == 200, clock_in.text

    first_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": first_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert first_arrival.status_code == 200, first_arrival.text
    assert first_arrival.json()["alreadyHere"] is False

    # The canonical Site table prevents concurrent duplicate addresses, but an
    # active historical visit keeps its old label after an admin edits Site A.
    # Once Site B takes the freed address, C3 must distinguish their durable ids.
    db.execute(
        "UPDATE locations SET address = %s WHERE id = %s",
        (f"{PREFIX} first address after edit", first_site_id),
    )
    second_site_id = _create_site("reused address second", address=shared_address)

    second_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": second_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert second_arrival.status_code == 200, second_arrival.text
    assert second_arrival.json()["alreadyHere"] is False
    assert second_arrival.json()["visit"]["locationId"] == second_site_id


def test_c3_rechecks_a_provisional_duplicate_before_returning_already_here(
    client,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "provisional duplicate")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    initial_site_id = _create_site("provisional duplicate initial")

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert clock_in.status_code == 200, clock_in.text
    first_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert first_arrival.status_code == 200, first_arrival.text
    assert first_arrival.json()["visit"]["locationId"] == initial_site_id

    original_resolver = api._c3_resolve_site
    replacement_site_id: int | None = None

    def resolve_after_site_replaced(*args, **kwargs):
        nonlocal replacement_site_id
        if kwargs.get("cur") is not None and replacement_site_id is None:
            db.execute(
                "UPDATE locations SET active = false WHERE id = %s",
                (initial_site_id,),
            )
            replacement_site_id = _create_site("provisional duplicate replacement")
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_after_site_replaced)
    second_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert second_arrival.status_code == 200, second_arrival.text
    assert second_arrival.json()["alreadyHere"] is False
    assert second_arrival.json()["visit"]["locationId"] == replacement_site_id
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visits WHERE shift_id = %s",
        (clock_in.json()["entry"]["id"],),
    ) == {"count": 2}


def test_c3_resolves_a_supported_per_site_radius_before_legacy_gate(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "per-site radius")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    site_id = _create_site("wide radius", geofence_radius_m=250)

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            # About 111m from the pin: outside the 50m legacy matcher but
            # inside this C2-enabled Site's supported effective radius.
            "latitude": LATITUDE + 0.001,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["siteResolution"]["state"] == "customer_site"
    assert response.json()["entry"]["locationId"] == site_id


def test_clock_radius_does_not_widen_arrival_or_residential_paths(client, monkeypatch):
    employee_id, _employee_auth = _create_employee(client, "clock radius isolation")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    commercial_site_id = _create_site(
        "clock-only wide commercial",
        geofence_radius_m=250,
        location_type="Commercial",
    )
    payload = api.ClockInRequest(
        latitude=LATITUDE + 0.001,
        longitude=LONGITUDE,
        accuracy=5,
    )
    db.execute(
        """
        UPDATE locations
        SET pin_provenance = 'gps_capture',
            pin_confidence = 'high',
            pin_capture_accuracy_m = 5
        WHERE id = %s
        """,
        (commercial_site_id,),
    )
    commercial_row = api._c3_customer_site_rows(
        payload,
        action="clock-in",
        selected_location_id=commercial_site_id,
    )[0]
    fingerprint = api._c3_location_geofence_state(commercial_row)[
        "currentFingerprint"
    ]
    db.execute(
        """
        UPDATE locations
        SET pin_attested_at = NOW(),
            pin_attestation_fingerprint = %s
        WHERE id = %s
        """,
        (fingerprint, commercial_site_id),
    )
    employee = {"id": employee_id}

    clock_resolution = api._c3_resolve_site("clock-in", payload, employee)
    assert clock_resolution["state"] == "customer_site"
    assert int(clock_resolution["site"]["location_id"]) == commercial_site_id
    assert clock_resolution["geofence"]["resolvedRadiusM"] == 250

    arrival_resolution = api._c3_resolve_site("arrive", payload, employee)
    assert arrival_resolution == {
        "state": "unresolved",
        "reason": "no_eligible_inside_site",
    }

    residential = {
        **clock_resolution["site"],
        "location_type": "Residential",
    }
    residential_geofence = api._c3_site_geofence(
        residential,
        payload,
        action="clock-in",
    )
    assert residential_geofence["status"] == "outside"
    assert residential_geofence["resolvedRadiusM"] == int(api.SITE_CHECK_IN_RADIUS_M)


def test_clock_radius_flag_activates_commercial_clock_in_and_out(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "clock radius endpoint")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site(
        "clock endpoint wide commercial",
        geofence_radius_m=250,
        location_type="Commercial",
    )
    body = {
        # About 111m from the pin: outside the legacy matcher but inside the
        # configured clock-boundary radius.
        "latitude": LATITUDE + 0.001,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    db.execute(
        """
        UPDATE locations
        SET pin_provenance = 'gps_capture',
            pin_confidence = 'high',
            pin_capture_accuracy_m = 5
        WHERE id = %s
        """,
        (site_id,),
    )
    fingerprint_row = api._c3_customer_site_rows(
        api.ClockInRequest(**body),
        action="clock-in",
        selected_location_id=site_id,
    )[0]
    fingerprint = api._c3_location_geofence_state(fingerprint_row)[
        "currentFingerprint"
    ]
    db.execute(
        """
        UPDATE locations
        SET pin_attested_at = NOW(),
            pin_attestation_fingerprint = %s
        WHERE id = %s
        """,
        (fingerprint, site_id),
    )

    current_status = client.get(
        "/api/timesheet/current-status",
        headers=employee_auth,
    )
    assert current_status.status_code == 200, current_status.text
    assert current_status.json()["siteResolutionEnabled"] is True
    assert current_status.json()["clockOutSiteResolutionRequired"] is True

    for action in ("clock-in", "clock-out"):
        preflight = client.post(
            "/api/timesheet/site-resolution",
            headers=employee_auth,
            json={**body, "action": action},
        )
        assert preflight.status_code == 200, preflight.text
        assert preflight.json()["enabled"] is True
        assert preflight.json()["resolution"]["state"] == "customer_site"

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=body,
    )
    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["siteResolution"]["state"] == "customer_site"
    assert clock_in.json()["entry"]["locationId"] == site_id

    mutation_lock_calls = []
    monkeypatch.setattr(
        api,
        "_lock_customer_site_mutations",
        lambda _cur: mutation_lock_calls.append("locked"),
    )
    clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json=body,
    )
    assert clock_out.status_code == 200, clock_out.text
    assert clock_out.json()["siteResolution"]["state"] == "customer_site"
    assert mutation_lock_calls == ["locked"]


@pytest.mark.parametrize("broad_resolution_enabled", [False, True])
def test_clock_radius_requires_exact_site_for_overlap_without_hard_gate(
    client,
    monkeypatch,
    broad_resolution_enabled,
):
    employee_id, employee_auth = _create_employee(client, "clock radius overlap")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_SITE_RESOLUTION_ENABLED",
        broad_resolution_enabled,
    )
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_ids = [
        _create_site(
            f"clock overlap {suffix}",
            geofence_radius_m=250,
            location_type="Commercial",
        )
        for suffix in ("first", "second")
    ]
    body = {"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5}
    for site_id in site_ids:
        db.execute(
            """
            UPDATE locations
            SET pin_provenance = 'gps_capture',
                pin_confidence = 'high',
                pin_capture_accuracy_m = 5
            WHERE id = %s
            """,
            (site_id,),
        )
        row = api._c3_customer_site_rows(
            api.ClockInRequest(**body),
            action="clock-in",
            selected_location_id=site_id,
        )[0]
        fingerprint = api._c3_location_geofence_state(row)["currentFingerprint"]
        db.execute(
            """
            UPDATE locations
            SET pin_attested_at = NOW(),
                pin_attestation_fingerprint = %s
            WHERE id = %s
            """,
            (fingerprint, site_id),
        )

    preflight = client.post(
        "/api/timesheet/site-resolution",
        headers=employee_auth,
        json={**body, "action": "clock-in"},
    )
    assert preflight.status_code == 200, preflight.text
    assert preflight.json()["resolution"]["state"] == "selection_required"

    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=body,
    )
    assert blocked.status_code == 400, blocked.text
    assert "Choose the exact Site" in blocked.text
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}

    invalid_selection = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={**body, "locationId": max(site_ids) + 100_000},
    )
    assert invalid_selection.status_code == 400, invalid_selection.text
    assert "selected customer Site is not eligible" in invalid_selection.text

    selected = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={**body, "locationId": site_ids[0]},
    )
    assert selected.status_code == 200, selected.text
    assert selected.json()["entry"]["locationId"] == site_ids[0]


def test_clock_radius_flag_preserves_existing_residential_site_resolution(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "clock radius residential")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site("clock radius residential", location_type="Residential")

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["siteResolution"]["state"] == "customer_site"
    assert clock_in.json()["entry"]["locationId"] == site_id


def test_clock_only_explicit_residential_selection_uses_legacy_match(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(
        client,
        "clock only explicit residential",
    )
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "LOCATION_MATCH_RADIUS_M", 50)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site(
        "clock only explicit residential",
        geofence_radius_m=15,
        location_type="Residential",
    )

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 0.00027,
            "longitude": LONGITUDE,
            "accuracy": 1,
        },
    )

    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["siteResolution"]["reason"] == (
        "selected_site_legacy_only"
    )
    assert clock_in.json()["entry"]["clockInGpsMeta"]["override"] is False


@pytest.mark.parametrize("location_type", ["Residential", "Commercial"])
def test_clock_boundary_fallback_is_inert_when_its_switch_is_off(
    client,
    monkeypatch,
    location_type,
):
    _employee_id, employee_auth = _create_employee(
        client,
        f"clock switch off {location_type}",
    )
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        False,
    )
    site_id = _create_site(
        f"clock switch off {location_type}",
        geofence_radius_m=15,
        location_type=location_type,
    )
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 0.00027,
            "longitude": LONGITUDE,
            "accuracy": 1,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["entry"]["clockInGpsMeta"]["override"] is False


def test_dual_switch_preserves_residential_legacy_fallback(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(
        client,
        "dual switch residential",
    )
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    monkeypatch.setattr(api, "LOCATION_MATCH_RADIUS_M", 50)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site(
        "dual switch residential",
        geofence_radius_m=15,
        location_type="Residential",
    )

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 0.00027,
            "longitude": LONGITUDE,
            "accuracy": 1,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["entry"]["clockInGpsMeta"]["override"] is False
    row = api._c3_customer_site_rows(
        api.ClockInRequest(
            locationId=site_id,
            latitude=LATITUDE + 0.00027,
            longitude=LONGITUDE,
            accuracy=1,
        ),
        action="clock-in",
        selected_location_id=site_id,
    )[0]
    geofence = api._c3_location_geofence_state(row)
    assert geofence["clockBoundaryEffectiveRadiusM"] == 50
    assert geofence["clockBoundaryRadiusSource"] == "legacy_location_match"
    assert geofence["clockBoundaryPerSiteRadiusEnabled"] is False


@pytest.mark.parametrize(
    ("broad_resolution_enabled", "legacy_radius_m", "latitude_offset"),
    [
        (False, 50, 0.00027),
        (True, 50, 0.00027),
        (False, 800, 0.006),
        (True, 800, 0.006),
    ],
)
def test_clock_radius_prevents_legacy_match_from_bypassing_narrow_boundary(
    client,
    monkeypatch,
    broad_resolution_enabled,
    legacy_radius_m,
    latitude_offset,
):
    _employee_id, employee_auth = _create_employee(client, "clock narrow boundary")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(
        api,
        "GEOFENCE_SITE_RESOLUTION_ENABLED",
        broad_resolution_enabled,
    )
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(api, "LOCATION_MATCH_RADIUS_M", legacy_radius_m)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site(
        "clock narrow commercial",
        geofence_radius_m=15,
        location_type="Commercial",
    )
    db.execute(
        """
        UPDATE locations
        SET pin_provenance = 'gps_capture',
            pin_confidence = 'high',
            pin_capture_accuracy_m = 1
        WHERE id = %s
        """,
        (site_id,),
    )
    point = {
        # Inside the configured legacy matcher but outside the Commercial
        # boundary, including when the legacy radius exceeds the 500m cap.
        "latitude": LATITUDE + latitude_offset,
        "longitude": LONGITUDE,
        "accuracy": 1,
    }
    fingerprint_row = api._c3_customer_site_rows(
        api.ClockInRequest(**point),
        action="clock-in",
        selected_location_id=site_id,
    )[0]
    fingerprint = api._c3_location_geofence_state(fingerprint_row)[
        "currentFingerprint"
    ]
    db.execute(
        """
        UPDATE locations
        SET pin_attested_at = NOW(),
            pin_attestation_fingerprint = %s
        WHERE id = %s
        """,
        (fingerprint, site_id),
    )

    blocked_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=point,
    )
    assert blocked_start.status_code == 400, blocked_start.text
    assert "configured Commercial Site clock boundary" in blocked_start.text

    selected_blocked_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={**point, "locationId": site_id},
    )
    assert selected_blocked_start.status_code == 400, selected_blocked_start.text
    assert "configured Commercial Site clock boundary" in selected_blocked_start.text

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={**point, "gpsOverrideReason": "Supervisor approved boundary exception."},
    )
    assert started.status_code == 200, started.text

    blocked_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json=point,
    )
    assert blocked_end.status_code == 400, blocked_end.text
    assert "configured Commercial Site clock boundary" in blocked_end.text

    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={**point, "gpsOverrideReason": "Supervisor approved boundary exception."},
    )
    assert ended.status_code == 200, ended.text

    _unready_employee_id, unready_auth = _create_employee(
        client,
        "clock unready narrow boundary",
    )
    db.execute(
        """
        UPDATE locations
        SET pin_attested_at = NULL,
            pin_attestation_fingerprint = NULL
        WHERE id = %s
        """,
        (site_id,),
    )
    unready = client.post(
        "/api/timesheet/clock-in",
        headers=unready_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 1},
    )
    assert unready.status_code == 400, unready.text
    assert "not ready for verification" in unready.text


def test_clock_radius_requires_accuracy_before_legacy_fallback(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "clock accuracy")
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    site_id = _create_site(
        "clock accuracy commercial",
        geofence_radius_m=15,
        location_type="Commercial",
    )
    db.execute(
        """
        UPDATE locations
        SET pin_provenance = 'gps_capture',
            pin_confidence = 'high',
            pin_capture_accuracy_m = 1
        WHERE id = %s
        """,
        (site_id,),
    )
    exact = {"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 1}
    row = api._c3_customer_site_rows(
        api.ClockInRequest(**exact),
        action="clock-in",
        selected_location_id=site_id,
    )[0]
    db.execute(
        """
        UPDATE locations
        SET pin_attested_at = NOW(),
            pin_attestation_fingerprint = %s
        WHERE id = %s
        """,
        (api._c3_location_geofence_state(row)["currentFingerprint"], site_id),
    )
    without_accuracy = {
        "latitude": LATITUDE + 0.00027,
        "longitude": LONGITUDE,
    }

    blocked_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=without_accuracy,
    )
    assert blocked_start.status_code == 400, blocked_start.text
    assert "GPS accuracy is required" in blocked_start.text

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=exact,
    )
    assert started.status_code == 200, started.text

    blocked_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json=without_accuracy,
    )
    assert blocked_end.status_code == 400, blocked_end.text
    assert "GPS accuracy is required" in blocked_end.text


def test_c3_commit_recheck_serializes_with_customer_site_mutations(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "site mutation lock")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    _create_site("locked recheck")
    events: list[str] = []
    original_resolver = api._c3_resolve_site

    def record_lock(_cur):
        events.append("lock")

    def record_commit_resolver(*args, **kwargs):
        if kwargs.get("cur") is not None:
            events.append("resolve")
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_lock_customer_site_mutations", record_lock)
    monkeypatch.setattr(api, "_c3_resolve_site", record_commit_resolver)
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert response.status_code == 200, response.text

    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert arrival.status_code == 200, arrival.text
    assert events == ["lock", "resolve", "lock", "resolve"]


def test_c3_tiebreak_recheck_waits_for_calendar_assignment_mutations(
    client,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "schedule mutation lock")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    planned_site_id = _create_site("schedule lock planned")
    _create_site("schedule lock alternate")
    _assign_planned_visit(employee_id, planned_site_id, "schedule-lock")

    blocker = _raw_conn()
    blocker.autocommit = False
    worker: threading.Thread | None = None
    completed: dict[str, object] = {}
    try:
        with blocker.cursor() as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (calendar_import_store.PLANNED_VISIT_ASSIGNMENT_MUTATION_LOCK,),
            )

        def clock_in_while_calendar_assignment_is_locked() -> None:
            completed["response"] = client.post(
                "/api/timesheet/clock-in",
                headers=employee_auth,
                json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
            )

        worker = threading.Thread(target=clock_in_while_calendar_assignment_is_locked)
        worker.start()
        worker.join(timeout=2)
        assert worker.is_alive(), "C3 did not wait for the calendar assignment lock"
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
            (employee_id,),
        ) == {"count": 0}

        blocker.rollback()
        worker.join(timeout=15)
        assert not worker.is_alive(), "C3 did not resume after the calendar lock released"
        response = completed.get("response")
        assert response is not None
        assert response.status_code == 200, response.text
    finally:
        if blocker.closed == 0:
            blocker.close()
        if worker is not None and worker.is_alive():
            worker.join(timeout=15)


def test_c3_clock_in_omitting_location_id_replays_a_predeploy_receipt(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "legacy fingerprint")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _create_site("legacy fingerprint pin")
    body = {
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "accuracy": 5,
        "idempotencyKey": str(uuid4()),
    }
    first = client.post("/api/timesheet/clock-in", headers=employee_auth, json=body)
    assert first.status_code == 200, first.text

    predeploy_payload = api.ClockInRequest(**body).model_dump(mode="json")
    predeploy_payload.pop("locationId", None)
    predeploy_fingerprint = hashlib.sha256(
        json.dumps(
            {"action": "clock-in", "payload": predeploy_payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    db.execute(
        """
        UPDATE plain_time_action_receipts
        SET request_fingerprint = %s
        WHERE idempotency_key = %s
        """,
        (predeploy_fingerprint, body["idempotencyKey"]),
    )

    replay = client.post("/api/timesheet/clock-in", headers=employee_auth, json=body)
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True


def test_c3_rechecks_before_persist_and_falls_back_when_legacy_gps_allows_it(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(client, "recheck")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    site_id = _create_site("rechecked site")
    original_resolver = api._c3_resolve_site

    def resolve_then_deactivate(*args, **kwargs):
        if kwargs.get("cur") is not None:
            db.execute("UPDATE locations SET active = false WHERE id = %s", (site_id,))
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_then_deactivate)
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["siteResolution"] == {
        "state": "unresolved",
        "reason": "no_eligible_inside_site",
    }
    assert "locationId" not in body["entry"]
    assert db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s", (body["entry"]["id"],)
    ) == {"location_id": None}


def test_c3_clock_in_fallback_reapplies_the_legacy_gps_guard(client, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "clock fallback guard")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    site_id = _create_site("clock fallback guard", geofence_radius_m=250)
    original_resolver = api._c3_resolve_site

    def resolve_after_site_becomes_ineligible(*args, **kwargs):
        if kwargs.get("cur") is not None:
            db.execute("UPDATE locations SET active = false WHERE id = %s", (site_id,))
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_after_site_becomes_ineligible)
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            # Inside the configured Site radius but outside the legacy 50m pin.
            "latitude": LATITUDE + 0.001,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert response.status_code == 400, response.text
    assert "GPS is" in response.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}


def test_c3_arrival_fallback_reapplies_the_legacy_gps_guard(client, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "arrival fallback guard")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    clock_in_latitude = LATITUDE - 0.02
    _create_site("arrival fallback start", latitude=clock_in_latitude)
    target_latitude = LATITUDE + 0.02
    target_site_id = _create_site(
        "arrival fallback target",
        latitude=target_latitude,
        geofence_radius_m=250,
    )

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": clock_in_latitude, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert clock_in.status_code == 200, clock_in.text

    original_resolver = api._c3_resolve_site

    def resolve_after_arrival_site_becomes_ineligible(*args, **kwargs):
        if kwargs.get("cur") is not None and args[0] == "arrive":
            db.execute(
                "UPDATE locations SET active = false WHERE id = %s",
                (target_site_id,),
            )
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_after_arrival_site_becomes_ineligible)
    response = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "latitude": target_latitude + 0.001,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert response.status_code == 400, response.text
    assert "GPS is" in response.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visits WHERE shift_id = %s",
        (clock_in.json()["entry"]["id"],),
    ) == {"count": 0}


def test_c3_dispatch_exception_reports_an_unassociated_resolution(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "dispatch exception")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    _create_site("dispatch exception overlap")
    home_base = {
        "home_base_id": 987654,
        "label": "C3 Test Home Base",
        "latitude": LATITUDE + 1,
        "longitude": LONGITUDE,
        "geofence_radius_m": 50,
    }
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: home_base)
    monkeypatch.setattr(api, "_record_home_base_event", lambda *args, **kwargs: {})

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "homeBaseExceptionReason": "Office was inaccessible",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["entry"]["location"] == "Dispatch exception"
    assert body["entry"]["locationId"] is None
    assert body["siteResolution"] == {
        "state": "unresolved",
        "reason": "home_base_exception",
    }


def test_c3_confirmed_home_base_keeps_its_resolution_despite_an_exception(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(
        client, "confirmed home base exception"
    )
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    home_base = {
        "home_base_id": 987655,
        "label": "C3 Test Home Base",
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "geofence_radius_m": 50,
    }
    monkeypatch.setattr(
        api,
        "_active_home_base_config",
        lambda *, cur=None: home_base,
    )
    monkeypatch.setattr(api, "_record_home_base_event", lambda *args, **kwargs: {})

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "homeBaseExceptionReason": "Office was inaccessible",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["entry"]["location"] == "Home Base — C3 Test Home Base"
    assert body["siteResolution"] == {"state": "home_base", "source": "home_base"}


def test_c3_rechecks_a_planned_overlap_tiebreak_before_persist(client, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "assignment recheck")
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    planned_site_id = _create_site("planned overlap")
    _other_site_id = _create_site("other overlap")
    planned_visit_id = _assign_planned_visit(employee_id, planned_site_id, "assignment-recheck")
    original_resolver = api._c3_resolve_site

    def resolve_after_assignment_removed(*args, **kwargs):
        if kwargs.get("cur") is not None:
            db.execute(
                "DELETE FROM planned_visit_assignments WHERE planned_visit_id = %s",
                (planned_visit_id,),
            )
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_after_assignment_removed)
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["siteResolution"]["state"] == "selection_required"
    assert "locationId" not in body["entry"]


def test_c3_gives_home_base_priority_for_clock_in_without_using_it_for_arrival(
    client,
    monkeypatch,
):
    home_base = {
        "home_base_id": 999,
        "label": "C3 Test Home Base",
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "active": True,
        "geofence_radius_m": None,
    }
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: home_base)
    payload = api.ClockInRequest(
        latitude=LATITUDE,
        longitude=LONGITUDE,
        accuracy=5,
    )
    employee = {"id": 1}

    clock_resolution = api._c3_resolve_site("clock-in", payload, employee)
    assert clock_resolution["state"] == "home_base"
    assert clock_resolution["source"] == "home_base"

    arrival_resolution = api._c3_resolve_site("arrive", payload, employee)
    assert arrival_resolution["state"] == "unresolved"
    assert arrival_resolution["reason"] == "no_eligible_inside_site"
