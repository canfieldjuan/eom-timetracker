"""Geofence C6 (#218): scoped foreground hard-gate integration contract."""

from __future__ import annotations

import bcrypt
import math
from datetime import date
from uuid import uuid4

import pytest

import db
import time_tracker_api as api
from conftest import _raw_conn


PREFIX = "C6_HARD_GATE_TEST"
LATITUDE = 39.5100000
LONGITUDE = -88.8100000
R_M = 6_371_000.0


def _clean_rows() -> None:
    conn = _raw_conn()
    with conn.cursor() as cur:
        # C6's enable-time readiness reads the one active Home Base globally,
        # rather than through a crew-local foreign key.  Earlier module tests
        # can legitimately leave an unready fixture Home Base behind, so this
        # C6 fixture must establish the global readiness input it depends on.
        # Clear its dependent evidence first, exactly as the Home Base suite
        # does, before removing the configuration rows.
        cur.execute("DELETE FROM home_base_events")
        cur.execute("DELETE FROM home_base_policies")
        cur.execute("DELETE FROM home_bases")
        cur.execute(
            "DELETE FROM shifts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM geofence_hard_gate_scopes WHERE crew_id IN "
            "(SELECT id FROM crews WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM crew_memberships WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute("DELETE FROM crews WHERE name LIKE %s", (f"{PREFIX}%",))
        cur.execute("DELETE FROM locations WHERE address LIKE %s", (f"{PREFIX}%",))
        cur.execute("DELETE FROM customers WHERE name LIKE %s", (f"{PREFIX}%",))
        cur.execute("DELETE FROM employees WHERE name LIKE %s", (f"{PREFIX}%",))
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def isolate_c6_data(setup_db):
    _clean_rows()
    yield
    _clean_rows()


def _create_employee(client, suffix: str) -> tuple[int, dict[str, str]]:
    name = f"{PREFIX} {suffix}"
    password = "c6-hard-gate-password"
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
    login = client.post("/api/auth/login", json={"name": name, "password": password})
    assert login.status_code == 200, login.text
    return int(row["id"]), {"Authorization": f"Bearer {login.json()['token']}"}


def _create_crew(employee_id: int, suffix: str) -> int:
    crew = db.query_one(
        """
        INSERT INTO crews (name, active)
        VALUES (%s, true)
        RETURNING id
        """,
        (f"{PREFIX} {suffix}",),
    )
    assert crew
    crew_id = int(crew["id"])
    db.execute(
        """
        INSERT INTO crew_memberships (crew_id, employee_id, effective_from)
        VALUES (%s, %s, %s)
        """,
        (crew_id, employee_id, date(2000, 1, 1)),
    )
    return crew_id


def _create_site(
    suffix: str,
    *,
    latitude: float | None = LATITUDE,
    longitude: float | None = LONGITUDE,
    ready: bool = True,
) -> int:
    customer_name = f"{PREFIX} Customer {suffix}"
    customer = db.query_one(
        "INSERT INTO customers (name) VALUES (%s) RETURNING id",
        (customer_name,),
    )
    assert customer
    site = db.query_one(
        """
        INSERT INTO locations (
            customer_id, address, customer_name, location_type, lat, lng,
            pin_provenance, pin_confidence
        ) VALUES (%s, %s, %s, 'Residential', %s, %s, %s, %s)
        RETURNING id
        """,
        (
            int(customer["id"]),
            f"{PREFIX} Site {suffix}",
            customer_name,
            latitude,
            longitude,
            "gps_capture" if ready else None,
            "high" if ready else None,
        ),
    )
    assert site
    site_id = int(site["id"])
    if ready:
        row = db.query_one(
            f"""
            SELECT {api.SITE_SELECT_COLUMNS}
            FROM locations l
            LEFT JOIN customers c ON c.id = l.customer_id
            WHERE l.id = %s
            """,
            (site_id,),
        )
        assert row
        fingerprint = api._location_geofence_state(dict(row))["currentFingerprint"]
        db.execute(
            """
            UPDATE locations
            SET pin_attested_at = NOW(),
                pin_attestation_fingerprint = %s
            WHERE id = %s
            """,
            (fingerprint, site_id),
        )
    return site_id


def _enable_scope(client, auth: dict[str, str], crew_id: int) -> dict:
    response = client.put(
        f"/api/admin/geofence-hard-gate-scopes/{crew_id}",
        headers=auth,
        json={"enabled": True},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _hard_gate_failure(response) -> dict:
    failure = response.json()
    assert failure["code"] == api.GEOFENCE_HARD_GATE_BLOCK_CODE
    assert isinstance(failure.get("details"), dict)
    return failure


def _destination(distance_m: float) -> tuple[float, float]:
    angle = distance_m / R_M
    latitude = math.radians(LATITUDE)
    longitude = math.radians(LONGITUDE)
    bearing = math.radians(90)
    target_latitude = math.asin(
        math.sin(latitude) * math.cos(angle)
        + math.cos(latitude) * math.sin(angle) * math.cos(bearing)
    )
    target_longitude = longitude + math.atan2(
        math.sin(bearing) * math.sin(angle) * math.cos(latitude),
        math.cos(angle) - math.sin(latitude) * math.sin(target_latitude),
    )
    return math.degrees(target_latitude), (
        math.degrees(target_longitude) + 540
    ) % 360 - 180


def test_c6_defaults_off_and_preserves_legacy_override(client, monkeypatch):
    _employee_id, employee_auth = _create_employee(client, "gate off")
    _create_site("gate off")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 1,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Parking is behind the building.",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["entry"]["clockInGpsMeta"]["override"] is True


def test_c6_refuses_scope_enable_until_all_eligible_sites_are_ready(
    client, auth, monkeypatch
):
    employee_id, _employee_auth = _create_employee(client, "readiness")
    crew_id = _create_crew(employee_id, "readiness crew")
    _create_site("unpinned", latitude=None, longitude=None, ready=False)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)

    rejected = client.put(
        f"/api/admin/geofence-hard-gate-scopes/{crew_id}",
        headers=auth,
        json={"enabled": True},
    )

    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["code"] == api.GEOFENCE_HARD_GATE_SCOPE_NOT_READY_CODE
    details = rejected.json()["details"]
    assert details["blockedReasons"] == ["eligible_sites_unready"]
    assert details["eligibleUnreadyLocations"][0]["reasons"] == [
        "unpinned",
        "low_or_missing_confidence",
        "not_attested",
    ]


def test_c6_blocks_free_text_bypass_and_advertises_scoped_capability(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "clock in")
    crew_id = _create_crew(employee_id, "clock in crew")
    site_id = _create_site("clock in")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    enabled = _enable_scope(client, auth, crew_id)
    assert enabled["scope"]["effective"] is True

    status = client.get("/api/timesheet/current-status", headers=employee_auth)
    assert status.status_code == 200, status.text
    assert status.json()["hardGateEnabled"] is True
    assert status.json()["siteResolutionEnabled"] is True

    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 1,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "I am definitely here.",
            "homeBaseExceptionReason": "Office was inaccessible.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert blocked.status_code == 409, blocked.text
    failure = _hard_gate_failure(blocked)
    assert failure["details"]["reason"] == "outside"
    assert failure["details"]["adminDirectRecordAvailable"] is True
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 0}

    accepted = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Documented but not authorizing.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["entry"]["locationId"] == site_id


@pytest.mark.parametrize(
    ("case_name", "body", "expected_reason"),
    [
        ("missing-gps", {"gpsOverrideReason": "No signal."}, "missing_gps"),
        (
            "permission-denied",
            {"gpsOverrideReason": "Location permission was denied."},
            "missing_gps",
        ),
        (
            "low-accuracy",
            {
                "latitude": LATITUDE,
                "longitude": LONGITUDE,
                "accuracy": api.SITE_CHECK_IN_MAX_ACCURACY_M + 1,
                "gpsOverrideReason": "Phone is inaccurate.",
            },
            "low_accuracy",
        ),
        (
            "uncertain",
            {
                "latitude": _destination(api.SITE_CHECK_IN_RADIUS_M)[0],
                "longitude": _destination(api.SITE_CHECK_IN_RADIUS_M)[1],
                "accuracy": 1,
                "gpsOverrideReason": "Near the boundary.",
            },
            "uncertain",
        ),
    ],
)
def test_c6_decision_table_blocks_weak_or_missing_gps(
    client, auth, monkeypatch, case_name, body, expected_reason
):
    employee_id, employee_auth = _create_employee(client, case_name)
    crew_id = _create_crew(employee_id, f"{case_name} crew")
    site_id = _create_site(case_name)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"locationId": site_id, **body},
    )

    assert response.status_code == 409, response.text
    assert _hard_gate_failure(response)["details"]["reason"] == expected_reason
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 0}


@pytest.mark.parametrize(
    ("global_enabled", "scope_enabled"),
    [(False, True), (True, False)],
    ids=["kill-switch-off", "crew-scope-off"],
)
def test_c6_disabled_modes_preserve_legacy_clock_in_and_selected_visit_contract(
    client, auth, monkeypatch, global_enabled, scope_enabled
):
    employee_id, employee_auth = _create_employee(client, "disabled modes")
    crew_id = _create_crew(employee_id, "disabled modes crew")
    site_id = _create_site("disabled modes")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", global_enabled)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    if scope_enabled:
        scope = _enable_scope(client, auth, crew_id)
        assert scope["scope"]["effective"] is False

    # A bare selected Site stays invalid for an employee outside C3/C6. The
    # route-level validation is intentionally where the scope can be known.
    selected_visit = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert selected_visit.status_code == 422, selected_visit.text
    assert selected_visit.json()["error"] == (
        "locationId and evidenceMethod are required for an explicit Site arrival"
    )

    legacy = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 1,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Parking is behind the building.",
        },
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["entry"]["clockInGpsMeta"]["override"] is True
    assert (
        api._c6_employee_scope_state(employee_id, api.utc_now())["effective"] is False
    )


def test_c6_never_traps_departure_or_clock_out_when_scope_is_effective(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "end actions")
    crew_id = _create_crew(employee_id, "end actions crew")
    site_id = _create_site("end actions")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)

    clocked_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert clocked_in.status_code == 200, clocked_in.text
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert arrived.status_code == 200, arrived.text

    # No GPS or free-text exception is supplied here. C6 is intentionally a
    # foreground-start gate only, so an employee cannot be left with open work.
    departed = client.post("/api/timesheet/depart", headers=employee_auth, json={})
    assert departed.status_code == 200, departed.text
    clocked_out = client.post(
        "/api/timesheet/clock-out", headers=employee_auth, json={}
    )
    assert clocked_out.status_code == 200, clocked_out.text
    assert clocked_out.json()["entry"]["clockOut"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}


def test_c6_gated_clock_in_is_idempotent_and_final_check_holds_writer_lock(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "idempotency")
    crew_id = _create_crew(employee_id, "idempotency crew")
    site_id = _create_site("idempotency")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    original = api._c6_hard_gate_failure_if_needed
    lock_observations: list[bool] = []

    def observe_final_gate(*args, **kwargs):
        if kwargs.get("cur") is not None:
            lock_conn = _raw_conn()
            try:
                with lock_conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_try_advisory_lock(%s)",
                        (api.TIMESHEET_PG_ADVISORY_LOCK_ID,),
                    )
                    acquired = bool(cur.fetchone()[0])
                    if acquired:
                        cur.execute(
                            "SELECT pg_advisory_unlock(%s)",
                            (api.TIMESHEET_PG_ADVISORY_LOCK_ID,),
                        )
            finally:
                lock_conn.close()
            lock_observations.append(not acquired)
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "_c6_hard_gate_failure_if_needed", observe_final_gate)
    payload = {
        "locationId": site_id,
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "accuracy": 5,
        "idempotencyKey": str(uuid4()),
    }
    first = client.post("/api/timesheet/clock-in", headers=employee_auth, json=payload)
    assert first.status_code == 200, first.text
    replay = client.post("/api/timesheet/clock-in", headers=employee_auth, json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["entry"]["id"] == first.json()["entry"]["id"]
    assert lock_observations and all(lock_observations)
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 1}


def test_c6_blocks_a_newly_unpinned_selected_site_after_scope_enable(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "site unpinned")
    crew_id = _create_crew(employee_id, "site unpinned crew")
    _create_site("ready before scope")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    unpinned_site_id = _create_site(
        "unready after scope", latitude=None, longitude=None, ready=False
    )

    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": unpinned_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "The pin is not ready.",
        },
    )

    assert blocked.status_code == 409, blocked.text
    assert _hard_gate_failure(blocked)["details"]["reason"] == "site_unpinned"

    readiness = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness.status_code == 200, readiness.text
    hard_gate = readiness.json()["hardGate"]
    assert hard_gate["readiness"]["ready"] is False
    scope = next(item for item in hard_gate["scopes"] if item["crewId"] == crew_id)
    assert scope["requested"] is True
    assert scope["effective"] is True


def test_c6_blocks_arrival_override_but_keeps_an_administrator_path(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "arrival")
    crew_id = _create_crew(employee_id, "arrival crew")
    site_id = _create_site("arrival")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)

    clocked_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert clocked_in.status_code == 200, clocked_in.text
    blocked = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 1,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Manager told me to proceed.",
        },
    )
    assert blocked.status_code == 409, blocked.text
    assert _hard_gate_failure(blocked)["details"]["reason"] == "outside"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visits WHERE shift_id = %s",
        (clocked_in.json()["entry"]["id"],),
    ) == {"count": 0}

    direct = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={
            "employeeId": employee_id,
            "action": "arrive",
            "targetKind": "site",
            "siteId": site_id,
            "reason": "GPS outage",
            "detail": "Supervisor records the immediate customer arrival.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert direct.status_code == 200, direct.text
    assert direct.json()["recordedSource"] == "admin_recorded"


def test_c6_valid_home_base_inside_passes_after_scope_enable(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "home base")
    crew_id = _create_crew(employee_id, "home base crew")
    _create_site("home base readiness")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    home_base = db.query_one(
        """
        INSERT INTO home_bases (label, address, latitude, longitude)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (f"{PREFIX} Home Base", "100 Dispatch Lane", LATITUDE, LONGITUDE),
    )
    assert home_base
    db.execute(
        """
        INSERT INTO home_base_policies (home_base_id, crew_id, active)
        VALUES (%s, %s, true)
        """,
        (int(home_base["id"]), crew_id),
    )

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "homeBaseExceptionReason": "This text cannot authorize the action.",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["entry"]["location"] == f"Home Base — {PREFIX} Home Base"
    assert response.json()["homeBaseEvent"]["outcome"] == "recorded"


def test_c6_commit_time_recheck_blocks_a_site_that_changes_after_preflight(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "commit recheck")
    crew_id = _create_crew(employee_id, "commit recheck crew")
    site_id = _create_site("commit recheck")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    original = api._c3_resolve_site
    changed = False

    def resolve_then_unpin(*args, **kwargs):
        nonlocal changed
        if kwargs.get("cur") is not None and not changed:
            changed = True
            db.execute(
                "UPDATE locations SET lat = NULL, lng = NULL WHERE id = %s", (site_id,)
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_then_unpin)
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert response.status_code == 409, response.text
    assert _hard_gate_failure(response)["details"]["reason"] == "site_unpinned"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 0}
