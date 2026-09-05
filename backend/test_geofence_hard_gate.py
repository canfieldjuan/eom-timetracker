"""Geofence C6 (#218): scoped foreground hard-gate integration contract."""

from __future__ import annotations

import bcrypt
import json
import math
import threading
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
            "DELETE FROM geofence_hard_gate_employee_scopes WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
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
    location_type: str = "Residential",
    geofence_radius_m: int | None = None,
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
            pin_provenance, pin_confidence, geofence_radius_m
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            int(customer["id"]),
            f"{PREFIX} Site {suffix}",
            customer_name,
            location_type,
            latitude,
            longitude,
            "gps_capture" if ready else None,
            "high" if ready else None,
            geofence_radius_m,
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


def _enable_employee_scope(client, auth: dict[str, str], employee_id: int) -> dict:
    response = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": True},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _enable_commercial_clock_boundary(
    client,
    auth: dict[str, str],
    employee_id: int,
) -> dict:
    response = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={
            "enabled": True,
            "profile": api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _configure_ready_home_base(client, auth: dict[str, str]) -> int:
    # Home Base owns an existing Morning Crew policy even though the new
    # individual boundary itself is not crew-scoped.
    crew = db.query_one(
        """
        INSERT INTO crews (name, active)
        VALUES ('Morning Crew', true)
        ON CONFLICT (name) DO UPDATE SET active = true
        RETURNING id
        """
    )
    assert crew
    configured = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": f"{PREFIX} Office",
            "address": f"{PREFIX} 100 Office Way",
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "pinProvenance": "gps_capture",
            "pinCaptureAccuracyM": 5,
            "pinConfidence": "high",
        },
    )
    assert configured.status_code == 200, configured.text
    attested = client.post(
        "/api/admin/home-base/attest-geofence",
        headers=auth,
        json={},
    )
    assert attested.status_code == 200, attested.text
    home_base = attested.json()["homeBase"]
    assert home_base["geofence"]["ready"] is True
    return int(home_base["id"])


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


@pytest.mark.parametrize("location_type", ["Commercial", "Residential"])
def test_effective_gate_reports_shared_radius_separately_from_legacy_fallback(
    client,
    auth,
    monkeypatch,
    location_type,
):
    employee_id, employee_auth = _create_employee(client, "shared radius compatibility")
    crew_id = _create_crew(employee_id, "shared radius compatibility crew")
    site_id = _create_site(
        "shared radius compatibility",
        location_type=location_type,
        geofence_radius_m=15,
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        False,
    )
    _enable_scope(client, auth, crew_id)
    outside_latitude, outside_longitude = _destination(30)

    outside_response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": outside_latitude,
            "longitude": outside_longitude,
            "accuracy": 1,
        },
    )

    assert outside_response.status_code == 409, outside_response.text
    latitude, longitude = _destination(10)

    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": latitude,
            "longitude": longitude,
            "accuracy": 5,
        },
    )

    assert response.status_code == 200, response.text
    row = api._c3_customer_site_rows(
        api.ClockInRequest(
            locationId=site_id,
            latitude=latitude,
            longitude=longitude,
            accuracy=1,
        ),
        action="clock-in",
        selected_location_id=site_id,
    )[0]
    geofence = api._c3_location_geofence_state(row)
    assert geofence["clockBoundaryEffectiveRadiusM"] == 15
    assert geofence["clockBoundaryRadiusSource"] == "per_site"
    assert geofence["clockBoundaryPerSiteRadiusEnabled"] is True
    assert geofence["clockBoundaryUnscopedLegacyFallbackRadiusM"] == 50


def test_home_base_clock_telemetry_never_uses_the_legacy_site_matcher(
    monkeypatch,
):
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        False,
    )
    monkeypatch.setattr(api, "LOCATION_MATCH_RADIUS_M", 50)

    geofence = api._home_base_geofence_state(
        {
            "home_base_id": 9001,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "geofence_radius_m": 15,
            "active": True,
        }
    )

    assert geofence["clockBoundaryEffectiveRadiusM"] == 15
    assert geofence["clockBoundaryRadiusSource"] == "per_site"
    assert geofence["clockBoundaryPerSiteRadiusEnabled"] is True
    assert geofence["clockBoundaryUnscopedLegacyFallbackRadiusM"] is None


def test_c6_individual_scope_defaults_off_without_a_scope_row(client, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "individual default off")
    _create_site("individual default off")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    state = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert state["effective"] is False
    assert state["individualScope"] is False
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM geofence_hard_gate_employee_scopes "
        "WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}

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


def test_c6_fleet_default_profileless_opt_out_cycle_preserves_inherited_profile(
    client,
    auth,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "fleet default")
    _create_site("fleet default commercial", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )

    inherited = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert inherited["effective"] is True
    assert inherited["individualScope"] is True
    assert inherited["individualProfile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY
    )
    readiness = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness.status_code == 200, readiness.text
    inherited_admin = next(
        row
        for row in readiness.json()["hardGate"]["employeeScopes"]
        if row["employeeId"] == employee_id
    )
    assert inherited_admin["scopeSource"] == "fleet_default"
    assert inherited_admin["requested"] is True
    assert inherited_admin["effective"] is True

    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Coffee stop",
        },
    )
    assert blocked.status_code == 409, blocked.text

    disabled = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["scope"]["scopeSource"] == "explicit"
    assert disabled.json()["scope"]["effective"] is False
    assert disabled.json()["scope"]["profile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY
    )
    opted_out = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert opted_out == {
        "effective": False,
        "requested": False,
        "blockedReasons": ["employee_not_scoped"],
        "crews": [],
        "individualScope": False,
    }
    refreshed = client.get("/api/admin/geofence-readiness", headers=auth)
    explicit_admin = next(
        row
        for row in refreshed.json()["hardGate"]["employeeScopes"]
        if row["employeeId"] == employee_id
    )
    assert explicit_admin["scopeSource"] == "explicit"
    assert explicit_admin["requested"] is False

    reenabled = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": True},
    )
    assert reenabled.status_code == 200, reenabled.text
    assert reenabled.json()["scope"]["profile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY
    )
    restored = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert restored["individualProfile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY
    )


def test_c6_fleet_default_never_enrolls_an_inactive_account(client, monkeypatch):
    employee_id, _employee_auth = _create_employee(client, "inactive fleet default")
    db.execute("UPDATE employees SET active = false WHERE id = %s", (employee_id,))
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )

    assert api._c6_employee_scope_state(employee_id, api.utc_now()) == {
        "effective": False,
        "requested": False,
        "blockedReasons": ["employee_not_scoped"],
        "crews": [],
        "individualScope": False,
    }


def test_c6_fleet_default_preserves_existing_crew_policy(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "fleet crew precedence")
    crew_id = _create_crew(employee_id, "fleet crew precedence")
    site_id = _create_site("fleet crew residential", location_type="Residential")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    _enable_scope(client, auth, crew_id)

    scope = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert scope["effective"] is True
    assert scope["crews"] == [{"id": crew_id, "name": f"{PREFIX} fleet crew precedence"}]
    assert scope["individualScope"] is False
    assert "individualProfile" not in scope

    readiness = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness.status_code == 200, readiness.text
    employee_scope = next(
        row
        for row in readiness.json()["hardGate"]["employeeScopes"]
        if row["employeeId"] == employee_id
    )
    assert employee_scope["scopeSource"] == "none"
    assert employee_scope["requested"] is False

    explicit_crew_member = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": False},
    )
    assert explicit_crew_member.status_code == 200, explicit_crew_member.text
    assert explicit_crew_member.json()["scope"]["profile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_ALL_BUSINESS_START
    )

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["entry"]["locationId"] == site_id


def test_c6_reports_home_base_and_commercial_readiness_failures_precisely(
    client,
    auth,
    monkeypatch,
):
    home_employee_id, home_auth = _create_employee(client, "home base unready")
    _configure_ready_home_base(client, auth)
    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 250 WHERE active = true"
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )

    home_blocked = client.post(
        "/api/timesheet/clock-in",
        headers=home_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert home_blocked.status_code == 409, home_blocked.text
    assert _hard_gate_failure(home_blocked)["details"]["reason"] == (
        "home_base_unready"
    )

    ready_overlap_id = _create_site(
        "ready overlap",
        latitude=LATITUDE + 0.02,
        location_type="Commercial",
    )
    ready_overlap = client.post(
        "/api/timesheet/clock-in",
        headers=home_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert ready_overlap.status_code == 200, ready_overlap.text
    assert ready_overlap.json()["entry"]["locationId"] == ready_overlap_id

    commercial_employee_id, commercial_auth = _create_employee(
        client,
        "commercial unready",
    )
    _create_site(
        "commercial unready",
        ready=False,
        location_type="Commercial",
    )
    commercial_blocked = client.post(
        "/api/timesheet/clock-in",
        headers=commercial_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert commercial_blocked.status_code == 409, commercial_blocked.text
    assert _hard_gate_failure(commercial_blocked)["details"]["reason"] == (
        "commercial_site_unready"
    )
    assert home_employee_id != commercial_employee_id


def test_c6_failure_log_is_structured_and_coordinate_free(
    client,
    auth,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "structured log")
    site_id = _create_site("structured log", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[tuple[str, dict]] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append((str(args[3]), dict(kwargs.get("details") or {})))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE + 0.01,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert blocked.status_code == 409, blocked.text
    assert "_log" not in blocked.json()
    assert len(captured) == 1
    reason, details = captured[0]
    assert reason == f"{api.GEOFENCE_HARD_GATE_BLOCK_CODE}: outside"
    assert f"{PREFIX} Site structured log" not in reason
    assert details["employeeId"] == employee_id
    assert details["action"] == "clock-in"
    assert details["reason"] == "outside"
    assert details["code"] == api.GEOFENCE_HARD_GATE_BLOCK_CODE
    assert details["targetKind"] == "site"
    assert details["targetId"] == site_id
    assert details["accuracyM"] == 5
    assert details["distanceM"] > details["effectiveRadiusM"]
    assert details["radiusSource"] in {"global_fallback", "per_site"}
    serialized = json.dumps(details).lower()
    assert "latitude" not in serialized
    assert "longitude" not in serialized


def test_c6_ineligible_selected_site_failure_log_retains_accuracy(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(
        client,
        "ineligible selected log",
    )
    site_id = _create_site(
        "ineligible selected log",
        location_type="Residential",
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 7.5,
        },
    )

    assert blocked.status_code == 409, blocked.text
    assert _hard_gate_failure(blocked)["details"]["reason"] == (
        "selected_site_ineligible"
    )
    assert len(captured) == 1
    assert captured[0]["reason"] == "selected_site_ineligible"
    assert captured[0]["targetKind"] == "site"
    assert captured[0]["targetId"] == site_id
    assert captured[0]["accuracyM"] == 7.5
    serialized = json.dumps(captured[0]).lower()
    assert "latitude" not in serialized
    assert "longitude" not in serialized


@pytest.mark.parametrize("site_ready", [True, False])
def test_c6_uncertain_single_commercial_target_is_retained_in_failure_log(
    client,
    auth,
    monkeypatch,
    site_ready,
):
    monkeypatch.setattr(api, "SITE_CHECK_IN_RADIUS_M", 50)
    employee_id, employee_auth = _create_employee(client, "uncertain target log")
    site_id = _create_site(
        "uncertain target log",
        location_type="Commercial",
        ready=site_ready,
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    latitude, longitude = _destination(45)
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": latitude,
            "longitude": longitude,
            "accuracy": 10,
        },
    )

    assert blocked.status_code == 409, blocked.text
    assert _hard_gate_failure(blocked)["details"]["reason"] == "uncertain"
    assert len(captured) == 1
    assert captured[0]["employeeId"] == employee_id
    assert captured[0]["targetKind"] == "site"
    assert captured[0]["targetId"] == site_id
    assert captured[0]["distanceM"] is not None
    assert captured[0]["effectiveRadiusM"] == 50
    assert captured[0]["radiusSource"] == "global_fallback"


def test_c6_overlapping_unready_sites_are_not_falsely_attributed(
    client,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(client, "overlapping unready log")
    _create_site(
        "overlapping unready log one",
        ready=False,
        location_type="Commercial",
    )
    _create_site(
        "overlapping unready log two",
        ready=False,
        location_type="Commercial",
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert blocked.status_code == 409, blocked.text
    failure = _hard_gate_failure(blocked)
    assert failure["details"]["reason"] == "commercial_site_unready"
    assert failure["details"].get("target") is None
    assert len(captured) == 1
    assert captured[0]["targetKind"] is None
    assert captured[0]["targetId"] is None


def test_c6_overlapping_unready_home_base_and_site_are_not_falsely_attributed(
    client,
    auth,
    monkeypatch,
):
    _employee_id, employee_auth = _create_employee(
        client,
        "mixed overlapping unready log",
    )
    _create_site(
        "mixed overlapping unready log",
        latitude=LATITUDE + 0.02,
        ready=False,
        location_type="Commercial",
    )
    home_base_id = _configure_ready_home_base(client, auth)
    db.execute(
        """
        UPDATE home_bases
        SET pin_attested_at = NULL,
            pin_attestation_fingerprint = NULL
        WHERE id = %s
        """,
        (home_base_id,),
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert blocked.status_code == 409, blocked.text
    failure = _hard_gate_failure(blocked)
    assert failure["details"]["reason"] == "commercial_site_unready"
    assert failure["details"].get("target") is None
    assert len(captured) == 1
    assert captured[0]["targetKind"] is None
    assert captured[0]["targetId"] is None
    assert captured[0]["distanceM"] is None
    assert captured[0]["effectiveRadiusM"] is None
    assert captured[0]["radiusSource"] is None


@pytest.mark.parametrize("uncertain_site_ready", [True, False])
def test_c6_mixed_inside_unready_and_uncertain_targets_are_not_attributed(
    client,
    monkeypatch,
    uncertain_site_ready,
):
    monkeypatch.setattr(api, "SITE_CHECK_IN_RADIUS_M", 50)
    _employee_id, employee_auth = _create_employee(
        client,
        "mixed unready uncertain log",
    )
    _create_site(
        "mixed unready uncertain inside",
        ready=False,
        location_type="Commercial",
    )
    uncertain_latitude, uncertain_longitude = _destination(45)
    _create_site(
        "mixed unready uncertain candidate",
        latitude=uncertain_latitude,
        longitude=uncertain_longitude,
        ready=uncertain_site_ready,
        location_type="Commercial",
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 10},
    )

    assert blocked.status_code == 409, blocked.text
    failure = _hard_gate_failure(blocked)
    assert failure["details"]["reason"] == "commercial_site_unready"
    assert failure["details"].get("target") is None
    assert len(captured) == 1
    assert captured[0]["targetKind"] is None
    assert captured[0]["targetId"] is None
    assert captured[0]["distanceM"] is None
    assert captured[0]["effectiveRadiusM"] is None
    assert captured[0]["radiusSource"] is None


def test_c6_unready_failure_logs_retain_target_metadata(
    client,
    auth,
    monkeypatch,
):
    commercial_employee_id, commercial_auth = _create_employee(
        client,
        "commercial unready log",
    )
    selected_employee_id, selected_auth = _create_employee(
        client,
        "selected unready log",
    )
    home_employee_id, home_auth = _create_employee(client, "home unready log")
    site_id = _create_site(
        "commercial unready log",
        ready=False,
        location_type="Commercial",
    )
    home_base_id = _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(
        api,
        "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED",
        True,
    )
    captured: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            captured.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    commercial = client.post(
        "/api/timesheet/clock-in",
        headers=commercial_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert commercial.status_code == 409, commercial.text

    selected = client.post(
        "/api/timesheet/clock-in",
        headers=selected_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert selected.status_code == 409, selected.text

    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 250 WHERE id = %s",
        (home_base_id,),
    )
    home = client.post(
        "/api/timesheet/clock-in",
        headers=home_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert home.status_code == 409, home.text

    by_employee = {item["employeeId"]: item for item in captured}
    commercial_log = by_employee[commercial_employee_id]
    assert commercial_log["reason"] == "commercial_site_unready"
    assert commercial_log["employeeId"] == commercial_employee_id
    assert commercial_log["targetKind"] == "site"
    assert commercial_log["targetId"] == site_id
    assert commercial_log["distanceM"] == 0
    assert commercial_log["effectiveRadiusM"] is not None
    assert commercial_log["radiusSource"] in {"global_fallback", "per_site"}

    selected_log = by_employee[selected_employee_id]
    assert selected_log["reason"] == "selected_site_unready"
    assert selected_log["targetKind"] == "site"
    assert selected_log["targetId"] == site_id
    assert selected_log["distanceM"] == 0
    assert selected_log["effectiveRadiusM"] is not None
    assert selected_log["radiusSource"] in {"global_fallback", "per_site"}

    home_log = by_employee[home_employee_id]
    assert home_log["reason"] == "home_base_unready"
    assert home_log["employeeId"] == home_employee_id
    assert home_log["targetKind"] == "home_base"
    assert home_log["targetId"] == home_base_id
    assert home_log["distanceM"] == 0
    assert home_log["effectiveRadiusM"] is not None
    assert home_log["radiusSource"] in {"global_fallback", "per_site"}
    serialized = json.dumps(captured).lower()
    assert "latitude" not in serialized
    assert "longitude" not in serialized


def test_geofence_client_diagnostic_is_bounded_coordinate_free_and_rate_limited(
    client,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "client diagnostic")
    written: list[dict] = []
    monkeypatch.setattr(
        api,
        "_append_access_log_to_postgres",
        lambda entry, _local_date: written.append(dict(entry)),
    )
    monkeypatch.setattr(api, "_append_access_log_to_file", lambda *_args: None)
    monkeypatch.setattr(api, "_maybe_prune_access_log_entries", lambda: None)
    with api._RATE_LIMIT_LOCK:
        api._RATE_LIMIT_BUCKETS.clear()

    recorded = client.post(
        "/api/timesheet/geofence-client-diagnostic",
        headers={**employee_auth, "User-Agent": "geofence-test-browser"},
        json={
            "action": "clock-in",
            "outcome": "timeout",
            "sampleCount": 3,
            "bestAccuracyM": 240.5,
            "elapsedMs": 12_000,
        },
    )
    assert recorded.status_code == 200, recorded.text
    assert recorded.json() == {"success": True}
    assert len(written) == 1
    entry = written[0]
    assert entry["action"] == "GEOFENCE_CLIENT_DIAGNOSTIC"
    assert entry["userAgent"] == "geofence-test-browser"
    assert entry["details"] == {
        "employeeId": employee_id,
        "action": "clock-in",
        "outcome": "timeout",
        "sampleCount": 3,
        "bestAccuracyM": 240.5,
        "elapsedMs": 12_000,
    }
    assert "latitude" not in json.dumps(entry).lower()
    assert "longitude" not in json.dumps(entry).lower()

    rejected_coordinates = client.post(
        "/api/timesheet/geofence-client-diagnostic",
        headers=employee_auth,
        json={
            "action": "clock-out",
            "outcome": "permission_denied",
            "sampleCount": 0,
            "elapsedMs": 20,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
        },
    )
    assert rejected_coordinates.status_code == 422, rejected_coordinates.text

    monkeypatch.setattr(api, "GEOFENCE_CLIENT_DIAGNOSTIC_RATE_LIMIT_MAX", 2)
    with api._RATE_LIMIT_LOCK:
        api._RATE_LIMIT_BUCKETS.clear()
    payload = {
        "action": "clock-out",
        "outcome": "no_valid_sample",
        "sampleCount": 0,
        "elapsedMs": 500,
    }
    assert client.post(
        "/api/timesheet/geofence-client-diagnostic",
        headers=employee_auth,
        json=payload,
    ).status_code == 200
    assert client.post(
        "/api/timesheet/geofence-client-diagnostic",
        headers=employee_auth,
        json=payload,
    ).status_code == 200
    limited = client.post(
        "/api/timesheet/geofence-client-diagnostic",
        headers=employee_auth,
        json=payload,
    )
    assert limited.status_code == 429, limited.text


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


def test_c6_refuses_individual_scope_enable_until_all_eligible_sites_are_ready(
    client, auth, monkeypatch
):
    employee_id, _employee_auth = _create_employee(client, "individual readiness")
    _create_site("individual unpinned", latitude=None, longitude=None, ready=False)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)

    rejected = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": True},
    )

    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["code"] == api.GEOFENCE_HARD_GATE_SCOPE_NOT_READY_CODE
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM geofence_hard_gate_employee_scopes "
        "WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}


def test_clock_radius_scope_requirement_preserves_global_default(monkeypatch):
    unscoped = {"effective": False}
    scoped = {"effective": True}
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", False
    )
    assert api._clock_radius_enabled_for_scope(unscoped)

    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    assert not api._clock_radius_enabled_for_scope(unscoped)
    assert api._clock_radius_enabled_for_scope(scoped)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    assert api._c3_action_resolution_enabled("clock-in", unscoped)
    assert api._c3_action_resolution_target_policy("clock-in", unscoped) == (
        api.GEOFENCE_HARD_GATE_PROFILE_ALL_BUSINESS_START
    )

    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", False
    )
    assert not api._clock_radius_enabled_for_scope(scoped)


def test_clock_radius_canary_isolates_scoped_employee_clock_actions(
    client, auth, monkeypatch
):
    unscoped_id, unscoped_auth = _create_employee(client, "radius canary off")
    scoped_id, scoped_auth = _create_employee(client, "radius canary on")
    site_id = _create_site(
        "radius canary", location_type="Commercial", geofence_radius_m=250
    )
    home_base_id = _configure_ready_home_base(client, auth)
    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 250 WHERE id = %s",
        (home_base_id,),
    )
    attested = client.post(
        "/api/admin/home-base/attest-geofence", headers=auth, json={}
    )
    assert attested.status_code == 200, attested.text
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_COMMERCIAL_HOME_BASE_DEFAULT_SCOPE_ENABLED", False
    )
    disabled = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{unscoped_id}",
        headers=auth,
        json={
            "enabled": False,
            "profile": api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY,
        },
    )
    assert disabled.status_code == 200, disabled.text
    _enable_commercial_clock_boundary(client, auth, scoped_id)
    readiness = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness.status_code == 200, readiness.text
    readiness_payload = readiness.json()
    assert readiness_payload["hardGate"]["clockBoundaryEmployeeScopeRequired"]
    site_geofence = next(
        row["geofence"]
        for row in readiness_payload["locations"]
        if row["id"] == site_id
    )
    assert site_geofence["clockBoundaryEffectiveRadiusM"] == 250
    assert site_geofence["clockBoundaryUnscopedLegacyFallbackRadiusM"] == (
        api.LOCATION_MATCH_RADIUS_M
    )
    home_base_geofence = readiness_payload["homeBases"][0]["geofence"]
    assert home_base_geofence["clockBoundaryEffectiveRadiusM"] == 250
    assert home_base_geofence["clockBoundaryUnscopedLegacyFallbackRadiusM"] == (
        api.SITE_CHECK_IN_RADIUS_M
    )

    site_sample = {
        # Roughly 111m from the Site: inside 250m, outside legacy 50m.
        "latitude": LATITUDE + 0.001,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    legacy_site_sample = {
        **site_sample,
        "gpsOverrideReason": "Supervisor verified the legacy fallback.",
    }
    unscoped_start = client.post(
        "/api/timesheet/clock-in", headers=unscoped_auth, json=legacy_site_sample
    )
    assert unscoped_start.status_code == 200, unscoped_start.text
    assert "siteResolution" not in unscoped_start.json()
    assert "locationId" not in unscoped_start.json()["entry"]
    unscoped_end = client.post(
        "/api/timesheet/clock-out", headers=unscoped_auth, json=legacy_site_sample
    )
    assert unscoped_end.status_code == 200, unscoped_end.text
    assert "siteResolution" not in unscoped_end.json()

    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    preflight = client.post(
        "/api/timesheet/site-resolution",
        headers=unscoped_auth,
        json={"action": "clock-in", **site_sample},
    )
    assert preflight.status_code == 200, preflight.text
    assert preflight.json()["resolution"] == {
        "state": "unresolved",
        "reason": "no_eligible_inside_site",
    }
    broad_start = client.post(
        "/api/timesheet/clock-in", headers=unscoped_auth, json=legacy_site_sample
    )
    assert broad_start.status_code == 200, broad_start.text
    assert broad_start.json()["siteResolution"] == {
        "state": "unresolved",
        "reason": "no_eligible_inside_site",
    }
    assert "locationId" not in broad_start.json()["entry"]
    broad_end = client.post(
        "/api/timesheet/clock-out", headers=unscoped_auth, json=legacy_site_sample
    )
    assert broad_end.status_code == 200, broad_end.text
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    home_sample = {
        # Roughly 111m from Home Base: inside 250m, outside legacy 50m.
        "latitude": LATITUDE + 0.021,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    legacy_home_sample = {
        **home_sample,
        "gpsOverrideReason": "Supervisor verified the legacy fallback.",
    }
    unscoped_home_start = client.post(
        "/api/timesheet/clock-in", headers=unscoped_auth, json=legacy_home_sample
    )
    assert unscoped_home_start.status_code == 200, unscoped_home_start.text
    assert "internalHomeBase" not in unscoped_home_start.json()["entry"]
    unscoped_home_end = client.post(
        "/api/timesheet/clock-out", headers=unscoped_auth, json=legacy_home_sample
    )
    assert unscoped_home_end.status_code == 200, unscoped_home_end.text

    scoped_start = client.post(
        "/api/timesheet/clock-in", headers=scoped_auth, json=site_sample
    )
    assert scoped_start.status_code == 200, scoped_start.text
    assert scoped_start.json()["entry"]["locationId"] == site_id
    assert scoped_start.json()["entry"]["clockInGpsMeta"]["distanceM"] > 50
    scoped_end = client.post(
        "/api/timesheet/clock-out", headers=scoped_auth, json=site_sample
    )
    assert scoped_end.status_code == 200, scoped_end.text
    assert scoped_end.json()["siteResolution"]["state"] == "customer_site"

    outside = client.post(
        "/api/timesheet/clock-in",
        headers=scoped_auth,
        json={"latitude": LATITUDE + 0.003, "longitude": LONGITUDE, "accuracy": 5},
    )
    assert outside.status_code == 409, outside.text
    assert _hard_gate_failure(outside)["details"]["reason"] == "outside"

    home_start = client.post(
        "/api/timesheet/clock-in", headers=scoped_auth, json=home_sample
    )
    assert home_start.status_code == 200, home_start.text
    assert home_start.json()["entry"]["internalHomeBase"] is True
    assert home_start.json()["entry"]["clockInGpsMeta"]["distanceM"] > 50
    home_end = client.post(
        "/api/timesheet/clock-out", headers=scoped_auth, json=home_sample
    )
    assert home_end.status_code == 200, home_end.text
    assert home_end.json()["siteResolution"]["state"] == "home_base"


def test_clock_radius_scope_loss_replays_legacy_home_base_boundaries(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "radius scope loss")
    site_id = _create_site(
        "radius scope loss", location_type="Commercial", geofence_radius_m=250
    )
    home_base_id = _configure_ready_home_base(client, auth)
    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 250 WHERE id = %s",
        (home_base_id,),
    )
    attested = client.post(
        "/api/admin/home-base/attest-geofence", headers=auth, json={}
    )
    assert attested.status_code == 200, attested.text
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    _enable_commercial_clock_boundary(client, auth, employee_id)
    site_sample = {
        "locationId": site_id,
        "latitude": LATITUDE,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    started = client.post(
        "/api/timesheet/clock-in", headers=employee_auth, json=site_sample
    )
    assert started.status_code == 200, started.text

    original_scope_read = api._c6_authoritative_scope_state
    original_override_check = api._c3_clock_boundary_override_error
    legacy_refresh_cursors = []

    def lose_scope_before_persist(*args, **kwargs):
        original_scope_read(*args, **kwargs)
        return {"effective": False}

    def track_legacy_refresh(*args, **kwargs):
        if kwargs.get("clock_radius_enabled") is False:
            legacy_refresh_cursors.append(kwargs.get("cur"))
        return original_override_check(*args, **kwargs)

    monkeypatch.setattr(
        api, "_c6_authoritative_scope_state", lose_scope_before_persist
    )
    monkeypatch.setattr(api, "_c3_clock_boundary_override_error", track_legacy_refresh)
    home_sample = {
        # Inside the configured 250m Home Base radius but outside legacy 50m.
        "latitude": LATITUDE + 0.021,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    rejected_end = client.post(
        "/api/timesheet/clock-out", headers=employee_auth, json=home_sample
    )
    assert rejected_end.status_code == 400, rejected_end.text
    assert "nearest saved site" in rejected_end.json()["error"]

    legacy_home_sample = {
        **home_sample,
        "gpsOverrideReason": "Supervisor verified the legacy fallback.",
    }
    accepted_end = client.post(
        "/api/timesheet/clock-out", headers=employee_auth, json=legacy_home_sample
    )
    assert accepted_end.status_code == 200, accepted_end.text
    assert "homeBaseEvent" not in accepted_end.json()
    assert accepted_end.json()["entry"]["clockOutGpsMeta"]["override"] is True

    rejected_start = client.post(
        "/api/timesheet/clock-in", headers=employee_auth, json=home_sample
    )
    assert rejected_start.status_code == 400, rejected_start.text
    assert "nearest saved site" in rejected_start.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}

    exception_sample = {
        **home_sample,
        "homeBaseExceptionReason": "Office entry was inaccessible.",
    }
    rejected_exception_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=exception_sample,
    )
    assert rejected_exception_start.status_code == 400, rejected_exception_start.text
    assert "nearest saved site" in rejected_exception_start.json()["error"]
    accepted_exception_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            **exception_sample,
            "gpsOverrideReason": "Supervisor approved dispatch exception.",
        },
    )
    assert accepted_exception_start.status_code == 200, accepted_exception_start.text
    assert accepted_exception_start.json()["entry"]["location"] == "Dispatch exception"
    accepted_exception_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            **exception_sample,
            "gpsOverrideReason": "Supervisor approved dispatch exception.",
        },
    )
    assert accepted_exception_end.status_code == 200, accepted_exception_end.text
    assert legacy_refresh_cursors
    assert all(cur is not None for cur in legacy_refresh_cursors)

    home_center = {
        "latitude": LATITUDE + 0.02,
        "longitude": LONGITUDE,
        "accuracy": 5,
    }
    started_home = client.post(
        "/api/timesheet/clock-in", headers=employee_auth, json=home_center
    )
    assert started_home.status_code == 200, started_home.text
    assert started_home.json()["homeBaseEvent"]["outcome"] == "recorded"
    rejected_exception_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            **home_sample,
            "homeBaseExceptionReason": "Office entry was inaccessible.",
        },
    )
    assert rejected_exception_end.status_code == 400, rejected_exception_end.text
    assert "nearest saved site" in rejected_exception_end.json()["error"]
    ended_with_exception = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            **home_sample,
            "homeBaseExceptionReason": "Office entry was inaccessible.",
            "gpsOverrideReason": "Supervisor approved dispatch exception.",
        },
    )
    assert ended_with_exception.status_code == 200, ended_with_exception.text
    assert ended_with_exception.json()["homeBaseEvent"]["outcome"] == "exception"

    started_before_deactivation = client.post(
        "/api/timesheet/clock-in", headers=employee_auth, json=home_center
    )
    assert started_before_deactivation.status_code == 200, started_before_deactivation.text
    assert started_before_deactivation.json()["homeBaseEvent"]["outcome"] == "recorded"
    db.execute("UPDATE home_bases SET active = false WHERE id = %s", (home_base_id,))
    ended_after_deactivation = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            **site_sample,
            "homeBaseExceptionReason": "Office was deactivated during the shift.",
        },
    )
    assert ended_after_deactivation.status_code == 200, ended_after_deactivation.text
    assert ended_after_deactivation.json()["homeBaseEvent"]["outcome"] == "exception"
    assert db.query_all(
        "SELECT action, outcome FROM home_base_events "
        "WHERE employee_id = %s ORDER BY action",
        (employee_id,),
    ) == [
        {"action": "end", "outcome": "exception"},
        {"action": "end", "outcome": "exception"},
        {"action": "end", "outcome": "exception"},
        {"action": "start", "outcome": "exception"},
        {"action": "start", "outcome": "recorded"},
        {"action": "start", "outcome": "recorded"},
    ]


def test_clock_radius_scope_loss_refreshes_legacy_site_data(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "radius stale site")
    site_id = _create_site(
        "radius stale site", location_type="Commercial", geofence_radius_m=250
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    _enable_commercial_clock_boundary(client, auth, employee_id)
    original_scope_read = api._c6_authoritative_scope_state
    site_mutation = 0
    current_address = f"{PREFIX} Site radius stale site current"
    current_customer = f"{PREFIX} Customer radius stale site current"

    def move_site_then_lose_scope(*args, **kwargs):
        nonlocal site_mutation
        original_scope_read(*args, **kwargs)
        if site_mutation == 0:
            db.execute(
                "UPDATE locations SET lat = %s WHERE id = %s",
                (LATITUDE + 1, site_id),
            )
        else:
            db.execute(
                "UPDATE locations SET address = %s, customer_name = %s "
                "WHERE id = %s",
                (current_address, current_customer, site_id),
            )
        site_mutation += 1
        return {"effective": False}

    monkeypatch.setattr(
        api, "_c6_authoritative_scope_state", move_site_then_lose_scope
    )
    rejected = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert rejected.status_code == 400, rejected.text
    assert "nearest saved site" in rejected.json()["error"]
    assert site_mutation == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}
    db.execute("UPDATE locations SET lat = %s WHERE id = %s", (LATITUDE, site_id))
    accepted = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert accepted.status_code == 200, accepted.text
    assert site_mutation == 2
    assert accepted.json()["entry"]["location"] == current_address
    assert accepted.json()["entry"]["customer"] == current_customer
    assert accepted.json()["entry"]["clockInGpsMeta"]["matchedLocation"] == (
        current_address
    )


def test_clock_radius_scope_loss_restores_exception_while_broad_c3_stays_enabled(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(
        client, "radius broad c3 exception"
    )
    _create_site(
        "radius broad c3 exception",
        location_type="Commercial",
        geofence_radius_m=250,
    )
    home_base_id = _configure_ready_home_base(client, auth)
    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 250 WHERE id = %s",
        (home_base_id,),
    )
    attested = client.post(
        "/api/admin/home-base/attest-geofence", headers=auth, json={}
    )
    assert attested.status_code == 200, attested.text
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    _enable_commercial_clock_boundary(client, auth, employee_id)

    original_scope_read = api._c6_authoritative_scope_state

    def lose_scope_before_persist(*args, **kwargs):
        original_scope_read(*args, **kwargs)
        return {"effective": False}

    monkeypatch.setattr(
        api, "_c6_authoritative_scope_state", lose_scope_before_persist
    )
    exception_sample = {
        # Inside the configured 250m Home Base radius but outside legacy 50m.
        "latitude": LATITUDE + 0.021,
        "longitude": LONGITUDE,
        "accuracy": 5,
        "homeBaseExceptionReason": "Office entry was inaccessible.",
    }
    rejected = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=exception_sample,
    )
    assert rejected.status_code == 400, rejected.text
    assert "nearest saved site" in rejected.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}

    accepted = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            **exception_sample,
            "gpsOverrideReason": "Supervisor approved dispatch exception.",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["entry"]["location"] == "Dispatch exception"
    assert accepted.json()["entry"]["internalHomeBase"] is True
    assert accepted.json()["siteResolution"] == {
        "state": "unresolved",
        "reason": "home_base_exception",
    }
    assert accepted.json()["homeBaseEvent"]["outcome"] == "exception"


def test_clock_radius_scope_loss_honors_final_legacy_clock_out_bypass(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "radius final end bypass")
    site_id = _create_site(
        "radius final end bypass",
        location_type="Commercial",
        geofence_radius_m=250,
    )
    _configure_ready_home_base(client, auth)
    crew_id = _create_crew(employee_id, "radius final end bypass crew")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    _enable_scope(client, auth, crew_id)
    _enable_commercial_clock_boundary(client, auth, employee_id)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text
    assert started.json()["homeBaseEvent"]["outcome"] == "recorded"

    original_scope_read = api._c6_authoritative_scope_state
    current_address = f"{PREFIX} Site radius final end bypass current"
    current_customer = f"{PREFIX} Customer radius final end bypass current"

    def drop_individual_profile_before_persist(*args, **kwargs):
        final_scope = original_scope_read(*args, **kwargs)
        final_scope["individualScope"] = False
        db.execute(
            "UPDATE locations SET address = %s, customer_name = %s WHERE id = %s",
            (current_address, current_customer, site_id),
        )
        return final_scope

    monkeypatch.setattr(
        api,
        "_c6_authoritative_scope_state",
        drop_individual_profile_before_persist,
    )
    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert ended.status_code == 200, ended.text
    assert ended.json()["entry"]["clockOutGpsMeta"]["matchedLocation"] == (
        current_address
    )
    assert "homeBaseEvent" not in ended.json()
    assert db.query_all(
        "SELECT action, outcome FROM home_base_events "
        "WHERE employee_id = %s ORDER BY action",
        (employee_id,),
    ) == [{"action": "start", "outcome": "recorded"}]


def test_clock_radius_unscoped_broad_c3_refreshes_legacy_site_data(
    client, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "radius broad stale site")
    site_id = _create_site(
        "radius broad stale site",
        location_type="Commercial",
        geofence_radius_m=250,
    )
    monkeypatch.setattr(api, "_active_home_base_config", lambda *, cur=None: None)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED", True
    )
    monkeypatch.setattr(
        api, "GEOFENCE_CLOCK_BOUNDARY_EMPLOYEE_SCOPE_REQUIRED", True
    )
    original_scope_read = api._c6_authoritative_scope_state

    def move_site_before_final_broad_resolution(*args, **kwargs):
        final_scope = original_scope_read(*args, **kwargs)
        db.execute(
            "UPDATE locations SET lat = %s WHERE id = %s",
            (LATITUDE + 1, site_id),
        )
        return final_scope

    monkeypatch.setattr(
        api,
        "_c6_authoritative_scope_state",
        move_site_before_final_broad_resolution,
    )
    rejected = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={"latitude": LATITUDE, "longitude": LONGITUDE, "accuracy": 5},
    )

    assert rejected.status_code == 400, rejected.text
    assert "nearest saved site" in rejected.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}


def test_commercial_home_base_clock_boundary_allows_ready_targets_without_gating_visits(
    client, auth, monkeypatch
):
    """The opt-in boundary rejects coffee/home, not ordinary visit evidence."""

    employee_id, employee_auth = _create_employee(client, "commercial boundary")
    commercial_site_id = _create_site(
        "commercial boundary",
        location_type="Commercial",
    )
    residential_site_id = _create_site(
        "residential boundary",
        latitude=LATITUDE + 0.01,
        location_type="Residential",
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    enabled = _enable_commercial_clock_boundary(client, auth, employee_id)
    assert enabled["scope"]["profile"] == (
        api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY
    )
    assert enabled["readiness"]["ready"] is True

    scope = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert api._c6_action_scope_state(scope, "clock-in") == {
        "effective": True,
        "targetPolicy": api.GEOFENCE_HARD_GATE_PROFILE_COMMERCIAL_HOME_BASE_CLOCK_BOUNDARY,
    }
    assert api._c6_action_scope_state(scope, "clock-out")["effective"] is True
    assert api._c6_action_scope_state(scope, "arrive")["effective"] is False
    assert api._c6_action_scope_state(scope, "depart")["effective"] is False

    # A coffee stop/home-sized miss is not converted into a time action by an
    # old free-text GPS override. The boundary admits only a ready Commercial
    # Site or Home Base whose geofence actually contains the sample.
    offsite_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Buying coffee before work.",
        },
    )
    assert offsite_start.status_code == 409, offsite_start.text
    assert _hard_gate_failure(offsite_start)["details"]["reason"] == "outside"

    residential_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": residential_site_id,
            "latitude": LATITUDE + 0.01,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert residential_start.status_code == 409, residential_start.text
    assert _hard_gate_failure(residential_start)["details"]["reason"] == (
        "selected_site_ineligible"
    )

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": commercial_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert clock_in.status_code == 200, clock_in.text
    assert clock_in.json()["entry"]["locationId"] == commercial_site_id

    # The new profile deliberately does not alter an ordinary arrival's
    # legacy GPS-override path or the QR/visit model it shares.
    legacy_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "location": "Supplier stop",
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Dispatch asked for a supply pickup.",
        },
    )
    assert legacy_arrival.status_code == 200, legacy_arrival.text
    departed = client.post(
        "/api/timesheet/depart",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Leaving the supply pickup.",
        },
    )
    assert departed.status_code == 200, departed.text

    resolution = client.post(
        "/api/timesheet/site-resolution",
        headers=employee_auth,
        json={
            "action": "clock-out",
            "locationId": commercial_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert resolution.status_code == 200, resolution.text
    assert resolution.json()["enabled"] is True
    assert resolution.json()["hardGateEnabled"] is True
    assert resolution.json()["resolution"]["state"] == "customer_site"

    residential_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "locationId": residential_site_id,
            "latitude": LATITUDE + 0.01,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert residential_end.status_code == 409, residential_end.text
    assert _hard_gate_failure(residential_end)["details"]["reason"] == (
        "selected_site_ineligible"
    )
    assert db.query_one(
        "SELECT clock_out FROM shifts WHERE id = %s",
        (int(clock_in.json()["entry"]["id"]),),
    ) == {"clock_out": None}

    offsite_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Heading home from coffee.",
        },
    )
    assert offsite_end.status_code == 409, offsite_end.text
    assert _hard_gate_failure(offsite_end)["details"]["reason"] == "outside"

    commercial_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "locationId": commercial_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert commercial_end.status_code == 200, commercial_end.text
    assert commercial_end.json()["siteResolution"]["state"] == "customer_site"


def test_commercial_home_base_clock_boundary_keeps_unready_commercial_sites_out(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "unready commercial")
    unready_commercial_id = _create_site(
        "unready commercial",
        location_type="Commercial",
        ready=False,
    )
    _create_site(
        "unready residential",
        latitude=None,
        longitude=None,
        location_type="Residential",
        ready=False,
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    # Unlike the legacy all-business profile, an unready old Commercial pin
    # does not disable every ready target. It is surfaced and rejected only
    # when selected at the live boundary.
    enabled = _enable_commercial_clock_boundary(client, auth, employee_id)
    assert enabled["readiness"]["ready"] is True
    assert [row["id"] for row in enabled["readiness"]["eligibleUnreadyLocations"]] == [
        unready_commercial_id
    ]

    attempted = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": unready_commercial_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert attempted.status_code == 409, attempted.text
    assert _hard_gate_failure(attempted)["details"]["reason"] == (
        "selected_site_unready"
    )
    assert _hard_gate_failure(attempted)["details"]["retryable"] is False

    automatic = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert automatic.status_code == 409, automatic.text
    automatic_failure = _hard_gate_failure(automatic)
    assert automatic_failure["details"]["reason"] == "commercial_site_unready"
    assert automatic_failure["details"]["retryable"] is False
    assert "administrator to repair" in automatic_failure["error"]


def test_commercial_home_base_clock_boundary_reports_unready_home_base(
    client,
    auth,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "unready home base")
    _create_site(
        "unready home base commercial",
        location_type="Commercial",
    )
    home_base_id = _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)
    db.execute(
        """
        UPDATE home_bases
        SET pin_attested_at = NULL,
            pin_attestation_fingerprint = NULL
        WHERE id = %s
        """,
        (home_base_id,),
    )

    attempted = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert attempted.status_code == 409, attempted.text
    failure = _hard_gate_failure(attempted)
    assert failure["details"]["reason"] == "home_base_unready"
    assert failure["details"]["retryable"] is False
    assert "administrator to repair" in failure["error"]


def test_non_gated_home_base_exception_survives_unready_clock_boundary(
    client,
    auth,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "unready home exception")
    home_base_id = _configure_ready_home_base(client, auth)
    db.execute(
        "UPDATE home_bases SET geofence_radius_m = 15 WHERE id = %s",
        (home_base_id,),
    )
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    exception_payload = {
        "homeBaseExceptionReason": "Office entry was inaccessible.",
        "latitude": LATITUDE + 0.02,
        "longitude": LONGITUDE,
        "accuracy": 5,
        "gpsOverrideReason": "Supervisor approved dispatch exception.",
        "gpsOverrideDetail": "The office entry could not be used.",
    }

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json=exception_payload,
    )
    assert started.status_code == 200, started.text
    assert started.json()["entry"]["location"] == "Dispatch exception"
    assert started.json()["siteResolution"] == {
        "state": "unresolved",
        "reason": "home_base_exception",
    }

    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json=exception_payload,
    )
    assert ended.status_code == 200, ended.text
    assert ended.json()["siteResolution"] == {
        "state": "unresolved",
        "reason": "home_base_exception",
    }
    assert db.query_all(
        "SELECT action, outcome FROM home_base_events "
        "WHERE employee_id = %s ORDER BY action",
        (employee_id,),
    ) == [
        {"action": "end", "outcome": "exception"},
        {"action": "start", "outcome": "exception"},
    ]


def test_commercial_home_base_clock_boundary_requires_exact_choice_for_overlaps(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "commercial overlap")
    first_commercial_id = _create_site(
        "commercial overlap first",
        location_type="Commercial",
    )
    second_commercial_id = _create_site(
        "commercial overlap second",
        location_type="Commercial",
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)

    resolution = client.post(
        "/api/timesheet/site-resolution",
        headers=employee_auth,
        json={
            "action": "clock-in",
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert resolution.status_code == 200, resolution.text
    assert resolution.json()["resolution"]["state"] == "selection_required"
    assert {
        row["locationId"] for row in resolution.json()["resolution"]["candidates"]
    } == {first_commercial_id, second_commercial_id}

    unspecified = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert unspecified.status_code == 409, unspecified.text
    assert _hard_gate_failure(unspecified)["details"]["reason"] == (
        "selection_required"
    )

    selected = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": second_commercial_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert selected.status_code == 200, selected.text
    assert selected.json()["entry"]["locationId"] == second_commercial_id


def test_commercial_home_base_clock_boundary_allows_the_ready_office_at_both_ends(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "office boundary")
    _create_site("office commercial", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)

    office_latitude = LATITUDE + 0.02
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": office_latitude,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text
    assert started.json()["entry"]["internalHomeBase"] is True
    assert started.json()["siteResolution"]["state"] == "home_base"

    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": office_latitude,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert ended.status_code == 200, ended.text
    assert ended.json()["siteResolution"]["state"] == "home_base"
    assert ended.json()["homeBaseEvent"]["action"] == "end"
    assert ended.json()["homeBaseEvent"]["outcome"] == "recorded"


def test_c6_rejects_an_inactive_individual_scope_target(client, auth):
    employee_id, _employee_auth = _create_employee(client, "inactive individual")
    db.execute("UPDATE employees SET active = false WHERE id = %s", (employee_id,))

    rejected = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": False},
    )

    assert rejected.status_code == 404, rejected.text
    assert rejected.json() == {"success": False, "error": "Active employee was not found"}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM geofence_hard_gate_employee_scopes "
        "WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}


def test_c6_deactivation_disarms_individual_scope_without_reactivation_reviving_it(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "individual lifecycle")
    _create_site("individual lifecycle")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_employee_scope(client, auth, employee_id)

    deactivated = client.patch(
        f"/api/admin/employees/{employee_id}",
        headers=auth,
        json={"active": False},
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["employee"]["active"] is False
    assert db.query_one(
        "SELECT enabled FROM geofence_hard_gate_employee_scopes WHERE employee_id = %s",
        (employee_id,),
    ) == {"enabled": False}
    readiness_while_inactive = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness_while_inactive.status_code == 200, readiness_while_inactive.text
    assert all(
        scope["employeeId"] != employee_id
        for scope in readiness_while_inactive.json()["hardGate"]["employeeScopes"]
    )

    reactivated = client.patch(
        f"/api/admin/employees/{employee_id}",
        headers=auth,
        json={"active": True},
    )
    assert reactivated.status_code == 200, reactivated.text
    assert reactivated.json()["employee"]["active"] is True
    assert api._c6_employee_scope_state(employee_id, api.utc_now()) == {
        "effective": False,
        "requested": False,
        "blockedReasons": ["employee_not_scoped"],
        "crews": [],
        "individualScope": False,
    }

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


def test_c6_individual_scope_blocks_free_text_bypass_and_keeps_crew_state_empty(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "individual clock in")
    site_id = _create_site("individual clock in")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    enabled = _enable_employee_scope(client, auth, employee_id)
    assert enabled["scope"]["employeeId"] == employee_id
    assert enabled["scope"]["effective"] is True
    readiness = client.get("/api/admin/geofence-readiness", headers=auth)
    assert readiness.status_code == 200, readiness.text
    employee_scope = next(
        item
        for item in readiness.json()["hardGate"]["employeeScopes"]
        if item["employeeId"] == employee_id
    )
    assert employee_scope == {
        "employeeId": employee_id,
        "employeeName": f"{PREFIX} individual clock in",
        "requested": True,
        "effective": True,
        "blockedReasons": [],
        "profile": api.GEOFENCE_HARD_GATE_PROFILE_ALL_BUSINESS_START,
        "scopeSource": "explicit",
    }
    assert api._c6_employee_scope_state(employee_id, api.utc_now()) == {
        "effective": True,
        "requested": True,
        "blockedReasons": [],
        "crews": [],
        "individualScope": True,
    }

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
            "idempotencyKey": str(uuid4()),
        },
    )
    assert blocked.status_code == 409, blocked.text
    assert _hard_gate_failure(blocked)["details"]["reason"] == "outside"


def test_c6_individual_scope_kill_switch_rolls_back_to_legacy_behavior(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "individual kill switch")
    _create_site("individual kill switch")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)

    scope = _enable_employee_scope(client, auth, employee_id)
    assert scope["scope"]["requested"] is True
    assert scope["scope"]["effective"] is False
    assert scope["scope"]["blockedReasons"] == ["kill_switch_off"]

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


def test_c6_individual_scope_composes_with_an_existing_crew_scope(
    client, auth, monkeypatch
):
    employee_id, _employee_auth = _create_employee(client, "individual and crew")
    crew_id = _create_crew(employee_id, "individual and crew")
    _create_site("individual and crew")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)

    _enable_scope(client, auth, crew_id)
    _enable_employee_scope(client, auth, employee_id)
    state = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert state["effective"] is True
    assert state["individualScope"] is True
    assert state["crews"] == [{"id": crew_id, "name": f"{PREFIX} individual and crew"}]

    disabled = client.put(
        f"/api/admin/geofence-hard-gate-employee-scopes/{employee_id}",
        headers=auth,
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    state_after = api._c6_employee_scope_state(employee_id, api.utc_now())
    assert state_after["effective"] is True
    assert state_after["individualScope"] is False
    assert state_after["crews"] == [{"id": crew_id, "name": f"{PREFIX} individual and crew"}]


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
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    _enable_scope(client, auth, crew_id)
    current_status = client.get(
        "/api/timesheet/current-status",
        headers=employee_auth,
    )
    assert current_status.status_code == 200, current_status.text
    assert current_status.json()["clockOutSiteResolutionRequired"] is False

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


def test_commercial_home_base_boundary_rechecks_the_office_under_lock(
    client, auth, monkeypatch
):
    """A Home Base move cannot race the narrow profile's final C3 decision."""

    employee_id, employee_auth = _create_employee(client, "office lock")
    commercial_site_id = _create_site("office lock", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)

    lock_conn = _raw_conn()
    worker: threading.Thread | None = None
    completed: dict[str, object] = {}
    try:
        with lock_conn.cursor() as cur:
            # The normal Home Base writer takes this conflicting row lock
            # before it changes either the pin or its readiness configuration.
            cur.execute("SELECT id FROM home_bases WHERE active = true FOR UPDATE")

        def clock_in_while_office_is_locked() -> None:
            completed["response"] = client.post(
                "/api/timesheet/clock-in",
                headers=employee_auth,
                json={
                    "locationId": commercial_site_id,
                    "latitude": LATITUDE,
                    "longitude": LONGITUDE,
                    "accuracy": 5,
                },
            )

        worker = threading.Thread(target=clock_in_while_office_is_locked)
        worker.start()
        worker.join(timeout=2)
        assert worker.is_alive(), "C6 did not wait for the Home Base configuration lock"
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
            (employee_id,),
        ) == {"count": 0}

        lock_conn.commit()
        worker.join(timeout=15)
        assert not worker.is_alive(), "C6 did not resume after the Home Base lock released"
        response = completed.get("response")
        assert response is not None
        assert response.status_code == 200, response.text
    finally:
        if lock_conn.closed == 0:
            lock_conn.close()
        if worker is not None and worker.is_alive():
            worker.join(timeout=15)


def test_commercial_home_base_boundary_uses_final_customer_site_for_end_event(
    client, auth, monkeypatch
):
    """A final Site result must not emit an event from a stale Home Base read."""

    employee_id, employee_auth = _create_employee(client, "final end target")
    start_site_id = _create_site("final end start", location_type="Commercial")
    _create_site(
        "final end office site",
        latitude=LATITUDE + 0.02,
        location_type="Commercial",
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": start_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text

    original_resolver = api._c3_resolve_site
    clock_out_resolutions = 0

    def move_home_base_after_provisional_resolution(action, *args, **kwargs):
        nonlocal clock_out_resolutions
        resolution = original_resolver(action, *args, **kwargs)
        if action == "clock-out":
            clock_out_resolutions += 1
            if clock_out_resolutions == 1:
                assert resolution["state"] == "home_base"
                db.execute(
                    "UPDATE home_bases SET latitude = %s WHERE active = true",
                    (LATITUDE + 0.3,),
                )
        return resolution

    monkeypatch.setattr(
        api,
        "_c3_resolve_site",
        move_home_base_after_provisional_resolution,
    )
    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert ended.status_code == 200, ended.text
    assert clock_out_resolutions == 2
    result = ended.json()
    assert result["siteResolution"]["state"] == "customer_site"
    assert "homeBaseEvent" not in result
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE shift_id = %s",
        (int(result["entry"]["id"]),),
    ) == {"count": 0}


def test_commercial_site_wins_clock_out_overlap_with_unready_home_base(
    client, auth, monkeypatch
):
    employee_id, employee_auth = _create_employee(client, "clock out overlap")
    start_site_id = _create_site("clock out overlap start", location_type="Commercial")
    overlap_site_id = _create_site(
        "clock out overlap target",
        latitude=LATITUDE + 0.02,
        location_type="Commercial",
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": start_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "location": "Active supplier visit",
            "latitude": LATITUDE + 0.3,
            "longitude": LONGITUDE,
            "accuracy": 5,
            "gpsOverrideReason": "Dispatch requested the supplier stop.",
        },
    )
    assert arrived.status_code == 200, arrived.text
    db.execute(
        "UPDATE home_bases SET pin_attestation_fingerprint = NULL WHERE active = true"
    )

    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "locationId": overlap_site_id,
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert ended.status_code == 200, ended.text
    assert ended.json()["siteResolution"]["state"] == "customer_site"
    assert ended.json()["siteResolution"]["site"]["locationId"] == overlap_site_id
    assert ended.json()["entry"]["clockOutGpsMeta"]["matchedLocation"] == (
        f"{PREFIX} Site clock out overlap target"
    )
    assert "homeBaseEvent" not in ended.json()


def test_clock_out_rejects_a_stale_provisional_home_base_confirmation(
    client,
    auth,
    monkeypatch,
):
    """A final Home Base move invalidates its provisional end confirmation."""

    employee_id, employee_auth = _create_employee(client, "stale office end")
    start_site_id = _create_site(
        "stale office end start",
        location_type="Commercial",
    )
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )

    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": start_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text

    original_resolver = api._c3_resolve_site
    clock_out_resolutions = 0

    def move_home_base_after_provisional_resolution(action, *args, **kwargs):
        nonlocal clock_out_resolutions
        resolution = original_resolver(action, *args, **kwargs)
        if action == "clock-out":
            clock_out_resolutions += 1
            if clock_out_resolutions == 1:
                assert resolution["state"] == "home_base"
                db.execute(
                    "UPDATE home_bases SET latitude = %s WHERE active = true",
                    (LATITUDE + 0.3,),
                )
        return resolution

    monkeypatch.setattr(
        api,
        "_c3_resolve_site",
        move_home_base_after_provisional_resolution,
    )
    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert ended.status_code == 400, ended.text
    assert clock_out_resolutions == 2
    assert "nearest saved site" in ended.text
    assert db.query_one(
        "SELECT clock_out FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"clock_out": None}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events "
        "WHERE shift_id = %s AND action = 'end'",
        (int(started.json()["entry"]["id"]),),
    ) == {"count": 0}


def test_clock_in_rejects_a_stale_provisional_home_base_confirmation(
    client,
    auth,
    monkeypatch,
):
    """A final Home Base move invalidates its provisional start confirmation."""

    employee_id, employee_auth = _create_employee(client, "stale office start")
    _create_site("stale office start fallback", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", False)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    monkeypatch.setattr(
        api,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )
    original_resolver = api._c3_resolve_site
    clock_in_resolutions = 0

    def move_home_base_after_provisional_resolution(action, *args, **kwargs):
        nonlocal clock_in_resolutions
        resolution = original_resolver(action, *args, **kwargs)
        if action == "clock-in":
            clock_in_resolutions += 1
            if clock_in_resolutions == 1:
                assert resolution["state"] == "home_base"
                db.execute(
                    "UPDATE home_bases SET latitude = %s WHERE active = true",
                    (LATITUDE + 0.3,),
                )
        return resolution

    monkeypatch.setattr(
        api,
        "_c3_resolve_site",
        move_home_base_after_provisional_resolution,
    )
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": LATITUDE + 0.02,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert started.status_code == 400, started.text
    assert clock_in_resolutions == 2
    assert "nearest saved site" in started.text
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE action = 'start'"
    ) == {"count": 0}


def test_c6_profile_upgrade_defaults_legacy_scope_rows(client):
    """The old scope table upgrades to a non-null historic policy by default."""

    legacy_employee_id, _ = _create_employee(client, "legacy profile scope")
    new_employee_id, _ = _create_employee(client, "new profile scope")
    try:
        db.execute(
            "ALTER TABLE geofence_hard_gate_employee_scopes "
            "DROP COLUMN IF EXISTS policy_profile"
        )
        db.execute(
            """
            INSERT INTO geofence_hard_gate_employee_scopes (employee_id, enabled)
            VALUES (%s, true)
            """,
            (legacy_employee_id,),
        )

        api._ensure_geofence_hard_gate_scope_schema()

        assert db.query_one(
            "SELECT policy_profile FROM geofence_hard_gate_employee_scopes "
            "WHERE employee_id = %s",
            (legacy_employee_id,),
        ) == {"policy_profile": "all_business_start"}
        assert db.query_one(
            """
            INSERT INTO geofence_hard_gate_employee_scopes (employee_id, enabled)
            VALUES (%s, false)
            RETURNING policy_profile
            """,
            (new_employee_id,),
        ) == {"policy_profile": "all_business_start"}
        profile_column = db.query_one(
            """
            SELECT is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'geofence_hard_gate_employee_scopes'
              AND column_name = 'policy_profile'
            """
        )
        assert profile_column == {
            "is_nullable": "NO",
            "column_default": "'all_business_start'::character varying",
        }
    finally:
        # Keep the shared test database compatible with following test modules.
        api._ensure_geofence_hard_gate_scope_schema()


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
    logged: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "VISIT_FAILED":
            logged.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)

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
    assert len(logged) == 1
    assert logged[0]["action"] == "arrive"
    assert logged[0]["reason"] == "outside"
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


def test_c6_commit_time_arrival_recheck_is_logged(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "arrival recheck")
    crew_id = _create_crew(employee_id, "arrival recheck crew")
    start_site_id = _create_site(
        "arrival recheck start",
        latitude=LATITUDE + 0.01,
    )
    arrival_site_id = _create_site("arrival recheck target")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": start_site_id,
            "latitude": LATITUDE + 0.01,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text

    original_resolver = api._c3_resolve_site
    changed = False

    def resolve_then_unpin(action, *args, **kwargs):
        nonlocal changed
        if action == "arrive" and kwargs.get("cur") is not None and not changed:
            changed = True
            db.execute(
                "UPDATE locations SET lat = NULL, lng = NULL WHERE id = %s",
                (arrival_site_id,),
            )
        return original_resolver(action, *args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_then_unpin)
    logged: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "VISIT_FAILED":
            logged.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": arrival_site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert arrived.status_code == 409, arrived.text
    assert _hard_gate_failure(arrived)["details"]["reason"] == "site_unpinned"
    assert len(logged) == 1
    assert logged[0]["action"] == "arrive"
    assert logged[0]["reason"] == "site_unpinned"


def test_c6_commit_time_explicit_arrival_recheck_is_logged(
    client,
    auth,
    monkeypatch,
):
    employee_id, employee_auth = _create_employee(client, "explicit arrival recheck")
    crew_id = _create_crew(employee_id, "explicit arrival recheck crew")
    start_site_id = _create_site(
        "explicit arrival recheck start",
        latitude=LATITUDE + 0.01,
    )
    arrival_site_id = _create_site("explicit arrival recheck target")
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    _enable_scope(client, auth, crew_id)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": start_site_id,
            "latitude": LATITUDE + 0.01,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text
    original_resolver = api._resolve_explicit_visit_site
    changed = False

    def resolve_then_move(*args, **kwargs):
        nonlocal changed
        if kwargs.get("cur") is not None and not changed:
            changed = True
            db.execute(
                "UPDATE locations SET lat = %s WHERE id = %s",
                (LATITUDE + 0.1, arrival_site_id),
            )
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(api, "_resolve_explicit_visit_site", resolve_then_move)
    logged: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "VISIT_FAILED":
            logged.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": arrival_site_id,
            "evidenceMethod": "unplanned_residential",
            "exceptionReason": "unplanned_visit",
            "exceptionDetail": "Supervisor assigned this stop during the shift.",
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert arrived.status_code == 409, arrived.text
    assert _hard_gate_failure(arrived)["details"]["reason"] == "outside"
    assert len(logged) == 1
    assert logged[0]["action"] == "arrive"
    assert logged[0]["reason"] == "outside"
    assert logged[0]["targetKind"] == "site"
    assert logged[0]["targetId"] == arrival_site_id


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
    logged: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_IN_FAILED":
            logged.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
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
    assert len(logged) == 1
    assert logged[0]["action"] == "clock-in"
    assert logged[0]["reason"] == "site_unpinned"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 0}


def test_c6_commit_time_clock_out_recheck_is_logged(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "clock out recheck")
    site_id = _create_site("clock out recheck", location_type="Commercial")
    _configure_ready_home_base(client, auth)
    monkeypatch.setattr(api, "GEOFENCE_HARD_GATE_ENABLED", True)
    monkeypatch.setattr(api, "GEOFENCE_SITE_RESOLUTION_ENABLED", False)
    _enable_commercial_clock_boundary(client, auth, employee_id)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )
    assert started.status_code == 200, started.text

    original_resolver = api._c3_resolve_site
    changed = False

    def resolve_then_unpin(action, *args, **kwargs):
        nonlocal changed
        if action == "clock-out" and kwargs.get("cur") is not None and not changed:
            changed = True
            db.execute(
                "UPDATE locations SET lat = NULL, lng = NULL WHERE id = %s",
                (site_id,),
            )
        return original_resolver(action, *args, **kwargs)

    monkeypatch.setattr(api, "_c3_resolve_site", resolve_then_unpin)
    logged: list[dict] = []
    original_append = api.append_access_log

    def capture_failure(*args, **kwargs):
        if len(args) > 1 and args[1] == "CLOCK_OUT_FAILED":
            logged.append(dict(kwargs.get("details") or {}))
        return original_append(*args, **kwargs)

    monkeypatch.setattr(api, "append_access_log", capture_failure)
    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "latitude": LATITUDE,
            "longitude": LONGITUDE,
            "accuracy": 5,
        },
    )

    assert ended.status_code == 409, ended.text
    assert _hard_gate_failure(ended)["details"]["reason"] == (
        "selected_site_unready"
    )
    assert len(logged) == 1
    assert logged[0]["action"] == "clock-out"
    assert logged[0]["reason"] == "selected_site_unready"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 1}
