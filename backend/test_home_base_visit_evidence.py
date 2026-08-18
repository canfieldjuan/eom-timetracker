"""Contract tests for internal Home Base and explicit customer-visit evidence."""

from __future__ import annotations

import bcrypt
import hashlib
import json
import math
import psycopg2
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

import db
import operations_schedule
import time_tracker_api
from conftest import _raw_conn


TEST_PREFIX = "HOME_BASE_VISIT_EVIDENCE_TEST"
BASE_LATITUDE = 39.2000000
BASE_LONGITUDE = -88.6000000


def _clean_rows() -> None:
    conn = _raw_conn()
    with conn.cursor() as cur:
        # These tables are new to this feature and no existing suite writes
        # them. Delete their dependents before the one-active-base records.
        cur.execute("DELETE FROM home_base_events")
        cur.execute("DELETE FROM home_base_policies")
        cur.execute("DELETE FROM home_bases")
        cur.execute(
            "DELETE FROM site_qr_action_receipts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM site_check_ins WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM plain_time_action_receipts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM visit_evidence_events WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_visit_assignments WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM shifts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM crew_memberships WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_visit_assignments WHERE planned_visit_id IN "
            "(SELECT id FROM planned_service_visits WHERE source_calendar_id LIKE %s)",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM planned_service_visits WHERE source_calendar_id LIKE %s",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute("DELETE FROM jobs WHERE customer_name LIKE %s", (f"{TEST_PREFIX}%",))
        cur.execute("DELETE FROM crews WHERE name LIKE %s", (f"{TEST_PREFIX}%",))
        cur.execute(
            "DELETE FROM google_calendar_connections WHERE google_account_email LIKE %s",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM locations WHERE address LIKE %s",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM customers WHERE name LIKE %s",
            (f"{TEST_PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM employees WHERE name LIKE %s",
            (f"{TEST_PREFIX}%",),
        )
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def isolate_home_base_visit_evidence_data(setup_db):
    _clean_rows()
    yield
    _clean_rows()


def _create_employee(client, suffix: str) -> tuple[int, dict[str, str]]:
    name = f"{TEST_PREFIX} {suffix}"
    password = "home-base-test-password"
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


def _enroll_in_morning_crew(employee_id: int) -> int:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO crews (name, active)
                VALUES ('Morning Crew', true)
                ON CONFLICT (name) DO UPDATE SET active = true
                RETURNING id
                """
            )
            crew_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO crew_memberships (crew_id, employee_id, effective_from)
                VALUES (%s, %s, %s)
                ON CONFLICT (crew_id, employee_id, effective_from) DO NOTHING
                """,
                (crew_id, employee_id, date(2000, 1, 1)),
            )
    return crew_id


def _configure_home_base(client, auth: dict[str, str]) -> dict:
    response = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": "EOM Office Home Base",
            "address": "100 Dispatch Lane, Effingham",
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["configured"] is True
    assert body["homeBase"]["label"] == "EOM Office Home Base"
    return body


def _insert_site(
    suffix: str,
    *,
    location_type: str,
    latitude: float | None,
    longitude: float | None,
) -> int:
    row = db.query_one(
        """
        INSERT INTO locations (
            address, customer_name, location_type, lat, lng,
            rate, rate_type, expected_hours
        ) VALUES (%s, %s, %s, %s, %s, 100, 'per_visit', 2)
        RETURNING id
        """,
        (
            f"{TEST_PREFIX} {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            location_type,
            latitude,
            longitude,
        ),
    )
    assert row
    return int(row["id"])


def _insert_assigned_planned_visit(
    *,
    employee_id: int,
    location_id: int,
    suffix: str,
    crew_id: int | None = None,
) -> int:
    now = datetime.now(timezone.utc)
    source_key = hashlib.sha256(f"{TEST_PREFIX}:{suffix}".encode()).hexdigest()
    source_fingerprint = hashlib.sha256(
        f"{TEST_PREFIX}:fingerprint:{suffix}".encode()
    ).hexdigest()
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO google_calendar_connections (
                    google_account_email, granted_scopes, revoked_at
                ) VALUES (%s, ARRAY['calendar.readonly'], NOW())
                RETURNING id
                """,
                (f"{TEST_PREFIX}_{suffix}@example.test",),
            )
            connection_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO planned_service_visits (
                    connection_id, source_calendar_id, source_event_id,
                    source_series_id, source_occurrence_id, source_key,
                    source_fingerprint, title, location_id,
                    approximate_start, approximate_end, source_timezone
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, 'America/Chicago'
                )
                RETURNING id
                """,
                (
                    connection_id,
                    f"{TEST_PREFIX}-{suffix}",
                    f"event-{suffix}",
                    f"series-{suffix}",
                    f"occurrence-{suffix}",
                    source_key,
                    source_fingerprint,
                    f"Planned {suffix}",
                    location_id,
                    now - timedelta(hours=1),
                    now + timedelta(hours=2),
                ),
            )
            planned_visit_id = int(cur.fetchone()[0])
            if crew_id is None:
                cur.execute(
                    """
                    INSERT INTO planned_visit_assignments (planned_visit_id, employee_id)
                    VALUES (%s, %s)
                    """,
                    (planned_visit_id, employee_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO planned_visit_assignments (planned_visit_id, crew_id)
                    VALUES (%s, %s)
                    """,
                    (planned_visit_id, crew_id),
                )
    return planned_visit_id


def _clock_in(client, employee_auth: dict[str, str]) -> int:
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "location": "",
            "latitude": 39.00009,
            "longitude": -88.00000,
            "accuracy": 5,
            "gpsOverrideReason": "test location setup",
            "gpsOverrideDetail": "Test starts before the selected customer visit.",
        },
    )
    assert response.status_code == 200, response.text
    return int(response.json()["entry"]["id"])


def _depart_and_clock_out(
    client,
    employee_auth: dict[str, str],
    *,
    latitude: float,
    longitude: float,
) -> None:
    depart = client.post(
        "/api/timesheet/depart",
        headers=employee_auth,
        json={"latitude": latitude, "longitude": longitude, "accuracy": 5},
    )
    assert depart.status_code == 200, depart.text
    clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={"latitude": latitude, "longitude": longitude, "accuracy": 5},
    )
    assert clock_out.status_code == 200, clock_out.text


def test_timesheet_locations_exposes_home_base_as_internal_gps_pin(client, auth):
    employee_id, employee_auth = _create_employee(client, "Home Base location meta")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)

    response = client.get("/api/timesheet/locations", headers=employee_auth)
    assert response.status_code == 200, response.text
    body = response.json()

    label = "Home Base — EOM Office Home Base"
    assert body["internal_locations"] == pytest.approx(
        [
            {
                "kind": "home_base",
                "name": label,
                "latitude": BASE_LATITUDE,
                "longitude": BASE_LONGITUDE,
            }
        ]
    )
    assert label not in body["location_coords"]
    assert label not in body["location_customers"]
    assert label not in body["locations"]
    assert all(site["name"] != label for site in body["sites"])


def test_timesheet_locations_preserves_customer_site_when_home_base_label_collides(client, auth):
    employee_id, employee_auth = _create_employee(client, "Home Base label collision")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)

    label = "Home Base — EOM Office Home Base"
    customer = f"{TEST_PREFIX} Collision Customer"
    row = db.query_one(
        """
        INSERT INTO locations (
            address, customer_name, location_type, lat, lng,
            rate, rate_type, expected_hours
        ) VALUES (%s, %s, 'Commercial', %s, %s, 100, 'per_visit', 2)
        RETURNING id
        """,
        (label, customer, BASE_LATITUDE + 0.5, BASE_LONGITUDE - 0.5),
    )
    assert row

    response = client.get("/api/timesheet/locations", headers=employee_auth)
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["location_coords"][label] == pytest.approx(
        {"lat": BASE_LATITUDE + 0.5, "lng": BASE_LONGITUDE - 0.5}
    )
    assert body["location_customers"][label] == customer
    assert label in body["locations"]
    assert any(site["name"] == label for site in body["sites"])
    assert body["internal_locations"] == pytest.approx(
        [
            {
                "kind": "home_base",
                "name": label,
                "latitude": BASE_LATITUDE,
                "longitude": BASE_LONGITUDE,
            }
        ]
    )


def test_home_base_scan_exception_and_server_enforced_policy(client, auth):
    employee_id, employee_auth = _create_employee(client, "Morning")
    _enroll_in_morning_crew(employee_id)
    missing_coordinates = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={"label": "Unlocatable office", "address": "100 Dispatch Lane, Effingham"},
    )
    assert missing_coordinates.status_code == 422, missing_coordinates.text
    _configure_home_base(client, auth)

    policy_status = client.get(
        "/api/timesheet/home-base/status",
        headers=employee_auth,
    )
    assert policy_status.status_code == 200, policy_status.text
    policy_body = policy_status.json()
    assert policy_body == {
        "success": True,
        "required": False,
        "homeBase": None,
    }

    # Morning Crew membership no longer creates a standing paid-time blocker.
    # Away-from-office time actions use the normal GPS/override path unless the
    # worker is actually inside the configured Home Base geofence.
    away_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "location": "Legacy entry",
            "latitude": 0,
            "longitude": 0,
            "gpsOverrideReason": "test legacy compatibility",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert away_start.status_code == 200, away_start.text
    assert "homeBaseEvent" not in away_start.json()
    away_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": 0,
            "longitude": 0,
            "gpsOverrideReason": "test legacy compatibility",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert away_end.status_code == 200, away_end.text

    gps_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert gps_start.status_code == 200, gps_start.text
    gps_shift_id = int(gps_start.json()["entry"]["id"])
    assert gps_start.json()["entry"]["location"] == "Home Base — EOM Office Home Base"
    assert gps_start.json()["homeBaseEvent"]["outcome"] == "recorded"
    open_home_base_status = client.get(
        "/api/timesheet/home-base/status",
        headers=employee_auth,
    )
    assert open_home_base_status.status_code == 200, open_home_base_status.text
    assert open_home_base_status.json()["required"] is True
    assert open_home_base_status.json()["homeBase"]["label"] == "EOM Office Home Base"
    gps_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert gps_end.status_code == 200, gps_end.text
    assert gps_end.json()["homeBaseEvent"]["action"] == "end"
    assert gps_end.json()["homeBaseEvent"]["outcome"] == "recorded"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE shift_id = %s",
        (gps_shift_id,),
    ) == {"count": 2}
    closed_home_base_status = client.get(
        "/api/timesheet/home-base/status",
        headers=employee_auth,
    )
    assert closed_home_base_status.status_code == 200, closed_home_base_status.text
    assert closed_home_base_status.json()["required"] is False

    qr = client.post(
        "/api/admin/home-base/check-in-qr",
        headers=auth,
        json={},
    )
    assert qr.status_code == 200, qr.text
    token = qr.json()["token"]
    start_payload = {
        "token": token,
        "action": "start",
        "latitude": BASE_LATITUDE,
        "longitude": BASE_LONGITUDE,
        "accuracy": 5,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "idempotencyKey": str(uuid4()),
    }
    started = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json=start_payload,
    )
    assert started.status_code == 200, started.text
    shift_id = int(started.json()["entry"]["id"])
    assert started.json()["homeBaseEvent"]["outcome"] == "recorded"

    stored_shift = db.query_one(
        "SELECT location_id, location_label FROM shifts WHERE id = %s", (shift_id,)
    )
    assert stored_shift == {"location_id": None, "location_label": "Home Base — EOM Office Home Base"}

    ended = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={**start_payload, "action": "end", "idempotencyKey": str(uuid4())},
    )
    assert ended.status_code == 200, ended.text
    assert ended.json()["homeBaseEvent"]["action"] == "end"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE shift_id = %s", (shift_id,)
    ) == {"count": 2}

    # A missed base scan does not silently pass: it is a paid dispatch shift
    # with a durable, reviewable exception at both boundaries.
    exception_start = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "homeBaseExceptionReason": "Office was inaccessible",
            "latitude": 0,
            "longitude": 0,
            "accuracy": 5,
            "gpsOverrideReason": "test Home Base exception",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert exception_start.status_code == 200, exception_start.text
    exception_shift_id = int(exception_start.json()["entry"]["id"])
    assert exception_start.json()["entry"]["location"] == "Dispatch exception"
    assert exception_start.json()["homeBaseEvent"]["outcome"] == "exception"

    # The initial exception stays internal after a later customer arrival; the
    # shift row must not be auto-linked to that first Site.
    exception_site_id = _insert_site(
        "Exception Follow-on Residential",
        location_type="Residential",
        latitude=39.35000,
        longitude=-88.75000,
    )
    exception_planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=exception_site_id,
        suffix="exception-follow-on-residential",
    )
    exception_arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": exception_site_id,
            "plannedVisitId": exception_planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.35000,
            "longitude": -88.75000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert exception_arrival.status_code == 200, exception_arrival.text
    assert db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s", (exception_shift_id,)
    ) == {"location_id": None}
    exception_depart = client.post(
        "/api/timesheet/depart",
        headers=employee_auth,
        json={"latitude": 39.35000, "longitude": -88.75000, "accuracy": 5},
    )
    assert exception_depart.status_code == 200, exception_depart.text

    exception_end = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "homeBaseExceptionReason": "Office was inaccessible",
            "latitude": 0,
            "longitude": 0,
            "accuracy": 5,
            "gpsOverrideReason": "test Home Base exception",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert exception_end.status_code == 200, exception_end.text
    assert db.query_all(
        "SELECT action, outcome, exception_reason FROM home_base_events WHERE shift_id = %s ORDER BY action",
        (exception_shift_id,),
    ) == [
        {"action": "end", "outcome": "exception", "exception_reason": "Office was inaccessible"},
        {"action": "start", "outcome": "exception", "exception_reason": "Office was inaccessible"},
    ]

    evening_id, evening_auth = _create_employee(client, "Evening")
    assert evening_id != employee_id
    out_of_scope = client.post(
        "/api/timesheet/clock-in",
        headers=evening_auth,
        json={
            "latitude": 0,
            "longitude": 0,
            "accuracy": 5,
            "gpsOverrideReason": "test out of scope",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
        },
    )
    assert out_of_scope.status_code == 200, out_of_scope.text

    # The old membership presentation endpoint remains non-blocking even after
    # the crew assignment is retired; Home Base evidence is derived from GPS or
    # an explicit exception on the paid-time action itself.
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE crew_memberships
                SET effective_to = %s
                WHERE employee_id = %s
                """,
                (datetime.now(timezone.utc).astimezone(ZoneInfo("America/Chicago")).date(), employee_id),
            )
    expired_policy = client.get(
        "/api/timesheet/home-base/status",
        headers=employee_auth,
    )
    assert expired_policy.status_code == 200, expired_policy.text
    assert expired_policy.json() == {
        "success": True,
        "required": False,
        "homeBase": None,
    }


def test_gps_confirmed_home_base_clock_out_rejects_active_customer_visit(client, auth):
    employee_id, employee_auth = _create_employee(client, "Home Base active visit")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert started.status_code == 200, started.text
    site_id = _insert_site(
        "Active visit before Home Base end",
        location_type="Residential",
        latitude=39.36000,
        longitude=-88.76000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="active-visit-before-home-base-end",
    )
    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.36000,
            "longitude": -88.76000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text

    refused = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert refused.status_code >= 400, refused.text
    assert "Depart the active customer Site" in refused.text
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 1}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM departures WHERE shift_id = %s",
        (int(started.json()["entry"]["id"]),),
    ) == {"count": 0}

    depart = client.post(
        "/api/timesheet/depart",
        headers=employee_auth,
        json={"latitude": 39.36000, "longitude": -88.76000, "accuracy": 5},
    )
    assert depart.status_code == 200, depart.text
    ended = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert ended.status_code == 200, ended.text
    assert ended.json()["homeBaseEvent"]["action"] == "end"


def test_home_base_status_uses_filtered_open_shift_lookup(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "Home Base status lookup")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    started = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert started.status_code == 200, started.text

    def fail_full_history_load():
        raise AssertionError("home-base status loaded full timesheet history")

    monkeypatch.setattr(
        time_tracker_api,
        "_load_timesheets_from_db",
        fail_full_history_load,
    )
    status = client.get(
        "/api/timesheet/home-base/status",
        headers=employee_auth,
    )

    assert status.status_code == 200, status.text
    body = status.json()
    assert body["required"] is True
    assert body["homeBase"]["label"] == "EOM Office Home Base"


def test_home_base_scan_rejects_uncommitted_stale_payload_before_paid_mutation(client, auth):
    employee_id, employee_auth = _create_employee(client, "Stale scan")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    qr = client.post(
        "/api/admin/home-base/check-in-qr",
        headers=auth,
        json={},
    )
    assert qr.status_code == 200, qr.text

    stale = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={
            "token": qr.json()["token"],
            "action": "start",
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "scannedAt": (
                datetime.now(timezone.utc)
                - timedelta(seconds=time_tracker_api.SITE_CHECK_IN_DEVICE_SKEW_SECONDS + 1)
            ).isoformat(),
            "idempotencyKey": str(uuid4()),
        },
    )
    assert stale.status_code == 409, stale.text
    assert "too old" in stale.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM plain_time_action_receipts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 0}


def test_commercial_qr_arrival_does_not_link_a_home_base_shift_to_customer(client, auth):
    """Customer arrival evidence must not relabel the internal base shift."""
    employee_id, employee_auth = _create_employee(client, "Home Base QR boundary")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)

    home_base_qr = client.post(
        "/api/admin/home-base/check-in-qr",
        headers=auth,
        json={},
    )
    assert home_base_qr.status_code == 200, home_base_qr.text
    started = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={
            "token": home_base_qr.json()["token"],
            "action": "start",
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "idempotencyKey": str(uuid4()),
        },
    )
    assert started.status_code == 200, started.text
    shift_id = int(started.json()["entry"]["id"])

    commercial_site_id = _insert_site(
        "Commercial QR After Home Base",
        location_type="Commercial",
        latitude=BASE_LATITUDE,
        longitude=BASE_LONGITUDE,
    )
    nonce = uuid4().hex
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE locations SET check_in_token_nonce = %s WHERE id = %s",
                (nonce, commercial_site_id),
            )
    site_token = time_tracker_api.build_site_check_in_token(commercial_site_id, nonce)

    resolved = client.post(
        "/api/timesheet/site-check-in/resolve",
        headers=employee_auth,
        json={"token": site_token},
    )
    assert resolved.status_code == 200, resolved.text
    action_state = resolved.json()["actionState"]
    assert action_state["recommendedAction"] == "arrive"

    arrived = client.post(
        "/api/timesheet/site-check-in",
        headers=employee_auth,
        json={
            "employeeId": employee_id,
            "siteId": commercial_site_id,
            "token": site_token,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "action": "arrive",
            "actionStateToken": action_state["stateToken"],
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrived.status_code == 200, arrived.text
    assert arrived.json()["visit"]["location"] == (
        f"{TEST_PREFIX} Commercial QR After Home Base"
    )
    assert db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s", (shift_id,)
    ) == {"location_id": None}


def test_residential_selection_persists_the_chosen_scheduled_site_not_nearest(client):
    employee_id, employee_auth = _create_employee(client, "Residential")
    scheduled_site_id = _insert_site(
        "Scheduled Residential",
        location_type="Residential",
        latitude=39.00000,
        longitude=-88.00000,
    )
    nearer_site_id = _insert_site(
        "Nearby Residential",
        location_type="Residential",
        latitude=39.00010,
        longitude=-88.00000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=scheduled_site_id,
        suffix="scheduled-residential",
    )
    _clock_in(client, employee_auth)

    candidates = client.post(
        "/api/timesheet/visit-candidates",
        headers=employee_auth,
        json={"latitude": 39.00009, "longitude": -88.00000, "accuracy": 5},
    )
    assert candidates.status_code == 200, candidates.text
    body = candidates.json()
    assert [row["locationId"] for row in body["scheduledResidential"]] == [scheduled_site_id]
    assert [row["locationId"] for row in body["nearbyResidential"]] == [nearer_site_id]

    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": scheduled_site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.00009,
            "longitude": -88.00000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrived.status_code == 200, arrived.text
    assert arrived.json()["visit"]["locationId"] == scheduled_site_id
    assert arrived.json()["visitEvidence"]["method"] == "residential_gps"
    visit_id = int(arrived.json()["visit"]["id"])
    assert db.query_one(
        "SELECT location_id FROM visits WHERE id = %s", (visit_id,)
    ) == {"location_id": scheduled_site_id}
    assert db.query_one(
        "SELECT location_id, planned_visit_id, evidence_method FROM visit_evidence_events WHERE visit_id = %s",
        (visit_id,),
    ) == {
        "location_id": scheduled_site_id,
        "planned_visit_id": planned_visit_id,
        "evidence_method": "residential_gps",
    }
    _depart_and_clock_out(
        client,
        employee_auth,
        latitude=39.00009,
        longitude=-88.00000,
    )


@pytest.mark.parametrize(
    "race",
    [
        "planned_visit_cancelled",
        "assignment_retired",
        "site_deactivated",
        "service_window_moved",
    ],
)
def test_explicit_visit_revalidates_eligibility_inside_the_persistence_transaction(
    client,
    monkeypatch,
    race,
):
    employee_id, employee_auth = _create_employee(client, f"Eligibility race {race}")
    site_id = _insert_site(
        f"Eligibility race {race}",
        location_type="Residential",
        latitude=39.45000,
        longitude=-88.85000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix=f"eligibility-race-{race}",
    )
    shift_id = _clock_in(client, employee_auth)
    original_resolver = time_tracker_api._resolve_explicit_visit_site

    def resolve_and_change_eligibility(*args, **kwargs):
        if kwargs.get("cur") is not None:
            if race == "planned_visit_cancelled":
                db.execute(
                    """
                    UPDATE planned_service_visits
                    SET status = 'cancelled', cancelled_at = NOW()
                    WHERE id = %s
                    """,
                    (planned_visit_id,),
                )
            elif race == "assignment_retired":
                db.execute(
                    """
                    UPDATE planned_visit_assignments
                    SET active = false, retired_at = NOW()
                    WHERE planned_visit_id = %s AND active = true
                    """,
                    (planned_visit_id,),
                )
            elif race == "site_deactivated":
                db.execute(
                    "UPDATE locations SET active = false WHERE id = %s",
                    (site_id,),
                )
            else:
                now = datetime.now(timezone.utc)
                db.execute(
                    """
                    UPDATE planned_service_visits
                    SET approximate_start = %s, approximate_end = %s
                    WHERE id = %s
                    """,
                    (now + timedelta(days=2), now + timedelta(days=2, hours=1), planned_visit_id),
                )
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(
        time_tracker_api,
        "_resolve_explicit_visit_site",
        resolve_and_change_eligibility,
    )
    rejected = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.45000,
            "longitude": -88.85000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert rejected.status_code == 409, rejected.text
    assert "changed before this arrival" in rejected.json()["error"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visits WHERE shift_id = %s",
        (shift_id,),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visit_evidence_events WHERE shift_id = %s",
        (shift_id,),
    ) == {"count": 0}


def test_crew_planned_visit_locks_effective_membership_through_commit(
    client,
    monkeypatch,
):
    """A crew replacement cannot retire membership during an arrival commit."""
    employee_id, employee_auth = _create_employee(client, "Crew membership lock")
    crew_id = _enroll_in_morning_crew(employee_id)
    site_id = _insert_site(
        "Crew membership lock",
        location_type="Residential",
        latitude=39.45000,
        longitude=-88.85000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="crew-membership-lock",
        crew_id=crew_id,
    )
    _clock_in(client, employee_auth)
    original_eligible = time_tracker_api._eligible_planned_visit
    retirement_blocked = False

    def eligible_then_try_retirement(*args, **kwargs):
        nonlocal retirement_blocked
        matched = original_eligible(*args, **kwargs)
        if kwargs.get("cur") is not None:
            assert matched is not None
            competing_conn = _raw_conn()
            try:
                with competing_conn.cursor() as competing_cur:
                    competing_cur.execute("SET LOCAL lock_timeout = '100ms'")
                    with pytest.raises(psycopg2.errors.LockNotAvailable):
                        competing_cur.execute(
                            """
                            UPDATE crew_memberships
                            SET effective_to = %s
                            WHERE crew_id = %s
                              AND employee_id = %s
                              AND effective_to IS NULL
                            """,
                            (date.today(), crew_id, employee_id),
                        )
                retirement_blocked = True
            finally:
                competing_conn.rollback()
                competing_conn.close()
        return matched

    monkeypatch.setattr(
        time_tracker_api,
        "_eligible_planned_visit",
        eligible_then_try_retirement,
    )
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.45000,
            "longitude": -88.85000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert retirement_blocked, "the test never reached the locked eligibility read"
    assert arrived.status_code == 200, arrived.text
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visit_evidence_events WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 1}

    # The lock is transactional, not a permanent reservation: membership
    # maintenance proceeds normally once the arrival transaction commits.
    db.execute(
        """
        UPDATE crew_memberships
        SET effective_to = %s
        WHERE crew_id = %s
          AND employee_id = %s
          AND effective_to IS NULL
        """,
        (date.today(), crew_id, employee_id),
    )


def test_explicit_visit_persists_the_geofence_validated_at_commit(
    client,
    monkeypatch,
):
    """The response, visit row, and evidence row must agree after a pin move."""
    employee_id, employee_auth = _create_employee(client, "Commit-time geofence")
    site_id = _insert_site(
        "Commit-time geofence",
        location_type="Residential",
        latitude=39.45000,
        longitude=-88.85000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="commit-time-geofence",
    )
    shift_id = _clock_in(client, employee_auth)
    original_save = time_tracker_api._save_timesheets_to_db
    moved_latitude = 39.45020
    moved_address = f"{TEST_PREFIX} Commit-time renamed Site"
    moved_customer = f"{TEST_PREFIX} Commit-time renamed Customer"
    moved = False

    def save_after_site_move(*args, **kwargs):
        nonlocal moved
        if not moved:
            moved = True
            # The Site changes after preflight but before the save transaction
            # inserts its visit row.  Once that row exists, PostgreSQL's FK lock
            # rightly serializes a Site identity change behind the arrival.
            db.execute(
                """
                UPDATE locations
                SET address = %s, customer_name = %s, lat = %s
                WHERE id = %s
                """,
                (moved_address, moved_customer, moved_latitude, site_id),
            )
        return original_save(*args, **kwargs)

    monkeypatch.setattr(
        time_tracker_api,
        "_save_timesheets_to_db",
        save_after_site_move,
    )
    payload = {
        "locationId": site_id,
        "plannedVisitId": planned_visit_id,
        "evidenceMethod": "residential_gps",
        "latitude": 39.45000,
        "longitude": -88.85000,
        "accuracy": 5,
        "idempotencyKey": str(uuid4()),
    }
    arrived = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json=payload,
    )
    assert moved, "the test never changed the Site between preflight and commit"
    assert arrived.status_code == 200, arrived.text
    visit = arrived.json()["visit"]
    expected_geofence = time_tracker_api.evaluate_site_check_in_geofence(
        site_latitude=moved_latitude,
        site_longitude=-88.85000,
        latitude=payload["latitude"],
        longitude=payload["longitude"],
        accuracy=payload["accuracy"],
    )
    assert visit["gpsMeta"]["distanceM"] == expected_geofence["distanceM"]
    assert visit["gpsMeta"]["withinRadius"] is True
    assert visit["gpsMeta"]["matchedLocation"] == moved_address
    assert visit["location"] == moved_address
    assert visit["customer"] == moved_customer

    visit_id = int(visit["id"])
    stored = db.query_one(
        """
        SELECT location_label, customer_name, gps_meta
        FROM visits WHERE id = %s
        """,
        (visit_id,),
    )
    assert stored is not None
    assert stored["location_label"] == moved_address
    assert stored["customer_name"] == moved_customer
    stored_meta = stored["gps_meta"]
    if isinstance(stored_meta, str):
        stored_meta = json.loads(stored_meta)
    assert stored_meta == visit["gpsMeta"]
    event = db.query_one(
        """
        SELECT geofence_status, distance_m, accuracy_m
        FROM visit_evidence_events
        WHERE visit_id = %s AND shift_id = %s
        """,
        (visit_id, shift_id),
    )
    assert event is not None
    assert event["geofence_status"] == expected_geofence["status"]
    assert float(event["distance_m"]) == expected_geofence["distanceM"]
    assert float(event["accuracy_m"]) == expected_geofence["accuracyM"]

    replay = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json=payload,
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["visit"]["gpsMeta"] == visit["gpsMeta"]
    assert replay.json()["visit"]["location"] == moved_address
    assert replay.json()["visit"]["customer"] == moved_customer


def test_residential_candidates_require_direct_assignment_or_effective_morning_crew(client):
    employee_id, employee_auth = _create_employee(client, "Residential crew scope")
    morning_crew_id = _enroll_in_morning_crew(employee_id)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO crews (name, active) VALUES (%s, true) RETURNING id",
                (f"{TEST_PREFIX} Evening Crew",),
            )
            evening_crew_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO crew_memberships (crew_id, employee_id, effective_from)
                VALUES (%s, %s, %s)
                """,
                (evening_crew_id, employee_id, date(2000, 1, 1)),
            )

    evening_residential_id = _insert_site(
        "Evening Crew Residential",
        location_type="Residential",
        latitude=39.40000,
        longitude=-88.80000,
    )
    direct_residential_id = _insert_site(
        "Direct Residential",
        location_type="Residential",
        latitude=39.40010,
        longitude=-88.80000,
    )
    morning_residential_id = _insert_site(
        "Morning Crew Residential",
        location_type="Residential",
        latitude=39.40020,
        longitude=-88.80000,
    )
    _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=evening_residential_id,
        suffix="evening-crew-residential",
        crew_id=evening_crew_id,
    )
    _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=direct_residential_id,
        suffix="direct-residential",
    )
    _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=morning_residential_id,
        suffix="morning-crew-residential",
        crew_id=morning_crew_id,
    )

    candidates = client.post(
        "/api/timesheet/visit-candidates",
        headers=employee_auth,
        json={"latitude": 39.40005, "longitude": -88.80000, "accuracy": 5},
    )
    assert candidates.status_code == 200, candidates.text
    assert {row["locationId"] for row in candidates.json()["scheduledResidential"]} == {
        direct_residential_id,
        morning_residential_id,
    }


def test_commercial_fallback_and_unplanned_residential_are_reasoned_audit_paths(client):
    employee_id, employee_auth = _create_employee(client, "Exceptions")
    commercial_site_id = _insert_site(
        "Scheduled Commercial",
        location_type="Commercial",
        latitude=39.30000,
        longitude=-88.70000,
    )
    commercial_planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=commercial_site_id,
        suffix="scheduled-commercial",
    )
    unplanned_site_id = _insert_site(
        "Unplanned Residential",
        location_type="Residential",
        latitude=39.30005,
        longitude=-88.70000,
    )
    _clock_in(client, employee_auth)

    malformed = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": commercial_site_id,
            "plannedVisitId": commercial_planned_visit_id,
            "evidenceMethod": "commercial_qr_fallback",
            "exceptionReason": "unplanned_visit",
            "exceptionDetail": "QR was damaged",
            "latitude": 39.30000,
            "longitude": -88.70000,
            "accuracy": 5,
        },
    )
    assert malformed.status_code == 422, malformed.text

    fallback = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": commercial_site_id,
            "plannedVisitId": commercial_planned_visit_id,
            "evidenceMethod": "commercial_qr_fallback",
            "exceptionReason": "qr_unavailable",
            "exceptionDetail": "Printed QR was damaged",
            "latitude": 39.30000,
            "longitude": -88.70000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert fallback.status_code == 200, fallback.text
    assert fallback.json()["visit"]["locationId"] == commercial_site_id
    assert isinstance(fallback.json()["visitEvidence"]["id"], int)
    assert fallback.json()["visitEvidence"]["method"] == "commercial_qr_fallback"
    assert fallback.json()["visitEvidence"]["exceptionReason"] == "qr_unavailable"
    _depart_and_clock_out(
        client,
        employee_auth,
        latitude=39.30000,
        longitude=-88.70000,
    )

    _clock_in(client, employee_auth)
    unplanned = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": unplanned_site_id,
            "evidenceMethod": "unplanned_residential",
            "exceptionReason": "unplanned_visit",
            "exceptionDetail": "Customer requested an extra visit",
            "latitude": 39.30005,
            "longitude": -88.70000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert unplanned.status_code == 200, unplanned.text
    assert unplanned.json()["visit"]["locationId"] == unplanned_site_id
    assert unplanned.json()["visitEvidence"]["method"] == "unplanned_residential"
    _depart_and_clock_out(
        client,
        employee_auth,
        latitude=39.30005,
        longitude=-88.70000,
    )

    unpinned_site_id = _insert_site(
        "Unplanned Residential Without Pin",
        location_type="Residential",
        latitude=None,
        longitude=None,
    )
    _clock_in(client, employee_auth)
    unpinned = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": unpinned_site_id,
            "evidenceMethod": "unplanned_residential",
            "exceptionReason": "unplanned_visit",
            "exceptionDetail": "Customer requested an extra visit",
            "latitude": 39.30005,
            "longitude": -88.70000,
            "accuracy": 5,
            "gpsOverrideReason": "Test an unpinned exception",
            "gpsOverrideDetail": "This override must not make an unpinned Site eligible.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert unpinned.status_code == 400, unpinned.text
    assert "pinned Residential Site" in unpinned.text
    clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={"latitude": 39.30005, "longitude": -88.70000, "accuracy": 5},
    )
    assert clock_out.status_code == 200, clock_out.text

    # The exception set is physically bounded, too: an override cannot make a
    # selected but distant Residential Site into an unplanned customer visit.
    _clock_in(client, employee_auth)
    outside_unplanned = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": unplanned_site_id,
            "evidenceMethod": "unplanned_residential",
            "exceptionReason": "unplanned_visit",
            "exceptionDetail": "Customer requested an extra visit",
            "latitude": 39.90000,
            "longitude": -88.10000,
            "accuracy": 5,
            "gpsOverrideReason": "GPS signal was delayed",
            "gpsOverrideDetail": "This must not expand the unplanned Site set.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert outside_unplanned.status_code == 400, outside_unplanned.text
    assert "require GPS confirmation" in outside_unplanned.text
    final_clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": 39.30005,
            "longitude": -88.70000,
            "accuracy": 5,
        },
    )
    assert final_clock_out.status_code == 200, final_clock_out.text


def test_commercial_fallback_requires_the_current_service_window(client, monkeypatch):
    _, employee_auth = _create_employee(client, "Commercial window")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scheduled_start = now + timedelta(
        hours=time_tracker_api.SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS + 1
    )
    scheduled = {
        "planned_visit_id": 8801,
        "location_id": 7701,
        "job_id": 6601,
        "approximate_start": scheduled_start,
        "approximate_end": scheduled_start + timedelta(hours=1),
        "address": "Future Commercial Site",
        "customer_name": "Future Commercial Customer",
        "location_type": "Commercial",
        "lat": 39.30000,
        "lng": -88.70000,
    }
    monkeypatch.setattr(
        time_tracker_api,
        "_scheduled_visit_candidates_for_employee",
        lambda *_args, **_kwargs: [scheduled],
    )

    candidates = client.post(
        "/api/timesheet/visit-candidates",
        headers=employee_auth,
        json={"latitude": 39.30000, "longitude": -88.70000, "accuracy": 5},
    )
    assert candidates.status_code == 200, candidates.text
    assert candidates.json()["scheduledCommercial"] == []

    fallback = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": scheduled["location_id"],
            "plannedVisitId": scheduled["planned_visit_id"],
            "evidenceMethod": "commercial_qr_fallback",
            "exceptionReason": "qr_unavailable",
            "exceptionDetail": "Printed QR was damaged",
            "latitude": 39.30000,
            "longitude": -88.70000,
            "accuracy": 5,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert fallback.status_code == 400, fallback.text
    assert "not scheduled near this time" in fallback.text


def test_home_base_windows_are_reported_as_dispatch_overhead_not_customer_labor():
    start = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    arrival = start + timedelta(minutes=30)
    departure = start + timedelta(minutes=90)
    end = start + timedelta(hours=2)
    segments = operations_schedule._closed_shift_segments(
        {
            "id": 991,
            "employee_id": 44,
            "employee_name": "Dispatch Test",
            "hourly_rate": 18.25,
            "payroll_break_minutes": 0,
            "location_id": None,
            "location_label": "Home Base — EOM Office Home Base",
            "job_id": None,
            "clock_in": start,
            "clock_out": end,
        },
        [
            {
                "id": 881,
                "location_id": 77,
                "location_label": "Customer Site",
                "arrival_time": arrival,
                "sequence_version": 2,
            }
        ],
        [
            {
                "id": 882,
                "visit_id": 881,
                "location_id": 77,
                "departure_time": departure,
            }
        ],
        {},
        start,
        end,
        [
            {"action": "start", "outcome": "recorded"},
            {"action": "end", "outcome": "recorded"},
        ],
    )
    dispatch = [segment for segment in segments if segment.get("dispatch_overhead")]
    customer = [segment for segment in segments if not segment.get("dispatch_overhead")]
    assert [(row["start"], row["end"], row["location_id"]) for row in dispatch] == [
        (start, arrival, None),
        (departure, end, None),
    ]
    assert [(row["start"], row["end"], row["location_id"]) for row in customer] == [
        (arrival, departure, 77)
    ]


def test_home_base_window_preserves_customer_time_after_corrected_clock_in():
    corrected_clock_in = datetime(2026, 8, 11, 13, 30, tzinfo=timezone.utc)
    recorded_arrival = corrected_clock_in - timedelta(minutes=30)
    departure = corrected_clock_in + timedelta(minutes=60)
    clock_out = corrected_clock_in + timedelta(minutes=90)
    segments = operations_schedule._closed_shift_segments(
        {
            "id": 993,
            "employee_id": 44,
            "employee_name": "Corrected dispatch test",
            "hourly_rate": 18.25,
            "payroll_break_minutes": 0,
            "location_id": None,
            "location_label": "Home Base — EOM Office Home Base",
            "job_id": None,
            "clock_in": corrected_clock_in,
            "clock_out": clock_out,
        },
        [
            {
                "id": 883,
                "location_id": 77,
                "location_label": "Customer Site",
                "arrival_time": recorded_arrival,
                "sequence_version": 2,
            }
        ],
        [
            {
                "id": 884,
                "visit_id": 883,
                "location_id": 77,
                "departure_time": departure,
            }
        ],
        {},
        corrected_clock_in,
        clock_out,
        [
            {"action": "start", "outcome": "recorded"},
            {"action": "end", "outcome": "recorded"},
        ],
    )
    dispatch = [segment for segment in segments if segment.get("dispatch_overhead")]
    customer = [segment for segment in segments if not segment.get("dispatch_overhead")]
    assert [(row["start"], row["end"], row["location_id"]) for row in customer] == [
        (corrected_clock_in, departure, 77)
    ]
    assert [(row["start"], row["end"], row["location_id"]) for row in dispatch] == [
        (departure, clock_out, None)
    ]


def test_home_base_legacy_analytics_stops_customer_time_at_paired_departure():
    """Legacy analytics must not credit the return-to-base interval to a Site."""
    start = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    arrival = start + timedelta(minutes=30)
    departure = start + timedelta(minutes=90)
    end = start + timedelta(hours=2)
    visits = [{"id": 881, "arrivalTime": time_tracker_api.to_utc_iso(arrival), "sequenceVersion": 2}]
    entry = {
        "departures": [
            {
                "visitId": 881,
                "departureTime": time_tracker_api.to_utc_iso(departure),
            }
        ]
    }

    assert time_tracker_api._analytics_visit_end(
        entry,
        visits,
        0,
        end,
        use_paired_departures=True,
    ) == departure
    assert time_tracker_api._analytics_visit_end(
        entry,
        visits,
        0,
        end,
        use_paired_departures=False,
    ) == end


def test_end_only_home_base_evidence_stops_legacy_customer_time_at_paired_departure(monkeypatch):
    import time_tracker_api as api

    clock_in = datetime(2026, 8, 11, 14, tzinfo=timezone.utc)
    arrival = clock_in + timedelta(minutes=30)
    departure = clock_in + timedelta(minutes=90)
    clock_out = clock_in + timedelta(hours=2)
    entry = {
        "id": 992,
        "employeeId": 44,
        "employeeName": "Dispatch Test",
        "clockIn": api.to_utc_iso(clock_in),
        "clockOut": api.to_utc_iso(clock_out),
        "totalHours": 2,
        "location": "Customer Site",
        "timeCategory": "productive",
        "visits": [
            {
                "id": 881,
                "location": "Customer Site",
                "arrivalTime": api.to_utc_iso(arrival),
                "sequenceVersion": 2,
                "jobId": None,
            }
        ],
        "departures": [
            {
                "visitId": 881,
                "departureTime": api.to_utc_iso(departure),
            }
        ],
    }
    monkeypatch.setattr(
        api,
        "load_timesheets",
        lambda: {
            "entries": [entry],
            "location_customers": {"Customer Site": "Customer"},
            "location_rate_types": {},
            "location_expected_hours": {},
        },
    )
    monkeypatch.setattr(
        api,
        "load_employees",
        lambda: {"employees": [{"id": 44, "name": "Dispatch Test", "hourlyRate": 18.25}]},
    )
    monkeypatch.setattr(api, "load_settings", lambda: dict(api._SETTINGS_DEFAULTS))
    monkeypatch.setattr(
        api,
        "_analytics_linked_job_revenue_cents",
        lambda _job_ids: ({}, set(), {}),
    )
    monkeypatch.setattr(api, "_load_shift_rate_snapshots", lambda _shift_ids=None: {})
    monkeypatch.setattr(api, "_home_base_shift_ids", lambda _shift_ids: set())
    monkeypatch.setattr(api, "_home_base_evidence_shift_ids", lambda _shift_ids: {992})

    result = api._compute_analytics("day", "2026-08-11")

    assert result["summary"]["hours"] == 1.0
    assert result["byCustomer"][0]["hours"] == 1.0


def test_home_base_only_shift_never_appears_in_customer_drilldown(monkeypatch):
    """A direct URL cannot turn the internal Home Base label into a customer."""
    import time_tracker_api as api

    now = api.utc_now().replace(microsecond=0)
    clock_in = api.to_utc_iso(now - timedelta(hours=2))
    clock_out = api.to_utc_iso(now - timedelta(hours=1))
    home_base_label = "Home Base — EOM Office Home Base"
    monkeypatch.setattr(
        api,
        "load_timesheets",
        lambda: {
            "entries": [{
                "id": 991,
                "employeeId": 44,
                "employeeName": "Dispatch Test",
                "clockIn": clock_in,
                "clockOut": clock_out,
                "totalHours": 1,
                "location": home_base_label,
                "jobId": None,
                "timeCategory": "productive",
                "visits": [],
            }],
            "location_customers": {},
            "location_rate_types": {},
        },
    )
    monkeypatch.setattr(
        api,
        "load_employees",
        lambda: {"employees": [{"id": 44, "name": "Dispatch Test", "hourlyRate": 18.25}]},
    )
    monkeypatch.setattr(api, "load_settings", lambda: dict(api._SETTINGS_DEFAULTS))
    monkeypatch.setattr(
        api,
        "_analytics_linked_job_revenue_cents",
        lambda _job_ids: ({}, set(), {}),
    )
    monkeypatch.setattr(api, "_load_shift_rate_snapshots", lambda _shift_ids=None: {})
    monkeypatch.setattr(api, "_home_base_shift_ids", lambda _shift_ids: {991})
    monkeypatch.setattr(api, "_home_base_evidence_shift_ids", lambda _shift_ids: {991})

    result = api.admin_analytics_customer(home_base_label, request=None, weeks=1)

    assert result["success"] is True
    assert result["summary"]["visits"] == 0
    assert result["summary"]["hours"] == 0
    assert result["byVisit"] == []


def test_residential_candidate_bounds_are_conservative_and_indexed():
    """The coarse lookup may filter candidates, never valid geofence evidence."""
    edge_distance = float(time_tracker_api.SITE_CHECK_IN_RADIUS_M) * 0.99
    edge_latitude = math.degrees(edge_distance / 6_371_000)
    equator_bounds = time_tracker_api._site_check_in_coordinate_bounds(0, 0, 0)
    assert (
        time_tracker_api.evaluate_site_check_in_geofence(
            site_latitude=edge_latitude,
            site_longitude=0,
            latitude=0,
            longitude=0,
            accuracy=0,
        )["status"]
        == "inside"
    )
    assert equator_bounds[0] <= edge_latitude <= equator_bounds[1]

    latitude_lower, latitude_upper, longitude_lower, longitude_upper, wraps = (
        time_tracker_api._site_check_in_coordinate_bounds(
            39.0,
            179.9999,
            5,
        )
    )

    assert latitude_lower <= 39.0 <= latitude_upper
    assert wraps is True
    assert longitude_lower > longitude_upper
    # This Site is only about 22 m away across the international date line, so
    # the SQL envelope must retain it for the authoritative haversine check.
    assert (
        time_tracker_api.evaluate_site_check_in_geofence(
            site_latitude=39.0,
            site_longitude=-179.9999,
            latitude=39.0,
            longitude=179.9999,
            accuracy=5,
        )["status"]
        == "inside"
    )
    assert -179.9999 <= longitude_upper

    index = db.query_one(
        """
        SELECT indexdef
        FROM pg_indexes
        WHERE schemaname = current_schema()
          AND indexname = 'idx_locations_active_residential_coordinates'
        """
    )
    assert index is not None
    assert "(lat, lng)" in str(index["indexdef"])
    assert "location_type = 'Residential'" in str(index["indexdef"])


def test_customer_label_with_home_base_prefix_still_auto_links_first_visit(client):
    """Presentation text cannot decide whether an ordinary shift is internal."""
    employee_id, _ = _create_employee(client, "Customer prefix auto-link")
    customer_site_id = _insert_site(
        "Customer Prefix Auto-link Site",
        location_type="Residential",
        latitude=39.42,
        longitude=-88.42,
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    entry = {
        "id": -1,
        "employeeId": employee_id,
        "employeeName": f"{TEST_PREFIX} Customer prefix auto-link",
        "location": "Home Base — Customer-facing label",
        "locationId": None,
        "internalHomeBase": False,
        "clockIn": time_tracker_api.to_utc_iso(now),
        "clockOut": time_tracker_api.to_utc_iso(now + timedelta(hours=1)),
        "totalHours": 1,
        "notes": "",
        "date": now.astimezone(ZoneInfo("America/Chicago")).date().isoformat(),
        "timezone": "America/Chicago",
        "clockInGps": None,
        "clockInGpsMeta": None,
        "clockOutGps": None,
        "clockOutGpsMeta": None,
        "jobId": None,
        "timeCategory": "productive",
        "nonProductiveType": None,
        "visits": [
            {
                "locationId": customer_site_id,
                "location": f"{TEST_PREFIX} Customer Prefix Auto-link Site",
                "customer": f"{TEST_PREFIX} Customer Customer Prefix Auto-link Site",
                "arrivalTime": time_tracker_api.to_utc_iso(now + timedelta(minutes=5)),
                "gps": None,
                "gpsMeta": None,
                "sequenceVersion": 2,
                "siteCheckInId": None,
                "jobId": None,
            }
        ],
        "departures": [],
    }

    time_tracker_api._save_timesheets_to_db(
        {"entries": [entry]},
        set(),
        {},
        {},
    )

    assert db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s",
        (entry["id"],),
    ) == {"location_id": customer_site_id}


def test_renamed_legacy_receipt_constraint_is_replaced_by_home_base_vocabulary():
    """Deployments may not retain the original generated CHECK name."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                ALTER TABLE plain_time_action_receipts
                DROP CONSTRAINT plain_time_action_receipts_action_check
                """
            )
            cur.execute(
                """
                ALTER TABLE plain_time_action_receipts
                ADD CONSTRAINT renamed_legacy_receipt_action_check
                CHECK (action IN ('clock-in', 'arrive', 'depart', 'clock-out'))
                """
            )

    time_tracker_api._ensure_home_base_schema()

    constraints = db.query_all(
        """
        SELECT conname, pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conrelid = 'plain_time_action_receipts'::regclass
          AND contype = 'c'
          AND position('action' IN pg_get_constraintdef(oid)) > 0
        ORDER BY conname
        """
    )
    assert [row["conname"] for row in constraints] == [
        "plain_time_action_receipts_action_check"
    ]
    assert "home-base-start" in str(constraints[0]["definition"])
    assert "home-base-end" in str(constraints[0]["definition"])


def test_end_only_home_base_evidence_does_not_make_a_shift_internal(client, auth):
    employee_id, _ = _create_employee(client, "End only evidence")
    _enroll_in_morning_crew(employee_id)
    config = _configure_home_base(client, auth)
    home_base = config["homeBase"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    shift = db.query_one(
        """
        INSERT INTO shifts (
            employee_id, location_label, clock_in, clock_out, total_hours,
            local_date, timezone, time_category
        ) VALUES (%s, %s, %s, %s, 1, %s, 'America/Chicago', 'productive')
        RETURNING id
        """,
        (
            employee_id,
            "Legacy customer shift",
            now - timedelta(hours=1),
            now,
            now.astimezone(ZoneInfo("America/Chicago")).date(),
        ),
    )
    assert shift is not None
    shift_id = int(shift["id"])
    db.execute(
        """
        INSERT INTO home_base_events (
            shift_id, employee_id, home_base_id, home_base_policy_id,
            action, outcome, recorded_at
        ) VALUES (%s, %s, %s, %s, 'end', 'recorded', %s)
        """,
        (
            shift_id,
            employee_id,
            int(home_base["id"]),
            int(home_base["policyId"]),
            now,
        ),
    )

    assert time_tracker_api._home_base_shift_ids([shift_id]) == set()
    assert time_tracker_api._home_base_evidence_shift_ids([shift_id]) == {shift_id}
    loaded_entry = next(
        entry
        for entry in time_tracker_api._load_timesheets_from_db()["entries"]
        if int(entry["id"]) == shift_id
    )
    assert loaded_entry["internalHomeBase"] is False

    unclassified = operations_schedule._closed_shift_segments(
        {
            "id": shift_id,
            "employee_id": employee_id,
            "employee_name": "End only evidence",
            "hourly_rate": 18.25,
            "location_id": 44,
            "location_label": "Legacy customer shift",
            "clock_in": now - timedelta(hours=1),
            "clock_out": now,
        },
        [],
        [],
        {},
        now - timedelta(hours=1),
        now,
        [{"action": "end", "outcome": "recorded"}],
    )
    assert not any(segment.get("dispatch_overhead") for segment in unclassified)

    db.execute(
        """
        INSERT INTO home_base_events (
            shift_id, employee_id, home_base_id, home_base_policy_id,
            action, outcome, recorded_at
        ) VALUES (%s, %s, %s, %s, 'start', 'recorded', %s)
        """,
        (
            shift_id,
            employee_id,
            int(home_base["id"]),
            int(home_base["policyId"]),
            now - timedelta(hours=1),
        ),
    )
    assert time_tracker_api._home_base_shift_ids([shift_id]) == {shift_id}


def test_open_home_base_presence_requires_a_start_event():
    started_at = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    observed_at = started_at + timedelta(hours=1)
    presence = operations_schedule._open_shift_presence(
        {
            "id": 91,
            "employee_id": 22,
            "employee_name": "Open dispatch",
            "hourly_rate": 18.25,
            "location_id": None,
            "location_label": "",
            "job_id": None,
            "clock_in": started_at,
        },
        [],
        [],
        {},
        observed_at,
    )

    end_only = operations_schedule._apply_open_home_base_dispatch_overhead(
        dict(presence),
        [{"action": "end", "outcome": "recorded"}],
    )
    assert end_only.get("dispatch_overhead") is not True
    assert end_only["unassigned_gap"] is True

    with_start = operations_schedule._apply_open_home_base_dispatch_overhead(
        dict(presence),
        [{"action": "start", "outcome": "recorded"}],
    )
    assert with_start["dispatch_overhead"] is True
    assert with_start["location_label"] == "Dispatch overhead"
    assert with_start["unassigned_gap"] is False


def test_dispatch_segments_receive_reverse_break_deduction_before_customer_time(monkeypatch):
    """A corrected break consumes paid dispatch before customer labor."""
    start = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    arrival = start + timedelta(minutes=30)
    departure = start + timedelta(minutes=90)
    end = start + timedelta(hours=2)
    job = {
        "id": 701,
        "location_id": 77,
        "customer_id": 3,
        "display_customer": "Customer",
        "site_address": "Customer Site",
        "site_type": "Residential",
        "scheduled_date": date(2026, 8, 11),
        "scheduled_start": arrival,
        "scheduled_end": departure,
        "source_role": "residential_morning",
        "source_title": "Customer work",
        "status": "scheduled",
        "site_expected_hours": 1,
        "rate": 100,
        "rate_type": "per_visit",
        "site_active": True,
        "source_all_day": False,
    }
    shift = {
        "id": 700,
        "employee_id": 22,
        "employee_name": "Break allocation",
        "hourly_rate": 18.25,
        "location_id": None,
        "location_label": "Home Base — EOM Office Home Base",
        "job_id": None,
        "clock_in": start,
        "clock_out": end,
        "payroll_break_minutes": 30,
    }
    monkeypatch.setattr(
        operations_schedule,
        "_load_time_evidence",
        lambda *_args, **_kwargs: (
            [shift],
            {
                700: [
                    {
                        "id": 881,
                        "location_id": 77,
                        "location_label": "Customer Site",
                        "arrival_time": arrival,
                        "sequence_version": 2,
                    }
                ]
            },
            {
                700: [
                    {
                        "id": 882,
                        "visit_id": 881,
                        "location_id": 77,
                        "departure_time": departure,
                    }
                ]
            },
            {},
            [],
            {
                700: [
                    {"action": "start", "outcome": "recorded"},
                    {"action": "end", "outcome": "recorded"},
                ]
            },
        ),
    )
    monkeypatch.setattr(
        operations_schedule,
        "_load_linked_job_metadata",
        lambda *_args, **_kwargs: {},
    )

    jobs, unmatched, _rates = operations_schedule._decorate_schedule_jobs(
        [job],
        start,
        end,
        end + timedelta(minutes=1),
        ZoneInfo("America/Chicago"),
        visible_range_start=start,
        visible_range_end=end,
    )

    assert jobs[0]["actualHours"] == 1.0
    assert [
        (segment["reason"], segment["hours"])
        for segment in unmatched
    ] == [
        ("dispatch_overhead", 0.5),
    ]


def test_version_two_analytics_without_a_paired_departure_stops_at_arrival():
    start = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    arrival = start + timedelta(minutes=30)
    next_arrival = start + timedelta(minutes=90)
    end = start + timedelta(hours=2)
    visits = [
        {
            "id": 881,
            "arrivalTime": time_tracker_api.to_utc_iso(arrival),
            "sequenceVersion": 2,
        },
        {
            "id": 882,
            "arrivalTime": time_tracker_api.to_utc_iso(next_arrival),
            "sequenceVersion": 2,
        },
    ]

    assert time_tracker_api._analytics_visit_end(
        {"departures": []},
        visits,
        0,
        end,
        use_paired_departures=True,
    ) == arrival
    assert time_tracker_api._analytics_visit_end(
        {"departures": []},
        visits,
        0,
        end,
        use_paired_departures=False,
    ) == next_arrival


def test_home_base_retry_replays_after_qr_rotation_and_later_skew(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "QR rotation replay")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    qr = client.post(
        "/api/admin/home-base/check-in-qr",
        headers=auth,
        json={},
    )
    assert qr.status_code == 200, qr.text
    payload = {
        "token": qr.json()["token"],
        "action": "start",
        "latitude": BASE_LATITUDE,
        "longitude": BASE_LONGITUDE,
        "accuracy": 5,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "idempotencyKey": str(uuid4()),
    }
    recorded = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json=payload,
    )
    assert recorded.status_code == 200, recorded.text

    rotated = client.post(
        "/api/admin/home-base/check-in-qr",
        headers=auth,
        json={"rotate": True},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["token"] != payload["token"]

    # The original request has become stale by server time, but the durable
    # receipt still wins before timestamp validation so a lost response remains
    # safe to retry exactly once.
    replay_time = datetime.now(timezone.utc) + timedelta(
        seconds=time_tracker_api.SITE_CHECK_IN_DEVICE_SKEW_SECONDS + 1
    )
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: replay_time)
    replay = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json=payload,
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["entry"]["id"] == recorded.json()["entry"]["id"]


def test_dispatch_labor_cost_is_separate_in_weekly_profitability(monkeypatch):
    week_start = date(2026, 8, 9)
    start = datetime(2026, 8, 11, 14, tzinfo=timezone.utc)
    end = start + timedelta(hours=2)
    dispatch_segment = {
        "shiftId": 701,
        "employeeId": 22,
        "employeeName": "Dispatch labor",
        "locationId": None,
        "locationLabel": "Dispatch overhead",
        "intervalStart": operations_schedule._utc_iso(start),
        "intervalEnd": operations_schedule._utc_iso(end),
        "hours": 2.0,
        "finalized": True,
        "presenceOnly": False,
        "reason": "dispatch_overhead",
        "dispatchOverhead": True,
        "candidateJobIds": [],
        "evidence": ["home_base_start_recorded"],
    }
    monkeypatch.setattr(operations_schedule, "_load_jobs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        operations_schedule,
        "monthly_revenue_allocations",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        operations_schedule,
        "_load_expected_hours_learning_by_site",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        operations_schedule,
        "_decorate_schedule_jobs",
        lambda *_args, **_kwargs: ([], [dispatch_segment], {701: 1825}),
    )

    result = operations_schedule.build_weekly_labor_profitability(
        week_start,
        now_provider=lambda: end + timedelta(hours=1),
    )

    assert result["summary"]["dispatchOverheadHours"] == 2.0
    assert result["summary"]["dispatchOverheadLaborCost"] == 36.5
    assert result["summary"]["knownDispatchOverheadLaborCost"] == 36.5
    assert result["summary"]["dispatchOverheadLaborCostComplete"] is True
    tuesday = next(row for row in result["byDay"] if row["date"] == "2026-08-11")
    assert tuesday["dispatchOverheadLaborCost"] == 36.5
    assert tuesday["dispatchOverheadLaborCostComplete"] is True


def test_cross_boundary_dispatch_charges_each_day_only_its_visible_cost(monkeypatch):
    """A day must be charged for the hours it shows, not the whole interval.

    This test previously asserted the opposite -- that Sunday carried the full
    $36.50 while displaying 1.0 of the interval's 2.0 hours -- which reads as
    an $36.50/hr day against an $18.25/hr rate. The weekly summary stays
    whole-interval, so byDay can sum to less than it when work crosses the
    range edge; that gap is the out-of-range portion and is real.
    """
    week_start = date(2026, 8, 9)
    start = datetime(2026, 8, 8, 23, tzinfo=timezone.utc)
    end = start + timedelta(hours=2)
    dispatch_segment = {
        "shiftId": 702,
        "employeeId": 22,
        "employeeName": "Cross-boundary dispatch",
        "locationId": None,
        "locationLabel": "Dispatch overhead",
        "intervalStart": operations_schedule._utc_iso(start),
        "intervalEnd": operations_schedule._utc_iso(end),
        "hours": 2.0,
        "finalized": True,
        "presenceOnly": False,
        "reason": "dispatch_overhead",
        "dispatchOverhead": True,
        "candidateJobIds": [],
        "evidence": ["home_base_start_recorded"],
    }
    monkeypatch.setattr(operations_schedule, "_load_jobs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        operations_schedule,
        "monthly_revenue_allocations",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        operations_schedule,
        "_load_expected_hours_learning_by_site",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        operations_schedule,
        "_decorate_schedule_jobs",
        lambda *_args, **_kwargs: ([], [dispatch_segment], {702: 1825}),
    )

    result = operations_schedule.build_weekly_labor_profitability(
        week_start,
        timezone_name="UTC",
        now_provider=lambda: datetime(2026, 8, 10, tzinfo=timezone.utc),
    )

    # The weekly figure is unchanged: the full interval is still two hours at
    # $18.25.
    assert result["summary"]["dispatchOverheadHours"] == 2.0
    assert result["summary"]["dispatchOverheadLaborCost"] == 36.5
    sunday = next(row for row in result["byDay"] if row["date"] == "2026-08-09")
    assert sunday["dispatchOverheadHours"] == 1.0
    # One visible hour at $18.25 -- NOT the full interval's $36.50.
    assert sunday["dispatchOverheadLaborCost"] == 18.25
    assert (
        sunday["dispatchOverheadLaborCost"]
        == round(sunday["dispatchOverheadHours"] * 18.25, 2)
    ), "the day's cost does not correspond to the hours it displays"


def test_gps_override_rationale_survives_into_the_exception_review(client, auth):
    """An outside-geofence residential arrival must show WHY it was accepted.

    Such an arrival reaches the review list by its geofence status, never by
    carrying an exception -- the request shape forbids exceptionReason and
    exceptionDetail for residential_gps, and the ledger CHECK requires them
    empty. So if the GPS override fields are not persisted, the reviewer gets
    a row with a blank rationale, which is the only thing the review is for.
    """
    employee_id, employee_auth = _create_employee(client, "Override rationale")
    site_id = _insert_site(
        "Override rationale",
        location_type="Residential",
        latitude=39.50000,
        longitude=-88.90000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="override-rationale",
    )
    shift_id = _clock_in(client, employee_auth)

    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            # Far enough out that this cannot be accepted on geofence alone.
            "latitude": 39.60000,
            "longitude": -88.90000,
            "accuracy": 5,
            "gpsOverrideReason": "gps_drift",
            "gpsOverrideDetail": "Phone placed distance at the next block over.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text

    stored = db.query_one(
        """
        SELECT gps_override_reason, gps_override_detail, geofence_status
        FROM visit_evidence_events WHERE shift_id = %s
        """,
        (shift_id,),
    )
    assert stored is not None, "no evidence row was written"
    assert stored["geofence_status"] != "inside", (
        "the arrival was inside the geofence, so this test never exercised an override"
    )
    assert stored["gps_override_reason"] == "gps_drift"
    assert "next block over" in stored["gps_override_detail"]

    review = client.get("/api/admin/visit-evidence-exceptions", headers=auth)
    assert review.status_code == 200, review.text
    rows = [r for r in review.json()["exceptions"] if int(r["shiftId"]) == shift_id]
    assert rows, "the outside-geofence arrival never reached the review list"
    row = rows[0]
    # The exception pair is empty by construction for this method -- that is
    # precisely why the override pair has to carry the reason.
    assert row["reason"] == "" and row["detail"] == ""
    assert row["gpsOverrideReason"] == "gps_drift"
    assert "next block over" in row["gpsOverrideDetail"]


def test_exception_review_uses_the_immutable_visit_identity_after_site_changes(client, auth):
    """Site maintenance must not rewrite the identity shown for old evidence."""
    employee_id, employee_auth = _create_employee(client, "Immutable review identity")
    suffix = "Immutable review identity"
    original_address = f"{TEST_PREFIX} {suffix}"
    original_customer = f"{TEST_PREFIX} Customer {suffix}"
    site_id = _insert_site(
        suffix,
        location_type="Residential",
        latitude=39.50000,
        longitude=-88.90000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="immutable-review-identity",
    )
    shift_id = _clock_in(client, employee_auth)

    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.60000,
            "longitude": -88.90000,
            "accuracy": 5,
            "gpsOverrideReason": "gps_drift",
            "gpsOverrideDetail": "Phone placed the worker on the next block.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text
    assert db.query_one(
        """
        SELECT visit.location_label, visit.customer_name
        FROM visit_evidence_events evidence
        JOIN visits visit ON visit.id = evidence.visit_id
        WHERE evidence.shift_id = %s
        """,
        (shift_id,),
    ) == {
        "location_label": original_address,
        "customer_name": original_customer,
    }

    db.execute(
        """
        UPDATE locations
        SET address = %s, customer_name = %s
        WHERE id = %s
        """,
        (
            f"{TEST_PREFIX} Reassigned review address",
            f"{TEST_PREFIX} Reassigned review customer",
            site_id,
        ),
    )

    review = client.get("/api/admin/visit-evidence-exceptions", headers=auth)
    assert review.status_code == 200, review.text
    row = next(
        item for item in review.json()["exceptions"] if int(item["shiftId"]) == shift_id
    )
    assert row["locationId"] == site_id
    assert row["address"] == original_address
    assert row["customerName"] == original_customer


@pytest.mark.parametrize("action", ["clock-in", "clock-out"])
def test_active_home_base_does_not_blanket_block_away_time_actions(
    client, auth, action,
):
    """Home Base GPS evidence is action-scoped, not a Morning Crew day gate."""
    employee_id, employee_auth = _create_employee(client, f"Active base {action}")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    if action == "clock-out":
        _clock_in(client, employee_auth)

    response = client.post(
        f"/api/timesheet/{action}",
        headers=employee_auth,
        json={
            "location": "",
            "latitude": 39.00009,
            "longitude": -88.00000,
            "accuracy": 5,
            "gpsOverrideReason": "test location setup",
            "gpsOverrideDetail": "Race test for Home Base policy activation.",
        },
    )

    assert response.status_code == 200, response.text
    assert "homeBaseEvent" not in response.json()
    if action == "clock-in":
        open_shifts = db.query_one(
            "SELECT COUNT(*) AS count FROM shifts "
            "WHERE employee_id = %s AND clock_out IS NULL",
            (employee_id,),
        )
        assert open_shifts == {"count": 1}


def test_job_totals_include_labor_recorded_only_through_a_visit(client, auth):
    """A Home Base shift's visit to a job must reach that job's totals.

    A Home Base start creates a shift with no job, and a scheduled arrival
    puts the planned job on the visit only -- the shift-side auto-link is
    suppressed for internal Home Base shifts. Deriving job hours solely from
    `shifts.job_id` therefore drops that labor from hours, cost, margin and
    variance without any sign that it is missing.
    """
    employee_id, employee_auth = _create_employee(client, "Visit labor")
    site_id = _insert_site(
        "Visit labor",
        location_type="Residential",
        latitude=39.55000,
        longitude=-88.95000,
    )
    db.execute("UPDATE employees SET hourly_rate = 20 WHERE id = %s", (employee_id,))
    job = db.query_one(
        """
        INSERT INTO jobs (customer_name, scheduled_date, revenue)
        VALUES (%s, CURRENT_DATE, 500) RETURNING id
        """,
        (f"{TEST_PREFIX} visit labor",),
    )
    job_id = int(job["id"])

    shift_id = _clock_in(client, employee_auth)
    # The shift itself is NOT linked to the job; only the visit is.
    db.execute("UPDATE shifts SET job_id = NULL WHERE id = %s", (shift_id,))
    arrival = datetime.now(timezone.utc) - timedelta(hours=2)
    visit = db.query_one(
        """
        INSERT INTO visits (shift_id, location_id, location_label, arrival_time, job_id)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
        """,
        (shift_id, site_id, "Visit labor", arrival, job_id),
    )
    visit_id = int(visit["id"])
    db.execute(
        """
        INSERT INTO departures (shift_id, visit_id, location_id, departure_time)
        VALUES (%s, %s, %s, %s)
        """,
        (shift_id, visit_id, site_id, arrival + timedelta(hours=2)),
    )

    detail = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
    assert detail.status_code == 200, detail.text
    body = detail.json()["job"]

    assert body["totalHours"] == pytest.approx(2.0), (
        "labor recorded through a visit never reached the job totals"
    )
    assert body["totalLaborCost"] == pytest.approx(40.0)
    rows = [r for r in body["shifts"] if r.get("source") == "visit"]
    assert len(rows) == 1 and rows[0]["visitId"] == visit_id

    # The other direction: once the shift itself carries the job, the visit
    # must NOT be counted a second time on top of the whole clock interval.
    db.execute("UPDATE shifts SET job_id = %s WHERE id = %s", (job_id, shift_id))
    again = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
    assert again.status_code == 200, again.text
    regrouped = again.json()["job"]
    assert [r for r in regrouped["shifts"] if r.get("source") == "visit"] == [], (
        "a shift already linked to the job also counted its own visit"
    )


def test_a_token_rotated_after_validation_cannot_still_buy_paid_time(
    client, auth, monkeypatch,
):
    """The scanned nonce must be re-checked under the write lock.

    A fresh Home Base scan validates the token before entering the serialized
    timesheet update, and rotation runs under its own lock in its own
    transaction. A token revoked in that window would otherwise still start a
    paid shift. This path has no committed receipt to replay, so the recheck
    has to happen inside the write.
    """
    employee_id, employee_auth = _create_employee(client, "QR rotation race")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)

    qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
    assert qr.status_code == 200, qr.text
    token = qr.json()["token"]

    original = time_tracker_api._resolve_home_base_qr
    calls = {"n": 0}

    def rotate_between_the_two_checks(*args, **kwargs):
        calls["n"] += 1
        result = original(*args, **kwargs)
        if calls["n"] == 1:
            # Admin rotates immediately after the pre-flight validation.
            rotated = client.post(
                "/api/admin/home-base/check-in-qr",
                headers=auth,
                json={"rotate": True},
            )
            assert rotated.status_code == 200, rotated.text
            assert rotated.json()["token"] != token, "rotation did not change the token"
        return result

    monkeypatch.setattr(
        time_tracker_api, "_resolve_home_base_qr", rotate_between_the_two_checks
    )

    response = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={
            "token": token,
            "action": "start",
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "idempotencyKey": str(uuid4()),
        },
    )

    assert calls["n"] >= 2, (
        "the token was resolved only once, so the write still trusts the "
        "pre-flight validation"
    )
    assert response.status_code >= 400, (
        f"a revoked token started a paid shift: {response.text}"
    )
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}


def test_the_correction_archive_keeps_why_an_override_was_accepted(client, auth):
    """Deleting the shift cascade-deletes the evidence row.

    So the before-image is the only surviving record. For an outside or
    uncertain residential arrival the exception pair is empty by constraint,
    which makes the GPS override fields the entire rationale -- an archive
    without them cannot say why the arrival was ever accepted.
    """
    employee_id, employee_auth = _create_employee(client, "Archive rationale")
    site_id = _insert_site(
        "Archive rationale",
        location_type="Residential",
        latitude=39.65000,
        longitude=-88.75000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="archive-rationale",
    )
    shift_id = _clock_in(client, employee_auth)
    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.75000,
            "longitude": -88.75000,
            "accuracy": 5,
            "gpsOverrideReason": "gps_drift",
            "gpsOverrideDetail": "Signal put the phone two streets away.",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text

    snapshots = time_tracker_api._correction_shift_snapshots([shift_id])
    assert len(snapshots) == 1, snapshots
    before = snapshots[0]
    events = before["visitEvidenceEvents"]
    assert events, "the before-image carried no evidence rows"
    assert events[0]["gpsOverrideReason"] == "gps_drift"
    assert "two streets away" in events[0]["gpsOverrideDetail"]

    # The signature must cover them, or the archive can be altered without
    # detection. It denylists a fixed set of keys, so new fields are included
    # by construction -- this asserts that actually holds.
    signature = time_tracker_api._correction_metadata_signature(before)
    assert "gps_drift" in signature
    assert "two streets away" in signature


def test_a_full_length_override_reason_is_accepted_not_rolled_back(client, auth):
    """The column must fit the request field that feeds it.

    gps_override_reason was sized to the neighbouring exception_reason (64)
    rather than to MAX_GPS_OVERRIDE_REASON_LEN (200), so a rationale the API
    had already validated failed at insertion and rolled back an otherwise
    valid arrival.
    """
    # Check the column itself, not only a round trip. The schema is built once
    # per session, so a test that merely inserts cannot tell a widened column
    # from one that was already widened by an earlier run -- reverting the DDL
    # leaves the live column untouched and the insert still succeeds.
    column = db.query_one(
        """
        SELECT data_type, character_maximum_length
        FROM information_schema.columns
        WHERE table_name = 'visit_evidence_events'
          AND column_name = 'gps_override_reason'
        """
    )
    assert column is not None, "gps_override_reason column is missing"
    assert (
        column["data_type"] == "text"
        or (column["character_maximum_length"] or 0)
        >= time_tracker_api.MAX_GPS_OVERRIDE_REASON_LEN
    ), (
        f"gps_override_reason is {column['data_type']}"
        f"({column['character_maximum_length']}), too narrow for a "
        f"{time_tracker_api.MAX_GPS_OVERRIDE_REASON_LEN}-char request field"
    )

    employee_id, employee_auth = _create_employee(client, "Long reason")
    site_id = _insert_site(
        "Long reason",
        location_type="Residential",
        latitude=39.85000,
        longitude=-88.55000,
    )
    planned_visit_id = _insert_assigned_planned_visit(
        employee_id=employee_id,
        location_id=site_id,
        suffix="long-reason",
    )
    shift_id = _clock_in(client, employee_auth)

    reason = "g" * time_tracker_api.MAX_GPS_OVERRIDE_REASON_LEN
    arrival = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.95000,
            "longitude": -88.55000,
            "accuracy": 5,
            "gpsOverrideReason": reason,
            "gpsOverrideDetail": "d" * 200,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert arrival.status_code == 200, arrival.text
    stored = db.query_one(
        "SELECT gps_override_reason FROM visit_evidence_events WHERE shift_id = %s",
        (shift_id,),
    )
    assert stored["gps_override_reason"] == reason

    # The other side: one character past the request limit is refused by the
    # API, so an oversized value never reaches the insert at all.
    over = client.post(
        "/api/timesheet/visit",
        headers=employee_auth,
        json={
            "locationId": site_id,
            "plannedVisitId": planned_visit_id,
            "evidenceMethod": "residential_gps",
            "latitude": 39.95000,
            "longitude": -88.55000,
            "accuracy": 5,
            "gpsOverrideReason": "g" * (
                time_tracker_api.MAX_GPS_OVERRIDE_REASON_LEN + 1),
            "gpsOverrideDetail": "still too long",
            "idempotencyKey": str(uuid4()),
        },
    )
    assert over.status_code == 422, over.text


def test_moving_home_base_after_the_scan_stops_the_clock_action(
    client, auth, monkeypatch,
):
    """Re-checking the token is not enough -- configuration can MOVE the base.

    Changing the coordinates does not rotate the nonce, so a still-valid token
    can point at a new location. A worker standing where Home Base used to be
    must not still be able to start paid time.
    """
    employee_id, employee_auth = _create_employee(client, "Home base moved")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)

    qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
    assert qr.status_code == 200, qr.text
    token = qr.json()["token"]

    original = time_tracker_api._resolve_home_base_qr
    calls = {"n": 0}

    def move_between_the_two_lookups(*args, **kwargs):
        calls["n"] += 1
        # Resolve FIRST, so the preflight sees the old row and passes its own
        # geofence check. Moving before that would fail preflight and never
        # reach the write -- which is not the race being tested.
        result = original(*args, **kwargs)
        if calls["n"] == 1:
            # Admin relocates Home Base -- same nonce, new coordinates.
            moved = client.put(
                "/api/admin/home-base",
                headers=auth,
                json={
                    "label": "EOM Office Home Base",
                    "address": "999 Somewhere Else, Effingham",
                    "latitude": BASE_LATITUDE + 0.5,
                    "longitude": BASE_LONGITUDE + 0.5,
                },
            )
            assert moved.status_code == 200, moved.text
        return result

    monkeypatch.setattr(
        time_tracker_api, "_resolve_home_base_qr", move_between_the_two_lookups
    )

    response = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={
            "token": token,
            "action": "start",
            # Still standing at the OLD Home Base.
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "idempotencyKey": str(uuid4()),
        },
    )

    assert calls["n"] >= 2, "the token was resolved only once"
    assert response.status_code >= 400, (
        f"a scan at the former Home Base started paid time: {response.text}"
    )
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 0}


def test_open_dispatch_covers_only_the_interval_before_the_first_arrival():
    """After a customer arrival, a no-Site gap is travel, not Home Base time.

    Classifying every departure gap as dispatch while the shift is open is a
    claim that gets silently rewritten once the shift closes: the same gap
    goes unassigned unless an end event proves the return envelope.
    """
    start_events = [{"action": "start", "outcome": "recorded"}]
    presence = {
        "location_id": None,
        "location_label": "",
        "job_id": None,
        "evidence": ["paid_shift"],
        "unassigned_gap": True,
    }

    # Before any arrival: the start scan is durable evidence of dispatch.
    initial = operations_schedule._apply_open_home_base_dispatch_overhead(
        dict(presence), start_events, []
    )
    assert initial["dispatch_overhead"] is True
    assert initial["location_label"] == "Dispatch overhead"

    # After an arrival: the same shape must NOT be claimed as Home Base time.
    after_customer = operations_schedule._apply_open_home_base_dispatch_overhead(
        dict(presence), start_events, [{"id": 1, "arrival_time": datetime.now(timezone.utc)}]
    )
    assert after_customer.get("dispatch_overhead") is not True, (
        "travel between customers was reported as Home Base overhead"
    )
    assert after_customer["unassigned_gap"] is True

    # An active Site is still never overwritten, in either case.
    on_site = operations_schedule._apply_open_home_base_dispatch_overhead(
        {**presence, "location_id": 7}, start_events, []
    )
    assert on_site.get("dispatch_overhead") is not True


def test_utilization_evidence_carries_home_base_events(client, auth):
    """The utilization loader must see what the profitability loader sees.

    A closed Home Base-only shift has no visit claims by design, so without
    this its whole paid envelope is reported `unclassified` -- inflating
    unknown labor even though start/end events prove dispatch work.
    """
    employee_id, employee_auth = _create_employee(client, "Utilization evidence")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
    assert qr.status_code == 200, qr.text
    token = qr.json()["token"]

    scan = {
        "token": token,
        "action": "start",
        "latitude": BASE_LATITUDE,
        "longitude": BASE_LONGITUDE,
        "accuracy": 5,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "idempotencyKey": str(uuid4()),
    }
    started = client.post(
        "/api/timesheet/home-base/scan", headers=employee_auth, json=scan)
    assert started.status_code == 200, started.text
    shift_id = int(started.json()["entry"]["id"])

    # Give the envelope real duration. Both scans land in the same second
    # otherwise, and a zero-length paid interval is correctly rejected as
    # invalid before any classification runs.
    db.execute(
        "UPDATE shifts SET clock_in = clock_in - INTERVAL '2 hours' WHERE id = %s",
        (shift_id,),
    )
    ended = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={**scan, "action": "end", "idempotencyKey": str(uuid4())},
    )
    assert ended.status_code == 200, ended.text
    closed = db.query_one(
        "SELECT clock_in, clock_out FROM shifts WHERE id = %s", (shift_id,))
    assert closed["clock_out"] > closed["clock_in"], "the envelope has no duration"

    now = datetime.now(timezone.utc)
    evidence = operations_schedule._load_utilization_evidence(
        now - timedelta(days=1), now + timedelta(days=1), now)
    assert len(evidence) == 4, (
        "the utilization loader still returns no Home Base evidence")
    assert evidence[3].get(shift_id), (
        "the Home Base events never reached the utilization classifier")

    # Call the ENDPOINT, not just the loader. The first version of this fix
    # reused the profitability overlay, which indexes segment["start"] while
    # utilization segments carry start_second -- so the endpoint raised
    # KeyError for exactly this shift while a loader-only test stayed green.
    report = client.get(
        "/api/admin/operations/utilization",
        headers=auth,
        params={
            "start": (now - timedelta(days=1)).date().isoformat(),
            "end": (now + timedelta(days=1)).date().isoformat(),
        },
    )
    assert report.status_code == 200, report.text
    body = report.json()
    row = next(
        (r for r in body.get("rows", []) if int(r.get("employeeId", 0)) == employee_id),
        None,
    )
    assert row is not None, "the Home Base shift is absent from the utilization report"
    assert (row.get("unclassifiedMinutes") or 0) == 0, (
        f"a proven Home Base envelope was still reported unclassified: {row}"
    )


def test_utilization_classifies_exception_dispatch_windows_without_rewriting_customer_time():
    """Exception evidence uses the same Home Base boundaries as profitability."""
    start = datetime(2026, 8, 11, 13, tzinfo=timezone.utc)
    arrival = start + timedelta(minutes=30)
    departure = start + timedelta(minutes=90)
    end = start + timedelta(hours=2)
    shift = {
        "id": 994,
        "employee_id": 44,
        "employee_name": "Exception dispatch test",
        "clock_in": start,
        "clock_out": end,
        "time_category": "productive",
    }
    segments, review_items = operations_schedule._closed_shift_utilization(
        shift,
        [
            {
                "id": 885,
                "location_id": 77,
                "location_label": "Customer Site",
                "arrival_time": arrival,
                "sequence_version": 2,
                "job_id": 501,
            }
        ],
        [
            {
                "id": 886,
                "visit_id": 885,
                "location_id": 77,
                "departure_time": departure,
            }
        ],
        home_base_events=[
            {"action": "start", "outcome": "exception"},
            {"action": "end", "outcome": "exception"},
        ],
    )

    assert review_items == []
    assert [
        (
            segment["category"],
            segment["category_detail"],
            segment["start_second"],
            segment["end_second"],
            segment["location_id"],
            segment["job_id"],
        )
        for segment in segments
    ] == [
        (
            "categorized",
            "dispatch",
            int(start.timestamp()),
            int(arrival.timestamp()),
            None,
            None,
        ),
        (
            "on_site",
            None,
            int(arrival.timestamp()),
            int(departure.timestamp()),
            77,
            501,
        ),
        (
            "categorized",
            "dispatch",
            int(departure.timestamp()),
            int(end.timestamp()),
            None,
            None,
        ),
    ]
    dispatch_evidence = [
        segment["evidence"]
        for segment in segments
        if segment["category_detail"] == "dispatch"
    ]
    assert dispatch_evidence == [
        ["home_base_start_exception", "paid_shift"],
        ["home_base_end_exception", "paid_shift"],
    ]


def test_moving_home_base_slightly_records_the_new_coordinates(
    client, auth, monkeypatch,
):
    """Acceptance and the audit trail must agree on which configuration.

    When the old and new geofences overlap the action still succeeds -- so the
    only sign of a mid-flight move is the evidence it stores. Persisting the
    preflight geofence would record the OLD distance for an action accepted
    against the NEW coordinates, and nothing downstream would reveal it.
    """
    employee_id, employee_auth = _create_employee(client, "Small move")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
    assert qr.status_code == 200, qr.text
    token = qr.json()["token"]

    moved_label = "EOM Office Home Base Annex"
    original = time_tracker_api._resolve_home_base_qr
    calls = {"n": 0}

    def nudge_after_preflight(*args, **kwargs):
        calls["n"] += 1
        result = original(*args, **kwargs)
        if calls["n"] == 1:
            # Small enough that the worker stays inside the new geofence.
            moved = client.put(
                "/api/admin/home-base",
                headers=auth,
                json={
                    "label": moved_label,
                    "address": "101 Dispatch Lane, Effingham",
                    "latitude": BASE_LATITUDE + 0.0001,
                    "longitude": BASE_LONGITUDE,
                },
            )
            assert moved.status_code == 200, moved.text
        return result

    monkeypatch.setattr(
        time_tracker_api, "_resolve_home_base_qr", nudge_after_preflight)

    response = client.post(
        "/api/timesheet/home-base/scan",
        headers=employee_auth,
        json={
            "token": token,
            "action": "start",
            "latitude": BASE_LATITUDE,
            "longitude": BASE_LONGITUDE,
            "accuracy": 5,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "idempotencyKey": str(uuid4()),
        },
    )
    assert calls["n"] >= 2, "the token was resolved only once"
    assert response.status_code == 200, response.text

    shift_id = int(response.json()["entry"]["id"])
    stored = db.query_one(
        "SELECT clock_in_gps_meta FROM shifts WHERE id = %s", (shift_id,))
    meta = stored["clock_in_gps_meta"]
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta["matchedLocation"] == moved_label, (
        f"the audit trail recorded the pre-move Home Base: {meta}"
    )


@pytest.mark.parametrize("path", ("scan", "exception"))
def test_home_base_start_does_not_require_employee_morning_crew_membership(
    client,
    auth,
    path,
):
    """Home Base starts are proven by office GPS or an exception, not membership."""
    employee_id, employee_auth = _create_employee(client, f"No membership {path}")
    crew_seed_id, _seed_auth = _create_employee(client, f"Crew seed {path}")
    _enroll_in_morning_crew(crew_seed_id)
    _configure_home_base(client, auth)
    if path == "scan":
        qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
        assert qr.status_code == 200, qr.text
        response = client.post(
            "/api/timesheet/home-base/scan",
            headers=employee_auth,
            json={
                "token": qr.json()["token"],
                "action": "start",
                "latitude": BASE_LATITUDE,
                "longitude": BASE_LONGITUDE,
                "accuracy": 5,
                "scannedAt": datetime.now(timezone.utc).isoformat(),
                "idempotencyKey": str(uuid4()),
            },
        )
    else:
        response = client.post(
            "/api/timesheet/clock-in",
            headers=employee_auth,
            json={
                "homeBaseExceptionReason": "Office was inaccessible",
                "latitude": 0,
                "longitude": 0,
                "accuracy": 5,
                "gpsOverrideReason": "test Home Base exception",
                "gpsOverrideDetail": "The office scan race is intentional.",
                "idempotencyKey": str(uuid4()),
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["homeBaseEvent"]["outcome"] == (
        "recorded" if path == "scan" else "exception"
    )
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 1}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 1}


@pytest.mark.parametrize("start_method", ("scan", "exception"))
def test_a_shift_started_with_home_base_evidence_still_owes_its_end_event(
    client, auth, start_method,
):
    """A Home Base-started shift cannot close away without end evidence."""
    employee_id, employee_auth = _create_employee(client, "End evidence owed")
    _enroll_in_morning_crew(employee_id)
    _configure_home_base(client, auth)
    if start_method == "scan":
        qr = client.post("/api/admin/home-base/check-in-qr", headers=auth, json={})
        assert qr.status_code == 200, qr.text
        started = client.post(
            "/api/timesheet/home-base/scan",
            headers=employee_auth,
            json={
                "token": qr.json()["token"],
                "action": "start",
                "latitude": BASE_LATITUDE,
                "longitude": BASE_LONGITUDE,
                "accuracy": 5,
                "scannedAt": datetime.now(timezone.utc).isoformat(),
                "idempotencyKey": str(uuid4()),
            },
        )
    else:
        started = client.post(
            "/api/timesheet/clock-in",
            headers=employee_auth,
            json={
                "homeBaseExceptionReason": "Office was inaccessible",
                "latitude": 0,
                "longitude": 0,
                "accuracy": 5,
                "gpsOverrideReason": "test dispatch exception",
                "gpsOverrideDetail": "The Office scan could not be completed.",
                "idempotencyKey": str(uuid4()),
            },
        )
    assert started.status_code == 200, started.text
    assert started.json()["homeBaseEvent"]["outcome"] == (
        "recorded" if start_method == "scan" else "exception"
    )

    # Everything ELSE about this clock-out must be valid, or the assertion
    # below passes on an unrelated refusal. Without the override reason the
    # GPS check rejects it first and the Home Base guard is never reached --
    # which is exactly how the first version of this test passed against the
    # unfixed code.
    refused = client.post(
        "/api/timesheet/clock-out",
        headers=employee_auth,
        json={
            "latitude": 0,
            "longitude": 0,
            "accuracy": 5,
            "gpsOverrideReason": "test teardown",
            "gpsOverrideDetail": "Ending the shift away from a saved site.",
        },
    )
    assert refused.status_code >= 400, (
        f"the shift closed with no Home Base end event: {refused.text}"
    )
    body = refused.json()
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else body
    assert str(detail.get("code") or body.get("code")) == "HOME_BASE_REQUIRED", (
        f"refused, but not by the Home Base guard: {refused.text}"
    )
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts "
        "WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    ) == {"count": 1}, "the shift was closed despite owing an end event"
