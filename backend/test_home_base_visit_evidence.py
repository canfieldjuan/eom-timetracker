"""Contract tests for internal Home Base and explicit customer-visit evidence."""

from __future__ import annotations

import bcrypt
import hashlib
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
        "required": True,
        "homeBase": {
            "id": policy_body["homeBase"]["id"],
            "label": "EOM Office Home Base",
            "address": "100 Dispatch Lane, Effingham",
            "crewName": "Morning Crew",
        },
    }

    # The policy is enforced by the server, not an opt-in browser field.  This
    # remains true if an old/cached portal never fetched Home Base status.
    blocked = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "location": "Legacy entry",
            "latitude": 0,
            "longitude": 0,
            "accuracy": 5,
            "gpsOverrideReason": "test legacy compatibility",
            "gpsOverrideDetail": "Test GPS is intentionally outside customer Sites.",
        },
    )
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["code"] == "HOME_BASE_REQUIRED"

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

    # Membership is evaluated at the current local workday, rather than being
    # a permanent employee flag or an arbitrary crew association.
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

    result = api.admin_analytics_customer(home_base_label, request=None, weeks=1)

    assert result["success"] is True
    assert result["summary"]["visits"] == 0
    assert result["summary"]["hours"] == 0
    assert result["byVisit"] == []
