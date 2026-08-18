"""End-to-end contract tests for authenticated QR site check-in."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from zoneinfo import ZoneInfo

import psycopg2
import psycopg2.extras
import pytest

from conftest import _raw_conn


SITE_LATITUDE = 39.1203
SITE_LONGITUDE = -88.54335
CANONICAL_TEST_PREFIX = "SITE_CHECK_IN_CANONICAL_TEST"


@pytest.fixture(autouse=True)
def isolate_site_check_in_data(setup_db):
    def clean() -> None:
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM arrival_policy_revisions")
            cur.execute("DELETE FROM site_check_in_schedule_rules")
            cur.execute("DELETE FROM site_check_in_schedules")
            cur.execute(
                "DELETE FROM jobs WHERE source_calendar_id LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_sources WHERE calendar_id LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_connections "
                "WHERE google_account_email LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM employees WHERE name LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                """
                UPDATE locations
                SET check_in_token_nonce = NULL,
                    check_in_token_rotated_at = NULL,
                    location_type = CASE
                        WHEN address = '123 Main St, Effingham' THEN NULL
                        ELSE location_type
                    END,
                    lat = CASE
                        WHEN address = '123 Main St, Effingham' THEN 39.1203
                        ELSE lat
                    END,
                    lng = CASE
                        WHEN address = '123 Main St, Effingham' THEN -88.54335
                        ELSE lng
                    END
                """
            )
        conn.commit()
        conn.close()

    clean()
    yield
    clean()


def create_site_qr(client, auth, location_id, *, rotate=False):
    response = client.post(
        f"/api/admin/locations/{location_id}/check-in-qr",
        headers=auth,
        json={"rotate": rotate},
    )
    assert response.status_code == 200, response.text
    return response.json()


def create_arrival_schedule(
    _client,
    _auth,
    employee_id,
    location_id,
    scheduled_start,
    *,
    grace_minutes=10,
):
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO site_check_in_schedules (
                employee_id, location_id, scheduled_start, grace_minutes
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (employee_id, location_id, scheduled_start, grace_minutes),
        )
        schedule_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    return {"id": schedule_id}


def create_recurring_schedule_rule(
    _client,
    _auth,
    employee_id,
    location_id,
    *,
    weekdays,
    local_start="07:00",
    starts_on="2026-07-20",
    ends_on=None,
    grace_minutes=10,
):
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO site_check_in_schedule_rules (
                employee_id, location_id, weekdays, local_start_time, timezone,
                starts_on, ends_on, grace_minutes
            )
            VALUES (
                %s, %s, %s, %s, 'America/Chicago', %s,
                COALESCE(%s, 'infinity'::date), %s
            )
            RETURNING id
            """,
            (
                employee_id,
                location_id,
                weekdays,
                local_start,
                starts_on,
                ends_on,
                grace_minutes,
            ),
        )
        rule_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    return {"id": rule_id}


def create_canonical_job(
    location_id,
    start,
    *,
    end=None,
    status="scheduled",
    role="residential_morning",
    suffix="job",
    all_day=False,
):
    end = end or (start + timedelta(hours=2))
    site_type = "Residential" if role == "residential_morning" else "Commercial"
    source_identity = (
        f"{CANONICAL_TEST_PREFIX}:{location_id}:{start.isoformat()}:{suffix}"
    )
    source_key = hashlib.sha256(source_identity.encode("utf-8")).hexdigest()
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE locations SET location_type = %s WHERE id = %s",
            (site_type, location_id),
        )
        cur.execute(
            """
            INSERT INTO google_calendar_connections (
                google_account_email, granted_scopes, revoked_at
            )
            VALUES (%s, ARRAY['calendar.readonly'], NOW())
            RETURNING id
            """,
            (f"{CANONICAL_TEST_PREFIX}_{suffix}@example.test",),
        )
        connection_id = int(cur.fetchone()[0])
        calendar_id = f"{CANONICAL_TEST_PREFIX}_{suffix}"
        cur.execute(
            """
            INSERT INTO google_calendar_sources (
                connection_id, role, calendar_id, calendar_name,
                calendar_timezone
            )
            VALUES (%s, %s, %s, %s, 'America/Chicago')
            RETURNING id
            """,
            (connection_id, role, calendar_id, calendar_id),
        )
        source_id = int(cur.fetchone()[0])
        cur.execute(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date,
                scheduled_start, scheduled_end, status, calendar_source_id,
                source_calendar_id, source_event_id, source_occurrence_id,
                source_key, source_fingerprint, source_title, source_all_day
            )
            SELECT
                l.id, COALESCE(l.customer_name, l.address),
                (%s AT TIME ZONE 'America/Chicago')::date,
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                COALESCE(l.customer_name, l.address), %s
            FROM locations l
            WHERE l.id = %s
            RETURNING id
            """,
            (
                start,
                start,
                end,
                status,
                source_id,
                calendar_id,
                source_identity,
                source_identity,
                source_key,
                source_key,
                all_day,
                location_id,
            ),
        )
        job_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    return job_id


def create_test_employee_auth(*, suffix):
    from time_tracker_api import create_auth_token

    employee_name = f"{CANONICAL_TEST_PREFIX} {suffix}"
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO employees (
                name, password_hash, active, role, hourly_rate
            )
            VALUES (%s, 'unused-test-hash', true, 'employee', 16.00)
            RETURNING id
            """,
            (employee_name,),
        )
        employee_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    token = create_auth_token(employee_id, employee_name)
    return employee_id, {"Authorization": f"Bearer {token}"}


@pytest.fixture
def site_qr_token(client, auth, location_id):
    return create_site_qr(client, auth, location_id)["token"]


def site_check_in_payload(
    employee_id,
    location_id,
    token,
    *,
    scanned_at=None,
    **overrides,
):
    payload = {
        "employeeId": employee_id,
        "siteId": location_id,
        "token": token,
        "scannedAt": (scanned_at or datetime.now(timezone.utc)).isoformat(),
        "latitude": SITE_LATITUDE,
        "longitude": SITE_LONGITUDE,
        "accuracy": 5.0,
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def explicit_action_employee(client, isolate_site_check_in_data):
    employee_id, employee_auth = create_test_employee_auth(suffix=f"action-{uuid4()}")
    yield employee_id, employee_auth
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM site_qr_action_receipts WHERE employee_id = %s",
            (employee_id,),
        )
        cur.execute("DELETE FROM site_check_ins WHERE employee_id = %s", (employee_id,))
        cur.execute("DELETE FROM shifts WHERE employee_id = %s", (employee_id,))
        cur.execute("DELETE FROM employees WHERE id = %s", (employee_id,))
    conn.commit()
    conn.close()


@pytest.fixture
def second_action_site(explicit_action_employee):
    employee_id, _ = explicit_action_employee
    address = f"{CANONICAL_TEST_PREFIX} SECOND SITE {uuid4()}"
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO locations (
                address, customer_name, lat, lng, active
            )
            VALUES (%s, 'Second Test Customer', %s, %s, true)
            RETURNING id
            """,
            (address, SITE_LATITUDE, SITE_LONGITUDE),
        )
        site_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    yield site_id, address
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM site_qr_action_receipts WHERE location_id = %s",
            (site_id,),
        )
        cur.execute("DELETE FROM site_check_ins WHERE location_id = %s", (site_id,))
        cur.execute("DELETE FROM shifts WHERE employee_id = %s", (employee_id,))
        cur.execute("DELETE FROM locations WHERE id = %s", (site_id,))
    conn.commit()
    conn.close()


def explicit_action_payload(
    employee_id,
    site_id,
    token,
    action_state,
    *,
    action=None,
    idempotency_key=None,
    scanned_at=None,
    **overrides,
):
    payload = site_check_in_payload(
        employee_id,
        site_id,
        token,
        scanned_at=scanned_at,
        action=action or action_state["recommendedAction"],
        actionStateToken=action_state["stateToken"],
        idempotencyKey=str(idempotency_key or uuid4()),
    )
    payload.update(overrides)
    return payload


def clock_in_action_employee(client, employee_auth):
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "location": "123 Main St, Effingham",
            "latitude": SITE_LATITUDE,
            "longitude": SITE_LONGITUDE,
            "accuracy": 5,
        },
    )
    assert response.status_code == 200, response.text
    return int(response.json()["entry"]["id"])


class TestExplicitSiteQrActions:
    def test_resolve_and_submit_require_active_shift(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
    ):
        employee_id, employee_auth = explicit_action_employee
        token = create_site_qr(client, auth, location_id)["token"]
        resolved = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        )
        assert resolved.status_code == 200, resolved.text
        state = resolved.json()["actionState"]
        assert state == {
            "status": "clock_in_required",
            "recommendedAction": None,
            "shiftId": None,
            "activeVisit": None,
            "missingDepartures": [],
            "stateToken": None,
            "blockReason": "active_shift_required",
        }

        rejected = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                token,
                action="arrive",
                actionStateToken="invalid-but-long-enough",
                idempotencyKey=str(uuid4()),
            ),
        )
        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["code"] == "ACTIVE_SHIFT_REQUIRED"
        assert rejected.json()["details"]["actionState"]["status"] == (
            "clock_in_required"
        )

    def test_arrive_depart_and_exact_replay_are_explicitly_paired(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
    ):
        import time_tracker_api as api

        employee_id, employee_auth = explicit_action_employee
        matched_job_id = create_canonical_job(
            location_id,
            datetime.now(timezone.utc) - timedelta(minutes=15),
            suffix="explicit-action-visit-job",
        )
        shift_id = clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        resolved = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()
        assert resolved["actionState"]["recommendedAction"] == "arrive"

        arrival_payload = explicit_action_payload(
            employee_id,
            location_id,
            token,
            resolved["actionState"],
        )
        arrived = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=arrival_payload,
        )
        assert arrived.status_code == 200, arrived.text
        arrival_body = arrived.json()
        assert arrival_body["outcome"] == "recorded"
        assert arrival_body["replayed"] is False
        assert arrival_body["shiftId"] == shift_id
        assert arrival_body["checkIn"]["jobId"] == matched_job_id
        assert arrival_body["visit"]["jobId"] == matched_job_id
        assert arrival_body["visit"]["sequenceVersion"] == 2
        assert arrival_body["visit"]["siteCheckInId"] == arrival_body["checkIn"]["id"]
        assert arrival_body["actionState"]["recommendedAction"] == "depart"

        replay = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=arrival_payload,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["replayed"] is True
        assert replay.json()["visit"]["id"] == arrival_body["visit"]["id"]

        departure_payload = explicit_action_payload(
            employee_id,
            location_id,
            token,
            arrival_body["actionState"],
        )
        departed = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=departure_payload,
        )
        assert departed.status_code == 200, departed.text
        departure_body = departed.json()
        assert departure_body["action"] == "depart"
        assert departure_body["departure"]["visitId"] == arrival_body["visit"]["id"]
        assert departure_body["actionState"]["activeVisit"] is None
        assert departure_body["actionState"]["recommendedAction"] == "arrive"

        conn = _raw_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT v.sequence_version, v.site_check_in_id, v.job_id AS visit_job_id,
                       ci.job_id AS check_in_job_id, d.visit_id, receipt.outcome
                FROM visits v
                JOIN site_check_ins ci ON ci.id = v.site_check_in_id
                JOIN departures d ON d.visit_id = v.id
                JOIN site_qr_action_receipts receipt
                  ON receipt.departure_id = d.id
                WHERE v.id = %s
                """,
                (arrival_body["visit"]["id"],),
            )
            stored = dict(cur.fetchone())
            cur.execute(
                "SELECT COUNT(*) AS n FROM visits WHERE shift_id = %s",
                (shift_id,),
            )
            assert int(cur.fetchone()["n"]) == 1
        conn.close()
        assert int(stored["sequence_version"]) == 2
        assert int(stored["site_check_in_id"]) == arrival_body["checkIn"]["id"]
        assert int(stored["visit_job_id"]) == matched_job_id
        assert int(stored["check_in_job_id"]) == matched_job_id
        assert int(stored["visit_id"]) == arrival_body["visit"]["id"]
        assert stored["outcome"] == "recorded"
        loaded_entry = next(
            entry
            for entry in api.load_timesheets()["entries"]
            if entry["id"] == shift_id
        )
        loaded_visit = next(
            visit
            for visit in loaded_entry["visits"]
            if visit["id"] == arrival_body["visit"]["id"]
        )
        assert loaded_visit["jobId"] == matched_job_id

    @pytest.mark.parametrize(
        "geofence_status",
        ["outside", "uncertain", "low_accuracy", "site_unpinned"],
    )
    def test_weak_arrival_gps_is_evidence_only(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
        monkeypatch,
        geofence_status,
    ):
        import time_tracker_api

        employee_id, employee_auth = explicit_action_employee
        shift_id = clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()["actionState"]
        monkeypatch.setattr(
            time_tracker_api,
            "evaluate_site_check_in_geofence",
            lambda **_: {
                "status": geofence_status,
                "distanceM": 75.0,
                "radiusM": 50,
                "accuracyM": 125.0,
            },
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                state,
            ),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "evidence_only_review"
        assert body["visit"] is None
        assert body["checkIn"]["reviewStatus"] == "pending"
        assert body["actionState"]["recommendedAction"] == "arrive"

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM visits WHERE shift_id = %s", (shift_id,))
            assert int(cur.fetchone()[0]) == 0
            cur.execute(
                """
                SELECT geofence_status, outcome, visit_id
                FROM site_qr_action_receipts
                WHERE employee_id = %s
                """,
                (employee_id,),
            )
            receipt = cur.fetchone()
        conn.close()
        assert receipt == (geofence_status, "evidence_only_review", None)

    def test_cross_site_arrival_leaves_missing_departure_visible_without_revival(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
        second_action_site,
    ):
        employee_id, employee_auth = explicit_action_employee
        second_site_id, _ = second_action_site
        shift_id = clock_in_action_employee(client, employee_auth)
        first_token = create_site_qr(client, auth, location_id)["token"]
        second_token = create_site_qr(client, auth, second_site_id)["token"]

        first_state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": first_token},
        ).json()["actionState"]
        first_arrival = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                first_token,
                first_state,
            ),
        ).json()
        first_visit_id = first_arrival["visit"]["id"]

        second_state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": second_token},
        ).json()["actionState"]
        assert second_state["recommendedAction"] == "arrive"
        assert [row["id"] for row in second_state["missingDepartures"]] == [
            first_visit_id
        ]
        second_arrival = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                second_site_id,
                second_token,
                second_state,
            ),
        ).json()
        second_visit_id = second_arrival["visit"]["id"]
        departed = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                second_site_id,
                second_token,
                second_arrival["actionState"],
            ),
        )
        assert departed.status_code == 200, departed.text
        final_state = departed.json()["actionState"]
        assert final_state["activeVisit"] is None
        assert final_state["recommendedAction"] == "arrive"
        assert [row["id"] for row in final_state["missingDepartures"]] == [
            first_visit_id
        ]

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT visit_id
                FROM departures
                WHERE shift_id = %s
                ORDER BY id
                """,
                (shift_id,),
            )
            paired_ids = [int(row[0]) for row in cur.fetchall()]
        conn.close()
        assert paired_ids == [second_visit_id]

    @pytest.mark.parametrize(
        "geofence_status",
        ["outside", "uncertain", "low_accuracy", "site_unpinned"],
    )
    def test_weak_departure_gps_is_evidence_only_and_keeps_depart_ready(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
        monkeypatch,
        geofence_status,
    ):
        import time_tracker_api

        employee_id, employee_auth = explicit_action_employee
        shift_id = clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        arrival_state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()["actionState"]
        arrived = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                arrival_state,
            ),
        )
        assert arrived.status_code == 200, arrived.text
        assert arrived.json()["actionState"]["recommendedAction"] == "depart"

        monkeypatch.setattr(
            time_tracker_api,
            "evaluate_site_check_in_geofence",
            lambda **_: {
                "status": geofence_status,
                "distanceM": 75.0,
                "radiusM": 50,
                "accuracyM": 125.0,
            },
        )
        weak_depart = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                arrived.json()["actionState"],
            ),
        )
        assert weak_depart.status_code == 200, weak_depart.text
        body = weak_depart.json()
        assert body["action"] == "depart"
        assert body["outcome"] == "evidence_only_review"
        assert body["departure"] is None
        assert body["actionState"]["recommendedAction"] == "depart"
        assert body["actionState"]["activeVisit"]["id"] == arrived.json()["visit"]["id"]

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM departures WHERE shift_id = %s",
                (shift_id,),
            )
            assert int(cur.fetchone()[0]) == 0
            cur.execute(
                """
                SELECT geofence_status, outcome, departure_id
                FROM site_qr_action_receipts
                WHERE employee_id = %s AND action = 'depart'
                """,
                (employee_id,),
            )
            receipt = cur.fetchone()
        conn.close()
        assert receipt == (geofence_status, "evidence_only_review", None)

    def test_depart_bypasses_hours_gate_while_arrive_still_enforces_it(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
        monkeypatch,
    ):
        from fastapi import HTTPException
        import time_tracker_api

        employee_id, employee_auth = explicit_action_employee
        clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        arrival_state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()["actionState"]
        arrived = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                arrival_state,
            ),
        )
        assert arrived.status_code == 200, arrived.text

        gate_calls = 0

        def reject_by_hours(_request):
            nonlocal gate_calls
            gate_calls += 1
            raise HTTPException(status_code=403, detail="test hours gate")

        monkeypatch.setattr(
            time_tracker_api,
            "enforce_clock_action_hours",
            reject_by_hours,
        )
        departed = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                arrived.json()["actionState"],
            ),
        )
        assert departed.status_code == 200, departed.text
        assert departed.json()["action"] == "depart"
        assert gate_calls == 0

        rejected_arrival = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                departed.json()["actionState"],
            ),
        )
        assert rejected_arrival.status_code == 403, rejected_arrival.text
        assert rejected_arrival.json()["error"] == "test hours gate"
        assert gate_calls == 1

    def test_changed_state_and_changed_idempotency_input_return_fresh_409(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
    ):
        employee_id, employee_auth = explicit_action_employee
        clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()["actionState"]
        request_key = uuid4()
        payload = explicit_action_payload(
            employee_id,
            location_id,
            token,
            state,
            idempotency_key=request_key,
        )
        recorded = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=payload,
        )
        assert recorded.status_code == 200, recorded.text

        changed = dict(payload)
        changed["latitude"] = SITE_LATITUDE + 0.00001
        conflict = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=changed,
        )
        assert conflict.status_code == 409, conflict.text
        conflict_body = conflict.json()
        assert conflict_body["code"] == "IDEMPOTENCY_KEY_REUSED"
        assert (
            conflict_body["details"]["actionState"]["recommendedAction"]
            == "depart"
        )

        old_state_new_key = dict(payload)
        old_state_new_key["idempotencyKey"] = str(uuid4())
        old_state_new_key["scannedAt"] = (
            datetime.now(timezone.utc) + timedelta(seconds=1)
        ).isoformat()
        stale = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=old_state_new_key,
        )
        assert stale.status_code == 409, stale.text
        assert stale.json()["code"] == "SITE_ACTION_STATE_CHANGED"
        assert (
            stale.json()["details"]["actionState"]["recommendedAction"]
            == "depart"
        )

    def test_new_manual_departure_closes_legacy_visit_once(
        self,
        client,
        explicit_action_employee,
    ):
        employee_id, employee_auth = explicit_action_employee
        shift_id = clock_in_action_employee(client, employee_auth)
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, sequence_version
                )
                SELECT %s, id, address, customer_name, NOW(), 1
                FROM locations
                WHERE address = '123 Main St, Effingham'
                RETURNING id
                """,
                (shift_id,),
            )
            legacy_visit_id = int(cur.fetchone()[0])
        conn.commit()
        conn.close()

        first = client.post(
            "/api/timesheet/depart",
            headers=employee_auth,
            json={
                "latitude": SITE_LATITUDE,
                "longitude": SITE_LONGITUDE,
                "accuracy": 5,
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["departure"]["visitId"] == legacy_visit_id
        second = client.post(
            "/api/timesheet/depart",
            headers=employee_auth,
            json={
                "latitude": SITE_LATITUDE,
                "longitude": SITE_LONGITUDE,
                "accuracy": 5,
            },
        )
        assert second.status_code == 400, second.text
        assert "No active arrival" in second.json()["error"]

    def test_explicit_qr_depart_closes_legacy_visit_and_cannot_repeat(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
    ):
        employee_id, employee_auth = explicit_action_employee
        shift_id = clock_in_action_employee(client, employee_auth)
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, sequence_version
                )
                SELECT %s, id, address, customer_name, NOW(), 1
                FROM locations
                WHERE id = %s
                RETURNING id
                """,
                (shift_id, location_id),
            )
            legacy_visit_id = int(cur.fetchone()[0])
        conn.commit()
        conn.close()

        token = create_site_qr(client, auth, location_id)["token"]
        resolved = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        )
        assert resolved.status_code == 200, resolved.text
        depart_state = resolved.json()["actionState"]
        assert depart_state["recommendedAction"] == "depart"
        assert depart_state["activeVisit"]["id"] == legacy_visit_id

        departed = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                depart_state,
            ),
        )
        assert departed.status_code == 200, departed.text
        assert departed.json()["departure"]["visitId"] == legacy_visit_id
        assert departed.json()["actionState"]["recommendedAction"] == "arrive"
        assert departed.json()["actionState"]["activeVisit"] is None

        fresh = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        )
        assert fresh.status_code == 200, fresh.text
        fresh_state = fresh.json()["actionState"]
        assert fresh_state["recommendedAction"] == "arrive"
        assert fresh_state["activeVisit"] is None

        second_depart = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                fresh_state,
                action="depart",
            ),
        )
        assert second_depart.status_code == 409, second_depart.text
        assert second_depart.json()["code"] == "SITE_ACTION_STATE_CHANGED"
        assert (
            second_depart.json()["details"]["actionState"]["recommendedAction"]
            == "arrive"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT visit_id FROM departures WHERE shift_id = %s",
                (shift_id,),
            )
            assert [int(row[0]) for row in cur.fetchall()] == [legacy_visit_id]
        conn.close()

    def test_manual_and_qr_event_writers_serialize_without_lost_events(
        self,
        client,
        auth,
        location_id,
        explicit_action_employee,
        monkeypatch,
    ):
        import time_tracker_api

        employee_id, employee_auth = explicit_action_employee
        shift_id = clock_in_action_employee(client, employee_auth)
        token = create_site_qr(client, auth, location_id)["token"]
        initial_state = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=employee_auth,
            json={"token": token},
        ).json()["actionState"]
        stale_qr_payload = explicit_action_payload(
            employee_id,
            location_id,
            token,
            initial_state,
        )

        manual_save_started = threading.Event()
        allow_manual_save = threading.Event()
        qr_action_started = threading.Event()
        original_save = time_tracker_api._save_timesheets_to_db
        original_qr_action = time_tracker_api._record_explicit_site_action

        def blocking_manual_save(*args, **kwargs):
            manual_save_started.set()
            assert allow_manual_save.wait(timeout=10)
            return original_save(*args, **kwargs)

        def observed_qr_action(payload, request, employee):
            qr_action_started.set()
            return original_qr_action(payload, request, employee)

        monkeypatch.setattr(
            time_tracker_api,
            "_save_timesheets_to_db",
            blocking_manual_save,
        )
        monkeypatch.setattr(
            time_tracker_api,
            "_record_explicit_site_action",
            observed_qr_action,
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            manual_future = executor.submit(
                client.post,
                "/api/timesheet/visit",
                headers=employee_auth,
                json={
                    "location": "123 Main St, Effingham",
                    "latitude": SITE_LATITUDE,
                    "longitude": SITE_LONGITUDE,
                    "accuracy": 5,
                },
            )
            assert manual_save_started.wait(timeout=10)
            try:
                lock_conn = _raw_conn()
                with lock_conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_try_advisory_lock(%s)",
                        (time_tracker_api.TIMESHEET_PG_ADVISORY_LOCK_ID,),
                    )
                    unexpectedly_acquired = bool(cur.fetchone()[0])
                    if unexpectedly_acquired:
                        cur.execute(
                            "SELECT pg_advisory_unlock(%s)",
                            (time_tracker_api.TIMESHEET_PG_ADVISORY_LOCK_ID,),
                        )
                lock_conn.close()
                assert unexpectedly_acquired is False

                qr_future = executor.submit(
                    client.post,
                    "/api/timesheet/site-check-in",
                    headers=employee_auth,
                    json=stale_qr_payload,
                )
                assert qr_action_started.wait(timeout=10)
                assert qr_future.done() is False
            finally:
                allow_manual_save.set()

            manual_response = manual_future.result(timeout=10)
            qr_response = qr_future.result(timeout=10)

        assert manual_response.status_code == 200, manual_response.text
        manual_visit_id = int(manual_response.json()["visit"]["id"])
        assert qr_response.status_code == 409, qr_response.text
        assert qr_response.json()["code"] == "SITE_ACTION_STATE_CHANGED"
        refreshed_state = qr_response.json()["details"]["actionState"]
        assert refreshed_state["recommendedAction"] == "depart"
        assert refreshed_state["activeVisit"]["id"] == manual_visit_id

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM visits WHERE shift_id = %s", (shift_id,))
            assert int(cur.fetchone()[0]) == 1
            cur.execute(
                "SELECT COUNT(*) FROM departures WHERE shift_id = %s",
                (shift_id,),
            )
            assert int(cur.fetchone()[0]) == 0
            cur.execute(
                """
                SELECT COUNT(*)
                FROM site_qr_action_receipts
                WHERE employee_id = %s
                """,
                (employee_id,),
            )
            assert int(cur.fetchone()[0]) == 0
        conn.close()

        confirmed_depart = client.post(
            "/api/timesheet/site-check-in",
            headers=employee_auth,
            json=explicit_action_payload(
                employee_id,
                location_id,
                token,
                refreshed_state,
            ),
        )
        assert confirmed_depart.status_code == 200, confirmed_depart.text
        assert confirmed_depart.json()["departure"]["visitId"] == manual_visit_id

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM visits WHERE shift_id = %s", (shift_id,))
            assert int(cur.fetchone()[0]) == 1
            cur.execute(
                """
                SELECT visit_id
                FROM departures
                WHERE shift_id = %s
                """,
                (shift_id,),
            )
            assert [int(row[0]) for row in cur.fetchall()] == [manual_visit_id]
            cur.execute(
                """
                SELECT action, outcome
                FROM site_qr_action_receipts
                WHERE employee_id = %s
                """,
                (employee_id,),
            )
            assert cur.fetchall() == [("depart", "recorded")]
        conn.close()


class TestSiteQr:
    def test_qr_requires_admin_and_resolution_requires_employee_session(
        self, client, emp_auth, location_id
    ):
        forbidden = client.post(
            f"/api/admin/locations/{location_id}/check-in-qr",
            headers=emp_auth,
            json={"rotate": False},
        )
        assert forbidden.status_code == 403

        unauthenticated = client.post(
            "/api/timesheet/site-check-in/resolve",
            json={"token": "eom1.1.aaaaaaaaaaaaaaaaaaaa.invalid"},
        )
        assert unauthenticated.status_code == 401

    def test_qr_is_rendered_resolved_and_rotatable(
        self, client, auth, emp_auth, location_id
    ):
        first = create_site_qr(client, auth, location_id)
        assert first["site"]["id"] == location_id
        assert first["checkInUrl"].startswith(
            "https://portal.example.test/portal?checkIn=eom1."
        )
        assert "<svg" in first["qrSvg"]

        resolved = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=emp_auth,
            json={"token": first["token"]},
        )
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["site"] == {
            "id": location_id,
            "name": "123 Main St, Effingham",
            "customerName": "Test Customer",
        }

        forged_token = first["token"][:-1] + (
            "A" if first["token"][-1] != "A" else "B"
        )
        forged = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=emp_auth,
            json={"token": forged_token},
        )
        assert forged.status_code == 404

        second = create_site_qr(client, auth, location_id, rotate=True)
        assert second["token"] != first["token"]
        expired = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=emp_auth,
            json={"token": first["token"]},
        )
        assert expired.status_code == 404
        current = client.post(
            "/api/timesheet/site-check-in/resolve",
            headers=emp_auth,
            json={"token": second["token"]},
        )
        assert current.status_code == 200

    def test_initial_qr_creation_is_idempotent_under_concurrent_requests(
        self, client, auth, location_id, monkeypatch
    ):
        import time_tracker_api

        original_query_one = time_tracker_api.db.query_one
        initial_read_barrier = threading.Barrier(2)

        def synchronized_query_one(sql, params=()):
            row = original_query_one(sql, params)
            normalized_sql = " ".join(sql.split())
            if normalized_sql.startswith(
                "SELECT id, address, customer_name, active, check_in_token_nonce,"
            ):
                initial_read_barrier.wait(timeout=10)
            return row

        monkeypatch.setattr(time_tracker_api.db, "query_one", synchronized_query_one)

        def load_or_create_qr():
            return client.post(
                f"/api/admin/locations/{location_id}/check-in-qr",
                headers=auth,
                json={"rotate": False},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = [
                future.result(timeout=15)
                for future in [executor.submit(load_or_create_qr) for _ in range(2)]
            ]

        assert all(response.status_code == 200 for response in responses)
        payloads = [response.json() for response in responses]
        assert len({payload["token"] for payload in payloads}) == 1
        assert sorted(payload["rotated"] for payload in payloads) == [False, True]


class TestSiteCheckInDecision:
    def test_session_employee_is_authoritative(
        self, client, emp_auth, employee_id, location_id, site_qr_token
    ):
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id + 999, location_id, site_qr_token
            ),
        )
        assert response.status_code == 403
        assert "signed-in employee" in response.json()["error"]

    def test_record_requires_matching_current_qr_token(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        missing_token = site_check_in_payload(
            employee_id, location_id, site_qr_token
        )
        missing_token.pop("token")
        missing = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=missing_token,
        )
        assert missing.status_code == 422

        mismatched_site = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id + 999, site_qr_token
            ),
        )
        assert mismatched_site.status_code == 400
        assert "scanned site QR" in mismatched_site.json()["error"]

        rotated = create_site_qr(client, auth, location_id, rotate=True)
        expired = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token
            ),
        )
        assert expired.status_code == 404
        assert "revoked" in expired.json()["error"]

        current = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, rotated["token"]
            ),
        )
        assert current.status_code == 200, current.text

    def test_server_timestamp_and_legacy_exact_schedule_uses_implicit_flexible(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        before = datetime.now(timezone.utc)
        job_id = create_canonical_job(
            location_id,
            before - timedelta(hours=1),
            suffix="exact-on-time",
        )
        create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            before + timedelta(minutes=5),
            grace_minutes=10,
        )
        device_scan = before - timedelta(seconds=30)
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=device_scan,
            ),
        )
        after = datetime.now(timezone.utc)
        assert response.status_code == 200, response.text
        check_in = response.json()["checkIn"]
        official = datetime.fromisoformat(check_in["serverCheckedInAt"].replace("Z", "+00:00"))
        assert before - timedelta(seconds=1) <= official <= after
        assert check_in["deviceScannedAt"] == device_scan.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        assert check_in["classification"] == "on_time"
        assert check_in["classificationReason"] == "verified_scheduled_site"
        assert check_in["reviewStatus"] == "not_required"
        assert check_in["scheduleId"] is None
        assert check_in["scheduleRuleId"] is None
        assert check_in["scheduledStart"] is None
        assert check_in["graceMinutes"] is None
        assert check_in["arrivalPolicySnapshot"]["classifiedBy"] == "implicit_flexible"
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (check_in["id"],),
            )
            assert cur.fetchone()[0] == job_id
        conn.close()

    def test_legacy_exact_schedule_after_grace_no_longer_marks_late(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        create_canonical_job(
            location_id,
            datetime.now(timezone.utc) - timedelta(hours=1),
            suffix="exact-late",
        )
        create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            datetime.now(timezone.utc) - timedelta(minutes=30),
            grace_minutes=5,
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        assert response.status_code == 200, response.text
        check_in = response.json()["checkIn"]
        assert check_in["classification"] == "on_time"
        assert check_in["classificationReason"] == "verified_scheduled_site"
        assert check_in["scheduleId"] is None
        assert check_in["scheduledStart"] is None
        assert check_in["graceMinutes"] is None
        assert check_in["arrivalPolicySnapshot"]["classifiedBy"] == "implicit_flexible"

    @pytest.mark.parametrize(
        ("overrides", "geofence_status", "reason"),
        [
            ({"accuracy": 250.0}, "low_accuracy", "location_accuracy_too_low"),
            (
                {"latitude": 39.2203, "longitude": SITE_LONGITUDE, "accuracy": 5.0},
                "outside",
                "outside_geofence",
            ),
            (
                {"latitude": 39.1207, "longitude": SITE_LONGITUDE, "accuracy": 20.0},
                "uncertain",
                "geofence_boundary_uncertain",
            ),
        ],
    )
    def test_geofence_evidence_routes_uncertain_punches_to_review(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        overrides,
        geofence_status,
        reason,
    ):
        create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            datetime.now(timezone.utc),
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token, **overrides
            ),
        )
        assert response.status_code == 200, response.text
        check_in = response.json()["checkIn"]
        assert check_in["classification"] == "needs_review"
        assert check_in["geofenceStatus"] == geofence_status
        assert check_in["classificationReason"] == reason
        assert check_in["reviewStatus"] == "pending"

    def test_missing_job_and_device_clock_skew_need_review(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        missing_job = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        assert missing_job.status_code == 200, missing_job.text
        assert missing_job.json()["checkIn"]["classificationReason"] == "no_scheduled_job"

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
        conn.commit()
        conn.close()
        create_canonical_job(
            location_id,
            datetime.now(timezone.utc) - timedelta(hours=1),
            suffix="device-skew",
        )
        create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            datetime.now(timezone.utc),
        )
        skewed = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=datetime.now(timezone.utc) - timedelta(hours=1),
            ),
        )
        assert skewed.status_code == 200, skewed.text
        assert skewed.json()["checkIn"]["classificationReason"] == "device_clock_skew"

    def test_unique_canonical_job_accepts_unassigned_employee(
        self, client, emp_auth, employee_id, location_id, site_qr_token
    ):
        job_id = create_canonical_job(
            location_id,
            datetime.now(timezone.utc) + timedelta(hours=8),
            suffix="flexible-unassigned",
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        assert response.status_code == 200, response.text
        check_in = response.json()["checkIn"]
        assert check_in["classification"] == "on_time"
        assert check_in["classificationReason"] == "verified_scheduled_site"
        assert check_in["reviewStatus"] == "not_required"
        assert check_in["scheduleId"] is None
        assert check_in["scheduleRuleId"] is None
        assert check_in["scheduledStart"] is None
        assert check_in["graceMinutes"] is None
        assert (
            check_in["arrivalPolicySnapshot"]["classifiedBy"]
            == "implicit_flexible"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (check_in["id"],),
            )
            assert cur.fetchone()[0] == job_id
            cur.execute("SELECT COUNT(*) FROM site_check_in_schedules")
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM site_check_in_schedule_rules")
            assert cur.fetchone()[0] == 0
        conn.close()

    def test_cancelled_and_ambiguous_jobs_fail_closed(
        self,
        client,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        import time_tracker_api

        official_time = datetime(2026, 7, 23, 15, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
        cancelled_job_id = create_canonical_job(
            location_id,
            official_time - timedelta(hours=1),
            end=official_time + timedelta(hours=1),
            status="cancelled",
            suffix="cancelled-only",
        )

        cancelled = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["checkIn"]["classification"] == "needs_review"
        assert (
            cancelled.json()["checkIn"]["classificationReason"]
            == "cancelled_job"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
        conn.commit()
        conn.close()
        active_job_id = create_canonical_job(
            location_id,
            official_time - timedelta(hours=2),
            end=official_time + timedelta(hours=2),
            suffix="active-with-cancelled",
        )
        accepted = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert accepted.status_code == 200, accepted.text
        assert (
            accepted.json()["checkIn"]["classificationReason"]
            == "verified_scheduled_site"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (accepted.json()["checkIn"]["id"],),
            )
            assert cur.fetchone()[0] == active_job_id
            cur.execute("DELETE FROM site_check_ins")
        conn.commit()
        conn.close()
        create_canonical_job(
            location_id,
            official_time - timedelta(minutes=30),
            end=official_time + timedelta(minutes=30),
            suffix="second-active",
        )
        ambiguous = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert ambiguous.status_code == 200, ambiguous.text
        assert ambiguous.json()["checkIn"]["classification"] == "needs_review"
        assert (
            ambiguous.json()["checkIn"]["classificationReason"]
            == "ambiguous_job"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (ambiguous.json()["checkIn"]["id"],),
            )
            assert cur.fetchone()[0] is None
            cur.execute(
                "SELECT status FROM jobs WHERE id = %s",
                (cancelled_job_id,),
            )
            assert cur.fetchone()[0] == "cancelled"
        conn.close()

    def test_matching_job_is_locked_until_qr_transaction_finishes(
        self, location_id
    ):
        from time_tracker_api import _matching_canonical_site_job

        official_time = datetime(2026, 7, 23, 15, 0, tzinfo=timezone.utc)
        job_id = create_canonical_job(
            location_id,
            official_time - timedelta(hours=1),
            end=official_time + timedelta(hours=1),
            suffix="share-lock",
        )
        matcher_conn = _raw_conn()
        try:
            with matcher_conn.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            ) as matcher_cur:
                matched_job, reason = _matching_canonical_site_job(
                    location_id,
                    official_time,
                    cur=matcher_cur,
                )
                assert matched_job is not None
                assert int(matched_job["id"]) == job_id
                assert reason == "verified_scheduled_site"

                competing_conn = _raw_conn()
                try:
                    with competing_conn.cursor() as competing_cur:
                        competing_cur.execute("SET LOCAL lock_timeout = '100ms'")
                        with pytest.raises(psycopg2.errors.LockNotAvailable):
                            competing_cur.execute(
                                """
                                UPDATE jobs
                                SET status = 'cancelled'
                                WHERE id = %s
                                """,
                                (job_id,),
                            )
                    competing_conn.rollback()
                finally:
                    competing_conn.close()
            matcher_conn.commit()
        finally:
            matcher_conn.close()

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status = 'cancelled' WHERE id = %s",
                (job_id,),
            )
        conn.commit()
        conn.close()

    def test_invalid_calendar_candidates_are_not_schedule_authority(
        self,
        client,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        import time_tracker_api

        official_time = datetime(2026, 7, 23, 16, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
        create_canonical_job(
            location_id,
            official_time - timedelta(hours=1),
            end=official_time + timedelta(hours=1),
            suffix="all-day",
            all_day=True,
        )
        all_day = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert all_day.status_code == 200, all_day.text
        assert (
            all_day.json()["checkIn"]["classificationReason"]
            == "no_scheduled_job"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute(
                "UPDATE locations SET location_type = 'Commercial' WHERE id = %s",
                (location_id,),
            )
        conn.commit()
        conn.close()
        wrong_role = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert wrong_role.status_code == 200, wrong_role.text
        assert (
            wrong_role.json()["checkIn"]["classificationReason"]
            == "no_scheduled_job"
        )

    def test_overnight_commercial_job_uses_bounded_calendar_association(
        self,
        client,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        import time_tracker_api

        official_time = datetime(2026, 7, 24, 5, 30, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
        job_id = create_canonical_job(
            location_id,
            datetime(2026, 7, 24, 1, 0, tzinfo=timezone.utc),
            end=datetime(2026, 7, 24, 7, 0, tzinfo=timezone.utc),
            role="commercial_evening_night",
            suffix="overnight-commercial",
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert response.status_code == 200, response.text
        assert (
            response.json()["checkIn"]["classificationReason"]
            == "verified_scheduled_site"
        )
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (response.json()["checkIn"]["id"],),
            )
            assert cur.fetchone()[0] == job_id
        conn.close()

    def test_two_employees_can_check_in_to_the_same_job(
        self,
        client,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        import time_tracker_api

        official_time = datetime(2026, 7, 23, 17, 0, tzinfo=timezone.utc)
        job_id = create_canonical_job(
            location_id,
            official_time - timedelta(hours=1),
            end=official_time + timedelta(hours=1),
            suffix="shared-job",
        )
        second_employee_id, second_emp_auth = create_test_employee_auth(
            suffix="Second Worker"
        )
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)

        responses = [
            client.post(
                "/api/timesheet/site-check-in",
                headers=headers,
                json=site_check_in_payload(
                    current_employee_id,
                    location_id,
                    site_qr_token,
                    scanned_at=official_time,
                ),
            )
            for current_employee_id, headers in (
                (employee_id, emp_auth),
                (second_employee_id, second_emp_auth),
            )
        ]
        assert all(response.status_code == 200 for response in responses)
        assert all(
            response.json()["checkIn"]["classificationReason"]
            == "verified_scheduled_site"
            for response in responses
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT employee_id, job_id
                FROM site_check_ins
                WHERE job_id = %s
                ORDER BY employee_id
                """,
                (job_id,),
            )
            assert cur.fetchall() == [
                (employee_id, job_id),
                (second_employee_id, job_id),
            ]
            cur.execute(
                "SELECT status FROM jobs WHERE id = %s",
                (job_id,),
            )
            assert cur.fetchone()[0] == "scheduled"
            cur.execute("SELECT COUNT(*) FROM site_check_in_schedules")
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM site_check_in_schedule_rules")
            assert cur.fetchone()[0] == 0
        conn.close()

    def test_geofence_then_device_skew_precede_ambiguous_job(
        self,
        client,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        import time_tracker_api

        official_time = datetime(2026, 7, 23, 18, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
        for suffix in ("ambiguous-one", "ambiguous-two"):
            create_canonical_job(
                location_id,
                official_time - timedelta(hours=1),
                end=official_time + timedelta(hours=1),
                suffix=suffix,
            )

        skewed = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time - timedelta(hours=1),
            ),
        )
        assert skewed.status_code == 200, skewed.text
        assert (
            skewed.json()["checkIn"]["classificationReason"]
            == "device_clock_skew"
        )

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute(
                "UPDATE locations SET lat = NULL, lng = NULL WHERE id = %s",
                (location_id,),
            )
        conn.commit()
        conn.close()
        unpinned = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time - timedelta(hours=1),
            ),
        )
        assert unpinned.status_code == 200, unpinned.text
        assert (
            unpinned.json()["checkIn"]["classificationReason"]
            == "site_missing_location_pin"
        )

    def test_retry_with_same_scan_evidence_is_idempotent(
        self, client, emp_auth, employee_id, location_id, site_qr_token
    ):
        job_id = create_canonical_job(
            location_id,
            datetime.now(timezone.utc),
            suffix="idempotent-link",
        )
        payload = site_check_in_payload(employee_id, location_id, site_qr_token)
        first = client.post(
            "/api/timesheet/site-check-in", headers=emp_auth, json=payload
        )
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status = 'cancelled' WHERE id = %s",
                (job_id,),
            )
        conn.commit()
        conn.close()
        second = client.post(
            "/api/timesheet/site-check-in", headers=emp_auth, json=payload
        )
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["checkIn"]["id"] == second.json()["checkIn"]["id"]
        assert first.json()["checkIn"]["classificationReason"] == "verified_scheduled_site"
        assert second.json()["checkIn"]["classificationReason"] == "verified_scheduled_site"
        assert first.json()["duplicate"] is False
        assert second.json()["duplicate"] is True
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (first.json()["checkIn"]["id"],),
            )
            assert cur.fetchone()[0] == job_id
        conn.close()

    def test_deleting_a_linked_job_preserves_immutable_qr_evidence(
        self, client, emp_auth, employee_id, location_id, site_qr_token
    ):
        job_id = create_canonical_job(
            location_id,
            datetime.now(timezone.utc) - timedelta(hours=1),
            suffix="delete-set-null",
        )
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        assert response.status_code == 200, response.text
        check_in_id = response.json()["checkIn"]["id"]

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
            cur.execute(
                """
                SELECT job_id, classification, classification_reason,
                       review_status
                FROM site_check_ins
                WHERE id = %s
                """,
                (check_in_id,),
            )
            assert cur.fetchone() == (
                None,
                "on_time",
                "verified_scheduled_site",
                "not_required",
            )
        conn.commit()
        conn.close()


class TestRecurringSiteCheckInSchedules:
    def test_legacy_recurring_rule_no_longer_sets_punctuality_schedule(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[0, 1, 2, 3, 4],
        )
        official_time = datetime(2026, 7, 20, 12, 5, tzinfo=timezone.utc)
        create_canonical_job(
            location_id,
            datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
            suffix="recurring-on-time",
        )
        import time_tracker_api

        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
        response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id,
                location_id,
                site_qr_token,
                scanned_at=official_time,
            ),
        )
        assert response.status_code == 200, response.text
        check_in = response.json()["checkIn"]
        assert check_in["classification"] == "on_time"
        assert check_in["classificationReason"] == "verified_scheduled_site"
        assert check_in["scheduleId"] is None
        assert check_in["scheduleRuleId"] is None
        assert check_in["scheduledStart"] is None
        assert check_in["graceMinutes"] is None
        assert (
            check_in["arrivalPolicySnapshot"]["classifiedBy"]
            == "implicit_flexible"
        )

    def test_legacy_recurring_and_exact_rows_do_not_override_implicit_flexible(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[0],
            grace_minutes=10,
        )
        import time_tracker_api

        late_time = datetime(2026, 7, 20, 12, 11, tzinfo=timezone.utc)
        create_canonical_job(
            location_id,
            datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
            suffix="recurring-override",
        )
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: late_time)
        late = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token, scanned_at=late_time
            ),
        )
        assert late.status_code == 200, late.text
        late_check_in = late.json()["checkIn"]
        assert late_check_in["classification"] == "on_time"
        assert late_check_in["classificationReason"] == "verified_scheduled_site"
        assert late_check_in["scheduleRuleId"] is None
        assert late_check_in["arrivalPolicySnapshot"]["classifiedBy"] == "implicit_flexible"

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
        conn.commit()
        conn.close()

        create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            datetime(2026, 7, 20, 12, 30, tzinfo=timezone.utc),
            grace_minutes=10,
        )
        override_time = datetime(2026, 7, 20, 12, 20, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: override_time)
        overridden = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token, scanned_at=override_time
            ),
        )
        assert overridden.status_code == 200, overridden.text
        check_in = overridden.json()["checkIn"]
        assert check_in["classification"] == "on_time"
        assert check_in["classificationReason"] == "verified_scheduled_site"
        assert check_in["scheduleId"] is None
        assert check_in["scheduleRuleId"] is None
        assert check_in["scheduledStart"] is None
        assert check_in["graceMinutes"] is None

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM site_check_in_schedules")
        conn.commit()
        conn.close()

        off_day = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: off_day)
        missing = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token, scanned_at=off_day
            ),
        )
        assert missing.status_code == 200, missing.text
        assert missing.json()["checkIn"]["classificationReason"] == "no_scheduled_job"

    def test_rule_history_is_readable_but_mutations_are_retired(
        self, client, auth, emp_auth, employee_id, location_id
    ):
        rule = create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[0, 1, 2, 3, 4],
        )
        payload = {
            "employeeId": employee_id,
            "siteId": location_id,
            "weekdays": [0, 1, 2, 3, 4],
            "localStart": "07:00",
            "startsOn": "2026-07-20",
            "endsOn": None,
            "graceMinutes": 15,
        }
        listed = client.get(
            "/api/admin/site-check-in-schedule-rules", headers=auth
        )
        assert listed.status_code == 200
        assert [row["id"] for row in listed.json()["rules"]] == [rule["id"]]
        assert listed.json()["rules"][0]["graceMinutes"] == 10

        for headers in ({}, emp_auth, auth):
            retired_post = client.post(
                "/api/admin/site-check-in-schedule-rules",
                headers=headers,
                json=payload,
            )
            retired_delete = client.delete(
                f"/api/admin/site-check-in-schedule-rules/{rule['id']}",
                headers=headers,
            )
            assert retired_post.status_code == 405
            assert retired_delete.status_code == 404

        persisted = client.get(
            "/api/admin/site-check-in-schedule-rules", headers=auth
        ).json()["rules"]
        assert [row["id"] for row in persisted] == [rule["id"]]
        assert persisted[0]["active"] is True
        assert persisted[0]["graceMinutes"] == 10

    def test_rule_api_distinguishes_open_end_from_literal_max_date(
        self, client, auth, employee_id, location_id
    ):
        open_ended = create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[0],
            ends_on=None,
        )
        max_dated = create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[1],
            ends_on="9999-12-31",
        )

        listed = client.get(
            "/api/admin/site-check-in-schedule-rules", headers=auth
        )
        assert listed.status_code == 200
        rules_by_id = {row["id"]: row for row in listed.json()["rules"]}
        assert rules_by_id[open_ended["id"]]["endsOn"] is None
        assert rules_by_id[max_dated["id"]]["endsOn"] == "9999-12-31"


class TestSiteCheckInAdminReview:
    def test_schedule_list_delete_and_review_queue(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        schedule = create_arrival_schedule(
            client,
            auth,
            employee_id,
            location_id,
            datetime.now(timezone.utc) + timedelta(days=1),
        )
        schedules = client.get(
            "/api/admin/site-check-in-schedules", headers=auth
        )
        assert schedules.status_code == 200
        assert any(row["id"] == schedule["id"] for row in schedules.json()["schedules"])
        for headers in ({}, emp_auth, auth):
            retired_delete = client.delete(
                f"/api/admin/site-check-in-schedules/{schedule['id']}",
                headers=headers,
            )
            assert retired_delete.status_code == 404
        persisted_schedules = client.get(
            "/api/admin/site-check-in-schedules", headers=auth
        ).json()["schedules"]
        assert any(
            row["id"] == schedule["id"] for row in persisted_schedules
        )

        check_in_response = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        check_in_id = check_in_response.json()["checkIn"]["id"]
        queue = client.get(
            "/api/admin/site-check-ins?review_status=pending", headers=auth
        )
        assert queue.status_code == 200
        assert any(row["id"] == check_in_id for row in queue.json()["checkIns"])

        company_today = datetime.now(ZoneInfo("America/Chicago")).date()
        filtered = client.get(
            "/api/admin/site-check-ins",
            headers=auth,
            params={
                "classification": "needs_review",
                "employeeId": employee_id,
                "siteId": location_id,
                "fromDate": company_today.isoformat(),
                "toDate": company_today.isoformat(),
            },
        )
        assert filtered.status_code == 200, filtered.text
        assert [row["id"] for row in filtered.json()["checkIns"]] == [check_in_id]

        no_employee_match = client.get(
            "/api/admin/site-check-ins?employeeId=999999", headers=auth
        )
        assert no_employee_match.status_code == 200
        assert no_employee_match.json()["checkIns"] == []

        future_date = company_today + timedelta(days=1)
        no_date_match = client.get(
            "/api/admin/site-check-ins",
            headers=auth,
            params={
                "fromDate": future_date.isoformat(),
                "toDate": future_date.isoformat(),
            },
        )
        assert no_date_match.status_code == 200
        assert no_date_match.json()["checkIns"] == []

        backwards_range = client.get(
            "/api/admin/site-check-ins",
            headers=auth,
            params={
                "fromDate": future_date.isoformat(),
                "toDate": company_today.isoformat(),
            },
        )
        assert backwards_range.status_code == 400

        forbidden = client.patch(
            f"/api/admin/site-check-ins/{check_in_id}",
            headers=emp_auth,
            json={"decision": "approved", "note": "GPS evidence verified"},
        )
        assert forbidden.status_code == 403

        blank_note = client.patch(
            f"/api/admin/site-check-ins/{check_in_id}",
            headers=auth,
            json={"decision": "approved", "note": "   "},
        )
        assert blank_note.status_code == 422

        reviewed = client.patch(
            f"/api/admin/site-check-ins/{check_in_id}",
            headers=auth,
            json={"decision": "approved", "note": "  GPS evidence verified  "},
        )
        assert reviewed.status_code == 200, reviewed.text
        first_decision = reviewed.json()["checkIn"]
        assert first_decision["reviewStatus"] == "approved"
        assert first_decision["reviewedBy"] == "Juan Canfield"
        assert first_decision["reviewNote"] == "GPS evidence verified"

        repeated = client.patch(
            f"/api/admin/site-check-ins/{check_in_id}",
            headers=auth,
            json={"decision": "rejected", "note": "Replace the first decision"},
        )
        assert repeated.status_code == 409, repeated.text

        persisted_response = client.get(
            "/api/admin/site-check-ins",
            headers=auth,
            params={"employeeId": employee_id, "siteId": location_id},
        )
        assert persisted_response.status_code == 200, persisted_response.text
        persisted = next(
            row
            for row in persisted_response.json()["checkIns"]
            if row["id"] == check_in_id
        )
        assert {
            key: persisted[key]
            for key in ("reviewStatus", "reviewedBy", "reviewedAt", "reviewNote")
        } == {
            key: first_decision[key]
            for key in ("reviewStatus", "reviewedBy", "reviewedAt", "reviewNote")
        }

    def test_locations_publish_site_ids_and_policy(
        self, client, emp_auth, location_id, monkeypatch
    ):
        import time_tracker_api

        fixed_utc = datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc)
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: fixed_utc)
        response = client.get("/api/timesheet/locations", headers=emp_auth)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["sites"][0]["id"] == location_id
        assert payload["siteCheckInPolicy"] == {
            "geofenceRadiusM": 50,
            "maxAccuracyM": 100,
            "deviceClockSkewReviewSeconds": 600,
            "scheduleTimezone": "America/Chicago",
            "companyDate": "2026-07-17",
            "offlineQueue": False,
        }
