"""Read-only QR arrival versus paid-time reconciliation coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conftest import _raw_conn


SITE_LATITUDE = 39.1203
SITE_LONGITUDE = -88.54335
TEST_SHIFT_NOTE = "reconciliation-test"
SECOND_SITE_ADDRESS = "456 Oak St, Effingham"


@pytest.fixture(autouse=True)
def isolate_reconciliation_data(setup_db):
    def clean() -> None:
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM site_check_in_schedule_rules")
            cur.execute("DELETE FROM site_check_in_schedules")
            cur.execute("DELETE FROM shifts WHERE notes = %s", (TEST_SHIFT_NOTE,))
            cur.execute(
                "DELETE FROM locations WHERE address = %s",
                (SECOND_SITE_ADDRESS,),
            )
            cur.execute(
                """
                UPDATE locations
                SET check_in_token_nonce = NULL,
                    check_in_token_rotated_at = NULL
                """
            )
        conn.commit()
        conn.close()

    clean()
    yield
    clean()


def create_qr_token(client, auth, location_id):
    response = client.post(
        f"/api/admin/locations/{location_id}/check-in-qr",
        headers=auth,
        json={"rotate": False},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def create_exact_schedule(client, auth, employee_id, location_id, scheduled_start):
    response = client.post(
        "/api/admin/site-check-in-schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "scheduledStart": scheduled_start.isoformat(),
            "graceMinutes": 10,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["schedule"]


def create_weekly_rule(client, auth, employee_id, location_id):
    response = client.post(
        "/api/admin/site-check-in-schedule-rules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "weekdays": [0],
            "localStart": "07:00",
            "startsOn": "2026-07-20",
            "graceMinutes": 10,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["rule"]


def record_qr_check_in(
    client,
    emp_auth,
    employee_id,
    location_id,
    token,
    checked_in_at,
    *,
    accuracy=5.0,
):
    response = client.post(
        "/api/timesheet/site-check-in",
        headers=emp_auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "token": token,
            "scannedAt": checked_in_at.isoformat(),
            "latitude": SITE_LATITUDE,
            "longitude": SITE_LONGITUDE,
            "accuracy": accuracy,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["checkIn"]


def insert_shift(
    employee_id,
    clock_in,
    *,
    location_id=None,
    location_label="Office Maids HQ",
):
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label, clock_in, clock_out,
                total_hours, notes, local_date, timezone
            )
            VALUES (%s, %s, %s, %s, %s, 1.00, %s, %s, 'America/Chicago')
            RETURNING id
            """,
            (
                employee_id,
                location_id,
                location_label,
                clock_in,
                clock_in + timedelta(hours=1),
                TEST_SHIFT_NOTE,
                clock_in.astimezone(timezone.utc).date(),
            ),
        )
        shift_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return shift_id


def insert_visit(shift_id, location_id, arrival_time):
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT address, customer_name FROM locations WHERE id = %s",
            (location_id,),
        )
        address, customer_name = cur.fetchone()
        cur.execute(
            """
            INSERT INTO visits (
                shift_id, location_id, location_label, customer_name, arrival_time
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (shift_id, location_id, address, customer_name, arrival_time),
        )
    conn.commit()
    conn.close()


def site_address(location_id):
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT address FROM locations WHERE id = %s", (location_id,))
        address = cur.fetchone()[0]
    conn.close()
    return address


def create_second_site():
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO locations (
                address, customer_name, lat, lng,
                rate, rate_type, expected_hours
            )
            VALUES (%s, 'Second Test Customer', %s, %s, 125.00, 'per_visit', 2.0)
            RETURNING id
            """,
            (SECOND_SITE_ADDRESS, SITE_LATITUDE, SITE_LONGITUDE),
        )
        location_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return location_id


def reconciliation_source_snapshot():
    conn = _raw_conn()
    statements = [
        """
        SELECT id, employee_id, location_id, location_label, clock_in, clock_out,
               total_hours, notes
        FROM shifts ORDER BY id
        """,
        """
        SELECT id, shift_id, location_id, location_label, arrival_time
        FROM visits ORDER BY id
        """,
        """
        SELECT id, employee_id, location_id, server_checked_in_at,
               classification, review_status, reviewed_by, reviewed_at, review_note
        FROM site_check_ins ORDER BY id
        """,
        """
        SELECT id, employee_id, location_id, scheduled_start, grace_minutes
        FROM site_check_in_schedules ORDER BY id
        """,
        """
        SELECT id, employee_id, location_id, weekdays, local_start_time,
               starts_on, ends_on, active, updated_at
        FROM site_check_in_schedule_rules ORDER BY id
        """,
    ]
    snapshot = []
    with conn.cursor() as cur:
        for statement in statements:
            cur.execute(statement)
            snapshot.append(cur.fetchall())
    conn.close()
    return snapshot


class TestArrivalTimecardReconciliation:
    def test_endpoint_is_admin_only_and_bounds_date_queries(
        self, client, auth, emp_auth
    ):
        forbidden = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=emp_auth,
        )
        assert forbidden.status_code == 403

        backwards = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-19"},
        )
        assert backwards.status_code == 400

        too_wide = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-01", "toDate": "2026-08-01"},
        )
        assert too_wide.status_code == 400

        invalid_outcome = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"outcome": "payroll_changed"},
        )
        assert invalid_outcome.status_code == 400

    def test_exact_schedule_overrides_weekly_rule_and_matches_clock_in(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        current_time = {"value": datetime(2026, 7, 20, 12, 5, tzinfo=timezone.utc)}
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time["value"])
        scheduled_start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        create_weekly_rule(client, auth, employee_id, location_id)
        exact = create_exact_schedule(
            client, auth, employee_id, location_id, scheduled_start
        )
        token = create_qr_token(client, auth, location_id)
        record_qr_check_in(
            client,
            emp_auth,
            employee_id,
            location_id,
            token,
            current_time["value"],
        )
        insert_shift(
            employee_id,
            scheduled_start + timedelta(minutes=3),
            location_id=location_id,
            location_label=site_address(location_id),
        )

        current_time["value"] = scheduled_start + timedelta(minutes=20)
        source_before = reconciliation_source_snapshot()
        response = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["readOnly"] is True
        assert payload["gapThresholdMinutes"] == 15
        assert payload["summary"] == {
            "total": 1,
            "matched": 1,
            "pending": 0,
            "exceptions": 0,
            "byOutcome": {
                "matched": 1,
                "missing_both": 0,
                "missing_qr": 0,
                "missing_time_entry": 0,
                "pending": 0,
                "qr_needs_review": 0,
                "qr_rejected": 0,
                "site_mismatch": 0,
                "time_gap": 0,
            },
        }
        row = payload["rows"][0]
        assert row["scheduleSource"] == "exact"
        assert row["scheduleId"] == exact["id"]
        assert row["scheduleRuleId"] is None
        assert row["outcome"] == "matched"
        assert row["timecardDifferenceMinutes"] == -2.0
        assert row["timecardEvent"]["eventType"] == "clock_in"
        assert row["timecardEvent"]["siteId"] == location_id
        assert reconciliation_source_snapshot() == source_before

    def test_explicit_arrived_event_wins_and_wrong_site_is_flagged(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        current_time = {"value": datetime(2026, 7, 20, 12, 5, tzinfo=timezone.utc)}
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time["value"])
        token = create_qr_token(client, auth, location_id)
        first_start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        second_start = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
        create_exact_schedule(client, auth, employee_id, location_id, first_start)
        create_exact_schedule(client, auth, employee_id, location_id, second_start)

        record_qr_check_in(
            client, emp_auth, employee_id, location_id, token, current_time["value"]
        )
        first_shift = insert_shift(
            employee_id,
            first_start - timedelta(minutes=30),
            location_label="Office Maids HQ",
        )
        insert_visit(first_shift, location_id, first_start + timedelta(minutes=4))

        current_time["value"] = second_start + timedelta(minutes=5)
        record_qr_check_in(
            client, emp_auth, employee_id, location_id, token, current_time["value"]
        )
        insert_shift(
            employee_id,
            second_start + timedelta(minutes=2),
            location_label="Office Maids HQ",
        )

        current_time["value"] = second_start + timedelta(minutes=20)
        response = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-21"},
        )
        assert response.status_code == 200, response.text
        rows = {row["scheduledStart"][:10]: row for row in response.json()["rows"]}
        first = rows["2026-07-20"]
        assert first["outcome"] == "matched"
        assert first["timecardEvent"]["eventType"] == "visit"
        assert first["timecardEvent"]["siteId"] == location_id
        assert first["timecardDifferenceMinutes"] == -1.0

        second = rows["2026-07-21"]
        assert second["outcome"] == "site_mismatch"
        assert second["timecardEvent"]["eventType"] == "clock_in"
        assert second["timecardEvent"]["siteId"] is None
        assert second["hasException"] is True

    def test_wrong_site_event_is_reserved_for_its_scheduled_stop(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        first_start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        second_start = first_start + timedelta(hours=1)
        current_time = {"value": first_start + timedelta(minutes=5)}
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time["value"])
        second_site_id = create_second_site()

        create_exact_schedule(client, auth, employee_id, location_id, first_start)
        create_exact_schedule(client, auth, employee_id, second_site_id, second_start)
        first_token = create_qr_token(client, auth, location_id)
        second_token = create_qr_token(client, auth, second_site_id)
        record_qr_check_in(
            client,
            emp_auth,
            employee_id,
            location_id,
            first_token,
            current_time["value"],
        )
        current_time["value"] = second_start + timedelta(minutes=5)
        record_qr_check_in(
            client,
            emp_auth,
            employee_id,
            second_site_id,
            second_token,
            current_time["value"],
        )
        insert_shift(
            employee_id,
            second_start + timedelta(minutes=3),
            location_id=second_site_id,
            location_label=site_address(second_site_id),
        )

        current_time["value"] = second_start + timedelta(hours=1)
        response = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
        )
        assert response.status_code == 200, response.text
        rows = {row["siteId"]: row for row in response.json()["rows"]}

        assert rows[location_id]["outcome"] == "missing_time_entry"
        assert rows[location_id]["timecardEvent"] is None
        assert rows[second_site_id]["outcome"] == "matched"
        assert rows[second_site_id]["timecardEvent"]["siteId"] == second_site_id

    def test_missing_evidence_and_pending_rows_are_separated(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        current_time = {"value": datetime(2026, 7, 20, 12, 5, tzinfo=timezone.utc)}
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time["value"])
        token = create_qr_token(client, auth, location_id)
        starts = [
            datetime(2026, 7, day, 12, 0, tzinfo=timezone.utc)
            for day in range(20, 24)
        ]
        for scheduled_start in starts:
            create_exact_schedule(
                client, auth, employee_id, location_id, scheduled_start
            )

        record_qr_check_in(
            client, emp_auth, employee_id, location_id, token, current_time["value"]
        )
        insert_shift(
            employee_id,
            starts[1] + timedelta(minutes=3),
            location_id=location_id,
            location_label=site_address(location_id),
        )
        current_time["value"] = starts[2] + timedelta(minutes=20)

        response = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-23"},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        outcomes = {
            row["scheduledStart"][:10]: row["outcome"] for row in payload["rows"]
        }
        assert outcomes == {
            "2026-07-20": "missing_time_entry",
            "2026-07-21": "missing_qr",
            "2026-07-22": "missing_both",
            "2026-07-23": "pending",
        }
        assert payload["summary"]["total"] == 4
        assert payload["summary"]["exceptions"] == 3
        assert payload["summary"]["pending"] == 1

        exceptions = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={
                "fromDate": "2026-07-20",
                "toDate": "2026-07-23",
                "exceptionsOnly": "true",
            },
        )
        assert exceptions.status_code == 200, exceptions.text
        assert exceptions.json()["returned"] == 3
        assert all(row["hasException"] for row in exceptions.json()["rows"])

    def test_time_gap_and_unresolved_qr_evidence_remain_exceptions(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        current_time = {"value": datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)}
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time["value"])
        token = create_qr_token(client, auth, location_id)
        first_start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        second_start = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
        create_exact_schedule(client, auth, employee_id, location_id, first_start)
        create_exact_schedule(client, auth, employee_id, location_id, second_start)

        record_qr_check_in(
            client,
            emp_auth,
            employee_id,
            location_id,
            token,
            current_time["value"],
            accuracy=150.0,
        )
        insert_shift(
            employee_id,
            first_start + timedelta(minutes=2),
            location_id=location_id,
            location_label=site_address(location_id),
        )

        current_time["value"] = second_start
        record_qr_check_in(
            client, emp_auth, employee_id, location_id, token, current_time["value"]
        )
        insert_shift(
            employee_id,
            second_start + timedelta(minutes=30),
            location_id=location_id,
            location_label=site_address(location_id),
        )
        current_time["value"] = second_start + timedelta(hours=1)

        response = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-21"},
        )
        assert response.status_code == 200, response.text
        rows = {row["scheduledStart"][:10]: row for row in response.json()["rows"]}
        assert rows["2026-07-20"]["outcome"] == "qr_needs_review"
        assert rows["2026-07-21"]["outcome"] == "time_gap"
        assert rows["2026-07-21"]["timecardDifferenceMinutes"] == 30.0

        rejected = client.patch(
            f"/api/admin/site-check-ins/{rows['2026-07-20']['qrCheckIn']['id']}",
            headers=auth,
            json={"decision": "rejected", "note": "Location evidence rejected"},
        )
        assert rejected.status_code == 200, rejected.text
        after_rejection = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
        )
        assert after_rejection.status_code == 200, after_rejection.text
        assert after_rejection.json()["rows"][0]["outcome"] == "qr_rejected"

    def test_ended_weekly_rule_keeps_history_without_creating_future_rows(
        self,
        client,
        auth,
        employee_id,
        location_id,
        monkeypatch,
    ):
        import time_tracker_api

        rule = create_weekly_rule(client, auth, employee_id, location_id)
        ended_at = datetime(2026, 7, 20, 20, 0, tzinfo=timezone.utc)
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE site_check_in_schedule_rules
                SET active = false, updated_at = %s
                WHERE id = %s
                """,
                (ended_at, rule["id"]),
            )
        conn.commit()
        conn.close()
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        )

        historical = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
        )
        assert historical.status_code == 200, historical.text
        assert historical.json()["summary"]["total"] == 1
        assert historical.json()["rows"][0]["outcome"] == "missing_both"

        future = client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-27", "toDate": "2026-07-27"},
        )
        assert future.status_code == 200, future.text
        assert future.json()["rows"] == []


def test_frontend_exposes_read_only_arrival_timecard_reconciliation():
    html = (Path(__file__).parent / "timetracker-mobile.html").read_text()
    assert "Arrival vs. Timecard" in html
    assert "This does not change timecards or wages" in html
    assert "loadArrivalTimecardReconciliation" in html
    assert "/admin/site-check-in-reconciliation?" in html
    assert "filters.set('exceptionsOnly', 'true')" in html
    assert "filters.set('outcome', selectedView)" in html
    assert "timecardDifferenceMinutes" in html
