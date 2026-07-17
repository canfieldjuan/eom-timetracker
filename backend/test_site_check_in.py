"""End-to-end contract tests for authenticated QR site check-in."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conftest import _raw_conn


SITE_LATITUDE = 39.1203
SITE_LONGITUDE = -88.54335


@pytest.fixture(autouse=True)
def isolate_site_check_in_data(setup_db):
    def clean() -> None:
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM site_check_in_schedule_rules")
            cur.execute("DELETE FROM site_check_in_schedules")
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


def create_site_qr(client, auth, location_id, *, rotate=False):
    response = client.post(
        f"/api/admin/locations/{location_id}/check-in-qr",
        headers=auth,
        json={"rotate": rotate},
    )
    assert response.status_code == 200, response.text
    return response.json()


def create_arrival_schedule(
    client,
    auth,
    employee_id,
    location_id,
    scheduled_start,
    *,
    grace_minutes=10,
):
    response = client.post(
        "/api/admin/site-check-in-schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "scheduledStart": scheduled_start.isoformat(),
            "graceMinutes": grace_minutes,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["schedule"]


def create_recurring_schedule_rule(
    client,
    auth,
    employee_id,
    location_id,
    *,
    weekdays,
    local_start="07:00",
    starts_on="2026-07-20",
    ends_on=None,
    grace_minutes=10,
):
    response = client.post(
        "/api/admin/site-check-in-schedule-rules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "weekdays": weekdays,
            "localStart": local_start,
            "startsOn": starts_on,
            "endsOn": ends_on,
            "graceMinutes": grace_minutes,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["rule"]


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
        assert first["checkInUrl"].startswith("http://testserver/")
        assert "?checkIn=eom1." in first["checkInUrl"]
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
        assert "expired" in expired.json()["error"]

        current = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, rotated["token"]
            ),
        )
        assert current.status_code == 200, current.text

    def test_server_timestamp_and_exact_schedule_produce_on_time(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        before = datetime.now(timezone.utc)
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
        assert check_in["classificationReason"] == "within_grace_period"
        assert check_in["reviewStatus"] == "not_required"

    def test_after_grace_period_is_late(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
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
        assert response.json()["checkIn"]["classification"] == "late"
        assert response.json()["checkIn"]["classificationReason"] == "after_grace_period"

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

    def test_missing_schedule_and_device_clock_skew_need_review(
        self, client, auth, emp_auth, employee_id, location_id, site_qr_token
    ):
        missing_schedule = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(employee_id, location_id, site_qr_token),
        )
        assert missing_schedule.status_code == 200, missing_schedule.text
        assert missing_schedule.json()["checkIn"]["classificationReason"] == "no_matching_schedule"

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

    def test_retry_with_same_scan_evidence_is_idempotent(
        self, client, emp_auth, employee_id, location_id, site_qr_token
    ):
        payload = site_check_in_payload(employee_id, location_id, site_qr_token)
        first = client.post(
            "/api/timesheet/site-check-in", headers=emp_auth, json=payload
        )
        second = client.post(
            "/api/timesheet/site-check-in", headers=emp_auth, json=payload
        )
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["checkIn"]["id"] == second.json()["checkIn"]["id"]
        assert first.json()["duplicate"] is False
        assert second.json()["duplicate"] is True


class TestRecurringSiteCheckInSchedules:
    def test_weekday_rule_computes_chicago_occurrence_and_classifies_on_time(
        self,
        client,
        auth,
        emp_auth,
        employee_id,
        location_id,
        site_qr_token,
        monkeypatch,
    ):
        rule = create_recurring_schedule_rule(
            client,
            auth,
            employee_id,
            location_id,
            weekdays=[0, 1, 2, 3, 4],
        )
        official_time = datetime(2026, 7, 20, 12, 5, tzinfo=timezone.utc)
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
        assert check_in["scheduleId"] is None
        assert check_in["scheduleRuleId"] == rule["id"]
        assert check_in["scheduledStart"] == "2026-07-20T12:00:00Z"

    def test_rule_respects_grace_weekdays_and_exact_schedule_override(
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
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: late_time)
        late = client.post(
            "/api/timesheet/site-check-in",
            headers=emp_auth,
            json=site_check_in_payload(
                employee_id, location_id, site_qr_token, scanned_at=late_time
            ),
        )
        assert late.status_code == 200, late.text
        assert late.json()["checkIn"]["classification"] == "late"

        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
        conn.commit()
        conn.close()

        exact = create_arrival_schedule(
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
        assert check_in["scheduleId"] == exact["id"]
        assert check_in["scheduleRuleId"] is None

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
        assert missing.json()["checkIn"]["classificationReason"] == "no_matching_schedule"

    def test_rule_admin_crud_is_validated_idempotent_and_soft_deleted(
        self, client, auth, emp_auth, employee_id, location_id
    ):
        payload = {
            "employeeId": employee_id,
            "siteId": location_id,
            "weekdays": [0, 1, 2, 3, 4],
            "localStart": "07:00",
            "startsOn": "2026-07-20",
            "endsOn": None,
            "graceMinutes": 10,
        }
        forbidden = client.post(
            "/api/admin/site-check-in-schedule-rules",
            headers=emp_auth,
            json=payload,
        )
        assert forbidden.status_code == 403

        duplicate_days = client.post(
            "/api/admin/site-check-in-schedule-rules",
            headers=auth,
            json={**payload, "weekdays": [0, 0]},
        )
        assert duplicate_days.status_code == 422
        backwards = client.post(
            "/api/admin/site-check-in-schedule-rules",
            headers=auth,
            json={**payload, "endsOn": "2026-07-19"},
        )
        assert backwards.status_code == 400

        first = client.post(
            "/api/admin/site-check-in-schedule-rules", headers=auth, json=payload
        )
        assert first.status_code == 200, first.text
        rule = first.json()["rule"]
        assert rule["weekdays"] == [0, 1, 2, 3, 4]
        assert rule["localStart"] == "07:00"
        assert rule["timezone"] == "America/Chicago"
        assert rule["endsOn"] is None

        updated = client.post(
            "/api/admin/site-check-in-schedule-rules",
            headers=auth,
            json={**payload, "graceMinutes": 15},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["rule"]["id"] == rule["id"]
        assert updated.json()["rule"]["graceMinutes"] == 15

        active = client.get(
            "/api/admin/site-check-in-schedule-rules", headers=auth
        )
        assert active.status_code == 200
        assert [row["id"] for row in active.json()["rules"]] == [rule["id"]]

        ended = client.delete(
            f"/api/admin/site-check-in-schedule-rules/{rule['id']}", headers=auth
        )
        assert ended.status_code == 200
        active_after = client.get(
            "/api/admin/site-check-in-schedule-rules", headers=auth
        )
        assert active_after.json()["rules"] == []
        history = client.get(
            "/api/admin/site-check-in-schedule-rules?activeOnly=false", headers=auth
        )
        assert history.status_code == 200
        assert history.json()["rules"][0]["active"] is False

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

        assert open_ended["endsOn"] is None
        assert max_dated["endsOn"] == "9999-12-31"

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
        deleted = client.delete(
            f"/api/admin/site-check-in-schedules/{schedule['id']}", headers=auth
        )
        assert deleted.status_code == 200

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
        assert reviewed.json()["checkIn"]["reviewStatus"] == "approved"
        assert reviewed.json()["checkIn"]["reviewedBy"] == "Juan Canfield"
        assert reviewed.json()["checkIn"]["reviewNote"] == "GPS evidence verified"

    def test_locations_publish_site_ids_and_policy(self, client, emp_auth, location_id):
        response = client.get("/api/timesheet/locations", headers=emp_auth)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["sites"][0]["id"] == location_id
        assert payload["siteCheckInPolicy"] == {
            "geofenceRadiusM": 50,
            "maxAccuracyM": 100,
            "deviceClockSkewReviewSeconds": 600,
            "scheduleTimezone": "America/Chicago",
            "offlineQueue": False,
        }


def test_frontend_contains_scan_then_tap_contract():
    html = (Path(__file__).parent / "timetracker-mobile.html").read_text()
    assert "siteCheckInButton" in html
    assert "queryParams.get('checkIn')" in html
    assert "'/timesheet/site-check-in/resolve'" in html
    assert "'/timesheet/site-check-in'" in html
    assert "await getCurrentCoordinates()" in html
    assert "token: state.pendingSiteCheckIn.token" in html
    assert "scannedAt: state.pendingSiteCheckIn.scannedAt" in html
    assert "saveRecurringSiteCheckInSchedule" in html
    assert "'/admin/site-check-in-schedule-rules'" in html
    assert "siteCheckInWeekday" in html
