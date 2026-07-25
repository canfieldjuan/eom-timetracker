"""End-to-end contract tests for authenticated QR site check-in."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
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

    def test_server_timestamp_and_exact_schedule_produce_on_time(
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
        assert check_in["classificationReason"] == "within_grace_period"
        assert check_in["reviewStatus"] == "not_required"
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM site_check_ins WHERE id = %s",
                (check_in["id"],),
            )
            assert cur.fetchone()[0] == job_id
        conn.close()

    def test_after_grace_period_is_late(
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
