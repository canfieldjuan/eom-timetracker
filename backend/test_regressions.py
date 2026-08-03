"""
Regression tests for bugs fixed on the claude/fix-bugs-integration-bBLKA
branch. Each test is named for the bug it locks in so a failure makes the
break obvious.

Run:  cd backend && pytest -v test_regressions.py
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest


SITE_GPS = {"latitude": 39.1203, "longitude": -88.54335}


def _access_log_entry(
    timestamp: str,
    action: str,
    *,
    endpoint: str = "/api/admin/example",
    event_id: str | None = None,
) -> dict:
    entry = {
        "timestamp": timestamp,
        "action": action,
        "allowed": True,
        "reason": "pytest",
        "clientIP": "203.0.113.10",
        "userAgent": "pytest",
        "endpoint": endpoint,
        "method": "GET",
    }
    if event_id is not None:
        entry["eventId"] = event_id
    return entry


def _insert_access_log_entry(api, date_text: str, entry: dict) -> None:
    event_id = str(
        entry.get("eventId")
        or f"test-{date_text}-{entry['action']}-{entry['timestamp']}"
    )
    stored_entry = {**entry, "eventId": event_id}
    api.db.execute(
        """
        INSERT INTO access_log_entries (
            event_id, logged_at, local_date, action, allowed, reason,
            client_ip, user_agent, endpoint, method, entry
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            event_id,
            api.parse_utc_iso(stored_entry["timestamp"]),
            date.fromisoformat(date_text),
            stored_entry["action"],
            stored_entry["allowed"],
            stored_entry["reason"],
            stored_entry["clientIP"],
            stored_entry["userAgent"],
            stored_entry["endpoint"],
            stored_entry["method"],
            api.psycopg2.extras.Json(stored_entry),
        ),
    )


def _ensure_clocked_out(client, headers) -> None:
    """Best-effort cleanup: close any open shift for the auth'd user. Ignore
    errors (no-op when nothing is open)."""
    client.post("/api/timesheet/clock-out", headers=headers, json=SITE_GPS)


# ===============================================================================
# admin_list_employees -- SQL aggregation refactor
# Originally three full table scans + per-employee Python filter; now a single
# CTE-based SQL query. Bug class: silent regression on response shape or hours.
# ===============================================================================

class TestAdminListEmployeesAggregation:
    def test_completed_shift_counts_in_total_hours_and_total_shifts(
        self, client, auth, emp_auth
    ):
        _ensure_clocked_out(client, emp_auth)
        ci = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham", **SITE_GPS},
        )
        assert ci.status_code == 200, ci.text
        co = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"notes": "regression-aggregate-closed", **SITE_GPS},
        )
        assert co.status_code == 200, co.text

        r = client.get("/api/admin/employees", headers=auth)
        assert r.status_code == 200, r.text
        rows = r.json()["employees"]
        catalina = next(e for e in rows if e["name"] == "Catalina Gomez")
        # All ten keys the original endpoint exposed must still be there.
        for key in (
            "id", "name", "role", "active", "created", "lastLogin",
            "totalHours", "totalShifts", "lastGps", "hourlyRate",
        ):
            assert key in catalina, f"Missing key: {key}"
        assert catalina["totalShifts"] >= 1
        assert isinstance(catalina["totalHours"], (int, float))

    def test_open_shift_contributes_elapsed_time(self, client, auth, emp_auth):
        """The SQL aggregation must compute live elapsed hours for an open
        shift (CASE on clock_out IS NULL). We backdate the shift by 1h via the
        admin entry-adjust endpoint so the assertion is deterministic."""
        import time_tracker_api as tta

        _ensure_clocked_out(client, emp_auth)
        ci = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham", **SITE_GPS},
        )
        assert ci.status_code == 200, ci.text
        entry_id = ci.json()["entry"]["id"]

        local_now = datetime.now(tta.APP_TIMEZONE)
        one_hour_ago = (local_now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        adj = client.patch(
            f"/api/admin/entries/{entry_id}",
            headers=auth,
            json={"clockIn": one_hour_ago},
        )
        assert adj.status_code == 200, adj.text

        try:
            r = client.get("/api/admin/employees", headers=auth)
            assert r.status_code == 200, r.text
            catalina = next(e for e in r.json()["employees"] if e["name"] == "Catalina Gomez")
            # Open shift backdated 1h must show at least ~0.95h once rounding
            # and any intra-test latency are accounted for.
            assert catalina["totalHours"] >= 0.9, catalina
        finally:
            _ensure_clocked_out(client, emp_auth)


# ===============================================================================
# my_timesheet_hours -- now uses entry_hours() instead of stored totalHours
# ===============================================================================

class TestMyTimesheetHoursLiveCalc:
    def test_open_shift_contributes_to_weekly_hours(self, client, auth, emp_auth):
        import time_tracker_api as tta

        _ensure_clocked_out(client, emp_auth)
        ci = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham", **SITE_GPS},
        )
        assert ci.status_code == 200, ci.text
        entry_id = ci.json()["entry"]["id"]

        local_now = datetime.now(tta.APP_TIMEZONE)
        one_hour_ago = (local_now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        adj = client.patch(
            f"/api/admin/entries/{entry_id}",
            headers=auth,
            json={"clockIn": one_hour_ago},
        )
        assert adj.status_code == 200, adj.text

        try:
            r = client.get("/api/timesheet/my-hours", headers=emp_auth)
            assert r.status_code == 200, r.text
            body = r.json()
            # Pre-fix this would have been 0 because totalHours is None on an
            # open shift.
            assert body["weeklyHours"] >= 0.9, body
        finally:
            _ensure_clocked_out(client, emp_auth)


class TestHoursReportCanonicalHours:
    def test_report_recomputes_closed_shift_duration_from_clock_span(
        self,
        client,
        auth,
        employee_id,
        location_id,
    ):
        import db

        shift_id = db.execute_returning(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label,
                clock_in, clock_out, total_hours, notes, local_date
            )
            VALUES (
                %s, %s, '123 Main St, Effingham',
                TIMESTAMPTZ '2048-01-13 08:00:00-06',
                TIMESTAMPTZ '2048-01-13 10:30:00-06',
                0.25, 'hours report canonical duration proof',
                DATE '2048-01-13'
            )
            RETURNING id
            """,
            (employee_id, location_id),
        )
        try:
            response = client.get(
                "/api/admin/reports/hours",
                headers=auth,
                params={
                    "period": "day",
                    "date": "2048-01-13",
                    "employee_id": employee_id,
                },
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["totalHours"] == 2.5
            assert body["totalShifts"] == 1
            assert body["rows"][0]["hours"] == 2.5
            assert body["summary"] == [
                {
                    "employeeId": employee_id,
                    "employeeName": "Catalina Gomez",
                    "totalHours": 2.5,
                    "totalShifts": 1,
                }
            ]
        finally:
            db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))


# ===============================================================================
# Pydantic max_length on free-text fields
# ===============================================================================

class TestRequestFieldBounds:
    def test_clock_in_rejects_oversized_location(self, client, emp_auth):
        r = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "x" * 600},
        )
        assert r.status_code == 422, r.text

    def test_clock_in_rejects_oversized_notes(self, client, emp_auth):
        r = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "ok", "notes": "n" * 3000},
        )
        assert r.status_code == 422, r.text

    def test_clock_out_rejects_oversized_override_reason(self, client, emp_auth):
        r = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"gpsOverrideReason": "r" * 300},
        )
        assert r.status_code == 422, r.text


# ===============================================================================
# admin_auto_link_jobs -- interval-aware matching and job_id IS NULL guard
# ===============================================================================

def _insert_auto_link_job(
    *,
    location_id,
    service_date,
    scheduled_start=None,
    scheduled_end=None,
    source_key=None,
    customer_name="Auto Link Regression",
):
    import db

    return db.execute_returning(
        """
        INSERT INTO jobs (
            location_id, customer_name, scheduled_date, scheduled_start,
            scheduled_end, notes, status, source_key
        )
        VALUES (%s, %s, %s, %s, %s, '', 'scheduled', %s)
        RETURNING id
        """,
        (
            location_id,
            customer_name,
            service_date,
            scheduled_start,
            scheduled_end,
            source_key,
        ),
    )


def _insert_auto_link_shift(
    *,
    employee_id,
    location_id,
    service_date,
    clock_in,
    clock_out,
):
    import db

    return db.execute_returning(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, clock_out,
            total_hours, notes, local_date, timezone, time_category
        )
        VALUES (
            %s, %s, '123 Main St, Effingham', %s, %s, 2,
            'interval-aware auto-link regression', %s,
            'America/Chicago', 'productive'
        )
        RETURNING id
        """,
        (employee_id, location_id, clock_in, clock_out, service_date),
    )


def _delete_auto_link_rows(*, job_ids, shift_ids):
    import db

    db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
    db.execute("DELETE FROM jobs WHERE id = ANY(%s)", (job_ids,))


class TestAutoLinkServiceWindows:
    def test_overnight_job_links_shift_that_starts_on_second_local_date(
        self, client, auth, employee_id, location_id
    ):
        import db

        product_zone = ZoneInfo("America/Chicago")
        job_start = datetime(2036, 2, 10, 23, tzinfo=product_zone)
        job_end = job_start + timedelta(hours=2)
        shift_start = job_start + timedelta(hours=1, minutes=15)
        shift_end = shift_start + timedelta(minutes=30)
        job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=job_start.date(),
            scheduled_start=job_start,
            scheduled_end=job_end,
            source_key="a" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=shift_start.date(),
            clock_in=shift_start,
            clock_out=shift_end,
        )
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == job_id
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])

    def test_shift_started_previous_day_links_after_midnight_job(
        self, client, auth, employee_id, location_id
    ):
        import db

        product_zone = ZoneInfo("America/Chicago")
        job_start = datetime(2036, 2, 12, 0, 15, tzinfo=product_zone)
        job_end = job_start + timedelta(hours=1)
        shift_start = job_start - timedelta(minutes=30)
        shift_end = shift_start + timedelta(hours=1)
        job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=job_start.date(),
            scheduled_start=job_start,
            scheduled_end=job_end,
            source_key="b" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=shift_start.date(),
            clock_in=shift_start,
            clock_out=shift_end,
        )
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == job_id
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])

    def test_cross_midnight_candidate_is_deduplicated_before_uniqueness(
        self, client, auth, employee_id, location_id, monkeypatch
    ):
        import db

        product_zone = ZoneInfo("America/Chicago")
        job_start = datetime(2036, 2, 13, 22, 30, tzinfo=product_zone)
        job_end = job_start + timedelta(hours=3)
        shift_start = job_start + timedelta(hours=1)
        shift_end = shift_start + timedelta(hours=1)
        job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=job_start.date(),
            scheduled_start=job_start,
            scheduled_end=job_end,
            source_key="c" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=shift_start.date(),
            clock_in=shift_start,
            clock_out=shift_end,
        )
        real_query_all = db.query_all

        def query_with_duplicate_job(sql, params=()):
            rows = real_query_all(sql, params)
            if "FROM jobs j" in sql and "j.status != 'cancelled'" in sql:
                duplicate = [row for row in rows if int(row["id"]) == job_id]
                return [*rows, *duplicate]
            return rows

        monkeypatch.setattr(db, "query_all", query_with_duplicate_job)
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert response.json()["linkedCount"] >= 1
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == job_id
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])

    def test_overnight_unique_name_job_keeps_legacy_resolution(
        self, client, auth, employee_id, location_id
    ):
        import db

        product_zone = ZoneInfo("America/Chicago")
        job_start = datetime(2036, 2, 14, 23, tzinfo=product_zone)
        job_end = job_start + timedelta(hours=2)
        shift_start = job_start + timedelta(hours=1, minutes=15)
        shift_end = shift_start + timedelta(minutes=30)
        customer_name = str(
            db.query_one(
                """
                SELECT COALESCE(c.name, l.customer_name, l.address) AS customer_name
                FROM locations l
                LEFT JOIN customers c ON c.id = l.customer_id
                WHERE l.id = %s
                """,
                (location_id,),
            )["customer_name"]
        )
        job_id = _insert_auto_link_job(
            location_id=None,
            customer_name=customer_name,
            service_date=job_start.date(),
            scheduled_start=job_start,
            scheduled_end=job_end,
            source_key="d" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=shift_start.date(),
            clock_in=shift_start,
            clock_out=shift_end,
        )
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == job_id
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])

    def test_nonoverlapping_timed_calendar_job_is_not_linked(
        self, client, auth, employee_id, location_id
    ):
        import db

        service_date = datetime(2036, 2, 10).date()
        shift_start = datetime(2036, 2, 10, 14, tzinfo=timezone.utc)
        shift_end = datetime(2036, 2, 10, 16, tzinfo=timezone.utc)
        job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=service_date,
            scheduled_start=shift_end,
            scheduled_end=shift_end + timedelta(hours=2),
            source_key="e" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=service_date,
            clock_in=shift_start,
            clock_out=shift_end,
        )
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert (
                db.query_one(
                    "SELECT job_id FROM shifts WHERE id = %s",
                    (shift_id,),
                )["job_id"]
                is None
            )
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])

    def test_overlap_filter_runs_before_existing_uniqueness_rule(
        self, client, auth, employee_id, location_id
    ):
        import db

        service_date = datetime(2036, 2, 11).date()
        shift_start = datetime(2036, 2, 11, 15, tzinfo=timezone.utc)
        shift_end = datetime(2036, 2, 11, 17, tzinfo=timezone.utc)
        nonoverlapping_job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=service_date,
            scheduled_start=shift_end + timedelta(hours=1),
            scheduled_end=shift_end + timedelta(hours=3),
            source_key="f" * 64,
        )
        overlapping_job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=service_date,
            scheduled_start=shift_start - timedelta(hours=1),
            scheduled_end=shift_end + timedelta(hours=1),
            source_key="9" * 64,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=service_date,
            clock_in=shift_start,
            clock_out=shift_end,
        )
        job_ids = [nonoverlapping_job_id, overlapping_job_id]
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == overlapping_job_id
        finally:
            _delete_auto_link_rows(job_ids=job_ids, shift_ids=[shift_id])

    def test_date_only_job_keeps_site_date_fallback(
        self, client, auth, employee_id, location_id
    ):
        import db

        service_date = datetime(2036, 2, 12).date()
        shift_start = datetime(2036, 2, 12, 15, tzinfo=timezone.utc)
        shift_end = shift_start + timedelta(hours=2)
        job_id = _insert_auto_link_job(
            location_id=location_id,
            service_date=service_date,
        )
        shift_id = _insert_auto_link_shift(
            employee_id=employee_id,
            location_id=location_id,
            service_date=service_date,
            clock_in=shift_start,
            clock_out=shift_end,
        )
        try:
            response = client.post("/api/admin/jobs/auto-link", headers=auth)

            assert response.status_code == 200, response.text
            assert db.query_one(
                "SELECT job_id FROM shifts WHERE id = %s",
                (shift_id,),
            )["job_id"] == job_id
        finally:
            _delete_auto_link_rows(job_ids=[job_id], shift_ids=[shift_id])


class TestAutoLinkPreservesManualLink:
    def test_auto_link_does_not_overwrite_manual_link(
        self, client, auth, emp_auth, location_id
    ):
        _ensure_clocked_out(client, emp_auth)
        ci = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham", **SITE_GPS},
        )
        assert ci.status_code == 200, ci.text
        shift_id = ci.json()["entry"]["id"]
        shift_date = ci.json()["entry"]["date"]
        co = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"notes": "regression-autolink", **SITE_GPS},
        )
        assert co.status_code == 200, co.text

        # Primary job (this is where the shift will be manually pinned).
        j1 = client.post(
            "/api/admin/jobs",
            headers=auth,
            json={
                "locationId": location_id,
                "customerName": "Test Customer",
                "scheduledDate": shift_date,
                "expectedHours": 1.0,
                "revenue": 50.0,
                "notes": "primary-regression",
            },
        )
        assert j1.status_code == 200, j1.text
        primary_id = j1.json()["job"]["id"]

        att = client.post(
            f"/api/admin/jobs/{primary_id}/shifts",
            headers=auth,
            json={"shiftIds": [shift_id]},
        )
        assert att.status_code == 200, att.text

        # Competing job (same customer + date) created AFTER the manual link.
        j2 = client.post(
            "/api/admin/jobs",
            headers=auth,
            json={
                "locationId": location_id,
                "customerName": "Test Customer",
                "scheduledDate": shift_date,
                "expectedHours": 1.0,
                "revenue": 50.0,
                "notes": "competitor-regression",
            },
        )
        assert j2.status_code == 200, j2.text
        competitor_id = j2.json()["job"]["id"]

        al = client.post("/api/admin/jobs/auto-link", headers=auth, json={})
        assert al.status_code == 200, al.text

        primary = client.get(f"/api/admin/jobs/{primary_id}", headers=auth)
        assert primary.status_code == 200
        primary_ids = [s["shiftId"] for s in primary.json()["job"]["shifts"]]
        assert shift_id in primary_ids, "shift was unlinked from manual primary job"

        comp = client.get(f"/api/admin/jobs/{competitor_id}", headers=auth)
        assert comp.status_code == 200
        comp_ids = [s["shiftId"] for s in comp.json()["job"]["shifts"]]
        assert shift_id not in comp_ids, "auto-link overwrote a manual link"


# ===============================================================================
# Per-IP login rate limit
# ===============================================================================

class TestLoginRateLimit:
    def test_429_after_threshold(self, client, monkeypatch):
        import time_tracker_api as tta

        # Re-enable rate limiting (conftest disables it for the rest of the suite).
        monkeypatch.setattr(tta, "LOGIN_RATE_LIMIT_MAX", 3)
        monkeypatch.setattr(tta, "LOGIN_RATE_LIMIT_WINDOW_S", 60)
        # Drop any prior bucket state for this IP.
        with tta._RATE_LIMIT_LOCK:
            tta._RATE_LIMIT_BUCKETS.clear()

        try:
            for _ in range(3):
                r = client.post(
                    "/api/auth/login",
                    json={"name": "Definitely Not A User", "password": "x"},
                )
                assert r.status_code == 401, r.text

            r = client.post(
                "/api/auth/login",
                json={"name": "Definitely Not A User", "password": "x"},
            )
            assert r.status_code == 429, r.text
            assert "retry-after" in {k.lower() for k in r.headers.keys()}
        finally:
            with tta._RATE_LIMIT_LOCK:
                tta._RATE_LIMIT_BUCKETS.clear()


class TestRemovedOrphanEndpoints:
    """Five endpoints with no production caller were deliberately removed
    (2026-07-22, refs issue #21). These assert they stay gone, and that the
    kept sibling variants still respond."""

    REMOVED = [
        "/api/admin/receivables/allocation-suggestions",
        "/api/admin/corrections/time-data/history",
        "/api/admin/logs",
        "/api/admin/analytics/customers",
        "/api/admin/analytics/flagged",
    ]

    def test_removed_endpoints_are_gone(self, client, auth):
        for path in self.REMOVED:
            r = client.get(path, headers=auth)
            assert r.status_code == 404, f"{path} should be removed, got {r.status_code}"

    def test_kept_sibling_variants_still_work(self, client, auth):
        # Dated logs variant used by canonical admin diagnostics still serves.
        r = client.get("/api/admin/logs/2026-01-01", headers=auth)
        assert r.status_code == 200, r.text
        # Main analytics endpoint (used by portal.html) still serves.
        r = client.get("/api/admin/analytics?period=day", headers=auth)
        assert r.status_code == 200, r.text


class TestAccessLogDurability:
    def test_access_log_entry_dual_writes_file_and_postgres(
        self, client, monkeypatch, tmp_path
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "LOGS_DIR", tmp_path / "logs")
        before = api.utc_now() - timedelta(seconds=1)

        response = client.post(
            "/api/auth/login",
            headers={"user-agent": "access-log-durability-test"},
            json={"name": "Definitely Not A User", "password": "x"},
        )
        assert response.status_code == 401, response.text

        rows = api.db.query_all(
            """
            SELECT event_id, local_date, entry
            FROM access_log_entries
            WHERE action = %s
              AND endpoint = %s
              AND logged_at >= %s
            ORDER BY id DESC
            LIMIT 1
            """,
            ("LOGIN_FAILED", "/api/auth/login", before),
        )
        assert rows, "login failure did not write a durable access-log row"

        entry = rows[0]["entry"]
        assert entry["eventId"] == rows[0]["event_id"]
        assert entry["action"] == "LOGIN_FAILED"
        assert entry["allowed"] is False
        assert entry["endpoint"] == "/api/auth/login"
        assert entry["method"] == "POST"
        assert entry["userAgent"] == "access-log-durability-test"

        file_payload = api.read_json_file(
            api.LOGS_DIR / f"access_{rows[0]['local_date']}.json",
            [],
        )
        assert entry in file_payload

    def test_admin_logs_reads_postgres_and_legacy_file_without_duplicates(
        self, client, auth, monkeypatch, tmp_path
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "LOGS_DIR", tmp_path / "logs")
        date_text = "2026-02-04"
        legacy_only = _access_log_entry(
            "2026-02-04T14:00:00Z",
            "LEGACY_FILE_ONLY",
        )
        duplicate_event_id = "test-cutover-duplicate-event"
        duplicated = _access_log_entry(
            "2026-02-04T15:00:00Z",
            "CUTOVER_DUPLICATE",
            event_id=duplicate_event_id,
        )
        postgres_only = _access_log_entry(
            "2026-02-04T16:00:00Z",
            "POSTGRES_ONLY",
            event_id="test-postgres-only-event",
        )
        api.write_json_atomic(
            api.LOGS_DIR / f"access_{date_text}.json",
            [legacy_only, duplicated],
        )
        _insert_access_log_entry(api, date_text, duplicated)
        _insert_access_log_entry(api, date_text, postgres_only)

        response = client.get(f"/api/admin/logs/{date_text}", headers=auth)

        assert response.status_code == 200, response.text
        logs = response.json()["logs"]
        assert all("eventId" not in entry for entry in logs)
        assert legacy_only in logs
        assert api._public_access_log_entry(postgres_only) in logs
        assert logs.count(api._public_access_log_entry(duplicated)) == 1

    def test_access_log_dedupe_preserves_identical_legacy_events_without_event_ids(
        self, client
    ):
        import time_tracker_api as api

        first = _access_log_entry(
            "2026-02-04T15:00:00Z",
            "IDENTICAL_LEGACY_LOGIN_FAILURE",
        )
        second = dict(first)
        assert api._dedupe_access_logs([first, second]) == [first, second]

        with_event_id = _access_log_entry(
            "2026-02-04T15:00:00Z",
            "DUPLICATED_CUTOVER_EVENT",
            event_id="shared-cutover-id",
        )
        assert api._dedupe_access_logs([with_event_id, dict(with_event_id)]) == [
            with_event_id
        ]

    def test_legacy_file_failure_does_not_block_postgres_access_log_write(
        self, client, monkeypatch, tmp_path
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "LOGS_DIR", tmp_path / "logs")

        def fail_file_write(*_args, **_kwargs):
            raise OSError("simulated legacy log disk failure")

        monkeypatch.setattr(api, "write_json_atomic", fail_file_write)
        before = api.utc_now() - timedelta(seconds=1)

        response = client.post(
            "/api/auth/login",
            headers={"user-agent": "access-log-file-failure-test"},
            json={"name": "Definitely Not A User", "password": "x"},
        )

        assert response.status_code == 401, response.text
        rows = api.db.query_all(
            """
            SELECT entry
            FROM access_log_entries
            WHERE action = %s
              AND endpoint = %s
              AND logged_at >= %s
            ORDER BY id DESC
            LIMIT 1
            """,
            ("LOGIN_FAILED", "/api/auth/login", before),
        )
        assert rows
        assert rows[0]["entry"]["userAgent"] == "access-log-file-failure-test"

    def test_health_endpoint_does_not_wait_on_access_log_write(self, client, monkeypatch):
        import time_tracker_api as api

        def fail_access_log(*_args, **_kwargs):
            raise RuntimeError("health should not synchronously audit")

        monkeypatch.setattr(api, "append_access_log", fail_access_log)

        response = client.get("/api/health")

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "ok"

    def test_admin_logs_fall_back_to_postgres_when_legacy_file_is_malformed(
        self, client, auth, monkeypatch, tmp_path
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "LOGS_DIR", tmp_path / "logs")
        date_text = "2026-02-05"
        postgres_only = _access_log_entry(
            "2026-02-05T16:00:00Z",
            "POSTGRES_SURVIVES_BAD_FILE",
            event_id="test-postgres-bad-file-fallback",
        )
        api.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        (api.LOGS_DIR / f"access_{date_text}.json").write_text(
            "{not valid json",
            encoding="utf-8",
        )
        _insert_access_log_entry(api, date_text, postgres_only)

        response = client.get(f"/api/admin/logs/{date_text}", headers=auth)

        assert response.status_code == 200, response.text
        assert response.json()["logs"] == [
            api._public_access_log_entry(postgres_only)
        ]

    def test_access_log_retention_prunes_only_expired_postgres_rows(
        self, client, monkeypatch
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ACCESS_LOG_RETENTION_DAYS", 30)
        now = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
        expired = _access_log_entry(
            "2026-06-14T12:00:00Z",
            "RETENTION_EXPIRED",
        )
        retained = _access_log_entry(
            "2026-06-16T12:00:00Z",
            "RETENTION_KEPT",
        )
        _insert_access_log_entry(api, "2026-06-14", expired)
        _insert_access_log_entry(api, "2026-06-16", retained)

        api._prune_access_log_entries(now)

        rows = api.db.query_all(
            """
            SELECT action
            FROM access_log_entries
            WHERE action LIKE %s
            ORDER BY action
            """,
            ("RETENTION_%",),
        )
        assert rows == [{"action": "RETENTION_KEPT"}]

    def test_access_log_retention_retry_is_not_suppressed_after_prune_failure(
        self, client, monkeypatch
    ):
        import time_tracker_api as api

        attempts = 0
        today = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)

        def fixed_now():
            return today

        def flaky_prune():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("simulated transient prune failure")

        monkeypatch.setattr(api, "_ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON", None)
        monkeypatch.setattr(api, "utc_now", fixed_now)
        monkeypatch.setattr(api, "_prune_access_log_entries", flaky_prune)

        with pytest.raises(RuntimeError, match="simulated transient prune failure"):
            api._maybe_prune_access_log_entries()

        assert api._ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON is None

        api._maybe_prune_access_log_entries()

        assert attempts == 2
        assert api._ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON == today.date()

    def test_access_log_schema_migration_installs_logged_at_retention_index(self, client):
        import time_tracker_api as api

        api.db.execute("DROP INDEX IF EXISTS idx_access_log_entries_logged_at")

        api._ensure_schema_migrations()

        row = api.db.query_one(
            """
            SELECT to_regclass('idx_access_log_entries_logged_at') AS index_name
            """
        )
        assert row == {"index_name": "idx_access_log_entries_logged_at"}
