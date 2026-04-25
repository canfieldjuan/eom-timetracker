"""
Regression tests for bugs fixed on the claude/fix-bugs-integration-bBLKA
branch. Each test is named for the bug it locks in so a failure makes the
break obvious.

Run:  cd backend && pytest -v test_regressions.py
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest


def _ensure_clocked_out(client, headers) -> None:
    """Best-effort cleanup: close any open shift for the auth'd user. Ignore
    errors (no-op when nothing is open)."""
    client.post("/api/timesheet/clock-out", headers=headers, json={})


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
            json={"location": "123 Main St, Effingham"},
        )
        assert ci.status_code == 200, ci.text
        co = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"notes": "regression-aggregate-closed"},
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
            json={"location": "123 Main St, Effingham"},
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
            json={"location": "123 Main St, Effingham"},
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
# admin_auto_link_jobs -- WHERE job_id IS NULL guard
# ===============================================================================

class TestAutoLinkPreservesManualLink:
    def test_auto_link_does_not_overwrite_manual_link(
        self, client, auth, emp_auth, location_id
    ):
        _ensure_clocked_out(client, emp_auth)
        ci = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham"},
        )
        assert ci.status_code == 200, ci.text
        shift_id = ci.json()["entry"]["id"]
        shift_date = ci.json()["entry"]["date"]
        co = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"notes": "regression-autolink"},
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
# /api/admin/generate-report -- email validation
# ===============================================================================

class TestReportEmailValidation:
    def test_invalid_email_rejected(self, client, auth):
        r = client.post(
            "/api/admin/generate-report",
            headers=auth,
            json={
                "month": 4,
                "year": 2026,
                "emails": ["not-an-email"],
                "send_email": True,
            },
        )
        assert r.status_code == 400, r.text

    def test_too_many_recipients_rejected(self, client, auth):
        emails = [f"user{i}@example.com" for i in range(51)]
        r = client.post(
            "/api/admin/generate-report",
            headers=auth,
            json={
                "month": 4,
                "year": 2026,
                "emails": emails,
                "send_email": True,
            },
        )
        assert r.status_code == 400, r.text


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
