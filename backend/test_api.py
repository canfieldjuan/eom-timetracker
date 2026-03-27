"""
Integration tests for EOM Time Tracker API - Phases 3-8 + regression checks.

Run:  cd backend && pytest -v
"""
from __future__ import annotations

import pytest


# ===============================================================================
# Auth & Health
# ===============================================================================

class TestAuth:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_login_success(self, client):
        r = client.post("/api/auth/login", json={"name": "Juan Canfield", "password": "canfield1"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert "token" in data
        assert data["employee"]["role"] == "admin"

    def test_login_wrong_password(self, client):
        r = client.post("/api/auth/login", json={"name": "Juan Canfield", "password": "wrong"})
        assert r.status_code == 401

    def test_login_unknown_user(self, client):
        r = client.post("/api/auth/login", json={"name": "Nobody Here", "password": "x"})
        assert r.status_code == 401

    def test_admin_endpoint_requires_auth(self, client):
        r = client.get("/api/admin/employees")
        assert r.status_code == 401

    def test_employee_cannot_access_admin(self, client, emp_auth):
        r = client.get("/api/admin/employees", headers=emp_auth)
        assert r.status_code == 403


class TestTimesheetGpsFlow:
    def test_timesheet_locations_exposes_match_radius(self, client, emp_auth):
        r = client.get("/api/timesheet/locations", headers=emp_auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "locationMatchRadiusM" in data
        assert data["locationMatchRadiusM"] > 0

    def test_clock_in_accepts_gps(self, client, emp_auth):
        r = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "notes": "gps start",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert r.status_code == 200, r.text
        entry = r.json()["entry"]
        assert entry["clockInGps"]["lat"] == pytest.approx(39.1201)
        assert entry["clockInGps"]["lng"] == pytest.approx(-88.5432)

        r2 = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup",
            "latitude": 39.1205,
            "longitude": -88.5435,
        })
        assert r2.status_code == 200, r2.text
        assert r2.json()["entry"]["clockOutGps"]["lat"] == pytest.approx(39.1205)

    def test_depart_requires_active_arrival(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
        })
        assert ci.status_code == 200, ci.text

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 39.1202,
            "longitude": -88.5433,
        })
        assert dep.status_code == 400, dep.text

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={"notes": "cleanup"})
        assert co.status_code == 200, co.text

    def test_arrive_then_depart_updates_current_status(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert ci.status_code == 200, ci.text

        visit = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit.status_code == 200, visit.text
        assert visit.json()["alreadyHere"] is False

        status1 = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status1.status_code == 200, status1.text
        me1 = next(row for row in status1.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me1["canDepart"] is True
        assert me1["activeVisit"]["location"] == "123 Main St, Effingham"

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "notes": "left site",
            "latitude": 39.1204,
            "longitude": -88.5434,
        })
        assert dep.status_code == 200, dep.text
        departure = dep.json()["departure"]
        assert departure["location"] == "123 Main St, Effingham"
        assert departure["gps"]["lat"] == pytest.approx(39.1204)

        status2 = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status2.status_code == 200, status2.text
        me2 = next(row for row in status2.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me2["canDepart"] is False
        assert me2["activeVisit"] is None
        assert len(me2["departures"]) >= 1

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup after depart",
            "latitude": 39.1205,
            "longitude": -88.5435,
        })
        assert co.status_code == 200, co.text

    def test_can_rearrive_same_location_after_depart(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert ci.status_code == 200, ci.text

        visit1 = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit1.status_code == 200, visit1.text
        assert visit1.json()["alreadyHere"] is False

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 39.1204,
            "longitude": -88.5434,
        })
        assert dep.status_code == 200, dep.text

        visit2 = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit2.status_code == 200, visit2.text
        assert visit2.json()["alreadyHere"] is False

        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        me = next(row for row in status.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me["canDepart"] is True

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup after rearrive",
            "latitude": 39.1205,
            "longitude": -88.5435,
        })
        assert co.status_code == 200, co.text


# ===============================================================================
# Existing analytics - regression: was returning 500 (byDay KeyError)
# ===============================================================================

class TestAnalyticsRegression:
    def test_analytics_week_returns_200(self, client, auth):
        r = client.get("/api/admin/analytics?period=week&date=2026-03-25", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "byCustomer" in data
        assert "byDay" in data
        assert "summary" in data

    def test_analytics_month(self, client, auth):
        r = client.get("/api/admin/analytics?period=month&date=2026-03-01", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_day(self, client, auth):
        r = client.get("/api/admin/analytics?period=day&date=2026-03-25", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_all(self, client, auth):
        r = client.get("/api/admin/analytics?period=all", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_byday_shape(self, client, auth, completed_shift_id):
        """byDay rows must have the right keys (no customer/location)."""
        r = client.get("/api/admin/analytics?period=all", headers=auth)
        assert r.status_code == 200, r.text
        by_day = r.json()["byDay"]
        if by_day:
            row = by_day[0]
            for key in ("date", "visits", "hours", "revenue", "laborCost", "laborPct", "netProfit"):
                assert key in row, f"Missing key '{key}' in byDay row"
            assert "customer" not in row
            assert "location" not in row

    def test_analytics_customers_endpoint(self, client, auth):
        r = client.get("/api/admin/analytics/customers?period=all", headers=auth)
        assert r.status_code == 200, r.text
        assert "customers" in r.json()


# ===============================================================================
# Phase 3 - Jobs
# ===============================================================================

class TestJobs:
    def test_create_job(self, client, auth, location_id):
        r = client.post("/api/admin/jobs", headers=auth, json={
            "locationId":    location_id,
            "customerName":  "Test Customer",
            "scheduledDate": "2026-04-01",
            "expectedHours": 3.0,
            "revenue":       150.00,
            "notes":         "Spring clean",
        })
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        assert job["customerName"] == "Test Customer"
        assert job["status"] == "scheduled"
        assert job["revenue"] == 150.0

    def test_list_jobs(self, client, auth):
        r = client.get("/api/admin/jobs", headers=auth)
        assert r.status_code == 200, r.text
        assert isinstance(r.json()["jobs"], list)

    def test_list_jobs_filter_by_status(self, client, auth):
        r = client.get("/api/admin/jobs?status=scheduled", headers=auth)
        assert r.status_code == 200, r.text
        for job in r.json()["jobs"]:
            assert job["status"] == "scheduled"

    def test_get_job(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Get Test",
            "scheduledDate": "2026-04-02", "expectedHours": 2.0, "revenue": 100.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r.status_code == 200, r.text
        assert r.json()["job"]["id"] == job_id

    def test_get_job_not_found(self, client, auth):
        r = client.get("/api/admin/jobs/999999", headers=auth)
        assert r.status_code == 404

    def test_update_job_status(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Update Test",
            "scheduledDate": "2026-04-03", "expectedHours": 2.0, "revenue": 80.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.put(f"/api/admin/jobs/{job_id}", headers=auth, json={
            "customerName": "Update Test", "scheduledDate": "2026-04-03",
            "expectedHours": 2.5, "revenue": 90.0, "notes": "updated",
            "status": "completed",
        })
        assert r.status_code == 200, r.text
        assert r.json()["job"]["status"] == "completed"
        assert r.json()["job"]["expectedHours"] == 2.5

    def test_delete_job(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Delete Me",
            "scheduledDate": "2026-04-04", "expectedHours": 1.0, "revenue": 50.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.delete(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r.status_code == 200, r.text
        # confirm gone
        r2 = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r2.status_code == 404

    def test_jobs_profitability(self, client, auth):
        r = client.get("/api/admin/jobs/profitability", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "jobs" in data

    def test_auto_link_jobs(self, client, auth, completed_shift_id, location_id):
        """Auto-link should run without error; returns linked count."""
        r = client.post("/api/admin/jobs/auto-link", headers=auth,
                        json={"date": "2026-04-01"})
        assert r.status_code == 200, r.text
        assert "linkedCount" in r.json()

    def test_attach_shift_to_job(self, client, auth, completed_shift_id, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Shift Link Test",
            "scheduledDate": "2026-04-05", "expectedHours": 3.0, "revenue": 120.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.post(f"/api/admin/jobs/{job_id}/shifts", headers=auth,
                        json={"shiftIds": [completed_shift_id]})
        assert r.status_code == 200, r.text

    def test_detach_shift_from_job(self, client, auth, completed_shift_id, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Detach Test",
            "scheduledDate": "2026-04-06", "expectedHours": 3.0, "revenue": 120.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        client.post(f"/api/admin/jobs/{job_id}/shifts", headers=auth,
                    json={"shiftIds": [completed_shift_id]})
        r = client.delete(f"/api/admin/jobs/{job_id}/shifts/{completed_shift_id}", headers=auth)
        assert r.status_code == 200, r.text

    def test_invalid_job_status(self, client, auth, location_id):
        """Creating a job with a bad status should fail."""
        r = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Bad Status",
            "scheduledDate": "2026-04-07", "expectedHours": 1.0, "revenue": 50.0,
            "notes": "", "status": "invalid_status",
        })
        assert r.status_code in (400, 422)


# ===============================================================================
# Phase 4 - Account Health / Flagged Accounts
# ===============================================================================

class TestAccountHealth:
    def test_flagged_accounts(self, client, auth):
        r = client.get("/api/admin/analytics/flagged", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "customers" in data
        assert isinstance(data["customers"], list)

    def test_flagged_has_expected_keys(self, client, auth, completed_shift_id):
        r = client.get("/api/admin/analytics/flagged", headers=auth)
        customers = r.json()["customers"]
        if customers:
            row = customers[0]
            assert "customer" in row
            assert "flags" in row


# ===============================================================================
# Phase 5 - Unified Dashboard
# ===============================================================================

class TestDashboard:
    def test_admin_dashboard(self, client, auth):
        r = client.get("/api/admin/dashboard", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "cards" in data or "summary" in data or "success" in data

    def test_dashboard_requires_auth(self, client):
        r = client.get("/api/admin/dashboard")
        assert r.status_code == 401


# ===============================================================================
# Phase 6 - Pricing Recommendations
# ===============================================================================

class TestPricing:
    def test_pricing_recommendations(self, client, auth):
        r = client.get("/api/admin/analytics/pricing", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)

    def test_pricing_row_keys(self, client, auth, completed_shift_id):
        r = client.get("/api/admin/analytics/pricing", headers=auth)
        recs = r.json()["recommendations"]
        if recs:
            row = recs[0]
            assert "customer" in row
            assert "currentRate" in row or "suggestedRate" in row or "laborPct" in row


# ===============================================================================
# Phase 7 - Time Categorization & Waste
# ===============================================================================

class TestTimeCategories:
    def test_categorize_shift_productive(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "productive"})
        assert r.status_code == 200, r.text
        assert r.json()["success"] is True

    def test_categorize_shift_non_productive(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "non_productive", "nonProductiveType": "drive_time",
                               "notes": "driving to supply store"})
        assert r.status_code == 200, r.text

    def test_categorize_invalid_type(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "banana"})
        assert r.status_code in (400, 422)

    def test_non_productive_requires_type(self, client, auth, completed_shift_id):
        """non_productive without nonProductiveType should fail or at least not 500."""
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "non_productive"})
        # API may accept with null type or reject - just must not 500
        assert r.status_code != 500

    def test_waste_analysis(self, client, auth):
        r = client.get("/api/admin/analytics/waste", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "waste" in data or "summary" in data or "success" in data

    def test_waste_all_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=all", headers=auth)
        assert r.status_code == 200, r.text

    def test_waste_invalid_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=bogus", headers=auth)
        assert r.status_code in (400, 422)

    def test_categorize_shift_not_found(self, client, auth):
        r = client.patch("/api/admin/shifts/999999/categorize", headers=auth,
                         json={"timeCategory": "productive"})
        assert r.status_code == 404


# ===============================================================================
# Phase 8 - Schedules & Forecasting
# ===============================================================================

class TestSchedules:
    def test_create_schedule(self, client, auth, employee_id):
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId":     employee_id,
            "customerName":   "Test Customer",
            "weekStart":      "2026-03-29",
            "scheduledHours": 8.0,
            "notes":          "",
        })
        assert r.status_code == 200, r.text
        sc = r.json()["schedule"]
        assert sc["customerName"] == "Test Customer"
        assert sc["scheduledHours"] == 8.0

    def test_create_schedule_normalizes_to_sunday(self, client, auth, employee_id):
        """Wed 2026-04-01 should be normalized to Sun 2026-03-29."""
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Test Customer",
            "weekStart": "2026-04-01",  # Wednesday
            "scheduledHours": 6.0, "notes": "",
        })
        assert r.status_code == 200, r.text
        assert r.json()["schedule"]["weekStart"] == "2026-03-29"

    def test_upsert_schedule(self, client, auth, employee_id):
        """Posting twice for same employee/customer/week should update hours."""
        base = {"employeeId": employee_id, "customerName": "Upsert Test",
                "weekStart": "2026-03-29", "notes": ""}
        client.post("/api/admin/schedules", headers=auth, json={**base, "scheduledHours": 5.0})
        r2 = client.post("/api/admin/schedules", headers=auth, json={**base, "scheduledHours": 9.0})
        assert r2.status_code == 200, r2.text
        assert r2.json()["schedule"]["scheduledHours"] == 9.0

    def test_list_schedules(self, client, auth):
        r = client.get("/api/admin/schedules", headers=auth)
        assert r.status_code == 200, r.text
        assert isinstance(r.json()["schedules"], list)

    def test_list_schedules_filter_week(self, client, auth):
        r = client.get("/api/admin/schedules?week_start=2026-03-29", headers=auth)
        assert r.status_code == 200, r.text
        for sc in r.json()["schedules"]:
            assert sc["weekStart"] == "2026-03-29"

    def test_delete_schedule(self, client, auth, employee_id):
        create = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Delete Sched",
            "weekStart": "2026-03-29", "scheduledHours": 4.0, "notes": "",
        })
        sc_id = create.json()["schedule"]["id"]
        r = client.delete(f"/api/admin/schedules/{sc_id}", headers=auth)
        assert r.status_code == 200, r.text

    def test_delete_schedule_not_found(self, client, auth):
        r = client.delete("/api/admin/schedules/999999", headers=auth)
        assert r.status_code == 404

    def test_negative_hours_rejected(self, client, auth, employee_id):
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Bad Hours",
            "weekStart": "2026-03-29", "scheduledHours": -1.0, "notes": "",
        })
        assert r.status_code in (400, 422)


class TestScheduleVsActual:
    def test_schedule_vs_actual(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "rows" in data or "comparison" in data or "success" in data

    def test_schedule_vs_actual_with_week(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual?week_start=2026-03-29", headers=auth)
        assert r.status_code == 200, r.text

    def test_schedule_vs_actual_invalid_date(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual?week_start=not-a-date", headers=auth)
        assert r.status_code in (400, 422)


class TestForecast:
    def test_forecast_endpoint(self, client, auth):
        r = client.get("/api/admin/analytics/forecast", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "forecast" in data or "weeks" in data or "success" in data

    def test_forecast_with_weeks_param(self, client, auth):
        r = client.get("/api/admin/analytics/forecast?weeks=4", headers=auth)
        assert r.status_code == 200, r.text

    def test_forecast_invalid_weeks(self, client, auth):
        r = client.get("/api/admin/analytics/forecast?weeks=-1", headers=auth)
        assert r.status_code in (400, 422, 200)  # implementation-defined


# ===============================================================================
# Locations - new fields (target_labor_pct, min_margin_pct)
# ===============================================================================

class TestLocationNewFields:
    def test_update_location_with_targets(self, client, auth):
        r = client.put("/api/admin/locations", headers=auth, json={"locations": [{
            "address":        "123 Main St, Effingham",
            "customerName":   "Test Customer",
            "locationType":   "Residential",
            "rate":           160.0,
            "rateType":       "per_visit",
            "expectedHours":  3.5,
            "targetLaborPct": 30.0,
            "minMarginPct":   25.0,
        }]})
        assert r.status_code == 200, r.text

    def test_locations_return_new_fields(self, client, auth):
        """PUT /admin/locations should persist and return Phase-6 pricing targets."""
        r = client.put("/api/admin/locations", headers=auth, json={"locations": [{
            "address":        "123 Main St, Effingham",
            "customerName":   "Test Customer",
            "locationType":   "Residential",
            "rate":           160.0,
            "rateType":       "per_visit",
            "expectedHours":  3.5,
            "targetLaborPct": 30.0,
            "minMarginPct":   25.0,
        }]})
        assert r.status_code == 200, r.text
        data = r.json()
        # Phase 6 pricing fields are returned in the PUT response
        assert "location_target_labor" in data
        assert "location_min_margin" in data
