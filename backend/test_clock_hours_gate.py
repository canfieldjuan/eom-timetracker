"""Regression tests for the clock-action hours gate (issue #21 access-hours
decision): clock-in / arrive / QR check-in are rejected outside the configured
window; clock-out and depart are never gated (so a shift that started inside
the window can always be closed); ENFORCE_CLOCK_HOURS=false disables the gate.
"""

import time_tracker_api as tta

GPS = {"latitude": 39.1203, "longitude": -88.54335}


def _close_window(monkeypatch):
    """Force check_schedule_access() to fail: no day is allowed."""
    monkeypatch.setattr(tta, "ALLOWED_DAYS", [])


def test_clock_in_blocked_outside_window(client, emp_auth, monkeypatch):
    _close_window(monkeypatch)
    r = client.post("/api/timesheet/clock-in", headers=emp_auth,
                    json={"location": "123 Main St, Effingham", **GPS})
    assert r.status_code == 403, r.text
    # HTTPException string details are reshaped to {"success": false, "error": ...}
    assert "allowed" in r.json()["error"]


def test_visit_blocked_outside_window(client, emp_auth, monkeypatch):
    _close_window(monkeypatch)
    r = client.post("/api/timesheet/visit", headers=emp_auth,
                    json={"location": "123 Main St, Effingham", **GPS})
    assert r.status_code == 403, r.text


def test_site_check_in_blocked_outside_window(client, emp_auth, employee_id, monkeypatch):
    _close_window(monkeypatch)
    r = client.post("/api/timesheet/site-check-in", headers=emp_auth, json={
        "employeeId": employee_id,
        "siteId": 1,
        "token": "eom1.1.aaaaaaaaaaaaaaaaaaaaaaaa.deadbeef",
        "scannedAt": "2026-07-22T12:00:00+00:00",
        "latitude": GPS["latitude"], "longitude": GPS["longitude"],
        "accuracy": 5,
    })
    assert r.status_code == 403, r.text
    # The gate fires before token resolution — hours message, not a QR error.
    assert "QR" not in r.json()["error"]
    assert "allowed" in r.json()["error"]


def test_clock_out_and_depart_never_gated(client, emp_auth, monkeypatch):
    # Open a shift inside the (test-default open) window...
    r = client.post("/api/timesheet/clock-in", headers=emp_auth,
                    json={"location": "123 Main St, Effingham", **GPS})
    assert r.status_code == 200, r.text
    # ...then close the window and prove clock-out still works (no trapped shift).
    _close_window(monkeypatch)
    r = client.post("/api/timesheet/depart", headers=emp_auth, json={**GPS})
    assert r.status_code != 403, r.text  # depart may 200 or business-4xx, never hours-403
    r = client.post("/api/timesheet/clock-out", headers=emp_auth, json={**GPS})
    assert r.status_code == 200, r.text


def test_kill_switch_disables_gate(client, emp_auth, monkeypatch):
    _close_window(monkeypatch)
    monkeypatch.setattr(tta, "ENFORCE_CLOCK_HOURS", False)
    r = client.post("/api/timesheet/clock-in", headers=emp_auth,
                    json={"location": "123 Main St, Effingham", **GPS})
    assert r.status_code == 200, r.text
    # cleanup: close the shift so later tests see no open entry
    client.post("/api/timesheet/clock-out", headers=emp_auth, json={**GPS})
