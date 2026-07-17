"""Security-containment and read-only time-data audit regression tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import db


@pytest.mark.parametrize("path", ["/", "/timetracker-mobile.html"])
def test_secured_time_tracker_page_is_served_same_origin(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "Firefly Time Tracker" in response.text
    assert "id=\"adminPanel\" class=\"panel hidden\"" in response.text
    assert "window.location.origin}/api" in response.text


@pytest.mark.parametrize("api_path", ["/api/hours", "/api/current-status"])
def test_owner_dashboard_requires_admin(client, emp_auth, auth, api_path):
    assert client.get(api_path).status_code == 401
    assert client.get(api_path, headers=emp_auth).status_code == 403
    assert client.get(api_path, headers=auth).status_code == 200


def test_employee_current_status_is_scoped_to_self(client, auth, emp_auth):
    admin_clocked_in = False
    employee_clocked_in = False
    try:
        admin_response = client.post(
            "/api/timesheet/clock-in",
            headers=auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 39.1203,
                "longitude": -88.54335,
            },
        )
        assert admin_response.status_code == 200, admin_response.text
        admin_clocked_in = True

        employee_response = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 39.1203,
                "longitude": -88.54335,
            },
        )
        assert employee_response.status_code == 200, employee_response.text
        employee_clocked_in = True

        employee_status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert employee_status.status_code == 200, employee_status.text
        assert {
            row["employeeName"] for row in employee_status.json()["currentlyWorking"]
        } == {"Catalina Gomez"}

        admin_status = client.get("/api/timesheet/current-status", headers=auth)
        assert admin_status.status_code == 200, admin_status.text
        assert {
            row["employeeName"] for row in admin_status.json()["currentlyWorking"]
        } == {"Juan Canfield", "Catalina Gomez"}
    finally:
        if employee_clocked_in:
            client.post("/api/timesheet/clock-out", headers=emp_auth, json={
                "notes": "cleanup",
                "latitude": 39.1203,
                "longitude": -88.54335,
            })
        if admin_clocked_in:
            client.post("/api/timesheet/clock-out", headers=auth, json={
                "notes": "cleanup",
                "latitude": 39.1203,
                "longitude": -88.54335,
            })


def test_public_registration_is_disabled(client):
    response = client.post(
        "/api/auth/register",
        json={"name": "Unapproved User", "password": "secret1"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "Public registration is disabled"
    assert db.query_one(
        "SELECT id FROM employees WHERE name = %s",
        ("Unapproved User",),
    ) is None


def test_admin_can_create_employee_without_public_registration(client, auth, emp_auth):
    payload = {
        "name": "Security Test Employee",
        "password": "secret1",
        "role": "employee",
        "hourlyRate": 18.25,
    }
    created_id = None
    try:
        # A deleted employee can leave the sequence ahead of MAX(id). The API
        # must return the database-assigned ID, not its pre-insert guess.
        db.execute("SELECT setval('employees_id_seq', 50, true)")
        assert client.post("/api/admin/employees", json=payload).status_code == 401
        assert client.post(
            "/api/admin/employees",
            headers=emp_auth,
            json=payload,
        ).status_code == 403

        response = client.post("/api/admin/employees", headers=auth, json=payload)
        assert response.status_code == 200, response.text
        employee = response.json()["employee"]
        created_id = employee["id"]
        assert created_id == db.query_one(
            "SELECT id FROM employees WHERE name = %s",
            (payload["name"],),
        )["id"]
        assert employee["role"] == "employee"
        assert employee["hourlyRate"] == pytest.approx(18.25)

        duplicate = client.post("/api/admin/employees", headers=auth, json=payload)
        assert duplicate.status_code == 409
    finally:
        if created_id is not None:
            db.execute("DELETE FROM employees WHERE id = %s", (created_id,))
        db.execute(
            "SELECT setval('employees_id_seq', COALESCE((SELECT MAX(id) FROM employees), 1), true)"
        )


def test_cors_allows_only_configured_origin(client):
    trusted = client.options(
        "/api/hours",
        headers={
            "Origin": "https://trusted.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert trusted.status_code == 200
    assert trusted.headers["access-control-allow-origin"] == "https://trusted.example"
    assert trusted.headers["access-control-allow-private-network"] == "true"

    untrusted = client.options(
        "/api/hours",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert untrusted.status_code == 400
    assert "access-control-allow-origin" not in untrusted.headers
    assert "access-control-allow-private-network" not in untrusted.headers


def _insert_shift(employee_id, location_id, clock_in, clock_out=None):
    return db.execute_returning(
        """
        INSERT INTO shifts (
            employee_id,
            location_id,
            location_label,
            clock_in,
            clock_out,
            local_date,
            timezone
        )
        VALUES (%s, %s, %s, %s, %s, %s, 'America/Chicago')
        RETURNING id
        """,
        (
            employee_id,
            location_id,
            "123 Main St, Effingham",
            clock_in,
            clock_out,
            clock_in.date(),
        ),
    )


def test_time_data_audit_is_admin_only_and_read_only(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    inserted_ids = []
    completed_start = datetime(2024, 1, 2, 14, 0, tzinfo=timezone.utc)
    completed_end = completed_start + timedelta(hours=2)
    now = datetime.now(timezone.utc)

    try:
        duplicate_one = _insert_shift(
            employee_id,
            location_id,
            completed_start,
            completed_end,
        )
        duplicate_two = _insert_shift(
            employee_id,
            location_id,
            completed_start,
            completed_end,
        )
        stale_open = _insert_shift(
            employee_id,
            location_id,
            now - timedelta(hours=30),
        )
        recent_open = _insert_shift(
            employee_id,
            location_id,
            now - timedelta(hours=1),
        )
        inserted_ids.extend([duplicate_one, duplicate_two, stale_open, recent_open])

        endpoint = "/api/admin/audits/time-data"
        assert client.get(endpoint).status_code == 401
        assert client.get(endpoint, headers=emp_auth).status_code == 403

        before = db.query_one("SELECT COUNT(*) AS count FROM shifts")["count"]
        response = client.get(endpoint, headers=auth)
        after = db.query_one("SELECT COUNT(*) AS count FROM shifts")["count"]

        assert response.status_code == 200, response.text
        assert before == after
        payload = response.json()
        assert payload["databaseReadOnly"] is True
        assert payload["summary"]["duplicateExtraShifts"] >= 1
        assert payload["summary"]["employeesWithMultipleOpenShifts"] >= 1
        assert payload["summary"]["staleOpenShifts"] >= 1

        duplicate_group = next(
            row
            for row in payload["duplicateShiftGroups"]
            if {duplicate_one, duplicate_two}.issubset(set(row["shiftIds"]))
        )
        assert duplicate_group["copies"] >= 2

        open_conflict = next(
            row
            for row in payload["multipleOpenShiftEmployees"]
            if row["employeeId"] == employee_id
        )
        assert {stale_open, recent_open}.issubset(set(open_conflict["shiftIds"]))
        assert stale_open in {
            row["shiftId"] for row in payload["staleOpenShifts"]
        }
        assert recent_open not in {
            row["shiftId"] for row in payload["staleOpenShifts"]
        }
    finally:
        for shift_id in inserted_ids:
            db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
