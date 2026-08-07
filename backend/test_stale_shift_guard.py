"""Regression coverage for unresolved stale shifts and payroll containment."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import db


def _insert_stale_shift(employee_id, location_id, *, days_old=3):
    clock_in = datetime.now(timezone.utc) - timedelta(days=days_old)
    shift_id = db.execute_returning(
        """
        INSERT INTO shifts (
            employee_id,
            location_id,
            location_label,
            clock_in,
            clock_out,
            total_hours,
            notes,
            local_date,
            timezone
        )
        VALUES (%s, %s, '123 Main St, Effingham', %s, NULL, NULL, '', %s, 'America/Chicago')
        RETURNING id
        """,
        (employee_id, location_id, clock_in, clock_in.date()),
    )
    return shift_id, clock_in


def _insert_recent_open_shift(employee_id, location_id, *, hours_old=1):
    clock_in = datetime.now(timezone.utc) - timedelta(hours=hours_old)
    shift_id = db.execute_returning(
        """
        INSERT INTO shifts (
            employee_id,
            location_id,
            location_label,
            clock_in,
            clock_out,
            total_hours,
            notes,
            local_date,
            timezone
        )
        VALUES (%s, %s, '123 Main St, Effingham', %s, NULL, NULL, '', %s, 'America/Chicago')
        RETURNING id
        """,
        (employee_id, location_id, clock_in, clock_in.date()),
    )
    return shift_id


def _delete_open_shifts(employee_id):
    db.execute(
        "DELETE FROM shifts WHERE employee_id = %s AND clock_out IS NULL",
        (employee_id,),
    )


def _employee_summary(client, auth, employee_id):
    response = client.get("/api/admin/employees", headers=auth)
    assert response.status_code == 200, response.text
    return next(
        employee
        for employee in response.json()["employees"]
        if employee["id"] == employee_id
    )


def test_stale_shift_is_visible_blocks_actions_and_adds_no_payable_hours(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    _delete_open_shifts(employee_id)
    before = _employee_summary(client, auth, employee_id)
    shift_id, _ = _insert_stale_shift(employee_id, location_id)

    try:
        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        body = status.json()
        assert body["currentlyWorking"] == []
        assert body["staleOpenShift"] == {
            "shiftId": shift_id,
            "clockIn": body["staleOpenShift"]["clockIn"],
            "location": "123 Main St, Effingham",
            "ageHours": body["staleOpenShift"]["ageHours"],
            "requiresAdminReview": True,
        }
        assert body["staleOpenShift"]["ageHours"] > 24
        assert body["staleOpenShifts"] == []

        admin_status = client.get("/api/timesheet/current-status", headers=auth)
        assert admin_status.status_code == 200, admin_status.text
        admin_stale = next(
            row
            for row in admin_status.json()["staleOpenShifts"]
            if row["shiftId"] == shift_id
        )
        assert admin_stale == {
            "shiftId": shift_id,
            "employeeId": employee_id,
            "employeeName": "Catalina Gomez",
            "clockIn": admin_stale["clockIn"],
            "location": "123 Main St, Effingham",
            "ageHours": admin_stale["ageHours"],
            "requiresAdminReview": True,
        }
        assert admin_stale["ageHours"] > 24

        attempts = [
            ("/api/timesheet/clock-in", {"location": "123 Main St, Effingham"}),
            ("/api/timesheet/clock-out", {}),
            ("/api/timesheet/visit", {"location": "123 Main St, Effingham"}),
            ("/api/timesheet/depart", {}),
        ]
        for endpoint, payload in attempts:
            response = client.post(endpoint, headers=emp_auth, json=payload)
            assert response.status_code == 409, (endpoint, response.text)
            error = response.json()
            assert error["code"] == "STALE_SHIFT_REQUIRES_REVIEW"
            assert error["details"]["staleOpenShift"]["shiftId"] == shift_id

        stored = db.query_one(
            "SELECT clock_out, total_hours, notes FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert stored["clock_out"] is None
        assert float(stored["total_hours"] or 0) == 0
        assert stored["notes"] == ""
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s AND clock_out IS NULL",
            (employee_id,),
        )["count"] == 1

        my_hours = client.get("/api/timesheet/my-hours", headers=emp_auth)
        assert my_hours.status_code == 200, my_hours.text
        stale_row = next(
            row
            for row in my_hours.json()["recentShifts"]
            if row["clockOut"] == "Needs review"
        )
        assert stale_row["hours"] == 0

        after = _employee_summary(client, auth, employee_id)
        assert after["totalHours"] == before["totalHours"]
        assert after["totalShifts"] == before["totalShifts"] + 1
    finally:
        db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))


def test_unrelated_write_never_auto_closes_stale_shift(
    client,
    monkeypatch,
    employee_id,
    location_id,
):
    import time_tracker_api as tta

    _delete_open_shifts(employee_id)
    shift_id, _ = _insert_stale_shift(employee_id, location_id)
    monkeypatch.setattr(tta, "AUTO_CLOSE_STALE_SHIFTS", True, raising=False)

    try:
        ok, result = tta.update_timesheets(lambda _: (True, "unrelated write"))
        assert ok is True
        assert result == "unrelated write"

        stored = db.query_one(
            "SELECT clock_out, total_hours, notes FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert stored["clock_out"] is None
        assert float(stored["total_hours"] or 0) == 0
        assert stored["notes"] == ""
    finally:
        db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))


def test_older_stale_shift_blocks_actions_when_a_newer_open_shift_exists(
    client,
    emp_auth,
    employee_id,
    location_id,
):
    _delete_open_shifts(employee_id)
    stale_id, _ = _insert_stale_shift(employee_id, location_id)
    recent_id = _insert_recent_open_shift(employee_id, location_id)

    try:
        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        assert status.json()["currentlyWorking"] == []
        assert status.json()["staleOpenShift"]["shiftId"] == stale_id

        attempts = [
            ("/api/timesheet/clock-in", {"location": "123 Main St, Effingham"}),
            ("/api/timesheet/clock-out", {}),
            ("/api/timesheet/visit", {"location": "123 Main St, Effingham"}),
            ("/api/timesheet/depart", {}),
        ]
        for endpoint, payload in attempts:
            response = client.post(endpoint, headers=emp_auth, json=payload)
            assert response.status_code == 409, (endpoint, response.text)
            error = response.json()
            assert error["code"] == "STALE_SHIFT_REQUIRES_REVIEW"
            assert error["details"]["staleOpenShift"]["shiftId"] == stale_id

        stored = db.query_all(
            """
            SELECT id, clock_out
            FROM shifts
            WHERE id = ANY(%s)
            ORDER BY id
            """,
            ([stale_id, recent_id],),
        )
        assert [row["id"] for row in stored] == [stale_id, recent_id]
        assert all(row["clock_out"] is None for row in stored)
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM visits WHERE shift_id = %s",
            (recent_id,),
        )["count"] == 0
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM departures WHERE shift_id = %s",
            (recent_id,),
        )["count"] == 0
    finally:
        db.execute("DELETE FROM shifts WHERE id = ANY(%s)", ([stale_id, recent_id],))


def test_verified_admin_correction_clears_stale_shift_block(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    reason = "verified stale shift correction clears employee block"
    _delete_open_shifts(employee_id)
    stale_id, clock_in = _insert_stale_shift(employee_id, location_id)
    new_shift_id = None

    try:
        selection = {
            "reason": reason,
            "duplicateResolutions": [],
            "staleShiftClosures": [
                {
                    "shiftId": stale_id,
                    "clockOut": (clock_in + timedelta(hours=2)).isoformat(),
                }
            ],
        }
        preview = client.post(
            "/api/admin/corrections/time-data/preview",
            headers=auth,
            json=selection,
        )
        assert preview.status_code == 200, preview.text
        plan = preview.json()
        assert plan["summary"] == {
            "duplicateShiftsToDelete": 0,
            "staleShiftsToClose": 1,
        }

        applied = client.post(
            "/api/admin/corrections/time-data/apply",
            headers=auth,
            json={
                **selection,
                "planToken": plan["planToken"],
                "confirmation": plan["confirmationPhrase"],
            },
        )
        assert applied.status_code == 200, applied.text
        assert applied.json()["closedShiftIds"] == [stale_id]

        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        assert status.json()["staleOpenShift"] is None

        clock_in_response = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 39.1203,
                "longitude": -88.54335,
            },
        )
        assert clock_in_response.status_code == 200, clock_in_response.text
        new_shift_id = clock_in_response.json()["entry"]["id"]

        clock_out_response = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={
                "notes": "cleanup after verified correction",
                "latitude": 39.1203,
                "longitude": -88.54335,
            },
        )
        assert clock_out_response.status_code == 200, clock_out_response.text
    finally:
        shift_ids = [stale_id]
        if new_shift_id is not None:
            shift_ids.append(new_shift_id)
        db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
        db.execute(
            "DELETE FROM time_data_correction_batches WHERE reason = %s",
            (reason,),
        )
