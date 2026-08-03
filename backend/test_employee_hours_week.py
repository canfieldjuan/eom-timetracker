from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

import db
import time_tracker_api


CHICAGO = ZoneInfo("America/Chicago")


def _utc_from_local(day: date, hour: int, minute: int = 0) -> datetime:
    return datetime(
        day.year,
        day.month,
        day.day,
        hour,
        minute,
        tzinfo=CHICAGO,
    ).astimezone(timezone.utc)


def _create_employee(name: str) -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO employees (name, password_hash, role)
            VALUES (%s, 'not-used', 'employee')
            RETURNING id
            """,
            (name,),
        )
    )


def _create_shift(employee_id: int, local_day: date, hour: int, hours: float) -> int:
    clock_in = _utc_from_local(local_day, hour)
    clock_out = clock_in + timedelta(hours=hours)
    return int(
        db.execute_returning(
            """
            INSERT INTO shifts (
                employee_id, clock_in, clock_out, total_hours,
                local_date, timezone, notes
            )
            VALUES (%s, %s, %s, %s, %s, 'America/Chicago', 'local-week-test')
            RETURNING id
            """,
            (employee_id, clock_in, clock_out, hours, local_day),
        )
    )


def _delete_employee(employee_id: int) -> None:
    db.execute("DELETE FROM shifts WHERE employee_id = %s", (employee_id,))
    db.execute("DELETE FROM employees WHERE id = %s", (employee_id,))


def _week_dates(body: dict) -> list[str]:
    return [row["date"] for row in body["weekGrid"]]


def test_employee_hours_uses_one_local_sunday_to_saturday_week(
    client,
    auth,
    monkeypatch,
):
    employee_id = _create_employee("Local Week Boundary Employee")
    fixed_now = _utc_from_local(date(2026, 7, 22), 10)
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: fixed_now)

    try:
        _create_shift(employee_id, date(2026, 7, 18), 23, 4.0)
        _create_shift(employee_id, date(2026, 7, 19), 0, 1.0)
        _create_shift(employee_id, date(2026, 7, 25), 23, 2.0)
        _create_shift(employee_id, date(2026, 7, 26), 0, 8.0)

        current = client.get(
            f"/api/admin/employees/{employee_id}/hours?week_offset=0",
            headers=auth,
        )
        assert current.status_code == 200, current.text
        body = current.json()
        assert body["weekStartDate"] == "2026-07-19"
        assert _week_dates(body) == [
            "2026-07-19",
            "2026-07-20",
            "2026-07-21",
            "2026-07-22",
            "2026-07-23",
            "2026-07-24",
            "2026-07-25",
        ]
        assert [row["dayLabel"].split(",", 1)[0] for row in body["weekGrid"]] == [
            "Sun",
            "Mon",
            "Tue",
            "Wed",
            "Thu",
            "Fri",
            "Sat",
        ]
        assert body["weekTotal"] == 3.0
        assert body["weeklyHours"] == 3.0
        assert body["weekGrid"][0]["totalHours"] == 1.0
        assert body["weekGrid"][6]["totalHours"] == 2.0

        previous = client.get(
            f"/api/admin/employees/{employee_id}/hours?week_offset=-1",
            headers=auth,
        )
        assert previous.status_code == 200, previous.text
        previous_body = previous.json()
        assert previous_body["weekStartDate"] == "2026-07-12"
        assert _week_dates(previous_body)[-1] == "2026-07-18"
        assert previous_body["weekTotal"] == 4.0
        assert previous_body["weeklyHours"] == 4.0
    finally:
        _delete_employee(employee_id)


def test_my_hours_uses_local_sunday_to_saturday_week(
    client,
    monkeypatch,
):
    employee_name = "Self Hours Sunday Employee"
    employee_id = _create_employee(employee_name)
    headers = {
        "Authorization": (
            f"Bearer {time_tracker_api.create_auth_token(employee_id, employee_name)}"
        )
    }
    fixed_now = _utc_from_local(date(2026, 7, 22), 10)
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: fixed_now)

    try:
        _create_shift(employee_id, date(2026, 7, 18), 23, 4.0)
        _create_shift(employee_id, date(2026, 7, 19), 0, 1.0)
        _create_shift(employee_id, date(2026, 7, 25), 23, 2.0)
        _create_shift(employee_id, date(2026, 7, 26), 0, 8.0)

        response = client.get("/api/timesheet/my-hours", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["weeklyHours"] == 3.0
        assert body["todayHours"] == 0.0
        assert {shift["date"] for shift in body["recentShifts"]} >= {
            "2026-07-18",
            "2026-07-19",
            "2026-07-25",
            "2026-07-26",
        }
    finally:
        _delete_employee(employee_id)


def test_dashboard_hours_summary_uses_local_sunday_to_saturday_week(
    client,
    auth,
    monkeypatch,
):
    employee_name = "Dashboard Hours Sunday Employee"
    employee_id = _create_employee(employee_name)
    fixed_now = _utc_from_local(date(2026, 7, 22), 10)
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: fixed_now)

    try:
        _create_shift(employee_id, date(2026, 7, 18), 23, 4.0)
        _create_shift(employee_id, date(2026, 7, 19), 0, 1.0)
        _create_shift(employee_id, date(2026, 7, 25), 23, 2.0)
        _create_shift(employee_id, date(2026, 7, 26), 0, 8.0)

        response = client.get("/api/hours", headers=auth)
        assert response.status_code == 200, response.text
        body = response.json()["data"]
        employee_row = next(
            row for row in body["employees"] if row["name"] == employee_name
        )
        assert employee_row["totalHours"] == 3.0
        assert body["summary"]["totalHours"] >= employee_row["totalHours"]
    finally:
        _delete_employee(employee_id)


@pytest.mark.parametrize(
    ("week_start", "reference_day"),
    [
        (date(2026, 3, 8), date(2026, 3, 11)),
        (date(2026, 11, 1), date(2026, 11, 4)),
    ],
)
def test_employee_hours_keeps_seven_local_dates_across_dst_weeks(
    client,
    auth,
    monkeypatch,
    week_start,
    reference_day,
):
    employee_id = _create_employee(f"DST Week Employee {week_start.isoformat()}")
    fixed_now = _utc_from_local(reference_day, 12)
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: fixed_now)
    week_end = week_start + timedelta(days=6)

    try:
        _create_shift(employee_id, week_start, 0, 1.0)
        _create_shift(employee_id, week_end, 23, 1.0)

        response = client.get(
            f"/api/admin/employees/{employee_id}/hours",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["weekStartDate"] == week_start.isoformat()
        assert _week_dates(body) == [
            (week_start + timedelta(days=offset)).isoformat()
            for offset in range(7)
        ]
        assert body["weekTotal"] == 2.0
        assert body["weeklyHours"] == 2.0
    finally:
        _delete_employee(employee_id)
