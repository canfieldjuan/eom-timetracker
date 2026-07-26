from __future__ import annotations

import csv
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from zoneinfo import ZoneInfo

import bcrypt
import pytest

import db
import time_tracker_api


CHICAGO = ZoneInfo("America/Chicago")
_HASH_CACHE: dict[str, str] = {}


def _bcrypt_hash(password: str = "payroll1234") -> str:
    if password not in _HASH_CACHE:
        _HASH_CACHE[password] = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(10),
        ).decode("utf-8")
    return _HASH_CACHE[password]


def _local_dt(day: date, hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, second, tzinfo=CHICAGO)


def _create_employee(
    name: str,
    *,
    role: str = "employee",
    active: bool = True,
    password: str = "payroll1234",
    hourly_rate: float | None = None,
) -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO employees (name, password_hash, role, active, hourly_rate)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (name, _bcrypt_hash(password), role, active, hourly_rate),
        )
    )


def _create_shift(
    employee_id: int,
    local_start: datetime,
    local_end: datetime | None,
) -> int:
    clock_in = local_start.astimezone(timezone.utc)
    clock_out = local_end.astimezone(timezone.utc) if local_end else None
    total_hours = None
    if clock_out is not None:
        total_hours = round((clock_out - clock_in).total_seconds() / 3600, 2)
    return int(
        db.execute_returning(
            """
            INSERT INTO shifts (
                employee_id, clock_in, clock_out, total_hours,
                local_date, timezone, notes
            )
            VALUES (%s, %s, %s, %s, %s, 'America/Chicago', 'payroll-weekly-hours-test')
            RETURNING id
            """,
            (employee_id, clock_in, clock_out, total_hours, local_start.date()),
        )
    )


def _delete_employees(employee_ids: list[int]) -> None:
    for employee_id in employee_ids:
        db.execute("DELETE FROM shifts WHERE employee_id = %s", (employee_id,))
    for employee_id in employee_ids:
        db.execute("DELETE FROM employees WHERE id = %s", (employee_id,))


def _login(client, name: str, password: str = "payroll1234") -> dict[str, str]:
    response = client.post("/api/auth/login", json={"name": name, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _employees_by_name(body: dict) -> dict[str, dict]:
    return {employee["employeeName"]: employee for employee in body["employees"]}


def test_admin_can_create_update_and_log_in_payroll_role(client, auth):
    employee_id = None
    try:
        created = client.post(
            "/api/admin/employees",
            headers=auth,
            json={
                "name": "Payroll Role Admin Create",
                "password": "payroll1234",
                "role": "payroll",
            },
        )
        assert created.status_code == 200, created.text
        employee_id = created.json()["employee"]["id"]
        assert created.json()["employee"]["role"] == "payroll"

        login = client.post(
            "/api/auth/login",
            json={"name": "Payroll Role Admin Create", "password": "payroll1234"},
        )
        assert login.status_code == 200, login.text
        assert login.json()["employee"]["role"] == "payroll"

        updated = client.patch(
            f"/api/admin/employees/{employee_id}",
            headers=auth,
            json={"role": "employee"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["employee"]["role"] == "employee"

        restored = client.patch(
            f"/api/admin/employees/{employee_id}",
            headers=auth,
            json={"role": "payroll"},
        )
        assert restored.status_code == 200, restored.text
        assert restored.json()["employee"]["role"] == "payroll"

        invalid = client.post(
            "/api/admin/employees",
            headers=auth,
            json={
                "name": "Payroll Role Invalid",
                "password": "payroll1234",
                "role": "owner",
            },
        )
        assert invalid.status_code == 400, invalid.text
        assert invalid.json()["error"] == "Role must be one of: admin, employee, payroll"
    finally:
        if employee_id is not None:
            _delete_employees([employee_id])


def test_payroll_role_can_read_weekly_hours_but_not_admin_surfaces(client, auth, emp_auth):
    payroll_id = _create_employee("Payroll Boundary Reader", role="payroll")
    try:
        payroll_auth = _login(client, "Payroll Boundary Reader")

        allowed = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=payroll_auth,
        )
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["weekStart"] == "2026-07-19"

        admin_allowed = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=auth,
        )
        assert admin_allowed.status_code == 200, admin_allowed.text

        employee_denied = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=emp_auth,
        )
        assert employee_denied.status_code == 403, employee_denied.text

        payroll_admin_list = client.get("/api/admin/employees", headers=payroll_auth)
        assert payroll_admin_list.status_code == 403, payroll_admin_list.text

        payroll_admin_create = client.post(
            "/api/admin/employees",
            headers=payroll_auth,
            json={
                "name": "Payroll Must Not Create",
                "password": "payroll1234",
                "role": "employee",
            },
        )
        assert payroll_admin_create.status_code == 403, payroll_admin_create.text
    finally:
        _delete_employees([payroll_id])


def test_weekly_hours_include_zero_active_and_inactive_with_week_shift(client, auth):
    week_start = date(2026, 7, 19)
    active_zero_id = _create_employee("Payroll Active Zero Hours")
    inactive_with_shift_id = _create_employee(
        "Payroll Inactive With Hours",
        active=False,
    )
    inactive_outside_id = _create_employee(
        "Payroll Inactive Outside Week",
        active=False,
    )
    sunday_worker_id = _create_employee("Payroll Sunday Worker")
    saturday_worker_id = _create_employee("Payroll Saturday Boundary Worker")
    employee_ids = [
        active_zero_id,
        inactive_with_shift_id,
        inactive_outside_id,
        sunday_worker_id,
        saturday_worker_id,
    ]

    try:
        _create_shift(
            inactive_with_shift_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 9, 30),
        )
        _create_shift(
            inactive_outside_id,
            _local_dt(week_start + timedelta(days=7), 8),
            _local_dt(week_start + timedelta(days=7), 9),
        )
        _create_shift(
            sunday_worker_id,
            _local_dt(week_start, 9),
            _local_dt(week_start, 11),
        )
        _create_shift(
            saturday_worker_id,
            _local_dt(week_start + timedelta(days=6), 23),
            _local_dt(week_start + timedelta(days=7), 1),
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        employees = _employees_by_name(body)

        assert body["period"] == "week"
        assert body["timezone"] == "America/Chicago"
        assert body["weekStart"] == "2026-07-19"
        assert body["weekEnd"] == "2026-07-25"
        assert "Payroll Active Zero Hours" in employees
        assert employees["Payroll Active Zero Hours"]["totalMinutes"] == 0
        assert employees["Payroll Active Zero Hours"]["active"] is True

        assert "Payroll Inactive With Hours" in employees
        assert employees["Payroll Inactive With Hours"]["active"] is False
        assert employees["Payroll Inactive With Hours"]["totalMinutes"] == 90
        assert employees["Payroll Inactive With Hours"]["totalHours"] == 1.5

        assert "Payroll Inactive Outside Week" not in employees
        assert employees["Payroll Sunday Worker"]["totalMinutes"] == 120
        assert employees["Payroll Sunday Worker"]["days"][0]["totalMinutes"] == 120
        assert employees["Payroll Saturday Boundary Worker"]["totalMinutes"] == 60
        assert employees["Payroll Saturday Boundary Worker"]["days"][6]["totalMinutes"] == 60
    finally:
        _delete_employees(employee_ids)


def test_weekly_hours_flags_open_and_invalid_without_counting_minutes(client, auth):
    employee_id = _create_employee("Payroll Issue Worker")
    week_start = date(2026, 7, 19)
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=2), 8),
            _local_dt(week_start + timedelta(days=2), 10),
        )
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=3), 8),
            None,
        )
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=4), 10),
            _local_dt(week_start + timedelta(days=4), 9),
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        employee = _employees_by_name(response.json())["Payroll Issue Worker"]

        assert employee["totalMinutes"] == 120
        assert employee["completedShiftCount"] == 1
        assert employee["overlappingShiftCount"] == 3
        assert employee["issueCodes"] == ["invalid_shift_duration", "missing_clock_out"]
        assert {issue["code"] for issue in employee["issues"]} == {
            "invalid_shift_duration",
            "missing_clock_out",
        }
        assert response.json()["summary"]["hasBlockingIssues"] is True
    finally:
        _delete_employees([employee_id])


def test_cross_midnight_shift_rounds_once_before_day_allocation(client, auth):
    employee_id = _create_employee("Payroll Midnight Rounding Worker")
    try:
        _create_shift(
            employee_id,
            _local_dt(date(2026, 7, 19), 23, 59, 29),
            _local_dt(date(2026, 7, 20), 0, 0, 31),
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        employee = _employees_by_name(response.json())["Payroll Midnight Rounding Worker"]

        assert employee["totalMinutes"] == 1
        assert sum(day["totalMinutes"] for day in employee["days"]) == 1
        assert employee["completedShiftCount"] == 1
    finally:
        _delete_employees([employee_id])


def test_invalid_shift_with_clock_out_before_week_start_is_flagged(client, auth):
    employee_id = _create_employee("Payroll Invalid Boundary Worker")
    week_start = date(2026, 7, 19)
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start, 0, 15),
            _local_dt(week_start - timedelta(days=1), 23, 45),
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-19",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        employee = _employees_by_name(response.json())["Payroll Invalid Boundary Worker"]

        assert employee["totalMinutes"] == 0
        assert employee["completedShiftCount"] == 0
        assert employee["overlappingShiftCount"] == 1
        assert employee["issueCodes"] == ["invalid_shift_duration"]
        assert response.json()["summary"]["hasBlockingIssues"] is True
    finally:
        _delete_employees([employee_id])


def test_open_current_shift_does_not_pollute_future_week(client, auth, monkeypatch):
    employee_id = _create_employee("Payroll Future Open Worker")
    current_time = _local_dt(date(2026, 7, 22), 12).astimezone(timezone.utc)
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: current_time)
    try:
        _create_shift(
            employee_id,
            _local_dt(date(2026, 7, 22), 8),
            None,
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours?weekStart=2026-07-26",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        employee = _employees_by_name(response.json())["Payroll Future Open Worker"]

        assert employee["totalMinutes"] == 0
        assert employee["completedShiftCount"] == 0
        assert employee["overlappingShiftCount"] == 0
        assert employee["issueCodes"] == []
    finally:
        _delete_employees([employee_id])


def test_week_start_must_be_a_sunday(client, auth):
    response = client.get(
        "/api/admin/payroll/weekly-hours?weekStart=2026-07-20",
        headers=auth,
    )
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "weekStart must be a Sunday"


def test_payroll_weekly_hours_export_uses_same_model_and_hides_rates(client, auth):
    employee_id = _create_employee(
        "Payroll CSV Worker",
        hourly_rate=22.50,
    )
    try:
        _create_shift(
            employee_id,
            _local_dt(date(2026, 7, 19), 7),
            _local_dt(date(2026, 7, 19), 9),
        )

        response = client.get(
            "/api/admin/payroll/weekly-hours/export?weekStart=2026-07-19",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/csv")
        assert "eom_payroll_weekly_hours_2026-07-19.csv" in response.headers[
            "content-disposition"
        ]

        text = response.text
        rows = list(csv.reader(StringIO(text)))
        assert ["Employee", "Status", "Total Hours", "Total Minutes", "Completed Shifts", "Issues"] in rows
        assert any(row[:4] == ["Payroll CSV Worker", "Active", "2.00", "120"] for row in rows)
        assert "hourlyRate" not in text
        assert "22.5" not in text
        assert "22.50" not in text
    finally:
        _delete_employees([employee_id])


def test_employee_role_migration_allows_payroll_on_existing_constraints():
    db.execute(
        """
        DO $$
        DECLARE
            role_constraint RECORD;
        BEGIN
            FOR role_constraint IN
                SELECT constraint_row.conname
                FROM pg_constraint constraint_row
                WHERE constraint_row.conrelid = 'employees'::regclass
                  AND constraint_row.contype = 'c'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(constraint_row.conkey) AS key_row(attnum)
                      JOIN pg_attribute attribute_row
                        ON attribute_row.attrelid = constraint_row.conrelid
                       AND attribute_row.attnum = key_row.attnum
                      WHERE attribute_row.attname = 'role'
                  )
            LOOP
                EXECUTE format(
                    'ALTER TABLE employees DROP CONSTRAINT %%I',
                    role_constraint.conname
                );
            END LOOP;
        END $$;

        ALTER TABLE employees
            ADD CONSTRAINT employees_role_check
            CHECK (role IN ('admin', 'employee')) NOT VALID;
        """
    )

    with pytest.raises(Exception):
        _create_employee("Payroll Before Role Migration", role="payroll")

    employee_id = None
    try:
        time_tracker_api._ensure_employee_role_schema()
        employee_id = _create_employee("Payroll After Role Migration", role="payroll")
        row = db.query_one("SELECT role FROM employees WHERE id = %s", (employee_id,))
        assert row is not None
        assert row["role"] == "payroll"
    finally:
        if employee_id is not None:
            _delete_employees([employee_id])
