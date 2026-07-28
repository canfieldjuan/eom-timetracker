from __future__ import annotations

import csv
from datetime import date, datetime, timedelta, timezone
from io import BytesIO, StringIO
from zoneinfo import ZoneInfo

import bcrypt
import pytest
from pypdf import PdfReader

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


def _delete_payroll_verification_weeks(week_starts: list[date]) -> None:
    for week_start in week_starts:
        db.execute(
            "DELETE FROM payroll_hour_corrections WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_verification_batches WHERE week_start = %s",
            (week_start,),
        )


def _login(client, name: str, password: str = "payroll1234") -> dict[str, str]:
    response = client.post("/api/auth/login", json={"name": name, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _employees_by_name(body: dict) -> dict[str, dict]:
    return {employee["employeeName"]: employee for employee in body["employees"]}


def _weekly_hours(client, auth: dict[str, str], week_start: date) -> dict:
    response = client.get(
        f"/api/admin/payroll/weekly-hours?weekStart={week_start.isoformat()}",
        headers=auth,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _delete_payroll_labor_profitability_rows() -> None:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM payroll_hour_corrections
                WHERE employee_id IN (
                    SELECT id FROM employees
                    WHERE name LIKE 'Payroll Labor Profitability%'
                )
                """
            )
            cur.execute(
                """
                DELETE FROM site_check_ins
                WHERE employee_id IN (
                    SELECT id FROM employees
                    WHERE name LIKE 'Payroll Labor Profitability%'
                )
                   OR location_id IN (
                    SELECT id FROM locations
                    WHERE address LIKE 'Payroll Labor Profitability%'
                )
                """
            )
            cur.execute(
                """
                DELETE FROM shifts
                WHERE employee_id IN (
                    SELECT id FROM employees
                    WHERE name LIKE 'Payroll Labor Profitability%'
                )
                   OR location_id IN (
                    SELECT id FROM locations
                    WHERE address LIKE 'Payroll Labor Profitability%'
                )
                """
            )
            cur.execute(
                "DELETE FROM jobs WHERE customer_name LIKE 'Payroll Labor Profitability%'"
            )
            cur.execute(
                "DELETE FROM locations WHERE address LIKE 'Payroll Labor Profitability%'"
            )
            cur.execute(
                "DELETE FROM customers WHERE name LIKE 'Payroll Labor Profitability%'"
            )
            cur.execute(
                """
                DELETE FROM google_calendar_sources
                WHERE calendar_id LIKE 'payroll_labor_profitability%'
                """
            )
            cur.execute(
                """
                DELETE FROM google_calendar_connections
                WHERE google_account_email LIKE 'payroll_labor_profitability%'
                """
            )
            cur.execute(
                "DELETE FROM employees WHERE name LIKE 'Payroll Labor Profitability%'"
            )


def _create_payroll_profitability_source() -> int:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO google_calendar_connections (
                    google_account_email, granted_scopes, revoked_at
                )
                VALUES (
                    'payroll_labor_profitability@example.test',
                    ARRAY['calendar.readonly'],
                    NOW()
                )
                RETURNING id
                """
            )
            connection_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO google_calendar_sources (
                    connection_id, role, calendar_id, calendar_name,
                    calendar_timezone
                )
                VALUES (
                    %s,
                    'residential_morning',
                    'payroll_labor_profitability_calendar',
                    'Payroll Labor Profitability Calendar',
                    'America/Chicago'
                )
                RETURNING id
                """,
                (connection_id,),
            )
            return int(cur.fetchone()[0])


def _create_payroll_profitability_site(
    address: str = "Payroll Labor Profitability Site",
) -> tuple[int, int]:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO customers (name)
                VALUES ('Payroll Labor Profitability Customer')
                RETURNING id
                """
            )
            customer_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO locations (
                    customer_id, address, customer_name, location_type,
                    rate, rate_type, expected_hours, target_labor_pct
                )
                VALUES (
                    %s,
                    %s,
                    'Payroll Labor Profitability Customer',
                    'Residential',
                    150.00,
                    'per_visit',
                    3.00,
                    40.00
                )
                RETURNING id
                """,
                (customer_id, address),
            )
            return customer_id, int(cur.fetchone()[0])


def _create_payroll_profitability_job_only(
    *,
    site_id: int,
    source_id: int,
    scheduled_date: date,
    scheduled_start: datetime,
    scheduled_end: datetime,
    source_key: str,
) -> int:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date,
                    scheduled_start, scheduled_end, status, calendar_source_id,
                    source_calendar_id, source_event_id, source_occurrence_id,
                    source_key, source_fingerprint, source_title
                )
                VALUES (
                    %s,
                    'Payroll Labor Profitability Customer',
                    %s,
                    %s,
                    %s,
                    'scheduled',
                    %s,
                    'payroll_labor_profitability_calendar',
                    'payroll-labor-profitability-event',
                    'payroll-labor-profitability-occurrence',
                    %s,
                    %s,
                    'Payroll Labor Profitability Customer'
                )
                RETURNING id
                """,
                (
                    site_id,
                    scheduled_date,
                    scheduled_start.astimezone(timezone.utc),
                    scheduled_end.astimezone(timezone.utc),
                    source_id,
                    source_key,
                    source_key,
                ),
            )
            return int(cur.fetchone()[0])


def _create_payroll_profitability_job_and_shift(
    *,
    employee_id: int,
    site_id: int,
    source_id: int,
    service_day: date,
    local_start: datetime | None = None,
    local_end: datetime | None = None,
) -> int:
    start = local_start or _local_dt(service_day, 9)
    end = local_end or _local_dt(service_day, 11)
    source_key = "1" * 64
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date,
                    scheduled_start, scheduled_end, status, calendar_source_id,
                    source_calendar_id, source_event_id, source_occurrence_id,
                    source_key, source_fingerprint, source_title
                )
                VALUES (
                    %s,
                    'Payroll Labor Profitability Customer',
                    %s,
                    %s,
                    %s,
                    'scheduled',
                    %s,
                    'payroll_labor_profitability_calendar',
                    'payroll-labor-profitability-event',
                    'payroll-labor-profitability-occurrence',
                    %s,
                    %s,
                    'Payroll Labor Profitability Customer'
                )
                RETURNING id
                """,
                (
                    site_id,
                    service_day,
                    start.astimezone(timezone.utc),
                    end.astimezone(timezone.utc),
                    source_id,
                    source_key,
                    source_key,
                ),
            )
            job_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, job_id,
                    clock_in, clock_out, total_hours, local_date, timezone,
                    time_category, notes
                )
                VALUES (
                    %s,
                    %s,
                    'Payroll Labor Profitability Site',
                    %s,
                    %s,
                    %s,
                    2.00,
                    %s,
                    'America/Chicago',
                    'productive',
                    'payroll labor profitability test'
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site_id,
                    job_id,
                    start.astimezone(timezone.utc),
                    end.astimezone(timezone.utc),
                    service_day,
                ),
            )
            shift_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', 'on_time', 'test', 0, 'not_required'
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site_id,
                    job_id,
                    start.astimezone(timezone.utc),
                    start.astimezone(timezone.utc),
                ),
            )
            check_in_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, sequence_version, site_check_in_id
                )
                VALUES (
                    %s,
                    %s,
                    'Payroll Labor Profitability Site',
                    'Payroll Labor Profitability Customer',
                    %s,
                    2,
                    %s
                )
                RETURNING id
                """,
                (shift_id, site_id, start.astimezone(timezone.utc), check_in_id),
            )
            visit_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO departures (
                    shift_id, visit_id, location_id, location_label,
                    customer_name, departure_time
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'Payroll Labor Profitability Site',
                    'Payroll Labor Profitability Customer',
                    %s
                )
                """,
                (shift_id, visit_id, site_id, end.astimezone(timezone.utc)),
            )
            return job_id


def _create_payroll_profitability_shift_evidence(
    *,
    employee_id: int,
    local_start: datetime,
    local_end: datetime,
    site_id: int | None = None,
    job_id: int | None = None,
    qr_site_id: int | None = None,
    qr_job_id: int | None = None,
    qr_local_time: datetime | None = None,
) -> int:
    clock_in = local_start.astimezone(timezone.utc)
    clock_out = local_end.astimezone(timezone.utc)
    total_hours = round((clock_out - clock_in).total_seconds() / 3600, 4)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, job_id,
                    clock_in, clock_out, total_hours, local_date, timezone,
                    time_category, notes
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'America/Chicago',
                    'productive',
                    'payroll labor profitability test'
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site_id,
                    (
                        "Payroll Labor Profitability Site"
                        if site_id is not None
                        else ""
                    ),
                    job_id,
                    clock_in,
                    clock_out,
                    total_hours,
                    local_start.date(),
                ),
            )
            shift_id = int(cur.fetchone()[0])
            if qr_site_id is not None and qr_job_id is not None:
                checked_in_at = (qr_local_time or local_start).astimezone(
                    timezone.utc
                )
                cur.execute(
                    """
                    INSERT INTO site_check_ins (
                        employee_id, location_id, job_id, server_checked_in_at,
                        device_scanned_at, latitude, longitude, accuracy_m,
                        geofence_radius_m, distance_m, geofence_status,
                        classification, classification_reason,
                        device_clock_skew_seconds, review_status
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                        100, 3, 'inside', 'on_time', 'test', 0, 'not_required'
                    )
                    """,
                    (
                        employee_id,
                        qr_site_id,
                        qr_job_id,
                        checked_in_at,
                        checked_in_at,
                    ),
                )
            return shift_id


def _assert_valid_pdf(payload: bytes) -> None:
    assert payload.startswith(b"%PDF-")
    assert b"%%EOF" in payload[-1024:]
    assert len(payload) > 1000


def _extract_pdf_text(payload: bytes) -> str:
    return "\n".join(
        page.extract_text() or ""
        for page in PdfReader(BytesIO(payload)).pages
    )


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _different_fingerprint(fingerprint: str) -> str:
    return ("0" * 64) if fingerprint != ("0" * 64) else ("1" * 64)


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


def test_payroll_week_verification_requires_current_fingerprint_and_records_audit(client, auth):
    week_start = date(2026, 8, 2)
    employee_id = _create_employee("Payroll Verification Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 10),
        )
        weekly = _weekly_hours(client, auth, week_start)

        stale = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": _different_fingerprint(weekly["sourceFingerprint"]),
            },
        )
        assert stale.status_code == 409, stale.text
        assert stale.json()["error"] == "Payroll weekly hours changed; refresh before verifying"

        verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
                "reason": "Mayra checked the weekly total before Square entry.",
            },
        )
        assert verified.status_code == 200, verified.text
        body = verified.json()
        assert body["action"] == "verify"
        assert body["idempotent"] is False
        assert body["weeklyHours"]["sourceFingerprint"] == weekly["sourceFingerprint"]
        assert body["verification"]["status"] == "verified"
        assert body["verification"]["sourceFingerprint"] == weekly["sourceFingerprint"]
        assert body["verification"]["stale"] is False
        assert body["verification"]["batchId"] is not None

        repeated = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["idempotent"] is True

        status_response = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert status_response.status_code == 200, status_response.text
        status_body = status_response.json()
        assert status_body["currentSourceFingerprint"] == weekly["sourceFingerprint"]
        assert status_body["summary"]["totalMinutes"] >= 120
        assert status_body["verification"]["status"] == "verified"
        assert status_body["verification"]["stale"] is False

        event_row = db.query_one(
            """
            SELECT COUNT(*) AS n
            FROM payroll_verification_events
            WHERE week_start = %s AND action = 'verify'
            """,
            (week_start,),
        )
        assert event_row is not None
        assert event_row["n"] == 1
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_verification_blocks_issue_weeks_and_employee_role(client, auth, emp_auth):
    week_start = date(2026, 7, 19)
    employee_id = _create_employee("Payroll Verification Issue Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=2), 8),
            None,
        )
        weekly = _weekly_hours(client, auth, week_start)
        assert weekly["summary"]["hasBlockingIssues"] is True

        employee_denied = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=emp_auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert employee_denied.status_code == 403, employee_denied.text

        blocked = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert blocked.status_code == 409, blocked.text
        assert blocked.json()["error"] == "Resolve payroll hour issues before verifying this week"

        event_row = db.query_one(
            "SELECT COUNT(*) AS n FROM payroll_verification_events WHERE week_start = %s",
            (week_start,),
        )
        assert event_row is not None
        assert event_row["n"] == 0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_verification_reports_stale_and_requires_reverify_before_finalize(client, auth):
    week_start = date(2026, 8, 16)
    employee_id = _create_employee("Payroll Verification Stale Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        shift_id = _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=3), 8),
            _local_dt(week_start + timedelta(days=3), 10),
        )
        first_weekly = _weekly_hours(client, auth, week_start)
        first_fingerprint = first_weekly["sourceFingerprint"]
        verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": first_fingerprint,
            },
        )
        assert verified.status_code == 200, verified.text

        corrected_clock_out = _local_dt(week_start + timedelta(days=3), 11).astimezone(
            timezone.utc
        )
        db.execute(
            """
            UPDATE shifts
            SET
                clock_out = %s,
                total_hours = ROUND(
                    (EXTRACT(EPOCH FROM (%s::timestamptz - clock_in)) / 3600.0)::numeric,
                    2
                )
            WHERE id = %s
            """,
            (corrected_clock_out, corrected_clock_out, shift_id),
        )

        status_response = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert status_response.status_code == 200, status_response.text
        status_body = status_response.json()
        assert status_body["currentSourceFingerprint"] != first_fingerprint
        assert status_body["verification"]["sourceFingerprint"] == first_fingerprint
        assert status_body["verification"]["stale"] is True

        stale_finalize = client.post(
            "/api/admin/payroll/weekly-hours/finalize",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": first_fingerprint,
            },
        )
        assert stale_finalize.status_code == 409, stale_finalize.text
        assert stale_finalize.json()["error"] == "Payroll weekly hours changed; refresh before finalizing"

        reopened = client.post(
            "/api/admin/payroll/weekly-hours/reopen",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "reason": "Clock-out was corrected before final payroll entry.",
            },
        )
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["verification"]["status"] == "reopened"

        second_weekly = _weekly_hours(client, auth, week_start)
        second_fingerprint = second_weekly["sourceFingerprint"]
        assert second_fingerprint != first_fingerprint

        reverified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": second_fingerprint,
            },
        )
        assert reverified.status_code == 200, reverified.text
        assert reverified.json()["verification"]["status"] == "verified"

        finalized = client.post(
            "/api/admin/payroll/weekly-hours/finalize",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": second_fingerprint,
            },
        )
        assert finalized.status_code == 200, finalized.text
        assert finalized.json()["verification"]["status"] == "finalized"

        events = db.query_all(
            """
            SELECT action
            FROM payroll_verification_events
            WHERE week_start = %s
            ORDER BY id
            """,
            (week_start,),
        )
        assert [row["action"] for row in events] == [
            "verify",
            "reopen",
            "verify",
            "finalize",
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_hour_correction_overlays_day_total_without_mutating_shift(client, auth):
    week_start = date(2026, 8, 23)
    correction_date = week_start + timedelta(days=2)
    employee_id = _create_employee("Payroll Correction Overlay Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        shift_id = _create_shift(
            employee_id,
            _local_dt(correction_date, 8),
            _local_dt(correction_date, 10),
        )
        before = _weekly_hours(client, auth, week_start)

        response = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra confirmed the cleaner worked one extra hour.",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["action"] == "correct"
        assert body["idempotent"] is False
        assert body["correction"]["employeeId"] == employee_id
        assert body["correction"]["correctedTotalMinutes"] == 180
        assert body["weeklyHours"]["sourceFingerprint"] != before["sourceFingerprint"]
        assert body["weeklyHours"]["summary"]["correctionCount"] == 1

        employee = _employees_by_name(body["weeklyHours"])["Payroll Correction Overlay Worker"]
        assert employee["totalMinutes"] == 180
        assert employee["totalHours"] == 3
        assert employee["correctionCount"] == 1
        corrected_day = employee["days"][2]
        assert corrected_day["totalMinutes"] == 180
        assert corrected_day["correction"]["sourceTotalMinutes"] == 120
        assert corrected_day["correction"]["deltaMinutes"] == 60
        assert corrected_day["correction"]["reason"] == (
            "Mayra confirmed the cleaner worked one extra hour."
        )

        stored_shift = db.query_one(
            "SELECT total_hours FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert stored_shift is not None
        assert float(stored_shift["total_hours"]) == 2

        corrections = client.get(
            f"/api/admin/payroll/weekly-hours/corrections?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert corrections.status_code == 200, corrections.text
        assert [row["correctionId"] for row in corrections.json()["corrections"]] == [
            body["correction"]["correctionId"]
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_corrections_require_reopen_after_verification_and_supersede(client, auth):
    week_start = date(2026, 8, 30)
    correction_date = week_start + timedelta(days=1)
    employee_id = _create_employee("Payroll Correction Reopen Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(correction_date, 8),
            _local_dt(correction_date, 9),
        )
        first_correction = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 90,
                "reason": "Initial correction from Mayra.",
            },
        )
        assert first_correction.status_code == 200, first_correction.text
        weekly = first_correction.json()["weeklyHours"]
        verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert verified.status_code == 200, verified.text

        blocked = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 120,
                "reason": "Attempt before reopen should fail.",
            },
        )
        assert blocked.status_code == 409, blocked.text
        assert blocked.json()["error"] == "Reopen the payroll week before changing corrections"

        reopened = client.post(
            "/api/admin/payroll/weekly-hours/reopen",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "reason": "Need to change one corrected day.",
            },
        )
        assert reopened.status_code == 200, reopened.text

        second_correction = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 120,
                "reason": "Updated correction from Mayra.",
            },
        )
        assert second_correction.status_code == 200, second_correction.text
        assert second_correction.json()["weeklyHours"]["summary"]["correctionCount"] == 1
        employee = _employees_by_name(second_correction.json()["weeklyHours"])[
            "Payroll Correction Reopen Worker"
        ]
        assert employee["totalMinutes"] == 120

        rows = db.query_all(
            """
            SELECT status, superseded_by
            FROM payroll_hour_corrections
            WHERE week_start = %s AND employee_id = %s
            ORDER BY id
            """,
            (week_start, employee_id),
        )
        assert [row["status"] for row in rows] == ["superseded", "active"]
        assert rows[0]["superseded_by"] == second_correction.json()["correction"]["correctionId"]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_void_payroll_correction_restores_shift_total_and_employee_role_is_denied(
    client,
    auth,
    emp_auth,
):
    week_start = date(2026, 9, 6)
    correction_date = week_start
    employee_id = _create_employee("Payroll Correction Void Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(correction_date, 8),
            _local_dt(correction_date, 10),
        )
        employee_denied = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=emp_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Employees cannot write payroll corrections.",
            },
        )
        assert employee_denied.status_code == 403, employee_denied.text

        created = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Temporary correction to void.",
            },
        )
        assert created.status_code == 200, created.text
        correction_id = created.json()["correction"]["correctionId"]

        voided = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/void",
            headers=auth,
            json={"reason": "Correction was entered for the wrong employee."},
        )
        assert voided.status_code == 200, voided.text
        assert voided.json()["correction"]["status"] == "voided"
        assert voided.json()["weeklyHours"]["summary"]["correctionCount"] == 0
        employee = _employees_by_name(voided.json()["weeklyHours"])[
            "Payroll Correction Void Worker"
        ]
        assert employee["totalMinutes"] == 120
        assert "correction" not in employee["days"][0]

        corrections = client.get(
            f"/api/admin/payroll/weekly-hours/corrections?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert corrections.status_code == 200, corrections.text
        assert corrections.json()["corrections"] == []
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_verification_schema_migration_installs_existing_deployments():
    db.execute(
        "DROP TABLE IF EXISTS payroll_hour_correction_allocations, "
        "payroll_hour_corrections, "
        "payroll_verification_events, payroll_verification_batches"
    )
    time_tracker_api._ensure_schema_migrations()

    batch_table = db.query_one(
        "SELECT to_regclass('payroll_verification_batches') AS table_name"
    )
    event_table = db.query_one(
        "SELECT to_regclass('payroll_verification_events') AS table_name"
    )
    correction_table = db.query_one(
        "SELECT to_regclass('payroll_hour_corrections') AS table_name"
    )
    allocation_table = db.query_one(
        "SELECT to_regclass('payroll_hour_correction_allocations') AS table_name"
    )
    status_check = db.query_one(
        """
        SELECT 1 AS found
        FROM pg_constraint
        WHERE conrelid = 'payroll_verification_batches'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%%finalized%%'
        LIMIT 1
        """
    )

    assert batch_table is not None
    assert batch_table["table_name"] == "payroll_verification_batches"
    assert event_table is not None
    assert event_table["table_name"] == "payroll_verification_events"
    assert correction_table is not None
    assert correction_table["table_name"] == "payroll_hour_corrections"
    assert allocation_table is not None
    assert allocation_table["table_name"] == "payroll_hour_correction_allocations"
    assert status_check == {"found": 1}


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


def test_payroll_weekly_hours_pdf_requires_payroll_before_computing(
    client,
    emp_auth,
    monkeypatch,
):
    calls = 0

    def forbidden_compute(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("unauthorized request reached payroll PDF computation")

    monkeypatch.setattr(time_tracker_api, "_compute_payroll_weekly_hours", forbidden_compute)

    assert client.get("/api/admin/payroll/weekly-hours/pdf").status_code == 401
    assert client.get("/api/admin/payroll/weekly-hours/pdf", headers=emp_auth).status_code == 403
    assert calls == 0


def test_payroll_weekly_hours_pdf_includes_verification_and_corrections_without_rates(
    client,
    auth,
):
    week_start = date(2026, 9, 13)
    correction_date = week_start + timedelta(days=1)
    employee_id = _create_employee(
        "Payroll PDF Worker",
        hourly_rate=22.50,
    )
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(correction_date, 8),
            _local_dt(correction_date, 10),
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": correction_date.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra confirmed PDF correction.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": corrected.json()["weeklyHours"]["sourceFingerprint"],
            },
        )
        assert verified.status_code == 200, verified.text

        response = client.get(
            f"/api/admin/payroll/weekly-hours/pdf?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/pdf"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-disposition"] == (
            'attachment; filename="eom_payroll_weekly_hours_2026-09-13.pdf"'
        )
        _assert_valid_pdf(response.content)

        text = _extract_pdf_text(response.content)
        normalized = _normalized_text(text)
        assert "Payroll Weekly Hours" in text
        assert "Horas semanales" in text
        assert "Verified / Verificado" in text
        assert "Payroll PDF Worker" in text
        assert "Mayra confirmed PDF correction." in text
        assert "Corrected from 2.00h" in normalized
        assert "change +1.00h" in normalized
        assert "3.00h" in normalized
        assert "22.5" not in text
        assert "22.50" not in text
        assert "$" not in text
        assert "Hourly rate" not in text
        assert "Gross" not in text
        assert "Net" not in text
        assert "Overtime" not in text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_labor_profitability_requires_payroll_before_computing(
    client,
    emp_auth,
    monkeypatch,
):
    def forbidden_compute(*_args, **_kwargs):
        raise AssertionError("payroll labor profitability computed before auth")

    monkeypatch.setattr(
        time_tracker_api,
        "build_weekly_labor_profitability",
        forbidden_compute,
    )

    assert client.get("/api/admin/payroll/labor-profitability").status_code == 401
    assert (
        client.get(
            "/api/admin/payroll/labor-profitability",
            headers=emp_auth,
        ).status_code
        == 403
    )


def test_payroll_labor_profitability_reports_actual_site_margin_without_rates(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["success"] is True
        assert body["weekStart"] == "2026-07-19"
        assert body["weekEnd"] == "2026-07-25"
        assert body["verification"]["status"] == "unverified"
        assert body["payrollHours"]["totalHours"] == 2.0
        assert body["payrollHours"]["correctionCount"] == 0
        assert body["issues"] == []

        assert body["summary"]["jobCount"] == 1
        assert body["summary"]["plannedHours"] == 3.0
        assert body["summary"]["actualHours"] == 2.0
        assert body["summary"]["varianceHours"] == -1.0
        assert body["summary"]["revenue"] == 150.0
        assert body["summary"]["actualLaborCost"] == 40.0
        assert body["summary"]["netProfit"] == 110.0
        assert body["summary"]["grossMarginPct"] == 73.3
        assert body["summary"]["actualLaborPct"] == 26.7
        assert body["summary"]["unmatchedActualHours"] == 0
        assert body["summary"]["unallocatedCorrectionCount"] == 0
        assert [row["date"] for row in body["byDay"]] == [
            "2026-07-19",
            "2026-07-20",
            "2026-07-21",
            "2026-07-22",
            "2026-07-23",
            "2026-07-24",
            "2026-07-25",
        ]
        assert body["byDay"][0]["jobCount"] == 0
        assert body["byDay"][0]["actualHours"] == 0.0
        monday = body["byDay"][1]
        assert monday["date"] == "2026-07-20"
        assert monday["revenue"] == 150.0
        assert monday["actualLaborCost"] == 40.0
        assert monday["actualLaborPct"] == 26.7
        assert monday["unallocatedCorrectionCount"] == 0
        assert len(monday["sites"]) == 1
        site = monday["sites"][0]
        assert site["customerName"] == "Payroll Labor Profitability Customer"
        assert site["siteAddress"] == "Payroll Labor Profitability Site"
        assert site["actualHours"] == 2.0
        assert site["actualLaborCost"] == 40.0
        assert site["jobs"][0]["jobId"] == job_id
        assert site["jobs"][0]["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Worker",
                "hours": 2.0,
                "laborCost": 40.0,
                "status": "finalized",
            }
        ]

        jobs = {row["jobId"]: row for row in body["jobs"]}
        job = jobs[job_id]
        assert job["customerName"] == "Payroll Labor Profitability Customer"
        assert job["plannedHours"] == 3.0
        assert job["actualHours"] == 2.0
        assert job["varianceHours"] == -1.0
        assert job["revenue"] == 150.0
        assert job["actualLaborCost"] == 40.0
        assert job["knownActualLaborCost"] == 40.0
        assert job["laborCostComplete"] is True
        assert job["targetLaborPct"] == 40.0
        assert job["laborTargetVariancePct"] == -13.3
        assert job["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Worker",
                "hours": 2.0,
                "laborCost": 40.0,
                "status": "finalized",
            }
        ]
        assert "hourlyRate" not in response.text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_assigns_boundary_jobs_to_daily_grid(
    client,
):
    week_start = date(2026, 7, 19)
    prior_day = week_start - timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=prior_day,
            scheduled_start=_local_dt(prior_day, 23),
            scheduled_end=_local_dt(week_start, 1),
            source_key="2" * 64,
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["summary"]["jobCount"] == 1
        sunday = body["byDay"][0]
        assert sunday["date"] == "2026-07-19"
        assert sunday["jobCount"] == 1
        assert sunday["revenue"] == 150.0
        assert sunday["sites"][0]["jobs"][0]["jobId"] == job_id
        assert sunday["sites"][0]["jobs"][0]["scheduledDate"] == "2026-07-18"
        assert sunday["sites"][0]["jobs"][0]["profitabilityDate"] == "2026-07-19"
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (payroll_id,) if value])


def test_payroll_labor_profitability_reports_unmatched_labor_by_day(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 21)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Unmatched Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["summary"]["unmatchedActualHours"] == 2.0
        tuesday = next(row for row in body["byDay"] if row["date"] == "2026-07-21")
        assert tuesday["jobCount"] == 0
        assert tuesday["unmatchedActualHours"] == 2.0
        assert tuesday["unmatchedActualSegmentCount"] == 1
        assert tuesday["unmatchedActualSegments"][0]["employeeId"] == employee_id
        assert [issue["code"] for issue in tuesday["issues"]] == [
            "unmatched_actual_labor"
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_splits_matched_labor_by_local_day(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = week_start
    next_day = week_start + timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Overnight Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
            local_start=_local_dt(service_day, 23),
            local_end=_local_dt(next_day, 1),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["summary"]["actualHours"] == 2.0
        assert body["summary"]["actualLaborCost"] == 40.0
        sunday = next(row for row in body["byDay"] if row["date"] == "2026-07-19")
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert sunday["actualHours"] == 1.0
        assert sunday["actualLaborCost"] == 20.0
        assert sunday["revenue"] == 150.0
        assert monday["actualHours"] == 1.0
        assert monday["actualLaborCost"] == 20.0
        assert monday["revenue"] == 0.0
        assert sunday["sites"][0]["jobs"][0]["jobId"] == job_id
        assert sunday["sites"][0]["jobs"][0]["workers"][0]["hours"] == 1.0
        assert monday["sites"][0]["jobs"][0]["jobId"] == job_id
        assert monday["sites"][0]["jobs"][0]["workers"][0]["hours"] == 1.0
        assert monday["sites"][0]["jobs"][0]["revenueRecognitionDate"] == "2026-07-19"
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_rounds_daily_hours_after_worker_sum(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_ids: list[int] = []
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        employee_ids = [
            _create_employee(
                f"Payroll Labor Profitability Minute Worker {index}",
                hourly_rate=60,
            )
            for index in range(1, 4)
        ]
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 10),
            source_key="3" * 64,
        )
        for offset, employee_id in enumerate(employee_ids):
            _create_payroll_profitability_shift_evidence(
                employee_id=employee_id,
                site_id=site_id,
                job_id=job_id,
                local_start=_local_dt(service_day, 9, offset),
                local_end=_local_dt(service_day, 9, offset + 1),
            )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        job = monday["sites"][0]["jobs"][0]
        assert body["summary"]["actualHours"] == 0.05
        assert monday["actualHours"] == 0.05
        assert monday["sites"][0]["actualHours"] == 0.05
        assert job["actualHours"] == 0.05
        assert [worker["hours"] for worker in job["workers"]] == [0.02, 0.02, 0.02]
        assert job["actualLaborCost"] == 3.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([*employee_ids, *([payroll_id] if payroll_id else [])])


def test_payroll_labor_profitability_assigns_qr_linked_boundary_labor_to_grid(
    client,
):
    week_start = date(2026, 7, 19)
    prior_day = week_start - timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Boundary Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=week_start,
            scheduled_start=_local_dt(week_start, 0, 30),
            scheduled_end=_local_dt(week_start, 1, 30),
            source_key="4" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            local_start=_local_dt(prior_day, 22),
            local_end=_local_dt(prior_day, 23),
            qr_site_id=site_id,
            qr_job_id=job_id,
            qr_local_time=_local_dt(prior_day, 22, 30),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        sunday = body["byDay"][0]
        assert body["summary"]["actualHours"] == 1.0
        assert body["summary"]["actualLaborCost"] == 20.0
        assert sunday["date"] == "2026-07-19"
        assert sunday["actualHours"] == 1.0
        assert sunday["actualLaborCost"] == 20.0
        assert sunday["sites"][0]["jobs"][0]["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Boundary Worker",
                "hours": 1.0,
                "laborCost": 20.0,
                "status": "finalized",
            }
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_scopes_daily_missing_rate_to_worker_day(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = week_start
    labor_day = week_start + timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Missing Rate Worker",
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 10),
            source_key="5" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            job_id=job_id,
            local_start=_local_dt(labor_day, 8),
            local_end=_local_dt(labor_day, 9),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["summary"]["laborCostComplete"] is False
        assert body["jobs"][0]["issues"][0]["code"] == "missing_worker_rate"
        sunday = next(row for row in body["byDay"] if row["date"] == "2026-07-19")
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert sunday["jobCount"] == 1
        assert sunday["actualHours"] == 0.0
        assert sunday["laborCostComplete"] is True
        assert sunday["issues"] == []
        assert monday["jobCount"] == 1
        assert monday["actualHours"] == 1.0
        assert monday["laborCostComplete"] is False
        assert [issue["code"] for issue in monday["issues"]] == [
            "missing_worker_rate"
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_reports_payroll_blockers_by_day(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 22)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Missing Clockout Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        _create_shift(employee_id, _local_dt(service_day, 8), None)

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["hasBlockingIssues"] is True
        wednesday = next(row for row in body["byDay"] if row["date"] == "2026-07-22")
        assert wednesday["payrollIssueCount"] == 1
        assert any(issue["code"] == "missing_clock_out" for issue in wednesday["issues"])
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_discloses_unallocated_hour_corrections(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        customer_id, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )

        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["totalHours"] == 3.0
        assert body["payrollHours"]["correctionCount"] == 1
        assert body["payrollHours"]["unallocatedCorrectionCount"] == 1
        assert body["payrollHours"]["unallocatedCorrectionCandidateCount"] == 1
        correction = body["payrollHours"]["unallocatedCorrections"][0]
        assert correction == {
            "correctionId": corrected.json()["correction"]["correctionId"],
            "employeeId": employee_id,
            "employeeName": "Payroll Labor Profitability Worker",
            "date": "2026-07-20",
            "allocationStatus": "unallocated",
            "sourceTotalMinutes": 120,
            "sourceTotalHours": 2.0,
            "correctedTotalMinutes": 180,
            "correctedTotalHours": 3.0,
            "deltaMinutes": 60,
            "deltaHours": 1.0,
            "reason": "Mayra corrected total hours.",
            "candidateSiteCount": 1,
            "candidateSites": [
                {
                    "locationId": site_id,
                    "customerId": customer_id,
                    "customerName": "Payroll Labor Profitability Customer",
                    "siteAddress": "Payroll Labor Profitability Site",
                    "actualHours": 2.0,
                    "actualLaborCost": 40.0,
                    "laborCostComplete": True,
                    "jobCount": 1,
                    "jobs": [
                        {
                            "jobId": job_id,
                            "scheduledDate": "2026-07-20",
                            "profitabilityDate": "2026-07-20",
                            "revenueRecognitionDate": "2026-07-20",
                            "actualHours": 2.0,
                            "actualLaborCost": 40.0,
                            "laborCostComplete": True,
                        }
                    ],
                }
            ],
        }
        assert body["summary"]["unallocatedCorrectionCount"] == 1
        assert body["summary"]["actualHours"] == 2.0
        assert "adjustedActualHours" not in body["summary"]
        assert [issue["code"] for issue in body["issues"]] == [
            "payroll_hour_corrections_not_allocated_to_sites"
        ]
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert monday["actualHours"] == 2.0
        assert monday["unallocatedCorrectionCount"] == 1
        assert monday["unallocatedCorrections"] == [correction]
        assert "adjustedActualHours" not in monday
        assert [issue["code"] for issue in monday["issues"]] == [
            "payroll_hour_corrections_not_allocated_to_sites"
        ]
        assert monday["sites"][0]["actualHours"] == 2.0
        assert "adjustedActualHours" not in monday["sites"][0]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_attaches_site_proof_without_blending_actuals(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Allocated Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        customer_id, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]

        allocation_response = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Juan assigned Mayra's correction to this Site.",
            },
        )

        assert allocation_response.status_code == 200, allocation_response.text
        allocation = allocation_response.json()["allocation"]
        assert allocation["correctionId"] == correction_id
        assert allocation["locationId"] == site_id
        assert allocation["jobId"] == job_id
        assert allocation["allocatedDeltaMinutes"] == 60
        assert allocation["allocatedDeltaHours"] == 1.0
        assert allocation["allocatedLaborCost"] == 20.0
        assert allocation["laborCostComplete"] is True

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["correctionCount"] == 1
        assert body["payrollHours"]["unallocatedCorrectionCount"] == 0
        assert body["payrollHours"]["allocatedCorrectionCount"] == 1
        assert body["payrollHours"]["allocatedCorrectionDeltaHours"] == 1.0
        assert body["payrollHours"]["allocatedCorrectionLaborCost"] == 20.0
        assert body["payrollHours"]["unallocatedCorrections"] == []
        correction = body["payrollHours"]["allocatedCorrections"][0]
        assert correction["allocationStatus"] == "allocated"
        assert correction["allocation"] == allocation
        assert correction["candidateSites"][0]["locationId"] == site_id
        assert body["issues"] == []
        assert body["summary"]["unallocatedCorrectionCount"] == 0
        assert body["summary"]["allocatedCorrectionCount"] == 1
        assert body["summary"]["actualHours"] == 2.0
        assert body["summary"]["actualLaborCost"] == 40.0
        assert body["summary"]["adjustedActualHours"] == 3.0
        assert body["summary"]["adjustedVarianceHours"] == 0.0
        assert body["summary"]["adjustedActualLaborCost"] == 60.0
        assert body["summary"]["knownAdjustedActualLaborCost"] == 60.0
        assert body["summary"]["adjustedLaborCostComplete"] is True
        assert body["summary"]["adjustedNetProfit"] == 90.0
        assert body["summary"]["adjustedGrossMarginPct"] == 60.0
        assert body["summary"]["adjustedActualLaborPct"] == 40.0
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert monday["unallocatedCorrectionCount"] == 0
        assert monday["unallocatedCorrections"] == []
        assert monday["allocatedCorrectionCount"] == 1
        assert monday["allocatedCorrections"] == [correction]
        assert monday["adjustedActualHours"] == 3.0
        assert monday["adjustedVarianceHours"] == 0.0
        assert monday["adjustedActualLaborCost"] == 60.0
        assert monday["adjustedNetProfit"] == 90.0
        assert monday["adjustedGrossMarginPct"] == 60.0
        assert monday["adjustedActualLaborPct"] == 40.0
        site = monday["sites"][0]
        assert site["locationId"] == site_id
        assert site["allocatedCorrections"] == [correction]
        assert site["actualHours"] == 2.0
        assert site["actualLaborCost"] == 40.0
        assert site["adjustedActualHours"] == 3.0
        assert site["adjustedVarianceHours"] == 0.0
        assert site["adjustedActualLaborCost"] == 60.0
        assert site["adjustedNetProfit"] == 90.0
        assert site["adjustedGrossMarginPct"] == 60.0
        assert site["adjustedActualLaborPct"] == 40.0
        assert site["jobs"][0]["jobId"] == job_id
        assert site["jobs"][0]["allocatedCorrections"] == [correction]
        assert site["jobs"][0]["actualHours"] == 2.0
        assert site["jobs"][0]["actualLaborCost"] == 40.0
        assert site["jobs"][0]["adjustedActualHours"] == 3.0
        assert site["jobs"][0]["adjustedVarianceHours"] == 0.0
        assert site["jobs"][0]["adjustedActualLaborCost"] == 60.0
        assert site["jobs"][0]["adjustedNetProfit"] == 90.0
        assert site["jobs"][0]["adjustedGrossMarginPct"] == 60.0
        assert site["jobs"][0]["adjustedActualLaborPct"] == 40.0
        assert site["jobs"][0]["adjustedLaborTargetVariancePct"] == 0.0
        weekly_site = next(
            row for row in body["bySite"] if row["locationId"] == site_id
        )
        assert weekly_site["allocatedCorrections"] == [correction]
        assert weekly_site["customerId"] == customer_id
        assert weekly_site["actualHours"] == 2.0
        assert weekly_site["actualLaborCost"] == 40.0
        assert weekly_site["adjustedActualHours"] == 3.0
        assert weekly_site["adjustedVarianceHours"] == 0.0
        assert weekly_site["adjustedActualLaborCost"] == 60.0
        assert weekly_site["adjustedNetProfit"] == 90.0
        assert weekly_site["adjustedGrossMarginPct"] == 60.0
        assert weekly_site["adjustedActualLaborPct"] == 40.0
        top_level_job = next(row for row in body["jobs"] if row["jobId"] == job_id)
        assert top_level_job["actualHours"] == 2.0
        assert top_level_job["actualLaborCost"] == 40.0
        assert top_level_job["allocatedCorrections"] == [correction]
        assert top_level_job["adjustedActualHours"] == 3.0
        assert top_level_job["adjustedVarianceHours"] == 0.0
        assert top_level_job["adjustedActualLaborCost"] == 60.0
        assert top_level_job["adjustedNetProfit"] == 90.0
        assert top_level_job["adjustedGrossMarginPct"] == 60.0
        assert top_level_job["adjustedActualLaborPct"] == 40.0

        voided = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation/void",
            headers=payroll_auth,
            json={"reason": "Juan needs to choose a different Site."},
        )
        assert voided.status_code == 200, voided.text
        assert voided.json()["allocation"]["status"] == "voided"
        after_void = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert after_void.status_code == 200, after_void.text
        assert after_void.json()["payrollHours"]["allocatedCorrectionCount"] == 0
        assert after_void.json()["payrollHours"]["unallocatedCorrectionCount"] == 1

        reallocated = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Juan reassigned the correction before voiding it.",
            },
        )
        assert reallocated.status_code == 200, reallocated.text
        voided_correction = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/void",
            headers=payroll_auth,
            json={"reason": "Correction no longer belongs in this week."},
        )
        assert voided_correction.status_code == 200, voided_correction.text
        after_correction_void = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert after_correction_void.status_code == 200, after_correction_void.text
        assert after_correction_void.json()["payrollHours"]["correctionCount"] == 0
        assert after_correction_void.json()["payrollHours"]["allocatedCorrectionCount"] == 0
        assert after_correction_void.json()["payrollHours"]["unallocatedCorrectionCount"] == 0
        allocation_status = db.query_one(
            """
            SELECT status
            FROM payroll_hour_correction_allocations
            WHERE correction_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (correction_id,),
        )
        assert allocation_status == {"status": "voided"}
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_recomputes_labor_after_rate_added(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Late Rate Worker",
            hourly_rate=None,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]
        allocated = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Juan assigned Mayra's correction to this Site.",
            },
        )
        assert allocated.status_code == 200, allocated.text
        allocation_snapshot = allocated.json()["allocation"]
        assert allocation_snapshot["allocatedLaborCost"] is None
        assert allocation_snapshot["laborCostComplete"] is False
        assert allocation_snapshot["currentAllocatedLaborCost"] is None
        assert allocation_snapshot["currentLaborCostComplete"] is False

        db.execute(
            "UPDATE employees SET hourly_rate = 20 WHERE id = %s",
            (employee_id,),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["issues"] == []
        assert body["payrollHours"]["allocatedCorrectionCount"] == 1
        assert body["payrollHours"]["invalidAllocationCount"] == 0
        assert body["payrollHours"]["allocatedCorrectionLaborCost"] == 20.0
        assert body["payrollHours"]["knownAllocatedCorrectionLaborCost"] == 20.0
        assert body["payrollHours"]["allocatedCorrectionLaborCostComplete"] is True
        correction = body["payrollHours"]["allocatedCorrections"][0]
        allocation = correction["allocation"]
        assert allocation["allocatedLaborCost"] is None
        assert allocation["laborCostComplete"] is False
        assert allocation["currentAllocatedLaborCost"] == 20.0
        assert allocation["currentLaborCostComplete"] is True
        assert body["summary"]["actualLaborCost"] == 40.0
        assert body["summary"]["adjustedActualLaborCost"] == 60.0
        assert body["summary"]["adjustedLaborCostComplete"] is True
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert monday["allocatedCorrections"] == [correction]
        assert monday["adjustedActualLaborCost"] == 60.0
        site = monday["sites"][0]
        assert site["allocatedCorrections"] == [correction]
        assert site["adjustedActualLaborCost"] == 60.0
        assert site["jobs"][0]["allocatedCorrections"] == [correction]
        assert site["jobs"][0]["adjustedActualLaborCost"] == 60.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_rejects_non_candidate_site(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Reject Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]

        rejected = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id + 9999,
                "reason": "This Site is not supported by clocked proof.",
            },
        )

        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["error"] == (
            "Payroll correction allocation Site is not a current candidate"
        )
        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        assert response.json()["payrollHours"]["unallocatedCorrectionCount"] == 1
        assert response.json()["payrollHours"]["allocatedCorrectionCount"] == 0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_stale_delta_is_reported_invalid(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Stale Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]
        allocated = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Juan assigned Mayra's correction to this Site.",
            },
        )
        assert allocated.status_code == 200, allocated.text
        db.execute(
            """
            UPDATE shifts
            SET clock_out = clock_in + INTERVAL '150 minutes',
                total_hours = 2.5
            WHERE employee_id = %s
              AND job_id = %s
            """,
            (employee_id, job_id),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert [issue["code"] for issue in body["issues"]] == [
            "payroll_hour_corrections_invalid_allocations"
        ]
        assert body["payrollHours"]["allocatedCorrectionCount"] == 0
        assert body["payrollHours"]["allocatedCorrections"] == []
        assert body["payrollHours"]["invalidAllocationCount"] == 1
        invalid = body["payrollHours"]["invalidAllocatedCorrections"][0]
        assert invalid["allocationStatus"] == "invalid"
        assert invalid["allocationValid"] is False
        assert invalid["deltaMinutes"] == 30
        assert invalid["allocation"]["allocatedDeltaMinutes"] == 60
        assert invalid["allocationIssue"]["code"] == (
            "payroll_correction_allocation_stale_delta"
        )
        assert body["summary"]["allocatedCorrectionDeltaHours"] == 0.0
        assert body["summary"]["invalidAllocationCount"] == 1
        assert "adjustedActualHours" not in body["summary"]
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert monday["invalidAllocationCount"] == 1
        assert monday["invalidAllocatedCorrections"] == [invalid]
        assert "adjustedActualHours" not in monday
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_rejects_negative_target_hours(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Negative Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, first_site_id = _create_payroll_profitability_site()
        _, second_site_id = _create_payroll_profitability_site(
            "Payroll Labor Profitability Second Site"
        )
        first_job_id = _create_payroll_profitability_job_only(
            site_id=first_site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 8),
            scheduled_end=_local_dt(service_day, 12),
            source_key="a" * 64,
        )
        second_job_id = _create_payroll_profitability_job_only(
            site_id=second_site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 13),
            scheduled_end=_local_dt(service_day, 17),
            source_key="b" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=first_site_id,
            job_id=first_job_id,
            local_start=_local_dt(service_day, 8),
            local_end=_local_dt(service_day, 12),
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=second_site_id,
            job_id=second_job_id,
            local_start=_local_dt(service_day, 13),
            local_end=_local_dt(service_day, 17),
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 0,
                "reason": "Mayra removed a duplicated clocked day.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]

        rejected = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": first_site_id,
                "jobId": first_job_id,
                "reason": "This one Site cannot absorb the whole day removal.",
            },
        )

        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["error"] == (
            "Payroll correction allocation would make selected profitability target negative"
        )
        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        assert response.json()["payrollHours"]["unallocatedCorrectionCount"] == 1
        assert response.json()["payrollHours"]["allocatedCorrectionCount"] == 0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_stale_target_is_reported_invalid(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Stale Target Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=service_day,
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]
        allocated = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Juan assigned Mayra's correction to this Site.",
            },
        )
        assert allocated.status_code == 200, allocated.text
        db.execute("UPDATE locations SET active = false WHERE id = %s", (site_id,))

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert [issue["code"] for issue in body["issues"]] == [
            "payroll_hour_corrections_invalid_allocations"
        ]
        assert body["payrollHours"]["allocatedCorrectionCount"] == 0
        assert body["payrollHours"]["allocatedCorrections"] == []
        assert body["payrollHours"]["invalidAllocationCount"] == 1
        invalid = body["payrollHours"]["invalidAllocatedCorrections"][0]
        assert invalid["allocationStatus"] == "invalid"
        assert invalid["allocationValid"] is False
        assert invalid["allocationIssue"]["code"] == (
            "payroll_correction_allocation_target_not_current_candidate"
        )
        assert body["summary"]["allocatedCorrectionDeltaHours"] == 0.0
        assert body["summary"]["invalidAllocationCount"] == 1
        assert "adjustedActualHours" not in body["summary"]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_allocation_rejects_excluded_profitability_target(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Excluded Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        db.execute("UPDATE locations SET active = false WHERE id = %s", (site_id,))
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 11),
            source_key="c" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            job_id=job_id,
            local_start=_local_dt(service_day, 9),
            local_end=_local_dt(service_day, 11),
        )
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected archived-site time.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        correction = response.json()["payrollHours"]["unallocatedCorrections"][0]
        assert correction["candidateSiteCount"] == 0
        assert correction["candidateSites"] == []

        rejected = client.post(
            f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
            headers=payroll_auth,
            json={
                "locationId": site_id,
                "jobId": job_id,
                "reason": "Archived Sites cannot receive profitability corrections.",
            },
        )

        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["error"] == (
            "Payroll correction allocation Site is not a current candidate"
        )
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_adjusted_profitability_clears_target_variance_when_labor_incomplete():
    target = {
        "actualHours": 2.0,
        "plannedHours": 3.0,
        "actualLaborCost": 40.0,
        "knownActualLaborCost": 40.0,
        "laborCostComplete": True,
        "revenue": 150.0,
        "targetLaborPct": 40.0,
    }
    complete_correction = {
        "allocation": {
            "allocatedDeltaMinutes": 60,
            "allocatedLaborCost": 20.0,
        }
    }
    incomplete_correction = {
        "allocation": {
            "allocatedDeltaMinutes": 30,
            "allocatedLaborCost": None,
        }
    }

    time_tracker_api._annotate_allocated_correction_adjusted_profitability(
        target,
        [complete_correction],
    )
    assert target["adjustedActualLaborPct"] == 40.0
    assert target["adjustedLaborTargetVariancePct"] == 0.0

    time_tracker_api._annotate_allocated_correction_adjusted_profitability(
        target,
        [complete_correction, incomplete_correction],
    )
    assert target["adjustedActualLaborPct"] is None
    assert target["adjustedLaborTargetVariancePct"] is None


def test_payroll_labor_profitability_reads_candidate_inputs_from_one_snapshot(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    payroll_id = None
    observed: dict[str, str] = {}

    def fake_profitability_builder(*_args, **kwargs):
        cursor = kwargs.get("cursor")
        assert cursor is not None
        cursor.execute("SHOW transaction_isolation")
        observed["isolation"] = cursor.fetchone()["transaction_isolation"]
        cursor.execute("SHOW transaction_read_only")
        observed["read_only"] = cursor.fetchone()["transaction_read_only"]
        return {
            "success": True,
            "period": "week",
            "timezone": "America/Chicago",
            "observedAt": "2026-07-20T00:00:00Z",
            "weekStart": week_start.isoformat(),
            "weekEnd": (week_start + timedelta(days=6)).isoformat(),
            "summary": {
                "jobCount": 0,
                "unmatchedActualSegmentCount": 0,
            },
            "bySite": [],
            "byDay": [],
            "jobs": [],
            "unmatchedActualSegments": [],
            "_payrollCorrectionCandidateSegments": [],
        }

    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Snapshot Mayra",
            role="payroll",
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Snapshot Mayra")
        monkeypatch.setattr(
            time_tracker_api,
            "build_weekly_labor_profitability",
            fake_profitability_builder,
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        assert observed == {"isolation": "repeatable read", "read_only": "on"}
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (payroll_id,) if value])


def test_payroll_labor_profitability_includes_ambiguous_unmatched_candidates(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Ambiguous Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        customer_id, site_id = _create_payroll_profitability_site()
        first_job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 11),
            source_key="6" * 64,
        )
        second_job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 11),
            source_key="7" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            local_start=_local_dt(service_day, 9),
            local_end=_local_dt(service_day, 11),
        )

        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected ambiguous site time.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        correction = body["payrollHours"]["unallocatedCorrections"][0]
        assert correction["candidateSiteCount"] == 1
        assert correction["candidateSites"] == [
            {
                "locationId": site_id,
                "customerId": customer_id,
                "customerName": "Payroll Labor Profitability Customer",
                "siteAddress": "Payroll Labor Profitability Site",
                "actualHours": 2.0,
                "actualLaborCost": None,
                "laborCostComplete": False,
                "jobCount": 2,
                "jobs": [
                    {
                        "jobId": first_job_id,
                        "scheduledDate": "2026-07-20",
                        "profitabilityDate": "2026-07-20",
                        "revenueRecognitionDate": "2026-07-20",
                        "actualHours": 2.0,
                        "actualLaborCost": None,
                        "laborCostComplete": False,
                    },
                    {
                        "jobId": second_job_id,
                        "scheduledDate": "2026-07-20",
                        "profitabilityDate": "2026-07-20",
                        "revenueRecognitionDate": "2026-07-20",
                        "actualHours": 2.0,
                        "actualLaborCost": None,
                        "laborCostComplete": False,
                    },
                ],
            }
        ]
        assert body["summary"]["actualHours"] == 0.0
        assert body["summary"]["unmatchedActualHours"] == 2.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_correction_candidate_sites_exclude_locationless_segments():
    candidates = time_tracker_api._payroll_correction_candidate_sites(
        [
            {
                "segmentKey": "locationless",
                "siteSegmentKey": "locationless",
                "date": "2026-07-20",
                "employeeId": 10,
                "locationId": None,
                "jobId": 100,
                "actualHours": 2.0,
                "actualLaborCost": 40.0,
            },
            {
                "segmentKey": "site",
                "siteSegmentKey": "site",
                "date": "2026-07-20",
                "employeeId": 10,
                "locationId": 50,
                "customerId": 60,
                "customerName": "Candidate Customer",
                "siteAddress": "Candidate Site",
                "jobId": 101,
                "scheduledDate": "2026-07-20",
                "profitabilityDate": "2026-07-20",
                "revenueRecognitionDate": "2026-07-20",
                "actualHours": 1.5,
                "actualLaborCost": 30.0,
            },
            {
                "segmentKey": "excluded",
                "siteSegmentKey": "excluded",
                "date": "2026-07-20",
                "employeeId": 10,
                "locationId": 51,
                "customerId": 61,
                "customerName": "Excluded Candidate Customer",
                "siteAddress": "Excluded Candidate Site",
                "jobId": 102,
                "includedInProfitability": False,
                "scheduledDate": "2026-07-20",
                "profitabilityDate": "2026-07-20",
                "revenueRecognitionDate": "2026-07-20",
                "actualHours": 1.5,
                "actualLaborCost": 30.0,
            },
        ],
        "2026-07-20",
        10,
    )

    assert candidates == [
        {
            "locationId": 50,
            "customerId": 60,
            "customerName": "Candidate Customer",
            "siteAddress": "Candidate Site",
            "actualHours": 1.5,
            "actualLaborCost": 30.0,
            "laborCostComplete": True,
            "jobCount": 1,
            "jobs": [
                {
                    "jobId": 101,
                    "scheduledDate": "2026-07-20",
                    "profitabilityDate": "2026-07-20",
                    "revenueRecognitionDate": "2026-07-20",
                    "actualHours": 1.5,
                    "actualLaborCost": 30.0,
                    "laborCostComplete": True,
                }
            ],
        }
    ]


def test_payroll_labor_profitability_does_not_offer_folded_boundary_labor_candidate(
    client,
):
    week_start = date(2026, 7, 19)
    prior_day = week_start - timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Boundary Candidate Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=week_start,
            scheduled_start=_local_dt(week_start, 0, 30),
            scheduled_end=_local_dt(week_start, 1, 30),
            source_key="8" * 64,
        )
        _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            local_start=_local_dt(prior_day, 22),
            local_end=_local_dt(prior_day, 23),
            qr_site_id=site_id,
            qr_job_id=job_id,
            qr_local_time=_local_dt(prior_day, 22, 30),
        )

        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": week_start.isoformat(),
                "correctedTotalMinutes": 60,
                "reason": "Mayra corrected Sunday total hours.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        correction = body["payrollHours"]["unallocatedCorrections"][0]
        assert correction["sourceTotalMinutes"] == 0
        assert correction["candidateSiteCount"] == 0
        assert correction["candidateSites"] == []
        sunday = body["byDay"][0]
        assert sunday["date"] == "2026-07-19"
        assert sunday["actualHours"] == 1.0
        assert sunday["unallocatedCorrections"] == [correction]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


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
