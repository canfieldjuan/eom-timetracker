from __future__ import annotations

import csv
import hashlib
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import inspect
from io import BytesIO, StringIO
import json
from types import SimpleNamespace
from uuid import uuid4
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
    *,
    location_id: int | None = None,
    location_label: str = "",
    job_id: int | None = None,
    time_category: str = "productive",
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
                employee_id, location_id, location_label, job_id,
                clock_in, clock_out, total_hours, local_date, timezone,
                time_category, notes
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, 'America/Chicago', %s,
                'payroll-weekly-hours-test'
            )
            RETURNING id
            """,
            (
                employee_id,
                location_id,
                location_label,
                job_id,
                clock_in,
                clock_out,
                total_hours,
                local_start.date(),
                time_category,
            ),
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
            "DELETE FROM payroll_shift_exclusions WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_manual_shift_versions WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_shift_corrections WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_hour_corrections WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_verification_batches WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_money_verification_batches WHERE week_start = %s",
            (week_start,),
        )
        db.execute(
            "DELETE FROM payroll_timesheet_change_batches WHERE week_start = %s",
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


def _payroll_timesheet(
    client,
    auth: dict[str, str],
    week_start: date,
    *,
    employee_id: int | None = None,
) -> dict:
    url = f"/api/admin/payroll/timesheet?weekStart={week_start.isoformat()}"
    if employee_id is not None:
        url += f"&employeeId={employee_id}"
    response = client.get(url, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def _create_timesheet_site(
    *,
    address: str = "Payroll Timesheet Contract Site",
    customer_name: str = "Payroll Timesheet Contract Customer",
) -> tuple[int, int]:
    customer_id = int(
        db.execute_returning(
            "INSERT INTO customers (name) VALUES (%s) RETURNING id",
            (customer_name,),
        )
    )
    location_id = int(
        db.execute_returning(
            """
            INSERT INTO locations (customer_id, address, customer_name, location_type)
            VALUES (%s, %s, %s, 'Commercial')
            RETURNING id
            """,
            (customer_id, address, customer_name),
        )
    )
    return customer_id, location_id


def _delete_timesheet_site(customer_id: int | None, location_id: int | None) -> None:
    if location_id is not None:
        db.execute("DELETE FROM locations WHERE id = %s", (location_id,))
    if customer_id is not None:
        db.execute("DELETE FROM customers WHERE id = %s", (customer_id,))


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
    source_seed: str = "1",
) -> int:
    start = local_start or _local_dt(service_day, 9)
    end = local_end or _local_dt(service_day, 11)
    # source_key is UNIQUE, so a test that needs two jobs must vary the seed.
    source_key = (source_seed * 64)[:64]
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
                    %s,
                    %s,
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
                    f"payroll-labor-profitability-event-{source_seed}",
                    f"payroll-labor-profitability-occurrence-{source_seed}",
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


def test_payroll_lock_helpers_avoid_shift_table_lock_for_payroll_edits():
    source_order = [
        "shifts",
        "payroll_shift_corrections",
        "payroll_hour_corrections",
        "payroll_hour_correction_allocations",
    ]
    source_lock = inspect.getsource(time_tracker_api._lock_payroll_source_rows)
    source_lock_clause = source_lock[source_lock.index("LOCK TABLE") :]
    source_positions = [
        source_lock_clause.index(table_name)
        for table_name in source_order
    ]
    assert source_positions == sorted(source_positions)

    write_lock = inspect.getsource(
        time_tracker_api._lock_payroll_correction_write_tables
    )
    write_lock_clause = write_lock[write_lock.index("LOCK TABLE") :]
    assert "shifts" not in write_lock_clause
    write_order = source_order[1:]
    write_positions = [
        write_lock_clause.index(table_name)
        for table_name in write_order
    ]
    assert write_positions == sorted(write_positions)

    cleanup_source = inspect.getsource(time_tracker_api.admin_apply_time_data_correction)
    assert cleanup_source.index("_lock_payroll_source_rows") < cleanup_source.index(
        "_lock_payroll_correction_write_tables"
    )
    shift_correction_source = inspect.getsource(
        time_tracker_api.admin_create_payroll_shift_correction
    )
    assert (
        shift_correction_source.index("timesheet_postgres_advisory_lock")
        < shift_correction_source.index("_lock_payroll_correction_write_tables")
    )
    void_shift_correction_source = inspect.getsource(
        time_tracker_api.admin_void_payroll_shift_correction
    )
    assert (
        void_shift_correction_source.index("timesheet_postgres_advisory_lock")
        < void_shift_correction_source.index("_lock_payroll_correction_write_tables")
    )
    assert (
        void_shift_correction_source.index(
            "_ensure_shift_correction_void_keeps_single_open_shift"
        )
        < void_shift_correction_source.index("UPDATE payroll_shift_corrections")
    )


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

        timesheet_allowed = client.get(
            "/api/admin/payroll/timesheet?weekStart=2026-07-19",
            headers=payroll_auth,
        )
        assert timesheet_allowed.status_code == 200, timesheet_allowed.text
        assert timesheet_allowed.json()["capabilities"]["rawShiftRows"] is True

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

        timesheet_denied = client.get(
            "/api/admin/payroll/timesheet?weekStart=2026-07-19",
            headers=emp_auth,
        )
        assert timesheet_denied.status_code == 403, timesheet_denied.text

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


def test_payroll_timesheet_route_reads_under_repeatable_read_snapshot(monkeypatch):
    statements: list[str] = []

    class FakeCursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=()):
            statements.append(" ".join(sql.split()))

    fake_cursor = FakeCursor()

    class FakeConnection:
        def cursor(self, cursor_factory=None):
            assert cursor_factory is not None
            return fake_cursor

    class FakeConnectionContext:
        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *_args):
            return None

    def fake_get_conn():
        return FakeConnectionContext()

    def fake_compute(week_start, *, employee_id=None, cursor=None):
        assert week_start == "2026-07-19"
        assert employee_id == 123
        assert cursor is fake_cursor
        return {
            "weekStart": "2026-07-19",
            "summary": {"employeeCount": 1, "issueCount": 0},
        }

    monkeypatch.setattr(time_tracker_api.db, "get_conn", fake_get_conn)
    monkeypatch.setattr(time_tracker_api, "_compute_payroll_timesheet", fake_compute)
    monkeypatch.setattr(time_tracker_api, "append_access_log", lambda *_args: None)

    body = time_tracker_api.admin_payroll_timesheet(
        SimpleNamespace(query_params={}),
        week_start="2026-07-19",
        employee_id=123,
        _={"id": 1, "name": "Payroll"},
    )

    assert body["weekStart"] == "2026-07-19"
    assert statements == [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    ]


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


def test_payroll_timesheet_exposes_shift_rows_for_employee_week(client):
    week_start = date(2026, 7, 12)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    customer_id = None
    location_id = None
    try:
        payroll_id = _create_employee("Payroll Timesheet Contract Mayra", role="payroll")
        employee_id = _create_employee("Payroll Timesheet Contract Alma")
        customer_id, location_id = _create_timesheet_site()
        payroll_auth = _login(client, "Payroll Timesheet Contract Mayra")

        first_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 7),
            _local_dt(service_day, 11),
            location_id=location_id,
            location_label="Supervisor",
        )
        second_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 16, 30),
            _local_dt(service_day, 20, 35),
            location_id=location_id,
            location_label="Supervisor",
        )

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        assert body["success"] is True
        assert body["selectedEmployeeId"] == employee_id
        assert body["capabilities"] == {
            "rawShiftRows": True,
            "dayTotalCorrections": True,
            "shiftClockCorrections": True,
            "breakMinutesTracked": False,
            "shiftBreakCorrections": True,
            "locationAllocatedCorrections": True,
            "atomicTimesheetChanges": True,
            "manualShiftRows": True,
            "shiftExclusions": True,
        }
        assert body["breakPolicy"]["tracked"] is False
        assert body["breakPolicy"]["correctionSupported"] is True
        assert body["summary"]["employeeCount"] == 1
        assert body["summary"]["totalMinutes"] == 485
        assert body["summary"]["totalHours"] == 8.08
        assert body["sourceFingerprint"]
        assert body["timesheetSourceFingerprint"]

        employee = body["employees"][0]
        assert employee["employeeId"] == employee_id
        assert employee["employeeName"] == "Payroll Timesheet Contract Alma"
        tuesday = employee["days"][2]
        assert tuesday["date"] == service_day.isoformat()
        assert tuesday["status"] == "registered"
        assert tuesday["totalMinutes"] == 485
        assert tuesday["totalHours"] == 8.08
        assert [shift["shiftId"] for shift in tuesday["shifts"]] == [
            first_shift_id,
            second_shift_id,
        ]
        assert [shift["clockIn"]["display"] for shift in tuesday["shifts"]] == [
            "07:00 AM",
            "04:30 PM",
        ]
        assert [shift["clockOut"]["display"] for shift in tuesday["shifts"]] == [
            "11:00 AM",
            "08:35 PM",
        ]
        assert [shift["totalMinutes"] for shift in tuesday["shifts"]] == [240, 245]
        assert all(shift["breakMinutes"] is None for shift in tuesday["shifts"])
        assert all(shift["locationId"] == location_id for shift in tuesday["shifts"])
        assert all(shift["locationLabel"] == "Supervisor" for shift in tuesday["shifts"])
        assert all(
            shift["customerName"] == "Payroll Timesheet Contract Customer"
            for shift in tuesday["shifts"]
        )
        assert all(shift["status"] == "registered" for shift in tuesday["shifts"])
        assert all(
            shift["fieldSupport"] == {
                "clockIn": {"display": True, "correction": True},
                "clockOut": {"display": True, "correction": True},
                "breakMinutes": {"display": True, "correction": True},
                "totalHours": {"display": True, "correction": False},
            }
            for shift in tuesday["shifts"]
        )

        weekly = _weekly_hours(client, payroll_auth, week_start)
        weekly_employee = _employees_by_name(weekly)["Payroll Timesheet Contract Alma"]
        assert "shifts" not in weekly_employee["days"][2]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])
        _delete_timesheet_site(customer_id, location_id)


def test_payroll_timesheet_reuses_one_shift_snapshot_for_rows_and_totals(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 12)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    calls = 0
    original = time_tracker_api._payroll_overlapping_shift_rows

    def counting_shift_rows(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        time_tracker_api,
        "_payroll_overlapping_shift_rows",
        counting_shift_rows,
    )

    try:
        payroll_id = _create_employee("Payroll Timesheet Snapshot Mayra", role="payroll")
        employee_id = _create_employee("Payroll Timesheet Snapshot Worker")
        payroll_auth = _login(client, "Payroll Timesheet Snapshot Mayra")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
        )

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        assert calls == 1
        wednesday = body["employees"][0]["days"][3]
        assert wednesday["totalMinutes"] == 120
        assert [shift["totalMinutes"] for shift in wednesday["shifts"]] == [120]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_keeps_day_total_corrections_out_of_shift_rows(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    payroll_id = None
    employee_id = None
    customer_id = None
    location_id = None
    try:
        payroll_id = _create_employee("Payroll Timesheet Correction Mayra", role="payroll")
        employee_id = _create_employee("Payroll Timesheet Correction Worker")
        customer_id, location_id = _create_timesheet_site(
            address="Payroll Timesheet Correction Site",
            customer_name="Payroll Timesheet Correction Customer",
        )
        payroll_auth = _login(client, "Payroll Timesheet Correction Mayra")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
            location_id=location_id,
            location_label="Correction Site",
        )

        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra confirmed the day total but not the location split.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        monday = body["employees"][0]["days"][1]
        assert monday["status"] == "corrected"
        assert monday["totalMinutes"] == 180
        assert sum(shift["totalMinutes"] for shift in monday["shifts"]) == 120
        assert monday["correction"]["sourceTotalMinutes"] == 120
        assert monday["correction"]["correctedTotalMinutes"] == 180
        assert monday["correction"]["deltaMinutes"] == 60
        assert monday["correction"]["allocationStatus"] == "unallocated"
        assert monday["correction"]["allocation"] is None
        assert monday["correction"]["unallocatedLocationLabel"] == (
            "Horas corregidas sin ubicación confirmada"
        )
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])
        _delete_timesheet_site(customer_id, location_id)


def test_payroll_shift_correction_overlays_clock_break_without_mutating_shift(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    customer_id = None
    location_id = None
    try:
        payroll_id = _create_employee("Payroll Shift Correction Mayra", role="payroll")
        employee_id = _create_employee("Payroll Shift Correction Alma")
        customer_id, location_id = _create_timesheet_site(
            address="Payroll Shift Correction Site",
            customer_name="Payroll Shift Correction Customer",
        )
        payroll_auth = _login(client, "Payroll Shift Correction Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
            location_id=location_id,
            location_label="Shift Correction Site",
        )
        before = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8, 15).isoformat(),
                "correctedClockOut": _local_dt(service_day, 13, 15).isoformat(),
                "correctedBreakMinutes": 30,
                "reason": "Mayra confirmed the row clock times and lunch break.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        body = corrected.json()
        correction = body["correction"]
        assert correction["shiftId"] == shift_id
        assert correction["sourceClockIn"]["display"] == "08:00 AM"
        assert correction["sourceClockOut"]["display"] == "12:00 PM"
        assert correction["sourceBreakMinutes"] is None
        assert correction["sourceTotalMinutes"] == 240
        assert correction["correctedClockIn"]["display"] == "08:15 AM"
        assert correction["correctedClockOut"]["display"] == "01:15 PM"
        assert correction["correctedBreakMinutes"] == 30
        assert correction["correctedTotalMinutes"] == 270
        assert correction["deltaMinutes"] == 30

        timesheet = body["timesheet"]
        assert timesheet["timesheetSourceFingerprint"] != before["timesheetSourceFingerprint"]
        assert timesheet["sourceFingerprint"] != before["sourceFingerprint"]
        tuesday = timesheet["employees"][0]["days"][2]
        assert tuesday["status"] == "corrected"
        assert tuesday["totalMinutes"] == 270
        shift = tuesday["shifts"][0]
        assert shift["status"] == "corrected"
        assert shift["clockIn"]["display"] == "08:15 AM"
        assert shift["clockOut"]["display"] == "01:15 PM"
        assert shift["breakMinutes"] == 30
        assert shift["totalMinutes"] == 270
        assert shift["original"]["clockIn"]["display"] == "08:00 AM"
        assert shift["original"]["clockOut"]["display"] == "12:00 PM"
        assert shift["original"]["breakMinutes"] is None
        assert shift["original"]["totalMinutes"] == 240
        assert shift["correction"]["correctionId"] == correction["correctionId"]

        weekly = _weekly_hours(client, payroll_auth, week_start)
        weekly_employee = _employees_by_name(weekly)["Payroll Shift Correction Alma"]
        assert weekly_employee["days"][2]["totalMinutes"] == 270
        assert weekly_employee["totalMinutes"] == 270
        assert weekly["summary"]["totalMinutes"] == 270

        raw_shift = db.query_one(
            "SELECT clock_in, clock_out, total_hours FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert raw_shift["clock_in"].astimezone(CHICAGO).strftime("%H:%M") == "08:00"
        assert raw_shift["clock_out"].astimezone(CHICAGO).strftime("%H:%M") == "12:00"
        assert float(raw_shift["total_hours"]) == 4.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])
        _delete_timesheet_site(customer_id, location_id)


def test_hours_report_uses_active_payroll_shift_correction_for_json_csv_pdf(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    admin_id = None
    employee_id = None
    try:
        admin_id = _create_employee(
            "Hours Report Correction Mayra",
            role="admin",
        )
        employee_id = _create_employee("Hours Report Corrected Alma")
        admin_auth = _login(client, "Hours Report Correction Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
            location_label="Hours Report Raw Site",
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=admin_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 11, 30).isoformat(),
                "correctedBreakMinutes": 30,
                "reason": "Mayra corrected the clock-out and lunch break for payroll.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        weekly = _weekly_hours(client, admin_auth, week_start)
        weekly_employee = _employees_by_name(weekly)["Hours Report Corrected Alma"]
        assert weekly_employee["days"][2]["totalMinutes"] == 180
        assert weekly_employee["totalMinutes"] == 180

        query = (
            "/api/admin/reports/hours"
            f"?period=day&date={service_day.isoformat()}&employee_id={employee_id}"
        )
        response = client.get(query, headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["totalHours"] == 3.0
        assert body["totalShifts"] == 1
        assert body["summary"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Hours Report Corrected Alma",
                "totalHours": 3.0,
                "totalShifts": 1,
            },
        ]
        assert len(body["rows"]) == 1
        row = body["rows"][0]
        assert row["employeeId"] == employee_id
        assert row["date"] == service_day.isoformat()
        assert row["clockIn"] == "08:00 AM"
        assert row["clockOut"] == "11:30 AM"
        assert row["hours"] == 3.0

        export_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/export"),
            headers=admin_auth,
        )
        assert export_response.status_code == 200, export_response.text
        csv_rows = list(csv.reader(StringIO(export_response.text)))
        assert [
            "Hours Report Corrected Alma",
            "Tue, Jul 21",
            "08:00 AM",
            "11:30 AM",
            "3.00",
            "Hours Report Raw Site",
            "",
        ] in csv_rows

        pdf_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/pdf"),
            headers=admin_auth,
        )
        assert pdf_response.status_code == 200, pdf_response.text
        _assert_valid_pdf(pdf_response.content)
        pdf_text = _normalized_text(_extract_pdf_text(pdf_response.content))
        assert "Hours Report Corrected Alma" in pdf_text
        assert "08:00 AM" in pdf_text
        assert "11:30 AM" in pdf_text
        assert "3.00" in pdf_text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, admin_id) if value])


def test_hours_report_aggregates_corrected_hours_before_rounding_totals(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    admin_id = None
    employee_id = None
    try:
        admin_id = _create_employee(
            "Hours Report Aggregate Correction Mayra",
            role="admin",
        )
        employee_id = _create_employee("Hours Report Aggregate Alma")
        admin_auth = _login(client, "Hours Report Aggregate Correction Mayra")
        morning_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 9),
            location_label="Hours Report Aggregate Morning Site",
        )
        afternoon_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 13),
            _local_dt(service_day, 14),
            location_label="Hours Report Aggregate Afternoon Site",
        )

        for shift_id, corrected_clock_in, corrected_clock_out in (
            (
                morning_shift_id,
                _local_dt(service_day, 8),
                _local_dt(service_day, 12, 5),
            ),
            (
                afternoon_shift_id,
                _local_dt(service_day, 13),
                _local_dt(service_day, 17, 5),
            ),
        ):
            corrected = client.post(
                "/api/admin/payroll/timesheet/shift-corrections",
                headers=admin_auth,
                json={
                    "weekStart": week_start.isoformat(),
                    "employeeId": employee_id,
                    "shiftId": shift_id,
                    "date": service_day.isoformat(),
                    "correctedClockIn": corrected_clock_in.isoformat(),
                    "correctedClockOut": corrected_clock_out.isoformat(),
                    "correctedBreakMinutes": 0,
                    "reason": "Mayra corrected the shift total for payroll reconciliation.",
                },
            )
            assert corrected.status_code == 200, corrected.text

        weekly = _weekly_hours(client, admin_auth, week_start)
        weekly_employee = _employees_by_name(weekly)["Hours Report Aggregate Alma"]
        assert weekly_employee["days"][3]["totalMinutes"] == 490
        assert weekly_employee["days"][3]["totalHours"] == 8.17
        assert weekly_employee["totalMinutes"] == 490
        assert weekly_employee["totalHours"] == 8.17

        query = (
            "/api/admin/reports/hours"
            f"?period=day&date={service_day.isoformat()}&employee_id={employee_id}"
        )
        response = client.get(query, headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["totalHours"] == 8.17
        assert body["totalShifts"] == 2
        assert body["summary"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Hours Report Aggregate Alma",
                "totalHours": 8.17,
                "totalShifts": 2,
            },
        ]
        assert [row["hours"] for row in body["rows"]] == [4.08, 4.08]

        export_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/export"),
            headers=admin_auth,
        )
        assert export_response.status_code == 200, export_response.text
        csv_rows = list(csv.reader(StringIO(export_response.text)))
        assert ["Total Hours", "8.17", "Total Shifts", "2"] in csv_rows
        assert [
            "Hours Report Aggregate Alma",
            "2",
            "8.17",
        ] in csv_rows
        detail_hours = [
            row[4]
            for row in csv_rows
            if row[:1] == ["Hours Report Aggregate Alma"]
            and row[1].startswith("Wed, Jul 22")
        ]
        assert detail_hours == ["4.08", "4.08"]

        pdf_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/pdf"),
            headers=admin_auth,
        )
        assert pdf_response.status_code == 200, pdf_response.text
        _assert_valid_pdf(pdf_response.content)
        pdf_text = _normalized_text(_extract_pdf_text(pdf_response.content))
        assert "Hours Report Aggregate Alma" in pdf_text
        assert "8.17" in pdf_text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, admin_id) if value])


def test_hours_report_preserves_unrounded_hours_for_report_wide_total(client):
    week_start = date(2026, 7, 26)
    service_day = week_start + timedelta(days=3)
    admin_id = None
    employee_ids: list[int] = []
    try:
        admin_id = _create_employee(
            "Hours Report Wide Aggregate Mayra",
            role="admin",
        )
        admin_auth = _login(client, "Hours Report Wide Aggregate Mayra")
        for name, start_hour in (
            ("Hours Report Wide Alma", 8),
            ("Hours Report Wide Beatriz", 13),
        ):
            employee_id = _create_employee(name)
            employee_ids.append(employee_id)
            shift_id = _create_shift(
                employee_id,
                _local_dt(service_day, start_hour),
                _local_dt(service_day, start_hour + 1),
                location_label=f"{name} Corrected Site",
            )
            corrected = client.post(
                "/api/admin/payroll/timesheet/shift-corrections",
                headers=admin_auth,
                json={
                    "weekStart": week_start.isoformat(),
                    "employeeId": employee_id,
                    "shiftId": shift_id,
                    "date": service_day.isoformat(),
                    "correctedClockIn": _local_dt(service_day, start_hour).isoformat(),
                    "correctedClockOut": _local_dt(
                        service_day,
                        start_hour + 4,
                        5,
                    ).isoformat(),
                    "correctedBreakMinutes": 0,
                    "reason": "Mayra corrected the shift total for payroll reconciliation.",
                },
            )
            assert corrected.status_code == 200, corrected.text

        weekly = _weekly_hours(client, admin_auth, week_start)
        weekly_by_name = _employees_by_name(weekly)
        for name in ("Hours Report Wide Alma", "Hours Report Wide Beatriz"):
            assert weekly_by_name[name]["days"][3]["totalMinutes"] == 245
            assert weekly_by_name[name]["totalHours"] == 4.08

        query = f"/api/admin/reports/hours?period=day&date={service_day.isoformat()}"
        response = client.get(query, headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["totalHours"] == 8.17
        assert body["totalShifts"] == 2
        summary_by_name = {
            employee["employeeName"]: employee
            for employee in body["summary"]
        }
        assert summary_by_name["Hours Report Wide Alma"]["totalHours"] == 4.08
        assert summary_by_name["Hours Report Wide Beatriz"]["totalHours"] == 4.08
        assert [row["hours"] for row in body["rows"]] == [4.08, 4.08]

        export_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/export"),
            headers=admin_auth,
        )
        assert export_response.status_code == 200, export_response.text
        csv_rows = list(csv.reader(StringIO(export_response.text)))
        assert ["Total Hours", "8.17", "Total Shifts", "2"] in csv_rows
        assert ["Hours Report Wide Alma", "1", "4.08"] in csv_rows
        assert ["Hours Report Wide Beatriz", "1", "4.08"] in csv_rows

        pdf_response = client.get(
            query.replace("/api/admin/reports/hours", "/api/admin/reports/hours/pdf"),
            headers=admin_auth,
        )
        assert pdf_response.status_code == 200, pdf_response.text
        _assert_valid_pdf(pdf_response.content)
        pdf_text = _normalized_text(_extract_pdf_text(pdf_response.content))
        assert "Hours Report Wide Alma" in pdf_text
        assert "Hours Report Wide Beatriz" in pdf_text
        assert "8.17" in pdf_text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees(employee_ids + ([admin_id] if admin_id else []))


def test_admin_entry_adjust_rejects_active_payroll_shift_correction(client, auth):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Raw Edit Guard Mayra",
            role="payroll",
        )
        employee_id = _create_employee("Payroll Raw Edit Guard Alma")
        payroll_auth = _login(client, "Payroll Raw Edit Guard Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8, 15).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12, 15).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra corrected this shift before a legacy raw edit.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        adjusted = client.patch(
            f"/api/admin/entries/{shift_id}",
            headers=auth,
            json={"clockOut": _local_dt(service_day, 13).strftime("%Y-%m-%dT%H:%M")},
        )

        assert adjusted.status_code == 400
        assert adjusted.json()["error"] == (
            "Entry has an active payroll correction; void or supersede "
            "the correction before editing raw clock times"
        )
        raw_shift = db.query_one(
            "SELECT clock_out, total_hours FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert raw_shift["clock_out"].astimezone(CHICAGO).strftime("%H:%M") == "12:00"
        assert float(raw_shift["total_hours"]) == 4.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_rejects_moving_source_shift_to_another_date(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Shift Date Guard Mayra", role="payroll")
        employee_id = _create_employee("Payroll Shift Date Guard Alma")
        payroll_auth = _login(client, "Payroll Shift Date Guard Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
        )

        moved = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": (service_day + timedelta(days=1)).isoformat(),
                "correctedClockIn": _local_dt(
                    service_day + timedelta(days=1),
                    8,
                ).isoformat(),
                "correctedClockOut": _local_dt(
                    service_day + timedelta(days=1),
                    12,
                ).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "This stale request tries to move the work date.",
            },
        )

        assert moved.status_code == 400
        assert moved.json()["error"] == (
            "Correction date must match the source shift work date"
        )
        assert db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM payroll_shift_corrections
            WHERE shift_id = %s
            """,
            (shift_id,),
        )["count"] == 0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_allows_anomalous_long_source_shift(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Long Source Mayra", role="payroll")
        employee_id = _create_employee("Payroll Long Source Alma")
        payroll_auth = _login(client, "Payroll Long Source Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day + timedelta(days=2), 8),
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra corrected a bad long clocked shift.",
            },
        )

        assert corrected.status_code == 200, corrected.text
        correction = corrected.json()["correction"]
        assert correction["sourceTotalMinutes"] == 2880
        assert correction["correctedTotalMinutes"] == 240
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_does_not_offer_row_edit_for_midnight_boundary_shift(
    client,
):
    week_start = date(2026, 7, 19)
    service_day = week_start
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Midnight Boundary Mayra", role="payroll")
        employee_id = _create_employee("Payroll Midnight Boundary Alma")
        payroll_auth = _login(client, "Payroll Midnight Boundary Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 20),
            _local_dt(service_day + timedelta(days=1), 0),
        )

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        sunday = body["employees"][0]["days"][0]
        shift = sunday["shifts"][0]
        assert shift["shiftId"] == shift_id
        assert shift["segmentCount"] == 1
        assert shift["spansMultipleDays"] is False
        assert shift["fieldSupport"] == {
            "clockIn": {"display": True, "correction": False},
            "clockOut": {"display": True, "correction": False},
            "breakMinutes": {"display": True, "correction": False},
            "totalHours": {"display": True, "correction": False},
        }
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_supersedes_and_voids(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Shift Void Mayra", role="payroll")
        employee_id = _create_employee("Payroll Shift Void Alma")
        payroll_auth = _login(client, "Payroll Shift Void Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
        )
        first = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 11).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Initial shift correction from Mayra.",
            },
        )
        assert first.status_code == 200, first.text
        first_id = first.json()["correction"]["correctionId"]

        second = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 10, 30).isoformat(),
                "correctedBreakMinutes": 15,
                "reason": "Updated shift correction from Mayra.",
            },
        )
        assert second.status_code == 200, second.text
        second_id = second.json()["correction"]["correctionId"]
        assert second_id != first_id
        assert second.json()["timesheet"]["employees"][0]["days"][3]["totalMinutes"] == 135

        rows = db.query_all(
            """
            SELECT id, status, superseded_by
            FROM payroll_shift_corrections
            WHERE week_start = %s AND shift_id = %s
            ORDER BY id
            """,
            (week_start, shift_id),
        )
        assert rows[0]["status"] == "superseded"
        assert rows[0]["superseded_by"] == second_id
        assert rows[1]["status"] == "active"
        assert rows[1]["superseded_by"] is None

        voided = client.post(
            f"/api/admin/payroll/timesheet/shift-corrections/{second_id}/void",
            headers=payroll_auth,
            json={"reason": "Mayra reversed the row correction."},
        )
        assert voided.status_code == 200, voided.text
        assert voided.json()["correction"]["status"] == "voided"
        wednesday = voided.json()["timesheet"]["employees"][0]["days"][3]
        assert wednesday["status"] == "registered"
        assert wednesday["totalMinutes"] == 120
        assert "correction" not in wednesday["shifts"][0]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_atomic_timesheet_changes_add_edit_exclude_restore_manual_rows(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Manual Rows Mayra", role="payroll")
        employee_id = _create_employee("Payroll Manual Rows Alma")
        payroll_auth = _login(client, "Payroll Manual Rows Mayra")
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)

        add_request_id = str(uuid4())
        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": add_request_id,
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["timesheetSourceFingerprint"],
                "reason": "Employee missed both Site clock-ins.",
                "operations": [
                    {
                        "action": "add_manual",
                        "clientRowId": "draft-a",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 11).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                    {
                        "action": "add_manual",
                        "clientRowId": "draft-b",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 12).isoformat(),
                        "clockOut": _local_dt(service_day, 14, 30).isoformat(),
                        "breakMinutes": 15,
                        "locationId": None,
                    },
                ],
            },
        )
        assert added.status_code == 200, added.text
        body = added.json()
        assert body["action"] == "save_timesheet_changes"
        assert body["idempotent"] is False
        tuesday = body["timesheet"]["employees"][0]["days"][2]
        assert tuesday["totalMinutes"] == 315
        assert [row["sourceKind"] for row in tuesday["shifts"]] == ["manual", "manual"]
        assert all(row["shiftId"] is None for row in tuesday["shifts"])
        assert [row["breakMinutes"] for row in tuesday["shifts"]] == [0, 15]
        assert [row["original"]["breakMinutes"] for row in tuesday["shifts"]] == [0, 15]
        manual_ids = [row["manualShiftId"] for row in tuesday["shifts"]]
        assert db.query_one(
            "SELECT COUNT(*) AS n FROM shifts WHERE employee_id = %s",
            (employee_id,),
        ) == {"n": 0}

        repeated = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": add_request_id,
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["timesheetSourceFingerprint"],
                "reason": "Employee missed both Site clock-ins.",
                "operations": [
                    {
                        "action": "add_manual",
                        "clientRowId": "draft-a",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 11).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                    {
                        "action": "add_manual",
                        "clientRowId": "draft-b",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 12).isoformat(),
                        "clockOut": _local_dt(service_day, 14, 30).isoformat(),
                        "breakMinutes": 15,
                        "locationId": None,
                    },
                ],
            },
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["idempotent"] is True
        assert db.query_one(
            "SELECT COUNT(*) AS n FROM payroll_manual_shift_versions WHERE employee_id = %s",
            (employee_id,),
        ) == {"n": 2}

        changed = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": body["timesheet"]["timesheetSourceFingerprint"],
                "reason": "Supervisor confirmed revised first shift and removed duplicate second shift.",
                "operations": [
                    {
                        "action": "edit_manual",
                        "manualShiftId": manual_ids[0],
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 12).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                    {"action": "exclude_manual", "manualShiftId": manual_ids[1]},
                ],
            },
        )
        assert changed.status_code == 200, changed.text
        changed_day = changed.json()["timesheet"]["employees"][0]["days"][2]
        assert changed_day["totalMinutes"] == 240
        assert len(changed_day["shifts"]) == 1
        assert len(changed_day["excludedShifts"]) == 1
        assert changed_day["excludedShifts"][0]["canRestore"] is True

        restored = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": changed.json()["timesheet"]["timesheetSourceFingerprint"],
                "reason": "Supervisor restored the second confirmed shift.",
                "operations": [{"action": "restore_manual", "manualShiftId": manual_ids[1]}],
            },
        )
        assert restored.status_code == 200, restored.text
        restored_day = restored.json()["timesheet"]["employees"][0]["days"][2]
        assert restored_day["totalMinutes"] == 375
        assert len(restored_day["shifts"]) == 2
        assert restored_day["excludedShifts"] == []
        versions = db.query_all(
            """
            SELECT manual_shift_id, version, status, included
            FROM payroll_manual_shift_versions
            WHERE employee_id = %s
            ORDER BY manual_shift_id, version
            """,
            (employee_id,),
        )
        assert len(versions) == 5
        assert sum(1 for row in versions if row["status"] == "current") == 2
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_atomic_timesheet_changes_exclude_restore_recorded_without_raw_mutation(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Exclusion Mayra", role="payroll")
        employee_id = _create_employee("Payroll Exclusion Alma")
        payroll_auth = _login(client, "Payroll Exclusion Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 10),
        )
        raw_before = db.query_one("SELECT * FROM shifts WHERE id = %s", (shift_id,))
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)

        excluded = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["timesheetSourceFingerprint"],
                "reason": "Duplicate clock record excluded from payroll.",
                "operations": [{"action": "exclude_recorded", "shiftId": shift_id}],
            },
        )
        assert excluded.status_code == 200, excluded.text
        day = excluded.json()["timesheet"]["employees"][0]["days"][3]
        assert day["totalMinutes"] == 0
        assert day["shifts"] == []
        assert day["excludedShifts"][0]["shiftId"] == shift_id
        assert db.query_one("SELECT * FROM shifts WHERE id = %s", (shift_id,)) == raw_before

        blocked_edit = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": excluded.json()["timesheet"][
                    "employees"
                ][0]["timesheetSourceFingerprint"],
                "reason": "Excluded evidence must be restored before editing.",
                "operations": [
                    {
                        "action": "correct_recorded",
                        "shiftId": shift_id,
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 10, 30).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    }
                ],
            },
        )
        assert blocked_edit.status_code == 409, blocked_edit.text
        assert blocked_edit.json()["error"] == (
            "Restore the recorded shift before editing it"
        )

        excluded_employee_token = excluded.json()["timesheet"]["employees"][0][
            "timesheetSourceFingerprint"
        ]
        db.execute(
            "UPDATE shifts SET clock_out = %s, total_hours = 3.00 WHERE id = %s",
            (_local_dt(service_day, 11).astimezone(timezone.utc), shift_id),
        )
        stale_restore = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": excluded_employee_token,
                "reason": "Stale excluded evidence must not be restored.",
                "operations": [{"action": "restore_recorded", "shiftId": shift_id}],
            },
        )
        assert stale_restore.status_code == 409, stale_restore.text
        refreshed = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        assert (
            refreshed["employees"][0]["timesheetSourceFingerprint"]
            != excluded_employee_token
        )

        restored = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": refreshed["employees"][0][
                    "timesheetSourceFingerprint"
                ],
                "reason": "Supervisor confirmed the recorded shift belongs in payroll.",
                "operations": [{"action": "restore_recorded", "shiftId": shift_id}],
            },
        )
        assert restored.status_code == 200, restored.text
        restored_day = restored.json()["timesheet"]["employees"][0]["days"][3]
        assert restored_day["totalMinutes"] == 180
        assert restored_day["excludedShifts"] == []
        assert db.query_one(
            "SELECT clock_out, total_hours FROM shifts WHERE id = %s",
            (shift_id,),
        ) == {
            "clock_out": _local_dt(service_day, 11).astimezone(timezone.utc),
            "total_hours": Decimal("3.00"),
        }
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_atomic_timesheet_can_exclude_and_restore_a_shift_spilling_into_the_week(client):
    week_start = date(2026, 7, 19)
    shift_start = week_start - timedelta(days=1)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Spillover Mayra", role="payroll")
        employee_id = _create_employee("Payroll Spillover Alma")
        payroll_auth = _login(client, "Payroll Spillover Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(shift_start, 22),
            _local_dt(week_start, 2),
        )
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)
        sunday = before["employees"][0]["days"][0]
        assert sunday["totalMinutes"] == 120
        assert sunday["shifts"][0]["shiftId"] == shift_id

        excluded = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["employees"][0][
                    "timesheetSourceFingerprint"
                ],
                "reason": "Saturday shift does not belong in Sunday payroll.",
                "operations": [{"action": "exclude_recorded", "shiftId": shift_id}],
            },
        )
        assert excluded.status_code == 200, excluded.text
        excluded_sunday = excluded.json()["timesheet"]["employees"][0]["days"][0]
        assert excluded_sunday["totalMinutes"] == 0
        assert excluded_sunday["shifts"] == []
        assert excluded_sunday["excludedShifts"][0]["shiftId"] == shift_id
        assert excluded_sunday["excludedShifts"][0]["date"] == week_start.isoformat()
        assert excluded_sunday["excludedShifts"][0]["totalMinutes"] == 120

        restored = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": excluded.json()["timesheet"][
                    "employees"
                ][0]["timesheetSourceFingerprint"],
                "reason": "Sunday spillover hours were confirmed for payroll.",
                "operations": [{"action": "restore_recorded", "shiftId": shift_id}],
            },
        )
        assert restored.status_code == 200, restored.text
        restored_sunday = restored.json()["timesheet"]["employees"][0]["days"][0]
        assert restored_sunday["totalMinutes"] == 120
        assert restored_sunday["excludedShifts"] == []
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_recorded_shift_changes_retire_day_totals_on_every_affected_date(client):
    week_start = date(2026, 7, 19)
    monday = week_start + timedelta(days=1)
    tuesday = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Multi Day Mayra", role="payroll")
        employee_id = _create_employee("Payroll Multi Day Alma")
        payroll_auth = _login(client, "Payroll Multi Day Mayra")
        shift_id = _create_shift(
            employee_id,
            _local_dt(monday, 22),
            _local_dt(tuesday, 2),
        )
        for correction_day in (monday, tuesday):
            corrected = client.post(
                "/api/admin/payroll/weekly-hours/corrections",
                headers=payroll_auth,
                json={
                    "weekStart": week_start.isoformat(),
                    "employeeId": employee_id,
                    "date": correction_day.isoformat(),
                    "correctedTotalMinutes": 180,
                    "reason": "Legacy total awaiting shift-level review.",
                },
            )
            assert corrected.status_code == 200, corrected.text
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)

        excluded = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["employees"][0][
                    "timesheetSourceFingerprint"
                ],
                "reason": "The overnight shift was duplicate evidence.",
                "operations": [{"action": "exclude_recorded", "shiftId": shift_id}],
            },
        )
        assert excluded.status_code == 200, excluded.text
        days = excluded.json()["timesheet"]["employees"][0]["days"]
        assert days[1]["totalMinutes"] == 0
        assert days[2]["totalMinutes"] == 0
        statuses = db.query_all(
            """
            SELECT correction_date, status
            FROM payroll_hour_corrections
            WHERE week_start = %s AND employee_id = %s
            ORDER BY correction_date
            """,
            (week_start, employee_id),
        )
        assert statuses == [
            {"correction_date": monday, "status": "voided"},
            {"correction_date": tuesday, "status": "voided"},
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_excluded_manual_shift_keeps_an_inactive_employee_visible(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Inactive Manual Mayra", role="payroll")
        employee_id = _create_employee("Payroll Inactive Manual Alma")
        payroll_auth = _login(client, "Payroll Inactive Manual Mayra")
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)
        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["employees"][0][
                    "timesheetSourceFingerprint"
                ],
                "reason": "Manual shift added before deactivation.",
                "operations": [
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 10).isoformat(),
                        "breakMinutes": 10,
                        "locationId": None,
                    }
                ],
            },
        )
        assert added.status_code == 200, added.text
        manual_id = added.json()["timesheet"]["employees"][0]["days"][2]["shifts"][0][
            "manualShiftId"
        ]
        excluded = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": added.json()["timesheet"][
                    "employees"
                ][0]["timesheetSourceFingerprint"],
                "reason": "Manual shift excluded before deactivation.",
                "operations": [{"action": "exclude_manual", "manualShiftId": manual_id}],
            },
        )
        assert excluded.status_code == 200, excluded.text
        db.execute("UPDATE employees SET active = FALSE WHERE id = %s", (employee_id,))

        inactive = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        assert inactive["summary"]["employeeCount"] == 1
        assert inactive["employees"][0]["active"] is False
        excluded_rows = inactive["employees"][0]["days"][2]["excludedShifts"]
        assert excluded_rows[0]["manualShiftId"] == manual_id
        assert excluded_rows[0]["breakMinutes"] == 10
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_inactive_employee_can_add_their_first_manual_payroll_shift(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=2)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Inactive First Edit Mayra", role="payroll")
        employee_id = _create_employee(
            "Payroll Inactive First Edit Alma",
            active=False,
        )
        payroll_auth = _login(client, "Payroll Inactive First Edit Mayra")

        before = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        assert before["summary"]["employeeCount"] == 1
        assert before["employees"][0]["active"] is False
        employee_token = before["employees"][0]["timesheetSourceFingerprint"]
        assert len(employee_token) == 64

        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": employee_token,
                "reason": "Historical worker missed the first payroll clock record.",
                "operations": [
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 10).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    }
                ],
            },
        )
        assert added.status_code == 200, added.text
        assert added.json()["timesheet"]["employees"][0]["days"][2][
            "totalMinutes"
        ] == 120
        batch = db.query_one(
            """
            SELECT before_source_fingerprint, after_source_fingerprint
            FROM payroll_timesheet_change_batches
            WHERE employee_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (employee_id,),
        )
        assert len(batch["before_source_fingerprint"]) == 64
        assert len(batch["after_source_fingerprint"]) == 64
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_employee_timesheet_token_ignores_unrelated_employee_clock_changes(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    payroll_id = None
    first_employee_id = None
    second_employee_id = None
    try:
        payroll_id = _create_employee("Payroll Scoped Token Mayra", role="payroll")
        first_employee_id = _create_employee("Payroll Scoped Token Alma")
        second_employee_id = _create_employee("Payroll Scoped Token Berta")
        payroll_auth = _login(client, "Payroll Scoped Token Mayra")
        before = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=first_employee_id,
        )
        first_token = before["employees"][0]["timesheetSourceFingerprint"]
        global_token = before["timesheetSourceFingerprint"]

        _create_shift(
            second_employee_id,
            _local_dt(service_day, 7),
            _local_dt(service_day, 9),
        )
        after_other_clock = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=first_employee_id,
        )
        assert after_other_clock["timesheetSourceFingerprint"] != global_token
        assert after_other_clock["employees"][0]["timesheetSourceFingerprint"] == first_token

        saved = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": first_employee_id,
                "expectedTimesheetSourceFingerprint": first_token,
                "reason": "Unrelated employee clocks do not stale this row.",
                "operations": [
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 10).isoformat(),
                        "clockOut": _local_dt(service_day, 11).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    }
                ],
            },
        )
        assert saved.status_code == 200, saved.text
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees(
            [
                value
                for value in (first_employee_id, second_employee_id, payroll_id)
                if value
            ]
        )


def test_atomic_timesheet_changes_are_stale_safe_atomic_and_retire_day_total(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Atomic Mayra", role="payroll")
        employee_id = _create_employee("Payroll Atomic Alma")
        payroll_auth = _login(client, "Payroll Atomic Mayra")
        baseline = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)
        correction = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 60,
                "reason": "Legacy total before granular evidence arrived.",
            },
        )
        assert correction.status_code == 200, correction.text
        with_total = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)

        failed = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": with_total["timesheetSourceFingerprint"],
                "reason": "This whole batch must roll back.",
                "operations": [
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 10).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                    {"action": "exclude_recorded", "shiftId": 2147483647},
                ],
            },
        )
        assert failed.status_code == 404, failed.text
        assert db.query_one(
            "SELECT COUNT(*) AS n FROM payroll_manual_shift_versions WHERE employee_id = %s",
            (employee_id,),
        ) == {"n": 0}
        assert db.query_one(
            "SELECT COUNT(*) AS n FROM payroll_timesheet_change_batches WHERE employee_id = %s",
            (employee_id,),
        ) == {"n": 0}

        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": with_total["timesheetSourceFingerprint"],
                "reason": "Granular row replaces the legacy day total.",
                "operations": [{
                    "action": "add_manual",
                    "date": service_day.isoformat(),
                    "clockIn": _local_dt(service_day, 8).isoformat(),
                    "clockOut": _local_dt(service_day, 10).isoformat(),
                    "breakMinutes": 0,
                    "locationId": None,
                }],
            },
        )
        assert added.status_code == 200, added.text
        day = added.json()["timesheet"]["employees"][0]["days"][1]
        assert day["totalMinutes"] == 120
        assert day.get("correction") is None
        assert db.query_one(
            """
            SELECT status FROM payroll_hour_corrections
            WHERE week_start = %s AND employee_id = %s AND correction_date = %s
            ORDER BY id DESC LIMIT 1
            """,
            (week_start, employee_id, service_day),
        ) == {"status": "voided"}

        stale = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": baseline["timesheetSourceFingerprint"],
                "reason": "Stale browser must not overwrite current payroll.",
                "operations": [{
                    "action": "add_manual",
                    "date": service_day.isoformat(),
                    "clockIn": _local_dt(service_day, 11).isoformat(),
                    "clockOut": _local_dt(service_day, 12).isoformat(),
                    "breakMinutes": 0,
                    "locationId": None,
                }],
            },
        )
        assert stale.status_code == 409, stale.text
        assert stale.json()["error"] == "Payroll timesheet changed; refresh before saving"
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_manual_shift_overlap_blocks_verification_and_verified_week_locks_changes(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=4)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Overlap Mayra", role="payroll")
        employee_id = _create_employee("Payroll Overlap Alma")
        payroll_auth = _login(client, "Payroll Overlap Mayra")
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)
        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["timesheetSourceFingerprint"],
                "reason": "Supervisor supplied two overlapping records for review.",
                "operations": [
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 8).isoformat(),
                        "clockOut": _local_dt(service_day, 11).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 10).isoformat(),
                        "clockOut": _local_dt(service_day, 12).isoformat(),
                        "breakMinutes": 0,
                        "locationId": None,
                    },
                ],
            },
        )
        assert added.status_code == 200, added.text
        added_body = added.json()["timesheet"]
        assert added_body["summary"]["hasBlockingIssues"] is True
        assert added_body["summary"]["issueCount"] == 2
        assert all(
            issue["code"] == "overlapping_shift" and issue["manualShiftId"]
            for issue in added_body["employees"][0]["issues"]
        )
        blocked = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": added_body["sourceFingerprint"],
            },
        )
        assert blocked.status_code == 409, blocked.text

        manual_ids = [
            row["manualShiftId"]
            for row in added_body["employees"][0]["days"][4]["shifts"]
        ]
        resolved_request_id = str(uuid4())
        resolved_request = {
            "requestId": resolved_request_id,
            "weekStart": week_start.isoformat(),
            "employeeId": employee_id,
            "expectedTimesheetSourceFingerprint": added_body["timesheetSourceFingerprint"],
            "reason": "Supervisor identified the second row as duplicate.",
            "operations": [{"action": "exclude_manual", "manualShiftId": manual_ids[1]}],
        }
        resolved = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json=resolved_request,
        )
        assert resolved.status_code == 200, resolved.text
        resolved_body = resolved.json()["timesheet"]
        assert resolved_body["summary"]["hasBlockingIssues"] is False
        verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": resolved_body["sourceFingerprint"],
                "reason": "Mayra verified the resolved payroll week.",
            },
        )
        assert verified.status_code == 200, verified.text

        repeated_after_verification = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json=resolved_request,
        )
        assert repeated_after_verification.status_code == 200, repeated_after_verification.text
        assert repeated_after_verification.json()["idempotent"] is True

        locked = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": resolved_body["timesheetSourceFingerprint"],
                "reason": "This edit requires reopening first.",
                "operations": [{
                    "action": "edit_manual",
                    "manualShiftId": manual_ids[0],
                    "date": service_day.isoformat(),
                    "clockIn": _local_dt(service_day, 8).isoformat(),
                    "clockOut": _local_dt(service_day, 11, 30).isoformat(),
                    "breakMinutes": 0,
                    "locationId": None,
                }],
            },
        )
        assert locked.status_code == 409, locked.text
        assert locked.json()["error"] == "Reopen the payroll week before changing corrections"
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_manual_payroll_rows_do_not_enter_employee_or_general_hours(client, auth, monkeypatch):
    week_start = date(2026, 8, 2)
    service_day = week_start + timedelta(days=3)
    observed_at = _local_dt(week_start + timedelta(days=5), 12).astimezone(timezone.utc)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Scope Mayra", role="payroll")
        employee_id = _create_employee("Payroll Scope Alma")
        payroll_auth = _login(client, "Payroll Scope Mayra")
        employee_auth = _login(client, "Payroll Scope Alma")
        monkeypatch.setattr(time_tracker_api, "utc_now", lambda: observed_at)
        before = _payroll_timesheet(client, payroll_auth, week_start, employee_id=employee_id)
        added = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["timesheetSourceFingerprint"],
                "reason": "Payroll-only verification row.",
                "operations": [{
                    "action": "add_manual",
                    "date": service_day.isoformat(),
                    "clockIn": _local_dt(service_day, 8).isoformat(),
                    "clockOut": _local_dt(service_day, 10).isoformat(),
                    "breakMinutes": 0,
                    "locationId": None,
                }],
            },
        )
        assert added.status_code == 200, added.text
        assert added.json()["timesheet"]["summary"]["totalMinutes"] == 120

        my_hours = client.get("/api/timesheet/my-hours", headers=employee_auth)
        assert my_hours.status_code == 200, my_hours.text
        assert my_hours.json()["weeklyHours"] == 0

        general_report = client.get(
            f"/api/admin/reports/hours?period=week&date={service_day.isoformat()}&employee_id={employee_id}",
            headers=auth,
        )
        assert general_report.status_code == 200, general_report.text
        assert general_report.json()["rows"] == []
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_allocation_labels_and_rate_fingerprint(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Timesheet Allocation Worker",
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
        # This test exercises the LIVE-tracked correction path, which requires a
        # shift with no snapshot (a pre-migration or rate-less-at-clock-in row).
        # The insert trigger now stamps every insert for a rated employee, so
        # clear this shift's snapshot back to NULL to recreate that state.
        _stamp_shift_snapshots(employee_id, service_day, {site_id: None})
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours for allocation labels.",
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

        first = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        first_fingerprint = first["timesheetSourceFingerprint"]
        monday = first["employees"][0]["days"][1]
        allocation = monday["correction"]["allocation"]
        assert allocation["customerId"] == customer_id
        assert allocation["customerName"] == "Payroll Labor Profitability Customer"
        assert allocation["siteAddress"] == "Payroll Labor Profitability Site"
        assert allocation["currentAllocatedLaborCost"] == 20.0

        db.execute(
            """
            UPDATE locations
            SET
                customer_name = 'Payroll Labor Profitability Renamed Customer',
                address = 'Payroll Labor Profitability Renamed Site'
            WHERE id = %s
            """,
            (site_id,),
        )

        second = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        second_allocation = second["employees"][0]["days"][1]["correction"]["allocation"]
        assert second_allocation["customerName"] == (
            "Payroll Labor Profitability Renamed Customer"
        )
        assert second_allocation["siteAddress"] == (
            "Payroll Labor Profitability Renamed Site"
        )
        assert second["timesheetSourceFingerprint"] != first_fingerprint

        db.execute(
            "UPDATE employees SET hourly_rate = 25 WHERE id = %s",
            (employee_id,),
        )

        third = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        third_allocation = third["employees"][0]["days"][1]["correction"]["allocation"]
        # This correction's shift carries NO snapshot: the profitability test
        # helper raw-inserts the shift without hourly_rate_cents, so it follows
        # the live rate exactly as the shift's own labor does. Finding 2 (#126):
        # a correction on an unfrozen shift must NOT itself freeze -- it stays
        # live-tracked (stored NULL, valued at the live recompute), or the
        # correction would stick while the shift labor moved on a rate edit.
        # After the raise it therefore reads $25, consistent with the shift.
        assert third_allocation["allocatedLaborCost"] is None
        assert third_allocation["laborCostIsLive"] is True
        assert third_allocation["currentAllocatedLaborCost"] == 25.0
        assert third_allocation["laborCostComplete"] is True
        # D3: the fingerprint deliberately still hashes the live rate, so a rate
        # edit still invalidates a verified payroll week. Out of scope for #126.
        assert third["timesheetSourceFingerprint"] != second["timesheetSourceFingerprint"]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_marks_stale_correction_allocation_invalid(client):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=1)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Timesheet Stale Allocation Worker",
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
        shift = db.query_one(
            "SELECT id FROM shifts WHERE employee_id = %s AND job_id = %s",
            (employee_id, job_id),
        )
        assert shift is not None

        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": service_day.isoformat(),
                "correctedTotalMinutes": 180,
                "reason": "Mayra corrected total hours before stale allocation.",
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
                "reason": "Juan assigned Mayra's correction before shift evidence changed.",
            },
        )
        assert allocated.status_code == 200, allocated.text
        assert allocated.json()["allocation"]["allocatedDeltaMinutes"] == 60

        before = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        before_correction = before["employees"][0]["days"][1]["correction"]
        before_fingerprint = before["timesheetSourceFingerprint"]
        assert before_correction["deltaMinutes"] == 60
        assert before_correction["allocationStatus"] == "allocated"
        assert before_correction["allocationValid"] is True

        changed_clock_out = _local_dt(service_day, 11, 30).astimezone(timezone.utc)
        db.execute(
            """
            UPDATE shifts
            SET
                clock_out = %s,
                total_hours = 2.50
            WHERE id = %s
            """,
            (changed_clock_out, int(shift["id"])),
        )

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        monday = body["employees"][0]["days"][1]
        correction = monday["correction"]
        assert correction["deltaMinutes"] == 30
        assert correction["allocationStatus"] == "invalid"
        assert correction["allocationValid"] is False
        assert correction["allocation"]["allocatedDeltaMinutes"] == 60
        assert correction["allocationIssue"]["code"] == (
            "payroll_correction_allocation_stale_delta"
        )
        assert body["timesheetSourceFingerprint"] != before_fingerprint
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_clips_open_shift_segment_to_week_start(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    prior_day = week_start - timedelta(days=1)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Timesheet Open Shift Mayra", role="payroll")
        employee_id = _create_employee("Payroll Timesheet Open Shift Worker")
        payroll_auth = _login(client, "Payroll Timesheet Open Shift Mayra")
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(week_start + timedelta(days=1), 12).astimezone(timezone.utc),
        )
        _create_shift(
            employee_id,
            _local_dt(prior_day, 20),
            None,
        )

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )
        sunday = body["employees"][0]["days"][0]
        assert sunday["status"] == "needs_review"
        assert sunday["issueCodes"] == ["missing_clock_out"]
        shift = sunday["shifts"][0]
        assert shift["clockIn"]["localIso"].startswith("2026-07-18T20:00:00")
        assert shift["segmentClockIn"]["localIso"].startswith("2026-07-19T00:00:00")
        assert shift["segmentClockOut"] is None
        assert shift["totalMinutes"] == 0
        assert shift["fieldSupport"] == {
            "clockIn": {"display": True, "correction": False},
            "clockOut": {"display": True, "correction": False},
            "breakMinutes": {"display": True, "correction": False},
            "totalHours": {"display": True, "correction": False},
        }
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_timesheet_offers_row_edit_for_same_day_open_shift(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Same Day Open Mayra", role="payroll")
        employee_id = _create_employee("Payroll Same Day Open Alma")
        payroll_auth = _login(client, "Payroll Same Day Open Mayra")
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12).astimezone(timezone.utc),
        )
        shift_id = _create_shift(employee_id, _local_dt(service_day, 8), None)

        body = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        wednesday = body["employees"][0]["days"][3]
        shift = wednesday["shifts"][0]
        assert shift["shiftId"] == shift_id
        assert wednesday["issueCodes"] == ["missing_clock_out"]
        assert shift["fieldSupport"] == {
            "clockIn": {"display": True, "correction": True},
            "clockOut": {"display": True, "correction": True},
            "breakMinutes": {"display": True, "correction": True},
            "totalHours": {"display": True, "correction": False},
        }
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_rejects_future_clock_out(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Future Clockout Mayra", role="payroll")
        employee_id = _create_employee("Payroll Future Clockout Alma")
        payroll_auth = _login(client, "Payroll Future Clockout Mayra")
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 10).astimezone(timezone.utc),
        )
        shift_id = _create_shift(employee_id, _local_dt(service_day, 8), None)

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "This correction should not count future hours.",
            },
        )

        assert corrected.status_code == 400
        assert corrected.json()["error"] == "Corrected clock-out cannot be in the future"
        assert db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM payroll_shift_corrections
            WHERE shift_id = %s
            """,
            (shift_id,),
        )["count"] == 0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_closes_open_source_shift_for_later_weeks(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    next_week_start = week_start + timedelta(days=7)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Open Closed Mayra", role="payroll")
        employee_id = _create_employee("Payroll Open Closed Alma")
        payroll_auth = _login(client, "Payroll Open Closed Mayra")
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12).astimezone(timezone.utc),
        )
        shift_id = _create_shift(employee_id, _local_dt(service_day, 8), None)

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra closed the missing clock-out from the source week.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(next_week_start + timedelta(days=2), 12).astimezone(
                timezone.utc
            ),
        )
        weekly = _weekly_hours(client, payroll_auth, next_week_start)
        employee = _employees_by_name(weekly)["Payroll Open Closed Alma"]
        assert employee["issueCodes"] == []
        assert employee["totalMinutes"] == 0
        assert employee["completedShiftCount"] == 0
        assert employee["overlappingShiftCount"] == 0

        timesheet = _payroll_timesheet(
            client,
            payroll_auth,
            next_week_start,
            employee_id=employee_id,
        )
        assert timesheet["summary"]["issueCount"] == 0
        assert all(day["shifts"] == [] for day in timesheet["employees"][0]["days"])
    finally:
        _delete_payroll_verification_weeks([week_start, next_week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_resolves_open_shift_for_next_clock_in(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Open Clockin Mayra", role="payroll")
        employee_id = _create_employee("Payroll Open Clockin Alma")
        payroll_auth = _login(client, "Payroll Open Clockin Mayra")
        employee_auth = _login(client, "Payroll Open Clockin Alma")
        monkeypatch.setattr(time_tracker_api, "ENFORCE_CLOCK_HOURS", False)
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12).astimezone(timezone.utc),
        )
        shift_id = _create_shift(employee_id, _local_dt(service_day, 8), None)

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 11).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra closed the missing clock-out before next work.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12, 30).astimezone(timezone.utc),
        )
        next_clock_in = client.post(
            "/api/timesheet/clock-in",
            headers=employee_auth,
            json={
                "location": "Payroll Open Clockin Next Site",
                "gpsOverrideReason": "payroll correction closed prior shift",
            },
        )

        assert next_clock_in.status_code == 200, next_clock_in.text
        assert int(next_clock_in.json()["entry"]["id"]) != shift_id
        raw_shift = db.query_one(
            "SELECT clock_out FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert raw_shift["clock_out"] is None
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_shift_correction_excludes_resolved_open_shift_from_status_views(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    admin_id = None
    employee_id = None
    try:
        admin_id = _create_employee("Payroll Open Status Admin", role="admin")
        employee_id = _create_employee("Payroll Open Status Alma")
        admin_auth = _login(client, "Payroll Open Status Admin")
        employee_auth = _login(client, "Payroll Open Status Alma")
        monkeypatch.setattr(time_tracker_api, "ENFORCE_CLOCK_HOURS", False)
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12).astimezone(timezone.utc),
        )
        source_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            None,
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=admin_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": source_shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 11).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra closed this raw open shift before status checks.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        employee_status = client.get(
            "/api/timesheet/current-status",
            headers=employee_auth,
        )
        assert employee_status.status_code == 200, employee_status.text
        assert employee_status.json()["currentlyWorking"] == []

        dashboard = time_tracker_api.build_dashboard_hours_data()
        employee_row = next(
            row
            for row in dashboard["employees"]
            if row["name"] == "Payroll Open Status Alma"
        )
        assert employee_row["currentlyWorking"] is False
        assert employee_row["totalHours"] == 0.0
        assert employee_row["shifts"] == []

        my_hours = client.get("/api/timesheet/my-hours", headers=employee_auth)
        assert my_hours.status_code == 200, my_hours.text
        # The resolved open shift stays out of live status views and
        # recentShifts, but weeklyHours now reports the payroll-effective
        # (corrected) 3 paid hours instead of hiding them from the employee.
        assert my_hours.json()["weeklyHours"] == 3.0
        assert my_hours.json()["weeklyHoursBasis"] == {
            "paidHours": 3.0,
            "liveOpenHours": 0.0,
        }
        assert my_hours.json()["recentShifts"] == []

        admin_hours = client.get(
            f"/api/admin/employees/{employee_id}/hours",
            headers=admin_auth,
        )
        assert admin_hours.status_code == 200, admin_hours.text
        assert admin_hours.json()["weeklyHours"] == 0.0
        assert admin_hours.json()["shifts"] == []
        assert all(day["shifts"] == [] for day in admin_hours.json()["weekGrid"])

        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12, 30).astimezone(timezone.utc),
        )
        next_clock_in = client.post(
            "/api/timesheet/clock-in",
            headers=employee_auth,
            json={
                "location": "Payroll Open Status Current Site",
                "gpsOverrideReason": "payroll correction closed prior shift",
            },
        )
        assert next_clock_in.status_code == 200, next_clock_in.text

        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 13).astimezone(timezone.utc),
        )
        current_status = client.get(
            "/api/timesheet/current-status",
            headers=employee_auth,
        )
        assert current_status.status_code == 200, current_status.text
        current_rows = current_status.json()["currentlyWorking"]
        assert [row["location"] for row in current_rows] == [
            "Payroll Open Status Current Site"
        ]

        current_my_hours = client.get("/api/timesheet/my-hours", headers=employee_auth)
        assert current_my_hours.status_code == 200, current_my_hours.text
        # 3.0 corrected paid hours from the resolved shift plus the 0.5 hours
        # elapsed on the new open shift.
        assert current_my_hours.json()["weeklyHours"] == 3.5
        assert current_my_hours.json()["weeklyHoursBasis"] == {
            "paidHours": 3.0,
            "liveOpenHours": 0.5,
        }
        assert current_my_hours.json()["recentShifts"] == [
            {
                "date": service_day.isoformat(),
                "clockIn": "12:30 PM",
                "clockOut": "Active",
                "hours": 0.5,
                "location": "Payroll Open Status Current Site",
                "customer": "",
            }
        ]

        current_admin_hours = client.get(
            f"/api/admin/employees/{employee_id}/hours",
            headers=admin_auth,
        )
        assert current_admin_hours.status_code == 200, current_admin_hours.text
        assert current_admin_hours.json()["weeklyHours"] == 0.5
        assert [
            shift["location"]
            for day in current_admin_hours.json()["weekGrid"]
            for shift in day["shifts"]
        ] == ["Payroll Open Status Current Site"]

        refreshed_dashboard = time_tracker_api.build_dashboard_hours_data()
        refreshed_row = next(
            row
            for row in refreshed_dashboard["employees"]
            if row["name"] == "Payroll Open Status Alma"
        )
        assert refreshed_row["currentlyWorking"] is True
        assert refreshed_row["totalHours"] == 0.5
        assert refreshed_row["shifts"] == [
            {
                "date": service_day.isoformat(),
                "startTime": "12:30",
                "endTime": "--:--",
                "hours": 0.5,
            }
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, admin_id) if value])


def test_payroll_shift_correction_void_rejects_second_open_shift(
    client,
    monkeypatch,
):
    week_start = date(2026, 7, 19)
    service_day = week_start + timedelta(days=3)
    payroll_id = None
    employee_id = None
    try:
        payroll_id = _create_employee("Payroll Open Void Mayra", role="payroll")
        employee_id = _create_employee("Payroll Open Void Alma")
        payroll_auth = _login(client, "Payroll Open Void Mayra")
        employee_auth = _login(client, "Payroll Open Void Alma")
        monkeypatch.setattr(time_tracker_api, "ENFORCE_CLOCK_HOURS", False)
        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12).astimezone(timezone.utc),
        )
        source_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            None,
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": source_shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 8).isoformat(),
                "correctedClockOut": _local_dt(service_day, 11).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra closed the missing clock-out before later work.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        correction_id = corrected.json()["correction"]["correctionId"]

        monkeypatch.setattr(
            time_tracker_api,
            "utc_now",
            lambda: _local_dt(service_day, 12, 30).astimezone(timezone.utc),
        )
        next_clock_in = client.post(
            "/api/timesheet/clock-in",
            headers=employee_auth,
            json={
                "location": "Payroll Open Void Current Site",
                "gpsOverrideReason": "payroll correction closed prior shift",
            },
        )
        assert next_clock_in.status_code == 200, next_clock_in.text

        voided = client.post(
            f"/api/admin/payroll/timesheet/shift-corrections/{correction_id}/void",
            headers=payroll_auth,
            json={"reason": "Mayra tried to restore the older raw open shift."},
        )

        assert voided.status_code == 409
        assert "another open shift" in voided.json()["error"]
        row = db.query_one(
            """
            SELECT status
            FROM payroll_shift_corrections
            WHERE id = %s
            """,
            (correction_id,),
        )
        assert row["status"] == "active"
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([value for value in (employee_id, payroll_id) if value])


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
    week_start = date(2026, 8, 30)
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
    week_start = date(2026, 6, 7)
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
        "DROP TABLE IF EXISTS payroll_shift_exclusions, "
        "payroll_manual_shift_versions, payroll_timesheet_change_batches, "
        "payroll_shift_corrections, "
        "payroll_hour_correction_allocations, "
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
    shift_correction_table = db.query_one(
        "SELECT to_regclass('payroll_shift_corrections') AS table_name"
    )
    change_batch_table = db.query_one(
        "SELECT to_regclass('payroll_timesheet_change_batches') AS table_name"
    )
    manual_shift_table = db.query_one(
        "SELECT to_regclass('payroll_manual_shift_versions') AS table_name"
    )
    exclusion_table = db.query_one(
        "SELECT to_regclass('payroll_shift_exclusions') AS table_name"
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
    assert shift_correction_table is not None
    assert shift_correction_table["table_name"] == "payroll_shift_corrections"
    assert change_batch_table == {"table_name": "payroll_timesheet_change_batches"}
    assert manual_shift_table == {"table_name": "payroll_manual_shift_versions"}
    assert exclusion_table == {"table_name": "payroll_shift_exclusions"}
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


def test_payroll_labor_profitability_applies_manual_and_exclusion_overlays(client):
    week_start = date(2026, 7, 19)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Overlay Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Overlay Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Overlay Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 8),
            scheduled_end=_local_dt(service_day, 15),
            source_key="d" * 64,
        )
        shift_id = _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            job_id=job_id,
            local_start=_local_dt(service_day, 8),
            local_end=_local_dt(service_day, 11),
        )
        before = _payroll_timesheet(
            client,
            payroll_auth,
            week_start,
            employee_id=employee_id,
        )

        changed = client.post(
            "/api/admin/payroll/timesheet/changes",
            headers=payroll_auth,
            json={
                "requestId": str(uuid4()),
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "expectedTimesheetSourceFingerprint": before["employees"][0][
                    "timesheetSourceFingerprint"
                ],
                "reason": "Duplicate clock excluded and missed Site shift restored.",
                "operations": [
                    {"action": "exclude_recorded", "shiftId": shift_id},
                    {
                        "action": "add_manual",
                        "date": service_day.isoformat(),
                        "clockIn": _local_dt(service_day, 12).isoformat(),
                        "clockOut": _local_dt(service_day, 14).isoformat(),
                        "breakMinutes": 0,
                        "locationId": site_id,
                    },
                ],
            },
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["timesheet"]["summary"]["totalHours"] == 2.0

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["totalHours"] == 2.0
        assert body["summary"]["actualHours"] == 2.0
        assert body["summary"]["actualLaborCost"] == 40.0
        job = next(row for row in body["jobs"] if row["jobId"] == job_id)
        assert job["actualHours"] == 2.0
        assert job["actualLaborCost"] == 40.0
        assert job["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Overlay Worker",
                "hours": 2.0,
                "laborCost": 40.0,
                "status": "finalized",
            }
        ]
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_uses_shift_correction_overlay(client):
    week_start = date(2026, 7, 19)
    next_week_start = week_start + timedelta(days=7)
    service_day = date(2026, 7, 20)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start, next_week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Mayra",
            role="payroll",
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Shift Correction Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 12),
            source_key="c" * 64,
        )
        shift_id = _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            job_id=job_id,
            local_start=_local_dt(service_day, 9),
            local_end=_local_dt(service_day, 11),
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 9).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Mayra corrected shift clock-out for site proof.",
            },
        )
        assert corrected.status_code == 200, corrected.text
        db.execute(
            """
            INSERT INTO payroll_shift_corrections (
                week_start,
                correction_date,
                employee_id,
                shift_id,
                source_clock_in,
                source_clock_out,
                source_break_minutes,
                source_total_minutes,
                corrected_clock_in,
                corrected_clock_out,
                corrected_break_minutes,
                corrected_total_minutes,
                reason,
                created_by_employee_id,
                created_by_name
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, NULL, 120,
                %s, %s, 0, 60,
                'A different payroll week correction must not fan out labor.',
                %s, 'Payroll Labor Profitability Mayra'
            )
            """,
            (
                next_week_start,
                next_week_start,
                employee_id,
                shift_id,
                _local_dt(service_day, 9).astimezone(timezone.utc),
                _local_dt(service_day, 11).astimezone(timezone.utc),
                _local_dt(service_day, 9).astimezone(timezone.utc),
                _local_dt(service_day, 10).astimezone(timezone.utc),
                payroll_id,
            ),
        )

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["totalHours"] == 3.0
        assert body["payrollHours"]["correctionCount"] == 1
        assert body["summary"]["actualHours"] == 3.0
        assert body["summary"]["varianceHours"] == 0.0
        assert body["summary"]["actualLaborCost"] == 60.0
        assert body["summary"]["netProfit"] == 90.0
        assert body["summary"]["actualLaborPct"] == 40.0

        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        site = monday["sites"][0]
        job = site["jobs"][0]
        assert monday["actualHours"] == 3.0
        assert site["actualHours"] == 3.0
        assert site["actualLaborCost"] == 60.0
        assert job["jobId"] == job_id
        assert job["actualHours"] == 3.0
        assert job["actualLaborCost"] == 60.0
        assert job["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Shift Correction Worker",
                "hours": 3.0,
                "laborCost": 60.0,
                "status": "finalized",
            }
        ]
    finally:
        _delete_payroll_verification_weeks([week_start, next_week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([value for value in (employee_id, payroll_id) if value])


def test_payroll_labor_profitability_applies_corrected_break_after_job_match(
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
            "Payroll Labor Profitability Break Match Worker",
            hourly_rate=20,
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Mayra")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        job_id = _create_payroll_profitability_job_only(
            site_id=site_id,
            source_id=source_id,
            scheduled_date=service_day,
            scheduled_start=_local_dt(service_day, 9),
            scheduled_end=_local_dt(service_day, 12),
            source_key="d" * 64,
        )
        shift_id = _create_payroll_profitability_shift_evidence(
            employee_id=employee_id,
            site_id=site_id,
            local_start=_local_dt(service_day, 9),
            local_end=_local_dt(service_day, 12),
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 9).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12).isoformat(),
                "correctedBreakMinutes": 30,
                "reason": "Mayra confirmed the default clock shift had a lunch break.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["payrollHours"]["totalHours"] == 2.5
        assert body["summary"]["actualHours"] == 2.5
        assert body["summary"]["actualLaborCost"] == 50.0

        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        site = monday["sites"][0]
        job = site["jobs"][0]
        assert site["actualHours"] == 2.5
        assert site["actualLaborCost"] == 50.0
        assert job["jobId"] == job_id
        assert job["actualHours"] == 2.5
        assert job["actualLaborCost"] == 50.0
        assert job["workers"] == [
            {
                "employeeId": employee_id,
                "employeeName": "Payroll Labor Profitability Break Match Worker",
                "hours": 2.5,
                "laborCost": 50.0,
                "status": "finalized",
            }
        ]
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
        # Live-tracked path needs a snapshot-less shift; the insert trigger now
        # stamps rated-employee inserts, so clear it back to NULL to recreate the
        # pre-migration / rate-less-at-clock-in state this test exercises.
        _stamp_shift_snapshots(employee_id, service_day, {site_id: None})
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
        # The profitability helper's shift carries no snapshot, so this
        # correction is live-tracked (finding 2, #126): stored NULL, valued at
        # the live recompute -- the cost is known ($20) and complete, but not
        # frozen, so it would move with a later rate edit like the shift's labor.
        assert allocation["allocatedLaborCost"] is None
        assert allocation["laborCostIsLive"] is True
        assert allocation["currentAllocatedLaborCost"] == 20.0
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


def test_payroll_correction_on_a_rateless_shift_tracks_the_live_rate(client):
    """A correction on a NULL-snapshot (rate-less) shift tracks the live rate.

    The shift here carries no snapshot (the employee had no rate at clock-in),
    so its own labor follows the live rate: once a rate is added, the shift
    reads $40 (2h x $20). Finding 2 (#126): the correction on that shift must
    track the live rate the same way -- if it stayed frozen/incomplete while the
    shift labor moved, adjusted profitability would be internally inconsistent
    (a live shift addend plus a stale correction addend for one employee-day).

    So, unlike a genuinely snapshotted correction (which freezes), this one is
    live-tracked: stored cost NULL + laborCostIsLive, valued at the live
    recompute. Before a rate exists it is unknown/incomplete; after the rate is
    added it becomes $20 and adjustedActualLaborCost is a consistent 40 + 20 =
    60, both addends at the live rate. This is NOT the retroactive restatement
    of a frozen shift -- the shift was never frozen.
    """
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
        # Live-tracked: the shift carries no snapshot, so the correction follows
        # the live rate. Once the rate is added it is known ($20) and complete,
        # consistent with the shift's own live-rate labor -- NOT a restatement of
        # a frozen shift, because this shift was never frozen.
        assert body["payrollHours"]["allocatedCorrectionLaborCost"] == 20.0
        assert body["payrollHours"]["knownAllocatedCorrectionLaborCost"] == 20.0
        assert body["payrollHours"]["allocatedCorrectionLaborCostComplete"] is True
        correction = body["payrollHours"]["allocatedCorrections"][0]
        allocation = correction["allocation"]
        assert allocation["allocatedLaborCost"] is None
        assert allocation["laborCostIsLive"] is True
        assert allocation["laborCostComplete"] is True
        assert allocation["currentAllocatedLaborCost"] == 20.0
        assert allocation["currentLaborCostComplete"] is True
        # The shift carries no rate snapshot (it predates the rate), so it falls
        # back to the live rate -- $40 for 2h at $20.
        assert body["summary"]["actualLaborCost"] == 40.0
        # 40 + 20 = 60, both addends at the live rate for the same employee-day:
        # a live shift and its live-tracked correction stay consistent.
        assert body["summary"]["adjustedActualLaborCost"] == 60.0
        assert body["summary"]["adjustedLaborCostComplete"] is True
        assert body["summary"]["knownAdjustedActualLaborCost"] == 60.0
        monday = next(row for row in body["byDay"] if row["date"] == "2026-07-20")
        assert monday["allocatedCorrections"] == [correction]
        assert monday["adjustedActualLaborCost"] == 60.0
        assert monday["adjustedLaborCostComplete"] is True
        assert monday["knownAdjustedActualLaborCost"] == 60.0
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


def test_overlapping_shifts_emit_issue_and_block_verify_and_finalize(client, auth):
    week_start = date(2026, 6, 7)
    service_day = week_start + timedelta(days=1)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Overlap Blocking Worker")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 16),
        )
        _create_shift(
            employee_id,
            _local_dt(service_day, 10),
            _local_dt(service_day, 12),
        )

        weekly = _weekly_hours(client, auth, week_start)
        row = next(
            employee
            for employee in weekly["employees"]
            if employee["employeeId"] == employee_id
        )
        assert "overlapping_shift" in row["issueCodes"]
        # Flag, don't zero: both shifts keep their real magnitudes so the
        # admin can see what to fix.
        assert row["totalMinutes"] == 600
        assert weekly["summary"]["hasBlockingIssues"] is True

        verify = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert verify.status_code == 409, verify.text
        assert verify.json()["error"] == (
            "Resolve payroll hour issues before verifying this week"
        )

        finalize = client.post(
            "/api/admin/payroll/weekly-hours/finalize",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert finalize.status_code == 409, finalize.text
        assert finalize.json()["error"] == (
            "Resolve payroll hour issues before finalizing this week"
        )
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_adjacent_back_to_back_shifts_do_not_flag_overlap(client, auth):
    week_start = date(2026, 6, 7)
    service_day = week_start + timedelta(days=2)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Back To Back Worker")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
        )
        _create_shift(
            employee_id,
            _local_dt(service_day, 12),
            _local_dt(service_day, 16),
        )

        weekly = _weekly_hours(client, auth, week_start)
        row = next(
            employee
            for employee in weekly["employees"]
            if employee["employeeId"] == employee_id
        )
        assert "overlapping_shift" not in row["issueCodes"]
        assert row["issueCodes"] == []
        assert row["totalMinutes"] == 480
        assert weekly["summary"]["hasBlockingIssues"] is False
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_shift_correction_that_removes_overlap_clears_issue(client):
    week_start = date(2026, 6, 7)
    service_day = week_start + timedelta(days=3)
    employee_id = None
    payroll_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        payroll_id = _create_employee("Overlap Correction Mayra", role="payroll")
        employee_id = _create_employee("Overlap Correction Worker")
        payroll_auth = _login(client, "Overlap Correction Mayra")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
        )
        overlapping_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 11),
            _local_dt(service_day, 15),
        )

        before = _weekly_hours(client, payroll_auth, week_start)
        before_row = next(
            employee
            for employee in before["employees"]
            if employee["employeeId"] == employee_id
        )
        assert "overlapping_shift" in before_row["issueCodes"]

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": overlapping_shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 12).isoformat(),
                "correctedClockOut": _local_dt(service_day, 16).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Second shift actually started at noon; no overlap.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        after = _weekly_hours(client, payroll_auth, week_start)
        after_row = next(
            employee
            for employee in after["employees"]
            if employee["employeeId"] == employee_id
        )
        # The effective (corrected) intervals no longer overlap, so the
        # issue clears without touching the raw rows.
        assert "overlapping_shift" not in after_row["issueCodes"]
        assert after["summary"]["hasBlockingIssues"] is False
        assert after_row["totalMinutes"] == 480
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees(
            [value for value in (employee_id, payroll_id) if value is not None]
        )


def test_payroll_timesheet_view_reports_overlapping_shift(client, auth):
    week_start = date(2026, 6, 7)
    service_day = week_start + timedelta(days=4)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Overlap Timesheet Worker")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 16),
        )
        _create_shift(
            employee_id,
            _local_dt(service_day, 10),
            _local_dt(service_day, 12),
        )

        timesheet = _payroll_timesheet(
            client, auth, week_start, employee_id=employee_id
        )
        employee = next(
            row
            for row in timesheet["employees"]
            if row["employeeId"] == employee_id
        )
        day_shifts = [
            shift
            for day in employee["days"]
            for shift in day.get("shifts", [])
        ]
        assert day_shifts, "expected serialized shifts for the service day"
        # Both producers must agree on the code.
        assert all(
            "overlapping_shift" in shift["issueCodes"] for shift in day_shifts
        )
        assert all(shift["status"] == "needs_review" for shift in day_shifts)
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_corrected_shift_still_overlapping_stays_needs_review(client):
    week_start = date(2026, 6, 7)
    service_day = week_start + timedelta(days=5)
    employee_id = None
    payroll_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        payroll_id = _create_employee("Still Overlapping Mayra", role="payroll")
        employee_id = _create_employee("Still Overlapping Worker")
        payroll_auth = _login(client, "Still Overlapping Mayra")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 16),
        )
        corrected_shift_id = _create_shift(
            employee_id,
            _local_dt(service_day, 10),
            _local_dt(service_day, 12),
        )

        corrected = client.post(
            "/api/admin/payroll/timesheet/shift-corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "shiftId": corrected_shift_id,
                "date": service_day.isoformat(),
                "correctedClockIn": _local_dt(service_day, 10, 30).isoformat(),
                "correctedClockOut": _local_dt(service_day, 12, 30).isoformat(),
                "correctedBreakMinutes": 0,
                "reason": "Shifted by half an hour; still overlaps the long shift.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        timesheet = _payroll_timesheet(
            client, payroll_auth, week_start, employee_id=employee_id
        )
        employee = next(
            row
            for row in timesheet["employees"]
            if row["employeeId"] == employee_id
        )
        corrected_rows = [
            shift
            for day in employee["days"]
            for shift in day.get("shifts", [])
            if shift["shiftId"] == corrected_shift_id
        ]
        assert corrected_rows, "expected the corrected shift to be serialized"
        # A correction that does not remove the overlap must not present the
        # row as settled: nonempty issue codes win over "corrected".
        assert all(
            "overlapping_shift" in shift["issueCodes"] for shift in corrected_rows
        )
        assert all(shift["status"] == "needs_review" for shift in corrected_rows)
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees(
            [value for value in (employee_id, payroll_id) if value is not None]
        )


def test_overlap_issue_attributed_to_collision_day(client, auth):
    week_start = date(2026, 6, 7)
    sunday = week_start
    monday = week_start + timedelta(days=1)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Collision Day Worker")
        overnight_shift_id = _create_shift(
            employee_id,
            _local_dt(sunday, 22),
            _local_dt(monday, 6),
        )
        _create_shift(
            employee_id,
            _local_dt(monday, 4),
            _local_dt(monday, 8),
        )

        weekly = _weekly_hours(client, auth, week_start)
        row = next(
            employee
            for employee in weekly["employees"]
            if employee["employeeId"] == employee_id
        )
        overlap_issues = [
            issue for issue in row["issues"] if issue["code"] == "overlapping_shift"
        ]
        assert overlap_issues
        # The collision starts Monday 04:00, so the issue belongs to Monday
        # even though the overnight shift clocks in on Sunday.
        assert all(
            issue["date"] == monday.isoformat() for issue in overlap_issues
        )
        day_by_date = {day["date"]: day for day in row["days"]}
        assert "overlapping_shift" in day_by_date[monday.isoformat()]["issueCodes"]
        assert "overlapping_shift" not in day_by_date[sunday.isoformat()]["issueCodes"]

        timesheet = _payroll_timesheet(
            client, auth, week_start, employee_id=employee_id
        )
        employee = next(
            r for r in timesheet["employees"] if r["employeeId"] == employee_id
        )
        overnight_segments = {
            day["date"]: shift
            for day in employee["days"]
            for shift in day.get("shifts", [])
            if shift["shiftId"] == overnight_shift_id
        }
        assert "overlapping_shift" not in overnight_segments[sunday.isoformat()]["issueCodes"]
        assert "overlapping_shift" in overnight_segments[monday.isoformat()]["issueCodes"]
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_overlap_spanning_midnight_marks_every_collision_day(client, auth):
    week_start = date(2026, 6, 7)
    sunday = week_start
    monday = week_start + timedelta(days=1)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Midnight Collision Worker")
        first_shift_id = _create_shift(
            employee_id,
            _local_dt(sunday, 22),
            _local_dt(monday, 6),
        )
        second_shift_id = _create_shift(
            employee_id,
            _local_dt(sunday, 23),
            _local_dt(monday, 5),
        )

        weekly = _weekly_hours(client, auth, week_start)
        row = next(
            employee
            for employee in weekly["employees"]
            if employee["employeeId"] == employee_id
        )
        day_by_date = {day["date"]: day for day in row["days"]}
        # The collision runs Sun 23:00 -> Mon 05:00, so BOTH days carry the
        # code -- matching the timesheet segments on both days.
        assert "overlapping_shift" in day_by_date[sunday.isoformat()]["issueCodes"]
        assert "overlapping_shift" in day_by_date[monday.isoformat()]["issueCodes"]
        overlap_issue_dates = {
            issue["date"]
            for issue in row["issues"]
            if issue["code"] == "overlapping_shift"
        }
        assert overlap_issue_dates == {sunday.isoformat(), monday.isoformat()}

        timesheet = _payroll_timesheet(
            client, auth, week_start, employee_id=employee_id
        )
        employee = next(
            r for r in timesheet["employees"] if r["employeeId"] == employee_id
        )
        for shift_id in (first_shift_id, second_shift_id):
            segments = {
                day["date"]: shift
                for day in employee["days"]
                for shift in day.get("shifts", [])
                if shift["shiftId"] == shift_id
            }
            assert "overlapping_shift" in segments[sunday.isoformat()]["issueCodes"]
            assert "overlapping_shift" in segments[monday.isoformat()]["issueCodes"]
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_source_fingerprint_unchanged_by_empty_blocking_issues():
    kwargs = dict(
        week_start=date(2026, 5, 3),
        week_end=date(2026, 5, 9),
        employees=[],
        shifts=[],
    )
    base = time_tracker_api._payroll_source_fingerprint(**kwargs)
    assert (
        time_tracker_api._payroll_source_fingerprint(**kwargs, blocking_issues=[])
        == base
    )
    assert (
        time_tracker_api._payroll_source_fingerprint(
            **kwargs,
            blocking_issues=[
                {"code": "overlapping_shift", "shiftId": 1, "date": "2026-05-04"}
            ],
        )
        != base
    )


def test_recorded_shift_source_fingerprint_keeps_the_pre_overlay_shape():
    week_start = date(2026, 5, 3)
    week_end = date(2026, 5, 9)
    clock_in = _local_dt(week_start + timedelta(days=1), 8)
    clock_out = _local_dt(week_start + timedelta(days=1), 10)
    employees = [{"id": 7, "name": "Fingerprint Alma", "active": True}]
    shifts = [
        {
            "id": 81,
            "employee_id": 7,
            "clock_in": clock_in,
            "clock_out": clock_out,
            "payroll_source_kind": "recorded",
            "manual_shift_id": None,
        }
    ]
    legacy_payload = {
        "timezone": time_tracker_api.TIMEZONE_NAME,
        "weekStart": week_start.isoformat(),
        "weekEnd": week_end.isoformat(),
        "employees": [{"id": 7, "name": "Fingerprint Alma", "active": True}],
        "shifts": [
            {
                "id": 81,
                "employee_id": 7,
                "clock_in": time_tracker_api.to_utc_iso(clock_in),
                "clock_out": time_tracker_api.to_utc_iso(clock_out),
            }
        ],
    }
    expected = hashlib.sha256(
        json.dumps(legacy_payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    assert (
        time_tracker_api._payroll_source_fingerprint(
            week_start=week_start,
            week_end=week_end,
            employees=employees,
            shifts=shifts,
        )
        == expected
    )


def _old_formula_fingerprint(week_start: date) -> str:
    """The fingerprint a pre-overlap-rule deployment would have stored,
    reconstructed from the same inputs the weekly computation uses."""
    week_end_date, week_start_utc, week_end_utc = (
        time_tracker_api._payroll_week_bounds(week_start)
    )
    shift_rows = time_tracker_api._payroll_overlapping_shift_rows(
        week_start_utc, week_end_utc, time_tracker_api.utc_now()
    )
    employee_rows = db.query_all(
        "SELECT id, name, active FROM employees ORDER BY LOWER(name), id"
    )
    fingerprint_rows = [row for row in employee_rows if bool(row["active"])]
    return time_tracker_api._payroll_source_fingerprint(
        week_start=week_start,
        week_end=week_end_date,
        employees=fingerprint_rows,
        shifts=shift_rows,
        corrections=[],
        shift_corrections=[],
    )


def test_clean_week_fingerprint_matches_pre_rule_formula(client, auth):
    week_start = date(2026, 4, 5)
    service_day = week_start + timedelta(days=1)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Fingerprint Compat Worker")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 12),
        )
        _create_shift(
            employee_id,
            _local_dt(service_day, 13),
            _local_dt(service_day, 17),
        )

        weekly = _weekly_hours(client, auth, week_start)
        assert weekly["summary"]["hasBlockingIssues"] is False
        # No blocking issues -> the digest key is absent -> stored proofs
        # from before the overlap rule keep matching byte for byte.
        assert weekly["sourceFingerprint"] == _old_formula_fingerprint(week_start)
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def test_stored_verification_reads_stale_when_new_rule_condemns_week(client, auth):
    week_start = date(2026, 5, 3)
    service_day = week_start + timedelta(days=1)
    employee_id = None
    _delete_payroll_verification_weeks([week_start])
    try:
        employee_id = _create_employee("Predeploy Proof Worker")
        _create_shift(
            employee_id,
            _local_dt(service_day, 8),
            _local_dt(service_day, 16),
        )
        _create_shift(
            employee_id,
            _local_dt(service_day, 10),
            _local_dt(service_day, 12),
        )

        # Simulate a proof stored by a deployment that predates the overlap
        # rule: same rows, fingerprint computed without the issue digest.
        pre_rule_fingerprint = _old_formula_fingerprint(week_start)
        db.execute(
            """
            INSERT INTO payroll_verification_batches
                (week_start, week_end, timezone, status, source_fingerprint,
                 snapshot, verified_by_name)
            VALUES (%s, %s, %s, 'verified', %s, '{}'::jsonb, 'Predeploy Mayra')
            """,
            (
                week_start,
                week_start + timedelta(days=6),
                time_tracker_api.TIMEZONE_NAME,
                pre_rule_fingerprint,
            ),
        )

        status_response = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert status_response.status_code == 200, status_response.text
        body = status_response.json()
        assert body["summary"]["hasBlockingIssues"] is True
        assert body["currentSourceFingerprint"] != pre_rule_fingerprint
        # The stored proof must not keep attesting a week the current rules
        # find blocking.
        assert body["verification"]["stale"] is True
    finally:
        _delete_payroll_verification_weeks([week_start])
        if employee_id is not None:
            _delete_employees([employee_id])


def _shift_ids(employee_id: int, service_day: date, site_id: int) -> set:
    """Ids of the employee's shifts at one site/day -- used to pick out a shift
    created after a known baseline (the insert trigger stamps by default, so a
    genuinely NULL-snapshot shift has to be identified and cleared explicitly)."""
    rows = db.query_all(
        "SELECT id FROM shifts "
        "WHERE employee_id = %s AND local_date = %s AND location_id = %s",
        (employee_id, service_day, site_id),
    )
    return {int(r["id"]) for r in rows}


def _stamp_shift_snapshots(employee_id: int, service_day: date, cents_by_site: dict) -> None:
    """Stamp each of the employee's shifts that day with its site's snapshot rate."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            for site_id, cents in cents_by_site.items():
                cur.execute(
                    """
                    UPDATE shifts
                    SET hourly_rate_cents = %s
                    WHERE employee_id = %s AND local_date = %s AND location_id = %s
                    """,
                    (cents, employee_id, service_day, site_id),
                )
        conn.commit()


def _allocate_correction_at_rate(
    client,
    *,
    week_start: date,
    service_day: date,
    snapshot_cents_by_site,
    live_rate_after,
    label: str,
    second_site: bool = False,
    allocate_to_second_site: bool = False,
):
    """Build a corrected shift-day, stamp snapshots, raise the rate, then allocate.

    Returns the allocation payload so the caller can assert how it was priced.
    """
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    # Names are unique per test: employees persist across tests in a run.
    payroll_name = f"Payroll Labor Profitability RS Payroll {label}"
    worker_name = f"Payroll Labor Profitability RS Worker {label}"
    _create_employee(payroll_name, role="payroll")
    employee_id = _create_employee(worker_name, hourly_rate=20.00)
    payroll_auth = _login(client, payroll_name)
    source_id = _create_payroll_profitability_source()
    _, site_id = _create_payroll_profitability_site()
    job_id = _create_payroll_profitability_job_and_shift(
        employee_id=employee_id,
        site_id=site_id,
        source_id=source_id,
        service_day=service_day,
    )
    target_site_id = site_id
    target_job_id = job_id
    sites = {site_id: snapshot_cents_by_site[0]}
    if second_site:
        _, other_site_id = _create_payroll_profitability_site(
            address=f"Payroll Labor Profitability RS Second {label}",
        )
        other_job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=other_site_id,
            source_id=source_id,
            service_day=service_day,
            local_start=_local_dt(service_day, 13),
            local_end=_local_dt(service_day, 15),
            source_seed="2",
        )
        sites[other_site_id] = snapshot_cents_by_site[1]
        if allocate_to_second_site:
            target_site_id = other_site_id
            target_job_id = other_job_id

    # Pass every site, including the None ones: the BEFORE INSERT trigger now
    # stamps a rated employee's shift on creation, so a "no snapshot" case (a
    # pre-migration row, or a shift clocked in while the employee was rate-less)
    # must be produced by explicitly clearing the snapshot back to NULL here.
    _stamp_shift_snapshots(employee_id, service_day, sites)

    # The raise lands AFTER the work was done. Nothing about the corrected hours
    # should be priced from it.
    db.execute(
        "UPDATE employees SET hourly_rate = %s WHERE id = %s",
        (live_rate_after, employee_id),
    )

    corrected = client.post(
        "/api/admin/payroll/weekly-hours/corrections",
        headers=payroll_auth,
        json={
            "weekStart": week_start.isoformat(),
            "employeeId": employee_id,
            "date": service_day.isoformat(),
            "correctedTotalMinutes": 180 if not second_site else 300,
            "reason": "Mayra corrected total hours.",
        },
    )
    assert corrected.status_code == 200, corrected.text
    correction_id = corrected.json()["correction"]["correctionId"]

    allocated = client.post(
        f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
        headers=payroll_auth,
        json={
            "locationId": target_site_id,
            "jobId": target_job_id,
            "reason": "Juan assigned Mayra's correction to this Site.",
        },
    )
    assert allocated.status_code == 200, allocated.text
    return allocated.json()["allocation"]


def test_correction_is_priced_from_the_shift_snapshot_not_the_live_rate(client):
    """A correction adjusts hours already worked, so a later raise must not reprice it.

    Shift worked at $20/h, employee raised to $25/h, then a +60 minute
    correction is allocated. The stored cost must be 60 min @ $20/h = $20.00.
    Pricing it at today's $25/h would restate history -- the defect #126 fixes.
    """
    allocation = _allocate_correction_at_rate(
        client,
        week_start=date(2026, 8, 16),
        service_day=date(2026, 8, 17),
        snapshot_cents_by_site=[2000],
        live_rate_after=25.00,
        label="Priced",
    )
    assert allocation["allocatedDeltaMinutes"] == 60
    assert allocation["allocatedLaborCost"] == 20.0
    assert allocation["laborCostComplete"] is True
    # Genuinely frozen: the shift is snapshotted, so the stored cost is
    # authoritative and cannot move. Distinct from a live-tracked allocation.
    assert allocation["laborCostIsLive"] is False
    # The audit half still tracks the live rate -- stored vs current is the pair.
    assert allocation["currentAllocatedLaborCost"] == 25.0


def test_correction_prices_from_the_snapshot_at_its_own_site(client):
    """Two sites that day at different worked rates: the allocation's site wins."""
    allocation = _allocate_correction_at_rate(
        client,
        week_start=date(2026, 8, 23),
        service_day=date(2026, 8, 24),
        snapshot_cents_by_site=[2000, 3000],
        live_rate_after=50.00,
        label="SitePrecedence",
        second_site=True,
        allocate_to_second_site=True,
    )
    # 60 minutes allocated at the SECOND site's $30/h snapshot, not the first
    # site's $20/h and not today's $50/h.
    assert allocation["allocatedDeltaMinutes"] == 60
    assert allocation["allocatedLaborCost"] == 30.0
    assert allocation["laborCostComplete"] is True


def test_correction_fails_closed_when_that_days_snapshots_disagree(client):
    """Two shifts at the SAME site that day carry different worked rates.

    The allocation names that site, so the site rule finds two candidate rates
    and the day-wide rule finds the same two. There is no basis for choosing,
    so the cost is left unknown rather than silently picking one -- a guess here
    would misprice money with no signal to the operator.
    """
    week_start = date(2026, 8, 30)
    service_day = date(2026, 8, 31)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    _create_employee("Payroll Labor Profitability RS Ambiguous Payroll", role="payroll")
    employee_id = _create_employee(
        "Payroll Labor Profitability RS Ambiguous Worker", hourly_rate=20.00
    )
    payroll_auth = _login(client, "Payroll Labor Profitability RS Ambiguous Payroll")
    source_id = _create_payroll_profitability_source()
    _, site_id = _create_payroll_profitability_site()
    job_id = _create_payroll_profitability_job_and_shift(
        employee_id=employee_id,
        site_id=site_id,
        source_id=source_id,
        service_day=service_day,
    )
    _create_payroll_profitability_job_and_shift(
        employee_id=employee_id,
        site_id=site_id,
        source_id=source_id,
        service_day=service_day,
        local_start=_local_dt(service_day, 13),
        local_end=_local_dt(service_day, 15),
        source_seed="2",
    )
    # Same site, same day, two different worked rates.
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE shifts SET hourly_rate_cents = CASE
                    WHEN EXTRACT(HOUR FROM clock_in AT TIME ZONE 'America/Chicago') < 12
                    THEN 2000 ELSE 3000 END
                WHERE employee_id = %s AND local_date = %s
                """,
                (employee_id, service_day),
            )
        conn.commit()

    corrected = client.post(
        "/api/admin/payroll/weekly-hours/corrections",
        headers=payroll_auth,
        json={
            "weekStart": week_start.isoformat(),
            "employeeId": employee_id,
            "date": service_day.isoformat(),
            "correctedTotalMinutes": 300,
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
    allocation = allocated.json()["allocation"]
    assert allocation["allocatedLaborCost"] is None
    assert allocation["laborCostComplete"] is False


def test_correction_falls_back_to_the_live_rate_without_snapshots(client):
    """No snapshot that day -> the correction is live-tracked, not frozen.

    Finding 2 (#126): a shift with no snapshot follows the live rate, so a
    correction on it must keep tracking the live rate too -- stored NULL, valued
    at the live recompute -- or a later raise would move the shift labor while
    the correction stayed frozen. The money value is the live $25 and complete.
    """
    allocation = _allocate_correction_at_rate(
        client,
        week_start=date(2026, 9, 6),
        service_day=date(2026, 9, 7),
        snapshot_cents_by_site=[None],
        live_rate_after=25.00,
        label="Fallback",
    )
    assert allocation["allocatedDeltaMinutes"] == 60
    assert allocation["allocatedLaborCost"] is None
    assert allocation["laborCostIsLive"] is True
    assert allocation["currentAllocatedLaborCost"] == 25.0
    assert allocation["laborCostComplete"] is True


def _allocate_with_mixed_snapshot_shift(client, *, week_start, service_day, live_rate_after, label):
    """One snapshotted shift + one NULL-snapshot shift at the same site/day.

    A NULL-snapshot shift follows the live rate, so once the rate moves it is a
    second effective rate for the day. Returns the allocation payload.
    """
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    payroll_name = f"Payroll Labor Profitability MIX Payroll {label}"
    worker_name = f"Payroll Labor Profitability MIX Worker {label}"
    _create_employee(payroll_name, role="payroll")
    employee_id = _create_employee(worker_name, hourly_rate=20.00)
    payroll_auth = _login(client, payroll_name)
    source_id = _create_payroll_profitability_source()
    _, site_id = _create_payroll_profitability_site()

    # Shift A stamped to $20. Shift B must keep a NULL snapshot (a rate-less-at-
    # clock-in / pre-migration row), but the BEFORE INSERT trigger now stamps
    # every insert for a rated employee -- so after creating B we identify it by
    # id-diff and explicitly clear its snapshot back to NULL.
    job_a = _create_payroll_profitability_job_and_shift(
        employee_id=employee_id, site_id=site_id, source_id=source_id,
        service_day=service_day, source_seed="1",
    )
    _stamp_shift_snapshots(employee_id, service_day, {site_id: 2000})
    before_b = _shift_ids(employee_id, service_day, site_id)
    _create_payroll_profitability_job_and_shift(
        employee_id=employee_id, site_id=site_id, source_id=source_id,
        service_day=service_day, local_start=_local_dt(service_day, 13),
        local_end=_local_dt(service_day, 15), source_seed="2",
    )
    b_id = (_shift_ids(employee_id, service_day, site_id) - before_b).pop()
    db.execute(
        "UPDATE shifts SET hourly_rate_cents = NULL WHERE id = %s", (b_id,)
    )

    db.execute(
        "UPDATE employees SET hourly_rate = %s WHERE id = %s",
        (live_rate_after, employee_id),
    )
    corrected = client.post(
        "/api/admin/payroll/weekly-hours/corrections",
        headers=payroll_auth,
        json={
            "weekStart": week_start.isoformat(),
            "employeeId": employee_id,
            "date": service_day.isoformat(),
            "correctedTotalMinutes": 300,
            "reason": "Mayra corrected total hours.",
        },
    )
    assert corrected.status_code == 200, corrected.text
    correction_id = corrected.json()["correction"]["correctionId"]
    allocated = client.post(
        f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
        headers=payroll_auth,
        json={"locationId": site_id, "jobId": job_a, "reason": "Assigned to this Site."},
    )
    assert allocated.status_code == 200, allocated.text
    return allocated.json()["allocation"]


def test_correction_fails_closed_when_a_null_snapshot_shift_diverges(client):
    """A frozen $20 shift + a NULL-snapshot shift now following a $25 live rate.

    The day's effective rates disagree ($20 vs $25), so the correction must fail
    closed rather than confidently price at the one frozen snapshot it can see.
    """
    allocation = _allocate_with_mixed_snapshot_shift(
        client, week_start=date(2026, 9, 6), service_day=date(2026, 9, 7),
        live_rate_after=25.00, label="Diverge",
    )
    assert allocation["allocatedLaborCost"] is None
    assert allocation["laborCostComplete"] is False


def test_correction_scope_ignores_an_unrelated_sites_snapshot(client):
    """A correction at Site B is classified by B's shifts alone, not the whole day.

    The employee works a snapshotted shift at Site A and a NULL-snapshot (live)
    shift at Site B on the same day. A correction allocated to Site B must be
    live-tracked from B's own shift -- Site A's snapshot is out of scope and must
    not drag B into fail-closed. (Before the fix the snapshot check spanned the
    whole day, so Site A wrongly forced B to unresolved.)
    """
    week_start = date(2026, 9, 20)
    service_day = date(2026, 9, 21)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    _create_employee("Payroll Labor Profitability SCOPE Payroll", role="payroll")
    # Live rate configured, so Site B's NULL-snapshot shift follows it ($18).
    employee_id = _create_employee(
        "Payroll Labor Profitability SCOPE Worker", hourly_rate=18.00
    )
    payroll_auth = _login(client, "Payroll Labor Profitability SCOPE Payroll")
    source_id = _create_payroll_profitability_source()
    _, site_a = _create_payroll_profitability_site(address="Payroll Labor Profitability SCOPE A")
    _, site_b = _create_payroll_profitability_site(address="Payroll Labor Profitability SCOPE B")

    # Shift at Site A, snapshotted to $20.
    _create_payroll_profitability_job_and_shift(
        employee_id=employee_id, site_id=site_a, source_id=source_id,
        service_day=service_day, local_start=_local_dt(service_day, 9),
        local_end=_local_dt(service_day, 11), source_seed="5ca",
    )
    _stamp_shift_snapshots(employee_id, service_day, {site_a: 2000})
    # Shift at Site B, snapshot cleared to NULL (a rate-less-at-clock-in row) so
    # it follows the live rate.
    before_b = _shift_ids(employee_id, service_day, site_b)
    job_b = _create_payroll_profitability_job_and_shift(
        employee_id=employee_id, site_id=site_b, source_id=source_id,
        service_day=service_day, local_start=_local_dt(service_day, 13),
        local_end=_local_dt(service_day, 15), source_seed="5cb",
    )
    b_id = (_shift_ids(employee_id, service_day, site_b) - before_b).pop()
    db.execute("UPDATE shifts SET hourly_rate_cents = NULL WHERE id = %s", (b_id,))

    corrected = client.post(
        "/api/admin/payroll/weekly-hours/corrections",
        headers=payroll_auth,
        json={
            "weekStart": week_start.isoformat(), "employeeId": employee_id,
            "date": service_day.isoformat(), "correctedTotalMinutes": 300,
            "reason": "Mayra corrected total hours.",
        },
    )
    assert corrected.status_code == 200, corrected.text
    correction_id = corrected.json()["correction"]["correctionId"]
    allocated = client.post(
        f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation",
        headers=payroll_auth,
        json={"locationId": site_b, "jobId": job_b, "reason": "Assigned to Site B."},
    )
    assert allocated.status_code == 200, allocated.text
    allocation = allocated.json()["allocation"]
    # Live-tracked from Site B's own shift, NOT fail-closed by Site A's snapshot.
    assert allocation["laborCostIsLive"] is True
    assert allocation["laborCostComplete"] is True
    assert allocation["allocatedLaborCost"] is None
    assert allocation["currentAllocatedLaborCost"] is not None


def test_correction_fails_closed_when_frozen_and_live_shifts_coexist(client):
    """A frozen $20 shift + a NULL-snapshot (live $20) shift: mixed, even agreeing.

    The rates coincide today, but the scope is still MIXED -- one frozen shift
    and one live shift. The correction's delta-minutes cannot be attributed to
    the frozen vs the live shift, and marking it live-tracked (as it wrongly was)
    would let a later rate edit restate the frozen shift's portion. So a mixed
    scope must FAIL CLOSED even when the rates agree: unknown, never a confident
    value that a raise could move.
    """
    allocation = _allocate_with_mixed_snapshot_shift(
        client, week_start=date(2026, 9, 13), service_day=date(2026, 9, 14),
        live_rate_after=20.00, label="Agree",
    )
    assert allocation["allocatedLaborCost"] is None
    assert allocation["laborCostComplete"] is False
    assert allocation["laborCostIsLive"] is False


def test_correction_candidate_splits_daily_labor_by_rate(client):
    """The correction-candidate daily labor must split by rate, not by hours.

    One worker, one job, two snapshotted shifts: 1h Monday at $20 and 1h Tuesday
    at $30 (job total $50). A Monday correction's candidate site/job labor must
    read $20 (Monday's actual rate), not the $25 an equal-hours split of the $50
    total would produce -- the sibling of the _daily_worker_rows fix.
    """
    week_start = date(2026, 7, 19)
    monday = date(2026, 7, 20)
    tuesday = date(2026, 7, 21)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    employee_id = None
    payroll_id = None
    try:
        payroll_id = _create_employee(
            "Payroll Labor Profitability Split Payroll", role="payroll"
        )
        employee_id = _create_employee(
            "Payroll Labor Profitability Split Worker", hourly_rate=30
        )
        payroll_auth = _login(client, "Payroll Labor Profitability Split Payroll")
        source_id = _create_payroll_profitability_source()
        _, site_id = _create_payroll_profitability_site()
        # Monday shift on a job, snapshotted at $20.
        job_id = _create_payroll_profitability_job_and_shift(
            employee_id=employee_id,
            site_id=site_id,
            source_id=source_id,
            service_day=monday,
            local_start=_local_dt(monday, 9),
            local_end=_local_dt(monday, 10),
            source_seed="dead",
        )
        # A second shift on the SAME job the next day, snapshotted at $30.
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label, job_id,
                        clock_in, clock_out, total_hours, local_date, timezone,
                        time_category, notes, hourly_rate_cents
                    )
                    VALUES (%s, %s, 'Payroll Labor Profitability Site', %s,
                            %s, %s, 1.00, %s, 'America/Chicago',
                            'productive', 'split tue', 3000)
                    """,
                    (
                        employee_id, site_id, job_id,
                        _local_dt(tuesday, 9).astimezone(timezone.utc),
                        _local_dt(tuesday, 10).astimezone(timezone.utc),
                        tuesday,
                    ),
                )
            conn.commit()
        _stamp_shift_snapshots(employee_id, monday, {site_id: 2000})

        # An unallocated Monday correction surfaces Monday's candidate labor.
        corrected = client.post(
            "/api/admin/payroll/weekly-hours/corrections",
            headers=payroll_auth,
            json={
                "weekStart": week_start.isoformat(),
                "employeeId": employee_id,
                "date": monday.isoformat(),
                "correctedTotalMinutes": 120,
                "reason": "Mayra corrected Monday.",
            },
        )
        assert corrected.status_code == 200, corrected.text

        response = client.get(
            f"/api/admin/payroll/labor-profitability?weekStart={week_start.isoformat()}",
            headers=payroll_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        correction = next(
            row for row in body["payrollHours"]["unallocatedCorrections"]
            if row["date"] == monday.isoformat()
        )
        site = next(
            s for s in correction["candidateSites"] if s["locationId"] == site_id
        )
        # Monday's actual labor is $20 (1h at the $20 snapshot), not the $25 an
        # equal-hours split of the $50 job total would report.
        assert site["actualLaborCost"] == 20.0
        job = next(j for j in site["jobs"] if j["jobId"] == job_id)
        assert job["actualLaborCost"] == 20.0
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_payroll_labor_profitability_rows()
        _delete_employees([v for v in (employee_id, payroll_id) if v])


def test_void_of_a_live_tracked_allocation_serializes_the_live_cost(client):
    """Voiding a live-tracked allocation must report its live value, not None.

    A live-tracked allocation (shift had no snapshot) stores NULL cost and is
    only serialized complete when the employee's current rate is injected. The
    void endpoint returns RETURNING * (no rate column), so without injecting the
    rate a voided live-tracked allocation would serialize as incomplete/None.
    """
    week_start = date(2026, 9, 6)
    service_day = date(2026, 9, 7)
    _delete_payroll_labor_profitability_rows()
    _delete_payroll_verification_weeks([week_start])
    label = "VoidLive"
    payroll_name = f"Payroll Labor Profitability RS Payroll {label}"
    worker_name = f"Payroll Labor Profitability RS Worker {label}"
    _create_employee(payroll_name, role="payroll")
    employee_id = _create_employee(worker_name, hourly_rate=20.00)
    payroll_auth = _login(client, payroll_name)
    source_id = _create_payroll_profitability_source()
    _, site_id = _create_payroll_profitability_site()
    job_id = _create_payroll_profitability_job_and_shift(
        employee_id=employee_id,
        site_id=site_id,
        source_id=source_id,
        service_day=service_day,
    )
    # No snapshot on the shift -> the allocation resolves via the live rate.
    _stamp_shift_snapshots(employee_id, service_day, {site_id: None})

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
    alloc = allocated.json()["allocation"]
    # Precondition: it really is live-tracked (no snapshot -> live rate).
    assert alloc["laborCostIsLive"] is True
    assert alloc["allocatedLaborCost"] is None
    assert alloc["currentAllocatedLaborCost"] is not None
    live_cost = alloc["currentAllocatedLaborCost"]

    voided = client.post(
        f"/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation/void",
        headers=payroll_auth,
        json={"reason": "Reallocating this correction elsewhere."},
    )
    assert voided.status_code == 200, voided.text
    void_alloc = voided.json()["allocation"]
    # The void response must carry the live valuation, not serialize as None.
    assert void_alloc["laborCostIsLive"] is True
    assert void_alloc["currentAllocatedLaborCost"] == live_cost
    assert void_alloc["laborCostComplete"] is True


# --- #138 Slice 2: money (payroll dollars) verification ----------------------

def test_payroll_money_verification_full_flow_and_gates(client, auth):
    week_start = date(2026, 9, 6)  # Sunday
    employee_id = _create_employee("Payroll Money Verify Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 12),
        )
        weekly = _weekly_hours(client, auth, week_start)
        timesheet = _payroll_timesheet(client, auth, week_start)
        money_fp = timesheet["timesheetSourceFingerprint"]

        # Money-verify is blocked until HOURS are verified.
        blocked = client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "moneyFingerprint": money_fp},
        )
        assert blocked.status_code == 409, blocked.text
        assert blocked.json()["error"] == (
            "Verify the payroll week's hours before verifying payroll dollars"
        )

        # Verify hours first.
        hours_verified = client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        assert hours_verified.status_code == 200, hours_verified.text

        # Optimistic-concurrency gate on the MONEY fingerprint.
        stale_money = client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "moneyFingerprint": _different_fingerprint(money_fp),
            },
        )
        assert stale_money.status_code == 409, stale_money.text
        assert stale_money.json()["error"] == "Payroll dollars changed; refresh before verifying"

        # Money-verify success.
        money_verified = client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "moneyFingerprint": money_fp,
                "reason": "Mayra checked rates and allocations before payout.",
            },
        )
        assert money_verified.status_code == 200, money_verified.text
        body = money_verified.json()
        assert body["action"] == "verify"
        assert body["idempotent"] is False
        assert body["moneyVerification"]["status"] == "verified"
        assert body["moneyVerification"]["moneyFingerprint"] == money_fp
        assert body["moneyVerification"]["stale"] is False
        assert body["moneyVerification"]["batchId"] is not None

        # Idempotent re-verify with the same fingerprint.
        repeated = client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "moneyFingerprint": money_fp},
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["idempotent"] is True

        # GET returns BOTH hours and money states.
        status_response = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        )
        assert status_response.status_code == 200, status_response.text
        sb = status_response.json()
        assert sb["currentMoneyFingerprint"] == money_fp
        assert sb["verification"]["status"] == "verified"
        assert sb["verification"]["stale"] is False
        assert sb["moneyVerification"]["status"] == "verified"
        assert sb["moneyVerification"]["stale"] is False

        event_row = db.query_one(
            """
            SELECT COUNT(*) AS n
            FROM payroll_money_verification_events
            WHERE week_start = %s AND action = 'verify'
            """,
            (week_start,),
        )
        assert event_row is not None
        assert event_row["n"] == 1
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_money_verification_staleness_is_independent_of_hours(client, auth):
    week_start = date(2026, 9, 13)  # Sunday
    employee_id = _create_employee("Payroll Money Independent Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        shift_id = _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 12),
        )
        weekly = _weekly_hours(client, auth, week_start)
        timesheet = _payroll_timesheet(client, auth, week_start)
        client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "moneyFingerprint": timesheet["timesheetSourceFingerprint"],
            },
        )

        # A MONEY-ONLY change: time_category is hashed by the money fingerprint
        # but NOT the hours fingerprint (which hashes only clock times).
        db.execute(
            "UPDATE shifts SET time_category = 'non_productive' WHERE id = %s",
            (shift_id,),
        )

        after_money = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        ).json()
        assert after_money["verification"]["status"] == "verified"
        assert after_money["verification"]["stale"] is False, (
            "hours verification must stay fresh on a money-only change"
        )
        assert after_money["moneyVerification"]["status"] == "verified"
        assert after_money["moneyVerification"]["stale"] is True, (
            "money verification must go stale on a money-only change"
        )

        # An HOURS change (clock time) invalidates BOTH truths.
        db.execute(
            """
            UPDATE shifts
            SET clock_out = clock_out + interval '30 minutes',
                total_hours = total_hours + 0.5
            WHERE id = %s
            """,
            (shift_id,),
        )
        both = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        ).json()
        assert both["verification"]["stale"] is True
        assert both["moneyVerification"]["stale"] is True
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_payroll_money_reopen_and_never_verified_guard(client, auth):
    week_start = date(2026, 9, 20)  # Sunday
    employee_id = _create_employee("Payroll Money Reopen Worker")
    _delete_payroll_verification_weeks([week_start])
    try:
        missing = client.post(
            "/api/admin/payroll/money/reopen",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "reason": "nothing to reopen yet"},
        )
        assert missing.status_code == 404, missing.text
        assert missing.json()["error"] == "Payroll dollars have not been verified"

        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 12),
        )
        weekly = _weekly_hours(client, auth, week_start)
        timesheet = _payroll_timesheet(client, auth, week_start)
        client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "sourceFingerprint": weekly["sourceFingerprint"],
            },
        )
        client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={
                "weekStart": week_start.isoformat(),
                "moneyFingerprint": timesheet["timesheetSourceFingerprint"],
            },
        )

        reopened = client.post(
            "/api/admin/payroll/money/reopen",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "reason": "Re-checking a rate before payout."},
        )
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["moneyVerification"]["status"] == "reopened"
        assert reopened.json()["idempotent"] is False

        repeated = client.post(
            "/api/admin/payroll/money/reopen",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "reason": "still re-checking that rate"},
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["idempotent"] is True
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_money_verification_stays_fresh_when_a_stamped_shift_rate_is_edited(client, auth):
    # A stamped shift's labor is frozen at its snapshot, so a later live-rate
    # edit must NOT reprice it -- money verification must stay fresh (no false
    # positive from the effective-rate hashing).
    week_start = date(2026, 9, 27)  # Sunday
    employee_id = _create_employee("Payroll Stamped Rate Worker", hourly_rate=20.00)
    _delete_payroll_verification_weeks([week_start])
    try:
        _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 12),
        )  # trigger-stamped at $20
        weekly = _weekly_hours(client, auth, week_start)
        timesheet = _payroll_timesheet(client, auth, week_start)
        client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "sourceFingerprint": weekly["sourceFingerprint"]},
        )
        client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "moneyFingerprint": timesheet["timesheetSourceFingerprint"]},
        )

        db.execute("UPDATE employees SET hourly_rate = 25.00 WHERE id = %s", (employee_id,))

        after = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        ).json()
        assert after["verification"]["stale"] is False
        assert after["moneyVerification"]["stale"] is False, (
            "a live-rate edit must not stale money when every shift is stamped (frozen)"
        )
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])


def test_money_verification_goes_stale_when_an_unstamped_shift_is_repriced(client, auth):
    # An UNSTAMPED shift (NULL snapshot) is priced at the live rate, so a
    # live-rate edit reprices its payroll dollars -- money verification MUST go
    # stale while hours (which is rate-blind) stays fresh. Regression for the
    # effective-rate hashing (P1).
    week_start = date(2026, 10, 4)  # Sunday
    employee_id = _create_employee("Payroll Unstamped Rate Worker", hourly_rate=20.00)
    _delete_payroll_verification_weeks([week_start])
    try:
        shift_id = _create_shift(
            employee_id,
            _local_dt(week_start + timedelta(days=1), 8),
            _local_dt(week_start + timedelta(days=1), 12),
        )
        # Make it a rate-less / pre-migration row priced at the live rate.
        db.execute("UPDATE shifts SET hourly_rate_cents = NULL WHERE id = %s", (shift_id,))
        weekly = _weekly_hours(client, auth, week_start)
        timesheet = _payroll_timesheet(client, auth, week_start)
        client.post(
            "/api/admin/payroll/weekly-hours/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "sourceFingerprint": weekly["sourceFingerprint"]},
        )
        client.post(
            "/api/admin/payroll/money/verify",
            headers=auth,
            json={"weekStart": week_start.isoformat(), "moneyFingerprint": timesheet["timesheetSourceFingerprint"]},
        )

        db.execute("UPDATE employees SET hourly_rate = 25.00 WHERE id = %s", (employee_id,))

        after = client.get(
            f"/api/admin/payroll/weekly-hours/verification?weekStart={week_start.isoformat()}",
            headers=auth,
        ).json()
        assert after["verification"]["stale"] is False, "hours stays fresh on a rate-only change"
        assert after["moneyVerification"]["stale"] is True, (
            "money must go stale when an unstamped shift is repriced by a rate edit"
        )
    finally:
        _delete_payroll_verification_weeks([week_start])
        _delete_employees([employee_id])
