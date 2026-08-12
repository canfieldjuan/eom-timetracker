"""Per-shift hourly-rate snapshot (issue #126).

`employees.hourly_rate` stays editable, but every shift carries the rate it was
actually worked at (`shifts.hourly_rate_cents`), so editing a rate only moves
FUTURE work instead of silently restating every past labor and margin figure.

These tests pin four things:

1. the snapshot is stamped once, at shift creation, and no later write moves it;
2. a rate edit does not restate a worked shift on ANY money surface;
3. the one-time backfill is a no-op-on-the-day, idempotent, and never invents a
   zero for an employee who has no rate;
4. the three pre-existing (and mutually inconsistent) missing-rate policies are
   unchanged when neither a snapshot nor a live rate exists.
"""
from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo

import bcrypt
import psycopg2.extras
import pytest

import db
import time_tracker_api as api


CHICAGO = ZoneInfo("America/Chicago")
PREFIX = "RATE_SNAPSHOT_TEST"
PASSWORD = "ratesnap1234"

# 2050 is untouched by every other suite, so period-scoped analytics rollups
# below see this module's rows and nothing else.
SERVICE_DAY = date(2050, 3, 15)          # Tuesday
NEXT_SERVICE_DAY = date(2050, 3, 16)     # Wednesday, same payroll week
WEEK_START = date(2050, 3, 13)           # Sunday

_HASH_CACHE: dict[str, str] = {}


# --- fixtures ----------------------------------------------------------------

def _hash(password: str = PASSWORD) -> str:
    if password not in _HASH_CACHE:
        _HASH_CACHE[password] = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(10)
        ).decode("utf-8")
    return _HASH_CACHE[password]


def _local_dt(day: date, hour: int, minute: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=CHICAGO)


def _employee(suffix: str, hourly_rate: float | None, role: str = "employee") -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO employees (name, password_hash, role, active, hourly_rate)
            VALUES (%s, %s, %s, true, %s)
            RETURNING id
            """,
            (f"{PREFIX} {suffix}", _hash(), role, hourly_rate),
        )
    )


def _calendar_source(suffix: str) -> int:
    connection_id = int(
        db.execute_returning(
            """
            INSERT INTO google_calendar_connections (
                google_account_email, granted_scopes, revoked_at
            )
            VALUES (%s, ARRAY['calendar.readonly'], NOW())
            RETURNING id
            """,
            (f"{PREFIX}_{suffix}@example.test",),
        )
    )
    return int(
        db.execute_returning(
            """
            INSERT INTO google_calendar_sources (
                connection_id, role, calendar_id, calendar_name, calendar_timezone
            )
            VALUES (%s, 'residential_morning', %s, %s, 'America/Chicago')
            RETURNING id
            """,
            (connection_id, f"{PREFIX}_{suffix}_cal", f"{PREFIX} {suffix} Calendar"),
        )
    )


def _customer_site(suffix: str) -> tuple[int, int, str, str]:
    customer_name = f"{PREFIX} Customer {suffix}"
    address = f"{PREFIX} Site {suffix}"
    customer_id = int(
        db.execute_returning(
            "INSERT INTO customers (name) VALUES (%s) RETURNING id",
            (customer_name,),
        )
    )
    site_id = int(
        db.execute_returning(
            """
            INSERT INTO locations (
                customer_id, address, customer_name, location_type,
                rate, rate_type, expected_hours, target_labor_pct
            )
            VALUES (%s, %s, %s, 'Residential', 150.00, 'per_visit', 3.00, 40.00)
            RETURNING id
            """,
            (customer_id, address, customer_name),
        )
    )
    return customer_id, site_id, customer_name, address


def _job(
    *,
    source_id: int,
    site_id: int,
    customer_name: str,
    service_day: date,
    seed: str,
    start_hour: int = 9,
    end_hour: int = 12,
) -> int:
    source_key = hashlib.sha256(f"{PREFIX}{seed}".encode("utf-8")).hexdigest()
    return int(
        db.execute_returning(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date,
                scheduled_start, scheduled_end, status, calendar_source_id,
                source_calendar_id, source_event_id, source_occurrence_id,
                source_key, source_fingerprint, source_title
            )
            VALUES (
                %s, %s, %s, %s, %s, 'scheduled', %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                site_id,
                customer_name,
                service_day,
                _local_dt(service_day, start_hour).astimezone(timezone.utc),
                _local_dt(service_day, end_hour).astimezone(timezone.utc),
                source_id,
                f"{PREFIX}_calendar",
                seed,
                seed,
                source_key,
                source_key,
                customer_name,
            ),
        )
    )


def _shift(
    *,
    employee_id: int,
    site_id: int | None,
    address: str,
    service_day: date,
    start_hour: int,
    end_hour: int,
    job_id: int | None = None,
    hourly_rate_cents: int | None = None,
    time_category: str = "productive",
    non_productive_type: str | None = None,
    extra_seconds: int = 0,
) -> int:
    clock_in = _local_dt(service_day, start_hour).astimezone(timezone.utc)
    # extra_seconds pushes the span off a whole hour so the labor cost lands on a
    # sub-cent fraction -- the only way to exercise the rounding boundary.
    clock_out = (
        _local_dt(service_day, end_hour) + timedelta(seconds=extra_seconds)
    ).astimezone(timezone.utc)
    return int(
        db.execute_returning(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label, job_id,
                clock_in, clock_out, total_hours, local_date, timezone,
                time_category, non_productive_type, hourly_rate_cents, notes
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, 'America/Chicago',
                %s, %s, %s, 'rate snapshot test'
            )
            RETURNING id
            """,
            (
                employee_id,
                site_id,
                address,
                job_id,
                clock_in,
                clock_out,
                round((clock_out - clock_in).total_seconds() / 3600, 2),
                service_day,
                time_category,
                non_productive_type,
                hourly_rate_cents,
            ),
        )
    )


def _snapshot_cents(shift_id: int) -> int | None:
    row = db.query_one(
        "SELECT hourly_rate_cents FROM shifts WHERE id = %s", (shift_id,)
    )
    assert row is not None, f"shift {shift_id} disappeared"
    return row["hourly_rate_cents"]


def _set_rate(employee_id: int, rate: float | None) -> None:
    db.execute(
        "UPDATE employees SET hourly_rate = %s WHERE id = %s", (rate, employee_id)
    )


def _login(client, suffix: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/login", json={"name": f"{PREFIX} {suffix}", "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _cleanup() -> None:
    owned = (f"{PREFIX}%", f"{PREFIX}%")
    for table in ("site_qr_action_receipts", "site_check_ins"):
        db.execute(
            f"""
            DELETE FROM {table}
            WHERE employee_id IN (SELECT id FROM employees WHERE name LIKE %s)
               OR location_id IN (SELECT id FROM locations WHERE address LIKE %s)
            """,
            owned,
        )
    for table in ("visits", "departures"):
        db.execute(
            f"""
            DELETE FROM {table}
            WHERE shift_id IN (
                SELECT id FROM shifts
                WHERE employee_id IN (SELECT id FROM employees WHERE name LIKE %s)
                   OR location_id IN (SELECT id FROM locations WHERE address LIKE %s)
            )
            """,
            owned,
        )
    # Correction/allocation rows reference PREFIX locations with ON DELETE
    # RESTRICT, so they must go before the location delete below.
    db.execute(
        """
        DELETE FROM payroll_hour_correction_allocations
        WHERE employee_id IN (SELECT id FROM employees WHERE name LIKE %s)
           OR location_id IN (SELECT id FROM locations WHERE address LIKE %s)
        """,
        owned,
    )
    db.execute(
        """
        DELETE FROM payroll_hour_corrections
        WHERE employee_id IN (SELECT id FROM employees WHERE name LIKE %s)
        """,
        (f"{PREFIX}%",),
    )
    db.execute(
        """
        DELETE FROM shifts
        WHERE employee_id IN (SELECT id FROM employees WHERE name LIKE %s)
           OR location_id IN (SELECT id FROM locations WHERE address LIKE %s)
        """,
        owned,
    )
    db.execute("DELETE FROM jobs WHERE customer_name LIKE %s", (f"{PREFIX}%",))
    db.execute("DELETE FROM locations WHERE address LIKE %s", (f"{PREFIX}%",))
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{PREFIX}%",))
    db.execute("DELETE FROM employees WHERE name LIKE %s", (f"{PREFIX}%",))
    db.execute(
        """
        DELETE FROM google_calendar_sources
        WHERE connection_id IN (
            SELECT id FROM google_calendar_connections
            WHERE google_account_email LIKE %s
        )
        """,
        (f"{PREFIX}%",),
    )
    db.execute(
        "DELETE FROM google_calendar_connections WHERE google_account_email LIKE %s",
        (f"{PREFIX}%",),
    )


@pytest.fixture(autouse=True)
def isolate_rate_snapshot_rows(setup_db):
    _cleanup()
    yield
    _cleanup()


# --- 1. the snapshot is stamped once and never moves --------------------------

def test_clock_in_stamps_the_current_rate_and_no_later_write_moves_it(
    client, auth
):
    """The whole point: the rate is fixed at clock-in, forever.

    Clock-out, an admin entry edit, a job relink, a Site relink and a
    categorization all write the same shift row. None of them may touch
    hourly_rate_cents -- a shift's rate is evidence of what was worked, not a
    field that tracks the employee record.
    """
    worker = _employee("Stamp Worker", 20.00)
    source_id = _calendar_source("stamp")
    _, site_id, customer_name, address = _customer_site("Stamp")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="stamp-job",
    )
    worker_auth = _login(client, "Stamp Worker")

    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=worker_auth,
        json={"location": address, "gpsOverrideReason": "gps_signal"},
    )
    assert clock_in.status_code == 200, clock_in.text
    shift_id = int(clock_in.json()["entry"]["id"])
    # Stamped from employees.hourly_rate at creation, in integer cents.
    assert _snapshot_cents(shift_id) == 2000

    # The rate is edited AFTER the shift was clocked in.
    _set_rate(worker, 50.00)
    assert _snapshot_cents(shift_id) == 2000

    clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=worker_auth,
        json={"notes": "done", "gpsOverrideReason": "gps_signal"},
    )
    assert clock_out.status_code == 200, clock_out.text
    assert _snapshot_cents(shift_id) == 2000

    adjusted = client.patch(
        f"/api/admin/entries/{shift_id}",
        headers=auth,
        json={
            "clockIn": _local_dt(SERVICE_DAY, 9).strftime("%Y-%m-%dT%H:%M"),
            "clockOut": _local_dt(SERVICE_DAY, 11).strftime("%Y-%m-%dT%H:%M"),
            "notes": "admin corrected the clock times",
        },
    )
    assert adjusted.status_code == 200, adjusted.text
    assert _snapshot_cents(shift_id) == 2000

    linked = client.post(
        f"/api/admin/jobs/{job_id}/shifts", headers=auth, json={"shiftIds": [shift_id]}
    )
    assert linked.status_code == 200, linked.text
    assert _snapshot_cents(shift_id) == 2000

    unlinked = client.delete(
        f"/api/admin/jobs/{job_id}/shifts/{shift_id}", headers=auth
    )
    assert unlinked.status_code == 200, unlinked.text
    assert _snapshot_cents(shift_id) == 2000

    relocated = client.patch(
        f"/api/admin/shifts/{shift_id}/location",
        headers=auth,
        json={"address": address},
    )
    assert relocated.status_code == 200, relocated.text
    assert _snapshot_cents(shift_id) == 2000

    categorized = client.patch(
        f"/api/admin/shifts/{shift_id}/categorize",
        headers=auth,
        json={
            "timeCategory": "non_productive",
            "nonProductiveType": "waiting",
            "notes": "waited for the customer to unlock the building",
        },
    )
    assert categorized.status_code == 200, categorized.text
    assert _snapshot_cents(shift_id) == 2000

    # A shift clocked in AFTER the edit carries the NEW rate. Editing a rate is
    # meant to change future work -- that half must still work.
    second = client.post(
        "/api/timesheet/clock-in",
        headers=worker_auth,
        json={"location": address, "gpsOverrideReason": "gps_signal"},
    )
    assert second.status_code == 200, second.text
    assert _snapshot_cents(int(second.json()["entry"]["id"])) == 5000


def test_clock_in_leaves_snapshot_null_when_the_employee_has_no_rate(client):
    """No rate configured means no snapshot -- never a fabricated zero."""
    worker = _employee("No Rate Clock Worker", None)
    _, _, _, address = _customer_site("NoRateClock")
    worker_auth = _login(client, "No Rate Clock Worker")

    response = client.post(
        "/api/timesheet/clock-in",
        headers=worker_auth,
        json={"location": address, "gpsOverrideReason": "gps_signal"},
    )
    assert response.status_code == 200, response.text
    assert _snapshot_cents(int(response.json()["entry"]["id"])) is None
    assert worker  # keeps the id referenced for readability of the fixture


# --- 2. a rate edit does not restate history on any money surface -------------

def _payroll_auth(client) -> dict[str, str]:
    _employee("Payroll Reader", None, role="payroll")
    return _login(client, "Payroll Reader")


def test_rate_edit_does_not_restate_labor_on_any_money_surface(
    client, auth, monkeypatch
):
    """One shift worked at $20/h stays $40 on every surface after the rate is $50.

    A second shift worked at $50/h on the next day costs $100, proving the edit
    still reaches new work. Both live in the same payroll week, so the weekly
    rollups also prove the two rates coexist.
    """
    worker = _employee("Freeze Worker", 20.00)
    # Mint the token before "now" moves: a token issued in 2050 would not
    # validate against the real clock.
    payroll_auth = _payroll_auth(client)
    # The customer drill-down looks back N weeks from "now", so it can only see
    # these rows if "now" sits just after them.
    monkeypatch.setattr(
        api, "utc_now", lambda: datetime(2050, 3, 17, 18, tzinfo=timezone.utc)
    )
    source_id = _calendar_source("freeze")
    _, site_id, customer_name, address = _customer_site("Freeze")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="freeze-job",
    )
    next_job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=NEXT_SERVICE_DAY,
        seed="freeze-job-next",
    )
    # Worked at $20/h for 2h -> $40, snapshotted.
    old_shift = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        job_id=job_id,
        hourly_rate_cents=2000,
    )

    _set_rate(worker, 50.00)

    # Worked at $50/h for 2h -> $100, snapshotted at the new rate.
    new_shift = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=NEXT_SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        job_id=next_job_id,
        hourly_rate_cents=5000,
    )
    assert _snapshot_cents(old_shift) == 2000
    assert _snapshot_cents(new_shift) == 5000

    # -- analytics summary / byCustomer / byDay --------------------------------
    day = client.get(
        "/api/admin/analytics",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert day.status_code == 200, day.text
    day_body = day.json()
    assert day_body["summary"]["laborCost"] == pytest.approx(40.0)
    frozen_customer = next(
        row for row in day_body["byCustomer"] if row["customer"] == customer_name
    )
    assert frozen_customer["hours"] == pytest.approx(2.0)
    assert frozen_customer["laborCost"] == pytest.approx(40.0)
    frozen_day = next(
        row for row in day_body["byDay"] if row["date"] == SERVICE_DAY.isoformat()
    )
    assert frozen_day["laborCost"] == pytest.approx(40.0)

    # The whole week: $40 frozen + $100 at the new rate.
    week = client.get(
        "/api/admin/analytics",
        headers=auth,
        params={"period": "week", "date": SERVICE_DAY.isoformat()},
    )
    assert week.status_code == 200, week.text
    week_body = week.json()
    assert week_body["summary"]["laborCost"] == pytest.approx(140.0)
    week_customer = next(
        row for row in week_body["byCustomer"] if row["customer"] == customer_name
    )
    assert week_customer["laborCost"] == pytest.approx(140.0)
    by_day = {row["date"]: row for row in week_body["byDay"]}
    assert by_day[SERVICE_DAY.isoformat()]["laborCost"] == pytest.approx(40.0)
    assert by_day[NEXT_SERVICE_DAY.isoformat()]["laborCost"] == pytest.approx(100.0)

    # -- CSV export ------------------------------------------------------------
    export = client.get(
        "/api/admin/analytics/export",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert export.status_code == 200, export.text
    assert (
        "Revenue,$150.00,Labor Cost,$40.00,Labor %,26.7%,Net Profit,$110.00"
        in export.text
    )
    assert (
        f"{customer_name},{address},1,2.00,$150.00,$40.00,26.7%,$110.00"
        in export.text
    )
    assert (
        f"{SERVICE_DAY.isoformat()},1,2.00,$150.00,$40.00,26.7%,$110.00"
        in export.text
    )
    # Restated at today's $50/h the same row would read $100.00 labor / $50.00
    # net. Neither may appear anywhere in the export.
    assert "$100.00" not in export.text
    assert "$50.00" not in export.text

    # -- customer drill-down ---------------------------------------------------
    detail = client.get(
        f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
        headers=auth,
        params={"weeks": 1},
    )
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    by_visit = {row["date"]: row for row in detail_body["byVisit"]}
    assert by_visit[SERVICE_DAY.isoformat()]["laborCost"] == pytest.approx(40.0)
    assert by_visit[NEXT_SERVICE_DAY.isoformat()]["laborCost"] == pytest.approx(100.0)
    assert detail_body["summary"]["laborCost"] == pytest.approx(140.0)
    week_row = next(
        row
        for row in detail_body["byWeek"]
        if row["weekStart"] == WEEK_START.isoformat()
    )
    assert week_row["laborCost"] == pytest.approx(140.0)

    # -- job detail ------------------------------------------------------------
    frozen_job = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
    assert frozen_job.status_code == 200, frozen_job.text
    frozen_job_body = frozen_job.json()["job"]
    assert frozen_job_body["totalLaborCost"] == pytest.approx(40.0)
    assert frozen_job_body["shifts"][0]["laborCost"] == pytest.approx(40.0)

    new_job = client.get(f"/api/admin/jobs/{next_job_id}", headers=auth)
    assert new_job.status_code == 200, new_job.text
    assert new_job.json()["job"]["totalLaborCost"] == pytest.approx(100.0)

    # -- operations schedule ---------------------------------------------------
    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": NEXT_SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    jobs_by_id = {job["id"]: job for job in schedule.json()["jobs"]}
    assert jobs_by_id[job_id]["actualLaborCost"] == pytest.approx(40.0)
    assert jobs_by_id[job_id]["knownActualLaborCost"] == pytest.approx(40.0)
    assert jobs_by_id[next_job_id]["actualLaborCost"] == pytest.approx(100.0)

    # -- payroll labor profitability ------------------------------------------
    profitability = client.get(
        "/api/admin/payroll/labor-profitability",
        headers=payroll_auth,
        params={"weekStart": WEEK_START.isoformat()},
    )
    assert profitability.status_code == 200, profitability.text
    profitability_body = profitability.json()
    assert profitability_body["summary"]["actualLaborCost"] == pytest.approx(140.0)
    assert profitability_body["summary"]["laborCostComplete"] is True
    days = {row["date"]: row for row in profitability_body["byDay"]}
    assert days[SERVICE_DAY.isoformat()]["actualLaborCost"] == pytest.approx(40.0)
    assert days[NEXT_SERVICE_DAY.isoformat()]["actualLaborCost"] == pytest.approx(100.0)


def test_rate_edit_does_not_restate_waste_cost(client, auth):
    """Waste analytics keeps its own rollups; they freeze too."""
    worker = _employee("Waste Worker", 20.00)
    _, site_id, customer_name, address = _customer_site("Waste")
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=2000,
        time_category="non_productive",
        non_productive_type="waiting",
    )

    _set_rate(worker, 50.00)

    waste = client.get(
        "/api/admin/analytics/waste",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert waste.status_code == 200, waste.text
    body = waste.json()
    assert body["summary"]["totalWasteHours"] == pytest.approx(2.0)
    assert body["summary"]["totalWasteCost"] == pytest.approx(40.0)
    assert body["summary"]["missingRateCount"] == 0
    customer_row = next(
        row for row in body["byCustomer"] if row["customer"] == customer_name
    )
    assert customer_row["cost"] == pytest.approx(40.0)
    employee_row = next(
        row for row in body["byEmployee"] if row["employee"] == f"{PREFIX} Waste Worker"
    )
    assert employee_row["cost"] == pytest.approx(40.0)
    cause_row = next(row for row in body["byCause"] if row["cause"] == "waiting")
    assert cause_row["cost"] == pytest.approx(40.0)


def test_shift_without_snapshot_still_follows_the_live_rate(client, auth):
    """The fallback half of the contract.

    A pre-migration row that was never backfilled (employee had no rate then)
    keeps reading the live rate, so nothing regresses for rows the snapshot
    cannot cover.
    """
    worker = _employee("Fallback Worker", None)
    _, site_id, customer_name, address = _customer_site("Fallback")
    shift_id = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=None,
    )
    _set_rate(worker, 30.00)
    assert _snapshot_cents(shift_id) is None

    response = client.get(
        "/api/admin/analytics",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert response.status_code == 200, response.text
    row = next(
        r for r in response.json()["byCustomer"] if r["customer"] == customer_name
    )
    assert row["laborCost"] == pytest.approx(60.0)


# --- 3. backfill --------------------------------------------------------------

def test_backfill_stamps_current_rate_is_idempotent_and_respects_null_rates():
    """D1 Option A: stamp every existing shift with the employee's CURRENT rate.

    Numerically a no-op on migration day; its job is to freeze history from then
    on. It must never overwrite a snapshot that already exists, and it must not
    invent a zero for an employee who has no rate.
    """
    rated = _employee("Backfill Rated", 30.00)
    unrated = _employee("Backfill Unrated", None)
    _, site_id, _, address = _customer_site("Backfill")

    needs_backfill = _shift(
        employee_id=rated,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=None,
    )
    already_snapshotted = _shift(
        employee_id=rated,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=13,
        end_hour=15,
        hourly_rate_cents=1234,
    )
    no_employee_rate = _shift(
        employee_id=unrated,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=None,
    )

    api._backfill_shift_hourly_rate_snapshots()

    assert _snapshot_cents(needs_backfill) == 3000
    # An existing snapshot is evidence; the backfill must not restate it.
    assert _snapshot_cents(already_snapshotted) == 1234
    # No rate to record -> stays NULL, so the surface keeps its missing-rate path.
    assert _snapshot_cents(no_employee_rate) is None

    # Idempotent: a second run changes nothing, including after a rate edit.
    _set_rate(rated, 99.00)
    api._backfill_shift_hourly_rate_snapshots()

    assert _snapshot_cents(needs_backfill) == 3000
    assert _snapshot_cents(already_snapshotted) == 1234
    assert _snapshot_cents(no_employee_rate) is None


def test_backfill_rounds_to_integer_cents():
    """Money is integer cents. A half-cent rate rounds, it does not truncate."""
    worker = _employee("Backfill Rounding", 16.75)
    _, site_id, _, address = _customer_site("Rounding")
    shift_id = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=None,
    )

    api._backfill_shift_hourly_rate_snapshots()

    assert _snapshot_cents(shift_id) == 1675
    assert isinstance(_snapshot_cents(shift_id), int)


# --- 4. the three missing-rate policies are unchanged -------------------------

def test_missing_rate_policies_are_unchanged_without_snapshot_or_live_rate(
    client, auth, monkeypatch
):
    """No snapshot AND no live rate must behave exactly as a missing rate today.

    The three policies below are mutually inconsistent, and deliberately so --
    this test pins each one to its own surface so the snapshot fallback cannot
    quietly flip any of them.
    """
    monkeypatch.setattr(
        api, "utc_now", lambda: datetime(2050, 3, 17, 18, tzinfo=timezone.utc)
    )
    worker = _employee("Missing Rate Worker", None)
    source_id = _calendar_source("missing")
    _, site_id, customer_name, address = _customer_site("Missing")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="missing-job",
    )
    productive = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        job_id=job_id,
        hourly_rate_cents=None,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=13,
        end_hour=15,
        hourly_rate_cents=None,
        time_category="non_productive",
        non_productive_type="waiting",
    )
    assert _snapshot_cents(productive) is None

    # (a) silent zero -- analytics, customer drill-down and job detail all read a
    #     missing rate as free labor.
    analytics = client.get(
        "/api/admin/analytics",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert analytics.status_code == 200, analytics.text
    analytics_row = next(
        row
        for row in analytics.json()["byCustomer"]
        if row["customer"] == customer_name
    )
    assert analytics_row["hours"] == pytest.approx(2.0)
    assert analytics_row["laborCost"] == 0.0

    detail = client.get(
        f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
        headers=auth,
        params={"weeks": 1},
    )
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    # The visit must actually be in range, or the zero below proves nothing.
    assert [row["date"] for row in detail_body["byVisit"]] == [
        SERVICE_DAY.isoformat()
    ]
    assert detail_body["byVisit"][0]["hours"] == pytest.approx(2.0)
    assert detail_body["byVisit"][0]["laborCost"] == 0.0
    assert detail_body["summary"]["laborCost"] == 0.0

    job_detail = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
    assert job_detail.status_code == 200, job_detail.text
    job_body = job_detail.json()["job"]
    assert job_body["totalHours"] == pytest.approx(2.0)
    assert job_body["totalLaborCost"] == 0.0
    assert job_body["shifts"][0]["laborCost"] == 0.0

    # (b) zero + counter -- waste reports the cost as zero but says so out loud.
    waste = client.get(
        "/api/admin/analytics/waste",
        headers=auth,
        params={"period": "day", "date": SERVICE_DAY.isoformat()},
    )
    assert waste.status_code == 200, waste.text
    waste_body = waste.json()
    assert waste_body["summary"]["totalWasteHours"] == pytest.approx(2.0)
    assert waste_body["summary"]["totalWasteCost"] == 0.0
    assert waste_body["summary"]["missingRateCount"] == 1

    # (c) fail-closed -- operations refuses to report a total it cannot compute,
    #     names the reason, and still reports the known partial.
    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    assert scheduled_job["actualHours"] == pytest.approx(2.0)
    assert scheduled_job["actualLaborCost"] is None
    assert scheduled_job["knownActualLaborCost"] == 0.0
    assert "missing_worker_rate" in {
        issue["code"] for issue in scheduled_job["issues"]
    }


def test_operations_fails_closed_when_only_one_of_two_shifts_has_a_rate(
    client, auth
):
    """Second side of the guard: a partially known worker total is still unknown.

    One shift carries a snapshot, the other has neither a snapshot nor a live
    rate. The worker's labor cost must fail closed rather than silently report
    only the half it can price.
    """
    worker = _employee("Partial Rate Worker", None)
    source_id = _calendar_source("partial")
    _, site_id, customer_name, address = _customer_site("Partial")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="partial-job",
        start_hour=9,
        end_hour=16,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        job_id=job_id,
        hourly_rate_cents=2000,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=13,
        end_hour=15,
        job_id=job_id,
        hourly_rate_cents=None,
    )

    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    assert scheduled_job["actualHours"] == pytest.approx(4.0)
    assert scheduled_job["actualLaborCost"] is None
    assert "missing_worker_rate" in {
        issue["code"] for issue in scheduled_job["issues"]
    }


def test_operations_prices_each_shift_at_its_own_snapshot_rate(client, auth):
    """Two shifts, same worker, same job, different snapshot rates.

    Worker labor used to be computed once from a single rate, which was harmless
    while every shift of an employee shared one live rate. With per-shift
    snapshots that collapse would misprice the later shift, so labor is now
    bucketed by rate: 2h @ $20 + 2h @ $50 = $140, not 4h at either rate.
    """
    worker = _employee("Mixed Rate Worker", 20.00)
    source_id = _calendar_source("mixed")
    _, site_id, customer_name, address = _customer_site("Mixed")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="mixed-job",
        start_hour=9,
        end_hour=16,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        job_id=job_id,
        hourly_rate_cents=2000,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=13,
        end_hour=15,
        job_id=job_id,
        hourly_rate_cents=5000,
    )

    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    assert scheduled_job["actualHours"] == pytest.approx(4.0)
    assert scheduled_job["actualLaborCost"] == pytest.approx(140.0)
    assert scheduled_job["issues"] == []
    assert len(scheduled_job["workers"]) == 1
    assert scheduled_job["workers"][0]["laborCost"] == pytest.approx(140.0)
    # The worker response still carries no rate field -- pay stays out of it.
    assert "hourlyRate" not in scheduled_job["workers"][0]


def test_qr_only_presence_stays_on_the_live_rate(client, auth):
    """D2, recorded deliberately.

    QR-only presence rows have no shift, so they have no snapshot and keep
    reading the live employee rate. They are out of scope because they are
    presence-only and contribute zero finalized hours, so that live rate is
    never multiplied into money. This test pins the "zero hours, no cost" part
    so the day it stops being true, it fails here.
    """
    worker = _employee("QR Worker", 20.00)
    source_id = _calendar_source("qr")
    _, site_id, customer_name, address = _customer_site("QR")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="qr-job",
    )
    db.execute(
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
            worker,
            site_id,
            job_id,
            _local_dt(SERVICE_DAY, 10).astimezone(timezone.utc),
            _local_dt(SERVICE_DAY, 10).astimezone(timezone.utc),
        ),
    )
    assert address  # the QR row is keyed by site id, not the label

    _set_rate(worker, 50.00)

    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    assert scheduled_job["actualHours"] == 0
    assert scheduled_job["actualLaborCost"] == 0.0


# --- the column itself --------------------------------------------------------

def test_shifts_hourly_rate_cents_is_a_nullable_integer_column():
    """Additive, backward-compatible, integer cents -- never a float for money."""
    row = db.query_one(
        """
        SELECT data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'shifts' AND column_name = 'hourly_rate_cents'
        """
    )
    assert row is not None, "shifts.hourly_rate_cents is missing"
    assert row["data_type"] == "integer"
    assert row["is_nullable"] == "YES"


def test_migration_is_idempotent_and_keeps_existing_snapshots():
    """The startup migration re-runs on every boot; it must stay a no-op."""
    worker = _employee("Migration Worker", 30.00)
    _, site_id, _, address = _customer_site("Migration")
    shift_id = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=2000,
    )

    api._ensure_schema_migrations()

    assert _snapshot_cents(shift_id) == 2000

    api._ensure_schema_migrations()

    assert _snapshot_cents(shift_id) == 2000


def test_mixed_rate_labor_rounds_once_not_per_bucket(client, auth):
    """Sub-cent remainders must not each round up independently.

    Two 1h1s segments at $20/h and $25/h cost 2000.5556c and 2500.6944c. Rounding
    each bucket first reports 2001 + 2501 = 4502c; the exact combined cost is
    4501.25c, which is 4501c. Rounding once at the end is the honest figure.
    """
    worker = _employee("Round Once Worker", 20.00)
    source_id = _calendar_source("roundonce")
    _, site_id, customer_name, address = _customer_site("RoundOnce")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="round-once-job",
        start_hour=8,
        end_hour=18,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=10,
        extra_seconds=1,
        job_id=job_id,
        hourly_rate_cents=2000,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=13,
        end_hour=14,
        extra_seconds=1,
        job_id=job_id,
        hourly_rate_cents=2500,
    )

    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    # 45.01, not the 45.02 that per-bucket rounding produced.
    assert scheduled_job["actualLaborCost"] == pytest.approx(45.01)
    assert scheduled_job["workers"][0]["laborCost"] == pytest.approx(45.01)


def test_single_rate_labor_is_unchanged_by_the_bucketing(client, auth):
    """The bucketed path must be arithmetically identical for one rate.

    This is what lets the backfill be a no-op: every historical shift carries one
    rate per worker, so bucketing cannot move a cent.
    """
    worker = _employee("Single Rate Worker", 20.00)
    source_id = _calendar_source("singlerate")
    _, site_id, customer_name, address = _customer_site("SingleRate")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="single-rate-job",
        start_hour=8,
        end_hour=18,
    )
    for start, end in ((9, 11), (13, 15)):
        _shift(
            employee_id=worker,
            site_id=site_id,
            address=address,
            service_day=SERVICE_DAY,
            start_hour=start,
            end_hour=end,
            job_id=job_id,
            hourly_rate_cents=2000,
        )

    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": SERVICE_DAY.isoformat(),
            "end_date": SERVICE_DAY.isoformat(),
            "planning_source": "calendar",
        },
    )
    assert schedule.status_code == 200, schedule.text
    scheduled_job = next(
        job for job in schedule.json()["jobs"] if job["id"] == job_id
    )
    assert scheduled_job["actualHours"] == pytest.approx(4.0)
    assert scheduled_job["actualLaborCost"] == pytest.approx(80.0)


def test_backfill_runs_after_the_first_run_json_import(client):
    """Imported legacy shifts must be stamped, not left exposed to rate edits.

    An imported shift is inserted without hourly_rate_cents. The BEFORE INSERT
    trigger now stamps it at insert time from the employee's current rate, so
    imported history is frozen regardless of which code path wrote it -- the
    trigger subsumes the earlier concern that imported rows kept a NULL snapshot.
    The startup path also re-runs the backfill after a legacy import as a
    defensive belt-and-suspenders (pinned by the AST check below).
    """
    worker = _employee("Import Backfill Worker", 21.50)
    _, site_id, _, address = _customer_site("ImportBackfill")
    # Stand in for the importer: a shift inserted with no explicit snapshot. The
    # insert trigger stamps it from the employee's rate ($21.50 -> 2150).
    imported = _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=11,
        hourly_rate_cents=None,
    )
    assert _snapshot_cents(imported) == 2150

    # The backfill re-run is a harmless no-op now (nothing left NULL), but must
    # stay wired for defense in depth.
    api._backfill_shift_hourly_rate_snapshots()
    assert _snapshot_cents(imported) == 2150

    # Calling the function directly proves it works, not that startup calls it.
    # Pin the wiring too: the backfill must run inside the imported-legacy-JSON
    # branch, or imported history silently keeps a NULL snapshot.
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(api.startup_event))
    imported_branch = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "imported_legacy_json"
    ]
    assert imported_branch, "startup_event no longer branches on imported_legacy_json"
    called = {
        node.func.id
        for node in ast.walk(imported_branch[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_backfill_shift_hourly_rate_snapshots" in called, (
        "startup_event must re-run the rate backfill after a legacy JSON import"
    )


# --- 4. correction rate resolver: shifts spanning local midnight --------------

def _insert_cross_midnight_shift(
    *, employee_id, site_id, address, start_day, start_hour, end_day, end_hour,
    hourly_rate_cents,
):
    """A shift whose worked interval crosses local midnight.

    local_date is the clock-in day, but weekly payroll attributes the minutes to
    both local days. Inserted directly so the two days differ.
    """
    clock_in = _local_dt(start_day, start_hour).astimezone(timezone.utc)
    clock_out = _local_dt(end_day, end_hour).astimezone(timezone.utc)
    return int(
        db.execute_returning(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label,
                clock_in, clock_out, total_hours, local_date, timezone,
                time_category, hourly_rate_cents, notes
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'America/Chicago',
                    'productive', %s, 'cross-midnight test')
            RETURNING id
            """,
            (
                employee_id, site_id, address, clock_in, clock_out,
                round((clock_out - clock_in).total_seconds() / 3600, 2),
                start_day, hourly_rate_cents,
            ),
        )
    )


def _resolve_correction_rate(employee_id, correction_date, location_id, live_rate):
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            return api._payroll_correction_rate_for_allocation(
                cur,
                employee_id=employee_id,
                correction_date=correction_date,
                location_id=location_id,
                live_hourly_rate=live_rate,
            )


def test_correction_resolver_matches_a_shift_that_spilled_over_midnight():
    """A shift crossing midnight is attributed to both days; a correction on the
    spillover day must price from its snapshot, not the post-raise live rate."""
    worker = _employee("Midnight", 20.00)
    _, site_id, _, address = _customer_site("Midnight")
    # Worked 23:00 Tue -> 01:00 Wed local, snapshotted at $20. local_date = Tue.
    _insert_cross_midnight_shift(
        employee_id=worker, site_id=site_id, address=address,
        start_day=SERVICE_DAY, start_hour=23,
        end_day=NEXT_SERVICE_DAY, end_hour=1,
        hourly_rate_cents=2000,
    )
    _set_rate(worker, 50.00)  # raise lands after the work

    # The spillover day (Wed) is NOT the shift's local_date, yet the resolver
    # must still see the $20 snapshot via interval overlap.
    rate, resolved, _ = _resolve_correction_rate(worker, NEXT_SERVICE_DAY, site_id, 50.00)
    assert resolved is True
    assert rate == Decimal("20")

    # The clock-in day (Tue) resolves the same snapshot.
    rate_in, resolved_in, _ = _resolve_correction_rate(worker, SERVICE_DAY, site_id, 50.00)
    assert resolved_in is True
    assert rate_in == Decimal("20")

    # A day the shift never touched still falls back to the live rate.
    untouched = SERVICE_DAY - timedelta(days=3)
    rate_none, resolved_none, _ = _resolve_correction_rate(worker, untouched, site_id, 50.00)
    assert resolved_none is True
    assert rate_none == 50.00


# --- 5. one-time backfill gating (no re-stamp on later boots) ------------------

def _clear_marker(key):
    db.execute("DELETE FROM settings WHERE key = %s", (key,))


def _marker_present(key):
    return db.query_one("SELECT 1 FROM settings WHERE key = %s", (key,)) is not None


def test_one_time_shift_backfill_stamps_preexisting_then_never_reruns():
    """First run stamps then-existing NULL snapshots and marks itself done; a
    later run must not touch anything, so a rate-less shift created afterwards
    keeps its NULL and its live-rate fallback."""
    _clear_marker(api._SHIFT_RATE_BACKFILL_MARKER)
    rated = _employee("OneTimeRated", 30.00)
    _, site_id, _, address = _customer_site("OneTime")
    pre_existing = _shift(
        employee_id=rated, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=None,
    )

    api._run_one_time_shift_rate_backfill()

    assert _snapshot_cents(pre_existing) == 3000
    assert _marker_present(api._SHIFT_RATE_BACKFILL_MARKER)

    # A rate-less shift created AFTER the migration, whose employee later gains a
    # rate, must NOT be re-stamped on a subsequent boot.
    later_unrated_emp = _employee("OneTimeLater", None)
    later_shift = _shift(
        employee_id=later_unrated_emp, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=13, end_hour=15, hourly_rate_cents=None,
    )
    _set_rate(later_unrated_emp, 40.00)

    api._run_one_time_shift_rate_backfill()  # simulated reboot

    assert _snapshot_cents(later_shift) is None
    # The genuine pre-existing stamp is untouched too.
    assert _snapshot_cents(pre_existing) == 3000


def test_one_time_shift_backfill_is_a_noop_once_marked():
    """With the marker already present (post-migration steady state), a shift
    created rate-less then given a rate stays NULL across the backfill."""
    # Ensure marked done.
    db.execute(
        "INSERT INTO settings (key, value) VALUES (%s, 'true'::jsonb) "
        "ON CONFLICT (key) DO NOTHING",
        (api._SHIFT_RATE_BACKFILL_MARKER,),
    )
    emp = _employee("MarkedNoop", None)
    _, site_id, _, address = _customer_site("MarkedNoop")
    shift_id = _shift(
        employee_id=emp, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=None,
    )
    _set_rate(emp, 25.00)

    api._run_one_time_shift_rate_backfill()

    assert _snapshot_cents(shift_id) is None


# --- 6. one-time migration of existing allocation costs -----------------------

def _seed_correction_with_allocation(
    *, employee_id, location_id, correction_date, week_start, delta_minutes,
    stored_cost_cents,
):
    """Insert an active correction + allocation with a chosen stored cost.

    Used to stand in for a row written BEFORE the allocation cost became
    authoritative -- its stored cost is whatever the live rate was then.
    """
    correction_id = int(
        db.execute_returning(
            """
            INSERT INTO payroll_hour_corrections (
                week_start, correction_date, employee_id,
                corrected_total_minutes, reason, status, created_by_name
            )
            VALUES (%s, %s, %s, %s, %s, 'active', 'Seed Payroll')
            RETURNING id
            """,
            (week_start, correction_date, employee_id, 180, "Seed correction."),
        )
    )
    allocation_id = int(
        db.execute_returning(
            """
            INSERT INTO payroll_hour_correction_allocations (
                correction_id, week_start, correction_date, employee_id,
                location_id, allocated_delta_minutes, allocated_labor_cost_cents,
                reason, status, created_by_name
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', 'Seed Payroll')
            RETURNING id
            """,
            (
                correction_id, week_start, correction_date, employee_id,
                location_id, delta_minutes, stored_cost_cents,
                "Seed allocation.",
            ),
        )
    )
    return allocation_id


def _allocation_cost(allocation_id):
    row = db.query_one(
        "SELECT allocated_labor_cost_cents FROM payroll_hour_correction_allocations WHERE id = %s",
        (allocation_id,),
    )
    return row["allocated_labor_cost_cents"]


def _allocation_is_live(allocation_id):
    row = db.query_one(
        "SELECT allocated_labor_cost_is_live FROM payroll_hour_correction_allocations WHERE id = %s",
        (allocation_id,),
    )
    return row["allocated_labor_cost_is_live"]


def _timesheet_fingerprint(week_start):
    """The money-inclusive fingerprint the payroll timesheet emits."""
    return api._compute_payroll_timesheet(week_start.isoformat())[
        "timesheetSourceFingerprint"
    ]


def test_allocation_reconcile_reprices_unstamped_rows_from_the_snapshot():
    """An unstamped allocation (NULL provenance -- a pre-migration row, or one an
    old instance wrote mid-deploy) is repriced to the shift's worked-rate
    snapshot and stamped, so adjusted profitability stops mixing rates. Runs
    re-runnably over IS NULL rows only, so a stamped row is never revisited."""
    worker = _employee("AllocMig", 20.00)
    _, site_id, _, address = _customer_site("AllocMig")
    # Worked at $20, snapshotted; the employee was later raised to $25.
    _shift(
        employee_id=worker, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=12, hourly_rate_cents=2000,
    )
    _set_rate(worker, 25.00)
    # Unstamped row (provenance NULL): +60 min stored at the $25 live rate,
    # inconsistent with the frozen $20 shift labor.
    allocation_id = _seed_correction_with_allocation(
        employee_id=worker, location_id=site_id,
        correction_date=SERVICE_DAY, week_start=SERVICE_DAY,
        delta_minutes=60, stored_cost_cents=2500,
    )
    assert _allocation_cost(allocation_id) == 2500
    assert _allocation_is_live(allocation_id) is None  # unreconciled

    api._reconcile_unstamped_allocation_costs()

    # Repriced to 60 min @ the $20 snapshot = $20.00, and stamped frozen.
    assert _allocation_cost(allocation_id) == 2000
    assert _allocation_is_live(allocation_id) is False

    # Idempotent: now that the row is stamped (not NULL), a second run leaves it
    # alone even if the stored value drifts -- it is no longer an IS NULL row.
    db.execute(
        "UPDATE payroll_hour_correction_allocations SET allocated_labor_cost_cents = 9999 WHERE id = %s",
        (allocation_id,),
    )
    api._reconcile_unstamped_allocation_costs()
    assert _allocation_cost(allocation_id) == 9999


def test_money_fingerprint_moves_on_allocation_provenance_flip_alone():
    """Contract 1 (#138): a live<->frozen provenance flip changes the money
    fingerprint even when the stored cents do not move. The allocation is seeded
    with cents that already equal the snapshot reprice, so the reconcile flips
    ``allocated_labor_cost_is_live`` (NULL -> False) WITHOUT touching the cents --
    isolating provenance as the only changed input. Without provenance in the
    fingerprint, the startup reconcile could silently re-value an already
    signed-off week without invalidating its (future) money verification."""
    worker = _employee("MoneyFpFlip", 20.00)
    _, site_id, _, address = _customer_site("MoneyFpFlip")
    # Worked at $20, snapshotted on the shift.
    _shift(
        employee_id=worker, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=12, hourly_rate_cents=2000,
    )
    # Stored cents ALREADY equal 60 min @ the $20 snapshot ($20.00), so the
    # reconcile changes only the provenance flag, never the cents.
    allocation_id = _seed_correction_with_allocation(
        employee_id=worker, location_id=site_id,
        correction_date=SERVICE_DAY, week_start=WEEK_START,
        delta_minutes=60, stored_cost_cents=2000,
    )
    assert _allocation_cost(allocation_id) == 2000
    assert _allocation_is_live(allocation_id) is None  # unreconciled

    fp_before = _timesheet_fingerprint(WEEK_START)

    api._reconcile_unstamped_allocation_costs()
    assert _allocation_cost(allocation_id) == 2000        # cents unchanged
    assert _allocation_is_live(allocation_id) is False    # provenance flipped

    fp_after = _timesheet_fingerprint(WEEK_START)
    assert fp_after != fp_before, (
        "a provenance flip must move the money fingerprint even with equal cents"
    )

    # Exactly once + idempotent: the row is now stamped (not IS NULL), so a second
    # reconcile is a no-op and the fingerprint is stable -- the transition
    # invalidates money verification once, not on every startup.
    api._reconcile_unstamped_allocation_costs()
    assert _allocation_is_live(allocation_id) is False
    assert _timesheet_fingerprint(WEEK_START) == fp_after


def test_allocation_reconcile_fails_closed_on_disagreeing_snapshots():
    """If that day's snapshots disagree and none is at the allocation's site, the
    resolver fails closed, so the reconciled cost becomes NULL rather than a guess."""
    worker = _employee("AllocMigAmbig", 20.00)
    _, site_a, _, addr_a = _customer_site("AllocMigAmbigA")
    _, site_b, _, addr_b = _customer_site("AllocMigAmbigB")
    _, site_c, _, addr_c = _customer_site("AllocMigAmbigC")
    # Two shifts that day at different rates, at sites A and B.
    _shift(employee_id=worker, site_id=site_a, address=addr_a,
           service_day=SERVICE_DAY, start_hour=8, end_hour=10, hourly_rate_cents=2000)
    _shift(employee_id=worker, site_id=site_b, address=addr_b,
           service_day=SERVICE_DAY, start_hour=12, end_hour=14, hourly_rate_cents=3000)
    # Allocation points at site C, which has no shift that day -> ambiguous.
    allocation_id = _seed_correction_with_allocation(
        employee_id=worker, location_id=site_c,
        correction_date=SERVICE_DAY, week_start=SERVICE_DAY,
        delta_minutes=60, stored_cost_cents=2500,
    )

    api._reconcile_unstamped_allocation_costs()

    assert _allocation_cost(allocation_id) is None
    assert _allocation_is_live(allocation_id) is False  # fail-closed, not live


# --- 7. resolver sees visit locations (multi-stop shifts), fails closed -------

def _add_visit(shift_id: int, location_id: int, address: str, arrival: datetime) -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO visits (shift_id, location_id, location_label,
                                arrival_time, sequence_version)
            VALUES (%s, %s, %s, %s, 2)
            RETURNING id
            """,
            (shift_id, location_id, address, arrival.astimezone(timezone.utc)),
        )
    )


def test_correction_resolver_sees_visited_sites_not_only_the_home_location():
    """A multi-stop shift homed at A that visits B genuinely worked at B. A
    second shift homed at B at a different rate makes B ambiguous, so a
    correction allocated to B must fail closed rather than confidently return
    the second shift's rate."""
    worker = _employee("MultiStop", 20.00)
    _, site_a, _, addr_a = _customer_site("MultiStopA")
    _, site_b, _, addr_b = _customer_site("MultiStopB")

    # Shift 1: home A, $20, visits B mid-shift.
    shift_a = _shift(
        employee_id=worker, site_id=site_a, address=addr_a,
        service_day=SERVICE_DAY, start_hour=8, end_hour=12, hourly_rate_cents=2000,
    )
    _add_visit(shift_a, site_b, addr_b, _local_dt(SERVICE_DAY, 10))

    # Shift 2 same day: home B, $25 (a different worked rate at B).
    _shift(
        employee_id=worker, site_id=site_b, address=addr_b,
        service_day=SERVICE_DAY, start_hour=13, end_hour=15, hourly_rate_cents=2500,
    )
    _set_rate(worker, 99.00)

    # B saw both $20 (via shift_a's visit) and $25 (shift_b's home): ambiguous.
    rate, resolved, _ = _resolve_correction_rate(worker, SERVICE_DAY, site_b, 99.00)
    assert resolved is False
    assert rate is None

    # Site A saw only $20 (shift_a's home) -> still resolves cleanly.
    rate_a, resolved_a, _ = _resolve_correction_rate(worker, SERVICE_DAY, site_a, 99.00)
    assert resolved_a is True
    assert rate_a == Decimal("20")


def test_correction_resolver_single_stop_home_site_unaffected():
    """A plain single-stop shift (home == worked site, no extra visits) prices
    from its snapshot exactly as before."""
    worker = _employee("SingleStop", 18.00)
    _, site_id, _, address = _customer_site("SingleStop")
    _shift(
        employee_id=worker, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=1800,
    )
    _set_rate(worker, 40.00)

    rate, resolved, _ = _resolve_correction_rate(worker, SERVICE_DAY, site_id, 40.00)
    assert resolved is True
    assert rate == Decimal("18")


# --- 8. migration markers stay out of the public settings surface -------------

def test_migration_markers_are_not_exposed_in_settings():
    """The one-time shift-backfill marker piggybacks on the settings table but
    must never leak into load_settings() / GET /api/admin/settings. (The
    allocation reconcile is no longer marker-gated, so it has no marker.)"""
    db.execute(
        "INSERT INTO settings (key, value) VALUES (%s, 'true'::jsonb) "
        "ON CONFLICT (key) DO NOTHING",
        (api._SHIFT_RATE_BACKFILL_MARKER,),
    )

    settings = api.load_settings()
    assert api._SHIFT_RATE_BACKFILL_MARKER not in settings
    assert not any(k.startswith("_") for k in settings)
    # A real setting is still present.
    assert "laborPctTarget" in settings


# --- 9. correction archive preserves the rate snapshot ------------------------

def test_correction_snapshot_serializes_the_rate_and_separates_rate_duplicates():
    """The archived correction snapshot must carry hourly_rate_cents, and two
    otherwise-identical shifts at different rates must NOT hash as consistent
    duplicates."""
    worker = _employee("ArchiveRate", 20.00)
    _, site_id, _, address = _customer_site("ArchiveRate")
    shift_20 = _shift(
        employee_id=worker, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=2000,
    )
    shift_25 = _shift(
        employee_id=worker, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=2500,
    )

    snapshots = api._correction_shift_snapshots([shift_20, shift_25])
    by_id = {int(s["id"]): s for s in snapshots}
    assert by_id[shift_20]["hourlyRateCents"] == 2000
    assert by_id[shift_25]["hourlyRateCents"] == 2500

    # Same clock times/location but different rate -> distinct signatures.
    sig_20 = api._correction_metadata_signature(by_id[shift_20])
    sig_25 = api._correction_metadata_signature(by_id[shift_25])
    assert sig_20 != sig_25


def test_daily_profitability_splits_labor_by_rate_not_by_hours(client, monkeypatch):
    """One job, one worker, two days at different snapshot rates.

    Before the fix the worker's correct $50 job total was re-split across the two
    days purely by hours (1h/1h), reporting $25/$25. The daily split must weight
    by each day's actual labor, so the days read $20 and $30 while the job total
    stays $50.
    """
    # Mint the token before "now" moves: a token issued in 2050 would not
    # validate against the real clock.
    payroll_auth = _payroll_auth(client)
    monkeypatch.setattr(
        api, "utc_now", lambda: datetime(2050, 3, 17, 18, tzinfo=timezone.utc)
    )
    worker = _employee("Split Worker", 99.00)  # live rate is irrelevant; shifts carry snapshots
    source_id = _calendar_source("split")
    _, site_id, customer_name, address = _customer_site("Split")
    job_id = _job(
        source_id=source_id,
        site_id=site_id,
        customer_name=customer_name,
        service_day=SERVICE_DAY,
        seed="split-job",
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=SERVICE_DAY,
        start_hour=9,
        end_hour=10,
        job_id=job_id,
        hourly_rate_cents=2000,
    )
    _shift(
        employee_id=worker,
        site_id=site_id,
        address=address,
        service_day=NEXT_SERVICE_DAY,
        start_hour=9,
        end_hour=10,
        job_id=job_id,
        hourly_rate_cents=3000,
    )

    resp = client.get(
        "/api/admin/payroll/labor-profitability",
        headers=payroll_auth,
        params={"weekStart": WEEK_START.isoformat()},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "byDay" in body, list(body.keys())
    days = {row["date"]: row for row in body["byDay"]}
    assert days[SERVICE_DAY.isoformat()]["actualLaborCost"] == pytest.approx(20.0)
    assert days[NEXT_SERVICE_DAY.isoformat()]["actualLaborCost"] == pytest.approx(30.0)
    assert body["summary"]["actualLaborCost"] == pytest.approx(50.0)
    assert body["summary"]["laborCostComplete"] is True


def test_one_time_backfills_are_declared_after_their_tables(client):
    """Deploy-breaker guard for the schema-migration order.

    _ensure_schema_migrations runs on every startup. The allocation backfill
    queries payroll_hour_correction_allocations and its resolver queries
    payroll_shift_corrections; if the backfill calls precede those CREATE TABLEs
    (as they originally did), an upgrade from a schema predating payroll
    corrections raises undefined_table and the service never starts. The test
    harness applies schema.sql fresh so the tables always exist, so this asserts
    the ordering structurally: both one-time backfills must be CALLED after the
    correction-table CREATEs within the migration function's source.
    """
    import inspect

    src = inspect.getsource(api._ensure_schema_migrations)
    create_alloc = src.index(
        "CREATE TABLE IF NOT EXISTS payroll_hour_correction_allocations"
    )
    create_shift_corr = src.index(
        "CREATE TABLE IF NOT EXISTS payroll_shift_corrections"
    )
    shift_backfill = src.index("_run_one_time_shift_rate_backfill()")
    alloc_reconcile = src.index("_reconcile_unstamped_allocation_costs()")
    # The allocation reconcile (and its resolver) depend on both correction
    # tables; the shift backfill only needs shifts.hourly_rate_cents, but both
    # are kept together at the end, after all DDL.
    assert shift_backfill > create_alloc
    assert shift_backfill > create_shift_corr
    assert alloc_reconcile > create_alloc
    assert alloc_reconcile > create_shift_corr


# --- 9. rolling-deploy safety: insert trigger + reconcilable provenance --------

def test_insert_trigger_stamps_shift_regardless_of_writer(client):
    """A shift inserted with no snapshot (as an old app instance would during a
    rolling deploy) is stamped at INSERT by the DB trigger for a rated employee,
    and left NULL for a rate-less one so it keeps following the live rate."""
    rated = _employee("TrigRated", 22.00)
    rateless = _employee("TrigRateless", None)
    _, site_id, _, address = _customer_site("Trig")

    rated_shift = _shift(
        employee_id=rated, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=None,
    )
    rateless_shift = _shift(
        employee_id=rateless, site_id=site_id, address=address,
        service_day=SERVICE_DAY, start_hour=9, end_hour=11, hourly_rate_cents=None,
    )

    # The trigger filled the rated employee's NULL insert from employees.hourly_rate.
    assert _snapshot_cents(rated_shift) == 2200
    # Nothing to copy for a rate-less employee -> stays NULL (follows live rate).
    assert _snapshot_cents(rateless_shift) is None


def test_pending_allocation_is_valued_live_not_frozen(client):
    """An allocation with NULL provenance (a pre-migration / deploy-window write)
    stores a stale live-rate cost, but must NOT be read as frozen: its frozen
    cost is dropped and it is valued at the live recompute until reconcile.

    The serializer call is pure; ``client`` only ensures the shared DB session
    fixture runs so the per-test cleanup can connect."""
    row = {
        "id": 1,
        "correction_id": 1,
        "week_start": SERVICE_DAY,
        "correction_date": SERVICE_DAY,
        "employee_id": 1,
        "location_id": 1,
        "job_id": None,
        "location_customer_id": None,
        "superseded_by": None,
        "voided_by_name": None,
        "created_by_name": "Seed",
        "allocated_delta_minutes": 60,
        "allocated_labor_cost_cents": 2500,      # stale live-rate cost from an old write
        "allocated_labor_cost_is_live": None,    # provenance unknown / unreconciled
        "employee_hourly_rate": 20,              # live rate now $20 -> current 60min = $20
        "reason": "Pending row.",
        "status": "active",
    }
    out = api._serialize_payroll_correction_allocation(row)
    # Not trusted as frozen: the stored $25 is dropped from the frozen view...
    assert out["allocatedLaborCost"] is None
    # ...and it is valued at the live recompute, known and complete.
    assert out["laborCostIsLive"] is True
    assert out["currentAllocatedLaborCost"] == 20.0
    assert out["laborCostComplete"] is True


def test_trigger_reinstall_has_no_uncommitted_drop_window(client):
    """The trigger DROP + CREATE must run in ONE transaction.

    db.execute commits each statement in its own transaction, so a separate
    DROP TRIGGER then CREATE TRIGGER would leave a window with no trigger, and
    an old app instance inserting a shift in that window would escape stamping.
    Assert structurally that both DDL statements execute on one get_conn block.
    """
    import inspect

    src = inspect.getsource(api._ensure_schema_migrations)
    drop = src.index("DROP TRIGGER IF EXISTS trg_stamp_shift_hourly_rate_cents")
    create = src.index("CREATE TRIGGER trg_stamp_shift_hourly_rate_cents")
    # The get_conn block that wraps them must open before the DROP and both
    # statements must be executed on that same cursor (no db.execute between).
    block_open = src.rindex("with db.get_conn() as conn:", 0, drop)
    between = src[block_open:create]
    assert "db.execute(" not in between, (
        "DROP and CREATE TRIGGER must share one transaction, not separate "
        "db.execute() calls"
    )
    assert between.count("cur.execute(") >= 1
    # And the CREATE is inside the same block (no new get_conn between them).
    assert "with db.get_conn() as conn:" not in src[drop:create]
