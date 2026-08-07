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
from zoneinfo import ZoneInfo

import bcrypt
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
) -> int:
    clock_in = _local_dt(service_day, start_hour).astimezone(timezone.utc)
    clock_out = _local_dt(service_day, end_hour).astimezone(timezone.utc)
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
