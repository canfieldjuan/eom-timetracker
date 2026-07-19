"""Regression tests: the monthly report must read real shift data from
PostgreSQL (the store the API actually writes), not the retired JSON file or the
mock generator."""

from datetime import datetime, timedelta

import db
import monthly_report_main as mrm


def test_report_reads_real_shift_hours_from_db(client, employee_id):
    # `client` initializes the DB pool; `employee_id` is the seeded "Catalina Gomez".
    now = datetime.now(mrm.REPORT_TIMEZONE)
    clock_in = datetime(now.year, now.month, 15, 10, 0, tzinfo=mrm.REPORT_TIMEZONE)
    clock_out = clock_in + timedelta(hours=2)
    db.execute(
        """
        INSERT INTO shifts (employee_id, clock_in, clock_out, location_label, timezone)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (employee_id, clock_in, clock_out, "Report Test Site", mrm.REPORT_TIMEZONE_NAME),
    )

    data = mrm.load_employee_data_from_db(now.month, now.year)
    assert data is not None
    names = [e["name"] for e in data["employees"]]
    # Real data, not the fabricated mock set.
    assert "John Smith" not in names

    cat = next(e for e in data["employees"] if e["id"] == employee_id)
    # The 2.0h shift on the 15th is read back with correct hours.
    assert any(s["date"].endswith("-15") and s["hours"] == 2.0 for s in cat["shifts"])
    assert data["summary"]["totalHours"] >= 2.0


def test_report_excludes_shifts_outside_the_requested_month(client, employee_id):
    # A shift in a clearly different month must not bleed into another month's
    # report — proves the DB-side month bound (and the defensive per-row filter).
    past_in = datetime(2020, 3, 15, 9, 0, tzinfo=mrm.REPORT_TIMEZONE)
    past_out = past_in + timedelta(hours=3)
    db.execute(
        """
        INSERT INTO shifts (employee_id, clock_in, clock_out, location_label, timezone)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (employee_id, past_in, past_out, "Old Site", mrm.REPORT_TIMEZONE_NAME),
    )

    # Present when we ask for March 2020...
    march = mrm.load_employee_data_from_db(3, 2020)
    march_hours = sum(
        s["hours"] for e in march["employees"] if e["id"] == employee_id for s in e["shifts"]
    )
    assert march_hours >= 3.0

    # ...absent from the current month's report.
    now = datetime.now(mrm.REPORT_TIMEZONE)
    if (now.year, now.month) != (2020, 3):
        current = mrm.load_employee_data_from_db(now.month, now.year)
        dates = [s["date"] for e in current["employees"] for s in e["shifts"]]
        assert not any(d.startswith("2020-03") for d in dates)


def test_mock_path_is_opt_in(client):
    # The mock generator still exists (for explicit testing) but is no longer the
    # default source — the endpoint only uses it when --mock-data is passed.
    now = datetime.now(mrm.REPORT_TIMEZONE)
    mock = mrm.load_mock_monthly_data(now.month, now.year)
    assert "John Smith" in [e["name"] for e in mock["employees"]]
