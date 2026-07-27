from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
import json

import revenue_definition_probe as probe
from revenue_definition_probe import (
    build_monthly_contract_revenue_divergence,
    completed_week_starts,
    main,
)


def _row(
    job_id: int,
    *,
    scheduled_date: date,
    location_id: int = 10,
    rate: Decimal = Decimal("1000.00"),
    status: str = "scheduled",
) -> dict:
    return {
        "id": job_id,
        "location_id": location_id,
        "customer_id": 3,
        "customer_name": "Acme Offices",
        "site_address": "100 Main St",
        "rate": rate,
        "scheduled_date": scheduled_date,
        "scheduled_start": datetime(
            scheduled_date.year,
            scheduled_date.month,
            scheduled_date.day,
            14,
            tzinfo=timezone.utc,
        ),
        "status": status,
    }


def test_monthly_probe_compares_week_rows_against_full_month_allocation():
    rows = [
        _row(1, scheduled_date=date(2026, 2, 1)),
        _row(2, scheduled_date=date(2026, 2, 8)),
        _row(3, scheduled_date=date(2026, 2, 15)),
        _row(4, scheduled_date=date(2026, 2, 22)),
    ]

    result = build_monthly_contract_revenue_divergence(
        reference_date=date(2026, 2, 15),
        rows=rows,
    )

    assert completed_week_starts(date(2026, 2, 15), 2) == [
        date(2026, 2, 1),
        date(2026, 2, 8),
    ]
    assert result["loadedDateRange"] == {
        "start": "2026-02-01",
        "end": "2026-02-28",
    }
    assert [row["jobIds"] for row in result["rows"]] == [[1], [2]]
    assert [row["jobCountInMonth"] for row in result["rows"]] == [4, 4]
    assert [row["canonicalAllocatedRevenue"] for row in result["rows"]] == [
        250.0,
        250.0,
    ]
    assert [row["legacyForecastRevenue"] for row in result["rows"]] == [
        230.95,
        230.95,
    ]
    assert [row["legacyAnalyticsProratedRevenue"] for row in result["rows"]] == [
        250.0,
        250.0,
    ]
    assert result["summary"]["canonicalAllocatedRevenue"] == 500.0
    assert result["summary"]["forecastDelta"] == 38.1


def test_monthly_probe_shows_proration_delta_and_skips_cancelled_jobs():
    rows = [
        _row(1, scheduled_date=date(2026, 3, 1)),
        _row(2, scheduled_date=date(2026, 3, 8), status="cancelled"),
        _row(3, scheduled_date=date(2026, 3, 15)),
        _row(4, scheduled_date=date(2026, 3, 22)),
    ]

    result = build_monthly_contract_revenue_divergence(
        reference_date=date(2026, 3, 15),
        rows=rows,
    )

    assert [row["jobIds"] for row in result["rows"]] == [[1]]
    first_row = result["rows"][0]
    assert first_row["jobCountInMonth"] == 3
    assert first_row["canonicalAllocatedRevenue"] == 333.34
    assert first_row["legacyForecastRevenue"] == 230.95
    assert first_row["legacyAnalyticsProratedRevenue"] == 225.81
    assert first_row["forecastDelta"] == 102.39
    assert first_row["analyticsDelta"] == 107.53


def test_cli_requires_database_url(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(
        probe.db,
        "init_pool",
        lambda _database_url: (_ for _ in ()).throw(
            AssertionError("init_pool should not run without a database URL")
        ),
    )

    exit_code = main(["--reference-date", "2026-07-27"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "DATABASE_URL or --db-url is required" in captured.err


def test_cli_initializes_pool_from_database_url(monkeypatch, capsys):
    initialized = []

    def fake_build(*, reference_date, week_count):
        assert reference_date == date(2026, 7, 27)
        assert week_count == 3
        return {
            "success": True,
            "summary": {"rowCount": 0},
            "rows": [],
        }

    monkeypatch.setenv("DATABASE_URL", "postgresql://example.test/eom")
    monkeypatch.setattr(probe.db, "init_pool", initialized.append)
    monkeypatch.setattr(probe, "build_monthly_contract_revenue_divergence", fake_build)

    exit_code = main(["--reference-date", "2026-07-27", "--weeks", "3"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert initialized == ["postgresql://example.test/eom"]
    assert json.loads(captured.out) == {
        "rows": [],
        "success": True,
        "summary": {"rowCount": 0},
    }
    assert captured.err == ""
