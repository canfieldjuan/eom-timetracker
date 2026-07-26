from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal

from revenue_definition_probe import (
    build_monthly_contract_revenue_divergence,
    completed_week_starts,
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
