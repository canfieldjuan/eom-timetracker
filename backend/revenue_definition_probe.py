"""Read-only monthly revenue-definition probe for #62 convergence work.

This compares scheduled monthly jobs against the exact allocation helper and
the two legacy weekly approximations before any live endpoint is rewired.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
import sys
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Callable, Mapping, Optional, Sequence
from zoneinfo import ZoneInfo

import db
from operations_schedule import allocate_monthly_cents


QueryAll = Callable[[str, tuple[Any, ...]], Sequence[Mapping[str, Any]]]


def _money_cents(value: Any) -> Optional[int]:
    if value is None:
        return None
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int((amount * 100).to_integral_value())


def _money(cents: Optional[int]) -> Optional[float]:
    return None if cents is None else float(Decimal(cents) / Decimal(100))


def _display_cents(value: float) -> int:
    rounded = Decimal(str(round(value, 2))).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )
    return int((rounded * 100).to_integral_value())


def _sunday_for(day: date) -> date:
    return day - timedelta(days=(day.weekday() + 1) % 7)


def completed_week_starts(reference_date: date, week_count: int = 2) -> list[date]:
    if week_count < 1:
        raise ValueError("week_count must be at least 1")
    current_week_start = _sunday_for(reference_date)
    return [
        current_week_start - timedelta(weeks=offset)
        for offset in range(week_count, 0, -1)
    ]


def _month_window(first_week: date, last_week_end: date) -> tuple[date, date]:
    start = first_week.replace(day=1)
    _, last_day = calendar.monthrange(last_week_end.year, last_week_end.month)
    return start, last_week_end.replace(day=last_day)


def _load_monthly_contract_jobs(
    start_date: date,
    end_date: date,
    query_all: QueryAll,
) -> list[dict[str, Any]]:
    rows = query_all(
        """
        SELECT
            j.id,
            j.location_id,
            COALESCE(c.id, l.customer_id) AS customer_id,
            COALESCE(c.name, NULLIF(l.customer_name, ''), j.customer_name)
                AS customer_name,
            l.address AS site_address,
            l.rate,
            j.scheduled_date,
            j.scheduled_start,
            j.status
        FROM jobs j
        JOIN locations l ON l.id = j.location_id
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE l.rate_type = 'monthly'
          AND j.scheduled_date BETWEEN %s AND %s
        ORDER BY j.scheduled_date, j.scheduled_start NULLS FIRST, j.id
        """,
        (start_date, end_date),
    )
    return [dict(row) for row in rows]


def _active_site_month(row: Mapping[str, Any]) -> Optional[tuple[int, int, int]]:
    if row.get("status") == "cancelled" or row.get("location_id") is None:
        return None
    scheduled_date = row["scheduled_date"]
    return int(row["location_id"]), scheduled_date.year, scheduled_date.month


def _ordered_job_ids(
    rows: Sequence[Mapping[str, Any]],
    app_timezone: ZoneInfo,
) -> list[int]:
    return [
        int(row["id"])
        for row in sorted(
            rows,
            key=lambda row: (
                row.get("scheduled_start")
                or datetime.combine(
                    row["scheduled_date"],
                    time.min,
                    tzinfo=app_timezone,
                ).astimezone(timezone.utc),
                int(row["id"]),
            ),
        )
    ]


def _monthly_allocations(
    rows: Sequence[Mapping[str, Any]],
    app_timezone: ZoneInfo,
) -> dict[int, int]:
    groups: dict[tuple[int, int, int], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        site_month = _active_site_month(row)
        if site_month is not None:
            groups[site_month].append(row)

    allocations: dict[int, int] = {}
    for jobs_in_month in groups.values():
        monthly_cents = _money_cents(jobs_in_month[0].get("rate"))
        if monthly_cents is not None:
            allocations.update(
                allocate_monthly_cents(
                    monthly_cents,
                    _ordered_job_ids(jobs_in_month, app_timezone),
                )
            )
    return allocations


def _forecast_monthly_week_cents(monthly_cents: int) -> int:
    return _display_cents(float(Decimal(monthly_cents) / Decimal(100)) / 4.33)


def _analytics_week_proration_cents(monthly_cents: int, year: int, month: int) -> int:
    days_in_month = calendar.monthrange(year, month)[1]
    return _display_cents(
        float(Decimal(monthly_cents) / Decimal(100)) * 7 / days_in_month
    )


def build_monthly_contract_revenue_divergence(
    *,
    reference_date: date,
    week_count: int = 2,
    timezone_name: str = "America/Chicago",
    rows: Optional[Sequence[Mapping[str, Any]]] = None,
    query_all: QueryAll = db.query_all,
) -> dict[str, Any]:
    week_starts = completed_week_starts(reference_date, week_count)
    first_week = week_starts[0]
    last_week_end = week_starts[-1] + timedelta(days=6)
    load_start, load_end = _month_window(first_week, last_week_end)
    source_rows = (
        [dict(row) for row in rows]
        if rows is not None
        else _load_monthly_contract_jobs(load_start, load_end, query_all)
    )
    app_timezone = ZoneInfo(timezone_name)
    allocations = _monthly_allocations(source_rows, app_timezone)

    week_groups: dict[tuple[date, int, int, int], list[Mapping[str, Any]]] = (
        defaultdict(list)
    )
    for row in source_rows:
        site_month = _active_site_month(row)
        if site_month is None:
            continue
        scheduled_date = row["scheduled_date"]
        week_start = next(
            (
                start
                for start in week_starts
                if start <= scheduled_date <= start + timedelta(days=6)
            ),
            None,
        )
        if week_start is not None:
            week_groups[(week_start, *site_month)].append(row)

    comparisons = []
    for (week_start, location_id, year, month), week_rows in sorted(
        week_groups.items()
    ):
        month_rows = [
            row
            for row in source_rows
            if _active_site_month(row) == (location_id, year, month)
        ]
        monthly_cents = _money_cents(week_rows[0].get("rate"))
        canonical_cents = (
            None
            if monthly_cents is None
            else sum(
                allocations.get(job_id, 0)
                for job_id in _ordered_job_ids(week_rows, app_timezone)
            )
        )
        forecast_cents = (
            None
            if monthly_cents is None
            else _forecast_monthly_week_cents(monthly_cents)
        )
        analytics_cents = (
            None
            if monthly_cents is None
            else _analytics_week_proration_cents(monthly_cents, year, month)
        )
        comparisons.append(
            {
                "weekStart": week_start.isoformat(),
                "weekEnd": (week_start + timedelta(days=6)).isoformat(),
                "month": f"{year:04d}-{month:02d}",
                "customerId": week_rows[0].get("customer_id"),
                "customerName": str(week_rows[0].get("customer_name") or ""),
                "locationId": location_id,
                "siteAddress": str(week_rows[0].get("site_address") or ""),
                "monthlyRate": _money(monthly_cents),
                "jobIds": _ordered_job_ids(week_rows, app_timezone),
                "jobCountInWeek": len(week_rows),
                "jobCountInMonth": len(month_rows),
                "canonicalAllocatedRevenue": _money(canonical_cents),
                "legacyForecastRevenue": _money(forecast_cents),
                "legacyAnalyticsProratedRevenue": _money(analytics_cents),
                "forecastDelta": _money(_delta(canonical_cents, forecast_cents)),
                "analyticsDelta": _money(_delta(canonical_cents, analytics_cents)),
            }
        )

    return {
        "success": True,
        "scope": "monthly_contract_revenue",
        "weekStarts": [week_start.isoformat() for week_start in week_starts],
        "loadedDateRange": {
            "start": load_start.isoformat(),
            "end": load_end.isoformat(),
        },
        "summary": _summary(comparisons),
        "rows": comparisons,
    }


def _delta(left: Optional[int], right: Optional[int]) -> Optional[int]:
    return None if left is None or right is None else left - right


def _sum_money(rows: Sequence[Mapping[str, Any]], key: str) -> Optional[int]:
    values = [row.get(key) for row in rows if row.get(key) is not None]
    return None if not values else sum(_money_cents(value) or 0 for value in values)


def _summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    canonical = _sum_money(rows, "canonicalAllocatedRevenue")
    forecast = _sum_money(rows, "legacyForecastRevenue")
    analytics = _sum_money(rows, "legacyAnalyticsProratedRevenue")
    return {
        "rowCount": len(rows),
        "canonicalAllocatedRevenue": _money(canonical),
        "legacyForecastRevenue": _money(forecast),
        "legacyAnalyticsProratedRevenue": _money(analytics),
        "forecastDelta": _money(_delta(canonical, forecast)),
        "analyticsDelta": _money(_delta(canonical, analytics)),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare monthly contract revenue definitions over completed weeks.",
    )
    parser.add_argument(
        "--reference-date",
        type=date.fromisoformat,
        default=date.today(),
        help="Reference date; previous complete Sunday-start weeks are measured.",
    )
    parser.add_argument("--weeks", type=int, default=2)
    parser.add_argument(
        "--db-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL URL (defaults to DATABASE_URL).",
    )
    args = parser.parse_args(argv)
    if not args.db_url:
        print("DATABASE_URL or --db-url is required", file=sys.stderr)
        return 2
    db.init_pool(args.db_url)
    result = build_monthly_contract_revenue_divergence(
        reference_date=args.reference_date,
        week_count=args.weeks,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
