"""Read-only probe for remaining unlinked analytics revenue fallback rows.

The #62 convergence arc already routes rows with durable job identity through
canonical Site rate-card allocation. This probe measures the remaining legacy
fallback branch: productive analytics rows that still have no jobId but do have
Site rate metadata.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
import sys
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_UP
from types import ModuleType
from typing import Any, Callable, Mapping, Optional, Sequence

import db
from revenue_definition_probe import completed_week_starts


LinkedRevenueLookup = Callable[
    [set[int]],
    tuple[dict[int, Optional[int]], set[tuple[str, str]], dict[int, dict[str, Any]]],
]


def _api_module() -> ModuleType:
    import time_tracker_api

    return time_tracker_api


def _money(value: Decimal | float | int) -> float:
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(amount)


def _float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _sunday_for(day: date) -> date:
    return day - timedelta(days=(day.weekday() + 1) % 7)


def _period_bounds(reference_date: date, week_count: int) -> tuple[date, date, list[date]]:
    week_starts = completed_week_starts(reference_date, week_count)
    start_date = week_starts[0]
    end_date = week_starts[-1] + timedelta(days=6)
    return start_date, end_date, week_starts


def _historical_map(
    api: ModuleType,
    timesheet_data: Mapping[str, Any],
    key: str,
) -> Mapping[str, Any]:
    return api._historical_location_metadata(dict(timesheet_data), key)


def _resolve_location(
    api: ModuleType,
    timesheet_data: Mapping[str, Any],
    location_customers: Mapping[str, str],
    raw_location: Any,
) -> tuple[str, str]:
    location = str(raw_location or "")
    resolved = location
    customer = location_customers.get(location)
    if not customer and location.startswith("GPS "):
        try:
            lat_text, lng_text = location[4:].split(",", 1)
            matched = api.find_nearest_location(
                float(lat_text.strip()),
                float(lng_text.strip()),
                dict(timesheet_data),
                coordinate_map_key="_historical_location_coords",
            )
        except (ValueError, IndexError):
            matched = None
        if matched:
            resolved = matched
            customer = location_customers.get(matched) or matched
    if not customer:
        customer = (
            location
            if location and not location.startswith("GPS ") and location != "Unknown"
            else "Unmatched Location"
        )
    return resolved, customer


def _iter_analytics_segments(
    api: ModuleType,
    timesheet_data: Mapping[str, Any],
    *,
    start_date: date,
    end_date: date,
) -> list[dict[str, Any]]:
    location_customers = _historical_map(
        api,
        timesheet_data,
        "location_customers",
    )
    location_rates = _historical_map(api, timesheet_data, "location_rates")
    location_rate_types = _historical_map(
        api,
        timesheet_data,
        "location_rate_types",
    )
    segments: list[dict[str, Any]] = []

    for entry in timesheet_data.get("entries", []):
        if entry.get("clockOut") is None:
            continue
        if entry.get("timeCategory") == "non_productive":
            continue
        try:
            clock_in = api.parse_utc_iso(str(entry.get("clockIn", "")).strip())
        except ValueError:
            continue
        entry_date = api.to_local(clock_in).date()
        if not (start_date <= entry_date <= end_date):
            continue
        date_key = entry_date.isoformat()
        week_start = _sunday_for(entry_date).isoformat()
        visits = entry.get("visits") or []
        if visits:
            try:
                clock_out = api.parse_utc_iso(str(entry["clockOut"]))
            except (ValueError, KeyError):
                continue
            for index, visit in enumerate(visits):
                if not isinstance(visit, dict):
                    continue
                try:
                    arrival = api.parse_utc_iso(str(visit["arrivalTime"]))
                except (ValueError, KeyError):
                    continue
                next_time = clock_out
                if index + 1 < len(visits):
                    try:
                        next_time = api.parse_utc_iso(
                            str(visits[index + 1]["arrivalTime"])
                        )
                    except (ValueError, KeyError):
                        pass
                resolved_location, customer = _resolve_location(
                    api,
                    timesheet_data,
                    location_customers,
                    visit.get("location", ""),
                )
                segments.append(
                    {
                        "shiftId": entry.get("id"),
                        "source": "visit",
                        "visitIndex": index,
                        "date": date_key,
                        "weekStart": week_start,
                        "customerName": customer,
                        "siteAddress": resolved_location,
                        "rate": _float(location_rates.get(resolved_location)),
                        "rateType": str(
                            location_rate_types.get(resolved_location)
                            or "per_visit"
                        ),
                        "hours": max(
                            (next_time - arrival).total_seconds() / 3600.0,
                            0.0,
                        ),
                        "jobId": api._analytics_entry_job_id(visit.get("jobId")),
                    }
                )
        else:
            resolved_location, customer = _resolve_location(
                api,
                timesheet_data,
                location_customers,
                entry.get("location", ""),
            )
            segments.append(
                {
                    "shiftId": entry.get("id"),
                    "source": "shift",
                    "visitIndex": None,
                    "date": date_key,
                    "weekStart": week_start,
                    "customerName": customer,
                    "siteAddress": resolved_location,
                    "rate": _float(location_rates.get(resolved_location)),
                    "rateType": str(
                        location_rate_types.get(resolved_location) or "per_visit"
                    ),
                    "hours": _float(entry.get("totalHours")) or 0.0,
                    "jobId": api._analytics_entry_job_id(entry.get("jobId")),
                }
            )
    return segments


def build_unlinked_analytics_revenue_fallback_probe(
    *,
    reference_date: date,
    week_count: int = 2,
    timesheet_data: Optional[Mapping[str, Any]] = None,
    linked_revenue_lookup: Optional[LinkedRevenueLookup] = None,
) -> dict[str, Any]:
    if week_count < 1:
        raise ValueError("week_count must be at least 1")
    api = _api_module()
    source = timesheet_data if timesheet_data is not None else api.load_timesheets()
    start_date, end_date, week_starts = _period_bounds(reference_date, week_count)
    segments = _iter_analytics_segments(
        api,
        source,
        start_date=start_date,
        end_date=end_date,
    )
    linked_job_ids = {
        int(segment["jobId"])
        for segment in segments
        if segment.get("jobId") is not None
    }
    if linked_revenue_lookup is None:
        linked_revenue_lookup = api._analytics_linked_job_revenue_cents
    _, canonical_monthly_site_months, _ = linked_revenue_lookup(linked_job_ids)

    top_level_visited_customer_dates: set[tuple[str, str]] = set()
    top_level_months_credited: set[tuple[str, str]] = set()
    detail_visited_location_dates: set[tuple[str, str, str]] = set()
    detail_months_credited: set[tuple[str, str]] = set()
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    missing_rate_segments = 0
    linked_segments = 0

    for segment in segments:
        if segment.get("jobId") is not None:
            linked_segments += 1
            continue
        rate = segment.get("rate")
        if rate is None:
            missing_rate_segments += 1
            continue
        rate_type = str(segment.get("rateType") or "per_visit")
        key = (
            str(segment["weekStart"]),
            str(segment["customerName"]),
            str(segment["siteAddress"]),
            rate_type,
        )
        group = groups.setdefault(
            key,
            {
                "weekStart": key[0],
                "customerName": key[1],
                "siteAddress": key[2],
                "rateType": key[3],
                "segmentCount": 0,
                "visitSegmentCount": 0,
                "shiftIds": set(),
                "hours": Decimal("0"),
                "topLevelLegacyRevenue": Decimal("0"),
                "customerDetailLegacyRevenue": Decimal("0"),
                "suppressedByLinkedMonthlySiteMonth": 0,
            },
        )
        group["segmentCount"] += 1
        if segment.get("source") == "visit":
            group["visitSegmentCount"] += 1
        if segment.get("shiftId") is not None:
            group["shiftIds"].add(int(segment["shiftId"]))
        group["hours"] += Decimal(str(segment.get("hours") or 0.0))

        top_revenue, top_suppressed = _top_level_legacy_revenue(
            segment,
            rate=rate,
            rate_type=rate_type,
            period_days=(end_date - start_date).days + 1,
            canonical_monthly_site_months=canonical_monthly_site_months,
            credited_customer_months=top_level_months_credited,
            visited_customer_dates=top_level_visited_customer_dates,
        )
        detail_revenue, detail_suppressed = _customer_detail_legacy_revenue(
            segment,
            rate=rate,
            rate_type=rate_type,
            canonical_monthly_site_months=canonical_monthly_site_months,
            credited_customer_months=detail_months_credited,
            visited_location_dates=detail_visited_location_dates,
        )
        group["topLevelLegacyRevenue"] += Decimal(str(top_revenue))
        group["customerDetailLegacyRevenue"] += Decimal(str(detail_revenue))
        if top_suppressed or detail_suppressed:
            group["suppressedByLinkedMonthlySiteMonth"] += 1

    rows = [_serialize_group(group) for group in groups.values()]
    rows.sort(
        key=lambda row: (
            row["weekStart"],
            row["customerName"],
            row["siteAddress"],
            row["rateType"],
        )
    )
    return {
        "success": True,
        "scope": "unlinked_analytics_revenue_fallback",
        "weekStarts": [week.isoformat() for week in week_starts],
        "loadedDateRange": {
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
        },
        "summary": _summary(rows, missing_rate_segments, linked_segments),
        "rows": rows,
    }


def _top_level_legacy_revenue(
    segment: Mapping[str, Any],
    *,
    rate: float,
    rate_type: str,
    period_days: int,
    canonical_monthly_site_months: set[tuple[str, str]],
    credited_customer_months: set[tuple[str, str]],
    visited_customer_dates: set[tuple[str, str]],
) -> tuple[float, bool]:
    date_key = str(segment["date"])
    customer = str(segment["customerName"])
    location = str(segment["siteAddress"])
    if rate_type == "hourly":
        return rate * float(segment.get("hours") or 0.0), False
    if rate_type == "monthly":
        month = date_key[:7]
        if (location, month) in canonical_monthly_site_months:
            return 0.0, True
        customer_month = (customer, month)
        if customer_month in credited_customer_months:
            return 0.0, False
        credited_customer_months.add(customer_month)
        _, days_in_month = calendar.monthrange(int(month[:4]), int(month[5:7]))
        return rate * min(period_days / days_in_month, 1.0), False
    visit_key = (customer, date_key)
    if visit_key in visited_customer_dates:
        return 0.0, False
    visited_customer_dates.add(visit_key)
    return rate, False


def _customer_detail_legacy_revenue(
    segment: Mapping[str, Any],
    *,
    rate: float,
    rate_type: str,
    canonical_monthly_site_months: set[tuple[str, str]],
    credited_customer_months: set[tuple[str, str]],
    visited_location_dates: set[tuple[str, str, str]],
) -> tuple[float, bool]:
    date_key = str(segment["date"])
    customer = str(segment["customerName"])
    location = str(segment["siteAddress"])
    if rate_type == "hourly":
        return rate * float(segment.get("hours") or 0.0), False
    if rate_type == "monthly":
        month = date_key[:7]
        if (location, month) in canonical_monthly_site_months:
            return 0.0, True
        customer_month = (customer, month)
        if customer_month in credited_customer_months:
            return 0.0, False
        credited_customer_months.add(customer_month)
        return rate, False
    visit_key = (customer, location, date_key)
    if visit_key in visited_location_dates:
        return 0.0, False
    visited_location_dates.add(visit_key)
    return rate, False


def _serialize_group(group: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "weekStart": group["weekStart"],
        "customerName": group["customerName"],
        "siteAddress": group["siteAddress"],
        "rateType": group["rateType"],
        "segmentCount": group["segmentCount"],
        "visitSegmentCount": group["visitSegmentCount"],
        "shiftIds": sorted(group["shiftIds"]),
        "hours": _money(group["hours"]),
        "topLevelLegacyRevenue": _money(group["topLevelLegacyRevenue"]),
        "customerDetailLegacyRevenue": _money(
            group["customerDetailLegacyRevenue"]
        ),
        "suppressedByLinkedMonthlySiteMonth": group[
            "suppressedByLinkedMonthlySiteMonth"
        ],
    }


def _summary(
    rows: Sequence[Mapping[str, Any]],
    missing_rate_segments: int,
    linked_segments: int,
) -> dict[str, Any]:
    return {
        "rowCount": len(rows),
        "segmentCount": sum(int(row["segmentCount"]) for row in rows),
        "linkedSegmentCount": linked_segments,
        "missingRateSegmentCount": missing_rate_segments,
        "suppressedByLinkedMonthlySiteMonth": sum(
            int(row["suppressedByLinkedMonthlySiteMonth"]) for row in rows
        ),
        "hours": _money(sum(Decimal(str(row["hours"])) for row in rows)),
        "topLevelLegacyRevenue": _money(
            sum(Decimal(str(row["topLevelLegacyRevenue"])) for row in rows)
        ),
        "customerDetailLegacyRevenue": _money(
            sum(
                Decimal(str(row["customerDetailLegacyRevenue"]))
                for row in rows
            )
        ),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure unlinked/manual analytics revenue fallback rows before "
            "changing #62 money behavior."
        ),
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
    result = build_unlinked_analytics_revenue_fallback_probe(
        reference_date=args.reference_date,
        week_count=args.weeks,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
