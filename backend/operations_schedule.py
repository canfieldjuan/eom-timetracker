"""Canonical Schedule, measured Utilization, and Forecast operations views.

Google Calendar synchronization owns source-linked job planning.  This module
never mutates jobs or raw time evidence. Its one write appends an
evidence-bound reviewed-departure overlay to the existing correction ledger.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from uuid import UUID
from zoneinfo import ZoneInfo

import db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
import psycopg2.extras
from pydantic import BaseModel, Field


MoneyCents = Optional[int]
SOURCE_ROLE_SITE_TYPES = {
    "residential_morning": "Residential",
    "commercial_evening_night": "Commercial",
}
UTILIZATION_CATEGORIES = (
    "on_site",
    "travel",
    "categorized",
    "unclassified",
)
OPERATIONS_FORECAST_ALLOWED_WEEKS = {4, 8, 12}
OPERATIONS_FORECAST_PLANNING_SOURCES = {"calendar", "native"}
UTILIZATION_REVIEW_KEY_VERSION = "utilization-review.v1"
UTILIZATION_EVIDENCE_VERSION = "utilization-classifier.v1"
UTILIZATION_MISSING_DEPARTURE_CORRECTION = "utilization_missing_departure.v1"
EXPECTED_HOURS_BASELINE_KEY_VERSION = "expected-hours-baseline.v1"
EXPECTED_HOURS_LEARNING_LOOKBACK_DAYS = 180
EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES = 3
EXPECTED_HOURS_MAX = Decimal("9999.99")
EXPECTED_HOURS_LEARNING_EXCLUSION_RULE_DEFINITIONS = (
    {"code": "requires_completed_job", "source": "candidate_pairs"},
    {"code": "requires_productive_v2_site_events", "source": "paired_visit_evidence"},
    {
        "code": "requires_positive_paired_arrive_depart_interval",
        "source": "paired_visit_evidence",
    },
    {
        "code": "requires_observed_evidence_at_or_before_request",
        "source": "paired_visit_evidence",
    },
    {"code": "requires_valid_paid_envelope", "source": "paired_visit_evidence"},
    {"code": "excludes_unpaired_or_invalid_site_events", "source": "invalid_jobs"},
    {"code": "excludes_unaccepted_qr_check_ins", "source": "invalid_jobs"},
    {"code": "excludes_legacy_site_events", "source": "legacy_shift_jobs"},
    {"code": "excludes_overlapping_worker_intervals", "source": "overlap_jobs"},
    {
        "code": "excludes_embedded_arrival_conflicts",
        "source": "contradictory_arrival_jobs",
    },
    {
        "code": "excludes_contradictory_departure_events",
        "source": "contradictory_departure_jobs",
    },
    {
        "code": "excludes_unassigned_worker_intervals",
        "source": "unassigned_worker_jobs",
    },
)
EXPECTED_HOURS_LEARNING_EXCLUSION_RULES = tuple(
    str(rule["code"]) for rule in EXPECTED_HOURS_LEARNING_EXCLUSION_RULE_DEFINITIONS
)


class UtilizationMissingDepartureCorrectionRequest(BaseModel):
    shiftId: int = Field(gt=0)
    visitId: int = Field(gt=0)
    evidenceFingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    effectiveDepartureAt: datetime
    reason: str = Field(min_length=10, max_length=500)
    idempotencyKey: UUID


class ExpectedHoursBaselineDecisionRequest(BaseModel):
    baselineFingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: str = Field(pattern="^(accept|reject)$")
    expectedUpdateToken: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    reason: str = Field(default="", max_length=500)


class ServiceScheduleRuleCreateRequest(BaseModel):
    locationId: int = Field(gt=0)
    shiftBucket: str = Field(pattern="^(morning|evening|night)$")
    cadence: str = Field(pattern="^(weekly|biweekly|monthly)$")
    weekdays: List[int] = Field(min_length=1, max_length=7)
    localStartTime: time
    localEndTime: time
    startsOn: date
    endsOn: Optional[date] = None
    notes: str = Field(default="", max_length=500)
    active: bool = True


class ServiceScheduleRuleUpdateRequest(BaseModel):
    shiftBucket: Optional[str] = Field(
        default=None,
        pattern="^(morning|evening|night)$",
    )
    cadence: Optional[str] = Field(default=None, pattern="^(weekly|biweekly|monthly)$")
    weekdays: Optional[List[int]] = Field(default=None, min_length=1, max_length=7)
    localStartTime: Optional[time] = None
    localEndTime: Optional[time] = None
    startsOn: Optional[date] = None
    endsOn: Optional[date] = None
    notes: Optional[str] = Field(default=None, max_length=500)
    active: Optional[bool] = None


class NativeSchedulePreviewRequest(BaseModel):
    startDate: date
    endDate: date


def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _money_cents(value: Any) -> MoneyCents:
    if value is None:
        return None
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int((amount * 100).to_integral_value())


def _money(cents: MoneyCents) -> Optional[float]:
    return None if cents is None else float(Decimal(cents) / Decimal(100))


def _hours(start: datetime, end: datetime) -> float:
    return max((end - start).total_seconds() / 3600.0, 0.0)


def _issue(code: str, message: str) -> Dict[str, str]:
    return {"code": code, "message": message}


def _median(values: List[float]) -> float:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def _empty_expected_hours_learning(
    *,
    observation_start: date,
    observation_end: date,
) -> Dict[str, Any]:
    return {
        "sampleSize": 0,
        "minimumSampleSize": EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES,
        "suggestedHours": None,
        "observationPeriod": {
            "startDate": str(observation_start),
            "endDate": str(observation_end),
            "lookbackDays": EXPECTED_HOURS_LEARNING_LOOKBACK_DAYS,
        },
        "exclusionRules": list(EXPECTED_HOURS_LEARNING_EXCLUSION_RULES),
    }


def _entity_update_token(entity: str, row: Dict[str, Any]) -> str:
    updated_at = row["updated_at"].astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    )
    canonical = f"{entity}:{int(row['id'])}:{updated_at}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_current_site_update_token(
    site: Dict[str, Any],
    expected_token: Optional[str],
) -> None:
    if expected_token is None:
        return
    if hmac.compare_digest(expected_token, _entity_update_token("site", site)):
        return
    raise HTTPException(
        status_code=409,
        detail={
            "code": "stale_site_update",
            "message": "Site changed after it was read; reload before retrying",
            "details": {"siteId": int(site["id"])},
        },
    )


def _cursor_rows_as_dicts(cursor: Any, rows: Iterable[Any]) -> List[Dict[str, Any]]:
    materialized_rows = rows if isinstance(rows, list) else list(rows)
    if not materialized_rows:
        return []
    if hasattr(materialized_rows[0], "keys"):
        return [dict(row) for row in materialized_rows]
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in materialized_rows]


def _query_all(
    sql: str,
    params: tuple = (),
    *,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    if cursor is None:
        return db.query_all(sql, params)
    cursor.execute(sql, params)
    return _cursor_rows_as_dicts(cursor, cursor.fetchall())


def _expected_hours_learning_site_ids(jobs: Iterable[Dict[str, Any]]) -> List[int]:
    return sorted(
        {
            int(job["location_id"])
            for job in jobs
            if job.get("location_id") is not None
            and job.get("site_expected_hours") is None
        }
    )


def _local_bounds(
    start_date: date,
    end_date: date,
    app_timezone: ZoneInfo,
) -> Tuple[datetime, datetime]:
    return (
        datetime.combine(start_date, time.min, tzinfo=app_timezone).astimezone(
            timezone.utc
        ),
        datetime.combine(
            end_date + timedelta(days=1),
            time.min,
            tzinfo=app_timezone,
        ).astimezone(timezone.utc),
    )


def _local_interval_day_slices(
    start_utc: datetime,
    end_utc: datetime,
    *,
    range_start: datetime,
    range_end: datetime,
    app_timezone: ZoneInfo,
) -> List[Tuple[date, float]]:
    slices: List[Tuple[date, float]] = []
    cursor = max(start_utc.astimezone(timezone.utc), range_start)
    clipped_end = min(end_utc.astimezone(timezone.utc), range_end)
    while cursor < clipped_end:
        local_cursor = cursor.astimezone(app_timezone)
        local_day = local_cursor.date()
        next_local_midnight = datetime.combine(
            local_day + timedelta(days=1),
            time.min,
            tzinfo=app_timezone,
        ).astimezone(timezone.utc)
        next_cursor = min(clipped_end, next_local_midnight)
        hours = _hours(cursor, next_cursor)
        if hours > 0:
            slices.append((local_day, hours))
        cursor = next_cursor
    return slices


def _local_interval_grid_day_slices(
    start_utc: datetime,
    end_utc: datetime,
    *,
    range_start: datetime,
    range_end: datetime,
    app_timezone: ZoneInfo,
) -> List[Tuple[date, float]]:
    """Split visible time by local day and fold retained boundary time into the grid."""

    normalized_start = start_utc.astimezone(timezone.utc)
    normalized_end = end_utc.astimezone(timezone.utc)
    if normalized_end <= normalized_start:
        return []

    first_grid_day = range_start.astimezone(app_timezone).date()
    last_grid_day = (range_end - timedelta(microseconds=1)).astimezone(
        app_timezone
    ).date()
    slices: List[Tuple[date, float]] = []

    if normalized_start < range_start:
        boundary_end = min(normalized_end, range_start)
        boundary_hours = _hours(normalized_start, boundary_end)
        if boundary_hours > 0:
            slices.append((first_grid_day, boundary_hours))

    overlap_start = max(normalized_start, range_start)
    overlap_end = min(normalized_end, range_end)
    if overlap_start < overlap_end:
        slices.extend(
            _local_interval_day_slices(
                overlap_start,
                overlap_end,
                range_start=range_start,
                range_end=range_end,
                app_timezone=app_timezone,
            )
        )

    if normalized_end > range_end:
        boundary_start = max(normalized_start, range_end)
        boundary_hours = _hours(boundary_start, normalized_end)
        if boundary_hours > 0:
            slices.append((last_grid_day, boundary_hours))

    return slices


def _sunday_for(day: date) -> date:
    return day - timedelta(days=(day.weekday() + 1) % 7)


def _month_end(day: date) -> date:
    next_month = (
        date(day.year + 1, 1, 1)
        if day.month == 12
        else date(day.year, day.month + 1, 1)
    )
    return next_month - timedelta(days=1)


def _normalize_weekdays(weekdays: Iterable[int]) -> List[int]:
    normalized = sorted({int(value) for value in weekdays})
    if not normalized or any(value < 0 or value > 6 for value in normalized):
        raise HTTPException(
            status_code=422,
            detail="weekdays must contain unique Python weekday numbers 0 through 6",
        )
    return normalized


def _validate_service_rule_times(start_time: time, end_time: time) -> None:
    if (
        start_time.second
        or start_time.microsecond
        or end_time.second
        or end_time.microsecond
    ):
        raise HTTPException(
            status_code=422,
            detail="Service schedule times must be minute-aligned",
        )
    if start_time == end_time:
        raise HTTPException(
            status_code=422,
            detail="localEndTime must differ from localStartTime",
        )


def _local_time_text(value: time) -> str:
    return value.replace(microsecond=0).isoformat(timespec="minutes")


def _serialize_service_schedule_rule(row: Dict[str, Any]) -> Dict[str, Any]:
    ends_on = row.get("ends_on")
    return {
        "id": int(row["id"]),
        "locationId": int(row["location_id"]),
        "customerId": (
            int(row["customer_id"]) if row.get("customer_id") is not None else None
        ),
        "customerName": str(row.get("display_customer") or ""),
        "siteAddress": str(row.get("site_address") or ""),
        "siteType": row.get("site_type"),
        "shiftBucket": str(row["shift_bucket"]),
        "cadence": str(row["cadence"]),
        "weekdays": [int(value) for value in row["weekdays"]],
        "localStartTime": _local_time_text(row["local_start_time"]),
        "localEndTime": _local_time_text(row["local_end_time"]),
        "startsOn": str(row["starts_on"]),
        "endsOn": str(ends_on) if ends_on is not None else None,
        "notes": str(row.get("notes") or ""),
        "active": bool(row["active"]),
        "createdAt": _utc_iso(row.get("created_at")),
        "updatedAt": _utc_iso(row.get("updated_at")),
    }


def _service_schedule_rule_columns() -> str:
    return """
        rule.id, rule.location_id, rule.shift_bucket, rule.cadence,
        rule.weekdays, rule.local_start_time, rule.local_end_time,
        rule.starts_on, rule.ends_on, rule.notes, rule.active,
        rule.created_at, rule.updated_at,
        location.customer_id, location.address AS site_address,
        location.location_type AS site_type, location.rate,
        location.rate_type, location.expected_hours AS site_expected_hours,
        location.active AS site_active,
        COALESCE(customer.name, location.customer_name, location.address)
            AS display_customer
    """


def _fetch_service_schedule_rule(
    cur: Any,
    rule_id: int,
    *,
    lock: bool = False,
) -> Optional[Dict[str, Any]]:
    cur.execute(
        f"""
        SELECT {_service_schedule_rule_columns()}
        FROM service_schedule_rules rule
        JOIN locations location ON location.id = rule.location_id
        LEFT JOIN customers customer ON customer.id = location.customer_id
        WHERE rule.id = %s
        {"FOR UPDATE OF rule" if lock else ""}
        """,
        (rule_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def _find_duplicate_service_schedule_rule(
    cur: Any,
    *,
    location_id: int,
    shift_bucket: str,
    cadence: str,
    weekdays: List[int],
    local_start_time: time,
    local_end_time: time,
    starts_on: date,
    ends_on: Optional[date],
    exclude_rule_id: Optional[int] = None,
) -> Optional[int]:
    exclude_clause = ""
    params: List[Any] = [
        location_id,
        shift_bucket,
        cadence,
        weekdays,
        local_start_time,
        local_end_time,
        starts_on,
        ends_on,
    ]
    if exclude_rule_id is not None:
        exclude_clause = "AND id <> %s"
        params.append(exclude_rule_id)
    cur.execute(
        f"""
        SELECT id
        FROM service_schedule_rules
        WHERE location_id = %s
          AND active = true
          AND shift_bucket = %s
          AND cadence = %s
          AND weekdays = %s::smallint[]
          AND local_start_time = %s
          AND local_end_time = %s
          AND starts_on = %s
          AND ends_on IS NOT DISTINCT FROM %s
          {exclude_clause}
        LIMIT 1
        """,
        tuple(params),
    )
    row = cur.fetchone()
    return int(row["id"]) if row else None


def _rule_active_on(rule: Dict[str, Any], service_day: date) -> bool:
    starts_on = rule["starts_on"]
    ends_on = rule.get("ends_on")
    if service_day < starts_on or (ends_on is not None and service_day > ends_on):
        return False
    if service_day.weekday() not in {int(value) for value in rule["weekdays"]}:
        return False
    cadence = str(rule["cadence"])
    if cadence == "weekly":
        return True
    if cadence == "biweekly":
        weeks = (_sunday_for(service_day) - _sunday_for(starts_on)).days // 7
        return weeks >= 0 and weeks % 2 == 0
    if cadence == "monthly":
        month_offset = (
            (service_day.year - starts_on.year) * 12
            + service_day.month
            - starts_on.month
        )
        return (
            month_offset >= 0
            and (service_day.day - 1) // 7 == (starts_on.day - 1) // 7
        )
    return False


def _preview_interval(
    service_day: date,
    start_time: time,
    end_time: time,
    app_timezone: ZoneInfo,
) -> Tuple[datetime, datetime, bool]:
    starts_at = datetime.combine(service_day, start_time, tzinfo=app_timezone)
    end_day = service_day + timedelta(days=1) if end_time <= start_time else service_day
    ends_at = datetime.combine(end_day, end_time, tzinfo=app_timezone)
    starts_utc = starts_at.astimezone(timezone.utc)
    ends_utc = ends_at.astimezone(timezone.utc)
    start_roundtrip = starts_utc.astimezone(app_timezone)
    end_roundtrip = ends_utc.astimezone(app_timezone)
    valid_wall_time = (
        start_roundtrip.replace(tzinfo=None) == starts_at.replace(tzinfo=None)
        and end_roundtrip.replace(tzinfo=None) == ends_at.replace(tzinfo=None)
        and ends_utc > starts_utc
    )
    return starts_utc, ends_utc, valid_wall_time


def _apply_native_monthly_allocations(rows: List[Dict[str, Any]]) -> None:
    groups: Dict[Tuple[int, int, int], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("_included_in_forecast") and row.get("rateType") == "monthly":
            groups[
                (
                    int(row["locationId"]),
                    date.fromisoformat(row["scheduledDate"]).year,
                    date.fromisoformat(row["scheduledDate"]).month,
                )
            ].append(row)
    for group_rows in groups.values():
        first = group_rows[0]
        rate_cents = first.get("_rate_cents")
        if rate_cents is None:
            continue
        allocations = allocate_monthly_cents(
            int(rate_cents),
            [int(row["jobId"]) for row in group_rows],
        )
        for row in group_rows:
            row["_revenue_cents"] = allocations.get(int(row["jobId"]))


def _native_preview_rows(
    rules: List[Dict[str, Any]],
    start_date: date,
    end_date: date,
    *,
    app_timezone: ZoneInfo,
    avg_hourly_rate: Optional[Decimal],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    service_day = start_date
    while service_day <= end_date:
        for rule in rules:
            if not _rule_active_on(rule, service_day):
                continue
            starts_at, ends_at, valid_service_window = _preview_interval(
                service_day,
                rule["local_start_time"],
                rule["local_end_time"],
                app_timezone,
            )
            issues: List[Dict[str, str]] = []
            if not valid_service_window:
                issues.append(
                    _issue(
                        "invalid_service_window",
                        "The configured service window does not exist in the local timezone.",
                    )
                )
            expected_hours = (
                float(rule["site_expected_hours"])
                if rule.get("site_expected_hours") is not None
                else None
            )
            rate_cents = _money_cents(rule.get("rate"))
            rate_type = rule.get("rate_type")
            revenue_cents: MoneyCents = None
            if valid_service_window and rate_cents is not None:
                if rate_type == "per_visit":
                    revenue_cents = rate_cents
                elif rate_type == "hourly" and expected_hours is not None:
                    revenue_cents = int(
                        (Decimal(rate_cents) * Decimal(str(expected_hours))).quantize(
                            Decimal("1"),
                            rounding=ROUND_HALF_UP,
                        )
                    )
            labor_cents: MoneyCents = None
            if (
                valid_service_window
                and expected_hours is not None
                and avg_hourly_rate is not None
            ):
                labor_cents = int(
                    (
                        avg_hourly_rate
                        * Decimal(str(expected_hours))
                        * Decimal(100)
                    ).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
                )
            if expected_hours is None:
                issues.append(
                    _issue(
                        "missing_expected_hours",
                        "Expected hours are not configured for this Site.",
                    )
                )
            if rate_cents is None:
                issues.append(
                    _issue("missing_rate", "A service price is not configured.")
                )
            if avg_hourly_rate is None:
                issues.append(
                    _issue(
                        "missing_average_employee_rate",
                        "No active employee has a configured hourly rate.",
                    )
                )
            row_number = len(rows) + 1
            net_cents = (
                revenue_cents - labor_cents
                if revenue_cents is not None and labor_cents is not None
                else None
            )
            rows.append(
                {
                    "jobId": row_number,
                    "projectionId": f"rule-{int(rule['id'])}:{service_day}",
                    "ruleId": int(rule["id"]),
                    "locationId": int(rule["location_id"]),
                    "customerId": (
                        int(rule["customer_id"])
                        if rule.get("customer_id") is not None
                        else None
                    ),
                    "customerName": str(rule.get("display_customer") or ""),
                    "siteAddress": str(rule.get("site_address") or ""),
                    "siteType": rule.get("site_type"),
                    "shiftBucket": str(rule["shift_bucket"]),
                    "cadence": str(rule["cadence"]),
                    "rateType": rate_type,
                    "scheduledDate": str(service_day),
                    "scheduledStart": _utc_iso(starts_at),
                    "scheduledEnd": _utc_iso(ends_at),
                    "includedInForecast": valid_service_window,
                    "plannedHours": expected_hours,
                    "estRevenue": _money(revenue_cents),
                    "estLaborCost": _money(labor_cents),
                    "estNetProfit": _money(net_cents),
                    "estMarginPct": (
                        round(net_cents / revenue_cents * 100, 1)
                        if net_cents is not None
                        and revenue_cents is not None
                        and revenue_cents > 0
                        else None
                    ),
                    "estLaborPct": (
                        round(labor_cents / revenue_cents * 100, 1)
                        if labor_cents is not None
                        and revenue_cents is not None
                        and revenue_cents > 0
                        else None
                    ),
                    "issues": issues,
                    "_included_in_forecast": valid_service_window,
                    "_rate_cents": rate_cents,
                    "_revenue_cents": revenue_cents,
                    "_labor_cents": labor_cents,
                }
            )
        service_day += timedelta(days=1)
    _apply_native_monthly_allocations(rows)
    for row in rows:
        if row.get("rateType") == "monthly":
            revenue_cents = row.get("_revenue_cents")
            labor_cents = row.get("_labor_cents")
            net_cents = (
                revenue_cents - labor_cents
                if revenue_cents is not None and labor_cents is not None
                else None
            )
            row["estRevenue"] = _money(revenue_cents)
            row["estNetProfit"] = _money(net_cents)
            row["estMarginPct"] = (
                round(net_cents / revenue_cents * 100, 1)
                if net_cents is not None and revenue_cents and revenue_cents > 0
                else None
            )
            row["estLaborPct"] = (
                round(labor_cents / revenue_cents * 100, 1)
                if labor_cents is not None and revenue_cents and revenue_cents > 0
                else None
            )
    return rows


def _load_active_service_schedule_rules(
    start_date: date,
    end_date: date,
) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in db.query_all(
            f"""
            SELECT {_service_schedule_rule_columns()}
            FROM service_schedule_rules rule
            JOIN locations location ON location.id = rule.location_id
            LEFT JOIN customers customer ON customer.id = location.customer_id
            WHERE rule.active = true
              AND location.active = true
              AND rule.starts_on <= %s
              AND (rule.ends_on IS NULL OR rule.ends_on >= %s)
            ORDER BY location.address, rule.local_start_time, rule.id
            """,
            (end_date, start_date),
        )
    ]


def _average_employee_rate_and_issues() -> Tuple[
    Optional[Decimal],
    List[Dict[str, str]],
]:
    wage_rows = db.query_all(
        """
        SELECT hourly_rate
        FROM employees
        WHERE active = true AND role = 'employee'
        """
    )
    wages = [
        Decimal(str(row["hourly_rate"]))
        for row in wage_rows
        if row.get("hourly_rate") is not None
    ]
    issues: List[Dict[str, str]] = []
    missing_wages = len(wage_rows) - len(wages)
    if not wages:
        issues.append(
            _issue(
                "missing_average_employee_rate",
                "No active employee has a configured hourly rate.",
            )
        )
    elif missing_wages:
        issues.append(
            _issue(
                "employees_missing_rates",
                f"{missing_wages} active employee account(s) have no hourly rate.",
            )
        )
    return (sum(wages) / Decimal(len(wages)) if wages else None), issues


def _native_projection_rows_for_period(
    start_date: date,
    end_date: date,
    *,
    app_timezone: ZoneInfo,
    avg_hourly_rate: Optional[Decimal],
) -> Tuple[List[Dict[str, Any]], int]:
    allocation_start = date(start_date.year, start_date.month, 1)
    allocation_end = _month_end(end_date)
    rules = _load_active_service_schedule_rules(allocation_start, allocation_end)
    allocated_rows = _native_preview_rows(
        rules,
        allocation_start,
        allocation_end,
        app_timezone=app_timezone,
        avg_hourly_rate=avg_hourly_rate,
    )
    return [
        row
        for row in allocated_rows
        if start_date <= date.fromisoformat(row["scheduledDate"]) <= end_date
    ], len(rules)


def _forecast_weeks_from_rows(
    rows: List[Dict[str, Any]],
    *,
    first_week: date,
    weeks_ahead: int,
) -> List[Dict[str, Any]]:
    weeks: List[Dict[str, Any]] = []
    for offset in range(weeks_ahead):
        week_start = first_week + timedelta(weeks=offset)
        week_end = week_start + timedelta(days=6)
        week_rows = [
            row
            for row in rows
            if week_start <= datetime.strptime(row["scheduledDate"], "%Y-%m-%d").date()
            <= week_end
        ]
        by_site_rows: Dict[Optional[int], List[Dict[str, Any]]] = defaultdict(list)
        for row in week_rows:
            by_site_rows[row.get("locationId")].append(row)
        by_site = []
        for location_id, site_rows in by_site_rows.items():
            site_summary = _aggregate_forecast_rows(site_rows)
            first = site_rows[0]
            by_site.append(
                {
                    "locationId": location_id,
                    "customerId": first.get("customerId"),
                    "customerName": first.get("customerName"),
                    "siteAddress": first.get("siteAddress"),
                    **site_summary,
                }
            )
        summary = _aggregate_forecast_rows(week_rows)
        weeks.append(
            {
                "weekStart": str(week_start),
                "weekEnd": str(week_end),
                **summary,
                "bySite": sorted(
                    by_site,
                    key=lambda row: (
                        str(row.get("customerName") or "").casefold(),
                        str(row.get("siteAddress") or "").casefold(),
                        int(row.get("locationId") or 0),
                    ),
                ),
                "jobs": [_public_forecast_job(row) for row in week_rows],
            }
        )
    return weeks


def _native_source_role(row: Dict[str, Any]) -> Optional[str]:
    for source_role, site_type in SOURCE_ROLE_SITE_TYPES.items():
        if row.get("siteType") == site_type:
            return source_role
    return None


def _native_schedule_execution_status(
    row: Dict[str, Any],
    *,
    observed_at: datetime,
) -> str:
    scheduled_end = row.get("scheduledEnd")
    if scheduled_end is None:
        return "scheduled"
    try:
        ends_at = datetime.fromisoformat(str(scheduled_end).replace("Z", "+00:00"))
    except ValueError:
        return "scheduled"
    return "no_actual" if ends_at <= observed_at else "scheduled"


def _native_row_schedule_visible(
    row: Dict[str, Any],
    *,
    range_start: datetime,
    range_end: datetime,
    resolved_start: date,
    resolved_end: date,
) -> bool:
    try:
        scheduled_start = datetime.fromisoformat(
            str(row.get("scheduledStart") or "").replace("Z", "+00:00")
        )
        scheduled_end = datetime.fromisoformat(
            str(row.get("scheduledEnd") or "").replace("Z", "+00:00")
        )
    except ValueError:
        scheduled_start = None
        scheduled_end = None
    if (
        scheduled_start is not None
        and scheduled_end is not None
        and scheduled_end > scheduled_start
    ):
        return scheduled_start < range_end and scheduled_end > range_start
    try:
        scheduled_date = date.fromisoformat(str(row.get("scheduledDate") or ""))
    except ValueError:
        return False
    return resolved_start <= scheduled_date <= resolved_end


def _native_schedule_job(row: Dict[str, Any], observed_at: datetime) -> Dict[str, Any]:
    planned_hours = row.get("plannedHours")
    actual_hours = 0.0
    included = bool(row.get("_included_in_forecast", True))
    variance_hours = (
        round(actual_hours - float(planned_hours), 2)
        if planned_hours is not None
        else None
    )
    return {
        "projectionId": row.get("projectionId"),
        "ruleId": row.get("ruleId"),
        "locationId": row.get("locationId"),
        "customerId": row.get("customerId"),
        "customerName": row.get("customerName"),
        "siteAddress": row.get("siteAddress"),
        "siteType": row.get("siteType"),
        "shiftBucket": row.get("shiftBucket"),
        "cadence": row.get("cadence"),
        "scheduledDate": row.get("scheduledDate"),
        "scheduledStart": row.get("scheduledStart"),
        "scheduledEnd": row.get("scheduledEnd"),
        "sourceRole": _native_source_role(row),
        "sourceTitle": "Native Site schedule rule",
        "status": "scheduled",
        "executionStatus": _native_schedule_execution_status(
            row,
            observed_at=observed_at,
        ),
        "includedInPlan": included,
        "plannedHours": planned_hours,
        "expectedHoursBaseline": None,
        "actualHours": actual_hours,
        "varianceHours": variance_hours,
        "actualLaborCost": None,
        "knownActualLaborCost": 0.0,
        "workers": [],
        "siteEconomics": {
            "rate": _money(row.get("_rate_cents")),
            "rateType": row.get("rateType"),
            "expectedHours": planned_hours,
            "expectedHoursBaseline": None,
        },
        "issues": list(row.get("issues") or []),
    }


def allocate_monthly_cents(
    monthly_cents: int,
    ordered_job_ids: Iterable[int],
) -> Dict[int, int]:
    """Allocate a monthly price exactly, giving remainder cents to early jobs."""
    job_ids = list(ordered_job_ids)
    if not job_ids:
        return {}
    base, remainder = divmod(monthly_cents, len(job_ids))
    return {
        job_id: base + (1 if index < remainder else 0)
        for index, job_id in enumerate(job_ids)
    }


def _load_jobs(
    start_date: date,
    end_date: date,
    *,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    if (window_start is None) != (window_end is None):
        raise ValueError("Both job window bounds are required")
    job_filter = "j.scheduled_date BETWEEN %s AND %s"
    params: Tuple[Any, ...] = (start_date, end_date)
    if window_start is not None and window_end is not None:
        job_filter = """
                (
                    j.scheduled_start IS NOT NULL
                    AND j.scheduled_end IS NOT NULL
                    AND j.scheduled_end > j.scheduled_start
                    AND j.scheduled_start < %s
                    AND j.scheduled_end > %s
                )
                OR (
                    (
                        j.scheduled_start IS NULL
                        OR j.scheduled_end IS NULL
                        OR j.scheduled_end <= j.scheduled_start
                    )
                    AND j.scheduled_date BETWEEN %s AND %s
                )
        """
        params = (window_end, window_start, start_date, end_date)
    return _query_all(
        f"""
        SELECT j.id, j.location_id, j.customer_name, j.scheduled_date,
               j.expected_hours AS legacy_expected_hours,
               j.revenue AS legacy_revenue, j.notes, j.status, j.created_at,
               j.scheduled_start, j.scheduled_end, j.calendar_source_id,
               j.source_calendar_id, j.source_event_id, j.source_series_id,
               j.source_occurrence_id, j.source_key, j.source_title,
               j.source_timezone, j.source_all_day, j.cancelled_at,
               j.cancellation_reason,
               cs.role AS source_role,
               l.customer_id, l.address AS site_address,
               l.location_type AS site_type, l.rate, l.rate_type,
               l.expected_hours AS site_expected_hours,
               l.expected_hours_source AS site_expected_hours_source,
               l.expected_hours_learning_decision
                   AS site_expected_hours_learning_decision,
               l.expected_hours_learning_fingerprint
                   AS site_expected_hours_learning_fingerprint,
               l.expected_hours_learning_snapshot
                   AS site_expected_hours_learning_snapshot,
               l.expected_hours_learning_decided_at
                   AS site_expected_hours_learning_decided_at,
               l.target_labor_pct AS site_target_labor_pct,
               l.min_margin_pct AS site_min_margin_pct,
               l.active AS site_active,
               COALESCE(c.name, l.customer_name, j.customer_name) AS display_customer
        FROM jobs j
        LEFT JOIN google_calendar_sources cs ON cs.id = j.calendar_source_id
        LEFT JOIN locations l ON l.id = j.location_id
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE ({job_filter})
        ORDER BY j.scheduled_date,
                 j.scheduled_start NULLS LAST,
                 j.id
        """,
        params,
        cursor=cursor,
    )


def _load_linked_job_metadata(
    job_ids: Iterable[int],
    *,
    cursor: Optional[Any] = None,
) -> Dict[int, Dict[str, Any]]:
    """Load explicit-link identity independently of the visible job window."""

    ids = sorted(set(int(job_id) for job_id in job_ids))
    if not ids:
        return {}
    return {
        int(row["id"]): row
        for row in _query_all(
            """
            SELECT id, location_id, status
            FROM jobs
            WHERE id = ANY(%s)
            ORDER BY id
            """,
            (ids,),
            cursor=cursor,
        )
    }


def _candidate_reviewed_departures_for_learning(
    site_ids: List[int],
    *,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    if not site_ids:
        return []
    return _query_all(
        """
        WITH correction_candidates AS (
            SELECT correction.id,
                   correction.snapshot,
                   correction.result,
                   (correction.result ->> 'shiftId')::integer AS shift_id,
                   (correction.result ->> 'visitId')::integer AS visit_id
            FROM time_data_correction_batches correction
            WHERE correction.snapshot ->> 'correctionType' = %s
              AND correction.result ? 'shiftId'
              AND correction.result ? 'visitId'
              AND correction.result ? 'locationId'
              AND correction.result ? 'effectiveDepartureAt'
              AND correction.result ->> 'shiftId' ~ '^[0-9]+$'
              AND correction.result ->> 'visitId' ~ '^[0-9]+$'
              AND correction.result ->> 'locationId' ~ '^[0-9]+$'
        )
        SELECT correction.id,
               correction.snapshot,
               correction.result,
               correction.shift_id,
               correction.visit_id
        FROM correction_candidates correction
        JOIN visits v ON v.id = correction.visit_id
        WHERE v.location_id = ANY(%s)
        ORDER BY correction.id
        """,
        (
            UTILIZATION_MISSING_DEPARTURE_CORRECTION,
            site_ids,
        ),
        cursor=cursor,
    )


def _current_reviewed_departure_ids_for_learning(
    site_ids: List[int],
    *,
    cursor: Optional[Any] = None,
) -> List[int]:
    candidate_rows = _candidate_reviewed_departures_for_learning(
        site_ids,
        cursor=cursor,
    )
    if not candidate_rows:
        return []

    def resolve_valid_ids(active_cursor: Any) -> List[int]:
        prepared_by_shift: Dict[int, List[Dict[str, Any]]] = {}
        valid_ids: List[int] = []
        for row in candidate_rows:
            result = dict(row.get("result") or {})
            snapshot = dict(row.get("snapshot") or {})
            try:
                shift_id = int(row.get("shift_id") or result["shiftId"])
                visit_id = int(row.get("visit_id") or result["visitId"])
            except (KeyError, TypeError, ValueError):
                continue
            if shift_id not in prepared_by_shift:
                try:
                    shift, visits, departures = _load_utilization_shift_evidence(
                        active_cursor,
                        shift_id,
                    )
                except HTTPException:
                    prepared_by_shift[shift_id] = []
                    continue
                _, raw_review_items = _closed_shift_utilization(
                    shift,
                    visits,
                    departures,
                )
                evidence_by_shift = {
                    shift_id: _utilization_shift_evidence_snapshot(
                        shift,
                        visits,
                        departures,
                    )
                }
                prepared_by_shift[shift_id] = _prepare_utilization_review_items(
                    raw_review_items,
                    evidence_by_shift,
                )

            current_review = next(
                (
                    item
                    for item in prepared_by_shift[shift_id]
                    if item.get("code") == "missing_departure"
                    and item.get("visitId") is not None
                    and int(item["visitId"]) == visit_id
                ),
                None,
            )
            if current_review is None:
                continue
            if (
                str(snapshot.get("reviewKey") or "")
                == str(current_review["reviewKey"])
                and str(snapshot.get("evidenceFingerprint") or "")
                == str(current_review["evidenceFingerprint"])
            ):
                valid_ids.append(int(row["id"]))
        return valid_ids

    if cursor is not None:
        return resolve_valid_ids(cursor)
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as review_cursor:
            return resolve_valid_ids(review_cursor)


def _load_expected_hours_learning_by_site(
    site_ids: Iterable[Any],
    *,
    observed_at: datetime,
    app_timezone: ZoneInfo,
    cursor: Optional[Any] = None,
) -> Dict[int, Dict[str, Any]]:
    resolved_site_ids = sorted(
        {int(site_id) for site_id in site_ids if site_id is not None}
    )
    observed_local_day = observed_at.astimezone(app_timezone).date()
    observation_start = observed_local_day - timedelta(
        days=EXPECTED_HOURS_LEARNING_LOOKBACK_DAYS
    )
    observation_end = observed_local_day
    learning = {
        site_id: _empty_expected_hours_learning(
            observation_start=observation_start,
            observation_end=observation_end,
        )
        for site_id in resolved_site_ids
    }
    if not resolved_site_ids:
        return learning

    timezone_name = getattr(app_timezone, "key", str(app_timezone))
    reviewed_departure_ids = _current_reviewed_departure_ids_for_learning(
        resolved_site_ids,
        cursor=cursor,
    )
    rows = _query_all(
        """
        WITH target_shifts AS (
            SELECT DISTINCT v.shift_id
            FROM visits v
            WHERE v.location_id = ANY(%s)
              AND v.sequence_version >= 2
        ),
        reviewed_departures AS (
            SELECT DISTINCT ON (
                (correction.result ->> 'shiftId')::integer,
                (correction.result ->> 'visitId')::integer
            )
                correction.id,
                (correction.result ->> 'shiftId')::integer AS shift_id,
                (correction.result ->> 'visitId')::integer AS visit_id,
                (correction.result ->> 'locationId')::integer AS location_id,
                (correction.result ->> 'effectiveDepartureAt')::timestamptz
                    AS departure_time
            FROM time_data_correction_batches correction
            WHERE correction.snapshot ->> 'correctionType' = %s
              AND correction.id = ANY(%s::bigint[])
              AND correction.result ? 'shiftId'
              AND correction.result ? 'visitId'
              AND correction.result ? 'locationId'
              AND correction.result ? 'effectiveDepartureAt'
              AND correction.result ->> 'shiftId' ~ '^[0-9]+$'
              AND correction.result ->> 'visitId' ~ '^[0-9]+$'
              AND correction.result ->> 'locationId' ~ '^[0-9]+$'
            ORDER BY
                (correction.result ->> 'shiftId')::integer,
                (correction.result ->> 'visitId')::integer,
                correction.id DESC
        ),
        visit_evidence AS (
            SELECT
                v.id AS visit_id,
                evidence_shift.id AS shift_id,
                v.location_id,
                v.arrival_time,
                v.sequence_version,
                evidence_shift.employee_id,
                d.id AS recorded_departure_id,
                reviewed_departure.id AS reviewed_departure_id,
                (
                    d.id IS NOT NULL
                    OR reviewed_departure.id IS NOT NULL
                ) AS has_departure,
                COALESCE(
                    d.departure_time,
                    reviewed_departure.departure_time
                ) AS departure_time,
                COALESCE(
                    d.location_id,
                    reviewed_departure.location_id
                ) AS departure_location_id,
                evidence_shift.time_category,
                COALESCE(
                    correction.corrected_clock_in,
                    evidence_shift.clock_in
                ) AS paid_clock_in,
                COALESCE(
                    correction.corrected_clock_out,
                    evidence_shift.clock_out
                ) AS paid_clock_out,
                COALESCE(
                    correction.corrected_break_minutes,
                    0
                ) AS payroll_break_minutes,
                COALESCE(
                    CASE
                        WHEN v.site_check_in_id IS NOT NULL
                         AND check_in_job.location_id = v.location_id
                        THEN sci.job_id
                    END,
                    CASE
                        WHEN v.site_check_in_id IS NULL
                         AND visit_job.location_id = v.location_id
                        THEN v.job_id
                    END,
                    CASE
                        WHEN shift_job.location_id = v.location_id
                        THEN evidence_shift.job_id
                    END
                ) AS resolved_job_id,
                (
                    v.site_check_in_id IS NULL
                    OR (
                        sci.employee_id = evidence_shift.employee_id
                        AND sci.location_id = v.location_id
                        AND DATE_TRUNC('second', sci.server_checked_in_at)
                            = DATE_TRUNC('second', v.arrival_time)
                        AND (
                            (
                                sci.classification IN ('on_time', 'late')
                                AND sci.review_status = 'not_required'
                            )
                            OR (
                                sci.classification = 'needs_review'
                                AND sci.review_status = 'approved'
                            )
                        )
                    )
                ) AS accepted_check_in
            FROM visits v
            JOIN target_shifts target ON target.shift_id = v.shift_id
            JOIN shifts evidence_shift ON evidence_shift.id = v.shift_id
            LEFT JOIN LATERAL (
                SELECT
                    shift_correction.corrected_clock_in,
                    shift_correction.corrected_clock_out,
                    shift_correction.corrected_break_minutes
                FROM payroll_shift_corrections shift_correction
                WHERE shift_correction.shift_id = evidence_shift.id
                  AND shift_correction.status = 'active'
                  AND shift_correction.week_start = (
                      COALESCE(
                          evidence_shift.local_date,
                          (evidence_shift.clock_in AT TIME ZONE %s)::date
                      )
                      - EXTRACT(
                          DOW FROM COALESCE(
                              evidence_shift.local_date,
                              (evidence_shift.clock_in AT TIME ZONE %s)::date
                          )
                      )::integer
                  )
                ORDER BY shift_correction.week_start DESC, shift_correction.id DESC
                LIMIT 1
            ) correction ON TRUE
            LEFT JOIN jobs visit_job ON visit_job.id = v.job_id
            LEFT JOIN jobs shift_job ON shift_job.id = evidence_shift.job_id
            LEFT JOIN site_check_ins sci ON sci.id = v.site_check_in_id
            LEFT JOIN jobs check_in_job ON check_in_job.id = sci.job_id
            LEFT JOIN departures d ON d.visit_id = v.id
                                  AND d.shift_id = v.shift_id
            LEFT JOIN reviewed_departures reviewed_departure
                   ON reviewed_departure.visit_id = v.id
                  AND reviewed_departure.shift_id = v.shift_id
                  AND d.id IS NULL
        ),
        paired_visit_evidence AS (
            SELECT *,
                   EXTRACT(EPOCH FROM (departure_time - arrival_time)) AS raw_seconds
            FROM visit_evidence
            WHERE time_category = 'productive'
              AND sequence_version >= 2
              AND location_id IS NOT NULL
              AND has_departure IS TRUE
              AND departure_time > arrival_time
              AND arrival_time <= %s
              AND departure_time <= %s
              AND paid_clock_in <= %s
              AND paid_clock_out <= %s
              AND departure_location_id IS NOT DISTINCT FROM location_id
              AND accepted_check_in IS TRUE
              AND paid_clock_in IS NOT NULL
              AND paid_clock_out IS NOT NULL
              AND paid_clock_out > paid_clock_in
              AND arrival_time >= paid_clock_in
              AND departure_time <= paid_clock_out
        ),
        invalid_jobs AS (
            SELECT DISTINCT resolved_job_id AS job_id
            FROM visit_evidence
            WHERE resolved_job_id IS NOT NULL
              AND (
                    time_category IS DISTINCT FROM 'productive'
                    OR sequence_version < 2
                    OR location_id IS NULL
                    OR has_departure IS NOT TRUE
                    OR departure_time <= arrival_time
                    OR departure_location_id IS DISTINCT FROM location_id
                    OR accepted_check_in IS NOT TRUE
                    OR paid_clock_in IS NULL
                    OR paid_clock_out IS NULL
                    OR paid_clock_out <= paid_clock_in
                    OR arrival_time < paid_clock_in
                    OR departure_time > paid_clock_out
                    OR arrival_time > %s
                    OR departure_time > %s
                    OR paid_clock_in > %s
                    OR paid_clock_out > %s
              )
        ),
        candidate_pairs AS (
            SELECT pairs.*,
                   j.id AS job_id,
                   j.scheduled_date
            FROM paired_visit_evidence pairs
            JOIN jobs j ON j.id = pairs.resolved_job_id
                       AND j.location_id = pairs.location_id
            WHERE j.status = 'completed'
              AND j.scheduled_date BETWEEN %s AND %s
        ),
        legacy_shift_jobs AS (
            SELECT DISTINCT candidate.job_id
            FROM candidate_pairs candidate
            WHERE EXISTS (
                SELECT 1
                FROM visit_evidence legacy
                WHERE legacy.shift_id = candidate.shift_id
                  AND legacy.sequence_version < 2
            )
        ),
        overlap_visits AS (
            SELECT DISTINCT left_pair.visit_id
            FROM paired_visit_evidence left_pair
            JOIN paired_visit_evidence right_pair
              ON right_pair.employee_id = left_pair.employee_id
             AND right_pair.visit_id <> left_pair.visit_id
             AND left_pair.arrival_time < right_pair.departure_time
             AND right_pair.arrival_time < left_pair.departure_time
        ),
        overlap_jobs AS (
            SELECT DISTINCT candidate.job_id
            FROM candidate_pairs candidate
            WHERE EXISTS (
                SELECT 1
                FROM overlap_visits overlap
                WHERE overlap.visit_id = candidate.visit_id
            )
        ),
        contradictory_arrival_visits AS (
            SELECT DISTINCT pair.visit_id
            FROM paired_visit_evidence pair
            JOIN visit_evidence other_arrival
              ON other_arrival.shift_id = pair.shift_id
             AND other_arrival.visit_id <> pair.visit_id
             AND pair.arrival_time <= other_arrival.arrival_time
             AND other_arrival.arrival_time < pair.departure_time
        ),
        contradictory_arrival_jobs AS (
            SELECT DISTINCT candidate.job_id
            FROM candidate_pairs candidate
            WHERE EXISTS (
                SELECT 1
                FROM contradictory_arrival_visits conflict
                WHERE conflict.visit_id = candidate.visit_id
            )
        ),
        contradictory_departure_visits AS (
            SELECT DISTINCT pair.visit_id
            FROM paired_visit_evidence pair
            JOIN departures other_departure
              ON other_departure.shift_id = pair.shift_id
             AND other_departure.id IS DISTINCT FROM pair.recorded_departure_id
             AND pair.arrival_time < other_departure.departure_time
             AND other_departure.departure_time <= pair.departure_time
        ),
        contradictory_departure_jobs AS (
            SELECT DISTINCT candidate.job_id
            FROM candidate_pairs candidate
            WHERE EXISTS (
                SELECT 1
                FROM contradictory_departure_visits conflict
                WHERE conflict.visit_id = candidate.visit_id
            )
        ),
        unassigned_worker_jobs AS (
            SELECT DISTINCT candidate.job_id
            FROM candidate_pairs candidate
            WHERE EXISTS (
                SELECT 1
                FROM paired_visit_evidence unassigned
                WHERE unassigned.location_id = candidate.location_id
                  AND unassigned.resolved_job_id IS NULL
                  AND (unassigned.arrival_time AT TIME ZONE %s)::date
                      = candidate.scheduled_date
            )
        ),
        clean_pairs AS (
            SELECT candidate.*
            FROM candidate_pairs candidate
            WHERE candidate.location_id = ANY(%s)
              AND NOT EXISTS (
                  SELECT 1
                  FROM invalid_jobs invalid
                  WHERE invalid.job_id = candidate.job_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM legacy_shift_jobs legacy
                  WHERE legacy.job_id = candidate.job_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM overlap_jobs overlap
                  WHERE overlap.job_id = candidate.job_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM contradictory_arrival_jobs conflict
                  WHERE conflict.job_id = candidate.job_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM contradictory_departure_jobs conflict
                  WHERE conflict.job_id = candidate.job_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM unassigned_worker_jobs unassigned
                  WHERE unassigned.job_id = candidate.job_id
              )
        ),
        scope_pairs AS (
            SELECT pairs.*
            FROM paired_visit_evidence pairs
            WHERE NOT EXISTS (
                SELECT 1
                FROM overlap_visits overlap
                WHERE overlap.visit_id = pairs.visit_id
            )
        ),
        shift_scopes AS (
            SELECT shift_id,
                   COUNT(DISTINCT location_id) AS location_count,
                   COUNT(DISTINCT resolved_job_id)
                       FILTER (WHERE resolved_job_id IS NOT NULL) AS job_count,
                   COUNT(*) FILTER (WHERE resolved_job_id IS NULL)
                       AS unassigned_job_count
            FROM scope_pairs
            GROUP BY shift_id
        ),
        shift_job_seconds AS (
            SELECT clean.job_id,
                   clean.location_id,
                   clean.scheduled_date,
                   clean.shift_id,
                   GREATEST(
                       SUM(clean.raw_seconds)
                       - CASE
                           WHEN MAX(scope.location_count) = 1
                            AND MAX(scope.job_count) = 1
                            AND MAX(scope.unassigned_job_count) = 0
                           THEN LEAST(
                               MAX(clean.payroll_break_minutes) * 60,
                               SUM(clean.raw_seconds)
                           )
                           ELSE 0
                         END,
                       0
                   ) AS person_seconds,
                   COUNT(*) AS interval_count
            FROM clean_pairs clean
            JOIN shift_scopes scope ON scope.shift_id = clean.shift_id
            GROUP BY clean.job_id, clean.location_id, clean.scheduled_date, clean.shift_id
        )
        SELECT job_id,
               location_id,
               scheduled_date,
               SUM(person_seconds) / 3600.0 AS person_hours,
               SUM(interval_count) AS interval_count
        FROM shift_job_seconds
        GROUP BY job_id, location_id, scheduled_date
        HAVING SUM(person_seconds) > 0
        ORDER BY location_id, scheduled_date, job_id
        """,
        (
            resolved_site_ids,
            UTILIZATION_MISSING_DEPARTURE_CORRECTION,
            reviewed_departure_ids,
            timezone_name,
            timezone_name,
            observed_at,
            observed_at,
            observed_at,
            observed_at,
            observed_at,
            observed_at,
            observed_at,
            observed_at,
            observation_start,
            observation_end,
            timezone_name,
            resolved_site_ids,
        ),
        cursor=cursor,
    )

    observations_by_site: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        observations_by_site[int(row["location_id"])].append(dict(row))
    for site_id, observations in observations_by_site.items():
        samples = [float(row["person_hours"]) for row in observations]
        sample_size = len(samples)
        first_date = min(row["scheduled_date"] for row in observations)
        last_date = max(row["scheduled_date"] for row in observations)
        learning[site_id] = {
            "sampleSize": sample_size,
            "minimumSampleSize": EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES,
            "suggestedHours": (
                round(_median(samples), 2)
                if sample_size >= EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES
                else None
            ),
            "observationPeriod": {
                "startDate": str(first_date),
                "endDate": str(last_date),
                "lookbackDays": EXPECTED_HOURS_LEARNING_LOOKBACK_DAYS,
            },
            "exclusionRules": list(EXPECTED_HOURS_LEARNING_EXCLUSION_RULES),
        }
    return learning


def _expected_hours_baseline_fingerprint(
    *,
    site_id: int,
    learning: Dict[str, Any],
) -> Optional[str]:
    suggested_hours = learning.get("suggestedHours")
    if suggested_hours is None:
        return None
    payload = {
        "version": EXPECTED_HOURS_BASELINE_KEY_VERSION,
        "siteId": int(site_id),
        "suggestedHours": float(suggested_hours),
        "sampleSize": int(learning.get("sampleSize") or 0),
        "minimumSampleSize": int(
            learning.get("minimumSampleSize")
            or EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES
        ),
        "observationPeriod": learning.get("observationPeriod"),
        "exclusionRules": list(
            learning.get("exclusionRules") or EXPECTED_HOURS_LEARNING_EXCLUSION_RULES
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _expected_hours_baseline(
    job: Dict[str, Any],
    learning_by_site: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    planned_hours = (
        float(job["site_expected_hours"])
        if job.get("site_expected_hours") is not None
        else None
    )
    if planned_hours is not None:
        source = (
            "learned_accepted"
            if job.get("site_expected_hours_source") == "learned_accepted"
            else "manual"
        )
        accepted_snapshot = (
            job.get("site_expected_hours_learning_snapshot")
            if isinstance(job.get("site_expected_hours_learning_snapshot"), dict)
            else {}
        )
        return {
            "source": source,
            "state": "accepted" if source == "learned_accepted" else "manual",
            "plannedHours": planned_hours,
            "manualHours": planned_hours if source == "manual" else None,
            "suggestedHours": (
                accepted_snapshot.get("suggestedHours", planned_hours)
                if source == "learned_accepted"
                else None
            ),
            "sampleSize": accepted_snapshot.get("sampleSize")
            if source == "learned_accepted"
            else None,
            "minimumSampleSize": (
                int(
                    accepted_snapshot.get("minimumSampleSize")
                    or EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES
                )
                if source == "learned_accepted"
                else EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES
            ),
            "observationPeriod": (
                accepted_snapshot.get("observationPeriod")
                if source == "learned_accepted"
                else None
            ),
            "exclusionRules": list(
                (
                    accepted_snapshot.get("exclusionRules")
                    if source == "learned_accepted"
                    else None
                )
                or EXPECTED_HOURS_LEARNING_EXCLUSION_RULES
            ),
            "baselineFingerprint": (
                (
                    accepted_snapshot.get("baselineFingerprint")
                    or job.get("site_expected_hours_learning_fingerprint")
                )
                if source == "learned_accepted"
                else None
            ),
        }
    site_id = job.get("location_id")
    learning = (
        (learning_by_site or {}).get(int(site_id))
        if site_id is not None
        else None
    )
    if learning is None:
        return {
            "source": "insufficient_data",
            "state": "learning",
            "plannedHours": None,
            "manualHours": None,
            "suggestedHours": None,
            "sampleSize": 0,
            "minimumSampleSize": EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES,
            "observationPeriod": None,
            "exclusionRules": list(EXPECTED_HOURS_LEARNING_EXCLUSION_RULES),
            "baselineFingerprint": None,
        }
    suggested_hours = learning.get("suggestedHours")
    baseline_fingerprint = (
        _expected_hours_baseline_fingerprint(
            site_id=int(site_id),
            learning=learning,
        )
        if site_id is not None
        else None
    )
    rejected = (
        suggested_hours is not None
        and job.get("site_expected_hours_learning_decision") == "rejected"
        and job.get("site_expected_hours_learning_fingerprint") == baseline_fingerprint
    )
    source = "learned_suggestion" if suggested_hours is not None else "insufficient_data"
    if rejected:
        source = "learned_rejected"
    return {
        "source": source,
        "state": (
            "rejected"
            if rejected
            else ("suggested" if suggested_hours is not None else "learning")
        ),
        "plannedHours": None,
        "manualHours": None,
        "suggestedHours": suggested_hours,
        "sampleSize": int(learning.get("sampleSize") or 0),
        "minimumSampleSize": int(
            learning.get("minimumSampleSize")
            or EXPECTED_HOURS_LEARNING_MIN_COMPLETED_OCCURRENCES
        ),
        "observationPeriod": learning.get("observationPeriod"),
        "exclusionRules": list(
            learning.get("exclusionRules") or EXPECTED_HOURS_LEARNING_EXCLUSION_RULES
        ),
        "baselineFingerprint": baseline_fingerprint,
    }


def _load_expected_hours_site(site_id: int, *, cursor: Any) -> Optional[Dict[str, Any]]:
    cursor.execute(
        """
        SELECT id, expected_hours, expected_hours_source,
               expected_hours_learning_decision,
               expected_hours_learning_fingerprint,
               expected_hours_learning_snapshot,
               expected_hours_learning_decided_at,
               expected_hours_learning_decided_by,
               expected_hours_learning_decision_reason,
               active, updated_at
        FROM locations
        WHERE id = %s
        FOR UPDATE
        """,
        (site_id,),
    )
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def _baseline_job_from_site(site: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(site["id"]),
        "location_id": int(site["id"]),
        "site_expected_hours": site.get("expected_hours"),
        "site_expected_hours_source": site.get("expected_hours_source"),
        "site_expected_hours_learning_decision": site.get(
            "expected_hours_learning_decision"
        ),
        "site_expected_hours_learning_fingerprint": site.get(
            "expected_hours_learning_fingerprint"
        ),
        "site_expected_hours_learning_snapshot": site.get(
            "expected_hours_learning_snapshot"
        ),
        "site_expected_hours_learning_decided_at": site.get(
            "expected_hours_learning_decided_at"
        ),
    }


def _job_issues(job: Dict[str, Any]) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    if job.get("location_id") is None:
        issues.append(
            _issue("missing_site", "This scheduled job is not linked to a Site.")
        )
    elif job.get("site_active") is False:
        issues.append(
            _issue("archived_site", "This scheduled job points to an archived Site.")
        )
    if job.get("location_id") is not None:
        if job.get("rate") is None:
            issues.append(
                _issue(
                    "missing_rate",
                    "A service price is not configured for this Site.",
                )
            )
    if job.get("location_id") is not None and job.get("rate_type") not in {
        "per_visit",
        "hourly",
        "monthly",
    }:
        issues.append(
            _issue(
                "invalid_rate_type",
                "This Site does not have a supported price type.",
            )
        )
    if job.get("source_role") not in {
        "residential_morning",
        "commercial_evening_night",
    }:
        issues.append(
            _issue(
                "missing_source_role",
                "This job is not bound to a Residential or Commercial Calendar.",
            )
        )
    expected_site_type = SOURCE_ROLE_SITE_TYPES.get(job.get("source_role"))
    if (
        job.get("location_id") is not None
        and expected_site_type is not None
        and job.get("site_type") != expected_site_type
    ):
        issues.append(
            _issue(
                "wrong_site_type",
                f"This {job['source_role']} job requires an active "
                f"{expected_site_type} Site.",
            )
        )
    if bool(job.get("source_all_day")):
        issues.append(
            _issue(
                "all_day_event",
                "All-day Calendar events cannot define a service window.",
            )
        )
    start = job.get("scheduled_start")
    end = job.get("scheduled_end")
    if start is None or end is None or end <= start:
        issues.append(
            _issue(
                "invalid_service_window",
                "This job does not have a valid Calendar start and end time.",
            )
        )
    return issues


def _job_is_projection_eligible(job: Dict[str, Any]) -> bool:
    """Require one valid canonical occurrence before adding planning totals."""

    expected_site_type = SOURCE_ROLE_SITE_TYPES.get(job.get("source_role"))
    start = job.get("scheduled_start")
    end = job.get("scheduled_end")
    return bool(
        job.get("location_id") is not None
        and job.get("site_active") is True
        and expected_site_type is not None
        and job.get("site_type") == expected_site_type
        and not bool(job.get("source_all_day"))
        and start is not None
        and end is not None
        and end > start
    )


def _schedule_execution_status(
    job: Dict[str, Any],
    *,
    in_progress: bool,
    actual_hours: float,
    observed_at: datetime,
) -> str:
    """Derive the read-only execution state from planning and paid-time evidence."""

    status = str(job.get("status") or "scheduled")
    if status == "cancelled":
        return "cancelled"
    if in_progress:
        return "in_progress"
    if status == "completed" or actual_hours > 0:
        return "completed"

    scheduled_start = job.get("scheduled_start")
    scheduled_end = job.get("scheduled_end")
    has_valid_timed_window = bool(
        not bool(job.get("source_all_day"))
        and scheduled_start is not None
        and scheduled_end is not None
        and scheduled_end > scheduled_start
    )
    if has_valid_timed_window and scheduled_end <= observed_at:
        return "no_actual"
    return "scheduled"


def _qr_sites_in_interval(
    qr_by_employee_site: Dict[Tuple[int, int], List[datetime]],
    *,
    employee_id: int,
    start: datetime,
    end: datetime,
) -> List[Tuple[datetime, int]]:
    """Return one immutable QR presence point per Site in a half-open interval."""

    check_ins: List[Tuple[datetime, int]] = []
    for (candidate_employee_id, location_id), timestamps in qr_by_employee_site.items():
        if candidate_employee_id != employee_id:
            continue
        matching = [timestamp for timestamp in timestamps if start <= timestamp < end]
        if matching:
            check_ins.append((min(matching), location_id))
    return sorted(check_ins, key=lambda item: (item[0], item[1]))


def _load_time_evidence(
    range_start: datetime,
    range_end: datetime,
    observed_at: datetime,
    visible_job_ids: Iterable[int],
    *,
    timezone_name: str = "America/Chicago",
    payroll_week_start: Optional[date] = None,
    cursor: Optional[Any] = None,
) -> Tuple[
    List[Dict[str, Any]],
    Dict[int, List[Dict[str, Any]]],
    Dict[int, List[Dict[str, Any]]],
    Dict[Tuple[int, int], List[datetime]],
    List[Dict[str, Any]],
]:
    linked_job_ids = [int(job_id) for job_id in visible_job_ids]
    shifts = _query_all(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name,
               -- Prefer the rate the shift was worked at; fall back to the live
               -- employee rate only when the shift carries no snapshot. NULL on
               -- both sides still means "no rate", so the fail-closed
               -- missing_worker_rate policy downstream is unchanged.
               COALESCE(s.hourly_rate_cents::numeric / 100, e.hourly_rate)
                   AS hourly_rate,
               s.location_id, s.location_label,
               COALESCE(correction.corrected_clock_in, s.clock_in) AS clock_in,
               COALESCE(correction.corrected_clock_out, s.clock_out) AS clock_out,
               COALESCE(correction.corrected_break_minutes, 0) AS payroll_break_minutes,
               s.job_id
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        LEFT JOIN LATERAL (
            SELECT
                shift_correction.corrected_clock_in,
                shift_correction.corrected_clock_out,
                shift_correction.corrected_break_minutes
            FROM payroll_shift_corrections shift_correction
            WHERE shift_correction.shift_id = s.id
              AND shift_correction.status = 'active'
              AND shift_correction.week_start = (
                  COALESCE(
                      s.local_date,
                      (s.clock_in AT TIME ZONE %s)::date
                  )
                  - EXTRACT(
                      DOW FROM COALESCE(
                          s.local_date,
                          (s.clock_in AT TIME ZONE %s)::date
                      )
                  )::integer
              )
            ORDER BY shift_correction.week_start DESC, shift_correction.id DESC
            LIMIT 1
        ) correction ON TRUE
        WHERE s.time_category = 'productive'
          AND (
              (
                  COALESCE(correction.corrected_clock_in, s.clock_in) < %s
                  AND COALESCE(correction.corrected_clock_out, s.clock_out, %s) > %s
              )
              OR EXISTS (
                  SELECT 1
                  FROM site_check_ins linked_sci
                  WHERE linked_sci.employee_id = s.employee_id
                    AND linked_sci.job_id = ANY(%s)
                    AND linked_sci.server_checked_in_at < %s
                    AND COALESCE(correction.corrected_clock_in, s.clock_in)
                        <= linked_sci.server_checked_in_at
                    AND COALESCE(correction.corrected_clock_out, s.clock_out, %s)
                        > linked_sci.server_checked_in_at
                    AND (
                        (
                            linked_sci.classification IN ('on_time', 'late')
                            AND linked_sci.review_status = 'not_required'
                        )
                        OR (
                            linked_sci.classification = 'needs_review'
                            AND linked_sci.review_status = 'approved'
                        )
                    )
              )
          )
        ORDER BY s.clock_in, s.id
        """,
        (
            timezone_name,
            timezone_name,
            range_end,
            observed_at,
            range_start,
            linked_job_ids,
            observed_at,
            observed_at,
        ),
        cursor=cursor,
    )

    if payroll_week_start is not None:
        excluded_shift_ids = {
            int(row["shift_id"])
            for row in _query_all(
                """
                SELECT shift_id
                FROM payroll_shift_exclusions
                WHERE week_start = %s
                  AND status = 'active'
                """,
                (payroll_week_start,),
                cursor=cursor,
            )
        }
        shifts = [
            row for row in shifts if int(row["id"]) not in excluded_shift_ids
        ]
        manual_shifts = _query_all(
            """
            SELECT
                -manual.id AS id,
                manual.employee_id,
                employee.name AS employee_name,
                employee.hourly_rate,
                manual.location_id,
                COALESCE(location.address, '') AS location_label,
                manual.clock_in,
                manual.clock_out,
                manual.break_minutes AS payroll_break_minutes,
                NULL::integer AS job_id
            FROM payroll_manual_shift_versions manual
            JOIN employees employee ON employee.id = manual.employee_id
            LEFT JOIN locations location ON location.id = manual.location_id
            WHERE manual.week_start = %s
              AND manual.status = 'current'
              AND manual.included = TRUE
              AND manual.clock_in < %s
              AND manual.clock_out > %s
            ORDER BY manual.clock_in, manual.id
            """,
            (payroll_week_start, range_end, range_start),
            cursor=cursor,
        )
        shifts.extend(manual_shifts)
        shifts.sort(key=lambda row: (row["clock_in"], int(row["id"])))

    shift_ids = [int(row["id"]) for row in shifts]
    visits: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    if shift_ids:
        for row in _query_all(
            """
            SELECT id, shift_id, location_id, location_label, customer_name,
                   arrival_time, sequence_version, site_check_in_id
            FROM visits
            WHERE shift_id = ANY(%s)
            ORDER BY shift_id, arrival_time, id
            """,
            (shift_ids,),
            cursor=cursor,
        ):
            visits[int(row["shift_id"])].append(row)

    departures: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    if shift_ids:
        for row in _query_all(
            """
            SELECT id, shift_id, location_id, location_label, customer_name,
                   departure_time, visit_id
            FROM departures
            WHERE shift_id = ANY(%s)
            ORDER BY shift_id, departure_time, id
            """,
            (shift_ids,),
            cursor=cursor,
        ):
            departures[int(row["shift_id"])].append(row)

    qr_by_employee_site: Dict[Tuple[int, int], List[datetime]] = defaultdict(list)
    # D2 (issue #126): QR-only presence rows have no shift, so they have no rate
    # snapshot and stay on the live employee rate. They are deliberately out of
    # scope: the segments they produce are presence-only (shift_id None, a
    # one-microsecond span) and contribute zero finalized hours, so the live rate
    # here is never multiplied into money today.
    qr_rows = _query_all(
        """
        SELECT sci.id, sci.employee_id, e.name AS employee_name, e.hourly_rate,
               sci.location_id, sci.job_id, l.address AS location_label,
               sci.server_checked_in_at
        FROM site_check_ins sci
        JOIN employees e ON e.id = sci.employee_id
        LEFT JOIN locations l ON l.id = sci.location_id
        WHERE sci.server_checked_in_at < %s
          AND (
              (
                  sci.server_checked_in_at >= %s
                  AND sci.server_checked_in_at < %s
              )
              OR sci.job_id = ANY(%s)
              OR EXISTS (
                  SELECT 1
                  FROM shifts evidence_shift
                  LEFT JOIN LATERAL (
                      SELECT
                          shift_correction.corrected_clock_in,
                          shift_correction.corrected_clock_out
                      FROM payroll_shift_corrections shift_correction
                      WHERE shift_correction.shift_id = evidence_shift.id
                        AND shift_correction.status = 'active'
                        AND shift_correction.week_start = (
                            COALESCE(
                                evidence_shift.local_date,
                                (
                                    evidence_shift.clock_in
                                    AT TIME ZONE %s
                                )::date
                            )
                            - EXTRACT(
                                DOW FROM COALESCE(
                                    evidence_shift.local_date,
                                    (
                                        evidence_shift.clock_in
                                        AT TIME ZONE %s
                                    )::date
                                )
                            )::integer
                        )
                      ORDER BY
                          shift_correction.week_start DESC,
                          shift_correction.id DESC
                      LIMIT 1
                  ) evidence_correction ON TRUE
                  WHERE evidence_shift.id = ANY(%s)
                    AND evidence_shift.employee_id = sci.employee_id
                    AND COALESCE(evidence_correction.corrected_clock_in, evidence_shift.clock_in)
                        <= sci.server_checked_in_at
                    AND COALESCE(
                            evidence_correction.corrected_clock_out,
                            evidence_shift.clock_out,
                            %s
                        )
                        > sci.server_checked_in_at
              )
          )
          AND (
              (
                  sci.classification IN ('on_time', 'late')
                  AND sci.review_status = 'not_required'
              )
              OR (
                  sci.classification = 'needs_review'
                  AND sci.review_status = 'approved'
              )
          )
        ORDER BY sci.employee_id, sci.location_id,
                 sci.server_checked_in_at, sci.id
        """,
        (
            observed_at,
            range_start,
            range_end,
            linked_job_ids,
            timezone_name,
            timezone_name,
            shift_ids,
            observed_at,
        ),
        cursor=cursor,
    )
    for row in qr_rows:
        qr_by_employee_site[(int(row["employee_id"]), int(row["location_id"]))].append(
            row["server_checked_in_at"]
        )

    return shifts, visits, departures, qr_by_employee_site, qr_rows


def _load_utilization_evidence(
    range_start: datetime,
    range_end: datetime,
    observed_at: datetime,
) -> Tuple[
    List[Dict[str, Any]],
    Dict[int, List[Dict[str, Any]]],
    Dict[int, List[Dict[str, Any]]],
]:
    """Load the immutable event atoms needed for paid-time classification."""

    shifts = db.query_all(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name,
               s.location_id, s.location_label, s.job_id,
               s.clock_in, s.clock_out, s.time_category,
               s.non_productive_type
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE (
                s.clock_out IS NOT NULL
                AND (
                    (
                        s.clock_in < %s
                        AND s.clock_out > %s
                    )
                    OR (
                        s.clock_out <= s.clock_in
                        AND s.clock_in >= %s
                        AND s.clock_in < %s
                    )
                )
              )
           OR (
                s.clock_out IS NULL
                AND s.clock_in < %s
                AND s.clock_in < %s
                AND %s > %s
              )
        ORDER BY s.employee_id, s.clock_in, s.id
        """,
        (
            range_end,
            range_start,
            range_start,
            range_end,
            range_end,
            observed_at,
            observed_at,
            range_start,
        ),
    )
    shift_ids = [int(row["id"]) for row in shifts]
    visits: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    departures: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    if not shift_ids:
        return shifts, visits, departures

    for row in db.query_all(
        """
        SELECT v.id, v.shift_id, v.location_id, v.location_label,
               v.arrival_time, v.sequence_version, v.site_check_in_id,
               sci.employee_id AS check_in_employee_id,
               sci.location_id AS check_in_location_id,
               sci.server_checked_in_at AS check_in_at,
               sci.classification AS check_in_classification,
               sci.review_status AS check_in_review_status,
               COALESCE(
                   CASE
                       WHEN check_in_job.location_id = v.location_id
                       THEN sci.job_id
                   END,
                   CASE
                       WHEN shift_job.location_id = v.location_id
                       THEN evidence_shift.job_id
                   END
               ) AS job_id
        FROM visits v
        JOIN shifts evidence_shift ON evidence_shift.id = v.shift_id
        LEFT JOIN jobs shift_job ON shift_job.id = evidence_shift.job_id
        LEFT JOIN site_check_ins sci ON sci.id = v.site_check_in_id
        LEFT JOIN jobs check_in_job ON check_in_job.id = sci.job_id
        WHERE v.shift_id = ANY(%s)
        ORDER BY v.shift_id, v.arrival_time, v.id
        """,
        (shift_ids,),
    ):
        visits[int(row["shift_id"])].append(row)

    for row in db.query_all(
        """
        SELECT id, shift_id, visit_id, location_id, location_label,
               departure_time
        FROM departures
        WHERE shift_id = ANY(%s)
        ORDER BY shift_id, departure_time, id
        """,
        (shift_ids,),
    ):
        departures[int(row["shift_id"])].append(row)

    return shifts, visits, departures


def _epoch_second(value: datetime) -> int:
    """Normalize authoritative timestamps to the API's whole-second precision."""

    return int(value.astimezone(timezone.utc).timestamp())


def _second_datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _utilization_evidence_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc_iso(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _utilization_evidence_value(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [_utilization_evidence_value(item) for item in value]
    return value


def _utilization_shift_evidence_snapshot(
    shift: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
) -> Dict[str, Any]:
    shift_fields = (
        "id",
        "employee_id",
        "location_id",
        "location_label",
        "job_id",
        "clock_in",
        "clock_out",
        "time_category",
        "non_productive_type",
    )
    visit_fields = (
        "id",
        "shift_id",
        "location_id",
        "location_label",
        "arrival_time",
        "sequence_version",
        "site_check_in_id",
        "check_in_employee_id",
        "check_in_location_id",
        "check_in_at",
        "check_in_classification",
        "check_in_review_status",
        "job_id",
    )
    departure_fields = (
        "id",
        "shift_id",
        "visit_id",
        "location_id",
        "location_label",
        "departure_time",
    )
    return _utilization_evidence_value(
        {
            "shift": {field: shift.get(field) for field in shift_fields},
            "visits": [
                {field: row.get(field) for field in visit_fields}
                for row in sorted(
                    visits,
                    key=lambda item: (
                        item.get("arrival_time"),
                        int(item.get("id") or 0),
                    ),
                )
            ],
            "departures": [
                {field: row.get(field) for field in departure_fields}
                for row in sorted(
                    departures,
                    key=lambda item: (
                        item.get("departure_time"),
                        int(item.get("id") or 0),
                    ),
                )
            ],
        }
    )


def _utilization_review_identity(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": UTILIZATION_REVIEW_KEY_VERSION,
        "shiftId": int(item["shiftId"]),
        "relatedShiftIds": sorted(
            {
                int(value)
                for value in item.get("relatedShiftIds") or [item["shiftId"]]
            }
        ),
        "code": str(item["code"]),
        "visitId": (
            int(item["visitId"]) if item.get("visitId") is not None else None
        ),
        "departureId": (
            int(item["departureId"])
            if item.get("departureId") is not None
            else None
        ),
    }


def _utilization_review_key(item: Dict[str, Any]) -> str:
    payload = json.dumps(
        _utilization_review_identity(item),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _utilization_review_evidence(
    item: Dict[str, Any],
    evidence_by_shift: Dict[int, Dict[str, Any]],
) -> Dict[str, Any]:
    shift_ids = sorted(
        {
            int(value)
            for value in item.get("relatedShiftIds") or [item["shiftId"]]
        }
    )
    return {
        "evidenceVersion": UTILIZATION_EVIDENCE_VERSION,
        "subject": _utilization_review_identity(item),
        "shifts": [
            evidence_by_shift[shift_id]
            for shift_id in shift_ids
            if shift_id in evidence_by_shift
        ],
    }


def _utilization_evidence_fingerprint(evidence: Dict[str, Any]) -> str:
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _prepare_utilization_review_items(
    review_items: List[Dict[str, Any]],
    evidence_by_shift: Dict[int, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    output = []
    for item in review_items:
        evidence = _utilization_review_evidence(item, evidence_by_shift)
        output.append(
            {
                **item,
                "reviewKey": _utilization_review_key(item),
                "evidenceVersion": UTILIZATION_EVIDENCE_VERSION,
                "evidenceFingerprint": _utilization_evidence_fingerprint(evidence),
                "_evidenceSnapshot": evidence,
            }
        )
    return output


def _utilization_correction_rows(
    review_keys: Iterable[str],
    *,
    cursor: Any = None,
) -> List[Dict[str, Any]]:
    keys = sorted({str(value) for value in review_keys if value})
    if not keys:
        return []
    sql = """
        SELECT id, plan_token, applied_by_employee_id, applied_by_name,
               reason, snapshot, result, created_at
        FROM time_data_correction_batches
        WHERE snapshot ->> 'correctionType' = %s
          AND snapshot ->> 'reviewKey' = ANY(%s)
        ORDER BY id
    """
    params = (UTILIZATION_MISSING_DEPARTURE_CORRECTION, keys)
    if cursor is None:
        return db.query_all(sql, params)
    cursor.execute(sql, params)
    return [dict(row) for row in cursor.fetchall()]


def _public_utilization_correction(row: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(row.get("result") or {})
    return {
        "batchId": int(row["id"]),
        "effectiveDepartureAt": result.get("effectiveDepartureAt"),
        "reviewedByEmployeeId": (
            int(row["applied_by_employee_id"])
            if row.get("applied_by_employee_id") is not None
            else None
        ),
        "reviewedByName": str(row.get("applied_by_name") or ""),
        "reason": str(row.get("reason") or ""),
        "reviewedAt": _utc_iso(row.get("created_at")),
    }


def _attach_utilization_correction_state(
    review_items: List[Dict[str, Any]],
    correction_rows: List[Dict[str, Any]],
) -> None:
    history_by_key: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in correction_rows:
        snapshot = dict(row.get("snapshot") or {})
        history_by_key[str(snapshot.get("reviewKey") or "")].append(row)

    for item in review_items:
        history = history_by_key.get(str(item["reviewKey"]), [])
        matching = [
            row
            for row in history
            if str((row.get("snapshot") or {}).get("evidenceFingerprint") or "")
            == str(item["evidenceFingerprint"])
        ]
        current = matching[-1] if matching else None
        if current is not None:
            state = "corrected"
        elif history:
            state = "reopened"
        else:
            state = "open"
        item["reviewState"] = state
        item["hasOpenReview"] = current is None
        item["canCorrect"] = item.get("code") == "missing_departure"
        item["correctionPath"] = (
            "/admin/operations/utilization/reviews/"
            f"{item['reviewKey']}/missing-departure"
            if item["canCorrect"]
            else None
        )
        item["correction"] = (
            _public_utilization_correction(current) if current is not None else None
        )
        item["previousCorrection"] = (
            _public_utilization_correction(history[-1])
            if current is None and history
            else None
        )
        item["correctionHistoryCount"] = len(history)
        item["_currentCorrection"] = current


def _reviewed_departure_overlay(row: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(row.get("result") or {})
    timestamp = datetime.fromisoformat(
        str(result["effectiveDepartureAt"]).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    return {
        "id": None,
        "shift_id": int(result["shiftId"]),
        "visit_id": int(result["visitId"]),
        "location_id": int(result["locationId"]),
        "location_label": str(result.get("locationLabel") or ""),
        "departure_time": timestamp,
        "reviewed_correction_id": int(row["id"]),
    }


def _utilization_review_item(
    shift: Dict[str, Any],
    *,
    code: str,
    message: str,
    visit: Optional[Dict[str, Any]] = None,
    departure: Optional[Dict[str, Any]] = None,
    occurred_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    return {
        "shiftId": int(shift["id"]),
        "employeeId": int(shift["employee_id"]),
        "employeeName": str(shift["employee_name"]),
        "code": code,
        "message": message,
        "visitId": (
            int(visit["id"]) if visit is not None and visit.get("id") is not None else None
        ),
        "siteCheckInId": (
            int(visit["site_check_in_id"])
            if visit is not None and visit.get("site_check_in_id") is not None
            else None
        ),
        "departureId": (
            int(departure["id"])
            if departure is not None and departure.get("id") is not None
            else None
        ),
        "occurredAt": occurred_at,
    }


def _utilization_segment(
    shift: Dict[str, Any],
    *,
    category: str,
    start_second: int,
    end_second: int,
    category_detail: Optional[str] = None,
    location_id: Optional[int] = None,
    location_label: str = "",
    job_id: Optional[int] = None,
    visit_id: Optional[int] = None,
    departure_id: Optional[int] = None,
    from_location_id: Optional[int] = None,
    to_location_id: Optional[int] = None,
    from_job_id: Optional[int] = None,
    to_job_id: Optional[int] = None,
    evidence: Optional[List[str]] = None,
    review_codes: Optional[Iterable[str]] = None,
    correction_id: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "shift_id": int(shift["id"]),
        "employee_id": int(shift["employee_id"]),
        "employee_name": str(shift["employee_name"]),
        "category": category,
        "category_detail": category_detail,
        "start_second": start_second,
        "end_second": end_second,
        "location_id": location_id,
        "location_label": location_label,
        "job_id": job_id,
        "visit_id": visit_id,
        "departure_id": departure_id,
        "from_location_id": from_location_id,
        "to_location_id": to_location_id,
        "from_job_id": from_job_id,
        "to_job_id": to_job_id,
        "evidence": evidence or ["paid_shift"],
        "review_codes": sorted(set(review_codes or ())),
        "correction_id": correction_id,
    }


def _closed_shift_utilization(
    shift: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
    reviewed_departures: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Partition one closed paid envelope without inferring missing events."""

    clock_out = shift.get("clock_out")
    if clock_out is None:
        return [], [
            _utilization_review_item(
                shift,
                code="open_shift",
                message="This shift is still open and is excluded from finalized totals.",
                occurred_at=shift["clock_in"],
            )
        ]

    shift_start = _epoch_second(shift["clock_in"])
    shift_end = _epoch_second(clock_out)
    if shift_end <= shift_start:
        return [], [
            _utilization_review_item(
                shift,
                code="invalid_paid_interval",
                message="Clock Out must be later than Clock In.",
                occurred_at=shift["clock_in"],
            )
        ]

    time_category = str(shift.get("time_category") or "productive")
    if time_category == "non_productive":
        subtype = str(shift.get("non_productive_type") or "").strip()
        if subtype:
            return [
                _utilization_segment(
                    shift,
                    category="categorized",
                    category_detail=subtype,
                    start_second=shift_start,
                    end_second=shift_end,
                    location_id=shift.get("location_id"),
                    location_label=str(shift.get("location_label") or ""),
                    job_id=shift.get("job_id"),
                    evidence=["paid_shift", "shift_category"],
                )
            ], []
        issue = _utilization_review_item(
            shift,
            code="missing_non_productive_type",
            message="This non-productive shift has no category subtype.",
            occurred_at=shift["clock_in"],
        )
        return [
            _utilization_segment(
                shift,
                category="unclassified",
                start_second=shift_start,
                end_second=shift_end,
                evidence=["paid_shift", "shift_category"],
                review_codes=[issue["code"]],
            )
        ], [issue]

    review_items: List[Dict[str, Any]] = []
    visit_by_id = {int(row["id"]): row for row in visits}
    departures_by_visit: Dict[int, Dict[str, Any]] = {}
    for departure in departures:
        visit_id = departure.get("visit_id")
        if visit_id is None:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="legacy_unpaired_departure",
                    message="A legacy departure is not paired to an explicit arrival.",
                    departure=departure,
                    occurred_at=departure["departure_time"],
                )
            )
            continue
        normalized_visit_id = int(visit_id)
        if normalized_visit_id not in visit_by_id:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="orphan_departure",
                    message="A departure references an arrival outside this shift.",
                    departure=departure,
                    occurred_at=departure["departure_time"],
                )
            )
            continue
        departures_by_visit[normalized_visit_id] = departure

    reviewed_departures = reviewed_departures or {}
    valid_arrivals: List[Dict[str, Any]] = []
    pair_candidates: List[Dict[str, Any]] = []
    for visit in visits:
        sequence_version = int(visit.get("sequence_version") or 1)
        arrival_second = _epoch_second(visit["arrival_time"])
        if sequence_version < 2:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="legacy_visit_evidence",
                    message="A legacy arrival has no authoritative paired duration.",
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue
        if visit.get("site_check_in_id") is not None and not (
            (
                visit.get("check_in_classification") in {"on_time", "late"}
                and visit.get("check_in_review_status") == "not_required"
            )
            or (
                visit.get("check_in_classification") == "needs_review"
                and visit.get("check_in_review_status") == "approved"
            )
        ):
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="unaccepted_site_check_in",
                    message=(
                        "A linked QR check-in is pending review, rejected, or "
                        "otherwise not accepted."
                    ),
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue
        if not (shift_start <= arrival_second < shift_end):
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="arrival_outside_paid_shift",
                    message="An arrival falls outside the paid shift envelope.",
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue
        if visit.get("location_id") is None:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="arrival_missing_site",
                    message="An arrival has no Site identity.",
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue
        if visit.get("site_check_in_id") is not None and not (
            visit.get("check_in_employee_id") is not None
            and int(visit["check_in_employee_id"]) == int(shift["employee_id"])
            and visit.get("check_in_location_id") is not None
            and int(visit["check_in_location_id"]) == int(visit["location_id"])
            and visit.get("check_in_at") is not None
            and _epoch_second(visit["check_in_at"]) == arrival_second
        ):
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="site_check_in_identity_mismatch",
                    message=(
                        "A linked QR check-in does not match this employee, Site, "
                        "and arrival time."
                    ),
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue

        arrival = {
            "visit": visit,
            "start_second": arrival_second,
            "location_id": int(visit["location_id"]),
            "job_id": (
                int(visit["job_id"]) if visit.get("job_id") is not None else None
            ),
        }
        valid_arrivals.append(arrival)
        departure = departures_by_visit.get(int(visit["id"])) or reviewed_departures.get(
            int(visit["id"])
        )
        if departure is None:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="missing_departure",
                    message="An explicit arrival has no paired departure.",
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )
            continue

        departure_second = _epoch_second(departure["departure_time"])
        if not (arrival_second < departure_second <= shift_end):
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="invalid_departure_order",
                    message="A paired departure is not after its arrival inside the shift.",
                    visit=visit,
                    departure=departure,
                    occurred_at=departure["departure_time"],
                )
            )
            continue
        if (
            departure.get("location_id") is None
            or int(departure["location_id"]) != int(visit["location_id"])
        ):
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="departure_site_mismatch",
                    message="A paired departure does not match its arrival Site.",
                    visit=visit,
                    departure=departure,
                    occurred_at=departure["departure_time"],
                )
            )
            continue
        pair_candidates.append(
            {
                **arrival,
                "departure": departure,
                "end_second": departure_second,
            }
        )

    valid_arrivals.sort(
        key=lambda row: (row["start_second"], int(row["visit"]["id"]))
    )
    pair_candidates.sort(
        key=lambda row: (
            row["start_second"],
            row["end_second"],
            int(row["visit"]["id"]),
        )
    )

    arrival_evidence_by_second: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for visit in visits:
        arrival_second = _epoch_second(visit["arrival_time"])
        if (
            shift_start <= arrival_second < shift_end
            and visit.get("location_id") is not None
        ):
            arrival_evidence_by_second[arrival_second].append(visit)
    simultaneous_conflict_ids: set[int] = set()
    for simultaneous_arrivals in arrival_evidence_by_second.values():
        evidence_targets = {
            (int(visit["location_id"]), visit.get("job_id"))
            for visit in simultaneous_arrivals
        }
        if len(evidence_targets) <= 1:
            continue
        simultaneous_conflict_ids.update(
            int(visit["id"]) for visit in simultaneous_arrivals
        )
        for visit in simultaneous_arrivals:
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="simultaneous_arrival_conflict",
                    message=(
                        "Simultaneous arrivals point to different Sites or service "
                        "occurrences."
                    ),
                    visit=visit,
                    occurred_at=visit["arrival_time"],
                )
            )

    conflicted_visit_ids: set[int] = set(simultaneous_conflict_ids)
    for index, left in enumerate(pair_candidates):
        for right in pair_candidates[index + 1 :]:
            if right["start_second"] >= left["end_second"]:
                break
            if (
                left["start_second"] < right["end_second"]
                and right["start_second"] < left["end_second"]
            ):
                conflicted_visit_ids.update(
                    (int(left["visit"]["id"]), int(right["visit"]["id"]))
                )
    classification_departures = [
        *departures,
        *[
            row
            for visit_id, row in reviewed_departures.items()
            if visit_id not in departures_by_visit
        ],
    ]
    all_arrivals = [
        (int(visit["id"]), _epoch_second(visit["arrival_time"])) for visit in visits
    ]
    for candidate in pair_candidates:
        candidate_visit_id = int(candidate["visit"]["id"])
        contains_other_arrival = any(
            visit_id != candidate_visit_id
            and candidate["start_second"]
            <= arrival_second
            < candidate["end_second"]
            for visit_id, arrival_second in all_arrivals
        )
        contains_other_departure = any(
            departure is not candidate["departure"]
            and candidate["start_second"]
            < _epoch_second(departure["departure_time"])
            <= candidate["end_second"]
            for departure in classification_departures
        )
        if contains_other_arrival or contains_other_departure:
            conflicted_visit_ids.add(candidate_visit_id)

    if conflicted_visit_ids:
        for candidate in pair_candidates:
            if int(candidate["visit"]["id"]) not in conflicted_visit_ids:
                continue
            review_items.append(
                _utilization_review_item(
                    shift,
                    code="overlapping_site_evidence",
                    message="Overlapping Site events cannot be classified safely.",
                    visit=candidate["visit"],
                    departure=candidate["departure"],
                    occurred_at=candidate["visit"]["arrival_time"],
                )
            )

    usable_pairs = [
        candidate
        for candidate in pair_candidates
        if int(candidate["visit"]["id"]) not in conflicted_visit_ids
    ]
    usable_arrivals = [
        arrival
        for arrival in valid_arrivals
        if int(arrival["visit"]["id"]) not in simultaneous_conflict_ids
    ]
    claims: List[Dict[str, Any]] = []
    for candidate in usable_pairs:
        correction_id = candidate["departure"].get("reviewed_correction_id")
        claims.append(
            _utilization_segment(
                shift,
                category="on_site",
                start_second=candidate["start_second"],
                end_second=candidate["end_second"],
                location_id=candidate["location_id"],
                location_label=str(candidate["visit"].get("location_label") or ""),
                job_id=candidate["job_id"],
                visit_id=int(candidate["visit"]["id"]),
                departure_id=(
                    int(candidate["departure"]["id"])
                    if candidate["departure"].get("id") is not None
                    else None
                ),
                evidence=(
                    ["visit_v2", "reviewed_departure"]
                    if correction_id is not None
                    else ["visit_v2", "paired_departure"]
                ),
                correction_id=(
                    int(correction_id) if correction_id is not None else None
                ),
            )
        )

    all_event_seconds = [
        _epoch_second(visit["arrival_time"]) for visit in visits
    ] + [
        _epoch_second(departure["departure_time"])
        for departure in classification_departures
    ]
    for candidate in usable_pairs:
        departure_second = candidate["end_second"]
        next_arrival = next(
            (
                arrival
                for arrival in usable_arrivals
                if int(arrival["visit"]["id"]) != int(candidate["visit"]["id"])
                and arrival["start_second"] >= departure_second
            ),
            None,
        )
        if next_arrival is None or next_arrival["start_second"] <= departure_second:
            continue
        if next_arrival["location_id"] == candidate["location_id"]:
            continue
        if any(
            departure_second < event_second < next_arrival["start_second"]
            for event_second in all_event_seconds
        ):
            continue
        if any(
            _epoch_second(departure["departure_time"])
            == next_arrival["start_second"]
            for departure in classification_departures
        ):
            continue
        correction_id = candidate["departure"].get("reviewed_correction_id")
        claims.append(
            _utilization_segment(
                shift,
                category="travel",
                start_second=departure_second,
                end_second=next_arrival["start_second"],
                from_location_id=candidate["location_id"],
                to_location_id=next_arrival["location_id"],
                from_job_id=candidate["job_id"],
                to_job_id=next_arrival["job_id"],
                visit_id=int(next_arrival["visit"]["id"]),
                departure_id=(
                    int(candidate["departure"]["id"])
                    if candidate["departure"].get("id") is not None
                    else None
                ),
                evidence=(
                    ["reviewed_departure", "next_visit_v2"]
                    if correction_id is not None
                    else ["paired_departure", "next_visit_v2"]
                ),
                correction_id=(
                    int(correction_id) if correction_id is not None else None
                ),
            )
        )

    claims.sort(
        key=lambda row: (
            row["start_second"],
            row["end_second"],
            row["category"],
            row.get("visit_id") or 0,
        )
    )
    overlapping_claim_indexes: set[int] = set()
    for index, left in enumerate(claims):
        for right_index in range(index + 1, len(claims)):
            right = claims[right_index]
            if right["start_second"] >= left["end_second"]:
                break
            overlapping_claim_indexes.update((index, right_index))
    if overlapping_claim_indexes:
        review_items.append(
            _utilization_review_item(
                shift,
                code="classification_overlap",
                message="Contradictory events produced overlapping measured intervals.",
                occurred_at=shift["clock_in"],
            )
        )
        claims = [
            claim
            for index, claim in enumerate(claims)
            if index not in overlapping_claim_indexes
        ]

    issue_codes = {item["code"] for item in review_items}
    output: List[Dict[str, Any]] = []
    cursor = shift_start
    for claim in claims:
        if claim["start_second"] > cursor:
            output.append(
                _utilization_segment(
                    shift,
                    category="unclassified",
                    start_second=cursor,
                    end_second=claim["start_second"],
                    evidence=["paid_shift"],
                    review_codes=issue_codes,
                )
            )
        output.append(claim)
        cursor = max(cursor, claim["end_second"])
    if cursor < shift_end:
        output.append(
            _utilization_segment(
                shift,
                category="unclassified",
                start_second=cursor,
                end_second=shift_end,
                evidence=["paid_shift"],
                review_codes=issue_codes,
            )
        )
    return output, review_items


def _split_utilization_segment(
    segment: Dict[str, Any],
    *,
    range_start: datetime,
    range_end: datetime,
    app_timezone: ZoneInfo,
) -> List[Dict[str, Any]]:
    range_start_second = _epoch_second(range_start)
    range_end_second = _epoch_second(range_end)
    cursor = max(int(segment["start_second"]), range_start_second)
    clipped_end = min(int(segment["end_second"]), range_end_second)
    output: List[Dict[str, Any]] = []
    while cursor < clipped_end:
        local_day = _second_datetime(cursor).astimezone(app_timezone).date()
        next_midnight = datetime.combine(
            local_day + timedelta(days=1),
            time.min,
            tzinfo=app_timezone,
        ).astimezone(timezone.utc)
        piece_end = min(clipped_end, _epoch_second(next_midnight))
        output.append(
            {
                **segment,
                "date": local_day,
                "start_second": cursor,
                "end_second": piece_end,
            }
        )
        cursor = piece_end
    return output


def _collapse_overlapping_paid_segments(
    segments: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Count overlapping paid records once and keep the overlap unclassified."""

    grouped: Dict[Tuple[int, date], List[Dict[str, Any]]] = defaultdict(list)
    for segment in segments:
        grouped[(int(segment["employee_id"]), segment["date"])].append(segment)

    output: List[Dict[str, Any]] = []
    for group in grouped.values():
        boundaries = sorted(
            {
                int(segment[boundary])
                for segment in group
                for boundary in ("start_second", "end_second")
            }
        )
        pieces: List[Dict[str, Any]] = []
        for start_second, end_second in zip(boundaries, boundaries[1:]):
            covering = [
                segment
                for segment in group
                if int(segment["start_second"]) <= start_second
                and int(segment["end_second"]) >= end_second
            ]
            if not covering:
                continue
            shift_ids = sorted({int(segment["shift_id"]) for segment in covering})
            if len(covering) == 1:
                piece = {
                    **covering[0],
                    "start_second": start_second,
                    "end_second": end_second,
                }
            else:
                review_codes = {
                    code
                    for segment in covering
                    for code in segment.get("review_codes") or ()
                }
                review_codes.add("overlapping_paid_shifts")
                piece = {
                    **covering[0],
                    "shift_id": shift_ids[0],
                    "related_shift_ids": shift_ids,
                    "category": "unclassified",
                    "category_detail": None,
                    "start_second": start_second,
                    "end_second": end_second,
                    "location_id": None,
                    "location_label": "",
                    "job_id": None,
                    "visit_id": None,
                    "departure_id": None,
                    "from_location_id": None,
                    "to_location_id": None,
                    "from_job_id": None,
                    "to_job_id": None,
                    "evidence": ["overlapping_paid_shifts"],
                    "review_codes": sorted(review_codes),
                    "correction_id": None,
                }
            if (
                pieces
                and pieces[-1]["end_second"] == piece["start_second"]
                and {
                    key: value
                    for key, value in pieces[-1].items()
                    if key not in {"start_second", "end_second"}
                }
                == {
                    key: value
                    for key, value in piece.items()
                    if key not in {"start_second", "end_second"}
                }
            ):
                pieces[-1]["end_second"] = piece["end_second"]
            else:
                pieces.append(piece)
        output.extend(pieces)

    overlap_segments = [
        segment
        for segment in output
        if "overlapping_paid_shifts" in segment.get("review_codes", [])
    ]
    review_items = [
        {
            "shiftId": int(segment["shift_id"]),
            "relatedShiftIds": list(segment["related_shift_ids"]),
            "employeeId": int(segment["employee_id"]),
            "employeeName": str(segment["employee_name"]),
            "code": "overlapping_paid_shifts",
            "message": "Overlapping paid shifts were counted once and left unclassified.",
            "visitId": None,
            "departureId": None,
            "occurredAt": _second_datetime(int(segment["start_second"])),
        }
        for segment in overlap_segments
    ]
    return output, review_items


def _allocate_utilization_minutes(segments: List[Dict[str, Any]]) -> None:
    """Allocate whole display minutes without breaking exact reconciliation."""

    if not segments:
        return
    durations = [
        int(segment["end_second"]) - int(segment["start_second"])
        for segment in segments
    ]
    total_minutes = (sum(durations) + 30) // 60
    allocated = [duration // 60 for duration in durations]
    remainder_count = total_minutes - sum(allocated)
    order = sorted(
        range(len(segments)),
        key=lambda index: (
            -(durations[index] % 60),
            int(segments[index]["start_second"]),
            int(segments[index]["end_second"]),
            int(segments[index]["shift_id"]),
            str(segments[index]["category"]),
        ),
    )
    for index in order[:remainder_count]:
        allocated[index] += 1
    for segment, duration, minutes in zip(segments, durations, allocated):
        segment["duration_seconds"] = duration
        segment["duration_minutes"] = minutes


def _utilization_totals(segments: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(segments)
    paid_seconds = sum(int(row["duration_seconds"]) for row in rows)
    paid_minutes = sum(int(row["duration_minutes"]) for row in rows)
    seconds_by_category = {
        category: sum(
            int(row["duration_seconds"])
            for row in rows
            if row["category"] == category
        )
        for category in UTILIZATION_CATEGORIES
    }
    minutes_by_category = {
        category: sum(
            int(row["duration_minutes"])
            for row in rows
            if row["category"] == category
        )
        for category in UTILIZATION_CATEGORIES
    }
    return {
        "paidSeconds": paid_seconds,
        "onSiteSeconds": seconds_by_category["on_site"],
        "travelSeconds": seconds_by_category["travel"],
        "categorizedSeconds": seconds_by_category["categorized"],
        "unclassifiedSeconds": seconds_by_category["unclassified"],
        "paidMinutes": paid_minutes,
        "onSiteMinutes": minutes_by_category["on_site"],
        "travelMinutes": minutes_by_category["travel"],
        "categorizedMinutes": minutes_by_category["categorized"],
        "unclassifiedMinutes": minutes_by_category["unclassified"],
        "reconciles": (
            paid_seconds == sum(seconds_by_category.values())
            and paid_minutes == sum(minutes_by_category.values())
        ),
    }


def _serialize_utilization_interval(segment: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "shiftId": int(segment["shift_id"]),
        "relatedShiftIds": list(
            segment.get("related_shift_ids") or [int(segment["shift_id"])]
        ),
        "category": segment["category"],
        "categoryDetail": segment.get("category_detail"),
        "intervalStart": _utc_iso(_second_datetime(segment["start_second"])),
        "intervalEnd": _utc_iso(_second_datetime(segment["end_second"])),
        "durationSeconds": int(segment["duration_seconds"]),
        "durationMinutes": int(segment["duration_minutes"]),
        "locationId": segment.get("location_id"),
        "locationLabel": segment.get("location_label") or "",
        "jobId": segment.get("job_id"),
        "visitId": segment.get("visit_id"),
        "departureId": segment.get("departure_id"),
        "fromLocationId": segment.get("from_location_id"),
        "toLocationId": segment.get("to_location_id"),
        "fromJobId": segment.get("from_job_id"),
        "toJobId": segment.get("to_job_id"),
        "evidence": list(segment.get("evidence") or []),
        "reviewCodes": list(segment.get("review_codes") or []),
        "correctionId": segment.get("correction_id"),
    }


def _utilization_rows(segments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[int, date], List[Dict[str, Any]]] = defaultdict(list)
    for segment in segments:
        grouped[(int(segment["employee_id"]), segment["date"])].append(segment)

    rows: List[Dict[str, Any]] = []
    for (employee_id, local_day), group in grouped.items():
        ordered = sorted(
            group,
            key=lambda row: (
                int(row["start_second"]),
                int(row["end_second"]),
                int(row["shift_id"]),
                str(row["category"]),
            ),
        )
        _allocate_utilization_minutes(ordered)
        rows.append(
            {
                "employeeId": employee_id,
                "employeeName": str(ordered[0]["employee_name"]),
                "date": str(local_day),
                **_utilization_totals(ordered),
                "intervals": [
                    _serialize_utilization_interval(segment) for segment in ordered
                ],
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["date"],
            row["employeeName"].casefold(),
            row["employeeId"],
        ),
    )


def _serialize_utilization_review_item(
    item: Dict[str, Any],
    app_timezone: ZoneInfo,
) -> Dict[str, Any]:
    occurred_at = item.get("occurredAt")
    return {
        **{
            key: value
            for key, value in item.items()
            if key != "occurredAt" and not key.startswith("_")
        },
        "date": (
            str(occurred_at.astimezone(app_timezone).date())
            if occurred_at is not None
            else None
        ),
        "occurredAt": _utc_iso(occurred_at),
    }


def _qr_only_presence_segments(
    qr_rows: List[Dict[str, Any]],
    represented_segments: List[Dict[str, Any]],
    observed_at: datetime,
    represented_qr_ids: Optional[Iterable[int]] = None,
) -> List[Dict[str, Any]]:
    """Keep Site presence not represented by a same-Site productive segment."""

    represented_ids = {int(check_in_id) for check_in_id in (represented_qr_ids or ())}
    segments_by_employee_site: Dict[Tuple[int, int], List[Dict[str, Any]]] = (
        defaultdict(list)
    )
    for segment in represented_segments:
        location_id = segment.get("location_id")
        if location_id is None:
            continue
        segments_by_employee_site[
            (int(segment["employee_id"]), int(location_id))
        ].append(segment)

    output: List[Dict[str, Any]] = []
    for row in qr_rows:
        employee_id = int(row["employee_id"])
        location_id = int(row["location_id"])
        checked_in_at = row["server_checked_in_at"]
        if row.get("job_id") is not None:
            covered_by_segment = (
                row.get("id") is not None and int(row["id"]) in represented_ids
            )
        else:
            covered_by_segment = any(
                segment["start"] <= checked_in_at
                and (segment.get("end") or observed_at) > checked_in_at
                for segment in segments_by_employee_site.get(
                    (employee_id, location_id), []
                )
            )
        if covered_by_segment:
            continue
        output.append(
            {
                "shift_id": None,
                "job_id": row.get("job_id"),
                "employee_id": employee_id,
                "employee_name": str(row["employee_name"]),
                "hourly_rate": row.get("hourly_rate"),
                "location_id": location_id,
                "location_label": str(row.get("location_label") or ""),
                "start": checked_in_at,
                "end": checked_in_at + timedelta(microseconds=1),
                "finalized": False,
                "in_progress": False,
                "presence_only": True,
                "evidence": ["qr_check_in"],
                "unassigned_gap": False,
                "qr_job_conflict_ids": row.get("qr_job_conflict_ids"),
            }
        )
    return output


def _job_link_applies_to_segment(
    segment: Dict[str, Any],
    job_id: int,
    linked_jobs_by_id: Dict[int, Dict[str, Any]],
) -> bool:
    """Mirror direct-link Site applicability without weakening unavailable links."""

    linked_job = linked_jobs_by_id.get(job_id)
    if linked_job is None:
        return True
    segment_location_id = segment.get("location_id")
    linked_location_id = linked_job.get("location_id")
    return bool(
        segment_location_id is None
        or linked_location_id is None
        or int(segment_location_id) == int(linked_location_id)
    )


def _add_qr_evidence(segment: Dict[str, Any]) -> None:
    raw_evidence = segment.get("evidence")
    if isinstance(raw_evidence, list):
        evidence = list(raw_evidence)
    elif raw_evidence == "unassigned_gap":
        evidence = ["shift"]
    elif raw_evidence:
        evidence = [str(raw_evidence)]
    else:
        evidence = ["shift"]
    if "qr_check_in" not in evidence:
        evidence.append("qr_check_in")
    segment["evidence"] = evidence


def _unique_visible_qr_shift_ids(
    shifts: List[Dict[str, Any]],
    qr_rows: List[Dict[str, Any]],
    visible_job_ids: Iterable[int],
    observed_at: datetime,
) -> set[int]:
    """Find cross-boundary shifts selected by exactly one visible-job QR."""

    visible_ids = {int(job_id) for job_id in visible_job_ids}
    selected: set[int] = set()
    for row in qr_rows:
        job_id = row.get("job_id")
        if job_id is None or int(job_id) not in visible_ids:
            continue
        checked_in_at = row["server_checked_in_at"]
        employee_id = int(row["employee_id"])
        candidates = [
            shift
            for shift in shifts
            if int(shift["employee_id"]) == employee_id
            and shift["clock_in"] <= checked_in_at
            and (shift.get("clock_out") or observed_at) > checked_in_at
        ]
        if len(candidates) == 1:
            selected.add(int(candidates[0]["id"]))
    return selected


def _apply_qr_job_links(
    qr_rows: List[Dict[str, Any]],
    represented_segments: List[Dict[str, Any]],
    linked_jobs_by_id: Dict[int, Dict[str, Any]],
) -> set[int]:
    """Use one unambiguous durable QR pair to identify one atomic shift segment."""

    represented_qr_ids: set[int] = set()
    rows_by_segment: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    segments_by_identity: Dict[int, Dict[str, Any]] = {}
    for row in qr_rows:
        if row.get("job_id") is None:
            continue
        job_id = int(row["job_id"])
        linked_job = linked_jobs_by_id.get(job_id)
        if linked_job is not None and (
            linked_job.get("location_id") is None
            or int(linked_job["location_id"]) != int(row["location_id"])
        ):
            row["qr_job_conflict_ids"] = [job_id]
        employee_id = int(row["employee_id"])
        checked_in_at = row["server_checked_in_at"]
        candidates = [
            segment
            for segment in represented_segments
            if segment.get("shift_id") is not None
            and bool(segment.get("finalized"))
            and not bool(segment.get("presence_only"))
            and int(segment["employee_id"]) == employee_id
            and segment["start"] <= checked_in_at < segment["end"]
        ]
        if len(candidates) != 1:
            continue
        segment = candidates[0]
        segment_identity = id(segment)
        segments_by_identity[segment_identity] = segment
        rows_by_segment[segment_identity].append(row)

    for segment_identity, rows in rows_by_segment.items():
        segment = segments_by_identity[segment_identity]
        segment_location_id = segment.get("location_id")
        compatible_rows = [
            row
            for row in rows
            if segment_location_id is None
            or int(row["location_id"]) == int(segment_location_id)
        ]
        if not compatible_rows:
            continue

        existing_job_id = segment.get("job_id")
        if existing_job_id is not None and _job_link_applies_to_segment(
            segment,
            int(existing_job_id),
            linked_jobs_by_id,
        ):
            corroborating = [
                row
                for row in compatible_rows
                if int(row["job_id"]) == int(existing_job_id)
                and not row.get("qr_job_conflict_ids")
            ]
            if not corroborating:
                continue
            if segment_location_id is None:
                segment["location_id"] = int(corroborating[0]["location_id"])
                segment["location_label"] = str(
                    corroborating[0].get("location_label") or ""
                )
                segment["unassigned_gap"] = False
            _add_qr_evidence(segment)
            represented_qr_ids.update(
                int(row["id"]) for row in corroborating if row.get("id") is not None
            )
            continue

        invalid_rows = [
            row for row in compatible_rows if row.get("qr_job_conflict_ids")
        ]
        if invalid_rows:
            segment["qr_job_conflict_ids"] = sorted(
                {int(row["job_id"]) for row in compatible_rows}
            )
            continue

        distinct_pairs = {
            (int(row["location_id"]), int(row["job_id"])) for row in compatible_rows
        }
        if len(distinct_pairs) != 1:
            segment["qr_job_conflict_ids"] = sorted(
                {job_id for _, job_id in distinct_pairs}
            )
            continue

        location_id, job_id = next(iter(distinct_pairs))
        segment["location_id"] = location_id
        segment["location_label"] = str(
            next(
                (
                    row.get("location_label")
                    for row in compatible_rows
                    if int(row["location_id"]) == location_id
                ),
                "",
            )
            or ""
        )
        segment["job_id"] = job_id
        segment["unassigned_gap"] = False
        _add_qr_evidence(segment)
        represented_qr_ids.update(
            int(row["id"]) for row in compatible_rows if row.get("id") is not None
        )
    return represented_qr_ids


def _apply_shift_break_minutes_to_segments(
    segments: List[Dict[str, Any]],
    break_minutes: int,
) -> List[Dict[str, Any]]:
    remaining_seconds = max(0, int(break_minutes)) * 60
    if remaining_seconds <= 0:
        return segments
    duration_segments = [
        segment
        for segment in segments
        if segment["end"] > segment["start"]
    ]
    located_site_ids = {
        int(segment["location_id"])
        for segment in duration_segments
        if segment.get("location_id") is not None
    }
    job_ids = {
        int(segment["job_id"])
        for segment in duration_segments
        if segment.get("job_id") is not None
    }
    has_unallocated_time = any(
        segment.get("location_id") is None
        for segment in duration_segments
    )
    has_unallocated_job = any(
        segment.get("job_id") is None
        for segment in duration_segments
    )
    if (
        has_unallocated_time
        or len(located_site_ids) != 1
        or has_unallocated_job
        or len(job_ids) != 1
    ):
        return segments

    adjusted: List[Dict[str, Any]] = []
    for segment in reversed(segments):
        segment_copy = dict(segment)
        duration_seconds = max(
            int((segment_copy["end"] - segment_copy["start"]).total_seconds()),
            0,
        )
        deducted_seconds = min(duration_seconds, remaining_seconds)
        remaining_seconds -= deducted_seconds
        if deducted_seconds >= duration_seconds:
            continue
        if deducted_seconds > 0:
            segment_copy["end"] = segment_copy["end"] - timedelta(
                seconds=deducted_seconds,
            )
        adjusted.append(segment_copy)
    adjusted.reverse()
    return adjusted


def _closed_shift_segments(
    shift: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
    qr_by_employee_site: Dict[Tuple[int, int], List[datetime]],
    range_start: datetime,
    range_end: datetime,
) -> List[Dict[str, Any]]:
    clock_in = shift["clock_in"]
    clock_out = shift["clock_out"]
    if clock_out is None or clock_out <= clock_in:
        return []

    lower = max(clock_in, range_start)
    upper = min(clock_out, range_end)
    if upper <= lower:
        return []

    common = {
        "shift_id": int(shift["id"]),
        "job_id": shift.get("job_id"),
        "employee_id": int(shift["employee_id"]),
        "employee_name": str(shift["employee_name"]),
        "hourly_rate": shift.get("hourly_rate"),
        "payroll_break_minutes": int(shift.get("payroll_break_minutes") or 0),
        "finalized": True,
    }

    def evidence_for(
        base_evidence: str,
        location_id: Optional[int],
        start: datetime,
        end: datetime,
    ) -> List[str]:
        evidence = [base_evidence]
        if location_id is None:
            return evidence
        check_ins = qr_by_employee_site.get(
            (int(shift["employee_id"]), int(location_id)),
            [],
        )
        if any(start <= checked_in_at < end for checked_in_at in check_ins):
            evidence.append("qr_check_in")
        return evidence

    output: List[Dict[str, Any]] = []

    def append_interval(
        *,
        location_id: Optional[int],
        location_label: str,
        start: datetime,
        end: datetime,
        base_evidence: str,
    ) -> None:
        if end <= start:
            return
        unassigned = location_id is None
        output.append(
            {
                **common,
                "location_id": location_id,
                "location_label": location_label,
                "start": start,
                "end": end,
                "evidence": (
                    "unassigned_gap"
                    if unassigned
                    else evidence_for(base_evidence, location_id, start, end)
                ),
                "unassigned_gap": unassigned,
                "presence_only": False,
            }
        )

    def initial_site_departure(before: datetime) -> Optional[Dict[str, Any]]:
        initial_location_id = shift.get("location_id")
        if initial_location_id is None:
            return None
        return next(
            (
                departure
                for departure in departures
                if departure.get("location_id") == initial_location_id
                and clock_in <= departure["departure_time"] <= before
            ),
            None,
        )

    if not visits:
        initial_location_id = shift.get("location_id")
        initial_departure = initial_site_departure(clock_out)
        initial_end = (
            initial_departure["departure_time"]
            if initial_departure is not None
            else clock_out
        )
        append_interval(
            location_id=initial_location_id,
            location_label=str(shift.get("location_label") or ""),
            start=lower,
            end=min(initial_end, upper),
            base_evidence="shift",
        )
        if initial_departure is not None:
            append_interval(
                location_id=None,
                location_label="",
                start=max(initial_end, lower),
                end=upper,
                base_evidence="unassigned_gap",
            )
        return output

    cursor = lower
    used_departures: set[int] = set()
    for index, visit in enumerate(visits):
        arrival = max(visit["arrival_time"], clock_in)
        if arrival >= clock_out:
            continue
        next_arrival = (
            min(visits[index + 1]["arrival_time"], clock_out)
            if index + 1 < len(visits)
            else clock_out
        )
        matching_departure: Optional[Dict[str, Any]] = None
        visit_site_id = visit.get("location_id")
        sequence_version = int(visit.get("sequence_version") or 1)
        if sequence_version >= 2:
            matching_departure = next(
                (
                    departure
                    for departure in departures
                    if departure.get("visit_id") is not None
                    and int(departure["visit_id"]) == int(visit["id"])
                ),
                None,
            )
            if matching_departure is not None:
                used_departures.add(int(matching_departure["id"]))
        elif visit_site_id is not None:
            for departure in departures:
                if int(departure["id"]) in used_departures:
                    continue
                if departure.get("location_id") != visit_site_id:
                    continue
                if arrival <= departure["departure_time"] <= next_arrival:
                    matching_departure = departure
                    used_departures.add(int(departure["id"]))
                    break
        if matching_departure is not None:
            work_end = matching_departure["departure_time"]
        elif sequence_version >= 2:
            # A version-2 visit without its explicitly paired departure is
            # incomplete evidence, not permission to invent an end at the next
            # arrival or shift clock-out.
            work_end = arrival
        else:
            work_end = next_arrival

        visible_arrival = max(arrival, lower)
        if visible_arrival > cursor:
            initial_departure = initial_site_departure(arrival) if index == 0 else None
            initial_end = (
                initial_departure["departure_time"]
                if initial_departure is not None
                else visible_arrival
            )
            append_interval(
                location_id=shift.get("location_id") if index == 0 else None,
                location_label=(
                    str(shift.get("location_label") or "") if index == 0 else ""
                ),
                start=cursor,
                end=min(initial_end, visible_arrival, upper),
                base_evidence="shift",
            )
            if initial_departure is not None:
                used_departures.add(int(initial_departure["id"]))
                append_interval(
                    location_id=None,
                    location_label="",
                    start=max(initial_end, cursor),
                    end=min(visible_arrival, upper),
                    base_evidence="unassigned_gap",
                )

        segment_start = max(arrival, lower)
        segment_end = min(work_end, upper)
        append_interval(
            location_id=visit_site_id,
            location_label=str(visit.get("location_label") or ""),
            start=segment_start,
            end=segment_end,
            base_evidence="visit",
        )
        cursor = max(cursor, min(work_end, upper))
        if cursor >= upper:
            break

    if cursor < upper:
        append_interval(
            location_id=None,
            location_label="",
            start=cursor,
            end=upper,
            base_evidence="unassigned_gap",
        )
    return [segment for segment in output if segment["end"] > segment["start"]]


def _open_shift_presence(
    shift: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
    qr_by_employee_site: Dict[Tuple[int, int], List[datetime]],
    observed_at: datetime,
) -> Dict[str, Any]:
    current_site = shift.get("location_id")
    current_label = str(shift.get("location_label") or "")
    current_since = shift["clock_in"]
    evidence = ["clock_in"]
    current_visit_id: Optional[int] = None
    current_sequence_version = 1

    events: List[Tuple[datetime, int, Dict[str, Any]]] = []
    events.extend((row["arrival_time"], 0, row) for row in visits)
    events.extend((row["departure_time"], 1, row) for row in departures)
    for event_at, kind, row in sorted(events, key=lambda item: (item[0], item[1])):
        if event_at > observed_at:
            continue
        if kind == 0:
            current_site = row.get("location_id")
            current_label = str(row.get("location_label") or "")
            current_since = event_at
            evidence = ["clock_in", "visit"]
            current_visit_id = int(row["id"])
            current_sequence_version = int(row.get("sequence_version") or 1)
        else:
            paired_visit_id = row.get("visit_id")
            explicitly_closes_current = (
                paired_visit_id is not None
                and current_visit_id is not None
                and int(paired_visit_id) == current_visit_id
            )
            legacy_closes_current = (
                paired_visit_id is None
                and current_sequence_version == 1
                and current_site is not None
                and row.get("location_id") == current_site
            )
            if explicitly_closes_current or legacy_closes_current:
                current_site = None
                current_label = ""
                current_since = event_at
                evidence = ["clock_in", "departure"]
                current_visit_id = None
                current_sequence_version = 1

    if current_site is None:
        unknown_site_check_ins = _qr_sites_in_interval(
            qr_by_employee_site,
            employee_id=int(shift["employee_id"]),
            start=current_since,
            end=observed_at + timedelta(microseconds=1),
        )
        if unknown_site_check_ins:
            checked_in_at, current_site = unknown_site_check_ins[-1]
            current_since = checked_in_at
            evidence = ["clock_in", "qr_check_in"]
    else:
        qr_times = qr_by_employee_site.get(
            (int(shift["employee_id"]), int(current_site)),
            [],
        )
        if any(current_since <= qr_time <= observed_at for qr_time in qr_times):
            evidence.append("qr_check_in")

    return {
        "shift_id": int(shift["id"]),
        "job_id": shift.get("job_id"),
        "employee_id": int(shift["employee_id"]),
        "employee_name": str(shift["employee_name"]),
        "hourly_rate": shift.get("hourly_rate"),
        "location_id": current_site,
        "location_label": current_label,
        "start": current_since,
        "end": observed_at,
        "finalized": False,
        "in_progress": True,
        "presence_only": False,
        "evidence": evidence,
        "unassigned_gap": current_site is None,
    }


def _segment_candidate_dates(
    segment: Dict[str, Any],
    app_timezone: ZoneInfo,
) -> set[date]:
    start_date = segment["start"].astimezone(app_timezone).date()
    end_marker = segment["end"] - timedelta(microseconds=1)
    end_date = end_marker.astimezone(app_timezone).date()
    return {start_date, end_date}


def _match_segment_to_job(
    segment: Dict[str, Any],
    jobs_by_site_date: Dict[Tuple[int, date], List[Dict[str, Any]]],
    jobs_by_id: Dict[int, Dict[str, Any]],
    app_timezone: ZoneInfo,
    *,
    linked_jobs_by_id: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Tuple[Optional[Dict[str, Any]], str, List[int]]:
    linked_job_id = segment.get("job_id")
    if linked_job_id is not None:
        normalized_linked_job_id = int(linked_job_id)
        linked_job_lookup = (
            jobs_by_id if linked_jobs_by_id is None else linked_jobs_by_id
        )
        linked_job = linked_job_lookup.get(normalized_linked_job_id)
        if linked_job is None:
            return None, "linked_job_unavailable", [normalized_linked_job_id]
        segment_location_id = segment.get("location_id")
        linked_location_id = linked_job.get("location_id")
        link_applies_to_segment = (
            segment_location_id is None
            or linked_location_id is None
            or int(segment_location_id) == int(linked_location_id)
        )
        if link_applies_to_segment:
            if linked_job.get("status") == "cancelled":
                return None, "cancelled_job", [normalized_linked_job_id]
            visible_linked_job = jobs_by_id.get(normalized_linked_job_id)
            if visible_linked_job is not None:
                return visible_linked_job, "linked_shift", [normalized_linked_job_id]
            return None, "linked_job_outside_range", [normalized_linked_job_id]

    qr_job_conflict_ids = sorted(
        {int(job_id) for job_id in segment.get("qr_job_conflict_ids") or []}
    )
    if qr_job_conflict_ids:
        return None, "ambiguous_job", qr_job_conflict_ids

    location_id = segment.get("location_id")
    if location_id is None:
        reason = "unassigned_gap" if segment.get("unassigned_gap") else "missing_site"
        return None, reason, []

    all_candidates: Dict[int, Dict[str, Any]] = {}
    for local_day in _segment_candidate_dates(segment, app_timezone):
        for job in jobs_by_site_date.get((int(location_id), local_day), []):
            all_candidates[int(job["id"])] = job
    ordered = sorted(
        (job for job in all_candidates.values() if job.get("status") != "cancelled"),
        key=lambda row: int(row["id"]),
    )
    if not ordered:
        cancelled_ids = sorted(all_candidates)
        if cancelled_ids:
            return None, "cancelled_job", cancelled_ids
        return None, "no_scheduled_job", []

    overlapping: List[Dict[str, Any]] = []
    windowless: List[Dict[str, Any]] = []
    for job in ordered:
        scheduled_start = job.get("scheduled_start")
        scheduled_end = job.get("scheduled_end")
        has_valid_window = (
            scheduled_start is not None
            and scheduled_end is not None
            and scheduled_end > scheduled_start
        )
        if not has_valid_window:
            windowless.append(job)
        elif scheduled_start < segment["end"] and scheduled_end > segment["start"]:
            overlapping.append(job)

    eligible = overlapping or windowless
    if not eligible:
        return None, "no_scheduled_job", [int(job["id"]) for job in ordered]

    eligible_ids = [int(job["id"]) for job in eligible]
    if len(eligible) == 1:
        sole_candidate = eligible[0]
        match_reason = "unique_service_window" if overlapping else "unique_site_date"
        return sole_candidate, match_reason, eligible_ids
    return None, "ambiguous_job", eligible_ids


def _serialize_unmatched(
    segment: Dict[str, Any],
    reason: str,
    candidate_job_ids: List[int],
) -> Dict[str, Any]:
    finalized = bool(segment["finalized"])
    return {
        "shiftId": (
            int(segment["shift_id"]) if segment.get("shift_id") is not None else None
        ),
        "employeeId": int(segment["employee_id"]),
        "employeeName": segment["employee_name"],
        "locationId": segment.get("location_id"),
        "locationLabel": segment.get("location_label") or "",
        "intervalStart": _utc_iso(segment["start"]),
        "intervalEnd": _utc_iso(segment["end"]) if finalized else None,
        "hours": round(_hours(segment["start"], segment["end"]), 2)
        if finalized
        else None,
        "finalized": finalized,
        "presenceOnly": bool(segment.get("presence_only")),
        "reason": reason,
        "candidateJobIds": candidate_job_ids,
        "evidence": (
            segment["evidence"]
            if isinstance(segment["evidence"], list)
            else [segment["evidence"]]
        ),
    }


def _apply_resolved_shift_break_minutes(
    resolved_segments: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Deduct corrected breaks only after every shift segment has a job verdict."""

    if not resolved_segments:
        return resolved_segments

    indexed_segments: List[Dict[str, Any]] = []
    segments_by_shift_id: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for index, resolved in enumerate(resolved_segments):
        segment = dict(resolved["segment"])
        segment["_break_allocation_index"] = index
        indexed = {**resolved, "segment": segment}
        indexed_segments.append(indexed)

        shift_id = segment.get("shift_id")
        if shift_id is None:
            continue
        segments_by_shift_id[int(shift_id)].append(indexed)

    active_indices = set(range(len(indexed_segments)))
    adjusted_by_index: Dict[int, Dict[str, Any]] = {}
    for shift_segments in segments_by_shift_id.values():
        break_minutes = max(
            int(resolved["segment"].get("payroll_break_minutes") or 0)
            for resolved in shift_segments
        )
        if break_minutes <= 0:
            continue

        adjusted = _apply_shift_break_minutes_to_segments(
            [resolved["segment"] for resolved in shift_segments],
            break_minutes,
        )
        adjusted_indices = {
            int(segment["_break_allocation_index"]) for segment in adjusted
        }
        for segment in adjusted:
            adjusted_by_index[int(segment["_break_allocation_index"])] = segment
        for resolved in shift_segments:
            index = int(resolved["segment"]["_break_allocation_index"])
            if index not in adjusted_indices:
                active_indices.discard(index)

    output: List[Dict[str, Any]] = []
    for index, resolved in enumerate(indexed_segments):
        if index not in active_indices:
            continue
        segment = dict(adjusted_by_index.get(index, resolved["segment"]))
        segment.pop("_break_allocation_index", None)
        output.append({**resolved, "segment": segment})
    return output


def _decorate_schedule_jobs(
    jobs: List[Dict[str, Any]],
    range_start: datetime,
    range_end: datetime,
    observed_at: datetime,
    app_timezone: ZoneInfo,
    *,
    visible_range_start: Optional[datetime] = None,
    visible_range_end: Optional[datetime] = None,
    expected_hours_learning_by_site: Optional[Dict[int, Dict[str, Any]]] = None,
    payroll_week_start: Optional[date] = None,
    cursor: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[int, Optional[int]]]:
    jobs_by_site_date: Dict[Tuple[int, date], List[Dict[str, Any]]] = defaultdict(list)
    jobs_by_id = {int(job["id"]): job for job in jobs}
    for job in jobs:
        if job.get("location_id") is not None:
            service_dates = {job["scheduled_date"]}
            scheduled_start = job.get("scheduled_start")
            scheduled_end = job.get("scheduled_end")
            if (
                scheduled_start is not None
                and scheduled_end is not None
                and scheduled_end > scheduled_start
            ):
                first_service_date = scheduled_start.astimezone(app_timezone).date()
                last_service_date = (
                    (scheduled_end - timedelta(microseconds=1))
                    .astimezone(app_timezone)
                    .date()
                )
                service_date_cursor = first_service_date
                while service_date_cursor <= last_service_date:
                    service_dates.add(service_date_cursor)
                    service_date_cursor += timedelta(days=1)
            for service_date in service_dates:
                jobs_by_site_date[(int(job["location_id"]), service_date)].append(job)

    shifts, visits, departures, qr_by_employee_site, qr_rows = _load_time_evidence(
        range_start,
        range_end,
        observed_at,
        jobs_by_id,
        timezone_name=getattr(app_timezone, "key", str(app_timezone)),
        payroll_week_start=payroll_week_start,
        cursor=cursor,
    )
    linked_jobs_by_id = dict(jobs_by_id)
    linked_jobs_by_id.update(
        _load_linked_job_metadata(
            [
                int(shift["job_id"])
                for shift in shifts
                if shift.get("job_id") is not None
                and int(shift["job_id"]) not in jobs_by_id
            ]
            + [
                int(row["job_id"])
                for row in qr_rows
                if row.get("job_id") is not None
                and int(row["job_id"]) not in jobs_by_id
            ],
            cursor=cursor,
        )
    )
    cross_boundary_shift_ids = _unique_visible_qr_shift_ids(
        shifts,
        qr_rows,
        jobs_by_id,
        observed_at,
    )
    segments: List[Dict[str, Any]] = []
    for shift in shifts:
        shift_id = int(shift["id"])
        shift_range_start = range_start
        shift_range_end = range_end
        if shift_id in cross_boundary_shift_ids:
            shift_range_start = min(shift_range_start, shift["clock_in"])
            shift_range_end = max(
                shift_range_end,
                shift.get("clock_out") or observed_at,
            )
        if shift.get("clock_out") is None:
            if shift_range_start <= observed_at < shift_range_end:
                presence = _open_shift_presence(
                    shift,
                    visits.get(shift_id, []),
                    departures.get(shift_id, []),
                    qr_by_employee_site,
                    observed_at,
                )
                presence["start"] = max(presence["start"], shift_range_start)
                presence["end"] = min(presence["end"], shift_range_end)
                if presence["end"] > presence["start"]:
                    segments.append(presence)
        else:
            segments.extend(
                _closed_shift_segments(
                    shift,
                    visits.get(shift_id, []),
                    departures.get(shift_id, []),
                    qr_by_employee_site,
                    shift_range_start,
                    shift_range_end,
                )
            )
    represented_qr_ids = _apply_qr_job_links(
        qr_rows,
        segments,
        linked_jobs_by_id,
    )
    segments.extend(
        _qr_only_presence_segments(
            qr_rows,
            segments,
            observed_at,
            represented_qr_ids,
        )
    )

    workers_by_job: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(dict)
    # shift id -> effective snapshot rate in cents, so the daily profitability
    # split can weight each day by labor without carrying the rate on the
    # (contract-pinned) interval dicts. Same effective rate the worker total uses.
    shift_rate_cents: Dict[int, Optional[int]] = {}
    unmatched: List[Dict[str, Any]] = []
    resolved_segments: List[Dict[str, Any]] = []
    for segment in segments:
        job, reason, candidate_job_ids = _match_segment_to_job(
            segment,
            jobs_by_site_date,
            jobs_by_id,
            app_timezone,
            linked_jobs_by_id=linked_jobs_by_id,
        )
        if job is None:
            resolved_segments.append(
                {
                    "segment": dict(segment),
                    "job": None,
                    "reason": reason,
                }
            )
            shift_id = segment.get("shift_id")
            is_cross_boundary_shift = (
                shift_id is not None and int(shift_id) in cross_boundary_shift_ids
            )
            if (
                not is_cross_boundary_shift
                and visible_range_start is not None
                and visible_range_end is not None
                and (
                    segment["end"] <= visible_range_start
                    or segment["start"] >= visible_range_end
                )
            ):
                continue
            unmatched.append(_serialize_unmatched(segment, reason, candidate_job_ids))
            continue

        matched_segment = dict(segment)
        matched_segment["job_id"] = int(job["id"])
        resolved_segments.append(
            {
                "segment": matched_segment,
                "job": job,
                "reason": reason,
            }
        )

    for resolved in _apply_resolved_shift_break_minutes(resolved_segments):
        segment = resolved["segment"]
        job = resolved["job"]
        if job is None:
            continue
        reason = resolved["reason"]
        job_id = int(job["id"])
        employee_id = int(segment["employee_id"])
        segment_shift_id = segment.get("shift_id")
        if segment_shift_id is not None:
            shift_rate_cents[int(segment_shift_id)] = _money_cents(
                segment.get("hourly_rate")
            )
        worker = workers_by_job[job_id].setdefault(
            employee_id,
            {
                "employeeId": employee_id,
                "employeeName": segment["employee_name"],
                "hourlyRate": (
                    float(segment["hourly_rate"])
                    if segment.get("hourly_rate") is not None
                    else None
                ),
                "intervals": [],
                "finalizedHours": 0.0,
                "_finalizedHoursByRateCents": {},
                "inProgress": False,
                "observedPresence": False,
            },
        )
        finalized = bool(segment["finalized"])
        segment_hours = _hours(segment["start"], segment["end"]) if finalized else None
        worker["intervals"].append(
            {
                "shiftId": (
                    int(segment["shift_id"])
                    if segment.get("shift_id") is not None
                    else None
                ),
                "intervalStart": _utc_iso(segment["start"]),
                "intervalEnd": _utc_iso(segment["end"]) if finalized else None,
                "hours": round(segment_hours, 2) if segment_hours is not None else None,
                "finalized": finalized,
                "presenceOnly": bool(segment.get("presence_only")),
                "evidence": (
                    segment["evidence"]
                    if isinstance(segment["evidence"], list)
                    else [segment["evidence"]]
                ),
                "match": reason,
            }
        )
        if finalized:
            worker["finalizedHours"] += segment_hours or 0.0
            # Bucket hours by the rate each segment was worked at. "hourlyRate"
            # above is the first segment's rate; before per-shift snapshots every
            # segment of an employee shared one live rate, so that was harmless.
            # With snapshots two shifts of the same employee on the same job can
            # legitimately carry different rates, and collapsing them onto the
            # first would misprice the later one.
            segment_rate_cents = _money_cents(segment.get("hourly_rate"))
            hours_by_rate = worker["_finalizedHoursByRateCents"]
            hours_by_rate[segment_rate_cents] = (
                hours_by_rate.get(segment_rate_cents, 0.0) + (segment_hours or 0.0)
            )
        elif bool(segment.get("in_progress", True)):
            worker["inProgress"] = True
        else:
            worker["observedPresence"] = True

    output: List[Dict[str, Any]] = []
    for job in jobs:
        job_id = int(job["id"])
        issues = _job_issues(job)
        workers: List[Dict[str, Any]] = []
        actual_hours = 0.0
        known_labor_cents = 0
        labor_complete = True
        for worker in workers_by_job.get(job_id, {}).values():
            finalized_hours = float(worker.pop("finalizedHours"))
            in_progress = bool(worker.pop("inProgress"))
            observed_presence = bool(worker.pop("observedPresence"))
            actual_hours += finalized_hours
            worker.pop("hourlyRate")
            hours_by_rate_cents = worker.pop("_finalizedHoursByRateCents")
            # Fail closed: an unknown rate anywhere in this worker's segments
            # makes the whole worker labor figure unknown, exactly as a worker
            # with no configured rate does today.
            if any(key is None for key in hours_by_rate_cents):
                labor_cents = None
            else:
                # One bucket per distinct rate, summed EXACTLY and rounded once
                # at the end. Rounding each bucket first would let sub-cent
                # remainders each round up independently: two one-second
                # segments at $20/h and $25/h are 1.25 cents combined, which is
                # one cent, not the two cents per-bucket rounding would report.
                # With a single rate this is arithmetically identical to the
                # previous round(finalized_hours * rate), so backfilled history
                # does not move by a cent.
                labor_cents = int(
                    sum(
                        (
                            Decimal(str(bucket_hours)) * Decimal(bucket_rate)
                            for bucket_rate, bucket_hours in hours_by_rate_cents.items()
                        ),
                        Decimal(0),
                    ).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
                )
            if finalized_hours > 0 and labor_cents is None:
                labor_complete = False
                issues.append(
                    _issue(
                        "missing_worker_rate",
                        f"{worker['employeeName']} has no configured hourly rate.",
                    )
                )
            if labor_cents is not None:
                known_labor_cents += labor_cents
            worker.update(
                {
                    "status": (
                        "in_progress"
                        if in_progress
                        else (
                            "finalized"
                            if finalized_hours > 0
                            else ("observed" if observed_presence else "finalized")
                        )
                    ),
                    "hours": round(finalized_hours, 2),
                    "laborCost": _money(labor_cents),
                }
            )
            workers.append(worker)

        planned_hours = (
            float(job["site_expected_hours"])
            if job.get("site_expected_hours") is not None
            else None
        )
        expected_hours_baseline = _expected_hours_baseline(
            job,
            expected_hours_learning_by_site,
        )
        in_progress = any(worker["status"] == "in_progress" for worker in workers)
        status = str(job.get("status") or "scheduled")
        included_in_plan = status != "cancelled" and _job_is_projection_eligible(job)
        execution_status = _schedule_execution_status(
            job,
            in_progress=in_progress,
            actual_hours=actual_hours,
            observed_at=observed_at,
        )
        output.append(
            {
                "id": job_id,
                "locationId": job.get("location_id"),
                "customerId": job.get("customer_id"),
                "customerName": str(job.get("display_customer") or ""),
                "siteAddress": str(job.get("site_address") or ""),
                "siteType": job.get("site_type"),
                "scheduledDate": str(job["scheduled_date"]),
                "scheduledStart": _utc_iso(job.get("scheduled_start")),
                "scheduledEnd": _utc_iso(job.get("scheduled_end")),
                "sourceRole": job.get("source_role"),
                "sourceTitle": str(job.get("source_title") or ""),
                "status": status,
                "executionStatus": execution_status,
                "includedInPlan": included_in_plan,
                "plannedHours": planned_hours,
                "expectedHoursBaseline": expected_hours_baseline,
                "actualHours": round(actual_hours, 2),
                "varianceHours": (
                    round(actual_hours - planned_hours, 2)
                    if planned_hours is not None
                    else None
                ),
                "actualLaborCost": (
                    _money(known_labor_cents) if labor_complete else None
                ),
                "knownActualLaborCost": _money(known_labor_cents),
                "workers": sorted(
                    workers,
                    key=lambda worker: (
                        worker["employeeName"].casefold(),
                        worker["employeeId"],
                    ),
                ),
                "siteEconomics": {
                    "rate": (
                        float(job["rate"]) if job.get("rate") is not None else None
                    ),
                    "rateType": job.get("rate_type"),
                    "expectedHours": planned_hours,
                    "expectedHoursBaseline": expected_hours_baseline,
                },
                "issues": issues,
            }
        )
    return output, unmatched, shift_rate_cents


def _complete_total(
    known_cents: int,
    incomplete_count: int,
) -> Optional[float]:
    return None if incomplete_count else _money(known_cents)


def _complete_hours(
    known_hours: float,
    incomplete_count: int,
) -> Optional[float]:
    return None if incomplete_count else round(known_hours, 2)


def _forecast_job_values(
    job: Dict[str, Any],
    avg_hourly_rate: Optional[Decimal],
    monthly_allocations: Dict[int, int],
    expected_hours_learning_by_site: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    issues = _job_issues(job)
    included_in_forecast = _job_is_projection_eligible(job)
    expected_hours = (
        float(job["site_expected_hours"])
        if job.get("site_expected_hours") is not None
        else None
    )
    expected_hours_baseline = _expected_hours_baseline(
        job,
        expected_hours_learning_by_site,
    )
    rate_cents = _money_cents(job.get("rate"))
    rate_type = job.get("rate_type")

    revenue_cents: MoneyCents = None
    if not included_in_forecast or job.get("location_id") is None:
        revenue_cents = None
    elif rate_cents is not None:
        if rate_type == "per_visit":
            revenue_cents = rate_cents
        elif rate_type == "hourly" and expected_hours is not None:
            revenue_cents = int(
                (Decimal(rate_cents) * Decimal(str(expected_hours))).quantize(
                    Decimal("1"), rounding=ROUND_HALF_UP
                )
            )
        elif rate_type == "monthly":
            revenue_cents = monthly_allocations.get(int(job["id"]))

    labor_cents: MoneyCents = None
    if (
        included_in_forecast
        and expected_hours is not None
        and avg_hourly_rate is not None
    ):
        labor_cents = int(
            (avg_hourly_rate * Decimal(str(expected_hours)) * Decimal(100)).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        )
    if avg_hourly_rate is None and included_in_forecast:
        issues.append(
            _issue(
                "missing_average_employee_rate",
                "No active employee has a configured hourly rate.",
            )
        )

    net_cents = (
        revenue_cents - labor_cents
        if revenue_cents is not None and labor_cents is not None
        else None
    )
    return {
        "jobId": int(job["id"]),
        "locationId": job.get("location_id"),
        "customerId": job.get("customer_id"),
        "customerName": str(job.get("display_customer") or ""),
        "siteAddress": str(job.get("site_address") or ""),
        "scheduledDate": str(job["scheduled_date"]),
        "scheduledStart": _utc_iso(job.get("scheduled_start")),
        "scheduledEnd": _utc_iso(job.get("scheduled_end")),
        "sourceRole": job.get("source_role"),
        "includedInForecast": included_in_forecast,
        "plannedHours": expected_hours,
        "expectedHoursBaseline": expected_hours_baseline,
        "estRevenue": _money(revenue_cents),
        "estLaborCost": _money(labor_cents),
        "estNetProfit": _money(net_cents),
        "estMarginPct": (
            round(net_cents / revenue_cents * 100, 1)
            if revenue_cents is not None and revenue_cents > 0 and net_cents is not None
            else None
        ),
        "estLaborPct": (
            round(labor_cents / revenue_cents * 100, 1)
            if revenue_cents is not None
            and revenue_cents > 0
            and labor_cents is not None
            else None
        ),
        "issues": issues,
        "_included_in_forecast": included_in_forecast,
        "_revenue_cents": revenue_cents,
        "_labor_cents": labor_cents,
    }


def _aggregate_forecast_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    included_rows = [
        row for row in rows if bool(row.get("_included_in_forecast", True))
    ]
    known_hours = sum(
        float(row["plannedHours"])
        for row in included_rows
        if row.get("plannedHours") is not None
    )
    hours_incomplete = sum(
        1 for row in included_rows if row.get("plannedHours") is None
    )
    known_revenue_cents = sum(
        int(row["_revenue_cents"])
        for row in included_rows
        if row.get("_revenue_cents") is not None
    )
    revenue_incomplete = sum(
        1 for row in included_rows if row.get("_revenue_cents") is None
    )
    known_labor_cents = sum(
        int(row["_labor_cents"])
        for row in included_rows
        if row.get("_labor_cents") is not None
    )
    labor_incomplete = sum(
        1 for row in included_rows if row.get("_labor_cents") is None
    )
    revenue = _complete_total(known_revenue_cents, revenue_incomplete)
    labor = _complete_total(known_labor_cents, labor_incomplete)
    net = (
        round(revenue - labor, 2) if revenue is not None and labor is not None else None
    )
    return {
        "jobCount": len(included_rows),
        "visibleJobCount": len(rows),
        "excludedJobCount": len(rows) - len(included_rows),
        "plannedHours": _complete_hours(known_hours, hours_incomplete),
        "knownPlannedHours": round(known_hours, 2),
        "plannedHoursComplete": hours_incomplete == 0,
        "estRevenue": revenue,
        "knownRevenue": _money(known_revenue_cents),
        "revenueComplete": revenue_incomplete == 0,
        "estLaborCost": labor,
        "knownLaborCost": _money(known_labor_cents),
        "laborCostComplete": labor_incomplete == 0,
        "estNetProfit": net,
        "estMarginPct": (
            round(net / revenue * 100, 1)
            if net is not None and revenue and revenue > 0
            else None
        ),
        "estLaborPct": (
            round(labor / revenue * 100, 1)
            if labor is not None and revenue and revenue > 0
            else None
        ),
        "incompleteJobCount": len(
            {int(row["jobId"]) for row in rows if row.get("issues")}
        ),
    }


def monthly_revenue_allocations(
    jobs: List[Dict[str, Any]],
    app_timezone: ZoneInfo,
) -> Dict[int, int]:
    monthly_groups: Dict[Tuple[int, int, int], List[Dict[str, Any]]] = defaultdict(list)
    for job in jobs:
        if (
            job.get("status") != "cancelled"
            and job.get("location_id") is not None
            and str(job.get("rate_type") or "") == "monthly"
        ):
            scheduled_date = job["scheduled_date"]
            monthly_groups[
                (
                    int(job["location_id"]),
                    scheduled_date.year,
                    scheduled_date.month,
                )
            ].append(job)

    monthly_allocations: Dict[int, int] = {}
    for jobs_in_month in monthly_groups.values():
        ordered = sorted(
            jobs_in_month,
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
        monthly_cents = _money_cents(ordered[0].get("rate"))
        if monthly_cents is not None:
            monthly_allocations.update(
                allocate_monthly_cents(
                    monthly_cents,
                    (int(job["id"]) for job in ordered),
                )
            )
    return monthly_allocations


def _actual_profitability_revenue_cents(
    row: Dict[str, Any],
    monthly_allocations: Dict[int, int],
) -> MoneyCents:
    if not bool(row.get("includedInProfitability")):
        return None

    site_economics = dict(row.get("siteEconomics") or {})
    rate_cents = _money_cents(site_economics.get("rate"))
    rate_type = site_economics.get("rateType")
    planned_hours = row.get("plannedHours")
    if rate_cents is None:
        return None
    if rate_type == "per_visit":
        return rate_cents
    if rate_type == "hourly" and planned_hours is not None:
        return int(
            (Decimal(rate_cents) * Decimal(str(planned_hours))).quantize(
                Decimal("1"),
                rounding=ROUND_HALF_UP,
            )
        )
    if rate_type == "monthly":
        return monthly_allocations.get(int(row.get("jobId") or row["id"]))
    return None


def _percent(numerator: Optional[int], denominator: Optional[int]) -> Optional[float]:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator / denominator * 100, 1)


def _actual_profitability_row(
    row: Dict[str, Any],
    source_job: Dict[str, Any],
    monthly_allocations: Dict[int, int],
    *,
    week_start: date,
    week_end: date,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
    default_target_labor_pct: Optional[float],
    default_min_margin_pct: Optional[float],
) -> Dict[str, Any]:
    included = bool(row["includedInPlan"]) and row.get("status") != "cancelled"
    working_row = {**row, "includedInProfitability": included}
    revenue_cents = _actual_profitability_revenue_cents(
        working_row,
        monthly_allocations,
    )
    actual_labor_cents = _money_cents(row.get("actualLaborCost"))
    known_actual_labor_cents = _money_cents(row.get("knownActualLaborCost")) or 0
    net_cents = (
        revenue_cents - actual_labor_cents
        if revenue_cents is not None and actual_labor_cents is not None
        else None
    )
    actual_labor_pct = _percent(actual_labor_cents, revenue_cents)
    target_labor_pct = (
        float(source_job["site_target_labor_pct"])
        if source_job.get("site_target_labor_pct") is not None
        else default_target_labor_pct
    )
    min_margin_pct = (
        float(source_job["site_min_margin_pct"])
        if source_job.get("site_min_margin_pct") is not None
        else default_min_margin_pct
    )
    issues = list(row.get("issues") or [])
    if included and revenue_cents is None:
        issues.append(
            _issue(
                "missing_revenue",
                "Revenue cannot be calculated from this Site's rate card.",
            )
        )

    return {
        "jobId": int(row["id"]),
        "locationId": row.get("locationId"),
        "customerId": row.get("customerId"),
        "customerName": row.get("customerName"),
        "siteAddress": row.get("siteAddress"),
        "siteType": row.get("siteType"),
        "scheduledDate": row.get("scheduledDate"),
        "profitabilityDate": _job_profitability_date(
            source_job,
            week_start=week_start,
            week_end=week_end,
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
        ),
        "scheduledStart": row.get("scheduledStart"),
        "scheduledEnd": row.get("scheduledEnd"),
        "status": row.get("status"),
        "executionStatus": row.get("executionStatus"),
        "includedInProfitability": included,
        "plannedHours": row.get("plannedHours"),
        "expectedHoursBaseline": row.get("expectedHoursBaseline"),
        "actualHours": row.get("actualHours"),
        "varianceHours": row.get("varianceHours"),
        "revenue": _money(revenue_cents),
        "revenueComplete": revenue_cents is not None,
        "actualLaborCost": _money(actual_labor_cents),
        "knownActualLaborCost": _money(known_actual_labor_cents),
        "laborCostComplete": actual_labor_cents is not None,
        "netProfit": _money(net_cents),
        "grossMarginPct": _percent(net_cents, revenue_cents),
        "actualLaborPct": actual_labor_pct,
        "targetLaborPct": target_labor_pct,
        "laborTargetVariancePct": (
            round(actual_labor_pct - target_labor_pct, 1)
            if actual_labor_pct is not None and target_labor_pct is not None
            else None
        ),
        "minMarginPct": min_margin_pct,
        "workers": [
            {
                "employeeId": int(worker["employeeId"]),
                "employeeName": worker["employeeName"],
                "hours": worker["hours"],
                "laborCost": worker["laborCost"],
                "status": worker["status"],
            }
            for worker in row.get("workers", [])
        ],
        "issues": issues,
    }


def _job_profitability_date(
    source_job: Dict[str, Any],
    *,
    week_start: date,
    week_end: date,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
) -> str:
    scheduled_start = source_job.get("scheduled_start")
    scheduled_end = source_job.get("scheduled_end")
    if (
        isinstance(scheduled_start, datetime)
        and isinstance(scheduled_end, datetime)
        and scheduled_end > scheduled_start
    ):
        overlap_start = max(scheduled_start.astimezone(timezone.utc), range_start)
        overlap_end = min(scheduled_end.astimezone(timezone.utc), range_end)
        if overlap_start < overlap_end:
            return overlap_start.astimezone(app_timezone).date().isoformat()

    scheduled_date = source_job.get("scheduled_date")
    if isinstance(scheduled_date, datetime):
        scheduled_day = scheduled_date.date()
    elif isinstance(scheduled_date, date):
        scheduled_day = scheduled_date
    else:
        scheduled_day = week_start
    if scheduled_day < week_start:
        return week_start.isoformat()
    if scheduled_day > week_end:
        return week_end.isoformat()
    return scheduled_day.isoformat()


def _allocate_cents_by_weight(
    total_cents: int,
    weights: Dict[str, float],
) -> Dict[str, int]:
    positive_weights = {
        key: weight
        for key, weight in weights.items()
        if weight > 0
    }
    total_weight = sum(positive_weights.values())
    if total_weight <= 0:
        return {key: 0 for key in weights}

    allocations = []
    allocated = 0
    for key, weight in sorted(positive_weights.items()):
        exact = (
            Decimal(total_cents)
            * Decimal(str(weight))
            / Decimal(str(total_weight))
        )
        floor_cents = int(exact)
        allocated += floor_cents
        allocations.append(
            {
                "key": key,
                "cents": floor_cents,
                "remainder": exact - Decimal(floor_cents),
            }
        )

    remaining = total_cents - allocated
    for item in sorted(
        allocations,
        key=lambda row: (-row["remainder"], row["key"]),
    )[:remaining]:
        item["cents"] = int(item["cents"]) + 1

    result = {key: 0 for key in weights}
    result.update({str(item["key"]): int(item["cents"]) for item in allocations})
    return result


def _daily_worker_rows(
    worker: Dict[str, Any],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
    shift_rate_cents: Optional[Dict[int, Optional[int]]] = None,
) -> Dict[str, Dict[str, Any]]:
    rate_by_shift = shift_rate_cents or {}
    hours_by_day: Dict[str, float] = defaultdict(float)
    # Weight the labor split by each day's actual labor (rate x hours), not by
    # hours alone: an employee who worked 1h at $20 on Monday and 1h at $30 on
    # Tuesday must read $20/$30, not the $25/$25 an equal-hours split produces.
    # Each interval's rate comes from its shift's snapshot (the same effective
    # rate the worker total is built from), looked up rather than carried on the
    # interval so the schedule response shape is untouched. With a single rate
    # the labor weight is proportional to hours, so this is identical to the
    # previous hours-weighted behavior.
    labor_weight_by_day: Dict[str, float] = defaultdict(float)
    for interval in worker.get("intervals") or []:
        if not interval.get("finalized") or not interval.get("intervalEnd"):
            continue
        interval_start = _parse_utc_iso(str(interval["intervalStart"]))
        interval_end = _parse_utc_iso(str(interval["intervalEnd"]))
        shift_id = interval.get("shiftId")
        interval_rate_cents = (
            rate_by_shift.get(int(shift_id)) if shift_id is not None else None
        )
        for local_day, hours in _local_interval_grid_day_slices(
            interval_start,
            interval_end,
            range_start=range_start,
            range_end=range_end,
            app_timezone=app_timezone,
        ):
            day_key = local_day.isoformat()
            hours_by_day[day_key] += hours
            if interval_rate_cents is not None:
                labor_weight_by_day[day_key] += hours * interval_rate_cents

    labor_cents = _money_cents(worker.get("laborCost"))
    # Allocating a known total by labor weight keeps every day rate-correct and
    # still sums exactly to that total. The total is None (fail-closed) whenever
    # any of the worker's segments had an unknown rate, so no day is priced from
    # a partial rate picture.
    labor_by_day = (
        _allocate_cents_by_weight(labor_cents, dict(labor_weight_by_day))
        if labor_cents is not None
        else {}
    )
    return {
        day: {
            "employeeId": int(worker["employeeId"]),
            "employeeName": worker["employeeName"],
            "_hours": hours,
            "laborCost": (
                _money(labor_by_day[day])
                if labor_cents is not None
                else None
            ),
            "status": worker["status"],
        }
        for day, hours in hours_by_day.items()
    }


def _daily_profitability_worker_response(
    worker: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "employeeId": int(worker["employeeId"]),
        "employeeName": worker["employeeName"],
        "hours": round(float(worker.get("_hours") or 0), 2),
        "laborCost": worker["laborCost"],
        "status": worker["status"],
    }


def _daily_profitability_issues(
    profit_row: Dict[str, Any],
    workers: List[Dict[str, Any]],
    *,
    day: str,
    revenue_date: str,
    revenue_cents: MoneyCents,
) -> List[Dict[str, str]]:
    dynamic_codes = {"missing_worker_rate", "missing_revenue"}
    issues = [
        issue
        for issue in profit_row.get("issues") or []
        if str(issue.get("code") or "") not in dynamic_codes
    ]
    if day == revenue_date and revenue_cents is None:
        issues.append(
            _issue(
                "missing_revenue",
                "Revenue cannot be calculated from this Site's rate card.",
            )
        )
    for worker in workers:
        if worker.get("laborCost") is not None:
            continue
        if float(worker.get("_hours") or 0) <= 0:
            continue
        issues.append(
            _issue(
                "missing_worker_rate",
                f"{worker['employeeName']} has no configured hourly rate.",
            )
        )
    return issues


def _daily_profitability_job_rows(
    profit_row: Dict[str, Any],
    decorated_row: Dict[str, Any],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
    shift_rate_cents: Optional[Dict[int, Optional[int]]] = None,
) -> List[Dict[str, Any]]:
    revenue_date = str(profit_row.get("profitabilityDate") or profit_row.get("scheduledDate") or "")
    worker_rows_by_day: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for worker in decorated_row.get("workers") or []:
        for day, daily_worker in _daily_worker_rows(
            worker,
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
            shift_rate_cents=shift_rate_cents,
        ).items():
            worker_rows_by_day[day].append(daily_worker)

    daily_rows: List[Dict[str, Any]] = []
    for day in sorted(set(worker_rows_by_day) | ({revenue_date} if revenue_date else set())):
        workers = sorted(
            worker_rows_by_day.get(day, []),
            key=lambda worker: (
                worker["employeeName"].casefold(),
                worker["employeeId"],
            ),
        )
        actual_hours = round(
            sum(float(worker.get("_hours") or 0) for worker in workers),
            2,
        )
        labor_incomplete = any(
            worker.get("laborCost") is None and float(worker.get("_hours") or 0) > 0
            for worker in workers
        )
        known_labor_cents = sum(
            _money_cents(worker.get("laborCost")) or 0
            for worker in workers
        )
        actual_labor_cents: MoneyCents = None if labor_incomplete else known_labor_cents
        revenue_cents = (
            _money_cents(profit_row.get("revenue"))
            if day == revenue_date
            else 0
        )
        issues = _daily_profitability_issues(
            profit_row,
            workers,
            day=day,
            revenue_date=revenue_date,
            revenue_cents=revenue_cents,
        )
        planned_hours = profit_row.get("plannedHours") if day == revenue_date else 0.0
        net_cents = (
            revenue_cents - actual_labor_cents
            if revenue_cents is not None and actual_labor_cents is not None
            else None
        )
        actual_labor_pct = _percent(actual_labor_cents, revenue_cents)
        target_labor_pct = profit_row.get("targetLaborPct")
        daily_row = {
            **profit_row,
            "profitabilityDate": day,
            "revenueRecognitionDate": revenue_date,
            "plannedHours": planned_hours,
            "actualHours": actual_hours,
            "varianceHours": (
                round(actual_hours - float(planned_hours), 2)
                if planned_hours is not None
                else None
            ),
            "revenue": _money(revenue_cents),
            "revenueComplete": revenue_cents is not None,
            "actualLaborCost": _money(actual_labor_cents),
            "knownActualLaborCost": _money(known_labor_cents),
            "laborCostComplete": actual_labor_cents is not None,
            "netProfit": _money(net_cents),
            "grossMarginPct": _percent(net_cents, revenue_cents),
            "actualLaborPct": actual_labor_pct,
            "laborTargetVariancePct": (
                round(actual_labor_pct - float(target_labor_pct), 1)
                if actual_labor_pct is not None and target_labor_pct is not None
                else None
            ),
            "workers": [
                _daily_profitability_worker_response(worker) for worker in workers
            ],
            "issues": issues,
        }
        daily_rows.append(daily_row)
    return daily_rows


def _payroll_local_hours_by_day(
    intervals: List[Dict[str, Any]],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
) -> Dict[str, float]:
    hours_by_day: Dict[str, float] = defaultdict(float)
    for interval in intervals:
        if not interval.get("finalized") or not interval.get("intervalEnd"):
            continue
        interval_start = _parse_utc_iso(str(interval["intervalStart"]))
        interval_end = _parse_utc_iso(str(interval["intervalEnd"]))
        for local_day, hours in _local_interval_day_slices(
            interval_start,
            interval_end,
            range_start=range_start,
            range_end=range_end,
            app_timezone=app_timezone,
        ):
            hours_by_day[local_day.isoformat()] += hours
    return hours_by_day


def _payroll_local_labor_weight_by_day(
    intervals: List[Dict[str, Any]],
    *,
    shift_rate_cents: Dict[int, Optional[int]],
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
) -> Dict[str, float]:
    """Per-day labor weight (rate x hours) over the same day slices as the hours
    map, so a mixed-rate worker total splits by labor instead of by hours."""
    labor_weight_by_day: Dict[str, float] = defaultdict(float)
    for interval in intervals:
        if not interval.get("finalized") or not interval.get("intervalEnd"):
            continue
        shift_id = interval.get("shiftId")
        rate_cents = (
            shift_rate_cents.get(int(shift_id)) if shift_id is not None else None
        )
        if rate_cents is None:
            continue
        interval_start = _parse_utc_iso(str(interval["intervalStart"]))
        interval_end = _parse_utc_iso(str(interval["intervalEnd"]))
        for local_day, hours in _local_interval_day_slices(
            interval_start,
            interval_end,
            range_start=range_start,
            range_end=range_end,
            app_timezone=app_timezone,
        ):
            labor_weight_by_day[local_day.isoformat()] += hours * rate_cents
    return labor_weight_by_day


def _payroll_correction_candidate_segments(
    profit_jobs: List[Dict[str, Any]],
    decorated_jobs: Dict[int, Dict[str, Any]],
    unmatched: List[Dict[str, Any]],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
    shift_rate_cents: Optional[Dict[int, Optional[int]]] = None,
) -> List[Dict[str, Any]]:
    rate_by_shift = shift_rate_cents or {}
    segments: List[Dict[str, Any]] = []
    profit_jobs_by_id = {int(row["jobId"]): row for row in profit_jobs}
    for job_id, profit_row in profit_jobs_by_id.items():
        if profit_row.get("locationId") is None:
            continue
        decorated = decorated_jobs.get(job_id)
        if not decorated:
            continue
        for worker in decorated.get("workers") or []:
            hours_by_day = _payroll_local_hours_by_day(
                worker.get("intervals") or [],
                app_timezone=app_timezone,
                range_start=range_start,
                range_end=range_end,
            )
            if not hours_by_day:
                continue
            worker_labor_cents = _money_cents(worker.get("laborCost"))
            # Split the worker's job labor across days by each day's actual labor
            # (rate x hours), mirroring _daily_worker_rows, so a day worked at a
            # different snapshot rate is priced at that rate rather than the
            # equal-hours average. Single-rate days weight proportional to hours,
            # so the split is unchanged there.
            labor_weight_by_day = _payroll_local_labor_weight_by_day(
                worker.get("intervals") or [],
                shift_rate_cents=rate_by_shift,
                app_timezone=app_timezone,
                range_start=range_start,
                range_end=range_end,
            )
            labor_by_day = (
                _allocate_cents_by_weight(
                    worker_labor_cents, dict(labor_weight_by_day)
                )
                if worker_labor_cents is not None
                else {}
            )
            for day_key, hours in hours_by_day.items():
                segments.append(
                    {
                        "segmentKey": (
                            f"matched:{job_id}:{worker['employeeId']}:{day_key}"
                        ),
                        "siteSegmentKey": (
                            f"matched:{job_id}:{worker['employeeId']}:{day_key}"
                        ),
                        "source": "matched_job",
                        "date": day_key,
                        "employeeId": int(worker["employeeId"]),
                        "employeeName": worker["employeeName"],
                        "locationId": profit_row.get("locationId"),
                        "customerId": profit_row.get("customerId"),
                        "customerName": profit_row.get("customerName"),
                        "siteAddress": profit_row.get("siteAddress"),
                        "jobId": job_id,
                        "includedInProfitability": bool(
                            profit_row.get("includedInProfitability")
                        ),
                        "scheduledDate": profit_row.get("scheduledDate"),
                        "profitabilityDate": profit_row.get("profitabilityDate"),
                        "revenueRecognitionDate": profit_row.get("profitabilityDate"),
                        "actualHours": round(hours, 2),
                        "actualLaborCost": (
                            _money(labor_by_day[day_key])
                            if worker_labor_cents is not None
                            else None
                        ),
                        "laborCostComplete": worker_labor_cents is not None,
                    }
                )

    for segment in unmatched:
        if not segment.get("finalized") or not segment.get("intervalEnd"):
            continue
        hours_by_day = _payroll_local_hours_by_day(
            [
                {
                    "intervalStart": segment["intervalStart"],
                    "intervalEnd": segment["intervalEnd"],
                    "finalized": True,
                }
            ],
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
        )
        if not hours_by_day:
            continue
        candidate_job_ids = [int(job_id) for job_id in segment.get("candidateJobIds") or []]
        for job_id in candidate_job_ids:
            profit_row = profit_jobs_by_id.get(job_id)
            if not profit_row or profit_row.get("locationId") is None:
                continue
            for day_key, hours in hours_by_day.items():
                segments.append(
                    {
                        "segmentKey": (
                            f"unmatched:{segment.get('shiftId')}:{job_id}:"
                            f"{segment['intervalStart']}:{segment['intervalEnd']}:{day_key}"
                        ),
                        "siteSegmentKey": (
                            f"unmatched:{segment.get('shiftId')}:"
                            f"{segment['intervalStart']}:{segment['intervalEnd']}:{day_key}"
                        ),
                        "source": "unmatched_actual_labor",
                        "reason": segment.get("reason"),
                        "date": day_key,
                        "employeeId": int(segment["employeeId"]),
                        "employeeName": segment["employeeName"],
                        "locationId": profit_row.get("locationId"),
                        "customerId": profit_row.get("customerId"),
                        "customerName": profit_row.get("customerName"),
                        "siteAddress": profit_row.get("siteAddress"),
                        "jobId": job_id,
                        "includedInProfitability": bool(
                            profit_row.get("includedInProfitability")
                        ),
                        "scheduledDate": profit_row.get("scheduledDate"),
                        "profitabilityDate": profit_row.get("profitabilityDate"),
                        "revenueRecognitionDate": profit_row.get("profitabilityDate"),
                        "actualHours": round(hours, 2),
                        "actualLaborCost": None,
                        "laborCostComplete": False,
                    }
                )
    return segments


def _aggregate_actual_profitability_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    included_rows = [row for row in rows if bool(row.get("includedInProfitability"))]
    known_planned_hours = sum(
        float(row["plannedHours"])
        for row in included_rows
        if row.get("plannedHours") is not None
    )
    planned_hours_incomplete = sum(
        1 for row in included_rows if row.get("plannedHours") is None
    )
    actual_hours = sum(float(row["actualHours"] or 0) for row in included_rows)
    known_revenue_cents = sum(
        _money_cents(row["revenue"]) or 0
        for row in included_rows
        if row.get("revenue") is not None
    )
    revenue_incomplete = sum(
        1 for row in included_rows if not bool(row.get("revenueComplete"))
    )
    known_labor_cents = sum(
        _money_cents(row["knownActualLaborCost"]) or 0
        for row in included_rows
    )
    labor_incomplete = sum(
        1 for row in included_rows if not bool(row.get("laborCostComplete"))
    )
    revenue = _complete_total(known_revenue_cents, revenue_incomplete)
    labor = _complete_total(known_labor_cents, labor_incomplete)
    revenue_cents = _money_cents(revenue)
    labor_cents = _money_cents(labor)
    net_cents = (
        revenue_cents - labor_cents
        if revenue_cents is not None and labor_cents is not None
        else None
    )
    return {
        "jobCount": len(included_rows),
        "visibleJobCount": len(rows),
        "excludedJobCount": len(rows) - len(included_rows),
        "plannedHours": _complete_hours(
            known_planned_hours,
            planned_hours_incomplete,
        ),
        "knownPlannedHours": round(known_planned_hours, 2),
        "plannedHoursComplete": planned_hours_incomplete == 0,
        "actualHours": round(actual_hours, 2),
        "varianceHours": (
            round(actual_hours - known_planned_hours, 2)
            if planned_hours_incomplete == 0
            else None
        ),
        "revenue": revenue,
        "knownRevenue": _money(known_revenue_cents),
        "revenueComplete": revenue_incomplete == 0,
        "actualLaborCost": labor,
        "knownActualLaborCost": _money(known_labor_cents),
        "laborCostComplete": labor_incomplete == 0,
        "netProfit": _money(net_cents),
        "grossMarginPct": _percent(net_cents, revenue_cents),
        "actualLaborPct": _percent(labor_cents, revenue_cents),
        "incompleteJobCount": len(
            {int(row["jobId"]) for row in rows if row.get("issues")}
        ),
    }


def _profitability_issue_details(rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for row in rows:
        for issue in row.get("issues") or []:
            code = str(issue.get("code") or "")
            message = str(issue.get("message") or "")
            key = (code, message)
            if key in seen:
                continue
            seen.add(key)
            issues.append({"code": code, "message": message})
    return issues


def _profitability_issue_count(rows: List[Dict[str, Any]]) -> int:
    return sum(len(row.get("issues") or []) for row in rows)


def _profitability_job_sort_key(row: Dict[str, Any]) -> Tuple[str, str, int]:
    return (
        str(row.get("scheduledDate") or ""),
        str(row.get("scheduledStart") or ""),
        int(row.get("jobId") or 0),
    )


def _profitability_site_sort_key(row: Dict[str, Any]) -> Tuple[str, str, int]:
    return (
        str(row.get("customerName") or "").casefold(),
        str(row.get("siteAddress") or "").casefold(),
        int(row.get("locationId") or 0),
    )


def _group_profitability_by_site(
    rows: List[Dict[str, Any]],
    *,
    include_jobs: bool = False,
) -> List[Dict[str, Any]]:
    by_site_rows: Dict[Optional[int], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_site_rows[row.get("locationId")].append(row)

    sites = []
    for location_id, site_rows in by_site_rows.items():
        first = site_rows[0]
        site = {
            "locationId": location_id,
            "customerId": first.get("customerId"),
            "customerName": first.get("customerName"),
            "siteAddress": first.get("siteAddress"),
            "siteType": first.get("siteType"),
            **_aggregate_actual_profitability_rows(site_rows),
            "issueCount": _profitability_issue_count(site_rows),
            "issues": _profitability_issue_details(site_rows),
        }
        if include_jobs:
            site["jobs"] = sorted(site_rows, key=_profitability_job_sort_key)
        sites.append(site)

    return sorted(sites, key=_profitability_site_sort_key)


def _daily_profitability_rows(
    week_start: date,
    week_end: date,
    profit_jobs: List[Dict[str, Any]],
    unmatched: List[Dict[str, Any]],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
) -> List[Dict[str, Any]]:
    rows_by_day: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in profit_jobs:
        profitability_date = str(row.get("profitabilityDate") or row.get("scheduledDate") or "")
        if profitability_date:
            rows_by_day[profitability_date].append(row)

    unmatched_by_day = _daily_unmatched_profitability_rows(
        week_start,
        week_end,
        unmatched,
        app_timezone=app_timezone,
        range_start=range_start,
        range_end=range_end,
    )

    by_day = []
    for offset in range(7):
        day = week_start + timedelta(days=offset)
        day_text = day.isoformat()
        day_rows = rows_by_day.get(day_text, [])
        unmatched_rows = unmatched_by_day.get(day_text, [])
        unmatched_actual_hours = round(
            sum(
                float(row["dailyHours"])
                for row in unmatched_rows
                if row.get("finalized") and row.get("dailyHours") is not None
            ),
            2,
        )
        issues = _profitability_issue_details(day_rows)
        if unmatched_rows:
            issues.append(
                _issue(
                    "unmatched_actual_labor",
                    "Labor was clocked on this day but could not be matched to a scheduled job.",
                )
            )
        by_day.append(
            {
                "date": day_text,
                **_aggregate_actual_profitability_rows(day_rows),
                "unmatchedActualHours": unmatched_actual_hours,
                "unmatchedActualSegmentCount": len(unmatched_rows),
                "unmatchedActualSegments": unmatched_rows,
                "issueCount": _profitability_issue_count(day_rows)
                + (1 if unmatched_rows else 0),
                "issues": issues,
                "sites": _group_profitability_by_site(
                    day_rows,
                    include_jobs=True,
                ),
            }
        )
    return by_day


def _parse_utc_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _daily_unmatched_profitability_rows(
    week_start: date,
    week_end: date,
    unmatched: List[Dict[str, Any]],
    *,
    app_timezone: ZoneInfo,
    range_start: datetime,
    range_end: datetime,
) -> Dict[str, List[Dict[str, Any]]]:
    by_day: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for segment in unmatched:
        interval_start = _parse_utc_iso(str(segment["intervalStart"]))
        interval_end_text = segment.get("intervalEnd")
        if bool(segment.get("finalized")) and interval_end_text:
            interval_end = _parse_utc_iso(str(interval_end_text))
            for local_day, hours in _local_interval_day_slices(
                interval_start,
                interval_end,
                range_start=range_start,
                range_end=range_end,
                app_timezone=app_timezone,
            ):
                by_day[local_day.isoformat()].append(
                    {**segment, "dailyHours": round(hours, 2)}
                )
            continue

        local_day = interval_start.astimezone(app_timezone).date()
        if week_start <= local_day <= week_end:
            by_day[local_day.isoformat()].append({**segment, "dailyHours": None})
    return by_day


def build_weekly_labor_profitability(
    week_start: date,
    *,
    timezone_name: str = "America/Chicago",
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    default_target_labor_pct: Optional[float] = None,
    default_min_margin_pct: Optional[float] = None,
    payroll_week_start: Optional[date] = None,
    cursor: Optional[Any] = None,
) -> Dict[str, Any]:
    app_timezone = ZoneInfo(timezone_name)
    observed_at = now_provider().astimezone(timezone.utc)
    week_end = week_start + timedelta(days=6)
    range_start, range_end = _local_bounds(week_start, week_end, app_timezone)
    allocation_start = date(week_start.year, week_start.month, 1)
    allocation_end = _month_end(week_end)
    jobs = _load_jobs(
        week_start,
        week_end,
        window_start=range_start,
        window_end=range_end,
        cursor=cursor,
    )
    allocation_jobs = _load_jobs(allocation_start, allocation_end, cursor=cursor)
    monthly_allocations = monthly_revenue_allocations(
        allocation_jobs,
        app_timezone,
    )
    expected_hours_learning_by_site = _load_expected_hours_learning_by_site(
        _expected_hours_learning_site_ids(jobs),
        observed_at=observed_at,
        app_timezone=app_timezone,
        cursor=cursor,
    )
    schedule_jobs, unmatched, shift_rate_cents = _decorate_schedule_jobs(
        jobs,
        range_start,
        range_end,
        observed_at,
        app_timezone,
        visible_range_start=range_start,
        visible_range_end=range_end,
        expected_hours_learning_by_site=expected_hours_learning_by_site,
        payroll_week_start=payroll_week_start,
        cursor=cursor,
    )
    source_jobs = {int(job["id"]): job for job in jobs}
    profit_jobs = [
        _actual_profitability_row(
            row,
            source_jobs[int(row["id"])],
            monthly_allocations,
            week_start=week_start,
            week_end=week_end,
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
            default_target_labor_pct=default_target_labor_pct,
            default_min_margin_pct=default_min_margin_pct,
        )
        for row in schedule_jobs
    ]
    decorated_jobs = {int(row["id"]): row for row in schedule_jobs}
    daily_profit_jobs = [
        daily_row
        for row in profit_jobs
        for daily_row in _daily_profitability_job_rows(
            row,
            decorated_jobs[int(row["jobId"])],
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
            shift_rate_cents=shift_rate_cents,
        )
    ]

    unmatched_actual_hours = sum(
        float(segment["hours"])
        for segment in unmatched
        if segment.get("finalized") and segment.get("hours") is not None
    )
    correction_candidate_segments = _payroll_correction_candidate_segments(
        profit_jobs,
        decorated_jobs,
        unmatched,
        app_timezone=app_timezone,
        range_start=range_start,
        range_end=range_end,
        shift_rate_cents=shift_rate_cents,
    )
    return {
        "success": True,
        "period": "week",
        "timezone": timezone_name,
        "observedAt": _utc_iso(observed_at),
        "weekStart": str(week_start),
        "weekEnd": str(week_end),
        "summary": {
            **_aggregate_actual_profitability_rows(profit_jobs),
            "unmatchedActualHours": round(unmatched_actual_hours, 2),
            "unmatchedActualSegmentCount": len(unmatched),
        },
        "bySite": _group_profitability_by_site(profit_jobs),
        "byDay": _daily_profitability_rows(
            week_start,
            week_end,
            daily_profit_jobs,
            unmatched,
            app_timezone=app_timezone,
            range_start=range_start,
            range_end=range_end,
        ),
        "jobs": profit_jobs,
        "unmatchedActualSegments": unmatched,
        "_payrollCorrectionCandidateSegments": correction_candidate_segments,
    }


def _public_forecast_job(row: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def _load_utilization_shift_evidence(
    cursor: Any,
    shift_id: int,
    *,
    lock_shift: bool = False,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    cursor.execute(
        f"""
        SELECT s.id, s.employee_id, e.name AS employee_name,
               s.location_id, s.location_label, s.job_id,
               s.clock_in, s.clock_out, s.time_category,
               s.non_productive_type
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE s.id = %s
        {"FOR UPDATE OF s" if lock_shift else ""}
        """,
        (shift_id,),
    )
    shift_row = cursor.fetchone()
    if not shift_row:
        raise HTTPException(status_code=404, detail="Paid shift not found")
    shift = _cursor_rows_as_dicts(cursor, [shift_row])[0]
    if lock_shift:
        # The shift row is the first mutable evidence lock. Take table-level
        # read locks only after it so job deletion cannot hold the shift while
        # waiting to upgrade its jobs table lock. QR review and job editing do
        # not share the timesheet advisory lock, so these locks freeze their
        # classifier inputs through the append-only ledger insert.
        cursor.execute("LOCK TABLE site_check_ins, jobs IN SHARE MODE")

    cursor.execute(
        """
        SELECT v.id, v.shift_id, v.location_id, v.location_label,
               v.arrival_time, v.sequence_version, v.site_check_in_id,
               sci.employee_id AS check_in_employee_id,
               sci.location_id AS check_in_location_id,
               sci.server_checked_in_at AS check_in_at,
               sci.classification AS check_in_classification,
               sci.review_status AS check_in_review_status,
               COALESCE(
                   CASE
                       WHEN check_in_job.location_id = v.location_id
                       THEN sci.job_id
                   END,
                   CASE
                       WHEN shift_job.location_id = v.location_id
                       THEN evidence_shift.job_id
                   END
               ) AS job_id
        FROM visits v
        JOIN shifts evidence_shift ON evidence_shift.id = v.shift_id
        LEFT JOIN jobs shift_job ON shift_job.id = evidence_shift.job_id
        LEFT JOIN site_check_ins sci ON sci.id = v.site_check_in_id
        LEFT JOIN jobs check_in_job ON check_in_job.id = sci.job_id
        WHERE v.shift_id = %s
        ORDER BY v.arrival_time, v.id
        """,
        (shift_id,),
    )
    visits = _cursor_rows_as_dicts(cursor, cursor.fetchall())
    cursor.execute(
        """
        SELECT id, shift_id, visit_id, location_id, location_label,
               departure_time
        FROM departures
        WHERE shift_id = %s
        ORDER BY departure_time, id
        """,
        (shift_id,),
    )
    departures = _cursor_rows_as_dicts(cursor, cursor.fetchall())
    return shift, visits, departures


def _utilization_review_signature(item: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        int(item["shiftId"]),
        str(item["code"]),
        int(item["visitId"]) if item.get("visitId") is not None else None,
        int(item["departureId"]) if item.get("departureId") is not None else None,
        tuple(sorted(int(value) for value in item.get("relatedShiftIds") or ())),
    )


def _validate_reviewed_departure(
    *,
    shift: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
    raw_review_items: List[Dict[str, Any]],
    target_review: Dict[str, Any],
    effective_departure_at: datetime,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    visit_id = int(target_review["visitId"])
    visit = next(
        (row for row in visits if int(row["id"]) == visit_id),
        None,
    )
    if visit is None:
        raise HTTPException(status_code=409, detail="Arrival evidence changed; refresh")
    if shift.get("clock_out") is None or str(shift.get("time_category")) != "productive":
        raise HTTPException(
            status_code=409,
            detail="Only a closed productive shift can receive this correction",
        )
    if effective_departure_at.tzinfo is None:
        raise HTTPException(
            status_code=400,
            detail="effectiveDepartureAt must include a timezone",
        )
    normalized_departure = effective_departure_at.astimezone(timezone.utc)
    if normalized_departure.microsecond:
        raise HTTPException(
            status_code=400,
            detail="effectiveDepartureAt must use whole-second precision",
        )
    if not (visit["arrival_time"] < normalized_departure <= shift["clock_out"]):
        raise HTTPException(
            status_code=400,
            detail="Reviewed departure must be after arrival and no later than Clock Out",
        )
    if visit.get("location_id") is None:
        raise HTTPException(
            status_code=409,
            detail="Arrival Site identity changed; refresh",
        )
    if any(
        row.get("visit_id") is not None and int(row["visit_id"]) == visit_id
        for row in departures
    ):
        raise HTTPException(
            status_code=409,
            detail="A recorded departure now exists; refresh",
        )

    overlay = {
        "id": None,
        "shift_id": int(shift["id"]),
        "visit_id": visit_id,
        "location_id": int(visit["location_id"]),
        "location_label": str(visit.get("location_label") or ""),
        "departure_time": normalized_departure,
        "reviewed_correction_id": 0,
    }
    corrected_segments, corrected_reviews = _closed_shift_utilization(
        shift,
        visits,
        departures,
        reviewed_departures={visit_id: overlay},
    )
    target_signature = _utilization_review_signature(target_review)
    expected_review_signatures = {
        _utilization_review_signature(item)
        for item in raw_review_items
        if _utilization_review_signature(item) != target_signature
    }
    corrected_review_signatures = {
        _utilization_review_signature(item) for item in corrected_reviews
    }
    if target_signature in corrected_review_signatures:
        raise HTTPException(
            status_code=409,
            detail="The reviewed departure did not resolve this evidence gap",
        )
    if corrected_review_signatures != expected_review_signatures:
        raise HTTPException(
            status_code=409,
            detail="The reviewed departure conflicts with other time evidence",
        )
    paid_seconds = _epoch_second(shift["clock_out"]) - _epoch_second(shift["clock_in"])
    corrected_seconds = sum(
        int(segment["end_second"]) - int(segment["start_second"])
        for segment in corrected_segments
    )
    if corrected_seconds != paid_seconds:
        raise HTTPException(
            status_code=409,
            detail="The reviewed departure does not reconcile to paid time",
        )
    return overlay, corrected_segments


def _utilization_correction_response(
    row: Dict[str, Any],
    *,
    idempotent_replay: bool,
) -> Dict[str, Any]:
    result = dict(row.get("result") or {})
    return {
        "success": True,
        "archiveStored": True,
        "idempotentReplay": idempotent_replay,
        "batchId": int(row["id"]),
        "reviewKey": result.get("reviewKey"),
        "evidenceFingerprint": result.get("evidenceFingerprint"),
        "shiftId": result.get("shiftId"),
        "visitId": result.get("visitId"),
        "effectiveDepartureAt": result.get("effectiveDepartureAt"),
        # This receipt describes what the append-only correction established
        # when it was recorded. Current review state is deliberately owned by
        # GET /utilization, whose evidence fingerprint can reopen or remove the
        # item after later raw evidence arrives.
        "reviewStateAtApply": "corrected",
    }


def _normalize_reviewed_departure_input(
    value: datetime,
    app_timezone: ZoneInfo,
) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc)
    candidates = {
        value.replace(tzinfo=app_timezone, fold=fold).astimezone(timezone.utc)
        for fold in (0, 1)
        if (
            value.replace(tzinfo=app_timezone, fold=fold)
            .astimezone(timezone.utc)
            .astimezone(app_timezone)
            .replace(tzinfo=None)
            == value
        )
    }
    if not candidates:
        raise HTTPException(
            status_code=400,
            detail="effectiveDepartureAt is not a valid Central Time",
        )
    if len(candidates) > 1:
        raise HTTPException(
            status_code=400,
            detail=(
                "effectiveDepartureAt is ambiguous at the Central Time change; "
                "include an explicit UTC offset"
            ),
        )
    return candidates.pop()


def build_operations_forecast(
    weeks_ahead: int,
    *,
    timezone_name: str = "America/Chicago",
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    planning_source: str = "calendar",
) -> Dict[str, Any]:
    if weeks_ahead < 1:
        raise ValueError("weeks_ahead must be at least 1")
    if planning_source not in OPERATIONS_FORECAST_PLANNING_SOURCES:
        raise ValueError("planning_source must be calendar or native")

    app_timezone = ZoneInfo(timezone_name)
    observed_at = now_provider().astimezone(timezone.utc)
    today = observed_at.astimezone(app_timezone).date()
    first_week = _sunday_for(today)
    forecast_end = first_week + timedelta(days=weeks_ahead * 7 - 1)

    avg_hourly_rate, global_issues = _average_employee_rate_and_issues()
    if planning_source == "native":
        native_rows, rule_count = _native_projection_rows_for_period(
            today,
            forecast_end,
            app_timezone=app_timezone,
            avg_hourly_rate=avg_hourly_rate,
        )
        forecast_rows = [
            row
            for row in native_rows
            if not (
                row["scheduledDate"] == str(today)
                and row.get("scheduledEnd") is not None
                and datetime.fromisoformat(
                    row["scheduledEnd"].replace("Z", "+00:00")
                )
                <= observed_at
            )
        ]
        weeks = _forecast_weeks_from_rows(
            forecast_rows,
            first_week=first_week,
            weeks_ahead=weeks_ahead,
        )
        return {
            "success": True,
            "timezone": timezone_name,
            "observedAt": _utc_iso(observed_at),
            "asOfDate": str(today),
            "startDate": str(today),
            "endDate": str(forecast_end),
            "weeksAhead": weeks_ahead,
            "planningSource": "native",
            "ruleCount": rule_count,
            "avgLaborRate": _money(_money_cents(avg_hourly_rate)),
            "issues": global_issues,
            "summary": _aggregate_forecast_rows(forecast_rows),
            "weeks": weeks,
            "forecasts": weeks,
        }

    allocation_start = date(today.year, today.month, 1)
    allocation_end = _month_end(forecast_end)
    allocation_jobs = _load_jobs(allocation_start, allocation_end)

    monthly_allocations = monthly_revenue_allocations(
        allocation_jobs,
        app_timezone,
    )

    forecast_jobs = []
    for job in allocation_jobs:
        if not today <= job["scheduled_date"] <= forecast_end or job.get(
            "status"
        ) not in {"scheduled", "in_progress"}:
            continue
        # The first forecast bucket is the current Sunday-Saturday week,
        # but its totals represent only work that is still ahead.  A
        # missing end time stays visible as an explicit setup issue.
        if (
            job.get("status") != "in_progress"
            and job["scheduled_date"] == today
            and job.get("scheduled_end") is not None
            and job["scheduled_end"] <= observed_at
        ):
            continue
        forecast_jobs.append(job)
    expected_hours_learning_by_site = _load_expected_hours_learning_by_site(
        _expected_hours_learning_site_ids(forecast_jobs),
        observed_at=observed_at,
        app_timezone=app_timezone,
    )
    calculated = [
        _forecast_job_values(
            job,
            avg_hourly_rate,
            monthly_allocations,
            expected_hours_learning_by_site,
        )
        for job in forecast_jobs
    ]

    weeks = _forecast_weeks_from_rows(
        calculated,
        first_week=first_week,
        weeks_ahead=weeks_ahead,
    )
    return {
        "success": True,
        "timezone": timezone_name,
        "observedAt": _utc_iso(observed_at),
        "asOfDate": str(today),
        "startDate": str(today),
        "endDate": str(forecast_end),
        "weeksAhead": weeks_ahead,
        "planningSource": "calendar",
        "avgLaborRate": _money(_money_cents(avg_hourly_rate)),
        "issues": global_issues,
        "summary": _aggregate_forecast_rows(calculated),
        "weeks": weeks,
        "forecasts": weeks,
    }


def build_operations_schedule_router(
    *,
    get_current_admin: Callable[..., Dict[str, Any]],
    timezone_name: str = "America/Chicago",
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    timesheet_advisory_lock_id: int,
    append_access_log: Optional[Callable[[Request, str, bool, str], None]] = None,
) -> APIRouter:
    router = APIRouter()
    app_timezone = ZoneInfo(timezone_name)

    @router.get("/api/admin/operations/service-schedule-rules")
    def service_schedule_rules(
        location_id: Optional[int] = Query(default=None, gt=0),
        include_inactive: bool = Query(default=False),
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        clauses = []
        params: List[Any] = []
        if location_id is not None:
            clauses.append("rule.location_id = %s")
            params.append(location_id)
        if not include_inactive:
            clauses.append("rule.active = true")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = db.query_all(
            f"""
            SELECT {_service_schedule_rule_columns()}
            FROM service_schedule_rules rule
            JOIN locations location ON location.id = rule.location_id
            LEFT JOIN customers customer ON customer.id = location.customer_id
            {where}
            ORDER BY location.address, rule.starts_on, rule.local_start_time, rule.id
            """,
            tuple(params),
        )
        return {
            "success": True,
            "rules": [_serialize_service_schedule_rule(dict(row)) for row in rows],
        }

    @router.post("/api/admin/operations/service-schedule-rules", status_code=201)
    def create_service_schedule_rule(
        payload: ServiceScheduleRuleCreateRequest,
        request: Request,
        admin: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        weekdays = _normalize_weekdays(payload.weekdays)
        _validate_service_rule_times(payload.localStartTime, payload.localEndTime)
        if payload.endsOn is not None and payload.endsOn < payload.startsOn:
            raise HTTPException(
                status_code=422,
                detail="endsOn must be on or after startsOn",
            )
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, active
                    FROM locations
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (payload.locationId,),
                )
                site = cur.fetchone()
                if not site or not bool(site["active"]):
                    raise HTTPException(status_code=404, detail="Active Site not found")
                if payload.active and _find_duplicate_service_schedule_rule(
                    cur,
                    location_id=payload.locationId,
                    shift_bucket=payload.shiftBucket,
                    cadence=payload.cadence,
                    weekdays=weekdays,
                    local_start_time=payload.localStartTime,
                    local_end_time=payload.localEndTime,
                    starts_on=payload.startsOn,
                    ends_on=payload.endsOn,
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Active service schedule rule already exists",
                    )
                cur.execute(
                    """
                    INSERT INTO service_schedule_rules (
                        location_id, shift_bucket, cadence, weekdays,
                        local_start_time, local_end_time, starts_on, ends_on,
                        notes, active, created_by, updated_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        payload.locationId,
                        payload.shiftBucket,
                        payload.cadence,
                        weekdays,
                        payload.localStartTime,
                        payload.localEndTime,
                        payload.startsOn,
                        payload.endsOn,
                        payload.notes.strip(),
                        payload.active,
                        int(admin["id"]),
                        int(admin["id"]),
                    ),
                )
                rule_id = int(cur.fetchone()["id"])
                rule = _fetch_service_schedule_rule(cur, rule_id)
        if append_access_log is not None:
            append_access_log(
                request,
                "SERVICE_SCHEDULE_RULE_CREATED",
                True,
                f"Service schedule rule {rule_id} by {admin['name']}",
            )
        return {
            "success": True,
            "rule": _serialize_service_schedule_rule(rule),
        }

    @router.patch("/api/admin/operations/service-schedule-rules/{rule_id}")
    def update_service_schedule_rule(
        rule_id: int,
        payload: ServiceScheduleRuleUpdateRequest,
        request: Request,
        admin: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        updates: List[str] = []
        params: List[Any] = []
        supplied_fields = getattr(payload, "model_fields_set", None)
        if supplied_fields is None:
            supplied_fields = getattr(payload, "__fields_set__", set())
        if payload.shiftBucket is not None:
            updates.append("shift_bucket = %s")
            params.append(payload.shiftBucket)
        if payload.cadence is not None:
            updates.append("cadence = %s")
            params.append(payload.cadence)
        if payload.weekdays is not None:
            updates.append("weekdays = %s")
            params.append(_normalize_weekdays(payload.weekdays))
        if payload.localStartTime is not None:
            updates.append("local_start_time = %s")
            params.append(payload.localStartTime)
        if payload.localEndTime is not None:
            updates.append("local_end_time = %s")
            params.append(payload.localEndTime)
        if payload.startsOn is not None:
            updates.append("starts_on = %s")
            params.append(payload.startsOn)
        if "endsOn" in supplied_fields:
            updates.append("ends_on = %s")
            params.append(payload.endsOn)
        if payload.notes is not None:
            updates.append("notes = %s")
            params.append(payload.notes.strip())
        if payload.active is not None:
            updates.append("active = %s")
            params.append(payload.active)
        if not updates:
            raise HTTPException(status_code=422, detail="No rule fields supplied")
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                existing = _fetch_service_schedule_rule(cur, rule_id, lock=True)
                if not existing:
                    raise HTTPException(
                        status_code=404,
                        detail="Service schedule rule not found",
                    )
                cur.execute(
                    """
                    SELECT active
                    FROM locations
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (existing["location_id"],),
                )
                site = cur.fetchone()
                site_active = bool(site and site["active"])
                starts_on = payload.startsOn or existing["starts_on"]
                ends_on = payload.endsOn if "endsOn" in supplied_fields else existing.get("ends_on")
                if ends_on is not None and ends_on < starts_on:
                    raise HTTPException(
                        status_code=422,
                        detail="endsOn must be on or after startsOn",
                    )
                final_start_time = payload.localStartTime or existing["local_start_time"]
                final_end_time = payload.localEndTime or existing["local_end_time"]
                activates_rule = payload.active is True
                final_active = bool(payload.active) if payload.active is not None else bool(existing["active"])
                if (
                    final_active
                    or payload.localStartTime is not None
                    or payload.localEndTime is not None
                ):
                    _validate_service_rule_times(final_start_time, final_end_time)
                if activates_rule and not site_active:
                    raise HTTPException(
                        status_code=409,
                        detail="Cannot activate a service schedule rule for an archived Site",
                    )
                final_weekdays = (
                    _normalize_weekdays(payload.weekdays)
                    if payload.weekdays is not None
                    else [int(value) for value in existing["weekdays"]]
                )
                if final_active and _find_duplicate_service_schedule_rule(
                    cur,
                    location_id=int(existing["location_id"]),
                    shift_bucket=payload.shiftBucket or str(existing["shift_bucket"]),
                    cadence=payload.cadence or str(existing["cadence"]),
                    weekdays=final_weekdays,
                    local_start_time=final_start_time,
                    local_end_time=final_end_time,
                    starts_on=starts_on,
                    ends_on=ends_on,
                    exclude_rule_id=rule_id,
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Active service schedule rule already exists",
                    )
                updates.extend(["updated_by = %s", "updated_at = NOW()"])
                params.extend([int(admin["id"]), rule_id])
                cur.execute(
                    f"""
                    UPDATE service_schedule_rules
                    SET {', '.join(updates)}
                    WHERE id = %s
                    """,
                    tuple(params),
                )
                rule = _fetch_service_schedule_rule(cur, rule_id)
        if append_access_log is not None:
            append_access_log(
                request,
                "SERVICE_SCHEDULE_RULE_UPDATED",
                True,
                f"Service schedule rule {rule_id} by {admin['name']}",
            )
        return {
            "success": True,
            "rule": _serialize_service_schedule_rule(rule),
        }

    @router.post("/api/admin/operations/native-schedule-preview")
    def native_schedule_preview(
        payload: NativeSchedulePreviewRequest,
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        if payload.endDate < payload.startDate:
            raise HTTPException(
                status_code=400,
                detail="endDate must be on or after startDate",
            )
        if (payload.endDate - payload.startDate).days > 120:
            raise HTTPException(
                status_code=400,
                detail="Native schedule preview is limited to 121 days",
            )
        avg_hourly_rate, global_issues = _average_employee_rate_and_issues()
        preview_rows, rule_count = _native_projection_rows_for_period(
            payload.startDate,
            payload.endDate,
            app_timezone=app_timezone,
            avg_hourly_rate=avg_hourly_rate,
        )
        first_week = _sunday_for(payload.startDate)
        last_week = _sunday_for(payload.endDate)
        week_count = ((last_week - first_week).days // 7) + 1
        weeks = _forecast_weeks_from_rows(
            preview_rows,
            first_week=first_week,
            weeks_ahead=week_count,
        )
        return {
            "success": True,
            "mode": "shadow",
            "planningSource": "native",
            "timezone": timezone_name,
            "startDate": str(payload.startDate),
            "endDate": str(payload.endDate),
            "ruleCount": rule_count,
            "issues": global_issues,
            "summary": _aggregate_forecast_rows(preview_rows),
            "weeks": weeks,
            "jobs": [_public_forecast_job(row) for row in preview_rows],
        }

    @router.get("/api/admin/operations/schedule")
    def operations_schedule(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
        planning_source: str = Query(default="calendar"),
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        if planning_source not in OPERATIONS_FORECAST_PLANNING_SOURCES:
            raise HTTPException(
                status_code=400,
                detail="planning_source must be calendar or native",
            )
        observed_at = now_provider().astimezone(timezone.utc)
        local_today = observed_at.astimezone(app_timezone).date()
        resolved_start = start_date or _sunday_for(local_today)
        resolved_end = end_date or (resolved_start + timedelta(days=6))
        if resolved_end < resolved_start:
            raise HTTPException(
                status_code=400,
                detail="end_date must be on or after start_date",
            )

        range_start, range_end = _local_bounds(
            resolved_start,
            resolved_end,
            app_timezone,
        )
        if planning_source == "native":
            avg_hourly_rate, global_issues = _average_employee_rate_and_issues()
            native_issues = [
                _issue(
                    "native_actual_matching_not_joined",
                    "Native Site-rule Schedule rows do not reconcile actual paid time yet.",
                ),
                *global_issues,
            ]
            native_rows, rule_count = _native_projection_rows_for_period(
                resolved_start - timedelta(days=1),
                resolved_end,
                app_timezone=app_timezone,
                avg_hourly_rate=avg_hourly_rate,
            )
            visible_native_rows = [
                row
                for row in native_rows
                if _native_row_schedule_visible(
                    row,
                    range_start=range_start,
                    range_end=range_end,
                    resolved_start=resolved_start,
                    resolved_end=resolved_end,
                )
            ]
            schedule_jobs = [
                _native_schedule_job(row, observed_at) for row in visible_native_rows
            ]
            _, unmatched, _ = _decorate_schedule_jobs(
                [],
                range_start,
                range_end,
                observed_at,
                app_timezone,
                visible_range_start=range_start,
                visible_range_end=range_end,
            )
            active_jobs = [job for job in schedule_jobs if job["includedInPlan"]]
            known_planned_hours = sum(
                float(job["plannedHours"])
                for job in active_jobs
                if job.get("plannedHours") is not None
            )
            planned_incomplete = sum(
                1 for job in active_jobs if job.get("plannedHours") is None
            )
            unmatched_actual = sum(
                float(segment["hours"])
                for segment in unmatched
                if segment.get("finalized") and segment.get("hours") is not None
            )
            in_progress_workers = {
                segment["employeeId"]
                for segment in unmatched
                if segment.get("finalized") is False
                and segment.get("employeeId") is not None
            }
            return {
                "success": True,
                "timezone": timezone_name,
                "observedAt": _utc_iso(observed_at),
                "startDate": str(resolved_start),
                "endDate": str(resolved_end),
                "planningSource": "native",
                "ruleCount": rule_count,
                "issues": native_issues,
                "summary": {
                    "jobCount": len(active_jobs),
                    "visibleJobCount": len(schedule_jobs),
                    "cancelledJobCount": 0,
                    "excludedJobCount": sum(
                        1 for job in schedule_jobs if not job["includedInPlan"]
                    ),
                    "plannedHours": _complete_hours(
                        known_planned_hours,
                        planned_incomplete,
                    ),
                    "knownPlannedHours": round(known_planned_hours, 2),
                    "plannedHoursComplete": planned_incomplete == 0,
                    "actualHours": 0.0,
                    "varianceHours": (
                        round(0.0 - known_planned_hours, 2)
                        if planned_incomplete == 0
                        else None
                    ),
                    "unmatchedActualHours": round(unmatched_actual, 2),
                    "inProgressWorkerCount": len(in_progress_workers),
                    "issueCount": sum(len(job["issues"]) for job in schedule_jobs)
                    + len(native_issues),
                },
                "jobs": schedule_jobs,
                "unmatchedActualSegments": unmatched,
            }
        jobs = _load_jobs(
            resolved_start,
            resolved_end,
            window_start=range_start,
            window_end=range_end,
        )
        expected_hours_learning_by_site = _load_expected_hours_learning_by_site(
            _expected_hours_learning_site_ids(jobs),
            observed_at=observed_at,
            app_timezone=app_timezone,
        )
        scheduled_starts = [
            job["scheduled_start"]
            for job in jobs
            if job.get("scheduled_start") is not None
        ]
        scheduled_ends = [
            job["scheduled_end"] for job in jobs if job.get("scheduled_end") is not None
        ]
        evidence_range_start = min([range_start, *scheduled_starts])
        evidence_range_end = max([range_end, *scheduled_ends])
        schedule_jobs, unmatched, _ = _decorate_schedule_jobs(
            jobs,
            evidence_range_start,
            evidence_range_end,
            observed_at,
            app_timezone,
            visible_range_start=range_start,
            visible_range_end=range_end,
            expected_hours_learning_by_site=expected_hours_learning_by_site,
        )
        active_jobs = [job for job in schedule_jobs if job["includedInPlan"]]
        known_planned_hours = sum(
            float(job["plannedHours"])
            for job in active_jobs
            if job.get("plannedHours") is not None
        )
        planned_incomplete = sum(
            1 for job in active_jobs if job.get("plannedHours") is None
        )
        finalized_actual = sum(float(job["actualHours"]) for job in schedule_jobs)
        unmatched_actual = sum(
            float(segment["hours"])
            for segment in unmatched
            if segment.get("finalized") and segment.get("hours") is not None
        )
        in_progress_workers = {
            worker["employeeId"]
            for job in schedule_jobs
            for worker in job["workers"]
            if worker["status"] == "in_progress"
        }
        return {
            "success": True,
            "timezone": timezone_name,
            "observedAt": _utc_iso(observed_at),
            "startDate": str(resolved_start),
            "endDate": str(resolved_end),
            "planningSource": "calendar",
            "summary": {
                "jobCount": len(active_jobs),
                "visibleJobCount": len(schedule_jobs),
                "cancelledJobCount": sum(
                    1 for job in schedule_jobs if job["status"] == "cancelled"
                ),
                "excludedJobCount": sum(
                    1
                    for job in schedule_jobs
                    if job["status"] != "cancelled" and not job["includedInPlan"]
                ),
                "plannedHours": _complete_hours(
                    known_planned_hours,
                    planned_incomplete,
                ),
                "knownPlannedHours": round(known_planned_hours, 2),
                "plannedHoursComplete": planned_incomplete == 0,
                "actualHours": round(finalized_actual, 2),
                "varianceHours": (
                    round(finalized_actual - known_planned_hours, 2)
                    if planned_incomplete == 0
                    else None
                ),
                "unmatchedActualHours": round(unmatched_actual, 2),
                "inProgressWorkerCount": len(in_progress_workers),
                "issueCount": sum(len(job["issues"]) for job in schedule_jobs),
            },
            "jobs": schedule_jobs,
            "unmatchedActualSegments": unmatched,
        }

    @router.get("/api/admin/operations/utilization")
    def operations_utilization(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        observed_at = now_provider().astimezone(timezone.utc)
        local_today = observed_at.astimezone(app_timezone).date()
        resolved_start = start_date or _sunday_for(local_today)
        resolved_end = end_date or (resolved_start + timedelta(days=6))
        if resolved_end < resolved_start:
            raise HTTPException(
                status_code=400,
                detail="end_date must be on or after start_date",
            )

        range_start, range_end = _local_bounds(
            resolved_start,
            resolved_end,
            app_timezone,
        )
        shifts, visits, departures = _load_utilization_evidence(
            range_start,
            range_end,
            observed_at,
        )
        evidence_by_shift = {
            int(shift["id"]): _utilization_shift_evidence_snapshot(
                shift,
                visits.get(int(shift["id"]), []),
                departures.get(int(shift["id"]), []),
            )
            for shift in shifts
        }
        raw_by_shift: Dict[int, Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]] = {}
        shift_review_items: List[Dict[str, Any]] = []
        finalized_shift_ids: set[int] = set()
        open_shift_ids: set[int] = set()
        for shift in shifts:
            shift_id = int(shift["id"])
            if shift.get("clock_out") is None:
                open_shift_ids.add(shift_id)
            else:
                finalized_shift_ids.add(shift_id)
            raw_segments, raw_review_items = _closed_shift_utilization(
                shift,
                visits.get(shift_id, []),
                departures.get(shift_id, []),
            )
            prepared_review_items = _prepare_utilization_review_items(
                raw_review_items,
                evidence_by_shift,
            )
            raw_by_shift[shift_id] = (raw_segments, prepared_review_items)
            shift_review_items.extend(prepared_review_items)

        correction_rows = _utilization_correction_rows(
            item["reviewKey"] for item in shift_review_items
        )
        _attach_utilization_correction_state(shift_review_items, correction_rows)
        reviewed_departures_by_shift: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(
            dict
        )
        for item in shift_review_items:
            correction = item.get("_currentCorrection")
            if correction is None or item.get("visitId") is None:
                continue
            reviewed_departures_by_shift[int(item["shiftId"])][int(item["visitId"])] = (
                _reviewed_departure_overlay(correction)
            )

        segments: List[Dict[str, Any]] = []
        for shift in shifts:
            shift_id = int(shift["id"])
            if reviewed_departures_by_shift.get(shift_id):
                shift_segments, _ = _closed_shift_utilization(
                    shift,
                    visits.get(shift_id, []),
                    departures.get(shift_id, []),
                    reviewed_departures=reviewed_departures_by_shift[shift_id],
                )
            else:
                shift_segments = raw_by_shift[shift_id][0]
            for segment in shift_segments:
                segments.extend(
                    _split_utilization_segment(
                        segment,
                        range_start=range_start,
                        range_end=range_end,
                        app_timezone=app_timezone,
                    )
                )

        segments, overlap_review_items = _collapse_overlapping_paid_segments(segments)
        prepared_overlap_items = _prepare_utilization_review_items(
            overlap_review_items,
            evidence_by_shift,
        )
        _attach_utilization_correction_state(prepared_overlap_items, [])
        review_items = [*shift_review_items, *prepared_overlap_items]
        rows = _utilization_rows(segments)
        summary = _utilization_totals(segments)
        overlapping_shift_ids = {
            shift_id
            for item in overlap_review_items
            for shift_id in item["relatedShiftIds"]
        }
        summary.update(
            {
                "finalizedShiftCount": len(finalized_shift_ids),
                "openShiftCount": len(open_shift_ids),
                "overlappingShiftCount": len(overlapping_shift_ids),
                "reviewItemCount": len(review_items),
                "openReviewItemCount": sum(
                    1 for item in review_items if item["hasOpenReview"]
                ),
                "correctedReviewItemCount": sum(
                    1 for item in review_items if item["reviewState"] == "corrected"
                ),
            }
        )
        ordered_review_items = sorted(
            review_items,
            key=lambda item: (
                item.get("occurredAt") or datetime.min.replace(tzinfo=timezone.utc),
                int(item["employeeId"]),
                int(item["shiftId"]),
                str(item["code"]),
            ),
        )
        return {
            "success": True,
            "timezone": timezone_name,
            "observedAt": _utc_iso(observed_at),
            "startDate": str(resolved_start),
            "endDate": str(resolved_end),
            "evidenceVersion": UTILIZATION_EVIDENCE_VERSION,
            "summary": summary,
            "rows": rows,
            "reviewItems": [
                _serialize_utilization_review_item(item, app_timezone)
                for item in ordered_review_items
            ],
        }

    @router.post(
        "/api/admin/operations/utilization/reviews/"
        "{review_key}/missing-departure"
    )
    def correct_utilization_missing_departure(
        review_key: str,
        payload: UtilizationMissingDepartureCorrectionRequest,
        current_admin: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", review_key):
            raise HTTPException(status_code=400, detail="Invalid utilization review key")
        reason = payload.reason.strip()
        if len(reason) < 10:
            raise HTTPException(
                status_code=400,
                detail="Correction reason must be at least 10 non-space characters",
            )
        effective_departure_at = _normalize_reviewed_departure_input(
            payload.effectiveDepartureAt,
            app_timezone,
        )
        if effective_departure_at.microsecond:
            raise HTTPException(
                status_code=400,
                detail="effectiveDepartureAt must use whole-second precision",
            )
        if effective_departure_at > now_provider().astimezone(timezone.utc):
            raise HTTPException(
                status_code=400,
                detail="Reviewed departure cannot be in the future",
            )

        plan_token = hashlib.sha256(
            (
                f"{UTILIZATION_MISSING_DEPARTURE_CORRECTION}:"
                f"{payload.idempotencyKey}"
            ).encode("utf-8")
        ).hexdigest()
        normalized_request = {
            "reviewKey": review_key,
            "shiftId": int(payload.shiftId),
            "visitId": int(payload.visitId),
            "evidenceFingerprint": payload.evidenceFingerprint,
            "effectiveDepartureAt": _utc_iso(effective_departure_at),
            "reason": reason,
        }
        request_fingerprint = hashlib.sha256(
            json.dumps(
                normalized_request,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (timesheet_advisory_lock_id,),
                )
                cursor.execute(
                    """
                    SELECT id, plan_token, applied_by_employee_id, applied_by_name,
                           reason, snapshot, result, created_at
                    FROM time_data_correction_batches
                    WHERE plan_token = %s
                    """,
                    (plan_token,),
                )
                existing_row = cursor.fetchone()
                if existing_row:
                    existing = dict(existing_row)
                    existing_fingerprint = str(
                        (existing.get("snapshot") or {}).get("requestFingerprint")
                        or ""
                    )
                    if existing_fingerprint != request_fingerprint:
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                "This correction request identity was already used "
                                "for different data"
                            ),
                        )
                    return _utilization_correction_response(
                        existing,
                        idempotent_replay=True,
                    )

                shift, visits, departures = _load_utilization_shift_evidence(
                    cursor,
                    int(payload.shiftId),
                    lock_shift=True,
                )
                _, raw_review_items = _closed_shift_utilization(
                    shift,
                    visits,
                    departures,
                )
                evidence_by_shift = {
                    int(shift["id"]): _utilization_shift_evidence_snapshot(
                        shift,
                        visits,
                        departures,
                    )
                }
                prepared_review_items = _prepare_utilization_review_items(
                    raw_review_items,
                    evidence_by_shift,
                )
                target_review = next(
                    (
                        item
                        for item in prepared_review_items
                        if item["reviewKey"] == review_key
                        and item["code"] == "missing_departure"
                        and item.get("visitId") == int(payload.visitId)
                    ),
                    None,
                )
                if target_review is None:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "The missing-departure review changed or no longer "
                            "exists; refresh before correcting"
                        ),
                    )
                if (
                    str(target_review["evidenceFingerprint"])
                    != payload.evidenceFingerprint
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Utilization evidence changed; refresh before correcting",
                    )

                overlay, corrected_segments = _validate_reviewed_departure(
                    shift=shift,
                    visits=visits,
                    departures=departures,
                    raw_review_items=raw_review_items,
                    target_review=target_review,
                    effective_departure_at=effective_departure_at,
                )
                visit = next(
                    row for row in visits if int(row["id"]) == int(payload.visitId)
                )
                snapshot = {
                    "correctionType": UTILIZATION_MISSING_DEPARTURE_CORRECTION,
                    "requestFingerprint": request_fingerprint,
                    "reviewKey": review_key,
                    "evidenceVersion": UTILIZATION_EVIDENCE_VERSION,
                    "evidenceFingerprint": target_review["evidenceFingerprint"],
                    "evidence": target_review["_evidenceSnapshot"],
                    "request": normalized_request,
                }
                result = {
                    "correctionType": UTILIZATION_MISSING_DEPARTURE_CORRECTION,
                    "reviewKey": review_key,
                    "evidenceVersion": UTILIZATION_EVIDENCE_VERSION,
                    "evidenceFingerprint": target_review["evidenceFingerprint"],
                    "shiftId": int(shift["id"]),
                    "visitId": int(visit["id"]),
                    "locationId": int(overlay["location_id"]),
                    "locationLabel": str(overlay.get("location_label") or ""),
                    "jobId": (
                        int(visit["job_id"])
                        if visit.get("job_id") is not None
                        else None
                    ),
                    "effectiveDepartureAt": _utc_iso(
                        overlay["departure_time"]
                    ),
                    "derivedIntervalCount": len(corrected_segments),
                    "evidence": ["reviewed_departure"],
                }
                cursor.execute(
                    """
                    INSERT INTO time_data_correction_batches (
                        plan_token,
                        applied_by_employee_id,
                        applied_by_name,
                        reason,
                        snapshot,
                        result
                    )
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
                    RETURNING id, plan_token, applied_by_employee_id,
                              applied_by_name, reason, snapshot, result, created_at
                    """,
                    (
                        plan_token,
                        int(current_admin["id"]),
                        str(current_admin["name"]),
                        reason,
                        json.dumps(snapshot, sort_keys=True),
                        json.dumps(result, sort_keys=True),
                    ),
                )
                inserted = dict(cursor.fetchone())

        return _utilization_correction_response(
            inserted,
            idempotent_replay=False,
        )

    @router.post("/api/admin/operations/sites/{site_id}/expected-hours-baseline/decision")
    def decide_expected_hours_baseline(
        site_id: int,
        payload: ExpectedHoursBaselineDecisionRequest,
        current_admin: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        observed_at = now_provider().astimezone(timezone.utc)
        reason = payload.reason.strip()
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                site = _load_expected_hours_site(site_id, cursor=cursor)
                if site is None or not bool(site.get("active")):
                    raise HTTPException(status_code=404, detail="Site not found")
                _require_current_site_update_token(site, payload.expectedUpdateToken)
                learning_by_site = _load_expected_hours_learning_by_site(
                    [site_id],
                    observed_at=observed_at,
                    app_timezone=app_timezone,
                    cursor=cursor,
                )
                baseline = _expected_hours_baseline(
                    _baseline_job_from_site(site),
                    learning_by_site,
                )
                current_fingerprint = baseline.get("baselineFingerprint")
                if baseline["state"] != "suggested" or current_fingerprint is None:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "expected_hours_baseline_not_suggested",
                            "message": (
                                "This Site does not have a current expected-hours "
                                "suggestion to decide."
                            ),
                            "details": {
                                "siteId": site_id,
                                "state": baseline["state"],
                                "source": baseline["source"],
                            },
                        },
                    )
                if current_fingerprint != payload.baselineFingerprint:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "stale_expected_hours_baseline",
                            "message": (
                                "Expected-hours evidence changed after it was read; "
                                "reload before deciding."
                            ),
                            "details": {
                                "siteId": site_id,
                                "currentFingerprint": current_fingerprint,
                            },
                        },
                    )

                baseline_snapshot_json = json.dumps(baseline, sort_keys=True)
                if payload.decision == "accept":
                    suggested_hours = Decimal(str(baseline["suggestedHours"])).quantize(
                        Decimal("0.01"),
                        rounding=ROUND_HALF_UP,
                    )
                    if suggested_hours > EXPECTED_HOURS_MAX:
                        raise HTTPException(
                            status_code=409,
                            detail={
                                "code": "expected_hours_baseline_out_of_range",
                                "message": (
                                    "The learned expected-hours suggestion is outside "
                                    "the supported Site expected-hours range."
                                ),
                                "details": {
                                    "siteId": site_id,
                                    "suggestedHours": float(suggested_hours),
                                },
                            },
                        )
                    cursor.execute(
                        """
                        UPDATE locations
                        SET expected_hours = %s,
                            expected_hours_source = 'learned_accepted',
                            expected_hours_learning_decision = 'accepted',
                            expected_hours_learning_fingerprint = %s,
                            expected_hours_learning_snapshot = %s::jsonb,
                            expected_hours_learning_decided_at = NOW(),
                            expected_hours_learning_decided_by = %s,
                            expected_hours_learning_decision_reason = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (
                            suggested_hours,
                            current_fingerprint,
                            baseline_snapshot_json,
                            int(current_admin["id"]),
                            reason,
                            site_id,
                        ),
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE locations
                        SET expected_hours_learning_decision = 'rejected',
                            expected_hours_learning_fingerprint = %s,
                            expected_hours_learning_snapshot = %s::jsonb,
                            expected_hours_learning_decided_at = NOW(),
                            expected_hours_learning_decided_by = %s,
                            expected_hours_learning_decision_reason = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (
                            current_fingerprint,
                            baseline_snapshot_json,
                            int(current_admin["id"]),
                            reason,
                            site_id,
                        ),
                    )

                updated_site = _load_expected_hours_site(site_id, cursor=cursor)
                updated_baseline = _expected_hours_baseline(
                    _baseline_job_from_site(updated_site),
                    learning_by_site,
                )

        return {
            "success": True,
            "siteId": site_id,
            "decision": payload.decision,
            "expectedHours": updated_baseline["plannedHours"],
            "expectedHoursBaseline": updated_baseline,
            "siteUpdateToken": _entity_update_token("site", updated_site),
        }

    @router.get("/api/admin/operations/forecast")
    def operations_forecast(
        weeks_ahead: int = Query(default=4),
        planning_source: str = Query(default="calendar"),
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        if weeks_ahead not in OPERATIONS_FORECAST_ALLOWED_WEEKS:
            raise HTTPException(
                status_code=400,
                detail="weeks_ahead must be one of: 4, 8, 12",
            )
        if planning_source not in OPERATIONS_FORECAST_PLANNING_SOURCES:
            raise HTTPException(
                status_code=400,
                detail="planning_source must be calendar or native",
            )
        return build_operations_forecast(
            weeks_ahead,
            timezone_name=timezone_name,
            now_provider=now_provider,
            planning_source=planning_source,
        )

    return router
