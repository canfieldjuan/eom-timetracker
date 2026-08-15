"""Read-only inventory and owner-mapping validation for arrival-policy migration."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from psycopg2.extras import RealDictCursor

import arrival_policies


MAPPING_DISPOSITIONS = {
    "map_to_appointment",
    "promote_to_site",
    "retain_history_only",
    "needs_review",
}


def _utc_text(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _date_text(value: Optional[date]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _time_text(value: Any) -> Optional[str]:
    return value.strftime("%H:%M") if value is not None else None


def _valid_timezone(value: Any) -> bool:
    try:
        ZoneInfo(str(value))
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def _query_all(conn: Any, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, tuple(params))
        return [dict(row) for row in cur.fetchall()]


VOLATILE_FINGERPRINT_KEYS = {
    "asOf",
    "historyReferenceCount",
    "historyReferences",
}


def _stable_inventory_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _stable_inventory_value(child)
            for key, child in value.items()
            if key not in VOLATILE_FINGERPRINT_KEYS
        }
    if isinstance(value, list):
        return [_stable_inventory_value(child) for child in value]
    return value


def _inventory_fingerprint(payload: Dict[str, Any]) -> str:
    stable_payload = _stable_inventory_value(payload)
    canonical = json.dumps(stable_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mapping_grace_minutes(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("grace_minutes must be an integer")
    return value


def build_inventory(
    conn: Any,
    *,
    as_of: datetime,
    schedule_window_hours: int = 12,
) -> Dict[str, Any]:
    """Read legacy policy evidence without writing or inferring from employees."""
    as_of_utc = as_of.astimezone(timezone.utc)
    schedule_window = timedelta(hours=max(1, int(schedule_window_hours)))
    company_today = as_of_utc.astimezone(ZoneInfo("America/Chicago")).date()
    exact_rows = _query_all(
        conn,
        """
        SELECT sc.id, sc.employee_id, e.name AS employee_name,
               sc.location_id, l.address AS site_name, sc.scheduled_start,
               sc.grace_minutes, sc.created_at,
               COUNT(ci.id) AS history_reference_count
        FROM site_check_in_schedules sc
        LEFT JOIN employees e ON e.id = sc.employee_id
        LEFT JOIN locations l ON l.id = sc.location_id
        LEFT JOIN site_check_ins ci ON ci.schedule_id = sc.id
        WHERE sc.cancelled_at IS NULL
          AND sc.scheduled_start >= %s
        GROUP BY sc.id, e.name, l.address
        ORDER BY sc.scheduled_start, sc.id
        """,
        (as_of_utc,),
    )
    recurring_rows = _query_all(
        conn,
        """
        SELECT sr.id, sr.employee_id, e.name AS employee_name,
               sr.location_id, l.address AS site_name, sr.weekdays,
               sr.local_start_time, sr.timezone, sr.starts_on,
               NULLIF(sr.ends_on, 'infinity'::date) AS ends_on,
               sr.grace_minutes, sr.created_at, sr.updated_at,
               COUNT(ci.id) AS history_reference_count
        FROM site_check_in_schedule_rules sr
        LEFT JOIN employees e ON e.id = sr.employee_id
        LEFT JOIN locations l ON l.id = sr.location_id
        LEFT JOIN site_check_ins ci ON ci.schedule_rule_id = sr.id
        WHERE sr.active = true
          AND sr.ends_on >= %s
        GROUP BY sr.id, e.name, l.address
        ORDER BY sr.location_id, sr.local_start_time, sr.id
        """,
        (company_today,),
    )
    jobs = _query_all(
        conn,
        """
        SELECT j.id, j.location_id, j.scheduled_start, j.scheduled_end,
               j.status
        FROM jobs j
        JOIN google_calendar_sources source ON source.id = j.calendar_source_id
        JOIN locations site ON site.id = j.location_id
        WHERE j.status != 'cancelled'
          AND j.source_all_day = false
          AND j.scheduled_start IS NOT NULL
          AND j.scheduled_end IS NOT NULL
          AND j.scheduled_end > j.scheduled_start
          AND site.active = true
          AND (
              (source.role = 'residential_morning'
               AND site.location_type = 'Residential')
              OR
              (source.role = 'commercial_evening_night'
               AND site.location_type = 'Commercial')
          )
        ORDER BY j.id
        """,
    )
    jobs_by_site: Dict[int, List[Dict[str, Any]]] = {}
    for job in jobs:
        jobs_by_site.setdefault(int(job["location_id"]), []).append(job)

    exact: List[Dict[str, Any]] = []
    for row in exact_rows:
        start = row["scheduled_start"]
        candidates = [
            int(job["id"])
            for job in jobs_by_site.get(int(row["location_id"]), [])
            if job["scheduled_start"] < start + schedule_window
            and job["scheduled_end"] > start - schedule_window
        ]
        exact.append(
            {
                "legacyKey": f"exact:{int(row['id'])}",
                "legacyId": int(row["id"]),
                "employeeId": int(row["employee_id"]),
                "employeeName": str(row.get("employee_name") or ""),
                "siteId": int(row["location_id"]),
                "siteName": str(row.get("site_name") or ""),
                "scheduledStart": _utc_text(start),
                "graceMinutes": int(row["grace_minutes"]),
                "historyReferenceCount": int(row["history_reference_count"]),
                "candidateJobIds": candidates,
                "eligibleAppointmentJobId": (
                    candidates[0] if len(candidates) == 1 else None
                ),
            }
        )

    recurring: List[Dict[str, Any]] = [
        {
            "legacyKey": f"recurring:{int(row['id'])}",
            "legacyId": int(row["id"]),
            "employeeId": int(row["employee_id"]),
            "employeeName": str(row.get("employee_name") or ""),
            "siteId": int(row["location_id"]),
            "siteName": str(row.get("site_name") or ""),
            "weekdays": [int(day) for day in row["weekdays"]],
            "localStart": _time_text(row["local_start_time"]),
            "timezone": str(row["timezone"]),
            "timezoneValid": _valid_timezone(row["timezone"]),
            "startsOn": _date_text(row["starts_on"]),
            "endsOn": _date_text(row.get("ends_on")),
            "graceMinutes": int(row["grace_minutes"]),
            "historyReferenceCount": int(row["history_reference_count"]),
        }
        for row in recurring_rows
    ]

    exact_conflicts: List[Dict[str, Any]] = []
    by_exact_site_start: Dict[tuple[int, str], List[str]] = {}
    for row in exact:
        key = (row["siteId"], row["scheduledStart"])
        by_exact_site_start.setdefault(key, []).append(row["legacyKey"])
    for (site_id, scheduled_start), keys in by_exact_site_start.items():
        if len(keys) > 1:
            exact_conflicts.append(
                {
                    "siteId": site_id,
                    "scheduledStart": scheduled_start,
                    "legacyKeys": keys,
                }
            )

    recurring_conflicts: List[Dict[str, Any]] = []
    for index, left in enumerate(recurring):
        for right in recurring[index + 1 :]:
            if left["siteId"] != right["siteId"]:
                continue
            if not set(left["weekdays"]).intersection(right["weekdays"]):
                continue
            left_end = left["endsOn"] or "9999-12-31"
            right_end = right["endsOn"] or "9999-12-31"
            if left["startsOn"] > right_end or right["startsOn"] > left_end:
                continue
            if (
                left["localStart"] == right["localStart"]
                and left["graceMinutes"] == right["graceMinutes"]
                and left["timezone"] == right["timezone"]
            ):
                continue
            recurring_conflicts.append(
                {
                    "siteId": left["siteId"],
                    "legacyKeys": [left["legacyKey"], right["legacyKey"]],
                }
            )

    orphan_rows = _query_all(
        conn,
        """
        SELECT 'exact' AS kind, sc.id, sc.employee_id, sc.location_id
        FROM site_check_in_schedules sc
        LEFT JOIN employees e ON e.id = sc.employee_id
        LEFT JOIN locations l ON l.id = sc.location_id
        WHERE e.id IS NULL OR l.id IS NULL
        UNION ALL
        SELECT 'recurring' AS kind, sr.id, sr.employee_id, sr.location_id
        FROM site_check_in_schedule_rules sr
        LEFT JOIN employees e ON e.id = sr.employee_id
        LEFT JOIN locations l ON l.id = sr.location_id
        WHERE e.id IS NULL OR l.id IS NULL
        ORDER BY kind, id
        """,
    )
    orphan_references = [
        {
            "legacyKey": f"{row['kind']}:{int(row['id'])}",
            "employeeId": int(row["employee_id"]),
            "siteId": int(row["location_id"]),
        }
        for row in orphan_rows
    ]
    history_rows = _query_all(
        conn,
        """
        SELECT 'exact' AS kind, sc.id AS legacy_id, COUNT(ci.id) AS reference_count
        FROM site_check_in_schedules sc
        JOIN site_check_ins ci ON ci.schedule_id = sc.id
        GROUP BY sc.id
        UNION ALL
        SELECT 'recurring' AS kind, sr.id AS legacy_id,
               COUNT(ci.id) AS reference_count
        FROM site_check_in_schedule_rules sr
        JOIN site_check_ins ci ON ci.schedule_rule_id = sr.id
        GROUP BY sr.id
        ORDER BY kind, legacy_id
        """,
    )

    inventory_core = {
        "schemaVersion": 1,
        "asOf": _utc_text(as_of_utc),
        "activeFutureExactSchedules": exact,
        "activeOpenRecurringRules": recurring,
        "conflicts": {
            "exact": exact_conflicts,
            "recurring": recurring_conflicts,
        },
        "orphanReferences": orphan_references,
        "historyReferences": [
            {
                "legacyKey": f"{row['kind']}:{int(row['legacy_id'])}",
                "checkInCount": int(row["reference_count"]),
            }
            for row in history_rows
        ],
        "invalidTimezones": [
            row["legacyKey"] for row in recurring if not row["timezoneValid"]
        ],
        "dateBounds": {
            "exactScheduledStartMin": (
                min((row["scheduledStart"] for row in exact), default=None)
            ),
            "exactScheduledStartMax": (
                max((row["scheduledStart"] for row in exact), default=None)
            ),
            "recurringStartsOnMin": (
                min((row["startsOn"] for row in recurring), default=None)
            ),
            "recurringEndsOnMax": (
                max(
                    (row["endsOn"] for row in recurring if row["endsOn"]),
                    default=None,
                )
            ),
        },
    }
    fingerprint = _inventory_fingerprint(inventory_core)
    mapping_entries = []
    for row in [*exact, *recurring]:
        mapping_entries.append(
            {
                "legacyKey": row["legacyKey"],
                "disposition": None,
                "targetJobId": None,
                "policy": None,
                "ownerConfirmedSitePromotion": False,
                "reviewNote": None,
            }
        )
    return {
        **inventory_core,
        "inventoryFingerprint": fingerprint,
        "ownerMappingTemplate": {
            "schemaVersion": 1,
            "inventoryFingerprint": fingerprint,
            "ownerReviewedBy": None,
            "ownerReviewedAt": None,
            "entries": mapping_entries,
        },
    }
def validate_owner_mapping(
    inventory: Dict[str, Any],
    mapping: Dict[str, Any],
) -> List[str]:
    """Return all validation errors; an empty list is eligible for apply review."""
    errors: List[str] = []
    if mapping.get("schemaVersion") != 1:
        errors.append("mapping.schemaVersion must equal 1")
    if mapping.get("inventoryFingerprint") != inventory.get("inventoryFingerprint"):
        errors.append("mapping inventoryFingerprint does not match this inventory")
    if not str(mapping.get("ownerReviewedBy") or "").strip():
        errors.append("mapping.ownerReviewedBy is required")
    if not str(mapping.get("ownerReviewedAt") or "").strip():
        errors.append("mapping.ownerReviewedAt is required")

    source_rows = {
        row["legacyKey"]: row
        for row in [
            *inventory.get("activeFutureExactSchedules", []),
            *inventory.get("activeOpenRecurringRules", []),
        ]
    }
    entries = mapping.get("entries")
    if not isinstance(entries, list):
        return [*errors, "mapping.entries must be a list"]
    seen: set[str] = set()
    seen_policy_targets: dict[tuple[str, int], str] = {}
    for index, entry in enumerate(entries):
        prefix = f"mapping.entries[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        key = str(entry.get("legacyKey") or "")
        if key in seen:
            errors.append(f"{prefix}.legacyKey is duplicated")
            continue
        seen.add(key)
        source = source_rows.get(key)
        if source is None:
            errors.append(f"{prefix}.legacyKey is not present in the inventory")
            continue
        disposition = entry.get("disposition")
        if disposition not in MAPPING_DISPOSITIONS:
            errors.append(f"{prefix}.disposition must be explicit")
            continue
        if not str(entry.get("reviewNote") or "").strip():
            errors.append(f"{prefix}.reviewNote is required")
        if disposition == "map_to_appointment":
            eligible = source.get("eligibleAppointmentJobId")
            if eligible is None or entry.get("targetJobId") != eligible:
                errors.append(
                    f"{prefix} may map only to its sole eligible appointment"
                )
            else:
                target = ("appointment", int(eligible))
                prior_key = seen_policy_targets.get(target)
                if prior_key is not None:
                    errors.append(
                        f"{prefix} duplicates appointment policy target {eligible} "
                        f"already selected by {prior_key}"
                    )
                else:
                    seen_policy_targets[target] = key
        if (
            disposition == "promote_to_site"
            and entry.get("ownerConfirmedSitePromotion") is not True
        ):
            errors.append(
                f"{prefix}.ownerConfirmedSitePromotion must be true"
            )
        if disposition == "promote_to_site":
            target = ("site", int(source["siteId"]))
            prior_key = seen_policy_targets.get(target)
            if prior_key is not None:
                errors.append(
                    f"{prefix} duplicates Site policy target {source['siteId']} "
                    f"already selected by {prior_key}"
                )
            else:
                seen_policy_targets[target] = key
        if disposition in {"map_to_appointment", "promote_to_site"}:
            policy = entry.get("policy")
            if not isinstance(policy, dict):
                errors.append(f"{prefix}.policy is required")
            elif "employeeId" in policy or "employeeName" in policy:
                errors.append(f"{prefix}.policy must not contain employee identity")
            else:
                try:
                    arrival_policies.validate_policy_values(
                        mode=str(policy.get("mode") or ""),
                        timezone_name=str(policy.get("timezone") or ""),
                        fixed_arrival=_mapping_time(policy.get("fixedArrival")),
                        grace_minutes=_mapping_grace_minutes(
                            policy.get("graceMinutes")
                        ),
                        window_start=_mapping_time(policy.get("windowStart")),
                        window_end=_mapping_time(policy.get("windowEnd")),
                        not_before=_mapping_time(policy.get("notBefore")),
                    )
                except (TypeError, ValueError) as exc:
                    errors.append(f"{prefix}.policy is invalid: {exc}")
    missing = sorted(set(source_rows) - seen)
    extra = sorted(seen - set(source_rows))
    if missing:
        errors.append(f"mapping is missing legacy keys: {', '.join(missing)}")
    if extra:
        errors.append(f"mapping has unknown legacy keys: {', '.join(extra)}")
    return errors


def _mapping_time(value: Any) -> Optional[time]:
    if value is None:
        return None
    if isinstance(value, time):
        return value
    if not isinstance(value, str):
        raise ValueError("arrival policy times must use HH:MM syntax")
    if len(value) != 5 or value[2] != ":":
        raise ValueError("arrival policy times must use HH:MM syntax")
    return time.fromisoformat(value)
