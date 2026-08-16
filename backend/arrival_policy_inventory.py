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


def _current_policy_rows(conn: Any) -> List[Dict[str, Any]]:
    return _query_all(
        conn,
        """
        WITH site AS (
            SELECT DISTINCT ON (site_id)
                   id, scope_type, site_id, job_id, version, state, mode
            FROM arrival_policy_revisions
            WHERE scope_type = 'site'
            ORDER BY site_id, version DESC, id DESC
        ),
        appointment AS (
            SELECT DISTINCT ON (job_id)
                   id, scope_type, site_id, job_id, version, state, mode
            FROM arrival_policy_revisions
            WHERE scope_type = 'appointment'
            ORDER BY job_id, version DESC, id DESC
        )
        SELECT * FROM site
        UNION ALL
        SELECT * FROM appointment
        """,
    )


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
    exact_cutoff = as_of_utc - schedule_window
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
        (exact_cutoff,),
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


def build_cutover_readiness(
    conn: Any,
    *,
    as_of: datetime,
    schedule_window_hours: int = 12,
    owner_mapping: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Report whether legacy schedule fallback can be removed without guessing."""
    inventory = build_inventory(
        conn,
        as_of=as_of,
        schedule_window_hours=schedule_window_hours,
    )
    mapping_errors: List[str] = []
    dispositions: Dict[str, str] = {}
    if owner_mapping is not None:
        mapping_errors = validate_owner_mapping(inventory, owner_mapping)
        if not mapping_errors:
            dispositions = {
                str(entry.get("legacyKey")): str(entry.get("disposition"))
                for entry in owner_mapping.get("entries", [])
                if isinstance(entry, dict)
            }

    current_site_policies: Dict[int, Dict[str, Any]] = {}
    current_appointment_policies: Dict[int, Dict[str, Any]] = {}
    for row in _current_policy_rows(conn):
        if row["state"] != "active":
            continue
        if row["scope_type"] == "site":
            current_site_policies[int(row["site_id"])] = row
        elif row.get("job_id") is not None:
            current_appointment_policies[int(row["job_id"])] = row

    legacy_rows: List[Dict[str, Any]] = []
    blockers: List[Dict[str, Any]] = []

    def add_legacy_row(
        source: Dict[str, Any],
        *,
        legacy_type: str,
        replacement: Optional[Dict[str, Any]],
        block_reason: Optional[str],
    ) -> None:
        key = str(source["legacyKey"])
        owner_disposition = dispositions.get(key)
        row = {
            "legacyKey": key,
            "legacyType": legacy_type,
            "siteId": int(source["siteId"]),
            "siteName": str(source.get("siteName") or ""),
            "employeeId": int(source["employeeId"]),
            "employeeName": str(source.get("employeeName") or ""),
            "ownerDisposition": owner_disposition,
            "currentlyCoveredByPolicy": replacement is not None,
            "replacement": replacement,
            "blocksCutover": block_reason is not None,
            "blockReason": block_reason,
        }
        if legacy_type == "exact":
            row.update(
                {
                    "scheduledStart": source["scheduledStart"],
                    "candidateJobIds": list(source.get("candidateJobIds") or []),
                    "eligibleAppointmentJobId": source.get(
                        "eligibleAppointmentJobId"
                    ),
                }
            )
        else:
            row.update(
                {
                    "weekdays": list(source.get("weekdays") or []),
                    "localStart": source.get("localStart"),
                    "timezone": source.get("timezone"),
                    "startsOn": source.get("startsOn"),
                    "endsOn": source.get("endsOn"),
                }
            )
        legacy_rows.append(row)
        if block_reason is not None:
            blockers.append(
                {
                    "legacyKey": key,
                    "legacyType": legacy_type,
                    "siteId": int(source["siteId"]),
                    "reason": block_reason,
                }
            )

    def replacement_for_exact(source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        job_id = source.get("eligibleAppointmentJobId")
        appointment_policy = (
            current_appointment_policies.get(int(job_id))
            if job_id is not None
            else None
        )
        if appointment_policy is not None:
            return {
                "authority": "appointment",
                "policyRevisionId": int(appointment_policy["id"]),
                "siteId": int(appointment_policy["site_id"]),
                "jobId": int(appointment_policy["job_id"]),
                "mode": appointment_policy.get("mode"),
            }
        site_policy = current_site_policies.get(int(source["siteId"]))
        if site_policy is not None:
            return {
                "authority": "site",
                "policyRevisionId": int(site_policy["id"]),
                "siteId": int(site_policy["site_id"]),
                "mode": site_policy.get("mode"),
            }
        return None

    def replacement_for_recurring(source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        site_policy = current_site_policies.get(int(source["siteId"]))
        if site_policy is None:
            return None
        return {
            "authority": "site",
            "policyRevisionId": int(site_policy["id"]),
            "siteId": int(site_policy["site_id"]),
            "mode": site_policy.get("mode"),
        }

    def block_reason(
        *,
        replacement: Optional[Dict[str, Any]],
        owner_disposition: Optional[str],
    ) -> Optional[str]:
        if owner_mapping is not None and mapping_errors:
            return "owner_mapping_invalid"
        if owner_mapping is not None and owner_disposition == "needs_review":
            return "owner_marked_needs_review"
        if replacement is not None:
            return None
        if owner_mapping is None:
            return "missing_replacement_policy_or_owner_mapping"
        if owner_disposition == "retain_history_only":
            return None
        return "owner_mapping_does_not_retire_or_replace_legacy_row"

    for source in inventory.get("activeFutureExactSchedules", []):
        replacement = replacement_for_exact(source)
        add_legacy_row(
            source,
            legacy_type="exact",
            replacement=replacement,
            block_reason=block_reason(
                replacement=replacement,
                owner_disposition=dispositions.get(str(source["legacyKey"])),
            ),
        )
    for source in inventory.get("activeOpenRecurringRules", []):
        replacement = replacement_for_recurring(source)
        add_legacy_row(
            source,
            legacy_type="recurring",
            replacement=replacement,
            block_reason=block_reason(
                replacement=replacement,
                owner_disposition=dispositions.get(str(source["legacyKey"])),
            ),
        )

    legacy_history = _query_all(
        conn,
        """
        SELECT
            COUNT(*) FILTER (
                WHERE schedule_id IS NOT NULL
                   OR arrival_policy_snapshot->>'classifiedBy' = 'legacy_exact'
            ) AS legacy_exact_count,
            COUNT(*) FILTER (
                WHERE schedule_rule_id IS NOT NULL
                   OR arrival_policy_snapshot->>'classifiedBy' = 'legacy_recurring'
            ) AS legacy_recurring_count
        FROM site_check_ins
        """,
    )
    history_counts = legacy_history[0] if legacy_history else {}
    covered_count = sum(1 for row in legacy_rows if row["currentlyCoveredByPolicy"])
    retained_count = sum(
        1
        for row in legacy_rows
        if row.get("ownerDisposition") == "retain_history_only"
        and not row["blocksCutover"]
    )
    return {
        "schemaVersion": 1,
        "asOf": inventory["asOf"],
        "inventoryFingerprint": inventory["inventoryFingerprint"],
        "scheduleWindowHours": max(1, int(schedule_window_hours)),
        "readyForLegacyFallbackRemoval": not blockers and not mapping_errors,
        "mappingProvided": owner_mapping is not None,
        "mappingValidationErrors": mapping_errors,
        "summary": {
            "legacyRows": len(legacy_rows),
            "coveredByPolicy": covered_count,
            "ownerRetainHistoryOnly": retained_count,
            "blockingRows": len(blockers),
            "historicalLegacyExactCheckIns": int(
                history_counts.get("legacy_exact_count") or 0
            ),
            "historicalLegacyRecurringCheckIns": int(
                history_counts.get("legacy_recurring_count") or 0
            ),
        },
        "legacyRows": legacy_rows,
        "blockers": blockers,
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
