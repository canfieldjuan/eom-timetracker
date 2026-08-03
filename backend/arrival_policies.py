"""Arrival-policy persistence and deterministic local-time evaluation.

Policy revisions are append-only. A scope's latest revision is its complete
current state; retirement inserts another revision instead of mutating history.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import db


POLICY_MODES = {"fixed", "window", "flexible", "not_before"}
POLICY_STATES = {"active", "retired"}


def ensure_schema() -> None:
    """Install the additive policy schema in an existing deployment."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS arrival_policy_revisions (
            id               BIGSERIAL PRIMARY KEY,
            scope_type       VARCHAR(16) NOT NULL
                                 CHECK (scope_type IN ('site', 'appointment')),
            site_id          INTEGER NOT NULL,
            job_id           INTEGER,
            version          INTEGER NOT NULL CHECK (version > 0),
            state            VARCHAR(16) NOT NULL
                                 CHECK (state IN ('active', 'retired')),
            mode             VARCHAR(16)
                                 CHECK (mode IN ('fixed', 'window', 'flexible', 'not_before')),
            timezone         TEXT,
            fixed_arrival    TIME,
            grace_minutes    INTEGER
                                 CHECK (grace_minutes BETWEEN 0 AND 120),
            window_start     TIME,
            window_end       TIME,
            not_before       TIME,
            update_token     VARCHAR(64) NOT NULL UNIQUE
                                 CHECK (update_token ~ '^[0-9a-f]{64}$'),
            change_note      TEXT NOT NULL
                                 CHECK (char_length(change_note) BETWEEN 3 AND 500),
            created_by       INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_by_name  TEXT NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (
                (scope_type = 'site' AND job_id IS NULL)
                OR (scope_type = 'appointment' AND job_id IS NOT NULL)
            ),
            CHECK (
                state = 'retired'
                OR (
                    mode IS NOT NULL
                    AND timezone IS NOT NULL
                    AND (
                        (mode = 'fixed'
                         AND fixed_arrival IS NOT NULL
                         AND grace_minutes IS NOT NULL
                         AND window_start IS NULL
                         AND window_end IS NULL
                         AND not_before IS NULL)
                        OR
                        (mode = 'window'
                         AND fixed_arrival IS NULL
                         AND grace_minutes IS NULL
                         AND window_start IS NOT NULL
                         AND window_end IS NOT NULL
                         AND not_before IS NULL)
                        OR
                        (mode = 'flexible'
                         AND fixed_arrival IS NULL
                         AND grace_minutes IS NULL
                         AND window_start IS NULL
                         AND window_end IS NULL
                         AND not_before IS NULL)
                        OR
                        (mode = 'not_before'
                         AND fixed_arrival IS NULL
                         AND grace_minutes IS NULL
                         AND window_start IS NULL
                         AND window_end IS NULL
                         AND not_before IS NOT NULL)
                    )
                )
            ),
            UNIQUE (scope_type, site_id, job_id, version)
        )
        """
    )
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_arrival_policy_site_version
        ON arrival_policy_revisions(site_id, version)
        WHERE scope_type = 'site'
        """
    )
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_arrival_policy_appointment_version
        ON arrival_policy_revisions(job_id, version)
        WHERE scope_type = 'appointment'
        """
    )
    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_arrival_policy_site_latest
        ON arrival_policy_revisions(site_id, version DESC)
        WHERE scope_type = 'site'
        """
    )
    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_arrival_policy_appointment_latest
        ON arrival_policy_revisions(job_id, version DESC)
        WHERE scope_type = 'appointment'
        """
    )
    db.execute(
        """
        ALTER TABLE site_check_ins
        ADD COLUMN IF NOT EXISTS arrival_policy_revision_id
            BIGINT REFERENCES arrival_policy_revisions(id) ON DELETE SET NULL
        """
    )
    db.execute(
        """
        ALTER TABLE site_check_ins
        ADD COLUMN IF NOT EXISTS arrival_policy_snapshot JSONB
        """
    )


def _time_text(value: Optional[time]) -> Optional[str]:
    return value.strftime("%H:%M") if value is not None else None


def serialize_revision(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "scopeType": str(row["scope_type"]),
        "siteId": int(row["site_id"]),
        "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
        "version": int(row["version"]),
        "state": str(row["state"]),
        "mode": row.get("mode"),
        "timezone": row.get("timezone"),
        "fixedArrival": _time_text(row.get("fixed_arrival")),
        "graceMinutes": (
            int(row["grace_minutes"])
            if row.get("grace_minutes") is not None
            else None
        ),
        "windowStart": _time_text(row.get("window_start")),
        "windowEnd": _time_text(row.get("window_end")),
        "notBefore": _time_text(row.get("not_before")),
        "updateToken": str(row["update_token"]),
        "changeNote": str(row["change_note"]),
        "createdBy": (
            int(row["created_by"]) if row.get("created_by") is not None else None
        ),
        "createdByName": str(row["created_by_name"]),
        "createdAt": (
            row["created_at"]
            .astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
    }


def snapshot_revision(row: Dict[str, Any]) -> Dict[str, Any]:
    serialized = serialize_revision(row)
    return {
        key: serialized[key]
        for key in (
            "id",
            "scopeType",
            "siteId",
            "jobId",
            "version",
            "state",
            "mode",
            "timezone",
            "fixedArrival",
            "graceMinutes",
            "windowStart",
            "windowEnd",
            "notBefore",
        )
    }


def policy_update_token(
    scope_type: str,
    site_id: int,
    job_id: Optional[int],
    version: int,
    created_at: datetime,
) -> str:
    canonical = ":".join(
        (
            scope_type,
            str(site_id),
            str(job_id or ""),
            str(version),
            created_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
        )
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def tokens_match(expected: str, actual: str) -> bool:
    return hmac.compare_digest(expected, actual)


def latest_revision(
    cur: Any,
    *,
    scope_type: str,
    site_id: int,
    job_id: Optional[int],
    for_update: bool = False,
) -> Optional[Dict[str, Any]]:
    if scope_type == "site":
        where = "scope_type = 'site' AND site_id = %s"
        params: Tuple[Any, ...] = (site_id,)
    else:
        where = "scope_type = 'appointment' AND job_id = %s"
        params = (job_id,)
    cur.execute(
        f"""
        SELECT *
        FROM arrival_policy_revisions
        WHERE {where}
        ORDER BY version DESC, id DESC
        LIMIT 1
        """ + (" FOR UPDATE" if for_update else ""),
        params,
    )
    row = cur.fetchone()
    return dict(row) if row else None


def rebind_active_appointment_policy(
    cur: Any,
    *,
    job_id: int,
    new_site_id: int,
    actor_id: int,
    actor_name: str,
) -> Optional[int]:
    """Append a revision when Calendar moves a policy-owning appointment."""

    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))",
        (f"arrival-policy:appointment:{job_id}",),
    )
    current = latest_revision(
        cur,
        scope_type="appointment",
        site_id=new_site_id,
        job_id=job_id,
        for_update=True,
    )
    if (
        current is None
        or current["state"] != "active"
        or int(current["site_id"]) == new_site_id
    ):
        return None

    version = int(current["version"]) + 1
    created_at = datetime.now(timezone.utc)
    update_token = policy_update_token(
        "appointment",
        new_site_id,
        job_id,
        version,
        created_at,
    )
    change_note = (
        "Calendar sync moved canonical appointment "
        f"from Site {int(current['site_id'])} to Site {new_site_id}"
    )
    cur.execute(
        """
        INSERT INTO arrival_policy_revisions (
            scope_type, site_id, job_id, version, state, mode,
            timezone, fixed_arrival, grace_minutes, window_start,
            window_end, not_before, update_token, change_note,
            created_by, created_by_name, created_at
        )
        VALUES (
            'appointment', %s, %s, %s, 'active', %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s
        )
        RETURNING id
        """,
        (
            new_site_id,
            job_id,
            version,
            current["mode"],
            current["timezone"],
            current["fixed_arrival"],
            current["grace_minutes"],
            current["window_start"],
            current["window_end"],
            current["not_before"],
            update_token,
            change_note,
            actor_id,
            actor_name,
            created_at,
        ),
    )
    return int(cur.fetchone()["id"])


def resolve_policy(
    cur: Any,
    *,
    site_id: int,
    job_id: Optional[int],
) -> Optional[Dict[str, Any]]:
    if job_id is not None:
        appointment = latest_revision(
            cur,
            scope_type="appointment",
            site_id=site_id,
            job_id=job_id,
        )
        if appointment and appointment["state"] == "active":
            return appointment
    site = latest_revision(
        cur,
        scope_type="site",
        site_id=site_id,
        job_id=None,
    )
    if site and site["state"] == "active":
        return site
    return None


def _wall_time_candidates(
    local_date: date,
    local_time: time,
    zone: ZoneInfo,
) -> list[datetime]:
    naive = datetime.combine(local_date, local_time)
    candidates: list[datetime] = []
    seen_offsets: set[timedelta] = set()
    for fold in (0, 1):
        aware = naive.replace(tzinfo=zone, fold=fold)
        round_trip = aware.astimezone(timezone.utc).astimezone(zone)
        if round_trip.replace(tzinfo=None) != naive or round_trip.fold != fold:
            continue
        offset = aware.utcoffset()
        if offset is None or offset in seen_offsets:
            continue
        seen_offsets.add(offset)
        candidates.append(aware.astimezone(timezone.utc))
    return candidates


def resolve_wall_time(
    local_date: date,
    local_time: time,
    timezone_name: str,
) -> Tuple[Optional[datetime], Optional[str]]:
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError):
        return None, "invalid_policy_timezone"
    candidates = _wall_time_candidates(local_date, local_time, zone)
    if not candidates:
        return None, "invalid_policy_local_time"
    if len(candidates) > 1:
        return None, "ambiguous_policy_local_time"
    return candidates[0], None


def validate_policy_values(
    *,
    mode: str,
    timezone_name: str,
    fixed_arrival: Optional[time],
    grace_minutes: Optional[int],
    window_start: Optional[time],
    window_end: Optional[time],
    not_before: Optional[time],
) -> Dict[str, Any]:
    if mode not in POLICY_MODES:
        raise ValueError("mode must be fixed, window, flexible, or not_before")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("timezone must be a valid IANA timezone") from exc
    fields = {
        "fixed_arrival": fixed_arrival,
        "grace_minutes": grace_minutes,
        "window_start": window_start,
        "window_end": window_end,
        "not_before": not_before,
    }
    for field_name in (
        "fixed_arrival",
        "window_start",
        "window_end",
        "not_before",
    ):
        field_value = fields[field_name]
        if field_value is None:
            continue
        if field_value.tzinfo is not None:
            raise ValueError(f"{field_name} must not include a timezone")
        if field_value.second or field_value.microsecond:
            raise ValueError(f"{field_name} must use HH:MM precision")
    required = {
        "fixed": {"fixed_arrival", "grace_minutes"},
        "window": {"window_start", "window_end"},
        "flexible": set(),
        "not_before": {"not_before"},
    }[mode]
    missing = sorted(name for name in required if fields[name] is None)
    unexpected = sorted(
        name for name, value in fields.items() if value is not None and name not in required
    )
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise ValueError(f"{mode} policy fields are invalid: {'; '.join(details)}")
    return fields


def evaluate_policy(
    policy: Dict[str, Any],
    *,
    site_id: int,
    job: Dict[str, Any],
    checked_in_at: datetime,
) -> Tuple[str, str, str, Dict[str, Any], Optional[datetime], Optional[int]]:
    """Return classification, reason, review state, snapshot, start, grace."""
    snapshot = snapshot_revision(policy)
    snapshot["authority"] = str(policy["scope_type"])
    snapshot["classifiedBy"] = "arrival_policy"
    snapshot["evaluatedAt"] = (
        checked_in_at.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if int(policy["site_id"]) != site_id or int(job.get("location_id") or 0) != site_id:
        return (
            "needs_review",
            "arrival_policy_site_mismatch",
            "pending",
            snapshot,
            None,
            None,
        )
    timezone_name = str(policy.get("timezone") or "")
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError):
        return (
            "needs_review",
            "invalid_policy_timezone",
            "pending",
            snapshot,
            None,
            None,
        )
    job_start = job.get("scheduled_start")
    if not isinstance(job_start, datetime):
        return (
            "needs_review",
            "arrival_policy_missing_job_time",
            "pending",
            snapshot,
            None,
            None,
        )
    anchor_date = job_start.astimezone(zone).date()
    mode = str(policy["mode"])

    if mode == "flexible":
        return (
            "on_time",
            "flexible_arrival_policy",
            "not_required",
            snapshot,
            None,
            None,
        )

    if mode == "fixed":
        scheduled_start, error = resolve_wall_time(
            anchor_date,
            policy["fixed_arrival"],
            timezone_name,
        )
        if error:
            return "needs_review", error, "pending", snapshot, None, None
        grace_minutes = int(policy["grace_minutes"])
        assert scheduled_start is not None
        if checked_in_at <= scheduled_start + timedelta(minutes=grace_minutes):
            result = ("on_time", "within_arrival_policy_grace", "not_required")
        else:
            result = ("late", "after_arrival_policy_grace", "not_required")
        return (*result, snapshot, scheduled_start, grace_minutes)

    if mode == "not_before":
        threshold, error = resolve_wall_time(
            anchor_date,
            policy["not_before"],
            timezone_name,
        )
        if error:
            return "needs_review", error, "pending", snapshot, None, None
        assert threshold is not None
        if checked_in_at < threshold:
            result = ("needs_review", "before_not_before_policy", "pending")
        else:
            result = ("on_time", "not_before_policy_satisfied", "not_required")
        return (*result, snapshot, threshold, None)

    window_start, start_error = resolve_wall_time(
        anchor_date,
        policy["window_start"],
        timezone_name,
    )
    end_date = anchor_date
    if policy["window_end"] <= policy["window_start"]:
        end_date += timedelta(days=1)
    window_end, end_error = resolve_wall_time(
        end_date,
        policy["window_end"],
        timezone_name,
    )
    error = start_error or end_error
    if error:
        return "needs_review", error, "pending", snapshot, None, None
    assert window_start is not None and window_end is not None
    if checked_in_at < window_start:
        result = ("needs_review", "before_arrival_window", "pending")
    elif checked_in_at <= window_end:
        result = ("on_time", "within_arrival_window", "not_required")
    else:
        result = ("late", "after_arrival_window", "not_required")
    snapshot["windowEndUtc"] = (
        window_end.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    return (*result, snapshot, window_start, None)
