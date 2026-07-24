"""Read-only canonical Schedule and Forecast views built from jobs.

Google Calendar synchronization owns source-linked job planning.  This module
never mutates jobs or time evidence: it projects the existing rows into the
operator-facing agenda and forecast.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

import db
from fastapi import APIRouter, Depends, HTTPException, Query


MoneyCents = Optional[int]
SOURCE_ROLE_SITE_TYPES = {
    "residential_morning": "Residential",
    "commercial_evening_night": "Commercial",
}


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


def _sunday_for(day: date) -> date:
    return day - timedelta(days=(day.weekday() + 1) % 7)


def _month_end(day: date) -> date:
    next_month = (
        date(day.year + 1, 1, 1)
        if day.month == 12
        else date(day.year, day.month + 1, 1)
    )
    return next_month - timedelta(days=1)


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
    return db.query_all(
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
    )


def _load_linked_job_metadata(job_ids: Iterable[int]) -> Dict[int, Dict[str, Any]]:
    """Load explicit-link identity independently of the visible job window."""

    ids = sorted(set(int(job_id) for job_id in job_ids))
    if not ids:
        return {}
    return {
        int(row["id"]): row
        for row in db.query_all(
            """
            SELECT id, location_id, status
            FROM jobs
            WHERE id = ANY(%s)
            ORDER BY id
            """,
            (ids,),
        )
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
        if job.get("site_expected_hours") is None:
            issues.append(
                _issue(
                    "missing_expected_hours",
                    "Expected labor hours per visit are not configured for this Site.",
                )
            )
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
) -> Tuple[
    List[Dict[str, Any]],
    Dict[int, List[Dict[str, Any]]],
    Dict[int, List[Dict[str, Any]]],
    Dict[Tuple[int, int], List[datetime]],
    List[Dict[str, Any]],
]:
    linked_job_ids = [int(job_id) for job_id in visible_job_ids]
    shifts = db.query_all(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name, e.hourly_rate,
               s.location_id, s.location_label, s.clock_in, s.clock_out,
               s.job_id
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE s.time_category = 'productive'
          AND (
              (
                  s.clock_in < %s
                  AND COALESCE(s.clock_out, %s) > %s
              )
              OR EXISTS (
                  SELECT 1
                  FROM site_check_ins linked_sci
                  WHERE linked_sci.employee_id = s.employee_id
                    AND linked_sci.job_id = ANY(%s)
                    AND linked_sci.server_checked_in_at < %s
                    AND s.clock_in <= linked_sci.server_checked_in_at
                    AND COALESCE(s.clock_out, %s)
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
            range_end,
            observed_at,
            range_start,
            linked_job_ids,
            observed_at,
            observed_at,
        ),
    )

    shift_ids = [int(row["id"]) for row in shifts]
    visits: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    if shift_ids:
        for row in db.query_all(
            """
            SELECT id, shift_id, location_id, location_label, customer_name,
                   arrival_time
            FROM visits
            WHERE shift_id = ANY(%s)
            ORDER BY shift_id, arrival_time, id
            """,
            (shift_ids,),
        ):
            visits[int(row["shift_id"])].append(row)

    departures: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    if shift_ids:
        for row in db.query_all(
            """
            SELECT id, shift_id, location_id, location_label, customer_name,
                   departure_time
            FROM departures
            WHERE shift_id = ANY(%s)
            ORDER BY shift_id, departure_time, id
            """,
            (shift_ids,),
        ):
            departures[int(row["shift_id"])].append(row)

    qr_by_employee_site: Dict[Tuple[int, int], List[datetime]] = defaultdict(list)
    qr_rows = db.query_all(
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
                  WHERE evidence_shift.id = ANY(%s)
                    AND evidence_shift.employee_id = sci.employee_id
                    AND evidence_shift.clock_in <= sci.server_checked_in_at
                    AND COALESCE(evidence_shift.clock_out, %s)
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
            shift_ids,
            observed_at,
        ),
    )
    for row in qr_rows:
        qr_by_employee_site[(int(row["employee_id"]), int(row["location_id"]))].append(
            row["server_checked_in_at"]
        )

    return shifts, visits, departures, qr_by_employee_site, qr_rows


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
        if visit_site_id is not None:
            for departure in departures:
                if int(departure["id"]) in used_departures:
                    continue
                if departure.get("location_id") != visit_site_id:
                    continue
                if arrival <= departure["departure_time"] <= next_arrival:
                    matching_departure = departure
                    used_departures.add(int(departure["id"]))
                    break
        work_end = (
            matching_departure["departure_time"]
            if matching_departure is not None
            else next_arrival
        )

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
        elif current_site is not None and row.get("location_id") == current_site:
            current_site = None
            current_label = ""
            current_since = event_at
            evidence = ["clock_in", "departure"]

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


def _decorate_schedule_jobs(
    jobs: List[Dict[str, Any]],
    range_start: datetime,
    range_end: datetime,
    observed_at: datetime,
    app_timezone: ZoneInfo,
    *,
    visible_range_start: Optional[datetime] = None,
    visible_range_end: Optional[datetime] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
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
                cursor = first_service_date
                while cursor <= last_service_date:
                    service_dates.add(cursor)
                    cursor += timedelta(days=1)
            for service_date in service_dates:
                jobs_by_site_date[(int(job["location_id"]), service_date)].append(job)

    shifts, visits, departures, qr_by_employee_site, qr_rows = _load_time_evidence(
        range_start,
        range_end,
        observed_at,
        jobs_by_id,
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
            ]
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
    unmatched: List[Dict[str, Any]] = []
    for segment in segments:
        job, reason, candidate_job_ids = _match_segment_to_job(
            segment,
            jobs_by_site_date,
            jobs_by_id,
            app_timezone,
            linked_jobs_by_id=linked_jobs_by_id,
        )
        if job is None:
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

        job_id = int(job["id"])
        employee_id = int(segment["employee_id"])
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
            rate_cents = _money_cents(worker.pop("hourlyRate"))
            labor_cents = (
                int(
                    (Decimal(str(finalized_hours)) * Decimal(rate_cents)).quantize(
                        Decimal("1"), rounding=ROUND_HALF_UP
                    )
                )
                if rate_cents is not None
                else None
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
        in_progress = any(worker["status"] == "in_progress" for worker in workers)
        status = str(job.get("status") or "scheduled")
        included_in_plan = status != "cancelled" and _job_is_projection_eligible(job)
        execution_status = (
            "cancelled"
            if status == "cancelled"
            else (
                "in_progress"
                if in_progress
                else (
                    "completed"
                    if status == "completed" or actual_hours > 0
                    else "scheduled"
                )
            )
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
                },
                "issues": issues,
            }
        )
    return output, unmatched


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
) -> Dict[str, Any]:
    issues = _job_issues(job)
    included_in_forecast = _job_is_projection_eligible(job)
    expected_hours = (
        float(job["site_expected_hours"])
        if job.get("site_expected_hours") is not None
        else None
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


def _public_forecast_job(row: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def build_operations_schedule_router(
    *,
    get_current_admin: Callable[..., Dict[str, Any]],
    timezone_name: str = "America/Chicago",
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> APIRouter:
    router = APIRouter()
    app_timezone = ZoneInfo(timezone_name)

    @router.get("/api/admin/operations/schedule")
    def operations_schedule(
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
        jobs = _load_jobs(
            resolved_start,
            resolved_end,
            window_start=range_start,
            window_end=range_end,
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
        schedule_jobs, unmatched = _decorate_schedule_jobs(
            jobs,
            evidence_range_start,
            evidence_range_end,
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

    @router.get("/api/admin/operations/forecast")
    def operations_forecast(
        weeks_ahead: int = Query(default=4),
        _: Dict[str, Any] = Depends(get_current_admin),
    ) -> Dict[str, Any]:
        if weeks_ahead not in {4, 8, 12}:
            raise HTTPException(
                status_code=400,
                detail="weeks_ahead must be one of: 4, 8, 12",
            )

        observed_at = now_provider().astimezone(timezone.utc)
        today = observed_at.astimezone(app_timezone).date()
        first_week = _sunday_for(today)
        forecast_end = first_week + timedelta(days=weeks_ahead * 7 - 1)
        allocation_start = date(today.year, today.month, 1)
        allocation_end = _month_end(forecast_end)
        allocation_jobs = _load_jobs(allocation_start, allocation_end)

        wage_rows = db.query_all(
            """
            SELECT id, hourly_rate
            FROM employees
            WHERE active = true AND role = 'employee'
            ORDER BY id
            """
        )
        configured_wages = [
            Decimal(str(row["hourly_rate"]))
            for row in wage_rows
            if row.get("hourly_rate") is not None
        ]
        avg_hourly_rate: Optional[Decimal] = None
        if configured_wages:
            avg_hourly_rate = sum(configured_wages) / Decimal(len(configured_wages))

        monthly_groups: Dict[Tuple[int, int, int], List[Dict[str, Any]]] = defaultdict(
            list
        )
        for job in allocation_jobs:
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
        calculated = [
            _forecast_job_values(job, avg_hourly_rate, monthly_allocations)
            for job in forecast_jobs
        ]

        weeks: List[Dict[str, Any]] = []
        for offset in range(weeks_ahead):
            week_start = first_week + timedelta(weeks=offset)
            week_end = week_start + timedelta(days=6)
            week_rows = [
                row
                for row in calculated
                if week_start
                <= datetime.strptime(row["scheduledDate"], "%Y-%m-%d").date()
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

        global_issues: List[Dict[str, str]] = []
        missing_wages = len(wage_rows) - len(configured_wages)
        if not configured_wages:
            global_issues.append(
                _issue(
                    "missing_average_employee_rate",
                    "No active employee has a configured hourly rate.",
                )
            )
        elif missing_wages:
            global_issues.append(
                _issue(
                    "employees_missing_rates",
                    f"{missing_wages} active employee account(s) have no hourly rate.",
                )
            )
        return {
            "success": True,
            "timezone": timezone_name,
            "observedAt": _utc_iso(observed_at),
            "asOfDate": str(today),
            "startDate": str(today),
            "endDate": str(forecast_end),
            "weeksAhead": weeks_ahead,
            "avgLaborRate": _money(_money_cents(avg_hourly_rate)),
            "issues": global_issues,
            "summary": _aggregate_forecast_rows(calculated),
            "weeks": weeks,
            "forecasts": weeks,
        }

    return router
