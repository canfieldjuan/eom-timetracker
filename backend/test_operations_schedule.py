from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from fastapi import HTTPException

import db
import operations_schedule as ops
from operations_schedule import (
    _allocate_utilization_minutes,
    _apply_shift_break_minutes_to_segments,
    _collapse_overlapping_paid_segments,
    _closed_shift_utilization,
    _closed_shift_segments,
    _forecast_job_values,
    _job_issues,
    _load_utilization_shift_evidence,
    _match_segment_to_job,
    _normalize_reviewed_departure_input,
    _qr_only_presence_segments,
    _schedule_execution_status,
    _utilization_rows,
    allocate_monthly_cents,
    monthly_revenue_allocations,
)


TEST_PREFIX = "OPS_CANONICAL_TEST"


def test_reviewed_departure_local_time_is_central_and_fails_closed_at_dst_edges():
    chicago = ZoneInfo("America/Chicago")
    assert _normalize_reviewed_departure_input(
        datetime(2026, 7, 20, 9, 30),
        chicago,
    ) == datetime(2026, 7, 20, 14, 30, tzinfo=timezone.utc)
    with pytest.raises(HTTPException, match="not a valid Central Time"):
        _normalize_reviewed_departure_input(
            datetime(2026, 3, 8, 2, 30),
            chicago,
        )
    with pytest.raises(HTTPException, match="ambiguous"):
        _normalize_reviewed_departure_input(
            datetime(2026, 11, 1, 1, 30),
            chicago,
        )


def test_correction_evidence_locks_shift_before_joined_mutable_inputs():
    class RecordingCursor:
        def __init__(self):
            self.queries = []

        def execute(self, query, _params=None):
            self.queries.append(" ".join(str(query).split()))

        def fetchone(self):
            return {"id": 17}

        def fetchall(self):
            return []

    cursor = RecordingCursor()
    shift, visits, departures = _load_utilization_shift_evidence(
        cursor,
        17,
        lock_shift=True,
    )

    assert shift == {"id": 17}
    assert visits == []
    assert departures == []
    assert "FOR UPDATE OF s" in cursor.queries[0]
    assert cursor.queries[1] == "LOCK TABLE site_check_ins, jobs IN SHARE MODE"
    assert "FROM visits v" in cursor.queries[2]
    assert "FROM departures" in cursor.queries[3]


def test_query_all_maps_plain_cursor_tuple_rows():
    class PlainCursor:
        description = (("id",), ("name",))

        def __init__(self):
            self.executed = None
            self.params = None

        def execute(self, query, params=None):
            self.executed = query
            self.params = params

        def fetchall(self):
            return [(17, "Reviewed")]

    cursor = PlainCursor()

    rows = ops._query_all("SELECT id, name FROM reviews WHERE id = %s", (17,), cursor=cursor)

    assert rows == [{"id": 17, "name": "Reviewed"}]
    assert cursor.executed == "SELECT id, name FROM reviews WHERE id = %s"
    assert cursor.params == (17,)


def test_expected_hours_learning_site_ids_skip_manual_expected_hours():
    assert ops._expected_hours_learning_site_ids(
        [
            {"location_id": 17, "site_expected_hours": 2.5},
            {"location_id": 18, "site_expected_hours": None},
            {"location_id": 19, "site_expected_hours": 0},
            {"location_id": None, "site_expected_hours": None},
            {"location_id": 18, "site_expected_hours": None},
        ]
    ) == [18]
    assert ops.EXPECTED_HOURS_LEARNING_EXCLUSION_RULES == tuple(
        rule["code"]
        for rule in ops.EXPECTED_HOURS_LEARNING_EXCLUSION_RULE_DEFINITIONS
    )
    assert {
        rule["source"]
        for rule in ops.EXPECTED_HOURS_LEARNING_EXCLUSION_RULE_DEFINITIONS
    } >= {
        "paired_visit_evidence",
        "invalid_jobs",
        "legacy_shift_jobs",
        "overlap_jobs",
        "contradictory_arrival_jobs",
        "contradictory_departure_jobs",
        "unassigned_worker_jobs",
    }


def test_aggregate_break_minutes_do_not_shorten_multi_site_segments():
    start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    segments = [
        {
            "start": start,
            "end": start + timedelta(hours=1),
            "location_id": 10,
            "job_id": 100,
        },
        {
            "start": start + timedelta(hours=1),
            "end": start + timedelta(hours=3),
            "location_id": 20,
            "job_id": 200,
        },
    ]

    adjusted = _apply_shift_break_minutes_to_segments(segments, 30)

    assert adjusted == segments


def test_aggregate_break_minutes_do_not_shorten_same_site_multi_job_segments():
    start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    segments = [
        {
            "start": start,
            "end": start + timedelta(hours=1),
            "location_id": 10,
            "job_id": 100,
        },
        {
            "start": start + timedelta(hours=1),
            "end": start + timedelta(hours=3),
            "location_id": 10,
            "job_id": 200,
        },
    ]

    adjusted = _apply_shift_break_minutes_to_segments(segments, 30)

    assert adjusted == segments


def test_aggregate_break_minutes_still_shorten_single_site_segments():
    start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    segments = [
        {
            "start": start,
            "end": start + timedelta(hours=3),
            "location_id": 10,
            "job_id": 100,
        },
    ]

    adjusted = _apply_shift_break_minutes_to_segments(segments, 30)

    assert len(adjusted) == 1
    assert adjusted[0]["start"] == start
    assert adjusted[0]["end"] == start + timedelta(hours=2, minutes=30)


@pytest.mark.parametrize(
    (
        "status",
        "in_progress",
        "actual_hours",
        "scheduled_start",
        "scheduled_end",
        "source_all_day",
        "expected",
    ),
    [
        (
            "scheduled",
            False,
            0,
            datetime(2026, 7, 23, 14, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 16, tzinfo=timezone.utc),
            False,
            "scheduled",
        ),
        (
            "scheduled",
            False,
            0,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 14, tzinfo=timezone.utc),
            False,
            "no_actual",
        ),
        (
            "scheduled",
            False,
            0,
            None,
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "scheduled",
        ),
        (
            "scheduled",
            False,
            0,
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            None,
            False,
            "scheduled",
        ),
        (
            "scheduled",
            False,
            0,
            datetime(2026, 7, 23, 14, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "scheduled",
        ),
        (
            "scheduled",
            False,
            0,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            True,
            "scheduled",
        ),
        (
            "cancelled",
            True,
            2,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "cancelled",
        ),
        (
            "completed",
            True,
            2,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "in_progress",
        ),
        (
            "completed",
            False,
            0,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "completed",
        ),
        (
            "scheduled",
            False,
            2,
            datetime(2026, 7, 23, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 23, 13, tzinfo=timezone.utc),
            False,
            "completed",
        ),
    ],
)
def test_schedule_execution_status_uses_elapsed_window_only_after_precedence(
    status,
    in_progress,
    actual_hours,
    scheduled_start,
    scheduled_end,
    source_all_day,
    expected,
):
    assert (
        _schedule_execution_status(
            {
                "status": status,
                "scheduled_start": scheduled_start,
                "scheduled_end": scheduled_end,
                "source_all_day": source_all_day,
            },
            in_progress=in_progress,
            actual_hours=actual_hours,
            observed_at=datetime(2026, 7, 23, 14, tzinfo=timezone.utc),
        )
        == expected
    )


def _clean_rows() -> None:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM time_data_correction_batches
                WHERE snapshot ->> 'correctionType' =
                      'utilization_missing_departure.v1'
                """
            )
            cur.execute(
                """
                DELETE FROM site_qr_action_receipts
                WHERE employee_id IN (
                    SELECT id FROM employees WHERE name LIKE %s
                )
                   OR location_id IN (
                    SELECT id FROM locations WHERE address LIKE %s
                )
                """,
                (f"{TEST_PREFIX}%", f"{TEST_PREFIX}%"),
            )
            cur.execute(
                """
                DELETE FROM site_check_ins
                WHERE employee_id IN (
                    SELECT id FROM employees WHERE name LIKE %s
                )
                   OR location_id IN (
                    SELECT id FROM locations WHERE address LIKE %s
                )
                """,
                (f"{TEST_PREFIX}%", f"{TEST_PREFIX}%"),
            )
            cur.execute(
                """
                DELETE FROM shifts
                WHERE employee_id IN (
                    SELECT id FROM employees WHERE name LIKE %s
                )
                   OR location_id IN (
                    SELECT id FROM locations WHERE address LIKE %s
                )
                """,
                (f"{TEST_PREFIX}%", f"{TEST_PREFIX}%"),
            )
            cur.execute(
                "DELETE FROM schedules WHERE customer_name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM jobs WHERE customer_name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM locations WHERE address LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM customers WHERE name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_sources WHERE calendar_id LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_connections WHERE google_account_email LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM employees WHERE name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )


@pytest.fixture(autouse=True)
def isolate_operations_rows(client):
    _clean_rows()
    yield
    _clean_rows()


def _source(cur, suffix: str, role: str) -> int:
    cur.execute(
        """
        INSERT INTO google_calendar_connections (
            google_account_email, granted_scopes, revoked_at
        )
        VALUES (%s, ARRAY['calendar.readonly'], NOW())
        RETURNING id
        """,
        (f"{TEST_PREFIX}_{suffix}@example.test",),
    )
    connection_id = int(cur.fetchone()[0])
    cur.execute(
        """
        INSERT INTO google_calendar_sources (
            connection_id, role, calendar_id, calendar_name, calendar_timezone
        )
        VALUES (%s, %s, %s, %s, 'America/Chicago')
        RETURNING id
        """,
        (
            connection_id,
            role,
            f"{TEST_PREFIX}_{suffix}",
            f"{TEST_PREFIX} {suffix}",
        ),
    )
    return int(cur.fetchone()[0])


def _customer_site(
    cur,
    suffix: str,
    *,
    site_type: str,
    rate: float,
    rate_type: str,
    expected_hours: float | None,
) -> tuple[int, int]:
    cur.execute(
        "INSERT INTO customers (name) VALUES (%s) RETURNING id",
        (f"{TEST_PREFIX} Customer {suffix}",),
    )
    customer_id = int(cur.fetchone()[0])
    cur.execute(
        """
        INSERT INTO locations (
            customer_id, address, customer_name, location_type,
            rate, rate_type, expected_hours
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            customer_id,
            f"{TEST_PREFIX} Site {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            site_type,
            rate,
            rate_type,
            expected_hours,
        ),
    )
    return customer_id, int(cur.fetchone()[0])


def _job(
    cur,
    *,
    source_id: int,
    location_id: int,
    customer_name: str,
    start: datetime,
    end: datetime,
    source_seed: str,
) -> int:
    source_key = hashlib.sha256(source_seed.encode("utf-8")).hexdigest()
    cur.execute(
        """
        INSERT INTO jobs (
            location_id, customer_name, scheduled_date,
            scheduled_start, scheduled_end, status, calendar_source_id,
            source_calendar_id, source_event_id, source_occurrence_id,
            source_key, source_fingerprint, source_title
        )
        VALUES (
            %s, %s, %s, %s, %s, 'scheduled', %s,
            %s, %s, %s, %s, %s, %s
        )
        RETURNING id
        """,
        (
            location_id,
            customer_name,
            start.astimezone(ZoneInfo("America/Chicago")).date(),
            start,
            end,
            source_id,
            f"{TEST_PREFIX}_calendar",
            source_seed,
            source_seed,
            source_key,
            source_key,
            customer_name,
        ),
    )
    return int(cur.fetchone()[0])


def _employee(cur, suffix: str, rate: float | None) -> int:
    cur.execute(
        """
        INSERT INTO employees (name, password_hash, role, hourly_rate)
        VALUES (%s, 'not-used', 'employee', %s)
        RETURNING id
        """,
        (f"{TEST_PREFIX} Employee {suffix}", rate),
    )
    return int(cur.fetchone()[0])


def _shift(
    cur,
    *,
    employee_id: int,
    start: datetime,
    end: datetime | None,
    service_day: date,
    location_id: int | None = None,
    location_label: str = "",
    job_id: int | None = None,
    time_category: str = "productive",
    non_productive_type: str | None = None,
) -> int:
    total_hours = (
        round((end - start).total_seconds() / 3600, 2) if end is not None else None
    )
    cur.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, job_id,
            clock_in, clock_out, total_hours, local_date,
            timezone, time_category, non_productive_type
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s,
            'America/Chicago', %s, %s
        )
        RETURNING id
        """,
        (
            employee_id,
            location_id,
            location_label,
            job_id,
            start,
            end,
            total_hours,
            service_day,
            time_category,
            non_productive_type,
        ),
    )
    return int(cur.fetchone()[0])


def _check_in(
    cur,
    *,
    employee_id: int,
    location_id: int,
    checked_in_at: datetime,
    job_id: int | None,
    classification: str = "on_time",
    review_status: str = "not_required",
) -> int:
    cur.execute(
        """
        INSERT INTO site_check_ins (
            employee_id, location_id, job_id, server_checked_in_at,
            device_scanned_at, latitude, longitude, accuracy_m,
            geofence_radius_m, distance_m, geofence_status,
            classification, classification_reason,
            device_clock_skew_seconds, review_status
        )
        VALUES (
            %s, %s, %s, %s, %s, 39.12, -88.54, 5,
            100, 3, 'inside', %s, 'test', 0, %s
        )
        RETURNING id
        """,
        (
            employee_id,
            location_id,
            job_id,
            checked_in_at,
            checked_in_at,
            classification,
            review_status,
        ),
    )
    return int(cur.fetchone()[0])


def _visit(
    cur,
    *,
    shift_id: int,
    location_id: int,
    at: datetime,
    suffix: str,
    sequence_version: int = 1,
    site_check_in_id: int | None = None,
    job_id: int | None = None,
) -> int:
    cur.execute(
        """
        INSERT INTO visits (
            shift_id, location_id, location_label, customer_name,
            arrival_time, sequence_version, site_check_in_id, job_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            shift_id,
            location_id,
            f"{TEST_PREFIX} Site {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            at,
            sequence_version,
            site_check_in_id,
            job_id,
        ),
    )
    return int(cur.fetchone()[0])


def _departure(
    cur,
    *,
    shift_id: int,
    location_id: int,
    at: datetime,
    suffix: str,
    visit_id: int | None = None,
) -> int:
    cur.execute(
        """
        INSERT INTO departures (
            shift_id, visit_id, location_id, location_label, customer_name,
            departure_time
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            shift_id,
            visit_id,
            location_id,
            f"{TEST_PREFIX} Site {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            at,
        ),
    )
    return int(cur.fetchone()[0])


def _paired_version_two_visit(
    cur,
    *,
    employee_id: int,
    shift_id: int,
    location_id: int,
    job_id: int,
    arrival: datetime,
    departure: datetime,
    suffix: str,
) -> tuple[int, int]:
    check_in_id = _check_in(
        cur,
        employee_id=employee_id,
        location_id=location_id,
        checked_in_at=arrival,
        job_id=job_id,
    )
    visit_id = _visit(
        cur,
        shift_id=shift_id,
        location_id=location_id,
        at=arrival,
        suffix=suffix,
        sequence_version=2,
        site_check_in_id=check_in_id,
        job_id=job_id,
    )
    departure_id = _departure(
        cur,
        shift_id=shift_id,
        location_id=location_id,
        at=departure,
        suffix=suffix,
        visit_id=visit_id,
    )
    return visit_id, departure_id


def _seed_expected_hours_suggestion(
    cur,
    suffix: str,
    *,
    durations: list[float] | None = None,
) -> dict[str, object]:
    app_timezone = ZoneInfo("America/Chicago")
    today = datetime.now(app_timezone).date()
    source_id = _source(
        cur,
        f"expected_hours_decision_{suffix}",
        "commercial_evening_night",
    )
    _, site_id = _customer_site(
        cur,
        f"Expected Hours Decision {suffix}",
        site_type="Commercial",
        rate=80,
        rate_type="per_visit",
        expected_hours=None,
    )
    employee_id = _employee(cur, f"Expected Hours Decision {suffix}", 25)
    clean_durations = durations or [2, 3, 4]
    # Anchor the completed visits to mid-week (Tuesday) of the three prior
    # complete Sunday-weeks, not raw today-minus-N-days. The learning logic
    # buckets visits by Sunday-week, so day-offsets landed in three distinct
    # weeks on some weekdays and collapsed on others, flipping the learned
    # sample and baseline state depending on the day the test ran (see #132).
    # Week-anchoring keeps the sample deterministic while staying relative to
    # "now" so it never drifts stale.
    current_week_start = today - timedelta(days=(today.weekday() + 1) % 7)
    completed_days = [
        current_week_start - timedelta(days=7 * 3 - 2),
        current_week_start - timedelta(days=7 * 2 - 2),
        current_week_start - timedelta(days=7 * 1 - 2),
    ][: len(clean_durations)]
    for index, (completed_day, duration) in enumerate(
        zip(completed_days, clean_durations)
    ):
        local_start = datetime.combine(
            completed_day,
            time(hour=18),
            tzinfo=app_timezone,
        )
        job_id = _job(
            cur,
            source_id=source_id,
            location_id=site_id,
            customer_name=f"{TEST_PREFIX} Customer Expected Hours Decision {suffix}",
            start=local_start.astimezone(timezone.utc),
            end=(local_start + timedelta(hours=duration)).astimezone(timezone.utc),
            source_seed=f"expected-hours-decision-{suffix}-{index}",
        )
        cur.execute("UPDATE jobs SET status = 'completed' WHERE id = %s", (job_id,))
        shift_id = _shift(
            cur,
            employee_id=employee_id,
            start=local_start.astimezone(timezone.utc),
            end=(local_start + timedelta(hours=duration)).astimezone(timezone.utc),
            service_day=completed_day,
            location_id=site_id,
            location_label=f"{TEST_PREFIX} Site Expected Hours Decision {suffix}",
            job_id=job_id,
        )
        _paired_version_two_visit(
            cur,
            employee_id=employee_id,
            shift_id=shift_id,
            location_id=site_id,
            job_id=job_id,
            arrival=local_start.astimezone(timezone.utc),
            departure=(local_start + timedelta(hours=duration)).astimezone(
                timezone.utc
            ),
            suffix=f"Expected Hours Decision {suffix} {index}",
        )

    future_day = today + timedelta(days=1)
    future_start = datetime.combine(future_day, time(hour=18), tzinfo=app_timezone)
    future_job_id = _job(
        cur,
        source_id=source_id,
        location_id=site_id,
        customer_name=f"{TEST_PREFIX} Customer Expected Hours Decision {suffix}",
        start=future_start.astimezone(timezone.utc),
        end=(future_start + timedelta(hours=2)).astimezone(timezone.utc),
        source_seed=f"expected-hours-decision-{suffix}-future",
    )
    return {
        "sourceId": source_id,
        "siteId": site_id,
        "employeeId": employee_id,
        "futureJobId": future_job_id,
        "futureDay": future_day,
    }


def _add_expected_hours_learning_sample(
    cur,
    *,
    source_id: int,
    site_id: int,
    employee_id: int,
    suffix: str,
    day: date,
    duration: float,
) -> None:
    app_timezone = ZoneInfo("America/Chicago")
    local_start = datetime.combine(day, time(hour=18), tzinfo=app_timezone)
    job_id = _job(
        cur,
        source_id=source_id,
        location_id=site_id,
        customer_name=f"{TEST_PREFIX} Customer Expected Hours Decision {suffix}",
        start=local_start.astimezone(timezone.utc),
        end=(local_start + timedelta(hours=duration)).astimezone(timezone.utc),
        source_seed=f"expected-hours-decision-{suffix}-extra",
    )
    cur.execute("UPDATE jobs SET status = 'completed' WHERE id = %s", (job_id,))
    shift_id = _shift(
        cur,
        employee_id=employee_id,
        start=local_start.astimezone(timezone.utc),
        end=(local_start + timedelta(hours=duration)).astimezone(timezone.utc),
        service_day=day,
        location_id=site_id,
        location_label=f"{TEST_PREFIX} Site Expected Hours Decision {suffix}",
        job_id=job_id,
    )
    _paired_version_two_visit(
        cur,
        employee_id=employee_id,
        shift_id=shift_id,
        location_id=site_id,
        job_id=job_id,
        arrival=local_start.astimezone(timezone.utc),
        departure=(local_start + timedelta(hours=duration)).astimezone(timezone.utc),
        suffix=f"Expected Hours Decision {suffix} extra",
    )


def _reviewed_departure_correction(
    cur,
    *,
    shift_id: int,
    visit_id: int,
    location_id: int,
    effective_departure_at: datetime,
    suffix: str,
) -> int:
    effective_departure_at = effective_departure_at.astimezone(timezone.utc).replace(
        microsecond=0
    )
    review_key = f"test-reviewed-departure:{shift_id}:{visit_id}:{suffix}"
    fingerprint = hashlib.sha256(review_key.encode("utf-8")).hexdigest()
    cur.execute(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name,
               s.location_id, s.location_label, s.job_id,
               s.clock_in, s.clock_out, s.time_category,
               s.non_productive_type
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE s.id = %s
        """,
        (shift_id,),
    )
    shift_row = cur.fetchone()
    shift = dict(zip([column[0] for column in cur.description], shift_row))
    cur.execute(
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
    visit_columns = [column[0] for column in cur.description]
    visits = [dict(zip(visit_columns, row)) for row in cur.fetchall()]
    cur.execute(
        """
        SELECT id, shift_id, visit_id, location_id, location_label,
               departure_time
        FROM departures
        WHERE shift_id = %s
        ORDER BY departure_time, id
        """,
        (shift_id,),
    )
    departure_columns = [column[0] for column in cur.description]
    departures = [dict(zip(departure_columns, row)) for row in cur.fetchall()]
    _, raw_review_items = ops._closed_shift_utilization(
        shift,
        visits,
        departures,
    )
    prepared_reviews = ops._prepare_utilization_review_items(
        raw_review_items,
        {
            shift_id: ops._utilization_shift_evidence_snapshot(
                shift,
                visits,
                departures,
            )
        },
    )
    target_review = next(
        item
        for item in prepared_reviews
        if item["code"] == "missing_departure"
        and item.get("visitId") is not None
        and int(item["visitId"]) == visit_id
    )
    visit = next(row for row in visits if int(row["id"]) == visit_id)
    snapshot = {
        "correctionType": ops.UTILIZATION_MISSING_DEPARTURE_CORRECTION,
        "requestFingerprint": fingerprint,
        "reviewKey": target_review["reviewKey"],
        "evidenceVersion": target_review["evidenceVersion"],
        "evidenceFingerprint": target_review["evidenceFingerprint"],
        "evidence": target_review["_evidenceSnapshot"],
        "request": {"test": suffix},
    }
    result = {
        "correctionType": ops.UTILIZATION_MISSING_DEPARTURE_CORRECTION,
        "reviewKey": target_review["reviewKey"],
        "evidenceVersion": target_review["evidenceVersion"],
        "evidenceFingerprint": target_review["evidenceFingerprint"],
        "shiftId": shift_id,
        "visitId": visit_id,
        "locationId": location_id,
        "locationLabel": f"{TEST_PREFIX} Site {suffix}",
        "jobId": int(visit["job_id"]) if visit.get("job_id") is not None else None,
        "effectiveDepartureAt": effective_departure_at.isoformat().replace(
            "+00:00", "Z"
        ),
        "derivedIntervalCount": 1,
        "evidence": ["reviewed_departure"],
    }
    cur.execute(
        """
        INSERT INTO time_data_correction_batches (
            plan_token,
            applied_by_employee_id,
            applied_by_name,
            reason,
            snapshot,
            result
        )
        VALUES (%s, NULL, 'Mayra', %s, %s::jsonb, %s::jsonb)
        RETURNING id
        """,
        (
            f"test-reviewed-departure-{shift_id}-{visit_id}-{suffix}",
            "Reviewed departure supplied by regression fixture.",
            json.dumps(snapshot, sort_keys=True),
            json.dumps(result, sort_keys=True),
        ),
    )
    return int(cur.fetchone()[0])


def _schedule_body(
    client,
    auth,
    service_day: date,
    *,
    end_day: date | None = None,
) -> dict:
    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(end_day or service_day)},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _utilization_body(
    client,
    auth,
    start_date: date,
    end_date: date | None = None,
) -> dict:
    response = client.get(
        "/api/admin/operations/utilization",
        headers=auth,
        params={
            "start_date": str(start_date),
            "end_date": str(end_date or start_date),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


UTILIZATION_TOTAL_KEYS = {
    "paidSeconds",
    "paidMinutes",
    "onSiteSeconds",
    "onSiteMinutes",
    "travelSeconds",
    "travelMinutes",
    "categorizedSeconds",
    "categorizedMinutes",
    "unclassifiedSeconds",
    "unclassifiedMinutes",
    "reconciles",
}
UTILIZATION_INTERVAL_KEYS = {
    "shiftId",
    "relatedShiftIds",
    "category",
    "categoryDetail",
    "intervalStart",
    "intervalEnd",
    "durationSeconds",
    "durationMinutes",
    "locationId",
    "jobId",
    "visitId",
    "departureId",
    "evidence",
    "reviewCodes",
}


def _assert_utilization_totals(
    value: dict,
    *,
    paid: int,
    on_site: int,
    travel: int,
    categorized: int,
    unclassified: int,
) -> None:
    assert UTILIZATION_TOTAL_KEYS <= value.keys()
    expected_minutes = {
        "paidMinutes": paid,
        "onSiteMinutes": on_site,
        "travelMinutes": travel,
        "categorizedMinutes": categorized,
        "unclassifiedMinutes": unclassified,
    }
    for key, minutes in expected_minutes.items():
        assert value[key] == minutes
        assert value[key.removesuffix("Minutes") + "Seconds"] == minutes * 60
    assert paid == on_site + travel + categorized + unclassified
    assert value["reconciles"] is True


def _utilization_row(body: dict, employee_id: int, service_day: date) -> dict:
    return next(
        row
        for row in body["rows"]
        if row["employeeId"] == employee_id and row["date"] == str(service_day)
    )


def _assert_interval_contract(intervals: list[dict]) -> None:
    assert intervals
    for interval in intervals:
        assert UTILIZATION_INTERVAL_KEYS <= interval.keys()
        assert interval["category"] in {
            "on_site",
            "travel",
            "categorized",
            "unclassified",
        }
        assert isinstance(interval["durationSeconds"], int)
        assert isinstance(interval["durationMinutes"], int)
        assert interval["durationSeconds"] >= 0
        assert interval["durationMinutes"] >= 0
        assert isinstance(interval["evidence"], list)
        assert isinstance(interval["reviewCodes"], list)


def test_utilization_minute_allocation_is_deterministic_and_reconciled():
    segments = [
        {
            "start_second": index * 20,
            "end_second": (index + 1) * 20,
            "shift_id": 1,
            "category": category,
        }
        for index, category in enumerate(("on_site", "travel", "unclassified"))
    ]

    _allocate_utilization_minutes(segments)

    assert [segment["duration_seconds"] for segment in segments] == [20, 20, 20]
    assert [segment["duration_minutes"] for segment in segments] == [1, 0, 0]
    assert sum(segment["duration_minutes"] for segment in segments) == 1


def test_utilization_minute_allocation_is_stable_per_employee_day():
    service_day = date(2026, 7, 20)
    segments = [
        {
            "employee_id": employee_id,
            "employee_name": f"Worker {employee_id}",
            "date": service_day,
            "start_second": employee_id * 100,
            "end_second": employee_id * 100 + 31,
            "shift_id": employee_id,
            "category": "unclassified",
        }
        for employee_id in (1, 2)
    ]

    rows = _utilization_rows(segments)

    assert [row["paidSeconds"] for row in rows] == [31, 31]
    assert [row["paidMinutes"] for row in rows] == [1, 1]
    assert all(row["reconciles"] for row in rows)


def test_utilization_mixed_legacy_arrival_invalidates_paired_site_interval():
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    shift = {
        "id": 1,
        "employee_id": 2,
        "employee_name": "Worker",
        "clock_in": shift_start,
        "clock_out": shift_start + timedelta(hours=3),
        "time_category": "productive",
    }
    visits = [
        {
            "id": 10,
            "location_id": 100,
            "location_label": "Site A",
            "arrival_time": shift_start + timedelta(minutes=30),
            "sequence_version": 2,
            "job_id": 1000,
        },
        {
            "id": 11,
            "location_id": 101,
            "location_label": "Legacy Site",
            "arrival_time": shift_start + timedelta(hours=1),
            "sequence_version": 1,
            "job_id": None,
        },
    ]
    departures = [
        {
            "id": 20,
            "visit_id": 10,
            "location_id": 100,
            "departure_time": shift_start + timedelta(hours=2),
        }
    ]

    segments, review_items = _closed_shift_utilization(
        shift,
        visits,
        departures,
    )

    assert {segment["category"] for segment in segments} == {"unclassified"}
    assert {item["code"] for item in review_items} == {
        "legacy_visit_evidence",
        "overlapping_site_evidence",
    }


@pytest.mark.parametrize(
    ("conflict_minute", "measured_sites", "review_codes"),
    (
        (
            60,
            [101],
            {"legacy_unpaired_departure", "overlapping_site_evidence"},
        ),
        (90, [100, 101], {"legacy_unpaired_departure"}),
    ),
)
def test_utilization_boundary_departure_conflict_fails_closed(
    conflict_minute,
    measured_sites,
    review_codes,
):
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    shift = {
        "id": 1,
        "employee_id": 2,
        "employee_name": "Worker",
        "clock_in": shift_start,
        "clock_out": shift_start + timedelta(hours=3),
        "time_category": "productive",
    }
    visits = [
        {
            "id": 10,
            "location_id": 100,
            "location_label": "Site A",
            "arrival_time": shift_start + timedelta(minutes=30),
            "sequence_version": 2,
            "job_id": 1000,
        },
        {
            "id": 11,
            "location_id": 101,
            "location_label": "Site B",
            "arrival_time": shift_start + timedelta(minutes=90),
            "sequence_version": 2,
            "job_id": 1001,
        },
    ]
    departures = [
        {
            "id": 20,
            "visit_id": 10,
            "location_id": 100,
            "departure_time": shift_start + timedelta(minutes=60),
        },
        {
            "id": 21,
            "visit_id": None,
            "location_id": 102,
            "departure_time": shift_start + timedelta(minutes=conflict_minute),
        },
        {
            "id": 22,
            "visit_id": 11,
            "location_id": 101,
            "departure_time": shift_start + timedelta(minutes=120),
        },
    ]

    segments, review_items = _closed_shift_utilization(
        shift,
        visits,
        departures,
    )

    assert [
        segment.get("location_id")
        for segment in segments
        if segment["category"] != "unclassified"
    ] == measured_sites
    assert not any(segment["category"] == "travel" for segment in segments)
    assert {item["code"] for item in review_items} == review_codes


def test_utilization_simultaneous_arrivals_fail_closed():
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    shift = {
        "id": 1,
        "employee_id": 2,
        "employee_name": "Worker",
        "clock_in": shift_start,
        "clock_out": shift_start + timedelta(hours=3),
        "time_category": "productive",
    }
    visits = [
        {
            "id": 10,
            "location_id": 100,
            "location_label": "Site A",
            "arrival_time": shift_start + timedelta(minutes=15),
            "sequence_version": 2,
            "job_id": 1000,
        },
        {
            "id": 11,
            "location_id": 101,
            "location_label": "Site B",
            "arrival_time": shift_start + timedelta(hours=1),
            "sequence_version": 2,
            "job_id": 1001,
        },
        {
            "id": 12,
            "location_id": 102,
            "location_label": "Site C",
            "arrival_time": shift_start + timedelta(hours=1),
            "sequence_version": 2,
            "job_id": 1002,
        },
    ]
    departures = [
        {
            "id": 20,
            "visit_id": 10,
            "location_id": 100,
            "departure_time": shift_start + timedelta(minutes=30),
        },
        {
            "id": 21,
            "visit_id": 11,
            "location_id": 101,
            "departure_time": shift_start + timedelta(hours=2),
        },
    ]

    segments, review_items = _closed_shift_utilization(
        shift,
        visits,
        departures,
    )

    assert [
        (segment["category"], segment.get("location_id"))
        for segment in segments
        if segment["category"] != "unclassified"
    ] == [("on_site", 100)]
    assert not any(segment["category"] == "travel" for segment in segments)
    assert {item["code"] for item in review_items} >= {
        "missing_departure",
        "simultaneous_arrival_conflict",
        "overlapping_site_evidence",
    }
    assert {
        item["visitId"]
        for item in review_items
        if item["code"] == "simultaneous_arrival_conflict"
    } == {11, 12}


@pytest.mark.parametrize(
    ("review_status", "measured"),
    (("pending", False), ("rejected", False), ("approved", True)),
)
def test_utilization_qr_review_decision_controls_measurement(
    review_status,
    measured,
):
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    shift = {
        "id": 1,
        "employee_id": 2,
        "employee_name": "Worker",
        "clock_in": shift_start,
        "clock_out": shift_start + timedelta(hours=2),
        "time_category": "productive",
    }
    visits = [
        {
            "id": 10,
            "location_id": 100,
            "location_label": "Site A",
            "arrival_time": shift_start + timedelta(minutes=30),
            "sequence_version": 2,
            "site_check_in_id": 30,
            "check_in_employee_id": 2,
            "check_in_location_id": 100,
            "check_in_at": shift_start + timedelta(minutes=30),
            "check_in_classification": "needs_review",
            "check_in_review_status": review_status,
            "job_id": 1000,
        }
    ]
    departures = [
        {
            "id": 20,
            "visit_id": 10,
            "location_id": 100,
            "departure_time": shift_start + timedelta(minutes=90),
        }
    ]

    segments, review_items = _closed_shift_utilization(
        shift,
        visits,
        departures,
    )

    if measured:
        assert {segment["category"] for segment in segments} == {
            "on_site",
            "unclassified",
        }
        assert review_items == []
    else:
        assert {segment["category"] for segment in segments} == {"unclassified"}
        assert [item["code"] for item in review_items] == [
            "unaccepted_site_check_in"
        ]


@pytest.mark.parametrize("mismatch", ("employee", "site", "time"))
def test_utilization_linked_qr_identity_mismatch_fails_closed(mismatch):
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    arrival_time = shift_start + timedelta(minutes=30)
    shift = {
        "id": 1,
        "employee_id": 2,
        "employee_name": "Worker",
        "clock_in": shift_start,
        "clock_out": shift_start + timedelta(hours=2),
        "time_category": "productive",
    }
    visit = {
        "id": 10,
        "location_id": 100,
        "location_label": "Site A",
        "arrival_time": arrival_time,
        "sequence_version": 2,
        "site_check_in_id": 30,
        "check_in_employee_id": 2,
        "check_in_location_id": 100,
        "check_in_at": arrival_time,
        "check_in_classification": "on_time",
        "check_in_review_status": "not_required",
        "job_id": 1000,
    }
    if mismatch == "employee":
        visit["check_in_employee_id"] = 3
    elif mismatch == "site":
        visit["check_in_location_id"] = 101
    else:
        visit["check_in_at"] = arrival_time + timedelta(seconds=1)
    departures = [
        {
            "id": 20,
            "visit_id": 10,
            "location_id": 100,
            "departure_time": shift_start + timedelta(minutes=90),
        }
    ]

    segments, review_items = _closed_shift_utilization(
        shift,
        [visit],
        departures,
    )

    assert {segment["category"] for segment in segments} == {"unclassified"}
    assert [item["code"] for item in review_items] == [
        "site_check_in_identity_mismatch"
    ]


def test_utilization_overlapping_paid_shifts_are_counted_once():
    service_day = date(2026, 7, 20)
    common = {
        "employee_id": 7,
        "employee_name": "Worker",
        "date": service_day,
        "category_detail": None,
        "location_label": "",
        "job_id": None,
        "visit_id": None,
        "departure_id": None,
        "from_location_id": None,
        "to_location_id": None,
        "from_job_id": None,
        "to_job_id": None,
        "evidence": ["test"],
        "review_codes": [],
    }
    segments = [
        {
            **common,
            "shift_id": 1,
            "category": "on_site",
            "start_second": 0,
            "end_second": 120,
            "location_id": 100,
        },
        {
            **common,
            "shift_id": 2,
            "category": "categorized",
            "category_detail": "drive_time",
            "start_second": 60,
            "end_second": 180,
            "location_id": None,
        },
    ]

    collapsed, review_items = _collapse_overlapping_paid_segments(segments)

    assert [
        (
            segment["start_second"],
            segment["end_second"],
            segment["category"],
            segment.get("related_shift_ids"),
        )
        for segment in collapsed
    ] == [
        (0, 60, "on_site", None),
        (60, 120, "unclassified", [1, 2]),
        (120, 180, "categorized", None),
    ]
    assert sum(
        segment["end_second"] - segment["start_second"] for segment in collapsed
    ) == 180
    assert [
        (
            item["code"],
            item["shiftId"],
            item["relatedShiftIds"],
        )
        for item in review_items
    ] == [("overlapping_paid_shifts", 1, [1, 2])]


def _canonical_job(
    cur,
    *,
    suffix: str,
    start: datetime,
    end: datetime,
    site_type: str = "Residential",
) -> tuple[int, int]:
    role = (
        "residential_morning"
        if site_type == "Residential"
        else "commercial_evening_night"
    )
    source_id = _source(cur, f"{suffix}_source", role)
    _, site_id = _customer_site(
        cur,
        suffix,
        site_type=site_type,
        rate=125,
        rate_type="per_visit",
        expected_hours=(end - start).total_seconds() / 3600,
    )
    job_id = _job(
        cur,
        source_id=source_id,
        location_id=site_id,
        customer_name=f"{TEST_PREFIX} Customer {suffix}",
        start=start,
        end=end,
        source_seed=f"{suffix}-job",
    )
    return site_id, job_id


def _schedule_job(body: dict, job_id: int) -> dict:
    return next(job for job in body["jobs"] if job["id"] == job_id)


def _unmatched_for_shift(body: dict, shift_id: int) -> list[dict]:
    return [
        segment
        for segment in body["unmatchedActualSegments"]
        if segment["shiftId"] == shift_id
    ]


def test_operations_schedule_scopes_shift_correction_overlay_to_visible_week(
    client,
    auth,
):
    chicago = ZoneInfo("America/Chicago")
    week_start = date(2026, 7, 19)
    next_week_start = week_start + timedelta(days=7)
    service_day = week_start + timedelta(days=1)
    next_service_day = next_week_start + timedelta(days=1)
    shift_start = datetime(2026, 7, 20, 9, tzinfo=chicago)
    source_shift_end = datetime(2026, 7, 20, 11, tzinfo=chicago)
    current_week_corrected_end = datetime(2026, 7, 20, 12, tzinfo=chicago)
    later_week_corrected_end = datetime(2026, 7, 20, 10, tzinfo=chicago)
    next_shift_start = datetime(2026, 7, 27, 9, tzinfo=chicago)
    next_source_shift_end = datetime(2026, 7, 27, 11, tzinfo=chicago)
    next_corrected_shift_end = datetime(2026, 7, 27, 12, tzinfo=chicago)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="Correction Scope",
                start=shift_start,
                end=current_week_corrected_end,
            )
            employee_id = _employee(cur, "Correction Scope", 20)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=source_shift_end,
                service_day=service_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Correction Scope",
                job_id=job_id,
            )
            next_site_id, next_job_id = _canonical_job(
                cur,
                suffix="Correction Scope Next Week",
                start=next_shift_start,
                end=next_corrected_shift_end,
            )
            next_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=next_shift_start,
                end=next_source_shift_end,
                service_day=next_service_day,
                location_id=next_site_id,
                location_label=f"{TEST_PREFIX} Site Correction Scope Next Week",
                job_id=next_job_id,
            )
            cur.execute(
                """
                INSERT INTO payroll_shift_corrections (
                    week_start,
                    correction_date,
                    employee_id,
                    shift_id,
                    source_clock_in,
                    source_clock_out,
                    source_break_minutes,
                    source_total_minutes,
                    corrected_clock_in,
                    corrected_clock_out,
                    corrected_break_minutes,
                    corrected_total_minutes,
                    reason,
                    status,
                    created_by_employee_id,
                    created_by_name
                )
                VALUES
                    (
                        %s, %s, %s, %s, %s, %s, NULL, 120,
                        %s, %s, 0, 180,
                        'Current payroll week correction.',
                        'active',
                        %s,
                        'Mayra'
                    ),
                    (
                        %s, %s, %s, %s, %s, %s, NULL, 120,
                        %s, %s, 0, 60,
                        'Later payroll week correction must not leak backward.',
                        'active',
                        %s,
                        'Mayra'
                    ),
                    (
                        %s, %s, %s, %s, %s, %s, NULL, 120,
                        %s, %s, 0, 180,
                        'Next payroll week correction.',
                        'active',
                        %s,
                        'Mayra'
                    )
                """,
                (
                    week_start,
                    service_day,
                    employee_id,
                    shift_id,
                    shift_start,
                    source_shift_end,
                    shift_start,
                    current_week_corrected_end,
                    employee_id,
                    next_week_start,
                    next_week_start + timedelta(days=1),
                    employee_id,
                    shift_id,
                    shift_start,
                    source_shift_end,
                    shift_start,
                    later_week_corrected_end,
                    employee_id,
                    next_week_start,
                    next_service_day,
                    employee_id,
                    next_shift_id,
                    next_shift_start,
                    next_source_shift_end,
                    next_shift_start,
                    next_corrected_shift_end,
                    employee_id,
                ),
            )

    body = _schedule_body(client, auth, service_day, end_day=next_service_day)
    job = _schedule_job(body, job_id)
    next_job = _schedule_job(body, next_job_id)

    assert job["actualHours"] == pytest.approx(3.0)
    assert job["actualLaborCost"] == pytest.approx(60.0)
    assert job["workers"][0]["hours"] == pytest.approx(3.0)
    assert next_job["actualHours"] == pytest.approx(3.0)
    assert next_job["actualLaborCost"] == pytest.approx(60.0)
    assert next_job["workers"][0]["hours"] == pytest.approx(3.0)


def test_monthly_allocation_is_exact_and_stable():
    assert allocate_monthly_cents(10_000, [7, 9, 11]) == {
        7: 3334,
        9: 3333,
        11: 3333,
    }
    assert sum(allocate_monthly_cents(10_001, [1, 2, 3, 4]).values()) == 10_001
    assert allocate_monthly_cents(10_000, []) == {}


def test_monthly_revenue_allocations_group_by_site_month_and_skip_cancelled():
    chicago = ZoneInfo("America/Chicago")
    rows = [
        {
            "id": 11,
            "location_id": 9,
            "scheduled_date": date(2026, 2, 1),
            "scheduled_start": datetime(2026, 2, 1, 15, tzinfo=timezone.utc),
            "status": "scheduled",
            "rate": Decimal("100.01"),
            "rate_type": "monthly",
        },
        {
            "id": 12,
            "location_id": 9,
            "scheduled_date": date(2026, 2, 2),
            "scheduled_start": datetime(2026, 2, 2, 15, tzinfo=timezone.utc),
            "status": "cancelled",
            "rate": Decimal("100.01"),
            "rate_type": "monthly",
        },
        {
            "id": 13,
            "location_id": 9,
            "scheduled_date": date(2026, 2, 8),
            "scheduled_start": datetime(2026, 2, 8, 15, tzinfo=timezone.utc),
            "status": "scheduled",
            "rate": Decimal("100.01"),
            "rate_type": "monthly",
        },
        {
            "id": 14,
            "location_id": 10,
            "scheduled_date": date(2026, 2, 1),
            "scheduled_start": datetime(2026, 2, 1, 15, tzinfo=timezone.utc),
            "status": "scheduled",
            "rate": Decimal("80.00"),
            "rate_type": "per_visit",
        },
    ]

    assert monthly_revenue_allocations(rows, chicago) == {
        11: 5001,
        13: 5000,
    }


def test_actual_matching_fails_closed_when_two_service_windows_overlap():
    service_day = date(2026, 7, 20)
    segment = {
        "location_id": 77,
        "start": datetime(2026, 7, 20, 14, tzinfo=timezone.utc),
        "end": datetime(2026, 7, 20, 16, tzinfo=timezone.utc),
    }
    jobs = [
        {
            "id": 1,
            "location_id": 77,
            "scheduled_date": service_day,
            "scheduled_start": datetime(2026, 7, 20, 13, tzinfo=timezone.utc),
            "scheduled_end": datetime(2026, 7, 20, 17, tzinfo=timezone.utc),
            "status": "scheduled",
        },
        {
            "id": 2,
            "location_id": 77,
            "scheduled_date": service_day,
            "scheduled_start": datetime(2026, 7, 20, 15, tzinfo=timezone.utc),
            "scheduled_end": datetime(2026, 7, 20, 18, tzinfo=timezone.utc),
            "status": "scheduled",
        },
    ]
    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(77, service_day): jobs},
        {int(job["id"]): job for job in jobs},
        ZoneInfo("America/Chicago"),
    )
    assert match is None
    assert reason == "ambiguous_job"
    assert candidate_ids == [1, 2]


def test_single_timed_candidate_requires_overlap_and_legacy_keeps_date_fallback():
    service_day = date(2026, 7, 20)
    app_timezone = ZoneInfo("America/Chicago")
    timed_job = {
        "id": 1,
        "location_id": 77,
        "scheduled_date": service_day,
        "scheduled_start": datetime(2026, 7, 20, 23, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 21, 1, tzinfo=timezone.utc),
        "status": "scheduled",
    }
    morning_segment = {
        "location_id": 77,
        "start": datetime(2026, 7, 20, 14, tzinfo=timezone.utc),
        "end": datetime(2026, 7, 20, 16, tzinfo=timezone.utc),
    }

    match, reason, candidate_ids = _match_segment_to_job(
        morning_segment,
        {(77, service_day): [timed_job]},
        {1: timed_job},
        app_timezone,
    )

    assert match is None
    assert reason == "no_scheduled_job"
    assert candidate_ids == [1]

    overlapping_segment = {
        **morning_segment,
        "start": timed_job["scheduled_start"],
        "end": timed_job["scheduled_end"],
    }
    match, reason, candidate_ids = _match_segment_to_job(
        overlapping_segment,
        {(77, service_day): [timed_job]},
        {1: timed_job},
        app_timezone,
    )

    assert match == timed_job
    assert reason == "unique_service_window"
    assert candidate_ids == [1]

    legacy_job = {
        **timed_job,
        "scheduled_start": None,
        "scheduled_end": None,
    }
    match, reason, candidate_ids = _match_segment_to_job(
        morning_segment,
        {(77, service_day): [legacy_job]},
        {1: legacy_job},
        app_timezone,
    )

    assert match == legacy_job
    assert reason == "unique_site_date"
    assert candidate_ids == [1]


def test_matching_prefers_overlapping_timed_jobs_then_windowless_fallbacks():
    service_day = date(2026, 7, 20)
    app_timezone = ZoneInfo("America/Chicago")
    segment = {
        "location_id": 77,
        "start": datetime(2026, 7, 20, 14, tzinfo=timezone.utc),
        "end": datetime(2026, 7, 20, 16, tzinfo=timezone.utc),
    }
    nonoverlapping_timed_job = {
        "id": 1,
        "location_id": 77,
        "scheduled_date": service_day,
        "scheduled_start": datetime(2026, 7, 20, 18, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 20, 20, tzinfo=timezone.utc),
        "status": "scheduled",
    }
    legacy_job = {
        "id": 2,
        "location_id": 77,
        "scheduled_date": service_day,
        "scheduled_start": None,
        "scheduled_end": None,
        "status": "scheduled",
    }

    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(77, service_day): [nonoverlapping_timed_job, legacy_job]},
        {1: nonoverlapping_timed_job, 2: legacy_job},
        app_timezone,
    )

    assert match == legacy_job
    assert reason == "unique_site_date"
    assert candidate_ids == [2]

    overlapping_timed_job = {
        **nonoverlapping_timed_job,
        "scheduled_start": datetime(2026, 7, 20, 15, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 20, 17, tzinfo=timezone.utc),
    }
    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(77, service_day): [overlapping_timed_job, legacy_job]},
        {1: overlapping_timed_job, 2: legacy_job},
        app_timezone,
    )

    assert match == overlapping_timed_job
    assert reason == "unique_service_window"
    assert candidate_ids == [1]

    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(77, service_day): [nonoverlapping_timed_job]},
        {1: nonoverlapping_timed_job},
        app_timezone,
    )

    assert match is None
    assert reason == "no_scheduled_job"
    assert candidate_ids == [1]


def test_linked_shift_does_not_override_an_explicit_different_site_segment():
    service_day = date(2026, 7, 20)
    linked_job = {
        "id": 1,
        "location_id": 77,
        "scheduled_date": service_day,
        "scheduled_start": datetime(2026, 7, 20, 13, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 20, 15, tzinfo=timezone.utc),
        "status": "scheduled",
    }
    visited_job = {
        "id": 2,
        "location_id": 88,
        "scheduled_date": service_day,
        "scheduled_start": datetime(2026, 7, 20, 15, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 20, 17, tzinfo=timezone.utc),
        "status": "scheduled",
    }
    segment = {
        "job_id": linked_job["id"],
        "location_id": visited_job["location_id"],
        "start": datetime(2026, 7, 20, 15, tzinfo=timezone.utc),
        "end": datetime(2026, 7, 20, 17, tzinfo=timezone.utc),
    }

    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(visited_job["location_id"], service_day): [visited_job]},
        {visited_job["id"]: visited_job},
        ZoneInfo("America/Chicago"),
        linked_jobs_by_id={
            linked_job["id"]: linked_job,
            visited_job["id"]: visited_job,
        },
    )

    assert match == visited_job
    assert reason == "unique_service_window"
    assert candidate_ids == [visited_job["id"]]


def test_linked_shift_outside_visible_range_never_rematches_same_site_segment():
    service_day = date(2026, 7, 20)
    linked_job = {
        "id": 1,
        "location_id": 77,
        "status": "scheduled",
    }
    visible_job = {
        "id": 2,
        "location_id": 77,
        "scheduled_date": service_day,
        "scheduled_start": datetime(2026, 7, 20, 14, tzinfo=timezone.utc),
        "scheduled_end": datetime(2026, 7, 20, 16, tzinfo=timezone.utc),
        "status": "scheduled",
    }
    segment = {
        "job_id": linked_job["id"],
        "location_id": visible_job["location_id"],
        "start": visible_job["scheduled_start"],
        "end": visible_job["scheduled_end"],
    }

    match, reason, candidate_ids = _match_segment_to_job(
        segment,
        {(visible_job["location_id"], service_day): [visible_job]},
        {visible_job["id"]: visible_job},
        ZoneInfo("America/Chicago"),
        linked_jobs_by_id={
            linked_job["id"]: linked_job,
            visible_job["id"]: visible_job,
        },
    )

    assert match is None
    assert reason == "linked_job_outside_range"
    assert candidate_ids == [linked_job["id"]]


def test_qr_presence_is_suppressed_only_by_a_same_site_segment():
    checked_in_at = datetime(2026, 7, 20, 15, tzinfo=timezone.utc)
    represented_segment = {
        "employee_id": 5,
        "location_id": 77,
        "start": checked_in_at - timedelta(hours=1),
        "end": checked_in_at + timedelta(hours=1),
    }
    qr_rows = [
        {
            "employee_id": 5,
            "employee_name": "Worker",
            "hourly_rate": Decimal("18.00"),
            "location_id": location_id,
            "location_label": f"Site {location_id}",
            "server_checked_in_at": checked_in_at,
        }
        for location_id in (77, 88)
    ]

    output = _qr_only_presence_segments(
        qr_rows,
        [represented_segment],
        checked_in_at + timedelta(hours=2),
    )

    assert [segment["location_id"] for segment in output] == [88]
    assert output[0]["presence_only"] is True
    assert output[0]["evidence"] == ["qr_check_in"]


def test_missing_site_does_not_report_site_economics_issues():
    start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    issue_codes = {
        issue["code"]
        for issue in _job_issues(
            {
                "location_id": None,
                "site_expected_hours": None,
                "rate": None,
                "rate_type": None,
                "source_role": "residential_morning",
                "source_all_day": False,
                "scheduled_start": start,
                "scheduled_end": start + timedelta(hours=2),
            }
        )
    }

    assert "missing_site" in issue_codes
    assert "missing_expected_hours" not in issue_codes
    assert "missing_rate" not in issue_codes


def test_closed_shift_preserves_initial_site_before_first_visit():
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    visit_start = shift_start + timedelta(hours=2)
    shift_end = shift_start + timedelta(hours=4)
    segments = _closed_shift_segments(
        {
            "id": 1,
            "employee_id": 2,
            "employee_name": "Worker",
            "hourly_rate": Decimal("18.00"),
            "location_id": 10,
            "location_label": "Initial Site",
            "clock_in": shift_start,
            "clock_out": shift_end,
        },
        [
            {
                "id": 3,
                "location_id": 20,
                "location_label": "Second Site",
                "arrival_time": visit_start,
            }
        ],
        [],
        {},
        shift_start,
        shift_end,
    )

    assert [
        (
            segment["location_id"],
            segment["start"],
            segment["end"],
            segment["evidence"],
        )
        for segment in segments
    ] == [
        (10, shift_start, visit_start, ["shift"]),
        (20, visit_start, shift_end, ["visit"]),
    ]


def test_version_two_missing_departure_never_invents_visit_end():
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    missing_arrival = shift_start + timedelta(hours=1)
    paired_arrival = shift_start + timedelta(hours=2)
    paired_departure = shift_start + timedelta(hours=3)
    shift_end = shift_start + timedelta(hours=4)
    segments = _closed_shift_segments(
        {
            "id": 1,
            "employee_id": 2,
            "employee_name": "Worker",
            "hourly_rate": Decimal("18.00"),
            "location_id": 10,
            "location_label": "Initial Site",
            "clock_in": shift_start,
            "clock_out": shift_end,
        },
        [
            {
                "id": 30,
                "location_id": 20,
                "location_label": "Missing Departure Site",
                "arrival_time": missing_arrival,
                "sequence_version": 2,
            },
            {
                "id": 31,
                "location_id": 30,
                "location_label": "Paired Site",
                "arrival_time": paired_arrival,
                "sequence_version": 2,
            },
        ],
        [
            {
                "id": 40,
                "visit_id": 31,
                "location_id": 30,
                "location_label": "Paired Site",
                "departure_time": paired_departure,
            }
        ],
        {},
        shift_start,
        shift_end,
    )

    assert [
        (
            segment["location_id"],
            segment["start"],
            segment["end"],
            segment["evidence"],
        )
        for segment in segments
    ] == [
        (10, shift_start, missing_arrival, ["shift"]),
        (None, missing_arrival, paired_arrival, "unassigned_gap"),
        (30, paired_arrival, paired_departure, ["visit"]),
        (None, paired_departure, shift_end, "unassigned_gap"),
    ]
    assert not any(segment["location_id"] == 20 for segment in segments)


@pytest.mark.parametrize("with_later_visit", [False, True])
def test_closed_shift_departure_splits_initial_site_before_qr_attribution(
    with_later_visit,
):
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    departure_at = shift_start + timedelta(hours=1)
    visit_start = shift_start + timedelta(hours=3)
    shift_end = shift_start + timedelta(hours=4)
    visits = (
        [
            {
                "id": 3,
                "location_id": 20,
                "location_label": "Second Site",
                "arrival_time": visit_start,
            }
        ]
        if with_later_visit
        else []
    )

    segments = _closed_shift_segments(
        {
            "id": 1,
            "employee_id": 2,
            "employee_name": "Worker",
            "hourly_rate": Decimal("18.00"),
            "location_id": 10,
            "location_label": "Initial Site",
            "clock_in": shift_start,
            "clock_out": shift_end,
        },
        visits,
        [
            {
                "id": 4,
                "location_id": 10,
                "location_label": "Initial Site",
                "departure_time": departure_at,
            }
        ],
        {(2, 10): [shift_start + timedelta(minutes=30)]},
        shift_start,
        shift_end,
    )

    observed = [
        (
            segment["location_id"],
            segment["start"],
            segment["end"],
            segment["evidence"],
        )
        for segment in segments
    ]
    expected = [
        (
            10,
            shift_start,
            departure_at,
            ["shift", "qr_check_in"],
        ),
        (
            None,
            departure_at,
            visit_start if with_later_visit else shift_end,
            "unassigned_gap",
        ),
    ]
    if with_later_visit:
        expected.append((20, visit_start, shift_end, ["visit"]))
    assert observed == expected


def test_forecast_uses_unrounded_average_wage_for_labor_cost():
    start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    job = {
        "id": 1,
        "location_id": 77,
        "customer_id": 88,
        "display_customer": "Customer",
        "site_address": "Site",
        "site_active": True,
        "site_type": "Residential",
        "site_expected_hours": 3,
        "rate": 100,
        "rate_type": "per_visit",
        "source_role": "residential_morning",
        "source_all_day": False,
        "scheduled_date": date(2026, 7, 20),
        "scheduled_start": start,
        "scheduled_end": start + timedelta(hours=2),
    }
    calculated = _forecast_job_values(
        job,
        Decimal("16.875"),
        {},
    )
    assert calculated["estLaborCost"] == 50.63
    invalid_price_type = _forecast_job_values(
        {**job, "id": 2, "rate_type": "unsupported"},
        Decimal("16.875"),
        {},
    )
    assert invalid_price_type["estRevenue"] is None
    assert {issue["code"] for issue in invalid_price_type["issues"]} >= {
        "invalid_rate_type"
    }
    missing_price_type = _forecast_job_values(
        {**job, "id": 3, "rate_type": None},
        Decimal("16.875"),
        {},
    )
    assert missing_price_type["estRevenue"] is None
    assert {issue["code"] for issue in missing_price_type["issues"]} >= {
        "invalid_rate_type"
    }


def test_schedule_segments_multi_stop_and_multi_worker_actuals(client, auth):
    service_day = date(2026, 7, 20)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            residential_source = _source(
                cur,
                "schedule_residential",
                "residential_morning",
            )
            commercial_source = _source(
                cur,
                "schedule_commercial",
                "commercial_evening_night",
            )
            _, site_a = _customer_site(
                cur,
                "Schedule A",
                site_type="Residential",
                rate=150,
                rate_type="per_visit",
                expected_hours=3,
            )
            _, site_b = _customer_site(
                cur,
                "Schedule B",
                site_type="Commercial",
                rate=200,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_a = _job(
                cur,
                source_id=residential_source,
                location_id=site_a,
                customer_name=f"{TEST_PREFIX} Customer Schedule A",
                start=datetime(2026, 7, 20, 13, tzinfo=timezone.utc),
                end=datetime(2026, 7, 20, 17, tzinfo=timezone.utc),
                source_seed="schedule-a",
            )
            job_b = _job(
                cur,
                source_id=commercial_source,
                location_id=site_b,
                customer_name=f"{TEST_PREFIX} Customer Schedule B",
                start=datetime(2026, 7, 20, 18, tzinfo=timezone.utc),
                end=datetime(2026, 7, 20, 21, tzinfo=timezone.utc),
                source_seed="schedule-b",
            )
            # A second same-Site/date occurrence proves interval overlap, not a
            # customer/date guess, selects the actual job.
            later_job_b = _job(
                cur,
                source_id=commercial_source,
                location_id=site_b,
                customer_name=f"{TEST_PREFIX} Customer Schedule B",
                start=datetime(2026, 7, 20, 22, tzinfo=timezone.utc),
                end=datetime(2026, 7, 20, 23, tzinfo=timezone.utc),
                source_seed="schedule-b-later",
            )
            worker_a = _employee(cur, "A", 16.75)
            worker_b = _employee(cur, "B", 20)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, clock_in, clock_out, total_hours,
                    local_date, timezone, time_category
                )
                VALUES (
                    %s, '2026-07-20 12:50+00', '2026-07-20 21:00+00',
                    8.17, %s, 'America/Chicago', 'productive'
                )
                RETURNING id
                """,
                (worker_a, service_day),
            )
            multi_stop_shift = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time
                )
                VALUES
                    (%s, %s, %s, %s, '2026-07-20 13:00+00'),
                    (%s, %s, %s, %s, '2026-07-20 18:00+00')
                """,
                (
                    multi_stop_shift,
                    site_a,
                    f"{TEST_PREFIX} Site Schedule A",
                    f"{TEST_PREFIX} Customer Schedule A",
                    multi_stop_shift,
                    site_b,
                    f"{TEST_PREFIX} Site Schedule B",
                    f"{TEST_PREFIX} Customer Schedule B",
                ),
            )
            cur.execute(
                """
                INSERT INTO departures (
                    shift_id, location_id, location_label, customer_name,
                    departure_time
                )
                VALUES
                    (%s, %s, %s, %s, '2026-07-20 16:00+00'),
                    (%s, %s, %s, %s, '2026-07-20 20:00+00')
                """,
                (
                    multi_stop_shift,
                    site_a,
                    f"{TEST_PREFIX} Site Schedule A",
                    f"{TEST_PREFIX} Customer Schedule A",
                    multi_stop_shift,
                    site_b,
                    f"{TEST_PREFIX} Site Schedule B",
                    f"{TEST_PREFIX} Customer Schedule B",
                ),
            )
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label,
                    clock_in, clock_out, total_hours, local_date,
                    timezone, time_category
                )
                VALUES (
                    %s, %s, %s, '2026-07-20 14:00+00',
                    '2026-07-20 16:00+00', 2, %s,
                    'America/Chicago', 'productive'
                )
                """,
                (
                    worker_b,
                    site_a,
                    f"{TEST_PREFIX} Site Schedule A",
                    service_day,
                ),
            )
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES
                    (
                        %s, %s, '2026-07-20 14:00+00',
                        '2026-07-20 14:00+00', 39.12, -88.54, 5,
                        100, 3, 'inside', 'on_time', 'test', 0,
                        'not_required'
                    ),
                    (
                        %s, %s, '2026-07-20 17:30+00',
                        '2026-07-20 17:30+00', 39.12, -88.54, 5,
                        100, 3, 'inside', 'on_time', 'test', 0,
                        'not_required'
                    ),
                    (
                        %s, %s, '2026-07-20 15:00+00',
                        '2026-07-20 15:00+00', 39.12, -88.54, 5,
                        100, 3, 'inside', 'on_time', 'test', 0,
                        'not_required'
                    )
                """,
                (
                    worker_a,
                    site_a,
                    worker_a,
                    site_b,
                    worker_b,
                    site_a,
                ),
            )

    before = db.query_one(
        """
        SELECT
            (SELECT COUNT(*) FROM shifts WHERE employee_id IN (%s, %s)) AS shifts,
            (SELECT COUNT(*) FROM visits WHERE shift_id = %s) AS visits,
            (SELECT COUNT(*) FROM jobs WHERE id IN (%s, %s, %s)) AS jobs
        """,
        (worker_a, worker_b, multi_stop_shift, job_a, job_b, later_job_b),
    )
    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    by_id = {job["id"]: job for job in body["jobs"]}

    assert by_id[job_a]["sourceRole"] == "residential_morning"
    assert by_id[job_a]["actualHours"] == pytest.approx(5)
    assert by_id[job_a]["varianceHours"] == pytest.approx(2)
    assert by_id[job_a]["actualLaborCost"] == pytest.approx(90.25)
    assert len(by_id[job_a]["workers"]) == 2
    job_a_workers = {worker["employeeId"]: worker for worker in by_id[job_a]["workers"]}
    assert job_a_workers[worker_a]["intervals"][0]["evidence"] == [
        "visit",
        "qr_check_in",
    ]
    assert job_a_workers[worker_b]["intervals"][0]["evidence"] == [
        "shift",
        "qr_check_in",
    ]

    assert by_id[job_b]["sourceRole"] == "commercial_evening_night"
    assert by_id[job_b]["actualHours"] == pytest.approx(2)
    assert by_id[job_b]["actualLaborCost"] == pytest.approx(33.50)
    job_b_worker = next(
        worker for worker in by_id[job_b]["workers"] if worker["employeeId"] == worker_a
    )
    assert job_b_worker["intervals"][0]["evidence"] == ["visit"]
    assert by_id[later_job_b]["actualHours"] == 0
    assert body["summary"]["actualHours"] == pytest.approx(7)
    assert body["summary"]["varianceHours"] == pytest.approx(0)
    assert body["summary"]["unmatchedActualHours"] == pytest.approx(3.17)
    assert {
        row["reason"] for row in body["unmatchedActualSegments"] if row["finalized"]
    } == {"unassigned_gap"}
    unmatched_qr_presence = [
        row
        for row in body["unmatchedActualSegments"]
        if row["presenceOnly"] and row["evidence"] == ["qr_check_in"]
    ]
    assert len(unmatched_qr_presence) == 1
    assert unmatched_qr_presence[0]["reason"] == "no_scheduled_job"
    assert unmatched_qr_presence[0]["hours"] is None

    after = db.query_one(
        """
        SELECT
            (SELECT COUNT(*) FROM shifts WHERE employee_id IN (%s, %s)) AS shifts,
            (SELECT COUNT(*) FROM visits WHERE shift_id = %s) AS visits,
            (SELECT COUNT(*) FROM jobs WHERE id IN (%s, %s, %s)) AS jobs
        """,
        (worker_a, worker_b, multi_stop_shift, job_a, job_b, later_job_b),
    )
    assert after == before


def test_schedule_open_shift_identifies_worker_without_finalized_hours(client, auth):
    observed_at = datetime.now(timezone.utc)
    app_timezone = ZoneInfo("America/Chicago")
    service_day = observed_at.astimezone(app_timezone).date()
    local_day_start = datetime.combine(
        service_day,
        time.min,
        tzinfo=app_timezone,
    ).astimezone(timezone.utc)
    job_start = max(local_day_start, observed_at - timedelta(hours=1))
    shift_start = max(local_day_start, observed_at - timedelta(minutes=30))
    checked_in_at = shift_start + (observed_at - shift_start) / 2
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "open_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "Open Shift",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Open Shift",
                start=job_start,
                end=observed_at + timedelta(hours=2),
                source_seed="open-shift",
            )
            employee_id = _employee(cur, "Open", 18)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, clock_in, local_date, timezone, time_category
                )
                VALUES (%s, %s, %s, 'America/Chicago', 'productive')
                RETURNING id
                """,
                (
                    employee_id,
                    shift_start,
                    service_day,
                ),
            )
            shift_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', 'on_time', 'test', 0,
                    'not_required'
                )
                """,
                (
                    employee_id,
                    site_id,
                    job_id,
                    checked_in_at,
                    checked_in_at,
                ),
            )

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    job = next(row for row in body["jobs"] if row["id"] == job_id)
    assert job["executionStatus"] == "in_progress"
    assert job["actualHours"] == 0
    assert job["workers"] == [
        {
            "employeeId": employee_id,
            "employeeName": f"{TEST_PREFIX} Employee Open",
            "intervals": [
                {
                    "shiftId": shift_id,
                    "intervalStart": checked_in_at.replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "intervalEnd": None,
                    "hours": None,
                    "finalized": False,
                    "presenceOnly": False,
                    "evidence": ["clock_in", "qr_check_in"],
                    "match": "unique_service_window",
                },
                {
                    "shiftId": None,
                    "intervalStart": checked_in_at.replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "intervalEnd": None,
                    "hours": None,
                    "finalized": False,
                    "presenceOnly": True,
                    "evidence": ["qr_check_in"],
                    "match": "linked_shift",
                },
            ],
            "status": "in_progress",
            "hours": 0,
            "laborCost": 0,
        }
    ]
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["inProgressWorkerCount"] == 1
    assert (
        db.query_one(
            "SELECT clock_out FROM shifts WHERE id = %s",
            (shift_id,),
        )["clock_out"]
        is None
    )


def test_open_rateless_segment_does_not_poison_finalized_labor_cost(client, auth):
    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
    app_timezone = ZoneInfo("America/Chicago")
    service_day = observed_at.astimezone(app_timezone).date()
    job_start = observed_at - timedelta(hours=2)
    job_end = observed_at + timedelta(hours=1)
    finalized_start = observed_at - timedelta(minutes=70)
    finalized_end = observed_at - timedelta(minutes=10)
    open_start = observed_at - timedelta(minutes=90)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "rateless_open_segment",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "Rateless Open Segment",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Rateless Open Segment",
                start=job_start,
                end=job_end,
                source_seed="rateless-open-segment",
            )
            employee_id = _employee(cur, "Rateless Open Segment", None)
            _shift(
                cur,
                employee_id=employee_id,
                start=open_start,
                end=None,
                service_day=service_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Rateless Open Segment",
                job_id=job_id,
            )
            finalized_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=finalized_start,
                end=finalized_end,
                service_day=service_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Rateless Open Segment",
                job_id=job_id,
            )
            cur.execute(
                "UPDATE shifts SET hourly_rate_cents = 1800 WHERE id = %s",
                (finalized_shift_id,),
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)
    worker = job["workers"][0]

    assert job["actualHours"] == 1
    assert job["actualLaborCost"] == 18
    assert worker["status"] == "in_progress"
    assert worker["hours"] == 1
    assert worker["laborCost"] == 18
    assert "missing_worker_rate" not in {issue["code"] for issue in job["issues"]}


@pytest.mark.parametrize(
    ("classification", "review_status"),
    [
        ("on_time", "not_required"),
        ("late", "not_required"),
        ("needs_review", "approved"),
    ],
)
def test_accepted_linked_qr_promotes_whole_unassigned_closed_shift(
    client,
    auth,
    classification,
    review_status,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    checked_in_at = shift_start + timedelta(hours=1)
    scheduled_start = shift_start
    scheduled_end = shift_end
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "qr_presence_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "QR Presence",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer QR Presence",
                start=scheduled_start,
                end=scheduled_end,
                source_seed="qr-presence",
            )
            employee_id = _employee(cur, "QR Presence", 18)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, clock_in, clock_out, total_hours,
                    local_date, timezone, time_category
                )
                VALUES (%s, %s, %s, 2, %s, 'America/Chicago', 'productive')
                RETURNING id
                """,
                (employee_id, shift_start, shift_end, service_day),
            )
            shift_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', %s, 'test', 0, %s
                )
                """,
                (
                    employee_id,
                    site_id,
                    job_id,
                    checked_in_at,
                    checked_in_at,
                    classification,
                    review_status,
                ),
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)

    assert job["actualHours"] == 2
    assert job["actualLaborCost"] == 36
    assert job["executionStatus"] == "completed"
    assert job["workers"] == [
        {
            "employeeId": employee_id,
            "employeeName": f"{TEST_PREFIX} Employee QR Presence",
            "intervals": [
                {
                    "shiftId": shift_id,
                    "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
                    "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
                    "hours": 2,
                    "finalized": True,
                    "presenceOnly": False,
                    "evidence": ["shift", "qr_check_in"],
                    "match": "linked_shift",
                }
            ],
            "status": "finalized",
            "hours": 2,
            "laborCost": 36,
        }
    ]
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0
    assert db.query_one(
        """
        SELECT job_id
        FROM site_check_ins
        WHERE employee_id = %s
          AND server_checked_in_at = %s
        """,
        (employee_id, checked_in_at),
    ) == {"job_id": job_id}
    assert _unmatched_for_shift(body, shift_id) == []


def test_repeated_same_job_qr_scans_do_not_duplicate_paid_time(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=3)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Repeat",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, "QR Repeat", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            for offset in (timedelta(minutes=30), timedelta(hours=2)):
                _check_in(
                    cur,
                    employee_id=employee_id,
                    location_id=site_id,
                    job_id=job_id,
                    checked_in_at=shift_start + offset,
                )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)
    intervals = job["workers"][0]["intervals"]

    assert job["actualHours"] == 3
    assert len(intervals) == 1
    assert intervals[0] == {
        "shiftId": shift_id,
        "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
        "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
        "hours": 3,
        "finalized": True,
        "presenceOnly": False,
        "evidence": ["shift", "qr_check_in"],
        "match": "linked_shift",
    }
    assert body["summary"]["actualHours"] == 3
    assert body["summary"]["unmatchedActualHours"] == 0
    assert _unmatched_for_shift(body, shift_id) == []


def test_distinct_qr_job_links_in_one_atomic_segment_fail_closed(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="QR Conflict A",
                start=shift_start,
                end=shift_end,
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="QR Conflict B",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, "QR Conflict", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_a,
                job_id=job_a,
                checked_in_at=shift_start + timedelta(minutes=30),
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_b,
                job_id=job_b,
                checked_in_at=shift_start + timedelta(minutes=90),
            )

    body = _schedule_body(client, auth, service_day)

    for job_id in (job_a, job_b):
        job = _schedule_job(body, job_id)
        assert job["actualHours"] == 0
        assert len(job["workers"]) == 1
        assert job["workers"][0]["status"] == "observed"
        assert job["workers"][0]["intervals"][0]["presenceOnly"] is True
        assert job["workers"][0]["intervals"][0]["hours"] is None
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["unmatchedActualHours"] == 2
    assert [
        (
            row["hours"],
            row["reason"],
            row["candidateJobIds"],
            row["finalized"],
        )
        for row in _unmatched_for_shift(body, shift_id)
        if row["finalized"]
    ] == [(2, "ambiguous_job", sorted([job_a, job_b]), True)]


def test_job_link_keeps_cross_day_qr_presence_on_the_calendar_job(client, auth):
    service_day = date(2026, 7, 20)
    scheduled_start = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
    scheduled_end = scheduled_start + timedelta(hours=2)
    checked_in_at = scheduled_start - timedelta(hours=11)
    assert checked_in_at.astimezone(ZoneInfo("America/Chicago")).date() < service_day
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "qr_cross_day_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "QR Cross Day",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer QR Cross Day",
                start=scheduled_start,
                end=scheduled_end,
                source_seed="qr-cross-day",
            )
            employee_id = _employee(cur, "QR Cross Day", 18)
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', 'on_time',
                    'verified_scheduled_site', 0, 'not_required'
                )
                """,
                (employee_id, site_id, job_id, checked_in_at, checked_in_at),
            )

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    job = next(row for row in body["jobs"] if row["id"] == job_id)

    assert job["actualHours"] == 0
    assert job["actualLaborCost"] == 0
    assert job["workers"] == [
        {
            "employeeId": employee_id,
            "employeeName": f"{TEST_PREFIX} Employee QR Cross Day",
            "intervals": [
                {
                    "shiftId": None,
                    "intervalStart": checked_in_at.isoformat().replace("+00:00", "Z"),
                    "intervalEnd": None,
                    "hours": None,
                    "finalized": False,
                    "presenceOnly": True,
                    "evidence": ["qr_check_in"],
                    "match": "linked_shift",
                }
            ],
            "status": "observed",
            "hours": 0,
            "laborCost": 0,
        }
    ]


def test_visible_job_loads_linked_qr_shift_across_evidence_boundary(client, auth):
    service_day = date(2026, 7, 20)
    job_start = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
    job_end = job_start + timedelta(hours=2)
    shift_start = datetime(2026, 7, 20, 2, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    checked_in_at = shift_start + timedelta(hours=1)
    assert shift_end < datetime(2026, 7, 20, 5, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Evidence Boundary",
                start=job_start,
                end=job_end,
            )
            employee_id = _employee(cur, "QR Evidence Boundary", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day - timedelta(days=1),
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id,
                checked_in_at=checked_in_at,
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)

    assert job["actualHours"] == 2
    assert job["workers"][0]["intervals"] == [
        {
            "shiftId": shift_id,
            "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
            "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
            "hours": 2,
            "finalized": True,
            "presenceOnly": False,
            "evidence": ["shift", "qr_check_in"],
            "match": "linked_shift",
        }
    ]
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0
    assert _unmatched_for_shift(body, shift_id) == []


def test_cross_boundary_shift_loads_conflicting_nonvisible_qr_and_fails_closed(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    visible_start = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
    shift_start = datetime(2026, 7, 20, 2, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            visible_site, visible_job = _canonical_job(
                cur,
                suffix="QR Cross Boundary Visible",
                start=visible_start,
                end=visible_start + timedelta(hours=2),
            )
            hidden_site, hidden_job = _canonical_job(
                cur,
                suffix="QR Cross Boundary Hidden",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, "QR Cross Boundary Conflict", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day - timedelta(days=1),
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=visible_site,
                job_id=visible_job,
                checked_in_at=shift_start + timedelta(minutes=30),
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=hidden_site,
                job_id=hidden_job,
                checked_in_at=shift_start + timedelta(minutes=90),
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, visible_job)

    assert hidden_job not in {row["id"] for row in body["jobs"]}
    assert job["actualHours"] == 0
    assert job["workers"][0]["status"] == "observed"
    assert job["workers"][0]["intervals"][0]["presenceOnly"] is True
    assert job["workers"][0]["intervals"][0]["hours"] is None
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["unmatchedActualHours"] == 2
    assert [
        (row["shiftId"], row["hours"], row["reason"], row["candidateJobIds"])
        for row in body["unmatchedActualSegments"]
        if row["finalized"]
    ] == [(shift_id, 2, "ambiguous_job", sorted([visible_job, hidden_job]))]


def test_post_midnight_qr_attributes_whole_overnight_shift_to_visible_job(
    client,
    auth,
):
    app_timezone = ZoneInfo("America/Chicago")
    service_day = date(2026, 7, 20)
    local_start = datetime.combine(
        service_day,
        time(hour=23),
        tzinfo=app_timezone,
    )
    shift_start = local_start.astimezone(timezone.utc)
    shift_end = (local_start + timedelta(hours=2)).astimezone(timezone.utc)
    checked_in_at = shift_start + timedelta(hours=1, minutes=30)
    assert checked_in_at.astimezone(app_timezone).date() == service_day + timedelta(
        days=1
    )
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Overnight Shift",
                start=shift_start,
                end=shift_end,
                site_type="Commercial",
            )
            employee_id = _employee(cur, "QR Overnight Shift", 20)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id,
                checked_in_at=checked_in_at,
            )

    body = _schedule_body(client, auth, service_day + timedelta(days=1))
    job = _schedule_job(body, job_id)

    assert job["scheduledDate"] == str(service_day)
    assert job["actualHours"] == 2
    assert job["workers"][0]["intervals"] == [
        {
            "shiftId": shift_id,
            "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
            "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
            "hours": 2,
            "finalized": True,
            "presenceOnly": False,
            "evidence": ["shift", "qr_check_in"],
            "match": "linked_shift",
        }
    ]
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0


def test_durable_qr_job_link_attaches_existing_paid_site_segment(client, auth):
    service_day = date(2026, 7, 20)
    scheduled_start = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
    scheduled_end = scheduled_start + timedelta(hours=1)
    shift_start = scheduled_end + timedelta(hours=1)
    shift_end = shift_start + timedelta(hours=2)
    checked_in_at = shift_start + timedelta(hours=1)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "qr_attached_segment_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "QR Attached Segment",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer QR Attached Segment",
                start=scheduled_start,
                end=scheduled_end,
                source_seed="qr-attached-segment",
            )
            employee_id = _employee(cur, "QR Attached Segment", 18)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label,
                    clock_in, clock_out, total_hours, local_date,
                    timezone, time_category
                )
                VALUES (
                    %s, %s, 'QR Attached Segment Site',
                    %s, %s, 2, %s, 'America/Chicago', 'productive'
                )
                RETURNING id
                """,
                (employee_id, site_id, shift_start, shift_end, service_day),
            )
            shift_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', 'on_time',
                    'verified_scheduled_site', 0, 'not_required'
                )
                """,
                (employee_id, site_id, job_id, checked_in_at, checked_in_at),
            )

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    job = next(row for row in body["jobs"] if row["id"] == job_id)

    assert job["actualHours"] == 2
    assert job["actualLaborCost"] == 36
    assert job["workers"] == [
        {
            "employeeId": employee_id,
            "employeeName": f"{TEST_PREFIX} Employee QR Attached Segment",
            "intervals": [
                {
                    "shiftId": shift_id,
                    "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
                    "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
                    "hours": 2,
                    "finalized": True,
                    "presenceOnly": False,
                    "evidence": ["shift", "qr_check_in"],
                    "match": "linked_shift",
                }
            ],
            "status": "finalized",
            "hours": 2,
            "laborCost": 36,
        }
    ]
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0


def test_qr_links_preserve_visit_departure_atoms_and_duration_conservation(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    site_a_start = shift_start + timedelta(hours=1)
    site_a_end = shift_start + timedelta(hours=3)
    site_b_start = shift_start + timedelta(hours=4)
    site_b_end = shift_start + timedelta(hours=5)
    shift_end = shift_start + timedelta(hours=6)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="QR Atoms A",
                start=site_a_start,
                end=site_a_end,
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="QR Atoms B",
                start=site_b_start,
                end=site_b_end,
            )
            employee_id = _employee(cur, "QR Atoms", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _visit(
                cur,
                shift_id=shift_id,
                location_id=site_a,
                at=site_a_start,
                suffix="QR Atoms A",
            )
            _departure(
                cur,
                shift_id=shift_id,
                location_id=site_a,
                at=site_a_end,
                suffix="QR Atoms A",
            )
            _visit(
                cur,
                shift_id=shift_id,
                location_id=site_b,
                at=site_b_start,
                suffix="QR Atoms B",
            )
            _departure(
                cur,
                shift_id=shift_id,
                location_id=site_b,
                at=site_b_end,
                suffix="QR Atoms B",
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_a,
                job_id=job_a,
                checked_in_at=site_a_start + timedelta(hours=1),
            )
            # Exact shared-boundary scans belong to the interval beginning
            # at the boundary, never the preceding unmatched atom.
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_b,
                job_id=job_b,
                checked_in_at=site_b_start,
            )

    body = _schedule_body(client, auth, service_day)
    interval_a = _schedule_job(body, job_a)["workers"][0]["intervals"][0]
    interval_b = _schedule_job(body, job_b)["workers"][0]["intervals"][0]

    assert interval_a == {
        "shiftId": shift_id,
        "intervalStart": site_a_start.isoformat().replace("+00:00", "Z"),
        "intervalEnd": site_a_end.isoformat().replace("+00:00", "Z"),
        "hours": 2,
        "finalized": True,
        "presenceOnly": False,
        "evidence": ["visit", "qr_check_in"],
        "match": "linked_shift",
    }
    assert interval_b == {
        "shiftId": shift_id,
        "intervalStart": site_b_start.isoformat().replace("+00:00", "Z"),
        "intervalEnd": site_b_end.isoformat().replace("+00:00", "Z"),
        "hours": 1,
        "finalized": True,
        "presenceOnly": False,
        "evidence": ["visit", "qr_check_in"],
        "match": "linked_shift",
    }
    unmatched = sorted(
        (
            row["intervalStart"],
            row["intervalEnd"],
            row["hours"],
        )
        for row in _unmatched_for_shift(body, shift_id)
        if row["finalized"]
    )
    assert unmatched == [
        (
            shift_start.isoformat().replace("+00:00", "Z"),
            site_a_start.isoformat().replace("+00:00", "Z"),
            1,
        ),
        (
            site_a_end.isoformat().replace("+00:00", "Z"),
            site_b_start.isoformat().replace("+00:00", "Z"),
            1,
        ),
        (
            site_b_end.isoformat().replace("+00:00", "Z"),
            shift_end.isoformat().replace("+00:00", "Z"),
            1,
        ),
    ]
    finalized = [
        (shift_start, site_a_start),
        (site_a_start, site_a_end),
        (site_a_end, site_b_start),
        (site_b_start, site_b_end),
        (site_b_end, shift_end),
    ]
    assert all(
        left_end <= right_start
        for (_, left_end), (right_start, _) in zip(finalized, finalized[1:])
    )
    assert (
        sum((end - start).total_seconds() for start, end in finalized)
        == (shift_end - shift_start).total_seconds()
    )
    assert body["summary"]["actualHours"] == 3
    assert body["summary"]["unmatchedActualHours"] == 3


def test_explicit_shift_job_link_wins_when_site_matching_is_ambiguous(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "linked_shift_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "Linked Shift",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            linked_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Linked Shift",
                start=shift_start - timedelta(hours=1),
                end=shift_end + timedelta(hours=1),
                source_seed="linked-shift-target",
            )
            other_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Linked Shift",
                start=shift_start - timedelta(minutes=30),
                end=shift_end + timedelta(minutes=30),
                source_seed="linked-shift-other",
            )
            employee_id = _employee(cur, "Linked Shift", 18)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, job_id, clock_in, clock_out, total_hours,
                    local_date, timezone, time_category
                )
                VALUES (
                    %s, %s, %s, %s, 2, %s,
                    'America/Chicago', 'productive'
                )
                """,
                (
                    employee_id,
                    linked_job_id,
                    shift_start,
                    shift_end,
                    service_day,
                ),
            )

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    jobs = {row["id"]: row for row in response.json()["jobs"]}

    assert jobs[linked_job_id]["actualHours"] == 2
    assert jobs[linked_job_id]["workers"][0]["intervals"][0]["match"] == "linked_shift"
    assert jobs[other_job_id]["actualHours"] == 0


def test_applicable_shift_job_link_wins_over_different_site_qr(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            shift_site, shift_job = _canonical_job(
                cur,
                suffix="Shift Link Winner",
                start=shift_start,
                end=shift_end,
            )
            qr_site, qr_job = _canonical_job(
                cur,
                suffix="Shift Link Other QR",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, "Shift Link Winner", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                location_id=shift_site,
                location_label=f"{TEST_PREFIX} Site Shift Link Winner",
                job_id=shift_job,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=qr_site,
                job_id=qr_job,
                checked_in_at=shift_start + timedelta(hours=1),
            )

    body = _schedule_body(client, auth, service_day)
    linked_job = _schedule_job(body, shift_job)
    qr_job_row = _schedule_job(body, qr_job)

    assert linked_job["actualHours"] == 2
    assert linked_job["workers"][0]["intervals"] == [
        {
            "shiftId": shift_id,
            "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
            "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
            "hours": 2,
            "finalized": True,
            "presenceOnly": False,
            "evidence": ["shift"],
            "match": "linked_shift",
        }
    ]
    assert qr_job_row["actualHours"] == 0
    assert qr_job_row["workers"][0]["status"] == "observed"
    assert qr_job_row["workers"][0]["intervals"][0]["presenceOnly"] is True
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0


def test_inapplicable_different_site_shift_link_allows_qr_on_visit_atom(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            shift_site, shift_job = _canonical_job(
                cur,
                suffix="Inapplicable Shift Link",
                start=shift_start,
                end=shift_end,
            )
            visit_site, visit_job = _canonical_job(
                cur,
                suffix="Inapplicable Shift QR",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, "Inapplicable Shift Link", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                location_id=shift_site,
                location_label=f"{TEST_PREFIX} Site Inapplicable Shift Link",
                job_id=shift_job,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _visit(
                cur,
                shift_id=shift_id,
                location_id=visit_site,
                at=shift_start,
                suffix="Inapplicable Shift QR",
            )
            _departure(
                cur,
                shift_id=shift_id,
                location_id=visit_site,
                at=shift_end,
                suffix="Inapplicable Shift QR",
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=visit_site,
                job_id=visit_job,
                checked_in_at=shift_start + timedelta(hours=1),
            )

    body = _schedule_body(client, auth, service_day)
    visit_job_row = _schedule_job(body, visit_job)

    assert _schedule_job(body, shift_job)["actualHours"] == 0
    assert visit_job_row["actualHours"] == 2
    assert visit_job_row["workers"][0]["intervals"] == [
        {
            "shiftId": shift_id,
            "intervalStart": shift_start.isoformat().replace("+00:00", "Z"),
            "intervalEnd": shift_end.isoformat().replace("+00:00", "Z"),
            "hours": 2,
            "finalized": True,
            "presenceOnly": False,
            "evidence": ["visit", "qr_check_in"],
            "match": "linked_shift",
        }
    ]
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0


def test_explicit_out_of_range_link_is_not_credited_to_visible_same_site_job(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "linked_outside_range_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "Linked Outside Range",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            linked_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Linked Outside Range",
                start=shift_start - timedelta(days=7),
                end=shift_end - timedelta(days=7),
                source_seed="linked-outside-range-target",
            )
            visible_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Linked Outside Range",
                start=shift_start - timedelta(hours=1),
                end=shift_end + timedelta(hours=1),
                source_seed="linked-outside-range-visible",
            )
            employee_id = _employee(cur, "Linked Outside Range", 18)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, job_id, location_id, clock_in, clock_out,
                    total_hours, local_date, timezone, time_category
                )
                VALUES (
                    %s, %s, %s, %s, %s, 2, %s,
                    'America/Chicago', 'productive'
                )
                RETURNING id
                """,
                (
                    employee_id,
                    linked_job_id,
                    site_id,
                    shift_start,
                    shift_end,
                    service_day,
                ),
            )
            shift_id = int(cur.fetchone()[0])

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    jobs = {row["id"]: row for row in body["jobs"]}

    assert linked_job_id not in jobs
    assert jobs[visible_job_id]["actualHours"] == 0
    unmatched = [
        row
        for row in body["unmatchedActualSegments"]
        if row["reason"] == "linked_job_outside_range"
    ]
    assert len(unmatched) == 1
    assert unmatched[0]["candidateJobIds"] == [linked_job_id]
    assert unmatched[0]["shiftId"] == shift_id
    assert unmatched[0]["hours"] == 2


def test_qr_contained_by_overlapping_shifts_fails_closed(client, auth):
    service_day = date(2026, 7, 20)
    first_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    second_start = first_start + timedelta(hours=1)
    first_end = first_start + timedelta(hours=3)
    second_end = second_start + timedelta(hours=3)
    checked_in_at = second_start + timedelta(minutes=30)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Overlapping Shifts",
                start=first_start,
                end=second_end,
            )
            employee_id = _employee(cur, "QR Overlapping Shifts", 18)
            shift_ids = [
                _shift(
                    cur,
                    employee_id=employee_id,
                    start=start,
                    end=end,
                    service_day=service_day,
                )
                for start, end in (
                    (first_start, first_end),
                    (second_start, second_end),
                )
            ]
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id,
                checked_in_at=checked_in_at,
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)

    assert job["actualHours"] == 0
    assert job["workers"][0]["status"] == "observed"
    assert job["workers"][0]["intervals"][0]["presenceOnly"] is True
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["unmatchedActualHours"] == 6
    assert {
        row["shiftId"]: (row["hours"], row["reason"], row["finalized"])
        for row in body["unmatchedActualSegments"]
        if row["shiftId"] in shift_ids and row["finalized"]
    } == {
        shift_ids[0]: (3, "unassigned_gap", True),
        shift_ids[1]: (3, "unassigned_gap", True),
    }


def test_ambiguous_overlap_qr_remains_presence_when_another_scan_links_shift(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    first_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    second_start = first_start + timedelta(hours=1)
    first_end = first_start + timedelta(hours=3)
    second_end = second_start + timedelta(hours=3)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Partial Overlap",
                start=first_start,
                end=second_end,
            )
            employee_id = _employee(cur, "QR Partial Overlap", 18)
            first_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=first_start,
                end=first_end,
                service_day=service_day,
            )
            second_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=second_start,
                end=second_end,
                service_day=service_day,
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id,
                checked_in_at=first_start + timedelta(minutes=30),
            )
            ambiguous_checked_in_at = second_start + timedelta(minutes=30)
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id,
                checked_in_at=ambiguous_checked_in_at,
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)
    intervals = job["workers"][0]["intervals"]

    assert job["actualHours"] == 3
    assert [
        (interval["shiftId"], interval["hours"], interval["presenceOnly"])
        for interval in intervals
    ] == [
        (first_shift_id, 3, False),
        (None, None, True),
    ]
    assert intervals[1]["intervalStart"] == ambiguous_checked_in_at.isoformat().replace(
        "+00:00", "Z"
    )
    assert body["summary"]["actualHours"] == 3
    assert body["summary"]["unmatchedActualHours"] == 3
    assert [
        (row["shiftId"], row["hours"], row["reason"])
        for row in body["unmatchedActualSegments"]
        if row["finalized"]
    ] == [(second_shift_id, 3, "unassigned_gap")]


def test_qr_site_job_mismatch_cannot_rematch_to_visible_same_site_job(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            canonical_site, canonical_job = _canonical_job(
                cur,
                suffix="QR Pair Canonical",
                start=shift_start,
                end=shift_end,
            )
            mismatched_site, same_site_job = _canonical_job(
                cur,
                suffix="QR Pair Mismatch",
                start=shift_start,
                end=shift_end,
            )
            assert canonical_site != mismatched_site
            employee_id = _employee(cur, "QR Pair Mismatch", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=canonical_site,
                job_id=canonical_job,
                checked_in_at=shift_start + timedelta(minutes=30),
            )
            checked_in_at = shift_start + timedelta(hours=1)
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=mismatched_site,
                job_id=canonical_job,
                checked_in_at=checked_in_at,
            )

    body = _schedule_body(client, auth, service_day)

    assert _schedule_job(body, canonical_job)["actualHours"] == 0
    assert _schedule_job(body, same_site_job)["actualHours"] == 0
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["unmatchedActualHours"] == 2
    unmatched = body["unmatchedActualSegments"]
    assert any(
        row["shiftId"] == shift_id
        and row["hours"] == 2
        and row["reason"] == "ambiguous_job"
        and row["candidateJobIds"] == [canonical_job]
        for row in unmatched
    )
    assert any(
        row["shiftId"] is None
        and row["presenceOnly"] is True
        and row["hours"] is None
        and row["reason"] == "ambiguous_job"
        and row["candidateJobIds"] == [canonical_job]
        for row in unmatched
    )


def test_two_employees_contribute_independent_intervals_to_one_qr_job(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="QR Two Employees",
                start=shift_start,
                end=shift_end,
            )
            employee_ids = [
                _employee(cur, "QR Two Employees A", 18),
                _employee(cur, "QR Two Employees B", 20),
            ]
            shift_ids = []
            for index, employee_id in enumerate(employee_ids):
                shift_ids.append(
                    _shift(
                        cur,
                        employee_id=employee_id,
                        start=shift_start,
                        end=shift_end,
                        service_day=service_day,
                    )
                )
                _check_in(
                    cur,
                    employee_id=employee_id,
                    location_id=site_id,
                    job_id=job_id,
                    checked_in_at=shift_start + timedelta(minutes=30 + index * 30),
                )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)
    workers = {worker["employeeId"]: worker for worker in job["workers"]}

    assert job["actualHours"] == 4
    assert job["actualLaborCost"] == 76
    assert set(workers) == set(employee_ids)
    for employee_id, shift_id in zip(employee_ids, shift_ids):
        worker = workers[employee_id]
        assert worker["hours"] == 2
        assert worker["status"] == "finalized"
        assert worker["intervals"][0]["shiftId"] == shift_id
        assert worker["intervals"][0]["evidence"] == ["shift", "qr_check_in"]
    assert body["summary"]["actualHours"] == 4
    assert body["summary"]["unmatchedActualHours"] == 0


@pytest.mark.parametrize(
    ("classification", "review_status", "accepted"),
    [
        ("on_time", "not_required", True),
        ("needs_review", "approved", True),
        ("needs_review", "pending", False),
        ("needs_review", "rejected", False),
    ],
)
def test_schedule_uses_only_accepted_qr_presence_without_paid_time(
    client,
    auth,
    classification,
    review_status,
    accepted,
):
    service_day = date(2026, 7, 20)
    checked_in_at = datetime(2026, 7, 20, 15, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "qr_without_shift_residential",
                "residential_morning",
            )
            _, site_id = _customer_site(
                cur,
                "QR Without Shift",
                site_type="Residential",
                rate=125,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer QR Without Shift",
                start=checked_in_at - timedelta(hours=1),
                end=checked_in_at + timedelta(hours=1),
                source_seed="qr-without-shift",
            )
            employee_id = _employee(cur, "QR Without Shift", 18)
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason,
                    device_clock_skew_seconds, review_status
                )
                VALUES (
                    %s, %s, %s, %s, 39.12, -88.54, 5,
                    100, 3, 'inside', %s, 'test', 0, %s
                )
                """,
                (
                    employee_id,
                    site_id,
                    checked_in_at,
                    checked_in_at,
                    classification,
                    review_status,
                ),
            )

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    job = next(row for row in response.json()["jobs"] if row["id"] == job_id)

    assert job["actualHours"] == 0
    assert job["executionStatus"] == "no_actual"
    if not accepted:
        assert job["workers"] == []
        return
    assert job["workers"] == [
        {
            "employeeId": employee_id,
            "employeeName": f"{TEST_PREFIX} Employee QR Without Shift",
            "intervals": [
                {
                    "shiftId": None,
                    "intervalStart": checked_in_at.isoformat().replace("+00:00", "Z"),
                    "intervalEnd": None,
                    "hours": None,
                    "finalized": False,
                    "presenceOnly": True,
                    "evidence": ["qr_check_in"],
                    "match": "unique_service_window",
                }
            ],
            "status": "observed",
            "hours": 0,
            "laborCost": 0,
        }
    ]


@pytest.mark.parametrize(
    (
        "case",
        "classification",
        "review_status",
        "shift_kind",
        "durable_job_link",
        "expected_unmatched_hours",
        "expected_observed",
    ),
    [
        (
            "pending",
            "needs_review",
            "pending",
            "closed_productive",
            True,
            2,
            False,
        ),
        (
            "rejected",
            "needs_review",
            "rejected",
            "closed_productive",
            True,
            2,
            False,
        ),
        (
            "unlinked",
            "on_time",
            "not_required",
            "closed_productive",
            False,
            2,
            True,
        ),
        (
            "no_shift",
            "on_time",
            "not_required",
            "none",
            True,
            0,
            True,
        ),
        (
            "open_shift",
            "on_time",
            "not_required",
            "open_productive",
            True,
            0,
            True,
        ),
        (
            "nonproductive",
            "on_time",
            "not_required",
            "closed_nonproductive",
            True,
            0,
            True,
        ),
    ],
)
def test_qr_without_one_closed_productive_shift_stays_zero_duration(
    client,
    auth,
    case,
    classification,
    review_status,
    shift_kind,
    durable_job_link,
    expected_unmatched_hours,
    expected_observed,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 14, tzinfo=timezone.utc)
    shift_end = shift_start + timedelta(hours=2)
    checked_in_at = shift_start + timedelta(hours=1)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix=f"QR Zero {case}",
                start=shift_start,
                end=shift_end,
            )
            employee_id = _employee(cur, f"QR Zero {case}", 18)
            if shift_kind != "none":
                _shift(
                    cur,
                    employee_id=employee_id,
                    start=shift_start,
                    end=None if shift_kind == "open_productive" else shift_end,
                    service_day=service_day,
                    time_category=(
                        "non_productive"
                        if shift_kind == "closed_nonproductive"
                        else "productive"
                    ),
                )
            _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                job_id=job_id if durable_job_link else None,
                checked_in_at=checked_in_at,
                classification=classification,
                review_status=review_status,
            )

    body = _schedule_body(client, auth, service_day)
    job = _schedule_job(body, job_id)

    assert job["actualHours"] == 0
    assert job["actualLaborCost"] == 0
    assert body["summary"]["actualHours"] == 0
    assert body["summary"]["unmatchedActualHours"] == expected_unmatched_hours
    if not expected_observed:
        assert job["workers"] == []
        return
    assert job["workers"][0]["hours"] == 0
    assert job["workers"][0]["status"] == "observed"
    assert all(
        interval["finalized"] is False
        and interval["presenceOnly"] is True
        and interval["hours"] is None
        for interval in job["workers"][0]["intervals"]
    )


def test_saturday_night_job_keeps_post_midnight_actual(client, auth):
    app_timezone = ZoneInfo("America/Chicago")
    service_day = date(2026, 7, 18)
    local_start = datetime.combine(
        service_day,
        time(hour=23),
        tzinfo=app_timezone,
    )
    start = local_start.astimezone(timezone.utc)
    end = (local_start + timedelta(hours=2)).astimezone(timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "overnight_commercial",
                "commercial_evening_night",
            )
            _, site_id = _customer_site(
                cur,
                "Overnight",
                site_type="Commercial",
                rate=200,
                rate_type="per_visit",
                expected_hours=2,
            )
            job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Overnight",
                start=start,
                end=end,
                source_seed="overnight",
            )
            employee_id = _employee(cur, "Overnight", 20)
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label,
                    clock_in, clock_out, total_hours, local_date,
                    timezone, time_category
                )
                VALUES (
                    %s, %s, %s, %s, %s, 2, %s,
                    'America/Chicago', 'productive'
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site_id,
                    f"{TEST_PREFIX} Site Overnight",
                    start,
                    end,
                    service_day,
                ),
            )
            shift_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    shift_id,
                    site_id,
                    f"{TEST_PREFIX} Site Overnight",
                    f"{TEST_PREFIX} Customer Overnight",
                    start + timedelta(hours=1),
                ),
            )
            next_service_day = service_day + timedelta(days=1)
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date, status,
                    calendar_source_id
                )
                VALUES (%s, %s, %s, 'scheduled', %s)
                RETURNING id
                """,
                (
                    site_id,
                    f"{TEST_PREFIX} Customer Legacy Date",
                    next_service_day,
                    source_id,
                ),
            )
            legacy_job_id = int(cur.fetchone()[0])

    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": str(next_service_day),
            "end_date": str(next_service_day),
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    jobs = {row["id"]: row for row in body["jobs"]}
    job = jobs[job_id]

    assert job["scheduledDate"] == str(service_day)
    assert jobs[legacy_job_id]["scheduledDate"] == str(next_service_day)
    assert jobs[legacy_job_id]["scheduledStart"] is None
    assert job["actualHours"] == 2
    assert job["varianceHours"] == 0
    intervals = job["workers"][0]["intervals"]
    assert [interval["intervalStart"] for interval in intervals] == [
        start.isoformat().replace("+00:00", "Z"),
        (start + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    ]
    assert [interval["intervalEnd"] for interval in intervals] == [
        (start + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
    ]
    assert sum(interval["hours"] for interval in intervals) == 2
    assert body["summary"]["actualHours"] == 2
    assert body["summary"]["unmatchedActualHours"] == 0


def _three_dates_in_one_forecast_month(today: date) -> list[date]:
    current_week = today - timedelta(days=(today.weekday() + 1) % 7)
    end = current_week + timedelta(days=27)
    by_month: dict[tuple[int, int], list[date]] = {}
    cursor = today + timedelta(days=1)
    while cursor <= end:
        by_month.setdefault((cursor.year, cursor.month), []).append(cursor)
        cursor += timedelta(days=1)
    return max(by_month.values(), key=len)[:3]


def test_monthly_rate_uses_all_non_cancelled_jobs_as_denominator(client, auth):
    today = datetime.now(ZoneInfo("America/Chicago")).date()
    service_dates = _three_dates_in_one_forecast_month(today)[:2]
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "monthly_denominator_commercial",
                "commercial_evening_night",
            )
            _, site_id = _customer_site(
                cur,
                "Monthly Denominator",
                site_type="Commercial",
                rate=100,
                rate_type="monthly",
                expected_hours=2,
            )
            job_ids = []
            for index, service_date in enumerate(service_dates):
                local_start = datetime.combine(
                    service_date,
                    time(hour=18),
                    tzinfo=ZoneInfo("America/Chicago"),
                )
                job_ids.append(
                    _job(
                        cur,
                        source_id=source_id,
                        location_id=site_id,
                        customer_name=f"{TEST_PREFIX} Customer Monthly Denominator",
                        start=local_start.astimezone(timezone.utc),
                        end=(local_start + timedelta(hours=2)).astimezone(timezone.utc),
                        source_seed=f"monthly-denominator-{index}",
                    )
                )
            cur.execute(
                "UPDATE jobs SET scheduled_end = NULL WHERE id = %s",
                (job_ids[1],),
            )

    response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert response.status_code == 200, response.text
    jobs = {
        row["jobId"]: row for week in response.json()["weeks"] for row in week["jobs"]
    }

    assert jobs[job_ids[0]]["estRevenue"] == 50
    assert jobs[job_ids[1]]["includedInForecast"] is False
    assert jobs[job_ids[1]]["estRevenue"] is None


def test_forecast_uses_jobs_site_economics_and_no_schedule_fallback(client, auth):
    today = datetime.now(ZoneInfo("America/Chicago")).date()
    service_dates = _three_dates_in_one_forecast_month(today)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "forecast_commercial",
                "commercial_evening_night",
            )
            _, monthly_site = _customer_site(
                cur,
                "Forecast Monthly",
                site_type="Commercial",
                rate=100,
                rate_type="monthly",
                expected_hours=2,
            )
            _, incomplete_site = _customer_site(
                cur,
                "Forecast Incomplete",
                site_type="Commercial",
                rate=50,
                rate_type="per_visit",
                expected_hours=None,
            )
            _, hourly_site = _customer_site(
                cur,
                "Forecast Hourly",
                site_type="Commercial",
                rate=25,
                rate_type="hourly",
                expected_hours=4,
            )
            _, archived_site = _customer_site(
                cur,
                "Forecast Archived",
                site_type="Commercial",
                rate=900,
                rate_type="per_visit",
                expected_hours=99,
            )
            _, wrong_type_site = _customer_site(
                cur,
                "Forecast Wrong Type",
                site_type="Commercial",
                rate=800,
                rate_type="per_visit",
                expected_hours=88,
            )
            monthly_job_ids = []
            for index, service_date in enumerate(service_dates):
                local_start = datetime.combine(
                    service_date,
                    time(hour=18 + index),
                    tzinfo=ZoneInfo("America/Chicago"),
                )
                monthly_job_ids.append(
                    _job(
                        cur,
                        source_id=source_id,
                        location_id=monthly_site,
                        customer_name=f"{TEST_PREFIX} Customer Forecast Monthly",
                        start=local_start.astimezone(timezone.utc),
                        end=(local_start + timedelta(hours=2)).astimezone(timezone.utc),
                        source_seed=f"forecast-monthly-{index}",
                    )
                )

            incomplete_date = service_dates[0]
            incomplete_start = datetime.combine(
                incomplete_date,
                time(hour=9),
                tzinfo=ZoneInfo("America/Chicago"),
            )
            incomplete_job_id = _job(
                cur,
                source_id=source_id,
                location_id=incomplete_site,
                customer_name=f"{TEST_PREFIX} Customer Forecast Incomplete",
                start=incomplete_start.astimezone(timezone.utc),
                end=(incomplete_start + timedelta(hours=1)).astimezone(timezone.utc),
                source_seed="forecast-incomplete",
            )
            hourly_start = incomplete_start + timedelta(hours=2)
            hourly_job_id = _job(
                cur,
                source_id=source_id,
                location_id=hourly_site,
                customer_name=f"{TEST_PREFIX} Customer Forecast Hourly",
                start=hourly_start.astimezone(timezone.utc),
                end=(hourly_start + timedelta(hours=4)).astimezone(timezone.utc),
                source_seed="forecast-hourly",
            )
            archived_job_id = _job(
                cur,
                source_id=source_id,
                location_id=archived_site,
                customer_name=f"{TEST_PREFIX} Customer Forecast Archived",
                start=(hourly_start + timedelta(hours=6)).astimezone(timezone.utc),
                end=(hourly_start + timedelta(hours=8)).astimezone(timezone.utc),
                source_seed="forecast-archived",
            )
            wrong_type_job_id = _job(
                cur,
                source_id=source_id,
                location_id=wrong_type_site,
                customer_name=f"{TEST_PREFIX} Customer Forecast Wrong Type",
                start=(hourly_start + timedelta(hours=9)).astimezone(timezone.utc),
                end=(hourly_start + timedelta(hours=11)).astimezone(timezone.utc),
                source_seed="forecast-wrong-type",
            )
            source_less_start = hourly_start + timedelta(hours=12)
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date,
                    scheduled_start, scheduled_end, status
                )
                VALUES (%s, %s, %s, %s, %s, 'scheduled')
                RETURNING id
                """,
                (
                    hourly_site,
                    f"{TEST_PREFIX} Customer Forecast Source-less",
                    source_less_start.astimezone(ZoneInfo("America/Chicago")).date(),
                    source_less_start.astimezone(timezone.utc),
                    (source_less_start + timedelta(hours=1)).astimezone(timezone.utc),
                ),
            )
            source_less_job_id = int(cur.fetchone()[0])
            cur.execute(
                "UPDATE locations SET active = false WHERE id = %s",
                (archived_site,),
            )
            cur.execute(
                "UPDATE locations SET location_type = 'Residential' WHERE id = %s",
                (wrong_type_site,),
            )
            employee = _employee(cur, "Forecast Missing Rate", None)
            week_start = service_dates[0] - timedelta(
                days=(service_dates[0].weekday() + 1) % 7
            )
            cur.execute(
                """
                INSERT INTO schedules (
                    employee_id, location_id, customer_name, week_start,
                    scheduled_hours
                )
                VALUES (%s, %s, %s, %s, 999)
                """,
                (
                    employee,
                    monthly_site,
                    f"{TEST_PREFIX} Customer Forecast Monthly",
                    week_start,
                ),
            )

    response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    forecast_as_of = date.fromisoformat(body["asOfDate"])
    jobs = {job["jobId"]: job for week in body["weeks"] for job in week["jobs"]}
    canonical_monthly_rows = [
        site
        for week in body["weeks"]
        for site in week["bySite"]
        if site["locationId"] == monthly_site
    ]
    allocations = [jobs[job_id]["estRevenue"] for job_id in monthly_job_ids]
    assert allocations == [33.34, 33.33, 33.33]
    assert sum(allocations) == pytest.approx(100)
    assert all(jobs[job_id]["plannedHours"] == 2 for job_id in monthly_job_ids)
    assert all(jobs[job_id]["estLaborCost"] is not None for job_id in monthly_job_ids)
    assert jobs[hourly_job_id]["plannedHours"] == 4
    assert jobs[hourly_job_id]["estRevenue"] == 100
    archived = jobs[archived_job_id]
    assert archived["includedInForecast"] is False
    assert archived["estRevenue"] is None
    assert archived["estLaborCost"] is None
    assert {issue["code"] for issue in archived["issues"]} >= {"archived_site"}
    wrong_type = jobs[wrong_type_job_id]
    assert wrong_type["includedInForecast"] is False
    assert wrong_type["estRevenue"] is None
    assert wrong_type["estLaborCost"] is None
    assert {issue["code"] for issue in wrong_type["issues"]} >= {"wrong_site_type"}
    source_less = jobs[source_less_job_id]
    assert source_less["includedInForecast"] is False
    assert source_less["estRevenue"] is None
    assert source_less["estLaborCost"] is None
    assert {issue["code"] for issue in source_less["issues"]} >= {"missing_source_role"}

    incomplete = jobs[incomplete_job_id]
    assert incomplete["plannedHours"] is None
    assert incomplete["estRevenue"] == 50
    assert incomplete["estLaborCost"] is None
    assert "missing_expected_hours" in {
        issue["code"] for issue in incomplete["issues"]
    }
    assert incomplete["expectedHoursBaseline"] == {
        "source": "insufficient_data",
        "state": "learning",
        "plannedHours": None,
        "manualHours": None,
        "suggestedHours": None,
        "sampleSize": 0,
        "minimumSampleSize": 3,
        "observationPeriod": {
            "startDate": str(forecast_as_of - timedelta(days=180)),
            "endDate": str(forecast_as_of),
            "lookbackDays": 180,
        },
        "exclusionRules": list(ops.EXPECTED_HOURS_LEARNING_EXCLUSION_RULES),
        "baselineFingerprint": None,
    }
    assert body["summary"]["plannedHours"] is None
    assert body["summary"]["knownPlannedHours"] == pytest.approx(10)
    assert body["summary"]["jobCount"] == 5
    assert body["summary"]["visibleJobCount"] == 8
    assert body["summary"]["excludedJobCount"] == 3
    assert body["summary"]["estRevenue"] == 250
    assert body["summary"]["knownRevenue"] == 250
    assert body["summary"]["laborCostComplete"] is False
    assert body["summary"]["knownPlannedHours"] != 999
    assert {issue["code"] for issue in body["issues"]} >= {"employees_missing_rates"}

    schedule_response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": str(min(service_dates)),
            "end_date": str(max(service_dates)),
        },
    )
    assert schedule_response.status_code == 200, schedule_response.text
    schedule = schedule_response.json()
    scheduled_jobs = {job["id"]: job for job in schedule["jobs"]}
    assert scheduled_jobs[archived_job_id]["includedInPlan"] is False
    assert {issue["code"] for issue in scheduled_jobs[archived_job_id]["issues"]} >= {
        "archived_site"
    }
    assert scheduled_jobs[wrong_type_job_id]["includedInPlan"] is False
    assert {issue["code"] for issue in scheduled_jobs[wrong_type_job_id]["issues"]} >= {
        "wrong_site_type"
    }
    assert scheduled_jobs[source_less_job_id]["includedInPlan"] is False
    assert {
        issue["code"] for issue in scheduled_jobs[source_less_job_id]["issues"]
    } >= {"missing_source_role"}
    assert schedule["summary"]["jobCount"] == 5
    assert schedule["summary"]["visibleJobCount"] == 8
    assert schedule["summary"]["excludedJobCount"] == 3
    assert schedule["summary"]["knownPlannedHours"] == pytest.approx(10)

    legacy_response = client.get(
        "/api/admin/analytics/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert legacy_response.status_code == 200, legacy_response.text
    legacy_body = legacy_response.json()
    legacy_monthly_rows = [
        customer
        for week in legacy_body["forecasts"]
        for customer in week["byCustomer"]
        if customer["locationId"] == monthly_site
    ]
    assert legacy_monthly_rows == [
        {
            "customerId": site["customerId"],
            "locationId": site["locationId"],
            "customer": site["customerName"],
            "forecastHours": site["plannedHours"],
            "source": "operations",
            "estLaborCost": site["estLaborCost"],
            "estRevenue": site["estRevenue"],
            "issues": site.get("issues", []),
        }
        for site in canonical_monthly_rows
    ]


def test_expected_hours_learning_suggests_median_from_completed_actual_visits(
    client,
    auth,
):
    app_timezone = ZoneInfo("America/Chicago")
    today = datetime.now(app_timezone).date()
    future_day = today + timedelta(days=1)
    completed_days = [
        today - timedelta(days=28),
        today - timedelta(days=21),
        today - timedelta(days=14),
        today - timedelta(days=7),
    ]
    durations = [2, 3, 4, 7]
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "expected_hours_learning",
                "commercial_evening_night",
            )
            _, site_id = _customer_site(
                cur,
                "Expected Hours Learning",
                site_type="Commercial",
                rate=80,
                rate_type="per_visit",
                expected_hours=None,
            )
            _, other_site_id = _customer_site(
                cur,
                "Expected Hours Learning Other Site",
                site_type="Commercial",
                rate=80,
                rate_type="per_visit",
                expected_hours=None,
            )
            employee_id = _employee(cur, "Expected Hours Learning", 22)
            other_employee_id = _employee(cur, "Expected Hours Learning Other", 22)
            for index, (service_day, hours) in enumerate(
                zip(completed_days, durations)
            ):
                local_start = datetime.combine(
                    service_day,
                    time(hour=18),
                    tzinfo=app_timezone,
                )
                job_id = _job(
                    cur,
                    source_id=source_id,
                    location_id=site_id,
                    customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                    start=local_start.astimezone(timezone.utc),
                    end=(local_start + timedelta(hours=hours)).astimezone(
                        timezone.utc
                    ),
                    source_seed=f"expected-hours-learning-history-{index}",
                )
                cur.execute(
                    "UPDATE jobs SET status = 'completed' WHERE id = %s",
                    (job_id,),
                )
                shift_start = local_start.astimezone(timezone.utc) - timedelta(
                    minutes=15
                )
                shift_end = shift_start + timedelta(hours=hours, minutes=30)
                shift_id = _shift(
                    cur,
                    employee_id=employee_id,
                    start=shift_start,
                    end=shift_end,
                    service_day=service_day,
                    location_id=site_id,
                    location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                    job_id=None if index == 0 else job_id,
                )
                arrival = local_start.astimezone(timezone.utc)
                departure = (local_start + timedelta(hours=hours)).astimezone(
                    timezone.utc
                )
                if index == 0:
                    manual_visit_id = _visit(
                        cur,
                        shift_id=shift_id,
                        location_id=site_id,
                        at=arrival,
                        suffix=f"Expected Hours Learning {index}",
                        sequence_version=2,
                        job_id=job_id,
                    )
                    _departure(
                        cur,
                        shift_id=shift_id,
                        location_id=site_id,
                        at=departure,
                        suffix=f"Expected Hours Learning {index}",
                        visit_id=manual_visit_id,
                    )
                elif index == 1:
                    reviewed_check_in_id = _check_in(
                        cur,
                        employee_id=employee_id,
                        location_id=site_id,
                        checked_in_at=arrival,
                        job_id=job_id,
                    )
                    reviewed_visit_id = _visit(
                        cur,
                        shift_id=shift_id,
                        location_id=site_id,
                        at=arrival,
                        suffix=f"Expected Hours Learning {index}",
                        sequence_version=2,
                        site_check_in_id=reviewed_check_in_id,
                        job_id=job_id,
                    )
                    _reviewed_departure_correction(
                        cur,
                        shift_id=shift_id,
                        visit_id=reviewed_visit_id,
                        location_id=site_id,
                        effective_departure_at=departure,
                        suffix=f"Expected Hours Learning {index}",
                    )
                else:
                    _paired_version_two_visit(
                        cur,
                        employee_id=employee_id,
                        shift_id=shift_id,
                        location_id=site_id,
                        job_id=job_id,
                        arrival=arrival,
                        departure=departure,
                        suffix=f"Expected Hours Learning {index}",
                    )
                if index == 2:
                    service_week_start = service_day - timedelta(
                        days=(service_day.weekday() + 1) % 7
                    )
                    cur.execute(
                        """
                        INSERT INTO payroll_shift_corrections (
                            week_start,
                            correction_date,
                            employee_id,
                            shift_id,
                            source_clock_in,
                            source_clock_out,
                            source_break_minutes,
                            source_total_minutes,
                            corrected_clock_in,
                            corrected_clock_out,
                            corrected_break_minutes,
                            corrected_total_minutes,
                            reason,
                            status,
                            created_by_employee_id,
                            created_by_name
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, NULL, 270,
                            %s, %s, 60, 210,
                            'Deduct scheduled meal break from learned hours.',
                            'active',
                            %s,
                            'Mayra'
                        )
                        """,
                        (
                            service_week_start,
                            service_day,
                            employee_id,
                            shift_id,
                            shift_start,
                            shift_end,
                            shift_start,
                            shift_end,
                            employee_id,
                        ),
                    )

            invalid_day = today - timedelta(days=3)
            invalid_local_start = datetime.combine(
                invalid_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            invalid_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=invalid_local_start.astimezone(timezone.utc),
                end=(invalid_local_start + timedelta(hours=11)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-invalid-qr-identity",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (invalid_job_id,),
            )
            invalid_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=invalid_local_start.astimezone(timezone.utc)
                - timedelta(minutes=15),
                end=(invalid_local_start + timedelta(hours=11, minutes=15)).astimezone(
                    timezone.utc
                ),
                service_day=invalid_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=invalid_job_id,
            )
            invalid_check_in_id = _check_in(
                cur,
                employee_id=other_employee_id,
                location_id=site_id,
                checked_in_at=invalid_local_start.astimezone(timezone.utc),
                job_id=invalid_job_id,
            )
            invalid_visit_id = _visit(
                cur,
                shift_id=invalid_shift_id,
                location_id=site_id,
                at=invalid_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Invalid",
                sequence_version=2,
                site_check_in_id=invalid_check_in_id,
            )
            _departure(
                cur,
                shift_id=invalid_shift_id,
                location_id=site_id,
                at=(invalid_local_start + timedelta(hours=11)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Invalid",
                visit_id=invalid_visit_id,
            )

            outside_day = today - timedelta(days=4)
            outside_local_start = datetime.combine(
                outside_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            outside_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=outside_local_start.astimezone(timezone.utc),
                end=(outside_local_start + timedelta(hours=9)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-outside-paid-shift",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (outside_job_id,),
            )
            outside_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=outside_local_start.astimezone(timezone.utc),
                end=(outside_local_start + timedelta(hours=2)).astimezone(
                    timezone.utc
                ),
                service_day=outside_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=outside_job_id,
            )
            outside_visit_id = _visit(
                cur,
                shift_id=outside_shift_id,
                location_id=site_id,
                at=(outside_local_start - timedelta(minutes=30)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Outside Paid Shift",
                sequence_version=2,
                job_id=outside_job_id,
            )
            _departure(
                cur,
                shift_id=outside_shift_id,
                location_id=site_id,
                at=(outside_local_start + timedelta(hours=1)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Outside Paid Shift",
                visit_id=outside_visit_id,
            )

            overlap_day = today - timedelta(days=5)
            overlap_local_start = datetime.combine(
                overlap_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            overlap_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=overlap_local_start.astimezone(timezone.utc),
                end=(overlap_local_start + timedelta(hours=10)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-overlap",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (overlap_job_id,),
            )
            overlap_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=overlap_local_start.astimezone(timezone.utc),
                end=(overlap_local_start + timedelta(hours=4)).astimezone(
                    timezone.utc
                ),
                service_day=overlap_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=overlap_job_id,
            )
            first_overlap_visit = _visit(
                cur,
                shift_id=overlap_shift_id,
                location_id=site_id,
                at=overlap_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Overlap A",
                sequence_version=2,
                job_id=overlap_job_id,
            )
            _departure(
                cur,
                shift_id=overlap_shift_id,
                location_id=site_id,
                at=(overlap_local_start + timedelta(hours=2)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Overlap A",
                visit_id=first_overlap_visit,
            )
            second_overlap_visit = _visit(
                cur,
                shift_id=overlap_shift_id,
                location_id=site_id,
                at=(overlap_local_start + timedelta(hours=1)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Overlap B",
                sequence_version=2,
                job_id=overlap_job_id,
            )
            _departure(
                cur,
                shift_id=overlap_shift_id,
                location_id=site_id,
                at=(overlap_local_start + timedelta(hours=3)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Overlap B",
                visit_id=second_overlap_visit,
            )

            non_productive_day = today - timedelta(days=6)
            non_productive_local_start = datetime.combine(
                non_productive_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            non_productive_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=non_productive_local_start.astimezone(timezone.utc),
                end=(non_productive_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-non-productive",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (non_productive_job_id,),
            )
            non_productive_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=non_productive_local_start.astimezone(timezone.utc),
                end=(non_productive_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=non_productive_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=non_productive_job_id,
                time_category="non_productive",
                non_productive_type="drive_time",
            )
            _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=non_productive_shift_id,
                location_id=site_id,
                job_id=non_productive_job_id,
                arrival=non_productive_local_start.astimezone(timezone.utc),
                departure=(non_productive_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Non Productive",
            )

            legacy_day = today - timedelta(days=8)
            legacy_local_start = datetime.combine(
                legacy_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            legacy_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=legacy_local_start.astimezone(timezone.utc),
                end=(legacy_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-legacy-visit",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (legacy_job_id,),
            )
            legacy_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=legacy_local_start.astimezone(timezone.utc),
                end=(legacy_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=legacy_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=legacy_job_id,
            )
            _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=legacy_shift_id,
                location_id=site_id,
                job_id=legacy_job_id,
                arrival=legacy_local_start.astimezone(timezone.utc),
                departure=(legacy_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Legacy Valid Pair",
            )
            _visit(
                cur,
                shift_id=legacy_shift_id,
                location_id=site_id,
                at=(legacy_local_start + timedelta(minutes=30)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Legacy Visit",
                sequence_version=1,
            )

            cross_shift_day = today - timedelta(days=9)
            cross_shift_local_start = datetime.combine(
                cross_shift_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            cross_shift_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=cross_shift_local_start.astimezone(timezone.utc),
                end=(cross_shift_local_start + timedelta(hours=9)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-cross-shift-departure",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (cross_shift_job_id,),
            )
            cross_shift_visit_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=cross_shift_local_start.astimezone(timezone.utc),
                end=(cross_shift_local_start + timedelta(hours=9)).astimezone(
                    timezone.utc
                ),
                service_day=cross_shift_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=cross_shift_job_id,
            )
            cross_shift_departure_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=cross_shift_local_start.astimezone(timezone.utc),
                end=(cross_shift_local_start + timedelta(hours=9)).astimezone(
                    timezone.utc
                ),
                service_day=cross_shift_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=cross_shift_job_id,
            )
            cross_shift_visit_id = _visit(
                cur,
                shift_id=cross_shift_visit_shift_id,
                location_id=site_id,
                at=cross_shift_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Cross Shift Visit",
                sequence_version=2,
                job_id=cross_shift_job_id,
            )
            _departure(
                cur,
                shift_id=cross_shift_departure_shift_id,
                location_id=site_id,
                at=(cross_shift_local_start + timedelta(hours=9)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Cross Shift Departure",
                visit_id=cross_shift_visit_id,
            )

            stale_review_day = today - timedelta(days=10)
            stale_review_local_start = datetime.combine(
                stale_review_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            stale_original_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=stale_review_local_start.astimezone(timezone.utc),
                end=(stale_review_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-stale-reviewed-original",
            )
            stale_poison_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=stale_review_local_start.astimezone(timezone.utc),
                end=(stale_review_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-stale-reviewed-poison",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (stale_poison_job_id,),
            )
            stale_review_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=stale_review_local_start.astimezone(timezone.utc),
                end=(stale_review_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=stale_review_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=stale_original_job_id,
            )
            stale_review_visit_id = _visit(
                cur,
                shift_id=stale_review_shift_id,
                location_id=site_id,
                at=stale_review_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Stale Reviewed",
                sequence_version=2,
            )
            _reviewed_departure_correction(
                cur,
                shift_id=stale_review_shift_id,
                visit_id=stale_review_visit_id,
                location_id=site_id,
                effective_departure_at=(
                    stale_review_local_start + timedelta(hours=8)
                ).astimezone(timezone.utc),
                suffix="Expected Hours Learning Stale Reviewed",
            )
            cur.execute(
                "UPDATE shifts SET job_id = %s WHERE id = %s",
                (stale_poison_job_id, stale_review_shift_id),
            )

            qr_mismatch_day = today - timedelta(days=11)
            qr_mismatch_local_start = datetime.combine(
                qr_mismatch_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            qr_identity_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=qr_mismatch_local_start.astimezone(timezone.utc),
                end=(qr_mismatch_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-qr-identity",
            )
            qr_visit_poison_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=qr_mismatch_local_start.astimezone(timezone.utc),
                end=(qr_mismatch_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-qr-visit-poison",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (qr_visit_poison_job_id,),
            )
            qr_mismatch_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=qr_mismatch_local_start.astimezone(timezone.utc),
                end=(qr_mismatch_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=qr_mismatch_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
            )
            qr_identity_check_in_id = _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_id,
                checked_in_at=qr_mismatch_local_start.astimezone(timezone.utc),
                job_id=qr_identity_job_id,
            )
            qr_mismatch_visit_id = _visit(
                cur,
                shift_id=qr_mismatch_shift_id,
                location_id=site_id,
                at=qr_mismatch_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning QR Mismatch",
                sequence_version=2,
                site_check_in_id=qr_identity_check_in_id,
                job_id=qr_visit_poison_job_id,
            )
            _departure(
                cur,
                shift_id=qr_mismatch_shift_id,
                location_id=site_id,
                at=(qr_mismatch_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning QR Mismatch",
                visit_id=qr_mismatch_visit_id,
            )

            paid_overlap_day = today - timedelta(days=12)
            paid_overlap_local_start = datetime.combine(
                paid_overlap_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            paid_overlap_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=paid_overlap_local_start.astimezone(timezone.utc),
                end=(paid_overlap_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-paid-overlap",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (paid_overlap_job_id,),
            )
            first_paid_overlap_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=paid_overlap_local_start.astimezone(timezone.utc),
                end=(paid_overlap_local_start + timedelta(hours=4)).astimezone(
                    timezone.utc
                ),
                service_day=paid_overlap_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=paid_overlap_job_id,
            )
            second_paid_overlap_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=(paid_overlap_local_start + timedelta(hours=1)).astimezone(
                    timezone.utc
                ),
                end=(paid_overlap_local_start + timedelta(hours=5)).astimezone(
                    timezone.utc
                ),
                service_day=paid_overlap_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=paid_overlap_job_id,
            )
            first_paid_overlap_visit_id = _visit(
                cur,
                shift_id=first_paid_overlap_shift_id,
                location_id=site_id,
                at=paid_overlap_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Paid Overlap A",
                sequence_version=2,
                job_id=paid_overlap_job_id,
            )
            _departure(
                cur,
                shift_id=first_paid_overlap_shift_id,
                location_id=site_id,
                at=(paid_overlap_local_start + timedelta(hours=3)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Paid Overlap A",
                visit_id=first_paid_overlap_visit_id,
            )
            second_paid_overlap_visit_id = _visit(
                cur,
                shift_id=second_paid_overlap_shift_id,
                location_id=site_id,
                at=(paid_overlap_local_start + timedelta(hours=1)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Paid Overlap B",
                sequence_version=2,
                job_id=paid_overlap_job_id,
            )
            _departure(
                cur,
                shift_id=second_paid_overlap_shift_id,
                location_id=site_id,
                at=(paid_overlap_local_start + timedelta(hours=4)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Paid Overlap B",
                visit_id=second_paid_overlap_visit_id,
            )

            orphan_departure_day = today - timedelta(days=13)
            orphan_departure_local_start = datetime.combine(
                orphan_departure_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            orphan_departure_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=orphan_departure_local_start.astimezone(timezone.utc),
                end=(orphan_departure_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-orphan-departure",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (orphan_departure_job_id,),
            )
            orphan_departure_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=orphan_departure_local_start.astimezone(timezone.utc),
                end=(orphan_departure_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=orphan_departure_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=orphan_departure_job_id,
            )
            orphan_departure_visit_id, _ = _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=orphan_departure_shift_id,
                location_id=site_id,
                job_id=orphan_departure_job_id,
                arrival=orphan_departure_local_start.astimezone(timezone.utc),
                departure=(orphan_departure_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Orphan Departure",
            )
            assert orphan_departure_visit_id is not None
            _departure(
                cur,
                shift_id=orphan_departure_shift_id,
                location_id=site_id,
                at=(orphan_departure_local_start + timedelta(hours=2)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Orphan Departure",
                visit_id=None,
            )

            embedded_arrival_day = today - timedelta(days=16)
            embedded_arrival_local_start = datetime.combine(
                embedded_arrival_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            embedded_arrival_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=embedded_arrival_local_start.astimezone(timezone.utc),
                end=(embedded_arrival_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-embedded-arrival",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (embedded_arrival_job_id,),
            )
            embedded_arrival_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=embedded_arrival_local_start.astimezone(timezone.utc),
                end=(embedded_arrival_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=embedded_arrival_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=embedded_arrival_job_id,
            )
            _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=embedded_arrival_shift_id,
                location_id=site_id,
                job_id=embedded_arrival_job_id,
                arrival=embedded_arrival_local_start.astimezone(timezone.utc),
                departure=(embedded_arrival_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Embedded Arrival",
            )
            _visit(
                cur,
                shift_id=embedded_arrival_shift_id,
                location_id=other_site_id,
                at=(embedded_arrival_local_start + timedelta(hours=2)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Embedded Arrival Other Site",
                sequence_version=2,
            )

            unassigned_worker_day = today - timedelta(days=17)
            unassigned_worker_local_start = datetime.combine(
                unassigned_worker_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            unassigned_worker_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=unassigned_worker_local_start.astimezone(timezone.utc),
                end=(unassigned_worker_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                source_seed="expected-hours-learning-unassigned-worker",
            )
            cur.execute(
                "UPDATE jobs SET status = 'completed' WHERE id = %s",
                (unassigned_worker_job_id,),
            )
            assigned_worker_shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=unassigned_worker_local_start.astimezone(timezone.utc),
                end=(unassigned_worker_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=unassigned_worker_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
                job_id=unassigned_worker_job_id,
            )
            _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=assigned_worker_shift_id,
                location_id=site_id,
                job_id=unassigned_worker_job_id,
                arrival=unassigned_worker_local_start.astimezone(timezone.utc),
                departure=(unassigned_worker_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Assigned Worker",
            )
            unassigned_worker_shift_id = _shift(
                cur,
                employee_id=other_employee_id,
                start=unassigned_worker_local_start.astimezone(timezone.utc),
                end=(unassigned_worker_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                service_day=unassigned_worker_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Expected Hours Learning",
            )
            unassigned_worker_visit_id = _visit(
                cur,
                shift_id=unassigned_worker_shift_id,
                location_id=site_id,
                at=unassigned_worker_local_start.astimezone(timezone.utc),
                suffix="Expected Hours Learning Unassigned Worker",
                sequence_version=2,
            )
            _departure(
                cur,
                shift_id=unassigned_worker_shift_id,
                location_id=site_id,
                at=(unassigned_worker_local_start + timedelta(hours=8)).astimezone(
                    timezone.utc
                ),
                suffix="Expected Hours Learning Unassigned Worker",
                visit_id=unassigned_worker_visit_id,
            )

            future_start = datetime.combine(
                future_day,
                time(hour=18),
                tzinfo=app_timezone,
            )
            future_job_id = _job(
                cur,
                source_id=source_id,
                location_id=site_id,
                customer_name=f"{TEST_PREFIX} Customer Expected Hours Learning",
                start=future_start.astimezone(timezone.utc),
                end=(future_start + timedelta(hours=2)).astimezone(timezone.utc),
                source_seed="expected-hours-learning-future",
            )

    forecast_response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert forecast_response.status_code == 200, forecast_response.text
    forecast_jobs = {
        row["jobId"]: row
        for week in forecast_response.json()["weeks"]
        for row in week["jobs"]
    }
    forecast_job = forecast_jobs[future_job_id]
    assert forecast_job["plannedHours"] is None
    assert forecast_job["estRevenue"] == 80
    assert "missing_expected_hours" in {
        issue["code"] for issue in forecast_job["issues"]
    }
    baseline = forecast_job["expectedHoursBaseline"]
    assert baseline["source"] == "learned_suggestion"
    assert baseline["state"] == "suggested"
    assert baseline["suggestedHours"] == 3
    assert baseline["plannedHours"] is None
    assert baseline["manualHours"] is None
    assert baseline["sampleSize"] == 4
    assert baseline["minimumSampleSize"] == 3
    assert baseline["observationPeriod"] == {
        "startDate": str(completed_days[0]),
        "endDate": str(completed_days[-1]),
        "lookbackDays": 180,
    }
    assert "excludes_unpaired_or_invalid_site_events" in baseline["exclusionRules"]

    schedule_response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(future_day), "end_date": str(future_day)},
    )
    assert schedule_response.status_code == 200, schedule_response.text
    schedule_job = {
        row["id"]: row for row in schedule_response.json()["jobs"]
    }[future_job_id]
    assert schedule_job["expectedHoursBaseline"] == baseline
    assert schedule_job["siteEconomics"]["expectedHoursBaseline"] == baseline
    assert {issue["code"] for issue in schedule_job["issues"]} == {
        "missing_expected_hours"
    }


def test_expected_hours_baseline_acceptance_promotes_suggestion_to_planned_hours(
    client,
    auth,
):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            seed = _seed_expected_hours_suggestion(cur, "Accept")

    forecast_response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert forecast_response.status_code == 200, forecast_response.text
    forecast_job = {
        row["jobId"]: row
        for week in forecast_response.json()["weeks"]
        for row in week["jobs"]
    }[seed["futureJobId"]]
    baseline = forecast_job["expectedHoursBaseline"]
    assert baseline["source"] == "learned_suggestion"
    assert baseline["state"] == "suggested"
    assert baseline["plannedHours"] is None
    assert baseline["suggestedHours"] == 3
    assert re.fullmatch(r"[0-9a-f]{64}", baseline["baselineFingerprint"])

    accepted = client.post(
        f"/api/admin/operations/sites/{seed['siteId']}/expected-hours-baseline/decision",
        headers=auth,
        json={
            "decision": "accept",
            "baselineFingerprint": baseline["baselineFingerprint"],
            "reason": "Use the current median after three clean visits",
        },
    )
    assert accepted.status_code == 200, accepted.text
    accepted_body = accepted.json()
    assert accepted_body["expectedHours"] == 3
    accepted_baseline = accepted_body["expectedHoursBaseline"]
    assert accepted_baseline["source"] == "learned_accepted"
    assert accepted_baseline["state"] == "accepted"
    assert accepted_baseline["plannedHours"] == 3
    assert accepted_baseline["manualHours"] is None
    assert accepted_baseline["suggestedHours"] == 3
    assert accepted_baseline["sampleSize"] == 3
    assert accepted_baseline["observationPeriod"] == baseline["observationPeriod"]
    assert accepted_baseline["exclusionRules"] == baseline["exclusionRules"]
    assert accepted_baseline["baselineFingerprint"] == baseline["baselineFingerprint"]
    assert re.fullmatch(r"[0-9a-f]{64}", accepted_body["siteUpdateToken"])

    row = db.query_one(
        """
        SELECT expected_hours, expected_hours_source,
               expected_hours_learning_decision,
               expected_hours_learning_fingerprint,
               expected_hours_learning_snapshot,
               expected_hours_learning_decision_reason
        FROM locations
        WHERE id = %s
        """,
        (seed["siteId"],),
    )
    assert float(row["expected_hours"]) == pytest.approx(3)
    assert row["expected_hours_source"] == "learned_accepted"
    assert row["expected_hours_learning_decision"] == "accepted"
    assert row["expected_hours_learning_fingerprint"] == baseline["baselineFingerprint"]
    assert row["expected_hours_learning_snapshot"]["baselineFingerprint"] == (
        baseline["baselineFingerprint"]
    )
    assert row["expected_hours_learning_snapshot"]["sampleSize"] == 3
    assert row["expected_hours_learning_decision_reason"] == (
        "Use the current median after three clean visits"
    )

    refreshed_response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert refreshed_response.status_code == 200, refreshed_response.text
    refreshed_job = {
        row["jobId"]: row
        for week in refreshed_response.json()["weeks"]
        for row in week["jobs"]
    }[seed["futureJobId"]]
    assert refreshed_job["plannedHours"] == 3
    assert refreshed_job["estLaborCost"] is not None
    assert "missing_expected_hours" not in {
        issue["code"] for issue in refreshed_job["issues"]
    }
    assert refreshed_job["expectedHoursBaseline"]["state"] == "accepted"

    manual_override = client.patch(
        f"/api/admin/locations/{seed['siteId']}",
        headers=auth,
        json={
            "expectedUpdateToken": accepted_body["siteUpdateToken"],
            "expectedHours": 4,
        },
    )
    assert manual_override.status_code == 200, manual_override.text
    manual_site = manual_override.json()["location"]
    assert manual_site["expectedHours"] == 4
    assert manual_site["expectedHoursSource"] == "manual"
    assert manual_site["expectedHoursLearningDecision"] is None
    assert manual_site["expectedHoursLearningFingerprint"] is None
    assert manual_site["expectedHoursLearningSnapshot"] is None
    manual_row = db.query_one(
        """
        SELECT expected_hours_learning_snapshot
        FROM locations
        WHERE id = %s
        """,
        (seed["siteId"],),
    )
    assert manual_row["expected_hours_learning_snapshot"] is None


def test_expected_hours_baseline_rejection_is_fingerprint_scoped(client, auth):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            seed = _seed_expected_hours_suggestion(cur, "Reject")

    forecast_response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert forecast_response.status_code == 200, forecast_response.text
    forecast_job = {
        row["jobId"]: row
        for week in forecast_response.json()["weeks"]
        for row in week["jobs"]
    }[seed["futureJobId"]]
    baseline = forecast_job["expectedHoursBaseline"]
    assert baseline["state"] == "suggested"

    stale = client.post(
        f"/api/admin/operations/sites/{seed['siteId']}/expected-hours-baseline/decision",
        headers=auth,
        json={
            "decision": "reject",
            "baselineFingerprint": "0" * 64,
        },
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["code"] == "stale_expected_hours_baseline"

    rejected = client.post(
        f"/api/admin/operations/sites/{seed['siteId']}/expected-hours-baseline/decision",
        headers=auth,
        json={
            "decision": "reject",
            "baselineFingerprint": baseline["baselineFingerprint"],
            "reason": "Wait for one more completed visit",
        },
    )
    assert rejected.status_code == 200, rejected.text
    rejected_baseline = rejected.json()["expectedHoursBaseline"]
    assert rejected_baseline["source"] == "learned_rejected"
    assert rejected_baseline["state"] == "rejected"
    assert rejected_baseline["plannedHours"] is None
    assert rejected_baseline["suggestedHours"] == 3
    assert rejected_baseline["sampleSize"] == 3
    assert rejected_baseline["baselineFingerprint"] == baseline["baselineFingerprint"]

    row = db.query_one(
        """
        SELECT expected_hours, expected_hours_learning_decision,
               expected_hours_learning_fingerprint,
               expected_hours_learning_snapshot
        FROM locations
        WHERE id = %s
        """,
        (seed["siteId"],),
    )
    assert row["expected_hours"] is None
    assert row["expected_hours_learning_decision"] == "rejected"
    assert row["expected_hours_learning_fingerprint"] == baseline["baselineFingerprint"]
    assert row["expected_hours_learning_snapshot"]["baselineFingerprint"] == (
        baseline["baselineFingerprint"]
    )

    rejected_forecast = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert rejected_forecast.status_code == 200, rejected_forecast.text
    rejected_job = {
        row["jobId"]: row
        for week in rejected_forecast.json()["weeks"]
        for row in week["jobs"]
    }[seed["futureJobId"]]
    assert rejected_job["expectedHoursBaseline"]["state"] == "rejected"
    assert rejected_job["plannedHours"] is None

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            _add_expected_hours_learning_sample(
                cur,
                source_id=int(seed["sourceId"]),
                site_id=int(seed["siteId"]),
                employee_id=int(seed["employeeId"]),
                suffix="Reject",
                day=seed["futureDay"] - timedelta(days=2),
                duration=8,
            )

    refreshed_response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 4},
    )
    assert refreshed_response.status_code == 200, refreshed_response.text
    refreshed_job = {
        row["jobId"]: row
        for week in refreshed_response.json()["weeks"]
        for row in week["jobs"]
    }[seed["futureJobId"]]
    refreshed_baseline = refreshed_job["expectedHoursBaseline"]
    assert refreshed_baseline["state"] == "suggested"
    assert refreshed_baseline["source"] == "learned_suggestion"
    assert refreshed_baseline["baselineFingerprint"] != baseline["baselineFingerprint"]


def test_expected_hours_learning_excludes_evidence_after_observed_at():
    app_timezone = ZoneInfo("America/Chicago")
    observed_local = datetime(2026, 7, 20, 9, tzinfo=app_timezone)
    future_local_starts = [
        datetime(2026, 7, 20, hour, tzinfo=app_timezone)
        for hour in (10, 13, 16)
    ]
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            source_id = _source(
                cur,
                "expected_hours_learning_future_evidence",
                "commercial_evening_night",
            )
            _, site_id = _customer_site(
                cur,
                "Expected Hours Learning Future Evidence",
                site_type="Commercial",
                rate=80,
                rate_type="per_visit",
                expected_hours=None,
            )
            employee_id = _employee(cur, "Expected Hours Learning Future Evidence", 22)
            for index, local_start in enumerate(future_local_starts):
                job_id = _job(
                    cur,
                    source_id=source_id,
                    location_id=site_id,
                    customer_name=(
                        f"{TEST_PREFIX} Customer Expected Hours Learning Future"
                    ),
                    start=local_start.astimezone(timezone.utc),
                    end=(local_start + timedelta(hours=1)).astimezone(timezone.utc),
                    source_seed=f"expected-hours-learning-future-evidence-{index}",
                )
                cur.execute(
                    "UPDATE jobs SET status = 'completed' WHERE id = %s",
                    (job_id,),
                )
                shift_id = _shift(
                    cur,
                    employee_id=employee_id,
                    start=(local_start - timedelta(minutes=5)).astimezone(
                        timezone.utc
                    ),
                    end=(local_start + timedelta(hours=1, minutes=5)).astimezone(
                        timezone.utc
                    ),
                    service_day=local_start.date(),
                    location_id=site_id,
                    location_label=(
                        f"{TEST_PREFIX} Site Expected Hours Learning Future"
                    ),
                    job_id=job_id,
                )
                _paired_version_two_visit(
                    cur,
                    employee_id=employee_id,
                    shift_id=shift_id,
                    location_id=site_id,
                    job_id=job_id,
                    arrival=local_start.astimezone(timezone.utc),
                    departure=(local_start + timedelta(hours=1)).astimezone(
                        timezone.utc
                    ),
                    suffix=f"Expected Hours Learning Future Evidence {index}",
                )

    learning = ops._load_expected_hours_learning_by_site(
        [site_id],
        observed_at=observed_local.astimezone(timezone.utc),
        app_timezone=app_timezone,
    )

    assert learning[site_id]["sampleSize"] == 0
    assert learning[site_id]["suggestedHours"] is None


def test_utilization_reconciles_complete_route_split_crew_and_categorized_time(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    worker_a_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    site_a_arrival = worker_a_start + timedelta(minutes=30)
    site_a_departure = worker_a_start + timedelta(hours=2, minutes=30)
    site_b_arrival = worker_a_start + timedelta(hours=3)
    site_b_departure = worker_a_start + timedelta(hours=5)
    worker_a_end = worker_a_start + timedelta(hours=6)
    categorized_start = worker_a_end + timedelta(hours=1)
    categorized_end = categorized_start + timedelta(minutes=30)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="Utilization Route A",
                start=site_a_arrival,
                end=site_a_departure,
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="Utilization Route B",
                start=site_b_arrival,
                end=site_b_departure,
            )
            worker_a = _employee(cur, "Utilization Route A", 18)
            worker_b = _employee(cur, "Utilization Route B", 20)
            worker_a_shift = _shift(
                cur,
                employee_id=worker_a,
                start=worker_a_start,
                end=worker_a_end,
                service_day=service_day,
                # Explicit QR arrival writes the first Site onto an unassigned
                # shift. Utilization must still leave the pre-arrival edge
                # unclassified.
                location_id=site_a,
                location_label=f"{TEST_PREFIX} Site Utilization Route A",
            )
            visit_a, departure_a = _paired_version_two_visit(
                cur,
                employee_id=worker_a,
                shift_id=worker_a_shift,
                location_id=site_a,
                job_id=job_a,
                arrival=site_a_arrival,
                departure=site_a_departure,
                suffix="Utilization Route A",
            )
            visit_b, departure_b = _paired_version_two_visit(
                cur,
                employee_id=worker_a,
                shift_id=worker_a_shift,
                location_id=site_b,
                job_id=job_b,
                arrival=site_b_arrival,
                departure=site_b_departure,
                suffix="Utilization Route B",
            )
            worker_b_shift = _shift(
                cur,
                employee_id=worker_b,
                start=site_a_arrival,
                end=site_a_departure,
                service_day=service_day,
                location_id=site_a,
                location_label=f"{TEST_PREFIX} Site Utilization Route A",
                job_id=job_a,
            )
            # Manual Arrive/Depart evidence has no QR check-in. The shift's
            # service occurrence is still valid because it belongs to this Site.
            worker_b_visit = _visit(
                cur,
                shift_id=worker_b_shift,
                location_id=site_a,
                at=site_a_arrival,
                suffix="Utilization Route A",
                sequence_version=2,
            )
            worker_b_departure = _departure(
                cur,
                shift_id=worker_b_shift,
                location_id=site_a,
                at=site_a_departure,
                suffix="Utilization Route A",
                visit_id=worker_b_visit,
            )
            categorized_shift = _shift(
                cur,
                employee_id=worker_a,
                start=categorized_start,
                end=categorized_end,
                service_day=service_day,
                time_category="non_productive",
                non_productive_type="drive_time",
            )
            cur.execute(
                "UPDATE shifts SET total_hours = 99 WHERE id = %s",
                (worker_a_shift,),
            )

    body = _utilization_body(client, auth, service_day)
    assert body["startDate"] == str(service_day)
    assert body["endDate"] == str(service_day)
    assert body["reviewItems"] == []
    _assert_utilization_totals(
        body["summary"],
        paid=510,
        on_site=360,
        travel=30,
        categorized=30,
        unclassified=90,
    )

    worker_a_row = _utilization_row(body, worker_a, service_day)
    worker_b_row = _utilization_row(body, worker_b, service_day)
    _assert_utilization_totals(
        worker_a_row,
        paid=390,
        on_site=240,
        travel=30,
        categorized=30,
        unclassified=90,
    )
    _assert_utilization_totals(
        worker_b_row,
        paid=120,
        on_site=120,
        travel=0,
        categorized=0,
        unclassified=0,
    )
    _assert_interval_contract(worker_a_row["intervals"])
    _assert_interval_contract(worker_b_row["intervals"])

    assert [
        (
            interval["category"],
            interval["durationMinutes"],
            interval["locationId"],
            interval["jobId"],
        )
        for interval in worker_a_row["intervals"]
    ] == [
        ("unclassified", 30, None, None),
        ("on_site", 120, site_a, job_a),
        ("travel", 30, None, None),
        ("on_site", 120, site_b, job_b),
        ("unclassified", 60, None, None),
        ("categorized", 30, None, None),
    ]
    categorized = next(
        interval
        for interval in worker_a_row["intervals"]
        if interval["category"] == "categorized"
    )
    assert categorized["shiftId"] == categorized_shift
    assert categorized["categoryDetail"] == "drive_time"

    worker_a_on_site = [
        interval
        for interval in worker_a_row["intervals"]
        if interval["category"] == "on_site"
    ]
    assert [
        (
            interval["visitId"],
            interval["departureId"],
            interval["reviewCodes"],
        )
        for interval in worker_a_on_site
    ] == [
        (visit_a, departure_a, []),
        (visit_b, departure_b, []),
    ]
    assert len(worker_b_row["intervals"]) == 1
    worker_b_interval = worker_b_row["intervals"][0]
    assert {
        "shiftId": worker_b_interval["shiftId"],
        "category": worker_b_interval["category"],
        "durationSeconds": worker_b_interval["durationSeconds"],
        "durationMinutes": worker_b_interval["durationMinutes"],
        "locationId": worker_b_interval["locationId"],
        "jobId": worker_b_interval["jobId"],
        "visitId": worker_b_interval["visitId"],
        "departureId": worker_b_interval["departureId"],
        "reviewCodes": worker_b_interval["reviewCodes"],
    } == {
        "shiftId": worker_b_shift,
        "category": "on_site",
        "durationSeconds": 120 * 60,
        "durationMinutes": 120,
        "locationId": site_a,
        "jobId": job_a,
        "visitId": worker_b_visit,
        "departureId": worker_b_departure,
        "reviewCodes": [],
    }

    all_on_site = [
        interval
        for row in body["rows"]
        for interval in row["intervals"]
        if interval["category"] == "on_site"
    ]
    assert sum(
        interval["durationMinutes"]
        for interval in all_on_site
        if interval["locationId"] == site_a
    ) == 240
    assert sum(
        interval["durationMinutes"]
        for interval in all_on_site
        if interval["locationId"] == site_b
    ) == 120
    assert {interval["jobId"] for interval in all_on_site} == {job_a, job_b}


def test_utilization_endpoint_rejects_mismatched_linked_qr_identity(client, auth):
    service_day = date(2026, 7, 20)
    first_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="Utilization QR Identity A",
                start=first_start,
                end=first_start + timedelta(hours=6),
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="Utilization QR Identity B",
                start=first_start,
                end=first_start + timedelta(hours=6),
            )
            worker = _employee(cur, "Utilization QR Identity", 18)
            other_worker = _employee(cur, "Utilization QR Other Worker", 19)
            visit_ids: list[int] = []

            for index, mismatch in enumerate(("employee", "site", "time")):
                shift_start = first_start + timedelta(hours=index * 2)
                arrival = shift_start + timedelta(minutes=10)
                shift_id = _shift(
                    cur,
                    employee_id=worker,
                    start=shift_start,
                    end=shift_start + timedelta(hours=1),
                    service_day=service_day,
                    location_id=site_a,
                    location_label=f"{TEST_PREFIX} Site Utilization QR Identity A",
                    job_id=job_a,
                )
                check_in_id = _check_in(
                    cur,
                    employee_id=(
                        other_worker if mismatch == "employee" else worker
                    ),
                    location_id=site_b if mismatch == "site" else site_a,
                    checked_in_at=(
                        arrival + timedelta(minutes=1)
                        if mismatch == "time"
                        else arrival
                    ),
                    job_id=job_b if mismatch == "site" else job_a,
                )
                visit_id = _visit(
                    cur,
                    shift_id=shift_id,
                    location_id=site_a,
                    at=arrival,
                    suffix=f"Utilization QR Identity {mismatch}",
                    sequence_version=2,
                    site_check_in_id=check_in_id,
                )
                _departure(
                    cur,
                    shift_id=shift_id,
                    location_id=site_a,
                    at=shift_start + timedelta(minutes=50),
                    suffix=f"Utilization QR Identity {mismatch}",
                    visit_id=visit_id,
                )
                visit_ids.append(visit_id)

    body = _utilization_body(client, auth, service_day)
    _assert_utilization_totals(
        body["summary"],
        paid=180,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    row = _utilization_row(body, worker, service_day)
    _assert_utilization_totals(
        row,
        paid=180,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    assert {interval["category"] for interval in row["intervals"]} == {
        "unclassified"
    }
    assert {
        (item["code"], item["visitId"])
        for item in body["reviewItems"]
    } == {
        ("site_check_in_identity_mismatch", visit_id)
        for visit_id in visit_ids
    }


def test_utilization_missing_departures_and_active_visit_fail_closed(
    client,
    auth,
):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="Utilization Missing A",
                start=shift_start + timedelta(minutes=30),
                end=shift_start + timedelta(hours=2),
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="Utilization Missing B",
                start=shift_start + timedelta(hours=2),
                end=shift_start + timedelta(hours=3),
            )
            route_worker = _employee(cur, "Utilization Missing Route", 18)
            active_worker = _employee(cur, "Utilization Active At Clock Out", 20)
            route_shift = _shift(
                cur,
                employee_id=route_worker,
                start=shift_start,
                end=shift_start + timedelta(hours=4),
                service_day=service_day,
                location_id=site_a,
                location_label=f"{TEST_PREFIX} Site Utilization Missing A",
            )
            missing_check_in = _check_in(
                cur,
                employee_id=route_worker,
                location_id=site_a,
                checked_in_at=shift_start + timedelta(minutes=30),
                job_id=job_a,
            )
            missing_visit = _visit(
                cur,
                shift_id=route_shift,
                location_id=site_a,
                at=shift_start + timedelta(minutes=30),
                suffix="Utilization Missing A",
                sequence_version=2,
                site_check_in_id=missing_check_in,
            )
            route_visit_b, _ = _paired_version_two_visit(
                cur,
                employee_id=route_worker,
                shift_id=route_shift,
                location_id=site_b,
                job_id=job_b,
                arrival=shift_start + timedelta(hours=2),
                departure=shift_start + timedelta(hours=3),
                suffix="Utilization Missing B",
            )

            active_shift = _shift(
                cur,
                employee_id=active_worker,
                start=shift_start,
                end=shift_start + timedelta(hours=2),
                service_day=service_day,
                location_id=site_a,
                location_label=f"{TEST_PREFIX} Site Utilization Missing A",
            )
            active_check_in = _check_in(
                cur,
                employee_id=active_worker,
                location_id=site_a,
                checked_in_at=shift_start + timedelta(minutes=30),
                job_id=job_a,
            )
            active_visit = _visit(
                cur,
                shift_id=active_shift,
                location_id=site_a,
                at=shift_start + timedelta(minutes=30),
                suffix="Utilization Missing A",
                sequence_version=2,
                site_check_in_id=active_check_in,
            )

    body = _utilization_body(client, auth, service_day)
    _assert_utilization_totals(
        body["summary"],
        paid=360,
        on_site=60,
        travel=0,
        categorized=0,
        unclassified=300,
    )
    route_row = _utilization_row(body, route_worker, service_day)
    active_row = _utilization_row(body, active_worker, service_day)
    _assert_utilization_totals(
        route_row,
        paid=240,
        on_site=60,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    _assert_utilization_totals(
        active_row,
        paid=120,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=120,
    )
    _assert_interval_contract(route_row["intervals"])
    _assert_interval_contract(active_row["intervals"])

    assert not any(
        interval["category"] == "on_site"
        and interval["locationId"] == site_a
        for interval in route_row["intervals"]
    )
    assert not any(
        interval["category"] == "travel" for interval in route_row["intervals"]
    )
    assert [
        (interval["locationId"], interval["visitId"], interval["durationMinutes"])
        for interval in route_row["intervals"]
        if interval["category"] == "on_site"
    ] == [(site_b, route_visit_b, 60)]
    assert {
        interval["category"] for interval in active_row["intervals"]
    } == {"unclassified"}
    assert any(
        "missing_departure" in interval["reviewCodes"]
        for interval in route_row["intervals"]
    )
    assert any(
        "missing_departure" in interval["reviewCodes"]
        for interval in active_row["intervals"]
    )
    assert {
        (
            item["code"],
            item["employeeId"],
            item["date"],
            item["shiftId"],
            item["visitId"],
        )
        for item in body["reviewItems"]
    } == {
        (
            "missing_departure",
            route_worker,
            str(service_day),
            route_shift,
            missing_visit,
        ),
        (
            "missing_departure",
            active_worker,
            str(service_day),
            active_shift,
            active_visit,
        ),
    }


def test_utilization_legacy_overlap_and_open_shift_fail_closed(client, auth):
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            legacy_site, _ = _canonical_job(
                cur,
                suffix="Utilization Legacy",
                start=shift_start,
                end=shift_start + timedelta(hours=2),
            )
            overlap_site_a, overlap_job_a = _canonical_job(
                cur,
                suffix="Utilization Overlap A",
                start=shift_start + timedelta(hours=3),
                end=shift_start + timedelta(hours=5),
            )
            overlap_site_b, overlap_job_b = _canonical_job(
                cur,
                suffix="Utilization Overlap B",
                start=shift_start + timedelta(hours=4),
                end=shift_start + timedelta(hours=6),
            )
            legacy_worker = _employee(cur, "Utilization Legacy", 18)
            overlap_worker = _employee(cur, "Utilization Overlap", 19)
            open_worker = _employee(cur, "Utilization Open", 20)
            reversed_worker = _employee(cur, "Utilization Reversed", 21)

            legacy_shift = _shift(
                cur,
                employee_id=legacy_worker,
                start=shift_start,
                end=shift_start + timedelta(hours=2),
                service_day=service_day,
                location_id=legacy_site,
                location_label=f"{TEST_PREFIX} Site Utilization Legacy",
            )
            _visit(
                cur,
                shift_id=legacy_shift,
                location_id=legacy_site,
                at=shift_start + timedelta(minutes=30),
                suffix="Utilization Legacy",
            )
            _departure(
                cur,
                shift_id=legacy_shift,
                location_id=legacy_site,
                at=shift_start + timedelta(hours=1, minutes=30),
                suffix="Utilization Legacy",
            )

            overlap_shift = _shift(
                cur,
                employee_id=overlap_worker,
                start=shift_start + timedelta(hours=2, minutes=30),
                end=shift_start + timedelta(hours=6, minutes=30),
                service_day=service_day,
            )
            _paired_version_two_visit(
                cur,
                employee_id=overlap_worker,
                shift_id=overlap_shift,
                location_id=overlap_site_a,
                job_id=overlap_job_a,
                arrival=shift_start + timedelta(hours=3),
                departure=shift_start + timedelta(hours=5),
                suffix="Utilization Overlap A",
            )
            _paired_version_two_visit(
                cur,
                employee_id=overlap_worker,
                shift_id=overlap_shift,
                location_id=overlap_site_b,
                job_id=overlap_job_b,
                arrival=shift_start + timedelta(hours=4),
                departure=shift_start + timedelta(hours=6),
                suffix="Utilization Overlap B",
            )

            open_shift = _shift(
                cur,
                employee_id=open_worker,
                # 11:30 p.m. Chicago time on the prior date. The still-open
                # envelope overlaps this report after local midnight.
                start=datetime(2026, 7, 20, 4, 30, tzinfo=timezone.utc),
                end=None,
                service_day=service_day - timedelta(days=1),
            )
            reversed_shift = _shift(
                cur,
                employee_id=reversed_worker,
                start=shift_start + timedelta(hours=10),
                end=shift_start + timedelta(hours=9),
                service_day=service_day,
            )

    body = _utilization_body(client, auth, service_day)
    _assert_utilization_totals(
        body["summary"],
        paid=360,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=360,
    )
    assert body["summary"]["finalizedShiftCount"] == 3
    assert body["summary"]["openShiftCount"] == 1
    assert body["summary"]["reviewItemCount"] == 6

    legacy_row = _utilization_row(body, legacy_worker, service_day)
    overlap_row = _utilization_row(body, overlap_worker, service_day)
    _assert_utilization_totals(
        legacy_row,
        paid=120,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=120,
    )
    _assert_utilization_totals(
        overlap_row,
        paid=240,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=240,
    )
    assert not any(row["employeeId"] == open_worker for row in body["rows"])
    assert not any(row["employeeId"] == reversed_worker for row in body["rows"])

    review_codes = [item["code"] for item in body["reviewItems"]]
    assert review_codes.count("legacy_visit_evidence") == 1
    assert review_codes.count("legacy_unpaired_departure") == 1
    assert review_codes.count("overlapping_site_evidence") == 2
    assert review_codes.count("open_shift") == 1
    assert review_codes.count("invalid_paid_interval") == 1
    assert any(
        item["code"] == "open_shift"
        and item["shiftId"] == open_shift
        and item["employeeId"] == open_worker
        and item["date"] == str(service_day - timedelta(days=1))
        for item in body["reviewItems"]
    )
    assert any(
        item["code"] == "invalid_paid_interval"
        and item["shiftId"] == reversed_shift
        and item["employeeId"] == reversed_worker
        for item in body["reviewItems"]
    )
    future_body = _utilization_body(
        client,
        auth,
        date(2099, 1, 1),
    )
    assert not any(
        item["shiftId"] == open_shift for item in future_body["reviewItems"]
    )
    assert {
        interval["category"]
        for row in (legacy_row, overlap_row)
        for interval in row["intervals"]
    } == {"unclassified"}


def test_utilization_splits_paid_and_site_intervals_at_local_midnight(
    client,
    auth,
):
    app_timezone = ZoneInfo("America/Chicago")
    first_day = date(2026, 7, 20)
    second_day = first_day + timedelta(days=1)
    local_start = datetime(2026, 7, 20, 23, 30, tzinfo=app_timezone)
    local_arrival = datetime(2026, 7, 20, 23, 45, tzinfo=app_timezone)
    local_departure = datetime(2026, 7, 21, 0, 45, tzinfo=app_timezone)
    local_end = datetime(2026, 7, 21, 1, 30, tzinfo=app_timezone)
    shift_start = local_start.astimezone(timezone.utc)
    arrival = local_arrival.astimezone(timezone.utc)
    departure = local_departure.astimezone(timezone.utc)
    shift_end = local_end.astimezone(timezone.utc)
    local_midnight_utc = datetime(
        2026,
        7,
        21,
        tzinfo=app_timezone,
    ).astimezone(timezone.utc)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_id, job_id = _canonical_job(
                cur,
                suffix="Utilization Midnight",
                start=arrival,
                end=departure,
                site_type="Commercial",
            )
            employee_id = _employee(cur, "Utilization Midnight", 19)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=first_day,
                location_id=site_id,
                location_label=f"{TEST_PREFIX} Site Utilization Midnight",
            )
            visit_id, departure_id = _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=shift_id,
                location_id=site_id,
                job_id=job_id,
                arrival=arrival,
                departure=departure,
                suffix="Utilization Midnight",
            )

    body = _utilization_body(client, auth, first_day, second_day)
    _assert_utilization_totals(
        body["summary"],
        paid=120,
        on_site=60,
        travel=0,
        categorized=0,
        unclassified=60,
    )
    first_row = _utilization_row(body, employee_id, first_day)
    second_row = _utilization_row(body, employee_id, second_day)
    _assert_utilization_totals(
        first_row,
        paid=30,
        on_site=15,
        travel=0,
        categorized=0,
        unclassified=15,
    )
    _assert_utilization_totals(
        second_row,
        paid=90,
        on_site=45,
        travel=0,
        categorized=0,
        unclassified=45,
    )
    _assert_interval_contract(first_row["intervals"])
    _assert_interval_contract(second_row["intervals"])
    assert [
        (interval["category"], interval["durationMinutes"])
        for interval in first_row["intervals"]
    ] == [("unclassified", 15), ("on_site", 15)]
    assert [
        (interval["category"], interval["durationMinutes"])
        for interval in second_row["intervals"]
    ] == [("on_site", 45), ("unclassified", 45)]
    assert first_row["intervals"][-1]["intervalEnd"] == (
        local_midnight_utc.isoformat().replace("+00:00", "Z")
    )
    assert second_row["intervals"][0]["intervalStart"] == (
        local_midnight_utc.isoformat().replace("+00:00", "Z")
    )
    split_site_intervals = [
        interval
        for row in (first_row, second_row)
        for interval in row["intervals"]
        if interval["category"] == "on_site"
    ]
    assert {
        (
            interval["locationId"],
            interval["jobId"],
            interval["visitId"],
            interval["departureId"],
        )
        for interval in split_site_intervals
    } == {(site_id, job_id, visit_id, departure_id)}


@pytest.mark.parametrize(
    ("local_start", "local_end"),
    [
        (
            datetime(2026, 3, 8, 0, 30, tzinfo=ZoneInfo("America/Chicago")),
            datetime(2026, 3, 8, 4, 30, tzinfo=ZoneInfo("America/Chicago")),
        ),
        (
            datetime(2026, 11, 1, 0, 30, tzinfo=ZoneInfo("America/Chicago")),
            datetime(2026, 11, 1, 2, 30, tzinfo=ZoneInfo("America/Chicago")),
        ),
    ],
)
def test_utilization_uses_elapsed_time_across_dst_transitions(
    client,
    auth,
    local_start,
    local_end,
):
    service_day = local_start.date()
    shift_start = local_start.astimezone(timezone.utc)
    shift_end = local_end.astimezone(timezone.utc)
    assert shift_end - shift_start == timedelta(hours=3)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            employee_id = _employee(
                cur,
                f"Utilization DST {service_day.isoformat()}",
                18,
            )
            _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_end,
                service_day=service_day,
            )

    body = _utilization_body(client, auth, service_day)
    _assert_utilization_totals(
        body["summary"],
        paid=180,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    row = _utilization_row(body, employee_id, service_day)
    _assert_utilization_totals(
        row,
        paid=180,
        on_site=0,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    _assert_interval_contract(row["intervals"])
    assert [
        (
            interval["category"],
            interval["durationSeconds"],
            interval["durationMinutes"],
        )
        for interval in row["intervals"]
    ] == [("unclassified", 3 * 60 * 60, 180)]


def _seed_missing_departure_correction_route() -> dict:
    service_day = date(2026, 7, 20)
    shift_start = datetime(2026, 7, 20, 13, tzinfo=timezone.utc)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            site_a, job_a = _canonical_job(
                cur,
                suffix="Utilization Correction A",
                start=shift_start + timedelta(minutes=30),
                end=shift_start + timedelta(hours=1, minutes=30),
            )
            site_b, job_b = _canonical_job(
                cur,
                suffix="Utilization Correction B",
                start=shift_start + timedelta(hours=2),
                end=shift_start + timedelta(hours=3),
            )
            employee_id = _employee(cur, "Utilization Correction", 18)
            shift_id = _shift(
                cur,
                employee_id=employee_id,
                start=shift_start,
                end=shift_start + timedelta(hours=4),
                service_day=service_day,
                location_id=site_a,
                location_label=f"{TEST_PREFIX} Site Utilization Correction A",
            )
            check_in_a = _check_in(
                cur,
                employee_id=employee_id,
                location_id=site_a,
                checked_in_at=shift_start + timedelta(minutes=30),
                job_id=job_a,
            )
            visit_a = _visit(
                cur,
                shift_id=shift_id,
                location_id=site_a,
                at=shift_start + timedelta(minutes=30),
                suffix="Utilization Correction A",
                sequence_version=2,
                site_check_in_id=check_in_a,
            )
            visit_b, departure_b = _paired_version_two_visit(
                cur,
                employee_id=employee_id,
                shift_id=shift_id,
                location_id=site_b,
                job_id=job_b,
                arrival=shift_start + timedelta(hours=2),
                departure=shift_start + timedelta(hours=3),
                suffix="Utilization Correction B",
            )
            cur.execute(
                """
                INSERT INTO site_qr_action_receipts (
                    employee_id, location_id, shift_id, action,
                    idempotency_key, request_fingerprint,
                    server_recorded_at, device_scanned_at,
                    latitude, longitude, accuracy_m, geofence_radius_m,
                    distance_m, geofence_status, outcome,
                    site_check_in_id, visit_id, response_body
                )
                VALUES (
                    %s, %s, %s, 'arrive', %s, %s, %s, %s,
                    39.12, -88.54, 5, 100, 3, 'inside', 'recorded',
                    %s, %s, '{"action":"arrive","outcome":"recorded"}'::jsonb
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site_a,
                    shift_id,
                    str(uuid4()),
                    hashlib.sha256(
                        f"correction-arrive:{shift_id}:{visit_a}".encode()
                    ).hexdigest(),
                    shift_start + timedelta(minutes=30),
                    shift_start + timedelta(minutes=30),
                    check_in_a,
                    visit_a,
                ),
            )
            receipt_id = int(cur.fetchone()[0])
    return {
        "serviceDay": service_day,
        "shiftStart": shift_start,
        "employeeId": employee_id,
        "shiftId": shift_id,
        "siteA": site_a,
        "siteB": site_b,
        "visitA": visit_a,
        "visitB": visit_b,
        "departureB": departure_b,
        "checkInA": check_in_a,
        "receiptId": receipt_id,
    }


def _raw_correction_evidence_snapshot(seed: dict) -> dict:
    return {
        "shifts": db.query_all(
            "SELECT * FROM shifts WHERE id = %s",
            (seed["shiftId"],),
        ),
        "visits": db.query_all(
            "SELECT * FROM visits WHERE shift_id = %s ORDER BY id",
            (seed["shiftId"],),
        ),
        "departures": db.query_all(
            "SELECT * FROM departures WHERE shift_id = %s ORDER BY id",
            (seed["shiftId"],),
        ),
        "siteCheckIns": db.query_all(
            """
            SELECT *
            FROM site_check_ins
            WHERE employee_id = %s
              AND server_checked_in_at >= %s
              AND server_checked_in_at < %s
            ORDER BY id
            """,
            (
                seed["employeeId"],
                seed["shiftStart"],
                seed["shiftStart"] + timedelta(hours=4),
            ),
        ),
        "qrReceipts": db.query_all(
            "SELECT * FROM site_qr_action_receipts WHERE id = %s",
            (seed["receiptId"],),
        ),
    }


def test_missing_departure_correction_is_audited_idempotent_and_non_destructive(
    client,
    auth,
):
    seed = _seed_missing_departure_correction_route()
    before = _raw_correction_evidence_snapshot(seed)
    initial = _utilization_body(client, auth, seed["serviceDay"])
    _assert_utilization_totals(
        initial["summary"],
        paid=240,
        on_site=60,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    review = next(
        item
        for item in initial["reviewItems"]
        if item["code"] == "missing_departure"
        and item["visitId"] == seed["visitA"]
    )
    assert re.fullmatch(r"[0-9a-f]{64}", review["reviewKey"])
    assert re.fullmatch(r"[0-9a-f]{64}", review["evidenceFingerprint"])
    assert review["reviewState"] == "open"
    assert review["hasOpenReview"] is True
    assert review["canCorrect"] is True
    assert review["correction"] is None

    idempotency_key = str(uuid4())
    payload = {
        "shiftId": seed["shiftId"],
        "visitId": seed["visitA"],
        "evidenceFingerprint": review["evidenceFingerprint"],
        # datetime-local values in the portal are explicitly Central Time.
        "effectiveDepartureAt": "2026-07-20T09:30",
        "reason": "Verified departure from supervisor time notes",
        "idempotencyKey": idempotency_key,
    }
    applied = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json=payload,
    )
    assert applied.status_code == 200, applied.text
    applied_body = applied.json()
    assert applied_body["idempotentReplay"] is False
    assert applied_body["reviewStateAtApply"] == "corrected"
    assert "reviewState" not in applied_body
    batch_id = applied_body["batchId"]
    assert _raw_correction_evidence_snapshot(seed) == before

    corrected = _utilization_body(client, auth, seed["serviceDay"])
    _assert_utilization_totals(
        corrected["summary"],
        paid=240,
        on_site=120,
        travel=30,
        categorized=0,
        unclassified=90,
    )
    corrected_review = next(
        item
        for item in corrected["reviewItems"]
        if item["reviewKey"] == review["reviewKey"]
    )
    assert corrected_review["reviewState"] == "corrected"
    assert corrected_review["hasOpenReview"] is False
    assert corrected_review["correction"]["batchId"] == batch_id
    assert corrected["summary"]["openReviewItemCount"] == 0
    assert corrected["summary"]["correctedReviewItemCount"] == 1
    corrected_row = _utilization_row(
        corrected,
        seed["employeeId"],
        seed["serviceDay"],
    )
    reviewed_intervals = [
        interval
        for interval in corrected_row["intervals"]
        if interval["correctionId"] == batch_id
    ]
    assert {interval["category"] for interval in reviewed_intervals} == {
        "on_site",
        "travel",
    }
    assert all(
        "reviewed_departure" in interval["evidence"]
        for interval in reviewed_intervals
    )

    batch = db.query_one(
        """
        SELECT applied_by_employee_id, applied_by_name, reason, snapshot, result
        FROM time_data_correction_batches
        WHERE id = %s
        """,
        (batch_id,),
    )
    assert batch["applied_by_employee_id"] is not None
    assert batch["applied_by_name"]
    assert batch["reason"] == payload["reason"]
    assert batch["snapshot"]["reviewKey"] == review["reviewKey"]
    assert (
        batch["snapshot"]["evidenceFingerprint"]
        == review["evidenceFingerprint"]
    )
    assert batch["snapshot"]["evidence"]["shifts"]
    assert batch["result"]["visitId"] == seed["visitA"]
    assert batch["result"]["evidence"] == ["reviewed_departure"]

    repeated = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json=payload,
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["idempotentReplay"] is True
    assert repeated.json()["batchId"] == batch_id
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM time_data_correction_batches
        WHERE snapshot ->> 'reviewKey' = %s
        """,
        (review["reviewKey"],),
    )["count"] == 1

    changed_reuse = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={
            **payload,
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert changed_reuse.status_code == 409

    amended = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={
            **payload,
            "idempotencyKey": str(uuid4()),
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(hours=1, minutes=15)
            ).isoformat().replace("+00:00", "Z"),
            "reason": "Supervisor clarified the reviewed departure time",
        },
    )
    assert amended.status_code == 200, amended.text
    assert amended.json()["batchId"] != batch_id
    amended_body = _utilization_body(client, auth, seed["serviceDay"])
    amended_review = next(
        item
        for item in amended_body["reviewItems"]
        if item["reviewKey"] == review["reviewKey"]
    )
    assert amended_review["correction"]["batchId"] == amended.json()["batchId"]
    _assert_utilization_totals(
        amended_body["summary"],
        paid=240,
        on_site=105,
        travel=45,
        categorized=0,
        unclassified=90,
    )
    assert _raw_correction_evidence_snapshot(seed) == before

    db.execute(
        "UPDATE visits SET location_label = location_label || ' updated' WHERE id = %s",
        (seed["visitA"],),
    )
    reopened = _utilization_body(client, auth, seed["serviceDay"])
    reopened_review = next(
        item
        for item in reopened["reviewItems"]
        if item["reviewKey"] == review["reviewKey"]
    )
    assert reopened_review["reviewState"] == "reopened"
    assert reopened_review["hasOpenReview"] is True
    assert reopened_review["evidenceFingerprint"] != review["evidenceFingerprint"]
    assert (
        reopened_review["previousCorrection"]["batchId"]
        == amended.json()["batchId"]
    )
    assert reopened_review["correctionHistoryCount"] == 2
    _assert_utilization_totals(
        reopened["summary"],
        paid=240,
        on_site=60,
        travel=0,
        categorized=0,
        unclassified=180,
    )
    stale = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={**payload, "idempotencyKey": str(uuid4())},
    )
    assert stale.status_code == 409

    historical_replay = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json=payload,
    )
    assert historical_replay.status_code == 200, historical_replay.text
    assert historical_replay.json()["idempotentReplay"] is True
    assert historical_replay.json()["batchId"] == batch_id
    assert historical_replay.json()["reviewStateAtApply"] == "corrected"
    assert "reviewState" not in historical_replay.json()
    still_reopened = _utilization_body(client, auth, seed["serviceDay"])
    still_reopened_review = next(
        item
        for item in still_reopened["reviewItems"]
        if item["reviewKey"] == review["reviewKey"]
    )
    assert still_reopened_review["reviewState"] == "reopened"


def test_missing_departure_correction_rejects_unauthorized_and_conflicting_time(
    client,
    auth,
    emp_auth,
):
    seed = _seed_missing_departure_correction_route()
    initial = _utilization_body(client, auth, seed["serviceDay"])
    review = next(
        item
        for item in initial["reviewItems"]
        if item["code"] == "missing_departure"
        and item["visitId"] == seed["visitA"]
    )
    base_payload = {
        "shiftId": seed["shiftId"],
        "visitId": seed["visitA"],
        "evidenceFingerprint": review["evidenceFingerprint"],
        "reason": "Verified against the supervisor route notes",
        "idempotencyKey": str(uuid4()),
    }
    unauthenticated = client.post(
        f"/api{review['correctionPath']}",
        json={
            **base_payload,
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    employee = client.post(
        f"/api{review['correctionPath']}",
        headers=emp_auth,
        json={
            **base_payload,
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert unauthenticated.status_code == 401
    assert employee.status_code == 403

    future = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={
            **base_payload,
            "idempotencyKey": str(uuid4()),
            "effectiveDepartureAt": (
                datetime.now(timezone.utc).replace(microsecond=0)
                + timedelta(days=1)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert future.status_code == 400
    assert future.json()["error"] == "Reviewed departure cannot be in the future"

    before_arrival = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={
            **base_payload,
            "idempotencyKey": str(uuid4()),
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(minutes=15)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert before_arrival.status_code == 400
    conflicting = client.post(
        f"/api{review['correctionPath']}",
        headers=auth,
        json={
            **base_payload,
            "idempotencyKey": str(uuid4()),
            "effectiveDepartureAt": (
                seed["shiftStart"] + timedelta(hours=2, minutes=30)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert conflicting.status_code == 409
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM time_data_correction_batches
        WHERE snapshot ->> 'reviewKey' = %s
        """,
        (review["reviewKey"],),
    )["count"] == 0


def test_utilization_rejects_reversed_range(client, auth):
    response = client.get(
        "/api/admin/operations/utilization",
        headers=auth,
        params={"start_date": "2026-07-21", "end_date": "2026-07-20"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "end_date must be on or after start_date"


def test_utilization_requires_admin(client, emp_auth):
    params = {"start_date": "2026-07-20", "end_date": "2026-07-20"}
    missing = client.get("/api/admin/operations/utilization", params=params)
    employee = client.get(
        "/api/admin/operations/utilization",
        headers=emp_auth,
        params=params,
    )
    assert missing.status_code == 401
    assert employee.status_code == 403


def test_operations_routes_require_admin(client, emp_auth):
    schedule = client.get("/api/admin/operations/schedule", headers=emp_auth)
    forecast = client.get("/api/admin/operations/forecast", headers=emp_auth)
    assert schedule.status_code == 403
    assert forecast.status_code == 403


def test_operations_forecast_builder_allows_future_legacy_one_week_seam(
    monkeypatch,
):
    fixed_now = datetime(2026, 7, 27, 15, tzinfo=timezone.utc)
    monkeypatch.setattr(ops, "_load_jobs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ops.db, "query_all", lambda *_args, **_kwargs: [])

    body = ops.build_operations_forecast(
        1,
        timezone_name="America/Chicago",
        now_provider=lambda: fixed_now,
    )

    assert body["success"] is True
    assert body["weeksAhead"] == 1
    assert body["asOfDate"] == "2026-07-27"
    assert body["startDate"] == "2026-07-27"
    assert body["endDate"] == "2026-08-01"
    assert [week["weekStart"] for week in body["weeks"]] == ["2026-07-26"]
    assert body["forecasts"] == body["weeks"]
    assert {issue["code"] for issue in body["issues"]} == {
        "missing_average_employee_rate"
    }


def test_operations_forecast_route_keeps_allowed_horizon_gate(
    client,
    auth,
    monkeypatch,
):
    calls: list[int] = []

    def fake_builder(weeks_ahead, *, timezone_name, now_provider):
        calls.append(weeks_ahead)
        assert timezone_name == "America/Chicago"
        assert now_provider().tzinfo is not None
        return {
            "success": True,
            "weeksAhead": weeks_ahead,
            "weeks": [],
            "forecasts": [],
        }

    monkeypatch.setattr(ops, "build_operations_forecast", fake_builder)

    allowed = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 8},
    )
    rejected = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 1},
    )

    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["weeksAhead"] == 8
    assert calls == [8]
    assert rejected.status_code == 400
    assert rejected.json()["error"] == "weeks_ahead must be one of: 4, 8, 12"
    assert calls == [8]


def test_forecast_rejects_unsupported_horizon(client, auth):
    response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 6},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "weeks_ahead must be one of: 4, 8, 12"
