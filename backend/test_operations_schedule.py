from __future__ import annotations

import hashlib
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest

import db
from operations_schedule import (
    _closed_shift_segments,
    _forecast_job_values,
    _job_issues,
    _match_segment_to_job,
    _qr_only_presence_segments,
    _schedule_execution_status,
    allocate_monthly_cents,
)


TEST_PREFIX = "OPS_CANONICAL_TEST"


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
) -> int:
    total_hours = (
        round((end - start).total_seconds() / 3600, 2) if end is not None else None
    )
    cur.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, job_id,
            clock_in, clock_out, total_hours, local_date,
            timezone, time_category
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s,
            'America/Chicago', %s
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
) -> None:
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
            location_id,
            job_id,
            checked_in_at,
            checked_in_at,
            classification,
            review_status,
        ),
    )


def _visit(
    cur,
    *,
    shift_id: int,
    location_id: int,
    at: datetime,
    suffix: str,
) -> None:
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
            location_id,
            f"{TEST_PREFIX} Site {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            at,
        ),
    )


def _departure(
    cur,
    *,
    shift_id: int,
    location_id: int,
    at: datetime,
    suffix: str,
) -> None:
    cur.execute(
        """
        INSERT INTO departures (
            shift_id, location_id, location_label, customer_name,
            departure_time
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            shift_id,
            location_id,
            f"{TEST_PREFIX} Site {suffix}",
            f"{TEST_PREFIX} Customer {suffix}",
            at,
        ),
    )


def _schedule_body(client, auth, service_day: date) -> dict:
    response = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={"start_date": str(service_day), "end_date": str(service_day)},
    )
    assert response.status_code == 200, response.text
    return response.json()


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


def test_monthly_allocation_is_exact_and_stable():
    assert allocate_monthly_cents(10_000, [7, 9, 11]) == {
        7: 3334,
        9: 3333,
        11: 3333,
    }
    assert sum(allocate_monthly_cents(10_001, [1, 2, 3, 4]).values()) == 10_001
    assert allocate_monthly_cents(10_000, []) == {}


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
    jobs = {job["jobId"]: job for week in body["weeks"] for job in week["jobs"]}
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
    assert {issue["code"] for issue in incomplete["issues"]} >= {
        "missing_expected_hours"
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


def test_operations_routes_require_admin(client, emp_auth):
    schedule = client.get("/api/admin/operations/schedule", headers=emp_auth)
    forecast = client.get("/api/admin/operations/forecast", headers=emp_auth)
    assert schedule.status_code == 403
    assert forecast.status_code == 403


def test_forecast_rejects_unsupported_horizon(client, auth):
    response = client.get(
        "/api/admin/operations/forecast",
        headers=auth,
        params={"weeks_ahead": 6},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "weeks_ahead must be one of: 4, 8, 12"
