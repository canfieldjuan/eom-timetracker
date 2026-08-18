"""Arrival-policy revision, precedence, boundary, and snapshot contracts."""

from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

import psycopg2
import pytest

import arrival_policies
import db
import time_tracker_api
from arrival_policy_inventory import (
    build_cutover_readiness,
    build_inventory,
    validate_owner_mapping,
)
from conftest import _raw_conn
from test_site_check_in import (
    CANONICAL_TEST_PREFIX,
    create_arrival_schedule,
    create_canonical_job,
    create_recurring_schedule_rule,
    create_site_qr,
    site_check_in_payload,
)


@pytest.fixture(autouse=True)
def isolate_arrival_policy_data(setup_db):
    def clean() -> None:
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM arrival_policy_revisions")
            cur.execute("DELETE FROM site_check_in_schedule_rules")
            cur.execute("DELETE FROM site_check_in_schedules")
            cur.execute(
                "DELETE FROM jobs WHERE source_calendar_id LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_sources WHERE calendar_id LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM google_calendar_connections "
                "WHERE google_account_email LIKE %s",
                (f"{CANONICAL_TEST_PREFIX}%",),
            )
            cur.execute(
                """
                UPDATE locations
                SET check_in_token_nonce = NULL,
                    check_in_token_rotated_at = NULL,
                    location_type = CASE
                        WHEN address = '123 Main St, Effingham' THEN NULL
                        ELSE location_type
                    END,
                    lat = CASE
                        WHEN address = '123 Main St, Effingham' THEN 39.1203
                        ELSE lat
                    END,
                    lng = CASE
                        WHEN address = '123 Main St, Effingham' THEN -88.54335
                        ELSE lng
                    END
                """
            )
        conn.commit()
        conn.close()

    clean()
    yield
    clean()


def policy_row(
    *,
    mode: str,
    fixed_arrival: time | None = None,
    grace_minutes: int | None = None,
    window_start: time | None = None,
    window_end: time | None = None,
    not_before: time | None = None,
) -> dict:
    return {
        "id": 41,
        "scope_type": "site",
        "site_id": 7,
        "job_id": None,
        "version": 2,
        "state": "active",
        "mode": mode,
        "timezone": "America/Chicago",
        "fixed_arrival": fixed_arrival,
        "grace_minutes": grace_minutes,
        "window_start": window_start,
        "window_end": window_end,
        "not_before": not_before,
        "update_token": "a" * 64,
        "change_note": "Owner-reviewed test policy",
        "created_by": 1,
        "created_by_name": "Test Admin",
        "created_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }


def evaluate(row: dict, checked_in_at: datetime, *, job_site_id: int = 7):
    return arrival_policies.evaluate_policy(
        row,
        site_id=7,
        job={
            "id": 91,
            "location_id": job_site_id,
            "scheduled_start": datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
        },
        checked_in_at=checked_in_at,
    )


@pytest.mark.parametrize(
    ("checked_in_at", "classification", "reason"),
    [
        (
            datetime(2026, 7, 20, 12, 10, tzinfo=timezone.utc),
            "on_time",
            "within_arrival_policy_grace",
        ),
        (
            datetime(2026, 7, 20, 12, 10, 0, 1, tzinfo=timezone.utc),
            "late",
            "after_arrival_policy_grace",
        ),
    ],
)
def test_fixed_policy_grace_boundary(checked_in_at, classification, reason):
    result = evaluate(
        policy_row(
            mode="fixed",
            fixed_arrival=time(7, 0),
            grace_minutes=10,
        ),
        checked_in_at,
    )
    assert result[:3] == (classification, reason, "not_required")


@pytest.mark.parametrize(
    ("checked_in_at", "classification", "reason", "review_status"),
    [
        (
            datetime(2026, 7, 20, 12, 59, 59, tzinfo=timezone.utc),
            "needs_review",
            "before_arrival_window",
            "pending",
        ),
        (
            datetime(2026, 7, 20, 13, 0, tzinfo=timezone.utc),
            "on_time",
            "within_arrival_window",
            "not_required",
        ),
        (
            datetime(2026, 7, 20, 14, 0, tzinfo=timezone.utc),
            "on_time",
            "within_arrival_window",
            "not_required",
        ),
        (
            datetime(2026, 7, 20, 14, 0, 0, 1, tzinfo=timezone.utc),
            "late",
            "after_arrival_window",
            "not_required",
        ),
    ],
)
def test_window_policy_boundaries(
    checked_in_at,
    classification,
    reason,
    review_status,
):
    result = evaluate(
        policy_row(
            mode="window",
            window_start=time(8, 0),
            window_end=time(9, 0),
        ),
        checked_in_at,
    )
    assert result[:3] == (classification, reason, review_status)


def test_overnight_window_ends_on_the_following_local_day():
    result = evaluate(
        policy_row(
            mode="window",
            window_start=time(22, 0),
            window_end=time(2, 0),
        ),
        datetime(2026, 7, 21, 6, 30, tzinfo=timezone.utc),
    )
    assert result[:3] == ("on_time", "within_arrival_window", "not_required")


def test_flexible_not_before_and_site_mismatch_contracts():
    flexible = evaluate(
        policy_row(mode="flexible"),
        datetime(2026, 7, 20, 16, 0, tzinfo=timezone.utc),
    )
    assert flexible[:3] == ("on_time", "flexible_arrival_policy", "not_required")

    not_before = policy_row(mode="not_before", not_before=time(7, 0))
    early = evaluate(
        not_before,
        datetime(2026, 7, 20, 11, 59, 59, tzinfo=timezone.utc),
    )
    boundary = evaluate(
        not_before,
        datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
    )
    assert early[:3] == ("needs_review", "before_not_before_policy", "pending")
    assert boundary[:3] == (
        "on_time",
        "not_before_policy_satisfied",
        "not_required",
    )

    mismatch = evaluate(
        policy_row(mode="flexible"),
        datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
        job_site_id=8,
    )
    assert mismatch[:3] == (
        "needs_review",
        "arrival_policy_site_mismatch",
        "pending",
    )


def test_dst_gap_and_fold_fail_closed():
    gap, gap_reason = arrival_policies.resolve_wall_time(
        date(2026, 3, 8),
        time(2, 30),
        "America/Chicago",
    )
    fold, fold_reason = arrival_policies.resolve_wall_time(
        date(2026, 11, 1),
        time(1, 30),
        "America/Chicago",
    )
    assert gap is None
    assert gap_reason == "invalid_policy_local_time"
    assert fold is None
    assert fold_reason == "ambiguous_policy_local_time"


@pytest.mark.parametrize(
    ("fixed_arrival", "message"),
    [
        (time(7, 0, 1), "fixed_arrival must use HH:MM precision"),
        (
            time(7, 0, tzinfo=timezone.utc),
            "fixed_arrival must not include a timezone",
        ),
    ],
)
def test_shared_policy_validator_enforces_canonical_wall_times(
    fixed_arrival,
    message,
):
    with pytest.raises(ValueError, match=message):
        arrival_policies.validate_policy_values(
            mode="fixed",
            timezone_name="America/Chicago",
            fixed_arrival=fixed_arrival,
            grace_minutes=10,
            window_start=None,
            window_end=None,
            not_before=None,
        )


def test_admin_revision_api_requires_tokens_notes_and_preserves_history(
    client,
    auth,
    emp_auth,
    location_id,
):
    fixed = {
        "mode": "fixed",
        "timezone": "America/Chicago",
        "fixedArrival": "07:00",
        "graceMinutes": 10,
        "changeNote": "Initial owner-reviewed Site policy",
    }
    assert client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=emp_auth,
        json=fixed,
    ).status_code == 403
    created = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json=fixed,
    )
    assert created.status_code == 200, created.text
    first = created.json()["policy"]
    assert first["version"] == 1
    assert first["state"] == "active"

    missing_token = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Reviewed switch to flexible",
        },
    )
    assert missing_token.status_code == 409
    stale = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "expectedUpdateToken": "0" * 64,
            "changeNote": "Reviewed switch to flexible",
        },
    )
    assert stale.status_code == 409
    updated = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "expectedUpdateToken": first["updateToken"],
            "changeNote": "Reviewed switch to flexible",
        },
    )
    assert updated.status_code == 200, updated.text
    second = updated.json()["policy"]
    assert second["version"] == 2
    assert [row["version"] for row in updated.json()["history"]] == [2, 1]

    retired = client.post(
        f"/api/admin/locations/{location_id}/arrival-policy/retire",
        headers=auth,
        json={
            "expectedUpdateToken": second["updateToken"],
            "changeNote": "Retired after owner review",
        },
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["policy"] is None
    assert retired.json()["currentRevision"]["state"] == "retired"
    assert [row["version"] for row in retired.json()["history"]] == [3, 2, 1]


def test_appointment_policy_put_requires_canonical_job_but_history_can_retire(
    client,
    auth,
    location_id,
):
    manual_job_id = int(
        db.query_one(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date, scheduled_start,
                scheduled_end, status, source_calendar_id, notes
            ) VALUES (
                %s, 'Manual policy target', '2026-07-20',
                '2026-07-20T12:00:00Z', '2026-07-20T14:00:00Z',
                'scheduled', %s, 'arrival-policy-noncanonical-test'
            )
            RETURNING id
            """,
            (location_id, f"{CANONICAL_TEST_PREFIX}-manual-policy-target"),
        )["id"]
    )
    rejected = client.put(
        f"/api/admin/jobs/{manual_job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Manual jobs are not canonical policy targets",
        },
    )
    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["code"] == "arrival_policy_job_not_canonical"

    canonical_job_id = create_canonical_job(
        location_id,
        datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
        suffix="policy-history-after-source-removal",
    )
    created = client.put(
        f"/api/admin/jobs/{canonical_job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Reviewed canonical appointment policy",
        },
    )
    assert created.status_code == 200, created.text
    first = created.json()["policy"]
    db.execute(
        "UPDATE jobs SET calendar_source_id = NULL WHERE id = %s",
        (canonical_job_id,),
    )

    historical = client.get(
        f"/api/admin/jobs/{canonical_job_id}/arrival-policy",
        headers=auth,
    )
    assert historical.status_code == 200, historical.text
    assert historical.json()["policy"]["id"] == first["id"]
    blocked_update = client.put(
        f"/api/admin/jobs/{canonical_job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "expectedUpdateToken": first["updateToken"],
            "changeNote": "This target is no longer canonical",
        },
    )
    assert blocked_update.status_code == 409, blocked_update.text
    retired = client.post(
        f"/api/admin/jobs/{canonical_job_id}/arrival-policy/retire",
        headers=auth,
        json={
            "expectedUpdateToken": first["updateToken"],
            "changeNote": "Retire history after canonical source removal",
        },
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["currentRevision"]["state"] == "retired"


def test_policy_mutation_responses_are_anchored_before_a_later_write(
    client,
    auth,
    location_id,
    monkeypatch,
):
    import time_tracker_api

    created = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "changeNote": "Initial policy before response race",
        },
    )
    assert created.status_code == 200, created.text
    trigger_action = {"value": "ARRIVAL_POLICY_SAVED"}

    def inject_later_revision(_request, action, _allowed, _reason=""):
        if action != trigger_action["value"]:
            return
        trigger_action["value"] = ""
        current = db.query_one(
            """
            SELECT version
            FROM arrival_policy_revisions
            WHERE scope_type = 'site' AND site_id = %s
            ORDER BY version DESC, id DESC
            LIMIT 1
            """,
            (location_id,),
        )
        version = int(current["version"]) + 1
        created_at = datetime.now(timezone.utc)
        db.execute(
            """
            INSERT INTO arrival_policy_revisions (
                scope_type, site_id, job_id, version, state, mode, timezone,
                update_token, change_note, created_by_name, created_at
            ) VALUES (
                'site', %s, NULL, %s, 'active', 'flexible',
                'America/Chicago', %s, 'Concurrent later write',
                'Concurrent Admin', %s
            )
            """,
            (
                location_id,
                version,
                arrival_policies.policy_update_token(
                    "site",
                    location_id,
                    None,
                    version,
                    created_at,
                ),
                created_at,
            ),
        )

    monkeypatch.setattr(time_tracker_api, "append_access_log", inject_later_revision)
    updated = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "expectedUpdateToken": created.json()["policy"]["updateToken"],
            "changeNote": "Response must remain anchored to this revision",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["currentRevision"]["version"] == 2
    assert [row["version"] for row in updated.json()["history"]] == [2, 1]
    latest = db.query_one(
        """
        SELECT version, update_token
        FROM arrival_policy_revisions
        WHERE scope_type = 'site' AND site_id = %s
        ORDER BY version DESC, id DESC
        LIMIT 1
        """,
        (location_id,),
    )
    assert int(latest["version"]) == 3

    trigger_action["value"] = "ARRIVAL_POLICY_RETIRED"
    retired = client.post(
        f"/api/admin/locations/{location_id}/arrival-policy/retire",
        headers=auth,
        json={
            "expectedUpdateToken": latest["update_token"],
            "changeNote": "Retirement response must remain anchored",
        },
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["policy"] is None
    assert retired.json()["currentRevision"]["version"] == 4
    assert retired.json()["currentRevision"]["state"] == "retired"
    assert [row["version"] for row in retired.json()["history"]] == [4, 3, 2, 1]
    assert int(
        db.query_one(
            """
            SELECT version
            FROM arrival_policy_revisions
            WHERE scope_type = 'site' AND site_id = %s
            ORDER BY version DESC, id DESC
            LIMIT 1
            """,
            (location_id,),
        )["version"]
    ) == 5


def test_appointment_precedence_and_duplicate_snapshot_are_immutable(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
    monkeypatch,
):
    import time_tracker_api

    official_time = datetime(2026, 7, 20, 12, 20, tzinfo=timezone.utc)
    job_id = create_canonical_job(
        location_id,
        datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
        suffix="arrival-policy-precedence",
    )
    legacy_exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        datetime(2026, 7, 20, 13, 0, tzinfo=timezone.utc),
        grace_minutes=10,
    )
    site = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Site allows flexible arrival",
        },
    )
    assert site.status_code == 200, site.text
    appointment = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 5,
            "changeNote": "Appointment requires a fixed arrival",
        },
    )
    assert appointment.status_code == 200, appointment.text
    first_revision = appointment.json()["policy"]

    token = create_site_qr(client, auth, location_id)["token"]
    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
    payload = site_check_in_payload(
        employee_id,
        location_id,
        token,
        scanned_at=official_time,
    )
    first = client.post(
        "/api/timesheet/site-check-in",
        headers=emp_auth,
        json=payload,
    )
    assert first.status_code == 200, first.text
    evidence = first.json()["checkIn"]
    assert evidence["classification"] == "late"
    assert evidence["classificationReason"] == "after_arrival_policy_grace"
    assert evidence["arrivalPolicyRevisionId"] == first_revision["id"]
    assert evidence["arrivalPolicySnapshot"]["authority"] == "appointment"
    assert evidence["arrivalPolicySnapshot"]["classifiedBy"] == "arrival_policy"
    assert evidence["scheduleId"] == legacy_exact["id"]
    assert evidence["scheduleRuleId"] is None
    assert evidence["scheduledStart"] == "2026-07-20T13:00:00Z"
    assert evidence["graceMinutes"] == 10
    assert "updateToken" not in evidence["arrivalPolicySnapshot"]
    assert "changeNote" not in evidence["arrivalPolicySnapshot"]

    changed = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "expectedUpdateToken": first_revision["updateToken"],
            "changeNote": "Owner changed this appointment to flexible",
        },
    )
    assert changed.status_code == 200, changed.text
    duplicate = client.post(
        "/api/timesheet/site-check-in",
        headers=emp_auth,
        json=payload,
    )
    assert duplicate.status_code == 200, duplicate.text
    duplicate_evidence = duplicate.json()["checkIn"]
    assert duplicate.json()["duplicate"] is True
    assert duplicate_evidence["arrivalPolicyRevisionId"] == first_revision["id"]
    assert duplicate_evidence["arrivalPolicySnapshot"] == evidence["arrivalPolicySnapshot"]
    assert duplicate_evidence["classification"] == "late"


def test_read_only_inventory_requires_explicit_owner_dispositions(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[0],
        starts_on="2026-07-20",
    )
    second_exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start + timedelta(hours=1),
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-inventory",
    )

    conn = _raw_conn()
    try:
        inventory = build_inventory(
            conn,
            as_of=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
        )
        repeated_inventory = build_inventory(
            conn,
            as_of=datetime(2026, 7, 19, 12, 1, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    exact_row = next(
        row
        for row in inventory["activeFutureExactSchedules"]
        if row["legacyId"] == exact["id"]
    )
    recurring_row = next(
        row
        for row in inventory["activeOpenRecurringRules"]
        if row["legacyId"] == recurring["id"]
    )
    assert exact_row["candidateJobIds"] == [job_id]
    assert exact_row["eligibleAppointmentJobId"] == job_id
    assert recurring_row["timezoneValid"] is True
    assert inventory["orphanReferences"] == []
    assert inventory["asOf"] != repeated_inventory["asOf"]
    assert (
        inventory["inventoryFingerprint"]
        == repeated_inventory["inventoryFingerprint"]
    )

    incomplete = inventory["ownerMappingTemplate"]
    incomplete_errors = validate_owner_mapping(inventory, incomplete)
    assert "mapping.ownerReviewedBy is required" in incomplete_errors
    assert any("disposition must be explicit" in error for error in incomplete_errors)

    mapping = json.loads(json.dumps(incomplete))
    mapping["ownerReviewedBy"] = "Juan Canfield"
    mapping["ownerReviewedAt"] = "2026-07-25T12:00:00Z"
    for entry in mapping["entries"]:
        entry["reviewNote"] = "Owner reviewed this legacy record"
        if entry["legacyKey"] == f"exact:{exact['id']}":
            entry["disposition"] = "map_to_appointment"
            entry["targetJobId"] = job_id
            entry["policy"] = {
                "mode": "fixed",
                "timezone": "America/Chicago",
                "fixedArrival": "07:00",
                "graceMinutes": 10,
            }
        else:
            entry["disposition"] = "needs_review"
    assert validate_owner_mapping(inventory, mapping) == []

    distant_job_id = create_canonical_job(
        location_id,
        scheduled_start + timedelta(hours=18),
        suffix="arrival-policy-wide-window-neighbor",
    )
    conn = _raw_conn()
    try:
        wide_window_inventory = build_inventory(
            conn,
            as_of=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            schedule_window_hours=24,
        )
    finally:
        conn.close()
    wide_window_exact_row = next(
        row
        for row in wide_window_inventory["activeFutureExactSchedules"]
        if row["legacyId"] == exact["id"]
    )
    assert wide_window_exact_row["candidateJobIds"] == [
        job_id,
        distant_job_id,
    ]
    assert wide_window_exact_row["eligibleAppointmentJobId"] is None

    recently_started = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc),
    )
    conn = _raw_conn()
    try:
        lookback_inventory = build_inventory(
            conn,
            as_of=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            schedule_window_hours=3,
        )
        narrow_inventory = build_inventory(
            conn,
            as_of=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            schedule_window_hours=1,
        )
    finally:
        conn.close()
    assert any(
        row["legacyId"] == recently_started["id"]
        for row in lookback_inventory["activeFutureExactSchedules"]
    )
    assert all(
        row["legacyId"] != recently_started["id"]
        for row in narrow_inventory["activeFutureExactSchedules"]
    )

    exact_mapping = next(
        entry
        for entry in mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )
    wrong_target = json.loads(json.dumps(mapping))
    next(
        entry
        for entry in wrong_target["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )["targetJobId"] = job_id + 999
    assert any(
        "sole eligible appointment" in error
        for error in validate_owner_mapping(inventory, wrong_target)
    )

    seconds_mapping = json.loads(json.dumps(mapping))
    next(
        entry
        for entry in seconds_mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )["policy"]["fixedArrival"] = "07:00:01"
    assert any(
        "arrival policy times must use HH:MM syntax" in error
        for error in validate_owner_mapping(inventory, seconds_mapping)
    )

    basic_iso_time_mapping = json.loads(json.dumps(mapping))
    next(
        entry
        for entry in basic_iso_time_mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )["policy"]["fixedArrival"] = "0700"
    assert any(
        "arrival policy times must use HH:MM syntax" in error
        for error in validate_owner_mapping(inventory, basic_iso_time_mapping)
    )

    grace_mapping = json.loads(json.dumps(mapping))
    next(
        entry
        for entry in grace_mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )["policy"]["graceMinutes"] = 121
    assert any(
        "grace_minutes must be between 0 and 120" in error
        for error in validate_owner_mapping(inventory, grace_mapping)
    )

    fractional_grace_mapping = json.loads(json.dumps(mapping))
    next(
        entry
        for entry in fractional_grace_mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )["policy"]["graceMinutes"] = 10.5
    assert any(
        "grace_minutes must be an integer" in error
        for error in validate_owner_mapping(inventory, fractional_grace_mapping)
    )

    truthy_site_confirmation = json.loads(json.dumps(mapping))
    recurring_mapping = next(
        entry
        for entry in truthy_site_confirmation["entries"]
        if entry["legacyKey"] == f"recurring:{recurring['id']}"
    )
    recurring_mapping.update(
        {
            "disposition": "promote_to_site",
            "ownerConfirmedSitePromotion": "false",
            "policy": {
                "mode": "window",
                "timezone": "America/Chicago",
                "windowStart": "06:30",
                "windowEnd": "08:30",
            },
        }
    )
    assert any(
        "ownerConfirmedSitePromotion must be true" in error
        for error in validate_owner_mapping(inventory, truthy_site_confirmation)
    )

    duplicate_target = json.loads(json.dumps(mapping))
    second_exact_mapping = next(
        entry
        for entry in duplicate_target["entries"]
        if entry["legacyKey"] == f"exact:{second_exact['id']}"
    )
    second_exact_mapping.update(
        {
            "disposition": "map_to_appointment",
            "targetJobId": job_id,
            "policy": exact_mapping["policy"],
        }
    )
    assert any(
        "duplicates appointment policy target" in error
        for error in validate_owner_mapping(inventory, duplicate_target)
    )


def test_admin_legacy_inventory_endpoint_is_admin_only_and_read_only(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 19, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[0],
        starts_on="2049-07-19",
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-inventory-api",
    )
    endpoint = "/api/admin/arrival-policy/legacy-inventory"

    assert client.get(endpoint).status_code == 401
    assert client.get(endpoint, headers=emp_auth).status_code == 403

    before = {
        "exact": db.query_one(
            "SELECT COUNT(*) AS count FROM site_check_in_schedules"
        )["count"],
        "recurring": db.query_one(
            "SELECT COUNT(*) AS count FROM site_check_in_schedule_rules"
        )["count"],
        "policies": db.query_one(
            "SELECT COUNT(*) AS count FROM arrival_policy_revisions"
        )["count"],
        "checkIns": db.query_one("SELECT COUNT(*) AS count FROM site_check_ins")[
            "count"
        ],
    }

    response = client.get(endpoint, headers=auth)
    assert response.status_code == 200, response.text
    inventory = response.json()
    assert inventory["databaseReadOnly"] is True
    assert inventory["schemaVersion"] == 1
    assert len(inventory["inventoryFingerprint"]) == 64
    exact_row = next(
        row
        for row in inventory["activeFutureExactSchedules"]
        if row["legacyId"] == exact["id"]
    )
    recurring_row = next(
        row
        for row in inventory["activeOpenRecurringRules"]
        if row["legacyId"] == recurring["id"]
    )
    assert exact_row["candidateJobIds"] == [job_id]
    assert exact_row["eligibleAppointmentJobId"] == job_id
    assert recurring_row["timezoneValid"] is True
    assert any(
        entry["legacyKey"] == f"exact:{exact['id']}"
        for entry in inventory["ownerMappingTemplate"]["entries"]
    )
    assert any(
        entry["legacyKey"] == f"recurring:{recurring['id']}"
        for entry in inventory["ownerMappingTemplate"]["entries"]
    )

    after = {
        "exact": db.query_one(
            "SELECT COUNT(*) AS count FROM site_check_in_schedules"
        )["count"],
        "recurring": db.query_one(
            "SELECT COUNT(*) AS count FROM site_check_in_schedule_rules"
        )["count"],
        "policies": db.query_one(
            "SELECT COUNT(*) AS count FROM arrival_policy_revisions"
        )["count"],
        "checkIns": db.query_one("SELECT COUNT(*) AS count FROM site_check_ins")[
            "count"
        ],
    }
    assert after == before


def test_cutover_readiness_reports_policy_covered_legacy_rows(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[3],
        starts_on="2049-07-22",
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start - timedelta(minutes=1),
        suffix="arrival-policy-cutover-covered",
    )
    created_policy = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Owner approved flexible Site policy for cutover",
        },
    )
    assert created_policy.status_code == 200, created_policy.text
    appointment_policy = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "changeNote": "Owner approved appointment policy for cutover",
        },
    )
    assert appointment_policy.status_code == 200, appointment_policy.text

    endpoint = "/api/admin/arrival-policy/cutover-readiness"
    assert client.get(endpoint).status_code == 401
    assert client.get(endpoint, headers=emp_auth).status_code == 403
    response = client.get(endpoint, headers=auth)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["databaseReadOnly"] is True
    assert body["readyForLegacyFallbackRemoval"] is True
    assert body["summary"]["legacyRows"] == 2
    assert body["summary"]["coveredByPolicy"] == 2
    assert body["summary"]["blockingRows"] == 0
    rows = {row["legacyKey"]: row for row in body["legacyRows"]}
    assert (
        rows[f"exact:{exact['id']}"]["replacement"]["authority"]
        == "appointment"
    )
    assert (
        rows[f"recurring:{recurring['id']}"]["replacement"]["authority"]
        == "site"
    )


def test_cutover_readiness_requires_policy_or_owner_retention(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 23, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[4],
        starts_on="2049-07-23",
    )
    create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-cutover-retain",
    )

    conn = _raw_conn()
    try:
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
        )
        inventory = build_inventory(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
        )
        mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
        mapping["ownerReviewedBy"] = "Juan Canfield"
        mapping["ownerReviewedAt"] = "2049-07-22T12:00:00Z"
        for entry in mapping["entries"]:
            entry["reviewNote"] = "Owner retained this legacy row for history only"
            entry["disposition"] = "retain_history_only"
        retained_report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
            owner_mapping=mapping,
        )
    finally:
        conn.close()

    assert report["readyForLegacyFallbackRemoval"] is False
    assert report["summary"]["blockingRows"] == 2
    assert {row["legacyKey"] for row in report["blockers"]} == {
        f"exact:{exact['id']}",
        f"recurring:{recurring['id']}",
    }
    assert report["blockers"][0]["reason"] == (
        "missing_replacement_policy_or_owner_mapping"
    )

    assert retained_report["readyForLegacyFallbackRemoval"] is True
    assert retained_report["summary"]["ownerRetainHistoryOnly"] == 2
    assert retained_report["summary"]["blockingRows"] == 0
    rows = {row["legacyKey"]: row for row in retained_report["legacyRows"]}
    assert rows[f"exact:{exact['id']}"]["ownerDisposition"] == "retain_history_only"
    assert (
        rows[f"recurring:{recurring['id']}"]["ownerDisposition"]
        == "retain_history_only"
    )

    covered_policy = client.put(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "flexible",
            "timezone": "America/Chicago",
            "changeNote": "Owner approved flexible policy before review finished",
        },
    )
    assert covered_policy.status_code == 200, covered_policy.text
    needs_review_mapping = json.loads(json.dumps(mapping))
    for entry in needs_review_mapping["entries"]:
        entry["reviewNote"] = "Owner has not resolved this legacy row yet"
        entry["disposition"] = "needs_review"
    conn = _raw_conn()
    try:
        needs_review_report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
            owner_mapping=needs_review_mapping,
        )
    finally:
        conn.close()
    assert needs_review_report["readyForLegacyFallbackRemoval"] is False
    assert needs_review_report["summary"]["coveredByPolicy"] == 2
    assert needs_review_report["summary"]["blockingRows"] == 2
    assert {row["reason"] for row in needs_review_report["blockers"]} == {
        "owner_marked_needs_review"
    }


def test_applied_retain_history_only_disposition_stops_runtime_legacy_review(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
    monkeypatch,
):
    import time_tracker_api

    official_time = datetime(2049, 7, 23, 12, 5, tzinfo=timezone.utc)
    scheduled_start = datetime(2049, 7, 23, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[4],
        starts_on="2049-07-23",
    )
    create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-retained-runtime",
    )
    token = create_site_qr(client, auth, location_id)["token"]

    monkeypatch.setattr(time_tracker_api, "utc_now", lambda: official_time)
    conn = _raw_conn()
    try:
        inventory = build_inventory(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()
    mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
    mapping["ownerReviewedBy"] = "Juan Canfield"
    mapping["ownerReviewedAt"] = "2049-07-22T12:00:00Z"
    for entry in mapping["entries"]:
        entry["reviewNote"] = "Owner retained this legacy row for history only"
        entry["disposition"] = "retain_history_only"

    applied = client.post(
        "/api/admin/arrival-policy/legacy-mapping/apply",
        headers=auth,
        json=mapping,
    )
    assert applied.status_code == 200, applied.text
    body = applied.json()
    assert body["skipped"] == []
    assert {row["legacyKey"] for row in body["applied"]} == {
        f"exact:{exact['id']}",
        f"recurring:{recurring['id']}",
    }
    assert {row["status"] for row in body["applied"]} == {
        "retained_history_only"
    }

    conn = _raw_conn()
    try:
        retained_report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 22, 12, 0, tzinfo=timezone.utc),
        )
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT owner_disposition, owner_disposition_note
                FROM site_check_in_schedules
                WHERE id = %s
                """,
                (exact["id"],),
            )
            exact_row = cur.fetchone()
            cur.execute(
                """
                SELECT owner_disposition, owner_disposition_note
                FROM site_check_in_schedule_rules
                WHERE id = %s
                """,
                (recurring["id"],),
            )
            recurring_row = cur.fetchone()
    finally:
        conn.close()
    assert retained_report["readyForLegacyFallbackRemoval"] is True
    assert retained_report["summary"]["ownerRetainHistoryOnly"] == 2
    assert exact_row == (
        "retain_history_only",
        "Owner retained this legacy row for history only",
    )
    assert recurring_row == (
        "retain_history_only",
        "Owner retained this legacy row for history only",
    )

    response = client.post(
        "/api/timesheet/site-check-in",
        headers=emp_auth,
        json=site_check_in_payload(
            employee_id,
            location_id,
            token,
            scanned_at=official_time,
        ),
    )
    assert response.status_code == 200, response.text
    check_in = response.json()["checkIn"]
    assert check_in["classification"] == "on_time"
    assert check_in["classificationReason"] == "verified_scheduled_site"
    assert check_in["reviewStatus"] == "not_required"
    assert check_in["scheduleId"] is None
    assert check_in["scheduleRuleId"] is None
    assert check_in["scheduledStart"] is None
    assert check_in["graceMinutes"] is None


def test_cutover_readiness_counts_pre_snapshot_legacy_check_ins(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 24, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[5],
        starts_on="2049-07-24",
    )
    conn = _raw_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO site_check_ins (
                employee_id, location_id, device_scanned_at, latitude, longitude,
                accuracy_m, geofence_radius_m, distance_m, geofence_status,
                classification, classification_reason, schedule_id,
                scheduled_start, grace_minutes, device_clock_skew_seconds,
                review_status
            ) VALUES (
                %s, %s, %s, 39.1203, -88.54335,
                5.0, 100, 0, 'inside',
                'on_time', 'legacy_exact', %s,
                %s, 10, 0,
                'not_required'
            )
            """,
            (
                employee_id,
                location_id,
                scheduled_start,
                exact["id"],
                scheduled_start,
            ),
        )
        cur.execute(
            """
            INSERT INTO site_check_ins (
                employee_id, location_id, device_scanned_at, latitude, longitude,
                accuracy_m, geofence_radius_m, distance_m, geofence_status,
                classification, classification_reason, schedule_rule_id,
                scheduled_start, grace_minutes, device_clock_skew_seconds,
                review_status
            ) VALUES (
                %s, %s, %s, 39.1203, -88.54335,
                5.0, 100, 0, 'inside',
                'on_time', 'legacy_recurring', %s,
                %s, 10, 0,
                'not_required'
            )
            """,
            (
                employee_id,
                location_id,
                scheduled_start + timedelta(minutes=1),
                recurring["id"],
                scheduled_start,
            ),
        )
        conn.commit()
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 23, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    assert report["summary"]["historicalLegacyExactCheckIns"] == 1
    assert report["summary"]["historicalLegacyRecurringCheckIns"] == 1


def test_cutover_readiness_uses_latest_appointment_revision_by_job(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 25, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-cutover-retired-appointment",
    )
    appointment_policy = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "changeNote": "Owner approved appointment policy before move",
        },
    )
    assert appointment_policy.status_code == 200, appointment_policy.text
    db.execute(
        """
        INSERT INTO arrival_policy_revisions (
            scope_type, site_id, job_id, version, state,
            update_token, change_note, created_by_name
        ) VALUES (
            'appointment', %s, %s, 2, 'retired',
            %s, 'Owner retired appointment policy after move', 'Juan Canfield'
        )
        """,
        (location_id + 100000, job_id, "f" * 64),
    )

    conn = _raw_conn()
    try:
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 24, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    row = next(
        row
        for row in report["legacyRows"]
        if row["legacyKey"] == f"exact:{exact['id']}"
    )
    assert row["currentlyCoveredByPolicy"] is False
    assert row["replacement"] is None
    assert row["blocksCutover"] is True


def test_cutover_readiness_keeps_timezone_boundary_recurring_rule(
    client,
    auth,
    employee_id,
    location_id,
):
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[5],
        starts_on="2049-07-01",
        ends_on="2049-07-23",
    )
    db.execute(
        """
        UPDATE site_check_in_schedule_rules
        SET timezone = 'Pacific/Honolulu'
        WHERE id = %s
        """,
        (recurring["id"],),
    )

    conn = _raw_conn()
    try:
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 24, 8, 30, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    assert report["readyForLegacyFallbackRemoval"] is False
    assert {row["legacyKey"] for row in report["legacyRows"]} == {
        f"recurring:{recurring['id']}"
    }
    assert report["blockers"] == [
        {
            "legacyKey": f"recurring:{recurring['id']}",
            "legacyType": "recurring",
            "siteId": location_id,
            "reason": "missing_replacement_policy_or_owner_mapping",
        }
    ]


def test_cutover_readiness_accepts_reviewed_mapping_after_row_ages_out(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 24, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )

    conn = _raw_conn()
    try:
        inventory = build_inventory(
            conn,
            as_of=datetime(2049, 7, 23, 12, 0, tzinfo=timezone.utc),
        )
        mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
        mapping["ownerReviewedBy"] = "Juan Canfield"
        mapping["ownerReviewedAt"] = "2049-07-23T12:00:00Z"
        for entry in mapping["entries"]:
            entry["reviewNote"] = "Owner retained this legacy row for history only"
            entry["disposition"] = "retain_history_only"

        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 25, 1, 0, tzinfo=timezone.utc),
            owner_mapping=mapping,
        )
    finally:
        conn.close()

    assert any(
        entry["legacyKey"] == f"exact:{exact['id']}"
        for entry in mapping["entries"]
    )
    assert report["mappingValidationErrors"] == []
    assert report["readyForLegacyFallbackRemoval"] is True
    assert report["summary"]["legacyRows"] == 0
    assert report["blockers"] == []


def test_cutover_readiness_rejects_stale_mapping_for_still_active_row(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 24, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )

    conn = _raw_conn()
    try:
        inventory = build_inventory(
            conn,
            as_of=datetime(2049, 7, 23, 12, 0, tzinfo=timezone.utc),
        )
        mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
        mapping["ownerReviewedBy"] = "Juan Canfield"
        mapping["ownerReviewedAt"] = "2049-07-23T12:00:00Z"
        for entry in mapping["entries"]:
            entry["reviewNote"] = "Owner retained this legacy row for history only"
            entry["disposition"] = "retain_history_only"

        db.execute(
            """
            UPDATE site_check_in_schedules
            SET grace_minutes = grace_minutes + 1
            WHERE id = %s
            """,
            (exact["id"],),
        )
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 23, 12, 5, tzinfo=timezone.utc),
            owner_mapping=mapping,
        )
    finally:
        conn.close()

    assert report["readyForLegacyFallbackRemoval"] is False
    assert report["mappingValidationErrors"] == [
        "mapping.entries[0].sourceFingerprint does not match "
        "current active inventory row"
    ]
    assert report["blockers"] == [
        {
            "legacyKey": f"exact:{exact['id']}",
            "legacyType": "exact",
            "siteId": location_id,
            "reason": "owner_mapping_invalid",
        }
    ]


def test_cutover_readiness_requires_appointment_to_cover_full_exact_window(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 26, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-cutover-window-primary",
    )
    competing_job_id = create_canonical_job(
        location_id,
        scheduled_start + timedelta(hours=20),
        suffix="arrival-policy-cutover-window-competing",
    )
    appointment_policy = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "changeNote": "Owner approved appointment policy for cutover",
        },
    )
    assert appointment_policy.status_code == 200, appointment_policy.text

    conn = _raw_conn()
    try:
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 25, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    row = next(
        row
        for row in report["legacyRows"]
        if row["legacyKey"] == f"exact:{exact['id']}"
    )
    assert row["candidateJobIds"] == [job_id]
    assert set(row["runtimeCandidateJobIds"]) == {job_id, competing_job_id}
    assert row["fullWindowAppointmentJobId"] is None
    assert row["currentlyCoveredByPolicy"] is False
    assert row["replacement"] is None
    assert row["blocksCutover"] is True


def test_cutover_readiness_rejects_edge_only_appointment_coverage(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 27, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-cutover-window-edge",
    )
    appointment_policy = client.put(
        f"/api/admin/jobs/{job_id}/arrival-policy",
        headers=auth,
        json={
            "mode": "fixed",
            "timezone": "America/Chicago",
            "fixedArrival": "07:00",
            "graceMinutes": 10,
            "changeNote": "Owner approved appointment policy for cutover",
        },
    )
    assert appointment_policy.status_code == 200, appointment_policy.text

    conn = _raw_conn()
    try:
        report = build_cutover_readiness(
            conn,
            as_of=datetime(2049, 7, 26, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    row = next(
        row
        for row in report["legacyRows"]
        if row["legacyKey"] == f"exact:{exact['id']}"
    )
    assert row["candidateJobIds"] == [job_id]
    assert row["runtimeCandidateJobIds"] == [job_id]
    assert row["fullWindowAppointmentJobId"] is None
    assert row["currentlyCoveredByPolicy"] is False
    assert row["replacement"] is None
    assert row["blocksCutover"] is True


def test_canonical_appointment_scope_locks_site_row_before_policy_write():
    class FakeCursor:
        def __init__(self):
            self.sql: list[str] = []
            self.params: list[tuple] = []
            self.rows = [
                {
                    "id": 17,
                    "location_id": 23,
                    "is_canonical_appointment": True,
                },
                {"id": 23},
            ]

        def execute(self, sql, params=()):
            self.sql.append(sql)
            self.params.append(tuple(params))

        def fetchone(self):
            return self.rows.pop(0)

    cur = FakeCursor()

    site_id, job_id = time_tracker_api._arrival_policy_scope_target(
        cur,
        scope_type="appointment",
        target_id=17,
        for_update=True,
        require_canonical_appointment=True,
    )

    assert (site_id, job_id) == (23, 17)
    assert cur.params[1] == (23,)
    assert "FROM locations" in cur.sql[1]
    assert "FOR SHARE" in cur.sql[1]


def test_legacy_inventory_fingerprint_ignores_live_history_counts(
    client,
    auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 20, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )

    conn = _raw_conn()
    try:
        before = build_inventory(
            conn,
            as_of=datetime(2049, 7, 19, 12, 0, tzinfo=timezone.utc),
        )
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO site_check_ins (
                employee_id, location_id, device_scanned_at, latitude, longitude,
                accuracy_m, geofence_radius_m, distance_m, geofence_status,
                classification, classification_reason, schedule_id,
                scheduled_start, grace_minutes, device_clock_skew_seconds,
                review_status
            )
            VALUES (
                %s, %s, %s, 39.1203, -88.54335,
                5.0, 100, 0, 'inside',
                'on_time', 'legacy_exact', %s,
                %s, 10, 0,
                'not_required'
            )
            """,
            (
                employee_id,
                location_id,
                scheduled_start,
                exact["id"],
                scheduled_start,
            ),
        )
        conn.commit()
        after = build_inventory(
            conn,
            as_of=datetime(2049, 7, 19, 12, 0, tzinfo=timezone.utc),
        )
    finally:
        conn.close()

    before_exact = next(
        row
        for row in before["activeFutureExactSchedules"]
        if row["legacyId"] == exact["id"]
    )
    after_exact = next(
        row
        for row in after["activeFutureExactSchedules"]
        if row["legacyId"] == exact["id"]
    )
    assert before_exact["historyReferenceCount"] == 0
    assert after_exact["historyReferenceCount"] == 1
    assert after["historyReferences"] == [
        {"legacyKey": f"exact:{exact['id']}", "checkInCount": 1}
    ]
    assert before["inventoryFingerprint"] == after["inventoryFingerprint"]


def test_admin_legacy_mapping_apply_creates_policy_revisions_idempotently(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    scheduled_start = datetime(2049, 7, 20, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    recurring = create_recurring_schedule_rule(
        client,
        auth,
        employee_id,
        location_id,
        weekdays=[0, 2],
        starts_on="2049-07-19",
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-mapping-apply",
    )
    inventory = client.get(
        "/api/admin/arrival-policy/legacy-inventory",
        headers=auth,
    ).json()
    mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
    mapping["ownerReviewedBy"] = "Juan Canfield"
    mapping["ownerReviewedAt"] = "2049-07-19T12:00:00Z"
    for entry in mapping["entries"]:
        entry["reviewNote"] = "Owner reviewed this legacy policy source"
        if entry["legacyKey"] == f"exact:{exact['id']}":
            entry.update(
                {
                    "disposition": "map_to_appointment",
                    "targetJobId": job_id,
                    "policy": {
                        "mode": "fixed",
                        "timezone": "America/Chicago",
                        "fixedArrival": "07:00",
                        "graceMinutes": 10,
                    },
                }
            )
        elif entry["legacyKey"] == f"recurring:{recurring['id']}":
            entry.update(
                {
                    "disposition": "promote_to_site",
                    "ownerConfirmedSitePromotion": True,
                    "policy": {
                        "mode": "window",
                        "timezone": "America/Chicago",
                        "windowStart": "06:30",
                        "windowEnd": "08:30",
                    },
                }
            )
        else:
            entry["disposition"] = "needs_review"

    endpoint = "/api/admin/arrival-policy/legacy-mapping/apply"
    assert client.post(endpoint, json=mapping).status_code == 401
    assert client.post(endpoint, headers=emp_auth, json=mapping).status_code == 403

    invalid = json.loads(json.dumps(mapping))
    invalid["inventoryFingerprint"] = "0" * 64
    rejected = client.post(endpoint, headers=auth, json=invalid)
    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["code"] == "invalid_arrival_policy_legacy_mapping"
    assert any(
        "inventoryFingerprint" in error
        for error in rejected.json()["details"]["errors"]
    )

    created = client.post(endpoint, headers=auth, json=mapping)
    assert created.status_code == 200, created.text
    created_body = created.json()
    assert created_body["success"] is True
    assert created_body["inventoryFingerprint"] == inventory["inventoryFingerprint"]
    assert {row["legacyKey"] for row in created_body["applied"]} == {
        f"exact:{exact['id']}",
        f"recurring:{recurring['id']}",
    }
    assert {row["status"] for row in created_body["applied"]} == {"created"}
    assert created_body["skipped"] == []

    rows = db.query_all(
        """
        SELECT scope_type, site_id, job_id, version, state, mode,
               fixed_arrival, grace_minutes, window_start, window_end,
               created_by_name
        FROM arrival_policy_revisions
        ORDER BY scope_type, job_id NULLS FIRST
        """
    )
    assert len(rows) == 2
    site_row = next(row for row in rows if row["scope_type"] == "site")
    appointment_row = next(row for row in rows if row["scope_type"] == "appointment")
    assert site_row["site_id"] == location_id
    assert site_row["job_id"] is None
    assert site_row["version"] == 1
    assert site_row["state"] == "active"
    assert site_row["mode"] == "window"
    assert site_row["window_start"].strftime("%H:%M") == "06:30"
    assert site_row["window_end"].strftime("%H:%M") == "08:30"
    assert appointment_row["job_id"] == job_id
    assert appointment_row["version"] == 1
    assert appointment_row["state"] == "active"
    assert appointment_row["mode"] == "fixed"
    assert appointment_row["fixed_arrival"].strftime("%H:%M") == "07:00"
    assert appointment_row["grace_minutes"] == 10

    repeated = client.post(endpoint, headers=auth, json=mapping)
    assert repeated.status_code == 200, repeated.text
    repeated_body = repeated.json()
    assert {row["status"] for row in repeated_body["applied"]} == {
        "already_applied"
    }
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM arrival_policy_revisions"
    )["count"] == 2

    site_policy = client.get(
        f"/api/admin/locations/{location_id}/arrival-policy",
        headers=auth,
    ).json()["policy"]
    retired = client.post(
        f"/api/admin/locations/{location_id}/arrival-policy/retire",
        headers=auth,
        json={
            "expectedUpdateToken": site_policy["updateToken"],
            "changeNote": "Owner retired the migrated Site policy",
        },
    )
    assert retired.status_code == 200, retired.text
    stale_retry = client.post(endpoint, headers=auth, json=mapping)
    assert stale_retry.status_code == 409, stale_retry.text
    assert stale_retry.json()["code"] == "arrival_policy_mapping_target_conflict"
    assert stale_retry.json()["details"]["currentState"] == "retired"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM arrival_policy_revisions"
    )["count"] == 3


@pytest.mark.parametrize(
    "retryable_error",
    [
        psycopg2.errors.SerializationFailure,
        psycopg2.errors.UniqueViolation,
        psycopg2.errors.DeadlockDetected,
    ],
)
def test_admin_legacy_mapping_apply_retries_after_database_race(
    client,
    auth,
    employee_id,
    location_id,
    monkeypatch,
    retryable_error,
):
    scheduled_start = datetime(2049, 7, 21, 12, 0, tzinfo=timezone.utc)
    exact = create_arrival_schedule(
        client,
        auth,
        employee_id,
        location_id,
        scheduled_start,
    )
    job_id = create_canonical_job(
        location_id,
        scheduled_start,
        suffix="arrival-policy-mapping-retry",
    )
    inventory = client.get(
        "/api/admin/arrival-policy/legacy-inventory",
        headers=auth,
    ).json()
    mapping = json.loads(json.dumps(inventory["ownerMappingTemplate"]))
    mapping["ownerReviewedBy"] = "Juan Canfield"
    mapping["ownerReviewedAt"] = "2049-07-21T12:00:00Z"
    for entry in mapping["entries"]:
        entry["reviewNote"] = "Owner reviewed this legacy policy source"
        if entry["legacyKey"] == f"exact:{exact['id']}":
            entry.update(
                {
                    "disposition": "map_to_appointment",
                    "targetJobId": job_id,
                    "policy": {
                        "mode": "fixed",
                        "timezone": "America/Chicago",
                        "fixedArrival": "07:00",
                        "graceMinutes": 10,
                    },
                }
            )
        else:
            entry["disposition"] = "needs_review"

    original = time_tracker_api._apply_arrival_policy_mapping_revision
    calls = {"count": 0}

    def fail_once_then_apply(*args, **kwargs):
        if calls["count"] == 0:
            calls["count"] += 1
            raise retryable_error()
        return original(*args, **kwargs)

    monkeypatch.setattr(
        time_tracker_api,
        "_apply_arrival_policy_mapping_revision",
        fail_once_then_apply,
    )

    response = client.post(
        "/api/admin/arrival-policy/legacy-mapping/apply",
        headers=auth,
        json=mapping,
    )
    assert response.status_code == 200, response.text
    assert calls["count"] == 1
    assert response.json()["applied"][0]["status"] == "created"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM arrival_policy_revisions"
    )["count"] == 1


def test_admin_legacy_inventory_uses_one_repeatable_read_snapshot():
    import inspect
    import time_tracker_api

    source = inspect.getsource(time_tracker_api.admin_arrival_policy_legacy_inventory)
    assert "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" in source


def test_admin_legacy_mapping_apply_uses_qr_window_and_locks_jobs():
    import inspect
    import time_tracker_api

    source = inspect.getsource(
        time_tracker_api._apply_arrival_policy_legacy_mapping_once
    )
    assert "LOCK TABLE jobs IN SHARE MODE" in source
    assert "schedule_window_hours=SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS" in source


def test_inventory_cli_preflight_uses_configured_qr_window():
    import inspect
    import inventory_arrival_policies

    source = inspect.getsource(inventory_arrival_policies.main)
    assert 'isolation_level="REPEATABLE READ"' in source
    assert "_configured_schedule_window_hours()" in source
    assert "build_cutover_readiness" in source
    assert "owner_mapping=mapping" in source
    assert "schedule_window_hours=schedule_window_hours" in source
