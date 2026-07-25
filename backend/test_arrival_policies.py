"""Arrival-policy revision, precedence, boundary, and snapshot contracts."""

from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

import pytest

import arrival_policies
from arrival_policy_inventory import build_inventory, validate_owner_mapping
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
    create_arrival_schedule(
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

    exact_mapping = next(
        entry
        for entry in mapping["entries"]
        if entry["legacyKey"] == f"exact:{exact['id']}"
    )
    exact_mapping["targetJobId"] = job_id + 999
    assert any(
        "sole eligible appointment" in error
        for error in validate_owner_mapping(inventory, mapping)
    )
