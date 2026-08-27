"""Tracker's evidence-backed first-clean completion bridge stays retry-safe."""

from __future__ import annotations

import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, time as clock_time, timedelta, timezone

import db
import pytest
import time_tracker_api as api
from conftest import _raw_conn


TEST_PREFIX = "ZZ First Clean "
CALENDAR_EMAIL_PREFIX = "first-clean-"


def _clean_first_clean_rows() -> None:
    """Remove every source row created by this module's evidence fixture."""

    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            customer_pattern = f"{TEST_PREFIX}%"
            calendar_pattern = f"{CALENDAR_EMAIL_PREFIX}%@example.test"
            cur.execute(
                "DELETE FROM eom_first_clean_completion_reports WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s)",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM planned_visit_audit_events WHERE planned_visit_id IN "
                "(SELECT id FROM planned_service_visits WHERE source_calendar_id LIKE %s)",
                (f"{CALENDAR_EMAIL_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM planned_visit_assignments WHERE planned_visit_id IN "
                "(SELECT id FROM planned_service_visits WHERE source_calendar_id LIKE %s)",
                (f"{CALENDAR_EMAIL_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM visit_evidence_events WHERE planned_visit_id IN "
                "(SELECT id FROM planned_service_visits WHERE source_calendar_id LIKE %s)",
                (f"{CALENDAR_EMAIL_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM planned_service_visits WHERE source_calendar_id LIKE %s",
                (f"{CALENDAR_EMAIL_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM departures WHERE location_id IN "
                "(SELECT id FROM locations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s))",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM shifts WHERE location_id IN "
                "(SELECT id FROM locations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s))",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM eom_office_conversion_handoffs WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s)",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM jobs WHERE location_id IN "
                "(SELECT id FROM locations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s))",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM service_schedule_rules WHERE location_id IN "
                "(SELECT id FROM locations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s))",
                (customer_pattern,),
            )
            cur.execute(
                "DELETE FROM google_calendar_connections WHERE google_account_email LIKE %s",
                (calendar_pattern,),
            )
            cur.execute(
                "DELETE FROM locations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s)",
                (customer_pattern,),
            )
            cur.execute("DELETE FROM customers WHERE name LIKE %s", (customer_pattern,))
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def isolate_first_clean_completion_rows(setup_db):
    _clean_first_clean_rows()
    yield
    _clean_first_clean_rows()


def _path(planned_visit_id: int) -> str:
    return f"/api/admin/funnel/planned-visits/{planned_visit_id}/first-clean-completions"


def _native_path(rule_id: int, occurrence_date: str) -> str:
    return (
        f"/api/admin/funnel/native-schedule-rules/{rule_id}/occurrences/"
        f"{occurrence_date}/first-clean-completions"
    )


def _receipt(source: dict[str, object], *, idempotent: bool = False) -> dict[str, object]:
    completed_at = source["completedAt"]
    return {
        "success": True,
        "receiptId": str(uuid.uuid4()),
        "contactId": source["contactId"],
        "handoffId": str(uuid.uuid4()),
        "trackerCustomerId": source["customerId"],
        "trackerSiteId": source["siteId"],
        "trackerServiceKind": "planned_visit",
        "trackerServiceId": source["plannedVisitId"],
        "completedAt": completed_at,
        "recordedAt": completed_at,
        "idempotent": idempotent,
    }


def _native_receipt(
    source: dict[str, object],
    payload: dict[str, object],
    *,
    idempotent: bool = False,
) -> dict[str, object]:
    return {
        "success": True,
        "receiptId": str(uuid.uuid4()),
        "contactId": source["contactId"],
        "handoffId": str(uuid.uuid4()),
        "trackerCustomerId": payload["tracker_customer_id"],
        "trackerSiteId": payload["tracker_site_id"],
        "trackerServiceKind": payload["tracker_service_kind"],
        "trackerServiceId": payload["tracker_service_id"],
        "completedAt": payload["completed_at"],
        "recordedAt": payload["completed_at"],
        "idempotent": idempotent,
    }


def _seed_first_clean(
    *,
    residential: bool = True,
    closed: bool = True,
    arrival_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> dict[str, object]:
    """Create fake, linked operational evidence without using customer PII."""

    admin = db.query_one(
        "SELECT id, name FROM employees WHERE role = 'admin' AND active = true "
        "ORDER BY id LIMIT 1"
    )
    worker = db.query_one(
        "SELECT id FROM employees WHERE role = 'employee' AND active = true "
        "ORDER BY id LIMIT 1"
    )
    if admin is None or worker is None:
        raise RuntimeError("First-clean tests require one active admin and employee")
    token = uuid.uuid4().hex
    contact_id = str(uuid.uuid4())
    completed_at = completed_at or (
        datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)
    )
    arrival_at = arrival_at or (completed_at - timedelta(hours=1))
    source_key = hashlib.sha256(f"first-clean:{token}".encode()).hexdigest()
    source_fingerprint = hashlib.sha256(f"fingerprint:{token}".encode()).hexdigest()
    customer_type = "residential" if residential else "commercial"
    location_type = "Residential" if residential else "Commercial"

    customer_id = int(
        db.execute_returning(
            """
            INSERT INTO customers (name, atlas_contact_id, customer_type)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (f"{TEST_PREFIX}{token}", contact_id, customer_type),
        )
    )
    site_id = int(
        db.execute_returning(
            """
            INSERT INTO locations (customer_id, address, customer_name, location_type)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                customer_id,
                f"{token} First Clean Test Way",
                f"{TEST_PREFIX}{token}",
                location_type,
            ),
        )
    )
    db.execute(
        """
        INSERT INTO eom_office_conversion_handoffs (
            atlas_contact_id, idempotency_key, request_fingerprint,
            customer_id, site_id, approved_by_employee_id, state, atlas_handoff_id
        ) VALUES (%s, %s, %s, %s, %s, %s, 'finalized', %s)
        """,
        (
            contact_id,
            str(uuid.uuid4()),
            "a" * 64,
            customer_id,
            site_id,
            int(admin["id"]),
            str(uuid.uuid4()),
        ),
    )
    connection_id = int(
        db.execute_returning(
            """
            INSERT INTO google_calendar_connections (google_account_email, revoked_at)
            VALUES (%s, NOW())
            RETURNING id
            """,
            (f"{CALENDAR_EMAIL_PREFIX}{token}@example.test",),
        )
    )
    planned_visit_id = int(
        db.execute_returning(
            """
            INSERT INTO planned_service_visits (
                connection_id, source_calendar_id, source_event_id,
                source_series_id, source_occurrence_id, source_key,
                source_fingerprint, title, location_id, approximate_start,
                approximate_end, source_timezone
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'America/Chicago')
            RETURNING id
            """,
            (
                connection_id,
                f"{CALENDAR_EMAIL_PREFIX}{token}",
                f"event-{token}",
                f"series-{token}",
                f"occurrence-{token}",
                source_key,
                source_fingerprint,
                "First clean test visit",
                site_id,
                arrival_at - timedelta(minutes=30),
                completed_at + timedelta(minutes=30),
            ),
        )
    )
    shift_id = int(
        db.execute_returning(
            """
            INSERT INTO shifts (employee_id, location_id, clock_in, clock_out)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                int(worker["id"]),
                site_id,
                arrival_at - timedelta(minutes=10),
                completed_at,
            ),
        )
    )
    visit_id = int(
        db.execute_returning(
            """
            INSERT INTO visits (shift_id, location_id, location_label, arrival_time)
            VALUES (%s, %s, 'First clean test site', %s)
            RETURNING id
            """,
            (shift_id, site_id, arrival_at),
        )
    )
    db.execute(
        """
        INSERT INTO visit_evidence_events (
            visit_id, shift_id, employee_id, location_id, planned_visit_id,
            evidence_method, geofence_status
        ) VALUES (%s, %s, %s, %s, %s, 'residential_gps', 'inside')
        """,
        (visit_id, shift_id, int(worker["id"]), site_id, planned_visit_id),
    )
    if closed:
        db.execute(
            """
            INSERT INTO departures (shift_id, visit_id, location_id, departure_time)
            VALUES (%s, %s, %s, %s)
            """,
            (shift_id, visit_id, site_id, completed_at),
        )

    return {
        "contactId": contact_id,
        "customerId": customer_id,
        "siteId": site_id,
        "calendarConnectionId": connection_id,
        "plannedVisitId": planned_visit_id,
        "arrivalAt": api.to_utc_iso(arrival_at),
        "completedAt": api.to_utc_iso(completed_at),
        "adminId": int(admin["id"]),
        "adminName": str(admin["name"]),
        "workerId": int(worker["id"]),
    }


def _seed_native_first_clean(
    *,
    residential: bool = True,
    closed: bool = True,
    exception_action: str | None = None,
    overnight: bool = False,
    geofence_status: str = "inside",
) -> dict[str, object]:
    """Seed the evidence shape produced by a native-only Residential arrival."""

    local_today = datetime.now(api.APP_TIMEZONE).date()
    if overnight:
        evidence_date = local_today - timedelta(days=2)
        arrival_local = datetime.combine(
            evidence_date + timedelta(days=1),
            clock_time(0, 30),
            tzinfo=api.APP_TIMEZONE,
        )
        completed_local = datetime.combine(
            evidence_date + timedelta(days=1),
            clock_time(1, 30),
            tzinfo=api.APP_TIMEZONE,
        )
        local_start_time = clock_time(22, 0)
        local_end_time = clock_time(2, 0)
    else:
        evidence_date = local_today - timedelta(days=1)
        arrival_local = datetime.combine(
            evidence_date,
            clock_time(9, 30),
            tzinfo=api.APP_TIMEZONE,
        )
        completed_local = datetime.combine(
            evidence_date,
            clock_time(10, 30),
            tzinfo=api.APP_TIMEZONE,
        )
        local_start_time = clock_time(9, 0)
        local_end_time = clock_time(11, 0)
    source = _seed_first_clean(
        residential=residential,
        closed=closed,
        arrival_at=arrival_local.astimezone(timezone.utc),
        completed_at=completed_local.astimezone(timezone.utc),
    )
    db.execute(
        "UPDATE visit_evidence_events "
        "SET planned_visit_id = NULL, "
        "evidence_method = 'unplanned_residential', "
        "exception_reason = 'unplanned_visit', "
        "exception_detail = 'native schedule arrival', "
        "geofence_status = %s "
        "WHERE planned_visit_id = %s",
        (geofence_status, source["plannedVisitId"]),
    )
    db.execute(
        "DELETE FROM planned_service_visits WHERE id = %s",
        (source["plannedVisitId"],),
    )
    occurrence_date = (
        evidence_date - timedelta(days=7)
        if exception_action == "rescheduled"
        else evidence_date
    )
    rule_id = int(
        db.execute_returning(
            """
            INSERT INTO service_schedule_rules (
                location_id, shift_bucket, cadence, weekdays,
                local_start_time, local_end_time, starts_on, ends_on
            ) VALUES (%s, 'morning', 'weekly', %s, %s, %s, %s, NULL)
            RETURNING id
            """,
            (
                source["siteId"],
                [occurrence_date.weekday()],
                local_start_time,
                local_end_time,
                occurrence_date,
            ),
        )
    )
    if exception_action == "cancelled":
        db.execute(
            """
            INSERT INTO service_schedule_occurrence_exceptions (
                rule_id, service_date, action, reason
            ) VALUES (%s, %s, 'cancelled', 'controlled test cancellation')
            """,
            (rule_id, occurrence_date),
        )
    elif exception_action == "rescheduled":
        db.execute(
            """
            INSERT INTO service_schedule_occurrence_exceptions (
                rule_id, service_date, action, scheduled_date,
                local_start_time, local_end_time, reason
            ) VALUES (%s, %s, 'rescheduled', %s, %s, %s,
                      'controlled test reschedule')
            """,
            (
                rule_id,
                occurrence_date,
                evidence_date,
                local_start_time,
                local_end_time,
            ),
        )
    source.update(
        {
            "ruleId": rule_id,
            "occurrenceDate": occurrence_date.isoformat(),
            "effectiveDate": evidence_date.isoformat(),
        }
    )
    return source


def _report(planned_visit_id: int) -> dict | None:
    return db.query_one(
        """
        SELECT state, completed_at, atlas_receipt_id, last_error_code,
               reported_by_employee_id, reported_by_name
        FROM eom_first_clean_completion_reports
        WHERE planned_visit_id = %s
        """,
        (planned_visit_id,),
    )


def _native_report(rule_id: int, occurrence_date: str) -> dict | None:
    return db.query_one(
        """
        SELECT report.state, report.completed_at, report.atlas_receipt_id,
               report.last_error_code, report.reported_by_employee_id,
               report.reported_by_name, report.job_id
        FROM eom_first_clean_completion_reports AS report
        JOIN jobs AS job ON job.id = report.job_id
        WHERE job.native_schedule_rule_id = %s
          AND job.native_occurrence_date = %s
        """,
        (rule_id, occurrence_date),
    )


def test_source_fixture_cleanup_removes_every_generated_operational_row(client):
    source = _seed_first_clean()

    _clean_first_clean_rows()

    assert db.query_one("SELECT COUNT(*) AS count FROM customers WHERE id = %s", (source["customerId"],)) == {
        "count": 0
    }
    assert db.query_one("SELECT COUNT(*) AS count FROM locations WHERE id = %s", (source["siteId"],)) == {
        "count": 0
    }
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM planned_service_visits WHERE id = %s",
        (source["plannedVisitId"],),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM visit_evidence_events WHERE planned_visit_id = %s",
        (source["plannedVisitId"],),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM departures WHERE location_id = %s",
        (source["siteId"],),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE location_id = %s",
        (source["siteId"],),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_office_conversion_handoffs WHERE atlas_contact_id = %s",
        (source["contactId"],),
    ) == {"count": 0}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM google_calendar_connections WHERE id = %s",
        (source["calendarConnectionId"],),
    ) == {"count": 0}


def test_completion_schema_runtime_migration_is_idempotent(client):
    api._ensure_first_clean_completion_report_schema()
    api._ensure_first_clean_completion_report_schema()

    assert db.query_one(
        """
        SELECT
            COUNT(*) FILTER (
                WHERE table_name = 'jobs'
                  AND column_name IN (
                      'native_schedule_rule_id', 'native_occurrence_date',
                      'native_schedule_snapshot'
                  )
            ) AS job_columns,
            COUNT(*) FILTER (
                WHERE table_name = 'eom_first_clean_completion_reports'
                  AND column_name = 'job_id'
                  AND is_nullable = 'YES'
            ) AS report_job_columns,
            COUNT(*) FILTER (
                WHERE table_name = 'eom_first_clean_completion_reports'
                  AND column_name = 'planned_visit_id'
                  AND is_nullable = 'YES'
            ) AS nullable_planned_visit_columns
        FROM information_schema.columns
        WHERE table_schema = current_schema()
        """
    ) == {
        "job_columns": 3,
        "report_job_columns": 1,
        "nullable_planned_visit_columns": 1,
    }
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM pg_constraint
        WHERE conname IN (
            'jobs_native_schedule_occurrence_pair_check',
            'eom_first_clean_completion_report_service_check'
        )
        """
    ) == {"count": 2}


def test_evidenced_residential_completion_posts_only_tracker_facts_and_finalizes(
    client, auth, monkeypatch
):
    source = _seed_first_clean()
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(
            {
                "path": path,
                "admin": admin,
                "payload": payload,
                "idempotencyKey": idempotency_key,
            }
        )
        return _receipt(source)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(_path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key})

    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "plannedVisitId": source["plannedVisitId"],
        "contactId": source["contactId"],
        "trackerCustomerId": source["customerId"],
        "trackerSiteId": source["siteId"],
        "completedAt": source["completedAt"],
        "receiptId": str(_report(int(source["plannedVisitId"]))["atlas_receipt_id"]),
        "status": "recorded",
        "idempotent": False,
    }
    assert calls == [
        {
            "path": api.ATLAS_FIRST_CLEAN_COMPLETIONS_PATH.format(contact_id=source["contactId"]),
            "admin": {
                "id": source["adminId"],
                "name": source["adminName"],
                "role": "admin",
            },
            "payload": {
                "tracker_customer_id": source["customerId"],
                "tracker_site_id": source["siteId"],
                "tracker_service_kind": "planned_visit",
                "tracker_service_id": source["plannedVisitId"],
                "completed_at": source["completedAt"],
            },
            "idempotencyKey": key,
        }
    ]
    assert db.query_one(
        "SELECT status, completed_at FROM planned_service_visits WHERE id = %s",
        (source["plannedVisitId"],),
    ) == {"status": "completed", "completed_at": datetime.fromisoformat(source["completedAt"].replace("Z", "+00:00"))}
    assert _report(int(source["plannedVisitId"])) == {
        "state": "finalized",
        "completed_at": datetime.fromisoformat(source["completedAt"].replace("Z", "+00:00")),
        "atlas_receipt_id": response.json()["receiptId"],
        "last_error_code": None,
        "reported_by_employee_id": source["adminId"],
        "reported_by_name": source["adminName"],
    }


def test_calendar_visit_without_a_closed_employee_interval_never_starts_a_completion(
    client, auth, monkeypatch
):
    source = _seed_first_clean(closed=False)
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("Atlas must not receive incomplete evidence"),
    )

    response = client.post(
        _path(int(source["plannedVisitId"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_evidence_missing"
    assert _report(int(source["plannedVisitId"])) is None
    assert db.query_one(
        "SELECT status, completed_at FROM planned_service_visits WHERE id = %s",
        (source["plannedVisitId"],),
    ) == {"status": "planned", "completed_at": None}


def test_non_residential_service_is_never_reported_as_a_first_clean(client, auth, monkeypatch):
    source = _seed_first_clean(residential=False)
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("commercial service must not reach Atlas"),
    )

    response = client.post(
        _path(int(source["plannedVisitId"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_not_eligible"
    assert _report(int(source["plannedVisitId"])) is None


def test_exception_evidence_cannot_be_recast_as_a_scheduled_first_clean(client, auth, monkeypatch):
    source = _seed_first_clean()
    db.execute(
        """
        UPDATE visit_evidence_events
        SET evidence_method = 'unplanned_residential',
            exception_reason = 'unplanned_visit',
            exception_detail = 'controlled test exception'
        WHERE planned_visit_id = %s
        """,
        (source["plannedVisitId"],),
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("exception evidence must not reach Atlas"),
    )

    response = client.post(
        _path(int(source["plannedVisitId"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_evidence_missing"
    assert _report(int(source["plannedVisitId"])) is None


def test_capability_outage_keeps_the_committed_completion_pending_for_later_recovery(
    client, auth, monkeypatch
):
    source = _seed_first_clean()
    key = str(uuid.uuid4())
    calls: list[str] = []

    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: {"capabilities": [], "capabilityRoutes": []},
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("unadvertised route must not be called"),
    )
    unavailable = client.post(
        _path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key}
    )

    assert unavailable.status_code == 501, unavailable.text
    assert _report(int(source["plannedVisitId"]))["state"] == "pending"
    assert _report(int(source["plannedVisitId"]))["last_error_code"] == "atlas_capability_unavailable"
    assert db.query_one(
        "SELECT status FROM planned_service_visits WHERE id = %s",
        (source["plannedVisitId"],),
    ) == {"status": "completed"}

    monkeypatch.setattr(api, "_require_atlas_funnel_capability_routes", lambda *_args: None)

    def recovered_request(_path, _admin, *, payload, idempotency_key):
        calls.append(idempotency_key)
        assert payload["completed_at"] == source["completedAt"]
        return _receipt(source, idempotent=True)

    monkeypatch.setattr(api, "_atlas_funnel_request", recovered_request)
    recovered = client.post(
        _path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key}
    )

    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["idempotent"] is True
    assert calls == [key]
    assert _report(int(source["plannedVisitId"]))["state"] == "finalized"


def test_remote_failure_retries_the_same_immutable_report_without_another_local_confirmation(
    client, auth, monkeypatch
):
    source = _seed_first_clean()
    key = str(uuid.uuid4())
    calls: list[tuple[str, dict[str, object]]] = []

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        calls.append((idempotency_key, payload))
        if len(calls) == 1:
            raise api.AtlasFunnelRequestError(503, "controlled test outage")
        return _receipt(source, idempotent=True)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first = client.post(
        _path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key}
    )
    assert first.status_code == 503
    assert _report(int(source["plannedVisitId"]))["state"] == "pending"
    assert _report(int(source["plannedVisitId"]))["last_error_code"] == "atlas_status_503"
    retried = client.post(
        _path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key}
    )
    replayed = client.post(
        _path(int(source["plannedVisitId"])), headers=auth, json={"idempotencyKey": key}
    )

    assert retried.status_code == 200, retried.text
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["idempotent"] is True
    assert [call[0] for call in calls] == [key, key]
    assert calls[0][1] == calls[1][1]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM planned_visit_audit_events WHERE planned_visit_id = %s",
        (source["plannedVisitId"],),
    ) == {"count": 1}


def test_concurrent_reservations_share_one_durable_completion_report(client):
    source = _seed_first_clean()
    payload = api.FunnelFirstCleanCompletionRequest(idempotencyKey=uuid.uuid4())
    admin = {
        "id": source["adminId"],
        "name": source["adminName"],
        "role": "admin",
    }

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(
            workers.map(
                lambda _unused: api._reserve_first_clean_completion_report(
                    int(source["plannedVisitId"]), payload, admin
                ),
                range(2),
            )
        )

    assert sorted(created for _report_row, created in results) == [False, True]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_first_clean_completion_reports WHERE planned_visit_id = %s",
        (source["plannedVisitId"],),
    ) == {"count": 1}


def test_native_completion_materializes_one_job_and_posts_job_identity(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean()
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        calls.append({"payload": payload, "idempotencyKey": idempotency_key})
        return _native_receipt(source, payload)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": key},
    )

    assert response.status_code == 201, response.text
    job_id = int(response.json()["jobId"])
    assert response.json() == {
        "success": True,
        "jobId": job_id,
        "contactId": source["contactId"],
        "trackerCustomerId": source["customerId"],
        "trackerSiteId": source["siteId"],
        "completedAt": source["completedAt"],
        "receiptId": str(
            _native_report(int(source["ruleId"]), str(source["occurrenceDate"]))[
                "atlas_receipt_id"
            ]
        ),
        "status": "recorded",
        "idempotent": False,
    }
    assert calls == [
        {
            "payload": {
                "tracker_customer_id": source["customerId"],
                "tracker_site_id": source["siteId"],
                "tracker_service_kind": "job",
                "tracker_service_id": job_id,
                "completed_at": source["completedAt"],
            },
            "idempotencyKey": key,
        }
    ]
    assert db.query_one(
        """
        SELECT id, status, native_schedule_rule_id, native_occurrence_date,
               scheduled_date, source_calendar_id
        FROM jobs
        WHERE id = %s
        """,
        (job_id,),
    ) == {
        "id": job_id,
        "status": "completed",
        "native_schedule_rule_id": source["ruleId"],
        "native_occurrence_date": datetime.fromisoformat(
            str(source["occurrenceDate"])
        ).date(),
        "scheduled_date": datetime.fromisoformat(str(source["effectiveDate"])).date(),
        "source_calendar_id": None,
    }
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM planned_service_visits WHERE location_id = %s",
        (source["siteId"],),
    ) == {"count": 0}
    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": source["effectiveDate"],
            "end_date": source["effectiveDate"],
            "planning_source": "native",
        },
    )
    assert schedule.status_code == 200, schedule.text
    site_jobs = [
        row
        for row in schedule.json()["jobs"]
        if row["locationId"] == source["siteId"]
    ]
    assert len(site_jobs) == 1
    assert site_jobs[0]["id"] == job_id
    assert site_jobs[0]["projectionId"] == (
        f"rule-{source['ruleId']}:{source['occurrenceDate']}"
    )
    assert site_jobs[0]["ruleId"] == source["ruleId"]
    assert site_jobs[0]["occurrenceDate"] == source["occurrenceDate"]
    assert site_jobs[0]["shiftBucket"] == "morning"
    assert site_jobs[0]["cadence"] == "weekly"
    assert site_jobs[0]["occurrenceException"] is None


def test_native_completion_remote_retry_reuses_the_same_job_and_report(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean()
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        calls.append(payload)
        if len(calls) == 1:
            raise api.AtlasFunnelRequestError(503, "controlled native outage")
        return _native_receipt(source, payload, idempotent=True)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    path = _native_path(int(source["ruleId"]), str(source["occurrenceDate"]))
    first = client.post(path, headers=auth, json={"idempotencyKey": key})
    retried = client.post(path, headers=auth, json={"idempotencyKey": key})
    replayed = client.post(path, headers=auth, json={"idempotencyKey": key})

    assert first.status_code == 503
    assert retried.status_code == 200, retried.text
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["idempotent"] is True
    assert calls[0] == calls[1]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE native_schedule_rule_id = %s "
        "AND native_occurrence_date = %s",
        (source["ruleId"], source["occurrenceDate"]),
    ) == {"count": 1}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_first_clean_completion_reports "
        "WHERE job_id = %s",
        (retried.json()["jobId"],),
    ) == {"count": 1}


def test_native_completion_requires_closed_same_day_residential_evidence(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean(closed=False)
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("Atlas must not receive open evidence"),
    )

    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_evidence_missing"
    assert _native_report(int(source["ruleId"]), str(source["occurrenceDate"])) is None
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE native_schedule_rule_id = %s",
        (source["ruleId"],),
    ) == {"count": 0}


def test_native_completion_accepts_following_day_arrival_inside_overnight_window(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean(overnight=True)

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        return _native_receipt(source, payload)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("arrival_time", "departure_time"),
    [
        (clock_time(8, 59), clock_time(10, 0)),
        (clock_time(11, 0), clock_time(11, 30)),
    ],
)
def test_native_completion_rejects_arrival_outside_the_occurrence_window(
    client,
    auth,
    monkeypatch,
    arrival_time,
    departure_time,
):
    source = _seed_native_first_clean()
    service_date = datetime.fromisoformat(str(source["effectiveDate"])).date()
    arrival_at = datetime.combine(
        service_date, arrival_time, tzinfo=api.APP_TIMEZONE
    ).astimezone(timezone.utc)
    departure_at = datetime.combine(
        service_date, departure_time, tzinfo=api.APP_TIMEZONE
    ).astimezone(timezone.utc)
    db.execute(
        "UPDATE visits SET arrival_time = %s WHERE location_id = %s",
        (arrival_at, source["siteId"]),
    )
    db.execute(
        "UPDATE departures SET departure_time = %s WHERE location_id = %s",
        (departure_at, source["siteId"]),
    )
    db.execute(
        "UPDATE shifts SET clock_in = %s, clock_out = %s WHERE location_id = %s",
        (arrival_at - timedelta(minutes=10), departure_at, source["siteId"]),
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail(
            "out-of-window evidence must not reach Atlas"
        ),
    )

    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_evidence_missing"


def test_native_completion_rejects_unplanned_evidence_outside_the_geofence(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean(geofence_status="outside")
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("outside evidence must not reach Atlas"),
    )

    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_evidence_missing"


def test_cancelled_native_occurrence_cannot_be_confirmed(client, auth, monkeypatch):
    source = _seed_native_first_clean(exception_action="cancelled")
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("cancelled work must not reach Atlas"),
    )

    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_visit_cancelled"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE native_schedule_rule_id = %s",
        (source["ruleId"],),
    ) == {"count": 0}


def test_rescheduled_native_occurrence_uses_its_effective_service_day(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean(exception_action="rescheduled")

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        return _native_receipt(source, payload)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 201, response.text
    assert db.query_one(
        "SELECT scheduled_date, native_occurrence_date FROM jobs WHERE id = %s",
        (response.json()["jobId"],),
    ) == {
        "scheduled_date": datetime.fromisoformat(str(source["effectiveDate"])).date(),
        "native_occurrence_date": datetime.fromisoformat(
            str(source["occurrenceDate"])
        ).date(),
    }
    schedule = client.get(
        "/api/admin/operations/schedule",
        headers=auth,
        params={
            "start_date": source["effectiveDate"],
            "end_date": source["effectiveDate"],
            "planning_source": "native",
        },
    )
    assert schedule.status_code == 200, schedule.text
    site_job = next(
        row
        for row in schedule.json()["jobs"]
        if row["locationId"] == source["siteId"]
    )
    assert site_job["shiftBucket"] == "morning"
    assert site_job["cadence"] == "weekly"
    assert site_job["occurrenceException"]["action"] == "rescheduled"
    assert site_job["occurrenceException"]["scheduledDate"] == source["effectiveDate"]


def test_materialized_native_occurrence_rejects_exception_changes(
    client, auth, monkeypatch
):
    source = _seed_native_first_clean(exception_action="rescheduled")

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        return _native_receipt(source, payload)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    completion = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )
    assert completion.status_code == 201, completion.text

    exception_path = (
        "/api/admin/operations/service-schedule-rules/"
        f"{source['ruleId']}/occurrence-exceptions/{source['occurrenceDate']}"
    )
    changed = client.put(
        exception_path,
        headers=auth,
        json={"action": "cancelled", "reason": "should be rejected"},
    )
    deleted = client.delete(exception_path, headers=auth)

    assert changed.status_code == 409
    assert deleted.status_code == 409
    assert db.query_one(
        "SELECT action, scheduled_date FROM service_schedule_occurrence_exceptions "
        "WHERE rule_id = %s AND service_date = %s",
        (source["ruleId"], source["occurrenceDate"]),
    ) == {
        "action": "rescheduled",
        "scheduled_date": datetime.fromisoformat(str(source["effectiveDate"])).date(),
    }


def test_non_residential_native_occurrence_never_materializes(client, auth, monkeypatch):
    source = _seed_native_first_clean(residential=False)
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: pytest.fail("commercial work must not reach Atlas"),
    )

    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "first_clean_completion_not_eligible"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE native_schedule_rule_id = %s",
        (source["ruleId"],),
    ) == {"count": 0}


def test_native_receipt_with_wrong_service_kind_stays_pending(client, auth, monkeypatch):
    source = _seed_native_first_clean()

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        receipt = _native_receipt(source, payload)
        receipt["trackerServiceKind"] = "planned_visit"
        return receipt

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _native_path(int(source["ruleId"]), str(source["occurrenceDate"])),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 502
    report = _native_report(int(source["ruleId"]), str(source["occurrenceDate"]))
    assert report["state"] == "pending"
    assert report["atlas_receipt_id"] is None


def test_concurrent_native_reservations_share_one_job_and_report(client):
    source = _seed_native_first_clean()
    payload = api.FunnelFirstCleanCompletionRequest(idempotencyKey=uuid.uuid4())
    admin = {
        "id": source["adminId"],
        "name": source["adminName"],
        "role": "admin",
    }

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(
            workers.map(
                lambda _unused: api._reserve_native_first_clean_completion_report(
                    int(source["ruleId"]),
                    datetime.fromisoformat(str(source["occurrenceDate"])).date(),
                    payload,
                    admin,
                ),
                range(2),
            )
        )

    assert sorted(created for _report_row, created in results) == [False, True]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE native_schedule_rule_id = %s "
        "AND native_occurrence_date = %s",
        (source["ruleId"], source["occurrenceDate"]),
    ) == {"count": 1}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_first_clean_completion_reports "
        "WHERE customer_id = %s",
        (source["customerId"],),
    ) == {"count": 1}
