"""Tracker's evidence-backed first-clean completion bridge stays retry-safe."""

from __future__ import annotations

import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

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


def _seed_first_clean(*, residential: bool = True, closed: bool = True) -> dict[str, object]:
    """Create fake, linked operational evidence without using customer PII."""

    token = uuid.uuid4().hex
    contact_id = str(uuid.uuid4())
    completed_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)
    arrival_at = completed_at - timedelta(hours=1)
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
        ) VALUES (%s, %s, %s, %s, %s, 1, 'finalized', %s)
        """,
        (contact_id, str(uuid.uuid4()), "a" * 64, customer_id, site_id, str(uuid.uuid4())),
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
            VALUES (2, %s, %s, %s)
            RETURNING id
            """,
            (site_id, arrival_at - timedelta(minutes=10), completed_at),
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
        ) VALUES (%s, %s, 2, %s, %s, 'residential_gps', 'inside')
        """,
        (visit_id, shift_id, site_id, planned_visit_id),
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
        "completedAt": api.to_utc_iso(completed_at),
    }


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
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
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
        "reported_by_employee_id": 1,
        "reported_by_name": "Juan Canfield",
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
    admin = {"id": 1, "name": "Juan Canfield", "role": "admin"}

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
