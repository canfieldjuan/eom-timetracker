"""Retirement coverage for employee-schedule arrival reconciliation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import _raw_conn


SCHEDULED_START = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def isolate_reconciliation_history(setup_db):
    def clean() -> None:
        conn = _raw_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM site_check_in_reconciliation_reviews")
            cur.execute("DELETE FROM site_check_ins")
            cur.execute("DELETE FROM site_check_in_schedule_rules")
            cur.execute("DELETE FROM site_check_in_schedules")
        conn.commit()
        conn.close()

    clean()
    yield
    clean()


def insert_retained_history(employee_id: int, location_id: int) -> dict[str, int]:
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO site_check_in_schedules (
                employee_id, location_id, scheduled_start,
                grace_minutes, created_by
            )
            VALUES (%s, %s, %s, 10, %s)
            RETURNING id
            """,
            (employee_id, location_id, SCHEDULED_START, employee_id),
        )
        schedule_id = int(cur.fetchone()[0])
        cur.execute(
            """
            INSERT INTO site_check_in_schedule_rules (
                employee_id, location_id, weekdays, local_start_time,
                timezone, starts_on, grace_minutes, active, created_by
            )
            VALUES (
                %s, %s, ARRAY[0]::SMALLINT[], '07:00',
                'America/Chicago', '2026-07-20', 10, false, %s
            )
            RETURNING id
            """,
            (employee_id, location_id, employee_id),
        )
        rule_id = int(cur.fetchone()[0])
        cur.execute(
            """
            INSERT INTO site_check_in_reconciliation_reviews (
                occurrence_key, evidence_fingerprint, employee_id,
                location_id, scheduled_start, outcome, evidence,
                disposition, note, reviewed_by, reviewed_by_name
            )
            VALUES (
                %s, %s, %s, %s, %s, 'missing_both', %s::jsonb,
                'resolved', 'Retained historical disposition',
                %s, 'Historical Admin'
            )
            RETURNING id
            """,
            (
                f"exact:{schedule_id}",
                "a" * 64,
                employee_id,
                location_id,
                SCHEDULED_START,
                json.dumps(
                    {
                        "employeeId": employee_id,
                        "siteId": location_id,
                        "outcome": "missing_both",
                    }
                ),
                employee_id,
            ),
        )
        review_id = int(cur.fetchone()[0])
    conn.commit()
    conn.close()
    return {
        "schedule_id": schedule_id,
        "rule_id": rule_id,
        "review_id": review_id,
    }


def retained_history_snapshot() -> list[list[tuple]]:
    statements = [
        """
        SELECT id, employee_id, location_id, scheduled_start, grace_minutes,
               created_by, cancelled_at, cancelled_by, cancellation_reason
        FROM site_check_in_schedules
        ORDER BY id
        """,
        """
        SELECT id, employee_id, location_id, weekdays, local_start_time,
               timezone, starts_on, ends_on, grace_minutes, active,
               created_by, created_at, updated_at
        FROM site_check_in_schedule_rules
        ORDER BY id
        """,
        """
        SELECT id, occurrence_key, evidence_fingerprint, employee_id,
               location_id, scheduled_start, outcome, evidence,
               disposition, note, reviewed_by, reviewed_by_name, reviewed_at
        FROM site_check_in_reconciliation_reviews
        ORDER BY id
        """,
    ]
    conn = _raw_conn()
    snapshot = []
    with conn.cursor() as cur:
        for statement in statements:
            cur.execute(statement)
            snapshot.append(cur.fetchall())
    conn.close()
    return snapshot


def test_forward_reconciliation_routes_are_absent_from_registry_and_openapi(
    client, auth
):
    import time_tracker_api

    registered_paths = {
        route.path
        for route in time_tracker_api.app.routes
        if getattr(route, "path", None) is not None
    }
    assert "/api/admin/site-check-in-reconciliation" not in registered_paths
    assert (
        "/api/admin/site-check-in-reconciliation/{occurrence_key}/review"
        not in registered_paths
    )

    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/admin/site-check-in-reconciliation" not in paths
    assert (
        "/api/admin/site-check-in-reconciliation/{occurrence_key}/review"
        not in paths
    )

    assert (
        client.get(
            "/api/admin/site-check-in-reconciliation",
            headers=auth,
            params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/admin/site-check-in-reconciliation/exact:1/review",
            headers=auth,
            json={
                "evidenceFingerprint": "a" * 64,
                "disposition": "resolved",
                "note": "This route is retired",
            },
        ).status_code
        == 404
    )


def test_retired_mutations_preserve_exact_rule_and_review_history(
    client, auth, employee_id, location_id
):
    history_ids = insert_retained_history(employee_id, location_id)
    before = retained_history_snapshot()

    schedules = client.get("/api/admin/site-check-in-schedules", headers=auth)
    assert schedules.status_code == 200, schedules.text
    assert [row["id"] for row in schedules.json()["schedules"]] == [
        history_ids["schedule_id"]
    ]

    rules = client.get(
        "/api/admin/site-check-in-schedule-rules",
        headers=auth,
        params={"activeOnly": "false"},
    )
    assert rules.status_code == 200, rules.text
    assert [row["id"] for row in rules.json()["rules"]] == [
        history_ids["rule_id"]
    ]

    exact_create = client.post(
        "/api/admin/site-check-in-schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "scheduledStart": "2026-07-21T12:00:00Z",
            "graceMinutes": 10,
        },
    )
    assert exact_create.status_code == 405
    exact_delete = client.delete(
        f"/api/admin/site-check-in-schedules/{history_ids['schedule_id']}",
        headers=auth,
    )
    assert exact_delete.status_code == 404

    rule_create = client.post(
        "/api/admin/site-check-in-schedule-rules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "siteId": location_id,
            "weekdays": [0],
            "localStart": "07:00",
            "startsOn": "2026-07-20",
            "graceMinutes": 10,
        },
    )
    assert rule_create.status_code == 405
    rule_delete = client.delete(
        f"/api/admin/site-check-in-schedule-rules/{history_ids['rule_id']}",
        headers=auth,
    )
    assert rule_delete.status_code == 404

    reconciliation = client.get(
        "/api/admin/site-check-in-reconciliation",
        headers=auth,
        params={"fromDate": "2026-07-20", "toDate": "2026-07-20"},
    )
    assert reconciliation.status_code == 404
    review = client.post(
        (
            "/api/admin/site-check-in-reconciliation/"
            f"exact:{history_ids['schedule_id']}/review"
        ),
        headers=auth,
        json={
            "evidenceFingerprint": "a" * 64,
            "disposition": "needs_correction",
            "note": "A retired route cannot append history",
        },
    )
    assert review.status_code == 404

    assert retained_history_snapshot() == before


def test_openapi_keeps_history_reads_but_omits_retired_mutations(client):
    paths = client.get("/openapi.json").json()["paths"]

    assert set(paths["/api/admin/site-check-in-schedules"]) == {"get"}
    assert "/api/admin/site-check-in-schedules/{schedule_id}" not in paths
    assert set(paths["/api/admin/site-check-in-schedule-rules"]) == {"get"}
    assert "/api/admin/site-check-in-schedule-rules/{rule_id}" not in paths


def test_legacy_page_has_no_forward_reconciliation_caller():
    html = (Path(__file__).parent / "timetracker-mobile.html").read_text()

    assert "Arrival vs. Timecard" not in html
    assert "loadArrivalTimecardReconciliation" not in html
    assert "/admin/site-check-in-reconciliation?" not in html
    assert "reviewArrivalTimecardException" not in html
    assert "/admin/site-check-in-reconciliation/${encodedKey}/review" not in html
