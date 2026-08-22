"""Integration coverage for the observe-only database time-mutation boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import os

import psycopg2

import db
import time_action_registry as registry
import time_tracker_api as api


_EXPECTED_GUARD_TRIGGERS = {
    "trg_observe_time_mutation_shifts_insert",
    "trg_observe_time_mutation_shifts_update",
    "trg_observe_time_mutation_shifts_delete",
    "trg_observe_time_mutation_visits_insert",
    "trg_observe_time_mutation_visits_update",
    "trg_observe_time_mutation_visits_delete",
    "trg_observe_time_mutation_departures_insert",
    "trg_observe_time_mutation_departures_update",
    "trg_observe_time_mutation_departures_delete",
    "trg_observe_time_mutation_correction_batches",
    "trg_observe_time_mutation_hour_corrections",
    "trg_observe_time_mutation_hour_allocations_insert_delete",
    "trg_observe_time_mutation_hour_allocations_update",
    "trg_observe_time_mutation_shift_corrections",
    "trg_observe_time_mutation_manual_shifts",
    "trg_observe_time_mutation_shift_exclusions",
}

_EXPECTED_GUARD_TRIGGER_CAPABILITIES = {
    "trg_observe_time_mutation_shifts_insert": "shift-time-write",
    "trg_observe_time_mutation_shifts_update": "shift-time-write",
    "trg_observe_time_mutation_shifts_delete": "time-evidence-delete",
    "trg_observe_time_mutation_visits_insert": "visit-time-write",
    "trg_observe_time_mutation_visits_update": "visit-time-write",
    "trg_observe_time_mutation_visits_delete": "time-evidence-delete",
    "trg_observe_time_mutation_departures_insert": "departure-time-write",
    "trg_observe_time_mutation_departures_update": "departure-time-write",
    "trg_observe_time_mutation_departures_delete": "time-evidence-delete",
    "trg_observe_time_mutation_correction_batches": "time-correction-batch-write",
    "trg_observe_time_mutation_hour_corrections": "payroll-hour-correction-write",
    "trg_observe_time_mutation_hour_allocations_insert_delete": (
        "payroll-hour-correction-allocation-write"
    ),
    "trg_observe_time_mutation_hour_allocations_update": (
        "payroll-hour-correction-allocation-write"
    ),
    "trg_observe_time_mutation_shift_corrections": "payroll-shift-correction-write",
    "trg_observe_time_mutation_manual_shifts": "payroll-timesheet-overlay-write",
    "trg_observe_time_mutation_shift_exclusions": "payroll-timesheet-overlay-write",
}


def _clear_guard_events() -> None:
    db.execute("DELETE FROM time_mutation_guard_events")


def _guard_events() -> list[dict]:
    return db.query_all(
        """
        SELECT table_name, operation, required_capability, action,
               supplied_capabilities, mode
        FROM time_mutation_guard_events
        ORDER BY id
        """
    )


def _insert_shift(cur, employee_id: int, location_id: int, label: str) -> int:
    cur.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, total_hours, local_date
        )
        VALUES (%s, %s, %s, NOW(), 0, CURRENT_DATE)
        RETURNING id
        """,
        (employee_id, location_id, label),
    )
    return int(cur.fetchone()[0])


def _raw_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def test_observe_guard_records_untagged_bulk_raw_cursor_writer(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    conn = _raw_connection()
    try:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, clock_in, total_hours, local_date
                )
                VALUES (%s, %s, %s, NOW(), 0, CURRENT_DATE)
                """,
                [(employee_id, location_id, "bulk guard proof")],
            )
        conn.commit()
    finally:
        conn.close()

    assert _guard_events() == [
        {
            "table_name": "shifts",
            "operation": "INSERT",
            "required_capability": "shift-time-write",
            "action": "",
            "supplied_capabilities": [],
            "mode": "observe",
        }
    ]


def test_pooled_action_context_matches_capability_and_resets_after_commit(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    with registry.registered_time_action_context("clock-in"):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                _insert_shift(cur, employee_id, location_id, "declared action proof")

    assert _guard_events() == []

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            _insert_shift(cur, employee_id, location_id, "context reset proof")

    assert _guard_events() == [
        {
            "table_name": "shifts",
            "operation": "INSERT",
            "required_capability": "shift-time-write",
            "action": "",
            "supplied_capabilities": [],
            "mode": "observe",
        }
    ]


def test_observe_guard_records_capability_mismatch_without_blocking(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    with registry.registered_time_action_context("clock-in"):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                shift_id = _insert_shift(cur, employee_id, location_id, "mismatch shift")

    _clear_guard_events()
    with registry.registered_time_action_context("clock-in"):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO visits (shift_id, location_id, location_label, arrival_time)
                    VALUES (%s, %s, %s, NOW())
                    """,
                    (shift_id, location_id, "mismatch visit"),
                )

    assert _guard_events() == [
        {
            "table_name": "visits",
            "operation": "INSERT",
            "required_capability": "visit-time-write",
            "action": "clock-in",
            "supplied_capabilities": ["shift-time-write"],
            "mode": "observe",
        }
    ]


def test_observe_guard_records_untagged_temporal_update_and_delete(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    with registry.registered_time_action_context("clock-in"):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                shift_id = _insert_shift(cur, employee_id, location_id, "update delete proof")

    _clear_guard_events()
    conn = _raw_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE shifts
                SET clock_out = clock_in + INTERVAL '1 hour', total_hours = 1
                WHERE id = %s
                """,
                (shift_id,),
            )
            cur.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
        conn.commit()
    finally:
        conn.close()

    assert _guard_events() == [
        {
            "table_name": "shifts",
            "operation": "UPDATE",
            "required_capability": "shift-time-write",
            "action": "",
            "supplied_capabilities": [],
            "mode": "observe",
        },
        {
            "table_name": "shifts",
            "operation": "DELETE",
            "required_capability": "time-evidence-delete",
            "action": "",
            "supplied_capabilities": [],
            "mode": "observe",
        },
    ]


def test_observe_guard_ignores_non_temporal_shift_metadata(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    with registry.registered_time_action_context("clock-in"):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                shift_id = _insert_shift(cur, employee_id, location_id, "metadata shift")

    _clear_guard_events()
    conn = _raw_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE shifts SET location_label = %s WHERE id = %s",
                ("metadata only", shift_id),
            )
        conn.commit()
    finally:
        conn.close()

    assert _guard_events() == []


def test_explicit_migration_context_carries_declared_database_capabilities(
    client,
    employee_id,
    location_id,
) -> None:
    _clear_guard_events()
    conn = _raw_connection()
    try:
        registry.apply_registered_time_action_database_context(
            conn,
            action="legacy-json-import",
        )
        with conn.cursor() as cur:
            shift_id = _insert_shift(cur, employee_id, location_id, "migration shift")
            cur.execute(
                """
                INSERT INTO visits (shift_id, location_id, location_label, arrival_time)
                VALUES (%s, %s, %s, NOW())
                """,
                (shift_id, location_id, "migration visit"),
            )
        conn.commit()
    finally:
        conn.close()

    assert _guard_events() == []


def test_observe_guard_schema_is_idempotent_and_installs_every_target(
    client,
) -> None:
    # Existing deployments created the event table with NOW(). The schema
    # installer must advance that default without rewriting prior evidence.
    db.execute(
        "ALTER TABLE time_mutation_guard_events "
        "ALTER COLUMN observed_at SET DEFAULT NOW()"
    )
    api._ensure_time_mutation_guard_schema()
    api._ensure_time_mutation_guard_schema()

    observed_at_default = db.query_one(
        """
        SELECT pg_get_expr(default_value.adbin, default_value.adrelid) AS expression
        FROM pg_attribute AS attribute
        JOIN pg_attrdef AS default_value
          ON default_value.adrelid = attribute.attrelid
         AND default_value.adnum = attribute.attnum
        WHERE attribute.attrelid = 'time_mutation_guard_events'::regclass
          AND attribute.attname = 'observed_at'
          AND NOT attribute.attisdropped
        """
    )
    assert observed_at_default["expression"] == "clock_timestamp()"

    rows = db.query_all(
        """
        SELECT tgname, pg_get_triggerdef(oid) AS definition
        FROM pg_trigger
        WHERE tgname LIKE 'trg_observe_time_mutation_%%'
          AND NOT tgisinternal
        """
    )
    definitions = {str(row["tgname"]): str(row["definition"]) for row in rows}
    assert set(definitions) == _EXPECTED_GUARD_TRIGGERS
    for trigger_name, capability in _EXPECTED_GUARD_TRIGGER_CAPABILITIES.items():
        assert "observe_time_mutation_guard" in definitions[trigger_name]
        assert capability in definitions[trigger_name]


def test_guard_observation_audit_is_admin_only_bounded_and_read_only(
    client,
    auth,
    emp_auth,
) -> None:
    _clear_guard_events()
    try:
        db.execute(
            """
            INSERT INTO time_mutation_guard_events (
                observed_at,
                mode,
                table_name,
                operation,
                required_capability,
                action,
                supplied_capabilities,
                database_user,
                application_name
            )
            VALUES
                (%s, 'observe', 'shifts', 'INSERT', 'shift-time-write', '',
                 ARRAY[]::TEXT[], 'guard-test', 'older-event'),
                (%s, 'observe', 'visits', 'INSERT', 'visit-time-write', 'clock-in',
                 ARRAY['shift-time-write']::TEXT[], 'guard-test', 'included-event'),
                (%s, 'observe', 'departures', 'DELETE', 'time-evidence-delete', '',
                 ARRAY[]::TEXT[], 'guard-test', 'newest-event')
            """,
            (
                datetime(2024, 1, 1, tzinfo=timezone.utc),
                datetime(2024, 1, 2, tzinfo=timezone.utc),
                datetime(2024, 1, 3, tzinfo=timezone.utc),
            ),
        )
        endpoint = "/api/admin/audits/time-mutation-guard"
        params = {"since": "2024-01-02T00:00:00Z", "limit": 1}

        assert client.get(endpoint, params=params).status_code == 401
        assert client.get(endpoint, params=params, headers=emp_auth).status_code == 403

        before = db.query_one(
            "SELECT COUNT(*) AS count FROM time_mutation_guard_events"
        )["count"]
        access_log_before = db.query_one(
            "SELECT COUNT(*) AS count FROM access_log_entries"
        )["count"]
        response = client.get(endpoint, params=params, headers=auth)
        after = db.query_one(
            "SELECT COUNT(*) AS count FROM time_mutation_guard_events"
        )["count"]
        access_log_after = db.query_one(
            "SELECT COUNT(*) AS count FROM access_log_entries"
        )["count"]

        assert response.status_code == 200, response.text
        assert before == after == 3
        assert access_log_after == access_log_before
        payload = response.json()
        assert payload["databaseReadOnly"] is True
        assert payload["window"]["observedSince"] == "2024-01-02T00:00:00Z"
        assert payload["summary"] == {
            "eventCount": 2,
            "firstObservedAt": "2024-01-02T00:00:00Z",
            "latestObservedAt": "2024-01-03T00:00:00Z",
        }
        assert payload["eventsTruncated"] is True
        assert isinstance(payload["nextCursor"], str)
        assert len(payload["events"]) == 1
        event = payload["events"][0]
        assert isinstance(event["id"], int)
        assert {key: value for key, value in event.items() if key != "id"} == {
            "observedAt": "2024-01-03T00:00:00Z",
            "mode": "observe",
            "tableName": "departures",
            "operation": "DELETE",
            "requiredCapability": "time-evidence-delete",
            "action": "",
            "suppliedCapabilities": [],
            "databaseUser": "guard-test",
            "applicationName": "newest-event",
        }

        next_response = client.get(
            endpoint,
            params={
                "since": params["since"],
                "limit": 1,
                "cursor": payload["nextCursor"],
            },
            headers=auth,
        )
        assert next_response.status_code == 200, next_response.text
        next_payload = next_response.json()
        assert next_payload["window"] == payload["window"]
        assert next_payload["summary"] == payload["summary"]
        assert next_payload["eventsTruncated"] is False
        assert next_payload["nextCursor"] is None
        assert len(next_payload["events"]) == 1
        assert next_payload["events"][0]["applicationName"] == "included-event"
        assert next_payload["events"][0]["id"] != event["id"]

        cursor = payload["nextCursor"]
        tampered_cursor = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
        tampered = client.get(
            endpoint,
            params={"since": params["since"], "limit": 1, "cursor": tampered_cursor},
            headers=auth,
        )
        assert tampered.status_code == 400

        invalid = client.get(
            endpoint,
            params={"since": "2024-01-02T00:00:00", "limit": 1},
            headers=auth,
        )
        assert invalid.status_code == 400

        future = client.get(
            endpoint,
            params={"since": "2099-01-01T00:00:00Z", "limit": 1},
            headers=auth,
        )
        assert future.status_code == 400
    finally:
        _clear_guard_events()


def test_guard_observation_preserves_fractional_window_boundaries(
    client,
    auth,
) -> None:
    _clear_guard_events()
    try:
        db.execute(
            """
            INSERT INTO time_mutation_guard_events (
                observed_at,
                mode,
                table_name,
                operation,
                required_capability,
                action,
                supplied_capabilities,
                database_user,
                application_name
            )
            VALUES
                (%s, 'observe', 'shifts', 'INSERT', 'shift-time-write', '',
                 ARRAY[]::TEXT[], 'guard-test', 'excluded-fraction'),
                (%s, 'observe', 'visits', 'INSERT', 'visit-time-write', '',
                 ARRAY[]::TEXT[], 'guard-test', 'included-fraction')
            """,
            (
                datetime(2024, 1, 2, 0, 0, 0, 500_000, tzinfo=timezone.utc),
                datetime(2024, 1, 2, 0, 0, 0, 900_000, tzinfo=timezone.utc),
            ),
        )
        response = client.get(
            "/api/admin/audits/time-mutation-guard",
            params={"since": "2024-01-02T00:00:00.900Z"},
            headers=auth,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["window"]["observedSince"] == "2024-01-02T00:00:00.900000Z"
        assert payload["summary"] == {
            "eventCount": 1,
            "firstObservedAt": "2024-01-02T00:00:00.900000Z",
            "latestObservedAt": "2024-01-02T00:00:00.900000Z",
        }
        assert [event["applicationName"] for event in payload["events"]] == [
            "included-fraction"
        ]
    finally:
        _clear_guard_events()


def test_guard_observation_late_writer_stays_in_the_next_window(
    client,
) -> None:
    _clear_guard_events()
    writer = _raw_connection()
    try:
        with writer.cursor() as cur:
            # Establish the writer transaction before the first audit. With the
            # old NOW() default, its later event would sort before the returned
            # audit cutoff and disappear from the next incremental window.
            cur.execute("SELECT NOW()")
            first_report = api.build_time_mutation_guard_observation(
                datetime(2024, 1, 1, tzinfo=timezone.utc),
                limit=100,
            )
            assert first_report["summary"]["eventCount"] == 0
            cur.execute(
                """
                INSERT INTO time_mutation_guard_events (
                    mode,
                    table_name,
                    operation,
                    required_capability,
                    action,
                    supplied_capabilities,
                    database_user,
                    application_name
                )
                VALUES (
                    'observe', 'shifts', 'INSERT', 'shift-time-write', '',
                    ARRAY[]::TEXT[], 'guard-test', 'late-writer'
                )
                """
            )
        writer.commit()

        next_since = api._parse_time_mutation_guard_timestamp(
            first_report["window"]["observedUntil"],
            field_name="since",
        )
        stored_event = db.query_one(
            "SELECT observed_at FROM time_mutation_guard_events "
            "WHERE application_name = %s",
            ("late-writer",),
        )
        assert stored_event["observed_at"] >= next_since

        next_report = api.build_time_mutation_guard_observation(next_since, limit=100)
        assert next_report["summary"]["eventCount"] == 1
        assert [event["applicationName"] for event in next_report["events"]] == [
            "late-writer"
        ]
    finally:
        writer.close()
        _clear_guard_events()


def test_guard_observation_retries_while_a_guard_event_write_is_in_progress(
    client,
    auth,
) -> None:
    _clear_guard_events()
    writer = _raw_connection()
    try:
        with writer.cursor() as cur:
            cur.execute(
                """
                INSERT INTO time_mutation_guard_events (
                    mode,
                    table_name,
                    operation,
                    required_capability,
                    action,
                    supplied_capabilities,
                    database_user,
                    application_name
                )
                VALUES (
                    'observe', 'shifts', 'INSERT', 'shift-time-write', '',
                    ARRAY[]::TEXT[], 'guard-test', 'uncommitted-event'
                )
                """
            )
            response = client.get(
                "/api/admin/audits/time-mutation-guard",
                params={"since": "2024-01-01T00:00:00Z"},
                headers=auth,
            )
            assert response.status_code == 503
        writer.rollback()
    finally:
        writer.close()
        _clear_guard_events()
