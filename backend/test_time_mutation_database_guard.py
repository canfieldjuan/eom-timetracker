"""Integration coverage for the observe-only database time-mutation boundary."""

from __future__ import annotations

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
    api._ensure_time_mutation_guard_schema()
    api._ensure_time_mutation_guard_schema()

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
