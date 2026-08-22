"""Structural contract tests for the Geofence C4 time-action registry."""

from __future__ import annotations

from dataclasses import replace
import inspect

import pytest

import time_action_registry as registry
import time_tracker_api as api


# workflow, shift/visit transitions, location-gate mode, and the distinctive
# idempotency/audit/exception behavior observed on each live route.
EXPECTED_RUNTIME_POLICIES = {
    "clock-in": ("interactive", True, False, False, False, "hard_when_enabled", "plain_time_action_receipts", "shifts", "GPS override", "Home Base"),
    "clock-out": ("interactive", False, True, False, False, "none", "plain_time_action_receipts", "shifts", "GPS override", "Home Base"),
    "arrive": ("interactive", False, False, True, False, "hard_when_enabled", "plain_time_action_receipts", "visits", "GPS override", "Site evidence"),
    "depart": ("interactive", False, False, False, True, "none", "plain_time_action_receipts", "departures", "GPS override", "GPS override"),
    "home-base-start": ("interactive", True, False, False, False, "evidence_paid_on_inside", "plain_time_action_receipts", "home_base_events", "QR scan", "none"),
    "home-base-end": ("interactive", False, True, False, False, "evidence_paid_on_inside", "plain_time_action_receipts", "home_base_events", "QR scan", "none"),
    "site-qr-arrive": ("interactive", False, False, True, False, "evidence_paid_on_inside", "site_qr_action_receipts", "site_check_ins", "no visit", "evidence-only"),
    "site-qr-depart": ("interactive", False, False, False, True, "evidence_paid_on_inside", "site_qr_action_receipts", "site_check_ins", "no departure", "evidence-only"),
    "site-check-in-evidence": ("interactive", False, False, False, False, "evidence_paid_on_inside", "site_check_ins", "site_check_ins", "without a time event", "none"),
    "admin-entry-adjustment": ("correction", True, True, False, False, "none", "none", "shifts", "administrator correction", "administrator correction"),
    "admin-direct-clock-in": ("correction", True, False, False, False, "none", "admin_direct_time_action_receipts", "shifts", "administrator records", "server time only"),
    "admin-direct-arrive": ("correction", False, False, True, False, "none", "admin_direct_time_action_receipts", "visits", "administrator records", "server time only"),
    "admin-time-data-correction": ("correction", False, True, False, False, "none", "plan token", "time_data_correction_batches", "reviewed data correction", "confirmation phrase"),
    "admin-utilization-missing-departure-correction": ("correction", False, False, False, True, "none", "plan token", "time_data_correction_batches", "utilization departure overlay", "evidence fingerprint"),
    "payroll-timesheet-change": ("correction", False, False, False, False, "none", "request id", "payroll_timesheet_change_batches", "payroll overlay", "payroll reason"),
    "payroll-hour-correction": ("correction", False, False, False, False, "none", "matching active correction", "payroll_hour_corrections", "payroll-total overlay", "payroll reason"),
    "payroll-hour-correction-void": ("correction", False, False, False, False, "none", "active correction state", "payroll_hour_corrections", "payroll-total overlay", "payroll void reason"),
    "payroll-hour-correction-allocation": ("correction", False, False, False, False, "none", "matching active allocation", "payroll_hour_correction_allocations", "payroll allocation correction", "payroll allocation reason"),
    "payroll-hour-correction-allocation-void": ("correction", False, False, False, False, "none", "active allocation state", "payroll_hour_correction_allocations", "payroll allocation correction", "payroll allocation void reason"),
    "payroll-shift-correction": ("correction", False, False, False, False, "none", "matching active correction", "payroll_shift_corrections", "payroll overlay", "payroll reason"),
    "payroll-shift-correction-void": ("correction", False, False, False, False, "none", "active correction state", "payroll_shift_corrections", "payroll overlay", "payroll void reason"),
}

EXPECTED_RUNTIME_HANDLERS = {
    "time_tracker_api.record_home_base_scan": frozenset(
        {"home-base-start", "home-base-end"}
    ),
    "time_tracker_api.record_site_check_in": frozenset(
        {"site-qr-arrive", "site-qr-depart", "site-check-in-evidence"}
    ),
    "time_tracker_api.clock_in": frozenset({"clock-in"}),
    "time_tracker_api.clock_out": frozenset({"clock-out"}),
    "time_tracker_api.log_visit": frozenset({"arrive"}),
    "time_tracker_api.depart_location": frozenset({"depart"}),
    "time_tracker_api.admin_adjust_entry": frozenset({"admin-entry-adjustment"}),
    "time_tracker_api.admin_direct_record_time_action": frozenset(
        {"admin-direct-clock-in", "admin-direct-arrive"}
    ),
    "time_tracker_api.admin_apply_time_data_correction": frozenset(
        {"admin-time-data-correction"}
    ),
    "operations_schedule.build_operations_schedule_router.<locals>.correct_utilization_missing_departure": frozenset(
        {"admin-utilization-missing-departure-correction"}
    ),
    "time_tracker_api.admin_apply_payroll_timesheet_changes": frozenset(
        {"payroll-timesheet-change"}
    ),
    "time_tracker_api.admin_create_payroll_hour_correction": frozenset(
        {"payroll-hour-correction"}
    ),
    "time_tracker_api.admin_void_payroll_hour_correction": frozenset(
        {"payroll-hour-correction-void"}
    ),
    "time_tracker_api.admin_allocate_payroll_hour_correction": frozenset(
        {"payroll-hour-correction-allocation"}
    ),
    "time_tracker_api.admin_void_payroll_hour_correction_allocation": frozenset(
        {"payroll-hour-correction-allocation-void"}
    ),
    "time_tracker_api.admin_create_payroll_shift_correction": frozenset(
        {"payroll-shift-correction"}
    ),
    "time_tracker_api.admin_void_payroll_shift_correction": frozenset(
        {"payroll-shift-correction-void"}
    ),
}

EXPECTED_DATABASE_MUTATION_CAPABILITIES = {
    "clock-in": frozenset({"shift-time-write"}),
    "clock-out": frozenset({"shift-time-write"}),
    "arrive": frozenset({"visit-time-write"}),
    "depart": frozenset({"departure-time-write"}),
    "home-base-start": frozenset({"shift-time-write"}),
    "home-base-end": frozenset({"shift-time-write"}),
    "site-qr-arrive": frozenset({"visit-time-write"}),
    "site-qr-depart": frozenset({"departure-time-write"}),
    "site-check-in-evidence": frozenset(),
    "admin-entry-adjustment": frozenset({"shift-time-write"}),
    "admin-direct-clock-in": frozenset({"shift-time-write"}),
    "admin-direct-arrive": frozenset({"visit-time-write"}),
    "admin-time-data-correction": frozenset(
        {
            "shift-time-write",
            "time-evidence-delete",
            "time-correction-batch-write",
            "payroll-timesheet-overlay-write",
            "payroll-shift-correction-write",
        }
    ),
    "admin-utilization-missing-departure-correction": frozenset(
        {"time-correction-batch-write"}
    ),
    "payroll-timesheet-change": frozenset(
        {
            "payroll-timesheet-overlay-write",
            "payroll-hour-correction-write",
            "payroll-hour-correction-allocation-write",
            "payroll-shift-correction-write",
        }
    ),
    "payroll-hour-correction": frozenset(
        {
            "payroll-hour-correction-write",
            "payroll-hour-correction-allocation-write",
        }
    ),
    "payroll-hour-correction-void": frozenset(
        {
            "payroll-hour-correction-write",
            "payroll-hour-correction-allocation-write",
        }
    ),
    "payroll-hour-correction-allocation": frozenset(
        {"payroll-hour-correction-allocation-write"}
    ),
    "payroll-hour-correction-allocation-void": frozenset(
        {"payroll-hour-correction-allocation-write"}
    ),
    "payroll-shift-correction": frozenset({"payroll-shift-correction-write"}),
    "payroll-shift-correction-void": frozenset(
        {"payroll-shift-correction-write"}
    ),
    "schema-migration": frozenset(),
    "legacy-json-import": frozenset(
        {"shift-time-write", "visit-time-write"}
    ),
    "post-import-rate-snapshot-backfill": frozenset(),
}


def test_startup_time_action_registry_is_complete() -> None:
    registry.validate_time_action_registry()
    api._validate_production_time_action_sources()


def test_startup_completeness_gate_rejects_handler_for_undeclared_policy() -> None:
    handlers = dict(registry.registered_time_action_handlers())
    handlers["synthetic.time_producing_route"] = registry.TimeActionHandlerRegistration(
        handler="synthetic.time_producing_route",
        action_names=frozenset({"synthetic-time-mutation"}),
    )

    with pytest.raises(RuntimeError, match="synthetic-time-mutation"):
        registry.validate_time_action_registry(handlers=handlers)


def test_startup_completeness_gate_rejects_unknown_database_capability() -> None:
    policies = dict(registry.TIME_ACTION_POLICIES)
    policies["clock-in"] = replace(
        policies["clock-in"],
        database_mutation_capabilities=frozenset({"unknown-database-capability"}),
    )

    with pytest.raises(RuntimeError, match="unknown database mutation capability"):
        registry.validate_time_action_registry(policies=policies)


def test_startup_completeness_gate_rejects_unguarded_direct_time_writer() -> None:
    source = """
def synthetic_time_writer():
    db.execute('INSERT INTO shifts (employee_id) VALUES (1)')
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_time_writer:3",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_rejects_module_scope_time_writer() -> None:
    source = """
db.execute('INSERT INTO shifts (employee_id) VALUES (1)')
"""

    with pytest.raises(RuntimeError, match=r"<module>:2"):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_rejects_conditionally_guarded_writer() -> None:
    source = """
def conditional_time_writer(enabled):
    if enabled:
        require_registered_time_action_context()
    db.execute('INSERT INTO shifts (employee_id) VALUES (1)')
"""

    with pytest.raises(
        RuntimeError,
        match="conditional_time_writer:5",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_rejects_short_circuited_guard() -> None:
    source = """
def short_circuited_time_writer(enabled):
    enabled and require_registered_time_action_context()
    db.execute('INSERT INTO shifts (employee_id) VALUES (1)')
"""

    with pytest.raises(
        RuntimeError,
        match="short_circuited_time_writer:4",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_rejects_unguarded_time_correction_overlay() -> None:
    source = """
def synthetic_time_correction_overlay():
    db.execute("INSERT INTO time_data_correction_batches (plan_token) VALUES ('x')")
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_time_correction_overlay:3",
    ):
        registry.validate_time_action_mutation_source(source)


@pytest.mark.parametrize(
    "table_name",
    (
        "payroll_hour_corrections",
        "payroll_hour_correction_allocations",
        "payroll_shift_corrections",
        "payroll_manual_shift_versions",
        "payroll_shift_exclusions",
    ),
)
def test_startup_completeness_gate_rejects_unguarded_payroll_overlay_insert(
    table_name: str,
) -> None:
    source = f"""
def synthetic_payroll_overlay_insert():
    db.execute(\"INSERT INTO {table_name} (id) VALUES (1)\")
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_payroll_overlay_insert:3",
    ):
        registry.validate_time_action_mutation_source(source)


@pytest.mark.parametrize(
    "table_name",
    (
        "payroll_hour_corrections",
        "payroll_hour_correction_allocations",
        "payroll_shift_corrections",
        "payroll_manual_shift_versions",
        "payroll_shift_exclusions",
    ),
)
def test_startup_completeness_gate_rejects_unguarded_payroll_overlay_update(
    table_name: str,
) -> None:
    source = f"""
def synthetic_payroll_overlay_update():
    db.execute(\"UPDATE {table_name} SET status = 'voided'\")
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_payroll_overlay_update:3",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_allows_only_declared_migration_sources() -> None:
    source = """
def import_legacy_time_data():
    cur.execute('INSERT INTO shifts (employee_id) VALUES (1)')
"""

    registry.validate_time_action_mutation_source(
        source,
        migration_action="legacy-json-import",
    )
    registry.validate_time_action_mutation_source(
        "db.execute('INSERT INTO shifts (employee_id) VALUES (1)')",
        migration_action="legacy-json-import",
    )

    with pytest.raises(
        RuntimeError,
        match="declared non-request migration: clock-in",
    ):
        registry.validate_time_action_mutation_source(
            source,
            migration_action="clock-in",
        )


def test_startup_completeness_gate_rejects_execute_returning_time_writer() -> None:
    source = """
def synthetic_returning_time_writer():
    db.execute_returning('INSERT INTO shifts (employee_id) VALUES (1) RETURNING id')
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_returning_time_writer:3",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_resolves_local_sql_before_classifying() -> None:
    source = """
def synthetic_bound_time_writer():
    statement = 'INSERT INTO ' + 'shifts (employee_id) VALUES (1)'
    db.execute(statement)
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_bound_time_writer:4",
    ):
        registry.validate_time_action_mutation_source(source)


@pytest.mark.parametrize("executor", ("query_one", "query_all", "executemany"))
def test_startup_completeness_gate_checks_every_local_sql_executor(
    executor: str,
) -> None:
    source = f"""
def synthetic_{executor}_time_writer():
    db.{executor}('DELETE FROM shifts WHERE id = 1 RETURNING id')
"""

    with pytest.raises(
        RuntimeError,
        match=rf"synthetic_{executor}_time_writer:3",
    ):
        registry.validate_time_action_mutation_source(source)


def test_startup_completeness_gate_checks_local_sql_wrappers() -> None:
    source = """
def query_rows(sql, cursor=None):
    if cursor is None:
        return db.query_all(sql)
    cursor.execute(sql)

def synthetic_wrapped_time_writer():
    query_rows('DELETE FROM shifts WHERE id = 1 RETURNING id')
"""

    with pytest.raises(
        RuntimeError,
        match="synthetic_wrapped_time_writer:8",
    ):
        registry.validate_time_action_mutation_source(source)


def test_registered_routes_preserve_evaluated_api_model_annotations() -> None:
    signature = inspect.signature(api.record_home_base_scan)

    assert signature.parameters["payload"].annotation is api.HomeBaseActionRequest
    assert not isinstance(signature.return_annotation, str)


def test_multi_action_handler_must_declare_its_resolver() -> None:
    with pytest.raises(ValueError, match="needs an action resolver"):
        registry.registered_time_action("clock-in", "clock-out")


def test_registered_time_action_rejects_async_handler_before_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_HANDLER_REGISTRATIONS", {})

    async def synthetic_handler() -> None:
        return None

    with pytest.raises(TypeError, match="does not support async handlers"):
        registry.registered_time_action("clock-in")(synthetic_handler)

    assert registry.registered_time_action_handlers() == {}


def test_identical_handler_registration_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_HANDLER_REGISTRATIONS", {})

    def build_handler() -> None:
        @registry.registered_time_action("clock-in")
        def synthetic_handler() -> None:
            return None

    build_handler()
    build_handler()

    handlers = registry.registered_time_action_handlers()
    assert len(handlers) == 1
    assert next(iter(handlers.values())).action_names == frozenset({"clock-in"})


def test_conflicting_handler_registration_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_HANDLER_REGISTRATIONS", {})

    def build_handler(action: str) -> None:
        @registry.registered_time_action(action)
        def synthetic_handler() -> None:
            return None

    build_handler("clock-in")
    with pytest.raises(RuntimeError, match="conflicting actions"):
        build_handler("clock-out")


def test_runtime_writers_are_all_registered_with_their_closed_action_set() -> None:
    handlers = registry.registered_time_action_handlers()
    assert set(handlers) == set(EXPECTED_RUNTIME_HANDLERS)
    for handler_name, expected_actions in EXPECTED_RUNTIME_HANDLERS.items():
        assert handlers[handler_name].action_names == expected_actions


def test_mutation_layer_rejects_missing_registered_action_context() -> None:
    with pytest.raises(RuntimeError, match="active registered time-action context"):
        api.update_timesheets(
            lambda _timesheet_data: (False, None),
            required_capabilities=frozenset({"opens_shift"}),
        )

    with pytest.raises(RuntimeError, match="active registered time-action context"):
        api._save_timesheets_to_db(
            {},
            set(),
            {},
            {},
            pre_shift_boundaries={},
            required_capabilities=frozenset({"opens_shift"}),
        )

    with registry.registered_time_action_context("schema-migration"):
        with pytest.raises(RuntimeError, match="migration-only"):
            api._save_timesheets_to_db(
                {},
                set(),
                {},
                {},
                pre_shift_boundaries={},
                required_capabilities=frozenset({"opens_shift"}),
            )

    with registry.registered_time_action_context("clock-in"):
        with pytest.raises(RuntimeError, match="expected arrive, active clock-in"):
            api.update_timesheets_for_plain_time_action(
                "arrive",
                None,
                {},
                lambda _timesheet_data: (False, None),
                lambda _result, _timesheet_data: {},
            )


def test_mutation_layer_rejects_a_policy_without_the_requested_capability() -> None:
    with registry.registered_time_action_context("site-check-in-evidence"):
        with pytest.raises(
            RuntimeError,
            match="site-check-in-evidence does not allow capability: opens_shift",
        ):
            registry.require_registered_time_action_context(
                required_capabilities=frozenset({"opens_shift"})
            )


def test_time_persistence_rejects_an_undeclared_appended_mutation_kind() -> None:
    with registry.registered_time_action_context("admin-entry-adjustment"):
        with pytest.raises(
            RuntimeError,
            match="capability declaration omits: opens_visit",
        ):
            api._save_timesheets_to_db(
                {"entries": [{"id": 1, "visits": [{}], "departures": []}]},
                {1},
                {1: 0},
                {1: 0},
                pre_shift_boundaries={1: (None, None)},
                required_capabilities=frozenset({"opens_shift"}),
            )


def test_time_persistence_rechecks_capabilities_after_a_pre_save_hook() -> None:
    entry = {"id": 1, "visits": [], "departures": []}

    def append_visit(_cur) -> None:
        entry["visits"].append({})

    with registry.registered_time_action_context("admin-entry-adjustment"):
        with pytest.raises(
            RuntimeError,
            match="capability declaration omits: opens_visit",
        ):
            api._save_timesheets_to_db(
                {"entries": [entry]},
                {1},
                {1: 0},
                {1: 0},
                pre_shift_boundaries={1: (None, None)},
                required_capabilities=frozenset({"opens_shift"}),
                before_save=append_visit,
            )


def test_runtime_policy_fields_match_the_current_time_action_contract() -> None:
    assert set(EXPECTED_RUNTIME_POLICIES) == {
        action_name
        for action_name, policy in registry.TIME_ACTION_POLICIES.items()
        if policy.requires_active_context
    }

    for action_name, expected in EXPECTED_RUNTIME_POLICIES.items():
        (
            workflow,
            opens_shift,
            closes_shift,
            opens_visit,
            closes_visit,
            location_gate_mode,
            idempotency_fragment,
            audit_fragment,
            gps_fragment,
            exception_fragment,
        ) = expected
        policy = registry.TIME_ACTION_POLICIES[action_name]
        assert policy.action == action_name
        assert (
            policy.workflow,
            policy.opens_shift,
            policy.closes_shift,
            policy.opens_visit,
            policy.closes_visit,
            policy.location_gate_mode,
        ) == (
            workflow,
            opens_shift,
            closes_shift,
            opens_visit,
            closes_visit,
            location_gate_mode,
        )
        assert idempotency_fragment in policy.idempotency_mechanism
        assert audit_fragment in policy.audit_target
        assert gps_fragment in policy.weak_or_missing_gps_behavior
        assert exception_fragment in policy.exception_method


def test_runtime_policy_database_capabilities_match_the_guard_contract() -> None:
    assert {
        action_name: policy.database_mutation_capabilities
        for action_name, policy in registry.TIME_ACTION_POLICIES.items()
    } == EXPECTED_DATABASE_MUTATION_CAPABILITIES


def test_migration_policies_are_declared_and_explicitly_non_gated() -> None:
    migration_actions = {
        "schema-migration",
        "legacy-json-import",
        "post-import-rate-snapshot-backfill",
    }
    assert migration_actions == {
        action_name
        for action_name, policy in registry.TIME_ACTION_POLICIES.items()
        if policy.workflow == "migration"
    }
    assert all(
        registry.TIME_ACTION_POLICIES[action_name].location_gate_mode == "none"
        and not registry.TIME_ACTION_POLICIES[action_name].requires_active_context
        for action_name in migration_actions
    )
    assert dict(registry.TIME_ACTION_MIGRATION_SOURCE_ACTIONS) == {
        "migrate_json_to_pg.py": "legacy-json-import"
    }
