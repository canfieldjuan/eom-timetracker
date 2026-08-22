"""Declared policy and execution context for time-producing workflows.

This module is deliberately independent of FastAPI and the database.  The API
registers concrete handlers with :func:`registered_time_action`; the mutation
layer asks :func:`require_registered_time_action_context` before it writes.
That makes an undeclared write fail structurally without turning any declared
location policy into new runtime enforcement.
"""

from __future__ import annotations

import ast
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
import inspect
import re
from types import MappingProxyType
from typing import Callable, Dict, FrozenSet, Iterable, Iterator, Literal, Mapping, Optional, ParamSpec, TypeVar


LocationGateMode = Literal[
    "none",
    "hard_when_enabled",
    "evidence_paid_on_inside",
]
TimeActionWorkflow = Literal["interactive", "correction", "migration"]
TimeMutationCapability = Literal[
    "opens_shift",
    "closes_shift",
    "opens_visit",
    "closes_visit",
]

P = ParamSpec("P")
T = TypeVar("T")
ActionResolver = Callable[..., str]

_DIRECT_TIME_MUTATION_SQL = re.compile(
    r"\b(?:insert\s+into|delete\s+from)\s+(?:shifts|visits|departures|time_data_correction_batches)\b"
)
_PAYROLL_HOUR_CORRECTION_OVERLAY_SQL = re.compile(
    r"\b(?:insert\s+into|delete\s+from|update)\s+payroll_hour_corrections\b"
)
_SQL_EXECUTION_METHODS = frozenset(
    {"execute", "execute_returning", "query_one", "query_all"}
)
_TEMPORAL_UPDATE_COLUMNS = {
    "shifts": frozenset({"clock_in", "clock_out", "total_hours"}),
    "visits": frozenset({"arrival_time"}),
    "departures": frozenset({"departure_time"}),
}
_TIME_MUTATION_CAPABILITIES: FrozenSet[TimeMutationCapability] = frozenset(
    {"opens_shift", "closes_shift", "opens_visit", "closes_visit"}
)
# A production source that writes historical time evidence outside a request
# context must be declared here.  The startup source sweep still examines every
# production module; this closed map makes the one intentional exception
# explicit rather than allowing a module to opt itself out of the guard.
TIME_ACTION_MIGRATION_SOURCE_ACTIONS: Mapping[str, str] = MappingProxyType(
    {"migrate_json_to_pg.py": "legacy-json-import"}
)


@dataclass
class _TimeMutationSourceScope:
    name: str
    guard_lines: list[int]
    sql_bindings: Dict[str, str]


@dataclass(frozen=True)
class TimeActionPolicy:
    """The complete declared policy for one time-producing workflow."""

    action: str
    workflow: TimeActionWorkflow
    opens_shift: bool
    closes_shift: bool
    opens_visit: bool
    closes_visit: bool
    location_gate_mode: LocationGateMode
    weak_or_missing_gps_behavior: str
    exception_method: str
    idempotency_mechanism: str
    audit_target: str
    requires_active_context: bool


@dataclass(frozen=True)
class TimeActionHandlerRegistration:
    """A handler that declares and activates one or more registry actions."""

    handler: str
    action_names: FrozenSet[str]


# CLOSED / ENUMERATED: these are the currently observed interactive writers,
# correction workflows, and data migrations.  Adding a new action means adding
# it here *and* registering its concrete handler below via the decorator.
TIME_ACTION_POLICIES: Mapping[str, TimeActionPolicy] = MappingProxyType(
    {
        "clock-in": TimeActionPolicy(
            action="clock-in",
            workflow="interactive",
            opens_shift=True,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="hard_when_enabled",
            weak_or_missing_gps_behavior="existing GPS override requirement remains in effect",
            exception_method="documented GPS or Home Base exception",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="shifts, plain_time_action_receipts, and Home Base events when applicable",
            requires_active_context=True,
        ),
        "clock-out": TimeActionPolicy(
            action="clock-out",
            workflow="interactive",
            opens_shift=False,
            closes_shift=True,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="existing GPS override requirement remains in effect",
            exception_method="documented GPS or Home Base exception",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="shifts, plain_time_action_receipts, and Home Base events when applicable",
            requires_active_context=True,
        ),
        "arrive": TimeActionPolicy(
            action="arrive",
            workflow="interactive",
            opens_shift=False,
            closes_shift=False,
            opens_visit=True,
            closes_visit=False,
            location_gate_mode="hard_when_enabled",
            weak_or_missing_gps_behavior="existing GPS override requirement remains in effect",
            exception_method="documented GPS override or selected Site evidence",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="visits, plain_time_action_receipts, and visit evidence when applicable",
            requires_active_context=True,
        ),
        "depart": TimeActionPolicy(
            action="depart",
            workflow="interactive",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=True,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="existing GPS override requirement remains in effect",
            exception_method="documented GPS override",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="departures and plain_time_action_receipts",
            requires_active_context=True,
        ),
        "home-base-start": TimeActionPolicy(
            action="home-base-start",
            workflow="interactive",
            opens_shift=True,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="evidence_paid_on_inside",
            weak_or_missing_gps_behavior="reject the QR scan unless GPS confirms Home Base",
            exception_method="none on the QR-scan path",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="shifts, home_base_events, and plain_time_action_receipts",
            requires_active_context=True,
        ),
        "home-base-end": TimeActionPolicy(
            action="home-base-end",
            workflow="interactive",
            opens_shift=False,
            closes_shift=True,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="evidence_paid_on_inside",
            weak_or_missing_gps_behavior="reject the QR scan unless GPS confirms Home Base",
            exception_method="none on the QR-scan path",
            idempotency_mechanism="plain_time_action_receipts by employee and idempotency key",
            audit_target="shifts, home_base_events, and plain_time_action_receipts",
            requires_active_context=True,
        ),
        "site-qr-arrive": TimeActionPolicy(
            action="site-qr-arrive",
            workflow="interactive",
            opens_shift=False,
            closes_shift=False,
            opens_visit=True,
            closes_visit=False,
            location_gate_mode="evidence_paid_on_inside",
            weak_or_missing_gps_behavior="store QR evidence; create no visit unless inside",
            exception_method="none; out-of-geofence scans remain evidence-only review",
            idempotency_mechanism="site_qr_action_receipts by key or scanned time",
            audit_target="site_check_ins, visits, and site_qr_action_receipts",
            requires_active_context=True,
        ),
        "site-qr-depart": TimeActionPolicy(
            action="site-qr-depart",
            workflow="interactive",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=True,
            location_gate_mode="evidence_paid_on_inside",
            weak_or_missing_gps_behavior="store QR evidence; create no departure unless inside",
            exception_method="none; out-of-geofence scans remain evidence-only review",
            idempotency_mechanism="site_qr_action_receipts by key or scanned time",
            audit_target="site_check_ins, departures, and site_qr_action_receipts",
            requires_active_context=True,
        ),
        "site-check-in-evidence": TimeActionPolicy(
            action="site-check-in-evidence",
            workflow="interactive",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="evidence_paid_on_inside",
            weak_or_missing_gps_behavior="store classified Site evidence without a time event",
            exception_method="none",
            idempotency_mechanism="site_check_ins employee, Site, and device timestamp uniqueness",
            audit_target="site_check_ins",
            requires_active_context=True,
        ),
        "admin-entry-adjustment": TimeActionPolicy(
            action="admin-entry-adjustment",
            workflow="correction",
            opens_shift=True,
            closes_shift=True,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to an administrator correction",
            exception_method="administrator correction workflow",
            idempotency_mechanism="none; current entry validation and locking apply",
            audit_target="shifts and access_log_entries",
            requires_active_context=True,
        ),
        "admin-time-data-correction": TimeActionPolicy(
            action="admin-time-data-correction",
            workflow="correction",
            opens_shift=False,
            closes_shift=True,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a reviewed data correction",
            exception_method="signed correction plan and confirmation phrase",
            idempotency_mechanism="locked plan token and source-row concurrency checks",
            audit_target="time_data_correction_batches, shifts, and access_log_entries",
            requires_active_context=True,
        ),
        "admin-utilization-missing-departure-correction": TimeActionPolicy(
            action="admin-utilization-missing-departure-correction",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=True,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a reviewed utilization departure overlay",
            exception_method="administrator correction reason and evidence fingerprint",
            idempotency_mechanism="locked plan token derived from the request idempotency key",
            audit_target="time_data_correction_batches and utilization review overlays",
            requires_active_context=True,
        ),
        "payroll-timesheet-change": TimeActionPolicy(
            action="payroll-timesheet-change",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a payroll overlay correction",
            exception_method="payroll reason and verification-week workflow",
            idempotency_mechanism="payroll request id and request fingerprint",
            audit_target="payroll_timesheet_change_batches and correction tables",
            requires_active_context=True,
        ),
        "payroll-hour-correction": TimeActionPolicy(
            action="payroll-hour-correction",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a payroll-total overlay correction",
            exception_method="payroll reason and verification-week workflow",
            idempotency_mechanism="matching active correction is replayed",
            audit_target="payroll_hour_corrections and access_log_entries",
            requires_active_context=True,
        ),
        "payroll-hour-correction-void": TimeActionPolicy(
            action="payroll-hour-correction-void",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a payroll-total overlay correction",
            exception_method="payroll void reason and verification-week workflow",
            idempotency_mechanism="active correction state and row locking",
            audit_target="payroll_hour_corrections and access_log_entries",
            requires_active_context=True,
        ),
        "payroll-shift-correction": TimeActionPolicy(
            action="payroll-shift-correction",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a payroll overlay correction",
            exception_method="payroll reason and verification-week workflow",
            idempotency_mechanism="matching active correction is replayed",
            audit_target="payroll_shift_corrections and access_log_entries",
            requires_active_context=True,
        ),
        "payroll-shift-correction-void": TimeActionPolicy(
            action="payroll-shift-correction-void",
            workflow="correction",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a payroll overlay correction",
            exception_method="payroll void reason and verification-week workflow",
            idempotency_mechanism="active correction state and row locking",
            audit_target="payroll_shift_corrections and access_log_entries",
            requires_active_context=True,
        ),
        "schema-migration": TimeActionPolicy(
            action="schema-migration",
            workflow="migration",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a server migration",
            exception_method="not applicable",
            idempotency_mechanism="idempotent schema and backfill guards",
            audit_target="database schema and migration markers",
            requires_active_context=False,
        ),
        "legacy-json-import": TimeActionPolicy(
            action="legacy-json-import",
            workflow="migration",
            opens_shift=True,
            closes_shift=True,
            opens_visit=True,
            closes_visit=True,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="historical import preserves recorded values",
            exception_method="not applicable",
            idempotency_mechanism="import upserts and empty-database precondition",
            audit_target="shifts, visits, departures, and import output",
            requires_active_context=False,
        ),
        "post-import-rate-snapshot-backfill": TimeActionPolicy(
            action="post-import-rate-snapshot-backfill",
            workflow="migration",
            opens_shift=False,
            closes_shift=False,
            opens_visit=False,
            closes_visit=False,
            location_gate_mode="none",
            weak_or_missing_gps_behavior="not applicable to a historical backfill",
            exception_method="not applicable",
            idempotency_mechanism="hourly_rate_cents IS NULL guard",
            audit_target="shifts.hourly_rate_cents and migration marker",
            requires_active_context=False,
        ),
    }
)


_ACTIVE_TIME_ACTION: ContextVar[Optional[TimeActionPolicy]] = ContextVar(
    "active_time_action",
    default=None,
)
_HANDLER_REGISTRATIONS: Dict[str, TimeActionHandlerRegistration] = {}


def registered_time_action_handlers() -> Mapping[str, TimeActionHandlerRegistration]:
    """Return a read-only snapshot of the handler declarations."""

    return MappingProxyType(dict(_HANDLER_REGISTRATIONS))


def active_registered_time_action() -> Optional[TimeActionPolicy]:
    """Return the policy active in the current request/workflow context."""

    return _ACTIVE_TIME_ACTION.get()


@contextmanager
def registered_time_action_context(action: str) -> Iterator[TimeActionPolicy]:
    """Activate one declared policy while its writer runs."""

    policy = TIME_ACTION_POLICIES.get(action)
    if policy is None:
        raise RuntimeError(f"Undeclared time action: {action}")
    token = _ACTIVE_TIME_ACTION.set(policy)
    try:
        yield policy
    finally:
        _ACTIVE_TIME_ACTION.reset(token)


def require_registered_time_action_context(
    expected_action: Optional[str] = None,
    *,
    required_capabilities: Iterable[TimeMutationCapability] = (),
) -> TimeActionPolicy:
    """Reject a time mutation outside its declared action or capabilities."""

    policy = _ACTIVE_TIME_ACTION.get()
    if policy is None:
        raise RuntimeError(
            "Time mutation requires an active registered time-action context"
        )
    if not policy.requires_active_context:
        raise RuntimeError(
            "Time mutation cannot use a migration-only time-action context"
        )
    if expected_action is not None and policy.action != expected_action:
        raise RuntimeError(
            "Time mutation action context mismatch: "
            f"expected {expected_action}, active {policy.action}"
        )
    requested_capabilities = frozenset(required_capabilities)
    unknown_capabilities = requested_capabilities - _TIME_MUTATION_CAPABILITIES
    if unknown_capabilities:
        raise RuntimeError(
            "Unknown time mutation capability: "
            + ", ".join(sorted(unknown_capabilities))
        )
    disallowed_capabilities = sorted(
        capability
        for capability in requested_capabilities
        if not getattr(policy, capability)
    )
    if disallowed_capabilities:
        raise RuntimeError(
            f"Time mutation action {policy.action} does not allow capability: "
            + ", ".join(disallowed_capabilities)
        )
    return policy


def registered_time_action(
    *action_names: str,
    resolver: Optional[ActionResolver] = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Register a handler and run it with its resolved action context.

    ``resolver`` is for endpoints such as Site QR and Home Base whose request
    payload selects one of a closed set of already-declared actions.
    """

    normalized_actions = frozenset(str(action_name) for action_name in action_names)
    if not normalized_actions:
        raise ValueError("A registered time action needs at least one action name")
    if len(normalized_actions) != len(action_names):
        raise ValueError("A registered time action cannot declare a duplicate action")
    if resolver is None and len(normalized_actions) != 1:
        raise ValueError("A multi-action handler needs an action resolver")

    def decorate(handler: Callable[P, T]) -> Callable[P, T]:
        handler_name = f"{handler.__module__}.{handler.__qualname__}"
        if handler_name in _HANDLER_REGISTRATIONS:
            raise RuntimeError(f"Time-action handler already registered: {handler_name}")
        _HANDLER_REGISTRATIONS[handler_name] = TimeActionHandlerRegistration(
            handler=handler_name,
            action_names=normalized_actions,
        )

        @wraps(handler)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
            resolved_action = (
                resolver(*args, **kwargs)
                if resolver is not None
                else next(iter(normalized_actions))
            )
            if resolved_action not in normalized_actions:
                raise RuntimeError(
                    f"Time-action resolver returned undeclared action {resolved_action} "
                    f"for {handler_name}"
                )
            with registered_time_action_context(resolved_action):
                return handler(*args, **kwargs)

        # FastAPI 0.115 resolves postponed annotations with the registered
        # callable's globals. ``wrapped`` lives in this module, while the
        # endpoint's request models live in the API module. Preserve an already
        # evaluated signature so supported FastAPI versions see the endpoint's
        # actual annotations rather than registry-module forward references.
        wrapped.__signature__ = inspect.signature(handler, eval_str=True)
        return wrapped

    return decorate


def validate_time_action_registry(
    *,
    policies: Mapping[str, TimeActionPolicy] = TIME_ACTION_POLICIES,
    handlers: Optional[Mapping[str, TimeActionHandlerRegistration]] = None,
) -> None:
    """Fail startup/CI if an action policy or time-producing handler is incomplete."""

    declared_handlers = (
        _HANDLER_REGISTRATIONS if handlers is None else handlers
    )
    errors = []
    allowed_gate_modes = {"none", "hard_when_enabled", "evidence_paid_on_inside"}
    allowed_workflows = {"interactive", "correction", "migration"}

    for action_name, policy in policies.items():
        if action_name != policy.action:
            errors.append(
                f"policy key {action_name} does not match action {policy.action}"
            )
        if policy.workflow not in allowed_workflows:
            errors.append(f"{action_name} has an invalid workflow {policy.workflow}")
        if policy.location_gate_mode not in allowed_gate_modes:
            errors.append(
                f"{action_name} has an invalid location gate {policy.location_gate_mode}"
            )
        for field_name in (
            "weak_or_missing_gps_behavior",
            "exception_method",
            "idempotency_mechanism",
            "audit_target",
        ):
            if not getattr(policy, field_name).strip():
                errors.append(f"{action_name} is missing {field_name}")
        if policy.workflow in {"correction", "migration"} and (
            policy.location_gate_mode != "none"
        ):
            errors.append(f"{action_name} must be non-gated")
        if policy.workflow in {"interactive", "correction"} and not (
            policy.requires_active_context
        ):
            errors.append(
                f"{action_name} must activate the request mutation context"
            )
        if policy.workflow == "migration" and policy.requires_active_context:
            errors.append(f"{action_name} must remain outside the request writer")

    for source_name, action_name in TIME_ACTION_MIGRATION_SOURCE_ACTIONS.items():
        policy = policies.get(action_name)
        if policy is None:
            errors.append(
                f"migration source {source_name} declares unknown action {action_name}"
            )
        elif policy.workflow != "migration" or policy.requires_active_context:
            errors.append(
                f"migration source {source_name} must declare a non-request migration"
            )

    bound_actions: set[str] = set()
    for handler_name, registration in declared_handlers.items():
        if handler_name != registration.handler:
            errors.append(
                f"handler key {handler_name} does not match {registration.handler}"
            )
        if not registration.action_names:
            errors.append(f"handler {handler_name} declares no time action")
        for action_name in registration.action_names:
            if action_name not in policies:
                errors.append(
                    f"handler {handler_name} declares undeclared action {action_name}"
                )
            else:
                bound_actions.add(action_name)

    required_actions = {
        action_name
        for action_name, policy in policies.items()
        if policy.requires_active_context
    }
    unbound_actions = sorted(required_actions - bound_actions)
    if unbound_actions:
        errors.append(
            "registry actions without a context-applying handler: "
            + ", ".join(unbound_actions)
        )

    if errors:
        raise RuntimeError("Time-action registry is incomplete: " + "; ".join(errors))


def _is_direct_time_mutation_sql(sql: str) -> bool:
    """Whether a literal statement creates, deletes, or changes time boundaries."""

    normalized = " ".join(sql.lower().split())
    if (
        _DIRECT_TIME_MUTATION_SQL.search(normalized)
        or _PAYROLL_HOUR_CORRECTION_OVERLAY_SQL.search(normalized)
    ):
        return True
    for table_name, columns in _TEMPORAL_UPDATE_COLUMNS.items():
        if re.search(rf"\bupdate\s+{table_name}\b", normalized) and any(
            re.search(rf"\b{column}\b", normalized) for column in columns
        ):
            return True
    return False


def validate_time_action_mutation_source(
    source: str,
    *,
    migration_action: Optional[str] = None,
) -> None:
    """Reject a direct time-table writer that omits the context guard.

    This intentionally derives writers from direct SQL in production sources
    rather than guessing from FastAPI route shape. A writer that creates/deletes
    a shift, visit, departure, or time-affecting correction overlay—or alters a
    temporal boundary—must establish its registered context unconditionally before
    executing that SQL. A caller may classify one source as a declared
    non-request migration; that exception is validated against the closed policy
    registry. The scanner covers all local SQL execution helpers and resolves
    simple local string bindings first.
    """

    tree = ast.parse(source)
    errors: list[str] = []
    migration_policy = None
    if migration_action is not None:
        migration_policy = TIME_ACTION_POLICIES.get(migration_action)
        if (
            migration_policy is None
            or migration_policy.workflow != "migration"
            or migration_policy.requires_active_context
        ):
            errors.append(
                "source migration action must name a declared non-request "
                f"migration: {migration_action}"
            )
            migration_policy = None

    class DirectTimeMutationVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.function_stack: list[_TimeMutationSourceScope] = []
            self.control_flow_depths: list[int] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_stack.append(_TimeMutationSourceScope(node.name, [], {}))
            self.control_flow_depths.append(0)
            for statement in node.body:
                self.visit(statement)
            self.control_flow_depths.pop()
            self.function_stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def _visit_nested_control_flow(self, node: ast.AST) -> None:
            if not self.function_stack:
                self.generic_visit(node)
                return
            self.control_flow_depths[-1] += 1
            try:
                self.generic_visit(node)
            finally:
                self.control_flow_depths[-1] -= 1

        visit_If = _visit_nested_control_flow
        visit_For = _visit_nested_control_flow
        visit_AsyncFor = _visit_nested_control_flow
        visit_While = _visit_nested_control_flow
        visit_Try = _visit_nested_control_flow
        visit_TryStar = _visit_nested_control_flow
        visit_With = _visit_nested_control_flow
        visit_AsyncWith = _visit_nested_control_flow
        visit_Match = _visit_nested_control_flow

        def _sql_text(self, node: ast.AST) -> Optional[str]:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.Name) and self.function_stack:
                return self.function_stack[-1].sql_bindings.get(node.id)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = self._sql_text(node.left)
                right = self._sql_text(node.right)
                return left + right if left is not None and right is not None else None
            if isinstance(node, ast.JoinedStr):
                parts = []
                for value in node.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        parts.append(value.value)
                    else:
                        parts.append(" ")
                return "".join(parts)
            return None

        def _bind_sql_name(self, target: ast.expr, value: ast.AST) -> None:
            if not self.function_stack or not isinstance(target, ast.Name):
                return
            sql = self._sql_text(value)
            if sql is None:
                self.function_stack[-1].sql_bindings.pop(target.id, None)
            else:
                self.function_stack[-1].sql_bindings[target.id] = sql

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                self._bind_sql_name(target, node.value)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self._bind_sql_name(node.target, node.value)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            if self.function_stack and isinstance(node.target, ast.Name) and isinstance(
                node.op, ast.Add
            ):
                bindings = self.function_stack[-1].sql_bindings
                existing = bindings.get(node.target.id)
                added = self._sql_text(node.value)
                if isinstance(existing, str) and added is not None:
                    bindings[node.target.id] = existing + added
                else:
                    bindings.pop(node.target.id, None)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if (
                self.function_stack
                and self.control_flow_depths[-1] == 0
                and isinstance(node.func, ast.Name)
                and node.func.id == "require_registered_time_action_context"
            ):
                self.function_stack[-1].guard_lines.append(node.lineno)

            sql = (
                self._sql_text(node.args[0])
                if (
                    self.function_stack
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _SQL_EXECUTION_METHODS
                    and node.args
                )
                else None
            )
            if isinstance(sql, str) and _is_direct_time_mutation_sql(sql):
                scope = self.function_stack[-1]
                if migration_policy is None and not any(
                    line < node.lineno for line in scope.guard_lines
                ):
                    errors.append(
                        "direct time mutation without a preceding unconditional "
                        f"registered context guard: {scope.name}:{node.lineno}"
                    )
            self.generic_visit(node)

    DirectTimeMutationVisitor().visit(tree)
    if errors:
        raise RuntimeError("Time-action registry is incomplete: " + "; ".join(errors))
