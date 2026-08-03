"""Unit coverage for the pure planned-visit planning contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from planned_visits import (
    EmployeeRecord,
    ExistingPlannedVisit,
    LocationRecord,
    PlanningContractError,
    SourceOccurrence,
    StalePreviewError,
    UnresolvedPreviewError,
    build_apply_actions,
    build_preview,
    find_soft_time_overlaps,
    normalize_match_text,
    occurrence_fingerprint,
    resolve_employee_name,
    resolve_location,
    source_set_fingerprint,
)


UTC = timezone.utc
START = datetime(2026, 7, 20, 13, 0, tzinfo=UTC)


def occurrence(
    event_id: str,
    *,
    title: str = "Acme",
    start: datetime = START,
    end: datetime | None = None,
    occurrence_id: str | None = None,
    match_hints: tuple[str, ...] = (),
    cancelled: bool = False,
    revision: str = "rev-1",
) -> SourceOccurrence:
    return SourceOccurrence(
        calendar_id="calendar-1",
        event_id=event_id,
        occurrence_id=occurrence_id,
        title=title,
        starts_at=start,
        ends_at=end or start + timedelta(hours=1),
        match_hints=match_hints,
        cancelled=cancelled,
        revision=revision,
    )


def tombstone(event_id: str, *, occurrence_id: str | None = None) -> SourceOccurrence:
    return SourceOccurrence(
        calendar_id="calendar-1",
        event_id=event_id,
        occurrence_id=occurrence_id,
        title="",
        starts_at=None,
        ends_at=None,
        cancelled=True,
        revision="cancelled-rev",
    )


def locations() -> tuple[LocationRecord, ...]:
    return (
        LocationRecord(1, "100 Main St", "Acme"),
        LocationRecord(2, "200 Oak St", "Acme"),
        LocationRecord(3, "300 Pine St", "Beta"),
        LocationRecord(4, "400 Closed St", "Closed Customer", active=False),
    )


def existing_for(
    source: SourceOccurrence,
    *,
    visit_id: int = 10,
    location_id: int = 1,
    employee_ids: tuple[int, ...] = (11,),
    cancelled: bool = False,
    fingerprint: str | None = None,
) -> ExistingPlannedVisit:
    return ExistingPlannedVisit(
        planned_visit_id=visit_id,
        source_key=source.source_key,
        source_fingerprint=fingerprint or occurrence_fingerprint(source),
        location_id=location_id,
        assigned_employee_ids=employee_ids,
        cancelled=cancelled,
    )


def test_matching_is_exact_normalized_and_unique_only():
    rows = locations()

    ambiguous = resolve_location(["  ACME  "], reversed(rows))
    unique_address = resolve_location([" 300   PINE ST "], rows)
    missing = resolve_location(["Pine"], rows)
    inactive_only = resolve_location(["Closed Customer"], rows)

    assert (
        normalize_match_text("  Caf\N{LATIN SMALL LETTER E WITH ACUTE}  Team ")
        == "caf\N{LATIN SMALL LETTER E WITH ACUTE} team"
    )
    assert ambiguous.status == "unresolved"
    assert ambiguous.reason == "ambiguous"
    assert ambiguous.candidate_ids == (1, 2)
    assert unique_address.resolved is True
    assert unique_address.location_id == 3
    assert missing.reason == "no_match"
    assert inactive_only.reason == "no_match"


def test_location_matching_rejects_conflicting_snapshots_for_one_id():
    with pytest.raises(PlanningContractError, match="conflicting snapshots"):
        resolve_location(
            ["Acme"],
            [
                LocationRecord(1, "100 Main St", "Acme"),
                LocationRecord(1, "DIFFERENT", "Acme"),
            ],
        )


@pytest.mark.parametrize(
    ("requested", "expected_status", "expected_id", "candidate_ids"),
    [
        ("Carmen", "resolved", 1, (1,)),
        ("Pamela", "inactive", None, (2,)),
        ("Tina", "ambiguous", None, (3, 4)),
        ("Missing", "missing", None, ()),
    ],
)
def test_employee_resolution_surfaces_every_non_unique_state(
    requested,
    expected_status,
    expected_id,
    candidate_ids,
):
    employees = [
        EmployeeRecord(4, " TINA "),
        EmployeeRecord(2, "Pamela", active=False),
        EmployeeRecord(1, "Carmen"),
        EmployeeRecord(3, "Tina"),
    ]

    resolution = resolve_employee_name(requested, employees)

    assert resolution.status == expected_status
    assert resolution.employee_id == expected_id
    assert resolution.candidate_ids == candidate_ids


def test_source_identity_distinguishes_recurring_occurrences():
    first = occurrence("series", occurrence_id="2026-07-20T13:00:00Z")
    second = occurrence("series", occurrence_id="2026-07-27T13:00:00Z")

    assert first.source_key != second.source_key
    assert occurrence_fingerprint(first) != occurrence_fingerprint(second)


def test_service_date_uses_calendar_timezone_not_utc_date():
    late_chicago = replace(
        occurrence(
            "late-chicago",
            start=datetime(2026, 7, 21, 1, 0, tzinfo=UTC),
            end=datetime(2026, 7, 21, 3, 0, tzinfo=UTC),
        ),
        time_zone="America/Chicago",
    )

    assert late_chicago.service_date.isoformat() == "2026-07-20"


def test_source_fingerprint_is_canonical_and_input_order_independent():
    first = occurrence(
        "event-a",
        title="Acme",
        match_hints=(" 100 Main St ", "ACME", "acme"),
    )
    equivalent_first = occurrence(
        "event-a",
        title="Acme",
        match_hints=("acme", "100   MAIN ST"),
    )
    second = occurrence("event-b", title="Beta", start=START + timedelta(hours=2))

    forward = source_set_fingerprint([first, second])
    reverse = source_set_fingerprint([second, equivalent_first])
    changed = source_set_fingerprint([first, replace(second, revision="rev-2")])

    assert forward == reverse
    assert forward != changed
    with pytest.raises(PlanningContractError, match="duplicate source occurrence"):
        source_set_fingerprint([first, first])


def test_preview_classifies_create_update_unchanged_and_explicit_cancel():
    create_source = occurrence("create", title="Beta")
    unchanged_source = occurrence("unchanged", title="Acme")
    update_source = occurrence("update", title="Beta", revision="new")
    cancelled_source = tombstone("cancel")
    existing = [
        existing_for(unchanged_source, visit_id=11, location_id=1),
        existing_for(
            update_source,
            visit_id=12,
            location_id=3,
            fingerprint="0" * 64,
        ),
        existing_for(
            occurrence("cancel"),
            visit_id=13,
            location_id=1,
        ),
    ]

    preview = build_preview(
        [cancelled_source, update_source, unchanged_source, create_source],
        existing,
        locations(),
        selected_location_ids_by_source={unchanged_source.source_key: 1},
    )
    classifications = {item.source_key: item.classification for item in preview.items}

    assert classifications[create_source.source_key] == "create"
    assert classifications[unchanged_source.source_key] == "unchanged"
    assert classifications[update_source.source_key] == "update"
    assert classifications[cancelled_source.source_key] == "cancel"


def test_bounded_source_window_does_not_treat_absence_as_cancellation():
    missing_active_source = occurrence("missing-active")
    missing_cancelled_source = occurrence("missing-cancelled")

    preview = build_preview(
        [],
        [
            existing_for(missing_active_source, visit_id=21),
            existing_for(missing_cancelled_source, visit_id=22, cancelled=True),
        ],
        locations(),
    )

    assert preview.items == ()


def test_unknown_or_ambiguous_location_remains_unresolved_until_selected():
    ambiguous_source = occurrence("ambiguous", title="Acme")
    unknown_source = occurrence("unknown", title="Not A Customer")

    unresolved = build_preview(
        [unknown_source, ambiguous_source],
        [],
        locations(),
    )
    resolved = build_preview(
        [unknown_source, ambiguous_source],
        [],
        locations(),
        selected_location_ids_by_source={
            ambiguous_source.source_key: 2,
            unknown_source.source_key: 3,
        },
    )

    assert {item.classification for item in unresolved.items} == {"unresolved"}
    assert all(item.unresolved_reasons for item in unresolved.items)
    assert {item.classification for item in resolved.items} == {"create"}


def test_assignment_resolution_issues_block_without_guessing():
    source = occurrence("employee-resolution", title="Beta")

    preview = build_preview(
        [source],
        [],
        locations(),
        assigned_employee_ids_by_source={source.source_key: [3, 1, 3]},
        assignment_issues_by_source={source.source_key: ["Pamela:inactive"]},
    )
    item = preview.items[0]

    assert item.classification == "unresolved"
    assert item.assigned_employee_ids == (1, 3)
    assert item.unresolved_reasons == ("assignment:Pamela:inactive",)


def test_overlaps_are_informational_and_do_not_change_classification():
    first = occurrence(
        "first", title="Beta", start=START, end=START + timedelta(hours=2)
    )
    second = occurrence(
        "second",
        title="Beta",
        start=START + timedelta(hours=1),
        end=START + timedelta(hours=3),
    )
    touching = occurrence(
        "touching",
        title="Beta",
        start=START + timedelta(hours=3),
        end=START + timedelta(hours=4),
    )
    cancelled = replace(
        occurrence(
            "cancelled-overlap",
            title="Beta",
            start=START + timedelta(minutes=30),
        ),
        cancelled=True,
    )

    warnings = find_soft_time_overlaps([touching, second, cancelled, first])
    preview = build_preview([first, second], [], locations())

    assert len(warnings) == 1
    assert warnings[0].code == "soft_time_overlap"
    assert warnings[0].blocking is False
    assert all(item.classification == "create" for item in preview.items)


def test_dense_overlap_cluster_returns_at_most_one_warning_per_later_occurrence():
    occurrences = [occurrence(f"dense-{index}", title="Beta") for index in range(2500)]

    warnings = find_soft_time_overlaps(occurrences)

    assert len(warnings) == len(occurrences) - 1
    assert all(warning.blocking is False for warning in warnings)


def test_reviewed_fingerprint_is_order_independent_but_exact_about_decisions():
    first = occurrence("first", title="Acme")
    second = occurrence("second", title="Beta", start=START + timedelta(hours=2))
    kwargs = {
        "selected_location_ids_by_source": {first.source_key: 1},
        "assigned_employee_ids_by_source": {
            first.source_key: [2, 1],
            second.source_key: [3],
        },
    }

    forward = build_preview([first, second], [], locations(), **kwargs)
    reverse = build_preview(
        [second, first],
        [],
        reversed(locations()),
        selected_location_ids_by_source={first.source_key: 1},
        assigned_employee_ids_by_source={
            second.source_key: [3],
            first.source_key: [1, 2],
        },
    )
    changed_location = build_preview(
        [first, second],
        [],
        locations(),
        selected_location_ids_by_source={first.source_key: 2},
        assigned_employee_ids_by_source=kwargs["assigned_employee_ids_by_source"],
    )
    changed_assignment = build_preview(
        [first, second],
        [],
        locations(),
        selected_location_ids_by_source={first.source_key: 1},
        assigned_employee_ids_by_source={
            first.source_key: [1],
            second.source_key: [3],
        },
    )

    assert forward.reviewed_fingerprint == reverse.reviewed_fingerprint
    assert forward.reviewed_fingerprint != changed_location.reviewed_fingerprint
    assert forward.reviewed_fingerprint != changed_assignment.reviewed_fingerprint


def test_apply_actions_require_exact_fingerprint_and_no_unresolved_items():
    create_source = occurrence("create-action", title="Beta")
    update_source = occurrence("update-action", title="Beta", revision="new")
    unchanged_source = occurrence("unchanged-action", title="Beta")
    explicit_cancel = tombstone("cancel-action")
    preview = build_preview(
        [create_source, update_source, unchanged_source, explicit_cancel],
        [
            existing_for(
                update_source, visit_id=31, location_id=3, fingerprint="0" * 64
            ),
            existing_for(unchanged_source, visit_id=32, location_id=3),
            existing_for(occurrence("cancel-action"), visit_id=33),
        ],
        locations(),
    )

    with pytest.raises(StalePreviewError):
        build_apply_actions(preview, "stale")

    actions = build_apply_actions(preview, preview.reviewed_fingerprint)
    by_source = {action.source_key: action for action in actions}

    assert {action.action for action in actions} == {"create", "update", "cancel"}
    assert unchanged_source.source_key not in by_source
    assert by_source[create_source.source_key].planned_visit_id is None
    assert by_source[update_source.source_key].planned_visit_id == 31
    assert (
        by_source[explicit_cancel.source_key].cancellation_reason == "source_cancelled"
    )

    unresolved = build_preview(
        [occurrence("unresolved-action", title="Unknown")],
        [],
        locations(),
    )
    with pytest.raises(UnresolvedPreviewError):
        build_apply_actions(unresolved, unresolved.reviewed_fingerprint)


def test_decisions_for_unknown_source_keys_are_rejected_not_ignored():
    source = occurrence("known", title="Beta")

    with pytest.raises(PlanningContractError, match="unknown source keys"):
        build_preview(
            [source],
            [],
            locations(),
            selected_location_ids_by_source={"not-present": 1},
        )


def test_active_occurrences_require_timezone_aware_ordered_times():
    with pytest.raises(PlanningContractError, match="timezone"):
        occurrence("naive", start=datetime(2026, 7, 20, 13, 0))
    with pytest.raises(PlanningContractError, match="after"):
        occurrence("backwards", start=START, end=START)
