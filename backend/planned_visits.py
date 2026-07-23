"""Pure planning rules for imported customer-service occurrences.

This module deliberately has no database, HTTP, authentication, or timekeeping
dependencies.  Callers supply read-only snapshots, review the returned preview,
and persist the resulting actions elsewhere.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Iterable, Literal, Mapping, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


Classification = Literal["create", "update", "cancel", "unchanged", "unresolved"]
LocationResolutionStatus = Literal["resolved", "unresolved"]
EmployeeResolutionStatus = Literal["resolved", "missing", "inactive", "ambiguous"]
ApplyActionKind = Literal["create", "update", "cancel"]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PlanningContractError(ValueError):
    """The supplied planning snapshot violates a deterministic input contract."""


class UnresolvedPreviewError(PlanningContractError):
    """The reviewed preview still contains a decision that needs an operator."""


class StalePreviewError(PlanningContractError):
    """The approved fingerprint does not describe the current reviewed preview."""


def _display_text(value: object) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).split())


def normalize_match_text(value: object) -> str:
    """Return the bounded, explainable comparison form used by matchers.

    Matching is exact after Unicode normalization, whitespace collapse, and
    case-folding.  It intentionally does not perform substring, token, or fuzzy
    matching.
    """

    return _display_text(value).casefold()


def _identifier(value: object, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise PlanningContractError(f"{label} is required")
    return normalized


def _utc(value: datetime | None, label: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlanningContractError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _positive_ids(values: Iterable[int], label: str) -> tuple[int, ...]:
    normalized = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise PlanningContractError(f"{label} must contain positive integer IDs")
        normalized.append(value)
    return tuple(sorted(set(normalized)))


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class LocationRecord:
    location_id: int
    address: str
    customer_name: str | None = None
    active: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.location_id, bool) or self.location_id <= 0:
            raise PlanningContractError("location_id must be a positive integer")
        address = _display_text(self.address)
        if not address:
            raise PlanningContractError("location address is required")
        object.__setattr__(self, "address", address)
        customer = _display_text(self.customer_name)
        object.__setattr__(self, "customer_name", customer or None)


@dataclass(frozen=True)
class EmployeeRecord:
    employee_id: int
    name: str
    active: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.employee_id, bool) or self.employee_id <= 0:
            raise PlanningContractError("employee_id must be a positive integer")
        name = _display_text(self.name)
        if not name:
            raise PlanningContractError("employee name is required")
        object.__setattr__(self, "name", name)


@dataclass(frozen=True)
class LocationResolution:
    status: LocationResolutionStatus
    reason: str
    location_id: int | None = None
    candidate_ids: tuple[int, ...] = ()

    @property
    def resolved(self) -> bool:
        return self.status == "resolved" and self.location_id is not None


@dataclass(frozen=True)
class EmployeeNameResolution:
    requested_name: str
    status: EmployeeResolutionStatus
    employee_id: int | None = None
    candidate_ids: tuple[int, ...] = ()

    @property
    def resolved(self) -> bool:
        return self.status == "resolved" and self.employee_id is not None


def _unique_location_records(
    locations: Iterable[LocationRecord],
) -> tuple[LocationRecord, ...]:
    by_id: dict[int, LocationRecord] = {}
    for location in locations:
        prior = by_id.get(location.location_id)
        if prior is not None and prior != location:
            raise PlanningContractError(
                f"location_id {location.location_id} has conflicting snapshots"
            )
        by_id[location.location_id] = location
    return tuple(by_id[key] for key in sorted(by_id))


def _unique_employee_records(
    employees: Iterable[EmployeeRecord],
) -> tuple[EmployeeRecord, ...]:
    by_id: dict[int, EmployeeRecord] = {}
    for employee in employees:
        prior = by_id.get(employee.employee_id)
        if prior is not None and prior != employee:
            raise PlanningContractError(
                f"employee_id {employee.employee_id} has conflicting snapshots"
            )
        by_id[employee.employee_id] = employee
    return tuple(by_id[key] for key in sorted(by_id))


def resolve_location(
    hints: Iterable[str],
    locations: Iterable[LocationRecord],
) -> LocationResolution:
    """Resolve exact customer/address hints only when one active row matches."""

    normalized_hints = {
        normalized for hint in hints if (normalized := normalize_match_text(hint))
    }
    if not normalized_hints:
        return LocationResolution("unresolved", "no_match")

    candidates = []
    for location in _unique_location_records(locations):
        if not location.active:
            continue
        identifiers = {
            normalize_match_text(location.address),
            normalize_match_text(location.customer_name),
        }
        if normalized_hints.intersection(identifiers):
            candidates.append(location.location_id)

    candidate_ids = tuple(sorted(candidates))
    if len(candidate_ids) == 1:
        return LocationResolution(
            "resolved",
            "unique_match",
            location_id=candidate_ids[0],
            candidate_ids=candidate_ids,
        )
    if not candidate_ids:
        return LocationResolution("unresolved", "no_match")
    return LocationResolution(
        "unresolved",
        "ambiguous",
        candidate_ids=candidate_ids,
    )


def select_location(
    location_id: int,
    locations: Iterable[LocationRecord],
) -> LocationResolution:
    """Validate an explicit operator selection against the read-only snapshot."""

    records = _unique_location_records(locations)
    selected = next(
        (row for row in records if row.location_id == location_id and row.active),
        None,
    )
    if selected is None:
        return LocationResolution("unresolved", "invalid_selection")
    return LocationResolution(
        "resolved",
        "operator_selection",
        location_id=selected.location_id,
        candidate_ids=(selected.location_id,),
    )


def resolve_employee_name(
    requested_name: str,
    employees: Iterable[EmployeeRecord],
) -> EmployeeNameResolution:
    """Resolve a name without guessing over missing, inactive, or duplicate rows."""

    display_name = _display_text(requested_name)
    normalized_name = normalize_match_text(display_name)
    records = _unique_employee_records(employees)
    matches = tuple(
        employee
        for employee in records
        if normalize_match_text(employee.name) == normalized_name
    )
    # Issue #20 supplies Carmen, Pamela, and Tina as given names while the
    # employee table commonly stores full names. A first-token match is still
    # bounded and explainable; more than one candidate remains ambiguous.
    if not matches and " " not in normalized_name:
        matches = tuple(
            employee
            for employee in records
            if normalize_match_text(employee.name).split(" ", 1)[0] == normalized_name
        )
    candidate_ids = tuple(employee.employee_id for employee in matches)
    if not matches:
        return EmployeeNameResolution(display_name, "missing")
    if len(matches) > 1:
        return EmployeeNameResolution(
            display_name,
            "ambiguous",
            candidate_ids=candidate_ids,
        )
    employee = matches[0]
    if not employee.active:
        return EmployeeNameResolution(
            display_name,
            "inactive",
            candidate_ids=candidate_ids,
        )
    return EmployeeNameResolution(
        display_name,
        "resolved",
        employee_id=employee.employee_id,
        candidate_ids=candidate_ids,
    )


@dataclass(frozen=True)
class SourceOccurrence:
    calendar_id: str
    event_id: str
    title: str
    starts_at: datetime | None
    ends_at: datetime | None
    source_key_value: str | None = None
    series_id: str | None = None
    occurrence_id: str | None = None
    description: str = ""
    location_text: str = ""
    time_zone: str = ""
    updated_at: datetime | None = None
    match_hints: tuple[str, ...] = ()
    all_day: bool = False
    cancelled: bool = False
    revision: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "calendar_id", _identifier(self.calendar_id, "calendar_id")
        )
        object.__setattr__(self, "event_id", _identifier(self.event_id, "event_id"))
        source_key_value = str(self.source_key_value or "").strip().lower()
        if source_key_value and not _SHA256_RE.fullmatch(source_key_value):
            raise PlanningContractError("source_key_value must be a SHA-256 hex digest")
        object.__setattr__(self, "source_key_value", source_key_value or None)
        series_id = str(self.series_id or self.event_id).strip()
        object.__setattr__(self, "series_id", _identifier(series_id, "series_id"))
        occurrence_id = str(self.occurrence_id or "").strip()
        object.__setattr__(self, "occurrence_id", occurrence_id or None)
        object.__setattr__(self, "title", _display_text(self.title))
        object.__setattr__(self, "description", str(self.description or "").strip())
        object.__setattr__(self, "location_text", _display_text(self.location_text))
        object.__setattr__(self, "time_zone", str(self.time_zone or "").strip())
        object.__setattr__(self, "revision", str(self.revision or "").strip())

        normalized_hints: set[str] = set()
        for hint in self.match_hints:
            normalized = normalize_match_text(hint)
            if normalized:
                normalized_hints.add(normalized)
        object.__setattr__(
            self,
            "match_hints",
            tuple(sorted(normalized_hints)),
        )

        starts_at = _utc(self.starts_at, "starts_at")
        ends_at = _utc(self.ends_at, "ends_at")
        if not self.cancelled and (starts_at is None or ends_at is None):
            raise PlanningContractError(
                "active occurrences require starts_at and ends_at"
            )
        if starts_at is not None and ends_at is not None and ends_at <= starts_at:
            raise PlanningContractError("ends_at must be after starts_at")
        object.__setattr__(self, "starts_at", starts_at)
        object.__setattr__(self, "ends_at", ends_at)
        object.__setattr__(self, "updated_at", _utc(self.updated_at, "updated_at"))

    @property
    def source_key(self) -> str:
        if self.source_key_value:
            return self.source_key_value
        identity = {
            "calendarId": self.calendar_id,
            "eventId": self.event_id,
            "occurrenceId": self.occurrence_id,
        }
        return _canonical_hash(identity)

    @property
    def effective_match_hints(self) -> tuple[str, ...]:
        if self.match_hints:
            return self.match_hints
        return (self.title,) if self.title else ()

    @property
    def service_date(self) -> date | None:
        """Return the Calendar-local date used for effective crew membership."""
        if self.starts_at is None:
            return None
        if not self.time_zone:
            return self.starts_at.date()
        try:
            zone = ZoneInfo(self.time_zone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise PlanningContractError(
                "time_zone must be a valid IANA timezone"
            ) from exc
        return self.starts_at.astimezone(zone).date()


def _source_payload(occurrence: SourceOccurrence) -> dict[str, object]:
    return {
        "sourceKey": occurrence.source_key,
        "calendarId": occurrence.calendar_id,
        "eventId": occurrence.event_id,
        "seriesId": occurrence.series_id,
        "occurrenceId": occurrence.occurrence_id,
        "title": occurrence.title,
        "description": occurrence.description,
        "locationText": occurrence.location_text,
        "timeZone": occurrence.time_zone,
        "updatedAt": _utc_text(occurrence.updated_at),
        "matchHints": list(occurrence.match_hints),
        "startsAt": _utc_text(occurrence.starts_at),
        "endsAt": _utc_text(occurrence.ends_at),
        "allDay": occurrence.all_day,
        "cancelled": occurrence.cancelled,
        "revision": occurrence.revision,
    }


def occurrence_fingerprint(occurrence: SourceOccurrence) -> str:
    """Fingerprint the complete normalized source occurrence."""

    return _canonical_hash(_source_payload(occurrence))


def _occurrence_index(
    occurrences: Iterable[SourceOccurrence],
) -> dict[str, SourceOccurrence]:
    indexed: dict[str, SourceOccurrence] = {}
    for occurrence in occurrences:
        key = occurrence.source_key
        if key in indexed:
            raise PlanningContractError(f"duplicate source occurrence: {key}")
        indexed[key] = occurrence
    return indexed


def source_set_fingerprint(occurrences: Iterable[SourceOccurrence]) -> str:
    """Fingerprint a source snapshot independently of occurrence input order."""

    indexed = _occurrence_index(occurrences)
    payload = [_source_payload(indexed[key]) for key in sorted(indexed)]
    return _canonical_hash(payload)


@dataclass(frozen=True)
class ExistingPlannedVisit:
    planned_visit_id: int
    source_key: str
    source_fingerprint: str
    location_id: int
    assigned_employee_ids: tuple[int, ...] = ()
    assigned_crew_id: int | None = None
    cancelled: bool = False
    completed: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.planned_visit_id, bool) or self.planned_visit_id <= 0:
            raise PlanningContractError("planned_visit_id must be a positive integer")
        object.__setattr__(
            self, "source_key", _identifier(self.source_key, "source_key")
        )
        fingerprint = str(self.source_fingerprint or "").strip().lower()
        if not _SHA256_RE.fullmatch(fingerprint):
            raise PlanningContractError(
                "source_fingerprint must be a SHA-256 hex digest"
            )
        object.__setattr__(self, "source_fingerprint", fingerprint)
        if isinstance(self.location_id, bool) or self.location_id <= 0:
            raise PlanningContractError("location_id must be a positive integer")
        object.__setattr__(
            self,
            "assigned_employee_ids",
            _positive_ids(self.assigned_employee_ids, "assigned_employee_ids"),
        )
        if self.assigned_crew_id is not None and (
            isinstance(self.assigned_crew_id, bool) or self.assigned_crew_id <= 0
        ):
            raise PlanningContractError("assigned_crew_id must be a positive integer")


@dataclass(frozen=True)
class OverlapWarning:
    first_source_key: str
    second_source_key: str
    overlap_starts_at: datetime
    overlap_ends_at: datetime
    code: str = "soft_time_overlap"
    blocking: bool = False


def find_soft_time_overlaps(
    occurrences: Iterable[SourceOccurrence],
) -> tuple[OverlapWarning, ...]:
    """Return bounded representative warnings without changing any decision.

    One warning is enough to prove that an occurrence overlaps the active
    interval set. This sweep returns at most ``n - 1`` warnings instead of
    materializing every pair in a dense overlap cluster.
    """

    active = sorted(
        (
            occurrence
            for occurrence in occurrences
            if not occurrence.cancelled
            and occurrence.starts_at is not None
            and occurrence.ends_at is not None
        ),
        key=lambda item: (item.starts_at, item.ends_at, item.source_key),
    )
    warnings = []
    interval_leader: SourceOccurrence | None = None
    for occurrence in active:
        assert occurrence.starts_at is not None and occurrence.ends_at is not None
        if interval_leader is None:
            interval_leader = occurrence
            continue
        assert interval_leader.starts_at is not None
        assert interval_leader.ends_at is not None
        if occurrence.starts_at < interval_leader.ends_at:
            first_key, second_key = sorted(
                (interval_leader.source_key, occurrence.source_key)
            )
            warnings.append(
                OverlapWarning(
                    first_source_key=first_key,
                    second_source_key=second_key,
                    overlap_starts_at=max(
                        interval_leader.starts_at, occurrence.starts_at
                    ),
                    overlap_ends_at=min(interval_leader.ends_at, occurrence.ends_at),
                )
            )
        if occurrence.ends_at > interval_leader.ends_at:
            interval_leader = occurrence
    return tuple(
        sorted(
            warnings,
            key=lambda warning: (
                warning.first_source_key,
                warning.second_source_key,
                warning.overlap_starts_at,
            ),
        )
    )


@dataclass(frozen=True)
class PreviewItem:
    source_key: str
    classification: Classification
    occurrence: SourceOccurrence | None
    existing: ExistingPlannedVisit | None
    location_resolution: LocationResolution
    assigned_employee_ids: tuple[int, ...] = ()
    assigned_crew_id: int | None = None
    assigned_crew_member_ids: tuple[int, ...] = ()
    unresolved_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlannedVisitPreview:
    source_fingerprint: str
    reviewed_fingerprint: str
    items: tuple[PreviewItem, ...]
    warnings: tuple[OverlapWarning, ...]

    @property
    def has_unresolved(self) -> bool:
        return any(item.classification == "unresolved" for item in self.items)


def _existing_index(
    visits: Iterable[ExistingPlannedVisit],
) -> dict[str, ExistingPlannedVisit]:
    indexed: dict[str, ExistingPlannedVisit] = {}
    ids: set[int] = set()
    for visit in visits:
        if visit.planned_visit_id in ids:
            raise PlanningContractError(
                f"duplicate planned_visit_id: {visit.planned_visit_id}"
            )
        ids.add(visit.planned_visit_id)
        if visit.source_key in indexed:
            raise PlanningContractError(
                f"multiple planned visits use source key: {visit.source_key}"
            )
        indexed[visit.source_key] = visit
    return indexed


def _existing_location(location_id: int) -> LocationResolution:
    return LocationResolution(
        "resolved",
        "existing_mapping",
        location_id=location_id,
        candidate_ids=(location_id,),
    )


def _validate_decision_keys(
    label: str,
    decisions: Mapping[str, object],
    source_keys: set[str],
) -> None:
    unknown = sorted(set(decisions).difference(source_keys))
    if unknown:
        raise PlanningContractError(
            f"{label} contains unknown source keys: {', '.join(unknown)}"
        )


def _warning_payload(warning: OverlapWarning) -> dict[str, object]:
    return {
        "code": warning.code,
        "blocking": warning.blocking,
        "firstSourceKey": warning.first_source_key,
        "secondSourceKey": warning.second_source_key,
        "overlapStartsAt": _utc_text(warning.overlap_starts_at),
        "overlapEndsAt": _utc_text(warning.overlap_ends_at),
    }


def _preview_item_payload(item: PreviewItem) -> dict[str, object]:
    return {
        "sourceKey": item.source_key,
        "classification": item.classification,
        "source": _source_payload(item.occurrence) if item.occurrence else None,
        "existing": (
            {
                "plannedVisitId": item.existing.planned_visit_id,
                "sourceFingerprint": item.existing.source_fingerprint,
                "locationId": item.existing.location_id,
                "assignedEmployeeIds": list(item.existing.assigned_employee_ids),
                "assignedCrewId": item.existing.assigned_crew_id,
                "cancelled": item.existing.cancelled,
                "completed": item.existing.completed,
            }
            if item.existing
            else None
        ),
        "locationResolution": {
            "status": item.location_resolution.status,
            "reason": item.location_resolution.reason,
            "locationId": item.location_resolution.location_id,
            "candidateIds": list(item.location_resolution.candidate_ids),
        },
        "assignedEmployeeIds": list(item.assigned_employee_ids),
        "assignedCrewId": item.assigned_crew_id,
        "assignedCrewMemberIds": list(item.assigned_crew_member_ids),
        "unresolvedReasons": list(item.unresolved_reasons),
    }


def reviewed_preview_fingerprint(
    source_fingerprint: str,
    items: Iterable[PreviewItem],
    warnings: Iterable[OverlapWarning],
) -> str:
    """Fingerprint source state plus every reviewed decision and warning."""

    item_payloads = sorted(
        (_preview_item_payload(item) for item in items),
        key=lambda item: str(item["sourceKey"]),
    )
    warning_payloads = sorted(
        (_warning_payload(warning) for warning in warnings),
        key=lambda warning: (
            str(warning["firstSourceKey"]),
            str(warning["secondSourceKey"]),
        ),
    )
    return _canonical_hash(
        {
            "sourceFingerprint": source_fingerprint,
            "items": item_payloads,
            "warnings": warning_payloads,
        }
    )


def build_preview(
    occurrences: Iterable[SourceOccurrence],
    existing_visits: Iterable[ExistingPlannedVisit],
    locations: Iterable[LocationRecord],
    *,
    selected_location_ids_by_source: Mapping[str, int] | None = None,
    assigned_employee_ids_by_source: Mapping[str, Sequence[int]] | None = None,
    assigned_crew_ids_by_source: Mapping[str, int | None] | None = None,
    assigned_crew_member_ids_by_source: Mapping[str, Sequence[int]] | None = None,
    assignment_issues_by_source: Mapping[str, Sequence[str]] | None = None,
) -> PlannedVisitPreview:
    """Compare a bounded source window with its existing planned visits.

    Existing rows supplied here must be limited to that same source window.
    Absence never proves cancellation; only explicit source tombstones cancel.
    """

    occurrence_index = _occurrence_index(occurrences)
    existing_index = _existing_index(existing_visits)
    location_snapshot = _unique_location_records(locations)
    selected_locations = dict(selected_location_ids_by_source or {})
    assigned_ids = dict(assigned_employee_ids_by_source or {})
    assigned_crew_ids = dict(assigned_crew_ids_by_source or {})
    assigned_crew_member_ids = dict(assigned_crew_member_ids_by_source or {})
    assignment_issues = dict(assignment_issues_by_source or {})
    source_keys = set(occurrence_index)
    _validate_decision_keys("selected locations", selected_locations, source_keys)
    _validate_decision_keys("employee assignments", assigned_ids, source_keys)
    _validate_decision_keys("crew assignments", assigned_crew_ids, source_keys)
    _validate_decision_keys(
        "crew membership snapshots", assigned_crew_member_ids, source_keys
    )
    _validate_decision_keys("assignment issues", assignment_issues, source_keys)

    items = []
    for source_key in sorted(occurrence_index):
        occurrence = occurrence_index[source_key]
        existing = existing_index.pop(source_key, None)

        if occurrence.cancelled:
            resolution = (
                _existing_location(existing.location_id)
                if existing
                else LocationResolution("unresolved", "not_applicable")
            )
            classification: Classification = (
                "cancel"
                if existing and not existing.cancelled and not existing.completed
                else "unchanged"
            )
            items.append(
                PreviewItem(
                    source_key=source_key,
                    classification=classification,
                    occurrence=occurrence,
                    existing=existing,
                    location_resolution=resolution,
                    assigned_employee_ids=(
                        existing.assigned_employee_ids if existing else ()
                    ),
                    assigned_crew_id=(existing.assigned_crew_id if existing else None),
                    assigned_crew_member_ids=(),
                    unresolved_reasons=(
                        ("protected:completed_visit",)
                        if existing and existing.completed
                        else ()
                    ),
                )
            )
            continue

        if source_key in selected_locations:
            resolution = select_location(
                selected_locations[source_key],
                location_snapshot,
            )
        else:
            resolution = resolve_location(
                occurrence.effective_match_hints,
                location_snapshot,
            )

        selected_assignments = _positive_ids(
            assigned_ids.get(
                source_key,
                existing.assigned_employee_ids if existing else (),
            ),
            "assigned employee IDs",
        )
        selected_crew_id = assigned_crew_ids.get(
            source_key,
            existing.assigned_crew_id if existing else None,
        )
        if selected_crew_id is not None and (
            isinstance(selected_crew_id, bool) or selected_crew_id <= 0
        ):
            raise PlanningContractError("assigned crew IDs must be positive integers")
        selected_crew_members = _positive_ids(
            assigned_crew_member_ids.get(source_key, ()),
            "assigned crew member IDs",
        )
        issues = tuple(
            sorted(
                {
                    _display_text(issue)
                    for issue in assignment_issues.get(source_key, ())
                    if _display_text(issue)
                }
            )
        )
        unresolved_reasons = []
        if not resolution.resolved:
            unresolved_reasons.append(f"location:{resolution.reason}")
        unresolved_reasons.extend(f"assignment:{issue}" for issue in issues)

        if existing is not None and existing.completed:
            classification = "unchanged"
            unresolved_reasons.append("protected:completed_visit")
        elif unresolved_reasons:
            classification = "unresolved"
        elif existing is None:
            classification = "create"
        elif (
            existing.cancelled
            or existing.source_fingerprint != occurrence_fingerprint(occurrence)
            or existing.location_id != resolution.location_id
            or existing.assigned_employee_ids != selected_assignments
            or existing.assigned_crew_id != selected_crew_id
        ):
            classification = "update"
        else:
            classification = "unchanged"

        items.append(
            PreviewItem(
                source_key=source_key,
                classification=classification,
                occurrence=occurrence,
                existing=existing,
                location_resolution=resolution,
                assigned_employee_ids=selected_assignments,
                assigned_crew_id=selected_crew_id,
                assigned_crew_member_ids=selected_crew_members,
                unresolved_reasons=tuple(unresolved_reasons),
            )
        )

    # Absence from a bounded 30-day result is not proof of cancellation: an
    # occurrence may simply have moved outside the window. Only an explicit
    # Google status=cancelled tombstone becomes a cancellation preview item.

    sorted_items = tuple(sorted(items, key=lambda item: item.source_key))
    sorted_occurrences = tuple(
        occurrence_index[key] for key in sorted(occurrence_index)
    )
    source_fingerprint = source_set_fingerprint(sorted_occurrences)
    warnings = find_soft_time_overlaps(sorted_occurrences)
    review_fingerprint = reviewed_preview_fingerprint(
        source_fingerprint,
        sorted_items,
        warnings,
    )
    return PlannedVisitPreview(
        source_fingerprint=source_fingerprint,
        reviewed_fingerprint=review_fingerprint,
        items=sorted_items,
        warnings=warnings,
    )


@dataclass(frozen=True)
class ApplyAction:
    action: ApplyActionKind
    source_key: str
    planned_visit_id: int | None
    source_fingerprint: str | None
    location_id: int
    assigned_employee_ids: tuple[int, ...]
    assigned_crew_id: int | None = None
    calendar_id: str | None = None
    event_id: str | None = None
    series_id: str | None = None
    occurrence_id: str | None = None
    title: str | None = None
    description: str | None = None
    location_text: str | None = None
    time_zone: str | None = None
    updated_at: datetime | None = None
    revision: str | None = None
    service_date: date | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    all_day: bool = False
    cancellation_reason: str | None = None


def build_apply_actions(
    preview: PlannedVisitPreview,
    reviewed_fingerprint: str,
) -> tuple[ApplyAction, ...]:
    """Construct persistence-neutral actions for the exact reviewed preview."""

    if not hmac.compare_digest(
        str(reviewed_fingerprint or ""),
        preview.reviewed_fingerprint,
    ):
        raise StalePreviewError("reviewed preview changed; refresh before approval")
    unresolved = [
        item.source_key for item in preview.items if item.classification == "unresolved"
    ]
    if unresolved:
        raise UnresolvedPreviewError(
            "preview contains unresolved items: " + ", ".join(sorted(unresolved))
        )

    actions = []
    for item in preview.items:
        if item.classification == "unchanged":
            continue
        if item.classification == "cancel":
            if (
                item.existing is None
                or item.occurrence is None
                or not item.occurrence.cancelled
            ):
                raise PlanningContractError(
                    f"cancellation {item.source_key} lacks an explicit source tombstone"
                )
            actions.append(
                ApplyAction(
                    action="cancel",
                    source_key=item.source_key,
                    planned_visit_id=item.existing.planned_visit_id,
                    source_fingerprint=occurrence_fingerprint(item.occurrence),
                    location_id=item.existing.location_id,
                    assigned_employee_ids=item.existing.assigned_employee_ids,
                    assigned_crew_id=item.existing.assigned_crew_id,
                    calendar_id=item.occurrence.calendar_id,
                    event_id=item.occurrence.event_id,
                    series_id=item.occurrence.series_id,
                    occurrence_id=item.occurrence.occurrence_id,
                    updated_at=item.occurrence.updated_at,
                    revision=item.occurrence.revision,
                    service_date=item.occurrence.service_date,
                    cancellation_reason="source_cancelled",
                )
            )
            continue

        occurrence = item.occurrence
        if occurrence is None or not item.location_resolution.resolved:
            raise PlanningContractError(
                f"{item.classification} {item.source_key} lacks reviewed source data"
            )
        assert item.location_resolution.location_id is not None
        actions.append(
            ApplyAction(
                action=item.classification,
                source_key=item.source_key,
                planned_visit_id=(
                    item.existing.planned_visit_id if item.existing else None
                ),
                source_fingerprint=occurrence_fingerprint(occurrence),
                location_id=item.location_resolution.location_id,
                assigned_employee_ids=item.assigned_employee_ids,
                assigned_crew_id=item.assigned_crew_id,
                calendar_id=occurrence.calendar_id,
                event_id=occurrence.event_id,
                series_id=occurrence.series_id,
                occurrence_id=occurrence.occurrence_id,
                title=occurrence.title,
                description=occurrence.description,
                location_text=occurrence.location_text,
                time_zone=occurrence.time_zone,
                updated_at=occurrence.updated_at,
                revision=occurrence.revision,
                service_date=occurrence.service_date,
                starts_at=occurrence.starts_at,
                ends_at=occurrence.ends_at,
                all_day=occurrence.all_day,
            )
        )
    return tuple(actions)
