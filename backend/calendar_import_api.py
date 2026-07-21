"""Admin API for reviewed, read-only Google Calendar planned visits."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import logging
import math
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil.parser import isoparse
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator, model_validator

import calendar_import_store as store
from google_calendar import (
    CALENDAR_READONLY_SCOPES,
    CalendarOccurrence,
    GoogleCalendarClient,
    GoogleCalendarConfigurationError,
    GoogleCalendarError,
    GoogleCalendarOAuthError,
    GoogleCalendarResponseError,
    MAX_PREVIEW_OCCURRENCES,
    OAuthTokenSet,
    TargetedOccurrenceRequest,
    pkce_challenge,
)
from planned_visits import (
    EmployeeRecord,
    ExistingPlannedVisit,
    LocationRecord,
    PlannedVisitPreview,
    PlanningContractError,
    SourceOccurrence,
    UnresolvedPreviewError,
    build_apply_actions,
    build_preview,
    resolve_employee_name,
    source_set_fingerprint,
)


AdminDependency = Callable[..., dict[str, Any]]
MAX_TARGETED_RECONCILIATIONS = MAX_PREVIEW_OCCURRENCES
OAUTH_CALLBACK_PATH = "/api/google-calendar/oauth/callback"


class CalendarOAuthAccessLogFilter(logging.Filter):
    """Redact OAuth query secrets from Uvicorn's access-log request target."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3:
            target = str(args[2])
            if target.split("?", 1)[0] == OAUTH_CALLBACK_PATH and "?" in target:
                redacted = list(args)
                redacted[2] = f"{OAUTH_CALLBACK_PATH}?redacted"
                record.args = tuple(redacted)
        return True


@dataclass(frozen=True)
class CalendarImportConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    encryption_key: str
    portal_url: str
    timeout_seconds: float
    timezone_name: str

    @property
    def configured(self) -> bool:
        try:
            _validate_runtime_config(self)
        except (GoogleCalendarConfigurationError, store.CalendarStoreError):
            return False
        return True


PositiveInt = int


class CalendarSelectionRequest(BaseModel):
    calendarId: str = Field(min_length=1, max_length=1024)


class CrewMembershipRequest(BaseModel):
    employeeIds: list[PositiveInt] = Field(min_length=1, max_length=50)

    @field_validator("employeeIds")
    @classmethod
    def validate_employee_ids(cls, values: list[int]) -> list[int]:
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise ValueError("Employee IDs must be positive integers")
        if len(set(values)) != len(values):
            raise ValueError("Employee IDs must be unique")
        return values


class PreviewResolutionRequest(BaseModel):
    sourceKey: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    locationId: int | None = Field(default=None, gt=0)
    crewId: int | None = Field(default=None, gt=0)
    employeeIds: list[int] = Field(default_factory=list, max_length=50)
    crewProvided: bool | None = Field(default=None, exclude=True)
    employeesProvided: bool | None = Field(default=None, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def record_assignment_field_presence(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        if normalized.get("crewProvided") is None:
            normalized["crewProvided"] = "crewId" in normalized
        if normalized.get("employeesProvided") is None:
            normalized["employeesProvided"] = "employeeIds" in normalized
        return normalized

    @field_validator("employeeIds")
    @classmethod
    def validate_assignment_ids(cls, values: list[int]) -> list[int]:
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise ValueError("Employee IDs must be positive integers")
        if len(set(values)) != len(values):
            raise ValueError("Employee IDs must be unique")
        return values


class CalendarPreviewRequest(BaseModel):
    resolutions: list[PreviewResolutionRequest] = Field(
        default_factory=list, max_length=2500
    )

    @field_validator("resolutions")
    @classmethod
    def validate_unique_source_keys(
        cls, values: list[PreviewResolutionRequest]
    ) -> list[PreviewResolutionRequest]:
        keys = [value.sourceKey for value in values]
        if len(set(keys)) != len(keys):
            raise ValueError("Each Calendar occurrence can be resolved only once")
        return values


class CalendarApproveRequest(BaseModel):
    previewId: str = Field(min_length=16, max_length=128)
    previewFingerprint: str = Field(
        min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )


def _client(config: CalendarImportConfig) -> GoogleCalendarClient:
    _require_runtime_config(config)
    try:
        return GoogleCalendarClient(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=config.redirect_uri,
            timeout_seconds=config.timeout_seconds,
        )
    except GoogleCalendarConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _cipher(config: CalendarImportConfig) -> store.CredentialCipher:
    try:
        return store.CredentialCipher(config.encryption_key)
    except store.CalendarConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _validated_absolute_url(value: str, *, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or any(character.isspace() for character in normalized):
        raise GoogleCalendarConfigurationError(f"{label} is invalid")
    try:
        parsed = urlsplit(normalized)
        parsed_port = parsed.port
    except ValueError:
        raise GoogleCalendarConfigurationError(f"{label} is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (
            parsed.scheme == "http"
            and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        )
    ):
        raise GoogleCalendarConfigurationError(f"{label} is invalid")
    # Reading ``parsed.port`` above validates malformed/non-numeric ports.
    _ = parsed_port
    return normalized


def _validated_oauth_redirect_uri(value: str) -> str:
    redirect_uri = _validated_absolute_url(value, label="Google redirect URI")
    if urlsplit(redirect_uri).path != OAUTH_CALLBACK_PATH:
        raise GoogleCalendarConfigurationError("Google redirect URI is invalid")
    return redirect_uri


def _validated_portal_url(value: str) -> str:
    return _validated_absolute_url(value, label="Calendar portal URL")


def _validate_runtime_config(config: CalendarImportConfig) -> None:
    """Validate every server-only setting without returning any setting value."""

    if (
        not isinstance(config.client_id, str)
        or not config.client_id.strip()
        or not isinstance(config.client_secret, str)
        or not config.client_secret.strip()
    ):
        raise GoogleCalendarConfigurationError(
            "Google Calendar service is not configured"
        )
    _validated_oauth_redirect_uri(config.redirect_uri)
    _validated_portal_url(config.portal_url)
    store.CredentialCipher(config.encryption_key)
    try:
        timeout_seconds = float(config.timeout_seconds)
    except (TypeError, ValueError):
        raise GoogleCalendarConfigurationError(
            "Google Calendar request timeout is invalid"
        ) from None
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise GoogleCalendarConfigurationError(
            "Google Calendar request timeout is invalid"
        )
    try:
        ZoneInfo(config.timezone_name)
    except (TypeError, ValueError, ZoneInfoNotFoundError):
        raise GoogleCalendarConfigurationError(
            "Google Calendar timezone is invalid"
        ) from None


def _require_runtime_config(config: CalendarImportConfig) -> None:
    try:
        _validate_runtime_config(config)
    except (GoogleCalendarConfigurationError, store.CalendarStoreError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Google Calendar service is not configured",
        ) from exc


def _google_failure(exc: GoogleCalendarError) -> HTTPException:
    if isinstance(exc, GoogleCalendarConfigurationError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, GoogleCalendarOAuthError):
        return HTTPException(
            status_code=409,
            detail="Google Calendar authorization expired; reconnect the calendar",
        )
    return HTTPException(
        status_code=503 if exc.retryable else 502,
        detail=str(exc),
        headers={"Retry-After": "5"} if exc.retryable else None,
    )


def _portal_redirect(config: CalendarImportConfig, marker: str) -> RedirectResponse:
    try:
        portal_url = _validated_portal_url(config.portal_url)
    except GoogleCalendarConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="Google Calendar service is not configured",
        ) from exc
    parsed = urlsplit(portal_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["calendarImport"] = marker
    target = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
    )
    return RedirectResponse(target, status_code=303)


def _token_payload(
    token: OAuthTokenSet, *, prior_refresh_token: str | None = None
) -> dict[str, Any]:
    return {
        "access_token": token.access_token,
        "refresh_token": token.refresh_token or prior_refresh_token,
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(seconds=token.expires_in)
        ).isoformat(),
        "token_type": token.token_type,
        "scopes": list(token.scopes or CALENDAR_READONLY_SCOPES),
    }


def _preview_window_bounds(
    time_zone_name: str, *, now_utc: datetime | None = None
) -> tuple[datetime, datetime]:
    """Return the selected Calendar's current local day plus 30 local days."""

    try:
        zone = ZoneInfo(time_zone_name)
    except (ValueError, TypeError, ZoneInfoNotFoundError) as exc:
        raise PlanningContractError("Calendar timezone is invalid") from exc
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise PlanningContractError("Calendar clock must include a timezone")
    local_now = now.astimezone(zone)
    local_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    local_end = local_start + timedelta(days=30)
    return (
        local_start.astimezone(timezone.utc),
        local_end.astimezone(timezone.utc),
    )


def _revoke_issued_token(client: GoogleCalendarClient, token: OAuthTokenSet) -> None:
    """Best-effort cleanup for a grant that cannot be installed locally."""

    try:
        client.revoke_token(token=token.refresh_token or token.access_token)
    except GoogleCalendarError:
        # The callback still fails closed locally. A later Google-side outage
        # must not cause the uninstalled token to be exposed in a response/log.
        pass


def _revoke_uninstalled_token(
    client: GoogleCalendarClient, token: OAuthTokenSet
) -> None:
    """Revoke only when no concurrently installed connection can share the grant."""

    try:
        if store.active_connection():
            return
    except Exception:
        # A database outage makes grant ownership unknowable. Avoid revoking a
        # token that may back a connection installed by a concurrent callback.
        return
    _revoke_issued_token(client, token)


def _parse_expiry(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = isoparse(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _access_context(
    config: CalendarImportConfig,
) -> tuple[GoogleCalendarClient, dict[str, Any], str]:
    connection = store.active_connection()
    if not connection:
        raise HTTPException(status_code=409, detail="Google Calendar is not connected")
    cipher = _cipher(config)
    try:
        credentials = store.connection_credentials(connection, cipher=cipher)
    except store.CalendarStoreError as exc:
        raise HTTPException(
            status_code=503,
            detail="Stored Google Calendar connection is unavailable",
        ) from exc
    access_token = str(credentials.get("access_token") or "").strip()
    expiry = _parse_expiry(credentials.get("expires_at"))
    client = _client(config)
    if (
        not access_token
        or expiry is None
        or expiry <= datetime.now(timezone.utc) + timedelta(minutes=2)
    ):
        refresh_token = str(credentials.get("refresh_token") or "").strip()
        if not refresh_token:
            raise HTTPException(
                status_code=409,
                detail="Google Calendar authorization expired; reconnect the calendar",
            )
        try:
            refreshed = client.refresh_access_token(refresh_token=refresh_token)
        except GoogleCalendarError as exc:
            raise _google_failure(exc) from exc
        credentials = _token_payload(refreshed, prior_refresh_token=refresh_token)
        try:
            store.update_connection_credentials(
                int(connection["id"]), credentials, cipher=cipher
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="Google Calendar connection changed; reconnect the calendar",
            ) from exc
        access_token = str(credentials["access_token"])
    return client, connection, access_token


def _calendar_dict(calendar: Any) -> dict[str, Any]:
    return {
        "id": calendar.calendar_id,
        "name": calendar.summary,
        "primary": calendar.primary,
        "selected": calendar.selected,
        "accessRole": calendar.access_role,
        "timeZone": calendar.time_zone,
    }


def _list_calendars(config: CalendarImportConfig) -> tuple[dict[str, Any], list[Any]]:
    client, connection, access_token = _access_context(config)
    try:
        calendars = client.list_calendars(access_token=access_token)
    except GoogleCalendarError as exc:
        raise _google_failure(exc) from exc
    return connection, calendars


def _morning_crew_payload(
    *, crews: list[dict[str, Any]], employees: list[dict[str, Any]]
) -> dict[str, Any]:
    morning = next(
        (crew for crew in crews if crew["name"] == store.MORNING_CREW_NAME),
        None,
    )
    employee_records = [
        EmployeeRecord(
            employee_id=int(employee["id"]),
            name=str(employee["name"]),
            active=bool(employee["active"]),
        )
        for employee in employees
    ]
    proposed = [
        resolve_employee_name(name, employee_records)
        for name in store.MORNING_CREW_EXPECTED_NAMES
    ]
    members = morning.get("members", []) if morning else []
    active_member_ids = sorted(
        int(member["employee_id"]) for member in members if member["employee_active"]
    )
    unresolved = [
        {
            "name": resolution.requested_name,
            "status": resolution.status,
            "candidateIds": list(resolution.candidate_ids),
        }
        for resolution in proposed
        if not resolution.resolved
    ]
    proposed_ids = [
        int(resolution.employee_id)
        for resolution in proposed
        if resolution.employee_id is not None
    ]
    every_expected_identity_resolved = len(proposed_ids) == len(
        store.MORNING_CREW_EXPECTED_NAMES
    )
    expected_members_ready = bool(morning and active_member_ids) and (
        every_expected_identity_resolved and set(active_member_ids) == set(proposed_ids)
    )
    memberships_were_explicitly_created = bool(members and active_member_ids) and all(
        member.get("created_by") is not None and bool(member["employee_active"])
        for member in members
    )
    operator_resolved = bool(
        morning and not expected_members_ready and memberships_were_explicitly_created
    )
    ready = expected_members_ready or operator_resolved
    return {
        "id": int(morning["id"]) if morning else None,
        "name": store.MORNING_CREW_NAME,
        "memberIds": active_member_ids,
        "members": [
            {
                "employeeId": int(member["employee_id"]),
                "name": member["employee_name"],
                "active": bool(member["employee_active"]),
            }
            for member in members
        ],
        "expectedNames": list(store.MORNING_CREW_EXPECTED_NAMES),
        "proposedEmployeeIds": proposed_ids,
        "identityIssues": unresolved,
        "operatorResolved": operator_resolved,
        "ready": ready,
    }


def _crew_response(config: CalendarImportConfig) -> dict[str, Any]:
    today = datetime.now(ZoneInfo(config.timezone_name)).date()
    employees = store.read_employees()
    crews = store.read_crews(today)
    crew_payloads = [
        {
            "id": int(crew["id"]),
            "name": crew["name"],
            "active": bool(crew["active"]),
            "memberIds": [int(member["employee_id"]) for member in crew["members"]],
            "members": [
                {
                    "employeeId": int(member["employee_id"]),
                    "name": member["employee_name"],
                    "active": bool(member["employee_active"]),
                }
                for member in crew["members"]
            ],
        }
        for crew in crews
    ]
    return {
        "crews": crew_payloads,
        "employees": [
            {
                "id": int(employee["id"]),
                "name": employee["name"],
                "active": bool(employee["active"]),
            }
            for employee in employees
        ],
        "morningCrew": _morning_crew_payload(crews=crews, employees=employees),
    }


def _boundary_datetime(
    raw: str | None, *, all_day: bool, time_zone: str
) -> datetime | None:
    if not raw:
        return None
    if all_day:
        try:
            parsed_date = date.fromisoformat(raw)
        except ValueError as exc:
            raise PlanningContractError("All-day Calendar date is invalid") from exc
        return datetime.combine(parsed_date, time.min, tzinfo=ZoneInfo(time_zone))
    try:
        parsed = isoparse(raw)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PlanningContractError("Calendar event time is invalid") from exc
    if parsed.tzinfo is None:
        raise PlanningContractError("Calendar event time must include a timezone")
    return parsed


def _source_occurrence(occurrence: CalendarOccurrence) -> SourceOccurrence:
    starts_at = _boundary_datetime(
        occurrence.start,
        all_day=occurrence.all_day,
        time_zone=occurrence.time_zone,
    )
    ends_at = _boundary_datetime(
        occurrence.end,
        all_day=occurrence.all_day,
        time_zone=occurrence.time_zone,
    )
    updated_at = _boundary_datetime(
        occurrence.updated,
        all_day=False,
        time_zone=occurrence.time_zone,
    )
    series_id = occurrence.recurring_event_id or occurrence.event_id
    return SourceOccurrence(
        calendar_id=occurrence.calendar_id,
        event_id=occurrence.event_id,
        series_id=series_id,
        occurrence_id=(
            occurrence.original_start_query
            or occurrence.original_start
            or occurrence.event_id
        ),
        source_key_value=occurrence.source_key,
        title=occurrence.summary,
        description=occurrence.description,
        location_text=occurrence.location,
        time_zone=occurrence.time_zone,
        starts_at=starts_at,
        ends_at=ends_at,
        updated_at=updated_at,
        match_hints=tuple(
            hint for hint in (occurrence.location, occurrence.summary) if hint
        ),
        all_day=occurrence.all_day,
        cancelled=occurrence.cancelled,
        revision=occurrence.etag or occurrence.updated or occurrence.status,
    )


def _deleted_source_occurrence(
    *, identity: dict[str, Any], calendar_id: str, time_zone: str
) -> SourceOccurrence:
    """Represent a provider-confirmed missing identity as a cancellation tombstone."""

    event_id = str(identity["source_event_id"])
    series_id = str(identity["source_series_id"])
    occurrence_id = str(identity["source_occurrence_id"])
    return SourceOccurrence(
        calendar_id=calendar_id,
        event_id=event_id,
        series_id=series_id,
        occurrence_id=occurrence_id,
        source_key_value=str(identity["source_key"]),
        title=str(identity.get("title") or ""),
        description=str(identity.get("description") or ""),
        location_text=str(identity.get("source_location_text") or ""),
        starts_at=identity.get("approximate_start"),
        ends_at=identity.get("approximate_end"),
        all_day=bool(identity.get("all_day")),
        time_zone=str(identity.get("source_timezone") or time_zone),
        updated_at=identity.get("source_updated_at"),
        cancelled=True,
        revision="provider-deleted",
    )


def _read_source_window(
    config: CalendarImportConfig,
    *,
    window_start: datetime | None,
    window_end: datetime | None = None,
    expected_connection_id: int | None = None,
    expected_calendar_id: str | None = None,
    expected_time_zone: str | None = None,
) -> tuple[dict[str, Any], list[SourceOccurrence], str, datetime, datetime]:
    client, connection, access_token = _access_context(config)
    if (
        expected_connection_id is not None
        and int(connection["id"]) != expected_connection_id
    ):
        raise HTTPException(
            status_code=409,
            detail="Google Calendar connection changed; create a new preview",
        )
    calendar_id = str(connection.get("selected_calendar_id") or "").strip()
    if not calendar_id:
        raise HTTPException(status_code=409, detail="Select a Google Calendar first")
    if expected_calendar_id is not None and calendar_id != expected_calendar_id:
        raise HTTPException(
            status_code=409,
            detail="Selected Google Calendar changed; create a new preview",
        )
    try:
        calendars = client.list_calendars(access_token=access_token)
        selected_calendar = next(
            (calendar for calendar in calendars if calendar.calendar_id == calendar_id),
            None,
        )
        if selected_calendar is None:
            raise GoogleCalendarResponseError(
                "Selected Google Calendar is no longer available"
            )
        calendar_time_zone = (
            str(selected_calendar.time_zone or "").strip() or config.timezone_name
        )
        if expected_time_zone is not None and calendar_time_zone != expected_time_zone:
            raise HTTPException(
                status_code=409,
                detail="Google Calendar timezone changed; create a new preview",
            )
        if expected_time_zone is None and (
            str(connection.get("selected_calendar_timezone") or "")
            != calendar_time_zone
            or str(connection.get("selected_calendar_name") or "")
            != selected_calendar.summary
        ):
            store.select_calendar(
                connection_id=int(connection["id"]),
                calendar_id=calendar_id,
                calendar_name=selected_calendar.summary,
                calendar_timezone=calendar_time_zone,
            )
            connection = {
                **connection,
                "selected_calendar_name": selected_calendar.summary,
                "selected_calendar_timezone": calendar_time_zone,
            }
        if window_start is None:
            window_start, window_end = _preview_window_bounds(calendar_time_zone)
        elif window_end is None:
            local_start = window_start.astimezone(ZoneInfo(calendar_time_zone))
            window_end = (local_start + timedelta(days=30)).astimezone(timezone.utc)
        assert window_end is not None
        rows = client.list_occurrences(
            access_token=access_token,
            calendar_id=calendar_id,
            window_start=window_start,
            window_end=window_end,
            time_zone=calendar_time_zone,
        )
        rows_by_key: dict[str, CalendarOccurrence] = {}
        for row in rows:
            if row.source_key in rows_by_key:
                raise GoogleCalendarResponseError(
                    "Google Calendar returned a duplicate occurrence identity"
                )
            rows_by_key[row.source_key] = row
        source_rows_by_key = {
            source_key: _source_occurrence(row)
            for source_key, row in rows_by_key.items()
        }
        identities = store.read_planned_source_identities(
            calendar_id=calendar_id,
            range_start=window_start,
            range_end=window_end,
        )
        missing_identities = [
            identity
            for identity in identities
            if str(identity["source_key"]) not in rows_by_key
        ]
        if len(missing_identities) > MAX_TARGETED_RECONCILIATIONS:
            raise GoogleCalendarResponseError(
                "Google Calendar omitted too many planned occurrences to reconcile safely"
            )
        targeted_requests = []
        for identity in missing_identities:
            event_id = str(identity["source_event_id"])
            series_id = str(identity["source_series_id"])
            occurrence_id = str(identity["source_occurrence_id"])
            if series_id != event_id and occurrence_id != event_id:
                targeted_requests.append(
                    TargetedOccurrenceRequest(
                        event_id=event_id,
                        recurring_event_id=series_id,
                        original_start=occurrence_id,
                    )
                )
            else:
                targeted_requests.append(TargetedOccurrenceRequest(event_id=event_id))
        targeted_rows = client.get_occurrences_batch(
            access_token=access_token,
            calendar_id=calendar_id,
            requests_=targeted_requests,
            time_zone=calendar_time_zone,
        )
        for identity, targeted in zip(missing_identities, targeted_rows, strict=True):
            source_key = str(identity["source_key"])
            if len(source_rows_by_key) >= MAX_PREVIEW_OCCURRENCES:
                raise GoogleCalendarResponseError(
                    "Google Calendar has too many occurrences in the 30-day preview"
                )
            if targeted is None:
                source_rows_by_key[source_key] = _deleted_source_occurrence(
                    identity=identity,
                    calendar_id=calendar_id,
                    time_zone=calendar_time_zone,
                )
                continue
            if targeted.source_key != source_key:
                raise GoogleCalendarResponseError(
                    "Google Calendar returned inconsistent occurrence identity"
                )
            source_rows_by_key[source_key] = _source_occurrence(targeted)
        occurrences = [source_rows_by_key[key] for key in sorted(source_rows_by_key)]
    except GoogleCalendarError as exc:
        raise _google_failure(exc) from exc
    except PlanningContractError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return (
        connection,
        occurrences,
        calendar_time_zone,
        window_start,
        window_end,
    )


def _existing_records(rows: Iterable[dict[str, Any]]) -> list[ExistingPlannedVisit]:
    records: list[ExistingPlannedVisit] = []
    for row in rows:
        crew_ids = tuple(sorted(set(int(value) for value in row.get("crew_ids", []))))
        if len(crew_ids) > 1:
            raise PlanningContractError(
                f"planned visit {row['id']} has multiple active crew assignments"
            )
        records.append(
            ExistingPlannedVisit(
                planned_visit_id=int(row["id"]),
                source_key=str(row["source_key"]),
                source_fingerprint=str(row["source_fingerprint"]),
                location_id=int(row["location_id"]),
                assigned_employee_ids=tuple(
                    sorted(set(int(value) for value in row.get("employee_ids", [])))
                ),
                assigned_crew_id=crew_ids[0] if crew_ids else None,
                cancelled=row["status"] == "cancelled",
                completed=row["status"] == "completed",
            )
        )
    return records


def _crew_snapshot(
    *, config: CalendarImportConfig, on_date: date
) -> tuple[dict[int, dict[str, Any]], int | None]:
    crews = store.read_crews(on_date)
    by_id = {int(crew["id"]): crew for crew in crews if crew["active"]}
    employees = store.read_employees()
    morning_payload = _morning_crew_payload(crews=crews, employees=employees)
    morning = int(morning_payload["id"]) if morning_payload["ready"] else None
    return by_id, morning


def _build_reviewed_preview(
    *,
    config: CalendarImportConfig,
    connection: dict[str, Any],
    occurrences: list[SourceOccurrence],
    range_start: datetime,
    range_end: datetime,
    resolutions: list[PreviewResolutionRequest],
) -> PlannedVisitPreview:
    locations_data = store.read_active_locations()
    locations = [
        LocationRecord(
            location_id=int(row["id"]),
            address=str(row["address"]),
            customer_name=row.get("customer_name"),
            active=bool(row["active"]),
        )
        for row in locations_data
    ]
    employee_rows = store.read_employees()
    active_employee_ids = {int(row["id"]) for row in employee_rows if row["active"]}
    calendar_id = str(connection["selected_calendar_id"])
    mappings = store.read_event_mappings(calendar_id=calendar_id)
    existing_rows = store.read_existing_visits(
        connection_id=int(connection["id"]),
        calendar_id=calendar_id,
        range_start=range_start,
        range_end=range_end,
        source_keys=(occurrence.source_key for occurrence in occurrences),
    )
    existing = _existing_records(existing_rows)
    existing_by_key = {record.source_key: record for record in existing}
    resolution_by_key = {resolution.sourceKey: resolution for resolution in resolutions}
    occurrence_keys = {occurrence.source_key for occurrence in occurrences}
    unknown_resolution_keys = sorted(set(resolution_by_key).difference(occurrence_keys))
    if unknown_resolution_keys:
        raise PlanningContractError(
            "resolutions contain occurrences that are no longer in the Calendar preview"
        )
    selected_locations: dict[str, int] = {}
    assigned_crews: dict[str, int | None] = {}
    assigned_employees: dict[str, tuple[int, ...]] = {}
    crew_members: dict[str, tuple[int, ...]] = {}
    assignment_issues: dict[str, list[str]] = {}
    crew_cache: dict[date, tuple[dict[int, dict[str, Any]], int | None]] = {}

    for occurrence in occurrences:
        if occurrence.cancelled:
            continue
        decision = resolution_by_key.get(occurrence.source_key)
        mapping = mappings.get(occurrence.source_key)
        if decision and decision.locationId is not None:
            selected_locations[occurrence.source_key] = decision.locationId
        elif mapping:
            selected_locations[occurrence.source_key] = int(mapping["location_id"])

        if occurrence.source_key in existing_by_key:
            # Preserve the existing assignment unless the operator reviews a
            # different one. It still participates in the preview fingerprint.
            current = existing_by_key[occurrence.source_key]
            crew_id = current.assigned_crew_id
            employee_ids = current.assigned_employee_ids
        else:
            if occurrence.starts_at is None:  # defensive; active rows require it
                crew_id = None
            else:
                snapshot_date = occurrence.service_date
                assert snapshot_date is not None
                if snapshot_date not in crew_cache:
                    crew_cache[snapshot_date] = _crew_snapshot(
                        config=config, on_date=snapshot_date
                    )
                _, crew_id = crew_cache[snapshot_date]
            employee_ids = ()

        if decision is not None and decision.crewProvided:
            crew_id = decision.crewId
        if decision is not None and decision.employeesProvided:
            employee_ids = tuple(sorted(set(decision.employeeIds)))

        issues: list[str] = []
        member_ids: tuple[int, ...] = ()
        if crew_id is not None:
            assert occurrence.starts_at is not None
            snapshot_date = occurrence.service_date
            assert snapshot_date is not None
            if snapshot_date not in crew_cache:
                crew_cache[snapshot_date] = _crew_snapshot(
                    config=config, on_date=snapshot_date
                )
            crews_by_id, _ = crew_cache[snapshot_date]
            crew = crews_by_id.get(crew_id)
            if not crew:
                issues.append("crew_unavailable")
            else:
                member_ids = tuple(
                    sorted(
                        int(member["employee_id"])
                        for member in crew["members"]
                        if member["employee_active"]
                    )
                )
                if not member_ids:
                    issues.append("crew_has_no_active_members")
        inactive_assignments = sorted(set(employee_ids).difference(active_employee_ids))
        if inactive_assignments:
            issues.append(
                "inactive_employees:"
                + ",".join(str(value) for value in inactive_assignments)
            )
        if crew_id is None and not employee_ids:
            issues.append("assignment_required")

        assigned_crews[occurrence.source_key] = crew_id
        assigned_employees[occurrence.source_key] = employee_ids
        crew_members[occurrence.source_key] = member_ids
        if issues:
            assignment_issues[occurrence.source_key] = issues

    return build_preview(
        occurrences,
        existing,
        locations,
        selected_location_ids_by_source=selected_locations,
        assigned_employee_ids_by_source=assigned_employees,
        assigned_crew_ids_by_source=assigned_crews,
        assigned_crew_member_ids_by_source=crew_members,
        assignment_issues_by_source=assignment_issues,
    )


def _preview_item_dict(item: Any) -> dict[str, Any]:
    occurrence = item.occurrence
    existing = item.existing
    return {
        "sourceKey": item.source_key,
        "classification": item.classification,
        "summary": occurrence.title if occurrence else "Removed from Calendar",
        "description": occurrence.description if occurrence else "",
        "start": occurrence.starts_at.isoformat()
        if occurrence and occurrence.starts_at
        else None,
        "end": occurrence.ends_at.isoformat()
        if occurrence and occurrence.ends_at
        else None,
        "allDay": bool(occurrence.all_day) if occurrence else False,
        "timingSemantics": "approximate",
        "calendarLocation": occurrence.location_text if occurrence else "",
        "seriesId": occurrence.series_id if occurrence else None,
        "location": {
            "status": item.location_resolution.status,
            "reason": item.location_resolution.reason,
            "locationId": item.location_resolution.location_id,
            "candidateIds": list(item.location_resolution.candidate_ids),
        },
        "crewId": item.assigned_crew_id,
        "crewMemberIds": list(item.assigned_crew_member_ids),
        "employeeIds": list(item.assigned_employee_ids),
        "unresolvedReasons": list(item.unresolved_reasons),
        "plannedVisitId": existing.planned_visit_id if existing else None,
        "completedVisitPreserved": bool(existing.completed) if existing else False,
    }


def _preview_response(
    *,
    config: CalendarImportConfig,
    stored: dict[str, Any],
    preview: PlannedVisitPreview,
    locations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    counts = {
        classification: sum(
            1 for item in preview.items if item.classification == classification
        )
        for classification in ("create", "update", "cancel", "unchanged", "unresolved")
    }
    crews = _crew_response(config)
    return {
        "previewId": stored["id"],
        "previewFingerprint": preview.reviewed_fingerprint,
        "sourceFingerprint": preview.source_fingerprint,
        "expiresAt": stored["expires_at"].isoformat(),
        "rangeStart": stored["range_start"].isoformat(),
        "rangeEnd": stored["range_end"].isoformat(),
        "canApprove": not preview.has_unresolved,
        "counts": counts,
        "items": [_preview_item_dict(item) for item in preview.items],
        "warnings": [
            {
                "code": warning.code,
                "blocking": warning.blocking,
                "firstSourceKey": warning.first_source_key,
                "secondSourceKey": warning.second_source_key,
                "overlapStart": warning.overlap_starts_at.isoformat(),
                "overlapEnd": warning.overlap_ends_at.isoformat(),
            }
            for warning in preview.warnings
        ],
        "locations": locations
        if locations is not None
        else [
            {
                "id": int(row["id"]),
                "address": row["address"],
                "customerName": row.get("customer_name"),
            }
            for row in store.read_active_locations()
        ],
        **crews,
    }


def _register_preview_routes(
    *,
    router: APIRouter,
    config: CalendarImportConfig,
    get_current_admin: AdminDependency,
) -> None:
    @router.post("/api/admin/google-calendar/preview")
    def preview_google_calendar(
        payload: CalendarPreviewRequest,
        admin: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        (
            connection,
            occurrences,
            calendar_time_zone,
            window_start,
            range_end,
        ) = _read_source_window(config, window_start=None)
        try:
            preview = _build_reviewed_preview(
                config=config,
                connection=connection,
                occurrences=occurrences,
                range_start=window_start,
                range_end=range_end,
                resolutions=payload.resolutions,
            )
        except PlanningContractError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        stored = store.create_preview(
            connection_id=int(connection["id"]),
            calendar_id=str(connection["selected_calendar_id"]),
            range_start=window_start,
            range_end=range_end,
            source_fingerprint=preview.source_fingerprint,
            preview_fingerprint=preview.reviewed_fingerprint,
            payload={
                "resolutions": [
                    {
                        **resolution.model_dump(),
                        "crewProvided": bool(resolution.crewProvided),
                        "employeesProvided": bool(resolution.employeesProvided),
                    }
                    for resolution in payload.resolutions
                ],
                "calendarTimeZone": calendar_time_zone,
            },
            admin_id=int(admin["id"]),
        )
        return _preview_response(config=config, stored=stored, preview=preview)

    @router.post("/api/admin/google-calendar/approve")
    def approve_google_calendar_preview(
        payload: CalendarApproveRequest,
        admin: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        stored = store.read_preview(payload.previewId)
        if not stored:
            raise HTTPException(
                status_code=404, detail="Calendar preview was not found"
            )
        if stored["preview_fingerprint"] != payload.previewFingerprint:
            raise HTTPException(
                status_code=409, detail="Calendar preview fingerprint does not match"
            )
        if stored["status"] == "applied":
            return dict(stored.get("result") or {})
        if stored["status"] != "open" or stored["expires_at"] <= datetime.now(
            timezone.utc
        ):
            raise HTTPException(
                status_code=409,
                detail="Calendar preview is stale; create a new preview",
            )
        raw_payload = stored.get("payload") or {}
        try:
            resolutions = [
                PreviewResolutionRequest.model_validate(value)
                for value in raw_payload.get("resolutions", [])
            ]
        except (AttributeError, ValueError, TypeError) as exc:
            store.mark_preview_stale(payload.previewId)
            raise HTTPException(
                status_code=409, detail="Stored Calendar preview is invalid"
            ) from exc
        connection, occurrences, calendar_time_zone, _, _ = _read_source_window(
            config,
            window_start=stored["range_start"],
            window_end=stored["range_end"],
            expected_connection_id=int(stored["connection_id"]),
            expected_calendar_id=str(stored["calendar_id"]),
            expected_time_zone=str(
                raw_payload.get("calendarTimeZone") or config.timezone_name
            ),
        )
        if source_set_fingerprint(occurrences) != stored["source_fingerprint"]:
            store.mark_preview_stale(payload.previewId)
            raise HTTPException(
                status_code=409,
                detail="Google Calendar changed after preview; review it again",
            )
        try:
            rebuilt = _build_reviewed_preview(
                config=config,
                connection=connection,
                occurrences=occurrences,
                range_start=stored["range_start"],
                range_end=stored["range_end"],
                resolutions=resolutions,
            )
            if rebuilt.reviewed_fingerprint != payload.previewFingerprint:
                store.mark_preview_stale(payload.previewId)
                raise HTTPException(
                    status_code=409,
                    detail="Calendar plan changed after preview; review it again",
                )
            actions = build_apply_actions(rebuilt, payload.previewFingerprint)
            return store.apply_reviewed_preview(
                preview_id=payload.previewId,
                expected_preview_fingerprint=payload.previewFingerprint,
                expected_calendar_timezone=calendar_time_zone,
                preview=rebuilt,
                actions=actions,
                actor_id=int(admin["id"]),
                actor_name=str(admin["name"]),
            )
        except UnresolvedPreviewError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PlanningContractError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except store.CalendarStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


def build_calendar_import_router(
    *, config: CalendarImportConfig, get_current_admin: AdminDependency
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/admin/google-calendar/status")
    def calendar_status(
        _: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        configured = config.configured
        connection = store.active_connection() if configured else None
        return {
            "configured": configured,
            "connected": bool(connection),
            "scope": " ".join(CALENDAR_READONLY_SCOPES),
            "scopes": list(CALENDAR_READONLY_SCOPES),
            "accountEmail": connection.get("google_account_email")
            if connection
            else None,
            "selectedCalendarId": connection.get("selected_calendar_id")
            if connection
            else None,
            "selectedCalendarName": connection.get("selected_calendar_name")
            if connection
            else None,
            "selectedCalendarTimeZone": (
                connection.get("selected_calendar_timezone") if connection else None
            ),
        }

    @router.post("/api/admin/google-calendar/connect")
    def start_calendar_connection(
        admin: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        client = _client(config)
        if store.active_connection():
            raise HTTPException(
                status_code=409,
                detail="Disconnect the active Google Calendar before reconnecting",
            )
        cipher = _cipher(config)
        try:
            raw_state, verifier = store.create_oauth_state(
                admin_id=int(admin["id"]), cipher=cipher
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            authorization_url = client.authorization_url(
                state=raw_state,
                code_challenge=pkce_challenge(verifier),
            )
        except GoogleCalendarError as exc:
            store.abandon_oauth_state(raw_state)
            raise _google_failure(exc) from exc
        return {"authorizationUrl": authorization_url}

    @router.get("/api/google-calendar/oauth/callback")
    def calendar_oauth_callback(
        state: str = Query(default="", max_length=512),
        code: str = Query(default="", max_length=4096),
        error: str = Query(default="", max_length=256),
    ) -> RedirectResponse:
        if not state:
            return _portal_redirect(config, "error")
        try:
            consumed = store.consume_oauth_state(state, cipher=_cipher(config))
        except (store.CalendarStoreError, HTTPException):
            return _portal_redirect(config, "error")
        try:
            # Validate the portal destination and exact callback URI before a
            # Google code can be exchanged or a connection can be installed.
            _require_runtime_config(config)
            if error or not code:
                return _portal_redirect(config, "error")
            if store.active_connection():
                return _portal_redirect(config, "error")
            client = _client(config)
            token: OAuthTokenSet | None = None
            try:
                token = client.exchange_code(
                    code=code, code_verifier=consumed.pkce_verifier
                )
                if not token.refresh_token:
                    _revoke_uninstalled_token(client, token)
                    return _portal_redirect(config, "error")
                calendars = client.list_calendars(access_token=token.access_token)
            except GoogleCalendarError:
                if token is not None:
                    _revoke_uninstalled_token(client, token)
                return _portal_redirect(config, "error")
            assert token is not None
            primary = next(
                (calendar for calendar in calendars if calendar.primary), None
            )
            try:
                store.create_active_connection(
                    account_email=primary.calendar_id if primary else None,
                    credentials=_token_payload(token),
                    scopes=token.scopes or CALENDAR_READONLY_SCOPES,
                    admin_id=consumed.admin_id,
                    admin_name=consumed.admin_name,
                    cipher=_cipher(config),
                )
            except store.CalendarStoreError:
                _revoke_uninstalled_token(client, token)
                return _portal_redirect(config, "error")
            except Exception:
                _revoke_uninstalled_token(client, token)
                raise
            return _portal_redirect(config, "connected")
        finally:
            store.finish_oauth_state(consumed.state_hash)

    @router.get("/api/admin/google-calendar/calendars")
    def list_google_calendars(
        _: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        connection, calendars = _list_calendars(config)
        return {
            "calendars": [_calendar_dict(calendar) for calendar in calendars],
            "selectedCalendarId": connection.get("selected_calendar_id"),
        }

    @router.put("/api/admin/google-calendar/calendar")
    def choose_google_calendar(
        payload: CalendarSelectionRequest,
        _: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        connection, calendars = _list_calendars(config)
        selected = next(
            (
                calendar
                for calendar in calendars
                if calendar.calendar_id == payload.calendarId
            ),
            None,
        )
        if not selected:
            raise HTTPException(
                status_code=422, detail="Selected Google Calendar is unavailable"
            )
        try:
            store.select_calendar(
                connection_id=int(connection["id"]),
                calendar_id=selected.calendar_id,
                calendar_name=selected.summary,
                calendar_timezone=selected.time_zone,
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"success": True, "calendar": _calendar_dict(selected)}

    @router.delete("/api/admin/google-calendar/connection")
    def disconnect_google_calendar(
        admin: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        connection = store.active_connection()
        if not connection:
            return {"success": True, "disconnected": False}
        try:
            credentials = store.connection_credentials(
                connection, cipher=_cipher(config)
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="Stored Google Calendar connection is unavailable",
            ) from exc
        revocation_token = str(
            credentials.get("refresh_token") or credentials.get("access_token") or ""
        ).strip()
        if not revocation_token:
            raise HTTPException(
                status_code=503,
                detail="Stored Google Calendar connection is unavailable",
            )
        try:
            disconnected = store.disconnect_calendar(
                connection_id=int(connection["id"]),
                admin_id=int(admin["id"]),
                admin_name=str(admin["name"]),
                before_disconnect=lambda: _client(config).revoke_token(
                    token=revocation_token
                ),
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except GoogleCalendarError as exc:
            raise _google_failure(exc) from exc
        return {"success": True, "disconnected": disconnected}

    @router.get("/api/admin/planned-visits/crews")
    def list_planned_visit_crews(
        _: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        return _crew_response(config)

    @router.put("/api/admin/planned-visits/crews/{crew_id}/memberships")
    def update_crew_memberships(
        crew_id: int,
        payload: CrewMembershipRequest,
        admin: dict[str, Any] = Depends(get_current_admin),
    ) -> dict[str, Any]:
        if crew_id <= 0:
            raise HTTPException(status_code=422, detail="Crew ID must be positive")
        try:
            result = store.replace_crew_memberships(
                crew_id=crew_id,
                employee_ids=payload.employeeIds,
                actor_id=int(admin["id"]),
                actor_name=str(admin["name"]),
                effective_from=datetime.now(ZoneInfo(config.timezone_name)).date(),
            )
        except store.CalendarStoreError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"success": True, "changed": result["changed"], **_crew_response(config)}

    _register_preview_routes(
        router=router,
        config=config,
        get_current_admin=get_current_admin,
    )
    return router
