"""Narrow, read-only Google Calendar OAuth and HTTP adapter.

This module owns protocol details only.  It deliberately has no database,
FastAPI, or portal dependencies so callers can keep credentials server-side
and tests can replace the outbound request boundary.
"""

from __future__ import annotations

import base64
from email import policy
from email.parser import BytesParser
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional
from urllib.parse import quote, urlencode, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from dateutil.parser import isoparse


CALENDAR_EVENTS_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/calendar.events.readonly"
)
CALENDAR_LIST_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
)
CALENDAR_READONLY_SCOPES = (
    CALENDAR_EVENTS_READONLY_SCOPE,
    CALENDAR_LIST_READONLY_SCOPE,
)
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOCATION_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_CALENDAR_API_BASE_URL = "https://www.googleapis.com/calendar/v3"
GOOGLE_CALENDAR_BATCH_URL = "https://www.googleapis.com/batch/calendar/v3"
DEFAULT_TIMEOUT_SECONDS = 10.0
PREVIEW_WINDOW_DAYS = 30
MAX_GOOGLE_PAGES = 100
MAX_PREVIEW_OCCURRENCES = 2500
MAX_BATCH_PARTS = 1000

_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_ALLOWED_GOOGLE_HOSTS = {
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
}
_RETRYABLE_GOOGLE_REASONS = {
    "calendarUsageLimitsExceeded",
    "quotaExceeded",
    "rateLimitExceeded",
    "userRateLimitExceeded",
}


class GoogleCalendarError(RuntimeError):
    """Base class for sanitized adapter errors."""

    code = "google_calendar_error"
    retryable = False

    def __init__(self, message: str, *, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GoogleCalendarConfigurationError(GoogleCalendarError):
    code = "google_calendar_configuration_error"


class GoogleCalendarOAuthError(GoogleCalendarError):
    code = "google_calendar_oauth_error"


class GoogleCalendarTransportError(GoogleCalendarError):
    code = "google_calendar_transport_error"
    retryable = True


class GoogleCalendarResponseError(GoogleCalendarError):
    code = "google_calendar_response_error"


@dataclass(frozen=True)
class OAuthTokenSet:
    access_token: str = field(repr=False)
    refresh_token: Optional[str] = field(repr=False)
    expires_in: int
    token_type: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class CalendarSummary:
    calendar_id: str
    summary: str
    primary: bool
    selected: bool
    access_role: str
    time_zone: Optional[str]


@dataclass(frozen=True)
class CalendarOccurrence:
    source_key: str
    calendar_id: str
    event_id: str
    recurring_event_id: Optional[str]
    original_start: Optional[str]
    summary: str
    location: str
    status: str
    cancelled: bool
    all_day: bool
    start: Optional[str]
    end: Optional[str]
    time_zone: str
    updated: Optional[str]
    description: str = ""
    etag: Optional[str] = None
    original_start_query: Optional[str] = None


@dataclass(frozen=True)
class TargetedOccurrenceRequest:
    event_id: str
    recurring_event_id: Optional[str] = None
    original_start: Optional[str] = None

    def __post_init__(self) -> None:
        event_id = _required_text(self.event_id, "Google event ID")
        recurring_event_id = _optional_text(self.recurring_event_id)
        original_start = _optional_text(self.original_start)
        if self.recurring_event_id is not None and recurring_event_id is None:
            raise GoogleCalendarConfigurationError(
                "Recurring Calendar identity is incomplete"
            )
        if self.original_start is not None and original_start is None:
            raise GoogleCalendarConfigurationError(
                "Recurring Calendar identity is incomplete"
            )
        if bool(recurring_event_id) != bool(original_start):
            raise GoogleCalendarConfigurationError(
                "Recurring Calendar identity is incomplete"
            )
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "recurring_event_id", recurring_event_id)
        object.__setattr__(self, "original_start", original_start)


@dataclass(frozen=True)
class _BatchJSONPart:
    status_code: int
    content: Mapping[str, Any]


RequestCallable = Callable[..., Any]


def generate_oauth_state() -> str:
    """Return a high-entropy value suitable for a single-use OAuth state."""

    return secrets.token_urlsafe(32)


def generate_pkce_verifier() -> str:
    """Return an RFC 7636 verifier using only the unreserved character set."""

    verifier = secrets.token_urlsafe(64)
    if not _PKCE_VERIFIER_RE.fullmatch(verifier):  # pragma: no cover - defensive
        raise RuntimeError("Unable to generate a valid PKCE verifier")
    return verifier


def pkce_challenge(verifier: str) -> str:
    """Derive the S256 PKCE challenge for a validated verifier."""

    if not _PKCE_VERIFIER_RE.fullmatch(str(verifier or "")):
        raise GoogleCalendarConfigurationError("PKCE verifier is invalid")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_authorization_url(
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    login_hint: Optional[str] = None,
) -> str:
    """Build the fixed-host, read-only Google authorization URL."""

    normalized_client_id = _required_text(client_id, "Google client ID")
    normalized_redirect = _validated_redirect_uri(redirect_uri)
    normalized_state = _required_text(state, "OAuth state")
    normalized_challenge = _required_text(code_challenge, "PKCE challenge")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", normalized_challenge):
        raise GoogleCalendarConfigurationError("PKCE challenge is invalid")

    params = {
        "access_type": "offline",
        "client_id": normalized_client_id,
        "code_challenge": normalized_challenge,
        "code_challenge_method": "S256",
        "include_granted_scopes": "false",
        "prompt": "consent",
        "redirect_uri": normalized_redirect,
        "response_type": "code",
        "scope": " ".join(CALENDAR_READONLY_SCOPES),
        "state": normalized_state,
    }
    if login_hint and login_hint.strip():
        params["login_hint"] = login_hint.strip()
    return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(params)}"


def stable_occurrence_identity(calendar_id: str, event: Mapping[str, Any]) -> str:
    """Return an edit-stable key for one event or recurring occurrence.

    Non-recurring events retain Google's event id when moved.  Recurring
    instances use the series id plus original start, so a moved occurrence and
    its cancellation reconcile to the same source identity.
    """

    normalized_calendar_id = _required_text(calendar_id, "Calendar ID")
    event_id = _required_text(event.get("id"), "Google event ID")
    recurring_event_id = _optional_text(event.get("recurringEventId"))
    original_start = _canonical_original_start(event.get("originalStartTime"))
    if recurring_event_id and original_start:
        occurrence_part = f"recurring\0{recurring_event_id}\0{original_start}"
    else:
        occurrence_part = f"event\0{event_id}"
    material = f"google-calendar\0{normalized_calendar_id}\0{occurrence_part}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class GoogleCalendarClient:
    """Synchronous, read-only client for the Google Calendar v3 REST API."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        request_fn: Optional[RequestCallable] = None,
    ) -> None:
        self.client_id = _required_text(client_id, "Google client ID")
        self.client_secret = _required_text(client_secret, "Google client secret")
        self.redirect_uri = _validated_redirect_uri(redirect_uri)
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            raise GoogleCalendarConfigurationError(
                "Google request timeout is invalid"
            ) from None
        if timeout <= 0:
            raise GoogleCalendarConfigurationError(
                "Google request timeout must be positive"
            )
        self.timeout_seconds = timeout
        self._request_fn = request_fn

    def authorization_url(
        self,
        *,
        state: str,
        code_challenge: str,
        login_hint: Optional[str] = None,
    ) -> str:
        return build_authorization_url(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            state=state,
            code_challenge=code_challenge,
            login_hint=login_hint,
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> OAuthTokenSet:
        normalized_code = _required_text(code, "Google authorization code")
        if not _PKCE_VERIFIER_RE.fullmatch(str(code_verifier or "")):
            raise GoogleCalendarConfigurationError("PKCE verifier is invalid")
        content = self._request_json(
            "POST",
            GOOGLE_TOKEN_URL,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": normalized_code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
            },
            oauth_request=True,
        )
        return _normalize_token_response(content)

    def refresh_access_token(self, *, refresh_token: str) -> OAuthTokenSet:
        normalized_refresh_token = _required_text(refresh_token, "Google refresh token")
        content = self._request_json(
            "POST",
            GOOGLE_TOKEN_URL,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": normalized_refresh_token,
            },
            oauth_request=True,
        )
        token_set = _normalize_token_response(content)
        if token_set.refresh_token is not None:
            return token_set
        return OAuthTokenSet(
            access_token=token_set.access_token,
            refresh_token=normalized_refresh_token,
            expires_in=token_set.expires_in,
            token_type=token_set.token_type,
            scopes=token_set.scopes,
        )

    def revoke_token(self, *, token: str) -> None:
        """Revoke one Google grant without following redirects.

        Google documents HTTP 400 for a token that is already invalid.  That
        is an idempotent success for this operation: there is no live grant
        left to revoke.  Retryable failures fail closed so the encrypted local
        credential remains available for a later revocation attempt.
        """

        normalized_token = _required_text(token, "Google token")
        request_fn = self._request_fn or requests.request
        try:
            response = request_fn(
                "POST",
                GOOGLE_REVOCATION_URL,
                headers={"Accept": "application/json"},
                params=None,
                data={"token": normalized_token},
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None
        except (OSError, TimeoutError):
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid response"
            )
        if status_code in (200, 400):
            return
        if status_code == 429 or status_code >= 500:
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable",
                status_code=status_code,
            )
        if 300 <= status_code < 400:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an unexpected redirect"
            )
        raise GoogleCalendarOAuthError(
            "Google authorization could not be revoked",
            status_code=status_code,
        )

    def list_calendars(self, *, access_token: str) -> List[CalendarSummary]:
        normalized_token = _required_text(access_token, "Google access token")
        params: Dict[str, Any] = {
            "maxResults": 250,
            "minAccessRole": "reader",
            "showDeleted": "false",
            "showHidden": "false",
        }
        calendars: List[CalendarSummary] = []
        for content in self._paged_get(
            f"{GOOGLE_CALENDAR_API_BASE_URL}/users/me/calendarList",
            access_token=normalized_token,
            params=params,
        ):
            for raw in _response_items(content):
                calendar_id = _required_upstream_text(raw.get("id"), "calendar id")
                calendars.append(
                    CalendarSummary(
                        calendar_id=calendar_id,
                        summary=_optional_text(raw.get("summaryOverride"))
                        or _optional_text(raw.get("summary"))
                        or calendar_id,
                        primary=bool(raw.get("primary", False)),
                        selected=bool(raw.get("selected", False)),
                        access_role=_required_upstream_text(
                            raw.get("accessRole"),
                            "calendar access role",
                        ),
                        time_zone=_optional_text(raw.get("timeZone")),
                    )
                )
        return calendars

    def list_occurrences(
        self,
        *,
        access_token: str,
        calendar_id: str,
        window_start: datetime,
        window_end: datetime | None = None,
        time_zone: str,
    ) -> List[CalendarOccurrence]:
        """Read and normalize the fixed 30-day occurrence window."""

        normalized_token = _required_text(access_token, "Google access token")
        normalized_calendar_id = _required_text(calendar_id, "Calendar ID")
        start_utc = _aware_utc(window_start)
        zone = _load_zone(time_zone)
        end_utc = (
            _aware_utc(window_end)
            if window_end is not None
            else (
                start_utc.astimezone(zone) + timedelta(days=PREVIEW_WINDOW_DAYS)
            ).astimezone(timezone.utc)
        )
        if end_utc <= start_utc:
            raise GoogleCalendarConfigurationError(
                "Calendar window end must be after its start"
            )
        params: Dict[str, Any] = {
            "maxResults": 2500,
            "orderBy": "startTime",
            "showDeleted": "true",
            "singleEvents": "true",
            "timeMax": _rfc3339_utc(end_utc),
            "timeMin": _rfc3339_utc(start_utc),
            "timeZone": zone.key,
        }
        encoded_calendar_id = quote(normalized_calendar_id, safe="")
        occurrences: List[CalendarOccurrence] = []
        for content in self._paged_get(
            f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/{encoded_calendar_id}/events",
            access_token=normalized_token,
            params=params,
        ):
            for raw in _response_items(content):
                if len(occurrences) >= MAX_PREVIEW_OCCURRENCES:
                    raise GoogleCalendarResponseError(
                        "Google Calendar has too many occurrences in the 30-day preview"
                    )
                occurrences.append(
                    _normalize_occurrence(normalized_calendar_id, raw, zone)
                )
        return occurrences

    def get_occurrence(
        self,
        *,
        access_token: str,
        calendar_id: str,
        event_id: str,
        time_zone: str,
    ) -> CalendarOccurrence:
        """Read one previously imported event independent of list-window moves."""

        normalized_token = _required_text(access_token, "Google access token")
        normalized_calendar_id = _required_text(calendar_id, "Calendar ID")
        normalized_event_id = _required_text(event_id, "Google event ID")
        zone = _load_zone(time_zone)
        content = self._request_json(
            "GET",
            (
                f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/"
                f"{quote(normalized_calendar_id, safe='')}/events/"
                f"{quote(normalized_event_id, safe='')}"
            ),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {normalized_token}",
            },
            params={"timeZone": zone.key},
        )
        return _normalize_occurrence(normalized_calendar_id, content, zone)

    def get_recurring_occurrence(
        self,
        *,
        access_token: str,
        calendar_id: str,
        recurring_event_id: str,
        original_start: str,
        time_zone: str,
    ) -> CalendarOccurrence:
        """Read one recurring instance by its edit-stable provider identity."""

        normalized_token = _required_text(access_token, "Google access token")
        normalized_calendar_id = _required_text(calendar_id, "Calendar ID")
        normalized_series_id = _required_text(
            recurring_event_id, "Google recurring event ID"
        )
        normalized_original_start = _required_text(
            original_start, "Google original start"
        )
        zone = _load_zone(time_zone)
        content = self._request_json(
            "GET",
            (
                f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/"
                f"{quote(normalized_calendar_id, safe='')}/events/"
                f"{quote(normalized_series_id, safe='')}/instances"
            ),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {normalized_token}",
            },
            params={
                "maxResults": 2,
                "originalStart": normalized_original_start,
                "showDeleted": "true",
                "timeZone": zone.key,
            },
        )
        items = _response_items(content)
        if len(items) != 1 or content.get("nextPageToken"):
            raise GoogleCalendarResponseError(
                "Google Calendar could not reconcile a planned recurring occurrence"
            )
        return _normalize_occurrence(normalized_calendar_id, items[0], zone)

    def get_occurrences_batch(
        self,
        *,
        access_token: str,
        calendar_id: str,
        requests_: Iterable[TargetedOccurrenceRequest],
        time_zone: str,
    ) -> List[Optional[CalendarOccurrence]]:
        """Read known identities in at most three bounded Calendar batch calls."""

        normalized_token = _required_text(access_token, "Google access token")
        normalized_calendar_id = _required_text(calendar_id, "Calendar ID")
        zone = _load_zone(time_zone)
        targets = list(requests_)
        if len(targets) > MAX_PREVIEW_OCCURRENCES:
            raise GoogleCalendarConfigurationError(
                "Too many planned Calendar occurrences to reconcile"
            )
        occurrences: List[Optional[CalendarOccurrence]] = []
        for offset in range(0, len(targets), MAX_BATCH_PARTS):
            chunk = targets[offset : offset + MAX_BATCH_PARTS]
            paths = [
                _targeted_occurrence_path(
                    calendar_id=normalized_calendar_id,
                    request=request,
                    time_zone=zone.key,
                )
                for request in chunk
            ]
            parts = self._request_batch_json(
                access_token=normalized_token,
                paths=paths,
            )
            for request, part in zip(chunk, parts, strict=True):
                reason = _google_error_reason_from_content(part.content)
                if part.status_code == 410 and reason == "deleted":
                    occurrences.append(None)
                    continue
                if part.status_code >= 400:
                    _raise_google_status(
                        part.status_code,
                        reason=reason,
                        oauth_request=False,
                    )
                if part.status_code < 200 or part.status_code >= 300:
                    raise GoogleCalendarResponseError(
                        "Google Calendar returned an invalid batch response"
                    )
                content = part.content
                if request.recurring_event_id is not None:
                    items = _response_items(content)
                    if content.get("nextPageToken") or len(items) > 1:
                        raise GoogleCalendarResponseError(
                            "Google Calendar could not reconcile a planned recurring occurrence"
                        )
                    if not items:
                        occurrences.append(None)
                        continue
                    raw = items[0]
                else:
                    raw = content
                occurrences.append(
                    _normalize_occurrence(normalized_calendar_id, raw, zone)
                )
        return occurrences

    def _request_batch_json(
        self, *, access_token: str, paths: List[str]
    ) -> List[_BatchJSONPart]:
        if not paths:
            return []
        boundary = f"calendar_batch_{secrets.token_hex(16)}"
        body_parts = []
        for index, path in enumerate(paths):
            body_parts.append(
                "\r\n".join(
                    (
                        f"--{boundary}",
                        "Content-Type: application/http",
                        f"Content-ID: <calendar-{index}>",
                        "",
                        f"GET {path} HTTP/1.1",
                        "Accept: application/json",
                        "",
                        "",
                    )
                )
            )
        body_parts.append(f"--{boundary}--\r\n")
        request_fn = self._request_fn or requests.request
        try:
            response = request_fn(
                "POST",
                GOOGLE_CALENDAR_BATCH_URL,
                headers={
                    "Accept": "multipart/mixed",
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": f"multipart/mixed; boundary={boundary}",
                },
                params=None,
                data="".join(body_parts).encode("utf-8"),
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None
        except (OSError, TimeoutError):
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid response"
            )
        if 300 <= status_code < 400:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an unexpected redirect"
            )
        if status_code >= 400:
            _raise_google_status(
                status_code,
                reason=_google_error_reason(response),
                oauth_request=False,
            )
        headers = getattr(response, "headers", None)
        content_type = (
            headers.get("Content-Type") if isinstance(headers, Mapping) else None
        )
        raw_content = getattr(response, "content", None)
        if not isinstance(content_type, str) or not isinstance(
            raw_content, (bytes, bytearray)
        ):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            )
        return _parse_batch_json_response(
            content_type=content_type,
            body=bytes(raw_content),
            expected_parts=len(paths),
        )

    def _paged_get(
        self,
        url: str,
        *,
        access_token: str,
        params: Mapping[str, Any],
    ) -> Iterator[Mapping[str, Any]]:
        seen_tokens: set[str] = set()
        next_page_token: Optional[str] = None
        for _ in range(MAX_GOOGLE_PAGES):
            page_params = dict(params)
            if next_page_token:
                page_params["pageToken"] = next_page_token
            content = self._request_json(
                "GET",
                url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
                params=page_params,
            )
            yield content
            raw_next = content.get("nextPageToken")
            if raw_next is None:
                return
            if not isinstance(raw_next, str) or not raw_next.strip():
                raise GoogleCalendarResponseError(
                    "Google Calendar returned invalid pagination"
                )
            next_page_token = raw_next.strip()
            if next_page_token in seen_tokens:
                raise GoogleCalendarResponseError(
                    "Google Calendar returned invalid pagination"
                )
            seen_tokens.add(next_page_token)
        raise GoogleCalendarResponseError("Google Calendar returned too many pages")

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        oauth_request: bool = False,
    ) -> Mapping[str, Any]:
        _validate_google_url(url)
        request_fn = self._request_fn or requests.request
        try:
            response = request_fn(
                method,
                url,
                headers=dict(headers or {"Accept": "application/json"}),
                params=dict(params) if params is not None else None,
                data=dict(data) if data is not None else None,
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None
        except (OSError, TimeoutError):
            raise GoogleCalendarTransportError(
                "Google Calendar is temporarily unavailable"
            ) from None

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid response"
            )
        if 300 <= status_code < 400:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an unexpected redirect"
            )
        if status_code >= 400:
            _raise_google_status(
                status_code,
                reason=_google_error_reason(response),
                oauth_request=oauth_request,
            )
        try:
            content = response.json()
        except (TypeError, ValueError):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid response"
            ) from None
        if not isinstance(content, Mapping):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid response"
            )
        return content


def _targeted_occurrence_path(
    *,
    calendar_id: str,
    request: TargetedOccurrenceRequest,
    time_zone: str,
) -> str:
    event_id = _required_text(request.event_id, "Google event ID")
    recurring_event_id = _optional_text(request.recurring_event_id)
    original_start = _optional_text(request.original_start)
    if bool(recurring_event_id) != bool(original_start):
        raise GoogleCalendarConfigurationError(
            "Recurring Calendar identity is incomplete"
        )
    calendar_path = quote(calendar_id, safe="")
    if recurring_event_id and original_start:
        query = urlencode(
            {
                "maxResults": 2,
                "originalStart": original_start,
                "showDeleted": "true",
                "timeZone": time_zone,
            }
        )
        return (
            f"/calendar/v3/calendars/{calendar_path}/events/"
            f"{quote(recurring_event_id, safe='')}/instances?{query}"
        )
    return (
        f"/calendar/v3/calendars/{calendar_path}/events/"
        f"{quote(event_id, safe='')}?{urlencode({'timeZone': time_zone})}"
    )


def _raise_google_status(
    status_code: int, *, reason: Optional[str], oauth_request: bool
) -> None:
    if status_code in {404, 429} or status_code >= 500:
        raise GoogleCalendarTransportError(
            "Google Calendar is temporarily unavailable",
            status_code=status_code,
        )
    if status_code == 403 and reason in _RETRYABLE_GOOGLE_REASONS:
        raise GoogleCalendarTransportError(
            "Google Calendar is temporarily unavailable",
            status_code=status_code,
        )
    if oauth_request or status_code == 401:
        raise GoogleCalendarOAuthError(
            "Google authorization is invalid or expired",
            status_code=status_code,
        )
    raise GoogleCalendarResponseError(
        "Google Calendar request failed",
        status_code=status_code,
    )


def _parse_batch_json_response(
    *, content_type: str, body: bytes, expected_parts: int
) -> List[_BatchJSONPart]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(
            (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode(
                "ascii"
            )
            + body
        )
    except (UnicodeEncodeError, ValueError):
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid batch response"
        ) from None
    if not message.is_multipart():
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid batch response"
        )
    parts = list(message.iter_parts())
    if len(parts) != expected_parts:
        raise GoogleCalendarResponseError(
            "Google Calendar returned an incomplete batch response"
        )
    contents: List[_BatchJSONPart] = []
    for part in parts:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            )
        header_bytes, separator, body_bytes = payload.partition(b"\r\n\r\n")
        if not separator:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            )
        status_line = header_bytes.split(b"\r\n", 1)[0]
        matched_status = re.fullmatch(rb"HTTP/\d(?:\.\d)? (\d{3})(?: .*)?", status_line)
        if not matched_status:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            )
        status_code = int(matched_status.group(1))
        try:
            content = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            ) from None
        if not isinstance(content, Mapping):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid batch response"
            )
        contents.append(_BatchJSONPart(status_code=status_code, content=content))
    return contents


def _normalize_token_response(content: Mapping[str, Any]) -> OAuthTokenSet:
    access_token = _required_upstream_text(content.get("access_token"), "access token")
    token_type = _optional_text(content.get("token_type")) or "Bearer"
    if token_type.casefold() != "bearer":
        raise GoogleCalendarOAuthError("Google returned an unsupported token type")
    try:
        expires_in = int(content.get("expires_in"))
    except (TypeError, ValueError):
        raise GoogleCalendarOAuthError(
            "Google returned invalid token metadata"
        ) from None
    if expires_in <= 0:
        raise GoogleCalendarOAuthError("Google returned invalid token metadata")

    raw_scope = content.get("scope")
    if raw_scope is None:
        scopes: tuple[str, ...] = ()
    elif isinstance(raw_scope, str):
        scopes = tuple(scope for scope in raw_scope.split() if scope)
    else:
        raise GoogleCalendarOAuthError("Google returned invalid scope metadata")
    if scopes and set(scopes) != set(CALENDAR_READONLY_SCOPES):
        raise GoogleCalendarOAuthError("Google granted an unexpected Calendar scope")

    return OAuthTokenSet(
        access_token=access_token,
        refresh_token=_optional_text(content.get("refresh_token")),
        expires_in=expires_in,
        token_type="Bearer",
        scopes=scopes,
    )


def _normalize_occurrence(
    calendar_id: str,
    raw: Mapping[str, Any],
    zone: ZoneInfo,
) -> CalendarOccurrence:
    event_id = _required_upstream_text(raw.get("id"), "event id")
    status = _optional_text(raw.get("status")) or "confirmed"
    cancelled = status == "cancelled"
    start_value, start_all_day = _normalize_event_boundary(raw.get("start"), zone)
    end_value, end_all_day = _normalize_event_boundary(raw.get("end"), zone)
    original_value, original_all_day = _normalize_event_boundary(
        raw.get("originalStartTime"), zone
    )
    if not cancelled and (start_value is None or end_value is None):
        raise GoogleCalendarResponseError(
            "Google Calendar event is missing its time range"
        )
    # The current occurrence boundary defines its current timing shape.  The
    # original boundary is identity metadata and may differ after Google moves
    # one recurring instance between all-day and timed service.
    all_day = start_all_day if start_value is not None else original_all_day
    if (
        start_value is not None
        and end_value is not None
        and start_all_day != end_all_day
    ):
        raise GoogleCalendarResponseError(
            "Google Calendar event has an invalid time range"
        )

    return CalendarOccurrence(
        source_key=stable_occurrence_identity(calendar_id, raw),
        calendar_id=calendar_id,
        event_id=event_id,
        recurring_event_id=_optional_text(raw.get("recurringEventId")),
        original_start=original_value,
        summary=_optional_text(raw.get("summary")) or "(Untitled event)",
        location=_optional_text(raw.get("location")) or "",
        status=status,
        cancelled=cancelled,
        all_day=all_day,
        start=start_value,
        end=end_value,
        time_zone=zone.key,
        updated=_normalized_updated(raw.get("updated")),
        description=_optional_text(raw.get("description")) or "",
        etag=_optional_text(raw.get("etag")),
        original_start_query=_original_start_query(raw.get("originalStartTime"), zone),
    )


def _normalize_event_boundary(
    raw: Any,
    zone: ZoneInfo,
) -> tuple[Optional[str], bool]:
    if raw is None:
        return None, False
    if not isinstance(raw, Mapping):
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid event time"
        )
    raw_date = raw.get("date")
    raw_datetime = raw.get("dateTime")
    if raw_date is not None and raw_datetime is not None:
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid event time"
        )
    if raw_date is not None:
        if not isinstance(raw_date, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid event date"
            )
        try:
            normalized = date.fromisoformat(raw_date).isoformat()
        except ValueError:
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid event date"
            ) from None
        return normalized, True
    if raw_datetime is not None:
        if not isinstance(raw_datetime, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned an invalid event time"
            )
        parsed = _parse_google_datetime(
            raw_datetime,
            raw.get("timeZone"),
            "Google Calendar returned an invalid event time",
        )
        return parsed.astimezone(zone).isoformat(), False
    return None, False


def _canonical_original_start(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise GoogleCalendarResponseError(
            "Google Calendar returned invalid recurrence identity"
        )
    raw_date = raw.get("date")
    raw_datetime = raw.get("dateTime")
    if raw_date is not None and raw_datetime is not None:
        raise GoogleCalendarResponseError(
            "Google Calendar returned invalid recurrence identity"
        )
    if raw_date is not None:
        if not isinstance(raw_date, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            )
        try:
            return f"date:{date.fromisoformat(raw_date).isoformat()}"
        except ValueError:
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            ) from None
    if raw_datetime is not None:
        if not isinstance(raw_datetime, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            )
        parsed = _parse_google_datetime(
            raw_datetime,
            raw.get("timeZone"),
            "Google Calendar returned invalid recurrence identity",
        )
        return f"dateTime:{_rfc3339_utc(parsed.astimezone(timezone.utc))}"
    return None


def _original_start_query(raw: Any, zone: ZoneInfo) -> Optional[str]:
    """Return the RFC3339 value accepted by events.instances.originalStart."""

    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise GoogleCalendarResponseError(
            "Google Calendar returned invalid recurrence identity"
        )
    raw_date = raw.get("date")
    raw_datetime = raw.get("dateTime")
    if raw_date is not None and raw_datetime is not None:
        raise GoogleCalendarResponseError(
            "Google Calendar returned invalid recurrence identity"
        )
    if raw_date is not None:
        if not isinstance(raw_date, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            )
        try:
            parsed_date = date.fromisoformat(raw_date)
        except ValueError:
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            ) from None
        return datetime.combine(
            parsed_date, datetime.min.time(), tzinfo=zone
        ).isoformat()
    if raw_datetime is not None:
        if not isinstance(raw_datetime, str):
            raise GoogleCalendarResponseError(
                "Google Calendar returned invalid recurrence identity"
            )
        parsed = _parse_google_datetime(
            raw_datetime,
            raw.get("timeZone"),
            "Google Calendar returned invalid recurrence identity",
        )
        return _rfc3339_utc(parsed.astimezone(timezone.utc))
    return None


def _parse_google_datetime(
    raw: str, raw_time_zone: Any, error_message: str
) -> datetime:
    try:
        parsed = isoparse(raw)
    except (TypeError, ValueError, OverflowError):
        raise GoogleCalendarResponseError(error_message) from None
    if parsed.tzinfo is not None:
        return parsed
    if not isinstance(raw_time_zone, str) or not raw_time_zone.strip():
        raise GoogleCalendarResponseError(error_message)
    try:
        source_zone = ZoneInfo(raw_time_zone.strip())
    except (ZoneInfoNotFoundError, ValueError):
        raise GoogleCalendarResponseError(error_message) from None
    return parsed.replace(tzinfo=source_zone)


def _normalized_updated(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid update time"
        )
    try:
        parsed = isoparse(raw)
    except (TypeError, ValueError, OverflowError):
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid update time"
        ) from None
    if parsed.tzinfo is None:
        raise GoogleCalendarResponseError(
            "Google Calendar returned an invalid update time"
        )
    return _rfc3339_utc(parsed.astimezone(timezone.utc))


def _response_items(content: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    raw_items = content.get("items", [])
    if not isinstance(raw_items, list) or any(
        not isinstance(item, Mapping) for item in raw_items
    ):
        raise GoogleCalendarResponseError("Google Calendar returned invalid items")
    return raw_items


def _google_error_reason(response: Any) -> Optional[str]:
    """Read only a documented reason code; prefer any retryable reason."""

    try:
        content = response.json()
    except (TypeError, ValueError):
        return None
    return _google_error_reason_from_content(content)


def _google_error_reason_from_content(content: Any) -> Optional[str]:
    if not isinstance(content, Mapping):
        return None
    error = content.get("error")
    if not isinstance(error, Mapping):
        return None
    errors = error.get("errors")
    if not isinstance(errors, list):
        return None
    reasons = []
    for item in errors:
        if not isinstance(item, Mapping):
            continue
        reason = item.get("reason")
        if isinstance(reason, str) and reason:
            reasons.append(reason)
    return next(
        (reason for reason in reasons if reason in _RETRYABLE_GOOGLE_REASONS),
        reasons[0] if reasons else None,
    )


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GoogleCalendarConfigurationError(f"{label} is required")
    return value.strip()


def _required_upstream_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GoogleCalendarResponseError(
            f"Google Calendar returned an invalid {label}"
        )
    return value.strip()


def _optional_text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _validated_redirect_uri(value: Any) -> str:
    redirect_uri = _required_text(value, "Google redirect URI")
    parsed = urlsplit(redirect_uri)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise GoogleCalendarConfigurationError("Google redirect URI is invalid")
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise GoogleCalendarConfigurationError("Google redirect URI must use HTTPS")
    return redirect_uri


def _validate_google_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_GOOGLE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise GoogleCalendarConfigurationError("Google endpoint is invalid")


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise GoogleCalendarConfigurationError(
            "Calendar window start must include a timezone"
        )
    return value.astimezone(timezone.utc)


def _load_zone(value: str) -> ZoneInfo:
    name = _required_text(value, "Calendar timezone")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise GoogleCalendarConfigurationError("Calendar timezone is invalid") from None


def _rfc3339_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
