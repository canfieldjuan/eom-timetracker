from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

import google_calendar as google_module
from google_calendar import (
    CALENDAR_READONLY_SCOPES,
    GOOGLE_AUTHORIZATION_URL,
    GOOGLE_CALENDAR_API_BASE_URL,
    GOOGLE_CALENDAR_BATCH_URL,
    GOOGLE_REVOCATION_URL,
    GOOGLE_TOKEN_URL,
    CalendarOccurrence,
    GoogleCalendarClient,
    GoogleCalendarConfigurationError,
    GoogleCalendarOAuthError,
    GoogleCalendarResponseError,
    GoogleCalendarTransportError,
    TargetedOccurrenceRequest,
    build_authorization_url,
    generate_oauth_state,
    generate_pkce_verifier,
    pkce_challenge,
    stable_occurrence_identity,
)


class StubResponse:
    def __init__(
        self,
        payload,
        status_code=200,
        *,
        json_error=None,
        headers=None,
        content=None,
    ):
        self.payload = payload
        self.status_code = status_code
        self.json_error = json_error
        self.headers = headers or {}
        self.content = content

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


class RequestRecorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def batch_response(payloads, *, statuses=None):
    boundary = "batch_response_boundary"
    statuses = statuses or [200] * len(payloads)
    parts = []
    for index, (payload, status) in enumerate(zip(payloads, statuses, strict=True)):
        parts.append(
            (
                f"--{boundary}\r\n"
                "Content-Type: application/http\r\n"
                f"Content-ID: <response-calendar-{index}>\r\n\r\n"
                f"HTTP/1.1 {status} Status\r\n"
                "Content-Type: application/json\r\n\r\n"
                f"{json.dumps(payload)}\r\n"
            ).encode("utf-8")
        )
    parts.append(f"--{boundary}--\r\n".encode("ascii"))
    return StubResponse(
        None,
        headers={"Content-Type": f"multipart/mixed; boundary={boundary}"},
        content=b"".join(parts),
    )


def calendar_client(request_fn, *, timeout=7.5):
    return GoogleCalendarClient(
        client_id="client.apps.googleusercontent.com",
        client_secret="server-only-client-secret",
        redirect_uri="https://api.example.test/api/admin/google-calendar/oauth/callback",
        timeout_seconds=timeout,
        request_fn=request_fn,
    )


def test_pkce_helpers_generate_valid_values_and_known_s256_challenge():
    state = generate_oauth_state()
    verifier = generate_pkce_verifier()

    assert len(state) >= 43
    assert re.fullmatch(r"[A-Za-z0-9_-]+", state)
    assert 43 <= len(verifier) <= 128
    assert re.fullmatch(r"[A-Za-z0-9._~-]+", verifier)
    assert pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == (
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_authorization_url_is_fixed_host_pkce_and_read_only():
    verifier = "a" * 64
    url = build_authorization_url(
        client_id="client-id",
        redirect_uri="https://api.example.test/oauth/callback",
        state="state-value",
        code_challenge=pkce_challenge(verifier),
        login_hint=" owner@example.com ",
    )

    parsed = urlsplit(url)
    params = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == GOOGLE_AUTHORIZATION_URL
    assert params["scope"] == [" ".join(CALENDAR_READONLY_SCOPES)]
    assert params["response_type"] == ["code"]
    assert params["access_type"] == ["offline"]
    assert params["include_granted_scopes"] == ["false"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"] == [pkce_challenge(verifier)]
    assert params["state"] == ["state-value"]
    assert params["login_hint"] == ["owner@example.com"]
    assert set(params["scope"][0].split()) == set(CALENDAR_READONLY_SCOPES)


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://example.test/callback",
        "https://user:password@example.test/callback",
        "https://example.test/callback#fragment",
        "javascript:alert(1)",
    ],
)
def test_redirect_uri_rejects_unsafe_values(redirect_uri):
    with pytest.raises(GoogleCalendarConfigurationError):
        GoogleCalendarClient(
            client_id="client",
            client_secret="secret",
            redirect_uri=redirect_uri,
        )


def test_code_exchange_uses_fixed_token_host_pkce_timeout_and_readonly_scope():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "access_token": "access-secret",
                    "refresh_token": "refresh-secret",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": " ".join(CALENDAR_READONLY_SCOPES),
                }
            )
        ]
    )
    client = calendar_client(recorder)

    token_set = client.exchange_code(code="one-time-code", code_verifier="v" * 64)

    assert token_set.access_token == "access-secret"
    assert token_set.refresh_token == "refresh-secret"
    assert token_set.scopes == CALENDAR_READONLY_SCOPES
    assert "access-secret" not in repr(token_set)
    assert "refresh-secret" not in repr(token_set)
    method, url, kwargs = recorder.calls[0]
    assert method == "POST"
    assert url == GOOGLE_TOKEN_URL
    assert kwargs["timeout"] == 7.5
    assert kwargs["allow_redirects"] is False
    assert kwargs["data"]["grant_type"] == "authorization_code"
    assert kwargs["data"]["code_verifier"] == "v" * 64
    assert kwargs["data"]["code"] == "one-time-code"
    assert "scope" not in kwargs["data"]


def test_refresh_preserves_existing_refresh_token_when_google_omits_it():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "access_token": "new-access-token",
                    "expires_in": 1800,
                    "token_type": "Bearer",
                    "scope": " ".join(CALENDAR_READONLY_SCOPES),
                }
            )
        ]
    )
    token_set = calendar_client(recorder).refresh_access_token(
        refresh_token="durable-refresh-token"
    )

    assert token_set.refresh_token == "durable-refresh-token"
    method, url, kwargs = recorder.calls[0]
    assert method == "POST"
    assert url == GOOGLE_TOKEN_URL
    assert kwargs["data"] == {
        "client_id": "client.apps.googleusercontent.com",
        "client_secret": "server-only-client-secret",
        "grant_type": "refresh_token",
        "refresh_token": "durable-refresh-token",
    }


@pytest.mark.parametrize("status_code", [200, 400])
def test_revoke_token_is_fixed_host_idempotent_and_does_not_parse_a_body(status_code):
    recorder = RequestRecorder(
        [StubResponse(None, status_code, json_error=ValueError("not json"))]
    )

    calendar_client(recorder).revoke_token(token="refresh-secret")

    method, url, kwargs = recorder.calls[0]
    assert method == "POST"
    assert url == GOOGLE_REVOCATION_URL
    assert kwargs["data"] == {"token": "refresh-secret"}
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 7.5


def test_revoke_retryable_failure_is_sanitized():
    recorder = RequestRecorder([StubResponse("refresh-secret", 503)])

    with pytest.raises(GoogleCalendarTransportError) as raised:
        calendar_client(recorder).revoke_token(token="refresh-secret")

    assert raised.value.retryable is True
    assert "refresh-secret" not in repr(raised.value)


@pytest.mark.parametrize(
    "unexpected_scope",
    [
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/drive.readonly",
    ],
)
def test_token_response_rejects_any_scope_outside_exact_readonly_set(
    unexpected_scope,
):
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "access_token": "access-secret",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": (
                        f"{' '.join(CALENDAR_READONLY_SCOPES)} {unexpected_scope}"
                    ),
                }
            )
        ]
    )

    with pytest.raises(GoogleCalendarOAuthError, match="unexpected Calendar scope"):
        calendar_client(recorder).exchange_code(code="code", code_verifier="v" * 64)


@pytest.mark.parametrize(
    "scope",
    [
        CALENDAR_READONLY_SCOPES[0],
        CALENDAR_READONLY_SCOPES[1],
        "https://www.googleapis.com/auth/calendar.readonly",
    ],
)
def test_token_response_rejects_incomplete_or_legacy_broad_scope(scope):
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "access_token": "access-secret",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": scope,
                }
            )
        ]
    )

    with pytest.raises(GoogleCalendarOAuthError, match="unexpected Calendar scope"):
        calendar_client(recorder).exchange_code(code="code", code_verifier="v" * 64)


def test_list_calendars_paginates_and_normalizes_without_write_calls():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "items": [
                        {
                            "id": "primary@example.com",
                            "summary": "Operations",
                            "primary": True,
                            "selected": True,
                            "accessRole": "owner",
                            "timeZone": "America/Chicago",
                        }
                    ],
                    "nextPageToken": "page-2",
                }
            ),
            StubResponse(
                {
                    "items": [
                        {
                            "id": "team@example.com",
                            "summary": "Team",
                            "summaryOverride": "Cleaning plan",
                            "accessRole": "reader",
                        }
                    ]
                }
            ),
        ]
    )

    calendars = calendar_client(recorder).list_calendars(access_token="access-secret")

    assert [calendar.calendar_id for calendar in calendars] == [
        "primary@example.com",
        "team@example.com",
    ]
    assert calendars[0].primary is True
    assert calendars[1].summary == "Cleaning plan"
    assert [call[0] for call in recorder.calls] == ["GET", "GET"]
    assert all(
        call[1] == f"{GOOGLE_CALENDAR_API_BASE_URL}/users/me/calendarList"
        for call in recorder.calls
    )
    assert recorder.calls[0][2]["headers"]["Authorization"] == "Bearer access-secret"
    assert "pageToken" not in recorder.calls[0][2]["params"]
    assert recorder.calls[1][2]["params"]["pageToken"] == "page-2"
    assert all(call[2]["timeout"] == 7.5 for call in recorder.calls)
    assert all(call[2]["allow_redirects"] is False for call in recorder.calls)


def test_list_occurrences_requests_fixed_30_days_and_normalizes_event_shapes():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "items": [
                        {
                            "id": "instance-1",
                            "recurringEventId": "series-1",
                            "originalStartTime": {
                                "dateTime": "2026-07-20T09:00:00",
                                "timeZone": "America/Chicago",
                            },
                            "summary": "Acme Office",
                            "location": "100 Main St",
                            "status": "confirmed",
                            "start": {
                                "dateTime": "2026-07-20T09:30:00",
                                "timeZone": "America/Chicago",
                            },
                            "end": {"dateTime": "2026-07-20T16:00:00Z"},
                            "updated": "2026-07-18T12:30:00-05:00",
                        },
                        {
                            "id": "all-day-1",
                            "summary": "Flexible service day",
                            "status": "tentative",
                            "start": {"date": "2026-07-21"},
                            "end": {"date": "2026-07-22"},
                        },
                    ],
                    "nextPageToken": "next-events",
                }
            ),
            StubResponse(
                {
                    "items": [
                        {
                            "id": "cancelled-instance",
                            "recurringEventId": "series-2",
                            "originalStartTime": {"date": "2026-07-25"},
                            "status": "cancelled",
                        }
                    ]
                }
            ),
        ]
    )
    start = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)

    occurrences = calendar_client(recorder).list_occurrences(
        access_token="access-secret",
        calendar_id="ops+plan@example.com",
        window_start=start,
        time_zone="America/Chicago",
    )

    assert len(occurrences) == 3
    timed = occurrences[0]
    assert isinstance(timed, CalendarOccurrence)
    assert timed.start == "2026-07-20T09:30:00-05:00"
    assert timed.end == "2026-07-20T11:00:00-05:00"
    assert timed.original_start == "2026-07-20T09:00:00-05:00"
    assert timed.updated == "2026-07-18T17:30:00Z"
    assert timed.all_day is False
    assert occurrences[1].all_day is True
    assert occurrences[1].start == "2026-07-21"
    assert occurrences[1].end == "2026-07-22"
    assert occurrences[2].cancelled is True
    assert occurrences[2].start is None
    assert occurrences[2].original_start == "2026-07-25"
    assert occurrences[2].all_day is True

    method, url, kwargs = recorder.calls[0]
    assert method == "GET"
    assert url == (
        f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/ops%2Bplan%40example.com/events"
    )
    assert kwargs["params"]["singleEvents"] == "true"
    assert kwargs["params"]["showDeleted"] == "true"
    assert kwargs["params"]["orderBy"] == "startTime"
    assert kwargs["params"]["timeZone"] == "America/Chicago"
    assert kwargs["params"]["timeMin"] == "2026-07-18T12:00:00Z"
    assert kwargs["params"]["timeMax"] == "2026-08-17T12:00:00Z"
    assert recorder.calls[1][2]["params"]["pageToken"] == "next-events"


def test_list_occurrences_rejects_more_than_bounded_preview_cap(monkeypatch):
    monkeypatch.setattr(google_module, "MAX_PREVIEW_OCCURRENCES", 1)
    event = {
        "id": "event-1",
        "status": "confirmed",
        "start": {"dateTime": "2026-07-20T09:00:00-05:00"},
        "end": {"dateTime": "2026-07-20T11:00:00-05:00"},
    }
    recorder = RequestRecorder(
        [StubResponse({"items": [event, {**event, "id": "event-2"}]})]
    )

    with pytest.raises(GoogleCalendarResponseError, match="too many occurrences"):
        calendar_client(recorder).list_occurrences(
            access_token="token",
            calendar_id="calendar",
            window_start=datetime(2026, 7, 18, tzinfo=timezone.utc),
            time_zone="America/Chicago",
        )


def test_get_occurrence_reads_one_fixed_identity_outside_the_list_window():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "id": "moved+instance",
                    "status": "confirmed",
                    "start": {"dateTime": "2026-09-01T09:00:00-05:00"},
                    "end": {"dateTime": "2026-09-01T11:00:00-05:00"},
                }
            )
        ]
    )

    occurrence = calendar_client(recorder).get_occurrence(
        access_token="token",
        calendar_id="ops@example.com",
        event_id="moved+instance",
        time_zone="America/Chicago",
    )

    assert occurrence.event_id == "moved+instance"
    method, url, kwargs = recorder.calls[0]
    assert method == "GET"
    assert url == (
        f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/"
        "ops%40example.com/events/moved%2Binstance"
    )
    assert kwargs["params"] == {"timeZone": "America/Chicago"}
    assert kwargs["headers"]["Authorization"] == "Bearer token"


def test_get_recurring_occurrence_reads_by_series_and_original_start():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "items": [
                        {
                            "id": "instance-v2",
                            "recurringEventId": "series+1",
                            "originalStartTime": {
                                "dateTime": "2026-07-20T09:00:00-05:00"
                            },
                            "status": "confirmed",
                            "start": {"dateTime": "2026-09-01T09:00:00-05:00"},
                            "end": {"dateTime": "2026-09-01T11:00:00-05:00"},
                        }
                    ]
                }
            )
        ]
    )

    occurrence = calendar_client(recorder).get_recurring_occurrence(
        access_token="token",
        calendar_id="ops@example.com",
        recurring_event_id="series+1",
        original_start="2026-07-20T14:00:00Z",
        time_zone="America/Chicago",
    )

    assert occurrence.event_id == "instance-v2"
    method, url, kwargs = recorder.calls[0]
    assert method == "GET"
    assert url == (
        f"{GOOGLE_CALENDAR_API_BASE_URL}/calendars/"
        "ops%40example.com/events/series%2B1/instances"
    )
    assert kwargs["params"] == {
        "maxResults": 2,
        "originalStart": "2026-07-20T14:00:00Z",
        "showDeleted": "true",
        "timeZone": "America/Chicago",
    }
    assert kwargs["headers"]["Authorization"] == "Bearer token"


def test_targeted_occurrences_use_one_bounded_batch_request():
    recorder = RequestRecorder(
        [
            batch_response(
                [
                    {
                        "id": "standalone+1",
                        "status": "confirmed",
                        "start": {"dateTime": "2026-09-01T09:00:00-05:00"},
                        "end": {"dateTime": "2026-09-01T11:00:00-05:00"},
                    },
                    {
                        "items": [
                            {
                                "id": "instance-v2",
                                "recurringEventId": "series+1",
                                "originalStartTime": {
                                    "dateTime": "2026-07-20T09:00:00-05:00"
                                },
                                "status": "confirmed",
                                "start": {"dateTime": "2026-09-02T09:00:00-05:00"},
                                "end": {"dateTime": "2026-09-02T11:00:00-05:00"},
                            }
                        ]
                    },
                ]
            )
        ]
    )

    occurrences = calendar_client(recorder).get_occurrences_batch(
        access_token="token",
        calendar_id="ops@example.com",
        requests_=[
            TargetedOccurrenceRequest(event_id="standalone+1"),
            TargetedOccurrenceRequest(
                event_id="instance-v1",
                recurring_event_id="series+1",
                original_start="2026-07-20T14:00:00Z",
            ),
        ],
        time_zone="America/Chicago",
    )

    assert [occurrence.event_id for occurrence in occurrences] == [
        "standalone+1",
        "instance-v2",
    ]
    assert len(recorder.calls) == 1
    method, url, kwargs = recorder.calls[0]
    assert method == "POST"
    assert url == GOOGLE_CALENDAR_BATCH_URL
    assert kwargs["headers"]["Authorization"] == "Bearer token"
    assert kwargs["headers"]["Content-Type"].startswith("multipart/mixed;")
    request_body = kwargs["data"].decode("utf-8")
    assert (
        "/calendar/v3/calendars/ops%40example.com/events/standalone%2B1" in request_body
    )
    assert (
        "/calendar/v3/calendars/ops%40example.com/events/series%2B1/instances"
        in request_body
    )
    assert "originalStart=2026-07-20T14%3A00%3A00Z" in request_body


def test_targeted_batch_returns_tombstones_for_confirmed_deleted_identities():
    recorder = RequestRecorder(
        [
            batch_response(
                [
                    {
                        "error": {
                            "errors": [{"reason": "deleted"}],
                            "message": "Resource has been deleted",
                        }
                    },
                    {"items": []},
                ],
                statuses=[410, 200],
            )
        ]
    )

    occurrences = calendar_client(recorder).get_occurrences_batch(
        access_token="token",
        calendar_id="ops@example.com",
        requests_=[
            TargetedOccurrenceRequest(event_id="deleted-standalone"),
            TargetedOccurrenceRequest(
                event_id="deleted-instance",
                recurring_event_id="series-1",
                original_start="2026-07-20T14:00:00Z",
            ),
        ],
        time_zone="America/Chicago",
    )

    assert occurrences == [None, None]


@pytest.mark.parametrize(
    ("recurring_event_id", "original_start"),
    [
        (" ", " "),
        ("series-1", None),
        (None, "2026-07-20T14:00:00Z"),
        (123, "2026-07-20T14:00:00Z"),
    ],
)
def test_targeted_occurrence_request_rejects_malformed_recurring_identity(
    recurring_event_id, original_start
):
    with pytest.raises(
        GoogleCalendarConfigurationError, match="Recurring Calendar identity"
    ):
        TargetedOccurrenceRequest(
            event_id="event-1",
            recurring_event_id=recurring_event_id,
            original_start=original_start,
        )


def test_targeted_batch_classifies_not_found_as_retryable_not_deleted():
    recorder = RequestRecorder(
        [
            batch_response(
                [
                    {
                        "error": {
                            "errors": [{"reason": "notFound"}],
                            "message": "body-secret",
                        }
                    }
                ],
                statuses=[404],
            )
        ]
    )

    with pytest.raises(GoogleCalendarTransportError) as raised:
        calendar_client(recorder).get_occurrences_batch(
            access_token="token",
            calendar_id="ops@example.com",
            requests_=[TargetedOccurrenceRequest(event_id="event-1")],
            time_zone="America/Chicago",
        )

    assert raised.value.status_code == 404
    assert raised.value.retryable is True
    assert "body-secret" not in repr(raised.value)


def test_targeted_batch_propagates_retryable_inner_error_without_body_leak():
    recorder = RequestRecorder(
        [
            batch_response(
                [
                    {
                        "error": {
                            "errors": [{"reason": "userRateLimitExceeded"}],
                            "message": "body-secret",
                        }
                    }
                ],
                statuses=[403],
            )
        ]
    )

    with pytest.raises(GoogleCalendarTransportError) as raised:
        calendar_client(recorder).get_occurrences_batch(
            access_token="token",
            calendar_id="ops@example.com",
            requests_=[TargetedOccurrenceRequest(event_id="event-1")],
            time_zone="America/Chicago",
        )

    assert raised.value.retryable is True
    assert "body-secret" not in repr(raised.value)


def test_moved_recurring_occurrence_uses_current_timing_shape_not_original_shape():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "items": [
                        {
                            "id": "moved-instance",
                            "recurringEventId": "all-day-series",
                            "originalStartTime": {"date": "2026-07-20"},
                            "status": "confirmed",
                            "start": {"dateTime": "2026-07-20T20:00:00-05:00"},
                            "end": {"dateTime": "2026-07-20T22:00:00-05:00"},
                        }
                    ]
                }
            )
        ]
    )

    occurrence = calendar_client(recorder).list_occurrences(
        access_token="token",
        calendar_id="calendar",
        window_start=datetime(2026, 7, 18, tzinfo=timezone.utc),
        time_zone="America/Chicago",
    )[0]

    assert occurrence.original_start == "2026-07-20"
    assert occurrence.original_start_query == "2026-07-20T00:00:00-05:00"
    assert occurrence.start == "2026-07-20T20:00:00-05:00"
    assert occurrence.all_day is False


def test_stable_occurrence_identity_survives_edit_and_move():
    original = {
        "id": "instance-v1",
        "recurringEventId": "series-1",
        "originalStartTime": {"dateTime": "2026-07-20T09:00:00-05:00"},
        "summary": "Original title",
        "start": {"dateTime": "2026-07-20T09:00:00-05:00"},
    }
    edited = {
        **original,
        "id": "instance-v2",
        "summary": "Edited title",
        "start": {"dateTime": "2026-07-20T11:00:00-05:00"},
    }
    non_recurring = {"id": "standalone", "start": {"date": "2026-07-20"}}
    moved_non_recurring = {"id": "standalone", "start": {"date": "2026-07-22"}}

    assert stable_occurrence_identity(
        "calendar", original
    ) == stable_occurrence_identity("calendar", edited)
    assert stable_occurrence_identity(
        "calendar", non_recurring
    ) == stable_occurrence_identity("calendar", moved_non_recurring)
    assert stable_occurrence_identity(
        "calendar-a", original
    ) != stable_occurrence_identity("calendar-b", original)


def test_pagination_cycle_is_rejected():
    recorder = RequestRecorder(
        [
            StubResponse({"items": [], "nextPageToken": "repeat"}),
            StubResponse({"items": [], "nextPageToken": "repeat"}),
        ]
    )

    with pytest.raises(GoogleCalendarResponseError, match="invalid pagination"):
        calendar_client(recorder).list_calendars(access_token="token")


@pytest.mark.parametrize(
    "reason",
    [
        "calendarUsageLimitsExceeded",
        "quotaExceeded",
        "rateLimitExceeded",
        "userRateLimitExceeded",
    ],
)
def test_calendar_403_rate_or_quota_limit_is_retryable(reason):
    recorder = RequestRecorder(
        [
            StubResponse(
                {"error": {"errors": [{"reason": reason}], "message": "secret"}},
                403,
            )
        ]
    )

    with pytest.raises(GoogleCalendarTransportError) as raised:
        calendar_client(recorder).list_calendars(access_token="access-secret")

    assert raised.value.retryable is True
    assert raised.value.status_code == 403
    assert "secret" not in repr(raised.value)


def test_calendar_403_prefers_retryable_reason_anywhere_in_error_list():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "error": {
                        "errors": [
                            {"reason": "forbidden"},
                            {"reason": "rateLimitExceeded"},
                        ]
                    }
                },
                403,
            )
        ]
    )

    with pytest.raises(GoogleCalendarTransportError):
        calendar_client(recorder).list_calendars(access_token="access-secret")


def test_calendar_generic_403_is_not_mislabeled_as_expired_oauth():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "error": {
                        "errors": [{"reason": "forbidden"}],
                        "message": "secret",
                    }
                },
                403,
            )
        ]
    )

    with pytest.raises(GoogleCalendarResponseError) as raised:
        calendar_client(recorder).list_calendars(access_token="access-secret")

    assert raised.value.status_code == 403
    assert not isinstance(raised.value, GoogleCalendarOAuthError)
    assert "secret" not in repr(raised.value)


def test_calendar_404_is_retryable_and_sanitized():
    recorder = RequestRecorder(
        [
            StubResponse(
                {
                    "error": {
                        "errors": [{"reason": "notFound"}],
                        "message": "body-secret",
                    }
                },
                404,
            )
        ]
    )

    with pytest.raises(GoogleCalendarTransportError) as raised:
        calendar_client(recorder).list_calendars(access_token="access-secret")

    assert raised.value.status_code == 404
    assert raised.value.retryable is True
    assert "body-secret" not in repr(raised.value)


@pytest.mark.parametrize(
    ("response", "expected_error"),
    [
        (
            StubResponse({"error": {"message": "body-secret"}}, 400),
            GoogleCalendarOAuthError,
        ),
        (StubResponse("body-secret", 503), GoogleCalendarTransportError),
        (StubResponse("body-secret", 307), GoogleCalendarResponseError),
        (
            StubResponse(None, json_error=ValueError("body-secret")),
            GoogleCalendarResponseError,
        ),
    ],
)
def test_errors_are_typed_and_do_not_leak_google_body_or_credentials(
    response, expected_error
):
    recorder = RequestRecorder([response])
    client = calendar_client(recorder)

    with pytest.raises(expected_error) as raised:
        client.exchange_code(code="authorization-secret", code_verifier="v" * 64)

    rendered = repr(raised.value)
    assert "body-secret" not in rendered
    assert "authorization-secret" not in rendered
    assert "server-only-client-secret" not in rendered
    assert raised.value.__cause__ is None


def test_transport_error_is_retryable_sanitized_and_uses_monkeypatchable_requests(
    monkeypatch,
):
    def fail_request(*_args, **_kwargs):
        raise requests.ConnectionError("access-secret body-secret")

    monkeypatch.setattr(requests, "request", fail_request)
    client = GoogleCalendarClient(
        client_id="client",
        client_secret="client-secret",
        redirect_uri="https://api.example.test/oauth/callback",
    )

    with pytest.raises(GoogleCalendarTransportError) as raised:
        client.list_calendars(access_token="access-secret")

    assert raised.value.retryable is True
    assert "access-secret" not in repr(raised.value)
    assert "body-secret" not in repr(raised.value)
    assert raised.value.__cause__ is None


def test_occurrence_validation_rejects_naive_window_and_invalid_timezone():
    client = calendar_client(RequestRecorder([]))

    with pytest.raises(GoogleCalendarConfigurationError, match="include a timezone"):
        client.list_occurrences(
            access_token="token",
            calendar_id="calendar",
            window_start=datetime(2026, 7, 18),
            time_zone="America/Chicago",
        )
    with pytest.raises(GoogleCalendarConfigurationError, match="timezone is invalid"):
        client.list_occurrences(
            access_token="token",
            calendar_id="calendar",
            window_start=datetime(2026, 7, 18, tzinfo=timezone.utc),
            time_zone="Not/AZone",
        )
