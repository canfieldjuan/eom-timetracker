"""Route and PostgreSQL proof for reviewed Google planned-visit imports."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import logging
from threading import Event
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import calendar_import_api as calendar_api
import calendar_import_store as store
import db
from google_calendar import (
    CALENDAR_READONLY_SCOPES,
    CalendarOccurrence,
    CalendarSummary,
    GoogleCalendarOAuthError,
    GoogleCalendarTransportError,
    GoogleCalendarResponseError,
    OAuthTokenSet,
    stable_occurrence_identity,
)


UTC = timezone.utc
WINDOW_START = datetime(2026, 7, 20, 13, 0, tzinfo=UTC)
REAL_PREVIEW_WINDOW_BOUNDS = calendar_api._preview_window_bounds


class FakeGoogleClient:
    occurrences: list[CalendarOccurrence] = []
    occurrences_by_calendar: dict[str, list[CalendarOccurrence]] = {}
    occurrence_errors_by_calendar: dict[str, Exception] = {}
    targeted_occurrences: dict[str, CalendarOccurrence | None] = {}
    targeted_recurring_occurrences: dict[
        tuple[str, str], CalendarOccurrence | None
    ] = {}
    calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        )
    ]
    exchanged_codes: list[str] = []
    revoked_tokens: list[str] = []
    revoke_error: Exception | None = None
    authorization_error: Exception | None = None
    refresh_error: Exception | None = None
    exchange_refresh_token = "refresh-secret"
    login_hints: list[str | None] = []
    batch_calls = 0

    def __init__(self, **_: object) -> None:
        pass

    def authorization_url(
        self, *, state: str, code_challenge: str, login_hint: str | None = None
    ) -> str:
        if self.authorization_error is not None:
            raise self.authorization_error
        assert len(code_challenge) == 43
        self.login_hints.append(login_hint)
        return (
            f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&scope=readonly"
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> OAuthTokenSet:
        assert len(code_verifier) >= 43
        self.exchanged_codes.append(code)
        return OAuthTokenSet(
            access_token="access-secret",
            refresh_token=self.exchange_refresh_token,
            expires_in=3600,
            token_type="Bearer",
            scopes=CALENDAR_READONLY_SCOPES,
        )

    def refresh_access_token(self, *, refresh_token: str) -> OAuthTokenSet:
        if self.refresh_error is not None:
            raise self.refresh_error
        assert refresh_token == "refresh-secret"
        return OAuthTokenSet(
            access_token="refreshed-secret",
            refresh_token=refresh_token,
            expires_in=3600,
            token_type="Bearer",
            scopes=CALENDAR_READONLY_SCOPES,
        )

    def revoke_token(self, *, token: str) -> None:
        if self.revoke_error is not None:
            raise self.revoke_error
        self.revoked_tokens.append(token)

    def list_calendars(self, *, access_token: str) -> list[CalendarSummary]:
        assert access_token in {"access-secret", "refreshed-secret"}
        return list(self.calendars)

    def list_occurrences(
        self, *, calendar_id: str, **_: object
    ) -> list[CalendarOccurrence]:
        error = self.occurrence_errors_by_calendar.get(calendar_id)
        if error is not None:
            raise error
        return list(self.occurrences_by_calendar.get(calendar_id, self.occurrences))

    def get_occurrence(self, *, event_id: str, **_: object) -> CalendarOccurrence:
        occurrence = self.targeted_occurrences.get(event_id)
        if occurrence is None:
            raise GoogleCalendarResponseError(
                "Google Calendar could not reconcile a planned occurrence"
            )
        return occurrence

    def get_recurring_occurrence(
        self,
        *,
        recurring_event_id: str,
        original_start: str,
        **_: object,
    ) -> CalendarOccurrence:
        occurrence = self.targeted_recurring_occurrences.get(
            (recurring_event_id, original_start)
        )
        if occurrence is None:
            raise GoogleCalendarResponseError(
                "Google Calendar could not reconcile a planned recurring occurrence"
            )
        return occurrence

    def get_occurrences_batch(
        self, *, requests_: list[object], **_: object
    ) -> list[CalendarOccurrence | None]:
        if requests_:
            type(self).batch_calls += 1
        occurrences = []
        for request in requests_:
            recurring_event_id = getattr(request, "recurring_event_id")
            original_start = getattr(request, "original_start")
            if recurring_event_id is not None:
                key = (recurring_event_id, original_start)
                if key not in self.targeted_recurring_occurrences:
                    raise GoogleCalendarResponseError(
                        "Google Calendar could not reconcile a planned occurrence"
                    )
                occurrence = self.targeted_recurring_occurrences[key]
            else:
                key = getattr(request, "event_id")
                if key not in self.targeted_occurrences:
                    raise GoogleCalendarResponseError(
                        "Google Calendar could not reconcile a planned occurrence"
                    )
                occurrence = self.targeted_occurrences[key]
            occurrences.append(occurrence)
        return occurrences


def google_occurrence(
    event_id: str,
    *,
    summary: str = "Test Customer",
    start: datetime = WINDOW_START,
    end: datetime | None = None,
    location: str = "123 Main St, Effingham",
    cancelled: bool = False,
    updated: str = "2026-07-18T12:00:00Z",
    recurring_event_id: str | None = None,
    original_start: datetime | None = None,
    calendar_id: str = "operations@example.test",
) -> CalendarOccurrence:
    raw: dict[str, object] = {"id": event_id}
    if recurring_event_id is not None:
        raw["recurringEventId"] = recurring_event_id
    if original_start is not None:
        raw["originalStartTime"] = {"dateTime": original_start.isoformat()}
    return CalendarOccurrence(
        source_key=stable_occurrence_identity(calendar_id, raw),
        calendar_id=calendar_id,
        event_id=event_id,
        recurring_event_id=recurring_event_id,
        original_start=original_start.isoformat() if original_start else None,
        summary=summary,
        location=location,
        status="cancelled" if cancelled else "confirmed",
        cancelled=cancelled,
        all_day=False,
        start=None if cancelled else start.isoformat(),
        end=None if cancelled else (end or start + timedelta(hours=2)).isoformat(),
        time_zone="America/Chicago",
        updated=updated,
        description="Approximate service block",
        etag=f'"{updated}"',
        original_start_query=original_start.isoformat() if original_start else None,
    )


def sparse_cancelled_occurrence(
    original: CalendarOccurrence,
    *,
    updated: str = "2026-07-20T18:00:00Z",
) -> CalendarOccurrence:
    return CalendarOccurrence(
        source_key=original.source_key,
        calendar_id=original.calendar_id,
        event_id=original.event_id,
        recurring_event_id=original.recurring_event_id,
        original_start=original.original_start,
        summary="(Untitled event)",
        location="",
        status="cancelled",
        cancelled=True,
        all_day=False,
        start=None,
        end=None,
        time_zone=original.time_zone,
        updated=updated,
        description="",
        etag=f'"{updated}"',
        original_start_query=original.original_start_query,
    )


@pytest.fixture(autouse=True)
def isolated_calendar_domain(monkeypatch):
    monkeypatch.setattr(calendar_api, "GoogleCalendarClient", FakeGoogleClient)
    monkeypatch.setattr(
        calendar_api,
        "_preview_window_bounds",
        lambda _time_zone_name, **_kwargs: (
            WINDOW_START,
            WINDOW_START + timedelta(days=30),
        ),
    )
    FakeGoogleClient.occurrences = []
    FakeGoogleClient.occurrences_by_calendar = {}
    FakeGoogleClient.occurrence_errors_by_calendar = {}
    FakeGoogleClient.targeted_occurrences = {}
    FakeGoogleClient.targeted_recurring_occurrences = {}
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        )
    ]
    FakeGoogleClient.exchanged_codes = []
    FakeGoogleClient.revoked_tokens = []
    FakeGoogleClient.revoke_error = None
    FakeGoogleClient.authorization_error = None
    FakeGoogleClient.refresh_error = None
    FakeGoogleClient.exchange_refresh_token = "refresh-secret"
    FakeGoogleClient.login_hints = []
    FakeGoogleClient.batch_calls = 0
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM planned_visit_audit_events;
                DELETE FROM planned_visit_assignments;
                DELETE FROM planned_service_visits;
                DELETE FROM google_calendar_event_mappings;
                DELETE FROM calendar_import_previews;
                DELETE FROM google_calendar_oauth_states;
                DELETE FROM shifts
                WHERE notes = 'canonical-calendar-test-evidence';
                DELETE FROM jobs WHERE source_key IS NOT NULL;
                DELETE FROM google_calendar_sources;
                DELETE FROM google_calendar_connections;
                DELETE FROM crew_memberships;
                DELETE FROM locations
                WHERE address IN (
                    '456 Oak St, Effingham', '789 Pine St, Effingham'
                );
                UPDATE locations SET location_type = NULL
                WHERE address = '123 Main St, Effingham';
                DELETE FROM employees WHERE name IN (
                    'Carmen Alvarez', 'Pamela Brown', 'Tina Davis',
                    'Carmen Duplicate'
                );
                """
            )
            cur.execute(
                """
                INSERT INTO employees (name, password_hash, role)
                VALUES ('Carmen Alvarez', 'unused', 'employee'),
                       ('Pamela Brown', 'unused', 'employee'),
                       ('Tina Davis', 'unused', 'employee')
                RETURNING id
                """
            )
            employee_ids = [row[0] for row in cur.fetchall()]
            cur.execute("SELECT id FROM crews WHERE name = 'Morning Crew'")
            crew_id = cur.fetchone()[0]
            for employee_id in employee_ids:
                cur.execute(
                    """
                    INSERT INTO crew_memberships (
                        crew_id, employee_id, effective_from
                    ) VALUES (%s, %s, '2026-01-01')
                    """,
                    (crew_id, employee_id),
                )
    yield
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM planned_visit_audit_events;
                DELETE FROM planned_visit_assignments;
                DELETE FROM planned_service_visits;
                DELETE FROM google_calendar_event_mappings;
                DELETE FROM calendar_import_previews;
                DELETE FROM google_calendar_oauth_states;
                DELETE FROM shifts
                WHERE notes = 'canonical-calendar-test-evidence';
                DELETE FROM jobs WHERE source_key IS NOT NULL;
                DELETE FROM google_calendar_sources;
                DELETE FROM google_calendar_connections;
                DELETE FROM crew_memberships;
                DELETE FROM locations
                WHERE address IN (
                    '456 Oak St, Effingham', '789 Pine St, Effingham'
                );
                UPDATE locations SET location_type = NULL
                WHERE address = '123 Main St, Effingham';
                DELETE FROM employees WHERE name IN (
                    'Carmen Alvarez', 'Pamela Brown', 'Tina Davis',
                    'Carmen Duplicate'
                );
                """
            )


def connect_unselected_calendar() -> int:
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    active = store.active_connection()
    if active:
        store.disconnect_calendar(
            connection_id=int(active["id"]),
            expected_credential_version=int(active["credential_version"]),
            admin_id=1,
            admin_name="Juan Canfield",
        )
    connection = store.create_active_connection(
        account_email="operations@example.test",
        credentials={
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "token_type": "Bearer",
            "scopes": list(CALENDAR_READONLY_SCOPES),
        },
        scopes=CALENDAR_READONLY_SCOPES,
        admin_id=1,
        admin_name="Juan Canfield",
        cipher=cipher,
    )
    return int(connection["id"])


def connect_selected_calendar() -> int:
    connection_id = connect_unselected_calendar()
    credential_version = int(store.active_connection()["credential_version"])
    store.select_calendar(
        connection_id=connection_id,
        calendar_id="operations@example.test",
        calendar_name="Operations",
        calendar_timezone="America/Chicago",
        expected_credential_version=credential_version,
    )
    return connection_id


def configure_canonical_sources(client, auth) -> dict[str, dict[str, object]]:
    connection_id = connect_unselected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="residential@example.test",
            summary="Residential Calendar",
            primary=False,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        ),
        CalendarSummary(
            calendar_id="commercial@example.test",
            summary="Commercial Calendar",
            primary=False,
            selected=True,
            access_role="reader",
            time_zone="America/Chicago",
        ),
    ]
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE locations
                SET location_type = 'Residential'
                WHERE address = '123 Main St, Effingham'
                """
            )
            cur.execute(
                """
                INSERT INTO locations (
                    address, customer_name, location_type, rate, rate_type,
                    expected_hours, active
                ) VALUES (
                    '456 Oak St, Effingham', 'Commercial Customer',
                    'Commercial', 250.00, 'per_visit', 5.0, true
                )
                ON CONFLICT (address) DO UPDATE
                SET customer_name = EXCLUDED.customer_name,
                    location_type = EXCLUDED.location_type,
                    active = true
                """
            )
    configured = client.put(
        "/api/admin/google-calendar/sources",
        headers=auth,
        json={
            "residentialMorningCalendarId": "residential@example.test",
            "commercialEveningNightCalendarId": "commercial@example.test",
        },
    )
    assert configured.status_code == 200, configured.text
    rows = configured.json()["sources"]
    assert {row["role"] for row in rows} == set(store.CALENDAR_SOURCE_ROLES)
    assert all(row["connectionId"] == connection_id for row in rows)
    return {row["role"]: row for row in rows}


def calendar_import_config(**overrides: object) -> calendar_api.CalendarImportConfig:
    values: dict[str, object] = {
        "client_id": "test-google-client",
        "client_secret": "test-google-secret",
        "redirect_uri": ("https://api.example.test/api/google-calendar/oauth/callback"),
        "encryption_key": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        "portal_url": "https://portal.example.test/portal.html",
        "timeout_seconds": 10.0,
        "timezone_name": "America/Chicago",
    }
    values.update(overrides)
    return calendar_api.CalendarImportConfig(**values)


def calendar_import_test_client(
    config: calendar_api.CalendarImportConfig,
) -> TestClient:
    app = FastAPI()
    app.include_router(
        calendar_api.build_calendar_import_router(
            config=config,
            get_current_admin=lambda: {
                "id": 1,
                "name": "Juan Canfield",
                "role": "admin",
            },
        )
    )
    return TestClient(app, raise_server_exceptions=True)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/api/admin/google-calendar/status", None),
        ("post", "/api/admin/google-calendar/connect", {}),
        ("get", "/api/admin/google-calendar/calendars", None),
        (
            "put",
            "/api/admin/google-calendar/sources",
            {
                "residentialMorningCalendarId": "residential@example.test",
                "commercialEveningNightCalendarId": "commercial@example.test",
            },
        ),
        ("post", "/api/admin/google-calendar/sync", {}),
        (
            "put",
            "/api/admin/google-calendar/mappings",
            {
                "sourceId": 1,
                "sourceKey": "a" * 64,
                "sourceFingerprint": "b" * 64,
                "eventId": "event",
                "seriesId": "event",
                "occurrenceId": "event",
                "locationId": 1,
            },
        ),
        ("delete", "/api/admin/google-calendar/connection", None),
        ("get", "/api/admin/planned-visits/crews", None),
        ("post", "/api/admin/google-calendar/preview", {"resolutions": []}),
    ],
)
def test_calendar_admin_routes_enforce_current_admin(
    client, emp_auth, method, path, body
):
    request = getattr(client, method)
    no_auth = request(path, json=body) if body is not None else request(path)
    employee = (
        request(path, headers=emp_auth, json=body)
        if body is not None
        else request(path, headers=emp_auth)
    )

    assert no_auth.status_code == 401
    assert employee.status_code == 403


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://api.example.test/api/google-calendar/oauth/callback/",
        "https://api.example.test/api/admin/google-calendar/oauth/callback",
        "https://api.example.test/%61pi/google-calendar/oauth/callback",
        "not-an-absolute-url",
    ],
)
def test_runtime_config_requires_exact_oauth_callback_path(client, redirect_uri):
    config = calendar_import_config(redirect_uri=redirect_uri)

    assert config.configured is False
    with calendar_import_test_client(config) as configured_client:
        status = configured_client.get("/api/admin/google-calendar/status")
        connect = configured_client.post("/api/admin/google-calendar/connect")

    assert status.status_code == 200
    assert status.json()["configured"] is False
    assert status.json()["connected"] is False
    assert connect.status_code == 503
    assert connect.json()["detail"] == "Google Calendar service is not configured"
    assert redirect_uri not in connect.text


@pytest.mark.parametrize(
    "overrides",
    [
        {"encryption_key": "invalid-fernet-key-secret-material"},
        {"portal_url": "javascript:secret-portal-target"},
        {"portal_url": "http://portal.example.test/portal.html"},
        {"client_secret": "   "},
        {"timeout_seconds": 0},
        {"timezone_name": "Not/A_Timezone"},
    ],
)
def test_status_and_connect_fail_closed_for_invalid_runtime_config(client, overrides):
    config = calendar_import_config(**overrides)

    assert config.configured is False
    with calendar_import_test_client(config) as configured_client:
        status = configured_client.get("/api/admin/google-calendar/status")
        connect = configured_client.post("/api/admin/google-calendar/connect")

    assert status.status_code == 200
    assert status.json()["configured"] is False
    assert status.json()["connected"] is False
    assert connect.status_code == 503
    assert connect.json()["detail"] == "Google Calendar service is not configured"
    for secret_value in overrides.values():
        if isinstance(secret_value, str) and secret_value.strip():
            assert secret_value not in status.text
            assert secret_value not in connect.text


def test_callback_validates_portal_before_exchange_or_connection_install(client):
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    admin = db.query_one("SELECT id FROM employees WHERE name = 'Juan Canfield'")
    state, _ = store.create_oauth_state(admin_id=int(admin["id"]), cipher=cipher)
    config = calendar_import_config(portal_url="javascript:secret-portal-target")

    with calendar_import_test_client(config) as configured_client:
        callback = configured_client.get(
            "/api/google-calendar/oauth/callback",
            params={"state": state, "code": "must-not-be-exchanged"},
            follow_redirects=False,
        )

    assert callback.status_code == 503
    assert callback.json()["detail"] == "Google Calendar service is not configured"
    assert "secret-portal-target" not in callback.text
    assert FakeGoogleClient.exchanged_codes == []
    assert store.active_connection() is None
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )


def test_oauth_state_is_one_use_and_tokens_are_encrypted(client, auth):
    started = client.post("/api/admin/google-calendar/connect", headers=auth)
    assert started.status_code == 200
    authorization_url = started.json()["authorizationUrl"]
    state = parse_qs(urlsplit(authorization_url).query)["state"][0]

    state_row = db.query_one(
        "SELECT state_hash, pkce_verifier_ciphertext FROM google_calendar_oauth_states"
    )
    assert state not in state_row["state_hash"]
    assert "verifier" not in state_row["pkce_verifier_ciphertext"]

    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "one-use-code"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=connected")
    connection = db.query_one(
        "SELECT credential_ciphertext, granted_scopes FROM google_calendar_connections WHERE revoked_at IS NULL"
    )
    assert "access-secret" not in connection["credential_ciphertext"]
    assert "refresh-secret" not in connection["credential_ciphertext"]
    assert set(connection["granted_scopes"]) == set(CALENDAR_READONLY_SCOPES)
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )

    replay = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "replayed-code"},
        follow_redirects=False,
    )
    assert replay.status_code == 303
    assert replay.headers["location"].endswith("calendarImport=error")
    assert FakeGoogleClient.exchanged_codes == ["one-use-code"]


def test_preview_window_is_thirty_calendar_days_in_selected_timezone():
    start, end = REAL_PREVIEW_WINDOW_BOUNDS(
        "America/Chicago",
        now_utc=datetime(2026, 3, 8, 6, 30, tzinfo=UTC),
    )

    assert start == datetime(2026, 3, 8, 6, 0, tzinfo=UTC)
    assert end == datetime(2026, 4, 7, 5, 0, tzinfo=UTC)
    assert end - start == timedelta(hours=719)


def test_only_one_oauth_connection_attempt_can_be_in_flight(client, auth):
    first = client.post("/api/admin/google-calendar/connect", headers=auth)
    second = client.post("/api/admin/google-calendar/connect", headers=auth)

    assert first.status_code == 200
    assert second.status_code == 409
    assert "already in progress" in second.json()["error"]
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 1
    )


def test_denied_oauth_callback_deletes_state_and_allows_immediate_retry(client, auth):
    started = client.post("/api/admin/google-calendar/connect", headers=auth).json()
    state = parse_qs(urlsplit(started["authorizationUrl"]).query)["state"][0]

    denied = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "error": "access_denied"},
        follow_redirects=False,
    )

    assert denied.status_code == 303
    assert denied.headers["location"].endswith("calendarImport=error")
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )
    assert (
        client.post("/api/admin/google-calendar/connect", headers=auth).status_code
        == 200
    )


def test_authorization_url_failure_deletes_state_and_allows_retry(client, auth):
    FakeGoogleClient.authorization_error = GoogleCalendarResponseError(
        "authorization failed"
    )

    failed = client.post("/api/admin/google-calendar/connect", headers=auth)

    assert failed.status_code == 502
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )
    FakeGoogleClient.authorization_error = None
    assert (
        client.post("/api/admin/google-calendar/connect", headers=auth).status_code
        == 200
    )


def test_failed_oauth_install_revokes_newly_issued_grant(client, auth, monkeypatch):
    started = client.post("/api/admin/google-calendar/connect", headers=auth).json()
    state = parse_qs(urlsplit(started["authorizationUrl"]).query)["state"][0]

    def reject_install(**_kwargs):
        raise store.CalendarStoreError("connection race")

    monkeypatch.setattr(store, "create_active_connection", reject_install)
    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "issued-but-not-installed"},
        follow_redirects=False,
    )

    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=error")
    assert FakeGoogleClient.revoked_tokens == ["refresh-secret"]
    assert store.active_connection() is None
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )
    assert (
        client.post("/api/admin/google-calendar/connect", headers=auth).status_code
        == 200
    )


def test_callback_install_race_does_not_revoke_the_winning_connection(
    client, auth, monkeypatch
):
    started = client.post("/api/admin/google-calendar/connect", headers=auth).json()
    state = parse_qs(urlsplit(started["authorizationUrl"]).query)["state"][0]
    real_create = store.create_active_connection

    def install_winner_then_report_race(**kwargs):
        real_create(**kwargs)
        raise store.CalendarStoreError("connection race")

    monkeypatch.setattr(
        store, "create_active_connection", install_winner_then_report_race
    )
    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "concurrent-install"},
        follow_redirects=False,
    )

    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=error")
    assert store.active_connection() is not None
    assert FakeGoogleClient.revoked_tokens == []
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_oauth_states")["n"] == 0
    )


def test_oauth_access_log_filter_redacts_callback_query_only():
    callback = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "127.0.0.1:1",
            "GET",
            "/api/google-calendar/oauth/callback?state=state-secret&code=code-secret",
            "1.1",
            303,
        ),
        None,
    )
    ordinary = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", "/api/health?probe=1", "1.1", 200),
        None,
    )

    filter_ = calendar_api.CalendarOAuthAccessLogFilter()
    assert filter_.filter(callback) is True
    assert filter_.filter(ordinary) is True
    assert "state-secret" not in callback.getMessage()
    assert "code-secret" not in callback.getMessage()
    assert "?redacted" in callback.getMessage()
    assert "/api/health?probe=1" in ordinary.getMessage()


def test_status_calendar_selection_and_morning_crew_resolution(client, auth):
    status = client.get("/api/admin/google-calendar/status", headers=auth)
    assert status.status_code == 200
    assert status.json() == {
        "configured": True,
        "connected": False,
        "connectionId": None,
        "scope": " ".join(CALENDAR_READONLY_SCOPES),
        "scopes": list(CALENDAR_READONLY_SCOPES),
        "accountEmail": None,
        "selectedCalendarId": None,
        "selectedCalendarName": None,
        "selectedCalendarTimeZone": None,
        "capabilityVersion": "canonical-schedule.v1",
        "sourcesReady": False,
        "syncStatus": "disconnected",
        "sources": [],
    }

    connection_id = connect_selected_calendar()
    connected_status = client.get("/api/admin/google-calendar/status", headers=auth)
    assert connected_status.status_code == 200
    assert connected_status.json()["connectionId"] == connection_id
    reconnect = client.post("/api/admin/google-calendar/connect", headers=auth)
    assert reconnect.status_code == 200
    assert reconnect.json()["authorizationUrl"].startswith(
        "https://accounts.google.com/"
    )
    assert FakeGoogleClient.login_hints == ["operations@example.test"]
    calendars = client.get("/api/admin/google-calendar/calendars", headers=auth)
    assert calendars.status_code == 200
    assert calendars.json()["calendars"][0]["name"] == "Operations"

    selected = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "operations@example.test"},
    )
    assert selected.status_code == 200

    crews = client.get("/api/admin/planned-visits/crews", headers=auth)
    assert crews.status_code == 200
    assert crews.json()["morningCrew"]["ready"] is True
    assert crews.json()["morningCrew"]["identityIssues"] == []
    assert len(crews.json()["morningCrew"]["memberIds"]) == 3


def test_calendar_without_provider_timezone_uses_configured_fallback(client, auth):
    connection_id = connect_unselected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone=None,
        )
    ]

    selected = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "operations@example.test"},
    )

    assert selected.status_code == 200, selected.text
    status = client.get("/api/admin/google-calendar/status", headers=auth)
    assert status.status_code == 200, status.text
    assert status.json()["connectionId"] == connection_id
    assert status.json()["selectedCalendarTimeZone"] == "America/Chicago"

    FakeGoogleClient.occurrences = [google_occurrence("timezone-fallback")]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "expectedConnectionId": connection_id,
            "expectedCalendarId": "operations@example.test",
            "expectedCalendarTimeZone": "America/Chicago",
            "resolutions": [],
        },
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["calendarTimeZone"] == "America/Chicago"


def test_preview_binds_and_returns_the_expected_source_identity(client, auth):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("source-bound-preview")]
    payload = {
        "expectedConnectionId": connection_id,
        "expectedCalendarId": "operations@example.test",
        "expectedCalendarTimeZone": "America/Chicago",
        "resolutions": [],
    }

    preview = client.post(
        "/api/admin/google-calendar/preview", headers=auth, json=payload
    )

    assert preview.status_code == 200, preview.text
    assert preview.json()["connectionId"] == connection_id
    assert preview.json()["calendarId"] == "operations@example.test"
    assert preview.json()["calendarTimeZone"] == "America/Chicago"

    changed = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={**payload, "expectedConnectionId": connection_id + 1},
    )
    assert changed.status_code == 409
    assert changed.json()["error"] == (
        "Google Calendar connection changed; create a new preview"
    )


def test_preview_rejects_partial_source_expectation(client, auth):
    response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"expectedConnectionId": 1, "resolutions": []},
    )

    assert response.status_code == 422


def test_bound_preview_normalizes_disconnect_and_cleared_selection_conflicts(
    client, auth
):
    connection_id = connect_selected_calendar()
    payload = {
        "expectedConnectionId": connection_id,
        "expectedCalendarId": "operations@example.test",
        "expectedCalendarTimeZone": "America/Chicago",
        "resolutions": [],
    }
    active = store.active_connection()
    store.disconnect_calendar(
        connection_id=connection_id,
        expected_credential_version=int(active["credential_version"]),
        admin_id=1,
        admin_name="Juan Canfield",
    )

    disconnected = client.post(
        "/api/admin/google-calendar/preview", headers=auth, json=payload
    )
    assert disconnected.status_code == 409
    assert disconnected.json()["error"] == (
        "Google Calendar connection changed; create a new preview"
    )

    replacement_id = connect_selected_calendar()
    db.execute(
        """
        UPDATE google_calendar_connections
        SET selected_calendar_id = NULL,
            selected_calendar_name = NULL,
            selected_calendar_timezone = NULL
        WHERE id = %s
        """,
        (replacement_id,),
    )
    no_selection = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={**payload, "expectedConnectionId": replacement_id},
    )
    assert no_selection.status_code == 409
    assert no_selection.json()["error"] == (
        "Selected Google Calendar changed; create a new preview"
    )


def test_preview_insert_rechecks_the_active_source_after_provider_reads(
    client, auth, monkeypatch
):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("preview-insert-race")]
    real_create_preview = store.create_preview

    def switch_source_then_create(**kwargs):
        active = store.active_connection()
        store.select_calendar(
            connection_id=connection_id,
            calendar_id="different@example.test",
            calendar_name="Different calendar",
            calendar_timezone="America/Chicago",
            expected_credential_version=int(active["credential_version"]),
        )
        return real_create_preview(**kwargs)

    monkeypatch.setattr(store, "create_preview", switch_source_then_create)

    response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "expectedConnectionId": connection_id,
            "expectedCalendarId": "operations@example.test",
            "expectedCalendarTimeZone": "America/Chicago",
            "resolutions": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"] == (
        "Google Calendar connection changed; create a new preview"
    )
    assert store.active_connection()["selected_calendar_id"] == "different@example.test"
    assert db.query_one("SELECT COUNT(*) AS n FROM calendar_import_previews")["n"] == 0


def test_invalid_grant_reauthorizes_exact_connection_with_future_visit(
    client, auth, monkeypatch
):
    future_start = datetime.now(UTC) + timedelta(days=1)
    monkeypatch.setattr(
        calendar_api,
        "_preview_window_bounds",
        lambda _time_zone_name, **_kwargs: (
            future_start - timedelta(hours=1),
            future_start + timedelta(days=30),
        ),
    )
    connection_id = connect_selected_calendar()
    original = google_occurrence("reauthorize-future", start=future_start)
    FakeGoogleClient.occurrences = [original]
    approve_current_preview(client, auth)

    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    store.update_connection_credentials(
        connection_id,
        {
            "access_token": "expired-access",
            "refresh_token": "refresh-secret",
            "expires_at": "2020-01-01T00:00:00+00:00",
            "token_type": "Bearer",
            "scopes": list(CALENDAR_READONLY_SCOPES),
        },
        expected_credential_version=int(
            store.active_connection()["credential_version"]
        ),
        cipher=cipher,
    )
    retained_ciphertext = db.query_one(
        "SELECT credential_ciphertext FROM google_calendar_connections WHERE id = %s",
        (connection_id,),
    )["credential_ciphertext"]
    FakeGoogleClient.refresh_error = GoogleCalendarOAuthError(
        "Google authorization is invalid or expired"
    )

    unavailable = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert unavailable.status_code == 409
    assert "reconnect" in unavailable.json()["error"]
    blocked_disconnect = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert blocked_disconnect.status_code == 409
    assert FakeGoogleClient.revoked_tokens == []

    started = client.post("/api/admin/google-calendar/connect", headers=auth)
    assert started.status_code == 200, started.text
    state = parse_qs(urlsplit(started.json()["authorizationUrl"]).query)["state"][0]
    stored_state = db.query_one(
        "SELECT reconnect_connection_id FROM google_calendar_oauth_states"
    )
    assert int(stored_state["reconnect_connection_id"]) == connection_id
    assert FakeGoogleClient.login_hints == ["operations@example.test"]

    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "replacement-grant"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=connected")
    active = store.active_connection()
    assert int(active["id"]) == connection_id
    assert active["selected_calendar_id"] == "operations@example.test"
    assert (
        db.query_one(
            "SELECT credential_ciphertext FROM google_calendar_connections WHERE id = %s",
            (connection_id,),
        )["credential_ciphertext"]
        != retained_ciphertext
    )
    assert db.query_one("SELECT connection_id, status FROM planned_service_visits") == {
        "connection_id": connection_id,
        "status": "planned",
    }
    assert (
        db.query_one(
            "SELECT action FROM planned_visit_audit_events WHERE action = 'calendar_reauthorized'"
        )["action"]
        == "calendar_reauthorized"
    )

    FakeGoogleClient.occurrences = [sparse_cancelled_occurrence(original)]
    cancellation = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert cancellation.status_code == 200, cancellation.text
    cancellation_body = cancellation.json()
    assert cancellation_body["counts"]["cancel"] == 1
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": cancellation_body["previewId"],
            "previewFingerprint": cancellation_body["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    assert (
        db.query_one("SELECT status FROM planned_service_visits")["status"]
        == "cancelled"
    )


def test_reauthorization_failure_retains_connection_without_revoking_uncertain_grant(
    client, auth
):
    connection_id = connect_selected_calendar()
    retained = db.query_one(
        "SELECT credential_ciphertext FROM google_calendar_connections WHERE id = %s",
        (connection_id,),
    )["credential_ciphertext"]
    started = client.post("/api/admin/google-calendar/connect", headers=auth).json()
    state = parse_qs(urlsplit(started["authorizationUrl"]).query)["state"][0]
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="other@example.test",
            summary="Other",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        )
    ]
    FakeGoogleClient.exchange_refresh_token = "wrong-account-refresh"

    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "wrong-calendar-grant"},
        follow_redirects=False,
    )

    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=error")
    active = store.active_connection()
    assert int(active["id"]) == connection_id
    assert active["selected_calendar_id"] == "operations@example.test"
    assert (
        db.query_one(
            "SELECT credential_ciphertext FROM google_calendar_connections WHERE id = %s",
            (connection_id,),
        )["credential_ciphertext"]
        == retained
    )
    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM planned_visit_audit_events WHERE action = 'calendar_reauthorized'"
        )["n"]
        == 0
    )
    # Calendar-only OAuth exposes no stable principal identifier. Revoking this
    # token could revoke the retained grant if the account's email was renamed.
    assert FakeGoogleClient.revoked_tokens == []


def test_reauthorization_callback_is_bound_to_original_connection(client, auth):
    original_connection_id = connect_selected_calendar()
    started = client.post("/api/admin/google-calendar/connect", headers=auth).json()
    state = parse_qs(urlsplit(started["authorizationUrl"]).query)["state"][0]
    db.execute(
        """
        UPDATE google_calendar_connections
        SET revoked_at = NOW(), credential_ciphertext = NULL
        WHERE id = %s
        """,
        (original_connection_id,),
    )
    replacement_connection_id = connect_unselected_calendar()

    callback = client.get(
        "/api/google-calendar/oauth/callback",
        params={"state": state, "code": "stale-reconnect"},
        follow_redirects=False,
    )

    assert callback.status_code == 303
    assert callback.headers["location"].endswith("calendarImport=error")
    assert FakeGoogleClient.exchanged_codes == []
    assert int(store.active_connection()["id"]) == replacement_connection_id


def test_stale_refresh_cannot_overwrite_reauthorized_credentials():
    connection_id = connect_selected_calendar()
    before = store.active_connection()
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    replacement_credentials = {
        "access_token": "replacement-access",
        "refresh_token": "replacement-refresh",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "token_type": "Bearer",
        "scopes": list(CALENDAR_READONLY_SCOPES),
    }
    store.reauthorize_active_connection(
        connection_id=connection_id,
        account_email="operations@example.test",
        credentials=replacement_credentials,
        scopes=CALENDAR_READONLY_SCOPES,
        accessible_calendar_ids=("operations@example.test",),
        admin_id=1,
        admin_name="Juan Canfield",
        cipher=cipher,
    )

    with pytest.raises(
        store.CalendarStoreError, match="credentials changed during refresh"
    ):
        store.update_connection_credentials(
            connection_id,
            {
                "access_token": "stale-refreshed-access",
                "refresh_token": "refresh-secret",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "token_type": "Bearer",
                "scopes": list(CALENDAR_READONLY_SCOPES),
            },
            expected_credential_version=int(before["credential_version"]),
            cipher=cipher,
        )

    active = store.active_connection()
    assert int(active["credential_version"]) == int(before["credential_version"]) + 1
    assert (
        store.connection_credentials(active, cipher=cipher) == replacement_credentials
    )


def test_stale_calendar_choice_cannot_cross_reauthorization():
    connection_id = connect_selected_calendar()
    listed_under_version = int(store.active_connection()["credential_version"])
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    store.reauthorize_active_connection(
        connection_id=connection_id,
        account_email="operations@example.test",
        credentials={
            "access_token": "replacement-access",
            "refresh_token": "replacement-refresh",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "token_type": "Bearer",
            "scopes": list(CALENDAR_READONLY_SCOPES),
        },
        scopes=CALENDAR_READONLY_SCOPES,
        accessible_calendar_ids=("operations@example.test",),
        admin_id=1,
        admin_name="Juan Canfield",
        cipher=cipher,
    )

    with pytest.raises(store.CalendarStoreError, match="credentials changed; reload"):
        store.select_calendar(
            connection_id=connection_id,
            calendar_id="dispatch@example.test",
            calendar_name="Dispatch",
            calendar_timezone="America/Chicago",
            expected_credential_version=listed_under_version,
        )

    assert (
        store.active_connection()["selected_calendar_id"] == "operations@example.test"
    )


def test_stale_disconnect_cannot_revoke_or_scrub_reauthorized_credentials():
    connection_id = connect_selected_calendar()
    disconnect_version = int(store.active_connection()["credential_version"])
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    replacement_credentials = {
        "access_token": "replacement-access",
        "refresh_token": "replacement-refresh",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "token_type": "Bearer",
        "scopes": list(CALENDAR_READONLY_SCOPES),
    }
    store.reauthorize_active_connection(
        connection_id=connection_id,
        account_email="operations@example.test",
        credentials=replacement_credentials,
        scopes=CALENDAR_READONLY_SCOPES,
        accessible_calendar_ids=("operations@example.test",),
        admin_id=1,
        admin_name="Juan Canfield",
        cipher=cipher,
    )
    revocation_attempts = 0

    def mark_revocation() -> None:
        nonlocal revocation_attempts
        revocation_attempts += 1

    with pytest.raises(
        store.CalendarStoreError, match="credentials changed; retry disconnecting"
    ):
        store.disconnect_calendar(
            connection_id=connection_id,
            expected_credential_version=disconnect_version,
            admin_id=1,
            admin_name="Juan Canfield",
            before_disconnect=mark_revocation,
        )

    active = store.active_connection()
    assert revocation_attempts == 0
    assert active["credential_ciphertext"] is not None
    assert (
        store.connection_credentials(active, cipher=cipher) == replacement_credentials
    )


def test_calendar_switch_preserves_future_planned_visit_reconciliation(
    client, auth, monkeypatch
):
    future_start = datetime.now(UTC) + timedelta(days=1)
    monkeypatch.setattr(
        calendar_api,
        "_preview_window_bounds",
        lambda _time_zone_name, **_kwargs: (
            future_start - timedelta(hours=1),
            future_start + timedelta(days=30),
        ),
    )
    connect_selected_calendar()
    FakeGoogleClient.calendars = [
        *FakeGoogleClient.calendars,
        CalendarSummary(
            calendar_id="dispatch@example.test",
            summary="Dispatch",
            primary=False,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        ),
    ]
    FakeGoogleClient.occurrences = [
        google_occurrence("future-switch-guard", start=future_start)
    ]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text

    same_calendar = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "operations@example.test"},
    )
    assert same_calendar.status_code == 200, same_calendar.text

    blocked_switch = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "dispatch@example.test"},
    )
    assert blocked_switch.status_code == 409
    assert "Resolve future planned visits" in blocked_switch.json()["error"]
    assert (
        store.active_connection()["selected_calendar_id"] == "operations@example.test"
    )

    active_connection_id = int(store.active_connection()["id"])
    blocked_disconnect = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert blocked_disconnect.status_code == 409, blocked_disconnect.text
    assert (
        "Resolve or cancel future planned visits" in blocked_disconnect.json()["error"]
    )
    assert FakeGoogleClient.revoked_tokens == []
    retained_connection = db.query_one(
        """
        SELECT revoked_at, credential_ciphertext
        FROM google_calendar_connections
        WHERE id = %s
        """,
        (active_connection_id,),
    )
    assert retained_connection["revoked_at"] is None
    assert retained_connection["credential_ciphertext"] is not None
    assert (
        db.query_one(
            """
            SELECT COUNT(*) AS n
            FROM planned_visit_audit_events
            WHERE action = 'calendar_disconnected'
            """
        )["n"]
        == 0
    )

    # Preserve proof that the selection guard also protects an orphaned legacy
    # row created before disconnects began failing closed.
    db.execute(
        """
        UPDATE google_calendar_connections
        SET revoked_at = NOW(), credential_ciphertext = NULL, updated_at = NOW()
        WHERE id = %s
        """,
        (active_connection_id,),
    )
    unselected_connection = connect_unselected_calendar()
    recoverable_disconnect = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert recoverable_disconnect.status_code == 200, recoverable_disconnect.text
    assert recoverable_disconnect.json() == {"success": True, "disconnected": True}
    assert FakeGoogleClient.revoked_tokens == ["refresh-secret"]
    released_unselected = db.query_one(
        """
        SELECT revoked_at, credential_ciphertext
        FROM google_calendar_connections
        WHERE id = %s
        """,
        (unselected_connection,),
    )
    assert released_unselected["revoked_at"] is not None
    assert released_unselected["credential_ciphertext"] is None
    connect_unselected_calendar()
    blocked_after_reconnect = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "dispatch@example.test"},
    )
    assert blocked_after_reconnect.status_code == 409
    assert store.active_connection()["selected_calendar_id"] is None

    restored_source = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "operations@example.test"},
    )
    assert restored_source.status_code == 200, restored_source.text

    FakeGoogleClient.occurrences = [
        google_occurrence(
            "future-switch-guard",
            cancelled=True,
            updated="2026-07-20T18:00:00Z",
        )
    ]
    cancellation = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert cancellation.status_code == 200, cancellation.text
    cancellation_body = cancellation.json()
    assert cancellation_body["counts"]["cancel"] == 1
    cancelled = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": cancellation_body["previewId"],
            "previewFingerprint": cancellation_body["previewFingerprint"],
        },
    )
    assert cancelled.status_code == 200, cancelled.text
    assert (
        db.query_one("SELECT status FROM planned_service_visits")["status"]
        == "cancelled"
    )
    assert (
        db.query_one(
            """
            SELECT COUNT(*) AS n
            FROM planned_visit_audit_events
            WHERE action = 'planned_visit_cancelled'
            """
        )["n"]
        == 1
    )

    recovered_switch = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "dispatch@example.test"},
    )
    assert recovered_switch.status_code == 200, recovered_switch.text
    assert store.active_connection()["selected_calendar_id"] == "dispatch@example.test"
    disconnected_after_reconciliation = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert disconnected_after_reconciliation.status_code == 200
    assert disconnected_after_reconciliation.json() == {
        "success": True,
        "disconnected": True,
    }
    assert FakeGoogleClient.revoked_tokens == ["refresh-secret", "refresh-secret"]


def test_bootstrap_seeds_morning_crew_only_from_three_unique_active_identities(
    client, auth
):
    crew_id = db.query_one("SELECT id FROM crews WHERE name = 'Morning Crew'")["id"]
    db.execute("DELETE FROM crew_memberships WHERE crew_id = %s", (crew_id,))

    result = store.bootstrap_morning_crew_memberships(
        effective_from=datetime.now(ZoneInfo("America/Chicago")).date()
    )

    assert result["changed"] is True
    assert len(result["employee_ids"]) == 3
    crew = client.get("/api/admin/planned-visits/crews", headers=auth).json()[
        "morningCrew"
    ]
    assert crew["ready"] is True
    assert set(crew["memberIds"]) == set(result["employee_ids"])
    assert (
        db.query_one(
            """
        SELECT action FROM planned_visit_audit_events
        WHERE action = 'crew_membership_bootstrapped'
        """
        )["action"]
        == "crew_membership_bootstrapped"
    )


def test_admin_can_affirm_same_legacy_membership_to_add_operator_provenance(
    client, auth
):
    duplicate_id = db.query_one(
        """
        INSERT INTO employees (name, password_hash, role)
        VALUES ('Carmen Duplicate', 'unused', 'employee')
        RETURNING id
        """
    )["id"]
    assert duplicate_id > 0
    current = client.get("/api/admin/planned-visits/crews", headers=auth).json()[
        "morningCrew"
    ]
    assert current["ready"] is False
    assert current["operatorResolved"] is False
    assert any(issue["name"] == "Carmen" for issue in current["identityIssues"])

    confirmed = client.put(
        f"/api/admin/planned-visits/crews/{current['id']}/memberships",
        headers=auth,
        json={"employeeIds": current["memberIds"]},
    )

    assert confirmed.status_code == 200, confirmed.text
    crew = confirmed.json()["morningCrew"]
    assert confirmed.json()["changed"] is True
    assert crew["ready"] is True
    assert crew["operatorResolved"] is True


def test_disconnect_revokes_google_grant_then_scrubs_local_credentials(client, auth):
    connection_id = connect_selected_calendar()

    response = client.delete("/api/admin/google-calendar/connection", headers=auth)

    assert response.status_code == 200
    assert response.json() == {"success": True, "disconnected": True}
    assert FakeGoogleClient.revoked_tokens == ["refresh-secret"]
    connection = db.query_one(
        "SELECT revoked_at, credential_ciphertext FROM google_calendar_connections WHERE id = %s",
        (connection_id,),
    )
    assert connection["revoked_at"] is not None
    assert connection["credential_ciphertext"] is None
    audit = db.query_one(
        "SELECT action FROM planned_visit_audit_events WHERE action = 'calendar_disconnected'"
    )
    assert audit["action"] == "calendar_disconnected"


def test_disconnect_retains_local_credential_when_revocation_is_retryable(client, auth):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.revoke_error = GoogleCalendarTransportError(
        "Google Calendar is temporarily unavailable"
    )

    response = client.delete("/api/admin/google-calendar/connection", headers=auth)

    assert response.status_code == 503
    connection = db.query_one(
        "SELECT revoked_at, credential_ciphertext FROM google_calendar_connections WHERE id = %s",
        (connection_id,),
    )
    assert connection["revoked_at"] is None
    assert connection["credential_ciphertext"] is not None


def test_retryable_google_not_found_maps_to_retryable_service_response(client):
    failure = calendar_api._google_failure(
        GoogleCalendarTransportError(
            "Google Calendar is temporarily unavailable", status_code=404
        )
    )

    assert failure.status_code == 503
    assert failure.headers == {"Retry-After": "5"}


def test_preview_is_read_only_then_approval_is_atomic_and_idempotent(client, auth):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("service-1")]
    evidence_before = {
        "shifts": db.query_one("SELECT COUNT(*) AS n FROM shifts")["n"],
        "checkins": db.query_one("SELECT COUNT(*) AS n FROM site_check_ins")["n"],
        "receivables": db.query_one(
            "SELECT COUNT(*) AS n FROM receivables_operation_attempts"
        )["n"],
    }

    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["canApprove"] is True
    assert body["counts"]["create"] == 1
    assert body["items"][0]["timingSemantics"] == "approximate"
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 0

    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": body["previewId"],
            "previewFingerprint": body["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    retry = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": body["previewId"],
            "previewFingerprint": body["previewFingerprint"],
        },
    )
    assert retry.status_code == 200
    assert retry.json() == approved.json()
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 1
    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM planned_visit_assignments WHERE active = true"
        )["n"]
        == 1
    )
    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM planned_visit_audit_events WHERE action = 'planned_visit_created'"
        )["n"]
        == 1
    )
    evidence_after = {
        "shifts": db.query_one("SELECT COUNT(*) AS n FROM shifts")["n"],
        "checkins": db.query_one("SELECT COUNT(*) AS n FROM site_check_ins")["n"],
        "receivables": db.query_one(
            "SELECT COUNT(*) AS n FROM receivables_operation_attempts"
        )["n"],
    }
    assert evidence_after == evidence_before


def test_source_change_after_preview_fails_closed_without_planned_write(client, auth):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("stale-1")]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    FakeGoogleClient.occurrences = [
        google_occurrence("stale-1", updated="2026-07-18T13:00:00Z")
    ]

    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )

    assert response.status_code == 409
    assert "changed after preview" in response.json()["error"]
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 0
    assert (
        db.query_one(
            "SELECT status FROM calendar_import_previews WHERE id = %s",
            (preview["previewId"],),
        )["status"]
        == "stale"
    )


@pytest.mark.parametrize(
    "connection_change", ["disconnect", "reconnect", "switch", "timezone"]
)
def test_connection_change_after_rebuild_fails_closed_inside_approval_transaction(
    client, auth, monkeypatch, connection_change
):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.occurrences = [
        google_occurrence(f"connection-{connection_change}")
    ]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    real_apply = store.apply_reviewed_preview

    def change_connection_then_apply(**kwargs):
        if connection_change == "disconnect":
            active = store.active_connection()
            store.disconnect_calendar(
                connection_id=connection_id,
                expected_credential_version=int(active["credential_version"]),
                admin_id=1,
                admin_name="Juan Canfield",
            )
        elif connection_change == "reconnect":
            connect_selected_calendar()
        elif connection_change == "switch":
            credential_version = int(store.active_connection()["credential_version"])
            store.select_calendar(
                connection_id=connection_id,
                calendar_id="different@example.test",
                calendar_name="Different calendar",
                calendar_timezone="America/Chicago",
                expected_credential_version=credential_version,
            )
        else:
            credential_version = int(store.active_connection()["credential_version"])
            store.select_calendar(
                connection_id=connection_id,
                calendar_id="operations@example.test",
                calendar_name="Operations",
                calendar_timezone="America/New_York",
                expected_credential_version=credential_version,
            )
        return real_apply(**kwargs)

    monkeypatch.setattr(store, "apply_reviewed_preview", change_connection_then_apply)
    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )

    assert response.status_code == 409, response.text
    assert "connection changed after preview" in response.json()["error"]
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 0


def test_provider_timezone_change_invalidates_preview_before_any_write(client, auth):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("timezone-change")]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/New_York",
        )
    ]

    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )

    assert response.status_code == 409
    assert "timezone changed" in response.json()["error"]
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 0


def test_bound_preview_refreshes_metadata_then_recovers_from_timezone_change(
    client, auth
):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Updated Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Denver",
        )
    ]
    FakeGoogleClient.occurrences = [google_occurrence("metadata-refresh")]

    response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "expectedConnectionId": connection_id,
            "expectedCalendarId": "operations@example.test",
            "expectedCalendarTimeZone": "America/Chicago",
            "resolutions": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"] == (
        "Google Calendar timezone changed; create a new preview"
    )
    connection = db.query_one(
        """
        SELECT selected_calendar_name, selected_calendar_timezone
        FROM google_calendar_connections WHERE id = %s
        """,
        (connection_id,),
    )
    assert connection == {
        "selected_calendar_name": "Updated Operations",
        "selected_calendar_timezone": "America/Denver",
    }
    status = client.get("/api/admin/google-calendar/status", headers=auth)
    assert status.json()["selectedCalendarName"] == "Updated Operations"
    assert status.json()["selectedCalendarTimeZone"] == "America/Denver"

    recovered = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "expectedConnectionId": connection_id,
            "expectedCalendarId": "operations@example.test",
            "expectedCalendarTimeZone": "America/Denver",
            "resolutions": [],
        },
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["calendarTimeZone"] == "America/Denver"


def test_metadata_refresh_connection_race_returns_retryable_conflict(
    client, auth, monkeypatch
):
    connect_selected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Updated Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Denver",
        )
    ]
    FakeGoogleClient.occurrences = [google_occurrence("metadata-refresh-race")]

    def reject_stale_metadata(**_kwargs):
        raise store.CalendarStoreError("credentials changed; reload")

    monkeypatch.setattr(store, "select_calendar", reject_stale_metadata)

    response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )

    assert response.status_code == 409
    assert response.json()["error"] == (
        "Google Calendar connection changed; create a new preview"
    )


def test_metadata_refresh_cannot_switch_back_a_concurrent_calendar_choice(
    client, auth, monkeypatch
):
    connection_id = connect_selected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="operations@example.test",
            summary="Updated Operations",
            primary=True,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        )
    ]
    FakeGoogleClient.occurrences = [google_occurrence("metadata-selection-race")]
    real_select_calendar = store.select_calendar

    def switch_then_refresh(**kwargs):
        active = store.active_connection()
        real_select_calendar(
            connection_id=connection_id,
            calendar_id="different@example.test",
            calendar_name="Different calendar",
            calendar_timezone="America/Chicago",
            expected_credential_version=int(active["credential_version"]),
        )
        return real_select_calendar(**kwargs)

    monkeypatch.setattr(store, "select_calendar", switch_then_refresh)

    response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "expectedConnectionId": connection_id,
            "expectedCalendarId": "operations@example.test",
            "expectedCalendarTimeZone": "America/Chicago",
            "resolutions": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"] == (
        "Google Calendar connection changed; create a new preview"
    )
    assert store.active_connection()["selected_calendar_id"] == "different@example.test"


def test_reconnect_reconciles_the_same_occurrence_without_a_duplicate(client, auth):
    first_connection = connect_selected_calendar()
    first_occurrence = google_occurrence(
        "reconnect-1", summary="Unmatched customer", location="Unmatched location"
    )
    FakeGoogleClient.occurrences = [first_occurrence]
    location_id = db.query_one(
        "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
    )["id"]
    crew_id = db.query_one("SELECT id FROM crews WHERE name = 'Morning Crew'")["id"]
    first_preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "resolutions": [
                {
                    "sourceKey": first_occurrence.source_key,
                    "locationId": location_id,
                    "crewId": crew_id,
                    "employeeIds": [],
                }
            ]
        },
    ).json()
    first_approval = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": first_preview["previewId"],
            "previewFingerprint": first_preview["previewFingerprint"],
        },
    )
    assert first_approval.status_code == 200, first_approval.text

    second_connection = connect_selected_calendar()
    assert second_connection != first_connection
    FakeGoogleClient.occurrences = [
        google_occurrence(
            "reconnect-1",
            summary="Unmatched customer",
            location="Unmatched location",
            updated="2026-07-18T13:00:00Z",
        )
    ]
    approve_current_preview(client, auth)

    visit = db.query_one(
        "SELECT connection_id, COUNT(*) OVER () AS total FROM planned_service_visits"
    )
    assert visit["total"] == 1
    assert visit["connection_id"] == second_connection
    mapping = db.query_one(
        "SELECT connection_id, COUNT(*) OVER () AS total FROM google_calendar_event_mappings"
    )
    assert mapping["total"] == 1
    assert mapping["connection_id"] == second_connection


def test_concurrent_approvals_serialize_one_occurrence_creation(client, auth):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("concurrent-1")]
    previews = [
        client.post(
            "/api/admin/google-calendar/preview",
            headers=auth,
            json={"resolutions": []},
        ).json()
        for _ in range(2)
    ]

    def approve(preview):
        return client.post(
            "/api/admin/google-calendar/approve",
            headers=auth,
            json={
                "previewId": preview["previewId"],
                "previewFingerprint": preview["previewFingerprint"],
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(approve, previews))

    assert sorted(response.status_code for response in responses) == [200, 409]
    assert db.query_one("SELECT COUNT(*) AS n FROM planned_service_visits")["n"] == 1


def approve_current_preview(client, auth) -> dict:
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_future_update_and_cancellation_preserve_rows_and_assignment_history(
    client, auth
):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("lifecycle-1")]
    approve_current_preview(client, auth)
    visit = db.query_one("SELECT id, source_key FROM planned_service_visits")
    first_assignment = db.query_one(
        "SELECT id FROM planned_visit_assignments WHERE planned_visit_id = %s AND active = true",
        (visit["id"],),
    )["id"]

    moved_start = WINDOW_START + timedelta(hours=1)
    FakeGoogleClient.occurrences = [
        google_occurrence(
            "lifecycle-1",
            start=moved_start,
            updated="2026-07-18T13:00:00Z",
        )
    ]
    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert preview["counts"]["update"] == 1
    approve_current_preview(client, auth)
    assert (
        db.query_one(
            "SELECT approximate_start FROM planned_service_visits WHERE id = %s",
            (visit["id"],),
        )["approximate_start"]
        == moved_start
    )

    FakeGoogleClient.occurrences = [
        google_occurrence("lifecycle-1", cancelled=True, updated="2026-07-18T14:00:00Z")
    ]
    cancellation = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert cancellation["counts"]["cancel"] == 1
    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": cancellation["previewId"],
            "previewFingerprint": cancellation["previewFingerprint"],
        },
    )
    assert response.status_code == 200, response.text
    assert (
        db.query_one(
            "SELECT status FROM planned_service_visits WHERE id = %s", (visit["id"],)
        )["status"]
        == "cancelled"
    )
    retired = db.query_one(
        "SELECT active, retired_at FROM planned_visit_assignments WHERE id = %s",
        (first_assignment,),
    )
    assert retired["active"] is False
    assert retired["retired_at"] is not None


def test_occurrence_moved_outside_list_window_is_targeted_and_updated(client, auth):
    connect_selected_calendar()
    original = google_occurrence(
        "moved-instance-v1",
        recurring_event_id="recurring-series",
        original_start=WINDOW_START,
    )
    FakeGoogleClient.occurrences = [original]
    approve_current_preview(client, auth)

    moved_start = WINDOW_START + timedelta(days=45)
    moved = google_occurrence(
        "moved-instance-v2",
        start=moved_start,
        updated="2026-07-19T12:00:00Z",
        recurring_event_id="recurring-series",
        original_start=WINDOW_START,
    )
    FakeGoogleClient.occurrences = []
    assert original.source_key == moved.source_key
    assert original.original_start_query is not None
    FakeGoogleClient.targeted_recurring_occurrences = {
        ("recurring-series", original.original_start_query): moved
    }
    preview_response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["counts"]["update"] == 1
    assert preview["counts"]["cancel"] == 0
    assert preview["items"][0]["start"] == moved_start.isoformat()

    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    stored = db.query_one(
        "SELECT approximate_start, status FROM planned_service_visits"
    )
    assert stored["approximate_start"] == moved_start
    assert stored["status"] == "planned"

    FakeGoogleClient.calendars = [
        *FakeGoogleClient.calendars,
        CalendarSummary(
            calendar_id="dispatch@example.test",
            summary="Dispatch",
            primary=False,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        ),
    ]
    blocked_switch = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "dispatch@example.test"},
    )
    assert blocked_switch.status_code == 409
    blocked_disconnect = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert blocked_disconnect.status_code == 409

    FakeGoogleClient.targeted_recurring_occurrences = {
        ("recurring-series", original.original_start_query): None
    }
    cancellation = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )
    assert cancellation.status_code == 200, cancellation.text
    cancellation_body = cancellation.json()
    assert cancellation_body["counts"]["cancel"] == 1
    assert cancellation_body["items"][0]["start"] == moved_start.isoformat()
    approved_cancellation = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": cancellation_body["previewId"],
            "previewFingerprint": cancellation_body["previewFingerprint"],
        },
    )
    assert approved_cancellation.status_code == 200, approved_cancellation.text

    recovered_switch = client.put(
        "/api/admin/google-calendar/calendar",
        headers=auth,
        json={"calendarId": "dispatch@example.test"},
    )
    assert recovered_switch.status_code == 200, recovered_switch.text
    recovered_disconnect = client.delete(
        "/api/admin/google-calendar/connection", headers=auth
    )
    assert recovered_disconnect.status_code == 200, recovered_disconnect.text


@pytest.mark.parametrize("recurring", [False, True])
def test_provider_confirmed_missing_occurrence_is_previewed_and_applied_as_cancelled(
    client, auth, recurring
):
    connect_selected_calendar()
    original = google_occurrence(
        "instance-that-google-deleted" if recurring else "event-that-google-deleted",
        recurring_event_id="deleted-series" if recurring else None,
        original_start=WINDOW_START if recurring else None,
    )
    FakeGoogleClient.occurrences = [original]
    approve_current_preview(client, auth)

    FakeGoogleClient.occurrences = []
    if recurring:
        FakeGoogleClient.targeted_recurring_occurrences = {
            ("deleted-series", original.original_start_query): None
        }
    else:
        FakeGoogleClient.targeted_occurrences = {original.event_id: None}
    preview_response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )

    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["counts"]["cancel"] == 1
    assert preview["counts"]["unresolved"] == 0
    cancelled_item = preview["items"][0]
    assert cancelled_item["summary"] == original.summary
    assert cancelled_item["calendarLocation"] == original.location
    assert cancelled_item["start"] == original.start
    assert cancelled_item["end"] == original.end
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    assert (
        db.query_one(
            "SELECT status FROM planned_service_visits WHERE source_key = %s",
            (original.source_key,),
        )["status"]
        == "cancelled"
    )


@pytest.mark.parametrize("delivery", ["listed", "targeted"])
def test_explicit_sparse_cancellation_preserves_reviewed_context(
    client, auth, delivery
):
    connect_selected_calendar()
    original = google_occurrence(
        "sparse-instance",
        summary="Rich Customer Name",
        location="123 Main St, Effingham",
        recurring_event_id="sparse-series",
        original_start=WINDOW_START,
    )
    FakeGoogleClient.occurrences = [original]
    approve_current_preview(client, auth)
    before = db.query_one(
        """
        SELECT title, description, source_location_text,
               approximate_start, approximate_end, all_day, source_timezone
        FROM planned_service_visits
        """
    )
    sparse = sparse_cancelled_occurrence(original)
    FakeGoogleClient.occurrences = [sparse] if delivery == "listed" else []
    if delivery == "targeted":
        FakeGoogleClient.targeted_recurring_occurrences = {
            ("sparse-series", original.original_start_query): sparse
        }

    preview_response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )

    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["counts"]["cancel"] == 1
    assert preview["counts"]["unresolved"] == 0
    item = preview["items"][0]
    assert item["summary"] == before["title"]
    assert item["description"] == before["description"]
    assert item["calendarLocation"] == before["source_location_text"]
    assert datetime.fromisoformat(item["start"]) == before["approximate_start"]
    assert datetime.fromisoformat(item["end"]) == before["approximate_end"]
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    after = db.query_one(
        """
        SELECT title, description, source_location_text,
               approximate_start, approximate_end, all_day, source_timezone, status
        FROM planned_service_visits
        """
    )
    assert after["status"] == "cancelled"
    for field in (
        "title",
        "description",
        "source_location_text",
        "approximate_start",
        "approximate_end",
        "all_day",
        "source_timezone",
    ):
        assert after[field] == before[field]


def test_more_than_ten_missing_occurrences_are_targeted_and_updated(client, auth):
    connect_selected_calendar()
    originals = [
        google_occurrence(
            f"moved-{index}",
            start=WINDOW_START + timedelta(minutes=index * 5),
        )
        for index in range(11)
    ]
    FakeGoogleClient.occurrences = originals
    approve_current_preview(client, auth)

    moved = [
        google_occurrence(
            original.event_id,
            start=WINDOW_START + timedelta(days=45, minutes=index * 5),
            updated="2026-07-19T12:00:00Z",
        )
        for index, original in enumerate(originals)
    ]
    FakeGoogleClient.occurrences = []
    FakeGoogleClient.targeted_occurrences = {
        occurrence.event_id: occurrence for occurrence in moved
    }

    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )

    assert preview.status_code == 200, preview.text
    assert preview.json()["counts"]["update"] == 11
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview.json()["previewId"],
            "previewFingerprint": preview.json()["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM planned_service_visits WHERE approximate_start >= %s",
            (WINDOW_START + timedelta(days=45),),
        )["n"]
        == 11
    )
    assert FakeGoogleClient.batch_calls == 2


def test_ongoing_occurrence_uses_interval_overlap_for_targeted_reconciliation(
    client, auth
):
    connect_selected_calendar()
    original = google_occurrence(
        "ongoing-at-window-start",
        start=WINDOW_START - timedelta(hours=2),
        end=WINDOW_START + timedelta(hours=1),
    )
    FakeGoogleClient.occurrences = [original]
    approve_current_preview(client, auth)

    moved = google_occurrence(
        original.event_id,
        start=WINDOW_START + timedelta(days=45),
        updated="2026-07-19T13:00:00Z",
    )
    FakeGoogleClient.occurrences = []
    FakeGoogleClient.targeted_occurrences = {original.event_id: moved}

    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    )

    assert preview.status_code == 200, preview.text
    assert preview.json()["counts"]["update"] == 1
    assert preview.json()["items"][0]["start"] == moved.start


def test_completed_visit_is_never_cancelled_by_later_google_change(client, auth):
    connect_selected_calendar()
    FakeGoogleClient.occurrences = [google_occurrence("completed-1")]
    approve_current_preview(client, auth)
    db.execute(
        """
        UPDATE planned_service_visits
        SET status = 'completed', completed_at = NOW()
        """
    )
    FakeGoogleClient.occurrences = [google_occurrence("completed-1", cancelled=True)]

    preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert preview["counts"]["unchanged"] == 1
    assert preview["items"][0]["completedVisitPreserved"] is True
    response = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert response.status_code == 200, response.text
    assert (
        db.query_one("SELECT status FROM planned_service_visits")["status"]
        == "completed"
    )


def test_unresolved_manual_mapping_and_overlap_warning_are_operator_controlled(
    client, auth
):
    connect_selected_calendar()
    second_start = WINDOW_START + timedelta(minutes=30)
    FakeGoogleClient.occurrences = [
        google_occurrence(
            "unknown-1", summary="Unknown Customer", location="Somewhere Else"
        ),
        google_occurrence(
            "unknown-2",
            summary="Unknown Customer",
            location="Somewhere Else",
            start=second_start,
        ),
    ]
    unresolved = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert unresolved["canApprove"] is False
    assert unresolved["counts"]["unresolved"] == 2
    assert unresolved["warnings"][0]["blocking"] is False

    location_id = db.query_one(
        "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
    )["id"]
    morning_id = db.query_one("SELECT id FROM crews WHERE name = 'Morning Crew'")["id"]
    resolutions = [
        {
            "sourceKey": item["sourceKey"],
            "locationId": location_id,
            "crewId": morning_id,
            "employeeIds": [],
        }
        for item in unresolved["items"]
    ]
    resolved = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": resolutions},
    ).json()
    assert resolved["canApprove"] is True
    assert resolved["counts"]["create"] == 2


def test_location_only_resolution_preserves_default_assignment_through_approval(
    client, auth
):
    connect_selected_calendar()
    occurrence = google_occurrence(
        "location-only",
        summary="Unmatched customer",
        location="Unmatched location",
    )
    FakeGoogleClient.occurrences = [occurrence]
    location_id = db.query_one(
        "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
    )["id"]
    crew_id = db.query_one("SELECT id FROM crews WHERE name = 'Morning Crew'")["id"]

    preview_response = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "resolutions": [
                {"sourceKey": occurrence.source_key, "locationId": location_id}
            ]
        },
    )
    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["canApprove"] is True
    assert preview["items"][0]["crewId"] == crew_id
    assert preview["items"][0]["employeeIds"] == []

    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": preview["previewId"],
            "previewFingerprint": preview["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text
    assignment = db.query_one(
        """
        SELECT crew_id, employee_id
        FROM planned_visit_assignments
        WHERE active = true
        """
    )
    assert assignment["crew_id"] == crew_id
    assert assignment["employee_id"] is None


def test_morning_crew_identity_issue_blocks_until_admin_sets_explicit_membership(
    client, auth, monkeypatch
):
    future_start = datetime.now(UTC) + timedelta(days=1)
    monkeypatch.setattr(
        calendar_api,
        "_preview_window_bounds",
        lambda _time_zone_name, **_kwargs: (
            future_start - timedelta(hours=1),
            future_start + timedelta(days=30),
        ),
    )
    connect_selected_calendar()
    db.execute("UPDATE employees SET active = false WHERE name = 'Pamela Brown'")

    unresolved_crew = client.get(
        "/api/admin/planned-visits/crews", headers=auth
    ).json()["morningCrew"]
    assert unresolved_crew["ready"] is False
    assert unresolved_crew["operatorResolved"] is False
    assert any(
        issue["name"] == "Pamela" and issue["status"] == "inactive"
        for issue in unresolved_crew["identityIssues"]
    )

    FakeGoogleClient.occurrences = [
        google_occurrence("crew-needs-resolution", start=future_start)
    ]
    blocked_preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert blocked_preview["canApprove"] is False
    assert blocked_preview["counts"]["unresolved"] == 1

    crew_id = unresolved_crew["id"]
    active_expected_ids = [
        row["id"]
        for row in db.query_all(
            """
            SELECT id FROM employees
            WHERE name IN ('Carmen Alvarez', 'Tina Davis') AND active = true
            ORDER BY id
            """
        )
    ]
    resolved_response = client.put(
        f"/api/admin/planned-visits/crews/{crew_id}/memberships",
        headers=auth,
        json={"employeeIds": active_expected_ids},
    )
    assert resolved_response.status_code == 200, resolved_response.text
    resolved_crew = resolved_response.json()["morningCrew"]
    assert resolved_crew["ready"] is True
    assert resolved_crew["operatorResolved"] is True
    assert resolved_crew["memberIds"] == active_expected_ids
    assert any(
        issue["name"] == "Pamela" and issue["status"] == "inactive"
        for issue in resolved_crew["identityIssues"]
    )

    approved_preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    assert approved_preview["canApprove"] is True
    assert approved_preview["counts"]["create"] == 1

    db.execute("UPDATE employees SET active = false WHERE name = 'Tina Davis'")
    stale_explicit_crew = client.get(
        "/api/admin/planned-visits/crews", headers=auth
    ).json()["morningCrew"]
    assert stale_explicit_crew["ready"] is False
    assert stale_explicit_crew["operatorResolved"] is False


def test_existing_per_visit_assignment_is_preserved_without_a_new_decision(
    client, auth
):
    connect_selected_calendar()
    occurrence = google_occurrence("assignment-override")
    FakeGoogleClient.occurrences = [occurrence]
    location_id = db.query_one(
        "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
    )["id"]
    employee_id = db.query_one(
        "SELECT id FROM employees WHERE name = 'Carmen Alvarez'"
    )["id"]

    reviewed = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "resolutions": [
                {
                    "sourceKey": occurrence.source_key,
                    "locationId": location_id,
                    "crewId": None,
                    "employeeIds": [employee_id],
                }
            ]
        },
    ).json()
    approved = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": reviewed["previewId"],
            "previewFingerprint": reviewed["previewFingerprint"],
        },
    )
    assert approved.status_code == 200, approved.text

    next_preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    item = next_preview["items"][0]
    assert item["classification"] == "unchanged"
    assert item["crewId"] is None
    assert item["employeeIds"] == [employee_id]


def test_recurring_occurrence_location_decisions_do_not_overwrite_each_other(
    client, auth
):
    connect_selected_calendar()
    first = google_occurrence(
        "instance-a",
        summary="Unmatched first",
        location="Calendar note A",
        recurring_event_id="shared-series",
        original_start=WINDOW_START,
    )
    second_start = WINDOW_START + timedelta(days=7)
    second = google_occurrence(
        "instance-b",
        summary="Unmatched second",
        location="Calendar note B",
        start=second_start,
        recurring_event_id="shared-series",
        original_start=second_start,
    )
    FakeGoogleClient.occurrences = [first, second]
    first_location_id = db.query_one(
        "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
    )["id"]
    second_location_id = db.query_one(
        """
        INSERT INTO locations (address, customer_name, active)
        VALUES ('456 Oak St, Effingham', 'Second Customer', true)
        RETURNING id
        """
    )["id"]
    crew_id = db.query_one("SELECT id FROM crews WHERE name = 'Morning Crew'")["id"]
    reviewed = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={
            "resolutions": [
                {
                    "sourceKey": first.source_key,
                    "locationId": first_location_id,
                    "crewId": crew_id,
                    "employeeIds": [],
                },
                {
                    "sourceKey": second.source_key,
                    "locationId": second_location_id,
                    "crewId": crew_id,
                    "employeeIds": [],
                },
            ]
        },
    ).json()
    applied = client.post(
        "/api/admin/google-calendar/approve",
        headers=auth,
        json={
            "previewId": reviewed["previewId"],
            "previewFingerprint": reviewed["previewFingerprint"],
        },
    )
    assert applied.status_code == 200, applied.text
    assert (
        db.query_one("SELECT COUNT(*) AS count FROM google_calendar_event_mappings")[
            "count"
        ]
        == 2
    )

    next_preview = client.post(
        "/api/admin/google-calendar/preview",
        headers=auth,
        json={"resolutions": []},
    ).json()
    items = {item["sourceKey"]: item for item in next_preview["items"]}
    assert items[first.source_key]["classification"] == "unchanged"
    assert items[first.source_key]["location"]["locationId"] == first_location_id
    assert items[second.source_key]["classification"] == "unchanged"
    assert items[second.source_key]["location"]["locationId"] == second_location_id


def test_canonical_sources_are_distinct_readable_and_reported_in_status(client, auth):
    connect_unselected_calendar()
    FakeGoogleClient.calendars = [
        CalendarSummary(
            calendar_id="residential@example.test",
            summary="Residential Calendar",
            primary=False,
            selected=True,
            access_role="owner",
            time_zone="America/Chicago",
        ),
        CalendarSummary(
            calendar_id="commercial@example.test",
            summary="Commercial Calendar",
            primary=False,
            selected=True,
            access_role="reader",
            time_zone="America/Chicago",
        ),
    ]

    duplicate = client.put(
        "/api/admin/google-calendar/sources",
        headers=auth,
        json={
            "residentialMorningCalendarId": "residential@example.test",
            "commercialEveningNightCalendarId": "residential@example.test",
        },
    )
    assert duplicate.status_code == 422
    assert store.list_calendar_sources() == []

    unavailable = client.put(
        "/api/admin/google-calendar/sources",
        headers=auth,
        json={
            "residentialMorningCalendarId": "residential@example.test",
            "commercialEveningNightCalendarId": "missing@example.test",
        },
    )
    assert unavailable.status_code == 422
    assert store.list_calendar_sources() == []

    configured = client.put(
        "/api/admin/google-calendar/sources",
        headers=auth,
        json={
            "residentialMorningCalendarId": "residential@example.test",
            "commercialEveningNightCalendarId": "commercial@example.test",
        },
    )
    assert configured.status_code == 200, configured.text
    assert configured.json()["sourcesReady"] is True

    status = client.get("/api/admin/google-calendar/status", headers=auth).json()
    assert status["capabilityVersion"] == "canonical-schedule.v1"
    assert status["sourcesReady"] is True
    assert status["syncStatus"] == "never"
    assert {source["role"] for source in status["sources"]} == set(
        store.CALENDAR_SOURCE_ROLES
    )
    assert status["selectedCalendarId"] == "residential@example.test"


def test_two_source_sync_is_idempotent_and_reconciles_reschedule_and_cancel(
    client, auth
):
    sources = configure_canonical_sources(client, auth)
    residential = google_occurrence(
        "residential-job",
        calendar_id="residential@example.test",
    )
    commercial = google_occurrence(
        "commercial-job",
        calendar_id="commercial@example.test",
        summary="Commercial Customer",
        location="456 Oak St, Effingham",
        start=WINDOW_START + timedelta(hours=8),
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [residential],
        "commercial@example.test": [commercial],
    }
    untouched_before = {
        table: int(db.query_one(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in (
            "schedules",
            "planned_service_visits",
            "planned_visit_assignments",
            "shifts",
        )
    }

    first = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "success"
    assert first.json()["counts"]["create"] == 2
    jobs = db.query_all(
        """
        SELECT j.id, j.source_key, j.scheduled_start, j.status, s.role
        FROM jobs j
        JOIN google_calendar_sources s ON s.id = j.calendar_source_id
        WHERE j.source_key IS NOT NULL
        ORDER BY s.role
        """
    )
    assert len(jobs) == 2
    assert {job["role"] for job in jobs} == set(store.CALENDAR_SOURCE_ROLES)
    assert {
        table: int(db.query_one(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in untouched_before
    } == untouched_before
    ids_by_key = {job["source_key"]: job["id"] for job in jobs}

    retry = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert retry.status_code == 200
    assert retry.json()["counts"]["unchanged"] == 2
    assert retry.json()["counts"]["create"] == 0

    moved = google_occurrence(
        "residential-job",
        calendar_id="residential@example.test",
        start=WINDOW_START + timedelta(days=1),
        updated="2026-07-22T12:00:00Z",
    )
    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [moved]
    rescheduled = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert rescheduled.status_code == 200
    assert rescheduled.json()["counts"]["update"] == 1
    moved_job = db.query_one(
        "SELECT id, scheduled_start FROM jobs WHERE source_key = %s",
        (moved.source_key,),
    )
    assert moved_job["id"] == ids_by_key[moved.source_key]
    assert moved_job["scheduled_start"] == WINDOW_START + timedelta(days=1)

    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [
        sparse_cancelled_occurrence(
            moved,
            updated="2026-07-23T12:00:00Z",
        )
    ]
    cancelled = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert cancelled.status_code == 200
    assert cancelled.json()["counts"]["cancel"] == 1
    cancelled_job = db.query_one(
        "SELECT status, cancellation_reason FROM jobs WHERE source_key = %s",
        (moved.source_key,),
    )
    assert cancelled_job == {
        "status": "cancelled",
        "cancellation_reason": "source_cancelled",
    }
    assert sources[store.RESIDENTIAL_MORNING_ROLE]["calendarId"] == (
        "residential@example.test"
    )


def test_late_older_or_equal_conflicting_snapshot_cannot_regress_job(client, auth):
    configure_canonical_sources(client, auth)
    original = google_occurrence(
        "monotonic-source",
        calendar_id="residential@example.test",
        updated="2026-07-18T12:00:00Z",
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [original],
        "commercial@example.test": [],
    }
    assert (
        client.post("/api/admin/google-calendar/sync", headers=auth).json()["counts"][
            "create"
        ]
        == 1
    )

    newest = google_occurrence(
        "monotonic-source",
        calendar_id="residential@example.test",
        start=WINDOW_START + timedelta(days=2),
        updated="2026-07-22T12:00:00Z",
    )
    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [newest]
    assert (
        client.post("/api/admin/google-calendar/sync", headers=auth).json()["counts"][
            "update"
        ]
        == 1
    )
    stored = db.query_one(
        """
        SELECT scheduled_start, source_updated_at, source_fingerprint
        FROM jobs
        WHERE source_key = %s
        """,
        (newest.source_key,),
    )

    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [original]
    older = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    assert older["counts"]["unresolved"] == 1
    assert older["exceptions"][0]["code"] == "stale_source_snapshot"
    assert (
        db.query_one(
            """
        SELECT scheduled_start, source_updated_at, source_fingerprint
        FROM jobs
        WHERE source_key = %s
        """,
            (newest.source_key,),
        )
        == stored
    )

    equal_timestamp_conflict = google_occurrence(
        "monotonic-source",
        calendar_id="residential@example.test",
        start=WINDOW_START + timedelta(days=3),
        updated="2026-07-22T12:00:00Z",
    )
    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [
        equal_timestamp_conflict
    ]
    equal = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    assert equal["counts"]["unresolved"] == 1
    assert equal["exceptions"][0]["code"] == "stale_source_snapshot"
    assert (
        db.query_one(
            """
        SELECT scheduled_start, source_updated_at, source_fingerprint
        FROM jobs
        WHERE source_key = %s
        """,
            (newest.source_key,),
        )
        == stored
    )


def test_source_sync_commits_one_calendar_when_the_other_fetch_fails(client, auth):
    configure_canonical_sources(client, auth)
    residential = google_occurrence(
        "residential-success",
        calendar_id="residential@example.test",
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [residential],
    }
    FakeGoogleClient.occurrence_errors_by_calendar = {
        "commercial@example.test": GoogleCalendarTransportError(
            "Google Calendar is temporarily unavailable"
        )
    }

    response = client.post("/api/admin/google-calendar/sync", headers=auth)

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["status"] == "partial"
    assert db.query_one(
        "SELECT id FROM jobs WHERE source_key = %s", (residential.source_key,)
    )
    statuses = {
        row["role"]: row["last_sync_status"]
        for row in db.query_all(
            "SELECT role, last_sync_status FROM google_calendar_sources"
        )
    }
    assert statuses == {
        store.RESIDENTIAL_MORNING_ROLE: "success",
        store.COMMERCIAL_EVENING_NIGHT_ROLE: "failed",
    }


def test_site_date_time_evidence_protects_job_without_shift_job_id(client, auth):
    configure_canonical_sources(client, auth)
    original = google_occurrence(
        "protected-by-site-date",
        calendar_id="residential@example.test",
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [original],
        "commercial@example.test": [],
    }
    created = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert created.status_code == 200
    job = db.query_one(
        """
        SELECT id, location_id, scheduled_date, scheduled_start
        FROM jobs
        WHERE source_key = %s
        """,
        (original.source_key,),
    )
    employee_id = int(
        db.query_one("SELECT id FROM employees WHERE name = 'Catalina Gomez'")["id"]
    )
    db.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, clock_out,
            total_hours, local_date, time_category, notes, job_id
        ) VALUES (
            %s, %s, 'Test Customer', %s, %s, 2.0, %s, 'productive',
            'canonical-calendar-test-evidence', NULL
        )
        """,
        (
            employee_id,
            int(job["location_id"]),
            WINDOW_START,
            WINDOW_START + timedelta(hours=2),
            job["scheduled_date"],
        ),
    )

    moved = google_occurrence(
        "protected-by-site-date",
        calendar_id="residential@example.test",
        start=WINDOW_START + timedelta(days=1),
        updated="2026-07-22T12:00:00Z",
    )
    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [moved]
    reschedule = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    assert reschedule["counts"]["unresolved"] == 1
    assert reschedule["exceptions"][0]["code"] == "protected_work"
    assert (
        db.query_one(
            "SELECT scheduled_start FROM jobs WHERE id = %s", (int(job["id"]),)
        )["scheduled_start"]
        == job["scheduled_start"]
    )

    FakeGoogleClient.occurrences_by_calendar["residential@example.test"] = [
        sparse_cancelled_occurrence(moved)
    ]
    cancellation = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    assert cancellation["counts"]["unresolved"] == 1
    assert cancellation["exceptions"][0]["code"] == "protected_work"
    assert (
        db.query_one("SELECT status FROM jobs WHERE id = %s", (int(job["id"]),))[
            "status"
        ]
        == "scheduled"
    )


def test_sync_surfaces_all_day_wrong_type_and_archived_site_exceptions(client, auth):
    configure_canonical_sources(client, auth)
    all_day_base = google_occurrence(
        "all-day",
        calendar_id="residential@example.test",
    )
    all_day = replace(
        all_day_base,
        all_day=True,
        start="2026-07-20",
        end="2026-07-21",
    )
    wrong_type = google_occurrence(
        "wrong-type",
        calendar_id="residential@example.test",
        summary="Commercial Customer",
        location="456 Oak St, Effingham",
        start=WINDOW_START + timedelta(days=1),
    )
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO locations (
                    address, customer_name, location_type, active
                ) VALUES (
                    '789 Pine St, Effingham', 'Archived Commercial',
                    'Commercial', false
                )
                """
            )
    archived = google_occurrence(
        "archived",
        calendar_id="commercial@example.test",
        summary="Archived Commercial",
        location="789 Pine St, Effingham",
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [all_day, wrong_type],
        "commercial@example.test": [archived],
    }

    response = client.post("/api/admin/google-calendar/sync", headers=auth)

    assert response.status_code == 200
    assert response.json()["counts"]["unresolved"] == 3
    assert {row["code"] for row in response.json()["exceptions"]} == {
        "all_day",
        "wrong_site_type",
        "archived_site",
    }
    exceptions = {row["code"]: row for row in response.json()["exceptions"]}
    assert exceptions["wrong_site_type"]["candidateSites"][0]["address"] == (
        "456 Oak St, Effingham"
    )
    assert exceptions["archived_site"]["candidateSites"][0]["address"] == (
        "789 Pine St, Effingham"
    )
    assert {
        site["address"]
        for site in response.json()["eligibleSitesByRole"][
            store.RESIDENTIAL_MORNING_ROLE
        ]
    } == {"123 Main St, Effingham"}
    assert {
        site["address"]
        for site in response.json()["eligibleSitesByRole"][
            store.COMMERCIAL_EVENING_NIGHT_ROLE
        ]
    } == {"456 Oak St, Effingham"}
    assert (
        db.query_one(
            """
            SELECT COUNT(*) AS n
            FROM jobs
            WHERE source_key = ANY(%s)
            """,
            ([all_day.source_key, wrong_type.source_key, archived.source_key],),
        )["n"]
        == 0
    )


def test_sync_collision_reports_job_ids_separately_from_site_candidates(client, auth):
    configure_canonical_sources(client, auth)
    occurrence = google_occurrence(
        "manual-job-collision",
        calendar_id="residential@example.test",
    )
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )
    job_id = int(
        db.query_one(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date, status
            ) VALUES (%s, 'Test Customer', %s, 'scheduled')
            RETURNING id
            """,
            (
                location_id,
                calendar_api._source_occurrence(occurrence).service_date,
            ),
        )["id"]
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [occurrence],
        "commercial@example.test": [],
    }

    response = client.post("/api/admin/google-calendar/sync", headers=auth).json()

    collision = response["exceptions"][0]
    assert collision["code"] == "legacy_job_collision"
    assert collision["conflictingJobIds"] == [job_id]
    assert collision["candidateSites"] == [
        {
            "id": location_id,
            "customerName": "Test Customer",
            "address": "123 Main St, Effingham",
            "locationType": "Residential",
            "active": True,
        }
    ]
    db.execute("DELETE FROM jobs WHERE id = %s", (job_id,))


def test_mapping_is_fingerprint_guarded_and_recurring_series_is_reused(client, auth):
    sources = configure_canonical_sources(client, auth)
    original_start = WINDOW_START
    unresolved = google_occurrence(
        "series-instance",
        calendar_id="residential@example.test",
        summary="Needs mapping",
        location="Calendar-only note",
        recurring_event_id="residential-series",
        original_start=original_start,
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [unresolved],
        "commercial@example.test": [],
    }
    FakeGoogleClient.targeted_recurring_occurrences = {
        ("residential-series", original_start.isoformat()): unresolved
    }
    synced = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    exception = next(
        row for row in synced["exceptions"] if row["sourceKey"] == unresolved.source_key
    )
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )
    request = {
        "sourceId": sources[store.RESIDENTIAL_MORNING_ROLE]["id"],
        "sourceKey": unresolved.source_key,
        "sourceFingerprint": exception["sourceFingerprint"],
        "eventId": unresolved.event_id,
        "seriesId": unresolved.recurring_event_id,
        "occurrenceId": unresolved.original_start_query,
        "locationId": location_id,
        "applyToSeries": True,
    }
    stale = client.put(
        "/api/admin/google-calendar/mappings",
        headers=auth,
        json={**request, "sourceFingerprint": "0" * 64},
    )
    assert stale.status_code == 409
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_event_mappings")["n"]
        == 0
    )

    saved = client.put(
        "/api/admin/google-calendar/mappings",
        headers=auth,
        json=request,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["mapping"]["scope"] == "series"

    applied = client.post("/api/admin/google-calendar/sync", headers=auth)
    assert applied.status_code == 200
    assert applied.json()["counts"]["create"] == 1
    assert (
        db.query_one(
            "SELECT location_id FROM jobs WHERE source_key = %s",
            (unresolved.source_key,),
        )["location_id"]
        == location_id
    )


def test_delayed_source_writes_reject_a_replaced_calendar(client, auth):
    sources = configure_canonical_sources(client, auth)
    residential = sources[store.RESIDENTIAL_MORNING_ROLE]
    commercial = sources[store.COMMERCIAL_EVENING_NIGHT_ROLE]
    connection = store.active_connection()
    assert connection is not None
    replaced = store.replace_calendar_sources(
        connection_id=int(connection["id"]),
        expected_credential_version=int(connection["credential_version"]),
        bindings=[
            {
                "role": store.RESIDENTIAL_MORNING_ROLE,
                "calendar_id": "replacement-residential@example.test",
                "calendar_name": "Replacement Residential",
                "calendar_timezone": "America/Chicago",
            },
            {
                "role": store.COMMERCIAL_EVENING_NIGHT_ROLE,
                "calendar_id": str(commercial["calendarId"]),
                "calendar_name": str(commercial["calendarName"]),
                "calendar_timezone": str(commercial["calendarTimeZone"]),
            },
        ],
        actor_id=1,
        actor_name="Juan Canfield",
    )
    replaced_residential = next(
        row for row in replaced if row["role"] == store.RESIDENTIAL_MORNING_ROLE
    )
    assert int(replaced_residential["id"]) == int(residential["id"])

    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )
    with pytest.raises(
        store.CalendarStoreError,
        match="Google Calendar source changed",
    ):
        store.upsert_canonical_mapping(
            source_id=int(residential["id"]),
            expected_credential_version=int(connection["credential_version"]),
            expected_calendar_id=str(residential["calendarId"]),
            expected_calendar_timezone=str(residential["calendarTimeZone"]),
            source_key="a" * 64,
            source_series_id="stale-series",
            source_fingerprint="b" * 64,
            location_id=location_id,
            apply_to_series=True,
            actor_id=1,
            actor_name="Juan Canfield",
        )
    recorded = store.mark_calendar_source_sync_failed(
        source_id=int(residential["id"]),
        expected_credential_version=int(connection["credential_version"]),
        expected_calendar_id=str(residential["calendarId"]),
        expected_calendar_timezone=str(residential["calendarTimeZone"]),
        window_start=WINDOW_START,
        window_end=WINDOW_START + timedelta(days=30),
        message="stale provider failure",
    )
    assert recorded is False
    assert db.query_one(
        """
        SELECT calendar_id, last_sync_status, last_sync_error
        FROM google_calendar_sources
        WHERE id = %s
        """,
        (int(residential["id"]),),
    ) == {
        "calendar_id": "replacement-residential@example.test",
        "last_sync_status": "never",
        "last_sync_error": None,
    }
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_event_mappings")["n"]
        == 0
    )


def test_provider_writes_reject_a_superseded_oauth_grant(client, auth):
    sources = configure_canonical_sources(client, auth)
    residential = sources[store.RESIDENTIAL_MORNING_ROLE]
    commercial = sources[store.COMMERCIAL_EVENING_NIGHT_ROLE]
    connection = store.active_connection()
    assert connection is not None
    stale_version = int(connection["credential_version"])
    reauthorized = store.reauthorize_active_connection(
        connection_id=int(connection["id"]),
        account_email="reauthorized@example.test",
        credentials={
            "access_token": "replacement-access",
            "refresh_token": "replacement-refresh",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "token_type": "Bearer",
            "scopes": list(CALENDAR_READONLY_SCOPES),
        },
        scopes=CALENDAR_READONLY_SCOPES,
        accessible_calendar_ids=[
            str(residential["calendarId"]),
            str(commercial["calendarId"]),
        ],
        admin_id=1,
        admin_name="Juan Canfield",
        cipher=store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="),
    )
    assert int(reauthorized["credential_version"]) == stale_version + 1
    occurrence = calendar_api._source_occurrence(
        google_occurrence(
            "stale-oauth-snapshot",
            calendar_id=str(residential["calendarId"]),
        )
    )
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )

    with pytest.raises(
        store.CalendarStoreError,
        match="Google Calendar credentials changed",
    ):
        store.sync_calendar_source(
            source_id=int(residential["id"]),
            expected_credential_version=stale_version,
            occurrences=[occurrence],
            window_start=WINDOW_START,
            window_end=WINDOW_START + timedelta(days=30),
            actor_id=1,
            actor_name="Juan Canfield",
        )
    with pytest.raises(
        store.CalendarStoreError,
        match="Google Calendar credentials changed",
    ):
        store.upsert_canonical_mapping(
            source_id=int(residential["id"]),
            expected_credential_version=stale_version,
            expected_calendar_id=str(residential["calendarId"]),
            expected_calendar_timezone=str(residential["calendarTimeZone"]),
            source_key=occurrence.source_key,
            source_series_id=occurrence.series_id,
            source_fingerprint=calendar_api.occurrence_fingerprint(occurrence),
            location_id=location_id,
            apply_to_series=True,
            actor_id=1,
            actor_name="Juan Canfield",
        )
    assert (
        store.mark_calendar_source_sync_failed(
            source_id=int(residential["id"]),
            expected_credential_version=stale_version,
            expected_calendar_id=str(residential["calendarId"]),
            expected_calendar_timezone=str(residential["calendarTimeZone"]),
            window_start=WINDOW_START,
            window_end=WINDOW_START + timedelta(days=30),
            message="failure from stale grant",
        )
        is False
    )
    assert db.query_one(
        """
        SELECT last_sync_status, last_sync_error
        FROM google_calendar_sources
        WHERE id = %s
        """,
        (int(residential["id"]),),
    ) == {"last_sync_status": "never", "last_sync_error": None}
    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM jobs WHERE source_key = %s",
            (occurrence.source_key,),
        )["n"]
        == 0
    )
    assert (
        db.query_one("SELECT COUNT(*) AS n FROM google_calendar_event_mappings")["n"]
        == 0
    )


def test_disconnect_serializes_an_inflight_canonical_sync(client, auth):
    sources = configure_canonical_sources(client, auth)
    residential = sources[store.RESIDENTIAL_MORNING_ROLE]
    connection = store.active_connection()
    assert connection is not None
    start = datetime.now(timezone.utc) + timedelta(days=7)
    occurrence = calendar_api._source_occurrence(
        google_occurrence(
            "disconnect-sync-race",
            calendar_id=str(residential["calendarId"]),
            start=start,
        )
    )
    disconnect_ready = Event()
    allow_disconnect = Event()

    def pause_before_disconnect() -> None:
        disconnect_ready.set()
        assert allow_disconnect.wait(timeout=5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        disconnect_future = executor.submit(
            store.disconnect_calendar,
            connection_id=int(connection["id"]),
            expected_credential_version=int(connection["credential_version"]),
            admin_id=1,
            admin_name="Juan Canfield",
            before_disconnect=pause_before_disconnect,
        )
        assert disconnect_ready.wait(timeout=2)
        sync_future = executor.submit(
            store.sync_calendar_source,
            source_id=int(residential["id"]),
            expected_credential_version=int(connection["credential_version"]),
            occurrences=[occurrence],
            window_start=start - timedelta(days=1),
            window_end=start + timedelta(days=30),
            actor_id=1,
            actor_name="Juan Canfield",
        )
        with pytest.raises(FutureTimeoutError):
            sync_future.result(timeout=0.2)
        allow_disconnect.set()
        assert disconnect_future.result(timeout=5) is True
        with pytest.raises(
            store.CalendarStoreError,
            match="Google Calendar source is no longer active",
        ):
            sync_future.result(timeout=5)

    assert (
        db.query_one(
            "SELECT COUNT(*) AS n FROM jobs WHERE source_key = %s",
            (occurrence.source_key,),
        )["n"]
        == 0
    )


@pytest.mark.parametrize("visit_status", ["planned", "completed", "cancelled"])
def test_legacy_migration_blocks_only_planned_work_from_revoked_connection(
    client, auth, visit_status
):
    sources = configure_canonical_sources(client, auth)
    residential = sources[store.RESIDENTIAL_MORNING_ROLE]
    connection = store.active_connection()
    assert connection is not None
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )
    occurrence = calendar_api._source_occurrence(
        google_occurrence(
            f"{visit_status}-revoked-legacy-migration",
            calendar_id=str(residential["calendarId"]),
        )
    )
    planned_visit_id = int(
        db.query_one(
            """
            INSERT INTO planned_service_visits (
                connection_id, source_calendar_id, source_event_id,
                source_series_id, source_occurrence_id, source_key,
                source_fingerprint, title, location_id, approximate_start,
                approximate_end, source_timezone, status, completed_at, cancelled_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s
            )
            RETURNING id
            """,
            (
                int(connection["id"]),
                occurrence.calendar_id,
                occurrence.event_id,
                occurrence.series_id,
                occurrence.occurrence_id,
                occurrence.source_key,
                calendar_api.occurrence_fingerprint(occurrence),
                occurrence.title,
                location_id,
                occurrence.starts_at,
                occurrence.ends_at,
                occurrence.time_zone,
                visit_status,
                occurrence.ends_at if visit_status == "completed" else None,
                occurrence.ends_at if visit_status == "cancelled" else None,
            ),
        )["id"]
    )
    assert store.disconnect_calendar(
        connection_id=int(connection["id"]),
        expected_credential_version=int(connection["credential_version"]),
        admin_id=1,
        admin_name="Juan Canfield",
    )

    migrated = store.migrate_legacy_planned_visits()

    if visit_status == "planned":
        assert migrated["counts"]["created"] == 0
        assert migrated["exceptions"] == [
            {
                "plannedVisitId": planned_visit_id,
                "sourceKey": occurrence.source_key,
                "code": "source_disconnected",
                "locationId": location_id,
            }
        ]
        assert (
            db.query_one(
                "SELECT migrated_job_id FROM planned_service_visits WHERE id = %s",
                (planned_visit_id,),
            )["migrated_job_id"]
            is None
        )
        assert (
            db.query_one(
                "SELECT COUNT(*) AS n FROM jobs WHERE source_key = %s",
                (occurrence.source_key,),
            )["n"]
            == 0
        )
    else:
        assert migrated["counts"]["created"] == 1
        assert migrated["exceptions"] == []
        migrated_row = db.query_one(
            """
            SELECT j.status, j.calendar_source_id, pv.migrated_job_id
            FROM planned_service_visits pv
            JOIN jobs j ON j.id = pv.migrated_job_id
            WHERE pv.id = %s
            """,
            (planned_visit_id,),
        )
        assert migrated_row["status"] == visit_status
        assert migrated_row["calendar_source_id"] == int(residential["id"])
        assert migrated_row["migrated_job_id"] is not None


def test_legacy_visit_migration_is_idempotent_and_refuses_manual_job_collision(
    client, auth
):
    sources = configure_canonical_sources(client, auth)
    connection_id = int(sources[store.RESIDENTIAL_MORNING_ROLE]["connectionId"])
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '123 Main St, Effingham'"
        )["id"]
    )
    occurrence = calendar_api._source_occurrence(
        google_occurrence(
            "legacy-migration",
            calendar_id="residential@example.test",
        )
    )
    fingerprint = calendar_api.occurrence_fingerprint(occurrence)
    manual_job_id = int(
        db.query_one(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date, status
            ) VALUES (%s, 'Test Customer', %s, 'scheduled')
            RETURNING id
            """,
            (location_id, occurrence.service_date),
        )["id"]
    )
    planned_visit_id = int(
        db.query_one(
            """
            INSERT INTO planned_service_visits (
                connection_id, source_calendar_id, source_event_id,
                source_series_id, source_occurrence_id, source_key,
                source_fingerprint, title, location_id, approximate_start,
                approximate_end, source_timezone
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                connection_id,
                occurrence.calendar_id,
                occurrence.event_id,
                occurrence.series_id,
                occurrence.occurrence_id,
                occurrence.source_key,
                fingerprint,
                occurrence.title,
                location_id,
                occurrence.starts_at,
                occurrence.ends_at,
                occurrence.time_zone,
            ),
        )["id"]
    )

    collision = store.migrate_legacy_planned_visits()
    assert collision["counts"]["collisions"] == 1
    assert collision["collisions"][0]["jobIds"] == [manual_job_id]
    assert (
        db.query_one(
            "SELECT migrated_job_id FROM planned_service_visits WHERE id = %s",
            (planned_visit_id,),
        )["migrated_job_id"]
        is None
    )
    FakeGoogleClient.occurrences_by_calendar = {
        "residential@example.test": [
            google_occurrence(
                "legacy-migration",
                calendar_id="residential@example.test",
            )
        ],
        "commercial@example.test": [],
    }
    surfaced = client.post("/api/admin/google-calendar/sync", headers=auth).json()
    assert surfaced["legacyMigration"]["counts"]["collisions"] == 1
    assert surfaced["exceptions"][0]["code"] == "legacy_job_collision"
    assert surfaced["exceptions"][0]["conflictingJobIds"] == [manual_job_id]

    db.execute("DELETE FROM jobs WHERE id = %s", (manual_job_id,))
    migrated = store.migrate_legacy_planned_visits()
    assert migrated["counts"]["created"] == 1
    linked = db.query_one(
        """
        SELECT pv.migrated_job_id, j.source_key, j.expected_hours, j.revenue
        FROM planned_service_visits pv
        JOIN jobs j ON j.id = pv.migrated_job_id
        WHERE pv.id = %s
        """,
        (planned_visit_id,),
    )
    assert linked["source_key"] == occurrence.source_key
    assert linked["expected_hours"] is None
    assert linked["revenue"] is None
    audit = db.query_one(
        """
        SELECT action, actor_name, after_state
        FROM planned_visit_audit_events
        WHERE planned_visit_id = %s
          AND action = 'canonical_job_migration_created'
        """,
        (planned_visit_id,),
    )
    assert audit["actor_name"] == "system:canonical-calendar-migration"
    assert int(audit["after_state"]["jobId"]) == int(linked["migrated_job_id"])
    retry = store.migrate_legacy_planned_visits()
    assert retry["counts"] == {
        "created": 0,
        "linked": 0,
        "collisions": 0,
    }
    assert retry["exceptions"] == []
    assert (
        db.query_one(
            """
        SELECT COUNT(*) AS n
        FROM planned_visit_audit_events
        WHERE planned_visit_id = %s
          AND action LIKE 'canonical_job_migration_%%'
        """,
            (planned_visit_id,),
        )["n"]
        == 1
    )


def test_legacy_migration_preserves_historical_status_despite_current_site_rules(
    client, auth
):
    sources = configure_canonical_sources(client, auth)
    connection_id = int(sources[store.RESIDENTIAL_MORNING_ROLE]["connectionId"])
    location_id = int(
        db.query_one(
            "SELECT id FROM locations WHERE address = '456 Oak St, Effingham'"
        )["id"]
    )
    db.execute("UPDATE locations SET active = false WHERE id = %s", (location_id,))
    occurrence = calendar_api._source_occurrence(
        google_occurrence(
            "legacy-completed",
            calendar_id="residential@example.test",
            summary="Commercial Customer",
            location="456 Oak St, Effingham",
        )
    )
    planned_visit_id = int(
        db.query_one(
            """
            INSERT INTO planned_service_visits (
                connection_id, source_calendar_id, source_event_id,
                source_series_id, source_occurrence_id, source_key,
                source_fingerprint, title, location_id, approximate_start,
                approximate_end, all_day, source_timezone, status, completed_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true, %s,
                'completed', %s
            )
            RETURNING id
            """,
            (
                connection_id,
                occurrence.calendar_id,
                occurrence.event_id,
                occurrence.series_id,
                occurrence.occurrence_id,
                occurrence.source_key,
                calendar_api.occurrence_fingerprint(occurrence),
                occurrence.title,
                location_id,
                occurrence.starts_at,
                occurrence.ends_at,
                occurrence.time_zone,
                occurrence.ends_at,
            ),
        )["id"]
    )
    db.execute(
        "DELETE FROM google_calendar_sources WHERE connection_id = %s",
        (connection_id,),
    )

    migrated = store.migrate_legacy_planned_visits()

    assert migrated["counts"] == {
        "created": 1,
        "linked": 0,
        "collisions": 0,
    }
    assert migrated["exceptions"] == []
    migrated_row = db.query_one(
        """
        SELECT j.status, j.source_all_day, j.calendar_source_id,
               pv.migrated_job_id
        FROM planned_service_visits pv
        JOIN jobs j ON j.id = pv.migrated_job_id
        WHERE pv.id = %s
        """,
        (planned_visit_id,),
    )
    assert migrated_row["status"] == "completed"
    assert migrated_row["source_all_day"] is True
    assert migrated_row["calendar_source_id"] is None
    assert migrated_row["migrated_job_id"] is not None
