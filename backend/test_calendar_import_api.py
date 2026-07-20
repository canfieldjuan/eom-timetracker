"""Route and PostgreSQL proof for reviewed Google planned-visit imports."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import logging
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
    batch_calls = 0

    def __init__(self, **_: object) -> None:
        pass

    def authorization_url(
        self, *, state: str, code_challenge: str, login_hint: str | None = None
    ) -> str:
        if self.authorization_error is not None:
            raise self.authorization_error
        assert len(code_challenge) == 43
        assert login_hint is None
        return (
            f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&scope=readonly"
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> OAuthTokenSet:
        assert len(code_verifier) >= 43
        self.exchanged_codes.append(code)
        return OAuthTokenSet(
            access_token="access-secret",
            refresh_token="refresh-secret",
            expires_in=3600,
            token_type="Bearer",
            scopes=CALENDAR_READONLY_SCOPES,
        )

    def refresh_access_token(self, *, refresh_token: str) -> OAuthTokenSet:
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

    def list_occurrences(self, **_: object) -> list[CalendarOccurrence]:
        return list(self.occurrences)

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
) -> CalendarOccurrence:
    raw: dict[str, object] = {"id": event_id}
    if recurring_event_id is not None:
        raw["recurringEventId"] = recurring_event_id
    if original_start is not None:
        raw["originalStartTime"] = {"dateTime": original_start.isoformat()}
    return CalendarOccurrence(
        source_key=stable_occurrence_identity("operations@example.test", raw),
        calendar_id="operations@example.test",
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
                DELETE FROM google_calendar_connections;
                DELETE FROM crew_memberships;
                DELETE FROM locations WHERE address = '456 Oak St, Effingham';
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
                DELETE FROM google_calendar_connections;
                DELETE FROM crew_memberships;
                DELETE FROM locations WHERE address = '456 Oak St, Effingham';
                DELETE FROM employees WHERE name IN (
                    'Carmen Alvarez', 'Pamela Brown', 'Tina Davis',
                    'Carmen Duplicate'
                );
                """
            )


def connect_selected_calendar() -> int:
    cipher = store.CredentialCipher("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    active = store.active_connection()
    if active:
        store.disconnect_calendar(
            connection_id=int(active["id"]),
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
    store.select_calendar(
        connection_id=int(connection["id"]),
        calendar_id="operations@example.test",
        calendar_name="Operations",
        calendar_timezone="America/Chicago",
    )
    return int(connection["id"])


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
        "scope": " ".join(CALENDAR_READONLY_SCOPES),
        "scopes": list(CALENDAR_READONLY_SCOPES),
        "accountEmail": None,
        "selectedCalendarId": None,
        "selectedCalendarName": None,
        "selectedCalendarTimeZone": None,
    }

    connect_selected_calendar()
    reconnect = client.post("/api/admin/google-calendar/connect", headers=auth)
    assert reconnect.status_code == 409
    assert "Disconnect" in reconnect.json()["error"]
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
            store.disconnect_calendar(
                connection_id=connection_id,
                admin_id=1,
                admin_name="Juan Canfield",
            )
        elif connection_change == "reconnect":
            connect_selected_calendar()
        elif connection_change == "switch":
            store.select_calendar(
                connection_id=connection_id,
                calendar_id="different@example.test",
                calendar_name="Different calendar",
                calendar_timezone="America/Chicago",
            )
        else:
            store.select_calendar(
                connection_id=connection_id,
                calendar_id="operations@example.test",
                calendar_name="Operations",
                calendar_timezone="America/New_York",
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


def test_new_preview_refreshes_live_calendar_name_and_timezone(client, auth):
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
        json={"resolutions": []},
    )

    assert response.status_code == 200, response.text
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
    client, auth
):
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

    FakeGoogleClient.occurrences = [google_occurrence("crew-needs-resolution")]
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
