"""Durable storage and secret handling for read-only Calendar imports.

Calendar synchronization writes canonical jobs and reads existing work evidence
only to prevent unsafe moves or cancellations. It never mutates shifts, payroll,
QR evidence, billing, or Customer/Site records.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Iterable
from zoneinfo import ZoneInfo

import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken

import db


MORNING_CREW_NAME = "Morning Crew"
MORNING_CREW_EXPECTED_NAMES = ("Carmen", "Pamela", "Tina")
RESIDENTIAL_MORNING_ROLE = "residential_morning"
COMMERCIAL_EVENING_NIGHT_ROLE = "commercial_evening_night"
CALENDAR_SOURCE_ROLES = (
    RESIDENTIAL_MORNING_ROLE,
    COMMERCIAL_EVENING_NIGHT_ROLE,
)
CALENDAR_ROLE_LOCATION_TYPES = {
    RESIDENTIAL_MORNING_ROLE: "Residential",
    COMMERCIAL_EVENING_NIGHT_ROLE: "Commercial",
}
PRODUCT_TIMEZONE = ZoneInfo("America/Chicago")


class CalendarStoreError(RuntimeError):
    """Base error for safe, user-displayable Calendar storage failures."""


class CalendarConfigurationError(CalendarStoreError):
    """Raised when server-only Calendar encryption is not configured."""


class OAuthStateError(CalendarStoreError):
    """Raised when an OAuth callback state is forged, expired, or reused."""


@dataclass(frozen=True)
class ConsumedOAuthState:
    state_hash: str
    admin_id: int
    admin_name: str
    pkce_verifier: str
    reconnect_connection_id: int | None


@dataclass(frozen=True)
class _CanonicalLocationSnapshot:
    by_id: dict[int, dict[str, Any]]
    by_normalized_hint: dict[str, tuple[dict[str, Any], ...]]


class CredentialCipher:
    """Fernet wrapper that never accepts an implicit or derived key."""

    def __init__(self, key: str):
        if not key:
            raise CalendarConfigurationError(
                "Google Calendar token encryption is not configured"
            )
        try:
            self._fernet = Fernet(key.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise CalendarConfigurationError(
                "Google Calendar token encryption key is invalid"
            ) from exc

    def encrypt_text(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt_text(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
            raise CalendarStoreError(
                "Stored Google Calendar credentials could not be decrypted"
            ) from exc

    def encrypt_json(self, value: dict[str, Any]) -> str:
        return self.encrypt_text(
            json.dumps(value, sort_keys=True, separators=(",", ":"))
        )

    def decrypt_json(self, value: str) -> dict[str, Any]:
        try:
            decoded = json.loads(self.decrypt_text(value))
        except json.JSONDecodeError as exc:
            raise CalendarStoreError(
                "Stored Google Calendar credentials are invalid"
            ) from exc
        if not isinstance(decoded, dict):
            raise CalendarStoreError("Stored Google Calendar credentials are invalid")
        return decoded


def ensure_schema() -> None:
    """Add the Calendar/planned-visit domain to an existing deployment."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS google_calendar_connections (
            id                     BIGSERIAL PRIMARY KEY,
            google_account_email   TEXT,
            credential_ciphertext  TEXT,
            granted_scopes         TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
            selected_calendar_id   TEXT,
            selected_calendar_name TEXT,
            selected_calendar_timezone TEXT,
            credential_version     BIGINT NOT NULL DEFAULT 1
                                       CHECK (credential_version > 0),
            connected_by           INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            connected_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at             TIMESTAMPTZ
        );

        ALTER TABLE google_calendar_connections
            ADD COLUMN IF NOT EXISTS selected_calendar_timezone TEXT;

        ALTER TABLE google_calendar_connections
            ADD COLUMN IF NOT EXISTS credential_version BIGINT NOT NULL DEFAULT 1
                CHECK (credential_version > 0);

        CREATE UNIQUE INDEX IF NOT EXISTS uq_google_calendar_active_connection
            ON google_calendar_connections ((revoked_at IS NULL))
            WHERE revoked_at IS NULL;

        CREATE TABLE IF NOT EXISTS google_calendar_sources (
            id                 BIGSERIAL PRIMARY KEY,
            connection_id      BIGINT NOT NULL REFERENCES google_calendar_connections(id),
            role               VARCHAR(40) NOT NULL
                                   CHECK (
                                       role IN (
                                           'residential_morning',
                                           'commercial_evening_night'
                                       )
                                   ),
            calendar_id        TEXT NOT NULL,
            calendar_name      TEXT NOT NULL,
            calendar_timezone  TEXT NOT NULL,
            last_synced_at     TIMESTAMPTZ,
            last_sync_status   VARCHAR(16) NOT NULL DEFAULT 'never'
                                   CHECK (
                                       last_sync_status IN ('never', 'success', 'failed')
                                   ),
            last_sync_error    TEXT,
            last_sync_counts   JSONB,
            last_sync_window_start TIMESTAMPTZ,
            last_sync_window_end   TIMESTAMPTZ,
            created_by         INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            updated_by         INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (connection_id, role),
            UNIQUE (connection_id, calendar_id)
        );

        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_end TIMESTAMPTZ;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS calendar_source_id
            BIGINT REFERENCES google_calendar_sources(id);
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_calendar_id TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_event_id TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_series_id TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_occurrence_id TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_key VARCHAR(64)
            CHECK (source_key IS NULL OR source_key ~ '^[0-9a-f]{64}$');
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_fingerprint VARCHAR(64)
            CHECK (
                source_fingerprint IS NULL
                OR source_fingerprint ~ '^[0-9a-f]{64}$'
            );
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_etag TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_updated_at TIMESTAMPTZ;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_title TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_location_text TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_timezone TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS source_all_day
            BOOLEAN NOT NULL DEFAULT false;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cancellation_reason TEXT;
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS updated_at
            TIMESTAMPTZ NOT NULL DEFAULT NOW();

        CREATE UNIQUE INDEX IF NOT EXISTS uq_jobs_google_source_key
            ON jobs(source_key) WHERE source_key IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_google_calendar_sources_connection
            ON google_calendar_sources(connection_id, role);
        CREATE INDEX IF NOT EXISTS idx_jobs_calendar_source_window
            ON jobs(calendar_source_id, scheduled_start, status);

        CREATE TABLE IF NOT EXISTS google_calendar_oauth_states (
            state_hash                 VARCHAR(64) PRIMARY KEY
                                           CHECK (state_hash ~ '^[0-9a-f]{64}$'),
            admin_employee_id          INTEGER NOT NULL REFERENCES employees(id),
            pkce_verifier_ciphertext   TEXT NOT NULL,
            reconnect_connection_id    BIGINT REFERENCES google_calendar_connections(id),
            expires_at                 TIMESTAMPTZ NOT NULL,
            consumed_at                TIMESTAMPTZ,
            created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        ALTER TABLE google_calendar_oauth_states
            ADD COLUMN IF NOT EXISTS reconnect_connection_id
                BIGINT REFERENCES google_calendar_connections(id);

        CREATE TABLE IF NOT EXISTS crews (
            id          BIGSERIAL PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            active      BOOLEAN NOT NULL DEFAULT true,
            created_by  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS crew_memberships (
            id             BIGSERIAL PRIMARY KEY,
            crew_id        BIGINT NOT NULL REFERENCES crews(id),
            employee_id    INTEGER NOT NULL REFERENCES employees(id),
            effective_from DATE NOT NULL,
            effective_to   DATE,
            created_by     INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (effective_to IS NULL OR effective_to >= effective_from),
            UNIQUE (crew_id, employee_id, effective_from)
        );

        INSERT INTO crews (name)
        VALUES ('Morning Crew')
        ON CONFLICT (name) DO NOTHING;

        CREATE TABLE IF NOT EXISTS calendar_import_previews (
            id                  TEXT PRIMARY KEY,
            connection_id       BIGINT NOT NULL REFERENCES google_calendar_connections(id),
            calendar_id         TEXT NOT NULL,
            range_start         TIMESTAMPTZ NOT NULL,
            range_end           TIMESTAMPTZ NOT NULL,
            source_fingerprint  VARCHAR(64) NOT NULL
                                    CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
            preview_fingerprint VARCHAR(64) NOT NULL
                                    CHECK (preview_fingerprint ~ '^[0-9a-f]{64}$'),
            payload             JSONB NOT NULL,
            status              VARCHAR(16) NOT NULL DEFAULT 'open'
                                    CHECK (status IN ('open', 'applied', 'stale')),
            created_by          INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at          TIMESTAMPTZ NOT NULL,
            applied_at          TIMESTAMPTZ,
            result              JSONB,
            CHECK (range_end > range_start)
        );

        CREATE TABLE IF NOT EXISTS google_calendar_event_mappings (
            id                BIGSERIAL PRIMARY KEY,
            connection_id     BIGINT NOT NULL REFERENCES google_calendar_connections(id),
            calendar_id       TEXT NOT NULL,
            source_key        VARCHAR(64) NOT NULL
                                  CHECK (source_key ~ '^[0-9a-f]{64}$'),
            source_series_id  TEXT,
            mapping_scope     VARCHAR(16) NOT NULL DEFAULT 'occurrence'
                                  CHECK (mapping_scope IN ('occurrence', 'series')),
            source_fingerprint VARCHAR(64)
                                  CHECK (
                                      source_fingerprint IS NULL
                                      OR source_fingerprint ~ '^[0-9a-f]{64}$'
                                  ),
            location_id       INTEGER NOT NULL REFERENCES locations(id),
            created_by        INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            updated_by        INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (source_key)
        );

        ALTER TABLE google_calendar_event_mappings
            ADD COLUMN IF NOT EXISTS source_series_id TEXT;
        ALTER TABLE google_calendar_event_mappings
            ADD COLUMN IF NOT EXISTS mapping_scope
                VARCHAR(16) NOT NULL DEFAULT 'occurrence'
                CHECK (mapping_scope IN ('occurrence', 'series'));
        ALTER TABLE google_calendar_event_mappings
            ADD COLUMN IF NOT EXISTS source_fingerprint VARCHAR(64)
                CHECK (
                    source_fingerprint IS NULL
                    OR source_fingerprint ~ '^[0-9a-f]{64}$'
                );

        CREATE TABLE IF NOT EXISTS planned_service_visits (
            id                    BIGSERIAL PRIMARY KEY,
            connection_id         BIGINT NOT NULL REFERENCES google_calendar_connections(id),
            mapping_id            BIGINT REFERENCES google_calendar_event_mappings(id),
            source_calendar_id    TEXT NOT NULL,
            source_event_id       TEXT NOT NULL,
            source_series_id      TEXT NOT NULL,
            source_occurrence_id  TEXT NOT NULL,
            source_key            VARCHAR(64) NOT NULL UNIQUE
                                      CHECK (source_key ~ '^[0-9a-f]{64}$'),
            source_fingerprint    VARCHAR(64) NOT NULL
                                      CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
            source_etag           TEXT,
            source_updated_at     TIMESTAMPTZ,
            title                 TEXT NOT NULL DEFAULT '',
            description           TEXT NOT NULL DEFAULT '',
            source_location_text  TEXT NOT NULL DEFAULT '',
            location_id           INTEGER NOT NULL REFERENCES locations(id),
            approximate_start     TIMESTAMPTZ NOT NULL,
            approximate_end       TIMESTAMPTZ NOT NULL,
            all_day               BOOLEAN NOT NULL DEFAULT false,
            source_timezone       TEXT,
            status                VARCHAR(16) NOT NULL DEFAULT 'planned'
                                      CHECK (status IN ('planned', 'cancelled', 'completed')),
            cancelled_at          TIMESTAMPTZ,
            completed_at          TIMESTAMPTZ,
            migrated_job_id       INTEGER REFERENCES jobs(id),
            last_preview_id       TEXT REFERENCES calendar_import_previews(id),
            last_imported_by      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (approximate_end > approximate_start),
            CHECK (status <> 'cancelled' OR cancelled_at IS NOT NULL),
            CHECK (status <> 'completed' OR completed_at IS NOT NULL)
        );

        ALTER TABLE planned_service_visits
            ADD COLUMN IF NOT EXISTS migrated_job_id INTEGER REFERENCES jobs(id);

        CREATE TABLE IF NOT EXISTS planned_visit_assignments (
            id                  BIGSERIAL PRIMARY KEY,
            planned_visit_id    BIGINT NOT NULL REFERENCES planned_service_visits(id),
            crew_id             BIGINT REFERENCES crews(id),
            employee_id         INTEGER REFERENCES employees(id),
            active              BOOLEAN NOT NULL DEFAULT true,
            assigned_by         INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            assigned_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            retired_by          INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            retired_at          TIMESTAMPTZ,
            CHECK ((crew_id IS NULL) <> (employee_id IS NULL)),
            CHECK (active OR retired_at IS NOT NULL)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS uq_planned_visit_active_crew_assignment
            ON planned_visit_assignments(planned_visit_id, crew_id)
            WHERE active AND crew_id IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS uq_planned_visit_active_employee_assignment
            ON planned_visit_assignments(planned_visit_id, employee_id)
            WHERE active AND employee_id IS NOT NULL;

        CREATE TABLE IF NOT EXISTS planned_visit_audit_events (
            id                  BIGSERIAL PRIMARY KEY,
            planned_visit_id    BIGINT REFERENCES planned_service_visits(id),
            preview_id          TEXT REFERENCES calendar_import_previews(id),
            action              VARCHAR(48) NOT NULL,
            source_key          VARCHAR(64),
            actor_employee_id   INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            actor_name          TEXT NOT NULL,
            before_state        JSONB,
            after_state         JSONB,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_google_calendar_oauth_states_expiry
            ON google_calendar_oauth_states(expires_at, consumed_at);
        CREATE INDEX IF NOT EXISTS idx_crew_memberships_effective
            ON crew_memberships(crew_id, effective_from, effective_to);
        CREATE INDEX IF NOT EXISTS idx_calendar_import_previews_status
            ON calendar_import_previews(status, expires_at);
        CREATE INDEX IF NOT EXISTS idx_google_calendar_event_mappings_source
            ON google_calendar_event_mappings(connection_id, calendar_id, source_key);
        CREATE UNIQUE INDEX IF NOT EXISTS uq_google_calendar_event_mappings_series
            ON google_calendar_event_mappings(
                connection_id, calendar_id, source_series_id
            )
            WHERE mapping_scope = 'series' AND source_series_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_planned_service_visits_window
            ON planned_service_visits(approximate_start, status);
        CREATE INDEX IF NOT EXISTS idx_planned_service_visits_source
            ON planned_service_visits(connection_id, source_calendar_id, source_series_id);
        CREATE INDEX IF NOT EXISTS idx_planned_visit_assignments_visit
            ON planned_visit_assignments(planned_visit_id, active);
        CREATE INDEX IF NOT EXISTS idx_planned_visit_audit_events_visit
            ON planned_visit_audit_events(planned_visit_id, created_at);
        """
    )
    migrate_legacy_planned_visits()


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def create_oauth_state(
    *,
    admin_id: int,
    cipher: CredentialCipher,
    reconnect_connection_id: int | None = None,
    ttl_minutes: int = 10,
) -> tuple[str, str]:
    """Persist a one-use OAuth state and return its raw value and PKCE verifier."""
    raw_state = secrets.token_urlsafe(32)
    pkce_verifier = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("google-calendar-oauth",),
            )
            cur.execute(
                "DELETE FROM google_calendar_oauth_states WHERE expires_at <= NOW()"
            )
            cur.execute(
                """
                SELECT state_hash
                FROM google_calendar_oauth_states
                WHERE expires_at > NOW()
                LIMIT 1
                FOR UPDATE
                """
            )
            if cur.fetchone():
                raise CalendarStoreError(
                    "A Google Calendar connection is already in progress"
                )
            cur.execute(
                """
                INSERT INTO google_calendar_oauth_states (
                    state_hash, admin_employee_id,
                    pkce_verifier_ciphertext, reconnect_connection_id, expires_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    _state_hash(raw_state),
                    admin_id,
                    cipher.encrypt_text(pkce_verifier),
                    reconnect_connection_id,
                    expires_at,
                ),
            )
    return raw_state, pkce_verifier


def consume_oauth_state(
    raw_state: str, *, cipher: CredentialCipher
) -> ConsumedOAuthState:
    """Atomically consume state and revalidate the initiating admin."""
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT s.state_hash, s.pkce_verifier_ciphertext,
                       s.reconnect_connection_id,
                       e.id AS admin_id, e.name AS admin_name,
                       e.active, e.role
                FROM google_calendar_oauth_states s
                JOIN employees e ON e.id = s.admin_employee_id
                WHERE s.state_hash = %s
                  AND s.consumed_at IS NULL
                  AND s.expires_at > NOW()
                FOR UPDATE
                """,
                (_state_hash(raw_state),),
            )
            row = cur.fetchone()
            if not row or not row["active"] or row["role"] != "admin":
                raise OAuthStateError(
                    "Google Calendar connection request is invalid or expired"
                )
            verifier = cipher.decrypt_text(str(row["pkce_verifier_ciphertext"]))
            cur.execute(
                """
                UPDATE google_calendar_oauth_states
                SET consumed_at = NOW()
                WHERE state_hash = %s
                """,
                (row["state_hash"],),
            )
    return ConsumedOAuthState(
        state_hash=str(row["state_hash"]),
        admin_id=int(row["admin_id"]),
        admin_name=str(row["admin_name"]),
        pkce_verifier=verifier,
        reconnect_connection_id=(
            int(row["reconnect_connection_id"])
            if row["reconnect_connection_id"] is not None
            else None
        ),
    )


def finish_oauth_state(state_hash: str) -> None:
    """Delete consumed PKCE material after the callback attempt finishes."""

    db.execute(
        "DELETE FROM google_calendar_oauth_states WHERE state_hash = %s",
        (state_hash,),
    )


def abandon_oauth_state(raw_state: str) -> None:
    """Delete an OAuth state when authorization cannot be started."""

    finish_oauth_state(_state_hash(raw_state))


def active_connection() -> dict[str, Any] | None:
    return db.query_one(
        """
        SELECT id, google_account_email, credential_ciphertext, granted_scopes,
               selected_calendar_id, selected_calendar_name,
               selected_calendar_timezone, credential_version, connected_by,
               connected_at, updated_at
        FROM google_calendar_connections
        WHERE revoked_at IS NULL
        LIMIT 1
        """
    )


def create_active_connection(
    *,
    account_email: str | None,
    credentials: dict[str, Any],
    scopes: Iterable[str],
    admin_id: int,
    admin_name: str,
    cipher: CredentialCipher,
) -> dict[str, Any]:
    """Install one company connection only when no live grant is present."""
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                SELECT id FROM google_calendar_connections
                WHERE revoked_at IS NULL
                FOR UPDATE
                """
            )
            if cur.fetchone():
                raise CalendarStoreError(
                    "Disconnect the active Google Calendar before reconnecting"
                )
            cur.execute(
                """
                INSERT INTO google_calendar_connections (
                    google_account_email, credential_ciphertext, granted_scopes,
                    connected_by
                ) VALUES (%s, %s, %s, %s)
                RETURNING id, google_account_email, granted_scopes,
                          credential_version, connected_at
                """,
                (
                    account_email,
                    cipher.encrypt_json(credentials),
                    sorted(set(scopes)),
                    admin_id,
                ),
            )
            connection = dict(cur.fetchone())
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_employee_id, actor_name, after_state
                ) VALUES ('calendar_connected', %s, %s, %s::jsonb)
                """,
                (
                    admin_id,
                    admin_name,
                    json.dumps(
                        {
                            "connectionId": connection["id"],
                            "accountEmail": account_email,
                            "scopes": sorted(set(scopes)),
                        }
                    ),
                ),
            )
            return connection


def reauthorize_active_connection(
    *,
    connection_id: int,
    account_email: str | None,
    credentials: dict[str, Any],
    scopes: Iterable[str],
    accessible_calendar_ids: Iterable[str],
    admin_id: int,
    admin_name: str,
    cipher: CredentialCipher,
) -> dict[str, Any]:
    """Replace one exact active grant without changing its source ownership."""

    accessible = {
        str(calendar_id).strip()
        for calendar_id in accessible_calendar_ids
        if str(calendar_id).strip()
    }
    normalized_scopes = sorted(set(scopes))
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                SELECT id, google_account_email, granted_scopes,
                       selected_calendar_id, selected_calendar_name,
                       selected_calendar_timezone, credential_version, connected_by,
                       connected_at
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (connection_id,),
            )
            before = cur.fetchone()
            if not before:
                raise CalendarStoreError(
                    "Google Calendar connection changed during reauthorization"
                )
            selected_calendar_id = str(before.get("selected_calendar_id") or "").strip()
            if selected_calendar_id and selected_calendar_id not in accessible:
                raise CalendarStoreError(
                    "The reauthorized Google account cannot access the selected Calendar"
                )
            cur.execute(
                """
                SELECT calendar_id
                FROM google_calendar_sources
                WHERE connection_id = %s
                """,
                (connection_id,),
            )
            configured_source_ids = {
                str(row["calendar_id"]).strip() for row in cur.fetchall()
            }
            if not configured_source_ids.issubset(accessible):
                raise CalendarStoreError(
                    "The reauthorized Google account cannot access all configured "
                    "Calendar sources"
                )
            cur.execute(
                """
                UPDATE google_calendar_connections
                SET google_account_email = %s, credential_ciphertext = %s,
                    granted_scopes = %s, connected_by = %s,
                    credential_version = credential_version + 1,
                    updated_at = NOW()
                WHERE id = %s AND revoked_at IS NULL
                RETURNING id, google_account_email, granted_scopes,
                          selected_calendar_id, selected_calendar_name,
                          selected_calendar_timezone, credential_version, connected_by,
                          connected_at, updated_at
                """,
                (
                    account_email,
                    cipher.encrypt_json(credentials),
                    normalized_scopes,
                    admin_id,
                    connection_id,
                ),
            )
            connection = dict(cur.fetchone())
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_employee_id, actor_name,
                    before_state, after_state
                ) VALUES ('calendar_reauthorized', %s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    admin_id,
                    admin_name,
                    json.dumps(dict(before), default=str),
                    json.dumps(connection, default=str),
                ),
            )
            return connection


def connection_credentials(
    connection: dict[str, Any], *, cipher: CredentialCipher
) -> dict[str, Any]:
    ciphertext = connection.get("credential_ciphertext")
    if not ciphertext:
        raise CalendarStoreError("Google Calendar connection has no usable credentials")
    return cipher.decrypt_json(str(ciphertext))


def update_connection_credentials(
    connection_id: int,
    credentials: dict[str, Any],
    *,
    expected_credential_version: int,
    cipher: CredentialCipher,
) -> int:
    updated = db.execute_returning(
        """
        UPDATE google_calendar_connections
        SET credential_ciphertext = %s,
            credential_version = credential_version + 1,
            updated_at = NOW()
        WHERE id = %s AND revoked_at IS NULL
          AND credential_version = %s
        RETURNING credential_version
        """,
        (
            cipher.encrypt_json(credentials),
            connection_id,
            expected_credential_version,
        ),
    )
    if not updated:
        raise CalendarStoreError("Google Calendar credentials changed during refresh")
    return int(updated)


def select_calendar(
    *,
    connection_id: int,
    calendar_id: str,
    calendar_name: str,
    calendar_timezone: str | None,
    expected_credential_version: int,
    expected_selected_calendar_id: str | None = None,
) -> None:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                SELECT selected_calendar_id, credential_version
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if not connection:
                raise CalendarStoreError(
                    "Google Calendar connection is no longer active"
                )
            if int(connection["credential_version"]) != expected_credential_version:
                raise CalendarStoreError(
                    "Google Calendar credentials changed; reload the Calendar list"
                )

            selected_calendar_id = str(
                connection.get("selected_calendar_id") or ""
            ).strip()
            if (
                expected_selected_calendar_id is not None
                and selected_calendar_id != expected_selected_calendar_id
            ):
                raise CalendarStoreError(
                    "Selected Google Calendar changed; reload the Calendar list"
                )
            if selected_calendar_id != calendar_id:
                cur.execute(
                    """
                    SELECT 1
                    FROM planned_service_visits
                    WHERE status = 'planned'
                      AND approximate_end > NOW()
                      AND source_calendar_id <> %s
                    LIMIT 1
                    """,
                    (calendar_id,),
                )
                if cur.fetchone():
                    raise CalendarStoreError(
                        "Resolve future planned visits from the current Google "
                        "Calendar before selecting a different Calendar"
                    )

            cur.execute(
                """
                UPDATE google_calendar_connections
                SET selected_calendar_id = %s, selected_calendar_name = %s,
                    selected_calendar_timezone = %s,
                    updated_at = NOW()
                WHERE id = %s AND revoked_at IS NULL
                """,
                (calendar_id, calendar_name, calendar_timezone, connection_id),
            )


def disconnect_calendar(
    *,
    connection_id: int,
    expected_credential_version: int,
    admin_id: int,
    admin_name: str,
    before_disconnect: Callable[[], None] | None = None,
) -> bool:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                SELECT id, selected_calendar_id, selected_calendar_name,
                       selected_calendar_timezone, credential_version
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (connection_id,),
            )
            row = cur.fetchone()
            if not row:
                return False
            if int(row["credential_version"]) != expected_credential_version:
                raise CalendarStoreError(
                    "Google Calendar credentials changed; retry disconnecting"
                )
            selected_calendar_id = str(row["selected_calendar_id"] or "").strip()
            if selected_calendar_id:
                cur.execute(
                    """
                    SELECT 1
                    FROM planned_service_visits
                    WHERE status = 'planned'
                      AND approximate_end > NOW()
                      AND source_calendar_id = %s
                    LIMIT 1
                    """,
                    (selected_calendar_id,),
                )
                if cur.fetchone():
                    raise CalendarStoreError(
                        "Resolve or cancel future planned visits before disconnecting "
                        "Google Calendar"
                    )
            cur.execute(
                """
                SELECT 1
                FROM jobs j
                JOIN google_calendar_sources s ON s.id = j.calendar_source_id
                WHERE s.connection_id = %s
                  AND j.status <> 'cancelled'
                  AND COALESCE(j.scheduled_end, j.scheduled_start) > NOW()
                LIMIT 1
                """,
                (connection_id,),
            )
            if cur.fetchone():
                raise CalendarStoreError(
                    "Resolve or cancel future scheduled work before disconnecting "
                    "Google Calendar"
                )
            if before_disconnect is not None:
                before_disconnect()
            cur.execute(
                """
                UPDATE google_calendar_connections
                SET revoked_at = NOW(), credential_ciphertext = NULL,
                    updated_at = NOW()
                WHERE id = %s AND revoked_at IS NULL
                """,
                (connection_id,),
            )
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_employee_id, actor_name, before_state
                ) VALUES ('calendar_disconnected', %s, %s, %s::jsonb)
                """,
                (admin_id, admin_name, json.dumps(dict(row), default=str)),
            )
            return True


def read_active_locations() -> list[dict[str, Any]]:
    return db.query_all(
        """
        SELECT id, address, customer_name, active
        FROM locations
        WHERE active = true
        ORDER BY customer_name NULLS LAST, address, id
        """
    )


def read_employees() -> list[dict[str, Any]]:
    return db.query_all(
        """
        SELECT id, name, active
        FROM employees
        ORDER BY name, id
        """
    )


def bootstrap_morning_crew_memberships(*, effective_from: date) -> dict[str, Any]:
    """Seed the named crew only when all three current identities are unique.

    Existing membership is never replaced by bootstrap logic. Missing,
    inactive, or ambiguous identities leave the crew empty for an admin to
    resolve through the explicit membership endpoint.
    """

    from planned_visits import EmployeeRecord, resolve_employee_name

    employee_rows = read_employees()
    records = [
        EmployeeRecord(
            employee_id=int(row["id"]),
            name=str(row["name"]),
            active=bool(row["active"]),
        )
        for row in employee_rows
    ]
    resolutions = [
        resolve_employee_name(name, records) for name in MORNING_CREW_EXPECTED_NAMES
    ]
    if not all(resolution.resolved for resolution in resolutions):
        return {"changed": False, "reason": "identity_resolution_required"}
    employee_ids = sorted(
        int(resolution.employee_id)
        for resolution in resolutions
        if resolution.employee_id is not None
    )
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("morning-crew-bootstrap",),
            )
            cur.execute(
                "SELECT id FROM crews WHERE name = %s AND active = true FOR UPDATE",
                (MORNING_CREW_NAME,),
            )
            crew = cur.fetchone()
            if not crew:
                raise CalendarStoreError("Morning Crew was not found")
            cur.execute(
                """
                SELECT employee_id
                FROM crew_memberships
                WHERE crew_id = %s
                  AND effective_from <= %s
                  AND (effective_to IS NULL OR effective_to > %s)
                FOR UPDATE
                """,
                (crew["id"], effective_from, effective_from),
            )
            if cur.fetchone():
                return {"changed": False, "reason": "membership_already_exists"}
            for employee_id in employee_ids:
                cur.execute(
                    """
                    INSERT INTO crew_memberships (
                        crew_id, employee_id, effective_from
                    ) VALUES (%s, %s, %s)
                    """,
                    (crew["id"], employee_id, effective_from),
                )
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_name, after_state
                ) VALUES ('crew_membership_bootstrapped', %s, %s::jsonb)
                """,
                (
                    "system:unique-employee-resolution",
                    json.dumps(
                        {
                            "crewId": int(crew["id"]),
                            "employeeIds": employee_ids,
                            "effectiveFrom": effective_from.isoformat(),
                        }
                    ),
                ),
            )
    return {"changed": True, "employee_ids": employee_ids}


def read_crews(on_date: date) -> list[dict[str, Any]]:
    crews = db.query_all(
        """
        SELECT id, name, active
        FROM crews
        ORDER BY name, id
        """
    )
    memberships = db.query_all(
        """
        SELECT cm.id, cm.crew_id, cm.employee_id, e.name AS employee_name,
               e.active AS employee_active, cm.effective_from, cm.effective_to,
               cm.created_by
        FROM crew_memberships cm
        JOIN employees e ON e.id = cm.employee_id
        WHERE cm.effective_from <= %s
          AND (cm.effective_to IS NULL OR cm.effective_to > %s)
        ORDER BY cm.crew_id, e.name, e.id
        """,
        (on_date, on_date),
    )
    by_crew: dict[int, list[dict[str, Any]]] = {}
    for membership in memberships:
        by_crew.setdefault(int(membership["crew_id"]), []).append(membership)
    for crew in crews:
        crew["members"] = by_crew.get(int(crew["id"]), [])
    return crews


def replace_crew_memberships(
    *,
    crew_id: int,
    employee_ids: Iterable[int],
    actor_id: int,
    actor_name: str,
    effective_from: date | None = None,
) -> dict[str, Any]:
    """Set today's effective members while retaining the prior rows."""
    desired_ids = sorted(set(int(employee_id) for employee_id in employee_ids))
    if not desired_ids:
        raise CalendarStoreError("A crew must contain at least one active employee")
    effective_from = effective_from or date.today()
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, name FROM crews WHERE id = %s AND active = true FOR UPDATE",
                (crew_id,),
            )
            crew = cur.fetchone()
            if not crew:
                raise CalendarStoreError("Crew was not found")
            cur.execute(
                """
                SELECT id, name FROM employees
                WHERE id = ANY(%s) AND active = true
                ORDER BY id
                """,
                (desired_ids,),
            )
            employees = [dict(row) for row in cur.fetchall()]
            if [int(row["id"]) for row in employees] != desired_ids:
                raise CalendarStoreError("Every crew member must be an active employee")
            cur.execute(
                """
                SELECT cm.id, cm.employee_id, e.name AS employee_name,
                       cm.effective_from, cm.effective_to, cm.created_by
                FROM crew_memberships cm
                JOIN employees e ON e.id = cm.employee_id
                WHERE cm.crew_id = %s
                  AND cm.effective_from <= %s
                  AND (cm.effective_to IS NULL OR cm.effective_to > %s)
                ORDER BY cm.employee_id
                FOR UPDATE OF cm
                """,
                (crew_id, effective_from, effective_from),
            )
            before = [dict(row) for row in cur.fetchall()]
            current_ids = {int(row["employee_id"]) for row in before}
            if current_ids == set(desired_ids) and all(
                row["created_by"] is not None for row in before
            ):
                return {"crew": dict(crew), "members": employees, "changed": False}

            cur.execute(
                """
                UPDATE crew_memberships
                SET effective_to = %s
                WHERE crew_id = %s
                  AND effective_from <= %s
                  AND (effective_to IS NULL OR effective_to > %s)
                """,
                (effective_from, crew_id, effective_from, effective_from),
            )
            for employee_id in desired_ids:
                cur.execute(
                    """
                    INSERT INTO crew_memberships (
                        crew_id, employee_id, effective_from, created_by
                    ) VALUES (%s, %s, %s, %s)
                    ON CONFLICT (crew_id, employee_id, effective_from)
                    DO UPDATE SET effective_to = NULL, created_by = EXCLUDED.created_by
                    """,
                    (crew_id, employee_id, effective_from, actor_id),
                )
            cur.execute(
                "UPDATE crews SET updated_at = NOW() WHERE id = %s",
                (crew_id,),
            )
            after = [
                {"employee_id": row["id"], "employee_name": row["name"]}
                for row in employees
            ]
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_employee_id, actor_name,
                    before_state, after_state
                ) VALUES ('crew_membership_changed', %s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    actor_id,
                    actor_name,
                    json.dumps(before, default=str),
                    json.dumps(after),
                ),
            )
    return {"crew": dict(crew), "members": employees, "changed": True}


def read_event_mappings(*, calendar_id: str) -> dict[str, dict[str, Any]]:
    rows = db.query_all(
        """
        SELECT id, source_key, location_id
        FROM google_calendar_event_mappings
        WHERE calendar_id = %s
        ORDER BY source_key
        """,
        (calendar_id,),
    )
    return {str(row["source_key"]): row for row in rows}


def read_existing_visits(
    *,
    connection_id: int,
    calendar_id: str,
    range_start: datetime,
    range_end: datetime,
    source_keys: Iterable[str],
) -> list[dict[str, Any]]:
    keys = sorted(set(source_keys))
    rows = db.query_all(
        """
        SELECT id, source_key, source_fingerprint, location_id, status,
               source_calendar_id, source_event_id, source_series_id,
               source_occurrence_id, approximate_start, approximate_end,
               title, description, source_location_text, all_day,
               source_timezone, source_updated_at, source_etag
        FROM planned_service_visits
        WHERE source_calendar_id = %s
          AND (
              (approximate_end > %s AND approximate_start < %s)
              OR source_key = ANY(%s)
          )
        ORDER BY source_key, id
        """,
        (calendar_id, range_start, range_end, keys),
    )
    if not rows:
        return []
    visit_ids = [int(row["id"]) for row in rows]
    assignments = db.query_all(
        """
        SELECT planned_visit_id, crew_id, employee_id
        FROM planned_visit_assignments
        WHERE planned_visit_id = ANY(%s) AND active = true
        ORDER BY planned_visit_id, crew_id NULLS LAST, employee_id NULLS LAST
        """,
        (visit_ids,),
    )
    by_visit: dict[int, dict[str, list[int]]] = {}
    for assignment in assignments:
        bucket = by_visit.setdefault(
            int(assignment["planned_visit_id"]),
            {"crew_ids": [], "employee_ids": []},
        )
        if assignment["crew_id"] is not None:
            bucket["crew_ids"].append(int(assignment["crew_id"]))
        if assignment["employee_id"] is not None:
            bucket["employee_ids"].append(int(assignment["employee_id"]))
    for row in rows:
        bucket = by_visit.get(int(row["id"]), {"crew_ids": [], "employee_ids": []})
        row.update(bucket)
    return rows


def read_planned_source_identities(
    *, calendar_id: str, range_start: datetime
) -> list[dict[str, Any]]:
    """Return planned identities at or after the preview's local-day floor."""

    return db.query_all(
        """
        SELECT source_key, source_event_id, source_series_id,
               source_occurrence_id, title, description,
               source_location_text, approximate_start, approximate_end,
               all_day, source_timezone, source_updated_at
        FROM planned_service_visits
        WHERE source_calendar_id = %s
          AND status = 'planned'
          AND approximate_end > %s
        ORDER BY source_key
        """,
        (calendar_id, range_start),
    )


def read_source_contexts(
    *, calendar_id: str, source_keys: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Return last-reviewed display context for exact imported identities."""

    keys = sorted(set(source_keys))
    if not keys:
        return {}
    rows = db.query_all(
        """
        SELECT source_key, title, description, source_location_text,
               approximate_start, approximate_end, all_day,
               source_timezone, source_updated_at
        FROM planned_service_visits
        WHERE source_calendar_id = %s
          AND source_key = ANY(%s)
        ORDER BY source_key
        """,
        (calendar_id, keys),
    )
    return {str(row["source_key"]): row for row in rows}


def create_preview(
    *,
    connection_id: int,
    calendar_id: str,
    calendar_timezone: str,
    range_start: datetime,
    range_end: datetime,
    source_fingerprint: str,
    preview_fingerprint: str,
    payload: dict[str, Any],
    admin_id: int,
    ttl_minutes: int = 30,
) -> dict[str, Any]:
    preview_id = secrets.token_urlsafe(24)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                SELECT selected_calendar_id, selected_calendar_timezone
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if (
                not connection
                or str(connection.get("selected_calendar_id") or "") != calendar_id
                or str(connection.get("selected_calendar_timezone") or "")
                != calendar_timezone
            ):
                raise CalendarStoreError(
                    "Google Calendar connection changed before preview"
                )
            cur.execute(
                """
                INSERT INTO calendar_import_previews (
                    id, connection_id, calendar_id, range_start, range_end,
                    source_fingerprint, preview_fingerprint, payload,
                    created_by, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                RETURNING id, connection_id, calendar_id, range_start, range_end,
                          source_fingerprint, preview_fingerprint, payload, status,
                          created_by, created_at, expires_at, applied_at, result
                """,
                (
                    preview_id,
                    connection_id,
                    calendar_id,
                    range_start,
                    range_end,
                    source_fingerprint,
                    preview_fingerprint,
                    json.dumps(payload),
                    admin_id,
                    expires_at,
                ),
            )
            result = cur.fetchone()
            row = dict(result) if result else None
    if not row:  # pragma: no cover - PostgreSQL RETURNING invariant
        raise CalendarStoreError("Calendar preview could not be saved")
    return row


def read_preview(preview_id: str) -> dict[str, Any] | None:
    return db.query_one(
        """
        SELECT id, connection_id, calendar_id, range_start, range_end,
               source_fingerprint, preview_fingerprint, payload, status,
               created_by, created_at, expires_at, applied_at, result
        FROM calendar_import_previews
        WHERE id = %s
        """,
        (preview_id,),
    )


def mark_preview_stale(preview_id: str) -> None:
    db.execute(
        """
        UPDATE calendar_import_previews
        SET status = 'stale'
        WHERE id = %s AND status = 'open'
        """,
        (preview_id,),
    )


def _json_state(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True)


def _audit(
    cur: Any,
    *,
    action: str,
    actor_id: int,
    actor_name: str,
    preview_id: str,
    source_key: str | None = None,
    visit_id: int | None = None,
    before: Any = None,
    after: Any = None,
) -> None:
    cur.execute(
        """
        INSERT INTO planned_visit_audit_events (
            planned_visit_id, preview_id, action, source_key,
            actor_employee_id, actor_name, before_state, after_state
        ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
        """,
        (
            visit_id,
            preview_id,
            action,
            source_key,
            actor_id,
            actor_name,
            _json_state(before) if before is not None else None,
            _json_state(after) if after is not None else None,
        ),
    )


def _upsert_mapping(
    cur: Any,
    *,
    connection_id: int,
    calendar_id: str,
    source_key: str,
    location_id: int,
    actor_id: int,
    actor_name: str,
    preview_id: str,
) -> int:
    cur.execute(
        """
        SELECT id, connection_id, location_id
        FROM google_calendar_event_mappings
        WHERE source_key = %s
        FOR UPDATE
        """,
        (source_key,),
    )
    before = cur.fetchone()
    if before:
        mapping_id = int(before["id"])
        if (
            int(before["connection_id"]) != connection_id
            or int(before["location_id"]) != location_id
        ):
            cur.execute(
                """
                UPDATE google_calendar_event_mappings
                SET connection_id = %s, calendar_id = %s,
                    location_id = %s, updated_by = %s, updated_at = NOW()
                WHERE id = %s
                """,
                (
                    connection_id,
                    calendar_id,
                    location_id,
                    actor_id,
                    mapping_id,
                ),
            )
            _audit(
                cur,
                action="event_mapping_changed",
                actor_id=actor_id,
                actor_name=actor_name,
                preview_id=preview_id,
                source_key=source_key,
                before=dict(before),
                after={
                    "id": mapping_id,
                    "connection_id": connection_id,
                    "calendar_id": calendar_id,
                    "source_key": source_key,
                    "location_id": location_id,
                },
            )
        return mapping_id
    cur.execute(
        """
        INSERT INTO google_calendar_event_mappings (
            connection_id, calendar_id, source_key,
            location_id, created_by, updated_by
        ) VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            connection_id,
            calendar_id,
            source_key,
            location_id,
            actor_id,
            actor_id,
        ),
    )
    mapping_id = int(cur.fetchone()["id"])
    _audit(
        cur,
        action="event_mapping_created",
        actor_id=actor_id,
        actor_name=actor_name,
        preview_id=preview_id,
        source_key=source_key,
        after={
            "id": mapping_id,
            "connection_id": connection_id,
            "calendar_id": calendar_id,
            "source_key": source_key,
            "location_id": location_id,
        },
    )
    return mapping_id


def _validate_assignments(
    cur: Any,
    *,
    crew_id: int | None,
    employee_ids: tuple[int, ...],
    service_date: date,
    expected_crew_member_ids: tuple[int, ...] = (),
) -> None:
    if crew_id is None and not employee_ids:
        raise CalendarStoreError(
            "Every planned visit needs a crew or employee assignment"
        )
    if crew_id is not None:
        cur.execute(
            """
            SELECT id FROM crews
            WHERE id = %s AND active = true
            FOR SHARE
            """,
            (crew_id,),
        )
        if not cur.fetchone():
            raise CalendarStoreError("Assigned crew is no longer active")
        cur.execute(
            """
            SELECT cm.employee_id
            FROM crew_memberships cm
            JOIN employees e ON e.id = cm.employee_id
            WHERE cm.crew_id = %s
              AND e.active = true
              AND cm.effective_from <= %s
              AND (cm.effective_to IS NULL OR cm.effective_to > %s)
            ORDER BY cm.employee_id
            FOR SHARE OF cm, e
            """,
            (crew_id, service_date, service_date),
        )
        actual_member_ids = tuple(int(row["employee_id"]) for row in cur.fetchall())
        if not actual_member_ids:
            raise CalendarStoreError(
                "Assigned crew has no active members for this visit"
            )
        if expected_crew_member_ids and actual_member_ids != expected_crew_member_ids:
            raise CalendarStoreError("Crew membership changed after preview")
    if employee_ids:
        cur.execute(
            """
            SELECT id FROM employees
            WHERE id = ANY(%s) AND active = true
            ORDER BY id
            FOR SHARE
            """,
            (list(employee_ids),),
        )
        found = tuple(int(row["id"]) for row in cur.fetchall())
        if found != employee_ids:
            raise CalendarStoreError("Every assigned employee must still be active")


def _lock_and_validate_reviewed_snapshot(cur: Any, preview: Any) -> None:
    """Serialize overlapping approvals and prove their DB snapshot is current."""
    lock_names = {f"planned-visit:{item.source_key}" for item in preview.items}
    for item in preview.items:
        occurrence = item.occurrence
        if occurrence is not None and not occurrence.cancelled:
            lock_names.add(
                "calendar-mapping:"
                f"{occurrence.calendar_id}:{occurrence.series_id or occurrence.event_id}"
            )
    for lock_name in sorted(lock_names):
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (lock_name,))

    for item in preview.items:
        cur.execute(
            """
            SELECT id, source_fingerprint, location_id, status
            FROM planned_service_visits
            WHERE source_key = %s
            FOR UPDATE
            """,
            (item.source_key,),
        )
        current = cur.fetchone()
        expected = item.existing
        if expected is None:
            if current is not None:
                raise CalendarStoreError("Planned visits changed after preview")
            continue
        expected_status = (
            "completed"
            if expected.completed
            else "cancelled"
            if expected.cancelled
            else "planned"
        )
        if (
            current is None
            or int(current["id"]) != expected.planned_visit_id
            or str(current["source_fingerprint"]) != expected.source_fingerprint
            or int(current["location_id"]) != expected.location_id
            or str(current["status"]) != expected_status
        ):
            raise CalendarStoreError("Planned visits changed after preview")
        cur.execute(
            """
            SELECT crew_id, employee_id
            FROM planned_visit_assignments
            WHERE planned_visit_id = %s AND active = true
            ORDER BY crew_id NULLS LAST, employee_id NULLS LAST
            FOR UPDATE
            """,
            (expected.planned_visit_id,),
        )
        assignment_rows = cur.fetchall()
        crew_ids = tuple(
            int(row["crew_id"]) for row in assignment_rows if row["crew_id"] is not None
        )
        employee_ids = tuple(
            int(row["employee_id"])
            for row in assignment_rows
            if row["employee_id"] is not None
        )
        expected_crews = (
            (expected.assigned_crew_id,)
            if expected.assigned_crew_id is not None
            else ()
        )
        if crew_ids != expected_crews or employee_ids != expected.assigned_employee_ids:
            raise CalendarStoreError("Planned visit assignments changed after preview")


def _replace_assignments(
    cur: Any,
    *,
    visit_id: int,
    crew_id: int | None,
    employee_ids: tuple[int, ...],
    actor_id: int,
    actor_name: str,
    preview_id: str,
    source_key: str,
) -> bool:
    cur.execute(
        """
        SELECT id, crew_id, employee_id
        FROM planned_visit_assignments
        WHERE planned_visit_id = %s AND active = true
        ORDER BY crew_id NULLS LAST, employee_id NULLS LAST
        FOR UPDATE
        """,
        (visit_id,),
    )
    before = [dict(row) for row in cur.fetchall()]
    existing = {
        ("crew", int(row["crew_id"]))
        if row["crew_id"] is not None
        else ("employee", int(row["employee_id"]))
        for row in before
    }
    desired = {("employee", employee_id) for employee_id in employee_ids}
    if crew_id is not None:
        desired.add(("crew", crew_id))
    if existing == desired:
        return False
    cur.execute(
        """
        UPDATE planned_visit_assignments
        SET active = false, retired_by = %s, retired_at = NOW()
        WHERE planned_visit_id = %s AND active = true
        """,
        (actor_id, visit_id),
    )
    for assignment_type, assignment_id in sorted(desired):
        cur.execute(
            """
            INSERT INTO planned_visit_assignments (
                planned_visit_id, crew_id, employee_id, assigned_by
            ) VALUES (%s, %s, %s, %s)
            """,
            (
                visit_id,
                assignment_id if assignment_type == "crew" else None,
                assignment_id if assignment_type == "employee" else None,
                actor_id,
            ),
        )
    _audit(
        cur,
        action="visit_assignment_changed",
        actor_id=actor_id,
        actor_name=actor_name,
        preview_id=preview_id,
        source_key=source_key,
        visit_id=visit_id,
        before=before,
        after={"crewId": crew_id, "employeeIds": list(employee_ids)},
    )
    return True


def apply_reviewed_preview(
    *,
    preview_id: str,
    expected_preview_fingerprint: str,
    expected_calendar_timezone: str,
    preview: Any,
    actions: Iterable[Any],
    actor_id: int,
    actor_name: str,
) -> dict[str, Any]:
    """Apply an exact rebuilt preview transactionally and idempotently."""
    action_list = list(actions)
    items_by_key = {item.source_key: item for item in preview.items}
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, connection_id, calendar_id, preview_fingerprint,
                       status, expires_at, result
                FROM calendar_import_previews
                WHERE id = %s
                FOR UPDATE
                """,
                (preview_id,),
            )
            preview_row = cur.fetchone()
            if not preview_row:
                raise CalendarStoreError("Calendar preview was not found")
            if preview_row["preview_fingerprint"] != expected_preview_fingerprint:
                raise CalendarStoreError("Calendar preview fingerprint does not match")
            if preview_row["status"] == "applied":
                return dict(preview_row["result"] or {})
            if preview_row["status"] != "open" or preview_row[
                "expires_at"
            ] <= datetime.now(timezone.utc):
                raise CalendarStoreError(
                    "Calendar preview is stale; create a new preview"
                )

            cur.execute(
                """
                SELECT id, selected_calendar_id, selected_calendar_timezone
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR SHARE
                """,
                (int(preview_row["connection_id"]),),
            )
            current_connection = cur.fetchone()
            if (
                current_connection is None
                or str(current_connection["selected_calendar_id"] or "")
                != str(preview_row["calendar_id"])
                or str(current_connection["selected_calendar_timezone"] or "")
                != expected_calendar_timezone
            ):
                raise CalendarStoreError(
                    "Google Calendar connection changed after preview"
                )

            _lock_and_validate_reviewed_snapshot(cur, preview)

            counts = {"create": 0, "update": 0, "cancel": 0, "unchanged": 0}
            for item in preview.items:
                if item.classification in counts:
                    counts[item.classification] += 1

            mapping_ids: dict[str, int] = {}
            for item in preview.items:
                occurrence = item.occurrence
                if (
                    occurrence is None
                    or occurrence.cancelled
                    or (item.existing is not None and item.existing.completed)
                    or not item.location_resolution.resolved
                    or occurrence.starts_at is None
                ):
                    continue
                cur.execute(
                    """
                    SELECT id FROM locations
                    WHERE id = %s AND active = true
                    FOR SHARE
                    """,
                    (item.location_resolution.location_id,),
                )
                if not cur.fetchone():
                    raise CalendarStoreError("Selected location changed after preview")
                _validate_assignments(
                    cur,
                    crew_id=item.assigned_crew_id,
                    employee_ids=item.assigned_employee_ids,
                    service_date=occurrence.service_date,
                    expected_crew_member_ids=item.assigned_crew_member_ids,
                )
                mapping_ids[item.source_key] = _upsert_mapping(
                    cur,
                    connection_id=int(preview_row["connection_id"]),
                    calendar_id=str(preview_row["calendar_id"]),
                    source_key=item.source_key,
                    location_id=int(item.location_resolution.location_id),
                    actor_id=actor_id,
                    actor_name=actor_name,
                    preview_id=preview_id,
                )

            for action in action_list:
                item = items_by_key[action.source_key]
                occurrence = item.occurrence
                if action.action == "cancel":
                    cur.execute(
                        """
                        SELECT * FROM planned_service_visits
                        WHERE id = %s AND source_key = %s
                        FOR UPDATE
                        """,
                        (action.planned_visit_id, action.source_key),
                    )
                    before = cur.fetchone()
                    if not before:
                        raise CalendarStoreError("Planned visit changed after preview")
                    if before["status"] == "completed":
                        raise CalendarStoreError(
                            "Completed planned visit changed after preview"
                        )
                    cur.execute(
                        """
                        UPDATE planned_service_visits
                        SET connection_id = %s,
                            source_calendar_id = COALESCE(%s, source_calendar_id),
                            source_event_id = COALESCE(%s, source_event_id),
                            source_series_id = COALESCE(%s, source_series_id),
                            source_occurrence_id = COALESCE(%s, source_occurrence_id),
                            status = 'cancelled', cancelled_at = NOW(),
                            source_fingerprint = COALESCE(%s, source_fingerprint),
                            source_etag = COALESCE(%s, source_etag),
                            source_updated_at = COALESCE(%s, source_updated_at),
                            last_preview_id = %s, last_imported_by = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (
                            int(preview_row["connection_id"]),
                            action.calendar_id,
                            action.event_id,
                            action.series_id,
                            action.occurrence_id,
                            action.source_fingerprint,
                            action.revision,
                            action.updated_at,
                            preview_id,
                            actor_id,
                            action.planned_visit_id,
                        ),
                    )
                    after = cur.fetchone()
                    _replace_assignments(
                        cur,
                        visit_id=int(after["id"]),
                        crew_id=None,
                        employee_ids=(),
                        actor_id=actor_id,
                        actor_name=actor_name,
                        preview_id=preview_id,
                        source_key=action.source_key,
                    )
                    _audit(
                        cur,
                        action="planned_visit_cancelled",
                        actor_id=actor_id,
                        actor_name=actor_name,
                        preview_id=preview_id,
                        source_key=action.source_key,
                        visit_id=int(after["id"]),
                        before=dict(before),
                        after=dict(after),
                    )
                    continue

                if (
                    occurrence is None
                    or action.starts_at is None
                    or action.ends_at is None
                ):
                    raise CalendarStoreError("Reviewed visit is missing source timing")
                service_date = action.service_date
                if service_date is None:
                    raise CalendarStoreError(
                        "Reviewed visit is missing its local service date"
                    )
                _validate_assignments(
                    cur,
                    crew_id=action.assigned_crew_id,
                    employee_ids=action.assigned_employee_ids,
                    service_date=service_date,
                    expected_crew_member_ids=item.assigned_crew_member_ids,
                )
                mapping_id = mapping_ids[action.source_key]
                values = (
                    mapping_id,
                    action.source_fingerprint,
                    action.revision,
                    action.updated_at,
                    action.title or "",
                    action.description or "",
                    action.location_text or "",
                    action.location_id,
                    action.starts_at,
                    action.ends_at,
                    bool(action.all_day),
                    action.time_zone or None,
                    preview_id,
                    actor_id,
                )
                if action.action == "create":
                    cur.execute(
                        """
                        INSERT INTO planned_service_visits (
                            connection_id, mapping_id, source_calendar_id,
                            source_event_id, source_series_id, source_occurrence_id,
                            source_key, source_fingerprint, source_etag,
                            source_updated_at, title, description,
                            source_location_text, location_id,
                            approximate_start, approximate_end, all_day,
                            source_timezone, last_preview_id, last_imported_by
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        RETURNING *
                        """,
                        (
                            int(preview_row["connection_id"]),
                            mapping_id,
                            action.calendar_id,
                            action.event_id,
                            action.series_id or action.event_id,
                            action.occurrence_id or action.event_id,
                            action.source_key,
                            action.source_fingerprint,
                            action.revision,
                            action.updated_at,
                            action.title or "",
                            action.description or "",
                            action.location_text or "",
                            action.location_id,
                            action.starts_at,
                            action.ends_at,
                            bool(action.all_day),
                            action.time_zone or None,
                            preview_id,
                            actor_id,
                        ),
                    )
                    after = cur.fetchone()
                    before = None
                    audit_action = "planned_visit_created"
                else:
                    cur.execute(
                        """
                        SELECT * FROM planned_service_visits
                        WHERE id = %s AND source_key = %s
                        FOR UPDATE
                        """,
                        (action.planned_visit_id, action.source_key),
                    )
                    before = cur.fetchone()
                    if not before or before["status"] == "completed":
                        raise CalendarStoreError("Planned visit changed after preview")
                    cur.execute(
                        """
                        UPDATE planned_service_visits
                        SET connection_id = %s, source_calendar_id = %s,
                            source_event_id = %s, source_series_id = %s,
                            source_occurrence_id = %s,
                            mapping_id = %s, source_fingerprint = %s,
                            source_etag = %s, source_updated_at = %s,
                            title = %s, description = %s,
                            source_location_text = %s, location_id = %s,
                            approximate_start = %s, approximate_end = %s,
                            all_day = %s, source_timezone = %s,
                            status = 'planned', cancelled_at = NULL,
                            last_preview_id = %s, last_imported_by = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (
                            int(preview_row["connection_id"]),
                            action.calendar_id,
                            action.event_id,
                            action.series_id or action.event_id,
                            action.occurrence_id or action.event_id,
                            *values,
                            action.planned_visit_id,
                        ),
                    )
                    after = cur.fetchone()
                    audit_action = "planned_visit_updated"
                visit_id = int(after["id"])
                _replace_assignments(
                    cur,
                    visit_id=visit_id,
                    crew_id=action.assigned_crew_id,
                    employee_ids=action.assigned_employee_ids,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    preview_id=preview_id,
                    source_key=action.source_key,
                )
                _audit(
                    cur,
                    action=audit_action,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    preview_id=preview_id,
                    source_key=action.source_key,
                    visit_id=visit_id,
                    before=dict(before) if before else None,
                    after=dict(after),
                )

            result = {
                "success": True,
                "previewId": preview_id,
                "counts": counts,
                "appliedActions": len(action_list),
            }
            cur.execute(
                """
                UPDATE calendar_import_previews
                SET status = 'applied', applied_at = NOW(), result = %s::jsonb
                WHERE id = %s
                """,
                (json.dumps(result), preview_id),
            )
            return result


def list_calendar_sources(*, connection_id: int | None = None) -> list[dict[str, Any]]:
    """Return the two canonical Calendar bindings without exposing credentials."""

    if connection_id is None:
        connection = active_connection()
        if not connection:
            return []
        connection_id = int(connection["id"])
    return db.query_all(
        """
        SELECT id, connection_id, role, calendar_id, calendar_name,
               calendar_timezone, last_synced_at, last_sync_status,
               last_sync_error, last_sync_counts, last_sync_window_start,
               last_sync_window_end, created_at, updated_at
        FROM google_calendar_sources
        WHERE connection_id = %s
        ORDER BY role
        """,
        (connection_id,),
    )


def replace_calendar_sources(
    *,
    connection_id: int,
    expected_credential_version: int,
    bindings: Iterable[dict[str, str]],
    actor_id: int,
    actor_name: str,
) -> list[dict[str, Any]]:
    """Atomically install the two distinct, pre-validated readable Calendars."""

    rows = [dict(binding) for binding in bindings]
    by_role = {str(row.get("role") or ""): row for row in rows}
    if set(by_role) != set(CALENDAR_SOURCE_ROLES) or len(rows) != len(by_role):
        raise CalendarStoreError("Both Calendar source roles are required")
    calendar_ids = [
        str(by_role[role].get("calendar_id") or "").strip()
        for role in CALENDAR_SOURCE_ROLES
    ]
    if any(not calendar_id for calendar_id in calendar_ids):
        raise CalendarStoreError("Both Calendar source IDs are required")
    if len(set(calendar_ids)) != len(calendar_ids):
        raise CalendarStoreError(
            "Residential and Commercial Calendars must be different"
        )
    for role in CALENDAR_SOURCE_ROLES:
        for field in ("calendar_name", "calendar_timezone"):
            if not str(by_role[role].get(field) or "").strip():
                raise CalendarStoreError("Calendar source metadata is incomplete")

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("google-calendar-sources",),
            )
            cur.execute(
                """
                SELECT id, credential_version
                FROM google_calendar_connections
                WHERE id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if not connection:
                raise CalendarStoreError(
                    "Google Calendar connection is no longer active"
                )
            if int(connection["credential_version"]) != expected_credential_version:
                raise CalendarStoreError(
                    "Google Calendar credentials changed; reload the Calendar list"
                )
            cur.execute(
                """
                SELECT id, role, calendar_id
                FROM google_calendar_sources
                WHERE connection_id = %s
                FOR UPDATE
                """,
                (connection_id,),
            )
            existing_by_role = {str(row["role"]): row for row in cur.fetchall()}
            for role, existing in existing_by_role.items():
                replacement_id = str(by_role[role]["calendar_id"]).strip()
                if str(existing["calendar_id"]) == replacement_id:
                    continue
                cur.execute(
                    """
                    SELECT 1
                    FROM jobs
                    WHERE calendar_source_id = %s
                      AND status <> 'cancelled'
                      AND COALESCE(scheduled_end, scheduled_start) > NOW()
                    LIMIT 1
                    """,
                    (int(existing["id"]),),
                )
                if cur.fetchone():
                    raise CalendarStoreError(
                        "Resolve future scheduled work before replacing a Calendar source"
                    )
            # Move changed IDs out of the unique-key space before either role is
            # updated. This keeps a no-work role swap atomic instead of letting
            # the first upsert collide with the second role's prior Calendar.
            for role, existing in existing_by_role.items():
                replacement_id = str(by_role[role]["calendar_id"]).strip()
                if str(existing["calendar_id"]) == replacement_id:
                    continue
                cur.execute(
                    """
                    UPDATE google_calendar_sources
                    SET calendar_id = %s
                    WHERE id = %s
                    """,
                    (
                        f"pending-calendar-source-{int(existing['id'])}-"
                        f"{secrets.token_hex(8)}",
                        int(existing["id"]),
                    ),
                )

            for role in CALENDAR_SOURCE_ROLES:
                binding = by_role[role]
                cur.execute(
                    """
                    INSERT INTO google_calendar_sources (
                        connection_id, role, calendar_id, calendar_name,
                        calendar_timezone, created_by, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (connection_id, role) DO UPDATE
                    SET calendar_id = EXCLUDED.calendar_id,
                        calendar_name = EXCLUDED.calendar_name,
                        calendar_timezone = EXCLUDED.calendar_timezone,
                        last_synced_at = CASE
                            WHEN google_calendar_sources.calendar_id
                                 = EXCLUDED.calendar_id
                             AND google_calendar_sources.calendar_timezone
                                 = EXCLUDED.calendar_timezone
                            THEN google_calendar_sources.last_synced_at
                            ELSE NULL
                        END,
                        last_sync_status = CASE
                            WHEN google_calendar_sources.calendar_id
                                 = EXCLUDED.calendar_id
                             AND google_calendar_sources.calendar_timezone
                                 = EXCLUDED.calendar_timezone
                            THEN google_calendar_sources.last_sync_status
                            ELSE 'never'
                        END,
                        last_sync_error = NULL,
                        last_sync_counts = CASE
                            WHEN google_calendar_sources.calendar_id
                                 = EXCLUDED.calendar_id
                             AND google_calendar_sources.calendar_timezone
                                 = EXCLUDED.calendar_timezone
                            THEN google_calendar_sources.last_sync_counts
                            ELSE NULL
                        END,
                        last_sync_window_start = CASE
                            WHEN google_calendar_sources.calendar_id
                                 = EXCLUDED.calendar_id
                             AND google_calendar_sources.calendar_timezone
                                 = EXCLUDED.calendar_timezone
                            THEN google_calendar_sources.last_sync_window_start
                            ELSE NULL
                        END,
                        last_sync_window_end = CASE
                            WHEN google_calendar_sources.calendar_id
                                 = EXCLUDED.calendar_id
                             AND google_calendar_sources.calendar_timezone
                                 = EXCLUDED.calendar_timezone
                            THEN google_calendar_sources.last_sync_window_end
                            ELSE NULL
                        END,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = NOW()
                    """,
                    (
                        connection_id,
                        role,
                        str(binding["calendar_id"]).strip(),
                        str(binding["calendar_name"]).strip(),
                        str(binding["calendar_timezone"]).strip(),
                        actor_id,
                        actor_id,
                    ),
                )

            residential = by_role[RESIDENTIAL_MORNING_ROLE]
            cur.execute(
                """
                UPDATE google_calendar_connections
                SET selected_calendar_id = %s,
                    selected_calendar_name = %s,
                    selected_calendar_timezone = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (
                    str(residential["calendar_id"]).strip(),
                    str(residential["calendar_name"]).strip(),
                    str(residential["calendar_timezone"]).strip(),
                    connection_id,
                ),
            )
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, actor_employee_id, actor_name, after_state
                ) VALUES ('calendar_sources_configured', %s, %s, %s::jsonb)
                """,
                (
                    actor_id,
                    actor_name,
                    json.dumps(
                        {
                            "connectionId": connection_id,
                            "sources": [
                                {
                                    "role": role,
                                    "calendarId": str(by_role[role]["calendar_id"]),
                                }
                                for role in CALENDAR_SOURCE_ROLES
                            ],
                        }
                    ),
                ),
            )
    return list_calendar_sources(connection_id=connection_id)


def mark_calendar_source_sync_failed(
    *,
    source_id: int,
    expected_credential_version: int,
    expected_calendar_id: str,
    expected_calendar_timezone: str,
    window_start: datetime,
    window_end: datetime,
    message: str,
) -> bool:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT connection_id FROM google_calendar_sources WHERE id = %s",
                (source_id,),
            )
            source_reference = cur.fetchone()
            if not source_reference:
                return False
            connection_id = int(source_reference["connection_id"])
            cur.execute(
                """
                SELECT revoked_at, credential_version
                FROM google_calendar_connections
                WHERE id = %s
                FOR SHARE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if not connection or connection["revoked_at"] is not None:
                return False
            if int(connection["credential_version"]) != expected_credential_version:
                return False
            cur.execute(
                """
                UPDATE google_calendar_sources
                SET last_synced_at = NOW(), last_sync_status = 'failed',
                    last_sync_error = %s, last_sync_counts = NULL,
                    last_sync_window_start = %s, last_sync_window_end = %s,
                    updated_at = NOW()
                WHERE id = %s AND connection_id = %s
                  AND calendar_id = %s AND calendar_timezone = %s
                RETURNING id
                """,
                (
                    message[:500],
                    window_start,
                    window_end,
                    source_id,
                    connection_id,
                    expected_calendar_id,
                    expected_calendar_timezone,
                ),
            )
            return cur.fetchone() is not None


def read_canonical_source_identities(
    *, source_id: int, range_start: datetime
) -> list[dict[str, Any]]:
    """Return source jobs that require targeted provider reconciliation."""

    return db.query_all(
        """
        SELECT id, source_key, source_event_id, source_series_id,
               source_occurrence_id, source_title AS title,
               source_location_text, scheduled_start AS approximate_start,
               scheduled_end AS approximate_end, source_all_day AS all_day,
               source_timezone, source_updated_at, source_etag,
               source_fingerprint, location_id, status
        FROM jobs
        WHERE calendar_source_id = %s
          AND source_key IS NOT NULL
          AND status = 'scheduled'
          AND COALESCE(scheduled_end, scheduled_start) > %s
        ORDER BY source_key
        """,
        (source_id, range_start),
    )


def _canonical_exception(
    *,
    source: dict[str, Any],
    occurrence: Any,
    fingerprint: str,
    code: str,
    candidate_sites: Iterable[dict[str, Any]] = (),
    conflicting_job_ids: Iterable[int] = (),
) -> dict[str, Any]:
    return {
        "code": code,
        "sourceId": int(source["id"]),
        "sourceRole": str(source["role"]),
        "sourceKey": occurrence.source_key,
        "sourceFingerprint": fingerprint,
        "eventId": occurrence.event_id,
        "seriesId": occurrence.series_id,
        "occurrenceId": occurrence.occurrence_id,
        "title": occurrence.title,
        "calendarLocation": occurrence.location_text,
        "start": occurrence.starts_at.isoformat() if occurrence.starts_at else None,
        "end": occurrence.ends_at.isoformat() if occurrence.ends_at else None,
        "candidateSites": list(candidate_sites),
        "conflictingJobIds": sorted(set(int(value) for value in conflicting_job_ids)),
    }


def _calendar_site_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "customerName": row.get("customer_name"),
        "address": str(row["address"]),
        "locationType": row.get("location_type"),
        "active": bool(row["active"]),
    }


def _calendar_sites_by_id(
    cur: Any, location_ids: Iterable[int]
) -> list[dict[str, Any]]:
    ids = sorted(set(int(value) for value in location_ids))
    if not ids:
        return []
    cur.execute(
        """
        SELECT id, customer_name, address, location_type, active
        FROM locations
        WHERE id = ANY(%s)
        ORDER BY customer_name NULLS LAST, address, id
        """,
        (ids,),
    )
    return [_calendar_site_payload(dict(row)) for row in cur.fetchall()]


def _canonical_job_service_dates(existing_job: dict[str, Any]) -> list[date]:
    """Return every local service date touched by the stored job window."""

    service_dates = {existing_job["scheduled_date"]}
    scheduled_start = existing_job.get("scheduled_start")
    scheduled_end = existing_job.get("scheduled_end")
    if (
        scheduled_start is None
        or scheduled_end is None
        or scheduled_end <= scheduled_start
    ):
        return sorted(service_dates)

    cursor = scheduled_start.astimezone(PRODUCT_TIMEZONE).date()
    final_date = (
        (scheduled_end - timedelta(microseconds=1)).astimezone(PRODUCT_TIMEZONE).date()
    )
    while cursor <= final_date:
        service_dates.add(cursor)
        cursor += timedelta(days=1)
    return sorted(service_dates)


def _canonical_job_has_work_evidence(cur: Any, existing_job: dict[str, Any]) -> bool:
    """Conservatively protect every local service date touched by a job."""

    job_id = int(existing_job["id"])
    location_id = int(existing_job["location_id"])
    service_dates = _canonical_job_service_dates(existing_job)
    cur.execute(
        """
        SELECT (
            EXISTS (
                SELECT 1 FROM shifts
                WHERE job_id = %s
            )
            OR EXISTS (
                SELECT 1 FROM shifts
                WHERE location_id = %s
                  AND time_category = 'productive'
                  AND COALESCE(
                      local_date,
                      (clock_in AT TIME ZONE 'America/Chicago')::date
                  ) = ANY(%s)
            )
            OR EXISTS (
                SELECT 1 FROM visits
                WHERE location_id = %s
                  AND (
                      arrival_time AT TIME ZONE 'America/Chicago'
                  )::date = ANY(%s)
            )
            OR EXISTS (
                SELECT 1 FROM departures
                WHERE location_id = %s
                  AND (
                      departure_time AT TIME ZONE 'America/Chicago'
                  )::date = ANY(%s)
            )
            OR EXISTS (
                SELECT 1 FROM site_check_ins
                WHERE location_id = %s
                  AND (
                      server_checked_in_at AT TIME ZONE 'America/Chicago'
                  )::date = ANY(%s)
            )
        ) AS has_work
        """,
        (
            job_id,
            location_id,
            service_dates,
            location_id,
            service_dates,
            location_id,
            service_dates,
            location_id,
            service_dates,
        ),
    )
    row = cur.fetchone()
    return bool(row and row["has_work"])


def _canonical_snapshot_is_stale(
    *,
    existing_job: dict[str, Any],
    occurrence: Any,
    fingerprint: str,
) -> bool:
    """Reject a provider snapshot that cannot be newer than stored source state."""

    stored_fingerprint = str(existing_job.get("source_fingerprint") or "")
    if stored_fingerprint == fingerprint:
        return False
    stored_updated = existing_job.get("source_updated_at")
    incoming_updated = occurrence.updated_at
    if stored_updated is None:
        return False
    if incoming_updated is None:
        return True
    if incoming_updated < stored_updated:
        return True
    if incoming_updated > stored_updated:
        return False
    incoming_is_confirmed_deletion = (
        occurrence.cancelled and occurrence.revision == "provider-deleted"
    )
    stored_is_confirmed_deletion = existing_job.get("source_etag") == "provider-deleted"
    return not incoming_is_confirmed_deletion or stored_is_confirmed_deletion


def _resolve_canonical_location(
    cur: Any,
    *,
    source: dict[str, Any],
    occurrence: Any,
    existing_job: dict[str, Any] | None,
    location_snapshot: _CanonicalLocationSnapshot,
) -> tuple[int | None, str | None, tuple[int, ...]]:
    """Resolve a Site by operator mapping or exact normalized title/address."""

    from planned_visits import normalize_match_text

    cur.execute(
        """
        SELECT location_id
        FROM google_calendar_event_mappings
        WHERE connection_id = %s AND calendar_id = %s
          AND (
              source_key = %s
              OR (
                  mapping_scope = 'series'
                  AND source_series_id = %s
              )
          )
        ORDER BY CASE WHEN source_key = %s THEN 0 ELSE 1 END, id
        LIMIT 1
        """,
        (
            int(source["connection_id"]),
            str(source["calendar_id"]),
            occurrence.source_key,
            occurrence.series_id,
            occurrence.source_key,
        ),
    )
    mapping = cur.fetchone()
    expected_type = CALENDAR_ROLE_LOCATION_TYPES[str(source["role"])]
    if mapping:
        selected = location_snapshot.by_id.get(int(mapping["location_id"]))
        if not selected or not bool(selected["active"]):
            return None, "archived_site", (int(mapping["location_id"]),)
        if str(selected.get("location_type") or "") != expected_type:
            return None, "wrong_site_type", (int(selected["id"]),)
        return int(selected["id"]), None, (int(selected["id"]),)

    hints = {
        value
        for raw in (occurrence.location_text, occurrence.title)
        if (value := normalize_match_text(raw))
    }
    matches_by_id: dict[int, dict[str, Any]] = {}
    for hint in hints:
        for row in location_snapshot.by_normalized_hint.get(hint, ()):
            matches_by_id[int(row["id"])] = row
    matches = [matches_by_id[row_id] for row_id in sorted(matches_by_id)]
    valid = [
        row
        for row in matches
        if bool(row["active"]) and str(row.get("location_type") or "") == expected_type
    ]
    if len(valid) == 1:
        resolved_id = int(valid[0]["id"])
        if existing_job and int(existing_job["location_id"]) != resolved_id:
            return (
                None,
                "site_changed",
                tuple(
                    sorted(
                        {
                            int(existing_job["location_id"]),
                            resolved_id,
                        }
                    )
                ),
            )
        return resolved_id, None, (resolved_id,)
    if len(valid) > 1:
        return None, "ambiguous_site", tuple(int(row["id"]) for row in valid)
    if matches and all(not bool(row["active"]) for row in matches):
        return None, "archived_site", tuple(int(row["id"]) for row in matches)
    wrong_type = [row for row in matches if bool(row["active"])]
    if wrong_type:
        return None, "wrong_site_type", tuple(int(row["id"]) for row in wrong_type)
    if existing_job:
        prior = location_snapshot.by_id.get(int(existing_job["location_id"]))
        if (
            prior
            and bool(prior["active"])
            and str(prior.get("location_type") or "") == expected_type
        ):
            return (
                int(existing_job["location_id"]),
                None,
                (int(existing_job["location_id"]),),
            )
    return None, "missing_site", ()


def _read_canonical_locations(cur: Any) -> _CanonicalLocationSnapshot:
    """Load the immutable Site matching snapshot once for one source sync."""

    from planned_visits import normalize_match_text

    cur.execute(
        """
        SELECT id, address, customer_name, active, location_type
        FROM locations
        ORDER BY id
        """
    )
    locations = tuple(dict(row) for row in cur.fetchall())
    by_normalized_hint: dict[str, list[dict[str, Any]]] = {}
    for row in locations:
        for raw_hint in (row.get("address"), row.get("customer_name")):
            normalized_hint = normalize_match_text(raw_hint)
            if normalized_hint:
                by_normalized_hint.setdefault(normalized_hint, []).append(row)
    return _CanonicalLocationSnapshot(
        by_id={int(row["id"]): row for row in locations},
        by_normalized_hint={
            hint: tuple(rows) for hint, rows in by_normalized_hint.items()
        },
    )


def sync_calendar_source(
    *,
    source_id: int,
    expected_credential_version: int,
    occurrences: Iterable[Any],
    window_start: datetime,
    window_end: datetime,
    actor_id: int,
    actor_name: str,
) -> dict[str, Any]:
    """Apply one complete source snapshot to canonical jobs, without assignments."""

    from planned_visits import occurrence_fingerprint

    occurrence_rows = sorted(list(occurrences), key=lambda row: row.source_key)
    if len({row.source_key for row in occurrence_rows}) != len(occurrence_rows):
        raise CalendarStoreError(
            "Google Calendar returned a duplicate occurrence identity"
        )
    counts = {
        "create": 0,
        "update": 0,
        "cancel": 0,
        "unchanged": 0,
        "unresolved": 0,
    }
    exceptions: list[dict[str, Any]] = []
    eligible_sites: list[dict[str, Any]] = []
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"google-calendar-source:{source_id}",),
            )
            cur.execute(
                "SELECT connection_id FROM google_calendar_sources WHERE id = %s",
                (source_id,),
            )
            source_reference = cur.fetchone()
            if not source_reference:
                raise CalendarStoreError("Google Calendar source is no longer active")
            connection_id = int(source_reference["connection_id"])
            cur.execute(
                """
                SELECT revoked_at, credential_version
                FROM google_calendar_connections
                WHERE id = %s
                FOR SHARE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if not connection or connection["revoked_at"] is not None:
                raise CalendarStoreError("Google Calendar source is no longer active")
            if int(connection["credential_version"]) != expected_credential_version:
                raise CalendarStoreError(
                    "Google Calendar credentials changed; sync again"
                )
            cur.execute(
                """
                SELECT *
                FROM google_calendar_sources
                WHERE id = %s AND connection_id = %s
                FOR UPDATE
                """,
                (source_id, connection_id),
            )
            source_row = cur.fetchone()
            if not source_row:
                raise CalendarStoreError("Google Calendar source is no longer active")
            source = dict(source_row)
            location_snapshot = _read_canonical_locations(cur)
            for occurrence in occurrence_rows:
                if occurrence.calendar_id != str(source["calendar_id"]):
                    raise CalendarStoreError(
                        "Google Calendar returned an inconsistent source identity"
                    )
                if occurrence.time_zone != str(source["calendar_timezone"]):
                    raise CalendarStoreError(
                        "Google Calendar source timezone changed; sync again"
                    )
                fingerprint = occurrence_fingerprint(occurrence)
                cur.execute(
                    """
                    SELECT *
                    FROM jobs
                    WHERE source_key = %s
                    FOR UPDATE
                    """,
                    (occurrence.source_key,),
                )
                existing_row = cur.fetchone()
                existing = dict(existing_row) if existing_row else None
                has_work = (
                    _canonical_job_has_work_evidence(cur, existing)
                    if existing is not None
                    else False
                )
                if existing is not None and _canonical_snapshot_is_stale(
                    existing_job=existing,
                    occurrence=occurrence,
                    fingerprint=fingerprint,
                ):
                    counts["unresolved"] += 1
                    exceptions.append(
                        _canonical_exception(
                            source=source,
                            occurrence=occurrence,
                            fingerprint=fingerprint,
                            code="stale_source_snapshot",
                            candidate_sites=_calendar_sites_by_id(
                                cur, (int(existing["location_id"]),)
                            ),
                        )
                    )
                    continue

                if occurrence.cancelled:
                    if existing is None:
                        counts["unchanged"] += 1
                        continue
                    if existing["status"] in {"in_progress", "completed"} or has_work:
                        counts["unresolved"] += 1
                        exceptions.append(
                            _canonical_exception(
                                source=source,
                                occurrence=occurrence,
                                fingerprint=fingerprint,
                                code="protected_work",
                                candidate_sites=_calendar_sites_by_id(
                                    cur, (int(existing["location_id"]),)
                                ),
                            )
                        )
                        continue
                    if (
                        existing["status"] == "cancelled"
                        and existing.get("source_fingerprint") == fingerprint
                    ):
                        counts["unchanged"] += 1
                        continue
                    cur.execute(
                        """
                        UPDATE jobs
                        SET status = 'cancelled', cancelled_at = NOW(),
                            cancellation_reason = 'source_cancelled',
                            source_fingerprint = %s,
                            source_etag = %s, source_updated_at = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (
                            fingerprint,
                            occurrence.revision or None,
                            occurrence.updated_at,
                            int(existing["id"]),
                        ),
                    )
                    counts["cancel"] += 1
                    continue

                if occurrence.all_day:
                    if existing is not None and (
                        existing["status"] in {"in_progress", "completed"} or has_work
                    ):
                        counts["unresolved"] += 1
                        exceptions.append(
                            _canonical_exception(
                                source=source,
                                occurrence=occurrence,
                                fingerprint=fingerprint,
                                code="protected_work",
                                candidate_sites=_calendar_sites_by_id(
                                    cur, (int(existing["location_id"]),)
                                ),
                            )
                        )
                        continue
                    if existing is not None:
                        scheduled_date = occurrence.starts_at.astimezone(
                            PRODUCT_TIMEZONE
                        ).date()
                        already_invalid = (
                            existing.get("source_fingerprint") == fingerprint
                            and bool(existing.get("source_all_day"))
                            and existing.get("scheduled_start") == occurrence.starts_at
                            and existing.get("scheduled_end") == occurrence.ends_at
                        )
                        if not already_invalid:
                            cur.execute(
                                """
                                UPDATE jobs
                                SET scheduled_date = %s, scheduled_start = %s,
                                    scheduled_end = %s, source_fingerprint = %s,
                                    source_etag = %s, source_updated_at = %s,
                                    source_title = %s, source_location_text = %s,
                                    source_timezone = %s, source_all_day = true,
                                    expected_hours = NULL, revenue = NULL,
                                    status = 'scheduled', cancelled_at = NULL,
                                    cancellation_reason = NULL, updated_at = NOW()
                                WHERE id = %s
                                """,
                                (
                                    scheduled_date,
                                    occurrence.starts_at,
                                    occurrence.ends_at,
                                    fingerprint,
                                    occurrence.revision or None,
                                    occurrence.updated_at,
                                    occurrence.title,
                                    occurrence.location_text,
                                    occurrence.time_zone
                                    or str(source["calendar_timezone"]),
                                    int(existing["id"]),
                                ),
                            )
                            cur.execute(
                                """
                                INSERT INTO planned_visit_audit_events (
                                    action, source_key, actor_employee_id,
                                    actor_name, after_state
                                ) VALUES (%s, %s, %s, %s, %s::jsonb)
                                """,
                                (
                                    "canonical_job_invalidated_all_day",
                                    occurrence.source_key,
                                    actor_id,
                                    actor_name,
                                    json.dumps(
                                        {
                                            "jobId": int(existing["id"]),
                                            "sourceId": int(source["id"]),
                                        }
                                    ),
                                ),
                            )
                    counts["unresolved"] += 1
                    exceptions.append(
                        _canonical_exception(
                            source=source,
                            occurrence=occurrence,
                            fingerprint=fingerprint,
                            code="all_day",
                            candidate_sites=(
                                _calendar_sites_by_id(
                                    cur, (int(existing["location_id"]),)
                                )
                                if existing is not None
                                else ()
                            ),
                        )
                    )
                    continue
                if occurrence.starts_at is None or occurrence.ends_at is None:
                    counts["unresolved"] += 1
                    exceptions.append(
                        _canonical_exception(
                            source=source,
                            occurrence=occurrence,
                            fingerprint=fingerprint,
                            code="missing_time",
                        )
                    )
                    continue

                location_id, issue, candidate_ids = _resolve_canonical_location(
                    cur,
                    source=source,
                    occurrence=occurrence,
                    existing_job=existing,
                    location_snapshot=location_snapshot,
                )
                if issue or location_id is None:
                    counts["unresolved"] += 1
                    exceptions.append(
                        _canonical_exception(
                            source=source,
                            occurrence=occurrence,
                            fingerprint=fingerprint,
                            code=issue or "missing_site",
                            candidate_sites=_calendar_sites_by_id(cur, candidate_ids),
                        )
                    )
                    continue
                if existing is not None and (
                    existing["status"] in {"in_progress", "completed"} or has_work
                ):
                    unchanged_source = (
                        existing.get("source_fingerprint") == fingerprint
                        and int(existing["location_id"]) == location_id
                    )
                    if unchanged_source:
                        counts["unchanged"] += 1
                    else:
                        counts["unresolved"] += 1
                        exceptions.append(
                            _canonical_exception(
                                source=source,
                                occurrence=occurrence,
                                fingerprint=fingerprint,
                                code="protected_work",
                                candidate_sites=_calendar_sites_by_id(
                                    cur, (location_id,)
                                ),
                            )
                        )
                    continue

                cur.execute(
                    """
                    SELECT COALESCE(l.customer_name, c.name, l.address) AS customer_name
                    FROM locations l
                    LEFT JOIN customers c ON c.id = l.customer_id
                    WHERE l.id = %s
                    """,
                    (location_id,),
                )
                location = cur.fetchone()
                customer_name = str(location["customer_name"])
                scheduled_date = occurrence.starts_at.astimezone(
                    PRODUCT_TIMEZONE
                ).date()
                source_values = (
                    location_id,
                    customer_name,
                    scheduled_date,
                    occurrence.starts_at,
                    occurrence.ends_at,
                    int(source["id"]),
                    str(source["calendar_id"]),
                    occurrence.event_id,
                    occurrence.series_id,
                    occurrence.occurrence_id or occurrence.event_id,
                    occurrence.source_key,
                    fingerprint,
                    occurrence.revision or None,
                    occurrence.updated_at,
                    occurrence.title,
                    occurrence.location_text,
                    occurrence.time_zone or str(source["calendar_timezone"]),
                    bool(occurrence.all_day),
                )
                if existing is None:
                    cur.execute(
                        """
                        SELECT id
                        FROM jobs
                        WHERE source_key IS NULL
                          AND location_id = %s
                          AND scheduled_date = %s
                          AND status <> 'cancelled'
                        ORDER BY id
                        LIMIT 2
                        """,
                        (location_id, scheduled_date),
                    )
                    collisions = [int(row["id"]) for row in cur.fetchall()]
                    if collisions:
                        counts["unresolved"] += 1
                        exceptions.append(
                            _canonical_exception(
                                source=source,
                                occurrence=occurrence,
                                fingerprint=fingerprint,
                                code="legacy_job_collision",
                                candidate_sites=_calendar_sites_by_id(
                                    cur, (location_id,)
                                ),
                                conflicting_job_ids=collisions,
                            )
                        )
                        continue
                    cur.execute(
                        """
                        INSERT INTO jobs (
                            location_id, customer_name, scheduled_date,
                            scheduled_start, scheduled_end, expected_hours,
                            revenue, notes, status, calendar_source_id,
                            source_calendar_id, source_event_id, source_series_id,
                            source_occurrence_id, source_key, source_fingerprint,
                            source_etag, source_updated_at, source_title,
                            source_location_text, source_timezone, source_all_day,
                            updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, NULL, NULL, '', 'scheduled',
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, NOW()
                        )
                        RETURNING id
                        """,
                        source_values,
                    )
                    job_id = int(cur.fetchone()["id"])
                    counts["create"] += 1
                    audit_action = "canonical_job_created"
                else:
                    unchanged = (
                        existing.get("source_fingerprint") == fingerprint
                        and int(existing["location_id"]) == location_id
                        and int(existing.get("calendar_source_id") or 0)
                        == int(source["id"])
                        and existing["status"] == "scheduled"
                        and existing["customer_name"] == customer_name
                        and existing["scheduled_date"] == scheduled_date
                        and existing.get("scheduled_start") == occurrence.starts_at
                        and existing.get("scheduled_end") == occurrence.ends_at
                        and existing.get("source_calendar_id")
                        == str(source["calendar_id"])
                        and existing.get("source_event_id") == occurrence.event_id
                        and existing.get("source_series_id") == occurrence.series_id
                        and existing.get("source_occurrence_id")
                        == (occurrence.occurrence_id or occurrence.event_id)
                    )
                    if unchanged:
                        counts["unchanged"] += 1
                        continue
                    job_id = int(existing["id"])
                    cur.execute(
                        """
                        UPDATE jobs
                        SET location_id = %s, customer_name = %s,
                            scheduled_date = %s, scheduled_start = %s,
                            scheduled_end = %s, calendar_source_id = %s,
                            source_calendar_id = %s, source_event_id = %s,
                            source_series_id = %s, source_occurrence_id = %s,
                            source_key = %s, source_fingerprint = %s,
                            source_etag = %s, source_updated_at = %s,
                            source_title = %s, source_location_text = %s,
                            source_timezone = %s, source_all_day = %s,
                            expected_hours = NULL, revenue = NULL,
                            status = 'scheduled', cancelled_at = NULL,
                            cancellation_reason = NULL, updated_at = NOW()
                        WHERE id = %s
                        """,
                        (*source_values, job_id),
                    )
                    counts["update"] += 1
                    audit_action = "canonical_job_updated"
                cur.execute(
                    """
                    INSERT INTO planned_visit_audit_events (
                        action, source_key, actor_employee_id, actor_name,
                        after_state
                    ) VALUES (%s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        audit_action,
                        occurrence.source_key,
                        actor_id,
                        actor_name,
                        json.dumps({"jobId": job_id, "sourceId": int(source["id"])}),
                    ),
                )

            cur.execute(
                """
                UPDATE google_calendar_sources
                SET last_synced_at = NOW(), last_sync_status = 'success',
                    last_sync_error = NULL, last_sync_counts = %s::jsonb,
                    last_sync_window_start = %s, last_sync_window_end = %s,
                    updated_by = %s, updated_at = NOW()
                WHERE id = %s
                """,
                (json.dumps(counts), window_start, window_end, actor_id, source_id),
            )
            cur.execute(
                """
                SELECT id, customer_name, address, location_type, active
                FROM locations
                WHERE active = true AND location_type = %s
                ORDER BY customer_name NULLS LAST, address, id
                """,
                (CALENDAR_ROLE_LOCATION_TYPES[str(source["role"])],),
            )
            eligible_sites = [
                _calendar_site_payload(dict(row)) for row in cur.fetchall()
            ]
    return {
        "sourceId": source_id,
        "sourceRole": str(source["role"]),
        "calendarId": str(source["calendar_id"]),
        "status": "success",
        "counts": counts,
        "exceptions": exceptions,
        "eligibleSites": eligible_sites,
    }


def upsert_canonical_mapping(
    *,
    source_id: int,
    expected_credential_version: int,
    expected_calendar_id: str,
    expected_calendar_timezone: str,
    source_key: str,
    source_series_id: str,
    source_fingerprint: str,
    location_id: int,
    apply_to_series: bool,
    actor_id: int,
    actor_name: str,
) -> dict[str, Any]:
    """Persist one fingerprint-reviewed Site decision for an occurrence/series."""

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT connection_id FROM google_calendar_sources WHERE id = %s",
                (source_id,),
            )
            source_reference = cur.fetchone()
            if not source_reference:
                raise CalendarStoreError("Google Calendar source is no longer active")
            connection_id = int(source_reference["connection_id"])
            cur.execute(
                """
                SELECT revoked_at, credential_version
                FROM google_calendar_connections
                WHERE id = %s
                FOR SHARE
                """,
                (connection_id,),
            )
            connection = cur.fetchone()
            if not connection or connection["revoked_at"] is not None:
                raise CalendarStoreError("Google Calendar source is no longer active")
            if int(connection["credential_version"]) != expected_credential_version:
                raise CalendarStoreError(
                    "Google Calendar credentials changed; sync again"
                )
            cur.execute(
                """
                SELECT *
                FROM google_calendar_sources
                WHERE id = %s AND connection_id = %s
                FOR SHARE
                """,
                (source_id, connection_id),
            )
            source = cur.fetchone()
            if not source:
                raise CalendarStoreError("Google Calendar source is no longer active")
            if (
                str(source["calendar_id"]) != expected_calendar_id
                or str(source["calendar_timezone"]) != expected_calendar_timezone
            ):
                raise CalendarStoreError("Google Calendar source changed; sync again")
            cur.execute(
                "SELECT id, active, location_type FROM locations WHERE id = %s FOR SHARE",
                (location_id,),
            )
            location = cur.fetchone()
            if not location or not bool(location["active"]):
                raise CalendarStoreError("Selected Site is no longer active")
            expected_type = CALENDAR_ROLE_LOCATION_TYPES[str(source["role"])]
            if str(location.get("location_type") or "") != expected_type:
                raise CalendarStoreError(
                    f"Selected Site must be {expected_type} for this Calendar"
                )
            mapping_scope = "series" if apply_to_series else "occurrence"
            if apply_to_series:
                cur.execute(
                    """
                    SELECT id, source_key, mapping_scope
                    FROM google_calendar_event_mappings
                    WHERE connection_id = %s AND calendar_id = %s
                      AND mapping_scope = 'series' AND source_series_id = %s
                    FOR UPDATE
                    """,
                    (
                        int(source["connection_id"]),
                        str(source["calendar_id"]),
                        source_series_id,
                    ),
                )
                existing = cur.fetchone()
                if not existing:
                    cur.execute(
                        """
                        SELECT id, source_key, mapping_scope
                        FROM google_calendar_event_mappings
                        WHERE source_key = %s
                        FOR UPDATE
                        """,
                        (source_key,),
                    )
                    existing = cur.fetchone()
            else:
                cur.execute(
                    """
                    SELECT id, source_key, mapping_scope
                    FROM google_calendar_event_mappings
                    WHERE source_key = %s
                    FOR UPDATE
                    """,
                    (source_key,),
                )
                existing = cur.fetchone()
            if existing:
                mapping_id = int(existing["id"])
                stored_source_key = (
                    str(existing["source_key"])
                    if str(existing["mapping_scope"]) == "series"
                    else source_key
                )
                cur.execute(
                    """
                    UPDATE google_calendar_event_mappings
                    SET source_key = %s, source_series_id = %s,
                        mapping_scope = %s, source_fingerprint = %s,
                        location_id = %s, updated_by = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        stored_source_key,
                        source_series_id,
                        mapping_scope,
                        source_fingerprint,
                        location_id,
                        actor_id,
                        mapping_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO google_calendar_event_mappings (
                        connection_id, calendar_id, source_key, source_series_id,
                        mapping_scope, source_fingerprint, location_id,
                        created_by, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        int(source["connection_id"]),
                        str(source["calendar_id"]),
                        source_key,
                        source_series_id,
                        mapping_scope,
                        source_fingerprint,
                        location_id,
                        actor_id,
                        actor_id,
                    ),
                )
                mapping_id = int(cur.fetchone()["id"])
            cur.execute(
                """
                INSERT INTO planned_visit_audit_events (
                    action, source_key, actor_employee_id, actor_name, after_state
                ) VALUES ('canonical_site_mapping_saved', %s, %s, %s, %s::jsonb)
                """,
                (
                    source_key,
                    actor_id,
                    actor_name,
                    json.dumps(
                        {
                            "mappingId": mapping_id,
                            "sourceId": source_id,
                            "scope": mapping_scope,
                            "seriesId": source_series_id,
                            "locationId": location_id,
                        }
                    ),
                ),
            )
    return {
        "id": mapping_id,
        "sourceId": source_id,
        "sourceKey": source_key,
        "seriesId": source_series_id,
        "scope": mapping_scope,
        "sourceFingerprint": source_fingerprint,
        "locationId": location_id,
    }


def migrate_legacy_planned_visits() -> dict[str, Any]:
    """Idempotently backfill non-conflicting legacy visits into canonical jobs."""

    counts = {"created": 0, "linked": 0, "collisions": 0}
    collision_rows: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("canonical-calendar-legacy-migration",),
            )
            cur.execute(
                """
                SELECT pv.*, COALESCE(l.customer_name, c.name, l.address) AS customer_name,
                       l.active AS location_active, l.location_type
                FROM planned_service_visits pv
                JOIN locations l ON l.id = pv.location_id
                LEFT JOIN customers c ON c.id = l.customer_id
                WHERE pv.migrated_job_id IS NULL
                ORDER BY pv.id
                FOR UPDATE OF pv
                """
            )
            visits = [dict(row) for row in cur.fetchall()]
            for visit in visits:
                cur.execute(
                    """
                    SELECT revoked_at
                    FROM google_calendar_connections
                    WHERE id = %s
                    FOR SHARE
                    """,
                    (int(visit["connection_id"]),),
                )
                connection = cur.fetchone()
                cur.execute(
                    """
                    SELECT id, role
                    FROM google_calendar_sources
                    WHERE connection_id = %s AND calendar_id = %s
                    """,
                    (
                        int(visit["connection_id"]),
                        str(visit["source_calendar_id"]),
                    ),
                )
                source = cur.fetchone()
                is_active_plan = str(visit["status"]) == "planned"
                migration_issue: str | None = None
                if is_active_plan:
                    if not connection or connection["revoked_at"] is not None:
                        migration_issue = "source_disconnected"
                    elif source is None:
                        migration_issue = "source_unbound"
                    elif bool(visit.get("all_day")):
                        migration_issue = "all_day"
                    elif not bool(visit.get("location_active")):
                        migration_issue = "archived_site"
                    else:
                        expected_type = CALENDAR_ROLE_LOCATION_TYPES[
                            str(source["role"])
                        ]
                        if str(visit.get("location_type") or "") != expected_type:
                            migration_issue = "wrong_site_type"
                if migration_issue is not None:
                    exceptions.append(
                        {
                            "plannedVisitId": int(visit["id"]),
                            "sourceKey": str(visit["source_key"]),
                            "code": migration_issue,
                            "locationId": int(visit["location_id"]),
                        }
                    )
                    continue
                cur.execute(
                    "SELECT id FROM jobs WHERE source_key = %s FOR UPDATE",
                    (str(visit["source_key"]),),
                )
                existing = cur.fetchone()
                if existing:
                    job_id = int(existing["id"])
                    counts["linked"] += 1
                else:
                    scheduled_date = (
                        visit["approximate_start"].astimezone(PRODUCT_TIMEZONE).date()
                    )
                    cur.execute(
                        """
                        SELECT id
                        FROM jobs
                        WHERE source_key IS NULL
                          AND location_id = %s
                          AND scheduled_date = %s
                          AND status <> 'cancelled'
                        ORDER BY id
                        LIMIT 2
                        """,
                        (int(visit["location_id"]), scheduled_date),
                    )
                    collision_ids = [int(row["id"]) for row in cur.fetchall()]
                    if collision_ids:
                        counts["collisions"] += 1
                        collision_rows.append(
                            {
                                "plannedVisitId": int(visit["id"]),
                                "sourceKey": str(visit["source_key"]),
                                "jobIds": collision_ids,
                            }
                        )
                        continue
                    status = {
                        "planned": "scheduled",
                        "cancelled": "cancelled",
                        "completed": "completed",
                    }[str(visit["status"])]
                    cur.execute(
                        """
                        INSERT INTO jobs (
                            location_id, customer_name, scheduled_date,
                            scheduled_start, scheduled_end, expected_hours,
                            revenue, notes, status, calendar_source_id,
                            source_calendar_id, source_event_id, source_series_id,
                            source_occurrence_id, source_key, source_fingerprint,
                            source_etag, source_updated_at, source_title,
                            source_location_text, source_timezone, source_all_day,
                            cancelled_at, cancellation_reason, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, NULL, NULL, '', %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, NOW()
                        )
                        RETURNING id
                        """,
                        (
                            int(visit["location_id"]),
                            str(visit["customer_name"]),
                            scheduled_date,
                            visit["approximate_start"],
                            visit["approximate_end"],
                            status,
                            int(source["id"]) if source else None,
                            str(visit["source_calendar_id"]),
                            str(visit["source_event_id"]),
                            str(visit["source_series_id"]),
                            str(visit["source_occurrence_id"]),
                            str(visit["source_key"]),
                            str(visit["source_fingerprint"]),
                            visit.get("source_etag"),
                            visit.get("source_updated_at"),
                            str(visit.get("title") or ""),
                            str(visit.get("source_location_text") or ""),
                            str(visit.get("source_timezone") or ""),
                            bool(visit.get("all_day")),
                            visit.get("cancelled_at"),
                            (
                                "legacy_calendar_cancelled"
                                if status == "cancelled"
                                else None
                            ),
                        ),
                    )
                    job_id = int(cur.fetchone()["id"])
                    counts["created"] += 1
                cur.execute(
                    """
                    UPDATE planned_service_visits
                    SET migrated_job_id = %s
                    WHERE id = %s AND migrated_job_id IS NULL
                    RETURNING id
                    """,
                    (job_id, int(visit["id"])),
                )
                if cur.fetchone():
                    cur.execute(
                        """
                        INSERT INTO planned_visit_audit_events (
                            planned_visit_id, action, source_key, actor_name,
                            before_state, after_state
                        ) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
                        """,
                        (
                            int(visit["id"]),
                            (
                                "canonical_job_migration_linked"
                                if existing
                                else "canonical_job_migration_created"
                            ),
                            str(visit["source_key"]),
                            "system:canonical-calendar-migration",
                            json.dumps(
                                {
                                    "plannedVisitId": int(visit["id"]),
                                    "status": str(visit["status"]),
                                }
                            ),
                            json.dumps(
                                {
                                    "jobId": job_id,
                                    "sourceKey": str(visit["source_key"]),
                                }
                            ),
                        ),
                    )
    return {
        "counts": counts,
        "collisions": collision_rows,
        "exceptions": exceptions,
    }
