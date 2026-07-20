"""Durable storage and secret handling for read-only Calendar imports.

This module intentionally has no shift, payroll, QR, billing, or location-write
dependencies. Google occurrences become planned-service obligations only.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken

import db


MORNING_CREW_NAME = "Morning Crew"
MORNING_CREW_EXPECTED_NAMES = ("Carmen", "Pamela", "Tina")


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
            connected_by           INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            connected_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at             TIMESTAMPTZ
        );

        ALTER TABLE google_calendar_connections
            ADD COLUMN IF NOT EXISTS selected_calendar_timezone TEXT;

        CREATE UNIQUE INDEX IF NOT EXISTS uq_google_calendar_active_connection
            ON google_calendar_connections ((revoked_at IS NULL))
            WHERE revoked_at IS NULL;

        CREATE TABLE IF NOT EXISTS google_calendar_oauth_states (
            state_hash                 VARCHAR(64) PRIMARY KEY
                                           CHECK (state_hash ~ '^[0-9a-f]{64}$'),
            admin_employee_id          INTEGER NOT NULL REFERENCES employees(id),
            pkce_verifier_ciphertext   TEXT NOT NULL,
            expires_at                 TIMESTAMPTZ NOT NULL,
            consumed_at                TIMESTAMPTZ,
            created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

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
            location_id       INTEGER NOT NULL REFERENCES locations(id),
            created_by        INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            updated_by        INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (source_key)
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
            last_preview_id       TEXT REFERENCES calendar_import_previews(id),
            last_imported_by      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (approximate_end > approximate_start),
            CHECK (status <> 'cancelled' OR cancelled_at IS NOT NULL),
            CHECK (status <> 'completed' OR completed_at IS NOT NULL)
        );

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


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def create_oauth_state(
    *, admin_id: int, cipher: CredentialCipher, ttl_minutes: int = 10
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
                    pkce_verifier_ciphertext, expires_at
                ) VALUES (%s, %s, %s, %s)
                """,
                (
                    _state_hash(raw_state),
                    admin_id,
                    cipher.encrypt_text(pkce_verifier),
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
               selected_calendar_timezone, connected_by,
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
                RETURNING id, google_account_email, granted_scopes, connected_at
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


def connection_credentials(
    connection: dict[str, Any], *, cipher: CredentialCipher
) -> dict[str, Any]:
    ciphertext = connection.get("credential_ciphertext")
    if not ciphertext:
        raise CalendarStoreError("Google Calendar connection has no usable credentials")
    return cipher.decrypt_json(str(ciphertext))


def update_connection_credentials(
    connection_id: int, credentials: dict[str, Any], *, cipher: CredentialCipher
) -> None:
    updated = db.execute_returning(
        """
        UPDATE google_calendar_connections
        SET credential_ciphertext = %s, updated_at = NOW()
        WHERE id = %s AND revoked_at IS NULL
        RETURNING id
        """,
        (cipher.encrypt_json(credentials), connection_id),
    )
    if not updated:
        raise CalendarStoreError("Google Calendar connection is no longer active")


def select_calendar(
    *,
    connection_id: int,
    calendar_id: str,
    calendar_name: str,
    calendar_timezone: str | None,
) -> None:
    updated = db.execute_returning(
        """
        UPDATE google_calendar_connections
        SET selected_calendar_id = %s, selected_calendar_name = %s,
            selected_calendar_timezone = %s,
            updated_at = NOW()
        WHERE id = %s AND revoked_at IS NULL
        RETURNING id
        """,
        (calendar_id, calendar_name, calendar_timezone, connection_id),
    )
    if not updated:
        raise CalendarStoreError("Google Calendar connection is no longer active")


def disconnect_calendar(*, connection_id: int, admin_id: int, admin_name: str) -> bool:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("google-calendar",)
            )
            cur.execute(
                """
                UPDATE google_calendar_connections
                SET revoked_at = NOW(), credential_ciphertext = NULL,
                    updated_at = NOW()
                WHERE id = %s AND revoked_at IS NULL
                RETURNING id, selected_calendar_id, selected_calendar_name,
                          selected_calendar_timezone
                """,
                (connection_id,),
            )
            row = cur.fetchone()
            if not row:
                return False
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
    *, calendar_id: str, range_start: datetime, range_end: datetime
) -> list[dict[str, Any]]:
    """Return active in-window identities that a bounded list must reconcile."""

    return db.query_all(
        """
        SELECT source_key, source_event_id, source_series_id,
               source_occurrence_id
        FROM planned_service_visits
        WHERE source_calendar_id = %s
          AND status = 'planned'
          AND approximate_end > %s
          AND approximate_start < %s
        ORDER BY source_key
        """,
        (calendar_id, range_start, range_end),
    )


def create_preview(
    *,
    connection_id: int,
    calendar_id: str,
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
    row = db.query_one(
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
