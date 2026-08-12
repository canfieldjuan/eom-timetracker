-- EOM Employee Management -- PostgreSQL Schema
-- Run once against a fresh database

-- Employees
CREATE TABLE employees (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT true,
    role          TEXT NOT NULL DEFAULT 'employee'
                      CHECK (role IN ('admin', 'employee', 'payroll')),
    hourly_rate   NUMERIC(8, 2),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Customers (stable business identity; a draft may have zero job sites)
CREATE TABLE customers (
    id                   SERIAL PRIMARY KEY,
    name                 TEXT NOT NULL,
    primary_contact_name VARCHAR(200),
    primary_phone        VARCHAR(50),
    primary_email        VARCHAR(320),
    billing_name         VARCHAR(200),
    billing_email        VARCHAR(320),
    billing_address      VARCHAR(500),
    atlas_contact_id     UUID,
    active               BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at          TIMESTAMPTZ,
    archived_by          INTEGER REFERENCES employees(id) ON DELETE SET NULL
);

-- Locations (customer job sites)
CREATE TABLE locations (
    id              SERIAL PRIMARY KEY,
    customer_id     INTEGER REFERENCES customers(id),
    address         TEXT NOT NULL UNIQUE,
    address_key     TEXT,
    customer_name   TEXT,
    location_type   TEXT CHECK (location_type IN ('Residential', 'Commercial')),
    rate            NUMERIC(8, 2),
    rate_type       TEXT NOT NULL DEFAULT 'per_visit'
                        CHECK (rate_type IN ('per_visit', 'hourly', 'monthly')),
    frequency         TEXT,
    expected_hours    NUMERIC(6, 2),
    expected_hours_source VARCHAR(32) NOT NULL DEFAULT 'manual'
                          CHECK (expected_hours_source IN ('manual', 'learned_accepted')),
    expected_hours_learning_decision VARCHAR(16)
                          CHECK (expected_hours_learning_decision IN ('accepted', 'rejected')),
    expected_hours_learning_fingerprint VARCHAR(64)
                          CHECK (
                              expected_hours_learning_fingerprint IS NULL
                              OR expected_hours_learning_fingerprint ~ '^[0-9a-f]{64}$'
                          ),
    expected_hours_learning_snapshot JSONB,
    expected_hours_learning_decided_at TIMESTAMPTZ,
    expected_hours_learning_decided_by INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    expected_hours_learning_decision_reason TEXT NOT NULL DEFAULT '',
    target_labor_pct  NUMERIC(5, 2),
    min_margin_pct    NUMERIC(5, 2),
    lat               NUMERIC(10, 7),
    lng               NUMERIC(10, 7),
    service_scope       TEXT,
    access_instructions TEXT,
    service_preferences TEXT,
    pet_notes           TEXT,
    service_start_date  DATE,
    check_in_token_nonce      VARCHAR(64),
    check_in_token_rotated_at TIMESTAMPTZ,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at     TIMESTAMPTZ,
    archived_by     INTEGER REFERENCES employees(id) ON DELETE SET NULL
);

-- One durable office approval links an Atlas lead to the operational Customer
-- and first Site created from its completed estimate. Operational price and
-- scheduling details remain on customers/locations, never in this record.
CREATE TABLE eom_office_conversion_handoffs (
    atlas_contact_id         UUID PRIMARY KEY,
    idempotency_key          UUID NOT NULL UNIQUE,
    request_fingerprint      VARCHAR(64) NOT NULL,
    customer_id              INTEGER NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
    site_id                  INTEGER NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
    approved_by_employee_id  INTEGER NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
    state                    VARCHAR(16) NOT NULL DEFAULT 'pending'
                               CHECK (state IN ('pending', 'finalized')),
    atlas_handoff_id         UUID,
    last_error               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at             TIMESTAMPTZ
);

-- Local office state for Atlas leads Juan has accepted into the estimate
-- pipeline before the customer has approved pricing/schedule details. The
-- version makes delayed browser actions fail closed after lost/reopen
-- transitions.
CREATE TABLE eom_lead_working (
    atlas_contact_id        UUID PRIMARY KEY,
    state                   VARCHAR(16) NOT NULL DEFAULT 'working'
                              CHECK (state IN ('working', 'lost', 'reopened')),
    state_version           INTEGER NOT NULL DEFAULT 1 CHECK (state_version >= 1),
    marked_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    marked_by_employee_id   INTEGER REFERENCES employees(id) ON DELETE RESTRICT,
    lost_at                 TIMESTAMPTZ,
    lost_by_employee_id     INTEGER REFERENCES employees(id) ON DELETE RESTRICT,
    reopened_at             TIMESTAMPTZ,
    reopened_by_employee_id INTEGER REFERENCES employees(id) ON DELETE RESTRICT
);

-- Request access diagnostics. During the file-to-Postgres cutover the API keeps
-- writing the legacy JSON files and reads both sources for the admin log view.
CREATE TABLE access_log_entries (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT NOT NULL,
    logged_at   TIMESTAMPTZ NOT NULL,
    local_date  DATE NOT NULL,
    action      TEXT NOT NULL,
    allowed     BOOLEAN NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    client_ip   TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    endpoint    TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    entry       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Jobs (service visits / scheduled work at a customer)
CREATE TABLE jobs (
    id              SERIAL PRIMARY KEY,
    location_id     INTEGER REFERENCES locations(id),
    customer_name   TEXT NOT NULL,
    scheduled_date  DATE NOT NULL,
    scheduled_start TIMESTAMPTZ,
    scheduled_end   TIMESTAMPTZ,
    expected_hours  NUMERIC(6, 2),
    revenue         NUMERIC(10, 2),
    notes           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'scheduled'
                        CHECK (status IN ('scheduled', 'in_progress', 'completed', 'cancelled')),
    source_calendar_id   TEXT,
    source_event_id      TEXT,
    source_series_id     TEXT,
    source_occurrence_id TEXT,
    source_key           VARCHAR(64)
                             CHECK (source_key IS NULL OR source_key ~ '^[0-9a-f]{64}$'),
    source_fingerprint   VARCHAR(64)
                             CHECK (
                                 source_fingerprint IS NULL
                                 OR source_fingerprint ~ '^[0-9a-f]{64}$'
                             ),
    source_etag          TEXT,
    source_updated_at    TIMESTAMPTZ,
    source_title         TEXT,
    source_location_text TEXT,
    source_timezone      TEXT,
    source_all_day       BOOLEAN NOT NULL DEFAULT false,
    cancelled_at         TIMESTAMPTZ,
    cancellation_reason  TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        scheduled_start IS NULL
        OR scheduled_end IS NULL
        OR scheduled_end > scheduled_start
    )
);

CREATE UNIQUE INDEX uq_jobs_google_source_key
    ON jobs(source_key) WHERE source_key IS NOT NULL;

-- Shifts (time entries)
CREATE TABLE shifts (
    id                  SERIAL PRIMARY KEY,
    employee_id         INTEGER NOT NULL REFERENCES employees(id),
    location_id         INTEGER REFERENCES locations(id),
    location_label      TEXT NOT NULL DEFAULT '',
    clock_in            TIMESTAMPTZ NOT NULL,
    clock_out           TIMESTAMPTZ,
    total_hours         NUMERIC(6, 2),
    notes               TEXT NOT NULL DEFAULT '',
    local_date          DATE,
    timezone            TEXT NOT NULL DEFAULT 'America/Chicago',
    clock_in_gps        JSONB,
    clock_in_gps_meta   JSONB,
    clock_out_gps       JSONB,
    clock_out_gps_meta  JSONB,
    job_id              INTEGER REFERENCES jobs(id),
    -- Rate the shift was actually worked at, stamped once at clock-in and never
    -- rewritten. employees.hourly_rate stays editable; money surfaces prefer
    -- this snapshot so an edit only moves future work. NULL means "no snapshot"
    -- (pre-migration row, or employee had no rate) and falls back to the live
    -- rate, preserving each surface's existing missing-rate policy.
    hourly_rate_cents   INTEGER,
    time_category       TEXT NOT NULL DEFAULT 'productive'
                            CHECK (time_category IN ('productive', 'non_productive')),
    non_productive_type TEXT
                            CHECK (non_productive_type IS NULL OR non_productive_type IN
                                   ('drive_time', 'waiting', 'supply_run', 'rework', 'lockout', 'other')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stamp every shift with the employee's current rate at INSERT, in the
-- DATABASE rather than the app, so it applies regardless of which app instance
-- (or a mid-deploy old instance that predates the column in its code) wrote the
-- row. Only fills a NULL -- an explicit value from the app is left untouched --
-- and a rate-less employee leaves the snapshot NULL so the shift keeps
-- following the live rate. This is the only trigger in the schema; it exists
-- specifically to close the rolling-deployment window where an old instance's
-- clock-in would otherwise store no snapshot.
CREATE OR REPLACE FUNCTION stamp_shift_hourly_rate_cents()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.hourly_rate_cents IS NULL THEN
        SELECT ROUND(e.hourly_rate * 100)
          INTO NEW.hourly_rate_cents
          FROM employees e
         WHERE e.id = NEW.employee_id
           AND e.hourly_rate IS NOT NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_stamp_shift_hourly_rate_cents ON shifts;
CREATE TRIGGER trg_stamp_shift_hourly_rate_cents
    BEFORE INSERT ON shifts
    FOR EACH ROW
    EXECUTE FUNCTION stamp_shift_hourly_rate_cents();

-- Visits (multi-stop tracking within a shift)
CREATE TABLE visits (
    id             SERIAL PRIMARY KEY,
    shift_id       INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    location_id    INTEGER REFERENCES locations(id),
    location_label TEXT NOT NULL DEFAULT '',
    customer_name  TEXT,
    arrival_time   TIMESTAMPTZ NOT NULL,
    gps            JSONB,
    gps_meta       JSONB,
    job_id         INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    sequence_version SMALLINT NOT NULL DEFAULT 1
                         CHECK (sequence_version IN (1, 2)),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Departures (explicit leaving events during a shift)
CREATE TABLE departures (
    id             SERIAL PRIMARY KEY,
    shift_id       INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    visit_id       INTEGER REFERENCES visits(id) ON DELETE SET NULL,
    location_id    INTEGER REFERENCES locations(id),
    location_label TEXT NOT NULL DEFAULT '',
    customer_name  TEXT,
    departure_time TIMESTAMPTZ NOT NULL,
    gps            JSONB,
    gps_meta       JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Schedules (planned hours per employee per exact job site per week)
CREATE TABLE schedules (
    id              SERIAL PRIMARY KEY,
    employee_id     INTEGER NOT NULL REFERENCES employees(id),
    location_id     INTEGER REFERENCES locations(id),
    customer_name   TEXT NOT NULL,
    week_start      DATE NOT NULL,
    scheduled_hours NUMERIC(6, 2) NOT NULL,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_schedules_week ON schedules(week_start);
CREATE INDEX idx_schedules_employee ON schedules(employee_id);
CREATE UNIQUE INDEX uq_schedules_employee_site_week
    ON schedules(employee_id, location_id, week_start)
    WHERE location_id IS NOT NULL;
CREATE UNIQUE INDEX uq_schedules_employee_legacy_name_week
    ON schedules(employee_id, customer_name, week_start)
    WHERE location_id IS NULL;

-- Native recurring service rules owned by Sites. These rules are a shadow
-- planning source until a later cutover promotes generated visits into jobs.
CREATE TABLE service_schedule_rules (
    id               BIGSERIAL PRIMARY KEY,
    location_id      INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    shift_bucket     TEXT NOT NULL
                         CHECK (shift_bucket IN ('morning', 'evening', 'night')),
    cadence          TEXT NOT NULL
                         CHECK (cadence IN ('weekly', 'biweekly', 'monthly')),
    weekdays         SMALLINT[] NOT NULL,
    local_start_time TIME NOT NULL,
    local_end_time   TIME NOT NULL,
    starts_on        DATE NOT NULL,
    ends_on          DATE,
    notes            TEXT NOT NULL DEFAULT '',
    active           BOOLEAN NOT NULL DEFAULT true,
    created_by       INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    updated_by       INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        cardinality(weekdays) BETWEEN 1 AND 7
        AND weekdays <@ ARRAY[0, 1, 2, 3, 4, 5, 6]::SMALLINT[]
    ),
    CHECK (ends_on IS NULL OR ends_on >= starts_on)
);

CREATE INDEX idx_service_schedule_rules_location
    ON service_schedule_rules(location_id, active, starts_on, ends_on);
CREATE INDEX idx_service_schedule_rules_window
    ON service_schedule_rules(active, starts_on, ends_on);

-- Exact employee/site start times used only for QR arrival classification.
-- The existing schedules table stores weekly hour totals and cannot determine
-- whether a specific arrival is on time.
CREATE TABLE site_check_in_schedules (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     INTEGER NOT NULL REFERENCES employees(id),
    location_id     INTEGER NOT NULL REFERENCES locations(id),
    scheduled_start TIMESTAMPTZ NOT NULL,
    grace_minutes   INTEGER NOT NULL DEFAULT 10
                        CHECK (grace_minutes BETWEEN 0 AND 120),
    created_by      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cancelled_at    TIMESTAMPTZ,
    cancelled_by    INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    cancellation_reason TEXT,
    UNIQUE (employee_id, location_id, scheduled_start)
);

-- Durable weekly arrival rules. Python weekday numbering is used:
-- Monday = 0 through Sunday = 6. Exact schedules above override a recurring
-- rule when both could classify the same check-in.
CREATE TABLE site_check_in_schedule_rules (
    id               BIGSERIAL PRIMARY KEY,
    employee_id      INTEGER NOT NULL REFERENCES employees(id),
    location_id      INTEGER NOT NULL REFERENCES locations(id),
    weekdays         SMALLINT[] NOT NULL,
    local_start_time TIME NOT NULL,
    timezone         TEXT NOT NULL,
    starts_on        DATE NOT NULL,
    ends_on          DATE NOT NULL DEFAULT 'infinity',
    grace_minutes    INTEGER NOT NULL DEFAULT 10
                         CHECK (grace_minutes BETWEEN 0 AND 120),
    active           BOOLEAN NOT NULL DEFAULT true,
    created_by       INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        cardinality(weekdays) BETWEEN 1 AND 7
        AND weekdays <@ ARRAY[0, 1, 2, 3, 4, 5, 6]::SMALLINT[]
    ),
    CHECK (ends_on >= starts_on),
    UNIQUE (
        employee_id, location_id, weekdays, local_start_time,
        timezone, starts_on, ends_on
    )
);

-- Append-only Site and canonical-appointment arrival-policy revisions. The
-- latest revision is current; retirement is a new revision, never an update.
CREATE TABLE arrival_policy_revisions (
    id               BIGSERIAL PRIMARY KEY,
    scope_type       VARCHAR(16) NOT NULL
                         CHECK (scope_type IN ('site', 'appointment')),
    site_id          INTEGER NOT NULL,
    job_id           INTEGER,
    version          INTEGER NOT NULL CHECK (version > 0),
    state            VARCHAR(16) NOT NULL
                         CHECK (state IN ('active', 'retired')),
    mode             VARCHAR(16)
                         CHECK (mode IN ('fixed', 'window', 'flexible', 'not_before')),
    timezone         TEXT,
    fixed_arrival    TIME,
    grace_minutes    INTEGER CHECK (grace_minutes BETWEEN 0 AND 120),
    window_start     TIME,
    window_end       TIME,
    not_before       TIME,
    update_token     VARCHAR(64) NOT NULL UNIQUE
                         CHECK (update_token ~ '^[0-9a-f]{64}$'),
    change_note      TEXT NOT NULL CHECK (char_length(change_note) BETWEEN 3 AND 500),
    created_by       INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name  TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (scope_type = 'site' AND job_id IS NULL)
        OR (scope_type = 'appointment' AND job_id IS NOT NULL)
    ),
    CHECK (
        state = 'retired'
        OR (
            mode IS NOT NULL
            AND timezone IS NOT NULL
            AND (
                (mode = 'fixed' AND fixed_arrival IS NOT NULL
                 AND grace_minutes IS NOT NULL AND window_start IS NULL
                 AND window_end IS NULL AND not_before IS NULL)
                OR
                (mode = 'window' AND fixed_arrival IS NULL
                 AND grace_minutes IS NULL AND window_start IS NOT NULL
                 AND window_end IS NOT NULL AND not_before IS NULL)
                OR
                (mode = 'flexible' AND fixed_arrival IS NULL
                 AND grace_minutes IS NULL AND window_start IS NULL
                 AND window_end IS NULL AND not_before IS NULL)
                OR
                (mode = 'not_before' AND fixed_arrival IS NULL
                 AND grace_minutes IS NULL AND window_start IS NULL
                 AND window_end IS NULL AND not_before IS NOT NULL)
            )
        )
    ),
    UNIQUE (scope_type, site_id, job_id, version)
);

CREATE UNIQUE INDEX uq_arrival_policy_site_version
    ON arrival_policy_revisions(site_id, version)
    WHERE scope_type = 'site';
CREATE UNIQUE INDEX uq_arrival_policy_appointment_version
    ON arrival_policy_revisions(job_id, version)
    WHERE scope_type = 'appointment';
CREATE INDEX idx_arrival_policy_site_latest
    ON arrival_policy_revisions(site_id, version DESC)
    WHERE scope_type = 'site';
CREATE INDEX idx_arrival_policy_appointment_latest
    ON arrival_policy_revisions(job_id, version DESC)
    WHERE scope_type = 'appointment';

-- Immutable evidence for each authenticated QR site check-in. Device time is
-- retained as evidence; server_checked_in_at is the official timestamp.
CREATE TABLE site_check_ins (
    id                       BIGSERIAL PRIMARY KEY,
    employee_id              INTEGER NOT NULL REFERENCES employees(id),
    location_id              INTEGER NOT NULL REFERENCES locations(id),
    job_id                   INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    server_checked_in_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_scanned_at        TIMESTAMPTZ NOT NULL,
    latitude                 NUMERIC(10, 7) NOT NULL,
    longitude                NUMERIC(10, 7) NOT NULL,
    accuracy_m               NUMERIC(10, 2) NOT NULL,
    geofence_radius_m        INTEGER NOT NULL,
    distance_m               NUMERIC(10, 2),
    geofence_status          VARCHAR(32) NOT NULL
                                 CHECK (geofence_status IN
                                    ('inside', 'outside', 'uncertain', 'low_accuracy', 'site_unpinned')),
    classification           VARCHAR(24) NOT NULL
                                 CHECK (classification IN ('on_time', 'late', 'needs_review')),
    classification_reason    VARCHAR(64) NOT NULL,
    schedule_id              BIGINT REFERENCES site_check_in_schedules(id) ON DELETE SET NULL,
    schedule_rule_id         BIGINT REFERENCES site_check_in_schedule_rules(id) ON DELETE SET NULL,
    arrival_policy_revision_id BIGINT REFERENCES arrival_policy_revisions(id) ON DELETE SET NULL,
    arrival_policy_snapshot  JSONB,
    scheduled_start          TIMESTAMPTZ,
    grace_minutes            INTEGER,
    device_clock_skew_seconds NUMERIC(12, 2) NOT NULL,
    review_status            VARCHAR(24) NOT NULL
                                 CHECK (review_status IN
                                    ('not_required', 'pending', 'approved', 'rejected')),
    reviewed_by              INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    reviewed_at              TIMESTAMPTZ,
    review_note              TEXT NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (employee_id, location_id, device_scanned_at)
);

-- Version-2 visits link the authoritative arrival event to its immutable QR
-- arrival evidence. Legacy/manual evidence remains nullable and readable.
ALTER TABLE visits
    ADD COLUMN site_check_in_id BIGINT
        REFERENCES site_check_ins(id) ON DELETE SET NULL;

-- Immutable request/decision envelopes for explicit QR Arrive/Depart actions.
-- Visits and departures remain the authoritative time events; these rows make
-- retries exact and retain rejected/weak-GPS evidence without inventing time.
CREATE TABLE site_qr_action_receipts (
    id                    BIGSERIAL PRIMARY KEY,
    employee_id           INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    location_id           INTEGER REFERENCES locations(id) ON DELETE SET NULL,
    shift_id              INTEGER REFERENCES shifts(id) ON DELETE SET NULL,
    action                VARCHAR(16) NOT NULL
                              CHECK (action IN ('arrive', 'depart')),
    idempotency_key       UUID NOT NULL,
    request_fingerprint   VARCHAR(64) NOT NULL
                              CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    server_recorded_at    TIMESTAMPTZ NOT NULL,
    device_scanned_at     TIMESTAMPTZ NOT NULL,
    latitude              NUMERIC(10, 7) NOT NULL,
    longitude             NUMERIC(10, 7) NOT NULL,
    accuracy_m            NUMERIC(10, 2) NOT NULL,
    geofence_radius_m     INTEGER NOT NULL,
    distance_m            NUMERIC(10, 2),
    geofence_status       VARCHAR(32) NOT NULL
                              CHECK (geofence_status IN
                                 ('inside', 'outside', 'uncertain',
                                  'low_accuracy', 'site_unpinned')),
    outcome               VARCHAR(32) NOT NULL
                              CHECK (outcome IN
                                 ('recorded', 'evidence_only_review')),
    site_check_in_id      BIGINT REFERENCES site_check_ins(id) ON DELETE SET NULL,
    visit_id              INTEGER REFERENCES visits(id) ON DELETE SET NULL,
    departure_id          INTEGER REFERENCES departures(id) ON DELETE SET NULL,
    missing_departure_visit_ids INTEGER[] NOT NULL DEFAULT '{}',
    response_body         JSONB NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (employee_id, idempotency_key),
    UNIQUE (employee_id, location_id, device_scanned_at)
);

-- Immutable request/response envelopes for ordinary paid-time button actions.
-- The shifts, visits, and departures tables remain authoritative; these rows
-- let the employee portal safely replay a committed action after a lost
-- response without creating a second shift event.
CREATE TABLE plain_time_action_receipts (
    id                    BIGSERIAL PRIMARY KEY,
    employee_id           INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    shift_id              INTEGER REFERENCES shifts(id) ON DELETE SET NULL,
    action                VARCHAR(16) NOT NULL
                              CHECK (action IN (
                                  'clock-in', 'arrive',
                                  'depart', 'clock-out',
                                  'home-base-start', 'home-base-end'
                              )),
    idempotency_key       UUID NOT NULL,
    request_fingerprint   VARCHAR(64) NOT NULL
                              CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    server_recorded_at    TIMESTAMPTZ NOT NULL,
    response_body         JSONB NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (employee_id, idempotency_key)
);

-- Append-only admin dispositions for derived reconciliation exceptions. A
-- disposition applies only to the exact evidence fingerprint that was
-- reviewed; changed QR or timecard evidence automatically reopens the row.
CREATE TABLE site_check_in_reconciliation_reviews (
    id                   BIGSERIAL PRIMARY KEY,
    occurrence_key       VARCHAR(128) NOT NULL,
    evidence_fingerprint VARCHAR(64) NOT NULL
                             CHECK (evidence_fingerprint ~ '^[0-9a-f]{64}$'),
    employee_id          INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    location_id          INTEGER REFERENCES locations(id) ON DELETE SET NULL,
    scheduled_start      TIMESTAMPTZ NOT NULL,
    outcome              VARCHAR(32) NOT NULL,
    evidence             JSONB NOT NULL,
    disposition          VARCHAR(32) NOT NULL
                             CHECK (disposition IN ('resolved', 'needs_correction')),
    note                 TEXT NOT NULL
                             CHECK (char_length(note) BETWEEN 3 AND 500),
    reviewed_by          INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    reviewed_by_name     TEXT NOT NULL,
    reviewed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One-way, read-only Google Calendar connection state. Credentials are
-- encrypted by the application before they reach PostgreSQL. Revoked rows are
-- retained as connection provenance, but their credential ciphertext is
-- scrubbed.
CREATE TABLE google_calendar_connections (
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

CREATE UNIQUE INDEX uq_google_calendar_active_connection
    ON google_calendar_connections ((revoked_at IS NULL))
    WHERE revoked_at IS NULL;

-- One OAuth grant supplies exactly two independently synchronized planning
-- sources. Roles are business semantics and do not depend on event clock time.
CREATE TABLE google_calendar_sources (
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
                           CHECK (last_sync_status IN ('never', 'success', 'failed')),
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

ALTER TABLE jobs
    ADD COLUMN calendar_source_id BIGINT REFERENCES google_calendar_sources(id);

-- OAuth callbacks cannot carry the portal bearer token. A random state value
-- is stored only as a hash, bound to the initiating admin and (for recovery)
-- one exact active connection, and consumed once.
CREATE TABLE google_calendar_oauth_states (
    state_hash                 VARCHAR(64) PRIMARY KEY
                                   CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    admin_employee_id          INTEGER NOT NULL REFERENCES employees(id),
    pkce_verifier_ciphertext   TEXT NOT NULL,
    reconnect_connection_id    BIGINT REFERENCES google_calendar_connections(id),
    expires_at                 TIMESTAMPTZ NOT NULL,
    consumed_at                TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reusable service crews and effective-dated membership. Imported Calendar
-- times are deliberately absent: membership describes who may be assigned,
-- not paid time or an exact arrival promise.
CREATE TABLE crews (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_by  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE crew_memberships (
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

-- The office is an internal paid-workplace boundary, not a Customer/Site.  It
-- deliberately has no customer, service, rate, revenue, or job reference.
-- A partial unique index below keeps the first release to one active office
-- without coupling it to the customer-location domain.
CREATE TABLE home_bases (
    id                     BIGSERIAL PRIMARY KEY,
    label                  TEXT NOT NULL CHECK (char_length(btrim(label)) BETWEEN 1 AND 160),
    address                TEXT NOT NULL DEFAULT '' CHECK (char_length(address) <= 500),
    latitude               NUMERIC(10, 7),
    longitude              NUMERIC(10, 7),
    active                 BOOLEAN NOT NULL DEFAULT true,
    check_in_token_nonce   VARCHAR(64),
    check_in_token_rotated_at TIMESTAMPTZ,
    created_by             INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (latitude IS NULL AND longitude IS NULL)
        OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180)
    )
);

CREATE UNIQUE INDEX uq_home_bases_one_active
    ON home_bases ((active)) WHERE active;

-- Scope is derived from effective-dated crew membership.  No employee list is
-- copied here, so Morning Crew changes take effect without a second roster.
CREATE TABLE home_base_policies (
    id             BIGSERIAL PRIMARY KEY,
    home_base_id   BIGINT NOT NULL REFERENCES home_bases(id) ON DELETE CASCADE,
    crew_id        BIGINT NOT NULL REFERENCES crews(id) ON DELETE RESTRICT,
    active         BOOLEAN NOT NULL DEFAULT true,
    created_by     INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (home_base_id, crew_id)
);

CREATE UNIQUE INDEX uq_home_base_policies_one_active
    ON home_base_policies ((active)) WHERE active;

-- Append-only Home Base evidence.  A documented exception is still durable
-- evidence, never an invisible bypass, and the one-event-per-shift/action
-- uniqueness prevents a scan/retry from creating duplicate dispatch markers.
CREATE TABLE home_base_events (
    id                 BIGSERIAL PRIMARY KEY,
    shift_id           INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    employee_id        INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    home_base_id       BIGINT NOT NULL REFERENCES home_bases(id) ON DELETE RESTRICT,
    home_base_policy_id BIGINT REFERENCES home_base_policies(id) ON DELETE SET NULL,
    action             VARCHAR(16) NOT NULL CHECK (action IN ('start', 'end')),
    outcome            VARCHAR(16) NOT NULL CHECK (outcome IN ('recorded', 'exception')),
    exception_reason   TEXT NOT NULL DEFAULT '' CHECK (char_length(exception_reason) <= 500),
    recorded_at        TIMESTAMPTZ NOT NULL,
    latitude           NUMERIC(10, 7),
    longitude          NUMERIC(10, 7),
    accuracy_m         NUMERIC(10, 2),
    geofence_radius_m  INTEGER,
    distance_m         NUMERIC(10, 2),
    geofence_status    VARCHAR(32),
    idempotency_key    UUID,
    request_fingerprint VARCHAR(64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (outcome = 'recorded' AND exception_reason = '')
        OR (outcome = 'exception' AND char_length(btrim(exception_reason)) >= 3)
    ),
    CHECK (
        (latitude IS NULL AND longitude IS NULL)
        OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180)
    ),
    UNIQUE (shift_id, action)
);

CREATE UNIQUE INDEX uq_home_base_events_employee_idempotency
    ON home_base_events(employee_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_home_base_events_review
    ON home_base_events(outcome, recorded_at DESC);
CREATE INDEX idx_home_base_events_shift
    ON home_base_events(shift_id, recorded_at);

-- A reviewed import is the immutable approval boundary. The source and full
-- resolved plan fingerprints let approval fail closed if Google changes after
-- preview, while an applied row makes an exact retry idempotent.
CREATE TABLE calendar_import_previews (
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

-- Manual customer/location decisions are durable per Google occurrence or
-- recurring series. They reference existing locations read-only; the importer
-- never creates or edits a customer/site.
CREATE TABLE google_calendar_event_mappings (
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

-- One row is one customer service obligation, including one expanded recurring
-- occurrence. Approximate times are ordering/capacity hints only and have no
-- relationship to shifts, payroll, QR evidence, or exact-arrival schedules.
CREATE TABLE planned_service_visits (
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

-- Assignment changes are retired, never deleted. Exactly one of crew or
-- employee is present so default crews and per-visit individual overrides can
-- coexist without inventing shifts.
CREATE TABLE planned_visit_assignments (
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

CREATE UNIQUE INDEX uq_planned_visit_active_crew_assignment
    ON planned_visit_assignments(planned_visit_id, crew_id)
    WHERE active AND crew_id IS NOT NULL;

CREATE UNIQUE INDEX uq_planned_visit_active_employee_assignment
    ON planned_visit_assignments(planned_visit_id, employee_id)
    WHERE active AND employee_id IS NOT NULL;

-- Explicit-selection provenance for the additive GPS and QR-fallback visit
-- flow. Legacy manual visits stay readable without this row.
CREATE TABLE visit_evidence_events (
    id                 BIGSERIAL PRIMARY KEY,
    visit_id           INTEGER NOT NULL UNIQUE REFERENCES visits(id) ON DELETE CASCADE,
    shift_id           INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    employee_id        INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    location_id        INTEGER NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
    planned_visit_id   BIGINT REFERENCES planned_service_visits(id) ON DELETE SET NULL,
    evidence_method    VARCHAR(32) NOT NULL
                           CHECK (evidence_method IN (
                               'residential_gps',
                               'unplanned_residential',
                               'commercial_qr_fallback'
                           )),
    exception_reason   VARCHAR(64) NOT NULL DEFAULT '',
    exception_detail   TEXT NOT NULL DEFAULT '' CHECK (char_length(exception_detail) <= 500),
    geofence_status    VARCHAR(32) NOT NULL,
    distance_m         NUMERIC(10, 2),
    accuracy_m         NUMERIC(10, 2),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (evidence_method = 'residential_gps'
         AND exception_reason = '' AND exception_detail = '')
        OR (evidence_method = 'unplanned_residential'
            AND exception_reason = 'unplanned_visit'
            AND char_length(btrim(exception_detail)) >= 3)
        OR (evidence_method = 'commercial_qr_fallback'
            AND exception_reason = 'qr_unavailable'
            AND char_length(btrim(exception_detail)) >= 3)
    )
);

CREATE INDEX idx_visit_evidence_events_review
    ON visit_evidence_events(evidence_method, created_at DESC);
CREATE INDEX idx_visit_evidence_events_planned_visit
    ON visit_evidence_events(planned_visit_id, created_at);

-- Append-only domain provenance lives in PostgreSQL with the mutation it
-- describes. It is intentionally separate from the best-effort request log.
CREATE TABLE planned_visit_audit_events (
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

-- Settings (key-value)
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

-- Recoverable before-images for explicitly confirmed time-data corrections.
CREATE TABLE time_data_correction_batches (
    id                     BIGSERIAL PRIMARY KEY,
    plan_token             TEXT NOT NULL UNIQUE,
    applied_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    applied_by_name        TEXT NOT NULL,
    reason                 TEXT NOT NULL,
    snapshot               JSONB NOT NULL,
    result                 JSONB NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Recoverable before-images for explicitly confirmed Atlas-contact linkage
-- backfills (customers.atlas_contact_id filled from an operator mapping).
CREATE TABLE atlas_linkage_backfill_batches (
    id                     BIGSERIAL PRIMARY KEY,
    plan_token             TEXT NOT NULL UNIQUE,
    applied_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    applied_by_name        TEXT NOT NULL,
    reason                 TEXT NOT NULL,
    snapshot               JSONB NOT NULL,
    result                 JSONB NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Durable weekly payroll verification snapshots and audit trail. A payroll
-- batch stores the source fingerprint Mayra verified; events preserve who moved
-- the week through verify/reopen/finalize.
CREATE TABLE payroll_verification_batches (
    id                       BIGSERIAL PRIMARY KEY,
    week_start               DATE NOT NULL UNIQUE,
    week_end                 DATE NOT NULL,
    timezone                 TEXT NOT NULL,
    status                   VARCHAR(16) NOT NULL DEFAULT 'verified'
                                 CHECK (status IN ('verified', 'reopened', 'finalized')),
    source_fingerprint       VARCHAR(64) NOT NULL
                                 CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    snapshot                 JSONB NOT NULL,
    verified_by_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    verified_by_name         TEXT NOT NULL,
    verified_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reopened_by_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    reopened_by_name         TEXT,
    reopened_reason          TEXT,
    reopened_at              TIMESTAMPTZ,
    finalized_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    finalized_by_name        TEXT,
    finalized_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (week_end = week_start + 6)
);

CREATE TABLE payroll_verification_events (
    id                 BIGSERIAL PRIMARY KEY,
    batch_id           BIGINT NOT NULL REFERENCES payroll_verification_batches(id) ON DELETE CASCADE,
    week_start         DATE NOT NULL,
    action             VARCHAR(16) NOT NULL
                           CHECK (action IN ('verify', 'reopen', 'finalize')),
    actor_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    actor_name         TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    source_fingerprint VARCHAR(64) NOT NULL
                           CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    before_state       JSONB,
    after_state        JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Money (payroll dollars) verification is a SECOND, independent truth from the
-- hours sign-off above: it signs off rates, correction amounts, allocations and
-- their live/frozen provenance. It mirrors the hours tables but has NO finalized
-- state -- the payroll-level FINALIZED lives on payroll_verification_batches
-- (the hours batch), gated on a current money verification. source_fingerprint
-- here is the money-inclusive timesheet fingerprint.
CREATE TABLE payroll_money_verification_batches (
    id                       BIGSERIAL PRIMARY KEY,
    week_start               DATE NOT NULL UNIQUE,
    week_end                 DATE NOT NULL,
    timezone                 TEXT NOT NULL,
    status                   VARCHAR(16) NOT NULL DEFAULT 'verified'
                                 CHECK (status IN ('verified', 'reopened')),
    source_fingerprint       VARCHAR(64) NOT NULL
                                 CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    snapshot                 JSONB NOT NULL,
    verified_by_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    verified_by_name         TEXT NOT NULL,
    verified_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reopened_by_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    reopened_by_name         TEXT,
    reopened_reason          TEXT,
    reopened_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (week_end = week_start + 6)
);

CREATE TABLE payroll_money_verification_events (
    id                 BIGSERIAL PRIMARY KEY,
    batch_id           BIGINT NOT NULL REFERENCES payroll_money_verification_batches(id) ON DELETE CASCADE,
    week_start         DATE NOT NULL,
    action             VARCHAR(16) NOT NULL
                           CHECK (action IN ('verify', 'reopen')),
    actor_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    actor_name         TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    source_fingerprint VARCHAR(64) NOT NULL
                           CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    before_state       JSONB,
    after_state        JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE payroll_hour_corrections (
    id                       BIGSERIAL PRIMARY KEY,
    week_start               DATE NOT NULL,
    correction_date          DATE NOT NULL,
    employee_id              INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    corrected_total_minutes  INTEGER NOT NULL CHECK (corrected_total_minutes BETWEEN 0 AND 1440),
    reason                   TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    status                   VARCHAR(16) NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('active', 'superseded', 'voided')),
    created_by_employee_id   INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name          TEXT NOT NULL,
    voided_by_employee_id    INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    voided_by_name           TEXT,
    voided_reason            TEXT,
    voided_at                TIMESTAMPTZ,
    superseded_by            BIGINT REFERENCES payroll_hour_corrections(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (correction_date >= week_start AND correction_date < week_start + 7)
);

CREATE TABLE payroll_hour_correction_allocations (
    id                         BIGSERIAL PRIMARY KEY,
    correction_id              BIGINT NOT NULL REFERENCES payroll_hour_corrections(id) ON DELETE CASCADE,
    week_start                 DATE NOT NULL,
    correction_date            DATE NOT NULL,
    employee_id                INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    location_id                INTEGER NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
    job_id                     INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    allocated_delta_minutes    INTEGER NOT NULL
                                   CHECK (
                                       allocated_delta_minutes BETWEEN -1440 AND 1440
                                       AND allocated_delta_minutes <> 0
                                   ),
    allocated_labor_cost_cents INTEGER,
    -- Provenance of the cost, three-state on purpose:
    --   TRUE  = live-tracked (shift carried no snapshot); cost stored NULL and
    --           valued at the live recompute so it tracks later rate edits.
    --   FALSE = frozen from a snapshot (or fail-closed unknown); the stored
    --           cents are authoritative and a rate edit cannot restate them.
    --   NULL  = not yet reconciled -- a row written before this column existed,
    --           or by an old app instance during a rolling deploy. Such rows are
    --           repriced on the next boot and, until then, are valued at the
    --           live recompute rather than trusted as frozen. NO DEFAULT: a
    --           writer that omits the column must leave it NULL, not FALSE, so
    --           it is distinguishable and reconcilable.
    allocated_labor_cost_is_live BOOLEAN,
    reason                     TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    status                     VARCHAR(16) NOT NULL DEFAULT 'active'
                                   CHECK (status IN ('active', 'superseded', 'voided')),
    created_by_employee_id     INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name            TEXT NOT NULL,
    voided_by_employee_id      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    voided_by_name             TEXT,
    voided_reason              TEXT,
    voided_at                  TIMESTAMPTZ,
    superseded_by              BIGINT REFERENCES payroll_hour_correction_allocations(id)
                                   ON DELETE SET NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (correction_date >= week_start AND correction_date < week_start + 7)
);

CREATE TABLE payroll_shift_corrections (
    id                        BIGSERIAL PRIMARY KEY,
    week_start                DATE NOT NULL,
    correction_date           DATE NOT NULL,
    employee_id               INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    shift_id                  INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    source_clock_in           TIMESTAMPTZ NOT NULL,
    source_clock_out          TIMESTAMPTZ,
    source_break_minutes      INTEGER CHECK (
                                  source_break_minutes IS NULL
                                  OR source_break_minutes BETWEEN 0 AND 1440
                              ),
    source_total_minutes      INTEGER NOT NULL CHECK (source_total_minutes >= 0),
    corrected_clock_in        TIMESTAMPTZ NOT NULL,
    corrected_clock_out       TIMESTAMPTZ NOT NULL,
    corrected_break_minutes   INTEGER NOT NULL DEFAULT 0
                                  CHECK (corrected_break_minutes BETWEEN 0 AND 1440),
    corrected_total_minutes   INTEGER NOT NULL CHECK (corrected_total_minutes BETWEEN 0 AND 1440),
    reason                    TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    status                    VARCHAR(16) NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'superseded', 'voided')),
    created_by_employee_id    INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name           TEXT NOT NULL,
    voided_by_employee_id     INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    voided_by_name            TEXT,
    voided_reason             TEXT,
    voided_at                 TIMESTAMPTZ,
    superseded_by             BIGINT REFERENCES payroll_shift_corrections(id) ON DELETE SET NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (correction_date >= week_start AND correction_date < week_start + 7),
    CHECK (corrected_clock_out > corrected_clock_in)
);

CREATE TABLE payroll_timesheet_change_batches (
    id                          BIGSERIAL PRIMARY KEY,
    request_id                  UUID NOT NULL UNIQUE,
    request_fingerprint         VARCHAR(64) NOT NULL
                                    CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    week_start                  DATE NOT NULL,
    employee_id                 INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    reason                      TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    operations                  JSONB NOT NULL,
    before_source_fingerprint   VARCHAR(64) NOT NULL
                                    CHECK (before_source_fingerprint ~ '^[0-9a-f]{64}$'),
    after_source_fingerprint    VARCHAR(64)
                                    CHECK (
                                        after_source_fingerprint IS NULL
                                        OR after_source_fingerprint ~ '^[0-9a-f]{64}$'
                                    ),
    created_by_employee_id      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name             TEXT NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE payroll_manual_shift_versions (
    id                        BIGSERIAL PRIMARY KEY,
    manual_shift_id           UUID NOT NULL,
    version                   INTEGER NOT NULL CHECK (version > 0),
    week_start                DATE NOT NULL,
    work_date                 DATE NOT NULL,
    employee_id               INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    clock_in                  TIMESTAMPTZ NOT NULL,
    clock_out                 TIMESTAMPTZ NOT NULL,
    break_minutes             INTEGER NOT NULL DEFAULT 0 CHECK (break_minutes BETWEEN 0 AND 1440),
    total_minutes             INTEGER NOT NULL CHECK (total_minutes BETWEEN 0 AND 1440),
    location_id               INTEGER REFERENCES locations(id) ON DELETE RESTRICT,
    included                  BOOLEAN NOT NULL DEFAULT TRUE,
    status                    VARCHAR(16) NOT NULL DEFAULT 'current'
                                  CHECK (status IN ('current', 'superseded')),
    reason                    TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    change_batch_id           BIGINT NOT NULL REFERENCES payroll_timesheet_change_batches(id)
                                  ON DELETE RESTRICT,
    created_by_employee_id    INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name           TEXT NOT NULL,
    superseded_by             BIGINT REFERENCES payroll_manual_shift_versions(id) ON DELETE SET NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (manual_shift_id, version),
    CHECK (work_date >= week_start AND work_date < week_start + 7),
    CHECK (clock_out > clock_in)
);

CREATE TABLE payroll_shift_exclusions (
    id                        BIGSERIAL PRIMARY KEY,
    week_start                DATE NOT NULL,
    employee_id               INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    shift_id                  INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    reason                    TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
    status                    VARCHAR(16) NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'voided')),
    change_batch_id           BIGINT NOT NULL REFERENCES payroll_timesheet_change_batches(id)
                                  ON DELETE RESTRICT,
    created_by_employee_id    INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_by_name           TEXT NOT NULL,
    voided_by_employee_id     INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    voided_by_name            TEXT,
    voided_reason             TEXT,
    voided_by_change_batch_id BIGINT REFERENCES payroll_timesheet_change_batches(id)
                                  ON DELETE RESTRICT,
    voided_at                 TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status <> 'voided' OR voided_at IS NOT NULL)
);

-- Durable business-scoped operation identity for Atlas money writes. The row
-- survives browser/tab/admin changes and is resolved only after Atlas confirms
-- the result, so an ambiguous retry cannot mint a second receipt. Payment
-- identities intentionally reserve an exact customer/method/reference tuple.
-- A confirmed void retires that generation: the exact retired request remains
-- blocked as stale, while one corrected request with a fresh key may become the
-- next active generation.
CREATE TABLE receivables_operation_attempts (
    attempt_id          BIGSERIAL PRIMARY KEY,
    operation_identity  VARCHAR(64) NOT NULL,
    request_fingerprint VARCHAR(64) NOT NULL,
    operation           VARCHAR(96) NOT NULL,
    idempotency_key     VARCHAR(128) NOT NULL UNIQUE,
    state               VARCHAR(16) NOT NULL DEFAULT 'pending'
                            CHECK (state IN ('pending', 'resolved', 'voided')),
    response_body       JSONB,
    created_by          VARCHAR(128) NOT NULL,
    last_attempt_by     VARCHAR(128) NOT NULL,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default settings
INSERT INTO settings (key, value) VALUES ('laborPctTarget', '35.0');

-- Indexes
CREATE INDEX idx_shifts_employee_id ON shifts(employee_id);
CREATE INDEX idx_shifts_clock_in    ON shifts(clock_in);
CREATE INDEX idx_shifts_local_date  ON shifts(local_date);
CREATE INDEX idx_shifts_location_id ON shifts(location_id);
CREATE INDEX idx_visits_shift_id    ON visits(shift_id);
CREATE INDEX idx_visits_arrival     ON visits(arrival_time);
CREATE INDEX idx_visits_location_id ON visits(location_id);
CREATE INDEX idx_visits_job_id      ON visits(job_id);
CREATE INDEX idx_departures_shift_id ON departures(shift_id);
CREATE INDEX idx_departures_time     ON departures(departure_time);
CREATE INDEX idx_departures_location_id ON departures(location_id);
CREATE UNIQUE INDEX uq_departures_visit_id
    ON departures(visit_id) WHERE visit_id IS NOT NULL;
CREATE UNIQUE INDEX uq_visits_site_check_in_id
    ON visits(site_check_in_id) WHERE site_check_in_id IS NOT NULL;
CREATE INDEX idx_jobs_location_id    ON jobs(location_id);
CREATE INDEX idx_jobs_scheduled_date ON jobs(scheduled_date);
CREATE INDEX idx_jobs_customer       ON jobs(customer_name);
CREATE INDEX idx_jobs_status         ON jobs(status);
CREATE INDEX idx_shifts_job_id       ON shifts(job_id);
CREATE INDEX idx_shifts_time_cat     ON shifts(time_category);
CREATE INDEX idx_shifts_clock_out    ON shifts(clock_out);
CREATE INDEX idx_customers_active    ON customers(active);
CREATE INDEX idx_locations_active    ON locations(active);
CREATE INDEX idx_locations_customer_id ON locations(customer_id);
CREATE INDEX idx_locations_active_residential_coordinates
    ON locations(lat, lng)
    WHERE active
      AND location_type = 'Residential'
      AND lat IS NOT NULL
      AND lng IS NOT NULL;
CREATE UNIQUE INDEX uq_locations_address_key
    ON locations(address_key) WHERE address_key IS NOT NULL;
CREATE INDEX idx_employees_active    ON employees(active);
CREATE UNIQUE INDEX uq_access_log_entries_event_id
    ON access_log_entries(event_id);
CREATE INDEX idx_access_log_entries_local_date
    ON access_log_entries(local_date, logged_at, id);
CREATE INDEX idx_access_log_entries_logged_at
    ON access_log_entries(logged_at);
CREATE INDEX idx_site_check_in_schedules_lookup
    ON site_check_in_schedules(employee_id, location_id, scheduled_start);
CREATE INDEX idx_site_check_in_schedule_rules_lookup
    ON site_check_in_schedule_rules(employee_id, location_id, active, starts_on, ends_on);
CREATE INDEX idx_site_check_ins_employee_time
    ON site_check_ins(employee_id, server_checked_in_at DESC);
CREATE INDEX idx_site_check_ins_job_time
    ON site_check_ins(job_id, server_checked_in_at DESC)
    WHERE job_id IS NOT NULL;
CREATE INDEX idx_site_check_ins_review
    ON site_check_ins(review_status, server_checked_in_at DESC);
CREATE INDEX idx_site_qr_action_receipts_shift
    ON site_qr_action_receipts(shift_id, server_recorded_at DESC);
CREATE INDEX idx_plain_time_action_receipts_shift
    ON plain_time_action_receipts(shift_id, server_recorded_at DESC);
CREATE INDEX idx_site_check_in_reconciliation_reviews_lookup
    ON site_check_in_reconciliation_reviews(
        occurrence_key, evidence_fingerprint, reviewed_at DESC
    );
CREATE INDEX idx_time_data_correction_batches_created
    ON time_data_correction_batches(created_at);
CREATE INDEX idx_atlas_linkage_backfill_batches_created
    ON atlas_linkage_backfill_batches(created_at);
CREATE INDEX idx_payroll_verification_batches_status_week
    ON payroll_verification_batches(status, week_start);
CREATE INDEX idx_payroll_verification_events_week
    ON payroll_verification_events(week_start, created_at);
CREATE INDEX idx_payroll_verification_events_batch
    ON payroll_verification_events(batch_id, created_at);
CREATE INDEX idx_payroll_money_verification_batches_status_week
    ON payroll_money_verification_batches(status, week_start);
CREATE INDEX idx_payroll_money_verification_events_week
    ON payroll_money_verification_events(week_start, created_at);
CREATE INDEX idx_payroll_money_verification_events_batch
    ON payroll_money_verification_events(batch_id, created_at);
CREATE UNIQUE INDEX uq_payroll_hour_corrections_active_day
    ON payroll_hour_corrections(week_start, employee_id, correction_date)
    WHERE status = 'active';
CREATE INDEX idx_payroll_hour_corrections_week
    ON payroll_hour_corrections(week_start, status, correction_date);
CREATE UNIQUE INDEX uq_payroll_hour_correction_allocations_active
    ON payroll_hour_correction_allocations(correction_id)
    WHERE status = 'active';
CREATE INDEX idx_payroll_hour_correction_allocations_week
    ON payroll_hour_correction_allocations(week_start, status, correction_date);
CREATE UNIQUE INDEX uq_payroll_shift_corrections_active_shift
    ON payroll_shift_corrections(week_start, shift_id)
    WHERE status = 'active';
CREATE INDEX idx_payroll_shift_corrections_week
    ON payroll_shift_corrections(week_start, status, correction_date);
CREATE INDEX idx_payroll_timesheet_change_batches_week
    ON payroll_timesheet_change_batches(week_start, employee_id, created_at);
CREATE UNIQUE INDEX uq_payroll_manual_shift_versions_current
    ON payroll_manual_shift_versions(manual_shift_id)
    WHERE status = 'current';
CREATE INDEX idx_payroll_manual_shift_versions_week
    ON payroll_manual_shift_versions(week_start, employee_id, work_date, status);
CREATE UNIQUE INDEX uq_payroll_shift_exclusions_active
    ON payroll_shift_exclusions(week_start, shift_id)
    WHERE status = 'active';
CREATE INDEX idx_payroll_shift_exclusions_week
    ON payroll_shift_exclusions(week_start, employee_id, status);
CREATE INDEX idx_receivables_operation_attempts_state
    ON receivables_operation_attempts(state, updated_at);
CREATE UNIQUE INDEX uq_receivables_operation_attempts_active_identity
    ON receivables_operation_attempts(operation_identity)
    WHERE state IN ('pending', 'resolved');
CREATE INDEX idx_google_calendar_oauth_states_expiry
    ON google_calendar_oauth_states(expires_at, consumed_at);
CREATE INDEX idx_google_calendar_sources_connection
    ON google_calendar_sources(connection_id, role);
CREATE INDEX idx_jobs_calendar_source_window
    ON jobs(calendar_source_id, scheduled_start, status);
CREATE INDEX idx_crew_memberships_effective
    ON crew_memberships(crew_id, effective_from, effective_to);
CREATE INDEX idx_calendar_import_previews_status
    ON calendar_import_previews(status, expires_at);
CREATE INDEX idx_google_calendar_event_mappings_source
    ON google_calendar_event_mappings(connection_id, calendar_id, source_key);
CREATE UNIQUE INDEX uq_google_calendar_event_mappings_series
    ON google_calendar_event_mappings(connection_id, calendar_id, source_series_id)
    WHERE mapping_scope = 'series' AND source_series_id IS NOT NULL;
CREATE INDEX idx_planned_service_visits_window
    ON planned_service_visits(approximate_start, status);
CREATE INDEX idx_planned_service_visits_source
    ON planned_service_visits(connection_id, source_calendar_id, source_series_id);
CREATE INDEX idx_planned_visit_assignments_visit
    ON planned_visit_assignments(planned_visit_id, active);
CREATE INDEX idx_planned_visit_audit_events_visit
    ON planned_visit_audit_events(planned_visit_id, created_at);
