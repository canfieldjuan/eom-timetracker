-- EOM Employee Management — PostgreSQL Schema
-- Run once against a fresh database

-- Employees
CREATE TABLE employees (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT true,
    role          TEXT NOT NULL DEFAULT 'employee'
                      CHECK (role IN ('admin', 'employee')),
    hourly_rate   NUMERIC(8, 2),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Locations (customers / job sites)
CREATE TABLE locations (
    id            SERIAL PRIMARY KEY,
    address       TEXT NOT NULL UNIQUE,
    customer_name TEXT,
    location_type TEXT CHECK (location_type IN ('Residential', 'Commercial')),
    rate          NUMERIC(8, 2),
    rate_type     TEXT NOT NULL DEFAULT 'per_visit'
                      CHECK (rate_type IN ('per_visit', 'hourly', 'monthly')),
    frequency       TEXT,
    expected_hours  NUMERIC(6, 2),
    target_labor_pct  NUMERIC(5, 2),
    min_margin_pct    NUMERIC(5, 2),
    lat             NUMERIC(10, 7),
    lng             NUMERIC(10, 7),
    active        BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Jobs (service visits / scheduled work at a customer)
CREATE TABLE jobs (
    id              SERIAL PRIMARY KEY,
    location_id     INTEGER REFERENCES locations(id),
    customer_name   TEXT NOT NULL,
    scheduled_date  DATE NOT NULL,
    expected_hours  NUMERIC(6, 2),
    revenue         NUMERIC(10, 2),
    notes           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'scheduled'
                        CHECK (status IN ('scheduled', 'in_progress', 'completed', 'cancelled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Shifts (time entries)
CREATE TABLE shifts (
    id            SERIAL PRIMARY KEY,
    employee_id   INTEGER NOT NULL REFERENCES employees(id),
    location_id   INTEGER REFERENCES locations(id),
    clock_in      TIMESTAMPTZ NOT NULL,
    clock_out     TIMESTAMPTZ,
    total_hours   NUMERIC(6, 2),
    notes         TEXT NOT NULL DEFAULT '',
    local_date    DATE,
    timezone      TEXT NOT NULL DEFAULT 'America/Chicago',
    clock_in_gps  JSONB,
    clock_out_gps JSONB,
    job_id        INTEGER REFERENCES jobs(id),
    time_category     TEXT NOT NULL DEFAULT 'productive'
                          CHECK (time_category IN ('productive', 'non_productive')),
    non_productive_type TEXT
                          CHECK (non_productive_type IS NULL OR non_productive_type IN
                                 ('drive_time', 'waiting', 'supply_run', 'rework', 'lockout', 'other')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Visits (multi-stop tracking within a shift)
CREATE TABLE visits (
    id            SERIAL PRIMARY KEY,
    shift_id      INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    location_id   INTEGER REFERENCES locations(id),
    customer_name TEXT,
    arrival_time  TIMESTAMPTZ NOT NULL,
    gps           JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Schedules (planned hours per employee per customer per week)
CREATE TABLE schedules (
    id              SERIAL PRIMARY KEY,
    employee_id     INTEGER NOT NULL REFERENCES employees(id),
    location_id     INTEGER REFERENCES locations(id),
    customer_name   TEXT NOT NULL,
    week_start      DATE NOT NULL,
    scheduled_hours NUMERIC(6, 2) NOT NULL,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (employee_id, customer_name, week_start)
);

CREATE INDEX idx_schedules_week ON schedules(week_start);
CREATE INDEX idx_schedules_employee ON schedules(employee_id);

-- Settings (key-value)
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
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
CREATE INDEX idx_jobs_location_id    ON jobs(location_id);
CREATE INDEX idx_jobs_scheduled_date ON jobs(scheduled_date);
CREATE INDEX idx_jobs_customer       ON jobs(customer_name);
CREATE INDEX idx_jobs_status         ON jobs(status);
CREATE INDEX idx_shifts_job_id       ON shifts(job_id);
