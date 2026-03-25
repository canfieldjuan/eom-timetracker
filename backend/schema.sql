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
    lat             NUMERIC(10, 7),
    lng             NUMERIC(10, 7),
    active        BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
