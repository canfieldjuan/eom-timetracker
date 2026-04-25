"""
Test configuration - sets up a fresh local PostgreSQL schema before the
session and tears it down afterwards.  Every test module gets a clean DB.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import bcrypt
import psycopg2
import pytest
from fastapi.testclient import TestClient

# -- path setup ----------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

TEST_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://eom_test:eom_test@localhost:5433/eom_test",
)
os.environ["DATABASE_URL"] = TEST_DB_URL
os.environ.setdefault("JWT_SECRET", "test_secret_at_least_32_chars_long_yes")
os.environ.setdefault("TIMEZONE", "America/Chicago")
os.environ.setdefault("ALLOWED_DAYS", "0,1,2,3,4,5,6")   # all days
os.environ.setdefault("ACCESS_START_HOUR", "0")
os.environ.setdefault("ACCESS_END_HOUR", "24")
os.environ.setdefault("ALLOWED_IPS", "")
os.environ.setdefault("TOKEN_TTL_HOURS", "12")
os.environ.setdefault("MAX_ACTIVE_SHIFT_HOURS", "24")
os.environ.setdefault("AUTO_CLOSE_STALE_SHIFTS", "false")

SCHEMA_FILE = BACKEND_DIR / "schema.sql"


def _raw_conn():
    return psycopg2.connect(TEST_DB_URL, sslmode="disable")


def _apply_schema(conn):
    """Drop and recreate all tables from schema.sql."""
    with conn.cursor() as cur:
        cur.execute("""
            DROP TABLE IF EXISTS schedules, departures, visits, shifts, jobs, locations, employees, settings CASCADE
        """)
    conn.commit()
    sql = SCHEMA_FILE.read_text()
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()


def _seed(conn):
    """Insert a minimal admin + employee so auth tests work."""
    admin_hash = bcrypt.hashpw(b"canfield1", bcrypt.gensalt(10)).decode()
    emp_hash   = bcrypt.hashpw(b"gomez1",    bcrypt.gensalt(10)).decode()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO employees (name, password_hash, role, hourly_rate)
            VALUES (%s, %s, 'admin',    17.00),
                   (%s, %s, 'employee', 16.75)
            ON CONFLICT (name) DO NOTHING
            """,
            ("Juan Canfield", admin_hash, "Catalina Gomez", emp_hash),
        )
        cur.execute(
            """
            INSERT INTO locations (address, customer_name, rate, rate_type, expected_hours)
            VALUES ('123 Main St, Effingham', 'Test Customer', 150.00, 'per_visit', 3.0)
            ON CONFLICT (address) DO NOTHING
            """,
        )
    conn.commit()


# -- session-scoped fixtures ----------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Recreate schema once per test session."""
    conn = _raw_conn()
    _apply_schema(conn)
    _seed(conn)
    conn.close()
    yield
    # Optionally keep tables for inspection; uncomment to tear down:
    # conn = _raw_conn(); conn.cursor().execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public"); conn.commit(); conn.close()


@pytest.fixture(scope="session")
def client(setup_db):
    import db as db_module
    db_module._pool = None          # reset pool between test runs if re-used
    db_module.init_pool(TEST_DB_URL)

    from time_tracker_api import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# -- helper fixtures ------------------------------------------------------------

@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post("/api/auth/login", json={"name": "Juan Canfield", "password": "canfield1"})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


@pytest.fixture(scope="session")
def emp_token(client):
    resp = client.post("/api/auth/login", json={"name": "Catalina Gomez", "password": "gomez1"})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


@pytest.fixture(scope="session")
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def emp_auth(emp_token):
    return {"Authorization": f"Bearer {emp_token}"}


@pytest.fixture(scope="session")
def employee_id(client, auth):
    resp = client.get("/api/admin/employees", headers=auth)
    emps = resp.json()["employees"]
    return next(e["id"] for e in emps if e["name"] == "Catalina Gomez")


@pytest.fixture(scope="session")
def location_id():
    """Return the DB id for the seeded test location."""
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM locations WHERE address = '123 Main St, Effingham'")
        row = cur.fetchone()
    conn.close()
    assert row, "Seed location not found in DB"
    return row[0]


@pytest.fixture(scope="session")
def completed_shift_id(client, emp_auth, employee_id, location_id):
    """Create and clock-out a shift owned by the employee, return its ID."""
    ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
        "location": "123 Main St, Effingham",
    })
    assert ci.status_code == 200, ci.text
    entry_id = ci.json()["entry"]["id"]

    co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
        "notes": "test shift",
    })
    assert co.status_code == 200, co.text
    return entry_id
