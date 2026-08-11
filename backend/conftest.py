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
os.environ.setdefault("LOGIN_RATE_LIMIT_MAX", "0")
os.environ.setdefault("REGISTER_RATE_LIMIT_MAX", "0")
os.environ.setdefault("ALLOW_PUBLIC_REGISTRATION", "false")
os.environ.setdefault("ALLOWED_ORIGINS", "https://trusted.example")
os.environ.setdefault("GOOGLE_CALENDAR_CLIENT_ID", "test-google-client")
os.environ.setdefault("GOOGLE_CALENDAR_CLIENT_SECRET", "test-google-secret")
os.environ.setdefault(
    "GOOGLE_CALENDAR_REDIRECT_URI",
    "https://api.example.test/api/google-calendar/oauth/callback",
)
os.environ.setdefault(
    "GOOGLE_CALENDAR_TOKEN_ENCRYPTION_KEY",
    "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
)
os.environ.setdefault(
    "GOOGLE_CALENDAR_PORTAL_URL", "https://portal.example.test/portal.html"
)
os.environ.setdefault("PUBLIC_APP_URL", "https://portal.example.test")

SCHEMA_FILE = BACKEND_DIR / "schema.sql"


def _raw_conn():
    return psycopg2.connect(TEST_DB_URL, sslmode="disable")


def _apply_schema(conn):
    """Drop and recreate all tables from schema.sql."""
    with conn.cursor() as cur:
        cur.execute("""
            DROP TABLE IF EXISTS access_log_entries,
                planned_visit_audit_events,
                planned_visit_assignments, planned_service_visits,
                google_calendar_event_mappings, calendar_import_previews,
                crew_memberships, crews, google_calendar_oauth_states,
                google_calendar_sources, google_calendar_connections,
                eom_lead_working,
                eom_customer_atlas_reservations,
                eom_office_conversion_handoffs,
                receivables_operation_attempts,
                payroll_shift_exclusions,
                payroll_manual_shift_versions,
                payroll_timesheet_change_batches,
                payroll_shift_corrections,
                payroll_hour_correction_allocations,
                payroll_hour_corrections,
                payroll_money_verification_events, payroll_money_verification_batches,
                payroll_verification_events, payroll_verification_batches,
                time_data_correction_batches,
                atlas_linkage_backfill_batches,
                plain_time_action_receipts,
                site_qr_action_receipts,
                site_check_in_reconciliation_reviews, site_check_ins,
                arrival_policy_revisions,
                service_schedule_rules,
                site_check_in_schedule_rules, site_check_in_schedules,
                schedules, departures, visits,
                shifts, jobs, locations, customers, employees, settings CASCADE
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
            INSERT INTO locations (
                address, customer_name, lat, lng,
                rate, rate_type, expected_hours
            )
            VALUES (
                '123 Main St, Effingham', 'Test Customer', 39.1203, -88.54335,
                150.00, 'per_visit', 3.0
            )
            ON CONFLICT (address) DO NOTHING
            """,
        )
    conn.commit()


@pytest.fixture(autouse=True)
def clear_receivables_operation_attempts(setup_db):
    """Keep operation replay records isolated between API test cases."""
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM receivables_operation_attempts")
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def clear_access_log_entries(setup_db):
    """Keep request-log rows isolated between API test cases."""
    conn = _raw_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM access_log_entries")
    conn.commit()
    conn.close()


# Every capability the deployed Atlas advertises today. Kept here rather than in
# one test module because Customer creation now needs
# `contact.operator_mutation` on any suite that creates a Customer.
ATLAS_FULL_CAPABILITIES = [
    "contact.operator_mutation",
    "lead.customer_handoff",
    "lead.estimate_booking",
    "lead.first_clean_booking",
    "lead.lost",
    "lead.reopen",
    "onboarding.draft.approve_send",
    "onboarding.draft.confirm_sent",
    "onboarding.draft.edit",
    "onboarding.draft.list",
    "onboarding.draft.revoke",
]


def fake_atlas_contact_id(idempotency_key: str) -> str:
    """The contact id the fake Atlas assigns for one idempotency key.

    Derived from the key, not random, so a replay resolves to the SAME contact
    exactly as the real Atlas receipt does. Tests assert on that identity.
    """
    import uuid as _uuid

    return str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"atlas-operator-contact:{idempotency_key}"))


class _FakeAtlasResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def stub_atlas_funnel(setup_db, monkeypatch):
    """Default every test to a healthy, fully-capable Atlas.

    Since Slice 0C, creating a Customer calls Atlas, so without this seam the
    unrelated Customer/Site suites would fail on funnel configuration rather
    than on what they actually assert.

    Deliberately patched at the HTTP boundary (`requests`) rather than at
    `_atlas_funnel_request` / `_atlas_funnel_read`: the real transport, header,
    and error-mapping code then still runs, and the suites that unit-test that
    transport by patching `requests` themselves keep working. Because this
    fixture is autouse it is set up first, so any explicit per-test monkeypatch
    -- at either level -- wins.
    """
    import time_tracker_api as api

    def _get(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            # Default: Atlas recognizes every id the tracker submits, so the
            # linkage audit reports no dangling links. A test that wants a
            # dangling link overrides api.requests.get to omit the planted id.
            submitted = list((params or {}).get("contact_id") or [])
            return _FakeAtlasResponse(
                200,
                {
                    "knownContactIds": [str(value) for value in submitted],
                    "checked": len(submitted),
                    "limit": 100,
                },
            )
        return _FakeAtlasResponse(
            200,
            {
                "leads": [],
                "cursor": None,
                "hasMore": False,
                "nextCursor": None,
                "capabilities": list(ATLAS_FULL_CAPABILITIES),
            },
        )

    def _post(url, *, headers=None, json=None, timeout=None):
        if not str(url).endswith(api.ATLAS_OPERATOR_CONTACTS_PATH):
            raise AssertionError(f"unstubbed Atlas funnel call: {url}")
        key = (headers or {}).get("Idempotency-Key", "")
        return _FakeAtlasResponse(
            201,
            {
                "success": True,
                "contactId": fake_atlas_contact_id(key),
                "operation": "contact_created",
                "idempotent": False,
                "contact": {},
            },
        )

    monkeypatch.setattr(api, "ATLAS_FUNNEL_BASE_URL", "https://atlas.example.test/api/v1")
    monkeypatch.setattr(api, "ATLAS_FUNNEL_SERVICE_TOKEN", "tracker-only-test-token")
    monkeypatch.setattr(api.requests, "get", _get)
    monkeypatch.setattr(api.requests, "post", _post)


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
        "latitude": 39.1203,
        "longitude": -88.54335,
    })
    assert ci.status_code == 200, ci.text
    entry_id = ci.json()["entry"]["id"]

    co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
        "notes": "test shift",
        "latitude": 39.1203,
        "longitude": -88.54335,
    })
    assert co.status_code == 200, co.text
    return entry_id
