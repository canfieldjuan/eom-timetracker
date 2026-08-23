"""Integration contract for the administrator's immediate time-record exception."""

from __future__ import annotations

import bcrypt
from contextlib import contextmanager
from datetime import date, datetime, timezone
from uuid import uuid4

import psycopg2
import pytest

import db
import time_tracker_api as api
from conftest import _raw_conn


PREFIX = "ADMIN_DIRECT_TIME_RECORD_TEST"
HOME_BASE_LABEL = f"{PREFIX} Home Base"


def _clean_rows() -> None:
    conn = _raw_conn()
    with conn.cursor() as cur:
        # The receipt is intentionally immutable, even in test cleanup. It has
        # no foreign keys, so fixture shifts and employees can be removed without
        # weakening that production invariant.
        cur.execute(
            "DELETE FROM shifts WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM crew_memberships WHERE employee_id IN "
            "(SELECT id FROM employees WHERE name LIKE %s)",
            (f"{PREFIX}%",),
        )
        cur.execute(
            "DELETE FROM home_base_policies WHERE home_base_id IN "
            "(SELECT id FROM home_bases WHERE label = %s)",
            (HOME_BASE_LABEL,),
        )
        cur.execute("DELETE FROM home_bases WHERE label = %s", (HOME_BASE_LABEL,))
        cur.execute("DELETE FROM locations WHERE address LIKE %s", (f"{PREFIX}%",))
        cur.execute("DELETE FROM customers WHERE name LIKE %s", (f"{PREFIX}%",))
        cur.execute("DELETE FROM employees WHERE name LIKE %s", (f"{PREFIX}%",))
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def isolate_admin_direct_time_record_data(setup_db):
    _clean_rows()
    yield
    _clean_rows()


def _create_employee(client, suffix: str) -> tuple[int, dict[str, str]]:
    name = f"{PREFIX} {suffix}"
    password = "admin-direct-time-record-password"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode()
    row = db.query_one(
        """
        INSERT INTO employees (name, password_hash, role, hourly_rate)
        VALUES (%s, %s, 'employee', 18.25)
        RETURNING id
        """,
        (name, password_hash),
    )
    assert row
    login = client.post("/api/auth/login", json={"name": name, "password": password})
    assert login.status_code == 200, login.text
    return int(row["id"]), {"Authorization": f"Bearer {login.json()['token']}"}


def _create_site(suffix: str) -> int:
    customer_name = f"{PREFIX} Customer {suffix}"
    customer = db.query_one(
        "INSERT INTO customers (name) VALUES (%s) RETURNING id",
        (customer_name,),
    )
    assert customer
    site = db.query_one(
        """
        INSERT INTO locations (
            customer_id, address, customer_name, location_type, lat, lng
        ) VALUES (%s, %s, %s, 'Residential', 39.1203, -88.54335)
        RETURNING id
        """,
        (int(customer["id"]), f"{PREFIX} Site {suffix}", customer_name),
    )
    assert site
    return int(site["id"])


def _enroll_in_morning_crew(employee_id: int) -> None:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO crews (name, active)
                VALUES ('Morning Crew', true)
                ON CONFLICT (name) DO UPDATE SET active = true
                RETURNING id
                """
            )
            crew_id = int(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO crew_memberships (crew_id, employee_id, effective_from)
                VALUES (%s, %s, %s)
                ON CONFLICT (crew_id, employee_id, effective_from) DO NOTHING
                """,
                (crew_id, employee_id, date(2000, 1, 1)),
            )


def _configure_home_base(client, auth: dict[str, str]) -> int:
    response = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": HOME_BASE_LABEL,
            "address": f"{PREFIX} 100 Dispatch Lane",
            "latitude": 39.2,
            "longitude": -88.6,
        },
    )
    assert response.status_code == 200, response.text
    return int(response.json()["homeBase"]["id"])


def _payload(employee_id: int, site_id: int, *, action: str = "clock-in") -> dict:
    return {
        "employeeId": employee_id,
        "action": action,
        "targetKind": "site",
        "siteId": site_id,
        "reason": "Office device outage",
        "detail": "Supervisor recorded the immediate time event from the office.",
        "idempotencyKey": str(uuid4()),
    }


def _clock_out_payload(employee_id: int) -> dict:
    return {
        "employeeId": employee_id,
        "action": "clock-out",
        "targetKind": "unverified-end",
        "reason": "Employee phone battery died",
        "detail": "Supervisor closed the open shift after speaking with the employee.",
        "idempotencyKey": str(uuid4()),
    }


def test_direct_clock_in_is_admin_only_server_timed_and_audited(client, auth, monkeypatch):
    employee_id, employee_auth = _create_employee(client, "admin only")
    site_id = _create_site("admin only")
    body = _payload(employee_id, site_id)

    employee_attempt = client.post(
        "/api/admin/time-actions/direct-record",
        headers=employee_auth,
        json=body,
    )
    assert employee_attempt.status_code == 403

    rejected_client_time = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={**body, "recordedAt": "2020-01-01T00:00:00Z"},
    )
    assert rejected_client_time.status_code == 422

    rejected_client_gps = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={**body, "latitude": 39.1203},
    )
    assert rejected_client_gps.status_code == 422

    recorded_at = datetime(2026, 8, 22, 15, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(api, "utc_now", lambda: recorded_at)
    response = client.post(
        "/api/admin/time-actions/direct-record", headers=auth, json=body
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["action"] == "clock-in"
    assert result["recordedAt"] == "2026-08-22T15:30:00Z"
    assert result["recordedSource"] == "admin_recorded"
    assert result["replayed"] is False
    assert result["target"] == {
        "kind": "site",
        "id": site_id,
        "label": f"{PREFIX} Site admin only",
        "customerName": f"{PREFIX} Customer admin only",
    }
    assert result["entry"]["recordedSource"] == "admin_recorded"
    assert result["entry"]["clockInGps"] is None
    assert result["entry"]["clockInGpsMeta"] == {
        "adminRecorded": True,
        "reason": "Office device outage",
        "detail": "Supervisor recorded the immediate time event from the office.",
    }

    stored_shift = db.query_one(
        """
        SELECT employee_id, location_id, clock_in, recorded_source, clock_in_gps,
               clock_in_gps_meta
        FROM shifts WHERE id = %s
        """,
        (int(result["entry"]["id"]),),
    )
    assert stored_shift == {
        "employee_id": employee_id,
        "location_id": site_id,
        "clock_in": recorded_at,
        "recorded_source": "admin_recorded",
        "clock_in_gps": None,
        "clock_in_gps_meta": {
            "adminRecorded": True,
            "reason": "Office device outage",
            "detail": "Supervisor recorded the immediate time event from the office.",
        },
    }
    receipt = db.query_one(
        """
        SELECT action, target_kind, target_id, reason, detail, server_recorded_at,
               shift_id, visit_id
        FROM admin_direct_time_action_receipts
        WHERE id = %s
        """,
        (int(result["receipt"]["id"]),),
    )
    assert receipt == {
        "action": "clock-in",
        "target_kind": "site",
        "target_id": site_id,
        "reason": "Office device outage",
        "detail": "Supervisor recorded the immediate time event from the office.",
        "server_recorded_at": recorded_at,
        "shift_id": int(result["entry"]["id"]),
        "visit_id": None,
    }


def test_direct_record_samples_its_timestamp_after_timesheet_serialization(
    client, auth, monkeypatch
):
    employee_id, _ = _create_employee(client, "serialized timestamp")
    site_id = _create_site("serialized timestamp")
    preflight_at = datetime(2026, 8, 22, 15, 30, tzinfo=timezone.utc)
    recorded_at = datetime(2026, 8, 22, 15, 31, tzinfo=timezone.utc)
    lock_held = False

    @contextmanager
    def tracked_timesheet_lock():
        nonlocal lock_held
        lock_held = True
        try:
            yield
        finally:
            lock_held = False

    monkeypatch.setattr(api, "timesheet_postgres_advisory_lock", tracked_timesheet_lock)
    monkeypatch.setattr(
        api,
        "utc_now",
        lambda: recorded_at if lock_held else preflight_at,
    )

    response = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json=_payload(employee_id, site_id),
    )

    assert response.status_code == 200, response.text
    assert response.json()["recordedAt"] == "2026-08-22T15:31:00Z"
    assert db.query_one(
        "SELECT clock_in FROM shifts WHERE employee_id = %s",
        (employee_id,),
    ) == {"clock_in": recorded_at}


def test_home_base_config_advertises_direct_record_capability(client, auth):
    response = client.get("/api/admin/home-base", headers=auth)

    assert response.status_code == 200, response.text
    assert response.json()["adminDirectRecordEnabled"] is True
    assert response.json()["adminDirectClockOutEnabled"] is True


def test_direct_record_replays_once_and_its_receipt_is_immutable(client, auth):
    employee_id, _ = _create_employee(client, "replay")
    site_id = _create_site("replay")
    body = _payload(employee_id, site_id)

    first = client.post("/api/admin/time-actions/direct-record", headers=auth, json=body)
    assert first.status_code == 200, first.text
    replay = client.post("/api/admin/time-actions/direct-record", headers=auth, json=body)
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["receipt"] == first.json()["receipt"]
    assert replay.json()["entry"]["id"] == first.json()["entry"]["id"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 1}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM admin_direct_time_action_receipts "
        "WHERE employee_id = %s",
        (employee_id,),
    ) == {"count": 1}

    changed = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={**body, "detail": "A different detail must not reuse the receipt key."},
    )
    assert changed.status_code == 409

    with pytest.raises(psycopg2.Error, match="receipts are immutable"):
        db.execute(
            "UPDATE admin_direct_time_action_receipts SET detail = 'changed' "
            "WHERE id = %s",
            (int(first.json()["receipt"]["id"]),),
        )


def test_direct_clock_out_closes_only_the_open_shift_with_an_unverified_end(
    client, auth, monkeypatch
):
    employee_id, _ = _create_employee(client, "unverified end")
    site_id = _create_site("unverified end")
    started_at = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
    ended_at = datetime(2026, 8, 22, 16, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(api, "utc_now", lambda: started_at)
    opened = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json=_payload(employee_id, site_id),
    )
    assert opened.status_code == 200, opened.text

    monkeypatch.setattr(api, "utc_now", lambda: ended_at)
    body = _clock_out_payload(employee_id)
    closed = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json=body,
    )
    assert closed.status_code == 200, closed.text
    result = closed.json()
    assert result["action"] == "clock-out"
    assert result["recordedAt"] == "2026-08-22T16:30:00Z"
    assert result["target"] == {
        "kind": "unverified_end",
        "label": "Unverified end location",
        "customerName": "",
    }
    assert result["entry"]["id"] == opened.json()["entry"]["id"]
    assert result["entry"]["totalHours"] == 1.5
    assert result["entry"]["clockOutGps"] is None
    assert result["entry"]["clockOutGpsMeta"] == {
        "adminRecorded": True,
        "reason": "Employee phone battery died",
        "detail": "Supervisor closed the open shift after speaking with the employee.",
        "unverifiedEndLocation": True,
    }
    assert db.query_one(
        """
        SELECT clock_out, total_hours, clock_out_gps, clock_out_gps_meta,
               recorded_source
        FROM shifts WHERE id = %s
        """,
        (int(result["entry"]["id"]),),
    ) == {
        "clock_out": ended_at,
        "total_hours": 1.5,
        "clock_out_gps": None,
        "clock_out_gps_meta": {
            "adminRecorded": True,
            "reason": "Employee phone battery died",
            "detail": "Supervisor closed the open shift after speaking with the employee.",
            "unverifiedEndLocation": True,
        },
        "recorded_source": "admin_recorded",
    }
    assert db.query_one(
        """
        SELECT action, target_kind, target_id, shift_id, visit_id
        FROM admin_direct_time_action_receipts
        WHERE id = %s
        """,
        (int(result["receipt"]["id"]),),
    ) == {
        "action": "clock-out",
        "target_kind": "unverified_end",
        "target_id": None,
        "shift_id": int(result["entry"]["id"]),
        "visit_id": None,
    }
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM home_base_events WHERE shift_id = %s",
        (int(result["entry"]["id"]),),
    ) == {"count": 0}

    replay = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json=body,
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["entry"]["id"] == result["entry"]["id"]

    invalid_target = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={
            **body,
            "targetKind": "site",
            "siteId": site_id,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert invalid_target.status_code == 422


def test_direct_arrival_requires_an_open_shift_and_records_site_provenance(client, auth):
    employee_id, _ = _create_employee(client, "arrival")
    site_id = _create_site("arrival")
    arrival = _payload(employee_id, site_id, action="arrive")

    no_shift = client.post(
        "/api/admin/time-actions/direct-record", headers=auth, json=arrival
    )
    assert no_shift.status_code == 400
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s", (employee_id,)
    ) == {"count": 0}

    opened = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json=_payload(employee_id, site_id),
    )
    assert opened.status_code == 200, opened.text
    recorded = client.post(
        "/api/admin/time-actions/direct-record", headers=auth, json=arrival
    )
    assert recorded.status_code == 200, recorded.text
    result = recorded.json()
    assert result["action"] == "arrive"
    assert result["recordedSource"] == "admin_recorded"
    assert result["visit"]["recordedSource"] == "admin_recorded"
    assert result["visit"]["gps"] is None
    assert result["visit"]["locationId"] == site_id
    assert result["entryId"] == opened.json()["entry"]["id"]
    assert db.query_one(
        "SELECT recorded_source, location_id, gps FROM visits WHERE id = %s",
        (int(result["visit"]["id"]),),
    ) == {
        "recorded_source": "admin_recorded",
        "location_id": site_id,
        "gps": None,
    }

    home_base_arrival = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={
            **arrival,
            "targetKind": "home-base",
            "siteId": None,
            "idempotencyKey": str(uuid4()),
        },
    )
    assert home_base_arrival.status_code == 422


def test_direct_home_base_clock_in_remains_internal_and_records_exception(client, auth):
    employee_id, _ = _create_employee(client, "home base")
    evening_employee_id, _ = _create_employee(client, "evening home base")
    _enroll_in_morning_crew(employee_id)
    home_base_id = _configure_home_base(client, auth)
    payload = {
        "employeeId": employee_id,
        "action": "clock-in",
        "targetKind": "home-base",
        "reason": "Office kiosk outage",
        "detail": "Supervisor recorded a present employee at the office.",
        "idempotencyKey": str(uuid4()),
    }

    evening_attempt = client.post(
        "/api/admin/time-actions/direct-record",
        headers=auth,
        json={**payload, "employeeId": evening_employee_id, "idempotencyKey": str(uuid4())},
    )
    assert evening_attempt.status_code == 409
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM shifts WHERE employee_id = %s",
        (evening_employee_id,),
    ) == {"count": 0}

    response = client.post(
        "/api/admin/time-actions/direct-record", headers=auth, json=payload
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["target"] == {
        "kind": "home_base",
        "id": home_base_id,
        "label": HOME_BASE_LABEL,
        "customerName": "",
    }
    assert result["entry"]["internalHomeBase"] is True
    assert result["entry"]["locationId"] is None
    assert result["homeBaseEvent"]["action"] == "start"
    assert result["homeBaseEvent"]["outcome"] == "exception"
    assert result["homeBaseEvent"]["exceptionReason"] == "Office kiosk outage"
    assert db.query_one(
        """
        SELECT location_id, location_label, recorded_source
        FROM shifts WHERE id = %s
        """,
        (int(result["entry"]["id"]),),
    ) == {
        "location_id": None,
        "location_label": f"Home Base — {HOME_BASE_LABEL}",
        "recorded_source": "admin_recorded",
    }
    assert db.query_one(
        """
        SELECT home_base_id, action, outcome, exception_reason
        FROM home_base_events WHERE shift_id = %s
        """,
        (int(result["entry"]["id"]),),
    ) == {
        "home_base_id": home_base_id,
        "action": "start",
        "outcome": "exception",
        "exception_reason": "Office kiosk outage",
    }


def test_ordinary_employee_clock_in_keeps_employee_provenance(client):
    _employee_id, employee_auth = _create_employee(client, "ordinary")
    site_id = _create_site("ordinary")
    response = client.post(
        "/api/timesheet/clock-in",
        headers=employee_auth,
        json={
            "location": f"{PREFIX} Site ordinary",
            "locationId": site_id,
            "latitude": 39.1203,
            "longitude": -88.54335,
            "accuracy": 10,
        },
    )
    assert response.status_code == 200, response.text
    assert db.query_one(
        "SELECT recorded_source FROM shifts WHERE id = %s",
        (int(response.json()["entry"]["id"]),),
    ) == {"recorded_source": "employee"}


def test_runtime_migration_is_additive_for_existing_time_rows(client):
    """Exercise the deployed upgrade path, not only schema.sql on a fresh DB."""

    employee_id, _ = _create_employee(client, "pre migration")
    site_id = _create_site("pre migration")
    recorded_at = datetime(2026, 8, 22, 16, 0, tzinfo=timezone.utc)
    shift = db.query_one(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, total_hours,
            notes, local_date, timezone
        ) VALUES (%s, %s, %s, %s, 0, '', %s, 'America/Chicago')
        RETURNING id
        """,
        (
            employee_id,
            site_id,
            f"{PREFIX} Site pre migration",
            recorded_at,
            recorded_at.date(),
        ),
    )
    assert shift
    visit = db.query_one(
        """
        INSERT INTO visits (
            shift_id, location_id, location_label, customer_name, arrival_time
        ) VALUES (%s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            int(shift["id"]),
            site_id,
            f"{PREFIX} Site pre migration",
            f"{PREFIX} Customer pre migration",
            recorded_at,
        ),
    )
    assert visit

    try:
        db.execute("DROP TABLE IF EXISTS admin_direct_time_action_receipts")
        db.execute("ALTER TABLE visits DROP COLUMN IF EXISTS recorded_source")
        db.execute("ALTER TABLE shifts DROP COLUMN IF EXISTS recorded_source")

        api._ensure_schema_migrations()
        api._ensure_schema_migrations()

        assert db.query_one(
            "SELECT recorded_source FROM shifts WHERE id = %s", (int(shift["id"]),)
        ) == {"recorded_source": "employee"}
        assert db.query_one(
            "SELECT recorded_source FROM visits WHERE id = %s", (int(visit["id"]),)
        ) == {"recorded_source": "employee"}
        assert db.query_one(
            "SELECT to_regclass('admin_direct_time_action_receipts') AS table_name"
        ) == {"table_name": "admin_direct_time_action_receipts"}

        # PostgreSQL generated these exact names for the pre-change unnamed
        # checks.  Recreate that deployed shape to prove the migration replaces
        # its *definition*, not merely a differently named legacy constraint.
        db.execute(
            "ALTER TABLE admin_direct_time_action_receipts "
            "DROP CONSTRAINT admin_direct_time_action_receipts_action_check"
        )
        db.execute(
            "ALTER TABLE admin_direct_time_action_receipts "
            "DROP CONSTRAINT admin_direct_time_action_receipts_target_kind_check"
        )
        db.execute(
            "ALTER TABLE admin_direct_time_action_receipts "
            "ALTER COLUMN target_id SET NOT NULL"
        )
        db.execute(
            """
            ALTER TABLE admin_direct_time_action_receipts
                ADD CONSTRAINT admin_direct_time_action_receipts_action_check
                CHECK (action IN ('clock-in', 'arrive')),
                ADD CONSTRAINT admin_direct_time_action_receipts_target_kind_check
                CHECK (target_kind IN ('site', 'home_base'))
            """
        )

        api._ensure_schema_migrations()
        upgraded_checks = {
            str(row["conname"]): str(row["definition"])
            for row in db.query_all(
                """
                SELECT conname, pg_get_constraintdef(oid) AS definition
                FROM pg_constraint
                WHERE conrelid = 'admin_direct_time_action_receipts'::regclass
                  AND conname IN (
                      'admin_direct_time_action_receipts_action_check',
                      'admin_direct_time_action_receipts_target_kind_check'
                  )
                """
            )
        }
        assert "clock-out" in upgraded_checks[
            "admin_direct_time_action_receipts_action_check"
        ]
        assert "unverified_end" in upgraded_checks[
            "admin_direct_time_action_receipts_target_kind_check"
        ]
        assert db.query_one(
            """
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_name = 'admin_direct_time_action_receipts'
              AND column_name = 'target_id'
            """
        ) == {"is_nullable": "YES"}
    finally:
        # Keep the shared test database compatible with following test modules.
        api._ensure_schema_migrations()
