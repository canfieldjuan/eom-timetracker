"""PostgreSQL contract tests for the Issue #19 Customer/Site backfill."""

from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
from psycopg2 import sql
from psycopg2.pool import ThreadedConnectionPool

from conftest import TEST_DB_URL, _raw_conn


TEST_ADDRESS_PREFIX = "Issue 19 Migration"
TEST_CUSTOMER_PREFIX = "Issue 19 Migration"


def _clean_test_rows() -> None:
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM locations WHERE address LIKE %s",
                (f"{TEST_ADDRESS_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM customers WHERE name LIKE %s",
                (f"{TEST_CUSTOMER_PREFIX}%",),
            )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def isolate_customer_backfill_rows(setup_db):
    _clean_test_rows()
    yield
    _clean_test_rows()


def _legacy_location_snapshot():
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, address, customer_name, location_type, rate, rate_type,
                       frequency, expected_hours, target_labor_pct, min_margin_pct,
                       lat, lng, check_in_token_nonce, active
                FROM locations
                WHERE address LIKE %s
                ORDER BY id
                """,
                (f"{TEST_ADDRESS_PREFIX}%",),
            )
            return cur.fetchall()
    finally:
        conn.close()


def test_customer_site_backfill_is_idempotent_and_never_merges_equal_names(
    client,
    auth,
):
    """Each named legacy Site owns a Customer; address collisions remain intact."""
    import time_tracker_api as api

    collision_a = f"{TEST_ADDRESS_PREFIX} 900 Test Lane, Suite 2, Effingham, IL"
    collision_b = (
        f"{TEST_ADDRESS_PREFIX} 900 TEST LANE ,  SUITE 2 , EFFINGHAM, IL"
    )
    legacy_rows = [
        (
            f"{TEST_ADDRESS_PREFIX} 101 First St, Effingham, IL",
            f"{TEST_CUSTOMER_PREFIX} Same Name",
            "Residential",
            135.00,
            "per_visit",
            "Every other week",
            3.25,
            31.00,
            24.00,
            39.1203000,
            -88.5433500,
            "legacy-nonce-one",
        ),
        (
            f"{TEST_ADDRESS_PREFIX} 102 Second St, Effingham, IL",
            f"{TEST_CUSTOMER_PREFIX} Same Name",
            "Commercial",
            225.00,
            "monthly",
            "Weekly",
            5.50,
            34.00,
            27.00,
            39.1300000,
            -88.5500000,
            "legacy-nonce-two",
        ),
        (
            f"{TEST_ADDRESS_PREFIX} 103 Blank Customer, Effingham, IL",
            "   ",
            "Residential",
            99.00,
            "hourly",
            None,
            1.00,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            collision_a,
            f"{TEST_CUSTOMER_PREFIX} Collision A",
            "Commercial",
            180.00,
            "per_visit",
            "Monthly",
            4.00,
            35.00,
            20.00,
            39.1400000,
            -88.5600000,
            None,
        ),
        (
            collision_b,
            f"{TEST_CUSTOMER_PREFIX} Collision B",
            "Commercial",
            190.00,
            "per_visit",
            "Monthly",
            4.50,
            36.00,
            21.00,
            39.1500000,
            -88.5700000,
            None,
        ),
    ]

    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO locations (
                    address, address_key, customer_id, customer_name,
                    location_type, rate, rate_type, frequency, expected_hours,
                    target_labor_pct, min_margin_pct, lat, lng,
                    check_in_token_nonce, active
                )
                VALUES (%s, NULL, NULL, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, true)
                """,
                legacy_rows,
            )
        conn.commit()
    finally:
        conn.close()

    before = _legacy_location_snapshot()
    api._ensure_schema_migrations()
    after_first_run = _legacy_location_snapshot()
    assert after_first_run == before

    linked_after_first_run = api.db.query_all(
        """
        SELECT l.id AS location_id, l.address, l.customer_name, l.customer_id,
               l.address_key, c.name AS canonical_customer_name
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE l.address LIKE %s
        ORDER BY l.id
        """,
        (f"{TEST_ADDRESS_PREFIX}%",),
    )
    by_address = {row["address"]: row for row in linked_after_first_run}

    named_rows = [
        row for row in linked_after_first_run if str(row["customer_name"] or "").strip()
    ]
    assert len(named_rows) == 4
    assert all(row["customer_id"] is not None for row in named_rows)
    assert len({row["customer_id"] for row in named_rows}) == len(named_rows)

    same_name_rows = [
        row
        for row in named_rows
        if str(row["customer_name"]).strip()
        == f"{TEST_CUSTOMER_PREFIX} Same Name"
    ]
    assert len(same_name_rows) == 2
    assert same_name_rows[0]["customer_id"] != same_name_rows[1]["customer_id"]
    assert {
        row["canonical_customer_name"] for row in same_name_rows
    } == {f"{TEST_CUSTOMER_PREFIX} Same Name"}

    blank_row = by_address[
        f"{TEST_ADDRESS_PREFIX} 103 Blank Customer, Effingham, IL"
    ]
    assert blank_row["customer_id"] is None

    assert by_address[collision_a]["address_key"] is None
    assert by_address[collision_b]["address_key"] is None
    collision_free_rows = [
        row
        for row in linked_after_first_run
        if row["address"] not in {collision_a, collision_b}
    ]
    assert all(row["address_key"] is not None for row in collision_free_rows)

    first_mapping = {
        row["location_id"]: (row["customer_id"], row["address_key"])
        for row in linked_after_first_run
    }
    customer_count = api.db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE name LIKE %s",
        (f"{TEST_CUSTOMER_PREFIX}%",),
    )["count"]

    api._ensure_schema_migrations()

    linked_after_second_run = api.db.query_all(
        """
        SELECT id AS location_id, customer_id, address_key
        FROM locations
        WHERE address LIKE %s
        ORDER BY id
        """,
        (f"{TEST_ADDRESS_PREFIX}%",),
    )
    assert {
        row["location_id"]: (row["customer_id"], row["address_key"])
        for row in linked_after_second_run
    } == first_mapping
    assert api.db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE name LIKE %s",
        (f"{TEST_CUSTOMER_PREFIX}%",),
    )["count"] == customer_count
    assert _legacy_location_snapshot() == before

    index_rows = api.db.query_all(
        """
        SELECT indexdef
        FROM pg_indexes
        WHERE schemaname = current_schema()
          AND tablename = 'locations'
          AND indexdef ILIKE '%%UNIQUE%%address_key%%'
        """
    )
    assert index_rows
    assert any(
        "WHERE" in row["indexdef"].upper()
        and "ADDRESS_KEY IS NOT NULL" in row["indexdef"].upper().replace("(", "").replace(")", "")
        for row in index_rows
    )

    listed = client.get(
        "/api/admin/locations?includeArchived=true",
        headers=auth,
    )
    assert listed.status_code == 200, listed.text
    listed_ids = {row["id"] for row in listed.json()["locations"]}
    assert {row["location_id"] for row in linked_after_first_run} <= listed_ids

    collision_attempt_name = f"{TEST_CUSTOMER_PREFIX} Collision Attempt"
    collision_attempt = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": collision_attempt_name,
            "primarySite": {
                "address": (
                    f"  {TEST_ADDRESS_PREFIX.upper()} 900 TEST LANE , "
                    "SUITE 2 , EFFINGHAM, IL  "
                ),
                "locationType": "Commercial",
            },
        },
    )
    assert collision_attempt.status_code == 409, collision_attempt.text
    assert collision_attempt.json()["code"] == "duplicate_site_address"
    assert set(collision_attempt.json()["details"]["matchingSiteIds"]) == {
        by_address[collision_a]["location_id"],
        by_address[collision_b]["location_id"],
    }
    assert api.db.query_one(
        "SELECT id FROM customers WHERE name = %s",
        (collision_attempt_name,),
    ) is None


def test_customer_site_migration_upgrades_the_actual_legacy_table_shape(client):
    """Origin/main's Customer-less locations table upgrades without data loss."""
    import time_tracker_api as api

    schema_name = f"issue19_legacy_{uuid4().hex}"
    setup_conn = _raw_conn()
    isolated_pool = None
    old_pool = api.db._pool
    long_name = f"{TEST_CUSTOMER_PREFIX} " + ("L" * 220)
    same_name = f"{TEST_CUSTOMER_PREFIX} Legacy Same Name"
    collision_a = f"{TEST_ADDRESS_PREFIX} 910 Legacy Lane, Suite 3"
    collision_b = f"{TEST_ADDRESS_PREFIX} 910 LEGACY LANE , SUITE 3"
    try:
        with setup_conn.cursor() as cur:
            cur.execute(
                sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name))
            )
            cur.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name))
            )
            cur.execute(
                """
                CREATE TABLE employees (
                    id            SERIAL PRIMARY KEY,
                    name          TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    active        BOOLEAN NOT NULL DEFAULT true,
                    role          TEXT NOT NULL DEFAULT 'employee',
                    hourly_rate   NUMERIC(8, 2),
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_login_at TIMESTAMPTZ
                );
                CREATE TABLE locations (
                    id                     SERIAL PRIMARY KEY,
                    address                TEXT NOT NULL UNIQUE,
                    customer_name          TEXT,
                    location_type          TEXT,
                    rate                   NUMERIC(8, 2),
                    rate_type              TEXT NOT NULL DEFAULT 'per_visit',
                    frequency              TEXT,
                    expected_hours         NUMERIC(6, 2),
                    target_labor_pct       NUMERIC(5, 2),
                    min_margin_pct         NUMERIC(5, 2),
                    lat                    NUMERIC(10, 7),
                    lng                    NUMERIC(10, 7),
                    check_in_token_nonce   VARCHAR(64),
                    check_in_token_rotated_at TIMESTAMPTZ,
                    active                 BOOLEAN NOT NULL DEFAULT true,
                    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE schedules (
                    id              SERIAL PRIMARY KEY,
                    employee_id     INTEGER NOT NULL REFERENCES employees(id),
                    customer_name   TEXT NOT NULL,
                    week_start      DATE NOT NULL,
                    scheduled_hours NUMERIC(6, 2) NOT NULL,
                    notes           TEXT NOT NULL DEFAULT '',
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (employee_id, customer_name, week_start)
                )
                """
            )
            cur.execute(
                """
                INSERT INTO employees (name, password_hash, role)
                VALUES ('Legacy Employee', 'unused', 'employee')
                RETURNING id
                """
            )
            legacy_employee_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO schedules (
                    employee_id, customer_name, week_start,
                    scheduled_hours, notes
                )
                VALUES (%s, %s, '2026-07-19', 4.5, 'Legacy schedule')
                RETURNING id
                """,
                (legacy_employee_id, same_name),
            )
            legacy_schedule_id = cur.fetchone()[0]
            cur.executemany(
                """
                INSERT INTO locations (address, customer_name, location_type)
                VALUES (%s, %s, 'Commercial')
                """,
                [
                    (f"{TEST_ADDRESS_PREFIX} 901 Legacy First", same_name),
                    (f"{TEST_ADDRESS_PREFIX} 902 Legacy Second", same_name),
                    (f"{TEST_ADDRESS_PREFIX} 903 Legacy Blank", "   "),
                    (collision_a, f"{TEST_CUSTOMER_PREFIX} Legacy Collision A"),
                    (collision_b, f"{TEST_CUSTOMER_PREFIX} Legacy Collision B"),
                    (f"{TEST_ADDRESS_PREFIX} 904 Legacy Long", long_name),
                ],
            )
        setup_conn.commit()

        isolated_pool = ThreadedConnectionPool(
            1,
            4,
            dsn=TEST_DB_URL,
            options=f"-c search_path={schema_name}",
        )
        api.db._pool = isolated_pool
        api._ensure_customer_site_schema()
        api._ensure_weekly_schedule_site_schema()

        rows = api.db.query_all(
            """
            SELECT l.id, l.address, l.customer_name, l.customer_id,
                   l.address_key, c.name AS canonical_name
            FROM locations l
            LEFT JOIN customers c ON c.id = l.customer_id
            ORDER BY l.id
            """
        )
        by_address = {row["address"]: row for row in rows}
        named_rows = [
            row for row in rows if str(row["customer_name"] or "").strip()
        ]
        assert len(named_rows) == 5
        assert len({row["customer_id"] for row in named_rows}) == 5
        assert all(row["canonical_name"] == row["customer_name"].strip() for row in named_rows)
        assert by_address[f"{TEST_ADDRESS_PREFIX} 903 Legacy Blank"]["customer_id"] is None
        assert by_address[collision_a]["address_key"] is None
        assert by_address[collision_b]["address_key"] is None
        assert by_address[f"{TEST_ADDRESS_PREFIX} 904 Legacy Long"]["canonical_name"] == long_name

        columns = {
            row["column_name"]: row["data_type"]
            for row in api.db.query_all(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'locations'
                """
            )
        }
        assert {
            "customer_id",
            "address_key",
            "service_scope",
            "access_instructions",
            "service_preferences",
            "pet_notes",
            "service_start_date",
            "updated_at",
            "archived_at",
            "archived_by",
        } <= set(columns)
        assert api.db.query_one(
            """
            SELECT data_type
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'customers'
              AND column_name = 'name'
            """
        ) == {"data_type": "text"}
        assert api.db.query_one(
            """
            SELECT id, employee_id, location_id, customer_name, week_start,
                   scheduled_hours, notes
            FROM schedules WHERE id = %s
            """,
            (legacy_schedule_id,),
        ) == {
            "id": legacy_schedule_id,
            "employee_id": legacy_employee_id,
            "location_id": None,
            "customer_name": same_name,
            "week_start": date(2026, 7, 19),
            "scheduled_hours": 4.5,
            "notes": "Legacy schedule",
        }
        assert api.db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM pg_constraint
            WHERE conrelid = 'schedules'::regclass
              AND contype = 'u'
              AND pg_get_constraintdef(oid) LIKE '%%customer_name%%'
            """
        ) == {"count": 1}

        same_name_sites = [
            row for row in rows if row["canonical_name"] == same_name
        ]
        assert len(same_name_sites) == 2
        api.db.execute(
            "UPDATE schedules SET location_id = %s WHERE id = %s",
            (same_name_sites[0]["id"], legacy_schedule_id),
        )
        with pytest.raises(api.HTTPException) as rollout_error:
            api.admin_create_schedule(
                api.ScheduleEntryRequest(
                    employeeId=legacy_employee_id,
                    locationId=same_name_sites[1]["id"],
                    customerName=same_name,
                    weekStart="2026-07-19",
                    scheduledHours=6.0,
                    notes="Must wait for staged finalization",
                ),
                None,
                {},
            )
        assert rollout_error.value.status_code == 409
        assert rollout_error.value.detail["code"] == "ambiguous_customer_site"
        assert rollout_error.value.detail["details"]["migrationPending"] is True
        assert api.db.query_one(
            "SELECT location_id, scheduled_hours, notes FROM schedules WHERE id = %s",
            (legacy_schedule_id,),
        ) == {
            "location_id": same_name_sites[0]["id"],
            "scheduled_hours": 4.5,
            "notes": "Legacy schedule",
        }

        alpha_customer_id = api.db.execute_returning(
            "INSERT INTO customers (name) VALUES ('Legacy Alpha') RETURNING id"
        )
        beta_customer_id = api.db.execute_returning(
            "INSERT INTO customers (name) VALUES ('Legacy Beta') RETURNING id"
        )
        alpha_site_id = api.db.execute_returning(
            """
            INSERT INTO locations (
                customer_id, address, address_key, customer_name,
                location_type
            )
            VALUES (%s, 'Legacy Alpha Site', 'legacy alpha site',
                    'Legacy Alpha', 'Commercial')
            RETURNING id
            """,
            (alpha_customer_id,),
        )
        beta_site_id = api.db.execute_returning(
            """
            INSERT INTO locations (
                customer_id, address, address_key, customer_name,
                location_type
            )
            VALUES (%s, 'Legacy Beta Site', 'legacy beta site',
                    'Legacy Beta', 'Commercial')
            RETURNING id
            """,
            (beta_customer_id,),
        )
        alpha_schedule_id = api.db.execute_returning(
            """
            INSERT INTO schedules (
                employee_id, location_id, customer_name, week_start,
                scheduled_hours, notes
            )
            VALUES (%s, %s, 'Legacy Alpha', '2026-07-26', 2.0, 'Alpha')
            RETURNING id
            """,
            (legacy_employee_id, alpha_site_id),
        )
        beta_schedule_id = api.db.execute_returning(
            """
            INSERT INTO schedules (
                employee_id, location_id, customer_name, week_start,
                scheduled_hours, notes
            )
            VALUES (%s, %s, 'Legacy Beta', '2026-07-26', 3.0, 'Beta')
            RETURNING id
            """,
            (legacy_employee_id, beta_site_id),
        )
        api.db.execute(
            "UPDATE customers SET name = 'Legacy Beta' WHERE id = %s",
            (alpha_customer_id,),
        )
        api.db.execute(
            "UPDATE locations SET customer_name = 'Legacy Beta' WHERE customer_id = %s",
            (alpha_customer_id,),
        )
        with pytest.raises(api.HTTPException) as rename_rollout_error:
            api.admin_create_schedule(
                api.ScheduleEntryRequest(
                    employeeId=legacy_employee_id,
                    locationId=alpha_site_id,
                    customerName="Legacy Beta",
                    weekStart="2026-07-26",
                    scheduledHours=7.0,
                    notes="Must not collide after rename",
                ),
                None,
                {},
            )
        assert rename_rollout_error.value.status_code == 409
        assert rename_rollout_error.value.detail["details"]["migrationPending"] is True
        assert rename_rollout_error.value.detail["details"][
            "matchingScheduleIds"
        ] == [beta_schedule_id]
        assert api.db.query_one(
            "SELECT customer_name, scheduled_hours, notes FROM schedules WHERE id = %s",
            (alpha_schedule_id,),
        ) == {
            "customer_name": "Legacy Alpha",
            "scheduled_hours": 2.0,
            "notes": "Alpha",
        }
        assert api.db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'schedules'
              AND indexname = 'idx_schedules_site_week'
            """
        ) == {"count": 1}

        first_mapping = {
            row["id"]: (row["customer_id"], row["address_key"])
            for row in api.db.query_all(
                "SELECT id, customer_id, address_key FROM locations ORDER BY id"
            )
        }
        first_customer_count = api.db.query_one(
            "SELECT COUNT(*) AS count FROM customers"
        )["count"]
        api._ensure_customer_site_schema()
        api._ensure_weekly_schedule_site_schema()
        assert {
            row["id"]: (row["customer_id"], row["address_key"])
            for row in api.db.query_all(
                "SELECT id, customer_id, address_key FROM locations ORDER BY id"
            )
        } == first_mapping
        assert api.db.query_one(
            "SELECT COUNT(*) AS count FROM customers"
        )["count"] == first_customer_count
    finally:
        api.db._pool = old_pool
        if isolated_pool is not None:
            isolated_pool.closeall()
        setup_conn.close()
        cleanup_conn = _raw_conn()
        try:
            with cleanup_conn.cursor() as cur:
                cur.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema_name)
                    )
                )
            cleanup_conn.commit()
        finally:
            cleanup_conn.close()
