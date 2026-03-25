#!/usr/bin/env python3
"""
Migrate flat JSON data (employees.json + timesheets.json) into PostgreSQL.
Safe to run multiple times — uses INSERT ... ON CONFLICT DO NOTHING / DO UPDATE.

Usage:
    DATABASE_URL=postgresql://... python3 migrate_json_to_pg.py
    or
    python3 migrate_json_to_pg.py --db-url postgresql://...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras

BACKEND_DIR = Path(__file__).resolve().parent
BASE_DIR = BACKEND_DIR.parent
DATA_DIR = BASE_DIR / "data"

EMPLOYEES_FILE = DATA_DIR / "employees.json"
TIMESHEETS_FILE = DATA_DIR / "timesheets.json"


def connect(url: str):
    return psycopg2.connect(url, sslmode="prefer")


def migrate_employees(cur, employees_data: dict) -> dict:
    """Insert employees. Returns {old_id: new_db_id}."""
    id_map = {}
    for emp in employees_data.get("employees", []):
        cur.execute(
            """
            INSERT INTO employees (name, password_hash, active, role, hourly_rate, created_at, last_login_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                active        = EXCLUDED.active,
                role          = EXCLUDED.role,
                hourly_rate   = EXCLUDED.hourly_rate,
                last_login_at = EXCLUDED.last_login_at
            RETURNING id
            """,
            (
                emp["name"],
                emp["password"],
                emp.get("active", True),
                emp.get("role", "employee"),
                emp.get("hourlyRate"),
                emp.get("created") or "NOW()",
                emp.get("lastLogin"),
            ),
        )
        db_id = cur.fetchone()[0]
        id_map[emp["id"]] = db_id
        print(f"  employee: {emp['name']} → db id {db_id}")
    return id_map


def migrate_locations(cur, timesheet_data: dict) -> dict:
    """Insert locations. Returns {address: db_id}."""
    addr_map = {}
    locations = timesheet_data.get("locations", [])
    coords    = timesheet_data.get("location_coords", {})
    customers = timesheet_data.get("location_customers", {})
    rates     = timesheet_data.get("location_rates", {})
    rate_types= timesheet_data.get("location_rate_types", {})
    types     = timesheet_data.get("location_types", {})
    freqs     = timesheet_data.get("location_frequencies", {})

    for addr in locations:
        c = coords.get(addr, {})
        cur.execute(
            """
            INSERT INTO locations (address, customer_name, location_type, rate, rate_type, frequency, lat, lng)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (address) DO UPDATE SET
                customer_name = EXCLUDED.customer_name,
                location_type = EXCLUDED.location_type,
                rate          = EXCLUDED.rate,
                rate_type     = EXCLUDED.rate_type,
                frequency     = EXCLUDED.frequency,
                lat           = EXCLUDED.lat,
                lng           = EXCLUDED.lng
            RETURNING id
            """,
            (
                addr,
                customers.get(addr),
                types.get(addr),
                rates.get(addr),
                rate_types.get(addr, "per_visit"),
                freqs.get(addr),
                c.get("lat"),
                c.get("lng"),
            ),
        )
        db_id = cur.fetchone()[0]
        addr_map[addr] = db_id
        print(f"  location: {addr[:60]} → db id {db_id}")
    return addr_map


def migrate_shifts(cur, timesheet_data: dict, emp_id_map: dict, addr_map: dict) -> None:
    """Insert shifts and their visits."""
    entries = timesheet_data.get("entries", [])
    for entry in entries:
        emp_db_id = emp_id_map.get(entry.get("employeeId"))
        if not emp_db_id:
            print(f"  SKIP shift id={entry.get('id')}: unknown employeeId {entry.get('employeeId')}")
            continue

        addr = entry.get("location", "")
        loc_db_id = addr_map.get(addr)

        cur.execute(
            """
            INSERT INTO shifts
              (employee_id, location_id, clock_in, clock_out, total_hours,
               notes, local_date, timezone, clock_in_gps, clock_out_gps)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id
            """,
            (
                emp_db_id,
                loc_db_id,
                entry.get("clockIn"),
                entry.get("clockOut"),
                entry.get("totalHours"),
                entry.get("notes", ""),
                entry.get("date"),
                entry.get("timezone", "America/Chicago"),
                json.dumps(entry["clockInGps"])  if entry.get("clockInGps")  else None,
                json.dumps(entry["clockOutGps"]) if entry.get("clockOutGps") else None,
            ),
        )
        row = cur.fetchone()
        if not row:
            print(f"  SKIP shift id={entry.get('id')}: already exists")
            continue
        shift_db_id = row[0]
        print(f"  shift id={entry.get('id')} → db id {shift_db_id}")

        for visit in entry.get("visits", []):
            v_addr = visit.get("location", "")
            v_loc_id = addr_map.get(v_addr)
            cur.execute(
                """
                INSERT INTO visits (shift_id, location_id, customer_name, arrival_time, gps)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    shift_db_id,
                    v_loc_id,
                    visit.get("customer") or None,
                    visit.get("arrivalTime"),
                    json.dumps(visit["gps"]) if visit.get("gps") else None,
                ),
            )
            print(f"    visit → {v_addr[:50]}")


def migrate_settings(cur, timesheet_data: dict) -> None:
    """Preserve existing laborPctTarget from settings.json if present."""
    settings_file = DATA_DIR / "settings.json"
    target = 35.0
    if settings_file.exists():
        try:
            target = json.loads(settings_file.read_text())["laborPctTarget"]
        except Exception:
            pass
    cur.execute(
        """
        INSERT INTO settings (key, value)
        VALUES ('laborPctTarget', %s)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """,
        (json.dumps(target),),
    )
    print(f"  settings: laborPctTarget = {target}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL", ""))
    args = parser.parse_args()

    if not args.db_url:
        sys.exit("ERROR: provide --db-url or set DATABASE_URL")

    if not EMPLOYEES_FILE.exists():
        sys.exit(f"ERROR: {EMPLOYEES_FILE} not found")
    if not TIMESHEETS_FILE.exists():
        sys.exit(f"ERROR: {TIMESHEETS_FILE} not found")

    employees_data  = json.loads(EMPLOYEES_FILE.read_text())
    timesheet_data  = json.loads(TIMESHEETS_FILE.read_text())

    conn = connect(args.db_url)
    cur  = conn.cursor()

    try:
        print("\n— Employees —")
        emp_id_map = migrate_employees(cur, employees_data)

        print("\n— Locations —")
        addr_map = migrate_locations(cur, timesheet_data)

        print("\n— Shifts & Visits —")
        migrate_shifts(cur, timesheet_data, emp_id_map, addr_map)

        print("\n— Settings —")
        migrate_settings(cur, timesheet_data)

        conn.commit()
        print("\nMigration complete.")
    except Exception as e:
        conn.rollback()
        print(f"\nERROR — rolled back: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
