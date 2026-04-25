#!/usr/bin/env python3
"""Unified Python backend for employee timekeeping and dashboard operations."""

from __future__ import annotations

import calendar
import csv
import io
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

import bcrypt
import jwt
import db
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
_data_dir_env = os.environ.get("DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
BACKEND_DIR = BASE_DIR / "backend"

EMPLOYEES_FILE = DATA_DIR / "employees.json"
TIMESHEETS_FILE = DATA_DIR / "timesheets.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

DEFAULT_LOCATIONS = [
    "Office Maids 101, Effingham",
    "Office Maids 102, Effingham",
    "Office Maids 103, Effingham",
]

JWT_ALGORITHM = "HS256"
EMPLOYEE_WRITE_LOCK = threading.Lock()
TIMESHEET_WRITE_LOCK = threading.Lock()
ACCESS_LOG_WRITE_LOCK = threading.Lock()

try:
    import fcntl
except ImportError:
    fcntl = None


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE entries without extra dependencies."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1]

        os.environ.setdefault(key, value)


def load_local_env() -> None:
    load_env_file(BASE_DIR / ".env")
    load_env_file(BACKEND_DIR / ".env")


def json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def read_json_file(path: Path, default_value: Any) -> Any:
    if not path.exists():
        return json_copy(default_value)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)
            file.write("\n")
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def lock_file_path(target_path: Path) -> Path:
    return target_path.with_name(f"{target_path.name}.lock")


@contextmanager
def process_file_lock(target_path: Path):
    lock_path = lock_file_path(target_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a+", encoding="utf-8") as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def to_local(dt: datetime) -> datetime:
    return dt.astimezone(APP_TIMEZONE)


def local_clock_string(dt: datetime) -> str:
    return to_local(dt).strftime("%I:%M %p")


def local_date_string(dt: datetime) -> str:
    return to_local(dt).strftime("%Y-%m-%d")


def local_date_for_logs() -> str:
    return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d")


def normalize_ip(raw_ip: str) -> str:
    ip = raw_ip.strip()
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    forwarded_ip = forwarded.split(",")[0].strip() if forwarded else ""

    direct_ip = request.client.host if request.client and request.client.host else ""
    selected = forwarded_ip if TRUST_PROXY and forwarded_ip else direct_ip
    return normalize_ip(selected) if selected else "unknown"


def parse_int(value: Optional[str], default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_allowed_days(value: Optional[str]) -> List[str]:
    if not value:
        return ["1", "2", "3", "4", "5"]

    days = [part.strip() for part in value.split(",") if part.strip()]
    if not days:
        return ["1", "2", "3", "4", "5"]

    for day in days:
        if not re.fullmatch(r"[0-6]", day):
            raise RuntimeError(f"Invalid ALLOWED_DAYS value: {day}")

    return days


def parse_allowed_ips(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


LOCATION_MATCH_RADIUS_DEFAULT_M = 50
LOCATION_MATCH_RADIUS_M = LOCATION_MATCH_RADIUS_DEFAULT_M


def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin(math.radians(lat2 - lat1) / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(math.radians(lng2 - lng1) / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def find_nearest_location_match(lat: float, lng: float, timesheet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    coords = timesheet_data.get("location_coords", {})
    best_name, best_dist = None, float("inf")
    for name, c in coords.items():
        d = haversine_m(lat, lng, c["lat"], c["lng"])
        if d < best_dist:
            best_name, best_dist = name, d
    if not best_name:
        return None
    return {
        "location": best_name,
        "distanceM": best_dist,
        "withinRadius": best_dist <= LOCATION_MATCH_RADIUS_M,
    }


def find_nearest_location(lat: float, lng: float, timesheet_data: Dict[str, Any]) -> Optional[str]:
    nearest = find_nearest_location_match(lat, lng, timesheet_data)
    if nearest and nearest["withinRadius"]:
        return str(nearest["location"])
    return None


def build_gps_meta(
    timesheet_data: Dict[str, Any],
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
    override_detail: str = "",
) -> Optional[Dict[str, Any]]:
    reason = str(override_reason or "").strip()
    detail = str(override_detail or "").strip()
    nearest = None
    if latitude is not None and longitude is not None:
        nearest = find_nearest_location_match(latitude, longitude, timesheet_data)

    if not nearest and not reason and not detail:
        return None

    return {
        "override": bool(reason),
        "overrideReason": reason,
        "overrideDetail": detail,
        "matchedLocation": str(nearest["location"]) if nearest else "",
        "distanceM": round(float(nearest["distanceM"]), 2) if nearest else None,
        "withinRadius": bool(nearest["withinRadius"]) if nearest else None,
    }


def require_gps_override(
    timesheet_data: Dict[str, Any],
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
) -> Optional[str]:
    if str(override_reason or "").strip():
        return None

    if latitude is None or longitude is None:
        return None

    nearest = find_nearest_location_match(latitude, longitude, timesheet_data)
    if nearest and not nearest["withinRadius"]:
        distance_m = round(float(nearest["distanceM"]))
        return (
            f"GPS is {distance_m}m from the nearest saved site "
            f"({nearest['location']}). Add an override reason to continue."
        )

    return None


def _format_gps_exception(source: str, meta: Any) -> Optional[str]:
    if not isinstance(meta, dict) or not meta.get("override"):
        return None
    parts = [source]
    reason = str(meta.get("overrideReason", "")).strip()
    if reason:
        parts.append(reason)
    distance = meta.get("distanceM")
    matched_location = str(meta.get("matchedLocation", "")).strip()
    if distance is not None:
        try:
            dist_label = f"{round(float(distance))}m"
        except (TypeError, ValueError):
            dist_label = ""
        if dist_label and matched_location:
            parts.append(f"{dist_label} from {matched_location}")
        elif dist_label:
            parts.append(dist_label)
    detail = str(meta.get("overrideDetail", "")).strip()
    if detail:
        parts.append(detail)
    return " - ".join(part for part in parts if part)


def collect_entry_gps_exceptions(entry: Dict[str, Any]) -> List[str]:
    exceptions: List[str] = []
    first = _format_gps_exception("clock_in", entry.get("clockInGpsMeta"))
    if first:
        exceptions.append(first)
    for idx, visit in enumerate(entry.get("visits") or [], start=1):
        formatted = _format_gps_exception(f"arrival_{idx}", visit.get("gpsMeta"))
        if formatted:
            exceptions.append(formatted)
    for idx, departure in enumerate(entry.get("departures") or [], start=1):
        formatted = _format_gps_exception(f"departure_{idx}", departure.get("gpsMeta"))
        if formatted:
            exceptions.append(formatted)
    last = _format_gps_exception("clock_out", entry.get("clockOutGpsMeta"))
    if last:
        exceptions.append(last)
    return exceptions


def validate_schedule(start_hour: int, end_hour: int) -> None:
    if start_hour < 0 or start_hour > 23:
        raise RuntimeError("ACCESS_START_HOUR must be between 0 and 23")
    if end_hour < 1 or end_hour > 24:
        raise RuntimeError("ACCESS_END_HOUR must be between 1 and 24")
    if start_hour >= end_hour:
        raise RuntimeError("ACCESS_START_HOUR must be less than ACCESS_END_HOUR")


def normalize_employees(raw_data: Any) -> Dict[str, Any]:
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw_employees = raw_data.get("employees")
    employees: List[Dict[str, Any]] = []
    max_id = 0

    if isinstance(raw_employees, list):
        for item in raw_employees:
            if not isinstance(item, dict):
                continue

            try:
                employee_id = int(item.get("id", 0))
            except (TypeError, ValueError):
                continue

            if employee_id <= 0:
                continue

            name = str(item.get("name", "")).strip()
            password_hash = str(item.get("password", "")).strip()
            if not name or not password_hash:
                continue

            try:
                raw_rate = item.get("hourlyRate")
                hourly_rate = float(raw_rate) if raw_rate is not None else None
            except (TypeError, ValueError):
                hourly_rate = None

            employee = {
                "id": employee_id,
                "name": name,
                "password": password_hash,
                "active": bool(item.get("active", True)),
                "role": str(item.get("role", "employee")),
                "created": item.get("created"),
                "lastLogin": item.get("lastLogin"),
                "hourlyRate": hourly_rate,
            }
            employees.append(employee)
            max_id = max(max_id, employee_id)

    raw_next_id = raw_data.get("nextId")
    try:
        next_id = int(raw_next_id)
    except (TypeError, ValueError):
        next_id = max_id + 1

    if next_id <= max_id:
        next_id = max_id + 1

    return {"employees": employees, "nextId": next_id}


def normalize_timesheets(raw_data: Any) -> Dict[str, Any]:
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw_entries = raw_data.get("entries")
    entries: List[Dict[str, Any]] = []
    max_id = 0

    if isinstance(raw_entries, list):
        for item in raw_entries:
            if not isinstance(item, dict):
                continue

            try:
                entry_id = int(item.get("id", 0))
                employee_id = int(item.get("employeeId", 0))
            except (TypeError, ValueError):
                continue

            if entry_id <= 0 or employee_id <= 0:
                continue

            raw_visits = item.get("visits")
            visits: List[Dict[str, Any]] = []
            if isinstance(raw_visits, list):
                for v in raw_visits:
                    if isinstance(v, dict) and v.get("arrivalTime"):
                        visits.append({
                            "arrivalTime": str(v["arrivalTime"]),
                            "location": str(v.get("location", "")),
                            "customer": str(v.get("customer", "")),
                            "gps": v.get("gps") if isinstance(v.get("gps"), dict) else None,
                        })

            entry = {
                "id": entry_id,
                "employeeId": employee_id,
                "employeeName": str(item.get("employeeName", "")).strip(),
                "location": str(item.get("location", "")).strip(),
                "clockIn": str(item.get("clockIn", "")).strip(),
                "clockOut": item.get("clockOut"),
                "totalHours": float(item.get("totalHours", 0) or 0),
                "notes": str(item.get("notes", "")),
                "date": str(item.get("date", "")).strip(),
                "timezone": str(item.get("timezone", "")).strip(),
                "clockInGps": item.get("clockInGps") if isinstance(item.get("clockInGps"), dict) else None,
                "clockOutGps": item.get("clockOutGps") if isinstance(item.get("clockOutGps"), dict) else None,
                "visits": visits,
            }
            entries.append(entry)
            max_id = max(max_id, entry_id)

    raw_locations = raw_data.get("locations")
    if isinstance(raw_locations, list) and raw_locations:
        locations = [str(value).strip() for value in raw_locations if str(value).strip()]
    else:
        locations = DEFAULT_LOCATIONS[:]

    raw_coords = raw_data.get("location_coords")
    location_coords: Dict[str, Dict[str, float]] = {}
    if isinstance(raw_coords, dict):
        for name, coords in raw_coords.items():
            if isinstance(coords, dict):
                try:
                    location_coords[str(name)] = {
                        "lat": float(coords["lat"]),
                        "lng": float(coords["lng"]),
                    }
                except (KeyError, TypeError, ValueError):
                    pass

    raw_customers = raw_data.get("location_customers")
    location_customers: Dict[str, str] = {}
    if isinstance(raw_customers, dict):
        for name, customer in raw_customers.items():
            if isinstance(name, str) and isinstance(customer, str) and customer.strip():
                location_customers[name] = customer.strip()

    raw_rates = raw_data.get("location_rates")
    location_rates: Dict[str, float] = {}
    if isinstance(raw_rates, dict):
        for name, rate in raw_rates.items():
            if isinstance(name, str):
                try:
                    location_rates[name] = float(rate)
                except (TypeError, ValueError):
                    pass

    raw_rate_types = raw_data.get("location_rate_types")
    location_rate_types: Dict[str, str] = {}
    if isinstance(raw_rate_types, dict):
        for name, rtype in raw_rate_types.items():
            if isinstance(name, str) and rtype in ("per_visit", "hourly", "monthly"):
                location_rate_types[name] = rtype

    raw_types = raw_data.get("location_types")
    location_types: Dict[str, str] = {}
    if isinstance(raw_types, dict):
        for name, ltype in raw_types.items():
            if isinstance(name, str) and ltype in ("Residential", "Commercial"):
                location_types[name] = ltype

    raw_frequencies = raw_data.get("location_frequencies")
    location_frequencies: Dict[str, str] = {}
    if isinstance(raw_frequencies, dict):
        for name, freq in raw_frequencies.items():
            if isinstance(name, str) and isinstance(freq, str) and freq.strip():
                location_frequencies[name] = freq.strip()

    raw_next_id = raw_data.get("nextId")
    try:
        next_id = int(raw_next_id)
    except (TypeError, ValueError):
        next_id = max_id + 1

    if next_id <= max_id:
        next_id = max_id + 1

    return {"entries": entries, "nextId": next_id, "locations": locations, "location_coords": location_coords, "location_customers": location_customers, "location_rates": location_rates, "location_rate_types": location_rate_types, "location_types": location_types, "location_frequencies": location_frequencies}


# --- PostgreSQL-backed data layer --------------------------------------------

def _row_to_employee(row: Dict[str, Any]) -> Dict[str, Any]:
    rate = row.get("hourly_rate")
    created = row.get("created_at")
    last_login = row.get("last_login_at")
    return {
        "id":         row["id"],
        "name":       row["name"],
        "password":   row["password_hash"],
        "active":     row["active"],
        "role":       row["role"],
        "hourlyRate": float(rate) if rate is not None else None,
        "created":    to_utc_iso(created) if created else None,
        "lastLogin":  to_utc_iso(last_login) if last_login else None,
    }


def _load_employees_from_db() -> Dict[str, Any]:
    rows = db.query_all(
        "SELECT id, name, password_hash, active, role, hourly_rate, created_at, last_login_at "
        "FROM employees ORDER BY id"
    )
    employees = [_row_to_employee(r) for r in rows]
    max_id = max((e["id"] for e in employees), default=0)
    return {"employees": employees, "nextId": max_id + 1}


def _save_employees_to_db(employees_data: Dict[str, Any], pre_ids: set) -> None:
    """Upsert employees. Updates in-memory dicts with DB-assigned IDs for new employees."""
    with db.get_conn() as conn:
        cur = conn.cursor()
        for emp in employees_data.get("employees", []):
            if emp["id"] not in pre_ids:
                cur.execute(
                    """
                    INSERT INTO employees
                      (name, password_hash, active, role, hourly_rate, last_login_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
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
                        emp.get("lastLogin"),
                    ),
                )
                emp["id"] = cur.fetchone()[0]
            else:
                cur.execute(
                    """
                    UPDATE employees SET
                        password_hash = %s,
                        active        = %s,
                        role          = %s,
                        hourly_rate   = %s,
                        last_login_at = %s
                    WHERE id = %s
                    """,
                    (
                        emp["password"],
                        emp.get("active", True),
                        emp.get("role", "employee"),
                        emp.get("hourlyRate"),
                        emp.get("lastLogin"),
                        emp["id"],
                    ),
                )
        cur.execute(
            "SELECT setval('employees_id_seq', COALESCE(MAX(id), 1)) FROM employees"
        )


def load_employees() -> Dict[str, Any]:
    return _load_employees_from_db()


def save_employees(employees_data: Dict[str, Any]) -> None:
    with EMPLOYEE_WRITE_LOCK:
        pre_ids: set = set()  # treat all as inserts (name conflict -> update)
        _save_employees_to_db(employees_data, pre_ids)


def update_employees(mutator) -> Tuple[bool, Any]:
    with EMPLOYEE_WRITE_LOCK:
        employees_data = _load_employees_from_db()
        pre_ids = {emp["id"] for emp in employees_data["employees"]}
        ok, payload = mutator(employees_data)
        if ok:
            _save_employees_to_db(employees_data, pre_ids)
        return ok, payload


def _row_to_visit(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "arrivalTime": to_utc_iso(row["arrival_time"]) if row.get("arrival_time") else "",
        "location":    row.get("location") or row.get("location_label") or "",
        "customer":    row["customer_name"] or "",
        "gps":         row["gps"],
        "gpsMeta":     row.get("gps_meta"),
    }


def _row_to_departure(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "departureTime": to_utc_iso(row["departure_time"]) if row.get("departure_time") else "",
        "location":      row.get("location") or row.get("location_label") or "",
        "customer":      row["customer_name"] or "",
        "gps":           row["gps"],
        "gpsMeta":       row.get("gps_meta"),
    }


def _row_to_entry(
    row: Dict[str, Any],
    visits: List[Dict[str, Any]],
    departures: List[Dict[str, Any]],
) -> Dict[str, Any]:
    co = row.get("clock_out")
    return {
        "id":           row["id"],
        "employeeId":   row["employee_id"],
        "employeeName": row["employee_name"] or "",
        "location":     row.get("location") or row.get("location_label") or "",
        "clockIn":      to_utc_iso(row["clock_in"]) if row.get("clock_in") else "",
        "clockOut":     to_utc_iso(co) if co else None,
        "totalHours":   float(row["total_hours"] or 0),
        "notes":        row["notes"] or "",
        "date":         str(row["local_date"]) if row.get("local_date") else "",
        "timezone":     row["timezone"] or "America/Chicago",
        "clockInGps":   row["clock_in_gps"],
        "clockInGpsMeta": row.get("clock_in_gps_meta"),
        "clockOutGps":  row["clock_out_gps"],
        "clockOutGpsMeta": row.get("clock_out_gps_meta"),
        "jobId":        row.get("job_id"),
        "timeCategory": row.get("time_category", "productive"),
        "nonProductiveType": row.get("non_productive_type"),
        "visits":       visits,
        "departures":   departures,
    }


def _load_timesheets_from_db() -> Dict[str, Any]:
    loc_rows = db.query_all(
        "SELECT address, customer_name, location_type, rate, rate_type, "
        "frequency, lat, lng, expected_hours, target_labor_pct, min_margin_pct "
        "FROM locations WHERE active = true ORDER BY id"
    )
    locations: List[str] = [r["address"] for r in loc_rows]
    location_coords: Dict[str, Dict[str, float]] = {}
    location_customers: Dict[str, str] = {}
    location_rates: Dict[str, float] = {}
    location_rate_types: Dict[str, str] = {}
    location_types: Dict[str, str] = {}
    location_frequencies: Dict[str, str] = {}
    location_expected_hours: Dict[str, float] = {}
    location_target_labor: Dict[str, float] = {}
    location_min_margin: Dict[str, float] = {}

    for r in loc_rows:
        addr = r["address"]
        if r.get("lat") is not None and r.get("lng") is not None:
            location_coords[addr] = {"lat": float(r["lat"]), "lng": float(r["lng"])}
        if r.get("customer_name"):
            location_customers[addr] = r["customer_name"]
        if r.get("rate") is not None:
            location_rates[addr] = float(r["rate"])
        if r.get("rate_type"):
            location_rate_types[addr] = r["rate_type"]
        if r.get("location_type"):
            location_types[addr] = r["location_type"]
        if r.get("frequency"):
            location_frequencies[addr] = r["frequency"]
        if r.get("expected_hours") is not None:
            location_expected_hours[addr] = float(r["expected_hours"])
        if r.get("target_labor_pct") is not None:
            location_target_labor[addr] = float(r["target_labor_pct"])
        if r.get("min_margin_pct") is not None:
            location_min_margin[addr] = float(r["min_margin_pct"])

    visit_rows = db.query_all(
        """
        SELECT v.shift_id, COALESCE(l.address, '') AS location,
               v.location_label, v.customer_name, v.arrival_time, v.gps, v.gps_meta
        FROM visits v
        LEFT JOIN locations l ON v.location_id = l.id
        ORDER BY v.shift_id, v.arrival_time
        """
    )
    visits_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for r in visit_rows:
        visits_by_shift.setdefault(r["shift_id"], []).append(_row_to_visit(r))

    departure_rows = db.query_all(
        """
        SELECT d.shift_id, COALESCE(l.address, '') AS location,
               d.location_label, d.customer_name, d.departure_time, d.gps, d.gps_meta
        FROM departures d
        LEFT JOIN locations l ON d.location_id = l.id
        ORDER BY d.shift_id, d.departure_time
        """
    )
    departures_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for r in departure_rows:
        departures_by_shift.setdefault(r["shift_id"], []).append(_row_to_departure(r))

    shift_rows = db.query_all(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name,
               COALESCE(l.address, '') AS location,
               s.location_label,
               s.clock_in, s.clock_out, s.total_hours,
               s.notes, s.local_date, s.timezone,
               s.clock_in_gps, s.clock_in_gps_meta,
               s.clock_out_gps, s.clock_out_gps_meta,
               s.job_id, s.time_category, s.non_productive_type
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        LEFT JOIN locations l ON s.location_id = l.id
        ORDER BY s.id
        """
    )
    entries = [
        _row_to_entry(
            r,
            visits_by_shift.get(r["id"], []),
            departures_by_shift.get(r["id"], []),
        )
        for r in shift_rows
    ]
    max_id = max((e["id"] for e in entries), default=0)

    return {
        "entries": entries,
        "nextId": max_id + 1,
        "locations": locations,
        "location_coords": location_coords,
        "location_customers": location_customers,
        "location_rates": location_rates,
        "location_rate_types": location_rate_types,
        "location_types": location_types,
        "location_frequencies": location_frequencies,
        "location_expected_hours": location_expected_hours,
        "location_target_labor": location_target_labor,
        "location_min_margin": location_min_margin,
    }


def _save_timesheets_to_db(
    timesheet_data: Dict[str, Any],
    pre_shift_ids: set,
    pre_visit_counts: Dict[int, int],
    pre_departure_counts: Dict[int, int],
) -> None:
    """Upsert locations, shifts, and new child events. Updates in-memory entry IDs for new shifts."""
    with db.get_conn() as conn:
        cur = conn.cursor()

        addr_to_id: Dict[str, int] = {}
        for addr in timesheet_data.get("locations", []):
            c = timesheet_data.get("location_coords", {}).get(addr, {})
            cur.execute(
                """
                INSERT INTO locations
                  (address, customer_name, location_type, rate, rate_type, frequency, lat, lng,
                   expected_hours, target_labor_pct, min_margin_pct)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (address) DO UPDATE SET
                    customer_name    = EXCLUDED.customer_name,
                    location_type    = EXCLUDED.location_type,
                    rate             = EXCLUDED.rate,
                    rate_type        = EXCLUDED.rate_type,
                    frequency        = EXCLUDED.frequency,
                    lat              = EXCLUDED.lat,
                    lng              = EXCLUDED.lng,
                    expected_hours   = EXCLUDED.expected_hours,
                    target_labor_pct = COALESCE(EXCLUDED.target_labor_pct, locations.target_labor_pct),
                    min_margin_pct   = COALESCE(EXCLUDED.min_margin_pct, locations.min_margin_pct)
                RETURNING id
                """,
                (
                    addr,
                    timesheet_data.get("location_customers", {}).get(addr),
                    timesheet_data.get("location_types", {}).get(addr),
                    timesheet_data.get("location_rates", {}).get(addr),
                    timesheet_data.get("location_rate_types", {}).get(addr, "per_visit"),
                    timesheet_data.get("location_frequencies", {}).get(addr),
                    c.get("lat"),
                    c.get("lng"),
                    timesheet_data.get("location_expected_hours", {}).get(addr),
                    timesheet_data.get("location_target_labor", {}).get(addr),
                    timesheet_data.get("location_min_margin", {}).get(addr),
                ),
            )
            addr_to_id[addr] = cur.fetchone()[0]

        for entry in timesheet_data.get("entries", []):
            loc_id = addr_to_id.get(entry.get("location", ""))
            is_new = entry["id"] not in pre_shift_ids

            if is_new:
                cur.execute(
                    """
                    INSERT INTO shifts
                      (employee_id, location_id, location_label, clock_in, clock_out, total_hours,
                       notes, local_date, timezone, clock_in_gps, clock_in_gps_meta,
                       clock_out_gps, clock_out_gps_meta,
                       job_id, time_category, non_productive_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        entry["employeeId"],
                        loc_id,
                        entry.get("location", ""),
                        entry.get("clockIn"),
                        entry.get("clockOut"),
                        entry.get("totalHours"),
                        entry.get("notes", ""),
                        entry.get("date") or None,
                        entry.get("timezone", "America/Chicago"),
                        json.dumps(entry["clockInGps"]) if entry.get("clockInGps") else None,
                        json.dumps(entry["clockInGpsMeta"]) if entry.get("clockInGpsMeta") else None,
                        json.dumps(entry["clockOutGps"]) if entry.get("clockOutGps") else None,
                        json.dumps(entry["clockOutGpsMeta"]) if entry.get("clockOutGpsMeta") else None,
                        entry.get("jobId"),
                        entry.get("timeCategory", "productive"),
                        entry.get("nonProductiveType"),
                    ),
                )
                entry["id"] = cur.fetchone()[0]
            else:
                cur.execute(
                    """
                    UPDATE shifts SET
                        location_id         = %s,
                        location_label      = %s,
                        clock_out           = %s,
                        total_hours         = %s,
                        notes               = %s,
                        local_date          = %s,
                        timezone            = %s,
                        clock_in_gps        = %s,
                        clock_in_gps_meta   = %s,
                        clock_out_gps       = %s,
                        clock_out_gps_meta  = %s,
                        job_id              = %s,
                        time_category       = %s,
                        non_productive_type = %s
                    WHERE id = %s
                    """,
                    (
                        loc_id,
                        entry.get("location", ""),
                        entry.get("clockOut"),
                        entry.get("totalHours"),
                        entry.get("notes", ""),
                        entry.get("date") or None,
                        entry.get("timezone", "America/Chicago"),
                        json.dumps(entry["clockInGps"]) if entry.get("clockInGps") else None,
                        json.dumps(entry["clockInGpsMeta"]) if entry.get("clockInGpsMeta") else None,
                        json.dumps(entry["clockOutGps"]) if entry.get("clockOutGps") else None,
                        json.dumps(entry["clockOutGpsMeta"]) if entry.get("clockOutGpsMeta") else None,
                        entry.get("jobId"),
                        entry.get("timeCategory", "productive"),
                        entry.get("nonProductiveType"),
                        entry["id"],
                    ),
                )

            # Insert only visits appended since last load
            existing_count = pre_visit_counts.get(entry["id"], 0)
            for visit in entry.get("visits", [])[existing_count:]:
                v_loc_id = addr_to_id.get(visit.get("location", ""))
                cur.execute(
                    """
                    INSERT INTO visits (shift_id, location_id, location_label, customer_name, arrival_time, gps, gps_meta)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        entry["id"],
                        v_loc_id,
                        visit.get("location", ""),
                        visit.get("customer") or None,
                        visit.get("arrivalTime"),
                        json.dumps(visit["gps"]) if visit.get("gps") else None,
                        json.dumps(visit["gpsMeta"]) if visit.get("gpsMeta") else None,
                    ),
                )
                # Auto-link shift to the first registered location visited
                if v_loc_id:
                    cur.execute(
                        "UPDATE shifts SET location_id = %s WHERE id = %s AND location_id IS NULL",
                        (v_loc_id, entry["id"]),
                    )

            existing_departure_count = pre_departure_counts.get(entry["id"], 0)
            for departure in entry.get("departures", [])[existing_departure_count:]:
                d_loc_id = addr_to_id.get(departure.get("location", ""))
                cur.execute(
                    """
                    INSERT INTO departures (shift_id, location_id, location_label, customer_name, departure_time, gps, gps_meta)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        entry["id"],
                        d_loc_id,
                        departure.get("location", ""),
                        departure.get("customer") or None,
                        departure.get("departureTime"),
                        json.dumps(departure["gps"]) if departure.get("gps") else None,
                        json.dumps(departure["gpsMeta"]) if departure.get("gpsMeta") else None,
                    ),
                )

        cur.execute(
            "SELECT setval('shifts_id_seq', COALESCE(MAX(id), 1)) FROM shifts"
        )


def load_timesheets() -> Dict[str, Any]:
    return _load_timesheets_from_db()


def get_open_entry(entries: List[Dict[str, Any]], employee_id: int) -> Optional[Dict[str, Any]]:
    open_entries = [
        entry for entry in entries if entry.get("employeeId") == employee_id and entry.get("clockOut") is None
    ]
    if not open_entries:
        return None

    open_entries.sort(key=lambda item: item.get("clockIn", ""), reverse=True)
    return open_entries[0]


def is_stale_open_entry(entry: Dict[str, Any], reference_time: datetime) -> bool:
    if entry.get("clockOut") is not None:
        return False

    try:
        started_at = parse_utc_iso(str(entry.get("clockIn", "")))
    except ValueError:
        return False

    elapsed_hours = (reference_time - started_at).total_seconds() / 3600
    return elapsed_hours > MAX_ACTIVE_SHIFT_HOURS


def close_stale_open_entries(timesheet_data: Dict[str, Any], reference_time: datetime) -> bool:
    changed = False
    marker = "[auto-closed stale shift]"

    for entry in timesheet_data.get("entries", []):
        if not is_stale_open_entry(entry, reference_time):
            continue

        started_at = parse_utc_iso(str(entry.get("clockIn", "")))
        closed_at = started_at + timedelta(hours=MAX_ACTIVE_SHIFT_HOURS)
        entry["clockOut"] = to_utc_iso(closed_at)
        entry["totalHours"] = round(MAX_ACTIVE_SHIFT_HOURS, 2)

        notes = str(entry.get("notes", "")).strip()
        if marker not in notes:
            entry["notes"] = f"{notes} {marker}".strip()

        changed = True

    return changed


def update_timesheets(mutator) -> Tuple[bool, Any]:
    with TIMESHEET_WRITE_LOCK:
        timesheet_data = _load_timesheets_from_db()
        pre_shift_ids = {e["id"] for e in timesheet_data["entries"]}
        pre_visit_counts = {e["id"]: len(e.get("visits", [])) for e in timesheet_data["entries"]}
        pre_departure_counts = {e["id"]: len(e.get("departures", [])) for e in timesheet_data["entries"]}

        changed = False
        if AUTO_CLOSE_STALE_SHIFTS:
            changed = close_stale_open_entries(timesheet_data, utc_now())

        ok, payload = mutator(timesheet_data)
        if ok or changed:
            _save_timesheets_to_db(timesheet_data, pre_shift_ids, pre_visit_counts, pre_departure_counts)
        return ok, payload


def find_employee_by_name(employees: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    lowered = name.strip().lower()
    for employee in employees:
        if not employee.get("active", True):
            continue
        if employee.get("name", "").strip().lower() == lowered:
            return employee
    return None


def find_employee_by_id(employees: List[Dict[str, Any]], employee_id: int) -> Optional[Dict[str, Any]]:
    for employee in employees:
        if employee.get("id") == employee_id:
            return employee
    return None


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# Pre-computed dummy hash used to equalise the wall-clock time of a login
# attempt against an unknown name with one against an existing user. Without
# this, an attacker can enumerate valid usernames by timing the response.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(
    b"timing-attack-mitigation-dummy", bcrypt.gensalt(10)
).decode()


# Sliding-window per-IP rate limiter. In-memory and per-worker; redeploys
# reset state and multi-worker setups don't coordinate. Acceptable for the
# single-instance Render deployment. For horizontal scale, replace with a
# Redis-backed implementation.
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_BUCKETS: Dict[str, "deque[float]"] = {}


def _rate_limit_check(
    request: Request,
    *,
    key_prefix: str,
    max_calls: int,
    window_seconds: int,
) -> None:
    """Raise HTTPException(429) when the per-IP call rate for the given
    key_prefix exceeds max_calls within window_seconds."""
    if max_calls <= 0 or window_seconds <= 0:
        return  # disabled

    client_ip = get_client_ip(request)
    key = f"{key_prefix}:{client_ip}"
    now = time.monotonic()
    cutoff = now - window_seconds

    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_BUCKETS.get(key)
        if bucket is None:
            bucket = deque()
            _RATE_LIMIT_BUCKETS[key] = bucket
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= max_calls:
            retry_after = max(1, int(bucket[0] + window_seconds - now) + 1)
            raise HTTPException(
                status_code=429,
                detail="Too many requests; try again later",
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)
        if len(_RATE_LIMIT_BUCKETS) > RATE_LIMIT_BUCKET_SOFT_CAP:
            _rate_limit_evict_expired(cutoff)


def _rate_limit_evict_expired(cutoff: float) -> None:
    """Drop buckets whose entries are all past the cutoff. Caller must hold
    _RATE_LIMIT_LOCK."""
    stale: List[str] = []
    for k, b in _RATE_LIMIT_BUCKETS.items():
        while b and b[0] < cutoff:
            b.popleft()
        if not b:
            stale.append(k)
    for k in stale:
        del _RATE_LIMIT_BUCKETS[k]


def create_auth_token(employee_id: int, employee_name: str, role: str = "employee") -> str:
    now = utc_now()
    payload = {
        "sub": str(employee_id),
        "name": employee_name,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=TOKEN_TTL_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_auth_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def entry_hours(entry: Dict[str, Any], reference_time: datetime) -> float:
    try:
        clock_in_time = parse_utc_iso(str(entry.get("clockIn", "")))
    except ValueError:
        return float(entry.get("totalHours", 0) or 0)

    clock_out_value = entry.get("clockOut")
    if clock_out_value is None:
        duration = reference_time - clock_in_time
        duration_hours = duration.total_seconds() / 3600
        if duration_hours < 0:
            return 0.0
        return round(min(duration_hours, MAX_ACTIVE_SHIFT_HOURS), 2)

    try:
        clock_out_time = parse_utc_iso(str(clock_out_value))
    except ValueError:
        return float(entry.get("totalHours", 0) or 0)

    duration_hours = (clock_out_time - clock_in_time).total_seconds() / 3600
    if duration_hours < 0:
        return 0.0
    return round(duration_hours, 2)


def latest_open_entry(entries: List[Dict[str, Any]], employee_id: int) -> Optional[Dict[str, Any]]:
    now = utc_now()
    open_entries = [
        entry
        for entry in entries
        if entry.get("employeeId") == employee_id
        and entry.get("clockOut") is None
        and not is_stale_open_entry(entry, now)
    ]
    if not open_entries:
        return None

    open_entries.sort(key=lambda item: item.get("clockIn", ""), reverse=True)
    return open_entries[0]


def build_dashboard_hours_data() -> Dict[str, Any]:
    employees_data = load_employees()
    timesheet_data = load_timesheets()
    now = utc_now()
    week_start = datetime.now(APP_TIMEZONE).date() - timedelta(days=6)

    active_employees = [employee for employee in employees_data["employees"] if employee.get("active", True)]
    employee_rows: List[Dict[str, Any]] = []
    total_hours = 0.0

    for employee in active_employees:
        employee_id = int(employee["id"])
        relevant_entries = [
            entry for entry in timesheet_data["entries"] if int(entry.get("employeeId", 0)) == employee_id
        ]
        open_entry = latest_open_entry(relevant_entries, employee_id)
        currently_working = open_entry is not None

        shifts: List[Dict[str, Any]] = []
        weekly_hours = 0.0

        for entry in relevant_entries:
            clock_in_text = str(entry.get("clockIn", ""))
            if not clock_in_text:
                continue

            try:
                clock_in_time = parse_utc_iso(clock_in_text)
            except ValueError:
                continue

            local_clock_in = to_local(clock_in_time)
            shift_date = local_clock_in.date()
            calculated_hours = entry_hours(entry, now)

            if shift_date >= week_start:
                weekly_hours += calculated_hours

            clock_out_value = entry.get("clockOut")
            if clock_out_value:
                try:
                    clock_out_time = parse_utc_iso(str(clock_out_value))
                    end_time = to_local(clock_out_time).strftime("%H:%M")
                except ValueError:
                    end_time = "--:--"
            else:
                end_time = "--:--"

            shifts.append(
                {
                    "date": local_clock_in.strftime("%Y-%m-%d"),
                    "startTime": local_clock_in.strftime("%H:%M"),
                    "endTime": end_time,
                    "hours": calculated_hours,
                }
            )

        shifts.sort(key=lambda item: (item["date"], item["startTime"]), reverse=True)
        row = {
            "id": employee_id,
            "name": employee["name"],
            "totalHours": round(weekly_hours, 2),
            "currentlyWorking": currently_working,
            "shifts": shifts[:12],
        }
        employee_rows.append(row)
        total_hours += row["totalHours"]

    employee_rows.sort(key=lambda item: item["name"].lower())
    summary = {
        "totalEmployees": len(employee_rows),
        "totalHours": round(total_hours, 2),
        "averageHours": round(total_hours / len(employee_rows), 2) if employee_rows else 0,
    }

    return {"employees": employee_rows, "summary": summary}


def _resolve_customer(location: str, location_customers: Dict[str, str]) -> str:
    """Return the customer name for a location address, or empty string if not found."""
    return location_customers.get(location, "")


def build_public_current_status() -> List[Dict[str, Any]]:
    timesheet_data = load_timesheets()
    location_customers: Dict[str, str] = timesheet_data.get("location_customers", {})
    now = utc_now()

    rows: List[Dict[str, Any]] = []
    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is not None:
            continue
        if is_stale_open_entry(entry, now):
            continue

        try:
            clock_in_time = parse_utc_iso(str(entry.get("clockIn", "")))
        except ValueError:
            continue

        visits = entry.get("visits") or []
        departures = entry.get("departures") or []
        active_visit = get_active_visit(entry)
        last_departure = departures[-1] if departures else None
        if active_visit:
            loc = active_visit.get("location", "")
            customer = active_visit.get("customer") or _resolve_customer(loc, location_customers)
        elif last_departure:
            loc = last_departure.get("location", "") or str(entry.get("location", ""))
            customer = last_departure.get("customer") or _resolve_customer(loc, location_customers)
        else:
            loc = str(entry.get("location", ""))
            customer = _resolve_customer(loc, location_customers)
        # Best available GPS: active visit, latest departure, latest visit, then clock-in GPS
        last_departure_gps = next((d for d in reversed(departures) if isinstance(d.get("gps"), dict)), None)
        last_gps_visit = next((v for v in reversed(visits) if isinstance(v.get("gps"), dict)), None)
        if active_visit and isinstance(active_visit.get("gps"), dict):
            gps = active_visit["gps"]
        elif last_departure_gps:
            gps = last_departure_gps["gps"]
        elif last_gps_visit:
            gps = last_gps_visit["gps"]
        else:
            gps = entry.get("clockInGps")

        visit_rows = []
        for v in visits:
            if not isinstance(v, dict) or not v.get("arrivalTime"):
                continue
            try:
                v_arr = parse_utc_iso(str(v["arrivalTime"]))
                visit_rows.append({
                    "arrivalTime": local_clock_string(v_arr),
                    "location": v.get("location", ""),
                    "customer": v.get("customer", ""),
                    "gps": v.get("gps") if isinstance(v.get("gps"), dict) else None,
                    "gpsMeta": v.get("gpsMeta") if isinstance(v.get("gpsMeta"), dict) else None,
                })
            except ValueError:
                pass

        departure_rows = []
        for d in departures:
            if not isinstance(d, dict) or not d.get("departureTime"):
                continue
            try:
                d_time = parse_utc_iso(str(d["departureTime"]))
                departure_rows.append({
                    "departureTime": local_clock_string(d_time),
                    "location": d.get("location", ""),
                    "customer": d.get("customer", ""),
                    "gps": d.get("gps") if isinstance(d.get("gps"), dict) else None,
                    "gpsMeta": d.get("gpsMeta") if isinstance(d.get("gpsMeta"), dict) else None,
                })
            except ValueError:
                pass

        rows.append(
            {
                "id": int(entry.get("employeeId", 0)),
                "name": str(entry.get("employeeName", "")),
                "clockedInAt": local_clock_string(clock_in_time),
                "hoursWorked": f"{entry_hours(entry, now):.2f}",
                "notes": str(entry.get("notes", "")),
                "location": loc,
                "customer": customer,
                "clockInGps": gps,
                "visits": visit_rows,
                "departures": departure_rows,
                "activeVisit": {
                    "location": active_visit.get("location", ""),
                    "customer": active_visit.get("customer", ""),
                    "gps": active_visit.get("gps") if isinstance(active_visit.get("gps"), dict) else None,
                    "gpsMeta": active_visit.get("gpsMeta") if isinstance(active_visit.get("gpsMeta"), dict) else None,
                } if active_visit else None,
                "canDepart": active_visit is not None,
            }
        )

    rows.sort(key=lambda item: item["name"].lower())
    return rows


def append_access_log(request: Request, action: str, allowed: bool, reason: str = "") -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = to_utc_iso(utc_now())
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    entry = {
        "timestamp": timestamp,
        "action": action,
        "allowed": allowed,
        "reason": reason,
        "clientIP": client_ip,
        "userAgent": user_agent,
        "endpoint": request.url.path,
        "method": request.method,
    }

    log_file = LOGS_DIR / f"access_{local_date_for_logs()}.json"

    with ACCESS_LOG_WRITE_LOCK:
        with process_file_lock(log_file):
            payload = read_json_file(log_file, [])
            if not isinstance(payload, list):
                payload = []
            payload.append(entry)
            write_json_atomic(log_file, payload)


def current_schedule_context() -> Dict[str, Any]:
    now_local = datetime.now(APP_TIMEZONE)
    js_day = (now_local.weekday() + 1) % 7
    return {
        "day": str(js_day),
        "hour": now_local.hour,
        "current_time": now_local.strftime("%Y-%m-%d %I:%M:%S %p"),
    }


def check_schedule_access() -> Tuple[bool, str, str]:
    context = current_schedule_context()

    if context["day"] not in ALLOWED_DAYS:
        return False, "Access is not allowed on this configured day", context["current_time"]

    if context["hour"] < ACCESS_START_HOUR or context["hour"] >= ACCESS_END_HOUR:
        return (
            False,
            f"Access only allowed between {ACCESS_START_HOUR}:00 and {ACCESS_END_HOUR}:00",
            context["current_time"],
        )

    return True, "Within scheduled hours", context["current_time"]


def check_ip_access(request: Request) -> Tuple[bool, str]:
    if not ALLOWED_IPS:
        return True, "No IP restrictions configured"

    client_ip_text = get_client_ip(request)
    try:
        client_ip = ip_address(client_ip_text)
    except ValueError:
        return False, f"IP {client_ip_text} not in whitelist"

    for rule in ALLOWED_IPS:
        try:
            if "/" in rule:
                network = ip_network(rule, strict=False)
                if client_ip in network:
                    return True, "IP is whitelisted"
            else:
                allowed_ip = ip_address(rule)
                if client_ip == allowed_ip:
                    return True, "IP is whitelisted"
        except ValueError:
            continue

    return False, f"IP {client_ip_text} not in whitelist"


def is_local_admin_request(request: Request) -> bool:
    return get_client_ip(request) in {"127.0.0.1", "::1"}


def get_current_admin(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    employee = get_current_employee(request, authorization)
    if employee.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return employee


def enforce_dashboard_access(request: Request) -> Optional[JSONResponse]:
    allowed_by_time, time_reason, current_time = check_schedule_access()
    if not allowed_by_time:
        append_access_log(request, "TIME_RESTRICTION", False, time_reason)
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "error": "Access Restricted",
                "message": time_reason,
                "accessHours": {
                    "start": f"{ACCESS_START_HOUR}:00",
                    "end": f"{ACCESS_END_HOUR}:00",
                    "timezone": TIMEZONE_NAME,
                    "currentTime": current_time,
                },
            },
        )

    allowed_by_ip, ip_reason = check_ip_access(request)
    if not allowed_by_ip:
        append_access_log(request, "IP_RESTRICTION", False, ip_reason)
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "error": "Access Denied",
                "message": "Your IP address is not authorized to access this resource",
            },
        )

    append_access_log(request, "ACCESS_GRANTED", True, "All checks passed")
    return None


def parse_report_path(stdout_text: str) -> str:
    for line in stdout_text.splitlines():
        if "Report available at:" in line:
            return line.split("Report available at:", 1)[1].strip()
    return ""


def get_current_employee(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        append_access_log(request, "TOKEN_MISSING", False, "No authorization header")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token required")

    token = authorization[7:].strip()
    if not token:
        append_access_log(request, "TOKEN_MISSING", False, "Empty bearer token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token required")

    try:
        decoded = decode_auth_token(token)
    except jwt.ExpiredSignatureError as exc:
        append_access_log(request, "TOKEN_INVALID", False, "Token expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        append_access_log(request, "TOKEN_INVALID", False, "Token verification failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc

    try:
        employee_id = int(decoded.get("sub", "0"))
    except (TypeError, ValueError) as exc:
        append_access_log(request, "TOKEN_INVALID", False, "Invalid token payload")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload") from exc

    employees_data = load_employees()
    employee = find_employee_by_id(employees_data["employees"], employee_id)
    if not employee or not employee.get("active", True):
        append_access_log(request, "TOKEN_INVALID", False, "Employee account not found")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Employee account not found")

    return {"id": employee["id"], "name": employee["name"], "role": employee.get("role", "employee")}


class LoginRequest(BaseModel):
    name: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2)
    password: str = Field(min_length=4)


MAX_LOCATION_LEN            = parse_int(os.getenv("MAX_LOCATION_LEN"),            500)
MAX_NOTES_LEN               = parse_int(os.getenv("MAX_NOTES_LEN"),               2000)
MAX_GPS_OVERRIDE_REASON_LEN = parse_int(os.getenv("MAX_GPS_OVERRIDE_REASON_LEN"), 200)
MAX_GPS_OVERRIDE_DETAIL_LEN = parse_int(os.getenv("MAX_GPS_OVERRIDE_DETAIL_LEN"), 500)


class ClockInRequest(BaseModel):
    location: str = Field(default="", max_length=MAX_LOCATION_LEN)
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class ClockOutRequest(BaseModel):
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class DepartRequest(BaseModel):
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class EntryAdjustRequest(BaseModel):
    clockIn: Optional[str] = None   # "YYYY-MM-DDTHH:MM" local time
    clockOut: Optional[str] = None  # "YYYY-MM-DDTHH:MM" local time, or "" to clear


class ReportGenerateRequest(BaseModel):
    month: int = Field(ge=1, le=12)
    year: int = Field(ge=2000, le=2100)
    emails: List[str] = Field(default=[])
    company_name: str = "Effingham Office Maids"
    send_email: bool = False
    use_mock_data: bool = False


class JobCreateRequest(BaseModel):
    customerName: str = Field(min_length=1)
    scheduledDate: str  # YYYY-MM-DD
    expectedHours: Optional[float] = None
    revenue: Optional[float] = None
    notes: str = ""
    status: str = "scheduled"
    locationId: Optional[int] = None


class JobUpdateRequest(BaseModel):
    customerName: Optional[str] = None
    scheduledDate: Optional[str] = None  # YYYY-MM-DD
    expectedHours: Optional[float] = None
    revenue: Optional[float] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    locationId: Optional[int] = None


class JobLinkShiftsRequest(BaseModel):
    shiftIds: List[int]


VALID_NON_PRODUCTIVE_TYPES = ("drive_time", "waiting", "supply_run", "rework", "lockout", "other")


class ShiftCategorizeRequest(BaseModel):
    timeCategory: str  # "productive" or "non_productive"
    nonProductiveType: Optional[str] = None
    notes: Optional[str] = None


class ScheduleEntryRequest(BaseModel):
    employeeId: int
    customerName: str = Field(min_length=1)
    weekStart: str  # YYYY-MM-DD (must be a Sunday)
    scheduledHours: float
    notes: str = ""
    locationId: Optional[int] = None


load_local_env()

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be configured with at least 32 characters")

TIMEZONE_NAME = os.getenv("TIMEZONE", "America/New_York")
APP_TIMEZONE = ZoneInfo(TIMEZONE_NAME)

TOKEN_TTL_HOURS = parse_int(os.getenv("TOKEN_TTL_HOURS"), 12)
MAX_ACTIVE_SHIFT_HOURS = float(os.getenv("MAX_ACTIVE_SHIFT_HOURS", "24"))
AUTO_CLOSE_STALE_SHIFTS = parse_bool(os.getenv("AUTO_CLOSE_STALE_SHIFTS"), True)
LOCATION_MATCH_RADIUS_M = parse_int(os.getenv("LOCATION_MATCH_RADIUS_M"), LOCATION_MATCH_RADIUS_DEFAULT_M)

ACCESS_START_HOUR = parse_int(os.getenv("ACCESS_START_HOUR"), 8)
ACCESS_END_HOUR = parse_int(os.getenv("ACCESS_END_HOUR"), 18)
validate_schedule(ACCESS_START_HOUR, ACCESS_END_HOUR)
ALLOWED_DAYS = parse_allowed_days(os.getenv("ALLOWED_DAYS"))
ALLOWED_IPS = parse_allowed_ips(os.getenv("ALLOWED_IPS"))
TRUST_PROXY = parse_bool(os.getenv("TRUST_PROXY"), False)
BOOTSTRAP_ADMIN_IDS = [
    int(x) for x in os.getenv("BOOTSTRAP_ADMIN_IDS", "").split(",") if x.strip().isdigit()
]

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ALLOWED_ORIGIN_REGEX = (os.getenv("ALLOWED_ORIGIN_REGEX") or "").strip() or None
MAX_REPORT_RECIPIENTS = parse_int(os.getenv("MAX_REPORT_RECIPIENTS"), 50)
MAX_REPORT_EMAIL_LEN = parse_int(os.getenv("MAX_REPORT_EMAIL_LEN"), 320)

LOGIN_RATE_LIMIT_MAX        = parse_int(os.getenv("LOGIN_RATE_LIMIT_MAX"),        10)
LOGIN_RATE_LIMIT_WINDOW_S   = parse_int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_S"),   60)
REGISTER_RATE_LIMIT_MAX     = parse_int(os.getenv("REGISTER_RATE_LIMIT_MAX"),      3)
REGISTER_RATE_LIMIT_WINDOW_S = parse_int(os.getenv("REGISTER_RATE_LIMIT_WINDOW_S"), 300)
RATE_LIMIT_BUCKET_SOFT_CAP  = parse_int(os.getenv("RATE_LIMIT_BUCKET_SOFT_CAP"), 10000)

# ---------------------------------------------------------------------------
# Business-rule defaults - single source of truth for all threshold settings.
# These seed the `settings` DB table on first boot and serve as in-code
# fallbacks if a key is somehow absent from the DB.
# ---------------------------------------------------------------------------
_SETTINGS_DEFAULTS: Dict[str, Any] = {
    "laborPctTarget":    35.0,   # target labor % of revenue
    "laborPctWatch":     40.0,   # labor % above this = Watch flag
    "laborPctFix":       55.0,   # labor % above this = Fix flag
    "laborPctDrop":      70.0,   # labor % above this = Drop flag
    "grossMarginMin":    30.0,   # gross margin % below this = Watch
    "grossMarginFix":    15.0,   # gross margin % below this = Fix
    "grossMarginDrop":    0.0,   # gross margin % at/below this = Drop
    "hourOverrunWatch":   0.5,   # hours over expected = Watch
    "hourOverrunFix":     2.0,   # hours over expected = Fix
    "rplhMin":           25.0,   # revenue per labor hour below this = flagged
    "laborRateFallback": 15.0,   # avg labor rate used when no employee rates are set
}


def apply_bootstrap_admins() -> None:
    if not BOOTSTRAP_ADMIN_IDS:
        return
    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        changed = False
        for emp in employees_data["employees"]:
            if emp["id"] in BOOTSTRAP_ADMIN_IDS and emp.get("role") != "admin":
                emp["role"] = "admin"
                changed = True
        return changed, None
    update_employees(mutator)


app = FastAPI(title="EOM Time Tracker API", version="2.0.0")

_cors_kwargs: Dict[str, Any] = {
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}
if ALLOWED_ORIGINS or ALLOWED_ORIGIN_REGEX:
    if ALLOWED_ORIGINS:
        _cors_kwargs["allow_origins"] = ALLOWED_ORIGINS
    if ALLOWED_ORIGIN_REGEX:
        _cors_kwargs["allow_origin_regex"] = ALLOWED_ORIGIN_REGEX
else:
    print(
        "[security] WARNING: ALLOWED_ORIGINS / ALLOWED_ORIGIN_REGEX are not set; "
        "falling back to allow_origins=['*']. Set ALLOWED_ORIGINS to your "
        "frontend origin(s) for production.",
        flush=True,
    )
    _cors_kwargs["allow_origins"] = ["*"]

app.add_middleware(CORSMiddleware, **_cors_kwargs)


@app.middleware("http")
async def private_network_access_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(status_code=exc.status_code, content={"success": False, "error": detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    first_error = exc.errors()[0] if exc.errors() else {}
    message = first_error.get("msg", "Invalid request payload")
    return JSONResponse(status_code=422, content={"success": False, "error": message})


def _ensure_schema_migrations() -> None:
    """Idempotent schema additions for existing deployments."""
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS expected_hours NUMERIC(6,2)"
    )
    db.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
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
        )
    """)
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS job_id INTEGER REFERENCES jobs(id)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_scheduled_date ON jobs(scheduled_date)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_customer ON jobs(customer_name)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_shifts_job_id ON shifts(job_id)")
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS target_labor_pct NUMERIC(5,2)"
    )
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS min_margin_pct NUMERIC(5,2)"
    )
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS time_category TEXT NOT NULL DEFAULT 'productive'"
    )
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS non_productive_type TEXT"
    )
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS location_label TEXT NOT NULL DEFAULT ''"
    )
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS clock_in_gps_meta JSONB"
    )
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS clock_out_gps_meta JSONB"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS gps_meta JSONB"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS location_label TEXT NOT NULL DEFAULT ''"
    )
    db.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id              SERIAL PRIMARY KEY,
            employee_id     INTEGER NOT NULL REFERENCES employees(id),
            location_id     INTEGER REFERENCES locations(id),
            customer_name   TEXT NOT NULL,
            week_start      DATE NOT NULL,
            scheduled_hours NUMERIC(6, 2) NOT NULL,
            notes           TEXT NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (employee_id, customer_name, week_start)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS departures (
            id             SERIAL PRIMARY KEY,
            shift_id       INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
            location_id    INTEGER REFERENCES locations(id),
            location_label TEXT NOT NULL DEFAULT '',
            customer_name  TEXT,
            departure_time TIMESTAMPTZ NOT NULL,
            gps            JSONB,
            gps_meta       JSONB,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    db.execute(
        "ALTER TABLE departures ADD COLUMN IF NOT EXISTS location_label TEXT NOT NULL DEFAULT ''"
    )
    db.execute(
        "ALTER TABLE departures ADD COLUMN IF NOT EXISTS gps_meta JSONB"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_schedules_week ON schedules(week_start)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_schedules_employee ON schedules(employee_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_departures_shift_id ON departures(shift_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_departures_time ON departures(departure_time)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_departures_location_id ON departures(location_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_shifts_time_cat ON shifts(time_category)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_shifts_clock_out ON shifts(clock_out)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_locations_active ON locations(active)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_employees_active ON employees(active)")

    # Seed threshold defaults if not already in settings
    for key, default_val in _SETTINGS_DEFAULTS.items():
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (%s, %s::jsonb)
            ON CONFLICT (key) DO NOTHING
            """,
            (key, json.dumps(default_val)),
        )


def _auto_migrate_if_empty() -> None:
    """Run JSON->PostgreSQL migration if the employees table is empty."""
    result = db.query_one("SELECT COUNT(*) AS n FROM employees")
    if result and result["n"] > 0:
        return
    if not EMPLOYEES_FILE.exists() or not TIMESHEETS_FILE.exists():
        return
    migrate_script = BACKEND_DIR / "migrate_json_to_pg.py"
    if not migrate_script.exists():
        return
    database_url = os.getenv("DATABASE_URL", "")
    completed = subprocess.run(
        [sys.executable, str(migrate_script), "--db-url", database_url],
        capture_output=True, text=True, cwd=str(BASE_DIR),
    )
    if completed.returncode != 0:
        print(f"[auto-migrate] ERROR:\n{completed.stderr}", flush=True)
    else:
        print(f"[auto-migrate] Done:\n{completed.stdout}", flush=True)


@app.on_event("startup")
def startup_event() -> None:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL env var not set")
    db.init_pool(database_url)
    _ensure_schema_migrations()
    _auto_migrate_if_empty()
    apply_bootstrap_admins()


@app.get("/api/health")
def health_check(request: Request) -> Dict[str, Any]:
    append_access_log(request, "HEALTH_CHECK", True, "Public endpoint")
    return {
        "status": "ok",
        "serverTime": to_utc_iso(utc_now()),
        "accessSchedule": {
            "hours": f"{ACCESS_START_HOUR}:00 - {ACCESS_END_HOUR}:00",
            "days": ALLOWED_DAYS,
            "timezone": TIMEZONE_NAME,
        },
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> Dict[str, Any]:
    _rate_limit_check(
        request,
        key_prefix="login",
        max_calls=LOGIN_RATE_LIMIT_MAX,
        window_seconds=LOGIN_RATE_LIMIT_WINDOW_S,
    )
    employee_name = payload.name.strip()
    password = payload.password
    if not employee_name or not password:
        append_access_log(request, "LOGIN_FAILED", False, "Missing credentials")
        raise HTTPException(status_code=400, detail="Name and password are required")

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        employee = find_employee_by_name(employees_data["employees"], employee_name)
        if not employee:
            # Burn the same bcrypt budget we would for a real user so the
            # wall-clock response time does not reveal that the username is
            # unknown.
            verify_password(password, _DUMMY_PASSWORD_HASH)
            return False, None
        if not verify_password(password, employee["password"]):
            return False, None

        employee["lastLogin"] = to_utc_iso(utc_now())
        return True, {"id": employee["id"], "name": employee["name"], "role": employee.get("role", "employee")}

    ok, employee = update_employees(mutator)
    if not ok or not employee:
        append_access_log(request, "LOGIN_FAILED", False, "Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid name or password")

    token = create_auth_token(employee["id"], employee["name"], employee.get("role", "employee"))
    append_access_log(request, "LOGIN_SUCCESS", True, f"Employee: {employee['name']}")
    return {
        "success": True,
        "token": token,
        "employee": {"id": employee["id"], "name": employee["name"], "role": employee.get("role", "employee")},
    }


@app.post("/api/auth/register")
def register(payload: RegisterRequest, request: Request) -> Dict[str, Any]:
    _rate_limit_check(
        request,
        key_prefix="register",
        max_calls=REGISTER_RATE_LIMIT_MAX,
        window_seconds=REGISTER_RATE_LIMIT_WINDOW_S,
    )
    employee_name = payload.name.strip()
    password = payload.password
    if not employee_name or not password:
        raise HTTPException(status_code=400, detail="Name and password are required")

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(10)).decode("utf-8")

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        existing = find_employee_by_name(employees_data["employees"], employee_name)
        if existing:
            return False, "An account with that name already exists"

        employee_id = int(employees_data["nextId"])
        employee = {
            "id": employee_id,
            "name": employee_name,
            "password": hashed,
            "active": True,
            "role": "employee",
            "created": to_utc_iso(utc_now()),
            "lastLogin": None,
        }
        employees_data["employees"].append(employee)
        employees_data["nextId"] = employee_id + 1
        return True, {"id": employee_id, "name": employee_name}

    ok, result = update_employees(mutator)
    if not ok:
        append_access_log(request, "REGISTER_FAILED", False, str(result))
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(request, "REGISTER_SUCCESS", True, f"New employee: {employee_name}")
    return {"success": True, "employee": result}


@app.patch("/api/admin/employees/{employee_id}")
def admin_update_employee(
    employee_id: int,
    payload: Dict[str, Any],
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    allowed_roles = {"admin", "employee"}
    new_role = payload.get("role", "").strip().lower()
    if new_role and new_role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(allowed_roles)}")

    new_password = payload.get("password", "").strip()
    if new_password and len(new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(10)).decode() if new_password else None

    new_hourly_rate = None
    if "hourlyRate" in payload:
        raw_rate = payload["hourlyRate"]
        if raw_rate is not None:
            try:
                new_hourly_rate = float(raw_rate)
                if new_hourly_rate < 0:
                    raise HTTPException(status_code=400, detail="Hourly rate cannot be negative")
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="Invalid hourly rate")
        else:
            new_hourly_rate = None

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        emp = find_employee_by_id(employees_data["employees"], employee_id)
        if not emp:
            return False, "Employee not found"
        if new_role:
            emp["role"] = new_role
        if "active" in payload:
            emp["active"] = bool(payload["active"])
        if hashed_password:
            emp["password"] = hashed_password
        if "hourlyRate" in payload:
            emp["hourlyRate"] = new_hourly_rate
        return True, {"id": emp["id"], "name": emp["name"], "role": emp["role"], "active": emp["active"], "hourlyRate": emp.get("hourlyRate")}

    ok, result = update_employees(mutator)
    if not ok:
        raise HTTPException(status_code=404, detail=str(result))
    append_access_log(request, "EMPLOYEE_UPDATED", True, f"id={employee_id} {payload}")
    return {"success": True, "employee": result}


@app.get("/api/admin/employees")
def admin_list_employees(
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    if employee.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    aggregate_rows = db.query_all(
        """
        WITH shift_stats AS (
            SELECT
                s.employee_id,
                SUM(
                    CASE
                        WHEN s.clock_out IS NOT NULL
                            THEN GREATEST(0.0, EXTRACT(EPOCH FROM (s.clock_out - s.clock_in)) / 3600.0)
                        ELSE GREATEST(0.0, LEAST(%s, EXTRACT(EPOCH FROM (NOW() - s.clock_in)) / 3600.0))
                    END
                ) AS total_hours,
                COUNT(*) AS total_shifts
            FROM shifts s
            GROUP BY s.employee_id
        ),
        last_shift AS (
            SELECT DISTINCT ON (s.employee_id)
                s.employee_id,
                COALESCE(s.clock_in_gps, s.clock_out_gps) AS last_gps
            FROM shifts s
            ORDER BY s.employee_id, s.clock_in DESC
        )
        SELECT
            e.id, e.name, e.role, e.active, e.hourly_rate,
            e.created_at, e.last_login_at,
            COALESCE(ss.total_hours, 0) AS total_hours,
            COALESCE(ss.total_shifts, 0) AS total_shifts,
            ls.last_gps
        FROM employees e
        LEFT JOIN shift_stats ss ON ss.employee_id = e.id
        LEFT JOIN last_shift  ls ON ls.employee_id = e.id
        ORDER BY e.id
        """,
        (MAX_ACTIVE_SHIFT_HOURS,),
    )

    rows = []
    for r in aggregate_rows:
        rate = r.get("hourly_rate")
        created = r.get("created_at")
        last_login = r.get("last_login_at")
        rows.append({
            "id":          r["id"],
            "name":        r["name"],
            "role":        r.get("role", "employee"),
            "active":      r["active"],
            "created":     to_utc_iso(created) if created else None,
            "lastLogin":   to_utc_iso(last_login) if last_login else None,
            "totalHours":  round(float(r.get("total_hours") or 0), 2),
            "totalShifts": int(r.get("total_shifts") or 0),
            "lastGps":     r.get("last_gps"),
            "hourlyRate":  float(rate) if rate is not None else None,
        })

    append_access_log(request, "ADMIN_EMPLOYEES", True, f"{len(rows)} employees")
    return {"success": True, "employees": rows}


@app.get("/api/admin/employees/{employee_id}/hours")
def admin_employee_hours(
    employee_id: int,
    request: Request,
    week_offset: int = 0,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    employees_data = load_employees()
    emp = next((e for e in employees_data["employees"] if e["id"] == employee_id), None)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    timesheet_data = load_timesheets()
    location_customers = timesheet_data.get("location_customers", {})
    now = utc_now()

    days_since_monday = now.weekday()
    week_start = (now - timedelta(days=days_since_monday)).replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    today_str = local_date_string(now)

    emp_entries = [e for e in timesheet_data["entries"] if e.get("employeeId") == employee_id]

    today_hours = 0.0
    weekly_hours = 0.0
    monthly_hours = 0.0
    yearly_hours = 0.0
    all_time_hours = 0.0
    shifts: List[Dict[str, Any]] = []

    for entry in emp_entries:
        clock_in_str = str(entry.get("clockIn", "")).strip()
        if not clock_in_str:
            continue
        try:
            clock_in_dt = parse_utc_iso(clock_in_str)
        except ValueError:
            continue

        total = entry_hours(entry, now)
        entry_date = local_date_string(clock_in_dt)

        all_time_hours += total
        if clock_in_dt >= year_start:
            yearly_hours += total
        if clock_in_dt >= month_start:
            monthly_hours += total
        if clock_in_dt >= week_start:
            weekly_hours += total
        if entry_date == today_str:
            today_hours += total

        clock_out_display = "Active"
        if entry.get("clockOut"):
            try:
                clock_out_display = local_clock_string(parse_utc_iso(str(entry["clockOut"])))
            except ValueError:
                pass

        loc = entry.get("location", "")
        shifts.append({
            "date": entry_date,
            "clockIn": local_clock_string(clock_in_dt),
            "clockOut": clock_out_display,
            "hours": round(total, 2),
            "location": loc,
            "customer": location_customers.get(loc, ""),
        })

    shifts.sort(key=lambda x: (x["date"], x["clockIn"]), reverse=True)

    # Build weekly grid (Sun-Sat) for the requested week
    days_since_sunday = (now.weekday() + 1) % 7
    this_sunday_utc = (now - timedelta(days=days_since_sunday)).replace(hour=0, minute=0, second=0, microsecond=0)
    grid_sunday_utc = this_sunday_utc + timedelta(weeks=week_offset)
    grid_saturday_utc = grid_sunday_utc + timedelta(days=6, hours=23, minutes=59, seconds=59)

    shifts_by_date: Dict[str, list] = {}
    for entry in emp_entries:
        ci_str = str(entry.get("clockIn", "")).strip()
        if not ci_str:
            continue
        try:
            ci_dt = parse_utc_iso(ci_str)
        except ValueError:
            continue
        if not (grid_sunday_utc <= ci_dt <= grid_saturday_utc):
            continue
        d_str = local_date_string(ci_dt)
        co_disp = "Active"
        if entry.get("clockOut"):
            try:
                co_disp = local_clock_string(parse_utc_iso(str(entry["clockOut"])))
            except ValueError:
                pass
        co_iso = None
        if entry.get("clockOut"):
            try:
                co_iso = to_local(parse_utc_iso(str(entry["clockOut"]))).strftime("%Y-%m-%dT%H:%M")
            except ValueError:
                pass
        loc = entry.get("location", "")
        raw_visits = entry.get("visits") or []
        visit_rows = []
        for j, v in enumerate(raw_visits):
            if not isinstance(v, dict) or not v.get("arrivalTime"):
                continue
            try:
                v_arr = parse_utc_iso(str(v["arrivalTime"]))
            except ValueError:
                continue
            visit_rows.append({
                "arrivalTime": local_clock_string(v_arr),
                "location": v.get("location", ""),
                "customer": v.get("customer", ""),
            })
        shifts_by_date.setdefault(d_str, []).append({
            "id": entry["id"],
            "clockIn": local_clock_string(ci_dt),
            "clockInIso": to_local(ci_dt).strftime("%Y-%m-%dT%H:%M"),
            "clockOut": co_disp,
            "clockOutIso": co_iso,
            "hours": round(entry_hours(entry, now), 2),
            "location": loc,
            "customer": location_customers.get(loc, ""),
            "isActive": entry.get("clockOut") is None,
            "visits": visit_rows,
        })

    week_grid = []
    week_total = 0.0
    for i in range(7):
        day_utc = grid_sunday_utc + timedelta(days=i)
        d_str = local_date_string(day_utc)
        day_shifts = shifts_by_date.get(d_str, [])
        day_hours = round(sum(s["hours"] for s in day_shifts), 2)
        week_total += day_hours
        week_grid.append({
            "date": d_str,
            "dayLabel": to_local(day_utc).strftime("%a, %b %-d"),
            "shifts": day_shifts,
            "totalHours": day_hours,
        })

    return {
        "success": True,
        "employeeId": employee_id,
        "employeeName": emp["name"],
        "todayHours": round(today_hours, 2),
        "weeklyHours": round(weekly_hours, 2),
        "monthlyHours": round(monthly_hours, 2),
        "yearlyHours": round(yearly_hours, 2),
        "allTimeHours": round(all_time_hours, 2),
        "weekGrid": week_grid,
        "weekTotal": round(week_total, 2),
        "weekOffset": week_offset,
        "weekStartDate": local_date_string(grid_sunday_utc),
        "shifts": shifts[:50],
    }


@app.post("/api/timesheet/clock-in")
def clock_in(
    payload: ClockInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    notes = payload.notes.strip()
    has_gps = payload.latitude is not None and payload.longitude is not None
    now_utc = utc_now()
    work_date = datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d")

    def mutator(timesheet_data: Dict[str, Any]) -> Tuple[bool, Any]:
        existing_open = get_open_entry(timesheet_data["entries"], employee["id"])
        if existing_open and not is_stale_open_entry(existing_open, now_utc):
            return False, "Already clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
        )
        if override_error:
            return False, override_error

        # Auto-match location from GPS; fall back to provided string or GPS coords
        if has_gps:
            matched = find_nearest_location(payload.latitude, payload.longitude, timesheet_data)
            location = matched or payload.location.strip() or f"GPS {payload.latitude:.5f},{payload.longitude:.5f}"
        else:
            location = payload.location.strip() or "Unknown"

        entry_id = int(timesheet_data["nextId"])
        entry = {
            "id": entry_id,
            "employeeId": employee["id"],
            "employeeName": employee["name"],
            "location": location,
            "clockIn": to_utc_iso(now_utc),
            "clockOut": None,
            "totalHours": 0,
            "notes": notes,
            "date": work_date,
            "timezone": TIMEZONE_NAME,
            "clockInGps": None,
            "clockInGpsMeta": None,
            "clockOutGps": None,
            "clockOutGpsMeta": None,
            "jobId": None,
            "timeCategory": "productive",
            "nonProductiveType": None,
            "visits": [],
        }
        if has_gps:
            entry["clockInGps"] = {"lat": payload.latitude, "lng": payload.longitude}
        entry["clockInGpsMeta"] = build_gps_meta(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
            payload.gpsOverrideDetail,
        )
        timesheet_data["entries"].append(entry)
        timesheet_data["nextId"] = entry_id + 1
        return True, entry

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "CLOCK_IN_FAILED", False, str(result))
        raise HTTPException(status_code=400, detail=str(result))

    loc = result.get("location", "")
    location_customers: Dict[str, str] = load_timesheets().get("location_customers", {})
    result["customer"] = _resolve_customer(loc, location_customers)
    append_access_log(request, "CLOCK_IN_SUCCESS", True, f"Employee: {employee['name']} at {loc}")
    return {"success": True, "entry": result}


@app.post("/api/timesheet/clock-out")
def clock_out(
    request: Request,
    payload: Optional[ClockOutRequest] = None,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    notes = payload.notes.strip() if payload else ""
    now_utc = utc_now()

    def mutator(timesheet_data: Dict[str, Any]) -> Tuple[bool, Any]:
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry or is_stale_open_entry(open_entry, now_utc):
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
        )
        if override_error:
            return False, override_error

        try:
            clock_in_time = parse_utc_iso(str(open_entry.get("clockIn", "")))
        except ValueError:
            return False, "Invalid clock-in timestamp"

        total_hours = (now_utc - clock_in_time).total_seconds() / 3600
        if total_hours < 0:
            return False, "Invalid clock-in timestamp"

        open_entry["clockOut"] = to_utc_iso(now_utc)
        open_entry["totalHours"] = round(total_hours, 2)
        if notes:
            open_entry["notes"] = notes
        if payload and payload.latitude is not None and payload.longitude is not None:
            open_entry["clockOutGps"] = {
                "lat": payload.latitude,
                "lng": payload.longitude,
            }
        open_entry["clockOutGpsMeta"] = build_gps_meta(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
            payload.gpsOverrideDetail if payload else "",
        )

        return True, open_entry

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "CLOCK_OUT_FAILED", False, str(result))
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(
        request,
        "CLOCK_OUT_SUCCESS",
        True,
        f"Employee: {employee['name']}, Hours: {result.get('totalHours', 0)}",
    )
    return {"success": True, "entry": result}


@app.post("/api/timesheet/visit")
def log_visit(
    payload: ClockInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    """Auto-log an arrival at a new location during an active shift."""
    has_gps = payload.latitude is not None and payload.longitude is not None
    now_utc = utc_now()

    def mutator(timesheet_data: Dict[str, Any]) -> Tuple[bool, Any]:
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry or is_stale_open_entry(open_entry, now_utc):
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
        )
        if override_error:
            return False, override_error

        if has_gps:
            matched = find_nearest_location(payload.latitude, payload.longitude, timesheet_data)
            location = matched or str(payload.location or "").strip() or f"GPS {payload.latitude:.5f},{payload.longitude:.5f}"
        else:
            location = str(payload.location or "").strip() or "Unknown"

        customer = timesheet_data.get("location_customers", {}).get(location, "")

        # Avoid duplicate: skip if location matches the most recent visit
        existing_visits = open_entry.get("visits") or []
        active_visit = get_active_visit(open_entry)
        if active_visit and active_visit.get("location") == location:
            return False, "already_at_location"

        visit = {
            "arrivalTime": to_utc_iso(now_utc),
            "location": location,
            "customer": customer,
            "gps": {"lat": payload.latitude, "lng": payload.longitude} if has_gps else None,
            "gpsMeta": build_gps_meta(
                timesheet_data,
                payload.latitude,
                payload.longitude,
                payload.gpsOverrideReason,
                payload.gpsOverrideDetail,
            ),
        }

        if not isinstance(open_entry.get("visits"), list):
            open_entry["visits"] = []
        open_entry["visits"].append(visit)

        return True, {"visit": visit, "entryId": open_entry["id"]}

    ok, result = update_timesheets(mutator)
    if not ok:
        if result == "already_at_location":
            return {"success": True, "alreadyHere": True}
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(request, "VISIT_LOGGED", True,
                      f"Employee: {employee['name']} arrived at {result['visit']['location']}")
    return {"success": True, "alreadyHere": False, **result}


def get_active_visit(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    visits = entry.get("visits") or []
    if not visits:
        return None

    departures = entry.get("departures") or []
    if len(departures) >= len(visits):
        return None

    last_visit = visits[-1]
    arrival_time = str(last_visit.get("arrivalTime", "")).strip()
    return last_visit if arrival_time else None


@app.post("/api/timesheet/depart")
def depart_location(
    payload: Optional[DepartRequest],
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    now_utc = utc_now()

    def mutator(timesheet_data: Dict[str, Any]) -> Tuple[bool, Any]:
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry or is_stale_open_entry(open_entry, now_utc):
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
        )
        if override_error:
            return False, override_error

        active_visit = get_active_visit(open_entry)
        if not active_visit:
            return False, "No active arrival to depart from"

        departure = {
            "departureTime": to_utc_iso(now_utc),
            "location": active_visit.get("location", ""),
            "customer": active_visit.get("customer", ""),
            "gps": None,
            "gpsMeta": build_gps_meta(
                timesheet_data,
                payload.latitude if payload else None,
                payload.longitude if payload else None,
                payload.gpsOverrideReason if payload else "",
                payload.gpsOverrideDetail if payload else "",
            ),
        }
        if payload and payload.latitude is not None and payload.longitude is not None:
            departure["gps"] = {
                "lat": payload.latitude,
                "lng": payload.longitude,
            }

        if not isinstance(open_entry.get("departures"), list):
            open_entry["departures"] = []
        open_entry["departures"].append(departure)

        if payload and payload.notes and not str(open_entry.get("notes", "")).strip():
            open_entry["notes"] = payload.notes.strip()

        return True, {"departure": departure, "entryId": open_entry["id"]}

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "DEPARTURE_FAILED", False, str(result))
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(
        request,
        "DEPARTURE_LOGGED",
        True,
        f"Employee: {employee['name']} departed {result['departure']['location']}",
    )
    return {"success": True, **result}


@app.patch("/api/admin/entries/{entry_id}")
def admin_adjust_entry(
    entry_id: int,
    payload: EntryAdjustRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    def parse_local_dt(s: str) -> datetime:
        return datetime.strptime(s.strip()[:16], "%Y-%m-%dT%H:%M").replace(tzinfo=APP_TIMEZONE)

    def mutator(timesheet_data: Dict[str, Any]) -> Tuple[bool, Any]:
        entry = next((e for e in timesheet_data["entries"] if e["id"] == entry_id), None)
        if not entry:
            return False, "Entry not found"

        new_ci_utc: Optional[datetime] = None
        new_co_utc: Optional[datetime] = None

        if payload.clockIn:
            try:
                new_ci_utc = parse_local_dt(payload.clockIn).astimezone(timezone.utc)
            except ValueError:
                return False, "Invalid clockIn - use YYYY-MM-DDTHH:MM"

        if payload.clockOut is not None:
            if payload.clockOut.strip() == "":
                # Clear clock-out -> make shift active again
                entry["clockOut"] = None
                entry["totalHours"] = 0.0
            else:
                try:
                    new_co_utc = parse_local_dt(payload.clockOut).astimezone(timezone.utc)
                except ValueError:
                    return False, "Invalid clockOut - use YYYY-MM-DDTHH:MM"

        # Apply clock-in change
        if new_ci_utc is not None:
            entry["clockIn"] = to_utc_iso(new_ci_utc)
            entry["date"] = new_ci_utc.astimezone(APP_TIMEZONE).strftime("%Y-%m-%d")

        # Apply clock-out change
        if new_co_utc is not None:
            try:
                ci_utc = parse_utc_iso(str(entry["clockIn"]))
            except ValueError:
                return False, "Existing clock-in is malformed; adjust clockIn first"
            if new_co_utc <= ci_utc:
                return False, "Clock-out must be after clock-in"
            entry["clockOut"] = to_utc_iso(new_co_utc)
            entry["totalHours"] = round((new_co_utc - ci_utc).total_seconds() / 3600, 2)
        elif new_ci_utc is not None and entry.get("clockOut"):
            # Recalculate hours after clock-in shift
            try:
                co_utc = parse_utc_iso(str(entry["clockOut"]))
                if co_utc <= new_ci_utc:
                    return False, "Clock-out must be after clock-in"
                entry["totalHours"] = round((co_utc - new_ci_utc).total_seconds() / 3600, 2)
            except ValueError:
                pass

        return True, entry

    ok, result = update_timesheets(mutator)
    if not ok:
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(request, "ENTRY_ADJUSTED", True, f"Entry {entry_id} adjusted by admin")
    return {"success": True, "entry": result}


@app.get("/api/timesheet/my-hours")
def my_timesheet_hours(
    request: Request,
    current_employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    timesheet_data = load_timesheets()
    location_customers: Dict[str, str] = timesheet_data.get("location_customers", {})
    employee_id = current_employee["id"]
    now = utc_now()

    days_since_monday = now.weekday()
    week_start = (now - timedelta(days=days_since_monday)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    today_str = local_date_string(now)

    my_entries = [
        e for e in timesheet_data.get("entries", [])
        if e.get("employeeId") == employee_id
    ]

    weekly_hours = 0.0
    today_hours = 0.0
    monthly_hours = 0.0
    yearly_hours = 0.0
    recent_shifts: List[Dict[str, Any]] = []

    for entry in my_entries:
        clock_in_str = str(entry.get("clockIn", "")).strip()
        if not clock_in_str:
            continue
        try:
            clock_in_dt = parse_utc_iso(clock_in_str)
        except ValueError:
            continue

        total = entry_hours(entry, now)
        entry_date = local_date_string(clock_in_dt)

        if clock_in_dt >= week_start:
            weekly_hours += total
        if entry_date == today_str:
            today_hours += total
        if clock_in_dt >= month_start:
            monthly_hours += total
        if clock_in_dt >= year_start:
            yearly_hours += total

        clock_out_display = "Active"
        if entry.get("clockOut"):
            try:
                clock_out_display = local_clock_string(parse_utc_iso(str(entry["clockOut"])))
            except ValueError:
                pass

        loc = entry.get("location", "")
        recent_shifts.append({
            "date": entry_date,
            "clockIn": local_clock_string(clock_in_dt),
            "clockOut": clock_out_display,
            "hours": round(total, 2),
            "location": loc,
            "customer": _resolve_customer(loc, location_customers),
        })

    recent_shifts.sort(key=lambda x: (x["date"], x["clockIn"]), reverse=True)
    append_access_log(request, "MY_HOURS_SUCCESS", True, f"Employee: {current_employee['name']}")
    return {
        "success": True,
        "todayHours": round(today_hours, 2),
        "weeklyHours": round(weekly_hours, 2),
        "monthlyHours": round(monthly_hours, 2),
        "yearlyHours": round(yearly_hours, 2),
        "recentShifts": recent_shifts[:30],
    }


@app.get("/api/timesheet/locations")
def timesheet_locations(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    payload = load_timesheets()
    append_access_log(request, "LOCATIONS_SUCCESS", True, "Locations fetched")
    return {"success": True, "locations": payload["locations"], "location_coords": payload["location_coords"], "location_customers": payload["location_customers"], "location_rates": payload["location_rates"], "location_rate_types": payload["location_rate_types"], "location_types": payload["location_types"], "location_frequencies": payload["location_frequencies"], "location_expected_hours": payload.get("location_expected_hours", {}), "locationMatchRadiusM": LOCATION_MATCH_RADIUS_M}


@app.put("/api/admin/locations")
def admin_update_locations(
    payload: Dict[str, Any],
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    raw = payload.get("locations")
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail="locations must be a list")

    locations = []
    location_coords: Dict[str, Dict[str, float]] = {}
    location_customers: Dict[str, str] = {}
    location_rates: Dict[str, float] = {}
    location_rate_types: Dict[str, str] = {}
    location_types: Dict[str, str] = {}
    location_frequencies: Dict[str, str] = {}
    location_expected_hours: Dict[str, float] = {}
    location_target_labor: Dict[str, float] = {}
    location_min_margin: Dict[str, float] = {}
    for item in raw:
        if isinstance(item, dict) and item.get("name", "").strip():
            name = str(item["name"]).strip()
            locations.append(name)
            if item.get("lat") is not None and item.get("lng") is not None:
                try:
                    location_coords[name] = {"lat": float(item["lat"]), "lng": float(item["lng"])}
                except (TypeError, ValueError):
                    pass
            if item.get("customer", "").strip():
                location_customers[name] = str(item["customer"]).strip()
            if item.get("rate") is not None:
                try:
                    location_rates[name] = float(item["rate"])
                except (TypeError, ValueError):
                    pass
            if item.get("rateType") in ("per_visit", "hourly", "monthly"):
                location_rate_types[name] = item["rateType"]
            if item.get("type") in ("Residential", "Commercial"):
                location_types[name] = item["type"]
            if isinstance(item.get("frequency"), str) and item["frequency"].strip():
                location_frequencies[name] = item["frequency"].strip()
            if item.get("expectedHours") is not None:
                try:
                    location_expected_hours[name] = float(item["expectedHours"])
                except (TypeError, ValueError):
                    pass
            if item.get("targetLaborPct") is not None:
                try:
                    location_target_labor[name] = float(item["targetLaborPct"])
                except (TypeError, ValueError):
                    pass
            if item.get("minMarginPct") is not None:
                try:
                    location_min_margin[name] = float(item["minMarginPct"])
                except (TypeError, ValueError):
                    pass
        elif isinstance(item, str) and item.strip():
            locations.append(item.strip())

    def mutator(data: Dict[str, Any]) -> Tuple[bool, Any]:
        data["locations"] = locations
        data["location_coords"] = location_coords
        data["location_customers"] = location_customers
        data["location_rates"] = location_rates
        data["location_rate_types"] = location_rate_types
        data["location_types"] = location_types
        data["location_frequencies"] = location_frequencies
        data["location_expected_hours"] = location_expected_hours
        data["location_target_labor"] = location_target_labor
        data["location_min_margin"] = location_min_margin
        return True, locations

    update_timesheets(mutator)
    append_access_log(request, "LOCATIONS_UPDATED", True, f"{len(locations)} locations, {len(location_coords)} with coords")
    return {"success": True, "locations": locations, "location_coords": location_coords, "location_customers": location_customers, "location_rates": location_rates, "location_rate_types": location_rate_types, "location_types": location_types, "location_frequencies": location_frequencies, "location_expected_hours": location_expected_hours, "location_target_labor": location_target_labor, "location_min_margin": location_min_margin}


@app.patch("/api/admin/locations/pin")
def admin_patch_location_pin(
    payload: Dict[str, Any],
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    location = str(payload.get("location", "")).strip()
    lat = payload.get("lat")
    lng = payload.get("lng")
    if not location:
        raise HTTPException(status_code=400, detail="location required")
    if lat is None or lng is None:
        raise HTTPException(status_code=400, detail="lat and lng required")
    try:
        lat, lng = float(lat), float(lng)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="lat and lng must be numbers")

    def mutator(data: Dict[str, Any]) -> Tuple[bool, Any]:
        if location not in data.get("locations", []):
            return False, "Location not found"
        data.setdefault("location_coords", {})[location] = {"lat": lat, "lng": lng}
        return True, None

    ok, err = update_timesheets(mutator)
    if not ok:
        raise HTTPException(status_code=400, detail=str(err))

    append_access_log(request, "LOCATION_PIN_SET", True, f"Pin set for: {location}")
    return {"success": True}


@app.get("/api/timesheet/current-status")
def timesheet_current_status(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    rows = build_public_current_status()
    response_rows = [
        {
            "employeeName": row["name"],
            "location": row["location"],
            "customer": row.get("customer", ""),
            "clockInTime": row["clockedInAt"],
            "hoursWorked": row["hoursWorked"],
            "notes": row["notes"],
            "clockInGps": row.get("clockInGps"),
            "clockInGpsMeta": row.get("clockInGpsMeta"),
            "visits": row.get("visits", []),
            "departures": row.get("departures", []),
            "activeVisit": row.get("activeVisit"),
            "canDepart": row.get("canDepart", False),
        }
        for row in rows
    ]
    append_access_log(request, "CURRENT_STATUS_SUCCESS", True, f"{len(response_rows)} employees working")
    return {"success": True, "currentlyWorking": response_rows}


@app.get("/api/hours")
def dashboard_hours(request: Request) -> Any:
    denied_response = enforce_dashboard_access(request)
    if denied_response is not None:
        return denied_response

    payload = build_dashboard_hours_data()
    return {"success": True, "data": payload, "timestamp": to_utc_iso(utc_now())}


@app.get("/api/current-status")
def dashboard_current_status(request: Request) -> Any:
    denied_response = enforce_dashboard_access(request)
    if denied_response is not None:
        return denied_response

    rows = build_public_current_status()
    return {
        "success": True,
        "currentlyWorking": rows,
        "count": len(rows),
        "timestamp": to_utc_iso(utc_now()),
    }


def read_access_logs_for_date(date_text: str) -> List[Dict[str, Any]]:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text):
        return []

    log_file = LOGS_DIR / f"access_{date_text}.json"
    payload = read_json_file(log_file, [])
    if not isinstance(payload, list):
        return []
    return payload


@app.get("/api/admin/logs")
def admin_logs_today(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    date_text = local_date_for_logs()
    return {"success": True, "date": date_text, "logs": read_access_logs_for_date(date_text)}


@app.get("/api/admin/logs/{date_text}")
def admin_logs_by_date(
    date_text: str,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    return {"success": True, "date": date_text, "logs": read_access_logs_for_date(date_text)}


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.post("/api/admin/generate-report")
def admin_generate_report(
    payload: ReportGenerateRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:

    if payload.send_email and payload.emails:
        if len(payload.emails) > MAX_REPORT_RECIPIENTS:
            raise HTTPException(
                status_code=400,
                detail=f"Too many recipients (max {MAX_REPORT_RECIPIENTS})",
            )
        for email in payload.emails:
            if not isinstance(email, str) or len(email) > MAX_REPORT_EMAIL_LEN or not _EMAIL_PATTERN.match(email):
                raise HTTPException(status_code=400, detail=f"Invalid email: {email[:64]!r}")

    append_access_log(request, "REPORT_GENERATION_STARTED", True, f"Month: {payload.month}/{payload.year}")

    script_path = BACKEND_DIR / "monthly_report_main.py"
    args = [
        sys.executable,
        str(script_path),
        "--month",
        str(payload.month),
        "--year",
        str(payload.year),
        "--output-dir",
        str(REPORTS_DIR),
    ]

    if payload.use_mock_data:
        args.append("--mock-data")

    if payload.company_name:
        args.extend(["--company", payload.company_name])

    if payload.send_email and payload.emails:
        for email in payload.emails:
            args.extend(["--email", email])
    else:
        args.append("--no-email")

    try:
        completed = subprocess.run(
            args,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        append_access_log(request, "REPORT_GENERATION_FAILED", False, "Timed out")
        raise HTTPException(status_code=408, detail="Report generation timed out")

    stdout_text = completed.stdout or ""
    stderr_text = completed.stderr or ""

    if completed.returncode != 0:
        # Log full subprocess output server-side for debugging, but do NOT
        # return it to the client: stderr can carry tracebacks, file paths,
        # or values pulled from environment variables (e.g. DB DSN parts).
        print(
            f"[report-gen] exit={completed.returncode}\n"
            f"  stdout: {stdout_text}\n  stderr: {stderr_text}",
            flush=True,
        )
        append_access_log(request, "REPORT_GENERATION_FAILED", False, f"Exit code: {completed.returncode}")
        return {
            "success": False,
            "error": "Report generation failed",
            "exitCode": completed.returncode,
        }

    report_path = parse_report_path(stdout_text).strip().strip("'\"")
    if not report_path:
        print(
            f"[report-gen] no report path in stdout\n"
            f"  stdout: {stdout_text}\n  stderr: {stderr_text}",
            flush=True,
        )
        append_access_log(request, "REPORT_GENERATION_FAILED", False, "No report path returned by generator")
        return {
            "success": False,
            "error": "Report generation failed",
            "exitCode": completed.returncode,
        }

    absolute_report_path = Path(report_path)
    if not absolute_report_path.is_absolute():
        absolute_report_path = (BASE_DIR / report_path).resolve()
    if not absolute_report_path.exists() or not absolute_report_path.is_file():
        append_access_log(
            request,
            "REPORT_GENERATION_FAILED",
            False,
            f"Report file not found: {absolute_report_path}",
        )
        return {
            "success": False,
            "error": "Report generation failed",
            "details": f"Report file not found: {absolute_report_path}",
            "exitCode": completed.returncode,
        }

    if not absolute_report_path.is_relative_to(REPORTS_DIR.resolve()):
        append_access_log(request, "REPORT_GENERATION_FAILED", False, "Report path outside reports directory")
        return {
            "success": False,
            "error": "Report generation failed",
            "details": "Unsafe report path returned by generator",
            "exitCode": completed.returncode,
        }

    append_access_log(request, "REPORT_GENERATION_SUCCESS", True, f"Generated: {absolute_report_path}")
    return {
        "success": True,
        "message": "Report generated successfully",
        "reportPath": str(absolute_report_path),
        "output": stdout_text,
        "emailSent": payload.send_email and len(payload.emails) > 0,
    }


@app.get("/api/admin/download-report/{filename}")
def admin_download_report(
    filename: str,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> FileResponse:

    reports_root = REPORTS_DIR.resolve()
    target_path = (REPORTS_DIR / filename).resolve()

    if not target_path.is_relative_to(reports_root):
        append_access_log(request, "DOWNLOAD_DENIED", False, "Path traversal attempt")
        raise HTTPException(status_code=403, detail="Access denied")

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    append_access_log(request, "REPORT_DOWNLOAD", True, filename)
    return FileResponse(str(target_path), media_type="application/pdf", filename=filename)


def _compute_hours_report(period: str, date_str: Optional[str], employee_id: Optional[int], exceptions_only: bool = False) -> Dict[str, Any]:
    now = utc_now()
    local_now = to_local(now)

    if date_str:
        try:
            ref_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")
    else:
        ref_date = local_now.date()

    if period == "day":
        start_date = ref_date
        end_date = ref_date
    elif period == "week":
        days_since_sunday = (ref_date.weekday() + 1) % 7
        start_date = ref_date - timedelta(days=days_since_sunday)
        end_date = start_date + timedelta(days=6)
    elif period == "month":
        start_date = ref_date.replace(day=1)
        if start_date.month == 12:
            end_date = start_date.replace(year=start_date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = start_date.replace(month=start_date.month + 1, day=1) - timedelta(days=1)
    elif period == "year":
        start_date = ref_date.replace(month=1, day=1)
        end_date = ref_date.replace(month=12, day=31)
    else:
        raise HTTPException(status_code=400, detail="period must be day, week, month, or year")

    timesheet_data = load_timesheets()
    location_customers: Dict[str, str] = timesheet_data.get("location_customers", {})
    employees_data = load_employees()
    emp_names = {emp["id"]: emp["name"] for emp in employees_data["employees"]}

    rows = []
    emp_totals: Dict[int, Dict[str, Any]] = {}

    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is None:
            continue
        ci_str = str(entry.get("clockIn", "")).strip()
        if not ci_str:
            continue
        try:
            ci_dt = parse_utc_iso(ci_str)
        except ValueError:
            continue

        entry_date = to_local(ci_dt).date()
        if not (start_date <= entry_date <= end_date):
            continue

        emp_id = int(entry.get("employeeId", 0))
        if employee_id and emp_id != employee_id:
            continue

        emp_name = emp_names.get(emp_id, str(entry.get("employeeName", f"Employee {emp_id}")))
        hours = float(entry.get("totalHours", 0) or 0)

        try:
            co_dt = parse_utc_iso(str(entry["clockOut"]))
            co_display = local_clock_string(co_dt)
        except (ValueError, KeyError):
            co_display = "-"

        loc = entry.get("location", "")
        gps_exceptions = collect_entry_gps_exceptions(entry)
        if exceptions_only and not gps_exceptions:
            continue
        rows.append({
            "employeeId": emp_id,
            "employeeName": emp_name,
            "date": entry_date.strftime("%Y-%m-%d"),
            "dateLabel": to_local(ci_dt).strftime("%a, %b %-d"),
            "clockIn": local_clock_string(ci_dt),
            "clockOut": co_display,
            "hours": round(hours, 2),
            "location": loc,
            "customer": _resolve_customer(loc, location_customers),
            "gpsExceptions": gps_exceptions,
            "gpsExceptionsText": "; ".join(gps_exceptions),
        })

        if emp_id not in emp_totals:
            emp_totals[emp_id] = {"employeeId": emp_id, "employeeName": emp_name, "totalHours": 0.0, "totalShifts": 0}
        emp_totals[emp_id]["totalHours"] += hours
        emp_totals[emp_id]["totalShifts"] += 1

    rows.sort(key=lambda r: (r["employeeName"].lower(), r["date"], r["clockIn"]))
    summary = sorted(emp_totals.values(), key=lambda e: e["employeeName"].lower())
    for s in summary:
        s["totalHours"] = round(s["totalHours"], 2)

    return {
        "success": True,
        "period": period,
        "startDate": start_date.strftime("%Y-%m-%d"),
        "endDate": end_date.strftime("%Y-%m-%d"),
        "exceptionsOnly": exceptions_only,
        "rows": rows,
        "summary": summary,
        "totalHours": round(sum(s["totalHours"] for s in summary), 2),
        "totalShifts": sum(s["totalShifts"] for s in summary),
        "totalGpsExceptionShifts": sum(1 for r in rows if r["gpsExceptions"]),
        "totalGpsExceptions": sum(len(r["gpsExceptions"]) for r in rows),
    }


@app.get("/api/admin/reports/hours")
def admin_reports_hours(
    request: Request,
    period: str = "week",
    date: Optional[str] = None,
    employee_id: Optional[int] = None,
    exceptions_only: bool = False,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    return _compute_hours_report(period, date, employee_id, exceptions_only)


@app.get("/api/admin/reports/hours/export")
def admin_reports_hours_export(
    request: Request,
    period: str = "week",
    date: Optional[str] = None,
    employee_id: Optional[int] = None,
    exceptions_only: bool = False,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> StreamingResponse:
    data = _compute_hours_report(period, date, employee_id, exceptions_only)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["EOM Hours Report"])
    w.writerow(["Period", data["period"], "From", data["startDate"], "To", data["endDate"]])
    w.writerow(["Total Hours", data["totalHours"], "Total Shifts", data["totalShifts"]])
    w.writerow([])
    w.writerow(["Employee", "Date", "Clock In", "Clock Out", "Hours", "Location", "GPS Exceptions"])
    for r in data["rows"]:
        w.writerow([r["employeeName"], r["dateLabel"], r["clockIn"], r["clockOut"], f'{r["hours"]:.2f}', r["location"], r.get("gpsExceptionsText", "")])
    w.writerow([])
    w.writerow(["Summary by Employee"])
    w.writerow(["Employee", "Total Shifts", "Total Hours"])
    for s in data["summary"]:
        w.writerow([s["employeeName"], s["totalShifts"], f'{s["totalHours"]:.2f}'])

    buf.seek(0)
    filename = f"eom_hours_{period}_{data['startDate']}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def load_settings() -> Dict[str, Any]:
    defaults: Dict[str, Any] = _SETTINGS_DEFAULTS.copy()
    rows = db.query_all("SELECT key, value FROM settings")
    data: Dict[str, Any] = {r["key"]: r["value"] for r in rows}
    for k, v in defaults.items():
        if k not in data:
            data[k] = v
    return data


@app.get("/api/admin/settings")
def admin_get_settings(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    return {"success": True, **load_settings()}


@app.put("/api/admin/settings")
def admin_update_settings(
    payload: Dict[str, Any],
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    settings = load_settings()
    numeric_keys = [
        "laborPctTarget", "laborPctWatch", "laborPctFix", "laborPctDrop",
        "grossMarginMin", "grossMarginFix", "grossMarginDrop",
        "hourOverrunWatch", "hourOverrunFix", "rplhMin",
    ]
    changed_keys = []
    for key in numeric_keys:
        if key in payload:
            try:
                val = float(payload[key])
                if val < 0:
                    raise HTTPException(status_code=400, detail=f"{key} cannot be negative")
                settings[key] = round(val, 2)
                changed_keys.append(key)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Invalid {key}")
    for key in changed_keys:
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (%s, %s::jsonb)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (key, json.dumps(settings[key])),
        )
    return {"success": True, **settings}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Scheduling & Forecasting - Phase 8
# ---------------------------------------------------------------------------

@app.post("/api/admin/schedules")
def admin_create_schedule(
    payload: ScheduleEntryRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    customer = payload.customerName.strip()
    if not customer:
        raise HTTPException(status_code=400, detail="customerName is required")
    try:
        ws = datetime.strptime(payload.weekStart, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="weekStart must be YYYY-MM-DD")
    if payload.scheduledHours < 0:
        raise HTTPException(status_code=400, detail="scheduledHours cannot be negative")
    # Normalize to Sunday
    days_since_sunday = (ws.weekday() + 1) % 7
    week_start = ws - timedelta(days=days_since_sunday)

    location_id = payload.locationId
    if location_id is None:
        loc = db.query_one(
            "SELECT id FROM locations WHERE customer_name = %s AND active = true LIMIT 1",
            (customer,),
        )
        if loc:
            location_id = loc["id"]

    row = db.query_one(
        """
        INSERT INTO schedules (employee_id, location_id, customer_name, week_start, scheduled_hours, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (employee_id, customer_name, week_start)
        DO UPDATE SET scheduled_hours = EXCLUDED.scheduled_hours, notes = EXCLUDED.notes
        RETURNING *
        """,
        (payload.employeeId, location_id, customer, week_start, payload.scheduledHours, payload.notes),
    )
    append_access_log(request, "SCHEDULE_CREATED", True, f"Schedule {row['id']}")
    return {"success": True, "schedule": {
        "id": row["id"], "employeeId": row["employee_id"], "customerName": row["customer_name"],
        "weekStart": str(row["week_start"]), "scheduledHours": float(row["scheduled_hours"]),
        "notes": row["notes"],
    }}


@app.get("/api/admin/schedules")
def admin_list_schedules(
    request: Request,
    week_start: Optional[str] = None,
    employee_id: Optional[int] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    clauses = []
    params: list = []
    if week_start:
        clauses.append("sc.week_start = %s")
        params.append(week_start)
    if employee_id:
        clauses.append("sc.employee_id = %s")
        params.append(employee_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = db.query_all(
        f"""
        SELECT sc.*, e.name AS employee_name
        FROM schedules sc
        JOIN employees e ON sc.employee_id = e.id
        {where}
        ORDER BY sc.week_start DESC, e.name
        """,
        tuple(params),
    )
    return {"success": True, "schedules": [
        {
            "id": r["id"], "employeeId": r["employee_id"], "employeeName": r["employee_name"],
            "customerName": r["customer_name"], "weekStart": str(r["week_start"]),
            "scheduledHours": float(r["scheduled_hours"]), "notes": r["notes"],
        }
        for r in rows
    ]}


@app.delete("/api/admin/schedules/{schedule_id}")
def admin_delete_schedule(
    schedule_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Delete a schedule entry."""
    existing = db.query_one("SELECT id FROM schedules WHERE id = %s", (schedule_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.execute("DELETE FROM schedules WHERE id = %s", (schedule_id,))
    append_access_log(request, "SCHEDULE_DELETED", True, f"Schedule {schedule_id}")
    return {"success": True, "scheduleId": schedule_id}


@app.get("/api/admin/analytics/schedule-vs-actual")
def admin_schedule_vs_actual(
    request: Request,
    week_start: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Compare scheduled vs actual hours per employee per customer for a given week."""
    now = utc_now()
    local_now = to_local(now)
    if week_start:
        try:
            ws = datetime.strptime(week_start, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    else:
        days_since_sunday = (local_now.date().weekday() + 1) % 7
        ws = local_now.date() - timedelta(days=days_since_sunday)

    # Normalize to Sunday
    days_since_sunday = (ws.weekday() + 1) % 7
    ws = ws - timedelta(days=days_since_sunday)
    we = ws + timedelta(days=6)

    schedules = db.query_all(
        """
        SELECT sc.employee_id, e.name AS employee_name, sc.customer_name, sc.scheduled_hours
        FROM schedules sc
        JOIN employees e ON sc.employee_id = e.id
        WHERE sc.week_start = %s
        """,
        (ws,),
    )

    location_customers = {
        r["address"]: r["customer_name"]
        for r in db.query_all("SELECT address, customer_name FROM locations WHERE customer_name IS NOT NULL")
    }

    actuals = db.query_all(
        """
        SELECT s.employee_id, e.name AS employee_name,
               COALESCE(l.address, '') AS location,
               COALESCE(SUM(s.total_hours), 0) AS actual_hours
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        LEFT JOIN locations l ON s.location_id = l.id
        WHERE s.clock_out IS NOT NULL AND s.local_date >= %s AND s.local_date <= %s
        GROUP BY s.employee_id, e.name, l.address
        """,
        (ws, we),
    )

    # Build actual hours by (employee_id, customer)
    actual_map: Dict[Tuple[int, str], float] = {}
    for a in actuals:
        cust = location_customers.get(a["location"], a["location"])
        key = (a["employee_id"], cust)
        actual_map[key] = actual_map.get(key, 0) + float(a["actual_hours"] or 0)

    comparisons = []
    all_keys = set()
    for sc in schedules:
        key = (sc["employee_id"], sc["customer_name"])
        all_keys.add(key)
        scheduled = float(sc["scheduled_hours"])
        actual = actual_map.get(key, 0.0)
        drift = round(actual - scheduled, 2)
        comparisons.append({
            "employeeId": sc["employee_id"],
            "employeeName": sc["employee_name"],
            "customerName": sc["customer_name"],
            "scheduledHours": round(scheduled, 2),
            "actualHours": round(actual, 2),
            "driftHours": drift,
            "driftPct": round(drift / scheduled * 100, 1) if scheduled > 0 else None,
        })

    # Add actuals with no schedule
    for (emp_id, cust), actual in actual_map.items():
        if (emp_id, cust) not in all_keys:
            emp_name = db.query_one("SELECT name FROM employees WHERE id = %s", (emp_id,))
            comparisons.append({
                "employeeId": emp_id,
                "employeeName": emp_name["name"] if emp_name else f"Employee {emp_id}",
                "customerName": cust,
                "scheduledHours": 0,
                "actualHours": round(actual, 2),
                "driftHours": round(actual, 2),
                "driftPct": None,
            })

    total_scheduled = sum(c["scheduledHours"] for c in comparisons)
    total_actual = sum(c["actualHours"] for c in comparisons)

    return {
        "success": True,
        "weekStart": str(ws),
        "weekEnd": str(we),
        "summary": {
            "totalScheduled": round(total_scheduled, 2),
            "totalActual": round(total_actual, 2),
            "totalDrift": round(total_actual - total_scheduled, 2),
            "driftPct": round((total_actual - total_scheduled) / total_scheduled * 100, 1) if total_scheduled > 0 else None,
        },
        "comparisons": sorted(comparisons, key=lambda c: abs(c["driftHours"]), reverse=True),
    }


@app.get("/api/admin/analytics/forecast")
def admin_forecast(
    request: Request,
    weeks_ahead: int = 4,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Simple weekly staffing forecast based on recent actual hours and scheduled data."""
    now = utc_now()
    local_now = to_local(now)
    today = local_now.date()
    days_since_sunday = (today.weekday() + 1) % 7
    current_week_start = today - timedelta(days=days_since_sunday)

    # Look back 8 weeks for historical averages
    lookback_start = current_week_start - timedelta(weeks=8)
    lookback_end = current_week_start - timedelta(days=1)

    timesheet_data = load_timesheets()
    settings = load_settings()
    location_customers = timesheet_data.get("location_customers", {})
    location_rates = timesheet_data.get("location_rates", {})
    location_rate_types = timesheet_data.get("location_rate_types", {})

    # Historical actuals by customer per week
    hist_rows = db.query_all(
        """
        SELECT COALESCE(l.customer_name, COALESCE(l.address, '')) AS customer,
               s.local_date,
               SUM(s.total_hours) AS hours,
               s.employee_id,
               e.hourly_rate
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        LEFT JOIN locations l ON s.location_id = l.id
        WHERE s.clock_out IS NOT NULL AND s.local_date >= %s AND s.local_date <= %s
        GROUP BY customer, s.local_date, s.employee_id, e.hourly_rate
        """,
        (lookback_start, lookback_end),
    )

    # Aggregate by customer weekly averages
    customer_weekly: Dict[str, Dict[str, float]] = {}  # customer -> {week -> hours}
    for r in hist_rows:
        cust = r["customer"] or "Unknown"
        d = r["local_date"]
        ds = (d.weekday() + 1) % 7
        wk = str(d - timedelta(days=ds))
        if cust not in customer_weekly:
            customer_weekly[cust] = {}
        customer_weekly[cust][wk] = customer_weekly[cust].get(wk, 0) + float(r["hours"] or 0)

    # Average hours per week per customer
    customer_avg: Dict[str, float] = {}
    for cust, weeks in customer_weekly.items():
        if weeks:
            customer_avg[cust] = round(sum(weeks.values()) / len(weeks), 2)

    # Get avg labor rate
    avg_rate_row = db.query_one("SELECT AVG(hourly_rate) AS avg_rate FROM employees WHERE hourly_rate IS NOT NULL AND active = true")
    avg_labor_rate = float(avg_rate_row["avg_rate"]) if avg_rate_row and avg_rate_row["avg_rate"] else _SETTINGS_DEFAULTS["laborRateFallback"]

    # Build forecast for each future week
    forecasts = []
    for i in range(weeks_ahead):
        forecast_week_start = current_week_start + timedelta(weeks=i)
        forecast_week_end = forecast_week_start + timedelta(days=6)

        # Check if we have schedules for this week
        scheduled = db.query_all(
            "SELECT customer_name, SUM(scheduled_hours) AS hours FROM schedules WHERE week_start = %s GROUP BY customer_name",
            (forecast_week_start,),
        )
        scheduled_map = {s["customer_name"]: float(s["hours"]) for s in scheduled}

        total_hours = 0.0
        total_labor = 0.0
        total_revenue = 0.0
        by_customer = []

        all_customers = set(customer_avg.keys()) | set(scheduled_map.keys())
        for cust in all_customers:
            # Use schedule if available, otherwise historical average
            hours = scheduled_map.get(cust, customer_avg.get(cust, 0))
            labor = hours * avg_labor_rate

            # Estimate revenue from location rates
            loc_addr = None
            for addr, cn in location_customers.items():
                if cn == cust:
                    loc_addr = addr
                    break
            rev = 0.0
            if loc_addr:
                rate = location_rates.get(loc_addr)
                rt = location_rate_types.get(loc_addr, "per_visit")
                if rate is not None:
                    if rt == "hourly":
                        rev = rate * hours
                    elif rt == "monthly":
                        rev = rate / 4.33  # approximate weekly from monthly
                    else:  # per_visit
                        # estimate visits from hours and expected hours per visit
                        exp_h = timesheet_data.get("location_expected_hours", {}).get(loc_addr)
                        if exp_h and exp_h > 0:
                            est_visits = hours / exp_h
                        else:
                            est_visits = 1
                        rev = rate * est_visits

            total_hours += hours
            total_labor += labor
            total_revenue += rev
            by_customer.append({
                "customer": cust,
                "forecastHours": round(hours, 2),
                "source": "schedule" if cust in scheduled_map else "historical",
                "estLaborCost": round(labor, 2),
                "estRevenue": round(rev, 2),
            })

        net = round(total_revenue - total_labor, 2)
        forecasts.append({
            "weekStart": str(forecast_week_start),
            "weekEnd": str(forecast_week_end),
            "totalHours": round(total_hours, 2),
            "estLaborCost": round(total_labor, 2),
            "estRevenue": round(total_revenue, 2),
            "estNetProfit": net,
            "estMarginPct": round(net / total_revenue * 100, 1) if total_revenue > 0 else None,
            "estLaborPct": round(total_labor / total_revenue * 100, 1) if total_revenue > 0 else None,
            "byCustomer": sorted(by_customer, key=lambda c: c["forecastHours"], reverse=True),
        })

    return {
        "success": True,
        "weeksAhead": weeks_ahead,
        "avgLaborRate": round(avg_labor_rate, 2),
        "laborPctTarget": settings.get("laborPctTarget", _SETTINGS_DEFAULTS["laborPctTarget"]),
        "forecasts": forecasts,
    }


# Time Categorization & Waste Tracking - Phase 7
# ---------------------------------------------------------------------------

@app.patch("/api/admin/shifts/{shift_id}/categorize")
def admin_categorize_shift(
    shift_id: int,
    payload: ShiftCategorizeRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Categorize a shift as productive or non-productive."""
    if payload.timeCategory not in ("productive", "non_productive"):
        raise HTTPException(status_code=400, detail="timeCategory must be 'productive' or 'non_productive'")

    npt = None
    if payload.timeCategory == "non_productive":
        if not payload.nonProductiveType or payload.nonProductiveType not in VALID_NON_PRODUCTIVE_TYPES:
            raise HTTPException(status_code=400, detail=f"nonProductiveType required, must be one of: {', '.join(VALID_NON_PRODUCTIVE_TYPES)}")
        npt = payload.nonProductiveType
        if not payload.notes or not payload.notes.strip():
            raise HTTPException(status_code=400, detail="Notes required when categorizing as non-productive")

    with TIMESHEET_WRITE_LOCK:
        shift = db.query_one("SELECT id FROM shifts WHERE id = %s", (shift_id,))
        if not shift:
            raise HTTPException(status_code=404, detail="Shift not found")

        if payload.notes and payload.notes.strip():
            db.execute(
                "UPDATE shifts SET time_category = %s, non_productive_type = %s, notes = %s WHERE id = %s",
                (payload.timeCategory, npt, payload.notes.strip(), shift_id),
            )
        else:
            db.execute(
                "UPDATE shifts SET time_category = %s, non_productive_type = %s WHERE id = %s",
                (payload.timeCategory, npt, shift_id),
            )

    append_access_log(request, "SHIFT_CATEGORIZED", True, f"Shift {shift_id}: {payload.timeCategory}/{npt}")
    return {"success": True, "shiftId": shift_id, "timeCategory": payload.timeCategory, "nonProductiveType": npt}


@app.get("/api/admin/analytics/unmatched-shifts")
def admin_unmatched_shifts(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Return individual productive shifts with no location assigned, plus all registered locations for the assignment dropdown."""
    timesheet_data = load_timesheets()
    location_customers = timesheet_data.get("location_customers", {})

    rows = db.query_all(
        """
        SELECT s.id, s.clock_in, s.clock_out, s.total_hours,
               s.local_date, s.notes,
               e.name AS employee_name
        FROM shifts s
        LEFT JOIN employees e ON e.id = s.employee_id
        WHERE s.clock_out IS NOT NULL
          AND s.time_category = 'productive'
          AND s.location_id IS NULL
        ORDER BY s.clock_in DESC
        """
    )

    shifts = []
    for r in rows:
        local_date = str(r["local_date"]) if r["local_date"] else (to_utc_iso(r["clock_in"])[:10] if r["clock_in"] else "")
        shifts.append({
            "id":           r["id"],
            "date":         local_date,
            "clockIn":      to_utc_iso(r["clock_in"]) if r["clock_in"] else None,
            "clockOut":     to_utc_iso(r["clock_out"]) if r["clock_out"] else None,
            "hours":        round(float(r["total_hours"] or 0), 2),
            "employee":     r["employee_name"] or "Unknown",
            "notes":        r["notes"] or "",
        })

    # Build location options: address -> customer name
    loc_rows = db.query_all(
        "SELECT address, customer_name FROM locations WHERE active = true ORDER BY customer_name, address"
    )
    locations = [
        {"address": r["address"], "customerName": r["customer_name"] or r["address"]}
        for r in loc_rows
    ]

    return {
        "success": True,
        "totalShifts": len(shifts),
        "totalHours": round(sum(s["hours"] for s in shifts), 2),
        "shifts": shifts,
        "locations": locations,
    }


@app.patch("/api/admin/shifts/{shift_id}/location")
def admin_assign_shift_location(
    shift_id: int,
    payload: Dict[str, Any],
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Assign a registered location to a shift that has none."""
    address = (payload.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="address is required")

    loc = db.query_one("SELECT id FROM locations WHERE address = %s AND active = true", (address,))
    if not loc:
        raise HTTPException(status_code=404, detail="Location not found or inactive")

    existing = db.query_one("SELECT id FROM shifts WHERE id = %s", (shift_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="Shift not found")

    db.execute(
        "UPDATE shifts SET location_id = %s WHERE id = %s",
        (loc["id"], shift_id),
    )
    append_access_log(request, "SHIFT_LOCATION_ASSIGNED", True, f"Shift {shift_id} -> {address}")
    return {"success": True, "shiftId": shift_id, "address": address, "locationId": loc["id"]}


@app.get("/api/admin/analytics/waste")
def admin_waste_analysis(
    request: Request,
    period: str = "month",
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Waste rollups by customer and employee, plus repeat cause identification."""
    now = utc_now()
    local_now = to_local(now)
    if date:
        try:
            ref_date = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    else:
        ref_date = local_now.date()

    if period == "day":
        start_date = ref_date
        end_date = ref_date
    elif period == "week":
        days_since_sunday = (ref_date.weekday() + 1) % 7
        start_date = ref_date - timedelta(days=days_since_sunday)
        end_date = start_date + timedelta(days=6)
    elif period == "month":
        start_date = ref_date.replace(day=1)
        if start_date.month == 12:
            end_date = start_date.replace(year=start_date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = start_date.replace(month=start_date.month + 1, day=1) - timedelta(days=1)
    elif period == "all":
        start_date = None  # type: ignore[assignment]
        end_date = None  # type: ignore[assignment]
    else:
        raise HTTPException(status_code=400, detail="period must be day, week, month, or all")

    date_clause = ""
    params: list = []
    if start_date is not None:
        date_clause = "AND s.local_date >= %s AND s.local_date <= %s"
        params = [start_date, end_date]

    rows = db.query_all(
        f"""
        SELECT s.id, s.employee_id, e.name AS employee_name,
               COALESCE(l.customer_name, COALESCE(l.address, '')) AS customer,
               s.total_hours, s.time_category, s.non_productive_type,
               s.notes, s.local_date, e.hourly_rate
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        LEFT JOIN locations l ON s.location_id = l.id
        WHERE s.clock_out IS NOT NULL AND s.time_category = 'non_productive'
        {date_clause}
        ORDER BY s.local_date DESC
        """,
        tuple(params),
    )

    by_customer: Dict[str, Dict[str, Any]] = {}
    by_employee: Dict[str, Dict[str, Any]] = {}
    by_cause: Dict[str, Dict[str, Any]] = {}
    total_waste_hours = 0.0
    total_waste_cost = 0.0
    missing_rate_count = 0

    for r in rows:
        hours = float(r["total_hours"] or 0)
        has_rate = r.get("hourly_rate") is not None
        rate = float(r["hourly_rate"]) if has_rate else 0.0
        cost = rate * hours
        npt = r["non_productive_type"] or "other"
        cust = r["customer"] or "Unknown"
        emp = r["employee_name"]

        total_waste_hours += hours
        total_waste_cost += cost
        if not has_rate:
            missing_rate_count += 1

        if cust not in by_customer:
            by_customer[cust] = {"customer": cust, "hours": 0.0, "cost": 0.0, "incidents": 0, "causes": {}}
        by_customer[cust]["hours"] += hours
        by_customer[cust]["cost"] += cost
        by_customer[cust]["incidents"] += 1
        by_customer[cust]["causes"][npt] = by_customer[cust]["causes"].get(npt, 0) + 1

        if emp not in by_employee:
            by_employee[emp] = {"employee": emp, "hours": 0.0, "cost": 0.0, "incidents": 0, "causes": {}}
        by_employee[emp]["hours"] += hours
        by_employee[emp]["cost"] += cost
        by_employee[emp]["incidents"] += 1
        by_employee[emp]["causes"][npt] = by_employee[emp]["causes"].get(npt, 0) + 1

        if npt not in by_cause:
            by_cause[npt] = {"cause": npt, "hours": 0.0, "cost": 0.0, "incidents": 0, "customers": set(), "employees": set()}
        by_cause[npt]["hours"] += hours
        by_cause[npt]["cost"] += cost
        by_cause[npt]["incidents"] += 1
        by_cause[npt]["customers"].add(cust)
        by_cause[npt]["employees"].add(emp)

    def _round_agg(d: Dict[str, Any]) -> Dict[str, Any]:
        d["hours"] = round(d["hours"], 2)
        d["cost"] = round(d["cost"], 2)
        return d

    customer_list = sorted([_round_agg(v) for v in by_customer.values()], key=lambda x: x["cost"], reverse=True)
    employee_list = sorted([_round_agg(v) for v in by_employee.values()], key=lambda x: x["cost"], reverse=True)
    cause_list = sorted(
        [
            {
                "cause": v["cause"],
                "hours": round(v["hours"], 2),
                "cost": round(v["cost"], 2),
                "incidents": v["incidents"],
                "customerCount": len(v["customers"]),
                "employeeCount": len(v["employees"]),
            }
            for v in by_cause.values()
        ],
        key=lambda x: x["incidents"],
        reverse=True,
    )

    return {
        "success": True,
        "period": period,
        "startDate": str(start_date) if start_date else None,
        "endDate": str(end_date) if end_date else None,
        "summary": {
            "totalWasteHours": round(total_waste_hours, 2),
            "totalWasteCost": round(total_waste_cost, 2),
            "totalIncidents": len(rows),
            "missingRateCount": missing_rate_count,
        },
        "byCustomer": customer_list,
        "byEmployee": employee_list,
        "byCause": cause_list,
    }


# ---------------------------------------------------------------------------
# Pricing Recommendations - Phase 6
# ---------------------------------------------------------------------------

@app.get("/api/admin/analytics/pricing")
def admin_pricing_recommendations(
    request: Request,
    period: str = "month",
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Calculate required revenue and suggested price changes per customer."""
    data = _compute_analytics(period, date)
    settings = load_settings()
    timesheet_data = load_timesheets()

    location_customers = timesheet_data.get("location_customers", {})
    location_rates = timesheet_data.get("location_rates", {})
    location_rate_types = timesheet_data.get("location_rate_types", {})
    location_target_labor = timesheet_data.get("location_target_labor", {})
    location_min_margin = timesheet_data.get("location_min_margin", {})

    # Build reverse map: customer_name -> location address
    customer_to_loc: Dict[str, str] = {}
    for addr, cust in location_customers.items():
        customer_to_loc[cust] = addr

    default_target_labor = settings.get("laborPctTarget", _SETTINGS_DEFAULTS["laborPctTarget"])
    default_min_margin = settings.get("grossMarginMin", _SETTINGS_DEFAULTS["grossMarginMin"])

    recommendations = []
    for c in data["byCustomer"]:
        customer = c["customer"]
        loc = customer_to_loc.get(customer, c.get("location", ""))

        target_labor = location_target_labor.get(loc, default_target_labor)
        min_margin = location_min_margin.get(loc, default_min_margin)
        current_rate = location_rates.get(loc)
        rate_type = location_rate_types.get(loc, "per_visit")

        actual_labor_cost = c["laborCost"]
        actual_revenue = c["revenue"]
        actual_hours = c["hours"]
        visits = c["visits"]

        # Required revenue to hit target labor %
        # target_labor% = laborCost / requiredRevenue * 100
        # requiredRevenue = laborCost / (target_labor% / 100)
        required_rev_labor = round(actual_labor_cost / (target_labor / 100), 2) if target_labor > 0 else None

        # Required revenue to hit minimum margin %
        # min_margin% = (rev - laborCost) / rev * 100
        # rev * min_margin/100 = rev - laborCost
        # rev * (1 - min_margin/100) = laborCost
        # rev = laborCost / (1 - min_margin/100)
        required_rev_margin = round(actual_labor_cost / (1 - min_margin / 100), 2) if min_margin < 100 else None

        # Use the higher of the two as the target
        required_revenue = None
        if required_rev_labor is not None and required_rev_margin is not None:
            required_revenue = max(required_rev_labor, required_rev_margin)
        elif required_rev_labor is not None:
            required_revenue = required_rev_labor
        elif required_rev_margin is not None:
            required_revenue = required_rev_margin

        # Calculate suggested increase
        revenue_gap = round(required_revenue - actual_revenue, 2) if required_revenue is not None else None
        pct_increase = round(revenue_gap / actual_revenue * 100, 1) if revenue_gap is not None and actual_revenue > 0 else None

        # Suggested new per-visit price
        needs_increase = revenue_gap is not None and revenue_gap > 0

        # Calculate suggested rate based on rate type
        suggested_rate = current_rate
        if needs_increase and required_revenue is not None:
            if rate_type == "per_visit" and visits > 0:
                suggested_rate = round(required_revenue / visits, 2)
            elif rate_type == "hourly" and actual_hours > 0:
                suggested_rate = round(required_revenue / actual_hours, 2)
            elif rate_type == "monthly" and required_revenue > 0:
                suggested_rate = round(required_revenue, 2)

        rec = {
            "customer": customer,
            "location": loc,
            "rateType": rate_type,
            "currentRate": current_rate,
            "targetLaborPct": target_labor,
            "minMarginPct": min_margin,
            "actualRevenue": actual_revenue,
            "actualLaborCost": actual_labor_cost,
            "actualLaborPct": c["laborPct"],
            "actualMarginPct": c["grossMarginPct"],
            "requiredRevenue": required_revenue,
            "revenueGap": revenue_gap if needs_increase else 0,
            "pctIncrease": pct_increase if needs_increase else 0,
            "suggestedRate": suggested_rate,
            "visits": visits,
            "hours": actual_hours,
            "flag": c.get("flag", "Healthy"),
            "needsIncrease": needs_increase,
        }
        recommendations.append(rec)

    # Sort: needs increase first, then by revenue gap descending
    recommendations.sort(key=lambda r: (not r["needsIncrease"], -(r["revenueGap"] or 0)))

    needs_action = [r for r in recommendations if r["needsIncrease"]]
    return {
        "success": True,
        "period": data["period"],
        "startDate": data["startDate"],
        "endDate": data["endDate"],
        "defaults": {
            "targetLaborPct": default_target_labor,
            "minMarginPct": default_min_margin,
        },
        "needsActionCount": len(needs_action),
        "totalRevenueGap": round(sum(r["revenueGap"] or 0 for r in needs_action), 2),
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Jobs (service visits) - Phase 3
# ---------------------------------------------------------------------------

def _job_row_to_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "locationId": row.get("location_id"),
        "customerName": row["customer_name"],
        "scheduledDate": str(row["scheduled_date"]),
        "expectedHours": float(row["expected_hours"]) if row.get("expected_hours") is not None else None,
        "revenue": float(row["revenue"]) if row.get("revenue") is not None else None,
        "notes": row["notes"] or "",
        "status": row["status"],
        "createdAt": to_utc_iso(row["created_at"]) if row.get("created_at") else None,
    }


@app.post("/api/admin/jobs")
def admin_create_job(
    payload: JobCreateRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    customer = payload.customerName.strip()
    if not customer:
        raise HTTPException(status_code=400, detail="customerName is required")
    try:
        scheduled = datetime.strptime(payload.scheduledDate, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="scheduledDate must be YYYY-MM-DD")
    if payload.status not in ("scheduled", "in_progress", "completed", "cancelled"):
        raise HTTPException(status_code=400, detail="Invalid status")
    if payload.expectedHours is not None and payload.expectedHours < 0:
        raise HTTPException(status_code=400, detail="expectedHours cannot be negative")
    if payload.revenue is not None and payload.revenue < 0:
        raise HTTPException(status_code=400, detail="revenue cannot be negative")

    location_id = payload.locationId
    if location_id is None:
        loc = db.query_one(
            "SELECT id FROM locations WHERE customer_name = %s AND active = true LIMIT 1",
            (customer,),
        )
        if loc:
            location_id = loc["id"]

    row = db.query_one(
        """
        INSERT INTO jobs (location_id, customer_name, scheduled_date, expected_hours, revenue, notes, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *
        """,
        (location_id, customer, scheduled, payload.expectedHours, payload.revenue,
         payload.notes, payload.status),
    )
    append_access_log(request, "JOB_CREATED", True, f"Job {row['id']} for {customer}")
    return {"success": True, "job": _job_row_to_dict(row)}


@app.get("/api/admin/jobs")
def admin_list_jobs(
    request: Request,
    status: Optional[str] = None,
    customer: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    clauses = []
    params: list = []
    if status:
        clauses.append("j.status = %s")
        params.append(status)
    if customer:
        clauses.append("j.customer_name = %s")
        params.append(customer)
    if start_date:
        clauses.append("j.scheduled_date >= %s")
        params.append(start_date)
    if end_date:
        clauses.append("j.scheduled_date <= %s")
        params.append(end_date)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = db.query_all(
        f"SELECT * FROM jobs j {where} ORDER BY j.scheduled_date DESC, j.id DESC",
        tuple(params),
    )
    return {"success": True, "jobs": [_job_row_to_dict(r) for r in rows]}


@app.post("/api/admin/jobs/auto-link")
def admin_auto_link_jobs(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Auto-link unlinked shifts to jobs by matching customer + date."""
    jobs = db.query_all(
        """
        SELECT j.id, j.customer_name, j.scheduled_date, l.address
        FROM jobs j
        LEFT JOIN locations l ON j.location_id = l.id
        WHERE j.status != 'cancelled'
        """
    )

    location_customers = {
        r["address"]: r["customer_name"]
        for r in db.query_all("SELECT address, customer_name FROM locations WHERE customer_name IS NOT NULL")
    }

    unlinked = db.query_all(
        """
        SELECT s.id, s.local_date, COALESCE(l.address, '') AS location
        FROM shifts s
        LEFT JOIN locations l ON s.location_id = l.id
        WHERE s.job_id IS NULL AND s.clock_out IS NOT NULL
        """
    )

    with TIMESHEET_WRITE_LOCK:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                linked = 0
                for shift in unlinked:
                    shift_customer = location_customers.get(shift["location"], shift["location"])
                    shift_date = shift["local_date"]
                    if not shift_date:
                        continue
                    shift_cust_norm = shift_customer.strip().lower() if shift_customer else ""
                    for job in jobs:
                        job_cust_norm = job["customer_name"].strip().lower() if job["customer_name"] else ""
                        if job_cust_norm == shift_cust_norm and job["scheduled_date"] == shift_date:
                            cur.execute(
                                "UPDATE shifts SET job_id = %s WHERE id = %s AND job_id IS NULL",
                                (job["id"], shift["id"]),
                            )
                            if cur.rowcount > 0:
                                linked += 1
                            break

    append_access_log(request, "JOBS_AUTO_LINKED", True, f"{linked} shifts auto-linked")
    return {"success": True, "linkedCount": linked}


@app.get("/api/admin/jobs/profitability")
def admin_jobs_profitability(
    request: Request,
    status: Optional[str] = None,
    customer: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Job-level profitability report with per-job hours, labor cost, revenue, profit, margin."""
    clauses = []
    params: list = []
    if status:
        clauses.append("j.status = %s")
        params.append(status)
    if customer:
        clauses.append("j.customer_name = %s")
        params.append(customer)
    if start_date:
        clauses.append("j.scheduled_date >= %s")
        params.append(start_date)
    if end_date:
        clauses.append("j.scheduled_date <= %s")
        params.append(end_date)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    rows = db.query_all(
        f"""
        SELECT j.id, j.customer_name, j.scheduled_date, j.expected_hours,
               j.revenue, j.status, j.notes,
               COALESCE(SUM(s.total_hours), 0) AS actual_hours,
               COUNT(DISTINCT s.employee_id) AS employee_count,
               COUNT(s.id) AS shift_count
        FROM jobs j
        LEFT JOIN shifts s ON s.job_id = j.id AND s.clock_out IS NOT NULL
        {where}
        GROUP BY j.id
        ORDER BY j.scheduled_date DESC, j.id DESC
        """,
        tuple(params),
    )

    emp_rates: Dict[int, float] = {
        r["id"]: float(r["hourly_rate"])
        for r in db.query_all("SELECT id, hourly_rate FROM employees WHERE hourly_rate IS NOT NULL")
    }

    # Batch-load all shift details for matched jobs in one query (avoids N+1)
    job_ids = [r["id"] for r in rows]
    labor_by_job: Dict[int, float] = {jid: 0.0 for jid in job_ids}
    if job_ids:
        all_shifts = db.query_all(
            """
            SELECT job_id, employee_id, total_hours
            FROM shifts
            WHERE job_id = ANY(%s) AND clock_out IS NOT NULL
            """,
            (job_ids,),
        )
        for sd in all_shifts:
            labor_by_job[sd["job_id"]] += (
                emp_rates.get(sd["employee_id"], 0.0) * float(sd["total_hours"] or 0)
            )

    jobs_out = []
    total_rev = 0.0
    total_labor = 0.0
    total_hours = 0.0
    for r in rows:
        labor_cost = labor_by_job.get(r["id"], 0.0)
        rev = float(r["revenue"] or 0)
        hours = float(r["actual_hours"] or 0)
        net = round(rev - labor_cost, 2)
        exp_h = float(r["expected_hours"]) if r["expected_hours"] is not None else None

        jobs_out.append({
            "jobId": r["id"],
            "customerName": r["customer_name"],
            "scheduledDate": str(r["scheduled_date"]),
            "status": r["status"],
            "expectedHours": exp_h,
            "actualHours": round(hours, 2),
            "varianceHours": round(exp_h - hours, 2) if exp_h is not None else None,
            "revenue": round(rev, 2),
            "laborCost": round(labor_cost, 2),
            "netProfit": net,
            "grossMarginPct": round(net / rev * 100, 1) if rev > 0 else None,
            "laborPct": round(labor_cost / rev * 100, 1) if rev > 0 else None,
            "employeeCount": r["employee_count"],
            "shiftCount": r["shift_count"],
        })

        total_rev += rev
        total_labor += labor_cost
        total_hours += hours

    total_net = round(total_rev - total_labor, 2)
    return {
        "success": True,
        "summary": {
            "jobCount": len(jobs_out),
            "totalRevenue": round(total_rev, 2),
            "totalLaborCost": round(total_labor, 2),
            "totalNetProfit": total_net,
            "grossMarginPct": round(total_net / total_rev * 100, 1) if total_rev > 0 else None,
            "totalHours": round(total_hours, 2),
        },
        "jobs": jobs_out,
    }


@app.get("/api/admin/jobs/{job_id}")
def admin_get_job(
    job_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    row = db.query_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    shift_rows = db.query_all(
        """
        SELECT s.id, s.employee_id, e.name AS employee_name,
               s.clock_in, s.clock_out, s.total_hours, s.notes,
               e.hourly_rate
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        WHERE s.job_id = %s
        ORDER BY s.clock_in
        """,
        (job_id,),
    )

    shifts = []
    total_hours = 0.0
    total_labor = 0.0
    for sr in shift_rows:
        h = float(sr["total_hours"] or 0)
        rate = float(sr["hourly_rate"]) if sr["hourly_rate"] is not None else None
        lc = (rate * h) if rate is not None else 0.0
        total_hours += h
        total_labor += lc
        shifts.append({
            "shiftId": sr["id"],
            "employeeId": sr["employee_id"],
            "employeeName": sr["employee_name"],
            "clockIn": to_utc_iso(sr["clock_in"]) if sr["clock_in"] else None,
            "clockOut": to_utc_iso(sr["clock_out"]) if sr["clock_out"] else None,
            "hours": round(h, 2),
            "laborCost": round(lc, 2),
            "notes": sr["notes"] or "",
        })

    job = _job_row_to_dict(row)
    rev = job["revenue"] or 0.0
    net = round(rev - total_labor, 2)
    job["shifts"] = shifts
    job["totalHours"] = round(total_hours, 2)
    job["totalLaborCost"] = round(total_labor, 2)
    job["netProfit"] = net
    job["grossMarginPct"] = round(net / rev * 100, 1) if rev > 0 else None
    job["laborPct"] = round(total_labor / rev * 100, 1) if rev > 0 else None
    job["varianceHours"] = round((job["expectedHours"] or 0) - total_hours, 2) if job["expectedHours"] is not None else None

    return {"success": True, "job": job}


@app.put("/api/admin/jobs/{job_id}")
def admin_update_job(
    job_id: int,
    payload: JobUpdateRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    existing = db.query_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="Job not found")

    sets = []
    params: list = []
    if payload.customerName is not None:
        sets.append("customer_name = %s")
        params.append(payload.customerName.strip())
    if payload.scheduledDate is not None:
        try:
            datetime.strptime(payload.scheduledDate, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="scheduledDate must be YYYY-MM-DD")
        sets.append("scheduled_date = %s")
        params.append(payload.scheduledDate)
    if payload.expectedHours is not None:
        if payload.expectedHours < 0:
            raise HTTPException(status_code=400, detail="expectedHours cannot be negative")
        sets.append("expected_hours = %s")
        params.append(payload.expectedHours)
    if payload.revenue is not None:
        if payload.revenue < 0:
            raise HTTPException(status_code=400, detail="revenue cannot be negative")
        sets.append("revenue = %s")
        params.append(payload.revenue)
    if payload.notes is not None:
        sets.append("notes = %s")
        params.append(payload.notes)
    if payload.status is not None:
        if payload.status not in ("scheduled", "in_progress", "completed", "cancelled"):
            raise HTTPException(status_code=400, detail="Invalid status")
        sets.append("status = %s")
        params.append(payload.status)
    if payload.locationId is not None:
        sets.append("location_id = %s")
        params.append(payload.locationId)

    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(job_id)
    row = db.query_one(
        f"UPDATE jobs SET {', '.join(sets)} WHERE id = %s RETURNING *",
        tuple(params),
    )
    append_access_log(request, "JOB_UPDATED", True, f"Job {job_id}")
    return {"success": True, "job": _job_row_to_dict(row)}


@app.delete("/api/admin/jobs/{job_id}")
def admin_delete_job(
    job_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Delete a job. Unlinks any associated shifts first."""
    existing = db.query_one("SELECT id FROM jobs WHERE id = %s", (job_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="Job not found")

    with TIMESHEET_WRITE_LOCK:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE shifts SET job_id = NULL WHERE job_id = %s", (job_id,))
                cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))

    append_access_log(request, "JOB_DELETED", True, f"Job {job_id}")
    return {"success": True, "jobId": job_id}


@app.post("/api/admin/jobs/{job_id}/shifts")
def admin_link_shifts_to_job(
    job_id: int,
    payload: JobLinkShiftsRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Link one or more shifts to a job."""
    existing = db.query_one("SELECT id FROM jobs WHERE id = %s", (job_id,))
    if not existing:
        raise HTTPException(status_code=404, detail="Job not found")

    with TIMESHEET_WRITE_LOCK:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                linked = 0
                for sid in payload.shiftIds:
                    cur.execute("SELECT id FROM shifts WHERE id = %s", (sid,))
                    if cur.fetchone():
                        cur.execute("UPDATE shifts SET job_id = %s WHERE id = %s", (job_id, sid))
                        linked += 1

    append_access_log(request, "JOB_SHIFTS_LINKED", True, f"Job {job_id}: {linked} shifts linked")
    return {"success": True, "jobId": job_id, "linkedCount": linked}


@app.delete("/api/admin/jobs/{job_id}/shifts/{shift_id}")
def admin_unlink_shift_from_job(
    job_id: int,
    shift_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Unlink a shift from a job."""
    with TIMESHEET_WRITE_LOCK:
        db.execute("UPDATE shifts SET job_id = NULL WHERE id = %s AND job_id = %s", (shift_id, job_id))
    append_access_log(request, "JOB_SHIFT_UNLINKED", True, f"Job {job_id}: shift {shift_id} unlinked")
    return {"success": True}


def _compute_analytics(period: str, date_str: Optional[str]) -> Dict[str, Any]:
    now = utc_now()
    local_now = to_local(now)

    if date_str:
        try:
            ref_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")
    else:
        ref_date = local_now.date()

    if period == "day":
        start_date = ref_date
        end_date = ref_date
    elif period == "week":
        days_since_sunday = (ref_date.weekday() + 1) % 7
        start_date = ref_date - timedelta(days=days_since_sunday)
        end_date = start_date + timedelta(days=6)
    elif period == "month":
        start_date = ref_date.replace(day=1)
        if start_date.month == 12:
            end_date = start_date.replace(year=start_date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = start_date.replace(month=start_date.month + 1, day=1) - timedelta(days=1)
    elif period == "all":
        start_date = None  # type: ignore[assignment]
        end_date = None    # type: ignore[assignment]
    else:
        raise HTTPException(status_code=400, detail="period must be day, week, month, or all")

    timesheet_data = load_timesheets()
    employees_data = load_employees()
    settings = load_settings()

    location_customers = timesheet_data.get("location_customers", {})
    location_rates = timesheet_data.get("location_rates", {})
    location_rate_types = timesheet_data.get("location_rate_types", {})
    location_expected_hours = timesheet_data.get("location_expected_hours", {})

    emp_rates: Dict[int, float] = {}
    for emp in employees_data["employees"]:
        rate = emp.get("hourlyRate")
        if rate is not None:
            emp_rates[emp["id"]] = float(rate)

    days_in_period = (end_date - start_date).days + 1 if (start_date and end_date) else 365
    monthly_customers_credited: set = set()
    visited_customer_dates: set = set()  # (customer, date_key) - dedup multi-employee same-day visits

    customer_agg: Dict[str, Dict[str, Any]] = {}
    day_agg: Dict[str, Dict[str, Any]] = {}

    def _resolve_loc(location: str) -> Tuple[str, str]:
        """Return (resolved_location, customer) for a location string."""
        resolved = location
        customer = location_customers.get(location)
        if not customer and location.startswith("GPS "):
            try:
                parts = location[4:].split(",")
                gps_lat, gps_lng = float(parts[0].strip()), float(parts[1].strip())
                matched = find_nearest_location(gps_lat, gps_lng, timesheet_data)
                if matched:
                    resolved = matched
                    customer = location_customers.get(matched) or matched
            except (ValueError, IndexError):
                pass
        if not customer:
            customer = location if (location and not location.startswith("GPS ") and location not in ("Unknown", "")) else "Unmatched Location"
        return resolved, customer

    def _aggregate(customer: str, resolved_location: str, hours: float, emp_id: int,
                   entry_date: Any, date_key: str, is_visit: bool) -> None:
        # Determine first-arrival: deduplicates multi-employee same-day visits
        visit_key = (customer, date_key)
        is_new_visit = is_visit and visit_key not in visited_customer_dates
        if is_new_visit:
            visited_customer_dates.add(visit_key)

        rate = location_rates.get(resolved_location)
        rate_type = location_rate_types.get(resolved_location, "per_visit")
        if rate is not None:
            if rate_type == "hourly":
                # Per-employee, per-hour: scales correctly with number of workers sent
                revenue = rate * hours
            elif rate_type == "monthly":
                # Credit once per customer per calendar month (handles multi-month periods)
                month_key = (customer, f"{entry_date.year}-{entry_date.month:02d}")
                if month_key not in monthly_customers_credited:
                    days_in_month = calendar.monthrange(entry_date.year, entry_date.month)[1]
                    revenue = round(rate * min(days_in_period / days_in_month, 1.0), 2)
                    monthly_customers_credited.add(month_key)
                else:
                    revenue = 0.0
            else:  # per_visit: credit once per customer per day
                revenue = rate if is_new_visit else 0.0
        else:
            revenue = 0.0

        emp_rate = emp_rates.get(emp_id)
        labor_cost = (emp_rate * hours) if emp_rate is not None else 0.0

        exp_h = location_expected_hours.get(resolved_location)

        if customer not in customer_agg:
            customer_agg[customer] = {
                "customer": customer, "location": resolved_location,
                "visits": 0, "hours": 0.0, "revenue": 0.0, "laborCost": 0.0,
                "expectedHours": 0.0, "_hasExpected": False,
            }
        if is_new_visit:
            customer_agg[customer]["visits"] += 1
            if exp_h is not None:
                customer_agg[customer]["expectedHours"] += exp_h
                customer_agg[customer]["_hasExpected"] = True
        customer_agg[customer]["hours"] += hours
        customer_agg[customer]["revenue"] += revenue
        customer_agg[customer]["laborCost"] += labor_cost

        if date_key not in day_agg:
            day_agg[date_key] = {"date": date_key, "visits": 0, "hours": 0.0, "revenue": 0.0, "laborCost": 0.0}
        if is_new_visit:
            day_agg[date_key]["visits"] += 1
        day_agg[date_key]["hours"] += hours
        day_agg[date_key]["revenue"] += revenue
        day_agg[date_key]["laborCost"] += labor_cost

    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is None:
            continue
        if entry.get("timeCategory") == "non_productive":
            continue  # non-productive time belongs in waste analytics, not customer analytics
        ci_str = str(entry.get("clockIn", "")).strip()
        if not ci_str:
            continue
        try:
            ci_dt = parse_utc_iso(ci_str)
        except ValueError:
            continue

        entry_date = to_local(ci_dt).date()
        if start_date is not None and not (start_date <= entry_date <= end_date):
            continue

        emp_id = int(entry.get("employeeId", 0))
        date_key = entry_date.strftime("%Y-%m-%d")

        visits = entry.get("visits") or []
        if visits:
            # Multi-stop: distribute hours across each visit segment
            try:
                co_dt = parse_utc_iso(str(entry["clockOut"]))
            except (ValueError, KeyError):
                continue
            for j, visit in enumerate(visits):
                try:
                    v_arrival = parse_utc_iso(str(visit["arrivalTime"]))
                except (ValueError, KeyError):
                    continue
                next_time = co_dt
                if j + 1 < len(visits):
                    try:
                        next_time = parse_utc_iso(str(visits[j + 1]["arrivalTime"]))
                    except (ValueError, KeyError):
                        pass
                visit_hours = max((next_time - v_arrival).total_seconds() / 3600, 0.0)
                v_loc = visit.get("location", "")
                resolved_location, customer = _resolve_loc(v_loc)
                _aggregate(customer, resolved_location, visit_hours, emp_id, entry_date, date_key, is_visit=True)
        else:
            # Legacy / single-location shift
            hours = float(entry.get("totalHours", 0) or 0)
            location = entry.get("location", "")
            resolved_location, customer = _resolve_loc(location)
            _aggregate(customer, resolved_location, hours, emp_id, entry_date, date_key, is_visit=True)

    def _classify(labor_pct, gross_margin, variance, rplh) -> Tuple[str, List[str]]:
        """Return (flag, reasons) - flag is Healthy/Watch/Fix/Raise Price/Drop."""
        reasons: List[str] = []
        severity = 0  # 0=Healthy, 1=Watch, 2=Fix/Raise Price, 3=Drop

        lp_drop  = settings.get("laborPctDrop",  _SETTINGS_DEFAULTS["laborPctDrop"])
        lp_fix   = settings.get("laborPctFix",   _SETTINGS_DEFAULTS["laborPctFix"])
        lp_watch = settings.get("laborPctWatch", _SETTINGS_DEFAULTS["laborPctWatch"])

        if labor_pct is not None:
            if labor_pct >= lp_drop:
                reasons.append(f"Labor % {labor_pct}% >= {lp_drop}% (drop)")
                severity = max(severity, 3)
            elif labor_pct >= lp_fix:
                reasons.append(f"Labor % {labor_pct}% >= {lp_fix}% (fix)")
                severity = max(severity, 2)
            elif labor_pct >= lp_watch:
                reasons.append(f"Labor % {labor_pct}% >= {lp_watch}% (watch)")
                severity = max(severity, 1)

        if gross_margin is not None:
            gm_drop = settings.get("grossMarginDrop", _SETTINGS_DEFAULTS["grossMarginDrop"])
            gm_fix  = settings.get("grossMarginFix",  _SETTINGS_DEFAULTS["grossMarginFix"])
            gm_min  = settings.get("grossMarginMin",  _SETTINGS_DEFAULTS["grossMarginMin"])
            if gross_margin <= gm_drop:
                reasons.append(f"Margin {gross_margin}% <= {gm_drop}% (drop)")
                severity = max(severity, 3)
            elif gross_margin < gm_fix:
                reasons.append(f"Margin {gross_margin}% < {gm_fix}% (fix)")
                severity = max(severity, 2)
            elif gross_margin < gm_min:
                reasons.append(f"Margin {gross_margin}% < {gm_min}% (watch)")
                severity = max(severity, 1)

        if variance is not None and variance < 0:
            overrun = abs(variance)
            fix_thresh   = settings.get("hourOverrunFix",   _SETTINGS_DEFAULTS["hourOverrunFix"])
            watch_thresh = settings.get("hourOverrunWatch", _SETTINGS_DEFAULTS["hourOverrunWatch"])
            if overrun >= fix_thresh:
                reasons.append(f"Overrun {overrun}h >= {fix_thresh}h (fix)")
                severity = max(severity, 2)
            elif overrun >= watch_thresh:
                reasons.append(f"Overrun {overrun}h >= {watch_thresh}h (watch)")
                severity = max(severity, 1)

        has_overrun = False
        if rplh is not None:
            rplh_min = settings.get("rplhMin", _SETTINGS_DEFAULTS["rplhMin"])
            if rplh < rplh_min:
                reasons.append(f"RPLH ${rplh:.2f} < ${rplh_min:.2f}")
                severity = max(severity, 1)

        if severity == 0:
            flag = "Healthy"
        elif severity == 3:
            flag = "Drop"
        elif severity == 1:
            flag = "Watch"
        else:
            # severity == 2: distinguish Fix (internal) vs Raise Price (pricing)
            labor_triggered   = labor_pct is not None and labor_pct >= lp_fix
            overrun_triggered = variance is not None and variance < 0 and abs(variance) >= settings.get("hourOverrunFix", _SETTINGS_DEFAULTS["hourOverrunFix"])
            if labor_triggered or overrun_triggered:
                flag = "Fix"
            else:
                flag = "Raise Price"
        return flag, reasons

    def _finalize(d: Dict[str, Any]) -> Dict[str, Any]:
        rev = d["revenue"]
        lc = d["laborCost"]
        actual_h = round(d["hours"], 2)
        lp = round(lc / rev * 100, 1) if rev > 0 else None
        net = round(rev - lc, 2)
        gross_margin = round(net / rev * 100, 1) if rev > 0 else None
        has_exp = d.get("_hasExpected", False)
        exp_h = round(d.get("expectedHours", 0.0), 2) if has_exp else None
        variance = round(exp_h - actual_h, 2) if exp_h is not None else None
        rplh = round(rev / actual_h, 2) if actual_h > 0 else None
        flag, flag_reasons = _classify(lp, gross_margin, variance, rplh)
        return {
            "customer": d["customer"],
            "location": d["location"],
            "visits": d["visits"],
            "hours": actual_h,
            "revenue": round(rev, 2),
            "laborCost": round(lc, 2),
            "laborPct": lp,
            "netProfit": net,
            "grossMarginPct": gross_margin,
            "expectedHours": exp_h,
            "varianceHours": variance,
            "rplh": rplh,
            "flag": flag,
            "flagReasons": flag_reasons,
        }

    by_customer = sorted([_finalize(c) for c in customer_agg.values()], key=lambda x: x["revenue"], reverse=True)
    by_day = sorted(
        [
            {
                "date": d["date"],
                "visits": d["visits"],
                "hours": round(d["hours"], 2),
                "revenue": round(d["revenue"], 2),
                "laborCost": round(d["laborCost"], 2),
                "laborPct": round(d["laborCost"] / d["revenue"] * 100, 1) if d["revenue"] > 0 else None,
                "netProfit": round(d["revenue"] - d["laborCost"], 2),
            }
            for d in day_agg.values()
        ],
        key=lambda x: x["date"],
    )

    total_rev = sum(c["revenue"] for c in by_customer)
    total_lc = sum(c["laborCost"] for c in by_customer)
    total_hours = round(sum(c["hours"] for c in by_customer), 2)
    total_visits = sum(c["visits"] for c in by_customer)

    return {
        "success": True,
        "period": period,
        "startDate": start_date.strftime("%Y-%m-%d") if start_date else None,
        "endDate": end_date.strftime("%Y-%m-%d") if end_date else None,
        "laborPctTarget": settings["laborPctTarget"],
        "summary": {
            "revenue": round(total_rev, 2),
            "laborCost": round(total_lc, 2),
            "laborPct": round(total_lc / total_rev * 100, 1) if total_rev > 0 else None,
            "netProfit": round(total_rev - total_lc, 2),
            "grossMarginPct": round((total_rev - total_lc) / total_rev * 100, 1) if total_rev > 0 else None,
            "hours": total_hours,
            "visits": total_visits,
        },
        "byCustomer": by_customer,
        "byDay": by_day,
    }


@app.get("/api/admin/analytics/customers")
def admin_analytics_customers(
    request: Request,
    period: str = "all",
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Customer profitability table. period=all (default) returns all-time data."""
    data = _compute_analytics(period, date)
    return {
        "success": True,
        "period": data["period"],
        "startDate": data["startDate"],
        "endDate": data["endDate"],
        "laborPctTarget": data["laborPctTarget"],
        "summary": data["summary"],
        "customers": data["byCustomer"],
    }


@app.get("/api/admin/analytics/flagged")
def admin_analytics_flagged(
    request: Request,
    period: str = "all",
    date: Optional[str] = None,
    flag: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Return only flagged (non-Healthy) customers, sorted by severity."""
    data = _compute_analytics(period, date)
    severity_order = {"Drop": 0, "Fix": 1, "Raise Price": 2, "Watch": 3, "Healthy": 4}
    flagged = [c for c in data["byCustomer"] if c["flag"] != "Healthy"]
    if flag:
        flagged = [c for c in flagged if c["flag"] == flag]
    flagged.sort(key=lambda c: (severity_order.get(c["flag"], 99), -(c.get("revenue") or 0)))
    counts = {}
    for c in data["byCustomer"]:
        counts[c["flag"]] = counts.get(c["flag"], 0) + 1
    settings = load_settings()
    return {
        "success": True,
        "period": data["period"],
        "startDate": data["startDate"],
        "endDate": data["endDate"],
        "thresholds": {
            "laborPctTarget": settings["laborPctTarget"],
            "laborPctWatch": settings["laborPctWatch"],
            "laborPctFix": settings["laborPctFix"],
            "laborPctDrop": settings["laborPctDrop"],
            "grossMarginMin": settings["grossMarginMin"],
            "grossMarginFix": settings["grossMarginFix"],
            "grossMarginDrop": settings["grossMarginDrop"],
            "hourOverrunWatch": settings["hourOverrunWatch"],
            "hourOverrunFix": settings["hourOverrunFix"],
            "rplhMin": settings["rplhMin"],
        },
        "flagCounts": counts,
        "flaggedCount": len(flagged),
        "customers": flagged,
    }


@app.get("/api/admin/analytics")
def admin_analytics(
    request: Request,
    period: str = "week",
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    return _compute_analytics(period, date)


@app.get("/api/admin/dashboard")
def admin_dashboard(
    request: Request,
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Single dashboard endpoint: daily/weekly/monthly cards + rankings + overruns + flags."""
    day_data = _compute_analytics("day", date)
    week_data = _compute_analytics("week", date)
    month_data = _compute_analytics("month", date)

    settings = load_settings()

    def _card(data: Dict[str, Any], label: str) -> Dict[str, Any]:
        s = data["summary"]
        rplh = round(s["revenue"] / s["hours"], 2) if s["hours"] > 0 else None
        return {
            "period": label,
            "startDate": data["startDate"],
            "endDate": data["endDate"],
            "revenue": s["revenue"],
            "laborCost": s["laborCost"],
            "laborPct": s["laborPct"],
            "netProfit": s["netProfit"],
            "grossMarginPct": s["grossMarginPct"],
            "hours": s["hours"],
            "visits": s["visits"],
            "rplh": rplh,
        }

    # Top/bottom 5 by net profit (from month data for meaningful ranking)
    customers = month_data["byCustomer"]
    by_profit = sorted(customers, key=lambda c: c["netProfit"], reverse=True)
    top5 = by_profit[:5]
    bottom5 = sorted(customers, key=lambda c: c["netProfit"])[:5]

    # Biggest hour overruns
    overruns = [
        c for c in customers
        if c.get("varianceHours") is not None and c["varianceHours"] < 0
    ]
    overruns.sort(key=lambda c: c["varianceHours"])  # most negative first
    top_overruns = overruns[:10]

    # Flagged summary from month data
    flag_counts: Dict[str, int] = {}
    for c in customers:
        f = c.get("flag", "Healthy")
        flag_counts[f] = flag_counts.get(f, 0) + 1

    return {
        "success": True,
        "cards": {
            "daily": _card(day_data, "day"),
            "weekly": _card(week_data, "week"),
            "monthly": _card(month_data, "month"),
        },
        "topCustomers": top5,
        "bottomCustomers": bottom5,
        "overruns": top_overruns,
        "flagCounts": flag_counts,
        "laborPctTarget": settings["laborPctTarget"],
    }


@app.get("/api/admin/analytics/export")
def admin_analytics_export(
    request: Request,
    period: str = "week",
    date: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> StreamingResponse:
    data = _compute_analytics(period, date)

    buf = io.StringIO()
    w = csv.writer(buf)
    s = data["summary"]

    w.writerow(["EOM Analytics Export"])
    w.writerow(["Period", data["period"], "From", data["startDate"], "To", data["endDate"]])
    w.writerow(["Revenue", f'${s["revenue"]:.2f}', "Labor Cost", f'${s["laborCost"]:.2f}',
                "Labor %", f'{s["laborPct"]}%' if s["laborPct"] is not None else "N/A",
                "Net Profit", f'${s["netProfit"]:.2f}', "Target", f'{data["laborPctTarget"]}%'])
    w.writerow([])

    w.writerow(["By Customer"])
    w.writerow(["Customer", "Location", "Visits", "Hours", "Revenue", "Labor Cost", "Labor %", "Net Profit"])
    for c in data["byCustomer"]:
        w.writerow([c["customer"], c["location"], c["visits"], f'{c["hours"]:.2f}',
                    f'${c["revenue"]:.2f}', f'${c["laborCost"]:.2f}',
                    f'{c["laborPct"]}%' if c["laborPct"] is not None else "N/A",
                    f'${c["netProfit"]:.2f}'])
    w.writerow([])

    w.writerow(["By Day"])
    w.writerow(["Date", "Visits", "Hours", "Revenue", "Labor Cost", "Labor %", "Net Profit"])
    for d in data["byDay"]:
        w.writerow([d["date"], d["visits"], f'{d["hours"]:.2f}',
                    f'${d["revenue"]:.2f}', f'${d["laborCost"]:.2f}',
                    f'{d["laborPct"]}%' if d["laborPct"] is not None else "N/A",
                    f'${d["netProfit"]:.2f}'])

    buf.seek(0)
    filename = f"eom_analytics_{period}_{data['startDate']}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/admin/analytics/customer/{customer_name}")
def admin_analytics_customer(
    customer_name: str,
    request: Request,
    weeks: int = 12,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Return per-visit history + weekly trend for a single customer over the last N weeks."""
    now = utc_now()
    local_now = to_local(now)
    ref_date = local_now.date()

    days_since_sunday = (ref_date.weekday() + 1) % 7
    current_week_start = ref_date - timedelta(days=days_since_sunday)
    start_date = current_week_start - timedelta(weeks=max(weeks - 1, 0))
    end_date = ref_date

    timesheet_data = load_timesheets()
    employees_data = load_employees()
    settings = load_settings()

    location_customers = timesheet_data.get("location_customers", {})
    location_rates = timesheet_data.get("location_rates", {})
    location_rate_types = timesheet_data.get("location_rate_types", {})

    emp_names: Dict[int, str] = {e["id"]: e["name"] for e in employees_data["employees"]}
    emp_rates: Dict[int, float] = {}
    for emp in employees_data["employees"]:
        rate = emp.get("hourlyRate")
        if rate is not None:
            emp_rates[emp["id"]] = float(rate)

    def _resolve_loc(location: str) -> Tuple[str, str]:
        resolved = location
        customer = location_customers.get(location)
        if not customer and location.startswith("GPS "):
            try:
                parts = location[4:].split(",")
                gps_lat, gps_lng = float(parts[0].strip()), float(parts[1].strip())
                matched = find_nearest_location(gps_lat, gps_lng, timesheet_data)
                if matched:
                    resolved = matched
                    customer = location_customers.get(matched) or matched
            except (ValueError, IndexError):
                pass
        if not customer:
            customer = location if (location and not location.startswith("GPS ") and location not in ("Unknown", "")) else "Unmatched Location"
        return resolved, customer

    def _calc_revenue(resolved_location: str, cust: str, hours: float, entry_date: Any, is_visit: bool, monthly_credited: set, date_key: str) -> float:
        rate = location_rates.get(resolved_location)
        rate_type = location_rate_types.get(resolved_location, "per_visit")
        if rate is None:
            return 0.0
        if rate_type == "hourly":
            return float(rate) * hours
        elif rate_type == "monthly":
            month_key = (cust, f"{entry_date.year}-{entry_date.month:02d}")
            if month_key not in monthly_credited:
                monthly_credited.add(month_key)
                return float(rate)
            return 0.0
        else:  # per_visit: credit once per location per day across all employees
            visit_key = (resolved_location, date_key)
            if is_visit and visit_key not in visited_for_revenue:
                visited_for_revenue.add(visit_key)
                return float(rate)
            return 0.0

    visits_list: List[Dict[str, Any]] = []
    week_agg: Dict[str, Dict[str, Any]] = {}
    monthly_credited: set = set()

    def _record(
        resolved_location: str,
        cust: str,
        hours: float,
        is_visit: bool,
        entry_date: Any,
        week_key: str,
        emp_name: str,
        emp_rate: Any,
        date_key: str,
    ) -> None:
        if cust != customer_name:
            return
        revenue = _calc_revenue(resolved_location, cust, hours, entry_date, is_visit, monthly_credited, date_key)
        labor_cost = (emp_rate * hours) if emp_rate is not None else 0.0
        lp = round(labor_cost / revenue * 100, 1) if revenue > 0 else None
        visits_list.append({
            "date": entry_date.strftime("%Y-%m-%d"),
            "weekStart": week_key,
            "employee": emp_name,
            "hours": round(hours, 2),
            "revenue": round(revenue, 2),
            "laborCost": round(labor_cost, 2),
            "laborPct": lp,
            "netProfit": round(revenue - labor_cost, 2),
        })
        if week_key not in week_agg:
            week_agg[week_key] = {"weekStart": week_key, "visits": 0, "hours": 0.0, "revenue": 0.0, "laborCost": 0.0}
        if is_visit:
            week_agg[week_key]["visits"] += 1
        week_agg[week_key]["hours"] += hours
        week_agg[week_key]["revenue"] += revenue
        week_agg[week_key]["laborCost"] += labor_cost

    visited_for_revenue: set = set()  # (resolved_location, date_key) - dedup per_visit in detail view
    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is None:
            continue
        if entry.get("timeCategory") == "non_productive":
            continue  # non-productive time belongs in waste analytics, not customer analytics
        ci_str = str(entry.get("clockIn", "")).strip()
        if not ci_str:
            continue
        try:
            ci_dt = parse_utc_iso(ci_str)
        except ValueError:
            continue

        entry_date = to_local(ci_dt).date()
        if not (start_date <= entry_date <= end_date):
            continue

        emp_id = int(entry.get("employeeId", 0))
        emp_name = emp_names.get(emp_id, f"Employee {emp_id}")
        emp_rate = emp_rates.get(emp_id)

        days_since_sunday_entry = (entry_date.weekday() + 1) % 7
        week_start = entry_date - timedelta(days=days_since_sunday_entry)
        week_key = week_start.strftime("%Y-%m-%d")
        date_key = entry_date.strftime("%Y-%m-%d")

        visits = entry.get("visits") or []
        if visits:
            try:
                co_dt = parse_utc_iso(str(entry["clockOut"]))
            except (ValueError, KeyError):
                continue
            for j, visit in enumerate(visits):
                try:
                    v_arrival = parse_utc_iso(str(visit["arrivalTime"]))
                except (ValueError, KeyError):
                    continue
                next_time = co_dt
                if j + 1 < len(visits):
                    try:
                        next_time = parse_utc_iso(str(visits[j + 1]["arrivalTime"]))
                    except (ValueError, KeyError):
                        pass
                v_hours = max((next_time - v_arrival).total_seconds() / 3600, 0.0)
                resolved_location, cust = _resolve_loc(visit.get("location", ""))
                _record(resolved_location, cust, v_hours, True, entry_date, week_key, emp_name, emp_rate, date_key)
        else:
            e_hours = float(entry.get("totalHours", 0) or 0)
            resolved_location, cust = _resolve_loc(entry.get("location", ""))
            _record(resolved_location, cust, e_hours, True, entry_date, week_key, emp_name, emp_rate, date_key)

    def _fin_week(w: Dict[str, Any]) -> Dict[str, Any]:
        rev = w["revenue"]
        lc = w["laborCost"]
        lp = round(lc / rev * 100, 1) if rev > 0 else None
        return {**w, "hours": round(w["hours"], 2), "revenue": round(rev, 2),
                "laborCost": round(lc, 2), "laborPct": lp, "netProfit": round(rev - lc, 2)}

    visits_list_sorted = sorted(visits_list, key=lambda x: x["date"], reverse=True)
    by_week = sorted([_fin_week(w) for w in week_agg.values()], key=lambda x: x["weekStart"])

    total_rev = sum(v["revenue"] for v in visits_list)
    total_lc = sum(v["laborCost"] for v in visits_list)
    total_hours = round(sum(v["hours"] for v in visits_list), 2)
    total_visits = len(visits_list)

    return {
        "success": True,
        "customer": customer_name,
        "weeks": weeks,
        "startDate": start_date.strftime("%Y-%m-%d"),
        "endDate": end_date.strftime("%Y-%m-%d"),
        "laborPctTarget": settings["laborPctTarget"],
        "summary": {
            "visits": total_visits,
            "hours": total_hours,
            "revenue": round(total_rev, 2),
            "laborCost": round(total_lc, 2),
            "laborPct": round(total_lc / total_rev * 100, 1) if total_rev > 0 else None,
            "netProfit": round(total_rev - total_lc, 2),
        },
        "byVisit": visits_list_sorted,
        "byWeek": by_week,
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("TIMETRACKER_HOST", "0.0.0.0")
    port = parse_int(os.getenv("PORT") or os.getenv("TIMETRACKER_PORT"), 9000)
    dev = os.getenv("ENV", "production").lower() == "development"
    uvicorn.run("time_tracker_api:app", host=host, port=port, reload=dev)
