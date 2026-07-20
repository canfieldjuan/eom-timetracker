#!/usr/bin/env python3
"""Unified Python backend for employee timekeeping and dashboard operations."""

from __future__ import annotations

import base64
import calendar
import csv
import hashlib
import hmac
import io
import inspect
import json
import logging
import math
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import date, datetime, time as clock_time, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated, Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID
from zoneinfo import ZoneInfo

import bcrypt
import jwt
import psycopg2
import psycopg2.extras
import requests
import qrcode
import qrcode.image.svg
import db
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

BASE_DIR = Path(__file__).resolve().parent.parent
_data_dir_env = os.environ.get("DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_FILE = BACKEND_DIR / "timetracker-mobile.html"

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
logger = logging.getLogger("eom.time_tracker")

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
    direct_ip = request.client.host if request.client and request.client.host else ""

    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [part.strip() for part in forwarded.split(",") if part.strip()]
        if hops:
            # A client can PREPEND fake entries on the left of X-Forwarded-For;
            # only the rightmost entries are appended by our own proxy layer.
            # Trust the hop TRUSTED_PROXY_HOPS from the right (default 1 = the
            # address our proxy actually observed), never the leftmost/
            # client-supplied value. For honest traffic (a single real hop) this
            # is identical to before.
            index = max(0, len(hops) - TRUSTED_PROXY_HOPS)
            return normalize_ip(hops[index])

    return normalize_ip(direct_ip) if direct_ip else "unknown"


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
SITE_CHECK_IN_RADIUS_DEFAULT_M = 50
SITE_CHECK_IN_MAX_ACCURACY_DEFAULT_M = 100
SITE_CHECK_IN_SCHEDULE_WINDOW_DEFAULT_HOURS = 12
SITE_CHECK_IN_DEVICE_SKEW_DEFAULT_SECONDS = 600
SITE_CHECK_IN_RECONCILIATION_GAP_DEFAULT_MINUTES = 15
SITE_CHECK_IN_RECONCILIATION_MAX_DAYS = 31
SITE_CHECK_IN_QR_VERSION = "eom1"
SITE_CHECK_IN_RADIUS_M = SITE_CHECK_IN_RADIUS_DEFAULT_M
SITE_CHECK_IN_MAX_ACCURACY_M = SITE_CHECK_IN_MAX_ACCURACY_DEFAULT_M
SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS = SITE_CHECK_IN_SCHEDULE_WINDOW_DEFAULT_HOURS
SITE_CHECK_IN_DEVICE_SKEW_SECONDS = SITE_CHECK_IN_DEVICE_SKEW_DEFAULT_SECONDS
SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES = (
    SITE_CHECK_IN_RECONCILIATION_GAP_DEFAULT_MINUTES
)


def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin(math.radians(lat2 - lat1) / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(math.radians(lng2 - lng1) / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _site_check_in_signature(site_id: int, nonce: str) -> str:
    message = f"{SITE_CHECK_IN_QR_VERSION}.{site_id}.{nonce}".encode("utf-8")
    digest = hmac.new(
        JWT_SECRET.encode("utf-8"),
        b"site-check-in\0" + message,
        hashlib.sha256,
    ).digest()
    return _base64url_encode(digest)


def build_site_check_in_token(site_id: int, nonce: str) -> str:
    signature = _site_check_in_signature(site_id, nonce)
    return f"{SITE_CHECK_IN_QR_VERSION}.{site_id}.{nonce}.{signature}"


def parse_site_check_in_token(token: str) -> Tuple[int, str]:
    parts = str(token or "").strip().split(".")
    if len(parts) != 4 or parts[0] != SITE_CHECK_IN_QR_VERSION:
        raise ValueError("Invalid or expired site QR code")

    try:
        site_id = int(parts[1])
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid or expired site QR code") from exc

    nonce, signature = parts[2], parts[3]
    if site_id <= 0 or not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", nonce):
        raise ValueError("Invalid or expired site QR code")

    expected = _site_check_in_signature(site_id, nonce)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid or expired site QR code")
    return site_id, nonce


def build_site_check_in_qr_svg(check_in_url: str) -> str:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
        image_factory=qrcode.image.svg.SvgPathFillImage,
    )
    qr.add_data(check_in_url)
    qr.make(fit=True)
    return qr.make_image().to_string(encoding="unicode")


def evaluate_site_check_in_geofence(
    *,
    site_latitude: Optional[float],
    site_longitude: Optional[float],
    latitude: float,
    longitude: float,
    accuracy: float,
) -> Dict[str, Any]:
    if site_latitude is None or site_longitude is None:
        return {
            "status": "site_unpinned",
            "distanceM": None,
            "radiusM": SITE_CHECK_IN_RADIUS_M,
            "accuracyM": round(float(accuracy), 2),
        }

    distance_m = haversine_m(
        latitude,
        longitude,
        float(site_latitude),
        float(site_longitude),
    )
    accuracy_m = float(accuracy)
    if accuracy_m > SITE_CHECK_IN_MAX_ACCURACY_M:
        geofence_status = "low_accuracy"
    elif distance_m + accuracy_m <= SITE_CHECK_IN_RADIUS_M:
        geofence_status = "inside"
    elif distance_m - accuracy_m > SITE_CHECK_IN_RADIUS_M:
        geofence_status = "outside"
    else:
        geofence_status = "uncertain"

    return {
        "status": geofence_status,
        "distanceM": round(distance_m, 2),
        "radiusM": SITE_CHECK_IN_RADIUS_M,
        "accuracyM": round(accuracy_m, 2),
    }


def find_nearest_location_match(
    lat: float,
    lng: float,
    timesheet_data: Dict[str, Any],
    *,
    coordinate_map_key: str = "location_coords",
) -> Optional[Dict[str, Any]]:
    coords = timesheet_data.get(coordinate_map_key, {})
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


def find_nearest_location(
    lat: float,
    lng: float,
    timesheet_data: Dict[str, Any],
    *,
    coordinate_map_key: str = "location_coords",
) -> Optional[str]:
    nearest = find_nearest_location_match(
        lat,
        lng,
        timesheet_data,
        coordinate_map_key=coordinate_map_key,
    )
    if nearest and nearest["withinRadius"]:
        return str(nearest["location"])
    return None


def build_gps_meta(
    timesheet_data: Dict[str, Any],
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
    override_detail: str = "",
    accuracy: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    reason = str(override_reason or "").strip()
    detail = str(override_detail or "").strip() if reason else ""
    nearest = None
    accuracy_m = None
    if latitude is not None and longitude is not None:
        nearest = find_nearest_location_match(latitude, longitude, timesheet_data)
        if accuracy is not None:
            accuracy_m = round(float(accuracy), 2)

    if not nearest and not reason and not detail and accuracy_m is None:
        return None

    return {
        "override": bool(reason),
        "overrideReason": reason,
        "overrideDetail": detail,
        "matchedLocation": str(nearest["location"]) if nearest else "",
        "distanceM": round(float(nearest["distanceM"]), 2) if nearest else None,
        "withinRadius": bool(nearest["withinRadius"]) if nearest else None,
        "accuracyM": accuracy_m,
    }


def build_gps_point(
    latitude: float,
    longitude: float,
    accuracy: Optional[float] = None,
) -> Dict[str, float]:
    point = {"lat": latitude, "lng": longitude}
    if accuracy is not None:
        point["accuracy"] = round(float(accuracy), 2)
    return point


def require_gps_override(
    timesheet_data: Dict[str, Any],
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
    override_detail: str = "",
) -> Optional[str]:
    has_latitude = latitude is not None
    has_longitude = longitude is not None
    if has_latitude != has_longitude:
        return "Latitude and longitude must be provided together."

    reason = str(override_reason or "").strip()
    detail = str(override_detail or "").strip()
    if detail and not reason:
        return "GPS override details require an override reason."

    if reason:
        return None

    if not has_latitude:
        return "GPS location is required. Add an override reason to continue."

    assert latitude is not None and longitude is not None
    nearest = find_nearest_location_match(latitude, longitude, timesheet_data)
    if not nearest:
        return (
            "GPS location cannot be matched because no saved site has a location pin. "
            "Add an override reason to continue."
        )
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
        "frequency, lat, lng, expected_hours, target_labor_pct, min_margin_pct, active "
        "FROM locations ORDER BY id"
    )
    active_loc_rows = [row for row in loc_rows if bool(row.get("active"))]
    locations: List[str] = [r["address"] for r in active_loc_rows]
    location_coords: Dict[str, Dict[str, float]] = {}
    location_customers: Dict[str, str] = {}
    location_rates: Dict[str, float] = {}
    location_rate_types: Dict[str, str] = {}
    location_types: Dict[str, str] = {}
    location_frequencies: Dict[str, str] = {}
    location_expected_hours: Dict[str, float] = {}
    location_target_labor: Dict[str, float] = {}
    location_min_margin: Dict[str, float] = {}

    for r in active_loc_rows:
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

    historical_location_coords: Dict[str, Dict[str, float]] = {}
    historical_location_customers: Dict[str, str] = {}
    historical_location_rates: Dict[str, float] = {}
    historical_location_rate_types: Dict[str, str] = {}
    historical_location_expected_hours: Dict[str, float] = {}
    historical_location_target_labor: Dict[str, float] = {}
    historical_location_min_margin: Dict[str, float] = {}
    for row in loc_rows:
        address = str(row["address"])
        if row.get("lat") is not None and row.get("lng") is not None:
            historical_location_coords[address] = {
                "lat": float(row["lat"]),
                "lng": float(row["lng"]),
            }
        if row.get("customer_name"):
            historical_location_customers[address] = str(row["customer_name"])
        if row.get("rate") is not None:
            historical_location_rates[address] = float(row["rate"])
        if row.get("rate_type"):
            historical_location_rate_types[address] = str(row["rate_type"])
        if row.get("expected_hours") is not None:
            historical_location_expected_hours[address] = float(row["expected_hours"])
        if row.get("target_labor_pct") is not None:
            historical_location_target_labor[address] = float(row["target_labor_pct"])
        if row.get("min_margin_pct") is not None:
            historical_location_min_margin[address] = float(row["min_margin_pct"])

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
        "_historical_location_coords": historical_location_coords,
        "_historical_location_customers": historical_location_customers,
        "_historical_location_rates": historical_location_rates,
        "_historical_location_rate_types": historical_location_rate_types,
        "_historical_location_expected_hours": historical_location_expected_hours,
        "_historical_location_target_labor": historical_location_target_labor,
        "_historical_location_min_margin": historical_location_min_margin,
    }


def _save_timesheets_to_db(
    timesheet_data: Dict[str, Any],
    pre_shift_ids: set,
    pre_visit_counts: Dict[int, int],
    pre_departure_counts: Dict[int, int],
) -> None:
    """Persist time evidence without mutating the server-authoritative Site list."""
    with db.get_conn() as conn:
        cur = conn.cursor()

        cur.execute("SELECT id, address FROM locations WHERE active = true")
        addr_to_id: Dict[str, int] = {
            str(address): int(location_id)
            for location_id, address in cur.fetchall()
        }

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
                        location_label      = %s,
                        clock_in            = %s,
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


def get_stale_open_entry(
    entries: List[Dict[str, Any]],
    employee_id: int,
    reference_time: datetime,
) -> Optional[Dict[str, Any]]:
    stale_entries = [
        entry
        for entry in entries
        if entry.get("employeeId") == employee_id
        and is_stale_open_entry(entry, reference_time)
    ]
    if not stale_entries:
        return None

    stale_entries.sort(
        key=lambda item: (str(item.get("clockIn", "")), int(item.get("id", 0)))
    )
    return stale_entries[0]


STALE_SHIFT_REVIEW_CODE = "STALE_SHIFT_REQUIRES_REVIEW"


def stale_open_shift_summary(
    entry: Dict[str, Any],
    reference_time: datetime,
) -> Optional[Dict[str, Any]]:
    if not is_stale_open_entry(entry, reference_time):
        return None

    try:
        started_at = parse_utc_iso(str(entry.get("clockIn", "")))
    except ValueError:
        return None

    return {
        "shiftId": int(entry.get("id", 0)),
        "clockIn": to_utc_iso(started_at),
        "location": str(entry.get("location", "")),
        "ageHours": round((reference_time - started_at).total_seconds() / 3600.0, 2),
        "requiresAdminReview": True,
    }


def stale_shift_review_failure(
    entry: Dict[str, Any],
    reference_time: datetime,
) -> Dict[str, Any]:
    summary = stale_open_shift_summary(entry, reference_time) or {
        "shiftId": int(entry.get("id", 0)),
        "requiresAdminReview": True,
    }
    shift_id = summary["shiftId"]
    return {
        "code": STALE_SHIFT_REVIEW_CODE,
        "message": (
            f"Shift {shift_id} is missing a verified clock-out. "
            "Ask an administrator to review it before recording more time."
        ),
        "details": {"staleOpenShift": summary},
    }


def raise_timesheet_mutation_failure(result: Any) -> None:
    if isinstance(result, dict) and result.get("code") == STALE_SHIFT_REVIEW_CODE:
        raise HTTPException(status_code=409, detail=result)
    raise HTTPException(status_code=400, detail=str(result))


def update_timesheets(mutator) -> Tuple[bool, Any]:
    with TIMESHEET_WRITE_LOCK:
        timesheet_data = _load_timesheets_from_db()
        pre_shift_ids = {e["id"] for e in timesheet_data["entries"]}
        pre_visit_counts = {e["id"]: len(e.get("visits", [])) for e in timesheet_data["entries"]}
        pre_departure_counts = {e["id"]: len(e.get("departures", [])) for e in timesheet_data["entries"]}

        ok, payload = mutator(timesheet_data)
        if ok:
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


def find_any_employee_by_name(employees: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    """Find an employee regardless of active status.

    Account creation must consider inactive employees too because the database
    enforces unique names and re-registering must never silently reactivate or
    overwrite an existing account.
    """
    lowered = name.strip().lower()
    for employee in employees:
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
        if is_stale_open_entry(entry, reference_time):
            return 0.0
        duration = reference_time - clock_in_time
        duration_hours = duration.total_seconds() / 3600
        if duration_hours < 0:
            return 0.0
        return round(duration_hours, 2)

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
            elif is_stale_open_entry(entry, now):
                end_time = "Needs review"
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


def _historical_location_metadata(
    timesheet_data: Dict[str, Any],
    key: str,
) -> Dict[str, Any]:
    historical = timesheet_data.get(f"_historical_{key}")
    if isinstance(historical, dict):
        return historical
    current = timesheet_data.get(key)
    return current if isinstance(current, dict) else {}


def build_public_current_status(
    timesheet_data: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    timesheet_data = timesheet_data or load_timesheets()
    location_customers = _historical_location_metadata(
        timesheet_data,
        "location_customers",
    )
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
        # Surface the latest action's evidence even when it is override-only.
        # Falling back only when GPS is absent can show stale coordinates and
        # hide the exception that an administrator actually needs to review.
        last_visit = visits[-1] if visits and isinstance(visits[-1], dict) else None
        if active_visit:
            evidence = active_visit
        elif last_departure and isinstance(last_departure, dict):
            evidence = last_departure
        elif last_visit:
            evidence = last_visit
        else:
            evidence = None

        if evidence:
            gps = evidence.get("gps") if isinstance(evidence.get("gps"), dict) else None
            gps_meta = evidence.get("gpsMeta")
        else:
            gps = entry.get("clockInGps")
            gps_meta = entry.get("clockInGpsMeta")

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
                "clockInGpsMeta": gps_meta if isinstance(gps_meta, dict) else None,
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


SELF_SERVICE_PASSWORD_MIN_LENGTH = 8
BCRYPT_PASSWORD_MAX_BYTES = 72


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(alias="currentPassword", min_length=1, max_length=256)
    new_password: str = Field(
        alias="newPassword",
        min_length=SELF_SERVICE_PASSWORD_MIN_LENGTH,
        max_length=BCRYPT_PASSWORD_MAX_BYTES,
    )

    @field_validator("new_password")
    @classmethod
    def new_password_must_fit_bcrypt(cls, value: str) -> str:
        if len(value.encode("utf-8")) > BCRYPT_PASSWORD_MAX_BYTES:
            raise ValueError(
                f"newPassword must be at most {BCRYPT_PASSWORD_MAX_BYTES} UTF-8 bytes"
            )
        return value


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2)
    password: str = Field(min_length=4)


class AdminEmployeeCreateRequest(RegisterRequest):
    role: str = "employee"
    hourlyRate: Optional[float] = None


CUSTOMER_NAME_MAX_LENGTH = 200
CUSTOMER_PHONE_MAX_LENGTH = 50
CUSTOMER_EMAIL_MAX_LENGTH = 320
SITE_ADDRESS_MAX_LENGTH = 500
SITE_FREQUENCY_MAX_LENGTH = 100
SITE_DETAIL_MAX_LENGTH = 4000
SITE_PET_NOTES_MAX_LENGTH = 2000
SITE_RATE_MAX = 999999.99
SITE_EXPECTED_HOURS_MAX = 9999.99


def _strip_required_text(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


def _strip_optional_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    return stripped or None


def _validate_optional_email(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ValueError("must be a valid email address")
    return value


def _validate_iso_service_date(value: Any) -> Any:
    if value is None or isinstance(value, date):
        return value
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("must use ISO YYYY-MM-DD format")
    return value


class PrimarySiteCreateRequest(BaseModel):
    address: str = Field(min_length=1, max_length=SITE_ADDRESS_MAX_LENGTH)
    locationType: str = Field(pattern="^(Residential|Commercial)$")
    rate: Optional[float] = Field(
        default=None,
        ge=0,
        le=SITE_RATE_MAX,
        allow_inf_nan=False,
    )
    rateType: str = Field(default="per_visit", pattern="^(per_visit|hourly|monthly)$")
    frequency: Optional[str] = Field(default=None, max_length=SITE_FREQUENCY_MAX_LENGTH)
    expectedHours: Optional[float] = Field(
        default=None,
        ge=0,
        le=SITE_EXPECTED_HOURS_MAX,
        allow_inf_nan=False,
    )
    targetLaborPct: Optional[float] = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    minMarginPct: Optional[float] = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    lat: Optional[float] = Field(default=None, ge=-90, le=90, allow_inf_nan=False)
    lng: Optional[float] = Field(default=None, ge=-180, le=180, allow_inf_nan=False)
    serviceScope: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    accessInstructions: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    servicePreferences: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    petNotes: Optional[str] = Field(default=None, max_length=SITE_PET_NOTES_MAX_LENGTH)
    serviceStartDate: Optional[date] = None

    @field_validator(
        "address",
        "frequency",
        "serviceScope",
        "accessInstructions",
        "servicePreferences",
        "petNotes",
        mode="before",
    )
    @classmethod
    def normalize_text_fields(cls, value: Any, info: Any) -> Any:
        if info.field_name == "address":
            return _strip_required_text(value)
        return _strip_optional_text(value)

    @field_validator("serviceStartDate", mode="before")
    @classmethod
    def validate_service_start_date(cls, value: Any) -> Any:
        return _validate_iso_service_date(value)

    @model_validator(mode="after")
    def coordinates_must_be_paired(self) -> "PrimarySiteCreateRequest":
        if (self.lat is None) != (self.lng is None):
            raise ValueError("lat and lng must be provided together")
        return self


class CustomerCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryContactName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryPhone: Optional[str] = Field(default=None, max_length=CUSTOMER_PHONE_MAX_LENGTH)
    primaryEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    billingEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingAddress: Optional[str] = Field(default=None, max_length=SITE_ADDRESS_MAX_LENGTH)
    atlasContactId: Optional[UUID] = None
    primarySite: Optional[PrimarySiteCreateRequest] = None

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: Any) -> Any:
        return _strip_required_text(value)

    @field_validator(
        "primaryContactName",
        "primaryPhone",
        "primaryEmail",
        "billingName",
        "billingEmail",
        "billingAddress",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(cls, value: Any) -> Any:
        return _strip_optional_text(value)

    @field_validator("primaryEmail", "billingEmail")
    @classmethod
    def validate_emails(cls, value: Optional[str]) -> Optional[str]:
        return _validate_optional_email(value)


class CustomerUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryContactName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryPhone: Optional[str] = Field(default=None, max_length=CUSTOMER_PHONE_MAX_LENGTH)
    primaryEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    billingEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingAddress: Optional[str] = Field(default=None, max_length=SITE_ADDRESS_MAX_LENGTH)
    atlasContactId: Optional[UUID] = None

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: Any) -> Any:
        return _strip_required_text(value)

    @field_validator(
        "primaryContactName",
        "primaryPhone",
        "primaryEmail",
        "billingName",
        "billingEmail",
        "billingAddress",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(cls, value: Any) -> Any:
        return _strip_optional_text(value)

    @field_validator("primaryEmail", "billingEmail")
    @classmethod
    def validate_emails(cls, value: Optional[str]) -> Optional[str]:
        return _validate_optional_email(value)


class SiteCreateRequest(PrimarySiteCreateRequest):
    customerId: Optional[int] = Field(default=None, gt=0)
    customerName: Optional[str] = Field(default=None, min_length=1, max_length=CUSTOMER_NAME_MAX_LENGTH)

    @field_validator("customerName", mode="before")
    @classmethod
    def normalize_customer_name(cls, value: Any) -> Any:
        return _strip_required_text(value)


class SiteUpdateRequest(BaseModel):
    customerId: Optional[int] = Field(default=None, gt=0)
    customerName: Optional[str] = Field(default=None, min_length=1, max_length=CUSTOMER_NAME_MAX_LENGTH)
    address: Optional[str] = Field(default=None, min_length=1, max_length=SITE_ADDRESS_MAX_LENGTH)
    locationType: Optional[str] = Field(default=None, pattern="^(Residential|Commercial)$")
    rate: Optional[float] = Field(default=None, ge=0, le=SITE_RATE_MAX, allow_inf_nan=False)
    rateType: Optional[str] = Field(default=None, pattern="^(per_visit|hourly|monthly)$")
    frequency: Optional[str] = Field(default=None, max_length=SITE_FREQUENCY_MAX_LENGTH)
    expectedHours: Optional[float] = Field(
        default=None,
        ge=0,
        le=SITE_EXPECTED_HOURS_MAX,
        allow_inf_nan=False,
    )
    targetLaborPct: Optional[float] = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    minMarginPct: Optional[float] = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    lat: Optional[float] = Field(default=None, ge=-90, le=90, allow_inf_nan=False)
    lng: Optional[float] = Field(default=None, ge=-180, le=180, allow_inf_nan=False)
    serviceScope: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    accessInstructions: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    servicePreferences: Optional[str] = Field(default=None, max_length=SITE_DETAIL_MAX_LENGTH)
    petNotes: Optional[str] = Field(default=None, max_length=SITE_PET_NOTES_MAX_LENGTH)
    serviceStartDate: Optional[date] = None

    @field_validator("customerName", "address", mode="before")
    @classmethod
    def normalize_required_text(cls, value: Any) -> Any:
        return _strip_required_text(value)

    @field_validator(
        "frequency",
        "serviceScope",
        "accessInstructions",
        "servicePreferences",
        "petNotes",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(cls, value: Any) -> Any:
        return _strip_optional_text(value)

    @field_validator("serviceStartDate", mode="before")
    @classmethod
    def validate_service_start_date(cls, value: Any) -> Any:
        return _validate_iso_service_date(value)


MAX_LOCATION_LEN            = parse_int(os.getenv("MAX_LOCATION_LEN"),            500)
MAX_NOTES_LEN               = parse_int(os.getenv("MAX_NOTES_LEN"),               2000)
MAX_GPS_OVERRIDE_REASON_LEN = parse_int(os.getenv("MAX_GPS_OVERRIDE_REASON_LEN"), 200)
MAX_GPS_OVERRIDE_DETAIL_LEN = parse_int(os.getenv("MAX_GPS_OVERRIDE_DETAIL_LEN"), 500)


class ClockInRequest(BaseModel):
    location: str = Field(default="", max_length=MAX_LOCATION_LEN)
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    accuracy: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class SiteQrRequest(BaseModel):
    rotate: bool = False


class SiteQrResolveRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)


class SiteCheckInRequest(BaseModel):
    employeeId: int = Field(gt=0)
    siteId: int = Field(gt=0)
    token: str = Field(min_length=20, max_length=256)
    scannedAt: datetime
    latitude: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitude: float = Field(ge=-180, le=180, allow_inf_nan=False)
    accuracy: float = Field(ge=0, le=100_000, allow_inf_nan=False)

    @field_validator("scannedAt")
    @classmethod
    def scanned_at_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scannedAt must include a timezone")
        return value.astimezone(timezone.utc)


class SiteCheckInScheduleRequest(BaseModel):
    employeeId: int = Field(gt=0)
    siteId: int = Field(gt=0)
    scheduledStart: datetime
    graceMinutes: int = Field(default=10, ge=0, le=120)

    @field_validator("scheduledStart")
    @classmethod
    def scheduled_start_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scheduledStart must include a timezone")
        return value.astimezone(timezone.utc)


class SiteCheckInScheduleRuleRequest(BaseModel):
    employeeId: int = Field(gt=0)
    siteId: int = Field(gt=0)
    weekdays: List[int] = Field(min_length=1, max_length=7)
    localStart: clock_time
    startsOn: date
    endsOn: Optional[date] = None
    graceMinutes: int = Field(default=10, ge=0, le=120)

    @field_validator("weekdays")
    @classmethod
    def weekdays_must_be_unique_business_days(cls, value: List[int]) -> List[int]:
        normalized = sorted(set(value))
        if len(normalized) != len(value) or any(
            day < 0 or day > 6 for day in normalized
        ):
            raise ValueError(
                "weekdays must contain unique values from 0 (Monday) to 6 (Sunday)"
            )
        return normalized

    @field_validator("localStart")
    @classmethod
    def local_start_must_use_minute_precision(cls, value: clock_time) -> clock_time:
        if value.tzinfo is not None:
            raise ValueError("localStart must not include a timezone")
        if value.second or value.microsecond:
            raise ValueError("localStart must use HH:MM precision")
        return value


class SiteCheckInReviewRequest(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    note: str = Field(min_length=3, max_length=500)

    @field_validator("note", mode="before")
    @classmethod
    def strip_review_note(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class SiteCheckInReconciliationReviewRequest(BaseModel):
    evidenceFingerprint: str = Field(pattern="^[0-9a-f]{64}$")
    disposition: str = Field(pattern="^(resolved|needs_correction)$")
    note: str = Field(min_length=3, max_length=500)

    @field_validator("note", mode="before")
    @classmethod
    def strip_reconciliation_review_note(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class ClockOutRequest(BaseModel):
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    accuracy: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class DepartRequest(BaseModel):
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    accuracy: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)


class EntryAdjustRequest(BaseModel):
    clockIn: Optional[str] = None   # "YYYY-MM-DDTHH:MM" local time
    clockOut: Optional[str] = None  # "YYYY-MM-DDTHH:MM" local time, or "" to clear


class DuplicateShiftResolutionRequest(BaseModel):
    canonicalShiftId: int = Field(gt=0)
    duplicateShiftIds: List[int] = Field(min_length=1, max_length=20)


class StaleShiftClosureRequest(BaseModel):
    shiftId: int = Field(gt=0)
    clockOut: str = Field(min_length=16, max_length=40)


class TimeDataCorrectionPlanRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)
    duplicateResolutions: List[DuplicateShiftResolutionRequest] = Field(
        default_factory=list,
        max_length=50,
    )
    staleShiftClosures: List[StaleShiftClosureRequest] = Field(
        default_factory=list,
        max_length=100,
    )


class TimeDataCorrectionApplyRequest(TimeDataCorrectionPlanRequest):
    planToken: str = Field(min_length=64, max_length=64)
    confirmation: str = Field(min_length=1, max_length=100)


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


PositiveCents = Annotated[int, Field(strict=True, gt=0)]


class ReceivablesAllocationRequest(BaseModel):
    invoice_id: UUID
    amount_cents: PositiveCents


class ReceivablesPaymentRequest(BaseModel):
    contact_id: UUID
    payer_name: str = Field(min_length=1, max_length=256)
    total_amount_cents: PositiveCents
    payment_method: str = Field(pattern="^(check|ach|square)$")
    received_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reference: str = Field(min_length=1, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=2000)
    allocations: List[ReceivablesAllocationRequest] = Field(min_length=1, max_length=100)

    @field_validator("reference")
    @classmethod
    def reference_must_identify_receipt(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError(
                "check number, ACH confirmation, or Square transaction ID is required"
            )
        return normalized


class ReceivablesAdjustmentRequest(BaseModel):
    allocations: List[ReceivablesAllocationRequest] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class ReceivablesActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class ReceivablesDepositRequest(BaseModel):
    payment_ids: List[UUID] = Field(min_length=1, max_length=500)
    deposit_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    bank_reference: Optional[str] = Field(default=None, max_length=256)

    @field_validator("payment_ids")
    @classmethod
    def payment_ids_must_be_unique(cls, value: List[UUID]) -> List[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("a payment may only appear once")
        return value


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
LOCATION_MATCH_RADIUS_M = parse_int(os.getenv("LOCATION_MATCH_RADIUS_M"), LOCATION_MATCH_RADIUS_DEFAULT_M)
SITE_CHECK_IN_RADIUS_M = max(
    1,
    parse_int(os.getenv("SITE_CHECK_IN_RADIUS_M"), SITE_CHECK_IN_RADIUS_DEFAULT_M),
)
SITE_CHECK_IN_MAX_ACCURACY_M = max(
    1,
    parse_int(
        os.getenv("SITE_CHECK_IN_MAX_ACCURACY_M"),
        SITE_CHECK_IN_MAX_ACCURACY_DEFAULT_M,
    ),
)
SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS = max(
    1,
    parse_int(
        os.getenv("SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS"),
        SITE_CHECK_IN_SCHEDULE_WINDOW_DEFAULT_HOURS,
    ),
)
SITE_CHECK_IN_DEVICE_SKEW_SECONDS = max(
    0,
    parse_int(
        os.getenv("SITE_CHECK_IN_DEVICE_SKEW_SECONDS"),
        SITE_CHECK_IN_DEVICE_SKEW_DEFAULT_SECONDS,
    ),
)
SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES = max(
    0,
    parse_int(
        os.getenv("SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES"),
        SITE_CHECK_IN_RECONCILIATION_GAP_DEFAULT_MINUTES,
    ),
)

ACCESS_START_HOUR = parse_int(os.getenv("ACCESS_START_HOUR"), 8)
ACCESS_END_HOUR = parse_int(os.getenv("ACCESS_END_HOUR"), 18)
validate_schedule(ACCESS_START_HOUR, ACCESS_END_HOUR)
ALLOWED_DAYS = parse_allowed_days(os.getenv("ALLOWED_DAYS"))
ALLOWED_IPS = parse_allowed_ips(os.getenv("ALLOWED_IPS"))
TRUST_PROXY = parse_bool(os.getenv("TRUST_PROXY"), False)
# Number of trusted reverse-proxy hops between the app and the public internet.
# Used to pick the real client IP from the RIGHT of X-Forwarded-For (Render's
# edge = 1). Increase only if you add another trusted proxy (e.g. a CDN).
TRUSTED_PROXY_HOPS = max(1, parse_int(os.getenv("TRUSTED_PROXY_HOPS"), 1))
BOOTSTRAP_ADMIN_IDS = [
    int(x) for x in os.getenv("BOOTSTRAP_ADMIN_IDS", "").split(",") if x.strip().isdigit()
]

DEFAULT_PORTAL_ALLOWED_ORIGINS = [
    "https://effinghamofficemaids.com",
    "https://www.effinghamofficemaids.com",
    "https://effingham-office-maids-website.vercel.app",
]
DEFAULT_PORTAL_ALLOWED_ORIGIN_REGEX = (
    r"^https://effingham-office-maids-[a-z0-9-]+-juan-canfields-projects\.vercel\.app$"
)
_configured_allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
# These are first-party portal origins, so keep them available even when an
# older Render environment value supplies additional origins. Environment
# configuration can extend this list but cannot accidentally disable the
# public portal.
ALLOWED_ORIGINS = list(
    dict.fromkeys([*DEFAULT_PORTAL_ALLOWED_ORIGINS, *_configured_allowed_origins])
)
ALLOWED_ORIGIN_REGEX = (
    (os.getenv("ALLOWED_ORIGIN_REGEX") or "").strip()
    or DEFAULT_PORTAL_ALLOWED_ORIGIN_REGEX
)
ALLOW_PUBLIC_REGISTRATION = parse_bool(os.getenv("ALLOW_PUBLIC_REGISTRATION"), False)
MAX_REPORT_RECIPIENTS = parse_int(os.getenv("MAX_REPORT_RECIPIENTS"), 50)
MAX_REPORT_EMAIL_LEN = parse_int(os.getenv("MAX_REPORT_EMAIL_LEN"), 320)
ATLAS_RECEIVABLES_BASE_URL = os.getenv("ATLAS_RECEIVABLES_BASE_URL", "").strip().rstrip("/")
ATLAS_RECEIVABLES_SERVICE_TOKEN = os.getenv(
    "ATLAS_RECEIVABLES_SERVICE_TOKEN", ""
).strip()
ATLAS_RECEIVABLES_TIMEOUT_SECONDS = max(
    1.0, float(os.getenv("ATLAS_RECEIVABLES_TIMEOUT_SECONDS", "10"))
)
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", "").strip().rstrip("/")
if PUBLIC_APP_URL and not re.fullmatch(r"https?://[^\s]+", PUBLIC_APP_URL):
    raise RuntimeError("PUBLIC_APP_URL must be an absolute http or https URL")

LOGIN_RATE_LIMIT_MAX        = parse_int(os.getenv("LOGIN_RATE_LIMIT_MAX"),        10)
LOGIN_RATE_LIMIT_WINDOW_S   = parse_int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_S"),   60)
PASSWORD_CHANGE_RATE_LIMIT_MAX = parse_int(
    os.getenv("PASSWORD_CHANGE_RATE_LIMIT_MAX"), 5
)
PASSWORD_CHANGE_RATE_LIMIT_WINDOW_S = parse_int(
    os.getenv("PASSWORD_CHANGE_RATE_LIMIT_WINDOW_S"), 300
)
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
if "allow_private_network" in inspect.signature(CORSMiddleware.__init__).parameters:
    # Starlette 1.3+ rejects Private Network Access preflights unless this is
    # explicitly enabled. Older supported releases do not expose the option,
    # so the response middleware below remains the compatibility path there.
    _cors_kwargs["allow_private_network"] = True
if ALLOWED_ORIGINS or ALLOWED_ORIGIN_REGEX:
    if ALLOWED_ORIGINS:
        _cors_kwargs["allow_origins"] = ALLOWED_ORIGINS
    if ALLOWED_ORIGIN_REGEX:
        _cors_kwargs["allow_origin_regex"] = ALLOWED_ORIGIN_REGEX
    app.add_middleware(CORSMiddleware, **_cors_kwargs)
else:
    print(
        "[security] WARNING: ALLOWED_ORIGINS / ALLOWED_ORIGIN_REGEX are not set; "
        "cross-origin browser access is disabled. Set ALLOWED_ORIGINS to the "
        "exact frontend origin(s) if cross-origin access is required.",
        flush=True,
    )


def _atlas_receivables_request(
    method: str,
    path: str,
    admin: Dict[str, Any],
    *,
    payload: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
) -> Any:
    """Proxy a finance request without exposing Atlas credentials to browsers."""
    if not ATLAS_RECEIVABLES_BASE_URL or not ATLAS_RECEIVABLES_SERVICE_TOKEN:
        raise HTTPException(
            status_code=503, detail="Receivables service is not configured"
        )
    if not path.startswith("/receivables/"):
        raise RuntimeError("Invalid receivables proxy path")
    headers = {
        "Authorization": f"Bearer {ATLAS_RECEIVABLES_SERVICE_TOKEN}",
        "X-EOM-Actor": str(admin["name"]),
        "Accept": "application/json",
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    try:
        response = requests.request(
            method,
            f"{ATLAS_RECEIVABLES_BASE_URL}{path}",
            headers=headers,
            json=payload,
            params=params,
            timeout=ATLAS_RECEIVABLES_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=503,
            detail="Receivables service is temporarily unavailable; retry this request",
            headers={"Retry-After": "5"},
        ) from exc
    try:
        content = response.json()
    except ValueError as exc:
        if response.status_code >= 500:
            raise HTTPException(
                status_code=response.status_code,
                detail="Receivables service is temporarily unavailable; retry this request",
                headers={"Retry-After": "5"},
            ) from exc
        raise HTTPException(
            status_code=502, detail="Receivables service returned an invalid response"
        ) from exc
    if response.status_code in (401, 403):
        # Browser-facing 401 is reserved for the EOM admin session. Forwarding
        # an Atlas service-credential rejection would make the portal log out a
        # valid admin and hide the real deployment/configuration failure.
        logger.error(
            "Atlas receivables service credential rejected status=%s",
            response.status_code,
        )
        raise HTTPException(
            status_code=502,
            detail="Receivables service authentication failed",
        )
    if response.status_code >= 400:
        detail: Any = content.get("detail", content) if isinstance(content, dict) else content
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or "Receivables request failed"
        if not isinstance(detail, str) or not detail.strip():
            detail = "Receivables request failed"
        headers = {"Retry-After": "5"} if response.status_code >= 500 else None
        raise HTTPException(
            status_code=response.status_code,
            detail=detail,
            headers=headers,
        )
    return content


def _canonicalize_receivables_payload(
    operation: str,
    payload: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if payload is None:
        return None
    canonical = dict(payload)
    if operation == "RECEIVABLES_DEPOSIT_CREATE":
        canonical["payment_ids"] = sorted(
            str(item) for item in payload.get("payment_ids", [])
        )
    return canonical


def _receivables_operation_fingerprint(
    operation: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]],
) -> str:
    encoded = json.dumps(
        {
            "operation": operation,
            "method": method.upper(),
            "path": path,
            "payload": payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _receivables_operation_identity(
    operation: str,
    path: str,
    payload: Optional[Dict[str, Any]],
    fingerprint: str,
) -> str:
    """Return the stable business identity used to reconcile retries.

    Receipt references stay case-sensitive because ACH and Square identifiers
    may be case-sensitive. Mutable form fields, including the received date,
    are deliberately excluded: changing them after an ambiguous response must
    not mint a second Atlas payment for the same referenced receipt.
    """
    if operation == "RECEIVABLES_PAYMENT_CREATE" and payload:
        identity: Dict[str, Any] = {
            "operation": operation,
            "contact_id": str(payload.get("contact_id", "")),
            "payment_method": str(payload.get("payment_method", "")).strip().lower(),
            "reference": str(payload.get("reference", "")).strip(),
        }
    elif operation == "RECEIVABLES_DEPOSIT_CREATE" and payload:
        identity = {
            "operation": operation,
            "payment_ids": sorted(str(item) for item in payload.get("payment_ids", [])),
        }
    else:
        # Resource actions and allocation replacements remain independently
        # repeatable when their full request changes.
        identity = {"operation": operation, "path": path, "request": fingerprint}
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reserve_receivables_operation(
    *,
    operation_identity: str,
    fingerprint: str,
    operation: str,
    candidate_key: str,
    actor: str,
) -> Dict[str, Any]:
    """Atomically create or recover the business-scoped retry identity."""
    try:
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # A receipt identity can have multiple historical generations
                # after explicit voids. Serialize the active-generation check
                # and insert so only one corrected request can replace a void.
                cur.execute(
                    """
                    SELECT pg_advisory_xact_lock(hashtext(%s))
                    """,
                    (operation_identity,),
                )

                cur.execute(
                    """
                    SELECT attempt_id, operation_identity, request_fingerprint,
                           operation, idempotency_key, state, response_body
                    FROM receivables_operation_attempts
                    WHERE operation_identity = %s
                      AND state IN ('pending', 'resolved')
                    ORDER BY attempt_id DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (operation_identity,),
                )
                active = cur.fetchone()
                if active:
                    cur.execute(
                        """
                        UPDATE receivables_operation_attempts
                        SET last_attempt_by = %s, updated_at = NOW()
                        WHERE attempt_id = %s
                        """,
                        (actor, active["attempt_id"]),
                    )
                    result = dict(active)
                    if result["request_fingerprint"] != fingerprint:
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                "This receipt or deposit is already reserved with "
                                "different details; reconcile the existing operation first"
                            ),
                        )
                    return result

                cur.execute(
                    """
                    SELECT 1
                    FROM receivables_operation_attempts
                    WHERE operation_identity = %s
                      AND state = 'voided'
                      AND request_fingerprint = %s
                    LIMIT 1
                    """,
                    (operation_identity, fingerprint),
                )
                if cur.fetchone():
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "This exact receipt entry was voided and cannot be replayed; "
                            "correct its details or add a correction note before re-entry"
                        ),
                    )

                cur.execute(
                    """
                    INSERT INTO receivables_operation_attempts (
                        operation_identity, request_fingerprint, operation,
                        idempotency_key, created_by, last_attempt_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING attempt_id, operation_identity, request_fingerprint,
                              operation, idempotency_key, state, response_body
                    """,
                    (
                        operation_identity,
                        fingerprint,
                        operation,
                        candidate_key,
                        actor,
                        actor,
                    ),
                )
                row = cur.fetchone()
                if not row:
                    raise RuntimeError("Operation reservation returned no row")
                return dict(row)
    except psycopg2.errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=409,
            detail="Idempotency key already belongs to a different operation",
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Could not persist receivables operation identity")
        raise HTTPException(
            status_code=503,
            detail=(
                "Safe payment retry tracking is unavailable; Atlas was not called"
            ),
            headers={"Retry-After": "5"},
        ) from exc


def _resolve_receivables_operation(attempt_id: int, response_body: Any) -> None:
    """Persist a confirmed Atlas response without invalidating that response."""
    try:
        db.execute(
            """
            UPDATE receivables_operation_attempts
            SET state = 'resolved', response_body = %s::jsonb,
                last_error = NULL, updated_at = NOW()
            WHERE attempt_id = %s
            """,
            (json.dumps(response_body), attempt_id),
        )
    except Exception:
        # The pending row and its Atlas key remain durable. A later retry will
        # safely replay against Atlas and can repair the cached response.
        logger.exception("Could not cache confirmed Atlas receivables response")


def _note_receivables_operation_error(attempt_id: int, reason: str) -> None:
    try:
        db.execute(
            """
            UPDATE receivables_operation_attempts
            SET last_error = %s, updated_at = NOW()
            WHERE attempt_id = %s
            """,
            (reason[:1000], attempt_id),
        )
    except Exception:
        logger.exception("Could not update pending receivables operation")


def _release_rejected_receivables_operation(attempt_id: int) -> None:
    """Release a definitively rejected request so corrected details may retry."""
    try:
        db.execute(
            """
            DELETE FROM receivables_operation_attempts
            WHERE attempt_id = %s AND state = 'pending'
            """,
            (attempt_id,),
        )
    except Exception:
        # Retaining the reservation fails safe: it blocks changed details rather
        # than risking a duplicate financial operation.
        logger.exception("Could not release rejected receivables operation")


def _mark_payment_create_voided(payment_id: UUID, response_body: Any) -> None:
    """Retire only the create generation Atlas confirms was voided."""
    if not isinstance(response_body, dict):
        raise HTTPException(
            status_code=502,
            detail="Atlas returned an invalid voided payment response",
        )
    if str(response_body.get("id", "")) != str(payment_id):
        raise HTTPException(
            status_code=502,
            detail="Atlas returned the wrong payment after voiding",
        )
    if str(response_body.get("status", "")).lower() != "voided":
        raise HTTPException(
            status_code=502,
            detail="Atlas did not confirm the payment was voided",
        )

    source = str(response_body.get("source", ""))
    if source and source != "eom_admin":
        # Payments created outside this proxy have no local create generation.
        return
    atlas_create_key = str(response_body.get("idempotency_key", "")).strip()
    contact_id = str(response_body.get("contact_id", "")).strip()
    payment_method = str(response_body.get("payment_method", "")).strip()
    reference = str(response_body.get("reference", "")).strip()
    if not all((atlas_create_key, contact_id, payment_method, reference)):
        raise HTTPException(
            status_code=502,
            detail="Atlas void response cannot be reconciled to the original receipt",
        )

    operation_identity = _receivables_operation_identity(
        "RECEIVABLES_PAYMENT_CREATE",
        "/receivables/payments",
        {
            "contact_id": contact_id,
            "payment_method": payment_method,
            "reference": reference,
        },
        "",
    )
    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (operation_identity,),
                )
                cur.execute(
                    """
                    UPDATE receivables_operation_attempts
                    SET state = 'voided', response_body = %s::jsonb,
                        last_error = NULL, updated_at = NOW()
                    WHERE operation_identity = %s
                      AND operation = 'RECEIVABLES_PAYMENT_CREATE'
                      AND idempotency_key = %s
                      AND state IN ('pending', 'resolved')
                    """,
                    (
                        json.dumps(response_body),
                        operation_identity,
                        atlas_create_key,
                    ),
                )
                if cur.rowcount == 0:
                    cur.execute(
                        """
                        SELECT state, operation_identity
                        FROM receivables_operation_attempts
                        WHERE operation = 'RECEIVABLES_PAYMENT_CREATE'
                          AND idempotency_key = %s
                        """,
                        (atlas_create_key,),
                    )
                    existing = cur.fetchone()
                    if existing and existing[0] in {"pending", "resolved"}:
                        raise RuntimeError(
                            "Atlas payment identity did not match its local create attempt"
                        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Could not retire voided payment create identity")
        raise HTTPException(
            status_code=503,
            detail=(
                "Payment was voided, but correction tracking is unavailable; "
                "retry the void before re-entering it"
            ),
            headers={"Retry-After": "5"},
        ) from exc


def _atlas_receivables_mutation(
    request: Request,
    audit_action: str,
    success_reason: str,
    method: str,
    path: str,
    admin: Dict[str, Any],
    *,
    payload: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
    after_atlas_success: Optional[Callable[[Any], None]] = None,
) -> Any:
    """Proxy one financial mutation and record its actual upstream outcome."""
    def audit_best_effort(allowed: bool, reason: str) -> None:
        try:
            append_access_log(request, audit_action, allowed, reason)
        except Exception:
            # Atlas is authoritative for the financial result. A local audit-file
            # failure must never replace an upstream success or rejection.
            logger.exception(
                "Could not append receivables audit action=%s allowed=%s",
                audit_action,
                allowed,
            )

    if not idempotency_key:
        raise HTTPException(status_code=422, detail="Idempotency key is required")
    payload = _canonicalize_receivables_payload(audit_action, payload)
    fingerprint = _receivables_operation_fingerprint(
        audit_action, method, path, payload
    )
    operation_identity = _receivables_operation_identity(
        audit_action, path, payload, fingerprint
    )
    try:
        attempt = _reserve_receivables_operation(
            operation_identity=operation_identity,
            fingerprint=fingerprint,
            operation=audit_action,
            candidate_key=idempotency_key,
            actor=str(admin["name"]),
        )
    except HTTPException as exc:
        audit_best_effort(False, str(exc.detail))
        raise

    try:
        result = _atlas_receivables_request(
            method,
            path,
            admin,
            payload=payload,
            idempotency_key=str(attempt["idempotency_key"]),
        )
    except HTTPException as exc:
        reason = exc.detail if isinstance(exc.detail, str) else "Atlas rejected request"
        _note_receivables_operation_error(
            int(attempt["attempt_id"]),
            f"Atlas request failed ({exc.status_code}): {reason}",
        )
        if exc.status_code < 500:
            _release_rejected_receivables_operation(int(attempt["attempt_id"]))
        audit_best_effort(
            False, f"Atlas request failed ({exc.status_code}): {reason}"
        )
        raise

    if audit_action == "RECEIVABLES_PAYMENT_CREATE" and isinstance(result, dict):
        payment_status = str(result.get("status", "")).lower()
        if payment_status == "voided":
            try:
                _mark_payment_create_voided(UUID(str(result.get("id", ""))), result)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=502,
                    detail="Atlas returned an invalid voided payment response",
                ) from exc
            detail = (
                "The original receipt was voided and cannot be replayed; "
                "enter corrected details with a new attempt"
            )
            audit_best_effort(False, detail)
            raise HTTPException(status_code=409, detail=detail)
        if payment_status == "returned":
            _resolve_receivables_operation(int(attempt["attempt_id"]), result)
            detail = "The original receipt was returned and cannot be recorded again"
            audit_best_effort(False, detail)
            raise HTTPException(status_code=409, detail=detail)

    if after_atlas_success:
        try:
            after_atlas_success(result)
        except HTTPException as exc:
            reason = exc.detail if isinstance(exc.detail, str) else "Local reconciliation failed"
            _note_receivables_operation_error(
                int(attempt["attempt_id"]),
                f"Atlas accepted the request but local reconciliation failed: {reason}",
            )
            audit_best_effort(False, str(reason))
            raise

    _resolve_receivables_operation(int(attempt["attempt_id"]), result)
    audit_best_effort(True, success_reason)
    return result


@app.middleware("http")
async def private_network_access_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        if response.headers.get("access-control-allow-origin"):
            response.headers["Access-Control-Allow-Private-Network"] = "true"
        else:
            # Newer Starlette versions add this header before determining that
            # the request origin is forbidden. Do not advertise private-network
            # access unless the same response also authorizes the origin.
            if "access-control-allow-private-network" in response.headers:
                del response.headers["access-control-allow-private-network"]
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        detail = str(exc.detail.get("message") or exc.detail.get("error") or "Request failed")
        content: Dict[str, Any] = {"success": False, "error": detail}
        if exc.detail.get("code"):
            content["code"] = exc.detail["code"]
        if isinstance(exc.detail.get("details"), dict):
            content["details"] = exc.detail["details"]
    else:
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        content = {"success": False, "error": detail}
    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    first_error = errors[0] if errors else {}
    message = first_error.get("msg", "Invalid request payload")
    field_errors: Dict[str, str] = {}
    for error in errors:
        location = [str(part) for part in error.get("loc", ()) if part != "body"]
        error_message = str(error.get("msg", "Invalid value"))
        if "lat and lng must be provided together" in error_message:
            prefix = ".".join(location)
            field_prefix = f"{prefix}." if prefix else ""
            field_errors.setdefault(f"{field_prefix}lat", "coordinate pair required")
            field_errors.setdefault(f"{field_prefix}lng", "coordinate pair required")
            continue
        field = ".".join(location) or "body"
        field_errors.setdefault(field, error_message)
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": message,
            "code": "validation_error",
            "details": {"fields": field_errors},
        },
    )


def normalize_site_address(address: str) -> str:
    """Return the durable identity key without erasing suite/unit identity."""
    normalized = re.sub(r"\s+", " ", address.strip())
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    return normalized.casefold()


CUSTOMER_SITE_MUTATION_LOCK = "eom_customer_site_mutations_v1"


def _lock_customer_site_mutations(cur: Any) -> None:
    """Serialize the small admin mutation surface before taking row locks."""
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))",
        (CUSTOMER_SITE_MUTATION_LOCK,),
    )


def _ensure_customer_site_schema() -> None:
    """Install and backfill the Customer/Site model in one transaction."""
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("eom_customer_site_schema_v1",))
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS customers (
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
                )
                """
            )
            cur.execute(
                """
                ALTER TABLE customers ALTER COLUMN name TYPE TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS customer_id INTEGER REFERENCES customers(id);
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS address_key TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS service_scope TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS access_instructions TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS service_preferences TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS pet_notes TEXT;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS service_start_date DATE;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
                ALTER TABLE locations ADD COLUMN IF NOT EXISTS archived_by INTEGER REFERENCES employees(id) ON DELETE SET NULL;
                """
            )

            cur.execute(
                """
                SELECT id, customer_id, customer_name, address, address_key
                FROM locations
                ORDER BY id
                FOR UPDATE
                """
            )
            sites = [dict(row) for row in cur.fetchall()]
            for site in sites:
                if site.get("customer_id") is not None:
                    continue
                customer_name = str(site.get("customer_name") or "").strip()
                if not customer_name:
                    continue
                cur.execute(
                    "INSERT INTO customers (name) VALUES (%s) RETURNING id",
                    (customer_name,),
                )
                customer_id = int(cur.fetchone()["id"])
                cur.execute(
                    """
                    UPDATE locations
                    SET customer_id = %s, customer_name = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (customer_id, customer_name, site["id"]),
                )

            keys_by_site = {
                int(site["id"]): normalize_site_address(str(site["address"]))
                for site in sites
            }
            key_counts: Dict[str, int] = {}
            for key in keys_by_site.values():
                key_counts[key] = key_counts.get(key, 0) + 1

            desired_keys = {
                site_id: key if key_counts[key] == 1 else None
                for site_id, key in keys_by_site.items()
            }
            current_keys = {
                int(site["id"]): site.get("address_key") for site in sites
            }
            changed_site_ids = [
                site_id
                for site_id, desired_key in desired_keys.items()
                if current_keys.get(site_id) != desired_key
            ]
            # Clear only changing rows first so key swaps/collisions remain safe
            # under an already-installed unique index without rewriting every
            # healthy Site on every process restart.
            if changed_site_ids:
                cur.execute(
                    "UPDATE locations SET address_key = NULL WHERE id = ANY(%s)",
                    (changed_site_ids,),
                )
            for site_id in changed_site_ids:
                key = desired_keys[site_id]
                if key is not None:
                    cur.execute(
                        "UPDATE locations SET address_key = %s WHERE id = %s",
                        (key, site_id),
                    )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_customers_active ON customers(active);
                CREATE INDEX IF NOT EXISTS idx_locations_customer_id ON locations(customer_id);
                CREATE UNIQUE INDEX IF NOT EXISTS uq_locations_address_key
                    ON locations(address_key) WHERE address_key IS NOT NULL;
                """
            )


def _ensure_weekly_schedule_site_schema() -> None:
    """Add Site identity while retaining the legacy arbiter for rollout safety."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id              SERIAL PRIMARY KEY,
            employee_id     INTEGER NOT NULL REFERENCES employees(id),
            location_id     INTEGER REFERENCES locations(id),
            customer_name   TEXT NOT NULL,
            week_start      DATE NOT NULL,
            scheduled_hours NUMERIC(6, 2) NOT NULL,
            notes           TEXT NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    db.execute(
        "ALTER TABLE schedules ADD COLUMN IF NOT EXISTS "
        "location_id INTEGER REFERENCES locations(id)"
    )
    # Do not remove origin/main's name-based UNIQUE constraint in the same
    # rolling deployment that stops using it as an ON CONFLICT arbiter. A
    # follow-up deployment can remove it after every serving instance runs the
    # Site-aware write path below.
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_schedules_site_week
        ON schedules(employee_id, location_id, week_start)
    """)


def _ensure_schema_migrations() -> None:
    """Idempotent schema additions for existing deployments."""
    _ensure_customer_site_schema()
    db.execute("""
        CREATE TABLE IF NOT EXISTS receivables_operation_attempts (
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
        )
    """)
    db.execute("""
        ALTER TABLE receivables_operation_attempts
            ADD COLUMN IF NOT EXISTS attempt_id BIGSERIAL;
        ALTER TABLE receivables_operation_attempts
            ALTER COLUMN attempt_id SET NOT NULL;

        DO $$
        DECLARE
            primary_name TEXT;
            primary_definition TEXT;
        BEGIN
            SELECT conname, pg_get_constraintdef(oid)
            INTO primary_name, primary_definition
            FROM pg_constraint
            WHERE conrelid = 'receivables_operation_attempts'::regclass
              AND contype = 'p'
            LIMIT 1;

            IF primary_name IS NOT NULL
               AND primary_definition NOT LIKE '%%attempt_id%%' THEN
                EXECUTE format(
                    'ALTER TABLE receivables_operation_attempts DROP CONSTRAINT %%I',
                    primary_name
                );
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'receivables_operation_attempts'::regclass
                  AND contype = 'p'
            ) THEN
                ALTER TABLE receivables_operation_attempts
                    ADD CONSTRAINT receivables_operation_attempts_pkey
                    PRIMARY KEY (attempt_id);
            END IF;
        END $$;

        DO $$
        DECLARE
            state_constraint TEXT;
            state_definition TEXT;
        BEGIN
            SELECT conname, pg_get_constraintdef(oid)
            INTO state_constraint, state_definition
            FROM pg_constraint
            WHERE conrelid = 'receivables_operation_attempts'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%%state%%'
            LIMIT 1;

            IF state_constraint IS NOT NULL
               AND state_definition NOT LIKE '%%voided%%' THEN
                EXECUTE format(
                    'ALTER TABLE receivables_operation_attempts DROP CONSTRAINT %%I',
                    state_constraint
                );
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'receivables_operation_attempts'::regclass
                  AND contype = 'c'
                  AND pg_get_constraintdef(oid) LIKE '%%voided%%'
            ) THEN
                ALTER TABLE receivables_operation_attempts
                    ADD CONSTRAINT receivables_operation_attempts_state_check
                    CHECK (state IN ('pending', 'resolved', 'voided'));
            END IF;
        END $$;

        CREATE UNIQUE INDEX IF NOT EXISTS
            uq_receivables_operation_attempts_active_identity
        ON receivables_operation_attempts(operation_identity)
        WHERE state IN ('pending', 'resolved');
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_receivables_operation_attempts_state
        ON receivables_operation_attempts(state, updated_at)
    """)
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS expected_hours NUMERIC(6,2)"
    )
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS check_in_token_nonce VARCHAR(64)"
    )
    db.execute(
        "ALTER TABLE locations ADD COLUMN IF NOT EXISTS check_in_token_rotated_at TIMESTAMPTZ"
    )
    db.execute("""
        CREATE TABLE IF NOT EXISTS site_check_in_schedules (
            id              BIGSERIAL PRIMARY KEY,
            employee_id     INTEGER NOT NULL REFERENCES employees(id),
            location_id     INTEGER NOT NULL REFERENCES locations(id),
            scheduled_start TIMESTAMPTZ NOT NULL,
            grace_minutes   INTEGER NOT NULL DEFAULT 10
                                CHECK (grace_minutes BETWEEN 0 AND 120),
            created_by      INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (employee_id, location_id, scheduled_start)
        )
    """)
    db.execute("""
        ALTER TABLE site_check_in_schedules
            ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
        ALTER TABLE site_check_in_schedules
            ADD COLUMN IF NOT EXISTS cancelled_by INTEGER REFERENCES employees(id) ON DELETE SET NULL;
        ALTER TABLE site_check_in_schedules
            ADD COLUMN IF NOT EXISTS cancellation_reason TEXT;
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS site_check_in_schedule_rules (
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
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS site_check_ins (
            id                        BIGSERIAL PRIMARY KEY,
            employee_id               INTEGER NOT NULL REFERENCES employees(id),
            location_id               INTEGER NOT NULL REFERENCES locations(id),
            server_checked_in_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            device_scanned_at         TIMESTAMPTZ NOT NULL,
            latitude                  NUMERIC(10, 7) NOT NULL,
            longitude                 NUMERIC(10, 7) NOT NULL,
            accuracy_m                NUMERIC(10, 2) NOT NULL,
            geofence_radius_m         INTEGER NOT NULL,
            distance_m                NUMERIC(10, 2),
            geofence_status           VARCHAR(32) NOT NULL
                                          CHECK (geofence_status IN
                                            ('inside', 'outside', 'uncertain', 'low_accuracy', 'site_unpinned')),
            classification            VARCHAR(24) NOT NULL
                                          CHECK (classification IN ('on_time', 'late', 'needs_review')),
            classification_reason     VARCHAR(64) NOT NULL,
            schedule_id               BIGINT REFERENCES site_check_in_schedules(id) ON DELETE SET NULL,
            schedule_rule_id          BIGINT REFERENCES site_check_in_schedule_rules(id) ON DELETE SET NULL,
            scheduled_start           TIMESTAMPTZ,
            grace_minutes             INTEGER,
            device_clock_skew_seconds NUMERIC(12, 2) NOT NULL,
            review_status             VARCHAR(24) NOT NULL
                                          CHECK (review_status IN
                                            ('not_required', 'pending', 'approved', 'rejected')),
            reviewed_by               INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            reviewed_at               TIMESTAMPTZ,
            review_note               TEXT NOT NULL DEFAULT '',
            created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (employee_id, location_id, device_scanned_at)
        )
    """)
    db.execute("""
        ALTER TABLE site_check_ins
        ADD COLUMN IF NOT EXISTS schedule_rule_id
            BIGINT REFERENCES site_check_in_schedule_rules(id) ON DELETE SET NULL
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_in_schedules_lookup
        ON site_check_in_schedules(employee_id, location_id, scheduled_start)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_in_schedule_rules_lookup
        ON site_check_in_schedule_rules(
            employee_id, location_id, active, starts_on, ends_on
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_ins_employee_time
        ON site_check_ins(employee_id, server_checked_in_at DESC)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_ins_review
        ON site_check_ins(review_status, server_checked_in_at DESC)
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS site_check_in_reconciliation_reviews (
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
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_in_reconciliation_reviews_lookup
        ON site_check_in_reconciliation_reviews(
            occurrence_key, evidence_fingerprint, reviewed_at DESC
        )
    """)
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
    _ensure_weekly_schedule_site_schema()
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
    db.execute("""
        CREATE TABLE IF NOT EXISTS time_data_correction_batches (
            id                     BIGSERIAL PRIMARY KEY,
            plan_token             TEXT NOT NULL UNIQUE,
            applied_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            applied_by_name        TEXT NOT NULL,
            reason                 TEXT NOT NULL,
            snapshot               JSONB NOT NULL,
            result                 JSONB NOT NULL,
            created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_time_data_correction_batches_created "
        "ON time_data_correction_batches(created_at)"
    )

    # Seed threshold defaults if not already in settings
    for key, default_val in _SETTINGS_DEFAULTS.items():
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (%s, %s::jsonb)
            ON CONFLICT (key) DO NOTHING
            """,
            (key, json.dumps(default_val)),
        )


def _auto_migrate_if_empty() -> bool:
    """Run JSON->PostgreSQL migration if the employees table is empty."""
    result = db.query_one("SELECT COUNT(*) AS n FROM employees")
    if result and result["n"] > 0:
        return False
    if not EMPLOYEES_FILE.exists() or not TIMESHEETS_FILE.exists():
        return False
    migrate_script = BACKEND_DIR / "migrate_json_to_pg.py"
    if not migrate_script.exists():
        return False
    database_url = os.getenv("DATABASE_URL", "")
    completed = subprocess.run(
        [sys.executable, str(migrate_script), "--db-url", database_url],
        capture_output=True, text=True, cwd=str(BASE_DIR),
    )
    if completed.returncode != 0:
        print(f"[auto-migrate] ERROR:\n{completed.stderr}", flush=True)
        return False
    else:
        print(f"[auto-migrate] Done:\n{completed.stdout}", flush=True)
        return True


@app.on_event("startup")
def startup_event() -> None:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL env var not set")
    db.init_pool(database_url)
    _ensure_schema_migrations()
    imported_legacy_json = _auto_migrate_if_empty()
    # A first-run JSON import happens after the schema upgrade and can insert
    # legacy Sites. Re-run the idempotent Customer/address backfill immediately.
    if imported_legacy_json:
        _ensure_customer_site_schema()
    apply_bootstrap_admins()


def _site_check_in_url(request: Request, token: str) -> str:
    app_url = PUBLIC_APP_URL or str(request.base_url).rstrip("/")
    return f"{app_url}/?checkIn={token}"


def _resolve_site_check_in_qr(
    token: str,
    *,
    cur: Optional[Any] = None,
    for_update: bool = False,
) -> Dict[str, Any]:
    try:
        site_id, nonce = parse_site_check_in_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    query = """
        SELECT id, address, customer_name, lat, lng, check_in_token_nonce,
               check_in_token_rotated_at
        FROM locations
        WHERE id = %s AND active = true
        """ + (" FOR UPDATE" if for_update else "")
    if cur is None:
        site = db.query_one(query, (site_id,))
    else:
        cur.execute(query, (site_id,))
        row = cur.fetchone()
        site = dict(row) if row else None
    configured_nonce = str(site.get("check_in_token_nonce") or "") if site else ""
    if not site or not configured_nonce or not hmac.compare_digest(configured_nonce, nonce):
        raise HTTPException(status_code=404, detail="Invalid or expired site QR code")
    return site


def _site_check_in_schedule_row(schedule_id: int) -> Optional[Dict[str, Any]]:
    return db.query_one(
        """
        SELECT sc.id, sc.employee_id, e.name AS employee_name,
               sc.location_id, l.address AS site_name,
               sc.scheduled_start, sc.grace_minutes, sc.created_at,
               sc.cancelled_at, sc.cancelled_by, sc.cancellation_reason
        FROM site_check_in_schedules sc
        JOIN employees e ON e.id = sc.employee_id
        JOIN locations l ON l.id = sc.location_id
        WHERE sc.id = %s
        """,
        (schedule_id,),
    )


def _serialize_site_check_in_schedule(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "employeeId": int(row["employee_id"]),
        "employeeName": str(row.get("employee_name") or ""),
        "siteId": int(row["location_id"]),
        "siteName": str(row.get("site_name") or ""),
        "scheduledStart": to_utc_iso(row["scheduled_start"]),
        "graceMinutes": int(row["grace_minutes"]),
        "cancelledAt": (
            to_utc_iso(row["cancelled_at"])
            if row.get("cancelled_at")
            else None
        ),
        "cancelledBy": (
            int(row["cancelled_by"])
            if row.get("cancelled_by") is not None
            else None
        ),
        "cancellationReason": row.get("cancellation_reason"),
        "createdAt": to_utc_iso(row["created_at"]),
    }


def _site_check_in_schedule_rule_row(rule_id: int) -> Optional[Dict[str, Any]]:
    return db.query_one(
        """
        SELECT sr.id, sr.employee_id, e.name AS employee_name,
               sr.location_id, l.address AS site_name, sr.weekdays,
               sr.local_start_time, sr.timezone, sr.starts_on,
               NULLIF(sr.ends_on, 'infinity'::date) AS ends_on,
               sr.grace_minutes, sr.active, sr.created_at, sr.updated_at
        FROM site_check_in_schedule_rules sr
        JOIN employees e ON e.id = sr.employee_id
        JOIN locations l ON l.id = sr.location_id
        WHERE sr.id = %s
        """,
        (rule_id,),
    )


def _serialize_site_check_in_schedule_rule(row: Dict[str, Any]) -> Dict[str, Any]:
    ends_on = row.get("ends_on")
    return {
        "id": int(row["id"]),
        "employeeId": int(row["employee_id"]),
        "employeeName": str(row.get("employee_name") or ""),
        "siteId": int(row["location_id"]),
        "siteName": str(row.get("site_name") or ""),
        "weekdays": [int(day) for day in row["weekdays"]],
        "localStart": row["local_start_time"].strftime("%H:%M"),
        "timezone": str(row["timezone"]),
        "startsOn": row["starts_on"].isoformat(),
        "endsOn": ends_on.isoformat() if ends_on is not None else None,
        "graceMinutes": int(row["grace_minutes"]),
        "active": bool(row["active"]),
        "createdAt": to_utc_iso(row["created_at"]),
        "updatedAt": to_utc_iso(row["updated_at"]),
    }


def _site_check_in_row(check_in_id: int) -> Optional[Dict[str, Any]]:
    return db.query_one(
        """
        SELECT ci.*, e.name AS employee_name, l.address AS site_name,
               reviewer.name AS reviewed_by_name
        FROM site_check_ins ci
        JOIN employees e ON e.id = ci.employee_id
        JOIN locations l ON l.id = ci.location_id
        LEFT JOIN employees reviewer ON reviewer.id = ci.reviewed_by
        WHERE ci.id = %s
        """,
        (check_in_id,),
    )


def _serialize_site_check_in(row: Dict[str, Any]) -> Dict[str, Any]:
    distance = row.get("distance_m")
    scheduled_start = row.get("scheduled_start")
    reviewed_at = row.get("reviewed_at")
    return {
        "id": int(row["id"]),
        "employeeId": int(row["employee_id"]),
        "employeeName": str(row.get("employee_name") or ""),
        "siteId": int(row["location_id"]),
        "siteName": str(row.get("site_name") or ""),
        "serverCheckedInAt": to_utc_iso(row["server_checked_in_at"]),
        "deviceScannedAt": to_utc_iso(row["device_scanned_at"]),
        "latitude": float(row["latitude"]),
        "longitude": float(row["longitude"]),
        "accuracyM": float(row["accuracy_m"]),
        "geofenceRadiusM": int(row["geofence_radius_m"]),
        "distanceM": float(distance) if distance is not None else None,
        "geofenceStatus": str(row["geofence_status"]),
        "classification": str(row["classification"]),
        "classificationReason": str(row["classification_reason"]),
        "scheduleId": int(row["schedule_id"]) if row.get("schedule_id") else None,
        "scheduleRuleId": int(row["schedule_rule_id"]) if row.get("schedule_rule_id") else None,
        "scheduledStart": to_utc_iso(scheduled_start) if scheduled_start else None,
        "graceMinutes": int(row["grace_minutes"]) if row.get("grace_minutes") is not None else None,
        "deviceClockSkewSeconds": float(row["device_clock_skew_seconds"]),
        "reviewStatus": str(row["review_status"]),
        "reviewedBy": str(row.get("reviewed_by_name") or ""),
        "reviewedAt": to_utc_iso(reviewed_at) if reviewed_at else None,
        "reviewNote": str(row.get("review_note") or ""),
    }


def _site_check_in_reconciliation_window(
    from_date: date,
    to_date: date,
) -> Tuple[datetime, datetime]:
    start_local = datetime.combine(from_date, clock_time.min, tzinfo=APP_TIMEZONE)
    end_local = datetime.combine(
        to_date + timedelta(days=1),
        clock_time.min,
        tzinfo=APP_TIMEZONE,
    )
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _site_check_in_reconciliation_occurrences(
    from_date: date,
    to_date: date,
    employee_id: Optional[int],
    site_id: Optional[int],
) -> List[Dict[str, Any]]:
    start_utc, end_utc = _site_check_in_reconciliation_window(from_date, to_date)
    override_window = timedelta(hours=SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS)
    exact_clauses = [
        "sc.cancelled_at IS NULL",
        "sc.scheduled_start >= %s",
        "sc.scheduled_start < %s",
    ]
    exact_params: List[Any] = [start_utc - override_window, end_utc + override_window]
    if employee_id is not None:
        exact_clauses.append("sc.employee_id = %s")
        exact_params.append(employee_id)
    if site_id is not None:
        exact_clauses.append("sc.location_id = %s")
        exact_params.append(site_id)
    exact_rows = db.query_all(
        f"""
        SELECT sc.id, sc.employee_id, e.name AS employee_name,
               sc.location_id, l.address AS site_name,
               sc.scheduled_start, sc.grace_minutes
        FROM site_check_in_schedules sc
        JOIN employees e ON e.id = sc.employee_id
        JOIN locations l ON l.id = sc.location_id
        WHERE {' AND '.join(exact_clauses)}
        ORDER BY sc.scheduled_start, sc.id
        """,
        tuple(exact_params),
    )

    occurrences: List[Dict[str, Any]] = []
    exact_starts: Dict[Tuple[int, int], List[datetime]] = {}
    for row in exact_rows:
        scheduled_start = row["scheduled_start"]
        pair = (int(row["employee_id"]), int(row["location_id"]))
        exact_starts.setdefault(pair, []).append(scheduled_start)
        if not start_utc <= scheduled_start < end_utc:
            continue
        occurrences.append(
            {
                "key": f"exact:{int(row['id'])}",
                "employee_id": pair[0],
                "employee_name": str(row.get("employee_name") or ""),
                "location_id": pair[1],
                "site_name": str(row.get("site_name") or ""),
                "scheduled_start": scheduled_start,
                "grace_minutes": int(row["grace_minutes"]),
                "schedule_id": int(row["id"]),
                "schedule_rule_id": None,
                "schedule_source": "exact",
            }
        )

    rule_clauses = [
        "sr.starts_on <= %s",
        "sr.ends_on >= %s",
        "(sr.active = true OR sr.updated_at >= %s)",
    ]
    rule_params: List[Any] = [to_date, from_date, start_utc]
    if employee_id is not None:
        rule_clauses.append("sr.employee_id = %s")
        rule_params.append(employee_id)
    if site_id is not None:
        rule_clauses.append("sr.location_id = %s")
        rule_params.append(site_id)
    rule_rows = db.query_all(
        f"""
        SELECT sr.id, sr.employee_id, e.name AS employee_name,
               sr.location_id, l.address AS site_name, sr.weekdays,
               sr.local_start_time, sr.timezone, sr.starts_on,
               NULLIF(sr.ends_on, 'infinity'::date) AS ends_on,
               sr.grace_minutes, sr.active, sr.updated_at
        FROM site_check_in_schedule_rules sr
        JOIN employees e ON e.id = sr.employee_id
        JOIN locations l ON l.id = sr.location_id
        WHERE {' AND '.join(rule_clauses)}
        ORDER BY sr.id
        """,
        tuple(rule_params),
    )

    recurring_keys: set[Tuple[int, int, datetime]] = set()
    override_window_seconds = SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS * 3600
    for row in rule_rows:
        try:
            rule_zone = ZoneInfo(str(row["timezone"]))
        except (KeyError, ValueError):
            logger.warning(
                "Ignoring site check-in rule %s with invalid timezone",
                row.get("id"),
            )
            continue
        employee_key = int(row["employee_id"])
        site_key = int(row["location_id"])
        pair = (employee_key, site_key)
        weekdays = {int(day) for day in row["weekdays"]}
        local_day = start_utc.astimezone(rule_zone).date() - timedelta(days=1)
        final_local_day = end_utc.astimezone(rule_zone).date() + timedelta(days=1)
        rule_end = row.get("ends_on") or date.max
        while local_day <= final_local_day:
            if (
                local_day.weekday() in weekdays
                and row["starts_on"] <= local_day <= rule_end
            ):
                local_start = datetime.combine(
                    local_day,
                    row["local_start_time"],
                    tzinfo=rule_zone,
                )
                scheduled_start = local_start.astimezone(timezone.utc)
                exact_override = any(
                    abs((exact_start - scheduled_start).total_seconds())
                    <= override_window_seconds
                    for exact_start in exact_starts.get(pair, [])
                )
                recurring_key = (employee_key, site_key, scheduled_start)
                active_at_occurrence = bool(row["active"]) or (
                    scheduled_start <= row["updated_at"]
                )
                if (
                    start_utc <= scheduled_start < end_utc
                    and not exact_override
                    and active_at_occurrence
                    and recurring_key not in recurring_keys
                ):
                    recurring_keys.add(recurring_key)
                    occurrences.append(
                        {
                            "key": f"rule:{int(row['id'])}:{local_day.isoformat()}",
                            "employee_id": employee_key,
                            "employee_name": str(row.get("employee_name") or ""),
                            "location_id": site_key,
                            "site_name": str(row.get("site_name") or ""),
                            "scheduled_start": scheduled_start,
                            "grace_minutes": int(row["grace_minutes"]),
                            "schedule_id": None,
                            "schedule_rule_id": int(row["id"]),
                            "schedule_source": "weekly_rule",
                        }
                    )
            local_day += timedelta(days=1)

    return sorted(
        occurrences,
        key=lambda row: (
            row["scheduled_start"],
            row["employee_name"],
            row["location_id"],
        ),
    )


def _site_check_in_reconciliation_check_ins(
    occurrences: List[Dict[str, Any]],
    start_utc: datetime,
    end_utc: datetime,
) -> List[Dict[str, Any]]:
    if not occurrences:
        return []
    employee_ids = sorted({row["employee_id"] for row in occurrences})
    site_ids = sorted({row["location_id"] for row in occurrences})
    window = timedelta(hours=SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS)
    return db.query_all(
        """
        SELECT ci.*, e.name AS employee_name, l.address AS site_name,
               reviewer.name AS reviewed_by_name
        FROM site_check_ins ci
        JOIN employees e ON e.id = ci.employee_id
        JOIN locations l ON l.id = ci.location_id
        LEFT JOIN employees reviewer ON reviewer.id = ci.reviewed_by
        WHERE ci.employee_id = ANY(%s)
          AND ci.location_id = ANY(%s)
          AND ci.server_checked_in_at >= %s
          AND ci.server_checked_in_at < %s
        ORDER BY ci.server_checked_in_at, ci.id
        """,
        (employee_ids, site_ids, start_utc - window, end_utc + window),
    )


def _site_check_in_reconciliation_timecard_events(
    occurrences: List[Dict[str, Any]],
    start_utc: datetime,
    end_utc: datetime,
) -> List[Dict[str, Any]]:
    if not occurrences:
        return []
    employee_ids = sorted({row["employee_id"] for row in occurrences})
    window = timedelta(hours=SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS)
    return db.query_all(
        """
        SELECT 'clock_in'::text AS event_type, s.id AS shift_id,
               NULL::integer AS visit_id, s.employee_id,
               CASE
                   WHEN l.id IS NOT NULL AND s.location_label = l.address THEN l.id
                   ELSE NULL
               END AS location_id,
               CASE
                   WHEN l.id IS NOT NULL AND s.location_label = l.address THEN l.address
                   ELSE NULL
               END AS site_name,
               s.location_label, s.clock_in AS event_at,
               s.clock_in AS shift_clock_in, s.clock_out AS shift_clock_out
        FROM shifts s
        LEFT JOIN locations l ON l.id = s.location_id
        WHERE s.employee_id = ANY(%s)
          AND s.clock_in >= %s
          AND s.clock_in < %s

        UNION ALL

        SELECT 'visit'::text AS event_type, s.id AS shift_id,
               v.id AS visit_id, s.employee_id, v.location_id,
               l.address AS site_name, v.location_label,
               v.arrival_time AS event_at, s.clock_in AS shift_clock_in,
               s.clock_out AS shift_clock_out
        FROM visits v
        JOIN shifts s ON s.id = v.shift_id
        LEFT JOIN locations l ON l.id = v.location_id
        WHERE s.employee_id = ANY(%s)
          AND v.arrival_time >= %s
          AND v.arrival_time < %s

        ORDER BY event_at, shift_id, event_type
        """,
        (
            employee_ids,
            start_utc - window,
            end_utc + window,
            employee_ids,
            start_utc - window,
            end_utc + window,
        ),
    )


def _match_reconciliation_check_in(
    occurrence: Dict[str, Any],
    check_ins: List[Dict[str, Any]],
    used_ids: set[int],
) -> Optional[Dict[str, Any]]:
    scheduled_start = occurrence["scheduled_start"]
    max_distance = SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS * 3600
    candidates = []
    for row in check_ins:
        row_id = int(row["id"])
        if row_id in used_ids:
            continue
        if (
            int(row["employee_id"]) != occurrence["employee_id"]
            or int(row["location_id"]) != occurrence["location_id"]
        ):
            continue
        distance = abs((row["server_checked_in_at"] - scheduled_start).total_seconds())
        if distance > max_distance:
            continue
        exact_link = (
            occurrence["schedule_id"] is not None
            and row.get("schedule_id") == occurrence["schedule_id"]
        )
        rule_link = (
            occurrence["schedule_rule_id"] is not None
            and row.get("schedule_rule_id") == occurrence["schedule_rule_id"]
        )
        candidates.append((0 if exact_link or rule_link else 1, distance, row_id, row))
    if not candidates:
        return None
    selected = min(candidates)[3]
    used_ids.add(int(selected["id"]))
    return selected


def _match_reconciliation_timecard_event(
    occurrence: Dict[str, Any],
    check_in: Optional[Dict[str, Any]],
    events: List[Dict[str, Any]],
    used_keys: set[str],
    *,
    same_site_only: bool = False,
) -> Optional[Dict[str, Any]]:
    scheduled_start = occurrence["scheduled_start"]
    anchor = check_in["server_checked_in_at"] if check_in else scheduled_start
    max_distance = SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS * 3600
    candidates = []
    for row in events:
        if int(row["employee_id"]) != occurrence["employee_id"]:
            continue
        event_key = (
            f"visit:{int(row['visit_id'])}"
            if row.get("visit_id") is not None
            else f"clock_in:{int(row['shift_id'])}"
        )
        if event_key in used_keys:
            continue
        schedule_distance = abs((row["event_at"] - scheduled_start).total_seconds())
        if schedule_distance > max_distance:
            continue
        row_site_id = int(row["location_id"]) if row.get("location_id") else None
        if same_site_only and row_site_id != occurrence["location_id"]:
            continue
        site_rank = 0 if row_site_id == occurrence["location_id"] else 1
        anchor_distance = abs((row["event_at"] - anchor).total_seconds())
        event_type_rank = 0 if row["event_type"] == "visit" else 1
        candidates.append(
            (site_rank, anchor_distance, event_type_rank, schedule_distance, event_key, row)
        )
    if not candidates:
        return None
    selected_entry = min(candidates)
    used_keys.add(selected_entry[4])
    return selected_entry[5]


def _site_check_in_reconciliation_outcome(
    occurrence: Dict[str, Any],
    check_in: Optional[Dict[str, Any]],
    event: Optional[Dict[str, Any]],
    now_utc: datetime,
) -> Tuple[str, str, Optional[float]]:
    due_at = occurrence["scheduled_start"] + timedelta(
        minutes=occurrence["grace_minutes"]
    )
    if now_utc <= due_at and (check_in is None or event is None):
        return "pending", "The scheduled arrival is still within its grace period.", None

    event_site_id = int(event["location_id"]) if event and event.get("location_id") else None
    site_matches = event_site_id == occurrence["location_id"]
    if check_in is None:
        if event is None:
            return "missing_both", "No QR arrival or paid-time arrival was found.", None
        if not site_matches:
            return "site_mismatch", "Paid-time evidence points to a different or unknown site.", None
        return "missing_qr", "Paid-time arrival exists, but no matching QR arrival was found.", None
    if event is None:
        return "missing_time_entry", "QR arrival exists, but no paid-time arrival was found.", None
    difference_minutes = round(
        (event["event_at"] - check_in["server_checked_in_at"]).total_seconds() / 60,
        1,
    )
    if not site_matches:
        return (
            "site_mismatch",
            "QR and paid-time evidence do not identify the same site.",
            difference_minutes,
        )
    if (
        check_in["classification"] == "needs_review"
        and check_in["review_status"] != "approved"
    ):
        if check_in["review_status"] == "rejected":
            return (
                "qr_rejected",
                "The matching QR evidence was rejected by an admin.",
                difference_minutes,
            )
        return (
            "qr_needs_review",
            "The matching QR evidence still requires an admin decision.",
            difference_minutes,
        )
    if abs(difference_minutes) > SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES:
        return (
            "time_gap",
            "QR and paid-time arrivals are farther apart than the allowed gap.",
            difference_minutes,
        )
    return (
        "matched",
        "QR and paid-time arrivals agree within the allowed gap.",
        difference_minutes,
    )


def _serialize_reconciliation_check_in(
    row: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    distance = row.get("distance_m")
    return {
        "id": int(row["id"]),
        "serverCheckedInAt": to_utc_iso(row["server_checked_in_at"]),
        "classification": str(row["classification"]),
        "classificationReason": str(row["classification_reason"]),
        "geofenceStatus": str(row["geofence_status"]),
        "distanceM": float(distance) if distance is not None else None,
        "accuracyM": float(row["accuracy_m"]),
        "reviewStatus": str(row["review_status"]),
    }


def _serialize_reconciliation_timecard_event(
    row: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {
        "eventType": str(row["event_type"]),
        "eventAt": to_utc_iso(row["event_at"]),
        "shiftId": int(row["shift_id"]),
        "visitId": int(row["visit_id"]) if row.get("visit_id") is not None else None,
        "siteId": int(row["location_id"]) if row.get("location_id") else None,
        "siteName": str(row.get("site_name") or ""),
        "locationLabel": str(row.get("location_label") or ""),
        "shiftClockIn": to_utc_iso(row["shift_clock_in"]),
        "shiftClockOut": (
            to_utc_iso(row["shift_clock_out"])
            if row.get("shift_clock_out") is not None
            else None
        ),
    }


def _site_check_in_reconciliation_evidence(
    row: Dict[str, Any],
) -> Dict[str, Any]:
    qr = row.get("qrCheckIn") or {}
    timecard = row.get("timecardEvent") or {}
    return {
        "employeeId": row["employeeId"],
        "siteId": row["siteId"],
        "scheduledStart": row["scheduledStart"],
        "dueAt": row["dueAt"],
        "graceMinutes": row["graceMinutes"],
        "scheduleId": row.get("scheduleId"),
        "scheduleRuleId": row.get("scheduleRuleId"),
        "outcome": row["outcome"],
        "timecardDifferenceMinutes": row.get("timecardDifferenceMinutes"),
        "qrCheckIn": (
            {
                "id": qr.get("id"),
                "serverCheckedInAt": qr.get("serverCheckedInAt"),
                "classification": qr.get("classification"),
                "classificationReason": qr.get("classificationReason"),
                "geofenceStatus": qr.get("geofenceStatus"),
                "distanceM": qr.get("distanceM"),
                "accuracyM": qr.get("accuracyM"),
                "reviewStatus": qr.get("reviewStatus"),
            }
            if qr
            else None
        ),
        "timecardEvent": (
            {
                "eventType": timecard.get("eventType"),
                "eventAt": timecard.get("eventAt"),
                "shiftId": timecard.get("shiftId"),
                "visitId": timecard.get("visitId"),
                "siteId": timecard.get("siteId"),
                "siteName": timecard.get("siteName"),
                "locationLabel": timecard.get("locationLabel"),
            }
            if timecard
            else None
        ),
    }


def _site_check_in_reconciliation_fingerprint(row: Dict[str, Any]) -> str:
    evidence = _site_check_in_reconciliation_evidence(row)
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _serialize_site_check_in_reconciliation_review(
    row: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "disposition": str(row["disposition"]),
        "note": str(row["note"]),
        "reviewedBy": str(row["reviewed_by_name"]),
        "reviewedAt": to_utc_iso(row["reviewed_at"]),
        "outcome": str(row["outcome"]),
    }


def _attach_site_check_in_reconciliation_reviews(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not rows:
        return rows
    review_rows = db.query_all(
        """
        SELECT id, occurrence_key, evidence_fingerprint, outcome,
               disposition, note, reviewed_by_name, reviewed_at
        FROM site_check_in_reconciliation_reviews
        WHERE occurrence_key = ANY(%s)
        ORDER BY reviewed_at DESC, id DESC
        """,
        ([str(row["key"]) for row in rows],),
    )
    reviews_by_key: Dict[str, List[Dict[str, Any]]] = {}
    for review in review_rows:
        reviews_by_key.setdefault(str(review["occurrence_key"]), []).append(review)

    for row in rows:
        fingerprint = _site_check_in_reconciliation_fingerprint(row)
        history = reviews_by_key.get(str(row["key"]), [])
        current_review = next(
            (
                review
                for review in history
                if str(review["evidence_fingerprint"]) == fingerprint
            ),
            None,
        )
        row["evidenceFingerprint"] = fingerprint
        row["reviewHistoryCount"] = len(history)
        row["review"] = (
            _serialize_site_check_in_reconciliation_review(current_review)
            if current_review
            else None
        )
        if not row["hasException"]:
            row["reviewState"] = "not_applicable"
            row["hasOpenReview"] = False
        elif current_review:
            row["reviewState"] = str(current_review["disposition"])
            row["hasOpenReview"] = current_review["disposition"] != "resolved"
        elif history:
            row["reviewState"] = "reopened"
            row["hasOpenReview"] = True
        else:
            row["reviewState"] = "open"
            row["hasOpenReview"] = True
    return rows


def build_site_check_in_reconciliation(
    from_date: date,
    to_date: date,
    employee_id: Optional[int] = None,
    site_id: Optional[int] = None,
    now_utc: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    occurrences = _site_check_in_reconciliation_occurrences(
        from_date,
        to_date,
        employee_id,
        site_id,
    )
    start_utc, end_utc = _site_check_in_reconciliation_window(from_date, to_date)
    check_ins = _site_check_in_reconciliation_check_ins(
        occurrences,
        start_utc,
        end_utc,
    )
    events = _site_check_in_reconciliation_timecard_events(
        occurrences,
        start_utc,
        end_utc,
    )
    used_check_in_ids: set[int] = set()
    used_event_keys: set[str] = set()
    official_now = now_utc or utc_now()
    occurrence_matches: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []
    for occurrence in occurrences:
        occurrence_matches.append(
            (
                occurrence,
                _match_reconciliation_check_in(
                    occurrence,
                    check_ins,
                    used_check_in_ids,
                ),
            )
        )

    # Allocate correct-site evidence across the full multi-stop day before a
    # wrong or unknown-site event can be used to explain a mismatch elsewhere.
    event_matches: List[Optional[Dict[str, Any]]] = []
    for occurrence, check_in in occurrence_matches:
        event_matches.append(
            _match_reconciliation_timecard_event(
                occurrence,
                check_in,
                events,
                used_event_keys,
                same_site_only=True,
            )
        )
    for index, (occurrence, check_in) in enumerate(occurrence_matches):
        if event_matches[index] is None:
            event_matches[index] = _match_reconciliation_timecard_event(
                occurrence,
                check_in,
                events,
                used_event_keys,
            )

    reconciled: List[Dict[str, Any]] = []
    for (occurrence, check_in), event in zip(occurrence_matches, event_matches):
        outcome, reason, difference_minutes = _site_check_in_reconciliation_outcome(
            occurrence,
            check_in,
            event,
            official_now,
        )
        due_at = occurrence["scheduled_start"] + timedelta(
            minutes=occurrence["grace_minutes"]
        )
        reconciled.append(
            {
                "key": occurrence["key"],
                "employeeId": occurrence["employee_id"],
                "employeeName": occurrence["employee_name"],
                "siteId": occurrence["location_id"],
                "siteName": occurrence["site_name"],
                "scheduledStart": to_utc_iso(occurrence["scheduled_start"]),
                "dueAt": to_utc_iso(due_at),
                "graceMinutes": occurrence["grace_minutes"],
                "scheduleId": occurrence["schedule_id"],
                "scheduleRuleId": occurrence["schedule_rule_id"],
                "scheduleSource": occurrence["schedule_source"],
                "outcome": outcome,
                "outcomeReason": reason,
                "hasException": outcome not in {"matched", "pending"},
                "timecardDifferenceMinutes": difference_minutes,
                "qrCheckIn": _serialize_reconciliation_check_in(check_in),
                "timecardEvent": _serialize_reconciliation_timecard_event(event),
            }
        )
    return sorted(
        reconciled,
        key=lambda row: (row["scheduledStart"], row["employeeName"], row["siteId"]),
        reverse=True,
    )


def _matching_site_check_in_schedule(
    employee_id: int,
    site_id: int,
    checked_in_at: datetime,
    *,
    cur: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    exact_sql = """
        SELECT id, scheduled_start, grace_minutes
        FROM site_check_in_schedules
        WHERE employee_id = %s
          AND location_id = %s
          AND cancelled_at IS NULL
          AND scheduled_start BETWEEN
              %s - (%s * INTERVAL '1 hour')
              AND %s + (%s * INTERVAL '1 hour')
        ORDER BY ABS(EXTRACT(EPOCH FROM (scheduled_start - %s))), id
        LIMIT 1
        """
    exact_params = (
        employee_id,
        site_id,
        checked_in_at,
        SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS,
        checked_in_at,
        SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS,
        checked_in_at,
    )
    if cur is None:
        exact_schedule = db.query_one(exact_sql, exact_params)
    else:
        cur.execute(exact_sql, exact_params)
        exact_row = cur.fetchone()
        exact_schedule = dict(exact_row) if exact_row else None
    if exact_schedule:
        exact_schedule["schedule_rule_id"] = None
        return exact_schedule

    rules_sql = """
        SELECT id, weekdays, local_start_time, timezone, starts_on, ends_on,
               grace_minutes
        FROM site_check_in_schedule_rules
        WHERE employee_id = %s
          AND location_id = %s
          AND active = true
        ORDER BY id
        """
    if cur is None:
        rules = db.query_all(rules_sql, (employee_id, site_id))
    else:
        cur.execute(rules_sql, (employee_id, site_id))
        rules = [dict(row) for row in cur.fetchall()]
    candidates: List[Tuple[float, int, datetime, int]] = []
    for rule in rules:
        try:
            rule_zone = ZoneInfo(str(rule["timezone"]))
        except (KeyError, ValueError):
            logger.warning(
                "Ignoring site check-in rule %s with invalid timezone",
                rule.get("id"),
            )
            continue
        local_date = checked_in_at.astimezone(rule_zone).date()
        weekdays = {int(day) for day in rule["weekdays"]}
        for day_offset in (-1, 0, 1):
            candidate_date = local_date + timedelta(days=day_offset)
            if candidate_date.weekday() not in weekdays:
                continue
            if candidate_date < rule["starts_on"] or candidate_date > rule["ends_on"]:
                continue
            local_start = datetime.combine(
                candidate_date,
                rule["local_start_time"],
                tzinfo=rule_zone,
            )
            scheduled_start = local_start.astimezone(timezone.utc)
            distance_seconds = abs((scheduled_start - checked_in_at).total_seconds())
            if distance_seconds <= SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS * 3600:
                candidates.append(
                    (
                        distance_seconds,
                        int(rule["id"]),
                        scheduled_start,
                        int(rule["grace_minutes"]),
                    )
                )

    if not candidates:
        return None
    _, rule_id, scheduled_start, grace_minutes = min(candidates)
    return {
        "id": None,
        "schedule_rule_id": rule_id,
        "scheduled_start": scheduled_start,
        "grace_minutes": grace_minutes,
    }


def _classify_site_check_in(
    geofence: Dict[str, Any],
    schedule: Optional[Dict[str, Any]],
    checked_in_at: datetime,
    device_clock_skew_seconds: float,
) -> Tuple[str, str, str]:
    geofence_reason = {
        "site_unpinned": "site_missing_location_pin",
        "low_accuracy": "location_accuracy_too_low",
        "outside": "outside_geofence",
        "uncertain": "geofence_boundary_uncertain",
    }.get(str(geofence["status"]))
    if geofence_reason:
        return "needs_review", geofence_reason, "pending"

    if device_clock_skew_seconds > SITE_CHECK_IN_DEVICE_SKEW_SECONDS:
        return "needs_review", "device_clock_skew", "pending"

    if not schedule:
        return "needs_review", "no_matching_schedule", "pending"

    scheduled_start = schedule["scheduled_start"]
    grace_deadline = scheduled_start + timedelta(minutes=int(schedule["grace_minutes"]))
    if checked_in_at <= grace_deadline:
        return "on_time", "within_grace_period", "not_required"
    return "late", "after_grace_period", "not_required"


@app.get("/", include_in_schema=False)
@app.get("/timetracker-mobile.html", include_in_schema=False)
def time_tracker_page() -> FileResponse:
    return FileResponse(str(FRONTEND_FILE), media_type="text/html")


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


@app.get("/api/admin/receivables/ready")
def receivables_ready(
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    result = _atlas_receivables_request("GET", "/receivables/ready", admin)
    append_access_log(request, "RECEIVABLES_READY", True, "Atlas checked")
    return result


@app.get("/api/admin/receivables/open-invoices")
def receivables_open_invoices(
    request: Request,
    contact_id: Optional[str] = Query(default=None, max_length=64),
    search: Optional[str] = Query(default=None, max_length=256),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_request(
        "GET",
        "/receivables/open-invoices",
        admin,
        params={"contact_id": contact_id, "search": search},
    )


@app.get("/api/admin/receivables/allocation-suggestions")
def receivables_allocation_suggestions(
    request: Request,
    contact_id: str = Query(min_length=1, max_length=64),
    total_amount_cents: int = Query(gt=0),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_request(
        "GET",
        "/receivables/allocation-suggestions",
        admin,
        params={
            "contact_id": contact_id,
            "total_amount_cents": total_amount_cents,
        },
    )


@app.get("/api/admin/receivables/payments")
def receivables_payments(
    request: Request,
    status_filter: Optional[str] = Query(default=None, alias="status", max_length=16),
    search: Optional[str] = Query(default=None, max_length=256),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_request(
        "GET",
        "/receivables/payments",
        admin,
        params={
            "status": status_filter,
            "search": search,
            "limit": limit,
            "offset": offset,
        },
    )


@app.post("/api/admin/receivables/payments")
def receivables_create_payment(
    payload: ReceivablesPaymentRequest,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_PAYMENT_CREATE",
        "Receipt accepted by Atlas",
        "POST",
        "/receivables/payments",
        admin,
        payload=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.put("/api/admin/receivables/payments/{payment_id}/allocations")
def receivables_adjust_payment(
    payment_id: UUID,
    payload: ReceivablesAdjustmentRequest,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_PAYMENT_ALLOCATIONS_ADJUST",
        "Payment allocations adjusted in Atlas",
        "PUT",
        f"/receivables/payments/{payment_id}/allocations",
        admin,
        payload=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.post("/api/admin/receivables/payments/{payment_id}/return")
def receivables_return_payment(
    payment_id: UUID,
    payload: ReceivablesActionRequest,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_PAYMENT_RETURN",
        "Payment returned in Atlas",
        "POST",
        f"/receivables/payments/{payment_id}/return",
        admin,
        payload=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.post("/api/admin/receivables/payments/{payment_id}/void")
def receivables_void_payment(
    payment_id: UUID,
    payload: ReceivablesActionRequest,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_PAYMENT_VOID",
        "Payment voided in Atlas",
        "POST",
        f"/receivables/payments/{payment_id}/void",
        admin,
        payload=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
        after_atlas_success=lambda result: _mark_payment_create_voided(
            payment_id, result
        ),
    )


@app.get("/api/admin/receivables/deposit-batches")
def receivables_deposit_batches(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_request(
        "GET",
        "/receivables/deposit-batches",
        admin,
        params={"limit": limit},
    )


@app.post("/api/admin/receivables/deposit-batches")
def receivables_create_deposit_batch(
    payload: ReceivablesDepositRequest,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_DEPOSIT_CREATE",
        "Deposit accepted by Atlas",
        "POST",
        "/receivables/deposit-batches",
        admin,
        payload=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.post("/api/admin/receivables/deposit-batches/{batch_id}/clear")
def receivables_clear_deposit_batch(
    batch_id: UUID,
    request: Request,
    idempotency_key: str = Header(
        alias="Idempotency-Key", min_length=1, max_length=128
    ),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    return _atlas_receivables_mutation(
        request,
        "RECEIVABLES_DEPOSIT_CLEAR",
        "Deposit cleared in Atlas",
        "POST",
        f"/receivables/deposit-batches/{batch_id}/clear",
        admin,
        idempotency_key=idempotency_key,
    )


@app.post("/api/admin/locations/{site_id}/check-in-qr")
def admin_site_check_in_qr(
    site_id: int,
    payload: SiteQrRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    site = db.query_one(
        """
        SELECT id, address, customer_name, active, check_in_token_nonce,
               check_in_token_rotated_at
        FROM locations
        WHERE id = %s
        """,
        (site_id,),
    )
    if not site or not site.get("active"):
        raise HTTPException(status_code=404, detail="Active site not found")

    nonce = str(site.get("check_in_token_nonce") or "")
    rotated = False
    if payload.rotate:
        candidate_nonce = secrets.token_urlsafe(18)
        row = db.query_one(
            """
            UPDATE locations
            SET check_in_token_nonce = %s, check_in_token_rotated_at = NOW()
            WHERE id = %s AND active = true
            RETURNING check_in_token_nonce, check_in_token_rotated_at
            """,
            (candidate_nonce, site_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Active site not found")
        nonce = str(row["check_in_token_nonce"])
        site["check_in_token_rotated_at"] = row["check_in_token_rotated_at"]
        rotated = True
    elif not nonce:
        candidate_nonce = secrets.token_urlsafe(18)
        row = db.query_one(
            """
            UPDATE locations
            SET check_in_token_nonce = %s, check_in_token_rotated_at = NOW()
            WHERE id = %s
              AND active = true
              AND COALESCE(check_in_token_nonce, '') = ''
            RETURNING check_in_token_nonce, check_in_token_rotated_at
            """,
            (candidate_nonce, site_id),
        )
        if row:
            rotated = True
        else:
            row = db.query_one(
                """
                SELECT check_in_token_nonce, check_in_token_rotated_at
                FROM locations
                WHERE id = %s
                  AND active = true
                  AND COALESCE(check_in_token_nonce, '') <> ''
                """,
                (site_id,),
            )
        if not row:
            raise HTTPException(status_code=404, detail="Active site not found")
        nonce = str(row["check_in_token_nonce"])
        site["check_in_token_rotated_at"] = row["check_in_token_rotated_at"]

    token = build_site_check_in_token(site_id, nonce)
    check_in_url = _site_check_in_url(request, token)
    rotated_at = site.get("check_in_token_rotated_at")
    append_access_log(
        request,
        "SITE_QR_ROTATED" if rotated else "SITE_QR_LOADED",
        True,
        f"Admin {admin['name']} site {site_id}",
    )
    return {
        "success": True,
        "site": {
            "id": int(site["id"]),
            "name": str(site["address"]),
            "customerName": str(site.get("customer_name") or ""),
        },
        "token": token,
        "checkInUrl": check_in_url,
        "qrSvg": build_site_check_in_qr_svg(check_in_url),
        "rotated": rotated,
        "rotatedAt": to_utc_iso(rotated_at) if rotated_at else None,
    }


@app.post("/api/timesheet/site-check-in/resolve")
def resolve_site_check_in_qr(
    payload: SiteQrResolveRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    site = _resolve_site_check_in_qr(payload.token)
    append_access_log(
        request,
        "SITE_QR_RESOLVED",
        True,
        f"Employee {employee['name']} site {site['id']}",
    )
    return {
        "success": True,
        "site": {
            "id": int(site["id"]),
            "name": str(site["address"]),
            "customerName": str(site.get("customer_name") or ""),
        },
    }


@app.post("/api/timesheet/site-check-in")
def record_site_check_in(
    payload: SiteCheckInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    if int(payload.employeeId) != int(employee["id"]):
        append_access_log(
            request,
            "SITE_CHECK_IN_REJECTED",
            False,
            f"Session employee {employee['id']} attempted employee {payload.employeeId}",
        )
        raise HTTPException(status_code=403, detail="employeeId must match the signed-in employee")

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            site = _resolve_site_check_in_qr(
                payload.token,
                cur=cur,
                for_update=True,
            )
            if int(site["id"]) != int(payload.siteId):
                append_access_log(
                    request,
                    "SITE_CHECK_IN_REJECTED",
                    False,
                    f"QR site {site['id']} did not match submitted site {payload.siteId}",
                )
                raise HTTPException(
                    status_code=400,
                    detail="siteId must match the scanned site QR",
                )

            official_time = utc_now()
            geofence = evaluate_site_check_in_geofence(
                site_latitude=(
                    float(site["lat"]) if site.get("lat") is not None else None
                ),
                site_longitude=(
                    float(site["lng"]) if site.get("lng") is not None else None
                ),
                latitude=payload.latitude,
                longitude=payload.longitude,
                accuracy=payload.accuracy,
            )
            schedule = _matching_site_check_in_schedule(
                int(employee["id"]),
                int(site["id"]),
                official_time,
                cur=cur,
            )
            device_clock_skew_seconds = abs(
                (
                    official_time - payload.scannedAt.astimezone(timezone.utc)
                ).total_seconds()
            )
            classification, reason, review_status = _classify_site_check_in(
                geofence,
                schedule,
                official_time,
                device_clock_skew_seconds,
            )
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason, schedule_id,
                    schedule_rule_id, scheduled_start, grace_minutes, device_clock_skew_seconds,
                    review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (employee_id, location_id, device_scanned_at)
                DO NOTHING
                RETURNING id
                """,
                (
                    int(employee["id"]),
                    int(site["id"]),
                    official_time,
                    payload.scannedAt,
                    payload.latitude,
                    payload.longitude,
                    payload.accuracy,
                    geofence["radiusM"],
                    geofence["distanceM"],
                    geofence["status"],
                    classification,
                    reason,
                    schedule.get("id") if schedule else None,
                    schedule.get("schedule_rule_id") if schedule else None,
                    schedule["scheduled_start"] if schedule else None,
                    schedule["grace_minutes"] if schedule else None,
                    device_clock_skew_seconds,
                    review_status,
                ),
            )
            inserted = cur.fetchone()
            duplicate = inserted is None
            if inserted:
                check_in_id = int(inserted["id"])
            else:
                cur.execute(
                    """
                    SELECT id FROM site_check_ins
                    WHERE employee_id = %s
                      AND location_id = %s
                      AND device_scanned_at = %s
                    """,
                    (int(employee["id"]), int(site["id"]), payload.scannedAt),
                )
                existing = cur.fetchone()
                if not existing:
                    raise RuntimeError("Unable to reconcile duplicate site check-in")
                check_in_id = int(existing["id"])

    row = _site_check_in_row(check_in_id)
    if not row:
        raise RuntimeError("Site check-in was stored but could not be reloaded")
    append_access_log(
        request,
        "SITE_CHECK_IN_RECORDED",
        True,
        f"Employee {employee['name']} site {site['id']} classification {row['classification']}",
    )
    return {
        "success": True,
        "duplicate": duplicate,
        "checkIn": _serialize_site_check_in(row),
    }


@app.post("/api/admin/site-check-in-schedules")
def admin_create_site_check_in_schedule(
    payload: SiteCheckInScheduleRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            cur.execute(
                "SELECT id FROM employees WHERE id = %s AND active = true",
                (payload.employeeId,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Active employee not found")
            cur.execute(
                "SELECT id FROM locations WHERE id = %s AND active = true FOR UPDATE",
                (payload.siteId,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Active site not found")
            cur.execute(
                """
                INSERT INTO site_check_in_schedules (
                    employee_id, location_id, scheduled_start,
                    grace_minutes, created_by
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (employee_id, location_id, scheduled_start)
                DO UPDATE SET grace_minutes = EXCLUDED.grace_minutes,
                              created_by = EXCLUDED.created_by,
                              cancelled_at = NULL,
                              cancelled_by = NULL,
                              cancellation_reason = NULL
                RETURNING id
                """,
                (
                    payload.employeeId,
                    payload.siteId,
                    payload.scheduledStart,
                    payload.graceMinutes,
                    int(admin["id"]),
                ),
            )
            inserted = cur.fetchone()
            if not inserted:
                raise RuntimeError("Site check-in schedule was not saved")
            schedule_id = int(inserted["id"])
    row = _site_check_in_schedule_row(schedule_id)
    append_access_log(
        request,
        "SITE_CHECK_IN_SCHEDULE_SAVED",
        True,
        f"Schedule {schedule_id} by {admin['name']}",
    )
    return {"success": True, "schedule": _serialize_site_check_in_schedule(row)}


@app.get("/api/admin/site-check-in-schedules")
def admin_list_site_check_in_schedules(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    rows = db.query_all(
        """
        SELECT sc.id, sc.employee_id, e.name AS employee_name,
               sc.location_id, l.address AS site_name,
               sc.scheduled_start, sc.grace_minutes, sc.created_at,
               sc.cancelled_at, sc.cancelled_by, sc.cancellation_reason
        FROM site_check_in_schedules sc
        JOIN employees e ON e.id = sc.employee_id
        JOIN locations l ON l.id = sc.location_id
        ORDER BY sc.scheduled_start DESC, sc.id DESC
        LIMIT %s
        """,
        (limit,),
    )
    return {
        "success": True,
        "schedules": [_serialize_site_check_in_schedule(row) for row in rows],
    }


@app.delete("/api/admin/site-check-in-schedules/{schedule_id}")
def admin_delete_site_check_in_schedule(
    schedule_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    deleted = db.query_one(
        "DELETE FROM site_check_in_schedules WHERE id = %s RETURNING id",
        (schedule_id,),
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Site check-in schedule not found")
    append_access_log(
        request,
        "SITE_CHECK_IN_SCHEDULE_DELETED",
        True,
        f"Schedule {schedule_id} by {admin['name']}",
    )
    return {"success": True, "scheduleId": schedule_id}


@app.post("/api/admin/site-check-in-schedule-rules")
def admin_create_site_check_in_schedule_rule(
    payload: SiteCheckInScheduleRuleRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    if payload.endsOn is not None and payload.endsOn < payload.startsOn:
        raise HTTPException(status_code=400, detail="endsOn must be on or after startsOn")
    try:
        ZoneInfo(TIMEZONE_NAME)
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"Configured timezone is invalid: {TIMEZONE_NAME}") from exc

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            cur.execute(
                "SELECT id FROM employees WHERE id = %s AND active = true",
                (payload.employeeId,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Active employee not found")
            cur.execute(
                "SELECT id FROM locations WHERE id = %s AND active = true FOR UPDATE",
                (payload.siteId,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Active site not found")
            cur.execute(
                """
                INSERT INTO site_check_in_schedule_rules (
                    employee_id, location_id, weekdays, local_start_time, timezone,
                    starts_on, ends_on, grace_minutes, active, created_by
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    COALESCE(%s, 'infinity'::date), %s, true, %s
                )
                ON CONFLICT (
                    employee_id, location_id, weekdays, local_start_time,
                    timezone, starts_on, ends_on
                )
                DO UPDATE SET grace_minutes = EXCLUDED.grace_minutes,
                              active = true,
                              created_by = EXCLUDED.created_by,
                              updated_at = NOW()
                RETURNING id
                """,
                (
                    payload.employeeId,
                    payload.siteId,
                    payload.weekdays,
                    payload.localStart,
                    TIMEZONE_NAME,
                    payload.startsOn,
                    payload.endsOn,
                    payload.graceMinutes,
                    int(admin["id"]),
                ),
            )
            inserted = cur.fetchone()
            if not inserted:
                raise RuntimeError("Recurring site check-in schedule was not saved")
            rule_id = int(inserted["id"])
    row = _site_check_in_schedule_rule_row(rule_id)
    append_access_log(
        request,
        "SITE_CHECK_IN_SCHEDULE_RULE_SAVED",
        True,
        f"Schedule rule {rule_id} by {admin['name']}",
    )
    return {
        "success": True,
        "rule": _serialize_site_check_in_schedule_rule(row),
    }


@app.get("/api/admin/site-check-in-schedule-rules")
def admin_list_site_check_in_schedule_rules(
    request: Request,
    active_only: bool = Query(default=True, alias="activeOnly"),
    limit: int = Query(default=200, ge=1, le=500),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    active_clause = "WHERE sr.active = true" if active_only else ""
    rows = db.query_all(
        f"""
        SELECT sr.id, sr.employee_id, e.name AS employee_name,
               sr.location_id, l.address AS site_name, sr.weekdays,
               sr.local_start_time, sr.timezone, sr.starts_on,
               NULLIF(sr.ends_on, 'infinity'::date) AS ends_on,
               sr.grace_minutes, sr.active, sr.created_at, sr.updated_at
        FROM site_check_in_schedule_rules sr
        JOIN employees e ON e.id = sr.employee_id
        JOIN locations l ON l.id = sr.location_id
        {active_clause}
        ORDER BY sr.active DESC, sr.starts_on DESC, sr.id DESC
        LIMIT %s
        """,
        (limit,),
    )
    return {
        "success": True,
        "rules": [_serialize_site_check_in_schedule_rule(row) for row in rows],
    }


@app.delete("/api/admin/site-check-in-schedule-rules/{rule_id}")
def admin_end_site_check_in_schedule_rule(
    rule_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    ended = db.query_one(
        """
        UPDATE site_check_in_schedule_rules
        SET active = false, updated_at = NOW()
        WHERE id = %s AND active = true
        RETURNING id
        """,
        (rule_id,),
    )
    if not ended:
        raise HTTPException(status_code=404, detail="Active recurring schedule not found")
    append_access_log(
        request,
        "SITE_CHECK_IN_SCHEDULE_RULE_ENDED",
        True,
        f"Schedule rule {rule_id} by {admin['name']}",
    )
    return {"success": True, "ruleId": rule_id}


@app.get("/api/admin/site-check-ins")
def admin_list_site_check_ins(
    request: Request,
    classification: Optional[str] = None,
    review_status: Optional[str] = None,
    employee_id: Optional[int] = Query(default=None, alias="employeeId", gt=0),
    site_id: Optional[int] = Query(default=None, alias="siteId", gt=0),
    from_date: Optional[date] = Query(default=None, alias="fromDate"),
    to_date: Optional[date] = Query(default=None, alias="toDate"),
    limit: int = Query(default=200, ge=1, le=500),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    if classification not in {None, "on_time", "late", "needs_review"}:
        raise HTTPException(status_code=400, detail="Invalid classification filter")
    if review_status not in {None, "not_required", "pending", "approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Invalid review status filter")
    if from_date and to_date and from_date > to_date:
        raise HTTPException(status_code=400, detail="fromDate must be on or before toDate")

    clauses: List[str] = []
    params: List[Any] = []
    if classification:
        clauses.append("ci.classification = %s")
        params.append(classification)
    if review_status:
        clauses.append("ci.review_status = %s")
        params.append(review_status)
    if employee_id:
        clauses.append("ci.employee_id = %s")
        params.append(employee_id)
    if site_id:
        clauses.append("ci.location_id = %s")
        params.append(site_id)

    company_timezone = ZoneInfo(TIMEZONE_NAME)
    if from_date:
        from_timestamp = datetime.combine(
            from_date, clock_time.min, tzinfo=company_timezone
        ).astimezone(timezone.utc)
        clauses.append("ci.server_checked_in_at >= %s")
        params.append(from_timestamp)
    if to_date and to_date < date.max:
        to_timestamp = datetime.combine(
            to_date + timedelta(days=1), clock_time.min, tzinfo=company_timezone
        ).astimezone(timezone.utc)
        clauses.append("ci.server_checked_in_at < %s")
        params.append(to_timestamp)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    rows = db.query_all(
        f"""
        SELECT ci.*, e.name AS employee_name, l.address AS site_name,
               reviewer.name AS reviewed_by_name
        FROM site_check_ins ci
        JOIN employees e ON e.id = ci.employee_id
        JOIN locations l ON l.id = ci.location_id
        LEFT JOIN employees reviewer ON reviewer.id = ci.reviewed_by
        {where}
        ORDER BY ci.server_checked_in_at DESC, ci.id DESC
        LIMIT %s
        """,
        tuple(params),
    )
    return {
        "success": True,
        "checkIns": [_serialize_site_check_in(row) for row in rows],
    }


@app.get("/api/admin/site-check-in-reconciliation")
def admin_site_check_in_reconciliation(
    employee_id: Optional[int] = Query(default=None, alias="employeeId", gt=0),
    site_id: Optional[int] = Query(default=None, alias="siteId", gt=0),
    from_date: Optional[date] = Query(default=None, alias="fromDate"),
    to_date: Optional[date] = Query(default=None, alias="toDate"),
    outcome: Optional[str] = Query(default=None, max_length=32),
    exceptions_only: bool = Query(default=False, alias="exceptionsOnly"),
    review_state: Optional[str] = Query(
        default=None,
        alias="reviewState",
        max_length=32,
    ),
    limit: int = Query(default=200, ge=1, le=500),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    official_now = utc_now()
    company_today = official_now.astimezone(APP_TIMEZONE).date()
    selected_from = from_date or company_today
    selected_to = to_date or selected_from
    if selected_from > selected_to:
        raise HTTPException(status_code=400, detail="fromDate must be on or before toDate")
    if selected_to == date.max:
        raise HTTPException(status_code=400, detail="toDate is outside the supported range")
    if (selected_to - selected_from).days >= SITE_CHECK_IN_RECONCILIATION_MAX_DAYS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Arrival reconciliation supports at most "
                f"{SITE_CHECK_IN_RECONCILIATION_MAX_DAYS} days at a time"
            ),
        )
    allowed_outcomes = {
        "matched",
        "pending",
        "missing_qr",
        "missing_time_entry",
        "missing_both",
        "site_mismatch",
        "time_gap",
        "qr_needs_review",
        "qr_rejected",
    }
    if outcome is not None and outcome not in allowed_outcomes:
        raise HTTPException(status_code=400, detail="Invalid reconciliation outcome filter")
    allowed_review_states = {
        "open",
        "reopened",
        "resolved",
        "needs_correction",
    }
    if review_state is not None and review_state not in allowed_review_states:
        raise HTTPException(
            status_code=400,
            detail="Invalid reconciliation review filter",
        )

    rows = build_site_check_in_reconciliation(
        selected_from,
        selected_to,
        employee_id=employee_id,
        site_id=site_id,
        now_utc=official_now,
    )
    _attach_site_check_in_reconciliation_reviews(rows)
    outcome_counts = {name: 0 for name in sorted(allowed_outcomes)}
    for row in rows:
        outcome_counts[row["outcome"]] += 1
    summary = {
        "total": len(rows),
        "matched": outcome_counts["matched"],
        "pending": outcome_counts["pending"],
        "exceptions": sum(
            count
            for name, count in outcome_counts.items()
            if name not in {"matched", "pending"}
        ),
        "byOutcome": outcome_counts,
    }
    exception_rows = [row for row in rows if row["hasException"]]
    review_summary = {
        "open": sum(1 for row in exception_rows if row["hasOpenReview"]),
        "resolved": sum(
            1 for row in exception_rows if row["reviewState"] == "resolved"
        ),
        "needsCorrection": sum(
            1
            for row in exception_rows
            if row["reviewState"] == "needs_correction"
        ),
        "reopened": sum(
            1 for row in exception_rows if row["reviewState"] == "reopened"
        ),
    }
    filtered_rows = rows
    if exceptions_only:
        filtered_rows = [row for row in filtered_rows if row["hasException"]]
    if outcome:
        filtered_rows = [row for row in filtered_rows if row["outcome"] == outcome]
    if review_state == "open":
        filtered_rows = [row for row in filtered_rows if row["hasOpenReview"]]
    elif review_state:
        filtered_rows = [
            row for row in filtered_rows if row["reviewState"] == review_state
        ]
    filtered_rows = filtered_rows[:limit]
    return {
        "success": True,
        "asOf": to_utc_iso(official_now),
        "fromDate": selected_from.isoformat(),
        "toDate": selected_to.isoformat(),
        "gapThresholdMinutes": SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES,
        "readOnly": True,
        "summary": summary,
        "reviewSummary": review_summary,
        "returned": len(filtered_rows),
        "rows": filtered_rows,
    }


def _site_check_in_reconciliation_date_for_key(occurrence_key: str) -> date:
    exact_match = re.fullmatch(r"exact:(\d+)", occurrence_key)
    if exact_match:
        schedule = db.query_one(
            "SELECT scheduled_start FROM site_check_in_schedules WHERE id = %s",
            (int(exact_match.group(1)),),
        )
        if not schedule:
            raise HTTPException(status_code=404, detail="Scheduled arrival not found")
        return schedule["scheduled_start"].astimezone(APP_TIMEZONE).date()

    rule_match = re.fullmatch(r"rule:(\d+):(\d{4}-\d{2}-\d{2})", occurrence_key)
    if rule_match:
        try:
            return date.fromisoformat(rule_match.group(2))
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="Invalid reconciliation occurrence key",
            ) from exc
    raise HTTPException(status_code=400, detail="Invalid reconciliation occurrence key")


@app.post("/api/admin/site-check-in-reconciliation/{occurrence_key}/review")
def admin_review_site_check_in_reconciliation(
    occurrence_key: str,
    payload: SiteCheckInReconciliationReviewRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    occurrence_date = _site_check_in_reconciliation_date_for_key(occurrence_key)
    rows = build_site_check_in_reconciliation(
        occurrence_date,
        occurrence_date,
        now_utc=utc_now(),
    )
    row = next((item for item in rows if item["key"] == occurrence_key), None)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Reconciliation occurrence not found",
        )
    _attach_site_check_in_reconciliation_reviews([row])
    if not row["hasException"]:
        raise HTTPException(
            status_code=409,
            detail="Only reconciliation exceptions require a disposition",
        )
    if row["evidenceFingerprint"] != payload.evidenceFingerprint:
        raise HTTPException(
            status_code=409,
            detail="Reconciliation evidence changed; refresh before reviewing",
        )

    evidence = _site_check_in_reconciliation_evidence(row)
    review = db.query_one(
        """
        INSERT INTO site_check_in_reconciliation_reviews (
            occurrence_key, evidence_fingerprint, employee_id, location_id,
            scheduled_start, outcome, evidence, disposition, note,
            reviewed_by, reviewed_by_name
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            occurrence_key,
            row["evidenceFingerprint"],
            row["employeeId"],
            row["siteId"],
            parse_utc_iso(row["scheduledStart"]),
            row["outcome"],
            json.dumps(evidence),
            payload.disposition,
            payload.note,
            int(admin["id"]),
            str(admin["name"]),
        ),
    )
    if not review:
        raise RuntimeError("Reconciliation review was saved but could not be reloaded")
    _attach_site_check_in_reconciliation_reviews([row])
    append_access_log(
        request,
        "ARRIVAL_EXCEPTION_REVIEWED",
        True,
        (
            f"Arrival {occurrence_key} marked {payload.disposition} "
            f"by {admin['name']}"
        ),
    )
    return {
        "success": True,
        "timecardsChanged": False,
        "row": row,
    }


@app.patch("/api/admin/site-check-ins/{check_in_id}")
def admin_review_site_check_in(
    check_in_id: int,
    payload: SiteCheckInReviewRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    existing = db.query_one(
        "SELECT id, classification FROM site_check_ins WHERE id = %s",
        (check_in_id,),
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Site check-in not found")
    if existing["classification"] != "needs_review":
        raise HTTPException(status_code=409, detail="Only needs-review check-ins require a decision")

    updated = db.query_one(
        """
        UPDATE site_check_ins
        SET review_status = %s,
            reviewed_by = %s,
            reviewed_at = NOW(),
            review_note = %s
        WHERE id = %s
        RETURNING id
        """,
        (payload.decision, int(admin["id"]), payload.note.strip(), check_in_id),
    )
    row = _site_check_in_row(int(updated["id"])) if updated else None
    if not row:
        raise RuntimeError("Site check-in review was saved but could not be reloaded")
    append_access_log(
        request,
        "SITE_CHECK_IN_REVIEWED",
        True,
        f"Check-in {check_in_id} {payload.decision} by {admin['name']}",
    )
    return {"success": True, "checkIn": _serialize_site_check_in(row)}


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


@app.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, bool]:
    _rate_limit_check(
        request,
        key_prefix=f"change-password:{employee['id']}",
        max_calls=PASSWORD_CHANGE_RATE_LIMIT_MAX,
        window_seconds=PASSWORD_CHANGE_RATE_LIMIT_WINDOW_S,
    )

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, str]:
        account = find_employee_by_id(employees_data["employees"], int(employee["id"]))
        if not account or not account.get("active", True):
            return False, "Current password is incorrect"
        if not verify_password(payload.current_password, account["password"]):
            return False, "Current password is incorrect"
        if verify_password(payload.new_password, account["password"]):
            return False, "New password must be different from the current password"

        account["password"] = bcrypt.hashpw(
            payload.new_password.encode("utf-8"),
            bcrypt.gensalt(10),
        ).decode("utf-8")
        return True, "Password updated"

    updated, result = update_employees(mutator)
    if not updated:
        append_access_log(
            request,
            "PASSWORD_CHANGE_FAILED",
            False,
            f"Employee id={employee['id']}",
        )
        raise HTTPException(status_code=400, detail=result)

    append_access_log(
        request,
        "PASSWORD_CHANGED",
        True,
        f"Employee id={employee['id']}",
    )
    return {"success": True}


def create_employee_account(
    employee_name: str,
    password: str,
    role: str = "employee",
    hourly_rate: Optional[float] = None,
) -> Tuple[bool, Any]:
    """Create an active employee without overwriting an existing account."""
    normalized_name = employee_name.strip()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(10)).decode("utf-8")

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        existing = find_any_employee_by_name(employees_data["employees"], normalized_name)
        if existing:
            return False, "An account with that name already exists"

        employee_id = int(employees_data["nextId"])
        employee = {
            "id": employee_id,
            "name": normalized_name,
            "password": hashed,
            "active": True,
            "role": role,
            "hourlyRate": hourly_rate,
            "created": to_utc_iso(utc_now()),
            "lastLogin": None,
        }
        employees_data["employees"].append(employee)
        employees_data["nextId"] = employee_id + 1
        return True, employee

    ok, result = update_employees(mutator)
    if not ok:
        return False, result
    return True, {
        "id": result["id"],
        "name": result["name"],
        "role": result["role"],
        "active": result["active"],
        "hourlyRate": result.get("hourlyRate"),
    }


@app.post("/api/auth/register")
def register(payload: RegisterRequest, request: Request) -> Dict[str, Any]:
    _rate_limit_check(
        request,
        key_prefix="register",
        max_calls=REGISTER_RATE_LIMIT_MAX,
        window_seconds=REGISTER_RATE_LIMIT_WINDOW_S,
    )
    if not ALLOW_PUBLIC_REGISTRATION:
        append_access_log(request, "REGISTER_DISABLED", False, "Public registration is disabled")
        raise HTTPException(status_code=403, detail="Public registration is disabled")

    employee_name = payload.name.strip()
    password = payload.password
    if not employee_name or not password:
        raise HTTPException(status_code=400, detail="Name and password are required")

    ok, result = create_employee_account(employee_name, password)
    if not ok:
        append_access_log(request, "REGISTER_FAILED", False, str(result))
        raise HTTPException(status_code=409, detail=str(result))

    append_access_log(request, "REGISTER_SUCCESS", True, f"New employee: {employee_name}")
    return {"success": True, "employee": result}


@app.post("/api/admin/employees")
def admin_create_employee(
    payload: AdminEmployeeCreateRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    role = payload.role.strip().lower()
    if role not in {"admin", "employee"}:
        raise HTTPException(status_code=400, detail="Role must be admin or employee")

    hourly_rate = payload.hourlyRate
    if hourly_rate is not None and (not math.isfinite(hourly_rate) or hourly_rate < 0):
        raise HTTPException(status_code=400, detail="Hourly rate must be a non-negative number")

    ok, result = create_employee_account(
        payload.name,
        payload.password,
        role=role,
        hourly_rate=hourly_rate,
    )
    if not ok:
        append_access_log(request, "ADMIN_EMPLOYEE_CREATE_FAILED", False, str(result))
        raise HTTPException(status_code=409, detail=str(result))

    append_access_log(request, "ADMIN_EMPLOYEE_CREATED", True, f"id={result['id']} role={role}")
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
        # Guard against locking everyone out: after applying role/active, at least
        # one active admin must remain. Checked inside the write lock (via
        # update_employees) so it is atomic against concurrent demotions.
        has_active_admin = any(
            str(e.get("role") or "").lower() == "admin" and bool(e.get("active"))
            for e in employees_data["employees"]
        )
        if not has_active_admin:
            raise HTTPException(
                status_code=409,
                detail="Cannot demote or deactivate the last active admin. Promote or activate another admin first.",
            )
        if hashed_password:
            emp["password"] = hashed_password
        if "hourlyRate" in payload:
            emp["hourlyRate"] = new_hourly_rate
        return True, {"id": emp["id"], "name": emp["name"], "role": emp["role"], "active": emp["active"], "hourlyRate": emp.get("hourlyRate")}

    ok, result = update_employees(mutator)
    if not ok:
        raise HTTPException(status_code=404, detail=str(result))
    changed_fields = ",".join(sorted(str(key) for key in payload))
    append_access_log(request, "EMPLOYEE_UPDATED", True, f"id={employee_id} fields={changed_fields}")
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
                        WHEN EXTRACT(EPOCH FROM (NOW() - s.clock_in)) / 3600.0 > %s
                            THEN 0.0
                        ELSE GREATEST(0.0, EXTRACT(EPOCH FROM (NOW() - s.clock_in)) / 3600.0)
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
    location_customers = _historical_location_metadata(
        timesheet_data,
        "location_customers",
    )
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

        clock_out_display = "Needs review" if is_stale_open_entry(entry, now) else "Active"
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
        co_disp = "Needs review" if is_stale_open_entry(entry, now) else "Active"
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
        stale_open = get_stale_open_entry(
            timesheet_data["entries"], employee["id"], now_utc
        )
        if stale_open:
            return False, stale_shift_review_failure(stale_open, now_utc)
        existing_open = get_open_entry(timesheet_data["entries"], employee["id"])
        if existing_open:
            return False, "Already clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
            payload.gpsOverrideDetail,
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
            assert payload.latitude is not None and payload.longitude is not None
            entry["clockInGps"] = build_gps_point(
                payload.latitude, payload.longitude, payload.accuracy
            )
        entry["clockInGpsMeta"] = build_gps_meta(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
            payload.gpsOverrideDetail,
            payload.accuracy,
        )
        timesheet_data["entries"].append(entry)
        timesheet_data["nextId"] = entry_id + 1
        return True, entry

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "CLOCK_IN_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

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
        stale_open = get_stale_open_entry(
            timesheet_data["entries"], employee["id"], now_utc
        )
        if stale_open:
            return False, stale_shift_review_failure(stale_open, now_utc)
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry:
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
            payload.gpsOverrideDetail if payload else "",
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
            open_entry["clockOutGps"] = build_gps_point(
                payload.latitude, payload.longitude, payload.accuracy
            )
        open_entry["clockOutGpsMeta"] = build_gps_meta(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
            payload.gpsOverrideDetail if payload else "",
            payload.accuracy if payload else None,
        )

        return True, open_entry

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "CLOCK_OUT_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

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
        stale_open = get_stale_open_entry(
            timesheet_data["entries"], employee["id"], now_utc
        )
        if stale_open:
            return False, stale_shift_review_failure(stale_open, now_utc)
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry:
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude,
            payload.longitude,
            payload.gpsOverrideReason,
            payload.gpsOverrideDetail,
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
            "gps": build_gps_point(
                payload.latitude, payload.longitude, payload.accuracy
            ) if has_gps else None,
            "gpsMeta": build_gps_meta(
                timesheet_data,
                payload.latitude,
                payload.longitude,
                payload.gpsOverrideReason,
                payload.gpsOverrideDetail,
                payload.accuracy,
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
        raise_timesheet_mutation_failure(result)

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
        stale_open = get_stale_open_entry(
            timesheet_data["entries"], employee["id"], now_utc
        )
        if stale_open:
            return False, stale_shift_review_failure(stale_open, now_utc)
        open_entry = get_open_entry(timesheet_data["entries"], employee["id"])
        if not open_entry:
            return False, "Not currently clocked in"

        override_error = require_gps_override(
            timesheet_data,
            payload.latitude if payload else None,
            payload.longitude if payload else None,
            payload.gpsOverrideReason if payload else "",
            payload.gpsOverrideDetail if payload else "",
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
                payload.accuracy if payload else None,
            ),
        }
        if payload and payload.latitude is not None and payload.longitude is not None:
            departure["gps"] = build_gps_point(
                payload.latitude, payload.longitude, payload.accuracy
            )

        if not isinstance(open_entry.get("departures"), list):
            open_entry["departures"] = []
        open_entry["departures"].append(departure)

        if payload and payload.notes and not str(open_entry.get("notes", "")).strip():
            open_entry["notes"] = payload.notes.strip()

        return True, {"departure": departure, "entryId": open_entry["id"]}

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "DEPARTURE_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

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
    location_customers = _historical_location_metadata(
        timesheet_data,
        "location_customers",
    )
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

        clock_out_display = "Needs review" if is_stale_open_entry(entry, now) else "Active"
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
    company_date = utc_now().astimezone(ZoneInfo(TIMEZONE_NAME)).date().isoformat()
    site_rows = db.query_all(
        """
        SELECT id, address, customer_name, lat, lng,
               check_in_token_nonce IS NOT NULL AS qr_configured
        FROM locations
        WHERE active = true
        ORDER BY id
        """
    )
    sites = [
        {
            "id": int(row["id"]),
            "name": str(row["address"]),
            "customerName": str(row.get("customer_name") or ""),
            "latitude": float(row["lat"]) if row.get("lat") is not None else None,
            "longitude": float(row["lng"]) if row.get("lng") is not None else None,
            "qrConfigured": bool(row.get("qr_configured")),
        }
        for row in site_rows
    ]
    append_access_log(request, "LOCATIONS_SUCCESS", True, "Locations fetched")
    return {
        "success": True,
        "locations": payload["locations"],
        "sites": sites,
        "location_coords": payload["location_coords"],
        "location_customers": payload["location_customers"],
        "location_rates": payload["location_rates"],
        "location_rate_types": payload["location_rate_types"],
        "location_types": payload["location_types"],
        "location_frequencies": payload["location_frequencies"],
        "location_expected_hours": payload.get("location_expected_hours", {}),
        "locationMatchRadiusM": LOCATION_MATCH_RADIUS_M,
        "siteCheckInPolicy": {
            "geofenceRadiusM": SITE_CHECK_IN_RADIUS_M,
            "maxAccuracyM": SITE_CHECK_IN_MAX_ACCURACY_M,
            "deviceClockSkewReviewSeconds": SITE_CHECK_IN_DEVICE_SKEW_SECONDS,
            "scheduleTimezone": TIMEZONE_NAME,
            "companyDate": company_date,
            "offlineQueue": False,
        },
    }


CUSTOMER_SELECT_COLUMNS = """
    c.id, c.name, c.primary_contact_name, c.primary_phone, c.primary_email,
    c.billing_name, c.billing_email, c.billing_address, c.atlas_contact_id,
    c.active, c.created_at, c.updated_at, c.archived_at, c.archived_by
"""

SITE_SELECT_COLUMNS = """
    l.id, l.customer_id, l.address, l.address_key, l.customer_name,
    l.location_type, l.rate, l.rate_type, l.frequency, l.expected_hours,
    l.target_labor_pct, l.min_margin_pct, l.lat, l.lng, l.service_scope,
    l.access_instructions, l.service_preferences, l.pet_notes,
    l.service_start_date, l.check_in_token_nonce, l.active, l.created_at,
    l.updated_at, l.archived_at, l.archived_by,
    c.name AS canonical_customer_name
"""


def _raise_validation_error(message: str, fields: Dict[str, str]) -> None:
    raise HTTPException(
        status_code=422,
        detail={
            "code": "validation_error",
            "message": message,
            "details": {"fields": fields},
        },
    )


def _raise_conflict(code: str, message: str, details: Dict[str, Any]) -> None:
    raise HTTPException(
        status_code=409,
        detail={"code": code, "message": message, "details": details},
    )


def _site_required_checklist(row: Dict[str, Any]) -> Dict[str, bool]:
    return {
        "address": bool(str(row.get("address") or "").strip()),
        "locationType": row.get("location_type") in ("Residential", "Commercial"),
        "rate": row.get("rate") is not None,
        "rateType": row.get("rate_type") in ("per_visit", "hourly", "monthly"),
        "gps": row.get("lat") is not None and row.get("lng") is not None,
    }


def _site_optional_checklist(row: Dict[str, Any]) -> Dict[str, bool]:
    return {
        "frequency": bool(row.get("frequency")),
        "expectedHours": row.get("expected_hours") is not None,
        "profitabilityTargets": (
            row.get("target_labor_pct") is not None
            and row.get("min_margin_pct") is not None
        ),
        "serviceScope": bool(row.get("service_scope")),
        "accessInstructions": bool(row.get("access_instructions")),
        "servicePreferences": bool(row.get("service_preferences")),
        "petNotes": bool(row.get("pet_notes")),
        "serviceStartDate": row.get("service_start_date") is not None,
        "qr": bool(row.get("check_in_token_nonce")),
    }


def _site_status(row: Dict[str, Any]) -> str:
    if not bool(row.get("active")):
        return "archived"
    return "ready" if all(_site_required_checklist(row).values()) else "needs_setup"


def _serialize_site(row: Dict[str, Any]) -> Dict[str, Any]:
    required = _site_required_checklist(row)
    optional = _site_optional_checklist(row)
    migration_review: List[str] = []
    if row.get("customer_id") is None:
        migration_review.append("unlinked_customer")
    if row.get("address_key") is None:
        migration_review.append("duplicate_normalized_address")
    service_start = row.get("service_start_date")
    return {
        "id": int(row["id"]),
        "customerId": int(row["customer_id"]) if row.get("customer_id") is not None else None,
        "customerName": str(
            row.get("canonical_customer_name") or row.get("customer_name") or ""
        ),
        "address": str(row["address"]),
        "locationType": row.get("location_type"),
        "rate": float(row["rate"]) if row.get("rate") is not None else None,
        "rateType": row.get("rate_type"),
        "frequency": row.get("frequency"),
        "expectedHours": (
            float(row["expected_hours"])
            if row.get("expected_hours") is not None
            else None
        ),
        "targetLaborPct": (
            float(row["target_labor_pct"])
            if row.get("target_labor_pct") is not None
            else None
        ),
        "minMarginPct": (
            float(row["min_margin_pct"])
            if row.get("min_margin_pct") is not None
            else None
        ),
        "latitude": float(row["lat"]) if row.get("lat") is not None else None,
        "longitude": float(row["lng"]) if row.get("lng") is not None else None,
        "serviceScope": row.get("service_scope"),
        "accessInstructions": row.get("access_instructions"),
        "servicePreferences": row.get("service_preferences"),
        "petNotes": row.get("pet_notes"),
        "serviceStartDate": service_start.isoformat() if service_start else None,
        "qrConfigured": bool(row.get("check_in_token_nonce")),
        "active": bool(row.get("active")),
        "status": _site_status(row),
        "checklist": {"required": required, "optional": optional},
        "migrationReview": migration_review,
        "createdAt": to_utc_iso(row["created_at"]),
        "updatedAt": to_utc_iso(row["updated_at"]),
        "archivedAt": to_utc_iso(row["archived_at"]) if row.get("archived_at") else None,
        "archivedBy": int(row["archived_by"]) if row.get("archived_by") is not None else None,
    }


def _customer_status(row: Dict[str, Any], sites: List[Dict[str, Any]]) -> str:
    if not bool(row.get("active")):
        return "archived"
    active_sites = [site for site in sites if site["active"]]
    if not active_sites:
        return "draft"
    has_name = bool(str(row.get("name") or "").strip())
    return (
        "ready"
        if has_name and all(site["status"] == "ready" for site in active_sites)
        else "needs_setup"
    )


def _serialize_customer(row: Dict[str, Any], sites: List[Dict[str, Any]]) -> Dict[str, Any]:
    active_sites = [site for site in sites if site["active"]]
    required = {
        "name": bool(str(row.get("name") or "").strip()),
        "activeSite": bool(active_sites),
        "allActiveSitesReady": bool(active_sites)
        and all(site["status"] == "ready" for site in active_sites),
    }
    optional = {
        "primaryContact": bool(
            row.get("primary_contact_name")
            or row.get("primary_phone")
            or row.get("primary_email")
        ),
        "billing": bool(
            row.get("billing_name")
            or row.get("billing_email")
            or row.get("billing_address")
        ),
        "atlasContact": row.get("atlas_contact_id") is not None,
    }
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "primaryContactName": row.get("primary_contact_name"),
        "primaryPhone": row.get("primary_phone"),
        "primaryEmail": row.get("primary_email"),
        "billingName": row.get("billing_name"),
        "billingEmail": row.get("billing_email"),
        "billingAddress": row.get("billing_address"),
        "atlasContactId": (
            str(row["atlas_contact_id"])
            if row.get("atlas_contact_id") is not None
            else None
        ),
        "active": bool(row.get("active")),
        "status": _customer_status(row, sites),
        "siteCount": len(sites),
        "activeSiteCount": len(active_sites),
        "readySiteCount": sum(site["status"] == "ready" for site in active_sites),
        "checklist": {"required": required, "optional": optional},
        "sites": sites,
        "createdAt": to_utc_iso(row["created_at"]),
        "updatedAt": to_utc_iso(row["updated_at"]),
        "archivedAt": to_utc_iso(row["archived_at"]) if row.get("archived_at") else None,
        "archivedBy": int(row["archived_by"]) if row.get("archived_by") is not None else None,
    }


def _customer_row(cur: Any, customer_id: int, for_update: bool = False) -> Optional[Dict[str, Any]]:
    cur.execute(
        f"SELECT {CUSTOMER_SELECT_COLUMNS} FROM customers c WHERE c.id = %s"
        + (" FOR UPDATE" if for_update else ""),
        (customer_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def _site_row(cur: Any, site_id: int, for_update: bool = False) -> Optional[Dict[str, Any]]:
    cur.execute(
        f"""
        SELECT {SITE_SELECT_COLUMNS}
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE l.id = %s
        """
        + (" FOR UPDATE OF l" if for_update else ""),
        (site_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def _sites_for_customer(cur: Any, customer_id: int, include_archived: bool) -> List[Dict[str, Any]]:
    active_clause = "" if include_archived else " AND l.active = true"
    cur.execute(
        f"""
        SELECT {SITE_SELECT_COLUMNS}
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE l.customer_id = %s{active_clause}
        ORDER BY l.id
        """,
        (customer_id,),
    )
    return [_serialize_site(dict(row)) for row in cur.fetchall()]


def _canonical_customer(cur: Any, customer_id: int, include_archived_sites: bool = True) -> Dict[str, Any]:
    row = _customer_row(cur, customer_id)
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")
    return _serialize_customer(
        row,
        _sites_for_customer(cur, customer_id, include_archived_sites),
    )


def _canonical_site(cur: Any, site_id: int) -> Dict[str, Any]:
    row = _site_row(cur, site_id)
    if not row:
        raise HTTPException(status_code=404, detail="Location not found")
    return _serialize_site(row)


def _lock_address_and_find_conflicts(
    cur: Any,
    address: str,
    exclude_site_id: Optional[int] = None,
) -> str:
    address_key = normalize_site_address(address)
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (address_key,))
    cur.execute(
        """
        SELECT id, customer_id, address, address_key, active
        FROM locations
        WHERE (%s IS NULL OR id <> %s)
        ORDER BY active DESC, id
        """,
        (exclude_site_id, exclude_site_id),
    )
    conflicts = [
        dict(row)
        for row in cur.fetchall()
        if normalize_site_address(str(row["address"])) == address_key
    ]
    if conflicts:
        active_conflicts = [row for row in conflicts if bool(row["active"])]
        match = active_conflicts[0] if active_conflicts else conflicts[0]
        code = "duplicate_site_address" if active_conflicts else "archived_site_address"
        details = {
            "siteId": int(match["id"]),
            "customerId": (
                int(match["customer_id"])
                if match.get("customer_id") is not None
                else None
            ),
            "matchingSiteIds": [int(row["id"]) for row in conflicts],
            "canRestore": not bool(active_conflicts),
        }
        _raise_conflict(
            code,
            (
                "A job site already uses this address"
                if active_conflicts
                else "An archived job site already uses this address"
            ),
            details,
        )
    return address_key


def _active_customer_for_site(cur: Any, customer_id: int) -> Dict[str, Any]:
    customer = _customer_row(cur, customer_id, for_update=True)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not bool(customer["active"]):
        _raise_conflict(
            "customer_archived",
            "Restore the Customer before adding or restoring a Site",
            {"customerId": customer_id, "canRestore": True},
        )
    return customer


def _insert_customer(cur: Any, payload: CustomerCreateRequest) -> int:
    cur.execute(
        """
        INSERT INTO customers (
            name, primary_contact_name, primary_phone, primary_email,
            billing_name, billing_email, billing_address, atlas_contact_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            payload.name,
            payload.primaryContactName,
            payload.primaryPhone,
            payload.primaryEmail,
            payload.billingName,
            payload.billingEmail,
            payload.billingAddress,
            str(payload.atlasContactId) if payload.atlasContactId is not None else None,
        ),
    )
    return int(cur.fetchone()["id"])


def _insert_site(
    cur: Any,
    customer_id: Optional[int],
    customer_name: Optional[str],
    payload: PrimarySiteCreateRequest,
) -> int:
    address_key = _lock_address_and_find_conflicts(cur, payload.address)
    cur.execute(
        """
        INSERT INTO locations (
            customer_id, address, address_key, customer_name, location_type,
            rate, rate_type, frequency, expected_hours, target_labor_pct,
            min_margin_pct, lat, lng, service_scope, access_instructions,
            service_preferences, pet_notes, service_start_date
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        RETURNING id
        """,
        (
            customer_id,
            payload.address,
            address_key,
            customer_name,
            payload.locationType,
            payload.rate,
            payload.rateType,
            payload.frequency,
            payload.expectedHours,
            payload.targetLaborPct,
            payload.minMarginPct,
            payload.lat,
            payload.lng,
            payload.serviceScope,
            payload.accessInstructions,
            payload.servicePreferences,
            payload.petNotes,
            payload.serviceStartDate,
        ),
    )
    return int(cur.fetchone()["id"])


@app.get("/api/admin/customers")
def admin_list_customers(
    request: Request,
    includeArchived: bool = Query(default=False),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    active_clause = "" if includeArchived else " WHERE c.active = true"
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT {CUSTOMER_SELECT_COLUMNS} FROM customers c"
                f"{active_clause} ORDER BY lower(c.name), c.id"
            )
            rows = [dict(row) for row in cur.fetchall()]
            customers = [
                _serialize_customer(
                    row,
                    _sites_for_customer(cur, int(row["id"]), includeArchived),
                )
                for row in rows
            ]
    append_access_log(request, "CUSTOMERS_LISTED", True, f"{len(customers)} customers")
    return {"success": True, "customers": customers}


@app.post("/api/admin/customers", status_code=201)
def admin_create_customer(
    payload: CustomerCreateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            customer_id = _insert_customer(cur, payload)
            if payload.primarySite is not None:
                _insert_site(cur, customer_id, payload.name, payload.primarySite)
            customer = _canonical_customer(cur, customer_id)
    append_access_log(
        request,
        "CUSTOMER_CREATED",
        True,
        f"Customer {customer_id} by {admin['name']}",
    )
    return {"success": True, "customer": customer}


@app.get("/api/admin/customers/{customer_id}")
def admin_get_customer(
    customer_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            customer = _canonical_customer(cur, customer_id)
    append_access_log(request, "CUSTOMER_VIEWED", True, f"Customer {customer_id}")
    return {"success": True, "customer": customer}


@app.patch("/api/admin/customers/{customer_id}")
def admin_patch_customer(
    customer_id: int,
    payload: CustomerUpdateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    present = payload.model_fields_set
    if "name" in present and payload.name is None:
        _raise_validation_error("Customer name cannot be cleared", {"name": "required"})

    field_map = {
        "name": "name",
        "primaryContactName": "primary_contact_name",
        "primaryPhone": "primary_phone",
        "primaryEmail": "primary_email",
        "billingName": "billing_name",
        "billingEmail": "billing_email",
        "billingAddress": "billing_address",
        "atlasContactId": "atlas_contact_id",
    }
    values = payload.model_dump()
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _customer_row(cur, customer_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Customer not found")
            assignments: List[str] = []
            params: List[Any] = []
            for request_field, column in field_map.items():
                if request_field not in present:
                    continue
                assignments.append(f"{column} = %s")
                value = values[request_field]
                if request_field == "atlasContactId" and value is not None:
                    value = str(value)
                params.append(value)
            if assignments:
                assignments.append("updated_at = NOW()")
                params.append(customer_id)
                cur.execute(
                    f"UPDATE customers SET {', '.join(assignments)} WHERE id = %s",
                    tuple(params),
                )
            if "name" in present:
                cur.execute(
                    """
                    UPDATE locations
                    SET customer_name = %s, updated_at = NOW()
                    WHERE customer_id = %s
                    """,
                    (payload.name, customer_id),
                )
            customer = _canonical_customer(cur, customer_id)
    append_access_log(
        request,
        "CUSTOMER_UPDATED",
        True,
        f"Customer {customer_id} by {admin['name']}",
    )
    return {"success": True, "customer": customer}


@app.delete("/api/admin/customers/{customer_id}")
def admin_archive_customer(
    customer_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _customer_row(cur, customer_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Customer not found")
            if bool(existing["active"]):
                cur.execute(
                    """
                    SELECT id, address FROM locations
                    WHERE customer_id = %s AND active = true
                    ORDER BY id
                    FOR UPDATE
                    """,
                    (customer_id,),
                )
                active_sites = [dict(row) for row in cur.fetchall()]
                if active_sites:
                    _raise_conflict(
                        "customer_has_active_sites",
                        "Archive every active Site before archiving this Customer",
                        {
                            "customerId": customer_id,
                            "activeSites": [
                                {"id": int(site["id"]), "address": str(site["address"])}
                                for site in active_sites
                            ],
                        },
                    )
                cur.execute(
                    """
                    UPDATE customers
                    SET active = false, archived_at = NOW(), archived_by = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (admin["id"], customer_id),
                )
            customer = _canonical_customer(cur, customer_id)
    append_access_log(
        request,
        "CUSTOMER_ARCHIVED",
        True,
        f"Customer {customer_id} by {admin['name']}",
    )
    return {"success": True, "customer": customer}


@app.post("/api/admin/customers/{customer_id}/restore")
def admin_restore_customer(
    customer_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _customer_row(cur, customer_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Customer not found")
            if not bool(existing["active"]):
                cur.execute(
                    """
                    UPDATE customers
                    SET active = true, archived_at = NULL, archived_by = NULL,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (customer_id,),
                )
            customer = _canonical_customer(cur, customer_id)
    append_access_log(
        request,
        "CUSTOMER_RESTORED",
        True,
        f"Customer {customer_id} by {admin['name']}",
    )
    return {"success": True, "customer": customer}


@app.post("/api/admin/customers/{customer_id}/locations", status_code=201)
def admin_create_customer_site(
    customer_id: int,
    payload: PrimarySiteCreateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            customer_row = _active_customer_for_site(cur, customer_id)
            site_id = _insert_site(cur, customer_id, str(customer_row["name"]), payload)
            location = _canonical_site(cur, site_id)
    append_access_log(
        request,
        "LOCATION_CREATED",
        True,
        f"Location {site_id} for Customer {customer_id} by {admin['name']}",
    )
    return {"success": True, "location": location}


@app.get("/api/admin/locations")
def admin_list_locations(
    request: Request,
    includeArchived: bool = Query(default=False),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    active_clause = "" if includeArchived else " WHERE l.active = true"
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT {SITE_SELECT_COLUMNS}
                FROM locations l
                LEFT JOIN customers c ON c.id = l.customer_id
                {active_clause}
                ORDER BY l.id
                """
            )
            locations = [_serialize_site(dict(row)) for row in cur.fetchall()]
    append_access_log(request, "LOCATIONS_LISTED", True, f"{len(locations)} locations")
    return {"success": True, "locations": locations}


@app.post("/api/admin/locations", status_code=201)
def admin_create_location(
    payload: SiteCreateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    if payload.customerId is None and payload.customerName is None:
        _raise_validation_error(
            "A Customer is required",
            {"customerId": "customerId or customerName is required"},
        )

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            if payload.customerId is not None:
                customer_row = _active_customer_for_site(cur, payload.customerId)
                customer_id = payload.customerId
                customer_name = str(customer_row["name"])
                if (
                    payload.customerName is not None
                    and payload.customerName != customer_name
                ):
                    _raise_validation_error(
                        "customerId and customerName identify different Customers",
                        {"customerName": "must match the selected Customer"},
                    )
            else:
                new_customer = CustomerCreateRequest(name=payload.customerName)
                customer_id = _insert_customer(cur, new_customer)
                customer_name = str(payload.customerName)
            site_id = _insert_site(cur, customer_id, customer_name, payload)
            location = _canonical_site(cur, site_id)
    append_access_log(
        request,
        "LOCATION_CREATED",
        True,
        f"Location {site_id} by {admin['name']}",
    )
    return {"success": True, "location": location}


@app.put("/api/admin/locations")
def admin_update_locations(
    payload: Dict[str, Any],
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    raw = payload.get("locations")
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail="locations must be a list")

    direct_fields = (
        "lat",
        "lng",
        "rate",
        "rateType",
        "frequency",
        "expectedHours",
        "targetLaborPct",
        "minMarginPct",
    )
    update_column_map = {
        "locationType": "location_type",
        "rate": "rate",
        "rateType": "rate_type",
        "frequency": "frequency",
        "expectedHours": "expected_hours",
        "targetLaborPct": "target_labor_pct",
        "minMarginPct": "min_margin_pct",
        "lat": "lat",
        "lng": "lng",
    }

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            for index, item in enumerate(raw):
                if isinstance(item, str):
                    address = item.strip()
                    patch_data: Dict[str, Any] = {}
                elif isinstance(item, dict):
                    if "address" in item:
                        address_value = item.get("address")
                    else:
                        address_value = item.get("name")
                    address = (
                        address_value.strip()
                        if isinstance(address_value, str)
                        else ""
                    )
                    patch_data = {}
                    if "customerName" in item:
                        patch_data["customerName"] = item.get("customerName")
                    elif "customer" in item:
                        patch_data["customerName"] = item.get("customer")
                    if "locationType" in item:
                        patch_data["locationType"] = item.get("locationType")
                    elif "type" in item:
                        patch_data["locationType"] = item.get("type")
                    for field in direct_fields:
                        if field in item:
                            patch_data[field] = item.get(field)
                else:
                    _raise_validation_error(
                        "Each location must be an address string or object",
                        {f"locations.{index}": "invalid entry"},
                    )

                if not address:
                    _raise_validation_error(
                        "Every legacy location entry requires an address",
                        {f"locations.{index}.address": "required"},
                    )
                if len(address) > SITE_ADDRESS_MAX_LENGTH:
                    _raise_validation_error(
                        "Location address is too long",
                        {
                            f"locations.{index}.address": (
                                f"must be at most {SITE_ADDRESS_MAX_LENGTH} characters"
                            )
                        },
                    )

                try:
                    validated = SiteUpdateRequest(**patch_data)
                except ValidationError as exc:
                    fields = {
                        f"locations.{index}."
                        + (".".join(str(part) for part in error.get("loc", ())) or "body"):
                        str(error.get("msg", "Invalid value"))
                        for error in exc.errors()
                    }
                    _raise_validation_error(next(iter(fields.values())), fields)
                present = validated.model_fields_set
                values = validated.model_dump()
                for field in ("customerName", "locationType", "rateType"):
                    if field in present and values[field] is None:
                        _raise_validation_error(
                            f"{field} cannot be cleared",
                            {f"locations.{index}.{field}": "cannot be cleared"},
                        )

                cur.execute(
                    "SELECT id FROM locations WHERE address = %s FOR UPDATE",
                    (address,),
                )
                existing_id_row = cur.fetchone()
                if not existing_id_row:
                    address_key = _lock_address_and_find_conflicts(cur, address)
                    customer_id: Optional[int] = None
                    customer_name = values.get("customerName") if "customerName" in present else None
                    if customer_name:
                        cur.execute(
                            "INSERT INTO customers (name) VALUES (%s) RETURNING id",
                            (customer_name,),
                        )
                        customer_id = int(cur.fetchone()["id"])
                    lat = values.get("lat") if "lat" in present else None
                    lng = values.get("lng") if "lng" in present else None
                    if (lat is None) != (lng is None):
                        _raise_validation_error(
                            "lat and lng must be provided or cleared together",
                            {
                                f"locations.{index}.lat": "coordinate pair required",
                                f"locations.{index}.lng": "coordinate pair required",
                            },
                        )
                    cur.execute(
                        """
                        INSERT INTO locations (
                            customer_id, address, address_key, customer_name,
                            location_type, rate, rate_type, frequency,
                            expected_hours, target_labor_pct, min_margin_pct,
                            lat, lng
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            customer_id,
                            address,
                            address_key,
                            customer_name,
                            values.get("locationType") if "locationType" in present else None,
                            values.get("rate") if "rate" in present else None,
                            values.get("rateType") if "rateType" in present else "per_visit",
                            values.get("frequency") if "frequency" in present else None,
                            values.get("expectedHours") if "expectedHours" in present else None,
                            values.get("targetLaborPct") if "targetLaborPct" in present else None,
                            values.get("minMarginPct") if "minMarginPct" in present else None,
                            lat,
                            lng,
                        ),
                    )
                    continue

                site_id = int(existing_id_row["id"])
                existing = _site_row(cur, site_id)
                if not existing:
                    raise RuntimeError("Location disappeared during legacy update")

                if "customerName" in present:
                    customer_name = str(values["customerName"])
                    customer_id = existing.get("customer_id")
                    if customer_id is None:
                        cur.execute(
                            "INSERT INTO customers (name) VALUES (%s) RETURNING id",
                            (customer_name,),
                        )
                        customer_id = int(cur.fetchone()["id"])
                        cur.execute(
                            """
                            UPDATE locations
                            SET customer_id = %s, customer_name = %s,
                                updated_at = NOW()
                            WHERE id = %s
                            """,
                            (customer_id, customer_name, site_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE customers SET name = %s, updated_at = NOW() WHERE id = %s",
                            (customer_name, customer_id),
                        )
                        cur.execute(
                            """
                            UPDATE locations
                            SET customer_name = %s, updated_at = NOW()
                            WHERE customer_id = %s
                            """,
                            (customer_name, customer_id),
                        )

                merged_lat = values["lat"] if "lat" in present else existing.get("lat")
                merged_lng = values["lng"] if "lng" in present else existing.get("lng")
                if (merged_lat is None) != (merged_lng is None):
                    _raise_validation_error(
                        "lat and lng must be provided or cleared together",
                        {
                            f"locations.{index}.lat": "coordinate pair required",
                            f"locations.{index}.lng": "coordinate pair required",
                        },
                    )

                assignments: List[str] = []
                params: List[Any] = []
                for request_field, column in update_column_map.items():
                    if request_field not in present:
                        continue
                    assignments.append(f"{column} = %s")
                    params.append(values[request_field])
                if assignments:
                    assignments.append("updated_at = NOW()")
                    params.append(site_id)
                    cur.execute(
                        f"UPDATE locations SET {', '.join(assignments)} WHERE id = %s",
                        tuple(params),
                    )

    canonical = load_timesheets()
    append_access_log(
        request,
        "LOCATIONS_UPDATED",
        True,
        f"{len(raw)} legacy entries by {admin['name']}",
    )
    return {
        "success": True,
        "locations": canonical["locations"],
        "location_coords": canonical["location_coords"],
        "location_customers": canonical["location_customers"],
        "location_rates": canonical["location_rates"],
        "location_rate_types": canonical["location_rate_types"],
        "location_types": canonical["location_types"],
        "location_frequencies": canonical["location_frequencies"],
        "location_expected_hours": canonical.get("location_expected_hours", {}),
        "location_target_labor": canonical.get("location_target_labor", {}),
        "location_min_margin": canonical.get("location_min_margin", {}),
    }


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
    if not -90 <= lat <= 90 or not -180 <= lng <= 180:
        raise HTTPException(status_code=400, detail="lat or lng is outside the valid range")

    updated = db.query_one(
        """
        UPDATE locations
        SET lat = %s, lng = %s, updated_at = NOW()
        WHERE address = %s AND active = true
        RETURNING id
        """,
        (lat, lng, location),
    )
    if not updated:
        raise HTTPException(status_code=400, detail="Location not found")

    append_access_log(request, "LOCATION_PIN_SET", True, f"Pin set for: {location}")
    return {"success": True}


@app.patch("/api/admin/locations/{site_id}")
def admin_patch_location(
    site_id: int,
    payload: SiteUpdateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    present = payload.model_fields_set
    required_fields = {
        "customerId": payload.customerId,
        "customerName": payload.customerName,
        "address": payload.address,
        "locationType": payload.locationType,
        "rateType": payload.rateType,
    }
    cleared_required = {
        field: "cannot be cleared"
        for field, value in required_fields.items()
        if field in present and value is None
    }
    if cleared_required:
        _raise_validation_error("Required Site fields cannot be cleared", cleared_required)

    values = payload.model_dump()
    site_field_map = {
        "address": "address",
        "locationType": "location_type",
        "rate": "rate",
        "rateType": "rate_type",
        "frequency": "frequency",
        "expectedHours": "expected_hours",
        "targetLaborPct": "target_labor_pct",
        "minMarginPct": "min_margin_pct",
        "lat": "lat",
        "lng": "lng",
        "serviceScope": "service_scope",
        "accessInstructions": "access_instructions",
        "servicePreferences": "service_preferences",
        "petNotes": "pet_notes",
        "serviceStartDate": "service_start_date",
    }

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _site_row(cur, site_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Location not found")

            assignments: List[str] = []
            params: List[Any] = []
            customer_id = existing.get("customer_id")
            customer_name = str(
                existing.get("canonical_customer_name")
                or existing.get("customer_name")
                or ""
            )

            if "customerId" in present:
                target_customer = _active_customer_for_site(cur, int(payload.customerId))
                target_name = str(target_customer["name"])
                if "customerName" in present and payload.customerName != target_name:
                    _raise_validation_error(
                        "customerId and customerName identify different Customers",
                        {"customerName": "must match the selected Customer"},
                    )
                customer_id = int(payload.customerId)
                customer_name = target_name
                assignments.extend(["customer_id = %s", "customer_name = %s"])
                params.extend([customer_id, customer_name])
            elif "customerName" in present:
                if customer_id is None:
                    _raise_validation_error(
                        "Select a Customer before renaming this unlinked legacy Site",
                        {"customerId": "required for an unlinked Site"},
                    )
                target_customer = _customer_row(cur, int(customer_id), for_update=True)
                if not target_customer:
                    raise HTTPException(status_code=404, detail="Customer not found")
                customer_name = str(payload.customerName)
                cur.execute(
                    """
                    UPDATE customers
                    SET name = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (customer_name, customer_id),
                )
                cur.execute(
                    """
                    UPDATE locations
                    SET customer_name = %s, updated_at = NOW()
                    WHERE customer_id = %s
                    """,
                    (customer_name, customer_id),
                )

            if "address" in present:
                address_key = _lock_address_and_find_conflicts(
                    cur,
                    str(payload.address),
                    exclude_site_id=site_id,
                )
                assignments.extend(["address = %s", "address_key = %s"])
                params.extend([payload.address, address_key])

            merged_lat = values["lat"] if "lat" in present else existing.get("lat")
            merged_lng = values["lng"] if "lng" in present else existing.get("lng")
            if (merged_lat is None) != (merged_lng is None):
                _raise_validation_error(
                    "lat and lng must be provided or cleared together",
                    {"lat": "coordinate pair required", "lng": "coordinate pair required"},
                )

            for request_field, column in site_field_map.items():
                if request_field not in present or request_field == "address":
                    continue
                assignments.append(f"{column} = %s")
                params.append(values[request_field])

            if assignments:
                assignments.append("updated_at = NOW()")
                params.append(site_id)
                cur.execute(
                    f"UPDATE locations SET {', '.join(assignments)} WHERE id = %s",
                    tuple(params),
                )
            location = _canonical_site(cur, site_id)

    append_access_log(
        request,
        "LOCATION_UPDATED",
        True,
        f"Location {site_id} by {admin['name']}",
    )
    return {"success": True, "location": location}


@app.delete("/api/admin/locations/{site_id}")
def admin_archive_location(
    site_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    archived_at = utc_now()
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _site_row(cur, site_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Location not found")
            if bool(existing["active"]):
                cur.execute(
                    """
                    UPDATE locations
                    SET active = false, archived_at = %s, archived_by = %s,
                        check_in_token_nonce = NULL,
                        check_in_token_rotated_at = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (archived_at, admin["id"], archived_at, archived_at, site_id),
                )
                cur.execute(
                    """
                    UPDATE site_check_in_schedule_rules
                    SET active = false, updated_at = %s
                    WHERE location_id = %s AND active = true
                    """,
                    (archived_at, site_id),
                )
                cur.execute(
                    """
                    UPDATE site_check_in_schedules
                    SET cancelled_at = %s, cancelled_by = %s,
                        cancellation_reason = 'site_archived'
                    WHERE location_id = %s
                      AND scheduled_start > %s
                      AND cancelled_at IS NULL
                    """,
                    (archived_at, admin["id"], site_id, archived_at),
                )
            location = _canonical_site(cur, site_id)

    append_access_log(
        request,
        "LOCATION_ARCHIVED",
        True,
        f"Location {site_id} by {admin['name']}",
    )
    return {"success": True, "location": location}


@app.post("/api/admin/locations/{site_id}/restore")
def admin_restore_location(
    site_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    restored_at = utc_now()
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _site_row(cur, site_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Location not found")
            customer_id = existing.get("customer_id")
            if customer_id is None:
                _raise_conflict(
                    "customer_archived",
                    "Assign this legacy Site to an active Customer before restoring it",
                    {"customerId": None, "siteId": site_id, "canRestore": False},
                )
            _active_customer_for_site(cur, int(customer_id))
            if not bool(existing["active"]):
                address_key = _lock_address_and_find_conflicts(
                    cur,
                    str(existing["address"]),
                    exclude_site_id=site_id,
                )
                cur.execute(
                    """
                    UPDATE locations
                    SET active = true, archived_at = NULL, archived_by = NULL,
                        address_key = %s, check_in_token_nonce = NULL,
                        check_in_token_rotated_at = %s, updated_at = %s
                    WHERE id = %s
                    """,
                    (address_key, restored_at, restored_at, site_id),
                )
            location = _canonical_site(cur, site_id)

    append_access_log(
        request,
        "LOCATION_RESTORED",
        True,
        f"Location {site_id} by {admin['name']}",
    )
    return {"success": True, "location": location}


@app.get("/api/timesheet/current-status")
def timesheet_current_status(
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    timesheet_data = load_timesheets()
    now_utc = utc_now()
    own_stale_open = get_stale_open_entry(
        timesheet_data.get("entries", []), int(employee["id"]), now_utc
    )
    rows = build_public_current_status(timesheet_data)
    if employee.get("role") != "admin":
        rows = (
            []
            if own_stale_open
            else [row for row in rows if int(row.get("id", 0)) == int(employee["id"])]
        )
    stale_open_shift = (
        stale_open_shift_summary(own_stale_open, now_utc)
        if own_stale_open
        else None
    )
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
    return {
        "success": True,
        "currentlyWorking": response_rows,
        "staleOpenShift": stale_open_shift,
    }


@app.get("/api/hours")
def dashboard_hours(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
    denied_response = enforce_dashboard_access(request)
    if denied_response is not None:
        return denied_response

    payload = build_dashboard_hours_data()
    return {"success": True, "data": payload, "timestamp": to_utc_iso(utc_now())}


@app.get("/api/current-status")
def dashboard_current_status(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Any:
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


def build_time_data_audit() -> Dict[str, Any]:
    """Inspect shift integrity without mutating operational data."""
    duplicate_rows = db.query_all(
        """
        SELECT
            e.id AS employee_id,
            e.name AS employee_name,
            COALESCE(l.address, s.location_label, '') AS location,
            s.clock_in,
            s.clock_out,
            ARRAY_AGG(s.id ORDER BY s.id) AS shift_ids,
            COUNT(*) AS copies
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        LEFT JOIN locations l ON l.id = s.location_id
        GROUP BY
            e.id,
            e.name,
            COALESCE(l.address, s.location_label, ''),
            s.clock_in,
            s.clock_out
        HAVING COUNT(*) > 1
        ORDER BY s.clock_in, e.name
        """
    )
    open_conflict_rows = db.query_all(
        """
        SELECT
            e.id AS employee_id,
            e.name AS employee_name,
            ARRAY_AGG(s.id ORDER BY s.clock_in, s.id) AS shift_ids,
            MIN(s.clock_in) AS oldest_clock_in,
            MAX(s.clock_in) AS newest_clock_in,
            COUNT(*) AS open_shift_count
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE s.clock_out IS NULL
        GROUP BY e.id, e.name
        HAVING COUNT(*) > 1
        ORDER BY e.name
        """
    )
    stale_rows = db.query_all(
        """
        SELECT
            s.id AS shift_id,
            e.id AS employee_id,
            e.name AS employee_name,
            COALESCE(l.address, s.location_label, '') AS location,
            s.clock_in,
            ROUND(
                (EXTRACT(EPOCH FROM (NOW() - s.clock_in)) / 3600.0)::numeric,
                2
            ) AS age_hours
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        LEFT JOIN locations l ON l.id = s.location_id
        WHERE
            s.clock_out IS NULL
            AND s.clock_in < NOW() - (%s * INTERVAL '1 hour')
        ORDER BY s.clock_in, e.name
        """,
        (MAX_ACTIVE_SHIFT_HOURS,),
    )

    duplicate_groups = [
        {
            "employeeId": int(row["employee_id"]),
            "employeeName": row["employee_name"],
            "location": row.get("location") or "",
            "clockIn": to_utc_iso(row["clock_in"]),
            "clockOut": to_utc_iso(row["clock_out"]) if row.get("clock_out") else None,
            "shiftIds": [int(value) for value in row.get("shift_ids") or []],
            "copies": int(row["copies"]),
        }
        for row in duplicate_rows
    ]
    multiple_open_shift_employees = [
        {
            "employeeId": int(row["employee_id"]),
            "employeeName": row["employee_name"],
            "shiftIds": [int(value) for value in row.get("shift_ids") or []],
            "openShiftCount": int(row["open_shift_count"]),
            "oldestClockIn": to_utc_iso(row["oldest_clock_in"]),
            "newestClockIn": to_utc_iso(row["newest_clock_in"]),
        }
        for row in open_conflict_rows
    ]
    stale_open_shifts = [
        {
            "shiftId": int(row["shift_id"]),
            "employeeId": int(row["employee_id"]),
            "employeeName": row["employee_name"],
            "location": row.get("location") or "",
            "clockIn": to_utc_iso(row["clock_in"]),
            "ageHours": float(row["age_hours"]),
        }
        for row in stale_rows
    ]

    return {
        "success": True,
        "databaseReadOnly": True,
        "generatedAt": to_utc_iso(utc_now()),
        "staleShiftThresholdHours": MAX_ACTIVE_SHIFT_HOURS,
        "summary": {
            "duplicateShiftGroups": len(duplicate_groups),
            "duplicateExtraShifts": sum(row["copies"] - 1 for row in duplicate_groups),
            "employeesWithMultipleOpenShifts": len(multiple_open_shift_employees),
            "staleOpenShifts": len(stale_open_shifts),
        },
        "duplicateShiftGroups": duplicate_groups,
        "multipleOpenShiftEmployees": multiple_open_shift_employees,
        "staleOpenShifts": stale_open_shifts,
    }


def _correction_query_all(
    sql: str,
    params: tuple = (),
    cursor: Any = None,
) -> List[Dict[str, Any]]:
    if cursor is None:
        return db.query_all(sql, params)
    cursor.execute(sql, params)
    return [dict(row) for row in cursor.fetchall()]


def _correction_shift_snapshots(
    shift_ids: List[int],
    cursor: Any = None,
    lock_shifts: bool = False,
) -> List[Dict[str, Any]]:
    ids = sorted({int(value) for value in shift_ids})
    if not ids:
        return []

    lock_clause = " FOR UPDATE OF s" if lock_shifts and cursor is not None else ""
    shift_rows = _correction_query_all(
        """
        SELECT
            s.id,
            s.employee_id,
            e.name AS employee_name,
            s.location_id,
            COALESCE(l.address, s.location_label, '') AS effective_location,
            s.location_label,
            s.clock_in,
            s.clock_out,
            s.total_hours,
            s.notes,
            s.local_date,
            s.timezone,
            s.clock_in_gps,
            s.clock_in_gps_meta,
            s.clock_out_gps,
            s.clock_out_gps_meta,
            s.job_id,
            s.time_category,
            s.non_productive_type,
            s.created_at
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        LEFT JOIN locations l ON l.id = s.location_id
        WHERE s.id = ANY(%s)
        ORDER BY s.id
        """ + lock_clause,
        (ids,),
        cursor,
    )
    visit_rows = _correction_query_all(
        """
        SELECT
            v.id,
            v.shift_id,
            v.location_id,
            COALESCE(l.address, v.location_label, '') AS effective_location,
            v.location_label,
            v.customer_name,
            v.arrival_time,
            v.gps,
            v.gps_meta,
            v.created_at
        FROM visits v
        LEFT JOIN locations l ON l.id = v.location_id
        WHERE v.shift_id = ANY(%s)
        ORDER BY v.shift_id, v.arrival_time, v.id
        """,
        (ids,),
        cursor,
    )
    departure_rows = _correction_query_all(
        """
        SELECT
            d.id,
            d.shift_id,
            d.location_id,
            COALESCE(l.address, d.location_label, '') AS effective_location,
            d.location_label,
            d.customer_name,
            d.departure_time,
            d.gps,
            d.gps_meta,
            d.created_at
        FROM departures d
        LEFT JOIN locations l ON l.id = d.location_id
        WHERE d.shift_id = ANY(%s)
        ORDER BY d.shift_id, d.departure_time, d.id
        """,
        (ids,),
        cursor,
    )

    visits_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for row in visit_rows:
        visits_by_shift.setdefault(int(row["shift_id"]), []).append({
            "id": int(row["id"]),
            "shiftId": int(row["shift_id"]),
            "locationId": int(row["location_id"]) if row.get("location_id") is not None else None,
            "location": row.get("effective_location") or "",
            "locationLabel": row.get("location_label") or "",
            "customerName": row.get("customer_name") or "",
            "arrivalTime": to_utc_iso(row["arrival_time"]),
            "gps": row.get("gps"),
            "gpsMeta": row.get("gps_meta"),
            "createdAt": to_utc_iso(row["created_at"]),
        })

    departures_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for row in departure_rows:
        departures_by_shift.setdefault(int(row["shift_id"]), []).append({
            "id": int(row["id"]),
            "shiftId": int(row["shift_id"]),
            "locationId": int(row["location_id"]) if row.get("location_id") is not None else None,
            "location": row.get("effective_location") or "",
            "locationLabel": row.get("location_label") or "",
            "customerName": row.get("customer_name") or "",
            "departureTime": to_utc_iso(row["departure_time"]),
            "gps": row.get("gps"),
            "gpsMeta": row.get("gps_meta"),
            "createdAt": to_utc_iso(row["created_at"]),
        })

    snapshots = []
    for row in shift_rows:
        shift_id = int(row["id"])
        snapshots.append({
            "id": shift_id,
            "employeeId": int(row["employee_id"]),
            "employeeName": row["employee_name"],
            "locationId": int(row["location_id"]) if row.get("location_id") is not None else None,
            "location": row.get("effective_location") or "",
            "locationLabel": row.get("location_label") or "",
            "clockIn": to_utc_iso(row["clock_in"]),
            "clockOut": to_utc_iso(row["clock_out"]) if row.get("clock_out") else None,
            "totalHours": float(row["total_hours"]) if row.get("total_hours") is not None else None,
            "notes": row.get("notes") or "",
            "localDate": str(row["local_date"]) if row.get("local_date") else None,
            "timezone": row.get("timezone") or TIMEZONE_NAME,
            "clockInGps": row.get("clock_in_gps"),
            "clockInGpsMeta": row.get("clock_in_gps_meta"),
            "clockOutGps": row.get("clock_out_gps"),
            "clockOutGpsMeta": row.get("clock_out_gps_meta"),
            "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
            "timeCategory": row.get("time_category") or "productive",
            "nonProductiveType": row.get("non_productive_type"),
            "createdAt": to_utc_iso(row["created_at"]),
            "visits": visits_by_shift.get(shift_id, []),
            "departures": departures_by_shift.get(shift_id, []),
        })
    return snapshots


def _correction_metadata_signature(snapshot: Dict[str, Any]) -> str:
    comparable = {
        key: value
        for key, value in snapshot.items()
        if key not in {"id", "createdAt", "employeeName", "visits", "departures"}
    }
    comparable["visits"] = [
        {
            key: value
            for key, value in row.items()
            if key not in {"id", "shiftId", "createdAt"}
        }
        for row in snapshot.get("visits", [])
    ]
    comparable["departures"] = [
        {
            key: value
            for key, value in row.items()
            if key not in {"id", "shiftId", "createdAt"}
        }
        for row in snapshot.get("departures", [])
    ]
    return json.dumps(comparable, sort_keys=True, separators=(",", ":"))


def _correction_richness_score(snapshot: Dict[str, Any]) -> int:
    score = 10 * (len(snapshot.get("visits", [])) + len(snapshot.get("departures", [])))
    score += 8 if snapshot.get("jobId") is not None else 0
    score += 4 if str(snapshot.get("notes") or "").strip() else 0
    score += 3 if snapshot.get("timeCategory") != "productive" else 0
    score += sum(
        1
        for key in ("clockInGps", "clockInGpsMeta", "clockOutGps", "clockOutGpsMeta")
        if snapshot.get(key)
    )
    return score


def build_time_data_correction_inventory(
    cursor: Any = None,
    lock_shifts: bool = False,
) -> Dict[str, Any]:
    """Return correction candidates and their complete, recoverable metadata."""
    duplicate_rows = _correction_query_all(
        """
        SELECT
            e.id AS employee_id,
            e.name AS employee_name,
            COALESCE(l.address, s.location_label, '') AS location,
            s.clock_in,
            s.clock_out,
            ARRAY_AGG(s.id ORDER BY s.id) AS shift_ids,
            COUNT(*) AS copies
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        LEFT JOIN locations l ON l.id = s.location_id
        GROUP BY
            e.id,
            e.name,
            COALESCE(l.address, s.location_label, ''),
            s.clock_in,
            s.clock_out
        HAVING COUNT(*) > 1
        ORDER BY s.clock_in, e.name
        """,
        cursor=cursor,
    )
    stale_rows = _correction_query_all(
        """
        SELECT
            s.id AS shift_id,
            ROUND(
                (EXTRACT(EPOCH FROM (NOW() - s.clock_in)) / 3600.0)::numeric,
                2
            ) AS age_hours
        FROM shifts s
        WHERE
            s.clock_out IS NULL
            AND s.clock_in < NOW() - (%s * INTERVAL '1 hour')
        ORDER BY s.clock_in, s.id
        """,
        (MAX_ACTIVE_SHIFT_HOURS,),
        cursor,
    )

    candidate_ids: List[int] = []
    for row in duplicate_rows:
        candidate_ids.extend(int(value) for value in row.get("shift_ids") or [])
    candidate_ids.extend(int(row["shift_id"]) for row in stale_rows)
    snapshots = _correction_shift_snapshots(
        candidate_ids,
        cursor=cursor,
        lock_shifts=lock_shifts,
    )
    snapshot_by_id = {int(row["id"]): row for row in snapshots}

    duplicate_groups = []
    for row in duplicate_rows:
        shift_ids = [int(value) for value in row.get("shift_ids") or []]
        group_shifts = [snapshot_by_id[value] for value in shift_ids if value in snapshot_by_id]
        recommended = max(
            group_shifts,
            key=lambda item: (_correction_richness_score(item), -int(item["id"])),
        )
        signatures = {_correction_metadata_signature(item) for item in group_shifts}
        group_key = json.dumps(
            {
                "employeeId": int(row["employee_id"]),
                "location": row.get("location") or "",
                "clockIn": to_utc_iso(row["clock_in"]),
                "clockOut": to_utc_iso(row["clock_out"]) if row.get("clock_out") else None,
                "shiftIds": shift_ids,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        duplicate_groups.append({
            "groupId": hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:16],
            "employeeId": int(row["employee_id"]),
            "employeeName": row["employee_name"],
            "location": row.get("location") or "",
            "clockIn": to_utc_iso(row["clock_in"]),
            "clockOut": to_utc_iso(row["clock_out"]) if row.get("clock_out") else None,
            "shiftIds": shift_ids,
            "copies": int(row["copies"]),
            "recommendedCanonicalShiftId": int(recommended["id"]),
            "metadataConsistent": len(signatures) == 1,
            "shifts": group_shifts,
        })

    stale_open_shifts = []
    for row in stale_rows:
        shift_id = int(row["shift_id"])
        snapshot = snapshot_by_id.get(shift_id)
        if not snapshot:
            continue
        stale_open_shifts.append({
            **snapshot,
            "shiftId": shift_id,
            "ageHours": float(row["age_hours"]),
        })

    version_material = {
        "duplicateGroups": duplicate_groups,
        "staleOpenShifts": [
            {key: value for key, value in row.items() if key != "ageHours"}
            for row in stale_open_shifts
        ],
    }
    inventory_version = hashlib.sha256(
        json.dumps(version_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "success": True,
        "databaseReadOnly": True,
        "generatedAt": to_utc_iso(utc_now()),
        "staleShiftThresholdHours": MAX_ACTIVE_SHIFT_HOURS,
        "inventoryVersion": inventory_version,
        "summary": {
            "duplicateShiftGroups": len(duplicate_groups),
            "duplicateExtraShifts": sum(row["copies"] - 1 for row in duplicate_groups),
            "staleOpenShifts": len(stale_open_shifts),
        },
        "duplicateGroups": duplicate_groups,
        "staleOpenShifts": stale_open_shifts,
    }


def _parse_correction_clock_out(value: str) -> datetime:
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Clock-out must be a valid ISO date and time",
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=APP_TIMEZONE)
    return parsed.astimezone(timezone.utc)


def _build_time_data_correction_plan(
    payload: TimeDataCorrectionPlanRequest,
    cursor: Any = None,
    lock_shifts: bool = False,
) -> Dict[str, Any]:
    reason = payload.reason.strip()
    if len(reason) < 10:
        raise HTTPException(status_code=400, detail="Correction reason must be at least 10 characters")
    if not payload.duplicateResolutions and not payload.staleShiftClosures:
        raise HTTPException(status_code=400, detail="Select at least one correction")

    inventory = build_time_data_correction_inventory(cursor=cursor, lock_shifts=lock_shifts)
    group_by_ids = {
        tuple(sorted(int(value) for value in group["shiftIds"])): group
        for group in inventory["duplicateGroups"]
    }
    stale_by_id = {
        int(row["shiftId"]): row
        for row in inventory["staleOpenShifts"]
    }

    normalized_duplicates = []
    delete_ids: set[int] = set()
    selected_group_ids: set[int] = set()
    for resolution in payload.duplicateResolutions:
        canonical_id = int(resolution.canonicalShiftId)
        duplicates = [int(value) for value in resolution.duplicateShiftIds]
        if len(duplicates) != len(set(duplicates)):
            raise HTTPException(status_code=400, detail="Duplicate shift IDs must be unique")
        if canonical_id in duplicates:
            raise HTTPException(status_code=400, detail="The canonical shift cannot also be deleted")
        group_ids = tuple(sorted({canonical_id, *duplicates}))
        group = group_by_ids.get(group_ids)
        if not group:
            raise HTTPException(
                status_code=409,
                detail="A duplicate group changed; reload the correction inventory",
            )
        if delete_ids.intersection(duplicates) or selected_group_ids.intersection(group_ids):
            raise HTTPException(status_code=400, detail="A duplicate group was selected more than once")
        delete_ids.update(duplicates)
        selected_group_ids.update(group_ids)
        normalized_duplicates.append({
            "groupId": group["groupId"],
            "employeeName": group["employeeName"],
            "canonicalShiftId": canonical_id,
            "duplicateShiftIds": sorted(duplicates),
            "metadataConsistent": bool(group["metadataConsistent"]),
        })

    normalized_closures = []
    closure_ids: set[int] = set()
    now = utc_now()
    for closure in payload.staleShiftClosures:
        shift_id = int(closure.shiftId)
        if shift_id in closure_ids:
            raise HTTPException(status_code=400, detail="A stale shift was selected more than once")
        if shift_id in delete_ids:
            raise HTTPException(status_code=400, detail="A deleted duplicate cannot also be closed")
        stale = stale_by_id.get(shift_id)
        if not stale:
            raise HTTPException(
                status_code=409,
                detail=f"Shift {shift_id} is no longer an eligible stale open shift",
            )
        clock_out = _parse_correction_clock_out(closure.clockOut)
        clock_in = parse_utc_iso(stale["clockIn"])
        if clock_out <= clock_in:
            raise HTTPException(status_code=400, detail=f"Shift {shift_id} clock-out must be after clock-in")
        if clock_out > now + timedelta(minutes=5):
            raise HTTPException(status_code=400, detail=f"Shift {shift_id} clock-out cannot be in the future")
        closure_ids.add(shift_id)
        normalized_closures.append({
            "shiftId": shift_id,
            "employeeName": stale["employeeName"],
            "clockIn": stale["clockIn"],
            "clockOut": to_utc_iso(clock_out),
            "totalHours": round((clock_out - clock_in).total_seconds() / 3600.0, 2),
        })

    selected_snapshot_ids = sorted(selected_group_ids | closure_ids)
    selected_snapshots = _correction_shift_snapshots(
        selected_snapshot_ids,
        cursor=cursor,
        lock_shifts=lock_shifts,
    )
    if {int(row["id"]) for row in selected_snapshots} != set(selected_snapshot_ids):
        raise HTTPException(status_code=409, detail="A selected shift changed or no longer exists")

    normalized_duplicates.sort(key=lambda row: (row["canonicalShiftId"], row["duplicateShiftIds"]))
    normalized_closures.sort(key=lambda row: row["shiftId"])
    archive_snapshot = {
        "inventoryVersion": inventory["inventoryVersion"],
        "reason": reason,
        "duplicateResolutions": normalized_duplicates,
        "staleShiftClosures": normalized_closures,
        "shiftsBefore": selected_snapshots,
    }
    token_material = json.dumps(archive_snapshot, sort_keys=True, separators=(",", ":"))
    plan_token = hmac.new(
        JWT_SECRET.encode("utf-8"),
        token_material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    delete_count = len(delete_ids)
    close_count = len(normalized_closures)
    duplicate_label = "DUPLICATE SHIFT" if delete_count == 1 else "DUPLICATE SHIFTS"
    stale_label = "STALE SHIFT" if close_count == 1 else "STALE SHIFTS"
    return {
        "success": True,
        "databaseReadOnly": True,
        "planToken": plan_token,
        "inventoryVersion": inventory["inventoryVersion"],
        "confirmationPhrase": f"DELETE {delete_count} {duplicate_label} AND CLOSE {close_count} {stale_label}",
        "summary": {
            "duplicateShiftsToDelete": delete_count,
            "staleShiftsToClose": close_count,
        },
        "duplicateResolutions": normalized_duplicates,
        "staleShiftClosures": normalized_closures,
        "_archiveSnapshot": archive_snapshot,
    }


@app.get("/api/admin/audits/time-data")
def admin_time_data_audit(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = build_time_data_audit()
    summary = result["summary"]
    append_access_log(
        request,
        "TIME_DATA_AUDIT",
        True,
        "duplicates={duplicateShiftGroups} multiple_open={employeesWithMultipleOpenShifts} "
        "stale={staleOpenShifts}".format(**summary),
    )
    return result


@app.get("/api/admin/corrections/time-data")
def admin_time_data_correction_inventory(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = build_time_data_correction_inventory()
    append_access_log(
        request,
        "TIME_DATA_CORRECTION_INVENTORY",
        True,
        "duplicates={duplicateShiftGroups} stale={staleOpenShifts}".format(**result["summary"]),
    )
    return result


@app.post("/api/admin/corrections/time-data/preview")
def admin_time_data_correction_preview(
    payload: TimeDataCorrectionPlanRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = _build_time_data_correction_plan(payload)
    result.pop("_archiveSnapshot", None)
    append_access_log(
        request,
        "TIME_DATA_CORRECTION_PLAN",
        True,
        "delete={duplicateShiftsToDelete} close={staleShiftsToClose}".format(**result["summary"]),
    )
    return result


@app.post("/api/admin/corrections/time-data/apply")
def admin_apply_time_data_correction(
    payload: TimeDataCorrectionApplyRequest,
    request: Request,
    current_admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    requested_ids = {
        int(value)
        for row in payload.duplicateResolutions
        for value in [row.canonicalShiftId, *row.duplicateShiftIds]
    }
    requested_ids.update(int(row.shiftId) for row in payload.staleShiftClosures)

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if requested_ids:
                cur.execute(
                    "SELECT id FROM shifts WHERE id = ANY(%s) ORDER BY id FOR UPDATE",
                    (sorted(requested_ids),),
                )
                cur.fetchall()

            plan = _build_time_data_correction_plan(payload, cursor=cur, lock_shifts=True)
            if not hmac.compare_digest(payload.planToken, plan["planToken"]):
                raise HTTPException(
                    status_code=409,
                    detail="Correction plan is stale or does not match; preview it again",
                )
            if payload.confirmation != plan["confirmationPhrase"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Type the exact confirmation phrase: {plan['confirmationPhrase']}",
                )

            cur.execute(
                """
                INSERT INTO time_data_correction_batches (
                    plan_token,
                    applied_by_employee_id,
                    applied_by_name,
                    reason,
                    snapshot,
                    result
                )
                VALUES (%s, %s, %s, %s, %s::jsonb, '{}'::jsonb)
                RETURNING id
                """,
                (
                    plan["planToken"],
                    int(current_admin["id"]),
                    current_admin["name"],
                    payload.reason.strip(),
                    json.dumps(plan["_archiveSnapshot"], sort_keys=True),
                ),
            )
            batch_id = int(cur.fetchone()["id"])

            closed_shift_ids = []
            for closure in plan["staleShiftClosures"]:
                clock_out = parse_utc_iso(closure["clockOut"])
                cur.execute(
                    """
                    UPDATE shifts
                    SET
                        clock_out = %s,
                        total_hours = ROUND(
                            (EXTRACT(EPOCH FROM (%s::timestamptz - clock_in)) / 3600.0)::numeric,
                            2
                        )
                    WHERE id = %s AND clock_out IS NULL
                    RETURNING id
                    """,
                    (clock_out, clock_out, closure["shiftId"]),
                )
                updated = cur.fetchone()
                if not updated:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Shift {closure['shiftId']} changed before correction could be applied",
                    )
                closed_shift_ids.append(int(updated["id"]))

            deleted_shift_ids = sorted(
                int(value)
                for row in plan["duplicateResolutions"]
                for value in row["duplicateShiftIds"]
            )
            if deleted_shift_ids:
                cur.execute(
                    "DELETE FROM shifts WHERE id = ANY(%s) RETURNING id",
                    (deleted_shift_ids,),
                )
                actually_deleted = sorted(int(row["id"]) for row in cur.fetchall())
                if actually_deleted != deleted_shift_ids:
                    raise HTTPException(
                        status_code=409,
                        detail="A duplicate shift changed before correction could be applied",
                    )

            result = {
                "deletedShiftIds": deleted_shift_ids,
                "closedShiftIds": sorted(closed_shift_ids),
            }
            cur.execute(
                "UPDATE time_data_correction_batches SET result = %s::jsonb WHERE id = %s",
                (json.dumps(result, sort_keys=True), batch_id),
            )

    append_access_log(
        request,
        "TIME_DATA_CORRECTION_APPLIED",
        True,
        f"batch={batch_id} deleted={len(result['deletedShiftIds'])} closed={len(result['closedShiftIds'])}",
    )
    return {
        "success": True,
        "batchId": batch_id,
        "archiveStored": True,
        **result,
    }


@app.get("/api/admin/corrections/time-data/history")
def admin_time_data_correction_history(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    rows = db.query_all(
        """
        SELECT id, applied_by_name, reason, result, created_at
        FROM time_data_correction_batches
        ORDER BY created_at DESC, id DESC
        LIMIT 50
        """
    )
    append_access_log(request, "TIME_DATA_CORRECTION_HISTORY", True, f"rows={len(rows)}")
    return {
        "success": True,
        "batches": [
            {
                "batchId": int(row["id"]),
                "appliedBy": row["applied_by_name"],
                "reason": row["reason"],
                "result": row.get("result") or {},
                "createdAt": to_utc_iso(row["created_at"]),
            }
            for row in rows
        ],
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
    location_customers = _historical_location_metadata(
        timesheet_data,
        "location_customers",
    )
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


def _resolve_site_for_creation(
    cur: Any,
    location_id: Optional[int],
    requested_customer_name: str,
    *,
    weekly_schedule: bool = False,
) -> Tuple[int, str, int]:
    if location_id is not None:
        cur.execute(
            """
            SELECT l.id, l.customer_id,
                   COALESCE(c.name, l.customer_name, '') AS customer_name
            FROM locations l
            LEFT JOIN customers c ON c.id = l.customer_id
            WHERE l.id = %s AND l.active = true
            FOR UPDATE OF l
            """,
            (location_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Active location not found")
        customer_name = str(row.get("customer_name") or "").strip()
        customer_id = row.get("customer_id")
        if customer_id is None or not customer_name:
            _raise_conflict(
                "ambiguous_customer_site",
                "The selected legacy Site must be assigned to a Customer first",
                {"locationId": location_id, "matchingSiteIds": []},
            )
        resolved_id = int(row["id"])
    else:
        cur.execute(
            """
            SELECT l.id, l.customer_id,
                   COALESCE(c.name, l.customer_name, '') AS customer_name
            FROM locations l
            LEFT JOIN customers c ON c.id = l.customer_id
            WHERE l.active = true
              AND COALESCE(c.name, l.customer_name, '') = %s
            ORDER BY l.id
            FOR UPDATE OF l
            """,
            (requested_customer_name,),
        )
        candidates = [dict(row) for row in cur.fetchall()]
        if len(candidates) != 1:
            _raise_conflict(
                "ambiguous_customer_site",
                "Select an exact active Site for this Customer",
                {
                    "customerName": requested_customer_name,
                    "matchingSiteIds": [int(row["id"]) for row in candidates],
                },
            )
        resolved_id = int(candidates[0]["id"])
        customer_id = candidates[0].get("customer_id")
        customer_name = str(candidates[0].get("customer_name") or "").strip()
        if customer_id is None or not customer_name:
            _raise_conflict(
                "ambiguous_customer_site",
                "The selected legacy Site must be assigned to a Customer first",
                {"locationId": resolved_id, "matchingSiteIds": [resolved_id]},
            )

    if weekly_schedule:
        cur.execute(
            """
            SELECT l.id
            FROM locations l
            WHERE l.active = true
              AND l.customer_id = %s
            ORDER BY l.id
            FOR UPDATE OF l
            """,
            (customer_id,),
        )
        same_customer_sites = [dict(row) for row in cur.fetchall()]
        if len(same_customer_sites) != 1:
            _raise_conflict(
                "ambiguous_customer_site",
                "Weekly multi-Site scheduling is deferred to Issue #20",
                {
                    "customerName": customer_name,
                    "matchingSiteIds": [
                        int(row["id"]) for row in same_customer_sites
                    ],
                },
            )
    return resolved_id, customer_name, int(customer_id)


def _legacy_schedule_name_arbiter_present(cur: Any) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'schedules'::regclass
              AND contype = 'u'
              AND pg_get_constraintdef(oid) LIKE '%%employee_id%%'
              AND pg_get_constraintdef(oid) LIKE '%%customer_name%%'
              AND pg_get_constraintdef(oid) LIKE '%%week_start%%'
        ) AS present
        """
    )
    return bool(cur.fetchone()["present"])


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

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            location_id, customer, customer_id = _resolve_site_for_creation(
                cur,
                payload.locationId,
                customer,
                weekly_schedule=True,
            )
            cur.execute(
                """
                SELECT sc.id
                FROM schedules sc
                WHERE sc.employee_id = %s
                  AND sc.week_start = %s
                  AND sc.location_id IS NULL
                  AND sc.customer_name = %s
                ORDER BY sc.id
                FOR UPDATE
                """,
                (payload.employeeId, week_start, customer),
            )
            legacy_name_schedule_ids = [
                int(item["id"]) for item in cur.fetchall()
            ]
            if legacy_name_schedule_ids:
                cur.execute(
                    """
                    SELECT l.id, l.customer_id
                    FROM locations l
                    LEFT JOIN customers c ON c.id = l.customer_id
                    WHERE COALESCE(c.name, l.customer_name, '') = %s
                    ORDER BY l.id
                    FOR UPDATE OF l
                    """,
                    (customer,),
                )
                matching_name_sites = [dict(item) for item in cur.fetchall()]
                matching_name_site_ids = [
                    int(item["id"]) for item in matching_name_sites
                ]
                matching_customer_ids = {
                    int(item["customer_id"])
                    for item in matching_name_sites
                    if item.get("customer_id") is not None
                }
                has_unlinked_match = any(
                    item.get("customer_id") is None
                    for item in matching_name_sites
                )
                if has_unlinked_match or matching_customer_ids != {customer_id}:
                    _raise_conflict(
                        "ambiguous_customer_site",
                        "A legacy weekly schedule with this shared Customer name "
                        "requires review before assigning an exact Site",
                        {
                            "customerName": customer,
                            "locationId": location_id,
                            "matchingSiteIds": matching_name_site_ids,
                            "matchingScheduleIds": legacy_name_schedule_ids,
                        },
                    )
            cur.execute(
                """
                SELECT sc.id
                FROM schedules sc
                LEFT JOIN locations existing_site ON existing_site.id = sc.location_id
                WHERE sc.employee_id = %s
                  AND sc.week_start = %s
                  AND (
                      sc.location_id = %s
                      OR existing_site.customer_id = %s
                      OR (sc.location_id IS NULL AND sc.customer_name = %s)
                  )
                ORDER BY sc.id
                FOR UPDATE OF sc
                """,
                (
                    payload.employeeId,
                    week_start,
                    location_id,
                    customer_id,
                    customer,
                ),
            )
            matching_schedule_ids = [int(item["id"]) for item in cur.fetchall()]
            if len(matching_schedule_ids) > 1:
                _raise_conflict(
                    "ambiguous_customer_site",
                    "Multiple legacy weekly schedules require review before updating",
                    {
                        "customerName": customer,
                        "locationId": location_id,
                        "matchingScheduleIds": matching_schedule_ids,
                    },
                )
            legacy_name_arbiter_present = _legacy_schedule_name_arbiter_present(cur)
            if legacy_name_arbiter_present:
                current_schedule_id = (
                    matching_schedule_ids[0] if matching_schedule_ids else None
                )
                cur.execute(
                    """
                    SELECT id, location_id
                    FROM schedules
                    WHERE employee_id = %s
                      AND week_start = %s
                      AND customer_name = %s
                      AND id <> %s
                    ORDER BY id
                    FOR UPDATE
                    """,
                    (
                        payload.employeeId,
                        week_start,
                        customer,
                        current_schedule_id or 0,
                    ),
                )
                rollout_conflicts = [dict(item) for item in cur.fetchall()]
                if rollout_conflicts:
                    _raise_conflict(
                        "ambiguous_customer_site",
                        "This shared Customer name cannot be scheduled at a "
                        "second Site until the staged Site-identity migration "
                        "is finalized",
                        {
                            "customerName": customer,
                            "locationId": location_id,
                            "matchingScheduleIds": [
                                int(item["id"]) for item in rollout_conflicts
                            ],
                            "migrationPending": True,
                        },
                    )
            if matching_schedule_ids:
                cur.execute(
                    """
                    UPDATE schedules
                    SET location_id = %s, customer_name = %s,
                        scheduled_hours = %s, notes = %s
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        location_id,
                        customer,
                        payload.scheduledHours,
                        payload.notes,
                        matching_schedule_ids[0],
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO schedules (
                        employee_id, location_id, customer_name, week_start,
                        scheduled_hours, notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        payload.employeeId,
                        location_id,
                        customer,
                        week_start,
                        payload.scheduledHours,
                        payload.notes,
                    ),
                )
            row = dict(cur.fetchone())
    append_access_log(request, "SCHEDULE_CREATED", True, f"Schedule {row['id']}")
    return {"success": True, "schedule": {
        "id": row["id"], "employeeId": row["employee_id"],
        "locationId": row["location_id"], "customerName": row["customer_name"],
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
            "id": r["id"], "employeeId": r["employee_id"],
            "employeeName": r["employee_name"], "locationId": r.get("location_id"),
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


def _reporting_site_identity_catalog() -> Tuple[
    Dict[int, Dict[str, Any]],
    Dict[str, List[int]],
]:
    """Return stable Site metadata and only-unambiguous legacy aliases."""
    rows = db.query_all(
        """
        SELECT l.id, l.customer_id, l.address, l.customer_name AS legacy_name,
               COALESCE(c.name, l.customer_name, l.address, '') AS customer_name,
               l.rate, l.rate_type, l.expected_hours, l.active
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        ORDER BY l.id
        """
    )
    sites = {int(row["id"]): dict(row) for row in rows}
    alias_sets: Dict[str, set[int]] = {}
    for row in rows:
        site_id = int(row["id"])
        for value in (
            row.get("customer_name"),
            row.get("legacy_name"),
            row.get("address"),
        ):
            alias = str(value or "").strip()
            if alias:
                alias_sets.setdefault(alias, set()).add(site_id)
    return sites, {
        alias: sorted(site_ids) for alias, site_ids in alias_sets.items()
    }


def _reporting_site_identity(
    location_id: Optional[int],
    legacy_label: str,
    alias_site_ids: Dict[str, List[int]],
    sites_by_id: Dict[int, Dict[str, Any]],
) -> Tuple[str, Any]:
    if location_id is not None:
        site_id = int(location_id)
        site = sites_by_id.get(site_id)
        if site and site.get("customer_id") is not None:
            return ("customer", int(site["customer_id"]))
        return ("site", site_id)
    label = str(legacy_label or "").strip()
    candidates = alias_site_ids.get(label, [])
    if candidates:
        candidate_sites = [sites_by_id[site_id] for site_id in candidates]
        candidate_customer_ids = {
            int(site["customer_id"])
            for site in candidate_sites
            if site.get("customer_id") is not None
        }
        has_unlinked_candidate = any(
            site.get("customer_id") is None for site in candidate_sites
        )
        if not has_unlinked_candidate and len(candidate_customer_ids) == 1:
            return ("customer", next(iter(candidate_customer_ids)))
    if len(candidates) == 1:
        return ("site", candidates[0])
    return ("legacy", label)


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

    sites_by_id, alias_site_ids = _reporting_site_identity_catalog()
    schedules = db.query_all(
        """
        SELECT sc.employee_id, e.name AS employee_name, sc.location_id,
               COALESCE(c.name, sc.customer_name) AS customer_name,
               sc.scheduled_hours
        FROM schedules sc
        JOIN employees e ON sc.employee_id = e.id
        LEFT JOIN locations l ON l.id = sc.location_id
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE sc.week_start = %s
        """,
        (ws,),
    )

    actuals = db.query_all(
        """
        SELECT s.employee_id, e.name AS employee_name,
               s.location_id,
               COALESCE(c.name, l.customer_name, l.address,
                        s.location_label, '') AS customer_name,
               COALESCE(SUM(s.total_hours), 0) AS actual_hours
        FROM shifts s
        JOIN employees e ON s.employee_id = e.id
        LEFT JOIN locations l ON s.location_id = l.id
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE s.clock_out IS NOT NULL AND s.local_date >= %s AND s.local_date <= %s
        GROUP BY s.employee_id, e.name, s.location_id, c.name,
                 l.customer_name, l.address, s.location_label
        """,
        (ws, we),
    )

    # Aggregate by stable Customer identity. A legacy alias resolves when all
    # matching Sites belong to one Customer; cross-Customer ambiguity remains.
    actual_map: Dict[Tuple[int, Tuple[str, Any]], Dict[str, Any]] = {}
    for a in actuals:
        identity = _reporting_site_identity(
            a.get("location_id"),
            str(a.get("customer_name") or ""),
            alias_site_ids,
            sites_by_id,
        )
        key = (int(a["employee_id"]), identity)
        current = actual_map.setdefault(
            key,
            {
                "employeeName": str(a["employee_name"]),
                "customerName": str(a.get("customer_name") or ""),
                "hours": 0.0,
                "locationIds": set(),
            },
        )
        current["hours"] += float(a["actual_hours"] or 0)
        if a.get("location_id") is not None:
            current["locationIds"].add(int(a["location_id"]))

    scheduled_map: Dict[Tuple[int, Tuple[str, Any]], Dict[str, Any]] = {}
    for sc in schedules:
        identity = _reporting_site_identity(
            sc.get("location_id"),
            str(sc.get("customer_name") or ""),
            alias_site_ids,
            sites_by_id,
        )
        key = (int(sc["employee_id"]), identity)
        current = scheduled_map.setdefault(
            key,
            {
                "employeeName": str(sc["employee_name"]),
                "customerName": str(sc.get("customer_name") or ""),
                "hours": 0.0,
                "locationIds": set(),
            },
        )
        current["hours"] += float(sc["scheduled_hours"] or 0)
        if sc.get("location_id") is not None:
            current["locationIds"].add(int(sc["location_id"]))

    comparisons = []
    for key in set(scheduled_map) | set(actual_map):
        employee_id_value, identity = key
        scheduled_entry = scheduled_map.get(key)
        actual_entry = actual_map.get(key)
        scheduled = float(scheduled_entry["hours"]) if scheduled_entry else 0.0
        actual = float(actual_entry["hours"]) if actual_entry else 0.0
        drift = round(actual - scheduled, 2)
        scheduled_location_ids = (
            scheduled_entry.get("locationIds", set()) if scheduled_entry else set()
        )
        actual_location_ids = (
            actual_entry.get("locationIds", set()) if actual_entry else set()
        )
        location_id_value = (
            next(iter(scheduled_location_ids))
            if len(scheduled_location_ids) == 1
            else (
                next(iter(actual_location_ids))
                if len(actual_location_ids) == 1
                else (int(identity[1]) if identity[0] == "site" else None)
            )
        )
        site = sites_by_id.get(location_id_value) if location_id_value else None
        customer_name = str(
            (scheduled_entry or {}).get("customerName")
            or (actual_entry or {}).get("customerName")
            or (site or {}).get("customer_name")
            or identity[1]
        )
        comparisons.append({
            "employeeId": employee_id_value,
            "employeeName": str(
                (scheduled_entry or actual_entry or {}).get(
                    "employeeName",
                    f"Employee {employee_id_value}",
                )
            ),
            "customerId": (
                int(identity[1])
                if identity[0] == "customer"
                else (
                    int(site["customer_id"])
                    if site and site.get("customer_id") is not None
                    else None
                )
            ),
            "locationId": location_id_value,
            "customerName": customer_name,
            "scheduledHours": round(scheduled, 2),
            "actualHours": round(actual, 2),
            "driftHours": drift,
            "driftPct": round(drift / scheduled * 100, 1) if scheduled > 0 else None,
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

    sites_by_id, alias_site_ids = _reporting_site_identity_catalog()
    settings = load_settings()
    active_site_ids_by_customer: Dict[int, set[int]] = {}
    for site_id, site in sites_by_id.items():
        if bool(site.get("active")) and site.get("customer_id") is not None:
            active_site_ids_by_customer.setdefault(
                int(site["customer_id"]),
                set(),
            ).add(site_id)

    # Historical actuals by customer per week
    hist_rows = db.query_all(
        """
        SELECT s.location_id,
               COALESCE(c.name, l.customer_name, l.address,
                        s.location_label, 'Unknown') AS customer,
               s.local_date, SUM(s.total_hours) AS hours
        FROM shifts s
        LEFT JOIN locations l ON s.location_id = l.id
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE s.clock_out IS NOT NULL AND s.local_date >= %s AND s.local_date <= %s
        GROUP BY s.location_id, customer, s.local_date
        """,
        (lookback_start, lookback_end),
    )

    # Aggregate by stable Site rather than a duplicate-prone display name.
    customer_weekly: Dict[Tuple[str, Any], Dict[str, float]] = {}
    identity_names: Dict[Tuple[str, Any], str] = {}
    historical_site_ids: Dict[Tuple[str, Any], set[int]] = {}
    for r in hist_rows:
        customer_name = str(r["customer"] or "Unknown")
        identity = _reporting_site_identity(
            r.get("location_id"),
            customer_name,
            alias_site_ids,
            sites_by_id,
        )
        identity_names.setdefault(identity, customer_name)
        if r.get("location_id") is not None:
            historical_site_ids.setdefault(identity, set()).add(
                int(r["location_id"])
            )
        d = r["local_date"]
        ds = (d.weekday() + 1) % 7
        wk = str(d - timedelta(days=ds))
        if identity not in customer_weekly:
            customer_weekly[identity] = {}
        customer_weekly[identity][wk] = (
            customer_weekly[identity].get(wk, 0) + float(r["hours"] or 0)
        )

    # Average hours per week per customer
    customer_avg: Dict[Tuple[str, Any], float] = {}
    for identity, weeks in customer_weekly.items():
        if weeks:
            customer_avg[identity] = round(sum(weeks.values()) / len(weeks), 2)

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
            """
            SELECT sc.location_id, COALESCE(c.name, sc.customer_name) AS customer_name,
                   SUM(sc.scheduled_hours) AS hours
            FROM schedules sc
            LEFT JOIN locations l ON l.id = sc.location_id
            LEFT JOIN customers c ON c.id = l.customer_id
            WHERE sc.week_start = %s
            GROUP BY sc.location_id, c.name, sc.customer_name
            """,
            (forecast_week_start,),
        )
        scheduled_map: Dict[Tuple[str, Any], Dict[str, Any]] = {}
        for schedule in scheduled:
            customer_name = str(schedule.get("customer_name") or "")
            identity = _reporting_site_identity(
                schedule.get("location_id"),
                customer_name,
                alias_site_ids,
                sites_by_id,
            )
            identity_names.setdefault(identity, customer_name)
            scheduled_entry = scheduled_map.setdefault(
                identity,
                {"hours": 0.0, "locationIds": set()},
            )
            scheduled_entry["hours"] += float(schedule["hours"] or 0)
            if schedule.get("location_id") is not None:
                scheduled_entry["locationIds"].add(int(schedule["location_id"]))

        total_hours = 0.0
        total_labor = 0.0
        total_revenue = 0.0
        by_customer = []

        all_customers = set(customer_avg) | set(scheduled_map)
        for identity in all_customers:
            # Use schedule if available, otherwise historical average
            scheduled_entry = scheduled_map.get(identity)
            hours = (
                float(scheduled_entry["hours"])
                if scheduled_entry
                else customer_avg.get(identity, 0)
            )
            labor = hours * avg_labor_rate

            scheduled_site_ids = (
                scheduled_entry.get("locationIds", set())
                if scheduled_entry
                else set()
            )
            historical_ids = historical_site_ids.get(identity, set())
            active_customer_site_ids = (
                active_site_ids_by_customer.get(int(identity[1]), set())
                if identity[0] == "customer"
                else set()
            )
            location_id_value = (
                next(iter(scheduled_site_ids))
                if len(scheduled_site_ids) == 1
                else (
                    next(iter(active_customer_site_ids))
                    if len(active_customer_site_ids) == 1
                    else (
                        next(iter(historical_ids))
                        if len(historical_ids) == 1
                        else (
                            int(identity[1])
                            if identity[0] == "site"
                            else None
                        )
                    )
                )
            )
            site = sites_by_id.get(location_id_value) if location_id_value else None
            rev = 0.0
            if site:
                rate = float(site["rate"]) if site.get("rate") is not None else None
                rt = str(site.get("rate_type") or "per_visit")
                if rate is not None:
                    if rt == "hourly":
                        rev = rate * hours
                    elif rt == "monthly":
                        rev = rate / 4.33  # approximate weekly from monthly
                    else:  # per_visit
                        # estimate visits from hours and expected hours per visit
                        exp_h = (
                            float(site["expected_hours"])
                            if site.get("expected_hours") is not None
                            else None
                        )
                        if exp_h and exp_h > 0:
                            est_visits = hours / exp_h
                        else:
                            est_visits = 1
                        rev = rate * est_visits

            total_hours += hours
            total_labor += labor
            total_revenue += rev
            by_customer.append({
                "customerId": (
                    int(identity[1])
                    if identity[0] == "customer"
                    else (
                        int(site["customer_id"])
                        if site and site.get("customer_id") is not None
                        else None
                    )
                ),
                "locationId": location_id_value,
                "customer": str(
                    (site or {}).get("customer_name")
                    or identity_names.get(identity)
                    or identity[1]
                ),
                "forecastHours": round(hours, 2),
                "source": "schedule" if identity in scheduled_map else "historical",
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

    location_customers = _historical_location_metadata(timesheet_data, "location_customers")
    location_rates = _historical_location_metadata(timesheet_data, "location_rates")
    location_rate_types = _historical_location_metadata(
        timesheet_data,
        "location_rate_types",
    )
    location_target_labor = _historical_location_metadata(
        timesheet_data,
        "location_target_labor",
    )
    location_min_margin = _historical_location_metadata(
        timesheet_data,
        "location_min_margin",
    )

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

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            location_id, customer, _customer_id = _resolve_site_for_creation(
                cur,
                payload.locationId,
                customer,
            )
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date, expected_hours,
                    revenue, notes, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    location_id,
                    customer,
                    scheduled,
                    payload.expectedHours,
                    payload.revenue,
                    payload.notes,
                    payload.status,
                ),
            )
            row = dict(cur.fetchone())
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

    location_customers = _historical_location_metadata(timesheet_data, "location_customers")
    location_rates = _historical_location_metadata(timesheet_data, "location_rates")
    location_rate_types = _historical_location_metadata(
        timesheet_data,
        "location_rate_types",
    )
    location_expected_hours = _historical_location_metadata(
        timesheet_data,
        "location_expected_hours",
    )

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
                matched = find_nearest_location(
                    gps_lat,
                    gps_lng,
                    timesheet_data,
                    coordinate_map_key="_historical_location_coords",
                )
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

    location_customers = _historical_location_metadata(timesheet_data, "location_customers")
    location_rates = _historical_location_metadata(timesheet_data, "location_rates")
    location_rate_types = _historical_location_metadata(
        timesheet_data,
        "location_rate_types",
    )

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
                matched = find_nearest_location(
                    gps_lat,
                    gps_lng,
                    timesheet_data,
                    coordinate_map_key="_historical_location_coords",
                )
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
