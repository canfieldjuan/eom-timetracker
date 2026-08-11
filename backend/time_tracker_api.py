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
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated, Any, Callable, Dict, FrozenSet, Iterable, List, Literal, Optional, Tuple
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

import bcrypt
import jwt
import psycopg2
import psycopg2.extras
import requests
import qrcode
import qrcode.image.svg
import arrival_policies
import db
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from hours_report_pdf import build_hours_report_pdf
from payroll_weekly_hours_pdf import build_payroll_weekly_hours_pdf
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

BASE_DIR = Path(__file__).resolve().parent.parent
_data_dir_env = os.environ.get("DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
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
ADMIN_ROLE = "admin"
EMPLOYEE_ROLE = "employee"
PAYROLL_ROLE = "payroll"
EMPLOYEE_ROLES = (ADMIN_ROLE, EMPLOYEE_ROLE, PAYROLL_ROLE)
PAYROLL_READ_ROLES = {ADMIN_ROLE, PAYROLL_ROLE}
PAYROLL_VERIFICATION_LOCK_PREFIX = "eom_payroll_verification_week_v1"
PAYROLL_MONEY_VERIFICATION_LOCK_PREFIX = "eom_payroll_money_verification_week_v1"
EMPLOYEE_WRITE_LOCK = threading.Lock()
TIMESHEET_WRITE_LOCK = threading.Lock()
TIMESHEET_PG_ADVISORY_LOCK_ID = 5_107_202_064
ACCESS_LOG_WRITE_LOCK = threading.Lock()
ACCESS_LOG_RETENTION_LOCK = threading.Lock()
_ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON: Optional[date] = None
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


def local_sunday_week_start(dt: datetime) -> date:
    local_day = to_local(dt).date()
    return local_day - timedelta(days=(local_day.weekday() + 1) % 7)


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
            # trusted proxies append addresses on the right. Select
            # TRUSTED_PROXY_HOPS from the right so the production chain ignores
            # that client-supplied prefix. Production Render traffic has two
            # trusted hops: Cloudflare and Render's load balancer.
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
ACCESS_LOG_RETENTION_DEFAULT_DAYS = 400
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
        raise ValueError("Invalid or revoked site QR code")

    try:
        site_id = int(parts[1])
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid or revoked site QR code") from exc

    nonce, signature = parts[2], parts[3]
    if site_id <= 0 or not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", nonce):
        raise ValueError("Invalid or revoked site QR code")

    expected = _site_check_in_signature(site_id, nonce)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid or revoked site QR code")
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
        "passwordChangedAt": row.get("password_changed_at"),
    }


def _load_employees_from_db() -> Dict[str, Any]:
    rows = db.query_all(
        "SELECT id, name, password_hash, active, role, hourly_rate, created_at, last_login_at, "
        "password_changed_at "
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
                      (name, password_hash, active, role, hourly_rate, last_login_at,
                       password_changed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        active        = EXCLUDED.active,
                        role          = EXCLUDED.role,
                        hourly_rate   = EXCLUDED.hourly_rate,
                        last_login_at = EXCLUDED.last_login_at,
                        password_changed_at = EXCLUDED.password_changed_at
                    RETURNING id
                    """,
                    (
                        emp["name"],
                        emp["password"],
                        emp.get("active", True),
                        emp.get("role", "employee"),
                        emp.get("hourlyRate"),
                        emp.get("lastLogin"),
                        emp.get("passwordChangedAt"),
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
                        last_login_at = %s,
                        password_changed_at = %s
                    WHERE id = %s
                    """,
                    (
                        emp["password"],
                        emp.get("active", True),
                        emp.get("role", "employee"),
                        emp.get("hourlyRate"),
                        emp.get("lastLogin"),
                        emp.get("passwordChangedAt"),
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
        "id":             int(row["id"]) if row.get("id") is not None else None,
        "arrivalTime": to_utc_iso(row["arrival_time"]) if row.get("arrival_time") else "",
        "location":    row.get("location") or row.get("location_label") or "",
        "customer":    row["customer_name"] or "",
        "gps":         row["gps"],
        "gpsMeta":     row.get("gps_meta"),
        "jobId":       (
            int(row["job_id"])
            if row.get("job_id") is not None
            else None
        ),
        "sequenceVersion": int(row.get("sequence_version") or 1),
        "siteCheckInId": (
            int(row["site_check_in_id"])
            if row.get("site_check_in_id") is not None
            else None
        ),
    }


def _row_to_departure(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id":             int(row["id"]) if row.get("id") is not None else None,
        "departureTime": to_utc_iso(row["departure_time"]) if row.get("departure_time") else "",
        "location":      row.get("location") or row.get("location_label") or "",
        "customer":      row["customer_name"] or "",
        "gps":           row["gps"],
        "gpsMeta":       row.get("gps_meta"),
        "visitId":       int(row["visit_id"]) if row.get("visit_id") is not None else None,
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
        SELECT v.id, v.shift_id, COALESCE(l.address, '') AS location,
               v.location_label, v.customer_name, v.arrival_time, v.gps, v.gps_meta,
               v.job_id, v.sequence_version, v.site_check_in_id
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
        SELECT d.id, d.shift_id, d.visit_id, COALESCE(l.address, '') AS location,
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
    after_save: Optional[Callable[[Any], None]] = None,
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
                # hourly_rate_cents is stamped here, at shift creation (clock-in
                # is the only moment guaranteed to happen -- clock_out is
                # nullable and shifts can stay open), and read straight from
                # employees so no caller can supply or spoof it. The UPDATE
                # branch below deliberately omits the column: a shift's rate is
                # fixed once set, so clock-out, admin entry edits, job relink and
                # categorization can never overwrite an existing snapshot.
                cur.execute(
                    """
                    INSERT INTO shifts
                      (employee_id, location_id, location_label, clock_in, clock_out, total_hours,
                       notes, local_date, timezone, clock_in_gps, clock_in_gps_meta,
                       clock_out_gps, clock_out_gps_meta,
                       job_id, time_category, non_productive_type, hourly_rate_cents)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            (SELECT ROUND(e.hourly_rate * 100)
                             FROM employees e
                             WHERE e.id = %s))
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
                        entry["employeeId"],
                    ),
                )
                entry["id"] = cur.fetchone()[0]
            else:
                cur.execute(
                    """
                    UPDATE shifts SET
                        location_id         = COALESCE(location_id, %s),
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
                        entry["id"],
                    ),
                )

            # Insert only visits appended since last load
            existing_count = pre_visit_counts.get(entry["id"], 0)
            for visit in entry.get("visits", [])[existing_count:]:
                v_loc_id = addr_to_id.get(visit.get("location", ""))
                cur.execute(
                    """
                    INSERT INTO visits (
                        shift_id, location_id, location_label, customer_name,
                        arrival_time, gps, gps_meta, sequence_version,
                        site_check_in_id, job_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        entry["id"],
                        v_loc_id,
                        visit.get("location", ""),
                        visit.get("customer") or None,
                        visit.get("arrivalTime"),
                        json.dumps(visit["gps"]) if visit.get("gps") else None,
                        json.dumps(visit["gpsMeta"]) if visit.get("gpsMeta") else None,
                        int(visit.get("sequenceVersion") or 2),
                        visit.get("siteCheckInId"),
                        visit.get("jobId"),
                    ),
                )
                visit["id"] = int(cur.fetchone()[0])
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
                    INSERT INTO departures (
                        shift_id, visit_id, location_id, location_label,
                        customer_name, departure_time, gps, gps_meta
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        entry["id"],
                        departure.get("visitId"),
                        d_loc_id,
                        departure.get("location", ""),
                        departure.get("customer") or None,
                        departure.get("departureTime"),
                        json.dumps(departure["gps"]) if departure.get("gps") else None,
                        json.dumps(departure["gpsMeta"]) if departure.get("gpsMeta") else None,
                    ),
                )
                departure["id"] = int(cur.fetchone()[0])

        if after_save is not None:
            after_save(cur)

        cur.execute(
            "SELECT setval('shifts_id_seq', COALESCE(MAX(id), 1)) FROM shifts"
        )


def load_timesheets() -> Dict[str, Any]:
    return _load_timesheets_from_db()


def _entry_resolved_by_payroll_correction(entry: Dict[str, Any]) -> bool:
    if entry.get("clockOut") is not None:
        return False
    try:
        shift_id = int(entry.get("id") or 0)
    except (TypeError, ValueError):
        return False
    if shift_id <= 0:
        return False
    return _shift_has_active_payroll_correction(shift_id)


def _raw_open_entry_is_stale(
    entry: Dict[str, Any],
    reference_time: datetime,
) -> bool:
    try:
        started_at = parse_utc_iso(str(entry.get("clockIn", "")))
    except ValueError:
        return False

    elapsed_hours = (reference_time - started_at).total_seconds() / 3600
    return elapsed_hours > MAX_ACTIVE_SHIFT_HOURS


def is_current_open_entry(
    entry: Dict[str, Any],
    reference_time: datetime,
) -> bool:
    if is_payroll_resolved_open_entry(entry):
        return False
    if entry.get("clockOut") is not None:
        return False
    return not _raw_open_entry_is_stale(entry, reference_time)


def is_payroll_resolved_open_entry(entry: Dict[str, Any]) -> bool:
    return (
        entry.get("clockOut") is None
        and _entry_resolved_by_payroll_correction(entry)
    )


def _exclude_payroll_resolved_open_entries(
    entries: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [
        entry
        for entry in entries
        if not is_payroll_resolved_open_entry(entry)
    ]


def get_open_entry(entries: List[Dict[str, Any]], employee_id: int) -> Optional[Dict[str, Any]]:
    now = utc_now()
    open_entries = [
        entry
        for entry in entries
        if entry.get("employeeId") == employee_id
        and is_current_open_entry(entry, now)
    ]
    if not open_entries:
        return None

    open_entries.sort(key=lambda item: item.get("clockIn", ""), reverse=True)
    return open_entries[0]


def is_stale_open_entry(entry: Dict[str, Any], reference_time: datetime) -> bool:
    if entry.get("clockOut") is not None:
        return False
    if _entry_resolved_by_payroll_correction(entry):
        return False
    return _raw_open_entry_is_stale(entry, reference_time)


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


def admin_stale_open_shift_summary(
    entry: Dict[str, Any],
    reference_time: datetime,
) -> Optional[Dict[str, Any]]:
    summary = stale_open_shift_summary(entry, reference_time)
    if not summary:
        return None
    return {
        **summary,
        "employeeId": int(entry.get("employeeId", 0)),
        "employeeName": str(entry.get("employeeName", "")),
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


def _shift_has_active_payroll_correction(shift_id: int) -> bool:
    row = db.query_one(
        """
        SELECT 1
        FROM payroll_shift_corrections
        WHERE shift_id = %s
          AND status = 'active'
        LIMIT 1
        """,
        (int(shift_id),),
    )
    return row is not None


@contextmanager
def timesheet_postgres_advisory_lock():
    """Serialize timesheet event writers across backend worker processes."""
    with db.get_conn() as lock_conn:
        with lock_conn.cursor() as lock_cur:
            lock_cur.execute(
                "SELECT pg_advisory_lock(%s)",
                (TIMESHEET_PG_ADVISORY_LOCK_ID,),
            )
            try:
                yield
            finally:
                lock_cur.execute(
                    "SELECT pg_advisory_unlock(%s)",
                    (TIMESHEET_PG_ADVISORY_LOCK_ID,),
                )


def update_timesheets(
    mutator,
    after_save: Optional[Callable[[Any], None]] = None,
) -> Tuple[bool, Any]:
    with TIMESHEET_WRITE_LOCK:
        with timesheet_postgres_advisory_lock():
            timesheet_data = _load_timesheets_from_db()
            pre_shift_ids = {e["id"] for e in timesheet_data["entries"]}
            pre_visit_counts = {
                e["id"]: len(e.get("visits", [])) for e in timesheet_data["entries"]
            }
            pre_departure_counts = {
                e["id"]: len(e.get("departures", []))
                for e in timesheet_data["entries"]
            }

            ok, payload = mutator(timesheet_data)
            if ok:
                _save_timesheets_to_db(
                    timesheet_data,
                    pre_shift_ids,
                    pre_visit_counts,
                    pre_departure_counts,
                    after_save=after_save,
                )
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


_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _password_stamp_micros(password_changed_at: datetime) -> int:
    # Exact integer arithmetic: a float timestamp() round-trip can wobble in
    # the last microsecond, and this value is compared for equality.
    delta = password_changed_at - _EPOCH_UTC
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def create_auth_token(
    employee_id: int,
    employee_name: str,
    role: str = "employee",
    *,
    password_changed_at: Optional[datetime] = None,
) -> str:
    now = utc_now()
    payload = {
        "sub": str(employee_id),
        "name": employee_name,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=TOKEN_TTL_HOURS)).timestamp()),
    }
    # The token is bound to the account's password version: get_current_employee
    # accepts a token only when this signed claim matches the account's current
    # password_changed_at stamp (absent stamp accepts any token). Timestamp
    # ordering cannot close the login-vs-change race; version equality can.
    if password_changed_at is not None:
        payload["pca"] = _password_stamp_micros(password_changed_at)
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
        if (
            _entry_resolved_by_payroll_correction(entry)
            or _raw_open_entry_is_stale(entry, reference_time)
        ):
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
        and is_current_open_entry(entry, now)
    ]
    if not open_entries:
        return None

    open_entries.sort(key=lambda item: item.get("clockIn", ""), reverse=True)
    return open_entries[0]


def build_dashboard_hours_data() -> Dict[str, Any]:
    employees_data = load_employees()
    timesheet_data = load_timesheets()
    now = utc_now()
    week_start = local_sunday_week_start(now)
    week_end = week_start + timedelta(days=7)

    active_employees = [employee for employee in employees_data["employees"] if employee.get("active", True)]
    employee_rows: List[Dict[str, Any]] = []
    total_hours = 0.0

    for employee in active_employees:
        employee_id = int(employee["id"])
        relevant_entries = [
            entry for entry in timesheet_data["entries"] if int(entry.get("employeeId", 0)) == employee_id
        ]
        relevant_entries = _exclude_payroll_resolved_open_entries(relevant_entries)
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

            if week_start <= shift_date < week_end:
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
        if not is_current_open_entry(entry, now):
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
    timestamp = to_utc_iso(utc_now())
    local_date_text = local_date_for_logs()
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    entry = {
        "eventId": str(uuid4()),
        "timestamp": timestamp,
        "action": action,
        "allowed": allowed,
        "reason": reason,
        "clientIP": client_ip,
        "userAgent": user_agent,
        "endpoint": request.url.path,
        "method": request.method,
    }

    postgres_written = False
    try:
        _append_access_log_to_postgres(entry, local_date_text)
        postgres_written = True
    except Exception:
        logger.warning("access_log_postgres_write_failed", exc_info=True)

    try:
        _append_access_log_to_file(entry, local_date_text)
    except Exception:
        logger.warning("access_log_file_write_failed", exc_info=True)

    if not postgres_written:
        return

    try:
        _maybe_prune_access_log_entries()
    except Exception:
        logger.warning("access_log_postgres_prune_failed", exc_info=True)


def _append_access_log_to_file(entry: Dict[str, Any], local_date_text: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_DIR / f"access_{local_date_text}.json"

    with ACCESS_LOG_WRITE_LOCK:
        with process_file_lock(log_file):
            payload = read_json_file(log_file, [])
            if not isinstance(payload, list):
                payload = []
            payload.append(entry)
            write_json_atomic(log_file, payload)


def _append_access_log_to_postgres(entry: Dict[str, Any], local_date_text: str) -> None:
    event_id = str(entry.get("eventId") or uuid4())
    entry = {**entry, "eventId": event_id}
    logged_at = parse_utc_iso(str(entry["timestamp"]))
    log_date = date.fromisoformat(local_date_text)
    db.execute(
        """
        INSERT INTO access_log_entries (
            event_id, logged_at, local_date, action, allowed, reason,
            client_ip, user_agent, endpoint, method, entry
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            event_id,
            logged_at,
            log_date,
            str(entry.get("action", "")),
            bool(entry.get("allowed")),
            str(entry.get("reason", "")),
            str(entry.get("clientIP", "")),
            str(entry.get("userAgent", "")),
            str(entry.get("endpoint", "")),
            str(entry.get("method", "")),
            psycopg2.extras.Json(entry),
        ),
    )


def _prune_access_log_entries(now: Optional[datetime] = None) -> None:
    cutoff = (now or utc_now()) - timedelta(days=ACCESS_LOG_RETENTION_DAYS)
    db.execute(
        "DELETE FROM access_log_entries WHERE logged_at < %s",
        (cutoff,),
    )


def _maybe_prune_access_log_entries() -> None:
    global _ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON

    today = utc_now().date()
    with ACCESS_LOG_RETENTION_LOCK:
        if _ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON == today:
            return

        _prune_access_log_entries()
        _ACCESS_LOG_RETENTION_LAST_ATTEMPTED_ON = today


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
    if employee.get("role") != ADMIN_ROLE:
        raise HTTPException(status_code=403, detail="Admin access required")
    return employee


def get_current_payroll(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    employee = get_current_employee(request, authorization)
    if employee.get("role") not in PAYROLL_READ_ROLES:
        raise HTTPException(status_code=403, detail="Payroll access required")
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


def enforce_clock_action_hours(request: Request) -> None:
    """Reject employee time-recording actions outside the configured window.

    Applies the same day + hour window as the dashboard gate
    (ALLOWED_DAYS / ACCESS_START_HOUR..ACCESS_END_HOUR, company timezone) but
    deliberately NOT the IP allowlist — field phones have churning mobile IPs.
    Disabled instantly via ENFORCE_CLOCK_HOURS=false (no deploy needed).
    """
    if not ENFORCE_CLOCK_HOURS:
        return
    allowed_by_time, time_reason, current_time = check_schedule_access()
    if not allowed_by_time:
        append_access_log(request, "CLOCK_TIME_RESTRICTION", False, time_reason)
        raise HTTPException(
            status_code=403,
            detail=(
                f"Time entry is only allowed between {ACCESS_START_HOUR}:00 and "
                f"{ACCESS_END_HOUR}:00 ({TIMEZONE_NAME}). Current time: {current_time}."
            ),
        )


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

    password_changed_at = employee.get("passwordChangedAt")
    if password_changed_at is not None:
        token_pca = decoded.get("pca")
        # Version binding, not timestamp ordering: once a stamp exists, a
        # token is valid only if it was minted against that exact stamp
        # (login and change_password both embed it, signed). iat comparison
        # cannot order a login racing a change, so it is not consulted.
        if not (
            isinstance(token_pca, int)
            and token_pca == _password_stamp_micros(password_changed_at)
        ):
            append_access_log(
                request, "TOKEN_INVALID", False,
                "Token not bound to current password version"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

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


def _strip_optional_atlas_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPException(
            status_code=502, detail="EOM lead review service returned an invalid response"
        )
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


class OfficeEstimatePrimarySiteRequest(PrimarySiteCreateRequest):
    """Completed estimate Site fields required before office approval."""

    rate: float = Field(
        ...,
        ge=0,
        le=SITE_RATE_MAX,
        allow_inf_nan=False,
    )
    rateType: Literal["per_visit", "hourly", "monthly"] = Field(...)
    frequency: str = Field(min_length=1, max_length=SITE_FREQUENCY_MAX_LENGTH)

    @field_validator("frequency", mode="before")
    @classmethod
    def normalize_required_frequency(cls, value: Any) -> Any:
        return _strip_required_text(value)


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
    # Slice 0C retry handle. Optional so the currently-deployed portal keeps
    # working; when absent the server derives a stable key from the payload so
    # a retry after a lost response still cannot create a second Atlas contact.
    # `OfficeEstimateApprovalRequest` narrows this to required. Supplying it is
    # what makes a retry after a lost response resolve to the same Atlas
    # contact; without it each attempt is a distinct operation.
    idempotencyKey: Optional[UUID] = None

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


class OfficeEstimateApprovalRequest(CustomerCreateRequest):
    """Completed-estimate facts needed for one office-created Customer/Site."""

    atlasContactId: UUID = Field(...)
    primarySite: OfficeEstimatePrimarySiteRequest = Field(...)
    idempotencyKey: UUID = Field(...)


class FunnelLeadLostRequest(BaseModel):
    """Office disposition for an Atlas lead that will not convert."""

    reasonCode: str = Field(
        ...,
        pattern="^(spam|no_response|declined_after_estimate|price|other)$",
    )
    note: Optional[str] = Field(default=None, max_length=1000)
    idempotencyKey: UUID = Field(...)


class FunnelLeadReopenRequest(BaseModel):
    """Return a previously-lost Atlas lead to the active queue."""

    idempotencyKey: UUID = Field(...)


class FunnelLeadStartEstimateRequest(BaseModel):
    """Fresh lead-review state required before moving a lead to Working."""

    expectedStateToken: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern="^[0-9a-f]{64}$",
    )


class CustomerUpdateRequest(BaseModel):
    expectedUpdateToken: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern="^[0-9a-f]{64}$",
    )
    name: Optional[str] = Field(default=None, min_length=1, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryContactName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    primaryPhone: Optional[str] = Field(default=None, max_length=CUSTOMER_PHONE_MAX_LENGTH)
    primaryEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingName: Optional[str] = Field(default=None, max_length=CUSTOMER_NAME_MAX_LENGTH)
    billingEmail: Optional[str] = Field(default=None, max_length=CUSTOMER_EMAIL_MAX_LENGTH)
    billingAddress: Optional[str] = Field(default=None, max_length=SITE_ADDRESS_MAX_LENGTH)
    atlasContactId: Optional[UUID] = None
    # Accepted so a portal that round-trips the whole record is not rejected by
    # the model, then refused in the handler if it actually differs from the
    # mirrored value. Declaring it is what makes that refusal reachable: with
    # the field absent the request would 422 on an unknown key and the operator
    # would see a validation error instead of the reason.
    customerType: Optional[str] = Field(default=None, max_length=16)

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
    expectedUpdateToken: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern="^[0-9a-f]{64}$",
    )
    expectedCustomerUpdateToken: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern="^[0-9a-f]{64}$",
    )
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
    idempotencyKey: Optional[UUID] = None


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
    action: Optional[Literal["arrive", "depart"]] = None
    actionStateToken: Optional[str] = Field(default=None, min_length=20, max_length=2048)
    idempotencyKey: Optional[UUID] = None

    @field_validator("scannedAt")
    @classmethod
    def scanned_at_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scannedAt must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def explicit_action_fields_are_all_or_none(self) -> "SiteCheckInRequest":
        supplied = (
            self.action is not None,
            self.actionStateToken is not None,
            self.idempotencyKey is not None,
        )
        if any(supplied) and not all(supplied):
            raise ValueError(
                "action, actionStateToken, and idempotencyKey must be provided together"
            )
        return self


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


class ArrivalPolicyPutRequest(BaseModel):
    mode: str = Field(pattern="^(fixed|window|flexible|not_before)$")
    timezone: str = Field(min_length=1, max_length=100)
    fixedArrival: Optional[clock_time] = None
    graceMinutes: Optional[int] = Field(default=None, ge=0, le=120)
    windowStart: Optional[clock_time] = None
    windowEnd: Optional[clock_time] = None
    notBefore: Optional[clock_time] = None
    expectedUpdateToken: Optional[str] = Field(
        default=None,
        pattern="^[0-9a-f]{64}$",
    )
    changeNote: str = Field(min_length=3, max_length=500)

    @field_validator("timezone", "changeNote", mode="before")
    @classmethod
    def strip_arrival_policy_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("fixedArrival", "windowStart", "windowEnd", "notBefore")
    @classmethod
    def policy_times_use_minute_precision(
        cls,
        value: Optional[clock_time],
    ) -> Optional[clock_time]:
        if value is None:
            return None
        if value.tzinfo is not None:
            raise ValueError("arrival policy times must not include a timezone")
        if value.second or value.microsecond:
            raise ValueError("arrival policy times must use HH:MM precision")
        return value

    @model_validator(mode="after")
    def validate_mode_fields(self) -> "ArrivalPolicyPutRequest":
        try:
            arrival_policies.validate_policy_values(
                mode=self.mode,
                timezone_name=self.timezone,
                fixed_arrival=self.fixedArrival,
                grace_minutes=self.graceMinutes,
                window_start=self.windowStart,
                window_end=self.windowEnd,
                not_before=self.notBefore,
            )
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return self


class ArrivalPolicyRetireRequest(BaseModel):
    expectedUpdateToken: str = Field(pattern="^[0-9a-f]{64}$")
    changeNote: str = Field(min_length=3, max_length=500)

    @field_validator("changeNote", mode="before")
    @classmethod
    def strip_arrival_policy_retirement_note(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


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
    idempotencyKey: Optional[UUID] = None


class DepartRequest(BaseModel):
    notes: str = Field(default="", max_length=MAX_NOTES_LEN)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    accuracy: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)
    gpsOverrideReason: str = Field(default="", max_length=MAX_GPS_OVERRIDE_REASON_LEN)
    gpsOverrideDetail: str = Field(default="", max_length=MAX_GPS_OVERRIDE_DETAIL_LEN)
    idempotencyKey: Optional[UUID] = None


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


class AtlasLinkageMappingEntry(BaseModel):
    customerId: int = Field(gt=0)
    atlasContactId: UUID


class AtlasLinkageBackfillPlanRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)
    mappings: List[AtlasLinkageMappingEntry] = Field(min_length=1, max_length=200)


class AtlasLinkageBackfillApplyRequest(AtlasLinkageBackfillPlanRequest):
    planToken: str = Field(min_length=64, max_length=64)
    confirmation: str = Field(min_length=1, max_length=100)


class CustomerTypeRefreshPlanRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_reason(cls, value: Any) -> Any:
        # Strip BEFORE length validation. The apply path strips before
        # persisting, so validating the raw string would let ten spaces satisfy
        # min_length and store an empty justification in the durable record.
        return value.strip() if isinstance(value, str) else value


class CustomerTypeRefreshApplyRequest(CustomerTypeRefreshPlanRequest):
    planToken: str = Field(min_length=64, max_length=64)
    confirmation: str = Field(min_length=1, max_length=100)


class PayrollWeekRequest(BaseModel):
    weekStart: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("weekStart", mode="before")
    @classmethod
    def strip_week_start(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollVerificationRequest(PayrollWeekRequest):
    sourceFingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(default="", max_length=500)

    @field_validator("sourceFingerprint", "reason", mode="before")
    @classmethod
    def strip_verification_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollReopenRequest(PayrollWeekRequest):
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_reopen_reason(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollMoneyVerificationRequest(PayrollWeekRequest):
    moneyFingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(default="", max_length=500)

    @field_validator("moneyFingerprint", "reason", mode="before")
    @classmethod
    def strip_money_verification_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollCorrectionRequest(PayrollWeekRequest):
    employeeId: int = Field(gt=0)
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    correctedTotalMinutes: int = Field(ge=0, le=24 * 60)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("date", "reason", mode="before")
    @classmethod
    def strip_correction_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollShiftCorrectionRequest(PayrollWeekRequest):
    employeeId: int = Field(gt=0)
    shiftId: int = Field(gt=0)
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    correctedClockIn: str = Field(min_length=16, max_length=40)
    correctedClockOut: str = Field(min_length=16, max_length=40)
    correctedBreakMinutes: int = Field(default=0, ge=0, le=24 * 60)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("date", "correctedClockIn", "correctedClockOut", "reason", mode="before")
    @classmethod
    def strip_shift_correction_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollTimesheetChangeOperation(BaseModel):
    action: Literal[
        "add_manual",
        "edit_manual",
        "exclude_manual",
        "restore_manual",
        "correct_recorded",
        "clear_recorded_correction",
        "exclude_recorded",
        "restore_recorded",
    ]
    clientRowId: Optional[str] = Field(default=None, max_length=100)
    shiftId: Optional[int] = Field(default=None, gt=0)
    manualShiftId: Optional[UUID] = None
    date: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    clockIn: Optional[str] = Field(default=None, min_length=16, max_length=40)
    clockOut: Optional[str] = Field(default=None, min_length=16, max_length=40)
    breakMinutes: Optional[int] = Field(default=None, ge=0, le=24 * 60)
    locationId: Optional[int] = Field(default=None, gt=0)

    @field_validator("clientRowId", "date", "clockIn", "clockOut", mode="before")
    @classmethod
    def strip_timesheet_change_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_timesheet_change_shape(self) -> "PayrollTimesheetChangeOperation":
        manual_identity_actions = {"edit_manual", "exclude_manual", "restore_manual"}
        recorded_identity_actions = {
            "correct_recorded",
            "clear_recorded_correction",
            "exclude_recorded",
            "restore_recorded",
        }
        value_actions = {"add_manual", "edit_manual", "correct_recorded"}
        if self.action in manual_identity_actions and self.manualShiftId is None:
            raise ValueError("manualShiftId is required for this action")
        if self.action in recorded_identity_actions and self.shiftId is None:
            raise ValueError("shiftId is required for this action")
        if self.action in value_actions:
            if not self.date or not self.clockIn or not self.clockOut:
                raise ValueError("date, clockIn, and clockOut are required for this action")
            if self.breakMinutes is None:
                self.breakMinutes = 0
        return self


class PayrollTimesheetChangesRequest(PayrollWeekRequest):
    requestId: UUID
    employeeId: int = Field(gt=0)
    expectedTimesheetSourceFingerprint: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    reason: str = Field(min_length=3, max_length=500)
    operations: List[PayrollTimesheetChangeOperation] = Field(min_length=1, max_length=100)

    @field_validator("expectedTimesheetSourceFingerprint", "reason", mode="before")
    @classmethod
    def strip_timesheet_change_request_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollCorrectionVoidRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_void_reason(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PayrollCorrectionAllocationRequest(BaseModel):
    locationId: int = Field(gt=0)
    jobId: Optional[int] = Field(default=None, gt=0)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_allocation_reason(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


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
# Used to pick the real client IP from the RIGHT of X-Forwarded-For. Render's
# production path is Cloudflare plus its load balancer, so its default is 2.
# Override this only when the deployed proxy topology differs.
DEFAULT_TRUSTED_PROXY_HOPS = 2
TRUSTED_PROXY_HOPS = max(
    1,
    parse_int(os.getenv("TRUSTED_PROXY_HOPS"), DEFAULT_TRUSTED_PROXY_HOPS),
)
ACCESS_LOG_RETENTION_DAYS = max(
    1,
    parse_int(os.getenv("ACCESS_LOG_RETENTION_DAYS"), ACCESS_LOG_RETENTION_DEFAULT_DAYS),
)
# Gate employee clock actions (clock-in/out, arrive, depart, QR check-in) to the
# ACCESS_START_HOUR..ACCESS_END_HOUR window on ALLOWED_DAYS. Deliberately does NOT
# apply the IP allowlist (field phones have churning mobile IPs). Kill switch:
# set ENFORCE_CLOCK_HOURS=false to disable without a deploy.
ENFORCE_CLOCK_HOURS = parse_bool(os.getenv("ENFORCE_CLOCK_HOURS"), True)
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
ATLAS_RECEIVABLES_BASE_URL = os.getenv("ATLAS_RECEIVABLES_BASE_URL", "").strip().rstrip("/")
ATLAS_RECEIVABLES_SERVICE_TOKEN = os.getenv(
    "ATLAS_RECEIVABLES_SERVICE_TOKEN", ""
).strip()
ATLAS_RECEIVABLES_TIMEOUT_SECONDS = max(
    1.0, float(os.getenv("ATLAS_RECEIVABLES_TIMEOUT_SECONDS", "10"))
)
ATLAS_RECEIVABLES_GENERATED_TOKEN_PREFIX = "eomrx_v1_"
ATLAS_RECEIVABLES_GENERATED_TOKEN_RANDOM_LENGTH = 43
ATLAS_RECEIVABLES_TOKEN_RANDOM_PATTERN = r"[A-Za-z0-9_-]+"
ATLAS_RECEIVABLES_API_PATH_SUFFIX = "/api/v1"
ATLAS_FUNNEL_BASE_URL = os.getenv("ATLAS_FUNNEL_BASE_URL", "").strip().rstrip("/")
ATLAS_FUNNEL_SERVICE_TOKEN = os.getenv("ATLAS_FUNNEL_SERVICE_TOKEN", "").strip()
ATLAS_FUNNEL_TIMEOUT_SECONDS = max(
    1.0, float(os.getenv("ATLAS_FUNNEL_TIMEOUT_SECONDS", "10"))
)
EOM_FUNNEL_APPROVER_EMPLOYEE_ID = parse_int(
    os.getenv("EOM_FUNNEL_APPROVER_EMPLOYEE_ID"), 0
)
GOOGLE_CALENDAR_CLIENT_ID = os.getenv("GOOGLE_CALENDAR_CLIENT_ID", "").strip()
GOOGLE_CALENDAR_CLIENT_SECRET = os.getenv(
    "GOOGLE_CALENDAR_CLIENT_SECRET", ""
).strip()
GOOGLE_CALENDAR_REDIRECT_URI = os.getenv(
    "GOOGLE_CALENDAR_REDIRECT_URI", ""
).strip()
GOOGLE_CALENDAR_TOKEN_ENCRYPTION_KEY = os.getenv(
    "GOOGLE_CALENDAR_TOKEN_ENCRYPTION_KEY", ""
).strip()
GOOGLE_CALENDAR_PORTAL_URL = os.getenv(
    "GOOGLE_CALENDAR_PORTAL_URL",
    "https://effinghamofficemaids.com/portal.html",
).strip()
GOOGLE_CALENDAR_TIMEOUT_SECONDS = max(
    1.0, float(os.getenv("GOOGLE_CALENDAR_TIMEOUT_SECONDS", "10"))
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


def _is_generated_atlas_receivables_token(token: str) -> bool:
    if not token.startswith(ATLAS_RECEIVABLES_GENERATED_TOKEN_PREFIX):
        return False
    random_part = token.removeprefix(ATLAS_RECEIVABLES_GENERATED_TOKEN_PREFIX)
    return (
        len(random_part) == ATLAS_RECEIVABLES_GENERATED_TOKEN_RANDOM_LENGTH
        and re.fullmatch(ATLAS_RECEIVABLES_TOKEN_RANDOM_PATTERN, random_part)
        is not None
    )


def _require_atlas_receivables_configuration() -> None:
    if not ATLAS_RECEIVABLES_BASE_URL or not ATLAS_RECEIVABLES_SERVICE_TOKEN:
        raise HTTPException(
            status_code=503, detail="Receivables service is not configured"
        )
    parsed_url = urlsplit(ATLAS_RECEIVABLES_BASE_URL)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Receivables service URL must be an absolute http or https URL "
                "ending in /api/v1"
            ),
        )
    if parsed_url.username or parsed_url.password:
        raise HTTPException(
            status_code=503,
            detail="Receivables service URL must not include credentials",
        )
    if not parsed_url.path.rstrip("/").endswith(ATLAS_RECEIVABLES_API_PATH_SUFFIX):
        raise HTTPException(
            status_code=503,
            detail="Receivables service URL must end in /api/v1",
        )
    if not _is_generated_atlas_receivables_token(ATLAS_RECEIVABLES_SERVICE_TOKEN):
        logger.warning(
            "Atlas receivables service token is not generated-format; preserving "
            "legacy caller credential during rotation"
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
    _require_atlas_receivables_configuration()
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


class AtlasFunnelRequestError(Exception):
    """A tracker-to-Atlas response that leaves the local handoff retryable."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


def _require_atlas_funnel_configuration() -> None:
    if not ATLAS_FUNNEL_BASE_URL or not ATLAS_FUNNEL_SERVICE_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="EOM customer handoff service is not configured",
        )


def _atlas_funnel_request(
    path: str,
    admin: Dict[str, Any],
    *,
    payload: Dict[str, Any],
    idempotency_key: str,
) -> Dict[str, Any]:
    """Call Atlas from the server; its service credential never reaches a browser."""
    _require_atlas_funnel_configuration()
    if not path.startswith("/eom-funnel/"):
        raise RuntimeError("Invalid EOM funnel proxy path")
    headers = {
        "Authorization": f"Bearer {ATLAS_FUNNEL_SERVICE_TOKEN}",
        "X-EOM-Actor": str(admin["name"]),
        "X-EOM-Actor-ID": str(admin["id"]),
        "Idempotency-Key": idempotency_key,
        "Accept": "application/json",
    }
    try:
        response = requests.post(
            f"{ATLAS_FUNNEL_BASE_URL}{path}",
            headers=headers,
            json=payload,
            timeout=ATLAS_FUNNEL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise AtlasFunnelRequestError(
            503,
            "EOM customer handoff service is temporarily unavailable; retry this approval",
        ) from exc
    try:
        content = response.json()
    except ValueError as exc:
        if response.status_code >= 500:
            raise AtlasFunnelRequestError(
                response.status_code,
                "EOM customer handoff service is temporarily unavailable; retry this approval",
            ) from exc
        raise AtlasFunnelRequestError(
            502, "EOM customer handoff service returned an invalid response"
        ) from exc
    if response.status_code in (401, 403):
        logger.error(
            "Atlas EOM funnel service credential rejected status=%s",
            response.status_code,
        )
        raise AtlasFunnelRequestError(
            502,
            "EOM customer handoff service authentication failed",
        )
    if response.status_code >= 400:
        detail: Any = content.get("detail", content) if isinstance(content, dict) else content
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or "EOM customer handoff failed"
        if not isinstance(detail, str) or not detail.strip():
            detail = "EOM customer handoff failed"
        raise AtlasFunnelRequestError(response.status_code, detail)
    if not isinstance(content, dict):
        raise AtlasFunnelRequestError(
            502,
            "EOM customer handoff service returned an invalid response",
        )
    return content


# Defined here rather than beside its caller so the allow-list below can be
# derived from it. Two copies of one path drift silently, and the drift is not
# cosmetic: the allow-list rejects an unlisted path with RuntimeError, which is
# not an HTTPException and so escapes the degradation path in
# _verify_atlas_contact_links instead of reporting status=unavailable.
_KNOWN_CONTACTS_PATH = "/eom-funnel/known-contacts"

# GET reads Atlas allows through the funnel credential. Kept as an explicit
# allow-list, not an open passthrough: a caller that could read any funnel path
# would turn this EOM-scoped token into a broad read oracle. known-contacts
# (ATLAS #2352) is id-only link verification, added for the write-boundary audit.
_ATLAS_FUNNEL_READ_PATHS = frozenset({"/eom-funnel/leads", _KNOWN_CONTACTS_PATH})


def _atlas_funnel_read(
    path: str,
    admin: Dict[str, Any],
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Read Atlas EOM funnel state without exposing the service credential."""
    _require_atlas_funnel_configuration()
    if path not in _ATLAS_FUNNEL_READ_PATHS:
        raise RuntimeError("Invalid EOM funnel read path")
    headers = {
        "Authorization": f"Bearer {ATLAS_FUNNEL_SERVICE_TOKEN}",
        "X-EOM-Actor": str(admin["name"]),
        "X-EOM-Actor-ID": str(admin["id"]),
        "Accept": "application/json",
    }
    try:
        response = requests.get(
            f"{ATLAS_FUNNEL_BASE_URL}{path}",
            headers=headers,
            params=params,
            timeout=ATLAS_FUNNEL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=503,
            detail="EOM lead review service is temporarily unavailable; retry this request",
        ) from exc
    try:
        content = response.json()
    except ValueError as exc:
        if response.status_code >= 500:
            raise HTTPException(
                status_code=response.status_code,
                detail="EOM lead review service is temporarily unavailable; retry this request",
            ) from exc
        raise HTTPException(
            status_code=502, detail="EOM lead review service returned an invalid response"
        ) from exc
    if response.status_code in (401, 403):
        logger.error(
            "Atlas EOM funnel service credential rejected status=%s",
            response.status_code,
        )
        raise HTTPException(
            status_code=502,
            detail="EOM lead review service authentication failed",
        )
    if response.status_code >= 400:
        detail: Any = content.get("detail", content) if isinstance(content, dict) else content
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or "EOM lead review failed"
        if not isinstance(detail, str) or not detail.strip():
            detail = "EOM lead review failed"
        headers = {"Retry-After": "5"} if response.status_code >= 500 else None
        raise HTTPException(status_code=response.status_code, detail=detail, headers=headers)
    if not isinstance(content, dict):
        raise HTTPException(status_code=502, detail="EOM lead review service returned an invalid response")
    return content


# Funnel capability names published by Atlas on the lead-review read. These are
# the names Atlas emits (atlas_brain/eom_api/funnel.py::_CAPABILITY_ROUTES), not
# names this service invents: a value here that Atlas never emits would gate a
# control off permanently.
ATLAS_FUNNEL_CAPABILITY_LEAD_LOST = "lead.lost"
ATLAS_FUNNEL_CAPABILITY_LEAD_REOPEN = "lead.reopen"
ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION = "contact.operator_mutation"

# The Atlas operator-mutation boundary this service writes customers through.
# `_atlas_funnel_request` requires the "/eom-funnel/" prefix and prepends
# ATLAS_FUNNEL_BASE_URL, which already ends in /api/v1.
ATLAS_OPERATOR_CONTACTS_PATH = "/eom-funnel/operator-contacts"

# Atlas constrains sourceChannel to a closed set
# (atlas_brain/services/eom_crm_mutations.py::EOM_OPERATOR_SOURCE_CHANNELS);
# this service is the tracker.
ATLAS_OPERATOR_SOURCE_CHANNEL = "time_tracker"


class AtlasFunnelCapabilityUnavailable(Exception):
    """The deployed Atlas does not serve the capability this action requires.

    A normal, expected state -- not a failure. Website (Vercel) and tracker
    (Render) auto-deploy from main while Atlas is deployed by hand, so the
    tracker running ahead of Atlas is the steady state. Distinct from
    AtlasFunnelRequestError, which means Atlas was reached and something went
    wrong; here Atlas is healthy and simply older than this caller.
    """

    def __init__(self, capability: str) -> None:
        super().__init__(
            f"The EOM funnel service does not yet support this action ({capability})"
        )
        self.capability = capability


def _extract_atlas_funnel_capabilities(
    content: Dict[str, Any]
) -> Optional[FrozenSet[str]]:
    """Capabilities Atlas advertises, or None when it did not advertise at all.

    None (key absent) and frozenset() (key present but empty) both mean "no
    capability confirmed", but only None means the deployed Atlas predates the
    manifest. Kept distinct because it is the version signal, and because
    collapsing them would make a rollback indistinguishable from a backend that
    genuinely serves nothing.

    Malformed shapes degrade to None rather than raising: an unreadable manifest
    must not break the lead queue, and "cannot confirm" is already the safe
    reading. Non-string members are dropped instead of poisoning the whole set.
    """
    if "capabilities" not in content:
        return None
    raw = content.get("capabilities")
    if not isinstance(raw, list):
        return None
    return frozenset(
        item.strip() for item in raw if isinstance(item, str) and item.strip()
    )


def _parse_atlas_lead_review_response(content: Dict[str, Any]) -> Dict[str, Any]:
    leads = content.get("leads")
    if not isinstance(leads, list):
        raise HTTPException(status_code=502, detail="EOM lead review service returned an invalid response")
    has_more = content.get("hasMore")
    next_cursor = _strip_optional_atlas_text(content.get("nextCursor"))
    cursor = _strip_optional_atlas_text(content.get("cursor"))
    if not isinstance(has_more, bool):
        raise HTTPException(status_code=502, detail="EOM lead review service returned an invalid response")
    if has_more and not next_cursor:
        raise HTTPException(status_code=502, detail="EOM lead review service returned an invalid response")
    parsed: List[Dict[str, Any]] = []
    for item in leads:
        if not isinstance(item, dict):
            raise HTTPException(
                status_code=502, detail="EOM lead review service returned an invalid response"
            )
        try:
            contact_id = str(UUID(str(item.get("contactId", ""))))
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=502, detail="EOM lead review service returned an invalid response"
            ) from exc
        full_name = str(item.get("fullName") or "").strip()
        created_at = str(item.get("createdAt") or "").strip()
        if not full_name or not created_at:
            raise HTTPException(
                status_code=502, detail="EOM lead review service returned an invalid response"
            )
        parsed.append(
            {
                "contactId": contact_id,
                "fullName": full_name,
                "email": _strip_optional_atlas_text(item.get("email")),
                "phone": _strip_optional_atlas_text(item.get("phone")),
                "address": _strip_optional_atlas_text(item.get("address")),
                "source": _strip_optional_atlas_text(item.get("source")),
                "createdAt": created_at,
            }
        )
    return {
        "leads": parsed,
        "cursor": cursor,
        "hasMore": has_more,
        "nextCursor": next_cursor,
        "capabilities": _extract_atlas_funnel_capabilities(content),
    }


def _validate_atlas_customer_handoff_result(
    atlas_result: Dict[str, Any],
    *,
    contact_id: str,
    customer_id: int,
    site_id: int,
    idempotency_key: str,
) -> str:
    try:
        response_customer_id = int(atlas_result.get("tracker_customer_id", 0))
        response_site_id = int(atlas_result.get("tracker_site_id", 0))
    except (TypeError, ValueError):
        response_customer_id = 0
        response_site_id = 0
    atlas_handoff_id = str(atlas_result.get("handoff_id", "")).strip()
    if (
        atlas_result.get("success") is not True
        or str(atlas_result.get("contact_id", "")) != contact_id
        or response_customer_id != customer_id
        or response_site_id != site_id
        or str(atlas_result.get("approval_key", "")) != idempotency_key
        or not atlas_handoff_id
    ):
        raise AtlasFunnelRequestError(
            502, "EOM customer handoff service returned a mismatched response"
        )
    return atlas_handoff_id


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
FUNNEL_LEAD_TRANSITION_LOCK = "eom_funnel_lead_transition_v1"


def _lock_customer_site_mutations(cur: Any) -> None:
    """Serialize the small admin mutation surface before taking row locks."""
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))",
        (CUSTOMER_SITE_MUTATION_LOCK,),
    )


def _lock_funnel_lead_transition(cur: Any, contact_id: str) -> None:
    """Serialize one Atlas lead's local transition with its remote command."""
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
        (FUNNEL_LEAD_TRANSITION_LOCK, contact_id),
    )


# The set Atlas owns, mirrored here. This tuple is the single tracker-side
# source: the CHECK constraint below is GENERATED from it, so the literal
# cannot drift between the filter and the database the way two hand-written
# copies would.
#
# It remains an enumerated copy of an externally owned set -- the tracker
# cannot import Atlas's definition across the repo boundary. A value Atlas
# adds later is therefore dropped by the mirror (recorded as 'unknown', never
# stored wrong) until this tuple is updated, which is the safe direction to
# fail. Deriving it for real needs Atlas to publish the set, e.g. through the
# capability manifest; tracked separately.
CUSTOMER_TYPES = ("residential", "commercial", "unknown")

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
                CREATE TABLE IF NOT EXISTS eom_office_conversion_handoffs (
                    atlas_contact_id UUID PRIMARY KEY,
                    idempotency_key UUID NOT NULL UNIQUE,
                    request_fingerprint VARCHAR(64) NOT NULL,
                    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
                    site_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
                    approved_by_employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
                    state VARCHAR(16) NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'finalized')),
                    atlas_handoff_id UUID,
                    last_error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    finalized_at TIMESTAMPTZ
                );
                CREATE INDEX IF NOT EXISTS idx_eom_office_conversion_handoffs_state
                    ON eom_office_conversion_handoffs(state, updated_at);
                """
            )
            # Slice 0C: the durable half of "Atlas is the only write authority
            # for customers". A reservation is written and committed BEFORE
            # Atlas is called, and the local `customers` row is written only
            # after Atlas confirms -- so an unreachable Atlas can never leave a
            # canonical customer behind. `id` doubles as the Atlas sourceRef,
            # which is what makes a replay resolve to the same contact.
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS eom_customer_atlas_reservations (
                    id UUID PRIMARY KEY,
                    idempotency_key UUID NOT NULL UNIQUE,
                    request_fingerprint VARCHAR(64) NOT NULL,
                    payload JSONB NOT NULL,
                    mode VARCHAR(16) NOT NULL DEFAULT 'create'
                        CHECK (mode IN ('create', 'link_existing')),
                    customer_id INTEGER REFERENCES customers(id) ON DELETE RESTRICT,
                    atlas_contact_id UUID,
                    state VARCHAR(16) NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'finalized')),
                    requested_by_employee_id INTEGER NOT NULL
                        REFERENCES employees(id) ON DELETE RESTRICT,
                    last_error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    finalized_at TIMESTAMPTZ,
                    CONSTRAINT eom_customer_atlas_reservations_finalized_complete
                        CHECK (
                            state <> 'finalized'
                            OR (
                                customer_id IS NOT NULL
                                AND atlas_contact_id IS NOT NULL
                            )
                        ),
                    CONSTRAINT eom_customer_atlas_reservations_link_has_customer
                        CHECK (mode <> 'link_existing' OR customer_id IS NOT NULL)
                );
                CREATE INDEX IF NOT EXISTS idx_eom_customer_atlas_reservations_state
                    ON eom_customer_atlas_reservations(state, updated_at);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS eom_lead_working (
                    atlas_contact_id UUID PRIMARY KEY,
                    state VARCHAR(16) NOT NULL DEFAULT 'working'
                        CHECK (state IN ('working', 'lost', 'reopened')),
                    state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version >= 1),
                    marked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    marked_by_employee_id INTEGER NOT NULL
                        REFERENCES employees(id) ON DELETE RESTRICT,
                    lost_at TIMESTAMPTZ,
                    lost_by_employee_id INTEGER REFERENCES employees(id) ON DELETE RESTRICT,
                    reopened_at TIMESTAMPTZ,
                    reopened_by_employee_id INTEGER REFERENCES employees(id) ON DELETE RESTRICT
                );
                """
            )
            cur.execute(
                """
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS state VARCHAR(16) NOT NULL DEFAULT 'working';
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS state_version INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS lost_at TIMESTAMPTZ;
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS lost_by_employee_id
                        INTEGER REFERENCES employees(id) ON DELETE RESTRICT;
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ;
                ALTER TABLE eom_lead_working
                    ADD COLUMN IF NOT EXISTS reopened_by_employee_id
                        INTEGER REFERENCES employees(id) ON DELETE RESTRICT;
                ALTER TABLE eom_lead_working
                    ALTER COLUMN marked_by_employee_id DROP NOT NULL;
                """
            )
            cur.execute(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conrelid = 'eom_lead_working'::regclass
                          AND conname = 'eom_lead_working_state_check'
                    ) THEN
                        ALTER TABLE eom_lead_working
                            ADD CONSTRAINT eom_lead_working_state_check
                            CHECK (state IN ('working', 'lost', 'reopened'));
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conrelid = 'eom_lead_working'::regclass
                          AND conname = 'eom_lead_working_state_version_check'
                    ) THEN
                        ALTER TABLE eom_lead_working
                            ADD CONSTRAINT eom_lead_working_state_version_check
                            CHECK (state_version >= 1);
                    END IF;
                END $$;
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

WEEKLY_SCHEDULE_SCHEMA_LOCK_TIMEOUT = "5s"


def _ensure_weekly_schedule_site_schema() -> None:
    """Finalize weekly schedule identity after the Site-aware rollout."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SET LOCAL lock_timeout = %s",
                (WEEKLY_SCHEDULE_SCHEMA_LOCK_TIMEOUT,),
            )
            _lock_customer_site_mutations(cur)
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("eom_weekly_schedule_site_schema_v2",),
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schedules (
                    id              SERIAL PRIMARY KEY,
                    employee_id     INTEGER NOT NULL REFERENCES employees(id),
                    location_id     INTEGER REFERENCES locations(id),
                    customer_name   TEXT NOT NULL,
                    week_start      DATE NOT NULL,
                    scheduled_hours NUMERIC(6, 2) NOT NULL,
                    notes           TEXT NOT NULL DEFAULT '',
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                ALTER TABLE schedules ADD COLUMN IF NOT EXISTS
                    location_id INTEGER REFERENCES locations(id);

                LOCK TABLE schedules IN SHARE ROW EXCLUSIVE MODE;

                CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_schedules_employee_site_week
                    ON schedules(employee_id, location_id, week_start)
                    WHERE location_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_schedules_employee_legacy_name_week
                    ON schedules(employee_id, customer_name, week_start)
                    WHERE location_id IS NULL;

                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_index index_row
                        WHERE index_row.indexrelid = to_regclass(
                                  'uq_schedules_employee_site_week'
                              )
                          AND index_row.indrelid = 'schedules'::regclass
                          AND index_row.indisunique
                          AND index_row.indisvalid
                          AND index_row.indisready
                          AND index_row.indnkeyatts = 3
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 1, true
                              ) = 'employee_id'
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 2, true
                              ) = 'location_id'
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 3, true
                              ) = 'week_start'
                          AND replace(
                                  replace(
                                      pg_get_expr(
                                          index_row.indpred,
                                          index_row.indrelid
                                      ),
                                      '(',
                                      ''
                                  ),
                                  ')',
                                  ''
                              ) = 'location_id IS NOT NULL'
                    ) THEN
                        RAISE EXCEPTION
                            'weekly schedule Site identity index is invalid';
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_index index_row
                        WHERE index_row.indexrelid = to_regclass(
                                  'uq_schedules_employee_legacy_name_week'
                              )
                          AND index_row.indrelid = 'schedules'::regclass
                          AND index_row.indisunique
                          AND index_row.indisvalid
                          AND index_row.indisready
                          AND index_row.indnkeyatts = 3
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 1, true
                              ) = 'employee_id'
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 2, true
                              ) = 'customer_name'
                          AND pg_get_indexdef(
                                  index_row.indexrelid, 3, true
                              ) = 'week_start'
                          AND replace(
                                  replace(
                                      pg_get_expr(
                                          index_row.indpred,
                                          index_row.indrelid
                                      ),
                                      '(',
                                      ''
                                  ),
                                  ')',
                                  ''
                              ) = 'location_id IS NULL'
                    ) THEN
                        RAISE EXCEPTION
                            'weekly schedule legacy identity index is invalid';
                    END IF;
                END $$;

                DO $$
                DECLARE
                    legacy_constraint RECORD;
                BEGIN
                    FOR legacy_constraint IN
                        SELECT constraint_row.conname
                        FROM pg_constraint constraint_row
                        WHERE constraint_row.conrelid = 'schedules'::regclass
                          AND constraint_row.contype = 'u'
                          AND (
                              SELECT array_agg(
                                  attribute_row.attname
                                  ORDER BY attribute_row.attname
                              )
                              FROM unnest(constraint_row.conkey)
                                   AS key_row(attnum)
                              JOIN pg_attribute attribute_row
                                ON attribute_row.attrelid =
                                   constraint_row.conrelid
                               AND attribute_row.attnum = key_row.attnum
                          ) = ARRAY[
                              'customer_name',
                              'employee_id',
                              'week_start'
                          ]::name[]
                    LOOP
                        EXECUTE format(
                            'ALTER TABLE schedules DROP CONSTRAINT %I',
                            legacy_constraint.conname
                        );
                    END LOOP;

                    IF EXISTS (
                        SELECT 1
                        FROM pg_constraint constraint_row
                        WHERE constraint_row.conrelid = 'schedules'::regclass
                          AND constraint_row.contype = 'u'
                          AND (
                              SELECT array_agg(
                                  attribute_row.attname
                                  ORDER BY attribute_row.attname
                              )
                              FROM unnest(constraint_row.conkey)
                                   AS key_row(attnum)
                              JOIN pg_attribute attribute_row
                                ON attribute_row.attrelid =
                                   constraint_row.conrelid
                               AND attribute_row.attnum = key_row.attnum
                          ) = ARRAY[
                              'customer_name',
                              'employee_id',
                              'week_start'
                          ]::name[]
                    ) THEN
                        RAISE EXCEPTION
                            'legacy weekly schedule name constraint remains';
                    END IF;
                END $$;

                DROP INDEX IF EXISTS idx_schedules_site_week;
                """
            )


def _ensure_employee_role_schema() -> None:
    """Allow the payroll role on existing employee tables without touching rows."""
    db.execute(
        """
        DO $$
        DECLARE
            role_constraint RECORD;
        BEGIN
            FOR role_constraint IN
                SELECT constraint_row.conname
                FROM pg_constraint constraint_row
                WHERE constraint_row.conrelid = 'employees'::regclass
                  AND constraint_row.contype = 'c'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(constraint_row.conkey) AS key_row(attnum)
                      JOIN pg_attribute attribute_row
                        ON attribute_row.attrelid = constraint_row.conrelid
                       AND attribute_row.attnum = key_row.attnum
                      WHERE attribute_row.attname = 'role'
                  )
                  AND pg_get_constraintdef(constraint_row.oid) NOT LIKE '%%payroll%%'
            LOOP
                EXECUTE format(
                    'ALTER TABLE employees DROP CONSTRAINT %%I',
                    role_constraint.conname
                );
            END LOOP;

            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint constraint_row
                WHERE constraint_row.conrelid = 'employees'::regclass
                  AND constraint_row.contype = 'c'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(constraint_row.conkey) AS key_row(attnum)
                      JOIN pg_attribute attribute_row
                        ON attribute_row.attrelid = constraint_row.conrelid
                       AND attribute_row.attnum = key_row.attnum
                      WHERE attribute_row.attname = 'role'
                  )
                  AND pg_get_constraintdef(constraint_row.oid) LIKE '%%payroll%%'
            ) THEN
                ALTER TABLE employees
                    ADD CONSTRAINT employees_role_check
                    CHECK (role IN ('admin', 'employee', 'payroll'));
            END IF;
        END $$;
        """
    )


def _backfill_shift_hourly_rate_snapshots() -> None:
    """Stamp shifts that predate the rate snapshot with the employee's current rate.

    Numerically a no-op on the day it runs: it records exactly what every money
    surface already computes from the live rate. Its purpose is to freeze that
    figure so a later rate edit cannot restate it.

    Honest caveat: rate changes made BEFORE this ran are unrecoverable, so this
    records "the rate as of migration", not reconstructed history.

    Idempotent by the `hourly_rate_cents IS NULL` guard -- a shift that already
    carries a snapshot is never rewritten, so re-running changes nothing.
    Employees with no configured rate leave the shift NULL rather than inventing
    a zero; those shifts keep falling back to the live rate and therefore keep
    each surface's existing missing-rate policy.
    """
    db.execute(
        """
        UPDATE shifts
        SET hourly_rate_cents = ROUND(e.hourly_rate * 100)
        FROM employees e
        WHERE shifts.employee_id = e.id
          AND shifts.hourly_rate_cents IS NULL
          AND e.hourly_rate IS NOT NULL
        """
    )


_SHIFT_RATE_BACKFILL_MARKER = "_migration.rate_snapshot_shift_backfill_completed"
# (The allocation reconcile is no longer marker-gated -- it runs re-runnably
# over IS NULL rows -- so its old completion marker was removed.)


def _run_one_time_shift_rate_backfill() -> None:
    """Stamp pre-existing shifts once, on the boot that introduces the snapshot.

    _ensure_schema_migrations runs on every startup, so calling the backfill
    unconditionally would re-stamp a shift created AFTER the migration for an
    employee who had no rate at the time -- freezing a rate the work was not
    done at and breaking the documented "rate-less shifts follow the live rate"
    contract. A persistent marker in ``settings`` makes this run exactly once:
    the first boot stamps every then-existing NULL snapshot; every later boot
    skips it, so a rate-less shift created afterwards keeps its NULL and its
    live-rate fallback. The backfill and the marker commit together, so a
    failure leaves both undone and the next boot retries cleanly.
    """
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT 1 FROM settings WHERE key = %s",
                (_SHIFT_RATE_BACKFILL_MARKER,),
            )
            if cur.fetchone():
                return
            cur.execute(
                """
                UPDATE shifts
                SET hourly_rate_cents = ROUND(e.hourly_rate * 100)
                FROM employees e
                WHERE shifts.employee_id = e.id
                  AND shifts.hourly_rate_cents IS NULL
                  AND e.hourly_rate IS NOT NULL
                """
            )
            cur.execute(
                "INSERT INTO settings (key, value) VALUES (%s, 'true'::jsonb) "
                "ON CONFLICT (key) DO NOTHING",
                (_SHIFT_RATE_BACKFILL_MARKER,),
            )


def _reconcile_unstamped_allocation_costs() -> None:
    """Price any allocation whose cost provenance is unknown, re-runnably.

    An allocation has NULL ``allocated_labor_cost_is_live`` in exactly two cases,
    both meaning "written without this code's provenance logic": a row that
    predates the column, or one an OLD app instance wrote during a rolling
    deploy (its writer omits the column, so the nullable-no-default column stays
    NULL). Both stored a live-rate cost that may disagree with the shift's worked
    rate and must not be trusted as frozen.

    Unlike the shift backfill -- where a NULL snapshot is a permanent, legitimate
    state for a rate-less shift, so that backfill is one-time and marker-gated --
    a NULL provenance here is always a transient "not yet reconciled" state that
    the write path never produces. So this runs every boot but only touches
    ``IS NULL`` rows: idempotent, cheap (normally zero rows), and it catches
    deploy-window writes on the next boot. Each row is repriced through the same
    resolver new allocations use, then stamped TRUE/FALSE so it is never
    revisited. Reads treat a still-NULL row as live-valued in the meantime, so a
    boundary row is never silently frozen while it waits.
    """
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT a.id, a.employee_id, a.correction_date, a.location_id,
                       a.allocated_delta_minutes, e.hourly_rate AS live_hourly_rate
                FROM payroll_hour_correction_allocations a
                JOIN employees e ON e.id = a.employee_id
                WHERE a.status = 'active'
                  AND a.allocated_labor_cost_is_live IS NULL
                """
            )
            allocations = cur.fetchall() or []
            for row in allocations:
                rate, resolved, from_snapshot = _payroll_correction_rate_for_allocation(
                    cur,
                    employee_id=int(row["employee_id"]),
                    correction_date=row["correction_date"],
                    location_id=int(row["location_id"]),
                    live_hourly_rate=row.get("live_hourly_rate"),
                )
                new_cost, is_live = _payroll_correction_allocation_cost(
                    int(row["allocated_delta_minutes"]),
                    rate,
                    resolved,
                    from_snapshot,
                )
                cur.execute(
                    """
                    UPDATE payroll_hour_correction_allocations
                    SET allocated_labor_cost_cents = %s,
                        allocated_labor_cost_is_live = %s
                    WHERE id = %s
                    """,
                    (new_cost, is_live, int(row["id"])),
                )


def _ensure_schema_migrations() -> None:
    """Idempotent schema additions for existing deployments."""
    _ensure_customer_site_schema()
    _ensure_employee_role_schema()
    # atlas_contact_id shipped inside CREATE TABLE IF NOT EXISTS customers and
    # was never applied via ALTER, so a customers table created before that
    # revision would lack the column. Additive and idempotent.
    db.execute(
        "ALTER TABLE customers ADD COLUMN IF NOT EXISTS atlas_contact_id UUID"
    )
    # Read-mirror of the Atlas account type (ATLAS #2354). Atlas is the write
    # authority; this copy exists so the portal, which reads customers from
    # here rather than from Atlas, can render the type and adapt billing to it
    # without a per-row round trip.
    #
    # 'unknown' rather than NULL for the same reason Atlas uses it: a customer
    # whose type has not been established is a distinct state, and every row
    # that predates this column genuinely is in it. The CHECK keeps the mirror
    # from holding a value Atlas itself would refuse.
    db.execute(
        "ALTER TABLE customers ADD COLUMN IF NOT EXISTS customer_type "
        "VARCHAR(16) NOT NULL DEFAULT 'unknown'"
    )
    # Rebuilt ONLY when the deployed constraint disagrees with CUSTOMER_TYPES.
    #
    # Two failure modes to avoid at once. Creating it only when absent pins an
    # existing deployment to the old set, so a value added to the tuple would be
    # accepted by the parser and then violate a stale CHECK -- rejecting local
    # finalization AFTER Atlas created the contact. Dropping and re-adding on
    # every boot avoids that but takes an exclusive table lock and revalidates
    # every row on each deploy, which can block live traffic.
    #
    # Comparing first gives both: no DDL and no lock on the overwhelmingly
    # common path where nothing changed, and a real rebuild exactly when the set
    # moves. The comparison is on the SET of literals Postgres renders, not on
    # the string, so its formatting is not load-bearing.
    deployed = db.query_one(
        """
        SELECT pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conname = 'chk_customers_customer_type'
          AND conrelid = 'customers'::regclass
        """
    )
    expected_values = set(CUSTOMER_TYPES)
    deployed_values = (
        set(re.findall(r"'([^']*)'", deployed["definition"])) if deployed else None
    )
    if deployed_values != expected_values:
        values_sql = ", ".join(f"'{value}'" for value in CUSTOMER_TYPES)
        db.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'chk_customers_customer_type'
                      AND conrelid = 'customers'::regclass
                ) THEN
                    ALTER TABLE customers
                        DROP CONSTRAINT chk_customers_customer_type;
                END IF;
                ALTER TABLE customers
                    ADD CONSTRAINT chk_customers_customer_type
                    CHECK (customer_type IN ({values_sql}));
            END $$;
            """
        )
    db.execute("""
        CREATE TABLE IF NOT EXISTS atlas_linkage_backfill_batches (
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
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_atlas_linkage_backfill_batches_created
            ON atlas_linkage_backfill_batches(created_at)
    """)
    db.execute("""
        ALTER TABLE employees
            ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS access_log_entries (
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
        )
    """)
    db.execute("""
        ALTER TABLE access_log_entries
            ADD COLUMN IF NOT EXISTS event_id TEXT;

        UPDATE access_log_entries
        SET event_id = COALESCE(NULLIF(entry->>'eventId', ''), 'legacy-' || id::text)
        WHERE event_id IS NULL OR event_id = '';

        ALTER TABLE access_log_entries
            ALTER COLUMN event_id SET NOT NULL;
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_access_log_entries_event_id
        ON access_log_entries(event_id)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_log_entries_local_date
        ON access_log_entries(local_date, logged_at, id)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_log_entries_logged_at
        ON access_log_entries(logged_at)
    """)
    _prune_access_log_entries()
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
    db.execute("""
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_source VARCHAR(32)
                NOT NULL DEFAULT 'manual';
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_decision VARCHAR(16);
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_fingerprint VARCHAR(64);
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_snapshot JSONB;
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_decided_at TIMESTAMPTZ;
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_decided_by
                INTEGER REFERENCES employees(id) ON DELETE SET NULL;
        ALTER TABLE locations
            ADD COLUMN IF NOT EXISTS expected_hours_learning_decision_reason
                TEXT NOT NULL DEFAULT '';
    """)
    db.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'locations'::regclass
                  AND conname = 'locations_expected_hours_source_check'
            ) THEN
                ALTER TABLE locations
                    ADD CONSTRAINT locations_expected_hours_source_check
                    CHECK (expected_hours_source IN ('manual', 'learned_accepted'));
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'locations'::regclass
                  AND conname = 'locations_expected_hours_learning_decision_check'
            ) THEN
                ALTER TABLE locations
                    ADD CONSTRAINT locations_expected_hours_learning_decision_check
                    CHECK (
                        expected_hours_learning_decision IS NULL
                        OR expected_hours_learning_decision IN ('accepted', 'rejected')
                    );
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'locations'::regclass
                  AND conname = 'locations_expected_hours_learning_fingerprint_check'
            ) THEN
                ALTER TABLE locations
                    ADD CONSTRAINT locations_expected_hours_learning_fingerprint_check
                    CHECK (
                        expected_hours_learning_fingerprint IS NULL
                        OR expected_hours_learning_fingerprint ~ '^[0-9a-f]{64}$'
                    );
            END IF;
        END $$;
    """)
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
        CREATE TABLE IF NOT EXISTS service_schedule_rules (
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
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_service_schedule_rules_location
        ON service_schedule_rules(location_id, active, starts_on, ends_on)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_service_schedule_rules_window
        ON service_schedule_rules(active, starts_on, ends_on)
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
    arrival_policies.ensure_schema()
    db.execute("""
        ALTER TABLE site_check_ins
        ADD COLUMN IF NOT EXISTS job_id
            INTEGER REFERENCES jobs(id) ON DELETE SET NULL
    """)
    db.execute(
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS job_id INTEGER REFERENCES jobs(id)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_scheduled_date ON jobs(scheduled_date)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_customer ON jobs(customer_name)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_check_ins_job_time
        ON site_check_ins(job_id, server_checked_in_at DESC)
        WHERE job_id IS NOT NULL
    """)
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
        "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS hourly_rate_cents INTEGER"
    )
    # DB-level snapshot stamp on every shift INSERT. The app also stamps at
    # clock-in, but a mid-deploy OLD instance whose code predates the column
    # omits it entirely; this trigger stamps those rows so the rolling-deploy
    # window cannot leave a rated employee's shift unsnapshotted. Only fills a
    # NULL (an app-supplied value wins) and leaves a rate-less employee NULL.
    # CREATE OR REPLACE + DROP/CREATE TRIGGER are idempotent. NOTE: this is the
    # only trigger in the codebase.
    db.execute("""
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
    """)
    # DROP + CREATE the trigger in a SINGLE transaction so the trigger is never
    # absent between two committed statements -- otherwise an old app instance
    # inserting a shift in that window would escape stamping. Kept as DROP/CREATE
    # (rather than CREATE OR REPLACE TRIGGER, PG14+) so it is version-agnostic.
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DROP TRIGGER IF EXISTS trg_stamp_shift_hourly_rate_cents ON shifts"
            )
            cur.execute("""
                CREATE TRIGGER trg_stamp_shift_hourly_rate_cents
                    BEFORE INSERT ON shifts
                    FOR EACH ROW
                    EXECUTE FUNCTION stamp_shift_hourly_rate_cents()
            """)
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS gps_meta JSONB"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS location_label TEXT NOT NULL DEFAULT ''"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS "
        "job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS "
        "sequence_version SMALLINT NOT NULL DEFAULT 1"
    )
    db.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conrelid = 'visits'::regclass
                  AND conname = 'visits_sequence_version_check'
            ) THEN
                ALTER TABLE visits
                    ADD CONSTRAINT visits_sequence_version_check
                    CHECK (sequence_version IN (1, 2));
            END IF;
        END $$;
    """)
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
    db.execute(
        "ALTER TABLE departures ADD COLUMN IF NOT EXISTS "
        "visit_id INTEGER REFERENCES visits(id) ON DELETE SET NULL"
    )
    db.execute(
        "ALTER TABLE visits ADD COLUMN IF NOT EXISTS "
        "site_check_in_id BIGINT REFERENCES site_check_ins(id) ON DELETE SET NULL"
    )
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_departures_visit_id
        ON departures(visit_id) WHERE visit_id IS NOT NULL
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_visits_site_check_in_id
        ON visits(site_check_in_id) WHERE site_check_in_id IS NOT NULL
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_visits_job_id ON visits(job_id)")
    db.execute("""
        UPDATE visits AS v
        SET job_id = ci.job_id
        FROM site_check_ins AS ci
        WHERE v.site_check_in_id = ci.id
          AND v.job_id IS NULL
          AND ci.job_id IS NOT NULL
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS site_qr_action_receipts (
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
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_site_qr_action_receipts_shift
        ON site_qr_action_receipts(shift_id, server_recorded_at DESC)
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS plain_time_action_receipts (
            id                    BIGSERIAL PRIMARY KEY,
            employee_id           INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            shift_id              INTEGER REFERENCES shifts(id) ON DELETE SET NULL,
            action                VARCHAR(16) NOT NULL
                                      CHECK (action IN (
                                          'clock-in', 'arrive',
                                          'depart', 'clock-out'
                                      )),
            idempotency_key       UUID NOT NULL,
            request_fingerprint   VARCHAR(64) NOT NULL
                                      CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
            server_recorded_at    TIMESTAMPTZ NOT NULL,
            response_body         JSONB NOT NULL,
            created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (employee_id, idempotency_key)
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_plain_time_action_receipts_shift
        ON plain_time_action_receipts(shift_id, server_recorded_at DESC)
    """)
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
    # ATLAS #2357: durable record of each customer_type mirror refresh. The
    # snapshot holds the exact from/to per customer, so a refresh driven by a
    # wrong Atlas value can be read back and reversed.
    # plan_token is deliberately NOT unique here, unlike the linkage-backfill
    # table this was modelled on. There the token hashes operator-supplied
    # mappings; here it hashes a DERIVED diff, and the same diff legitimately
    # recurs -- a customer moved commercial -> residential -> commercial ->
    # residential produces the identical token on the first and third refresh.
    # The batch id is the identity; the token stays for traceability.
    db.execute("""
        CREATE TABLE IF NOT EXISTS customer_type_refresh_batches (
            id                     BIGSERIAL PRIMARY KEY,
            plan_token             TEXT NOT NULL,
            applied_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            applied_by_name        TEXT NOT NULL,
            reason                 TEXT NOT NULL,
            snapshot               JSONB NOT NULL,
            result                 JSONB NOT NULL,
            created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    # Drop the UNIQUE that an earlier build of this table created, so a database
    # already carrying it stops rejecting a legitimate repeated transition.
    db.execute(
        "ALTER TABLE customer_type_refresh_batches "
        "DROP CONSTRAINT IF EXISTS customer_type_refresh_batches_plan_token_key"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_type_refresh_batches_created "
        "ON customer_type_refresh_batches(created_at)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_type_refresh_batches_token "
        "ON customer_type_refresh_batches(plan_token)"
    )
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_verification_batches (
            id                      BIGSERIAL PRIMARY KEY,
            week_start              DATE NOT NULL UNIQUE,
            week_end                DATE NOT NULL,
            timezone                TEXT NOT NULL,
            status                  VARCHAR(16) NOT NULL DEFAULT 'verified'
                                        CHECK (status IN ('verified', 'reopened', 'finalized')),
            source_fingerprint      VARCHAR(64) NOT NULL
                                        CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
            snapshot                JSONB NOT NULL,
            verified_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            verified_by_name        TEXT NOT NULL,
            verified_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reopened_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            reopened_by_name        TEXT,
            reopened_reason         TEXT,
            reopened_at             TIMESTAMPTZ,
            finalized_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            finalized_by_name       TEXT,
            finalized_at            TIMESTAMPTZ,
            created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (week_end = week_start + 6)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_verification_events (
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
        )
    """)
    # Money (payroll dollars) verification: a second, independent truth from the
    # hours sign-off. Mirrors the hours tables but has NO finalized state -- the
    # payroll-level FINALIZED lives on the hours batch, gated on a current money
    # verification. source_fingerprint here is the money-inclusive timesheet
    # fingerprint (timesheetSourceFingerprint).
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_money_verification_batches (
            id                      BIGSERIAL PRIMARY KEY,
            week_start              DATE NOT NULL UNIQUE,
            week_end                DATE NOT NULL,
            timezone                TEXT NOT NULL,
            status                  VARCHAR(16) NOT NULL DEFAULT 'verified'
                                        CHECK (status IN ('verified', 'reopened')),
            source_fingerprint      VARCHAR(64) NOT NULL
                                        CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
            snapshot                JSONB NOT NULL,
            verified_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            verified_by_name        TEXT NOT NULL,
            verified_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reopened_by_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            reopened_by_name        TEXT,
            reopened_reason         TEXT,
            reopened_at             TIMESTAMPTZ,
            created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (week_end = week_start + 6)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_money_verification_events (
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
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_hour_corrections (
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
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_hour_correction_allocations (
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
        )
    """)
    # Cost provenance flag, three-state (TRUE live / FALSE frozen / NULL not yet
    # reconciled). Nullable with NO default: a writer that omits it -- including
    # an old app instance during a rolling deploy -- must leave NULL so the row
    # is distinguishable from a genuinely-frozen FALSE and gets repriced. The
    # DROP DEFAULT / DROP NOT NULL make this idempotent for any install that
    # already added the column in its earlier NOT NULL DEFAULT FALSE shape.
    db.execute(
        "ALTER TABLE payroll_hour_correction_allocations "
        "ADD COLUMN IF NOT EXISTS allocated_labor_cost_is_live BOOLEAN"
    )
    db.execute(
        "ALTER TABLE payroll_hour_correction_allocations "
        "ALTER COLUMN allocated_labor_cost_is_live DROP DEFAULT"
    )
    db.execute(
        "ALTER TABLE payroll_hour_correction_allocations "
        "ALTER COLUMN allocated_labor_cost_is_live DROP NOT NULL"
    )
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_shift_corrections (
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
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_timesheet_change_batches (
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
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_manual_shift_versions (
            id                        BIGSERIAL PRIMARY KEY,
            manual_shift_id           UUID NOT NULL,
            version                   INTEGER NOT NULL CHECK (version > 0),
            week_start                DATE NOT NULL,
            work_date                 DATE NOT NULL,
            employee_id               INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
            clock_in                  TIMESTAMPTZ NOT NULL,
            clock_out                 TIMESTAMPTZ NOT NULL,
            break_minutes             INTEGER NOT NULL DEFAULT 0
                                          CHECK (break_minutes BETWEEN 0 AND 1440),
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
            superseded_by             BIGINT REFERENCES payroll_manual_shift_versions(id)
                                          ON DELETE SET NULL,
            created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (manual_shift_id, version),
            CHECK (work_date >= week_start AND work_date < week_start + 7),
            CHECK (clock_out > clock_in)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payroll_shift_exclusions (
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
        )
    """)
    db.execute("""
        DO $$
        DECLARE
            source_total_constraint RECORD;
            has_current_constraint BOOLEAN := FALSE;
        BEGIN
            FOR source_total_constraint IN
                SELECT
                    constraint_row.conname,
                    pg_get_constraintdef(constraint_row.oid) AS definition
                FROM pg_constraint constraint_row
                WHERE constraint_row.conrelid = 'payroll_shift_corrections'::regclass
                  AND constraint_row.contype = 'c'
                  AND pg_get_constraintdef(constraint_row.oid)
                      LIKE '%%source_total_minutes%%'
            LOOP
                IF replace(source_total_constraint.definition, ' ', '')
                       LIKE '%%source_total_minutes>=0%%'
                   AND source_total_constraint.definition NOT LIKE '%%1440%%' THEN
                    has_current_constraint := TRUE;
                ELSE
                    EXECUTE format(
                        'ALTER TABLE payroll_shift_corrections DROP CONSTRAINT %%I',
                        source_total_constraint.conname
                    );
                END IF;
            END LOOP;

            IF NOT has_current_constraint THEN
                ALTER TABLE payroll_shift_corrections
                    ADD CONSTRAINT payroll_shift_corrections_source_total_minutes_check
                    CHECK (source_total_minutes >= 0);
            END IF;
        END $$;
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_verification_batches_status_week
        ON payroll_verification_batches(status, week_start)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_verification_events_week
        ON payroll_verification_events(week_start, created_at)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_verification_events_batch
        ON payroll_verification_events(batch_id, created_at)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_money_verification_batches_status_week
        ON payroll_money_verification_batches(status, week_start)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_money_verification_events_week
        ON payroll_money_verification_events(week_start, created_at)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_money_verification_events_batch
        ON payroll_money_verification_events(batch_id, created_at)
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_hour_corrections_active_day
        ON payroll_hour_corrections(week_start, employee_id, correction_date)
        WHERE status = 'active'
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_hour_corrections_week
        ON payroll_hour_corrections(week_start, status, correction_date)
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_hour_correction_allocations_active
        ON payroll_hour_correction_allocations(correction_id)
        WHERE status = 'active'
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_hour_correction_allocations_week
        ON payroll_hour_correction_allocations(week_start, status, correction_date)
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_shift_corrections_active_shift
        ON payroll_shift_corrections(week_start, shift_id)
        WHERE status = 'active'
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_shift_corrections_week
        ON payroll_shift_corrections(week_start, status, correction_date)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_timesheet_change_batches_week
        ON payroll_timesheet_change_batches(week_start, employee_id, created_at)
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_manual_shift_versions_current
        ON payroll_manual_shift_versions(manual_shift_id)
        WHERE status = 'current'
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_manual_shift_versions_week
        ON payroll_manual_shift_versions(week_start, employee_id, work_date, status)
    """)
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_shift_exclusions_active
        ON payroll_shift_exclusions(week_start, shift_id)
        WHERE status = 'active'
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_payroll_shift_exclusions_week
        ON payroll_shift_exclusions(week_start, employee_id, status)
    """)

    # Seed threshold defaults if not already in settings
    for key, default_val in _SETTINGS_DEFAULTS.items():
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (%s, %s::jsonb)
            ON CONFLICT (key) DO NOTHING
            """,
            (key, json.dumps(default_val)),
        )

    # Calendar planning is an additive domain. Keeping its migration in the
    # focused module prevents accidental coupling to shifts, QR evidence,
    # customer/location writes, or receivables.
    from calendar_import_store import ensure_schema as ensure_calendar_schema

    ensure_calendar_schema()

    # One-time rate backfills run LAST, after every CREATE TABLE / ALTER above.
    # The allocation backfill queries payroll_hour_correction_allocations and
    # payroll_shift_corrections, which are created earlier in this same function
    # -- running the backfill before those CREATEs raised undefined_table and
    # crashed startup on any upgrade from a schema predating payroll corrections.
    # Both are marker-gated (exactly-once) and each commits its mutation and
    # marker atomically, so their position only needs to be after their tables.
    # Shift backfill: one-time (marker-gated) -- stamps only shifts predating the
    # snapshot column, never re-stamping rate-less shifts created afterwards
    # (their NULL is a permanent, legitimate state).
    _run_one_time_shift_rate_backfill()
    # Allocation reconcile: re-runnable over IS NULL rows -- reprices allocations
    # that predate the provenance column or were written by an old instance
    # during a rolling deploy, catching the latter on the next boot.
    _reconcile_unstamped_allocation_costs()


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
        # The importer inserts shifts without hourly_rate_cents, and the backfill
        # above already ran against an empty table, so imported history would
        # keep a NULL snapshot forever and stay exposed to rate edits. Idempotent.
        _backfill_shift_hourly_rate_snapshots()
    apply_bootstrap_admins()


def _canonical_portal_base(request: Request) -> Optional[str]:
    """PUBLIC_APP_URL when it points somewhere other than this backend.

    Hostname-only comparison: behind the Render proxy the request scheme can
    differ from the public one, and a scheme-sensitive check would let a
    misconfigured PUBLIC_APP_URL redirect the backend to itself in a loop.
    """
    if not PUBLIC_APP_URL:
        return None
    portal_host = (urlsplit(PUBLIC_APP_URL).hostname or "").lower()
    request_host = (request.url.hostname or "").lower()
    if not portal_host or portal_host == request_host:
        return None
    return PUBLIC_APP_URL


def _require_canonical_portal_base(request: Request) -> str:
    portal_base = _canonical_portal_base(request)
    if not portal_base:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="QR check-in portal is not configured",
            headers={"Cache-Control": "no-store"},
        )
    return portal_base


def _site_check_in_url(request: Request, token: str) -> str:
    portal_base = _require_canonical_portal_base(request)
    # Canonical EOM portal (issue #35): /portal, not /portal.html — the
    # website deploy uses cleanUrls and 308-hops the .html form.
    return f"{portal_base}/portal?checkIn={quote(token, safe='')}"


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
        raise HTTPException(status_code=404, detail="Invalid or revoked site QR code")
    return site


SITE_ACTION_STATE_TOKEN_VERSION = "eom-action1"
SITE_ACTION_STATE_TOKEN_TTL_SECONDS = 15 * 60


def _site_action_state_signature(encoded_claims: str) -> str:
    digest = hmac.new(
        JWT_SECRET.encode("utf-8"),
        b"site-action-state\0" + encoded_claims.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _base64url_encode(digest)


def _build_site_action_state_token(claims: Dict[str, Any]) -> str:
    encoded = _base64url_encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return (
        f"{SITE_ACTION_STATE_TOKEN_VERSION}.{encoded}."
        f"{_site_action_state_signature(encoded)}"
    )


def _parse_site_action_state_token(token: str) -> Dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) != 3 or parts[0] != SITE_ACTION_STATE_TOKEN_VERSION:
        raise ValueError("Invalid action state token")
    encoded, signature = parts[1], parts[2]
    expected = _site_action_state_signature(encoded)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid action state token")
    padding = "=" * (-len(encoded) % 4)
    try:
        claims = json.loads(
            base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid action state token") from exc
    if not isinstance(claims, dict):
        raise ValueError("Invalid action state token")
    return claims


def _site_action_visit_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "siteId": (
            int(row["location_id"])
            if row.get("location_id") is not None
            else None
        ),
        "siteName": str(row.get("site_name") or row.get("location_label") or ""),
        "customerName": str(row.get("customer_name") or ""),
        "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
        "arrivalTime": to_utc_iso(row["arrival_time"]),
        "sequenceVersion": int(row.get("sequence_version") or 1),
    }


def _build_site_action_state(
    cur: Any,
    *,
    employee_id: int,
    site: Dict[str, Any],
    reference_time: datetime,
    lock_shifts: bool = False,
) -> Dict[str, Any]:
    lock_clause = " FOR UPDATE" if lock_shifts else ""
    cur.execute(
        """
        SELECT id, employee_id, clock_in, clock_out
        FROM shifts
        WHERE employee_id = %s AND clock_out IS NULL
        ORDER BY clock_in DESC, id DESC
        """ + lock_clause,
        (employee_id,),
    )
    open_shifts = [dict(row) for row in cur.fetchall()]
    base: Dict[str, Any] = {
        "status": "clock_in_required",
        "recommendedAction": None,
        "shiftId": None,
        "activeVisit": None,
        "missingDepartures": [],
        "stateToken": None,
        "blockReason": "active_shift_required",
    }
    if not open_shifts:
        base["_fingerprint"] = hashlib.sha256(
            f"no-shift:{employee_id}".encode("utf-8")
        ).hexdigest()
        return base

    stale_shifts = [
        row
        for row in open_shifts
        if (
            reference_time - row["clock_in"].astimezone(timezone.utc)
        ).total_seconds() > MAX_ACTIVE_SHIFT_HOURS * 3600
    ]
    if stale_shifts or len(open_shifts) > 1:
        base.update(
            {
                "status": "review_required",
                "shiftId": int(open_shifts[0]["id"]),
                "blockReason": (
                    "stale_shift_requires_review"
                    if stale_shifts
                    else "multiple_open_shifts_require_review"
                ),
            }
        )
        fingerprint_material = {
            "employeeId": employee_id,
            "siteId": int(site["id"]),
            "openShiftIds": [int(row["id"]) for row in open_shifts],
            "staleShiftIds": [int(row["id"]) for row in stale_shifts],
        }
        base["_fingerprint"] = hashlib.sha256(
            json.dumps(
                fingerprint_material, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        return base

    shift_id = int(open_shifts[0]["id"])
    cur.execute(
        """
        SELECT v.id, v.location_id, v.location_label, v.customer_name,
               v.arrival_time, v.job_id, v.sequence_version, l.address AS site_name,
               paired.id AS paired_departure_id
        FROM visits v
        LEFT JOIN locations l ON l.id = v.location_id
        LEFT JOIN departures paired ON paired.visit_id = v.id
        WHERE v.shift_id = %s
        ORDER BY v.arrival_time DESC, v.id DESC
        LIMIT 1
        """,
        (shift_id,),
    )
    latest_row = cur.fetchone()
    latest_visit = dict(latest_row) if latest_row else None

    active_visit: Optional[Dict[str, Any]] = None
    if latest_visit:
        if latest_visit.get("paired_departure_id") is not None:
            active_visit = None
        elif int(latest_visit.get("sequence_version") or 1) >= 2:
            active_visit = latest_visit
        else:
            cur.execute(
                """
                SELECT COUNT(*) AS n
                FROM visits
                WHERE shift_id = %s AND sequence_version = 1
                """,
                (shift_id,),
            )
            legacy_visit_count = int(cur.fetchone()["n"])
            cur.execute(
                """
                SELECT COUNT(*) AS n
                FROM departures
                WHERE shift_id = %s AND visit_id IS NULL
                """,
                (shift_id,),
            )
            legacy_departure_count = int(cur.fetchone()["n"])
            if legacy_departure_count < legacy_visit_count:
                active_visit = latest_visit

    cur.execute(
        """
        SELECT v.id, v.location_id, v.location_label, v.customer_name,
               v.arrival_time, v.job_id, v.sequence_version, l.address AS site_name
        FROM visits v
        LEFT JOIN locations l ON l.id = v.location_id
        LEFT JOIN departures paired ON paired.visit_id = v.id
        WHERE v.shift_id = %s
          AND v.sequence_version >= 2
          AND paired.id IS NULL
        ORDER BY v.arrival_time, v.id
        """,
        (shift_id,),
    )
    missing_rows = [dict(row) for row in cur.fetchall()]
    if active_visit and int(active_visit.get("sequence_version") or 1) == 1:
        missing_rows.append(active_visit)

    active_summary = (
        _site_action_visit_summary(active_visit) if active_visit else None
    )
    recommended_action: Literal["arrive", "depart"] = "arrive"
    if (
        active_visit
        and active_visit.get("location_id") is not None
        and int(active_visit["location_id"]) == int(site["id"])
    ):
        recommended_action = "depart"

    cur.execute(
        "SELECT COALESCE(MAX(id), 0) AS latest_id FROM departures WHERE shift_id = %s",
        (shift_id,),
    )
    latest_departure_id = int(cur.fetchone()["latest_id"])
    fingerprint_material = {
        "employeeId": employee_id,
        "siteId": int(site["id"]),
        "shiftId": shift_id,
        "latestVisitId": int(latest_visit["id"]) if latest_visit else None,
        "latestVisitSequenceVersion": (
            int(latest_visit.get("sequence_version") or 1)
            if latest_visit
            else None
        ),
        "latestVisitJobId": (
            int(latest_visit["job_id"])
            if latest_visit and latest_visit.get("job_id") is not None
            else None
        ),
        "latestVisitPairedDepartureId": (
            int(latest_visit["paired_departure_id"])
            if latest_visit and latest_visit.get("paired_departure_id") is not None
            else None
        ),
        "latestDepartureId": latest_departure_id,
        "missingDepartureVisitIds": [int(row["id"]) for row in missing_rows],
        "missingDepartureJobIds": [
            int(row["job_id"]) if row.get("job_id") is not None else None
            for row in missing_rows
        ],
        "recommendedAction": recommended_action,
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_material, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    claims = {
        "employeeId": employee_id,
        "siteId": int(site["id"]),
        "action": recommended_action,
        "stateFingerprint": fingerprint,
        "expiresAt": int(reference_time.timestamp())
        + SITE_ACTION_STATE_TOKEN_TTL_SECONDS,
    }
    return {
        "status": "ready",
        "recommendedAction": recommended_action,
        "shiftId": shift_id,
        "activeVisit": active_summary,
        "missingDepartures": [
            _site_action_visit_summary(row) for row in missing_rows
        ],
        "stateToken": _build_site_action_state_token(claims),
        "blockReason": None,
        "_fingerprint": fingerprint,
    }


def _public_site_action_state(state_row: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in state_row.items() if not key.startswith("_")}


def _site_action_state_error(
    *,
    code: str,
    message: str,
    action_state: Dict[str, Any],
) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": code,
            "message": message,
            "details": {
                "actionState": _public_site_action_state(action_state),
            },
        },
    )


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
        "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
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
        "arrivalPolicyRevisionId": (
            int(row["arrival_policy_revision_id"])
            if row.get("arrival_policy_revision_id")
            else None
        ),
        "arrivalPolicySnapshot": row.get("arrival_policy_snapshot"),
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


def _matching_canonical_site_job(
    site_id: int,
    checked_in_at: datetime,
    *,
    cur: Optional[Any] = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    sql = """
        SELECT j.id, j.location_id, j.status, j.scheduled_start, j.scheduled_end
        FROM jobs j
        JOIN google_calendar_sources source ON source.id = j.calendar_source_id
        JOIN locations site ON site.id = j.location_id
        WHERE j.location_id = %s
          AND site.active = true
          AND (
              (
                  source.role = 'residential_morning'
                  AND site.location_type = 'Residential'
              )
              OR (
                  source.role = 'commercial_evening_night'
                  AND site.location_type = 'Commercial'
              )
          )
          AND j.source_all_day = false
          AND j.scheduled_start IS NOT NULL
          AND j.scheduled_end IS NOT NULL
          AND j.scheduled_end > j.scheduled_start
          AND j.scheduled_start < %s + (%s * INTERVAL '1 hour')
          AND j.scheduled_end > %s - (%s * INTERVAL '1 hour')
        ORDER BY j.source_key, j.id
        FOR SHARE OF j
        """
    params = (
        site_id,
        checked_in_at,
        SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS,
        checked_in_at,
        SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS,
    )
    if cur is None:
        rows = db.query_all(sql, params)
    else:
        cur.execute(sql, params)
        rows = [dict(row) for row in cur.fetchall()]

    active = [row for row in rows if row["status"] != "cancelled"]
    if len(active) == 1:
        return active[0], "verified_scheduled_site"
    if len(active) > 1:
        return None, "ambiguous_job"
    if rows:
        return None, "cancelled_job"
    return None, "no_scheduled_job"


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
    job: Optional[Dict[str, Any]],
    job_match_reason: str,
    schedule: Optional[Dict[str, Any]],
    policy: Optional[Dict[str, Any]],
    site_id: int,
    checked_in_at: datetime,
    device_clock_skew_seconds: float,
) -> Tuple[
    str,
    str,
    str,
    Dict[str, Any],
    Optional[datetime],
    Optional[int],
]:
    if policy:
        snapshot = arrival_policies.snapshot_revision(policy)
        snapshot["authority"] = str(policy["scope_type"])
        snapshot["classifiedBy"] = "arrival_policy"
    elif schedule:
        snapshot = {
            "authority": "legacy_employee_schedule",
            "classifiedBy": (
                "legacy_exact"
                if schedule.get("id") is not None
                else "legacy_recurring"
            ),
            "scheduleId": schedule.get("id"),
            "scheduleRuleId": schedule.get("schedule_rule_id"),
            "scheduledStart": to_utc_iso(schedule["scheduled_start"]),
            "graceMinutes": int(schedule["grace_minutes"]),
        }
    else:
        snapshot = {
            "authority": "implicit_flexible_during_migration",
            "classifiedBy": "implicit_flexible",
        }
    geofence_reason = {
        "site_unpinned": "site_missing_location_pin",
        "low_accuracy": "location_accuracy_too_low",
        "outside": "outside_geofence",
        "uncertain": "geofence_boundary_uncertain",
    }.get(str(geofence["status"]))
    if geofence_reason:
        return "needs_review", geofence_reason, "pending", snapshot, None, None

    if device_clock_skew_seconds > SITE_CHECK_IN_DEVICE_SKEW_SECONDS:
        return "needs_review", "device_clock_skew", "pending", snapshot, None, None

    if not job:
        return "needs_review", job_match_reason, "pending", snapshot, None, None

    if policy:
        return arrival_policies.evaluate_policy(
            policy,
            site_id=site_id,
            job=job,
            checked_in_at=checked_in_at,
        )

    if schedule:
        scheduled_start = schedule["scheduled_start"]
        grace_deadline = scheduled_start + timedelta(
            minutes=int(schedule["grace_minutes"])
        )
        if checked_in_at <= grace_deadline:
            result = ("on_time", "within_grace_period", "not_required")
        else:
            result = ("late", "after_grace_period", "not_required")
        return (
            *result,
            snapshot,
            scheduled_start,
            int(schedule["grace_minutes"]),
        )

    return (
        "on_time",
        "verified_scheduled_site",
        "not_required",
        snapshot,
        None,
        None,
    )


def _insert_site_arrival_evidence(
    cur: Any,
    *,
    employee: Dict[str, Any],
    site: Dict[str, Any],
    payload: SiteCheckInRequest,
    official_time: datetime,
    geofence: Dict[str, Any],
) -> Tuple[int, bool, Dict[str, Any]]:
    job, job_match_reason = _matching_canonical_site_job(
        int(site["id"]),
        official_time,
        cur=cur,
    )
    policy = arrival_policies.resolve_policy(
        cur,
        site_id=int(site["id"]),
        job_id=int(job["id"]) if job else None,
    )
    schedule = None
    if policy is None:
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
    (
        classification,
        reason,
        review_status,
        policy_snapshot,
        policy_scheduled_start,
        policy_grace_minutes,
    ) = _classify_site_check_in(
        geofence,
        job,
        job_match_reason,
        schedule,
        policy,
        int(site["id"]),
        official_time,
        device_clock_skew_seconds,
    )
    cur.execute(
        """
        INSERT INTO site_check_ins (
            employee_id, location_id, job_id, server_checked_in_at,
            device_scanned_at, latitude, longitude, accuracy_m,
            geofence_radius_m, distance_m, geofence_status,
            classification, classification_reason, schedule_id,
            schedule_rule_id, arrival_policy_revision_id,
            arrival_policy_snapshot, scheduled_start, grace_minutes,
            device_clock_skew_seconds, review_status
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (employee_id, location_id, device_scanned_at)
        DO NOTHING
        RETURNING id
        """,
        (
            int(employee["id"]),
            int(site["id"]),
            int(job["id"]) if job else None,
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
            int(policy["id"]) if policy else None,
            psycopg2.extras.Json(policy_snapshot),
            (
                policy_scheduled_start
                if policy
                else (schedule["scheduled_start"] if schedule else None)
            ),
            (
                policy_grace_minutes
                if policy
                else (schedule["grace_minutes"] if schedule else None)
            ),
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
            SELECT id
            FROM site_check_ins
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

    cur.execute(
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
    check_in_row = cur.fetchone()
    if not check_in_row:
        raise RuntimeError("Site check-in was stored but could not be reloaded")
    return check_in_id, duplicate, _serialize_site_check_in(dict(check_in_row))


@app.get("/", include_in_schema=False)
@app.get("/timetracker-mobile.html", include_in_schema=False)
def time_tracker_page(
    request: Request,
    check_in: Optional[str] = Query(default=None, alias="checkIn"),
) -> Response:
    # Both retired backend entry points belong to the canonical EOM portal
    # (issue #35). Forward ONLY a non-empty checkIn value: apiBaseUrl and other
    # legacy parameters must not ride a printed-QR redirect. 302 + no-store
    # keeps the cutover reversible and prevents phone browsers from caching it.
    portal_base = _require_canonical_portal_base(request)
    destination = f"{portal_base}/portal"
    if check_in:
        destination = f"{destination}?checkIn={quote(check_in, safe='')}"
    return RedirectResponse(
        destination,
        status_code=302,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
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

    # Validate the destination before creating or rotating a token. A failed
    # configuration check must not revoke an already-printed QR code.
    _require_canonical_portal_base(request)

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


def _site_action_request_fingerprint(payload: SiteCheckInRequest) -> str:
    material = payload.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _site_action_gps_meta(
    site: Dict[str, Any],
    geofence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "override": False,
        "overrideReason": "",
        "overrideDetail": "",
        "matchedLocation": str(site.get("address") or ""),
        "distanceM": geofence.get("distanceM"),
        "withinRadius": geofence.get("status") == "inside",
        "accuracyM": geofence.get("accuracyM"),
    }


def _current_site_action_state_for_id(
    cur: Any,
    *,
    employee_id: int,
    site_id: int,
    reference_time: datetime,
) -> Dict[str, Any]:
    cur.execute(
        """
        SELECT id, address, customer_name, lat, lng
        FROM locations
        WHERE id = %s AND active = true
        """,
        (site_id,),
    )
    site_row = cur.fetchone()
    if site_row:
        return _build_site_action_state(
            cur,
            employee_id=employee_id,
            site=dict(site_row),
            reference_time=reference_time,
            lock_shifts=True,
        )
    return {
        "status": "review_required",
        "recommendedAction": None,
        "shiftId": None,
        "activeVisit": None,
        "missingDepartures": [],
        "stateToken": None,
        "blockReason": "site_unavailable",
        "_fingerprint": hashlib.sha256(
            f"site-unavailable:{employee_id}:{site_id}".encode("utf-8")
        ).hexdigest(),
    }


def _record_explicit_site_action(
    payload: SiteCheckInRequest,
    request: Request,
    employee: Dict[str, Any],
) -> Dict[str, Any]:
    assert payload.action is not None
    assert payload.actionStateToken is not None
    assert payload.idempotencyKey is not None
    fingerprint = _site_action_request_fingerprint(payload)
    employee_id = int(employee["id"])
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (TIMESHEET_PG_ADVISORY_LOCK_ID,),
            )
            cur.execute(
                """
                SELECT id, request_fingerprint, response_body
                FROM site_qr_action_receipts
                WHERE employee_id = %s
                  AND (
                      idempotency_key = %s
                      OR (location_id = %s AND device_scanned_at = %s)
                  )
                ORDER BY
                    CASE WHEN idempotency_key = %s THEN 0 ELSE 1 END,
                    id
                """,
                (
                    employee_id,
                    str(payload.idempotencyKey),
                    int(payload.siteId),
                    payload.scannedAt,
                    str(payload.idempotencyKey),
                ),
            )
            existing_rows = [dict(row) for row in cur.fetchall()]
            if existing_rows:
                if (
                    len(existing_rows) == 1
                    and hmac.compare_digest(
                        str(existing_rows[0]["request_fingerprint"]),
                        fingerprint,
                    )
                ):
                    replay = dict(existing_rows[0]["response_body"])
                    replay["replayed"] = True
                    return replay
                fresh_state = _current_site_action_state_for_id(
                    cur,
                    employee_id=employee_id,
                    site_id=int(payload.siteId),
                    reference_time=utc_now(),
                )
                raise _site_action_state_error(
                    code="IDEMPOTENCY_KEY_REUSED",
                    message=(
                        "This QR action key or scan time already belongs to "
                        "different action details."
                    ),
                    action_state=fresh_state,
                )

            # The official timestamp belongs to the serialized mutation order,
            # not to time spent queued behind an earlier event writer.
            official_time = utc_now()
            site = _resolve_site_check_in_qr(
                payload.token,
                cur=cur,
                for_update=True,
            )
            if int(site["id"]) != int(payload.siteId):
                raise HTTPException(
                    status_code=400,
                    detail="siteId must match the scanned site QR",
                )

            current_state = _build_site_action_state(
                cur,
                employee_id=employee_id,
                site=site,
                reference_time=official_time,
                lock_shifts=True,
            )
            if current_state["status"] == "clock_in_required":
                raise _site_action_state_error(
                    code="ACTIVE_SHIFT_REQUIRED",
                    message="Clock in before recording this Site action.",
                    action_state=current_state,
                )
            if current_state["status"] != "ready":
                raise _site_action_state_error(
                    code="SITE_ACTION_STATE_CHANGED",
                    message=(
                        "Your shift state needs review before this Site action "
                        "can be recorded."
                    ),
                    action_state=current_state,
                )

            try:
                claims = _parse_site_action_state_token(payload.actionStateToken)
                token_matches = (
                    int(claims.get("employeeId", 0)) == employee_id
                    and int(claims.get("siteId", 0)) == int(site["id"])
                    and str(claims.get("action") or "") == payload.action
                    and hmac.compare_digest(
                        str(claims.get("stateFingerprint") or ""),
                        str(current_state["_fingerprint"]),
                    )
                    and int(claims.get("expiresAt", 0))
                    >= int(official_time.timestamp())
                )
            except (TypeError, ValueError):
                token_matches = False
            if (
                not token_matches
                or current_state["recommendedAction"] != payload.action
            ):
                raise _site_action_state_error(
                    code="SITE_ACTION_STATE_CHANGED",
                    message=(
                        "The Site action changed. Review the current action and "
                        "confirm it again."
                    ),
                    action_state=current_state,
                )

            if payload.action == "arrive":
                enforce_clock_action_hours(request)

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
            records_time_event = geofence["status"] == "inside"
            outcome = (
                "recorded" if records_time_event else "evidence_only_review"
            )
            shift_id = int(current_state["shiftId"])
            missing_visit_ids = [
                int(row["id"]) for row in current_state["missingDepartures"]
            ]
            check_in_id: Optional[int] = None
            check_in: Optional[Dict[str, Any]] = None
            duplicate = False
            visit: Optional[Dict[str, Any]] = None
            departure: Optional[Dict[str, Any]] = None

            if payload.action == "arrive":
                check_in_id, duplicate, check_in = _insert_site_arrival_evidence(
                    cur,
                    employee=employee,
                    site=site,
                    payload=payload,
                    official_time=official_time,
                    geofence=geofence,
                )
                if records_time_event:
                    visit_job_id = check_in.get("jobId") if check_in else None
                    gps = build_gps_point(
                        payload.latitude,
                        payload.longitude,
                        payload.accuracy,
                    )
                    gps_meta = _site_action_gps_meta(site, geofence)
                    cur.execute(
                        """
                        INSERT INTO visits (
                            shift_id, location_id, location_label, customer_name,
                            arrival_time, gps, gps_meta, sequence_version,
                            site_check_in_id, job_id
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 2, %s, %s)
                        RETURNING id
                        """,
                        (
                            shift_id,
                            int(site["id"]),
                            str(site["address"]),
                            str(site.get("customer_name") or "") or None,
                            official_time,
                            psycopg2.extras.Json(gps),
                            psycopg2.extras.Json(gps_meta),
                            check_in_id,
                            visit_job_id,
                        ),
                    )
                    visit_id = int(cur.fetchone()["id"])
                    cur.execute(
                        """
                        UPDATE shifts
                        SET location_id = %s
                        WHERE id = %s AND location_id IS NULL
                        """,
                        (int(site["id"]), shift_id),
                    )
                    visit = {
                        "id": visit_id,
                        "arrivalTime": to_utc_iso(official_time),
                        "location": str(site["address"]),
                        "customer": str(site.get("customer_name") or ""),
                        "gps": gps,
                        "gpsMeta": gps_meta,
                        "jobId": visit_job_id,
                        "sequenceVersion": 2,
                        "siteCheckInId": check_in_id,
                    }
            elif records_time_event:
                active_visit = current_state.get("activeVisit")
                if not active_visit:
                    raise _site_action_state_error(
                        code="SITE_ACTION_STATE_CHANGED",
                        message=(
                            "There is no active Site arrival to depart from. "
                            "Review the current action and confirm it again."
                        ),
                        action_state=current_state,
                    )
                visit_id = int(active_visit["id"])
                gps = build_gps_point(
                    payload.latitude,
                    payload.longitude,
                    payload.accuracy,
                )
                gps_meta = _site_action_gps_meta(site, geofence)
                cur.execute(
                    """
                    INSERT INTO departures (
                        shift_id, visit_id, location_id, location_label,
                        customer_name, departure_time, gps, gps_meta
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        shift_id,
                        visit_id,
                        int(site["id"]),
                        str(site["address"]),
                        str(site.get("customer_name") or "") or None,
                        official_time,
                        psycopg2.extras.Json(gps),
                        psycopg2.extras.Json(gps_meta),
                    ),
                )
                departure_id = int(cur.fetchone()["id"])
                departure = {
                    "id": departure_id,
                    "departureTime": to_utc_iso(official_time),
                    "location": str(site["address"]),
                    "customer": str(site.get("customer_name") or ""),
                    "visitId": visit_id,
                    "gps": gps,
                    "gpsMeta": gps_meta,
                }

            fresh_state = _build_site_action_state(
                cur,
                employee_id=employee_id,
                site=site,
                reference_time=official_time,
                lock_shifts=False,
            )
            response: Dict[str, Any] = {
                "success": True,
                "action": payload.action,
                "outcome": outcome,
                "replayed": False,
                "duplicate": duplicate,
                "shiftId": shift_id,
                "actionState": _public_site_action_state(fresh_state),
            }
            if payload.action == "arrive":
                response["checkIn"] = check_in
                response["visit"] = visit
            else:
                response["departure"] = departure

            cur.execute(
                """
                INSERT INTO site_qr_action_receipts (
                    employee_id, location_id, shift_id, action,
                    idempotency_key, request_fingerprint, server_recorded_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status, outcome,
                    site_check_in_id, visit_id, departure_id,
                    missing_departure_visit_ids, response_body
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    employee_id,
                    int(site["id"]),
                    shift_id,
                    payload.action,
                    str(payload.idempotencyKey),
                    fingerprint,
                    official_time,
                    payload.scannedAt,
                    payload.latitude,
                    payload.longitude,
                    payload.accuracy,
                    geofence["radiusM"],
                    geofence["distanceM"],
                    geofence["status"],
                    outcome,
                    check_in_id,
                    visit.get("id") if visit else None,
                    departure.get("id") if departure else None,
                    missing_visit_ids,
                    psycopg2.extras.Json(response),
                ),
            )
            return response


PLAIN_TIME_ACTION_NAMES = ("clock-in", "arrive", "depart", "clock-out")
PLAIN_TIME_ACTION_RECEIPT_UNIQUE_CONSTRAINT = (
    "plain_time_action_receipts_employee_id_idempotency_key_key"
)


def _plain_time_action_request_fingerprint(
    action: str,
    payload: Optional[BaseModel],
) -> str:
    material = {
        "action": action,
        "payload": payload.model_dump(mode="json") if payload is not None else {},
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _plain_time_action_shift_id(result: Any, response: Dict[str, Any]) -> Optional[int]:
    candidates = []
    if isinstance(result, dict):
        candidates.extend([result.get("entryId"), result.get("id")])
    entry = response.get("entry")
    if isinstance(entry, dict):
        candidates.append(entry.get("id"))
    for value in candidates:
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _plain_time_action_recorded_at(
    action: str,
    response: Dict[str, Any],
) -> datetime:
    if action in {"clock-in", "clock-out"}:
        entry = response.get("entry") if isinstance(response, dict) else None
        if isinstance(entry, dict):
            key = "clockIn" if action == "clock-in" else "clockOut"
            value = entry.get(key)
            if value:
                try:
                    return parse_utc_iso(str(value))
                except ValueError:
                    pass
    if action == "arrive":
        visit = response.get("visit") if isinstance(response, dict) else None
        if isinstance(visit, dict) and visit.get("arrivalTime"):
            try:
                return parse_utc_iso(str(visit["arrivalTime"]))
            except ValueError:
                pass
    if action == "depart":
        departure = response.get("departure") if isinstance(response, dict) else None
        if isinstance(departure, dict) and departure.get("departureTime"):
            try:
                return parse_utc_iso(str(departure["departureTime"]))
            except ValueError:
                pass
    return utc_now()


def _plain_time_action_replay_response(
    action: str,
    payload: Optional[BaseModel],
    employee: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    idempotency_key = getattr(payload, "idempotencyKey", None) if payload else None
    if not idempotency_key:
        return None
    fingerprint = _plain_time_action_request_fingerprint(action, payload)
    existing = db.query_one(
        """
        SELECT request_fingerprint, response_body
        FROM plain_time_action_receipts
        WHERE employee_id = %s
          AND idempotency_key = %s
        """,
        (int(employee["id"]), str(idempotency_key)),
    )
    if not existing:
        return None
    if hmac.compare_digest(str(existing["request_fingerprint"]), fingerprint):
        replay = dict(existing["response_body"])
        replay["replayed"] = True
        return replay
    raise HTTPException(
        status_code=409,
        detail=(
            "This time action key already belongs to different action details."
        ),
    )


def update_timesheets_for_plain_time_action(
    action: str,
    payload: Optional[BaseModel],
    employee: Dict[str, Any],
    mutator: Callable[[Dict[str, Any]], Tuple[bool, Any]],
    response_builder: Callable[[Any, Dict[str, Any]], Dict[str, Any]],
) -> Tuple[bool, Any]:
    if action not in PLAIN_TIME_ACTION_NAMES:
        raise ValueError(f"Unsupported plain time action: {action}")

    idempotency_key = getattr(payload, "idempotencyKey", None) if payload else None
    fingerprint = (
        _plain_time_action_request_fingerprint(action, payload)
        if idempotency_key
        else ""
    )
    employee_id = int(employee["id"])

    with TIMESHEET_WRITE_LOCK:
        with timesheet_postgres_advisory_lock():
            replay = _plain_time_action_replay_response(action, payload, employee)
            if replay is not None:
                return True, replay

            timesheet_data = _load_timesheets_from_db()
            pre_shift_ids = {e["id"] for e in timesheet_data["entries"]}
            pre_visit_counts = {
                e["id"]: len(e.get("visits", [])) for e in timesheet_data["entries"]
            }
            pre_departure_counts = {
                e["id"]: len(e.get("departures", []))
                for e in timesheet_data["entries"]
            }

            ok, result = mutator(timesheet_data)
            if not ok:
                return ok, result
            if (
                not idempotency_key
                and isinstance(result, dict)
                and result.get("alreadyHere")
            ):
                return True, response_builder(result, timesheet_data)

            holder: Dict[str, Any] = {}

            def after_save(cur: Any) -> None:
                response = response_builder(result, timesheet_data)
                if idempotency_key:
                    response = {**response, "replayed": False}
                    cur.execute(
                        """
                        INSERT INTO plain_time_action_receipts (
                            employee_id, shift_id, action, idempotency_key,
                            request_fingerprint, server_recorded_at, response_body
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            employee_id,
                            _plain_time_action_shift_id(result, response),
                            action,
                            str(idempotency_key),
                            fingerprint,
                            _plain_time_action_recorded_at(action, response),
                            psycopg2.extras.Json(jsonable_encoder(response)),
                        ),
                    )
                holder["response"] = response

            try:
                _save_timesheets_to_db(
                    timesheet_data,
                    pre_shift_ids,
                    pre_visit_counts,
                    pre_departure_counts,
                    after_save=after_save,
                )
            except psycopg2.errors.UniqueViolation as exc:
                constraint = getattr(getattr(exc, "diag", None), "constraint_name", "")
                if (
                    idempotency_key
                    and constraint == PLAIN_TIME_ACTION_RECEIPT_UNIQUE_CONSTRAINT
                ):
                    replay = _plain_time_action_replay_response(
                        action,
                        payload,
                        employee,
                    )
                    if replay is not None:
                        return True, replay
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "This time action is still being recorded; retry the "
                            "same request."
                        ),
                    ) from exc
                raise
            return True, holder["response"]


@app.post("/api/timesheet/site-check-in/resolve")
def resolve_site_check_in_qr(
    payload: SiteQrResolveRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    site = _resolve_site_check_in_qr(payload.token)
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            action_state = _build_site_action_state(
                cur,
                employee_id=int(employee["id"]),
                site=site,
                reference_time=utc_now(),
            )
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
        "actionState": _public_site_action_state(action_state),
    }


@app.post("/api/timesheet/site-check-in")
def record_site_check_in(
    payload: SiteCheckInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    if payload.action is None:
        enforce_clock_action_hours(request)
    if int(payload.employeeId) != int(employee["id"]):
        append_access_log(
            request,
            "SITE_CHECK_IN_REJECTED",
            False,
            f"Session employee {employee['id']} attempted employee {payload.employeeId}",
        )
        raise HTTPException(status_code=403, detail="employeeId must match the signed-in employee")

    if payload.action is not None:
        result = _record_explicit_site_action(payload, request, employee)
        append_access_log(
            request,
            "SITE_QR_ACTION_REPLAYED" if result["replayed"] else "SITE_QR_ACTION_RECORDED",
            True,
            (
                f"Employee {employee['name']} site {payload.siteId} "
                f"action {result['action']} outcome {result['outcome']}"
            ),
        )
        return result

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
            job, job_match_reason = _matching_canonical_site_job(
                int(site["id"]),
                official_time,
                cur=cur,
            )
            policy = arrival_policies.resolve_policy(
                cur,
                site_id=int(site["id"]),
                job_id=int(job["id"]) if job else None,
            )
            schedule = None
            if policy is None:
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
            (
                classification,
                reason,
                review_status,
                policy_snapshot,
                policy_scheduled_start,
                policy_grace_minutes,
            ) = _classify_site_check_in(
                geofence,
                job,
                job_match_reason,
                schedule,
                policy,
                int(site["id"]),
                official_time,
                device_clock_skew_seconds,
            )
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, job_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason, schedule_id,
                    schedule_rule_id, arrival_policy_revision_id,
                    arrival_policy_snapshot, scheduled_start, grace_minutes,
                    device_clock_skew_seconds,
                    review_status
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (employee_id, location_id, device_scanned_at)
                DO NOTHING
                RETURNING id
                """,
                (
                    int(employee["id"]),
                    int(site["id"]),
                    int(job["id"]) if job else None,
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
                    int(policy["id"]) if policy else None,
                    psycopg2.extras.Json(policy_snapshot),
                    (
                        policy_scheduled_start
                        if policy
                        else (schedule["scheduled_start"] if schedule else None)
                    ),
                    (
                        policy_grace_minutes
                        if policy
                        else (schedule["grace_minutes"] if schedule else None)
                    ),
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


def _arrival_policy_scope_target(
    cur: Any,
    *,
    scope_type: str,
    target_id: int,
    for_update: bool,
    require_canonical_appointment: bool = False,
) -> Tuple[int, Optional[int]]:
    lock_clause = " FOR SHARE" if for_update else ""
    if scope_type == "site":
        cur.execute(
            """
            SELECT id
            FROM locations
            WHERE id = %s AND active = true
            """ + lock_clause,
            (target_id,),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Active Site not found")
        return target_id, None

    appointment_lock_clause = " FOR SHARE OF j" if for_update else ""
    cur.execute(
        """
        SELECT j.id, j.location_id,
               (
                   j.status != 'cancelled'
                   AND site.active = true
                   AND j.source_all_day = false
                   AND j.scheduled_start IS NOT NULL
                   AND j.scheduled_end IS NOT NULL
                   AND j.scheduled_end > j.scheduled_start
                   AND (
                       (
                           source.role = 'residential_morning'
                           AND site.location_type = 'Residential'
                       )
                       OR (
                           source.role = 'commercial_evening_night'
                           AND site.location_type = 'Commercial'
                       )
                   )
               ) AS is_canonical_appointment
        FROM jobs j
        LEFT JOIN google_calendar_sources source
               ON source.id = j.calendar_source_id
        LEFT JOIN locations site ON site.id = j.location_id
        WHERE j.id = %s
        """ + appointment_lock_clause,
        (target_id,),
    )
    job = cur.fetchone()
    if not job:
        raise HTTPException(status_code=404, detail="Appointment not found")
    if job.get("location_id") is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "arrival_policy_job_missing_site",
                "message": "The appointment must resolve to one Site before it can own an arrival policy",
                "details": {"jobId": target_id},
            },
        )
    if require_canonical_appointment and not bool(
        job.get("is_canonical_appointment")
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "arrival_policy_job_not_canonical",
                "message": (
                    "Only an active canonical Calendar appointment can own "
                    "a new arrival policy revision"
                ),
                "details": {"jobId": target_id},
            },
        )
    return int(job["location_id"]), target_id


def _arrival_policy_history(
    *,
    scope_type: str,
    site_id: int,
    job_id: Optional[int],
    cur: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    if scope_type == "site":
        sql = """
            SELECT *
            FROM arrival_policy_revisions
            WHERE scope_type = 'site' AND site_id = %s
            ORDER BY version DESC, id DESC
            """
        params: Tuple[Any, ...] = (site_id,)
    else:
        sql = """
            SELECT *
            FROM arrival_policy_revisions
            WHERE scope_type = 'appointment' AND job_id = %s
            ORDER BY version DESC, id DESC
            """
        params = (job_id,)
    if cur is None:
        rows = db.query_all(sql, params)
    else:
        cur.execute(sql, params)
        rows = [dict(row) for row in cur.fetchall()]
    return [arrival_policies.serialize_revision(row) for row in rows]


def _arrival_policy_scope_response(
    *,
    scope_type: str,
    site_id: int,
    job_id: Optional[int],
    cur: Optional[Any] = None,
    current_revision_id: Optional[int] = None,
) -> Dict[str, Any]:
    history = _arrival_policy_history(
        scope_type=scope_type,
        site_id=site_id,
        job_id=job_id,
        cur=cur,
    )
    if current_revision_id is None:
        current = history[0] if history else None
    else:
        current = next(
            (row for row in history if row["id"] == current_revision_id),
            None,
        )
        if current is None:
            raise RuntimeError(
                f"Arrival policy revision {current_revision_id} was not readable "
                "inside its mutation transaction"
            )
    return {
        "success": True,
        "scopeType": scope_type,
        "siteId": site_id,
        "jobId": job_id,
        "policy": current if current and current["state"] == "active" else None,
        "currentRevision": current,
        "history": history,
    }


def _arrival_policy_conflict(
    *,
    scope_type: str,
    site_id: int,
    job_id: Optional[int],
) -> None:
    raise HTTPException(
        status_code=409,
        detail={
            "code": "stale_arrival_policy_update",
            "message": "Arrival policy changed after it was read; reload before retrying",
            "details": {
                "scopeType": scope_type,
                "siteId": site_id,
                "jobId": job_id,
            },
        },
    )


def _write_arrival_policy(
    *,
    scope_type: str,
    target_id: int,
    payload: ArrivalPolicyPutRequest,
    admin: Dict[str, Any],
) -> Tuple[int, int, Optional[int], Dict[str, Any]]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            site_id, job_id = _arrival_policy_scope_target(
                cur,
                scope_type=scope_type,
                target_id=target_id,
                for_update=True,
                require_canonical_appointment=scope_type == "appointment",
            )
            lock_identity = (
                f"arrival-policy:{scope_type}:{job_id if job_id is not None else site_id}"
            )
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (lock_identity,))
            current = arrival_policies.latest_revision(
                cur,
                scope_type=scope_type,
                site_id=site_id,
                job_id=job_id,
                for_update=True,
            )
            expected = payload.expectedUpdateToken
            if current is None:
                if expected is not None:
                    _arrival_policy_conflict(
                        scope_type=scope_type,
                        site_id=site_id,
                        job_id=job_id,
                    )
                version = 1
            else:
                if expected is None or not arrival_policies.tokens_match(
                    expected,
                    str(current["update_token"]),
                ):
                    _arrival_policy_conflict(
                        scope_type=scope_type,
                        site_id=site_id,
                        job_id=job_id,
                    )
                version = int(current["version"]) + 1

            created_at = utc_now()
            update_token = arrival_policies.policy_update_token(
                scope_type,
                site_id,
                job_id,
                version,
                created_at,
            )
            cur.execute(
                """
                INSERT INTO arrival_policy_revisions (
                    scope_type, site_id, job_id, version, state, mode,
                    timezone, fixed_arrival, grace_minutes, window_start,
                    window_end, not_before, update_token, change_note,
                    created_by, created_by_name, created_at
                )
                VALUES (
                    %s, %s, %s, %s, 'active', %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                RETURNING id
                """,
                (
                    scope_type,
                    site_id,
                    job_id,
                    version,
                    payload.mode,
                    payload.timezone,
                    payload.fixedArrival,
                    payload.graceMinutes,
                    payload.windowStart,
                    payload.windowEnd,
                    payload.notBefore,
                    update_token,
                    payload.changeNote,
                    int(admin["id"]),
                    str(admin["name"]),
                    created_at,
                ),
            )
            revision_id = int(cur.fetchone()["id"])
            response = _arrival_policy_scope_response(
                scope_type=scope_type,
                site_id=site_id,
                job_id=job_id,
                cur=cur,
                current_revision_id=revision_id,
            )
    return revision_id, site_id, job_id, response


def _retire_arrival_policy(
    *,
    scope_type: str,
    target_id: int,
    payload: ArrivalPolicyRetireRequest,
    admin: Dict[str, Any],
) -> Tuple[int, int, Optional[int], Dict[str, Any]]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            site_id, job_id = _arrival_policy_scope_target(
                cur,
                scope_type=scope_type,
                target_id=target_id,
                for_update=True,
            )
            lock_identity = (
                f"arrival-policy:{scope_type}:{job_id if job_id is not None else site_id}"
            )
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (lock_identity,))
            current = arrival_policies.latest_revision(
                cur,
                scope_type=scope_type,
                site_id=site_id,
                job_id=job_id,
                for_update=True,
            )
            if (
                current is None
                or current["state"] != "active"
                or not arrival_policies.tokens_match(
                    payload.expectedUpdateToken,
                    str(current["update_token"]),
                )
            ):
                _arrival_policy_conflict(
                    scope_type=scope_type,
                    site_id=site_id,
                    job_id=job_id,
                )
            version = int(current["version"]) + 1
            created_at = utc_now()
            update_token = arrival_policies.policy_update_token(
                scope_type,
                site_id,
                job_id,
                version,
                created_at,
            )
            cur.execute(
                """
                INSERT INTO arrival_policy_revisions (
                    scope_type, site_id, job_id, version, state,
                    update_token, change_note, created_by, created_by_name,
                    created_at
                )
                VALUES (
                    %s, %s, %s, %s, 'retired',
                    %s, %s, %s, %s, %s
                )
                RETURNING id
                """,
                (
                    scope_type,
                    site_id,
                    job_id,
                    version,
                    update_token,
                    payload.changeNote,
                    int(admin["id"]),
                    str(admin["name"]),
                    created_at,
                ),
            )
            revision_id = int(cur.fetchone()["id"])
            response = _arrival_policy_scope_response(
                scope_type=scope_type,
                site_id=site_id,
                job_id=job_id,
                cur=cur,
                current_revision_id=revision_id,
            )
    return revision_id, site_id, job_id, response


@app.get("/api/admin/locations/{site_id}/arrival-policy")
def admin_get_site_arrival_policy(
    site_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    site = db.query_one("SELECT id FROM locations WHERE id = %s", (site_id,))
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    return _arrival_policy_scope_response(
        scope_type="site",
        site_id=site_id,
        job_id=None,
    )


@app.put("/api/admin/locations/{site_id}/arrival-policy")
def admin_put_site_arrival_policy(
    site_id: int,
    payload: ArrivalPolicyPutRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    revision_id, resolved_site_id, _, response = _write_arrival_policy(
        scope_type="site",
        target_id=site_id,
        payload=payload,
        admin=admin,
    )
    append_access_log(
        request,
        "ARRIVAL_POLICY_SAVED",
        True,
        f"Site {resolved_site_id} revision {revision_id} by {admin['name']}",
    )
    return response


@app.post("/api/admin/locations/{site_id}/arrival-policy/retire")
def admin_retire_site_arrival_policy(
    site_id: int,
    payload: ArrivalPolicyRetireRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    revision_id, resolved_site_id, _, response = _retire_arrival_policy(
        scope_type="site",
        target_id=site_id,
        payload=payload,
        admin=admin,
    )
    append_access_log(
        request,
        "ARRIVAL_POLICY_RETIRED",
        True,
        f"Site {resolved_site_id} revision {revision_id} by {admin['name']}",
    )
    return response


@app.get("/api/admin/jobs/{job_id}/arrival-policy")
def admin_get_appointment_arrival_policy(
    job_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            site_id, resolved_job_id = _arrival_policy_scope_target(
                cur,
                scope_type="appointment",
                target_id=job_id,
                for_update=False,
            )
    return _arrival_policy_scope_response(
        scope_type="appointment",
        site_id=site_id,
        job_id=resolved_job_id,
    )


@app.put("/api/admin/jobs/{job_id}/arrival-policy")
def admin_put_appointment_arrival_policy(
    job_id: int,
    payload: ArrivalPolicyPutRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    revision_id, site_id, resolved_job_id, response = _write_arrival_policy(
        scope_type="appointment",
        target_id=job_id,
        payload=payload,
        admin=admin,
    )
    append_access_log(
        request,
        "ARRIVAL_POLICY_SAVED",
        True,
        f"Appointment {job_id} revision {revision_id} by {admin['name']}",
    )
    return response


@app.post("/api/admin/jobs/{job_id}/arrival-policy/retire")
def admin_retire_appointment_arrival_policy(
    job_id: int,
    payload: ArrivalPolicyRetireRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    revision_id, site_id, resolved_job_id, response = _retire_arrival_policy(
        scope_type="appointment",
        target_id=job_id,
        payload=payload,
        admin=admin,
    )
    append_access_log(
        request,
        "ARRIVAL_POLICY_RETIRED",
        True,
        f"Appointment {job_id} revision {revision_id} by {admin['name']}",
    )
    return response


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
    updated = db.query_one(
        """
        UPDATE site_check_ins
        SET review_status = %s,
            reviewed_by = %s,
            reviewed_at = NOW(),
            review_note = %s
        WHERE id = %s
          AND classification = 'needs_review'
          AND review_status = 'pending'
        RETURNING id
        """,
        (payload.decision, int(admin["id"]), payload.note.strip(), check_in_id),
    )
    if not updated:
        existing = db.query_one(
            "SELECT id, classification FROM site_check_ins WHERE id = %s",
            (check_in_id,),
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Site check-in not found")
        if existing["classification"] != "needs_review":
            raise HTTPException(
                status_code=409,
                detail="Only needs-review check-ins require a decision",
            )
        raise HTTPException(
            status_code=409,
            detail="This site check-in already has a review decision",
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
        return True, {
            "id": employee["id"],
            "name": employee["name"],
            "role": employee.get("role", "employee"),
            "passwordChangedAt": employee.get("passwordChangedAt"),
        }

    ok, employee = update_employees(mutator)
    if not ok or not employee:
        append_access_log(request, "LOGIN_FAILED", False, "Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid name or password")

    # The token is bound to the password version that was just verified
    # (read under the same employee write lock), so a login racing a
    # concurrent password change cannot outlive that change.
    token = create_auth_token(
        employee["id"],
        employee["name"],
        employee.get("role", "employee"),
        password_changed_at=employee.get("passwordChangedAt"),
    )
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
) -> Dict[str, Any]:
    _rate_limit_check(
        request,
        key_prefix=f"change-password:{employee['id']}",
        max_calls=PASSWORD_CHANGE_RATE_LIMIT_MAX,
        window_seconds=PASSWORD_CHANGE_RATE_LIMIT_WINDOW_S,
    )

    # The stamp is applied inside the same update_employees transaction as the
    # new hash, so the password can never change without revoking old tokens.
    stamp = utc_now()

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
        account["passwordChangedAt"] = stamp
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
    return {
        "success": True,
        "token": create_auth_token(
            int(employee["id"]),
            employee["name"],
            employee.get("role", "employee"),
            password_changed_at=stamp,
        ),
    }


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
    if role not in EMPLOYEE_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Role must be one of: {', '.join(EMPLOYEE_ROLES)}",
        )

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
    new_role = payload.get("role", "").strip().lower()
    if new_role and new_role not in EMPLOYEE_ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(EMPLOYEE_ROLES)}")

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
            str(e.get("role") or "").lower() == ADMIN_ROLE and bool(e.get("active"))
            for e in employees_data["employees"]
        )
        if not has_active_admin:
            raise HTTPException(
                status_code=409,
                detail="Cannot demote or deactivate the last active admin. Promote or activate another admin first.",
            )
        if hashed_password:
            emp["password"] = hashed_password
            # An admin reset is the compromise-response path: revoke every
            # token issued up to this moment, atomically with the new hash.
            emp["passwordChangedAt"] = utc_now()
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

    local_today = to_local(now).date()
    current_week_start_date = local_sunday_week_start(now)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    today_str = local_today.isoformat()

    emp_entries = _exclude_payroll_resolved_open_entries(
        [
            e
            for e in timesheet_data["entries"]
            if e.get("employeeId") == employee_id
        ]
    )

    today_hours = 0.0
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
        entry_local_date = to_local(clock_in_dt).date()
        entry_date = entry_local_date.isoformat()

        all_time_hours += total
        if clock_in_dt >= year_start:
            yearly_hours += total
        if clock_in_dt >= month_start:
            monthly_hours += total
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
    grid_sunday_date = current_week_start_date + timedelta(weeks=week_offset)
    grid_end_date = grid_sunday_date + timedelta(days=7)

    shifts_by_date: Dict[str, list] = {}
    for entry in emp_entries:
        ci_str = str(entry.get("clockIn", "")).strip()
        if not ci_str:
            continue
        try:
            ci_dt = parse_utc_iso(ci_str)
        except ValueError:
            continue
        local_shift_date = to_local(ci_dt).date()
        if not (grid_sunday_date <= local_shift_date < grid_end_date):
            continue
        d_str = local_shift_date.isoformat()
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
        local_day = grid_sunday_date + timedelta(days=i)
        d_str = local_day.isoformat()
        day_shifts = shifts_by_date.get(d_str, [])
        day_hours = round(sum(s["hours"] for s in day_shifts), 2)
        week_total += day_hours
        week_grid.append({
            "date": d_str,
            "dayLabel": local_day.strftime("%a, %b %-d"),
            "shifts": day_shifts,
            "totalHours": day_hours,
        })

    return {
        "success": True,
        "employeeId": employee_id,
        "employeeName": emp["name"],
        "todayHours": round(today_hours, 2),
        "weeklyHours": round(week_total, 2),
        "monthlyHours": round(monthly_hours, 2),
        "yearlyHours": round(yearly_hours, 2),
        "allTimeHours": round(all_time_hours, 2),
        "weekGrid": week_grid,
        "weekTotal": round(week_total, 2),
        "weekOffset": week_offset,
        "weekStartDate": grid_sunday_date.isoformat(),
        "shifts": shifts[:50],
    }


@app.post("/api/timesheet/clock-in")
def clock_in(
    payload: ClockInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    replay = _plain_time_action_replay_response("clock-in", payload, employee)
    if replay is not None:
        return replay
    enforce_clock_action_hours(request)
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

    def response_builder(
        result: Dict[str, Any],
        timesheet_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        loc = result.get("location", "")
        location_customers: Dict[str, str] = timesheet_data.get("location_customers", {})
        result["customer"] = _resolve_customer(loc, location_customers)
        return {"success": True, "entry": result}

    ok, result = update_timesheets_for_plain_time_action(
        "clock-in",
        payload,
        employee,
        mutator,
        response_builder,
    )
    if not ok:
        append_access_log(request, "CLOCK_IN_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

    loc = result.get("entry", {}).get("location", "")
    append_access_log(request, "CLOCK_IN_SUCCESS", True, f"Employee: {employee['name']} at {loc}")
    return result


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

    ok, result = update_timesheets_for_plain_time_action(
        "clock-out",
        payload,
        employee,
        mutator,
        lambda result, _timesheet_data: {"success": True, "entry": result},
    )
    if not ok:
        append_access_log(request, "CLOCK_OUT_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

    if not result.get("replayed"):
        append_access_log(
            request,
            "CLOCK_OUT_SUCCESS",
            True,
            f"Employee: {employee['name']}, Hours: {result.get('entry', {}).get('totalHours', 0)}",
        )
    return result


@app.post("/api/timesheet/visit")
def log_visit(
    payload: ClockInRequest,
    request: Request,
    employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    """Auto-log an arrival at a new location during an active shift."""
    replay = _plain_time_action_replay_response("arrive", payload, employee)
    if replay is not None:
        return replay
    enforce_clock_action_hours(request)
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
        active_visit = get_active_visit(open_entry)
        if active_visit and active_visit.get("location") == location:
            return True, {
                "alreadyHere": True,
                "entryId": open_entry["id"],
            }

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
            "sequenceVersion": 2,
            "siteCheckInId": None,
        }

        if not isinstance(open_entry.get("visits"), list):
            open_entry["visits"] = []
        open_entry["visits"].append(visit)

        return True, {"visit": visit, "entryId": open_entry["id"]}

    ok, result = update_timesheets_for_plain_time_action(
        "arrive",
        payload,
        employee,
        mutator,
        lambda result, _timesheet_data: {
            "success": True,
            "alreadyHere": bool(result.get("alreadyHere")),
            **result,
        },
    )
    if not ok:
        raise_timesheet_mutation_failure(result)

    if not result.get("alreadyHere"):
        append_access_log(request, "VISIT_LOGGED", True,
                          f"Employee: {employee['name']} arrived at {result['visit']['location']}")
    return result


def get_active_visit(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    visits = entry.get("visits") or []
    if not visits:
        return None

    last_visit = visits[-1]
    arrival_time = str(last_visit.get("arrivalTime", "")).strip()
    if not arrival_time:
        return None

    departures = entry.get("departures") or []
    if last_visit.get("id"):
        last_visit_id = int(last_visit["id"])
        if any(
            departure.get("visitId") is not None
            and int(departure["visitId"]) == last_visit_id
            for departure in departures
            if isinstance(departure, dict)
        ):
            return None
    if int(last_visit.get("sequenceVersion") or 1) >= 2:
        return last_visit

    # Version-1 rows predate explicit pairing. Keep their historical count
    # interpretation, but never let an older legacy gap reactivate after a
    # newer version-2 visit has been closed.
    legacy_visits = [
        visit
        for visit in visits
        if int(visit.get("sequenceVersion") or 1) == 1
    ]
    legacy_departures = [
        departure
        for departure in departures
        if departure.get("visitId") is None
    ]
    return None if len(legacy_departures) >= len(legacy_visits) else last_visit


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
            "visitId": active_visit.get("id"),
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

    ok, result = update_timesheets_for_plain_time_action(
        "depart",
        payload,
        employee,
        mutator,
        lambda result, _timesheet_data: {"success": True, **result},
    )
    if not ok:
        append_access_log(request, "DEPARTURE_FAILED", False, str(result))
        raise_timesheet_mutation_failure(result)

    if not result.get("replayed"):
        append_access_log(
            request,
            "DEPARTURE_LOGGED",
            True,
            f"Employee: {employee['name']} departed {result['departure']['location']}",
        )
    return result


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
        if (
            (payload.clockIn is not None or payload.clockOut is not None)
            and _shift_has_active_payroll_correction(entry_id)
        ):
            return (
                False,
                (
                    "Entry has an active payroll correction; void or supersede "
                    "the correction before editing raw clock times"
                ),
            )

        new_ci_utc: Optional[datetime] = None
        new_co_utc: Optional[datetime] = None

        if payload.clockIn:
            try:
                new_ci_utc = parse_local_dt(payload.clockIn).astimezone(timezone.utc)
            except ValueError:
                return False, "Invalid clockIn - use YYYY-MM-DDTHH:MM"

        if payload.clockOut is not None:
            if payload.clockOut.strip() == "":
                # Clear clock-out -> make shift active again. Reject when the
                # employee already has another open entry (stale ones included:
                # a raw check, unlike get_open_entry): two open shifts strand
                # the older one until it trips the stale-shift guard. An open
                # row resolved by an active payroll correction is deliberately
                # parked, not strandable, so it does not block the clear.
                other_open = next(
                    (
                        e for e in timesheet_data["entries"]
                        if e["id"] != entry_id
                        and e.get("employeeId") == entry.get("employeeId")
                        and e.get("clockOut") is None
                        and not _entry_resolved_by_payroll_correction(e)
                    ),
                    None,
                )
                if other_open is not None:
                    return (
                        False,
                        (
                            f"Employee already has open shift {other_open['id']}; "
                            "close it before reopening this entry"
                        ),
                    )
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

    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    today_str = local_date_string(now)

    my_entries = [
        e for e in timesheet_data.get("entries", [])
        if e.get("employeeId") == employee_id
    ]
    my_entries = _exclude_payroll_resolved_open_entries(my_entries)

    # Weekly hours use the payroll-effective math (shift corrections, local-week
    # clipping, break minutes) so the number here matches what payroll pays once
    # shifts close. Open shifts earn 0 there, so the currently-open non-stale
    # shift is added back as live elapsed time clipped to this week. Paid and
    # live are both derived from ONE set of shift rows, fetched here, so a
    # clock-out committing between two reads can never count the same shift as
    # both paid and live.
    payroll_week_start = local_sunday_week_start(now)
    _, week_start_utc, week_end_utc = _payroll_week_bounds(payroll_week_start)
    my_shift_rows = _payroll_overlapping_shift_rows(
        week_start_utc,
        week_end_utc,
        now,
        employee_id=int(employee_id),
        include_timesheet_overlays=False,
    )
    my_shift_correction_rows = _payroll_active_shift_correction_rows_for_shift_ids(
        [int(row["id"]) for row in my_shift_rows]
    )
    payroll_week = _compute_payroll_weekly_hours(
        payroll_week_start.isoformat(),
        employee_rows=[{
            "id": employee_id,
            "name": current_employee["name"],
            "active": True,
        }],
        shift_rows=my_shift_rows,
        shift_correction_rows=my_shift_correction_rows,
        now_utc=now,
        include_timesheet_adjustments=False,
    )
    paid_weekly_minutes = 0
    for payroll_employee in payroll_week.get("employees", []):
        if int(payroll_employee.get("employeeId", 0)) == int(employee_id):
            paid_weekly_minutes = int(payroll_employee.get("totalMinutes", 0))
            break

    my_corrections_by_shift_id = _payroll_shift_corrections_by_shift_id(
        my_shift_correction_rows
    )
    live_open_hours = 0.0
    for shift_row in my_shift_rows:
        effective_row = _effective_payroll_shift_row(
            shift_row,
            my_corrections_by_shift_id.get(int(shift_row["id"])),
        )
        if effective_row.get("clock_out") is not None:
            continue
        open_clock_in = effective_row.get("clock_in")
        if open_clock_in is None:
            continue
        if (now - open_clock_in).total_seconds() / 3600 > MAX_ACTIVE_SHIFT_HOURS:
            continue
        live_start = max(open_clock_in, week_start_utc)
        if live_start < now:
            live_open_hours += (now - live_start).total_seconds() / 3600

    # Round the components first and sum the rounded values so weeklyHours
    # always equals paidHours + liveOpenHours exactly as displayed.
    paid_weekly_hours = round(paid_weekly_minutes / 60.0, 2)
    live_open_hours = round(live_open_hours, 2)
    weekly_hours = round(paid_weekly_hours + live_open_hours, 2)
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
        "weeklyHoursBasis": {
            "paidHours": round(paid_weekly_hours, 2),
            "liveOpenHours": round(live_open_hours, 2),
        },
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
    c.customer_type,
    c.active, c.created_at, c.updated_at, c.archived_at, c.archived_by
"""

SITE_SELECT_COLUMNS = """
    l.id, l.customer_id, l.address, l.address_key, l.customer_name,
    l.location_type, l.rate, l.rate_type, l.frequency, l.expected_hours,
    l.expected_hours_source, l.expected_hours_learning_decision,
    l.expected_hours_learning_fingerprint, l.expected_hours_learning_snapshot,
    l.expected_hours_learning_decided_at, l.expected_hours_learning_decided_by,
    l.expected_hours_learning_decision_reason,
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


def _entity_update_token(entity: str, row: Dict[str, Any]) -> str:
    updated_at = row["updated_at"].astimezone(timezone.utc).isoformat(timespec="microseconds")
    canonical = f"{entity}:{int(row['id'])}:{updated_at}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_current_update_token(
    entity: str,
    row: Dict[str, Any],
    expected_token: Optional[str],
) -> None:
    if expected_token is None:
        return
    current_token = _entity_update_token(entity, row)
    if hmac.compare_digest(expected_token, current_token):
        return
    entity_label = "Customer" if entity == "customer" else "Site"
    _raise_conflict(
        f"stale_{entity}_update",
        f"{entity_label} changed after it was read; reload before retrying",
        {f"{entity}Id": int(row["id"])},
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
        "expectedHoursSource": str(row.get("expected_hours_source") or "manual"),
        "expectedHoursLearningDecision": row.get("expected_hours_learning_decision"),
        "expectedHoursLearningFingerprint": row.get(
            "expected_hours_learning_fingerprint"
        ),
        "expectedHoursLearningSnapshot": row.get("expected_hours_learning_snapshot"),
        "expectedHoursLearningDecidedAt": to_utc_iso(
            row["expected_hours_learning_decided_at"]
        )
        if row.get("expected_hours_learning_decided_at") is not None
        else None,
        "expectedHoursLearningDecidedBy": (
            int(row["expected_hours_learning_decided_by"])
            if row.get("expected_hours_learning_decided_by") is not None
            else None
        ),
        "expectedHoursLearningDecisionReason": str(
            row.get("expected_hours_learning_decision_reason") or ""
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
        "updateToken": _entity_update_token("site", row),
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
        # Mirrored from Atlas, read-only here. Serialized so the portal can
        # render the type and adapt billing to it without a per-row round trip
        # to Atlas; PATCHing it back is refused as system-managed.
        "customerType": str(row.get("customer_type") or "unknown"),
        "active": bool(row.get("active")),
        "status": _customer_status(row, sites),
        "siteCount": len(sites),
        "activeSiteCount": len(active_sites),
        "readySiteCount": sum(site["status"] == "ready" for site in active_sites),
        "checklist": {"required": required, "optional": optional},
        "sites": sites,
        "createdAt": to_utc_iso(row["created_at"]),
        "updatedAt": to_utc_iso(row["updated_at"]),
        "updateToken": _entity_update_token("customer", row),
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


def _insert_customer(
    cur: Any,
    payload: CustomerCreateRequest,
    *,
    atlas_contact_id: Optional[str] = None,
    customer_type: Optional[str] = None,
) -> int:
    """Insert one Customer.

    `atlas_contact_id` is passed explicitly by the Slice 0C saga, which learns
    the canonical contact id from Atlas rather than from the request body. The
    payload field remains the source for the office estimate-approval path,
    where the contact already exists in Atlas before the Customer does.

    `customer_type` is likewise a keyword and never read from the payload:
    Atlas owns it, this row only mirrors what Atlas reported. A caller with an
    opinion about the type has to change it in Atlas. None means Atlas did not
    report one -- an older Atlas that does not serve the field yet, or a create
    that did not specify it -- and the column default records that honestly as
    'unknown' rather than inventing a classification.
    """
    linked_contact_id = atlas_contact_id
    if linked_contact_id is None and payload.atlasContactId is not None:
        linked_contact_id = str(payload.atlasContactId)
    cur.execute(
        """
        INSERT INTO customers (
            name, primary_contact_name, primary_phone, primary_email,
            billing_name, billing_email, billing_address, atlas_contact_id,
            customer_type
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, 'unknown'))
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
            linked_contact_id,
            customer_type,
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


def _require_juan_funnel_approver(
    admin: Dict[str, Any], *, action: str = "approve estimates"
) -> None:
    """Require the configured stable employee identity, not a display name."""
    if EOM_FUNNEL_APPROVER_EMPLOYEE_ID <= 0:
        raise HTTPException(
            status_code=503,
            detail="EOM funnel approval is not configured",
        )
    if int(admin["id"]) != EOM_FUNNEL_APPROVER_EMPLOYEE_ID:
        raise HTTPException(
            status_code=403,
            detail=f"Only the configured EOM funnel approver may {action}",
        )


def _can_approve_eom_funnel(admin: Dict[str, Any]) -> bool:
    return (
        EOM_FUNNEL_APPROVER_EMPLOYEE_ID > 0
        and int(admin["id"]) == EOM_FUNNEL_APPROVER_EMPLOYEE_ID
    )


def _office_conversion_fingerprint(payload: OfficeEstimateApprovalRequest) -> str:
    """Fingerprint every customer/site field while excluding the retry key."""
    source = payload.model_dump(mode="json", exclude={"idempotencyKey"})
    canonical = json.dumps(source, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _serialize_office_conversion_handoff(
    row: Dict[str, Any],
    customer: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "contactId": str(row["atlas_contact_id"]),
        "customerId": int(row["customer_id"]),
        "siteId": int(row["site_id"]),
        "status": str(row["state"]),
        "atlasHandoffId": (
            str(row["atlas_handoff_id"])
            if row.get("atlas_handoff_id") is not None
            else None
        ),
        "lastError": row.get("last_error"),
        "customer": customer,
    }


def _list_pending_office_conversion_handoffs() -> List[Dict[str, Any]]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM eom_office_conversion_handoffs
                WHERE state = 'pending'
                ORDER BY updated_at DESC, created_at DESC
                """
            )
            rows = [dict(row) for row in cur.fetchall()]
            return [
                _serialize_office_conversion_handoff(
                    row,
                    _canonical_customer(cur, int(row["customer_id"])),
                )
                for row in rows
            ]


def _office_conversion_handoff_for_contact(contact_id: str) -> Optional[Dict[str, Any]]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM eom_office_conversion_handoffs
                WHERE atlas_contact_id = %s
                """,
                (contact_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            handoff = dict(row)
            return {
                "handoff": handoff,
                "customer": _canonical_customer(cur, int(handoff["customer_id"])),
            }


def _reserve_office_conversion_handoff(
    payload: OfficeEstimateApprovalRequest,
    admin: Dict[str, Any],
) -> tuple[Dict[str, Any], bool]:
    """Create once or return the canonical local operation under one lock."""
    fingerprint = _office_conversion_fingerprint(payload)
    contact_id = str(payload.atlasContactId)
    key = str(payload.idempotencyKey)
    try:
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                _lock_customer_site_mutations(cur)
                cur.execute(
                    """
                    SELECT *
                    FROM eom_office_conversion_handoffs
                    WHERE atlas_contact_id = %s
                    FOR UPDATE
                    """,
                    (contact_id,),
                )
                existing = cur.fetchone()
                if existing:
                    row = dict(existing)
                    if str(row["idempotency_key"]) != key:
                        _raise_conflict(
                            "office_conversion_contact_already_reserved",
                            "This Atlas lead already has an office conversion approval",
                            {"customerId": int(row["customer_id"]), "siteId": int(row["site_id"])},
                        )
                    if not hmac.compare_digest(str(row["request_fingerprint"]), fingerprint):
                        _raise_conflict(
                            "office_conversion_retry_mismatch",
                            "This approval key was already used with different estimate details",
                            {"customerId": int(row["customer_id"]), "siteId": int(row["site_id"])},
                        )
                    customer = _canonical_customer(cur, int(row["customer_id"]))
                    return {"handoff": row, "customer": customer}, False

                cur.execute(
                    "SELECT id FROM customers WHERE atlas_contact_id = %s FOR UPDATE",
                    (contact_id,),
                )
                legacy_matches = cur.fetchall()
                if legacy_matches:
                    _raise_conflict(
                        "office_conversion_existing_atlas_customer",
                        "An existing Atlas-linked Customer must be reconciled before approval",
                        {"customerIds": [int(match["id"]) for match in legacy_matches]},
                    )

                customer_id = _insert_customer(cur, payload)
                site_id = _insert_site(cur, customer_id, payload.name, payload.primarySite)
                cur.execute(
                    """
                    INSERT INTO eom_office_conversion_handoffs (
                        atlas_contact_id, idempotency_key, request_fingerprint,
                        customer_id, site_id, approved_by_employee_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (contact_id, key, fingerprint, customer_id, site_id, int(admin["id"])),
                )
                row = dict(cur.fetchone())
                customer = _canonical_customer(cur, customer_id)
                return {"handoff": row, "customer": customer}, True
    except psycopg2.errors.UniqueViolation as exc:
        if (
            getattr(exc.diag, "constraint_name", "")
            == "eom_office_conversion_handoffs_idempotency_key_key"
        ):
            _raise_conflict(
                "office_conversion_approval_key_already_reserved",
                "This approval key already belongs to a different office conversion",
                {"idempotencyKey": key},
            )
        raise


def _mark_office_conversion_finalized(
    contact_id: str,
    idempotency_key: str,
    atlas_handoff_id: str,
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            cur.execute(
                """
                UPDATE eom_office_conversion_handoffs
                SET state = 'finalized', atlas_handoff_id = %s,
                    last_error = NULL, finalized_at = COALESCE(finalized_at, NOW()),
                    updated_at = NOW()
                WHERE atlas_contact_id = %s AND idempotency_key = %s
                RETURNING *
                """,
                (atlas_handoff_id, contact_id, idempotency_key),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Office conversion handoff disappeared before finalization")
            return dict(row)


def _note_office_conversion_error(
    contact_id: str,
    idempotency_key: str,
    reason: str,
) -> bool:
    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE eom_office_conversion_handoffs
                    SET last_error = %s, updated_at = NOW()
                    WHERE atlas_contact_id = %s
                      AND idempotency_key = %s
                      AND state = 'pending'
                    """,
                    (reason[:1000], contact_id, idempotency_key),
                )
                return cur.rowcount == 1
    except Exception:
        logger.exception("Could not save office conversion handoff error")
        return False


def _finalized_office_conversion_after_lost_error_race(
    contact_id: str,
) -> Optional[Dict[str, Any]]:
    refreshed = _office_conversion_handoff_for_contact(contact_id)
    if not refreshed:
        return None
    handoff = refreshed["handoff"]
    if handoff.get("state") != "finalized":
        return None
    return refreshed


# --- Slice 0C: canonical customer creation through Atlas ---------------------
#
# Reservation-first saga. The tracker and Atlas are separate databases, so this
# is deliberately NOT a distributed transaction: the reservation is committed
# before Atlas is called, and the local `customers` row is written only after
# Atlas confirms. That ordering is what makes "no local-only canonical
# customer" structural rather than a flag every reader has to remember to
# honor.
#
# Recovery relies on Atlas's own idempotency receipt rather than local
# bookkeeping: finalization is one local transaction, so if it fails the
# reservation simply stays pending, and the retry re-sends the SAME
# Idempotency-Key, which Atlas answers with the SAME contact. There is no
# window in which a retry can produce a second contact, and no compensating
# delete is ever issued against a contact Atlas already created.


def _customer_atlas_stored_payload(payload: CustomerCreateRequest) -> Dict[str, Any]:
    """The canonical stored form of one customer-create request."""
    return payload.model_dump(mode="json", exclude={"idempotencyKey"})


def _customer_atlas_fingerprint(
    stored_payload: Dict[str, Any],
    *,
    mode: str,
    customer_id: Optional[int],
) -> str:
    """Fingerprint everything that defines the operation except its retry key."""
    canonical = json.dumps(
        {"mode": mode, "customerId": customer_id, "payload": stored_payload},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _atlas_operator_contact_body(reservation: Dict[str, Any]) -> Dict[str, Any]:
    """Build the Atlas operator-mutation request for one reservation.

    Only non-empty identity fields are sent. Atlas's operator boundary is
    create-OR-return: when it matches an existing contact it applies the fields
    it receives as operator intent, so sending an explicit null would CLEAR a
    value on a contact this customer merely matched by phone or email. Address
    and notes are deliberately not mapped -- the CRM's copies come from other
    sources, the operational address lives on the tracker Site, and overwriting
    them here would be a silent data loss for no gain in 0C's guarantee.
    """
    stored = reservation.get("payload") or {}
    candidates = {
        "full_name": stored.get("name"),
        "email": stored.get("primaryEmail"),
        "phone": stored.get("primaryPhone"),
    }
    body: Dict[str, Any] = {
        key: value for key, value in candidates.items() if value
    }
    body["contact_type"] = "customer"
    body["source_channel"] = ATLAS_OPERATOR_SOURCE_CHANNEL
    body["source_ref"] = str(reservation["id"])
    return body


def _serialize_customer_atlas_reservation(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload") or {}
    return {
        "reservationId": str(row["id"]),
        "idempotencyKey": str(row["idempotency_key"]),
        "mode": str(row["mode"]),
        "status": str(row["state"]),
        "customerId": (
            int(row["customer_id"]) if row.get("customer_id") is not None else None
        ),
        "customerName": payload.get("name"),
        "atlasContactId": (
            str(row["atlas_contact_id"])
            if row.get("atlas_contact_id") is not None
            else None
        ),
        "lastError": row.get("last_error"),
    }


def _list_pending_customer_atlas_reservations(cur: Any) -> List[Dict[str, Any]]:
    """Pending reservations, read on the caller's cursor.

    Takes a cursor so the customers listing can read both representations
    back-to-back on one connection, and read THIS one first. Ordering is what
    matters: finalization inserts the Customer and flips the reservation in one
    transaction, so reading customers first would let that commit land in the
    gap and produce a response showing the operation in neither collection.
    Reading reservations first makes the worst case a row that appears briefly
    in both, which self-corrects on the next load and never hides work.
    """
    cur.execute(
        """
        SELECT *
        FROM eom_customer_atlas_reservations
        WHERE state = 'pending'
        ORDER BY updated_at DESC, created_at DESC
        """
    )
    return [
        _serialize_customer_atlas_reservation(dict(row))
        for row in cur.fetchall()
    ]


def _finalized_customer_atlas_reservation(
    reservation_id: str,
) -> Optional[Dict[str, Any]]:
    """The saga result for a reservation another attempt already finalized."""
    reservation = _customer_atlas_reservation(reservation_id)
    if not reservation or reservation["state"] != "finalized":
        return None
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            return {
                "reservation": reservation,
                "customer": _canonical_customer(
                    cur, int(reservation["customer_id"])
                ),
            }


def _finalized_customer_atlas_reservation_for_key(
    idempotency_key: str,
    request_fingerprint: str,
) -> Optional[Dict[str, Any]]:
    """Resolve a key that already belongs to a completed operation.

    Both answers are given locally, before capability negotiation, because
    neither needs anything from Atlas and both are true regardless of what
    Atlas currently serves:

    - the same details on a finalized key are a replay, answered with the
      Customer that key created, so a capability rollback cannot break the
      replay guarantee;
    - different details are invalid key reuse, refused with the same 409 the
      reservation path raises, so it cannot hide behind deployment state.

    Pending reservations are read too, and only for the mismatch answer: a key
    is just as invalid to reuse while its first attempt is still unfinished,
    and the reservation path that would otherwise catch it sits behind
    capability negotiation. A pending key with matching details falls through
    to be re-driven normally.
    """
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM eom_customer_atlas_reservations
                WHERE idempotency_key = %s
                """,
                (idempotency_key,),
            )
            row = cur.fetchone()
            if not row:
                return None
            reservation = dict(row)
            if not hmac.compare_digest(
                str(reservation["request_fingerprint"]), request_fingerprint
            ):
                _raise_conflict(
                    "customer_atlas_retry_mismatch",
                    "This key was already used with different customer details",
                    {"reservationId": str(reservation["id"])},
                )
            if reservation["state"] != "finalized":
                return None
            return {
                "reservation": reservation,
                "customer": _canonical_customer(
                    cur, int(reservation["customer_id"])
                ),
            }


def _customer_atlas_reservation(reservation_id: str) -> Optional[Dict[str, Any]]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM eom_customer_atlas_reservations WHERE id = %s",
                (reservation_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def _customer_request_from_row(row: Dict[str, Any]) -> CustomerCreateRequest:
    """Rebuild the create request that describes an existing Customer."""
    return CustomerCreateRequest(
        name=str(row["name"]),
        primaryContactName=row.get("primary_contact_name"),
        primaryPhone=row.get("primary_phone"),
        primaryEmail=row.get("primary_email"),
        billingName=row.get("billing_name"),
        billingEmail=row.get("billing_email"),
        billingAddress=row.get("billing_address"),
    )


def _reserve_customer_atlas_creation(
    payload: Optional[CustomerCreateRequest],
    admin: Dict[str, Any],
    *,
    customer_id: Optional[int] = None,
) -> tuple[Dict[str, Any], bool]:
    """Create once or return the canonical local reservation under one lock.

    Validates everything the eventual local insert will validate BEFORE the
    reservation exists, so a payload that cannot succeed locally never reaches
    Atlas and never strands an orphan contact.

    For `link_existing` the payload is read from the LOCKED Customer row rather
    than from a snapshot the caller took earlier. A snapshot would let a
    concurrent identity edit slip in between the read and the lock, and Atlas
    would then match or create a contact for the old name/phone/email and link
    it to the edited Customer.
    """
    mode = "link_existing" if customer_id is not None else "create"
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)

            if mode == "link_existing":
                customer = _customer_row(cur, int(customer_id), for_update=True)
                if not customer:
                    raise HTTPException(status_code=404, detail="Customer not found")
                if customer.get("atlas_contact_id") is not None:
                    _raise_conflict(
                        "customer_already_linked",
                        "This Customer already has an Atlas contact",
                        {
                            "customerId": int(customer_id),
                            "atlasContactId": str(customer["atlas_contact_id"]),
                        },
                    )
                cur.execute(
                    """
                    SELECT id
                    FROM eom_customer_atlas_reservations
                    WHERE customer_id = %s AND state = 'pending'
                    FOR UPDATE
                    """,
                    (int(customer_id),),
                )
                open_reservation = cur.fetchone()
                if open_reservation:
                    _raise_conflict(
                        "customer_atlas_reservation_open",
                        "This Customer already has a pending Atlas reservation",
                        {"reservationId": str(open_reservation["id"])},
                    )
                payload = _customer_request_from_row(customer)

            stored_payload = _customer_atlas_stored_payload(payload)
            fingerprint = _customer_atlas_fingerprint(
                stored_payload, mode=mode, customer_id=customer_id
            )
            # A caller-supplied key is what buys replay protection: the same key
            # always resolves to the same reservation and therefore the same
            # Atlas contact.
            #
            # When none is supplied we mint a fresh one rather than deriving it
            # from the payload. A derived key looks safer but is not: two
            # genuinely distinct customers can share every field (equal names
            # are normal here -- Edward Jones and Mid Illinois are live
            # examples), and a derived key would silently merge them into one
            # Customer. Losing replay protection for a caller that opted out of
            # it is recoverable and visible; silently merging two real customers
            # is neither.
            key = str(payload.idempotencyKey or uuid4())
            cur.execute(
                """
                SELECT *
                FROM eom_customer_atlas_reservations
                WHERE idempotency_key = %s
                FOR UPDATE
                """,
                (key,),
            )
            existing = cur.fetchone()
            if existing:
                row = dict(existing)
                if not hmac.compare_digest(
                    str(row["request_fingerprint"]), fingerprint
                ):
                    _raise_conflict(
                        "customer_atlas_retry_mismatch",
                        "This key was already used with different customer details",
                        {"reservationId": str(row["id"])},
                    )
                return row, False

            if mode == "create" and payload.primarySite is not None:
                # Pre-flight the address uniqueness the finalizing insert will
                # enforce. Raising here costs nothing; raising after Atlas has
                # already created the contact would strand it.
                _lock_address_and_find_conflicts(cur, payload.primarySite.address)

            cur.execute(
                """
                INSERT INTO eom_customer_atlas_reservations (
                    id, idempotency_key, request_fingerprint, payload, mode,
                    customer_id, requested_by_employee_id
                )
                VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s)
                RETURNING *
                """,
                (
                    str(uuid4()),
                    key,
                    fingerprint,
                    json.dumps(stored_payload, sort_keys=True),
                    mode,
                    customer_id,
                    int(admin["id"]),
                ),
            )
            return dict(cur.fetchone()), True


def _finalize_customer_atlas_reservation(
    reservation_id: str,
    atlas_contact_id: str,
    payload: CustomerCreateRequest,
    customer_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Write the local half once Atlas has confirmed the canonical contact.

    One transaction: if any part fails, nothing is written and the reservation
    stays pending. The retry re-sends the same Idempotency-Key, Atlas returns
    the same contact, and this runs again -- so a partial failure is forward
    recoverable against that same contact, never a second one.
    """
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            cur.execute(
                """
                SELECT *
                FROM eom_customer_atlas_reservations
                WHERE id = %s
                FOR UPDATE
                """,
                (reservation_id,),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Customer Atlas reservation disappeared")
            reservation = dict(row)
            if reservation["state"] == "finalized":
                return {
                    "reservation": reservation,
                    "customer": _canonical_customer(
                        cur, int(reservation["customer_id"])
                    ),
                }

            if reservation["mode"] == "link_existing":
                customer_id = int(reservation["customer_id"])
                cur.execute(
                    """
                    UPDATE customers
                    SET atlas_contact_id = %s,
                        customer_type = COALESCE(%s, customer_type),
                        updated_at = NOW()
                    WHERE id = %s AND atlas_contact_id IS NULL
                    """,
                    (atlas_contact_id, customer_type, customer_id),
                )
                if cur.rowcount == 0:
                    # Someone linked this Customer while we were talking to
                    # Atlas -- the legacy linkage-backfill endpoint takes the
                    # same mutation lock and can land in that gap. Finalizing
                    # anyway would record the reservation against contact A
                    # while the Customer points at contact B.
                    current = _customer_row(cur, customer_id, for_update=True)
                    linked = (
                        str(current["atlas_contact_id"])
                        if current and current.get("atlas_contact_id") is not None
                        else None
                    )
                    if linked != atlas_contact_id:
                        _raise_conflict(
                            "customer_atlas_link_conflict",
                            "This Customer was linked to a different Atlas "
                            "contact while this reconciliation was in flight",
                            {"customerId": customer_id, "atlasContactId": linked},
                        )
                    # The winner linked the SAME contact, so this reservation
                    # finalizes normally -- but its UPDATE matched nothing, and
                    # the linkage-backfill endpoint that won sets only
                    # atlas_contact_id. Without this the type Atlas just
                    # reported is dropped on the floor and the customer keeps
                    # 'unknown' purely because of who won a race.
                    if customer_type is not None:
                        cur.execute(
                            """
                            UPDATE customers
                            SET customer_type = %s, updated_at = NOW()
                            WHERE id = %s
                            """,
                            (customer_type, customer_id),
                        )
            else:
                customer_id = _insert_customer(
                    cur,
                    payload,
                    atlas_contact_id=atlas_contact_id,
                    customer_type=customer_type,
                )
                if payload.primarySite is not None:
                    _insert_site(
                        cur, customer_id, payload.name, payload.primarySite
                    )

            cur.execute(
                """
                UPDATE eom_customer_atlas_reservations
                SET state = 'finalized', atlas_contact_id = %s,
                    customer_id = %s, last_error = NULL,
                    finalized_at = COALESCE(finalized_at, NOW()), updated_at = NOW()
                WHERE id = %s
                RETURNING *
                """,
                (atlas_contact_id, customer_id, reservation_id),
            )
            finalized = dict(cur.fetchone())
            return {
                "reservation": finalized,
                "customer": _canonical_customer(cur, customer_id),
            }


def _note_customer_atlas_error(reservation_id: str, reason: str) -> bool:
    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE eom_customer_atlas_reservations
                    SET last_error = %s, updated_at = NOW()
                    WHERE id = %s AND state = 'pending'
                    """,
                    (reason[:1000], reservation_id),
                )
                return cur.rowcount == 1
    except Exception:
        logger.exception("Could not save customer Atlas reservation error")
        return False


def _customer_type_from_operator_result(result: Dict[str, Any]) -> Optional[str]:
    """Read the account type Atlas reported, or None when it reported none.

    Absence is not an error. Atlas deploys by hand and routinely lags this
    tracker, so a build that predates ATLAS #2354 simply omits the field --
    mirroring None then records 'unknown', which is true, instead of failing a
    customer create over a field the mirror does not need to function.

    A value Atlas would not itself accept is dropped rather than stored: the
    mirror must never hold a classification the source of truth would refuse,
    and the tracker has no business inventing one.
    """
    contact = result.get("contact")
    if not isinstance(contact, dict):
        return None
    reported = contact.get("customerType")
    if not isinstance(reported, str):
        return None
    normalized = reported.strip().lower()
    return normalized if normalized in CUSTOMER_TYPES else None


def _atlas_contact_id_from_operator_result(result: Dict[str, Any]) -> str:
    """Read the contact id Atlas assigned, refusing anything else.

    A malformed body is a 502, not a silent link to nothing: the whole point of
    this slice is that the local row is never written without a real contact.
    """
    if not result.get("success"):
        raise AtlasFunnelRequestError(
            502, "EOM contact service returned an unsuccessful result"
        )
    contact_id = result.get("contactId")
    if not isinstance(contact_id, str) or not contact_id.strip():
        raise AtlasFunnelRequestError(
            502, "EOM contact service returned no contact id"
        )
    try:
        return str(UUID(contact_id.strip()))
    except (ValueError, AttributeError, TypeError) as exc:
        raise AtlasFunnelRequestError(
            502, "EOM contact service returned an invalid contact id"
        ) from exc


def _run_customer_atlas_reservation(
    reservation: Dict[str, Any],
    payload: CustomerCreateRequest,
    admin: Dict[str, Any],
) -> tuple[Optional[Dict[str, Any]], Optional[AtlasFunnelRequestError]]:
    """Call Atlas for one pending reservation and finalize on success."""
    try:
        atlas_result = _atlas_funnel_request(
            ATLAS_OPERATOR_CONTACTS_PATH,
            admin,
            payload=_atlas_operator_contact_body(reservation),
            idempotency_key=str(reservation["idempotency_key"]),
        )
        atlas_contact_id = _atlas_contact_id_from_operator_result(atlas_result)
    except AtlasFunnelRequestError as exc:
        if not _note_customer_atlas_error(str(reservation["id"]), str(exc)):
            # The conditional update matched nothing, so this reservation is no
            # longer pending: a concurrent attempt on the same key finalized it
            # while this one was failing. Reporting our own timeout would tell
            # the operator to retry a Customer that already exists. Same race,
            # and same resolution, as the office-conversion saga.
            finalized = _finalized_customer_atlas_reservation(
                str(reservation["id"])
            )
            if finalized is not None:
                return finalized, None
        return None, exc
    try:
        return (
            _finalize_customer_atlas_reservation(
                str(reservation["id"]),
                atlas_contact_id,
                payload,
                _customer_type_from_operator_result(atlas_result),
            ),
            None,
        )
    except HTTPException as exc:
        # A precise, user-actionable refusal (an address conflict that raced in
        # after the pre-flight) keeps its own status and message. The
        # reservation still has to carry the reason, or it would sit in the
        # pending list with a blank error nobody can act on.
        _note_customer_atlas_error(str(reservation["id"]), str(exc.detail))
        raise
    except Exception as exc:  # local half failed; Atlas already has the contact
        logger.exception("Customer Atlas reservation could not be finalized")
        failure = AtlasFunnelRequestError(
            503,
            "The Atlas contact was created but this Customer could not be "
            "saved locally; retry this reservation",
        )
        _note_customer_atlas_error(str(reservation["id"]), str(exc))
        return None, failure


def _customer_atlas_capability_refusal(
    admin: Dict[str, Any],
) -> Optional[JSONResponse]:
    """Refuse early only when Atlas AFFIRMS it cannot serve this mutation.

    The distinction matters. A manifest that says the capability is absent is a
    definite "no": refusing before any local write is correct, and a reservation
    would be litter for an operation that can never succeed on this deployment.

    A manifest we could not READ is an outage, not a refusal. Aborting there
    would return 503 with no reservation and lose the operator's entry -- the
    opposite of the promise that an unreachable Atlas still leaves a visible,
    retryable record. So fall through and let the mutation attempt create that
    record.
    """
    # A tracker with no Atlas credentials is a deterministic local "no", not an
    # outage: it will never reach Atlas on any retry, so it must refuse here
    # rather than bank a reservation that can only fail. Deliberately outside
    # the catch below -- otherwise its 503 would be mistaken for an unreachable
    # Atlas and escape later from the mutation call, which raises HTTPException
    # rather than AtlasFunnelRequestError for this case.
    _require_atlas_funnel_configuration()
    try:
        _require_atlas_funnel_capability(
            ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION, admin
        )
    except AtlasFunnelCapabilityUnavailable as exc:
        return _atlas_capability_unavailable_response(exc)
    except HTTPException as exc:
        logger.warning(
            "Atlas capability manifest unreadable (status=%s); reserving anyway",
            exc.status_code,
        )
    return None


def _customer_atlas_pending_response(
    reservation: Dict[str, Any],
    exc: AtlasFunnelRequestError,
    *,
    created: bool,
) -> JSONResponse:
    visible = _serialize_customer_atlas_reservation(dict(reservation))
    visible["lastError"] = str(exc)
    visible["status"] = "atlas_pending"
    return JSONResponse(
        status_code=202,
        content=jsonable_encoder(
            {
                "success": False,
                "idempotent": not created,
                "error": "customer_atlas_pending",
                "reservation": visible,
            }
        ),
    )


def _serialize_working_lead(
    lead: Dict[str, Any],
    marker: Dict[str, Any],
) -> Dict[str, Any]:
    working_lead = _lead_with_state_token(lead, marker)
    marked_at = marker.get("marked_at")
    working_lead["markedAt"] = to_utc_iso(marked_at) if marked_at else None
    working_lead["markedByEmployeeId"] = (
        int(marker["marked_by_employee_id"])
        if marker.get("marked_by_employee_id") is not None
        else None
    )
    return working_lead


def _lead_state_token(contact_id: str, state_version: int) -> str:
    return hashlib.sha256(
        f"eom-lead-working-state:v1:{contact_id}:{state_version}".encode("utf-8")
    ).hexdigest()


def _lead_with_state_token(
    lead: Dict[str, Any],
    marker: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    contact_id = str(lead["contactId"])
    state_version = int(marker["state_version"]) if marker else 0
    enriched = dict(lead)
    enriched["stateToken"] = _lead_state_token(contact_id, state_version)
    return enriched


def _list_lead_state_markers(contact_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not contact_ids:
        return {}
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT atlas_contact_id, state, state_version, marked_at,
                       marked_by_employee_id, lost_at, lost_by_employee_id,
                       reopened_at, reopened_by_employee_id
                FROM eom_lead_working
                WHERE atlas_contact_id = ANY(%s::uuid[])
                """,
                (contact_ids,),
            )
            return {str(row["atlas_contact_id"]): dict(row) for row in cur.fetchall()}


def _mark_lead_working(
    contact_id: str,
    admin: Dict[str, Any],
    expected_state_token: str,
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            _lock_funnel_lead_transition(cur, contact_id)
            cur.execute(
                """
                SELECT state
                FROM eom_office_conversion_handoffs
                WHERE atlas_contact_id = %s
                """,
                (contact_id,),
            )
            handoff = cur.fetchone()
            if handoff:
                _raise_conflict(
                    "funnel_lead_already_reserved",
                    "This Atlas lead already has an office conversion approval",
                    {"contactId": contact_id, "handoffState": str(handoff["state"])},
                )

            cur.execute(
                """
                SELECT atlas_contact_id, state, state_version, marked_at,
                       marked_by_employee_id, lost_at, lost_by_employee_id,
                       reopened_at, reopened_by_employee_id
                FROM eom_lead_working
                WHERE atlas_contact_id = %s
                FOR UPDATE
                """,
                (contact_id,),
            )
            existing = cur.fetchone()
            if existing and str(existing["state"]) == "working":
                return dict(existing)

            current_version = int(existing["state_version"]) if existing else 0
            current_token = _lead_state_token(contact_id, current_version)
            if not hmac.compare_digest(expected_state_token, current_token):
                _raise_conflict(
                    "funnel_lead_state_changed",
                    "Lead review state changed; refresh before starting the estimate",
                    {"contactId": contact_id},
                )
            if existing and str(existing["state"]) == "lost":
                _raise_conflict(
                    "funnel_lead_not_active",
                    "This lead is not active; reopen it before starting the estimate",
                    {"contactId": contact_id},
                )

            if existing:
                cur.execute(
                    """
                    UPDATE eom_lead_working
                    SET state = 'working',
                        state_version = state_version + 1,
                        marked_at = NOW(),
                        marked_by_employee_id = %s
                    WHERE atlas_contact_id = %s
                    RETURNING atlas_contact_id, state, state_version, marked_at,
                              marked_by_employee_id, lost_at, lost_by_employee_id,
                              reopened_at, reopened_by_employee_id
                    """,
                    (int(admin["id"]), contact_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO eom_lead_working (
                        atlas_contact_id, state, state_version,
                        marked_by_employee_id
                    )
                    VALUES (%s, 'working', 1, %s)
                    RETURNING atlas_contact_id, state, state_version, marked_at,
                              marked_by_employee_id, lost_at, lost_by_employee_id,
                              reopened_at, reopened_by_employee_id
                    """,
                    (contact_id, int(admin["id"])),
                )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Working lead marker was saved but could not be reloaded")
            return dict(row)


def _mark_lead_lost_locally(
    cur: psycopg2.extras.RealDictCursor,
    contact_id: str,
    admin: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        INSERT INTO eom_lead_working (
            atlas_contact_id, state, state_version,
            lost_at, lost_by_employee_id
        )
        VALUES (%s, 'lost', 1, NOW(), %s)
        ON CONFLICT (atlas_contact_id) DO UPDATE
        SET state = 'lost',
            state_version = eom_lead_working.state_version + 1,
            lost_at = NOW(),
            lost_by_employee_id = EXCLUDED.lost_by_employee_id
        RETURNING atlas_contact_id, state, state_version, marked_at,
                  marked_by_employee_id, lost_at, lost_by_employee_id,
                  reopened_at, reopened_by_employee_id
        """,
        (contact_id, int(admin["id"])),
    )
    row = cur.fetchone()
    if not row:
        raise RuntimeError("Lost lead marker was saved but could not be reloaded")
    return dict(row)


def _mark_lead_reopened_locally(
    cur: psycopg2.extras.RealDictCursor,
    contact_id: str,
    admin: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        INSERT INTO eom_lead_working (
            atlas_contact_id, state, state_version,
            reopened_at, reopened_by_employee_id
        )
        VALUES (%s, 'reopened', 1, NOW(), %s)
        ON CONFLICT (atlas_contact_id) DO UPDATE
        SET state = 'reopened',
            state_version = eom_lead_working.state_version + 1,
            reopened_at = NOW(),
            reopened_by_employee_id = EXCLUDED.reopened_by_employee_id
        RETURNING atlas_contact_id, state, state_version, marked_at,
                  marked_by_employee_id, lost_at, lost_by_employee_id,
                  reopened_at, reopened_by_employee_id
        """,
        (contact_id, int(admin["id"])),
    )
    row = cur.fetchone()
    if not row:
        raise RuntimeError("Reopened lead marker was saved but could not be reloaded")
    return dict(row)


def _clear_working_lead_marker(contact_id: str) -> None:
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM eom_lead_working WHERE atlas_contact_id = %s", (contact_id,))


@app.get("/api/admin/customers")
def admin_list_customers(
    request: Request,
    includeArchived: bool = Query(default=False),
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    active_clause = "" if includeArchived else " WHERE c.active = true"
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            pending_reservations = _list_pending_customer_atlas_reservations(cur)
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
    # `pendingAtlasReservations` is additive: the `customers` shape the deployed
    # portals read is unchanged. Customer creates that reached Atlas but have
    # not finalized appear here and nowhere else -- they are deliberately not
    # Customers yet.
    return {
        "success": True,
        "customers": customers,
        "pendingAtlasReservations": pending_reservations,
    }


@app.post("/api/admin/customers", status_code=201)
def admin_create_customer(
    payload: CustomerCreateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Create one Customer, through Atlas, or not at all.

    Slice 0C (website #110): Atlas is the only write authority for canonical
    customers, so this route no longer writes a Customer directly. It reserves
    the operation durably, asks Atlas for the canonical contact, and writes the
    local rows only once Atlas has answered. An unreachable Atlas yields a
    visible, retryable reservation and NO Customer -- never a silent local-only
    row that the CRM has never heard of.
    """
    if payload.atlasContactId is not None:
        _raise_validation_error(
            "atlasContactId is assigned by Atlas and cannot be supplied",
            {"atlasContactId": "system managed"},
        )
    # A key whose operation already completed is answered from local state.
    # This precedes capability negotiation on purpose: the Customer exists, the
    # replay asks nothing of Atlas, and refusing it because Atlas has since
    # rolled the capability back would break the documented replay guarantee.
    if payload.idempotencyKey is not None:
        completed = _finalized_customer_atlas_reservation_for_key(
            str(payload.idempotencyKey),
            _customer_atlas_fingerprint(
                _customer_atlas_stored_payload(payload),
                mode="create",
                customer_id=None,
            ),
        )
        if completed is not None:
            append_access_log(
                request,
                "CUSTOMER_CREATE_REPLAYED",
                True,
                f"customer={completed['reservation']['customer_id']} "
                f"by {admin['name']}",
            )
            return JSONResponse(
                status_code=200,
                content=jsonable_encoder(
                    {
                        "success": True,
                        "idempotent": True,
                        "customer": completed["customer"],
                    }
                ),
            )

    # Refused before any local write, so a partially-deployed Atlas cannot
    # leave a Customer behind.
    refusal = _customer_atlas_capability_refusal(admin)
    if refusal is not None:
        append_access_log(
            request,
            "CUSTOMER_CREATE_CAPABILITY_UNAVAILABLE",
            False,
            f"capability={ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION}",
        )
        return refusal

    reservation, created = _reserve_customer_atlas_creation(payload, admin)
    if reservation["state"] == "finalized":
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                customer = _canonical_customer(cur, int(reservation["customer_id"]))
        append_access_log(
            request,
            "CUSTOMER_CREATE_REPLAYED",
            True,
            f"customer={reservation['customer_id']} by {admin['name']}",
        )
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder(
                {"success": True, "idempotent": True, "customer": customer}
            ),
        )

    result, failure = _run_customer_atlas_reservation(reservation, payload, admin)
    if failure is not None:
        append_access_log(
            request,
            "CUSTOMER_CREATE_PENDING",
            False,
            f"reservation={reservation['id']} status={failure.status_code}",
        )
        return _customer_atlas_pending_response(
            reservation, failure, created=created
        )

    customer = result["customer"]
    append_access_log(
        request,
        "CUSTOMER_CREATED",
        True,
        f"Customer {customer['id']} contact={result['reservation']['atlas_contact_id']} "
        f"by {admin['name']}",
    )
    # A first-time create keeps the exact legacy body. `idempotent` appears only
    # where it carries information the status code does not -- on a replay or a
    # recovered retry, which return 200.
    body: Dict[str, Any] = {"success": True, "customer": customer}
    if not created:
        body["idempotent"] = True
    return JSONResponse(
        status_code=201 if created else 200,
        content=jsonable_encoder(body),
    )


@app.post("/api/admin/customers/reservations/{reservation_id}/retry")
def admin_retry_customer_atlas_reservation(
    reservation_id: UUID,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Re-drive one pending customer reservation against the same Atlas key.

    Retrying is always safe: the stored Idempotency-Key means Atlas returns the
    contact it already created rather than a second one.
    """
    reservation = _customer_atlas_reservation(str(reservation_id))
    if not reservation:
        raise HTTPException(status_code=404, detail="Customer reservation not found")

    if reservation["state"] == "finalized":
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                customer = _canonical_customer(cur, int(reservation["customer_id"]))
        append_access_log(
            request,
            "CUSTOMER_CREATE_RETRY_REPLAYED",
            True,
            f"reservation={reservation_id} customer={reservation['customer_id']}",
        )
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder(
                {"success": True, "idempotent": True, "customer": customer}
            ),
        )

    refusal = _customer_atlas_capability_refusal(admin)
    if refusal is not None:
        return refusal

    payload = CustomerCreateRequest(**(reservation["payload"] or {}))
    result, failure = _run_customer_atlas_reservation(reservation, payload, admin)
    if failure is not None:
        append_access_log(
            request,
            "CUSTOMER_CREATE_RETRY_PENDING",
            False,
            f"reservation={reservation_id} status={failure.status_code}",
        )
        return _customer_atlas_pending_response(reservation, failure, created=False)

    customer = result["customer"]
    append_access_log(
        request,
        "CUSTOMER_CREATE_RETRIED",
        True,
        f"reservation={reservation_id} customer={customer['id']}",
    )
    # `idempotent` describes the operation, not the endpoint: this re-drives a
    # reservation that already existed, exactly as the create route does when it
    # finds one, so both must label it the same way.
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder(
            {"success": True, "idempotent": True, "customer": customer}
        ),
    )


@app.post("/api/admin/customers/{customer_id}/atlas-contact")
def admin_link_customer_to_atlas(
    customer_id: int,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Give an existing unlinked Customer its canonical Atlas contact.

    The reconcile half of Slice 0C: customers created before this slice (and by
    the legacy Site writers that 0D still has to converge) have no contact. This
    runs them through the same saga, so the link is created the one canonical
    way rather than typed in by hand.
    """
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            existing = _customer_row(cur, customer_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Customer not found")
    if existing.get("atlas_contact_id") is not None:
        _raise_conflict(
            "customer_already_linked",
            "This Customer already has an Atlas contact",
            {
                "customerId": customer_id,
                "atlasContactId": str(existing["atlas_contact_id"]),
            },
        )

    refusal = _customer_atlas_capability_refusal(admin)
    if refusal is not None:
        return refusal

    # The identity sent to Atlas is built from the row under its lock inside the
    # reservation, not from the unlocked pre-check above: a concurrent edit
    # between the two would otherwise link a contact created for stale details.
    reservation, created = _reserve_customer_atlas_creation(
        None, admin, customer_id=customer_id
    )
    payload = CustomerCreateRequest(**(reservation["payload"] or {}))
    result, failure = _run_customer_atlas_reservation(reservation, payload, admin)
    if failure is not None:
        append_access_log(
            request,
            "CUSTOMER_ATLAS_LINK_PENDING",
            False,
            f"customer={customer_id} status={failure.status_code}",
        )
        return _customer_atlas_pending_response(
            reservation, failure, created=created
        )

    customer = result["customer"]
    append_access_log(
        request,
        "CUSTOMER_ATLAS_LINKED",
        True,
        f"customer={customer_id} contact={result['reservation']['atlas_contact_id']}",
    )
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder(
            {"success": True, "idempotent": not created, "customer": customer}
        ),
    )


@app.post("/api/admin/funnel/approve-estimate")
def admin_approve_estimate(
    payload: OfficeEstimateApprovalRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Create one operational Customer/Site and finalize its Atlas lead link.

    This is intentionally an office command. It neither creates a job nor
    projects a calendar event: those follow after the approved estimate through
    their existing operational workflows.
    """
    _require_juan_funnel_approver(admin)
    _require_atlas_funnel_configuration()
    reserved, created = _reserve_office_conversion_handoff(payload, admin)
    handoff = reserved["handoff"]
    customer = reserved["customer"]
    contact_id = str(payload.atlasContactId)
    idempotency_key = str(payload.idempotencyKey)
    _clear_working_lead_marker(contact_id)

    if handoff["state"] == "finalized":
        append_access_log(
            request,
            "EOM_ESTIMATE_APPROVAL_REPLAYED",
            True,
            f"contact={contact_id} customer={handoff['customer_id']}",
        )
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder(
                {
                    "success": True,
                    "idempotent": True,
                    "handoff": _serialize_office_conversion_handoff(handoff, customer),
                }
            ),
        )

    atlas_payload = {
        "contact_id": contact_id,
        "tracker_customer_id": int(handoff["customer_id"]),
        "tracker_site_id": int(handoff["site_id"]),
    }
    try:
        atlas_result = _atlas_funnel_request(
            "/eom-funnel/customer-handoffs",
            admin,
            payload=atlas_payload,
            idempotency_key=idempotency_key,
        )
        atlas_handoff_id = _validate_atlas_customer_handoff_result(
            atlas_result,
            contact_id=contact_id,
            customer_id=int(handoff["customer_id"]),
            site_id=int(handoff["site_id"]),
            idempotency_key=idempotency_key,
        )
    except AtlasFunnelRequestError as exc:
        if not _note_office_conversion_error(contact_id, idempotency_key, str(exc)):
            finalized = _finalized_office_conversion_after_lost_error_race(contact_id)
            if finalized:
                append_access_log(
                    request,
                    "EOM_ESTIMATE_APPROVAL_REPLAYED",
                    True,
                    f"contact={contact_id} customer={finalized['handoff']['customer_id']}",
                )
                return JSONResponse(
                    status_code=200,
                    content=jsonable_encoder(
                        {
                            "success": True,
                            "idempotent": True,
                            "handoff": _serialize_office_conversion_handoff(
                                finalized["handoff"],
                                finalized["customer"],
                            ),
                        }
                    ),
                )
        handoff = dict(handoff)
        handoff["last_error"] = str(exc)
        visible = _serialize_office_conversion_handoff(handoff, customer)
        visible["status"] = "atlas_pending"
        append_access_log(
            request,
            "EOM_ESTIMATE_APPROVAL_PENDING",
            False,
            f"contact={contact_id} customer={handoff['customer_id']} status={exc.status_code}",
        )
        return JSONResponse(
            status_code=202,
            content=jsonable_encoder(
                {"success": False, "idempotent": not created, "handoff": visible}
            ),
        )

    handoff = _mark_office_conversion_finalized(
        contact_id,
        idempotency_key,
        atlas_handoff_id,
    )
    visible = _serialize_office_conversion_handoff(handoff, customer)
    append_access_log(
        request,
        "EOM_ESTIMATE_APPROVED",
        True,
        f"contact={contact_id} customer={handoff['customer_id']} site={handoff['site_id']}",
    )
    return JSONResponse(
        status_code=201 if created else 200,
        content=jsonable_encoder(
            {"success": True, "idempotent": not created, "handoff": visible}
        ),
    )


@app.post("/api/admin/funnel/leads/{contact_id}/start-estimate")
def admin_start_funnel_lead_estimate(
    contact_id: UUID,
    payload: FunnelLeadStartEstimateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Mark an Atlas lead as actively working before estimate approval."""
    _require_juan_funnel_approver(admin, action="start estimates")
    contact_id_text = str(contact_id)
    marker = _mark_lead_working(contact_id_text, admin, payload.expectedStateToken)
    append_access_log(
        request,
        "EOM_FUNNEL_LEAD_ESTIMATE_STARTED",
        True,
        f"contact={contact_id_text}",
    )
    return {
        "success": True,
        "workingLead": {
            "contactId": contact_id_text,
            "markedAt": to_utc_iso(marker["marked_at"]),
            "markedByEmployeeId": int(marker["marked_by_employee_id"]),
            "stateToken": _lead_state_token(contact_id_text, int(marker["state_version"])),
        },
    }


@app.get("/api/admin/funnel/review")
def admin_list_funnel_review(
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    content = _atlas_funnel_read("/eom-funnel/leads", admin, params=params)
    lead_page = _parse_atlas_lead_review_response(content)
    leads = lead_page["leads"]
    lead_state_markers = _list_lead_state_markers([lead["contactId"] for lead in leads])
    new_leads: List[Dict[str, Any]] = []
    working_leads: List[Dict[str, Any]] = []
    for lead in leads:
        marker = lead_state_markers.get(str(lead["contactId"]))
        if marker and str(marker["state"]) == "working":
            working_leads.append(_serialize_working_lead(lead, marker))
        else:
            new_leads.append(_lead_with_state_token(lead, marker))
    pending_handoffs = _list_pending_office_conversion_handoffs()
    append_access_log(
        request,
        "EOM_FUNNEL_REVIEW_LISTED",
        True,
        f"leads={len(new_leads)} working={len(working_leads)} pending={len(pending_handoffs)}",
    )
    return {
        "success": True,
        "canApprove": _can_approve_eom_funnel(admin),
        "leads": new_leads,
        "workingLeads": working_leads,
        "cursor": lead_page["cursor"],
        "hasMore": lead_page["hasMore"],
        "nextCursor": lead_page["nextCursor"],
        "pendingHandoffs": pending_handoffs,
        # What the DEPLOYED Atlas serves, so the caller can gate a control
        # instead of rendering one that 404s. `capabilitiesDeclared` false means
        # Atlas predates the manifest and advertised nothing -- distinct from
        # declaring an empty set, and the caller must treat both as "do not
        # enable", per Atlas #2308.
        "capabilities": sorted(lead_page["capabilities"] or ()),
        "capabilitiesDeclared": lead_page["capabilities"] is not None,
    }


@app.post("/api/admin/funnel/handoffs/{contact_id}/retry")
def admin_retry_funnel_handoff(
    contact_id: UUID,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    _require_juan_funnel_approver(admin)
    _require_atlas_funnel_configuration()
    contact_id_text = str(contact_id)
    reserved = _office_conversion_handoff_for_contact(contact_id_text)
    if not reserved:
        raise HTTPException(status_code=404, detail="Office conversion handoff not found")
    handoff = reserved["handoff"]
    customer = reserved["customer"]
    if handoff["state"] == "finalized":
        append_access_log(
            request,
            "EOM_ESTIMATE_APPROVAL_RETRY_REPLAYED",
            True,
            f"contact={contact_id_text} customer={handoff['customer_id']}",
        )
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder(
                {
                    "success": True,
                    "idempotent": True,
                    "handoff": _serialize_office_conversion_handoff(handoff, customer),
                }
            ),
        )

    idempotency_key = str(handoff["idempotency_key"])
    atlas_payload = {
        "contact_id": contact_id_text,
        "tracker_customer_id": int(handoff["customer_id"]),
        "tracker_site_id": int(handoff["site_id"]),
    }
    try:
        atlas_result = _atlas_funnel_request(
            "/eom-funnel/customer-handoffs",
            admin,
            payload=atlas_payload,
            idempotency_key=idempotency_key,
        )
        atlas_handoff_id = _validate_atlas_customer_handoff_result(
            atlas_result,
            contact_id=contact_id_text,
            customer_id=int(handoff["customer_id"]),
            site_id=int(handoff["site_id"]),
            idempotency_key=idempotency_key,
        )
    except AtlasFunnelRequestError as exc:
        if not _note_office_conversion_error(contact_id_text, idempotency_key, str(exc)):
            finalized = _finalized_office_conversion_after_lost_error_race(contact_id_text)
            if finalized:
                append_access_log(
                    request,
                    "EOM_ESTIMATE_APPROVAL_RETRY_REPLAYED",
                    True,
                    f"contact={contact_id_text} customer={finalized['handoff']['customer_id']}",
                )
                return JSONResponse(
                    status_code=200,
                    content=jsonable_encoder(
                        {
                            "success": True,
                            "idempotent": True,
                            "handoff": _serialize_office_conversion_handoff(
                                finalized["handoff"],
                                finalized["customer"],
                            ),
                        }
                    ),
                )
        handoff = dict(handoff)
        handoff["last_error"] = str(exc)
        visible = _serialize_office_conversion_handoff(handoff, customer)
        visible["status"] = "atlas_pending"
        append_access_log(
            request,
            "EOM_ESTIMATE_APPROVAL_RETRY_PENDING",
            False,
            f"contact={contact_id_text} customer={handoff['customer_id']} status={exc.status_code}",
        )
        return JSONResponse(
            status_code=202,
            content=jsonable_encoder(
                {"success": False, "idempotent": True, "handoff": visible}
            ),
        )

    handoff = _mark_office_conversion_finalized(
        contact_id_text,
        idempotency_key,
        atlas_handoff_id,
    )
    visible = _serialize_office_conversion_handoff(handoff, customer)
    append_access_log(
        request,
        "EOM_ESTIMATE_APPROVAL_RETRIED",
        True,
        f"contact={contact_id_text} customer={handoff['customer_id']} site={handoff['site_id']}",
    )
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder(
            {"success": True, "idempotent": True, "handoff": visible}
        ),
    )


def _require_atlas_funnel_capability(capability: str, admin: Dict[str, Any]) -> None:
    """Refuse an action the deployed Atlas cannot serve, before attempting it.

    Reads the manifest rather than inferring capability from a failed mutation.
    Atlas publishes this list precisely so callers stop guessing from failure
    modes, and a 404 body cannot distinguish "route not deployed" from "contact
    not found" -- guessing there would reinstate exactly what this slice removes.

    Costs one read on a human-initiated action. The read is deliberately
    limit=1: it is issued for the manifest, not for the page.
    """
    content = _atlas_funnel_read("/eom-funnel/leads", admin, params={"limit": 1})
    capabilities = _extract_atlas_funnel_capabilities(content)
    if capabilities is None or capability not in capabilities:
        raise AtlasFunnelCapabilityUnavailable(capability)


def _atlas_capability_unavailable_response(
    exc: AtlasFunnelCapabilityUnavailable,
) -> JSONResponse:
    """A typed, machine-readable outcome -- not a generic failure toast.

    501 rather than 5xx-generic: the upstream is healthy and simply does not
    implement this yet, which is neither a transient outage (503, used by
    _atlas_funnel_request for timeouts) nor a malformed response (502). Callers
    branch on `error`, never on the prose.
    """
    return JSONResponse(
        status_code=501,
        content={
            "success": False,
            "error": "atlas_capability_unavailable",
            "capability": exc.capability,
            "message": str(exc),
        },
    )


@app.post("/api/admin/funnel/leads/{contact_id}/lost")
def admin_mark_funnel_lead_lost(
    contact_id: UUID,
    payload: FunnelLeadLostRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Disposition an Atlas lead that will not convert. No local Customer/Site
    is created, so there is no pending-handoff row and no 202 retry path: Atlas
    is the single owner of the lead's stage."""
    _require_juan_funnel_approver(admin, action="mark leads lost")
    _require_atlas_funnel_configuration()
    # Before the DB lock: a capability refusal must not hold a row lock while
    # this service talks to Atlas, and must not leave a local transition
    # half-applied against a backend that cannot complete it.
    try:
        _require_atlas_funnel_capability(ATLAS_FUNNEL_CAPABILITY_LEAD_LOST, admin)
    except AtlasFunnelCapabilityUnavailable as exc:
        return _atlas_capability_unavailable_response(exc)
    contact_id_text = str(contact_id)
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_funnel_lead_transition(cur, contact_id_text)
            try:
                atlas_result = _atlas_funnel_request(
                    f"/eom-funnel/leads/{contact_id_text}/lost",
                    admin,
                    payload={"reason_code": payload.reasonCode, "note": payload.note},
                    idempotency_key=str(payload.idempotencyKey),
                )
            except AtlasFunnelRequestError as exc:
                raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
            _mark_lead_lost_locally(cur, contact_id_text, admin)
    append_access_log(
        request,
        "EOM_FUNNEL_LEAD_MARKED_LOST",
        True,
        f"contact={contact_id_text} reason={payload.reasonCode}",
    )
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({"success": True, "lead": atlas_result}),
    )


@app.post("/api/admin/funnel/leads/{contact_id}/reopen")
def admin_reopen_funnel_lead(
    contact_id: UUID,
    payload: FunnelLeadReopenRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> JSONResponse:
    """Return a previously-lost Atlas lead to the active review queue."""
    _require_juan_funnel_approver(admin, action="reopen leads")
    _require_atlas_funnel_configuration()
    # Before the DB lock: a capability refusal must not hold a row lock while
    # this service talks to Atlas, and must not leave a local transition
    # half-applied against a backend that cannot complete it.
    try:
        _require_atlas_funnel_capability(ATLAS_FUNNEL_CAPABILITY_LEAD_REOPEN, admin)
    except AtlasFunnelCapabilityUnavailable as exc:
        return _atlas_capability_unavailable_response(exc)
    contact_id_text = str(contact_id)
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_funnel_lead_transition(cur, contact_id_text)
            try:
                atlas_result = _atlas_funnel_request(
                    f"/eom-funnel/leads/{contact_id_text}/reopen",
                    admin,
                    payload={},
                    idempotency_key=str(payload.idempotencyKey),
                )
            except AtlasFunnelRequestError as exc:
                raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
            _mark_lead_reopened_locally(cur, contact_id_text, admin)
    append_access_log(
        request,
        "EOM_FUNNEL_LEAD_REOPENED",
        True,
        f"contact={contact_id_text}",
    )
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({"success": True, "lead": atlas_result}),
    )


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

    # `atlasContactId` is deliberately absent: CRM linkage is system-managed
    # (Slice 0C) and is set only by the reservation saga. Leaving it here would
    # let an ordinary customer edit silently repoint a Customer at a different
    # Atlas contact.
    field_map = {
        "name": "name",
        "primaryContactName": "primary_contact_name",
        "primaryPhone": "primary_phone",
        "primaryEmail": "primary_email",
        "billingName": "billing_name",
        "billingEmail": "billing_email",
        "billingAddress": "billing_address",
    }
    values = payload.model_dump()
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            existing = _customer_row(cur, customer_id, for_update=True)
            if not existing:
                raise HTTPException(status_code=404, detail="Customer not found")
            _require_current_update_token(
                "customer",
                existing,
                payload.expectedUpdateToken,
            )
            if "atlasContactId" in present:
                # Echoing back the stored value is what the deployed portal does
                # on every edit, so that stays a no-op. Actually CHANGING the
                # link is refused loudly rather than ignored: a silent drop
                # would look like a successful edit that did nothing.
                submitted = values["atlasContactId"]
                submitted_text = str(submitted) if submitted is not None else None
                stored = existing.get("atlas_contact_id")
                stored_text = str(stored) if stored is not None else None
                if submitted_text != stored_text:
                    _raise_conflict(
                        "customer_atlas_link_system_managed",
                        "The Atlas contact link is managed by Atlas and cannot "
                        "be edited here",
                        {
                            "customerId": customer_id,
                            "atlasContactId": stored_text,
                        },
                    )
            if "customerType" in present:
                # Same rule as the Atlas link above, and for the same reason:
                # this column is a mirror of Atlas, which is the sole write
                # authority for it. Echoing the stored value stays a no-op so a
                # portal that round-trips the whole record keeps working;
                # CHANGING it here is refused loudly, because a tracker-side
                # edit would either be silently discarded on the next mirror
                # refresh or, worse, drive billing from a value Atlas never
                # agreed to.
                submitted = values["customerType"]
                submitted_text = str(submitted).strip().lower() if submitted else None
                stored_text = str(existing.get("customer_type") or "unknown")
                if submitted_text != stored_text:
                    _raise_conflict(
                        "customer_type_system_managed",
                        "The customer type is managed by Atlas and cannot be "
                        "edited here",
                        {
                            "customerId": customer_id,
                            "customerType": stored_text,
                        },
                    )
            assignments: List[str] = []
            params: List[Any] = []
            for request_field, column in field_map.items():
                if request_field not in present:
                    continue
                assignments.append(f"{column} = %s")
                params.append(values[request_field])
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
                if "expectedHours" in present:
                    assignments.extend(
                        [
                            "expected_hours_source = 'manual'",
                            "expected_hours_learning_decision = NULL",
                            "expected_hours_learning_fingerprint = NULL",
                            "expected_hours_learning_snapshot = NULL",
                            "expected_hours_learning_decided_at = NULL",
                            "expected_hours_learning_decided_by = NULL",
                            "expected_hours_learning_decision_reason = ''",
                        ]
                    )
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
            _require_current_update_token(
                "site",
                existing,
                payload.expectedUpdateToken,
            )
            if payload.expectedCustomerUpdateToken is not None:
                owning_customer_id = existing.get("customer_id")
                if owning_customer_id is None:
                    _raise_conflict(
                        "site_customer_unlinked",
                        "Site is not linked to a Customer; reload before retrying",
                        {"siteId": site_id, "customerId": None},
                    )
                owning_customer = _customer_row(
                    cur,
                    int(owning_customer_id),
                    for_update=True,
                )
                if not owning_customer:
                    _raise_conflict(
                        "site_customer_missing",
                        "Site's Customer no longer exists; reload before retrying",
                        {
                            "siteId": site_id,
                            "customerId": int(owning_customer_id),
                        },
                    )
                _require_current_update_token(
                    "customer",
                    owning_customer,
                    payload.expectedCustomerUpdateToken,
                )

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
            if "expectedHours" in present:
                assignments.extend(
                    [
                        "expected_hours_source = 'manual'",
                        "expected_hours_learning_decision = NULL",
                        "expected_hours_learning_fingerprint = NULL",
                        "expected_hours_learning_snapshot = NULL",
                        "expected_hours_learning_decided_at = NULL",
                        "expected_hours_learning_decided_by = NULL",
                        "expected_hours_learning_decision_reason = ''",
                    ]
                )

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
                    UPDATE service_schedule_rules
                    SET active = false, updated_at = %s, updated_by = %s
                    WHERE location_id = %s AND active = true
                    """,
                    (archived_at, admin["id"], site_id),
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
    stale_open_shifts = []
    if employee.get("role") == "admin":
        stale_open_shifts = [
            summary
            for entry in timesheet_data.get("entries", [])
            for summary in [admin_stale_open_shift_summary(entry, now_utc)]
            if summary
        ]
        stale_open_shifts.sort(
            key=lambda item: (str(item.get("clockIn", "")), int(item.get("shiftId", 0)))
        )
    response_rows = [
        {
            "employeeId": row["id"],
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
        "staleOpenShifts": stale_open_shifts,
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
            s.hourly_rate_cents,
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
            v.job_id,
            v.sequence_version,
            v.site_check_in_id,
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
            d.visit_id,
            d.created_at
        FROM departures d
        LEFT JOIN locations l ON l.id = d.location_id
        WHERE d.shift_id = ANY(%s)
        ORDER BY d.shift_id, d.departure_time, d.id
        """,
        (ids,),
        cursor,
    )
    receipt_rows = _correction_query_all(
        """
        SELECT
            receipt.id,
            receipt.employee_id,
            receipt.location_id,
            receipt.shift_id,
            receipt.action,
            receipt.idempotency_key,
            receipt.request_fingerprint,
            receipt.server_recorded_at,
            receipt.device_scanned_at,
            receipt.latitude,
            receipt.longitude,
            receipt.accuracy_m,
            receipt.geofence_radius_m,
            receipt.distance_m,
            receipt.geofence_status,
            receipt.outcome,
            receipt.site_check_in_id,
            receipt.visit_id,
            receipt.departure_id,
            receipt.missing_departure_visit_ids,
            receipt.response_body,
            receipt.created_at
        FROM site_qr_action_receipts receipt
        WHERE receipt.shift_id = ANY(%s)
        ORDER BY receipt.shift_id, receipt.server_recorded_at, receipt.id
        """,
        (ids,),
        cursor,
    )
    payroll_shift_correction_rows = _correction_query_all(
        """
        SELECT
            correction.id,
            correction.week_start,
            correction.correction_date,
            correction.employee_id,
            correction.shift_id,
            correction.source_clock_in,
            correction.source_clock_out,
            correction.source_break_minutes,
            correction.source_total_minutes,
            correction.corrected_clock_in,
            correction.corrected_clock_out,
            correction.corrected_break_minutes,
            correction.corrected_total_minutes,
            correction.reason,
            correction.status,
            correction.created_by_employee_id,
            correction.created_by_name,
            correction.voided_by_employee_id,
            correction.voided_by_name,
            correction.voided_reason,
            correction.voided_at,
            correction.superseded_by,
            correction.created_at,
            correction.updated_at
        FROM payroll_shift_corrections correction
        WHERE correction.shift_id = ANY(%s)
        ORDER BY
            correction.shift_id,
            correction.week_start,
            correction.status,
            correction.id
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
            "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
            "sequenceVersion": int(row.get("sequence_version") or 1),
            "siteCheckInId": (
                int(row["site_check_in_id"])
                if row.get("site_check_in_id") is not None
                else None
            ),
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
            "visitId": (
                int(row["visit_id"])
                if row.get("visit_id") is not None
                else None
            ),
            "createdAt": to_utc_iso(row["created_at"]),
        })

    receipts_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for row in receipt_rows:
        if row.get("shift_id") is None:
            continue
        receipts_by_shift.setdefault(int(row["shift_id"]), []).append({
            "id": int(row["id"]),
            "employeeId": (
                int(row["employee_id"])
                if row.get("employee_id") is not None
                else None
            ),
            "locationId": (
                int(row["location_id"])
                if row.get("location_id") is not None
                else None
            ),
            "shiftId": int(row["shift_id"]),
            "action": str(row["action"]),
            "idempotencyKey": str(row["idempotency_key"]),
            "requestFingerprint": str(row["request_fingerprint"]),
            "serverRecordedAt": to_utc_iso(row["server_recorded_at"]),
            "deviceScannedAt": to_utc_iso(row["device_scanned_at"]),
            "latitude": float(row["latitude"]),
            "longitude": float(row["longitude"]),
            "accuracyM": float(row["accuracy_m"]),
            "geofenceRadiusM": int(row["geofence_radius_m"]),
            "distanceM": (
                float(row["distance_m"])
                if row.get("distance_m") is not None
                else None
            ),
            "geofenceStatus": str(row["geofence_status"]),
            "outcome": str(row["outcome"]),
            "siteCheckInId": (
                int(row["site_check_in_id"])
                if row.get("site_check_in_id") is not None
                else None
            ),
            "visitId": (
                int(row["visit_id"]) if row.get("visit_id") is not None else None
            ),
            "departureId": (
                int(row["departure_id"])
                if row.get("departure_id") is not None
                else None
            ),
            "missingDepartureVisitIds": [
                int(value)
                for value in (row.get("missing_departure_visit_ids") or [])
            ],
            "responseBody": row.get("response_body"),
            "createdAt": to_utc_iso(row["created_at"]),
        })

    payroll_corrections_by_shift: Dict[int, List[Dict[str, Any]]] = {}
    for row in payroll_shift_correction_rows:
        payroll_corrections_by_shift.setdefault(int(row["shift_id"]), []).append(
            {
                "correctionId": int(row["id"]),
                "weekStart": str(row["week_start"]),
                "date": str(row["correction_date"]),
                "employeeId": int(row["employee_id"]),
                "shiftId": int(row["shift_id"]),
                "sourceClockIn": to_utc_iso(row["source_clock_in"]),
                "sourceClockOut": (
                    to_utc_iso(row["source_clock_out"])
                    if row.get("source_clock_out")
                    else None
                ),
                "sourceBreakMinutes": row.get("source_break_minutes"),
                "sourceTotalMinutes": int(row["source_total_minutes"]),
                "correctedClockIn": to_utc_iso(row["corrected_clock_in"]),
                "correctedClockOut": to_utc_iso(row["corrected_clock_out"]),
                "correctedBreakMinutes": int(row["corrected_break_minutes"]),
                "correctedTotalMinutes": int(row["corrected_total_minutes"]),
                "reason": row["reason"],
                "status": row["status"],
                "createdByEmployeeId": (
                    int(row["created_by_employee_id"])
                    if row.get("created_by_employee_id") is not None
                    else None
                ),
                "createdByName": row["created_by_name"],
                "voidedByEmployeeId": (
                    int(row["voided_by_employee_id"])
                    if row.get("voided_by_employee_id") is not None
                    else None
                ),
                "voidedByName": row.get("voided_by_name"),
                "voidedReason": row.get("voided_reason"),
                "voidedAt": (
                    to_utc_iso(row["voided_at"])
                    if row.get("voided_at")
                    else None
                ),
                "supersededBy": (
                    int(row["superseded_by"])
                    if row.get("superseded_by") is not None
                    else None
                ),
                "createdAt": to_utc_iso(row["created_at"]),
                "updatedAt": to_utc_iso(row["updated_at"]),
            }
        )

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
            # The worked-rate snapshot is part of a shift's identity for
            # deduplication: two otherwise-identical shifts at different rates
            # are NOT interchangeable, and the archived before-image must retain
            # each shift's rate so a deletion never loses that evidence. It is
            # not in the signature exclusion set, so it participates in the
            # consistency check automatically.
            "hourlyRateCents": int(row["hourly_rate_cents"]) if row.get("hourly_rate_cents") is not None else None,
            "createdAt": to_utc_iso(row["created_at"]),
            "visits": visits_by_shift.get(shift_id, []),
            "departures": departures_by_shift.get(shift_id, []),
            "siteQrActionReceipts": receipts_by_shift.get(shift_id, []),
            "payrollShiftCorrections": payroll_corrections_by_shift.get(
                shift_id,
                [],
            ),
        })
    return snapshots


def _correction_metadata_signature(snapshot: Dict[str, Any]) -> str:
    comparable = {
        key: value
        for key, value in snapshot.items()
        if key not in {
            "id",
            "createdAt",
            "employeeName",
            "visits",
            "departures",
            "siteQrActionReceipts",
        }
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
    comparable["siteQrActionReceipts"] = [
        {
            key: value
            for key, value in row.items()
            if key
            not in {
                "id",
                "shiftId",
                "siteCheckInId",
                "visitId",
                "departureId",
                "createdAt",
            }
        }
        for row in snapshot.get("siteQrActionReceipts", [])
    ]
    return json.dumps(comparable, sort_keys=True, separators=(",", ":"))


def _correction_richness_score(snapshot: Dict[str, Any]) -> int:
    score = 10 * (len(snapshot.get("visits", [])) + len(snapshot.get("departures", [])))
    score += 5 * len(snapshot.get("siteQrActionReceipts", []))
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


def _migrate_duplicate_payroll_shift_corrections(
    cur: Any,
    duplicate_resolutions: List[Dict[str, Any]],
) -> List[int]:
    migrated_ids: List[int] = []
    for resolution in duplicate_resolutions:
        canonical_shift_id = int(resolution["canonicalShiftId"])
        duplicate_shift_ids = [
            int(value)
            for value in resolution.get("duplicateShiftIds", [])
        ]
        if not duplicate_shift_ids:
            continue

        cur.execute(
            """
            WITH duplicate_active AS (
                SELECT week_start, COUNT(*) AS active_count
                FROM payroll_shift_corrections
                WHERE shift_id = ANY(%s)
                  AND status = 'active'
                GROUP BY week_start
            )
            SELECT week_start
            FROM duplicate_active
            WHERE active_count > 1
            UNION
            SELECT duplicate_correction.week_start
            FROM payroll_shift_corrections duplicate_correction
            JOIN payroll_shift_corrections canonical_correction
              ON canonical_correction.week_start = duplicate_correction.week_start
             AND canonical_correction.shift_id = %s
             AND canonical_correction.status = 'active'
            WHERE duplicate_correction.shift_id = ANY(%s)
              AND duplicate_correction.status = 'active'
            LIMIT 1
            """,
            (duplicate_shift_ids, canonical_shift_id, duplicate_shift_ids),
        )
        if cur.fetchone():
            raise HTTPException(
                status_code=409,
                detail=(
                    "Duplicate shift payroll correction conflicts with the "
                    "canonical shift; resolve the payroll correction first"
                ),
            )

        cur.execute(
            """
            UPDATE payroll_shift_corrections
            SET shift_id = %s, updated_at = NOW()
            WHERE shift_id = ANY(%s)
            RETURNING id
            """,
            (canonical_shift_id, duplicate_shift_ids),
        )
        migrated_ids.extend(int(row["id"]) for row in cur.fetchall())
    return sorted(migrated_ids)


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
            cur.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (TIMESHEET_PG_ADVISORY_LOCK_ID,),
            )
            _lock_payroll_source_rows(cur)
            _lock_payroll_correction_write_tables(cur)
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

            migrated_payroll_shift_correction_ids = (
                _migrate_duplicate_payroll_shift_corrections(
                    cur,
                    plan["duplicateResolutions"],
                )
            )
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
                "migratedPayrollShiftCorrectionIds": (
                    migrated_payroll_shift_correction_ids
                ),
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


# A reservation pending right after an Atlas failure is normal and retryable:
# the operator sees it and the retry route exists for exactly that. One still
# pending an hour later means nobody came back for it, and the customer the
# operator thought they created does not exist anywhere.
#
# Measured from the last attempt, not from creation: a reservation someone
# retried a minute ago is being worked, however old it is. Creation time is
# still reported, as pendingSince, because that is how long the customer has
# actually been missing.
STALE_CUSTOMER_RESERVATION_MINUTES = 60

# ATLAS #2352: verify that a stored customers.atlas_contact_id still names a live
# EOM contact. The endpoint answers id-only and caps one request at 100 ids.
# _KNOWN_CONTACTS_PATH is defined beside _ATLAS_FUNNEL_READ_PATHS, which derives
# from it, so the path and its authorization cannot drift apart.
_KNOWN_CONTACTS_BATCH = 100


def _fetch_known_contacts(
    admin: Dict[str, Any],
    distinct_ids: List[str],
) -> Tuple[set, Dict[str, str], Dict[str, Any], Dict[str, Any]]:
    """Ask Atlas which of ``distinct_ids`` name a live EOM contact, and their type.

    Shared by the read-only link audit and the customer_type mirror refresh so
    the response-shape hardening below is written once. A second copy of this
    loop would be a second chance to get "malformed 200" wrong, and the two
    consumers fail in opposite directions -- the audit would flag every link as
    dangling, the refresh would blank every mirrored type.

    This answers TWO questions with TWO confidences, and they must not be
    conflated. "Which ids resolve" and "what type is each" can fail
    independently: a malformed or incomplete customerTypes map says nothing
    about whether knownContactIds is trustworthy, and the link audit consumes
    only the ids. Collapsing them into one status let a type-level problem
    suppress dangling-link detection the audit had everything it needed for.

    Returns ``(known, types, status, types_status)``:

    - ``known`` -- ids Atlas resolved. An id absent from this set is dangling.
    - ``types`` -- ``{contact_id: customer_type}``, containing ONLY ids Atlas
      actually reported a type for. An id present in ``known`` but missing here
      means Atlas is running a build older than ATLAS #2357, which does not
      report the field at all. That is not "Atlas says unknown" and callers must
      not treat it as a value; see _build_customer_type_refresh_plan.
    - ``status`` -- ID-level: ok / unconfigured / unavailable. Both consumers
      must respect it. Never report a clean result for a question that could
      not be asked.
    - ``types_status`` -- TYPE-level: ok / unavailable, for a malformed,
      incomplete, or deployment-straddling type map. Only the refresh respects
      it; the audit ignores it because it never reads ``types``.
    """
    ok = {"status": "ok", "checked": len(distinct_ids), "error": None}

    def _types_broken(error: str) -> Dict[str, Any]:
        return {"status": "unavailable", "checked": 0, "error": error}

    if not distinct_ids:
        return set(), {}, {"status": "ok", "checked": 0, "error": None}, ok
    if not (ATLAS_FUNNEL_BASE_URL and ATLAS_FUNNEL_SERVICE_TOKEN):
        unconfigured = {
            "status": "unconfigured",
            "checked": 0,
            "error": "Atlas funnel base URL or service token is not configured",
        }
        return set(), {}, unconfigured, unconfigured

    known = set()
    types: Dict[str, str] = {}
    # Version skew is a property of the whole fetch, not of one batch. Above 100
    # distinct ids this loop issues several requests, which can straddle an
    # Atlas deployment: an early batch omits customerTypes while a later one
    # reports it. Judging each batch alone would accept the omission as skew and
    # still apply the types the newer batches returned -- the partial refresh
    # this route exists to refuse. Track presence across every batch instead.
    batches_with_field = 0
    batches_total = 0
    types_fault: Optional[str] = None
    for start in range(0, len(distinct_ids), _KNOWN_CONTACTS_BATCH):
        batch = distinct_ids[start : start + _KNOWN_CONTACTS_BATCH]
        try:
            body = _atlas_funnel_read(
                _KNOWN_CONTACTS_PATH, admin, params={"contact_id": batch}
            )
        except HTTPException as exc:
            # Fail loud, not clean: a partial answer cannot certify the ids we
            # never reached, so the whole verdict is withheld and flagged.
            transport = {
                "status": "unavailable",
                "checked": 0,
                "error": (str(exc.detail) if exc.detail else f"HTTP {exc.status_code}"),
            }
            return set(), {}, transport, transport
        known_ids = body.get("knownContactIds")
        checked = body.get("checked")
        # `batch` is what WE asked for and is the only trustworthy reference.
        # Validating the response against its own knownContactIds is circular:
        # a malformed batch B could name batch A's id in both knownContactIds
        # and customerTypes, satisfy every self-consistency check, and retype
        # customer A. It is also an ID-level fault, not merely a type one --
        # an unrequested id landing in `known` can MASK a dangling link, since
        # the audit reports an id as dangling only when it is absent from that
        # set.
        requested = {str(value) for value in batch}
        if (
            not isinstance(known_ids, list)
            or not isinstance(checked, int)
            or isinstance(checked, bool)
            # Equality, not >=. ATLAS #2358 sets checked = len(requested) after
            # de-duplicating, and `batch` is already distinct, so the two must
            # match exactly. A HIGHER count means the server saw more ids than
            # we sent -- the request did not arrive as issued.
            or checked != len(batch)
            or not {str(value) for value in known_ids} <= requested
        ):
            # A 200 that omits knownContactIds or under-reports the count cannot
            # be trusted: treating a missing set as "known nothing" would flag
            # every id as dangling. Degrade to unavailable, never false-positive.
            malformed_ids = {
                "status": "unavailable",
                "checked": 0,
                "error": (
                    "Atlas known-contacts response was incomplete, malformed, "
                    "or named an id outside the requested batch"
                ),
            }
            return set(), {}, malformed_ids, malformed_ids
        for value in known_ids:
            known.add(str(value))
        # Absent and malformed are DIFFERENT answers and must not collapse.
        #
        # Absent is the supported version-skew case: an Atlas older than
        # ATLAS #2357 does not report the field, and the refresh must treat
        # that as "no information" and leave the mirror alone.
        #
        # Present-but-malformed is an upstream schema error. Dropping it
        # silently would look identical to version skew, so a broken Atlas
        # build would yield a confident partial refresh -- some batches
        # applied, the malformed ones quietly skipped -- with nothing
        # recording which. Degrade the whole read instead.
        batches_total += 1
        batch_known = {str(value) for value in known_ids}
        if "customerTypes" in body:
            batches_with_field += 1
            reported = body.get("customerTypes")
            # A type-level fault must NOT stop the loop. Every remaining batch
            # still has to be fetched or `known` ends up partial, and a partial
            # `known` makes the link audit report ids as dangling that were
            # simply never asked about. Record the fault and keep going.
            if not isinstance(reported, dict) or any(
                not isinstance(value, str) for value in reported.values()
            ):
                types_fault = (
                    "Atlas known-contacts response reported a malformed "
                    "customerTypes map"
                )
            elif {str(key) for key in reported} != batch_known:
                # EQUALITY, not coverage. ATLAS #2358 builds customerTypes from
                # exactly the ids it reports in knownContactIds, so anything
                # else is a malformed response.
                #
                # Missing keys would be a truncated map read as version skew --
                # skipping those contacts while applying the rest.
                #
                # EXTRA keys are worse. Matching them against the globally
                # accumulated `known` instead of this batch's ids let a later
                # response carry an entry for a contact resolved in an EARLIER
                # batch, silently overwriting that contact's type -- so a
                # malformed response for batch B could change a customer in
                # batch A, and the apply route would persist it.
                types_fault = (
                    "Atlas reported customerTypes whose ids do not match the "
                    "batch's knownContactIds"
                )
            else:
                for key, value in reported.items():
                    types[str(key)] = value

    if types_fault is None and 0 < batches_with_field < batches_total:
        # Some batches reported the field and some did not: the reads straddled
        # an Atlas deployment, so neither "version skew" nor "fully reported"
        # is true and any plan built from this evidence would be partial.
        types_fault = (
            "Atlas reported customerTypes for only some batches; the reads "
            "straddled a deployment"
        )

    if types_fault is not None:
        # The ids were validated independently and every batch was still
        # fetched, so `known` is complete and the link audit keeps working.
        # Only the type evidence is withheld.
        return known, {}, ok, _types_broken(types_fault)

    return known, types, ok, ok


def _verify_atlas_contact_links(
    admin: Dict[str, Any],
    linked_rows: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Reconcile linked customers against live Atlas contacts (read-only).

    A non-null atlas_contact_id only proves the tracker once wrote *something*;
    a bypass or a stale write can leave it pointing at a UUID Atlas never
    issued, and a NULL check can never see that. This asks Atlas which stored
    ids still name a live EOM contact and returns the customers whose link
    resolves to nothing. Being unable to ask -- Atlas unconfigured or
    unreachable -- is reported as a non-ok status, never as a clean result, so
    a consumer cannot mistake "could not verify" for "verified clean".

    Read-only, and deliberately kept that way: build_atlas_linkage_audit calls
    this, and an audit that mutates customer rows as a side effect would be a
    trap for anyone reading the call site. The mirror refresh that DOES write
    lives in _build_customer_type_refresh_plan and shares only the fetch.
    """
    # One id can be held by several customers (a duplicate); verify the distinct
    # id set once and fan the verdict back out to every customer that holds it.
    customers_by_contact: Dict[str, List[Dict[str, Any]]] = {}
    for row in linked_rows:
        customers_by_contact.setdefault(str(row["atlas_contact_id"]), []).append(row)
    distinct_ids = list(customers_by_contact)

    # The audit reads ids only, so it deliberately ignores types_status: a
    # malformed or straddled customerTypes map says nothing about whether
    # knownContactIds is trustworthy, and suppressing dangling-link detection
    # over it would withhold a verdict every batch supplied the data for.
    known, _types, status, _types_status = _fetch_known_contacts(admin, distinct_ids)
    if status["status"] != "ok":
        return [], status
    if not distinct_ids:
        return [], status

    dangling = [
        {
            "customerId": int(row["id"]),
            "customerName": row["name"],
            "atlasContactId": contact_id,
        }
        for contact_id in distinct_ids
        if contact_id not in known
        for row in customers_by_contact[contact_id]
    ]
    dangling.sort(key=lambda item: ((item["customerName"] or ""), item["customerId"]))
    return dangling, {"status": "ok", "checked": len(distinct_ids), "error": None}


def build_atlas_linkage_audit(
    admin: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Report Customer <-> Atlas contact linkage integrity without writes.

    When ``admin`` is supplied the audit also verifies every non-null
    ``atlas_contact_id`` against live Atlas contacts (ATLAS #2352) and reports
    ``danglingLinks`` -- links that resolve to no EOM contact. Without an actor
    that verification is skipped (the funnel read needs the actor headers), and
    an Atlas outage degrades that one signal rather than failing the audit.
    """
    duplicate_rows = db.query_all(
        """
        SELECT
            atlas_contact_id,
            ARRAY_AGG(id ORDER BY id) AS customer_ids,
            ARRAY_AGG(name ORDER BY id) AS customer_names,
            ARRAY_AGG(active ORDER BY id) AS active_flags,
            COUNT(*) AS copies
        FROM customers
        WHERE atlas_contact_id IS NOT NULL
        GROUP BY atlas_contact_id
        HAVING COUNT(*) > 1
        ORDER BY COUNT(*) DESC, atlas_contact_id::text
        """
    )
    unlinked_rows = db.query_all(
        """
        SELECT id, name, primary_contact_name, primary_phone, primary_email,
               active, created_at
        FROM customers
        WHERE atlas_contact_id IS NULL
        ORDER BY active DESC, name, id
        """
    )
    orphan_rows = db.query_all(
        """
        SELECT
            h.atlas_contact_id,
            h.customer_id,
            h.state,
            c.atlas_contact_id AS customer_atlas_contact_id,
            c.name AS customer_name
        FROM eom_office_conversion_handoffs h
        LEFT JOIN customers c ON c.id = h.customer_id
        WHERE c.id IS NULL
           OR c.atlas_contact_id IS NULL
           OR c.atlas_contact_id <> h.atlas_contact_id
        ORDER BY h.customer_id, h.atlas_contact_id
        """
    )
    linked_rows = db.query_all(
        """
        SELECT id, name, atlas_contact_id
        FROM customers
        WHERE atlas_contact_id IS NOT NULL
        ORDER BY name, id
        """
    )
    stale_reservation_rows = db.query_all(
        """
        SELECT id, mode, customer_id, payload ->> 'name' AS customer_name,
               last_error, created_at, updated_at
        FROM eom_customer_atlas_reservations
        WHERE state = 'pending'
          AND updated_at < NOW() - make_interval(mins => %s)
        ORDER BY updated_at, id
        """,
        (STALE_CUSTOMER_RESERVATION_MINUTES,),
    )

    duplicate_groups = [
        {
            "atlasContactId": str(row["atlas_contact_id"]),
            "customerIds": [int(value) for value in row.get("customer_ids") or []],
            "customerNames": list(row.get("customer_names") or []),
            "activeFlags": [bool(value) for value in row.get("active_flags") or []],
            "copies": int(row["copies"]),
        }
        for row in duplicate_rows
    ]
    unlinked_customers = [
        {
            "customerId": int(row["id"]),
            "customerName": row["name"],
            "primaryContactName": row.get("primary_contact_name"),
            "primaryPhone": row.get("primary_phone"),
            "primaryEmail": row.get("primary_email"),
            "active": bool(row["active"]),
            "createdAt": to_utc_iso(row["created_at"]) if row.get("created_at") else None,
        }
        for row in unlinked_rows
    ]
    stale_reservations = [
        {
            "reservationId": str(row["id"]),
            "mode": str(row["mode"]),
            "customerId": (
                int(row["customer_id"]) if row.get("customer_id") is not None else None
            ),
            "customerName": row.get("customer_name"),
            "lastError": row.get("last_error"),
            # Two different questions, so two different timestamps. How long the
            # customer has been missing is created_at, which never moves; a
            # failed retry advances updated_at, so reporting that as
            # "pendingSince" understates a reservation that has been stuck for
            # hours but was retried a minute ago.
            "pendingSince": to_utc_iso(row["created_at"]) if row.get("created_at") else None,
            # Deliberately "updatedAt" and not "lastAttemptAt": updated_at
            # defaults to NOW() at insert and the reservation is committed
            # before Atlas is called, so a row that never got an attempt still
            # carries a value here. It is the last time the row was touched --
            # which is what the staleness cutoff measures from -- and claiming
            # more than that would invent an attempt that never happened.
            "updatedAt": (
                to_utc_iso(row["updated_at"]) if row.get("updated_at") else None
            ),
        }
        for row in stale_reservation_rows
    ]
    handoff_orphans = [
        {
            "atlasContactId": str(row["atlas_contact_id"]),
            "customerId": int(row["customer_id"]),
            "handoffState": row["state"],
            "customerName": row.get("customer_name"),
            "customerAtlasContactId": (
                str(row["customer_atlas_contact_id"])
                if row.get("customer_atlas_contact_id")
                else None
            ),
        }
        for row in orphan_rows
    ]
    mapping_template = [
        {
            "customerId": row["customerId"],
            "customerName": row["customerName"],
            "atlasContactId": None,
        }
        for row in unlinked_customers
        if row["active"]
    ]
    # Verify stored links against live Atlas contacts when we have an actor to
    # authenticate the funnel read; skip (not fail) otherwise. An Atlas outage
    # degrades this one signal to a non-ok status instead of failing the audit.
    if admin is not None:
        dangling_links, atlas_link_verification = _verify_atlas_contact_links(
            admin, linked_rows
        )
    else:
        dangling_links = []
        atlas_link_verification = {"status": "skipped", "checked": 0, "error": None}

    # Every defect class the audit reports, not just the ones it started with:
    # a poller treating this as a change token would otherwise see an unchanged
    # fingerprint at the moment a reservation crosses the staleness cutoff, and
    # miss the one signal that says a customer exists in neither database. The
    # verification status is in the material too: a shift from "ok" to
    # "unavailable" means danglingLinks can no longer be trusted, which a
    # change-token consumer must not sleep through.
    fingerprint_material = json.dumps(
        {
            "duplicateGroups": duplicate_groups,
            "unlinkedCustomers": unlinked_customers,
            "handoffOrphans": handoff_orphans,
            "staleReservations": stale_reservations,
            "danglingLinks": dangling_links,
            "atlasLinkVerificationStatus": atlas_link_verification["status"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "success": True,
        "databaseReadOnly": True,
        "generatedAt": to_utc_iso(utc_now()),
        "inventoryFingerprint": hashlib.sha256(
            fingerprint_material.encode("utf-8")
        ).hexdigest(),
        "summary": {
            "duplicateGroups": len(duplicate_groups),
            "duplicateExtraCustomers": sum(
                group["copies"] - 1 for group in duplicate_groups
            ),
            "unlinkedCustomers": len(unlinked_customers),
            "unlinkedActiveCustomers": len(mapping_template),
            "linkedCustomers": len(linked_rows),
            "handoffOrphans": len(handoff_orphans),
            "staleReservations": len(stale_reservations),
            "danglingLinks": len(dangling_links),
        },
        "duplicateGroups": duplicate_groups,
        "unlinkedCustomers": unlinked_customers,
        "handoffOrphans": handoff_orphans,
        "staleReservations": stale_reservations,
        "danglingLinks": dangling_links,
        "atlasLinkVerification": atlas_link_verification,
        "mappingTemplate": mapping_template,
    }


def _build_atlas_linkage_backfill_plan(
    payload: AtlasLinkageBackfillPlanRequest,
    cursor: Any = None,
    lock_rows: bool = False,
) -> Dict[str, Any]:
    reason = payload.reason.strip()
    if len(reason) < 10:
        raise HTTPException(
            status_code=400,
            detail="Backfill reason must be at least 10 characters",
        )

    customer_ids = [int(entry.customerId) for entry in payload.mappings]
    if len(customer_ids) != len(set(customer_ids)):
        raise HTTPException(
            status_code=400,
            detail="Each customer may appear only once in the mapping",
        )
    contact_ids = [str(entry.atlasContactId) for entry in payload.mappings]
    if len(contact_ids) != len(set(contact_ids)):
        raise HTTPException(
            status_code=400,
            detail="Each Atlas contact may appear only once in the mapping",
        )
    mapping_by_contact = {
        str(entry.atlasContactId): int(entry.customerId)
        for entry in payload.mappings
    }

    def _rows(sql: str, params: tuple) -> List[Dict[str, Any]]:
        if cursor is not None:
            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        return db.query_all(sql, params)

    lock_clause = " FOR UPDATE" if lock_rows else ""
    customer_rows = _rows(
        "SELECT id, name, active, atlas_contact_id FROM customers "
        "WHERE id = ANY(%s) ORDER BY id" + lock_clause,
        (sorted(customer_ids),),
    )
    by_id = {int(row["id"]): row for row in customer_rows}
    missing = sorted(set(customer_ids) - set(by_id))
    if missing:
        raise HTTPException(
            status_code=409,
            detail=f"Customer(s) {missing} no longer exist; reload the linkage audit",
        )
    for customer_id in customer_ids:
        row = by_id[customer_id]
        if row["atlas_contact_id"] is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Customer {customer_id} already carries an Atlas contact "
                    "link; reload the linkage audit"
                ),
            )
        if not row["active"]:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Customer {customer_id} is archived; only active "
                    "Customers can be backfilled"
                ),
            )

    conflict_rows = _rows(
        "SELECT id, atlas_contact_id FROM customers "
        "WHERE atlas_contact_id = ANY(%s::uuid[])",
        (contact_ids,),
    )
    if conflict_rows:
        held = sorted(
            {
                f"{row['atlas_contact_id']} (customer {int(row['id'])})"
                for row in conflict_rows
            }
        )
        raise HTTPException(
            status_code=409,
            detail=(
                "Atlas contact(s) already linked to existing Customers: "
                + "; ".join(held)
            ),
        )

    handoff_rows = _rows(
        "SELECT atlas_contact_id, customer_id FROM eom_office_conversion_handoffs "
        "WHERE atlas_contact_id = ANY(%s::uuid[])",
        (contact_ids,),
    )
    reserved = sorted(
        str(row["atlas_contact_id"])
        for row in handoff_rows
        if mapping_by_contact.get(str(row["atlas_contact_id"]))
        != int(row["customer_id"])
    )
    if reserved:
        raise HTTPException(
            status_code=409,
            detail=(
                "Atlas contact(s) already reserved by an office conversion "
                "for a different Customer: " + ", ".join(reserved)
            ),
        )

    normalized = sorted(
        (
            {
                "customerId": int(entry.customerId),
                "customerName": by_id[int(entry.customerId)]["name"],
                "atlasContactId": str(entry.atlasContactId),
            }
            for entry in payload.mappings
        ),
        key=lambda row: row["customerId"],
    )
    snapshot = {
        "reason": reason,
        "mappings": normalized,
        "customersBefore": [
            {
                "id": int(row["id"]),
                "name": row["name"],
                "active": bool(row["active"]),
                "atlasContactId": None,
            }
            for row in sorted(customer_rows, key=lambda row: int(row["id"]))
        ],
    }
    token_material = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    plan_token = hmac.new(
        JWT_SECRET.encode("utf-8"),
        token_material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    count = len(normalized)
    label = "CUSTOMER" if count == 1 else "CUSTOMERS"
    return {
        "success": True,
        "databaseReadOnly": True,
        "planToken": plan_token,
        "confirmationPhrase": f"LINK {count} {label} TO ATLAS CONTACTS",
        "summary": {"customersToLink": count},
        "mappings": normalized,
        "_archiveSnapshot": snapshot,
    }


def _build_customer_type_refresh_plan(
    admin: Dict[str, Any],
    *,
    cursor: Any = None,
    lock_rows: bool = False,
) -> Dict[str, Any]:
    """Plan a refresh of the customer_type mirror from Atlas (ATLAS #2357).

    The mirror is otherwise populate-on-write-path only: it fills in from the
    one Atlas call that returns a contact, so office estimate approval, the
    bulk linkage backfill, and any type changed in Atlas after the local row
    exists all leave it stranded. Two of those three make no Atlas call that
    could carry the value, so the correction has to be a read over every linked
    customer rather than a hook on any one path.

    Atlas is the write authority; the tracker never originates a type. This
    only copies, and only when Atlas actually stated a value.
    """
    linked_rows = _read_linked_customers(cursor=cursor, lock_rows=lock_rows)
    known, types, status, types_status = _fetch_known_contacts(
        admin, _distinct_contact_ids(linked_rows)
    )
    # The refresh reads types, so unlike the audit it must respect BOTH.
    if status["status"] == "ok" and types_status["status"] != "ok":
        status = types_status
    if status["status"] != "ok":
        # Refuse the whole plan rather than refreshing the subset we happened to
        # reach: a partial refresh is indistinguishable from a complete one once
        # it is applied, and nothing records which rows were never asked about.
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot refresh customer types: Atlas link verification is "
                f"{status['status']} ({status['error']})"
            ),
        )
    return _compute_customer_type_refresh_plan(linked_rows, known, types)


def _read_linked_customers(
    *,
    cursor: Any = None,
    lock_rows: bool = False,
) -> List[Dict[str, Any]]:
    sql = (
        "SELECT id, name, atlas_contact_id, customer_type FROM customers "
        "WHERE atlas_contact_id IS NOT NULL ORDER BY id"
    )
    if cursor is not None:
        cursor.execute(sql + (" FOR UPDATE" if lock_rows else ""))
        return list(cursor.fetchall())
    return db.query_all(sql)


def _distinct_contact_ids(linked_rows: List[Dict[str, Any]]) -> List[str]:
    seen: Dict[str, None] = {}
    for row in linked_rows:
        seen.setdefault(str(row["atlas_contact_id"]), None)
    return list(seen)


def _compute_customer_type_refresh_plan(
    linked_rows: List[Dict[str, Any]],
    known: set,
    types: Dict[str, str],
) -> Dict[str, Any]:
    """Derive the plan from already-fetched evidence. Pure: no I/O, no lock.

    Split out so the apply path can do its Atlas reads BEFORE taking the global
    customer/site mutation lock. Holding that lock across one HTTP call per 100
    contact ids would stall every ordinary customer edit for the duration.
    """
    by_contact: Dict[str, List[Dict[str, Any]]] = {}
    for row in linked_rows:
        by_contact.setdefault(str(row["atlas_contact_id"]), []).append(row)
    distinct_ids = list(by_contact)

    changes = []
    skipped_dangling = 0
    skipped_unreported = 0
    for contact_id in distinct_ids:
        if contact_id not in known:
            # The link does not resolve. That is a linkage defect, reported by
            # the linkage audit's danglingLinks signal; it says nothing about
            # classification, so the mirrored type is left exactly as it is.
            skipped_dangling += len(by_contact[contact_id])
            continue
        if contact_id not in types:
            # Atlas resolved the id but reported no type for it, which means it
            # predates ATLAS #2357. Absent is NOT "unknown": treating it as a
            # value would blank every mirrored type the first time this runs
            # against an Atlas that has not been deployed yet.
            skipped_unreported += len(by_contact[contact_id])
            continue
        reported = types[contact_id]
        if reported not in CUSTOMER_TYPES:
            # Refuse a value the local CHECK constraint would reject anyway,
            # rather than letting the UPDATE fail mid-batch.
            raise HTTPException(
                status_code=502,
                detail=(
                    f"Atlas reported an unsupported customer_type {reported!r} "
                    f"for contact {contact_id}"
                ),
            )
        for row in by_contact[contact_id]:
            current = row["customer_type"]
            if current == reported:
                continue
            changes.append(
                {
                    "customerId": int(row["id"]),
                    "customerName": row["name"],
                    "atlasContactId": contact_id,
                    "from": current,
                    "to": reported,
                }
            )

    changes.sort(key=lambda item: item["customerId"])
    snapshot = {
        "reason": None,
        "changes": changes,
        "linkedCustomers": len(linked_rows),
    }
    token_material = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    plan_token = hmac.new(
        JWT_SECRET.encode("utf-8"),
        token_material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    count = len(changes)
    label = "CUSTOMER" if count == 1 else "CUSTOMERS"
    return {
        "success": True,
        "databaseReadOnly": True,
        "planToken": plan_token,
        "confirmationPhrase": f"REFRESH {count} {label} FROM ATLAS",
        "summary": {
            "customersToUpdate": count,
            "linkedCustomers": len(linked_rows),
            "skippedDanglingLinks": skipped_dangling,
            "skippedTypeNotReported": skipped_unreported,
        },
        "changes": changes,
        "_archiveSnapshot": snapshot,
    }


@app.get("/api/admin/audits/atlas-linkage")
def admin_atlas_linkage_audit(
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = build_atlas_linkage_audit(admin)
    append_access_log(
        request,
        "ATLAS_LINKAGE_AUDIT",
        True,
        "duplicates={duplicateGroups} unlinked={unlinkedCustomers} "
        "orphans={handoffOrphans} dangling={danglingLinks}".format(**result["summary"])
        # Record the verification status so a "dangling=0" from an outage or an
        # unconfigured funnel is never mistaken for a verified-clean audit.
        + " atlasVerify=" + result["atlasLinkVerification"]["status"],
    )
    return result


@app.post("/api/admin/corrections/atlas-linkage/preview")
def admin_atlas_linkage_backfill_preview(
    payload: AtlasLinkageBackfillPlanRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = _build_atlas_linkage_backfill_plan(payload)
    result.pop("_archiveSnapshot", None)
    append_access_log(
        request,
        "ATLAS_LINKAGE_BACKFILL_PLAN",
        True,
        "link={customersToLink}".format(**result["summary"]),
    )
    return result


@app.post("/api/admin/corrections/atlas-linkage/apply")
def admin_apply_atlas_linkage_backfill(
    payload: AtlasLinkageBackfillApplyRequest,
    request: Request,
    current_admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            plan = _build_atlas_linkage_backfill_plan(
                payload, cursor=cur, lock_rows=True
            )
            if not hmac.compare_digest(payload.planToken, plan["planToken"]):
                raise HTTPException(
                    status_code=409,
                    detail="Backfill plan is stale or does not match; preview it again",
                )
            if payload.confirmation != plan["confirmationPhrase"]:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Type the exact confirmation phrase: "
                        f"{plan['confirmationPhrase']}"
                    ),
                )

            cur.execute(
                """
                INSERT INTO atlas_linkage_backfill_batches (
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

            linked_ids = []
            for row in plan["mappings"]:
                cur.execute(
                    """
                    UPDATE customers
                    SET atlas_contact_id = %s, updated_at = NOW()
                    WHERE id = %s AND atlas_contact_id IS NULL
                    RETURNING id
                    """,
                    (row["atlasContactId"], row["customerId"]),
                )
                updated = cur.fetchone()
                if not updated:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"Customer {row['customerId']} changed before the "
                            "backfill could be applied"
                        ),
                    )
                linked_ids.append(int(updated["id"]))

            result = {"linkedCustomerIds": sorted(linked_ids)}
            cur.execute(
                "UPDATE atlas_linkage_backfill_batches SET result = %s::jsonb WHERE id = %s",
                (json.dumps(result, sort_keys=True), batch_id),
            )

    append_access_log(
        request,
        "ATLAS_LINKAGE_BACKFILL_APPLIED",
        True,
        f"batch={batch_id} linked={len(linked_ids)}",
    )
    return {
        "success": True,
        "batchId": batch_id,
        "archiveStored": True,
        **result,
    }


@app.post("/api/admin/corrections/customer-type/preview")
def admin_customer_type_refresh_preview(
    payload: CustomerTypeRefreshPlanRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    result = _build_customer_type_refresh_plan(admin)
    result.pop("_archiveSnapshot", None)
    append_access_log(
        request,
        "CUSTOMER_TYPE_REFRESH_PLAN",
        True,
        "update={customersToUpdate} linked={linkedCustomers} "
        "skipDangling={skippedDanglingLinks} "
        "skipUnreported={skippedTypeNotReported}".format(**result["summary"]),
    )
    return result


@app.post("/api/admin/corrections/customer-type/apply")
def admin_apply_customer_type_refresh(
    payload: CustomerTypeRefreshApplyRequest,
    request: Request,
    current_admin: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    # Atlas I/O happens BEFORE the global customer/site mutation lock is taken.
    # Rebuilding under the lock would hold it across one HTTP request per 100
    # contact ids -- each able to burn the full 10s timeout -- while every
    # ordinary customer edit queues behind it.
    unlocked_rows = _read_linked_customers()
    asked_ids = _distinct_contact_ids(unlocked_rows)
    known, types, status, types_status = _fetch_known_contacts(
        current_admin, asked_ids
    )
    if status["status"] == "ok" and types_status["status"] != "ok":
        status = types_status
    if status["status"] != "ok":
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot refresh customer types: Atlas link verification is "
                f"{status['status']} ({status['error']})"
            ),
        )

    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_customer_site_mutations(cur)
            # Re-read under the lock and recompute from it, so the token is
            # still checked against the state actually being written rather
            # than the one the operator previewed.
            locked_rows = _read_linked_customers(cursor=cur, lock_rows=True)
            unasked = set(_distinct_contact_ids(locked_rows)) - set(asked_ids)
            if unasked:
                # A customer was linked to a contact we never asked Atlas about,
                # so this plan cannot speak for the current row set. Refuse
                # rather than apply a verdict built from incomplete evidence.
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Linked customers changed while planning; preview again"
                    ),
                )
            plan = _compute_customer_type_refresh_plan(locked_rows, known, types)
            if not plan["changes"]:
                # Nothing to do. Returning early also avoids writing a batch row
                # whose plan_token -- derived from an empty change list and the
                # linked count -- would collide with the previous no-op apply on
                # the UNIQUE constraint and surface as a raw database error.
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "No customer types need refreshing; nothing was applied"
                    ),
                )
            if not hmac.compare_digest(payload.planToken, plan["planToken"]):
                raise HTTPException(
                    status_code=409,
                    detail="Refresh plan is stale or does not match; preview it again",
                )
            if payload.confirmation != plan["confirmationPhrase"]:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Type the exact confirmation phrase: "
                        f"{plan['confirmationPhrase']}"
                    ),
                )

            snapshot = dict(plan["_archiveSnapshot"])
            snapshot["reason"] = payload.reason.strip()
            cur.execute(
                """
                INSERT INTO customer_type_refresh_batches (
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
                    json.dumps(snapshot, sort_keys=True),
                ),
            )
            batch_id = int(cur.fetchone()["id"])

            updated_ids = []
            for row in plan["changes"]:
                # Guarded on the value the plan was built from, so a row that
                # moved between planning and writing fails loudly instead of
                # being silently overwritten.
                cur.execute(
                    """
                    UPDATE customers
                    SET customer_type = %s, updated_at = NOW()
                    WHERE id = %s AND customer_type IS NOT DISTINCT FROM %s
                    RETURNING id
                    """,
                    (row["to"], row["customerId"], row["from"]),
                )
                updated = cur.fetchone()
                if not updated:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"Customer {row['customerId']} changed before the "
                            "refresh could be applied"
                        ),
                    )
                updated_ids.append(int(updated["id"]))

            result = {"updatedCustomerIds": sorted(updated_ids)}
            cur.execute(
                "UPDATE customer_type_refresh_batches SET result = %s::jsonb "
                "WHERE id = %s",
                (json.dumps(result, sort_keys=True), batch_id),
            )

    append_access_log(
        request,
        "CUSTOMER_TYPE_REFRESH_APPLIED",
        True,
        f"batch={batch_id} updated={len(updated_ids)}",
    )
    return {
        "success": True,
        "batchId": batch_id,
        "archiveStored": True,
        **result,
    }


def _read_access_logs_file_for_date(date_text: str) -> List[Dict[str, Any]]:
    log_file = LOGS_DIR / f"access_{date_text}.json"
    payload = read_json_file(log_file, [])
    if not isinstance(payload, list):
        return []
    return [entry for entry in payload if isinstance(entry, dict)]


def _read_access_logs_postgres_for_date(log_date: date) -> List[Dict[str, Any]]:
    rows = db.query_all(
        """
        SELECT entry
        FROM access_log_entries
        WHERE local_date = %s
        ORDER BY logged_at ASC, id ASC
        """,
        (log_date,),
    )
    logs: List[Dict[str, Any]] = []
    for row in rows:
        entry = row.get("entry")
        if isinstance(entry, dict):
            logs.append(entry)
    return logs


def _dedupe_access_logs(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        event_id = str(entry.get("eventId") or "").strip()
        if event_id:
            key = f"event:{event_id}"
            if key in seen:
                continue
            seen.add(key)
        deduped.append(entry)

    return sorted(deduped, key=lambda item: str(item.get("timestamp", "")))


def _public_access_log_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    public_entry = dict(entry)
    public_entry.pop("eventId", None)
    return public_entry


def read_access_logs_for_date(date_text: str) -> List[Dict[str, Any]]:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text):
        return []

    try:
        log_date = date.fromisoformat(date_text)
    except ValueError:
        return []

    postgres_logs: Optional[List[Dict[str, Any]]] = None
    try:
        postgres_logs = _read_access_logs_postgres_for_date(log_date)
    except Exception:
        logger.warning("access_log_postgres_read_failed", exc_info=True)

    file_logs: Optional[List[Dict[str, Any]]] = None
    try:
        file_logs = _read_access_logs_file_for_date(date_text)
    except Exception:
        logger.warning("access_log_file_read_failed", exc_info=True)

    if postgres_logs is None:
        if file_logs is None:
            return []
        return [_public_access_log_entry(entry) for entry in file_logs]
    if not postgres_logs:
        if file_logs is None:
            return []
        return [_public_access_log_entry(entry) for entry in file_logs]
    if not file_logs:
        return [_public_access_log_entry(entry) for entry in postgres_logs]
    return [
        _public_access_log_entry(entry)
        for entry in _dedupe_access_logs([*file_logs, *postgres_logs])
    ]


@app.get("/api/admin/logs/{date_text}")
def admin_logs_by_date(
    date_text: str,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    return {"success": True, "date": date_text, "logs": read_access_logs_for_date(date_text)}


def _parse_payroll_week_start(week_start: Optional[str]) -> date:
    if week_start:
        try:
            parsed = datetime.strptime(week_start, "%Y-%m-%d").date()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid weekStart format, use YYYY-MM-DD") from exc
    else:
        local_today = to_local(utc_now()).date()
        parsed = local_today - timedelta(days=(local_today.weekday() + 1) % 7)

    if parsed.weekday() != 6:
        raise HTTPException(status_code=400, detail="weekStart must be a Sunday")
    return parsed


def _payroll_week_bounds(week_start: date) -> Tuple[date, datetime, datetime]:
    week_end = week_start + timedelta(days=6)
    start_local = datetime.combine(week_start, clock_time.min, tzinfo=APP_TIMEZONE)
    end_local_exclusive = datetime.combine(
        week_start + timedelta(days=7),
        clock_time.min,
        tzinfo=APP_TIMEZONE,
    )
    return (
        week_end,
        start_local.astimezone(timezone.utc),
        end_local_exclusive.astimezone(timezone.utc),
    )


def _empty_payroll_day(day: date) -> Dict[str, Any]:
    return {
        "date": day.isoformat(),
        "totalMinutes": 0,
        "totalHours": 0.0,
        "completedShiftCount": 0,
        "issueCodes": [],
    }


def _empty_payroll_employee(row: Dict[str, Any], week_start: date) -> Dict[str, Any]:
    return {
        "employeeId": int(row["id"]),
        "employeeName": str(row["name"]),
        "active": bool(row["active"]),
        "totalMinutes": 0,
        "totalHours": 0.0,
        "completedShiftCount": 0,
        "overlappingShiftCount": 0,
        "correctionCount": 0,
        "issueCodes": [],
        "issues": [],
        "days": [
            _empty_payroll_day(week_start + timedelta(days=offset))
            for offset in range(7)
        ],
    }


def _payroll_day_map(employee_row: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {str(day["date"]): day for day in employee_row["days"]}


def _add_payroll_issue(
    employee_row: Dict[str, Any],
    code: str,
    shift_row: Dict[str, Any],
    message: str,
    issue_at_utc: datetime,
) -> None:
    issue_date = to_local(issue_at_utc).date().isoformat()
    source_kind = str(shift_row.get("payroll_source_kind") or "recorded")
    shift_id = int(shift_row["id"]) if source_kind == "recorded" else None
    manual_shift_id = (
        str(shift_row["manual_shift_id"])
        if source_kind == "manual" and shift_row.get("manual_shift_id") is not None
        else None
    )
    employee_row["issues"].append(
        {
            "code": code,
            "rowId": (
                f"manual:{manual_shift_id}"
                if manual_shift_id is not None
                else f"recorded:{shift_id}"
            ),
            "sourceKind": source_kind,
            "shiftId": shift_id,
            "manualShiftId": manual_shift_id,
            "date": issue_date,
            "message": message,
        }
    )
    if code not in employee_row["issueCodes"]:
        employee_row["issueCodes"].append(code)

    day = _payroll_day_map(employee_row).get(issue_date)
    if day is not None and code not in day["issueCodes"]:
        day["issueCodes"].append(code)


def _iter_payroll_local_day_slices(
    start_utc: datetime,
    end_utc: datetime,
) -> List[Tuple[date, float]]:
    slices: List[Tuple[date, float]] = []
    cursor = start_utc
    while cursor < end_utc:
        local_cursor = to_local(cursor)
        local_day = local_cursor.date()
        next_local_midnight = datetime.combine(
            local_day + timedelta(days=1),
            clock_time.min,
            tzinfo=APP_TIMEZONE,
        )
        next_cursor = min(end_utc, next_local_midnight.astimezone(timezone.utc))
        if next_cursor <= cursor:
            break
        seconds = max(0.0, (next_cursor - cursor).total_seconds())
        if seconds > 0:
            slices.append((local_day, seconds))
        cursor = next_cursor
    return slices


def _allocate_payroll_shift_minutes(
    day_slices: List[Tuple[date, float]],
) -> List[Tuple[date, int]]:
    total_minutes = int((sum(seconds for _, seconds in day_slices) + 30) // 60)
    base_allocations = [
        {
            "index": index,
            "day": local_day,
            "minutes": int(seconds // 60),
            "remainder": seconds % 60,
        }
        for index, (local_day, seconds) in enumerate(day_slices)
    ]
    allocated_minutes = sum(int(item["minutes"]) for item in base_allocations)
    remaining_minutes = total_minutes - allocated_minutes
    if remaining_minutes > 0:
        by_remainder = sorted(
            base_allocations,
            key=lambda item: (-float(item["remainder"]), int(item["index"])),
        )
        for item in by_remainder[:remaining_minutes]:
            item["minutes"] = int(item["minutes"]) + 1
    base_allocations.sort(key=lambda item: int(item["index"]))
    return [
        (item["day"], int(item["minutes"]))
        for item in base_allocations
    ]


def _payroll_source_fingerprint(
    *,
    week_start: date,
    week_end: date,
    employees: List[Dict[str, Any]],
    shifts: List[Dict[str, Any]],
    corrections: Optional[List[Dict[str, Any]]] = None,
    shift_corrections: Optional[List[Dict[str, Any]]] = None,
    blocking_issues: Optional[List[Dict[str, Any]]] = None,
) -> str:
    payload = {
        "timezone": TIMEZONE_NAME,
        "weekStart": week_start.isoformat(),
        "weekEnd": week_end.isoformat(),
        "employees": [
            {
                "id": int(row["id"]),
                "name": str(row["name"]),
                "active": bool(row["active"]),
            }
            for row in employees
        ],
        "shifts": [
            {
                "id": int(row["id"]),
                "employee_id": int(row["employee_id"]),
                "clock_in": to_utc_iso(row["clock_in"]),
                "clock_out": to_utc_iso(row["clock_out"]) if row.get("clock_out") else None,
                **(
                    {
                        "source_kind": "manual",
                        "manual_shift_id": str(row["manual_shift_id"]),
                    }
                    if row.get("payroll_source_kind") == "manual"
                    and row.get("manual_shift_id") is not None
                    else {}
                ),
            }
            for row in shifts
        ],
    }
    if corrections:
        payload["corrections"] = [
            {
                "id": int(row["id"]),
                "employee_id": int(row["employee_id"]),
                "correction_date": row["correction_date"].isoformat(),
                "corrected_total_minutes": int(row["corrected_total_minutes"]),
                "reason": str(row["reason"]),
                "created_at": to_utc_iso(row["created_at"]),
            }
            for row in corrections
        ]
    if shift_corrections:
        payload["shiftCorrections"] = [
            {
                "id": int(row["id"]),
                "employee_id": int(row["employee_id"]),
                "shift_id": int(row["shift_id"]),
                "correction_date": row["correction_date"].isoformat(),
                "corrected_clock_in": to_utc_iso(row["corrected_clock_in"]),
                "corrected_clock_out": to_utc_iso(row["corrected_clock_out"]),
                "corrected_break_minutes": int(row["corrected_break_minutes"]),
                "corrected_total_minutes": int(row["corrected_total_minutes"]),
                "reason": str(row["reason"]),
                "created_at": to_utc_iso(row["created_at"]),
            }
            for row in shift_corrections
        ]
    if blocking_issues:
        # Conditional like the keys above: a week without blocking issues
        # hashes exactly as before, so stored verification proofs for clean
        # weeks stay valid. A week whose recomputation now carries blocking
        # issues (e.g. a rule such as overlapping_shift added after the
        # proof was stored) diverges, so its proof correctly reads stale.
        payload["blockingIssues"] = blocking_issues
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payroll_query_all(
    sql: str,
    params: tuple = (),
    *,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    if cursor is None:
        return db.query_all(sql, params)
    cursor.execute(sql, params)
    return [dict(row) for row in cursor.fetchall()]


def _payroll_overlapping_shift_rows(
    week_start_utc: datetime,
    week_end_utc: datetime,
    now_utc: datetime,
    *,
    cursor: Optional[Any] = None,
    employee_id: Optional[int] = None,
    include_timesheet_overlays: bool = True,
) -> List[Dict[str, Any]]:
    rows = _payroll_query_all(
        """
        SELECT
            shift_row.id,
            shift_row.employee_id,
            shift_row.clock_in,
            shift_row.clock_out,
            shift_row.total_hours,
            shift_row.hourly_rate_cents,
            shift_row.local_date,
            shift_row.timezone,
            shift_row.location_id,
            shift_row.location_label,
            shift_row.job_id,
            shift_row.time_category,
            shift_row.non_productive_type,
            shift_row.notes,
            location.address AS location_address,
            location.customer_name AS location_customer_name,
            customer.name AS customer_name
        FROM shifts shift_row
        LEFT JOIN locations location ON location.id = shift_row.location_id
        LEFT JOIN customers customer ON customer.id = location.customer_id
        WHERE shift_row.clock_in < %s
          AND (
              (shift_row.clock_out IS NULL AND shift_row.clock_in < %s AND %s > %s)
              OR (
                  shift_row.clock_out IS NOT NULL
                  AND (
                      shift_row.clock_out > %s
                      OR (shift_row.clock_in >= %s AND shift_row.clock_in < %s)
                  )
              )
          )
          AND (%s::integer IS NULL OR shift_row.employee_id = %s)
        ORDER BY shift_row.employee_id, shift_row.clock_in, shift_row.id
        """,
        (
            week_end_utc,
            now_utc,
            now_utc,
            week_start_utc,
            week_start_utc,
            week_start_utc,
            week_end_utc,
            employee_id,
            employee_id,
        ),
        cursor=cursor,
    )
    for row in rows:
        row["payroll_source_kind"] = "recorded"

    if not include_timesheet_overlays:
        return rows

    week_start = week_start_utc.astimezone(APP_TIMEZONE).date()
    exclusions = _payroll_query_all(
        """
        SELECT shift_id
        FROM payroll_shift_exclusions
        WHERE week_start = %s
          AND status = 'active'
          AND (%s::integer IS NULL OR employee_id = %s)
        """,
        (week_start, employee_id, employee_id),
        cursor=cursor,
    )
    excluded_shift_ids = {int(row["shift_id"]) for row in exclusions}
    rows = [row for row in rows if int(row["id"]) not in excluded_shift_ids]

    manual_rows = _payroll_query_all(
        """
        SELECT
            manual.id AS manual_shift_version_id,
            manual.manual_shift_id,
            manual.version AS manual_shift_version,
            manual.employee_id,
            manual.clock_in,
            manual.clock_out,
            manual.total_minutes,
            manual.work_date AS local_date,
            manual.location_id,
            manual.break_minutes,
            manual.reason AS manual_shift_reason,
            manual.created_by_name AS manual_shift_created_by_name,
            manual.created_at AS manual_shift_created_at,
            location.address AS location_address,
            location.customer_name AS location_customer_name,
            customer.name AS customer_name
        FROM payroll_manual_shift_versions manual
        LEFT JOIN locations location ON location.id = manual.location_id
        LEFT JOIN customers customer ON customer.id = location.customer_id
        WHERE manual.week_start = %s
          AND manual.status = 'current'
          AND manual.included = TRUE
          AND manual.clock_in < %s
          AND manual.clock_out > %s
          AND (%s::integer IS NULL OR manual.employee_id = %s)
        ORDER BY manual.employee_id, manual.clock_in, manual.id
        """,
        (week_start, week_end_utc, week_start_utc, employee_id, employee_id),
        cursor=cursor,
    )
    for manual in manual_rows:
        version_id = int(manual["manual_shift_version_id"])
        rows.append(
            {
                **manual,
                "id": -version_id,
                "total_hours": round(int(manual["total_minutes"]) / 60, 2),
                "timezone": TIMEZONE_NAME,
                "location_label": manual.get("location_address") or "",
                "job_id": None,
                "time_category": "productive",
                "non_productive_type": None,
                "notes": "",
                "payroll_break_minutes": int(manual["break_minutes"]),
                "payroll_source_kind": "manual",
            }
        )
    rows.sort(key=lambda row: (int(row["employee_id"]), row["clock_in"], int(row["id"])))
    return rows


def _payroll_shift_correction_rows(
    week_start: date,
    *,
    cursor: Optional[Any] = None,
    active_only: bool = True,
) -> List[Dict[str, Any]]:
    status_clause = "AND correction.status = 'active'" if active_only else ""
    return _payroll_query_all(
        f"""
        SELECT
            correction.*,
            employee.name AS employee_name
        FROM payroll_shift_corrections correction
        JOIN employees employee ON employee.id = correction.employee_id
        WHERE correction.week_start = %s
          {status_clause}
        ORDER BY correction.correction_date, LOWER(employee.name), correction.shift_id, correction.id
        """,
        (week_start,),
        cursor=cursor,
    )


def _payroll_active_shift_correction_rows_for_shift_ids(
    shift_ids: Iterable[int],
    *,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    normalized_shift_ids = sorted({int(shift_id) for shift_id in shift_ids if int(shift_id) > 0})
    if not normalized_shift_ids:
        return []
    return _payroll_query_all(
        """
        SELECT DISTINCT ON (correction.shift_id)
            correction.*,
            employee.name AS employee_name
        FROM payroll_shift_corrections correction
        JOIN employees employee ON employee.id = correction.employee_id
        JOIN shifts shift_row ON shift_row.id = correction.shift_id
        JOIN LATERAL (
            SELECT COALESCE(
                shift_row.local_date,
                (shift_row.clock_in AT TIME ZONE %s)::date
            ) AS source_work_date
        ) source ON TRUE
        WHERE correction.shift_id = ANY(%s)
          AND correction.status = 'active'
          AND correction.week_start = (
              source.source_work_date
              - EXTRACT(DOW FROM source.source_work_date)::integer
          )
        ORDER BY correction.shift_id, correction.id DESC
        """,
        (TIMEZONE_NAME, normalized_shift_ids),
        cursor=cursor,
    )


def _payroll_shift_corrections_by_shift_id(
    rows: List[Dict[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    return {
        int(row["shift_id"]): row
        for row in rows
        if row.get("shift_id") is not None
    }


def _hours_report_entry_shift_id(entry: Dict[str, Any]) -> Optional[int]:
    try:
        shift_id = int(entry.get("id") or 0)
    except (TypeError, ValueError):
        return None
    if shift_id <= 0:
        return None
    return shift_id


def _hours_report_shift_ids(entries: Iterable[Dict[str, Any]]) -> List[int]:
    shift_ids: set[int] = set()
    for entry in entries:
        shift_id = _hours_report_entry_shift_id(entry)
        if shift_id is not None:
            shift_ids.add(shift_id)
    return sorted(shift_ids)


def _hours_report_effective_shift_interval(
    entry: Dict[str, Any],
    correction_row: Optional[Dict[str, Any]],
    reference_time: datetime,
) -> Optional[Tuple[datetime, datetime, float]]:
    if correction_row is not None:
        clock_in = correction_row["corrected_clock_in"].astimezone(timezone.utc)
        clock_out = correction_row["corrected_clock_out"].astimezone(timezone.utc)
        hours = int(correction_row["corrected_total_minutes"]) / 60
        return clock_in, clock_out, hours

    if entry.get("clockOut") is None:
        return None

    ci_str = str(entry.get("clockIn", "")).strip()
    if not ci_str:
        return None
    try:
        clock_in = parse_utc_iso(ci_str)
        clock_out = parse_utc_iso(str(entry["clockOut"]))
    except (KeyError, ValueError):
        return None

    return clock_in, clock_out, entry_hours(entry, reference_time)


def _payroll_raw_shift_total_minutes(shift_row: Dict[str, Any]) -> int:
    clock_out = shift_row.get("clock_out")
    if clock_out is None:
        return 0
    clock_in = shift_row["clock_in"].astimezone(timezone.utc)
    clock_out = clock_out.astimezone(timezone.utc)
    if clock_out <= clock_in:
        return 0
    return int(((clock_out - clock_in).total_seconds() + 30) // 60)


def _payroll_corrected_shift_total_minutes(
    clock_in: datetime,
    clock_out: datetime,
    break_minutes: int,
) -> int:
    span_minutes = int(((clock_out - clock_in).total_seconds() + 30) // 60)
    if break_minutes > span_minutes:
        raise HTTPException(
            status_code=400,
            detail="Corrected break minutes cannot exceed corrected shift length",
        )
    corrected_total_minutes = span_minutes - break_minutes
    if corrected_total_minutes > 24 * 60:
        raise HTTPException(
            status_code=400,
            detail="Corrected shift total cannot exceed 24 hours",
        )
    return corrected_total_minutes


def _payroll_shift_overlaps_week(
    shift_row: Dict[str, Any],
    *,
    week_start_utc: datetime,
    week_end_utc: datetime,
    now_utc: datetime,
) -> bool:
    clock_in = shift_row["clock_in"].astimezone(timezone.utc)
    if clock_in >= week_end_utc:
        return False
    clock_out = shift_row.get("clock_out")
    if clock_out is None:
        return clock_in < now_utc and now_utc > week_start_utc
    clock_out = clock_out.astimezone(timezone.utc)
    return clock_out > week_start_utc or (
        week_start_utc <= clock_in < week_end_utc
    )


def _payroll_apply_break_minutes(
    day_minutes: List[Tuple[date, int]],
    break_minutes: int,
) -> List[Tuple[date, int]]:
    remaining_break = max(0, int(break_minutes))
    if remaining_break <= 0:
        return day_minutes
    adjusted = list(day_minutes)
    for index in range(len(adjusted) - 1, -1, -1):
        local_day, minutes = adjusted[index]
        deducted = min(minutes, remaining_break)
        adjusted[index] = (local_day, minutes - deducted)
        remaining_break -= deducted
        if remaining_break <= 0:
            break
    return adjusted


def _effective_payroll_shift_row(
    shift_row: Dict[str, Any],
    correction_row: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if correction_row is None:
        return dict(shift_row)
    effective = dict(shift_row)
    effective["clock_in"] = correction_row["corrected_clock_in"]
    effective["clock_out"] = correction_row["corrected_clock_out"]
    effective["total_hours"] = round(int(correction_row["corrected_total_minutes"]) / 60, 2)
    effective["payroll_shift_correction"] = correction_row
    effective["payroll_break_minutes"] = int(correction_row["corrected_break_minutes"])
    return effective


def _payroll_overlapping_shift_collisions(
    shift_rows: List[Dict[str, Any]],
    shift_corrections_by_shift_id: Dict[int, Dict[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    """Collision info for shifts whose effective closed interval overlaps
    another shift of the same employee, keyed by shift id.

    Each value carries firstOverlapUtc (the earliest instant this shift
    collides with another) and overlapDates (the local dates the collision
    intervals cover), so issues can be attributed to the day the collision
    actually happens rather than the shift's clock-in day. Overlap is strict
    (back-to-back end == next start is legal). Open and non-positive-duration
    shifts are excluded -- they already carry their own issue codes.
    Intervals are the post-correction ones and are re-sorted, because a
    correction can reorder shifts relative to the raw fetch order. Both
    members of an overlapping pair are flagged.
    """
    intervals_by_employee: Dict[int, List[Tuple[datetime, datetime, int]]] = {}
    for raw_shift_row in shift_rows:
        shift_row = _effective_payroll_shift_row(
            raw_shift_row,
            shift_corrections_by_shift_id.get(int(raw_shift_row["id"])),
        )
        clock_out = shift_row.get("clock_out")
        if clock_out is None:
            continue
        clock_in = shift_row["clock_in"].astimezone(timezone.utc)
        clock_out = clock_out.astimezone(timezone.utc)
        if clock_out <= clock_in:
            continue
        intervals_by_employee.setdefault(int(shift_row["employee_id"]), []).append(
            (clock_in, clock_out, int(shift_row["id"]))
        )

    collisions: Dict[int, Dict[str, Any]] = {}

    def record(shift_id: int, overlap_start: datetime, overlap_end: datetime) -> None:
        entry = collisions.setdefault(
            shift_id,
            {"firstOverlapUtc": overlap_start, "overlapDates": set()},
        )
        if overlap_start < entry["firstOverlapUtc"]:
            entry["firstOverlapUtc"] = overlap_start
        entry["overlapDates"].update(
            local_day
            for local_day, _seconds in _iter_payroll_local_day_slices(
                overlap_start, overlap_end
            )
        )

    for intervals in intervals_by_employee.values():
        intervals.sort(key=lambda item: (item[0], item[2]))
        running_end: Optional[datetime] = None
        running_id: Optional[int] = None
        for clock_in, clock_out, shift_id in intervals:
            if running_end is not None and clock_in < running_end:
                overlap_end = min(clock_out, running_end)
                record(shift_id, clock_in, overlap_end)
                if running_id is not None:
                    record(running_id, clock_in, overlap_end)
            if running_end is None or clock_out > running_end:
                running_end = clock_out
                running_id = shift_id
    return collisions


def _compute_payroll_weekly_hours(
    week_start_text: Optional[str],
    *,
    cursor: Optional[Any] = None,
    employee_rows: Optional[List[Dict[str, Any]]] = None,
    shift_rows: Optional[List[Dict[str, Any]]] = None,
    correction_rows: Optional[List[Dict[str, Any]]] = None,
    shift_correction_rows: Optional[List[Dict[str, Any]]] = None,
    now_utc: Optional[datetime] = None,
    include_timesheet_adjustments: bool = True,
    selected_employee_id: Optional[int] = None,
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(week_start_text)
    week_end, week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
    now_utc = now_utc or utc_now()

    if employee_rows is None:
        employee_rows = _payroll_query_all(
            """
            SELECT id, name, active
            FROM employees
            ORDER BY LOWER(name), id
            """,
            cursor=cursor,
        )
    if shift_rows is None:
        shift_rows = _payroll_overlapping_shift_rows(
            week_start_utc,
            week_end_utc,
            now_utc,
            cursor=cursor,
            include_timesheet_overlays=include_timesheet_adjustments,
        )
    if correction_rows is None:
        correction_rows = _payroll_query_all(
            """
            SELECT
                correction.id,
                correction.week_start,
                correction.correction_date,
                correction.employee_id,
                employee.name AS employee_name,
                correction.corrected_total_minutes,
                correction.reason,
                correction.created_at
            FROM payroll_hour_corrections correction
            JOIN employees employee ON employee.id = correction.employee_id
            WHERE correction.week_start = %s
              AND correction.status = 'active'
            ORDER BY correction.employee_id, correction.correction_date, correction.id
            """,
            (week_start,),
            cursor=cursor,
        )
    if shift_correction_rows is None:
        shift_correction_rows = _payroll_active_shift_correction_rows_for_shift_ids(
            [int(row["id"]) for row in shift_rows],
            cursor=cursor,
        )
    shift_corrections_by_shift_id = _payroll_shift_corrections_by_shift_id(
        shift_correction_rows
    )
    overlap_collisions = _payroll_overlapping_shift_collisions(
        shift_rows, shift_corrections_by_shift_id
    )

    employee_lookup = {int(row["id"]): row for row in employee_rows}
    included: Dict[int, Dict[str, Any]] = {
        int(row["id"]): _empty_payroll_employee(row, week_start)
        for row in employee_rows
        if bool(row["active"])
        or (
            selected_employee_id is not None
            and int(row["id"]) == int(selected_employee_id)
        )
    }
    shifted_employee_ids: set[int] = set()
    corrected_employee_ids: set[int] = set()

    for raw_shift_row in shift_rows:
        shift_row = _effective_payroll_shift_row(
            raw_shift_row,
            shift_corrections_by_shift_id.get(int(raw_shift_row["id"])),
        )
        if not _payroll_shift_overlaps_week(
            shift_row,
            week_start_utc=week_start_utc,
            week_end_utc=week_end_utc,
            now_utc=now_utc,
        ):
            continue
        employee_id = int(shift_row["employee_id"])
        employee_source = employee_lookup.get(employee_id)
        if employee_source is None:
            continue
        shifted_employee_ids.add(employee_id)
        shift_correction = shift_row.get("payroll_shift_correction")
        is_manual_shift = shift_row.get("payroll_source_kind") == "manual"
        if shift_correction or is_manual_shift:
            corrected_employee_ids.add(employee_id)
        included.setdefault(
            employee_id,
            _empty_payroll_employee(employee_source, week_start),
        )
        employee_result = included[employee_id]
        employee_result["overlappingShiftCount"] += 1
        if shift_correction or is_manual_shift:
            employee_result["correctionCount"] += 1

        clock_in = shift_row["clock_in"].astimezone(timezone.utc)
        clock_out = shift_row.get("clock_out")
        issue_at_utc = max(clock_in, week_start_utc)
        if issue_at_utc >= week_end_utc:
            issue_at_utc = week_start_utc

        if clock_out is None:
            _add_payroll_issue(
                employee_result,
                "missing_clock_out",
                shift_row,
                "Shift overlaps this payroll week but has no clock-out.",
                issue_at_utc,
            )
            continue

        clock_out = clock_out.astimezone(timezone.utc)
        if clock_out <= clock_in:
            _add_payroll_issue(
                employee_result,
                "invalid_shift_duration",
                shift_row,
                "Shift clock-out is not after clock-in.",
                issue_at_utc,
            )
            continue

        collision = overlap_collisions.get(int(shift_row["id"]))
        if collision is not None:
            # Flag without zeroing the minutes: blocking already prevents
            # verify/finalize, and admins need the real magnitudes to fix it.
            # Mark every in-week collision date -- not the clock-in day, and
            # not only the first collision day -- so the weekly day statuses
            # agree with the timesheet segments. A collision lying wholly
            # outside this week is flagged in the week it belongs to.
            for collision_day in sorted(collision["overlapDates"]):
                if collision_day < week_start or collision_day > week_end:
                    continue
                day_start_utc = datetime.combine(
                    collision_day, clock_time.min, tzinfo=APP_TIMEZONE
                ).astimezone(timezone.utc)
                _add_payroll_issue(
                    employee_result,
                    "overlapping_shift",
                    shift_row,
                    "Shift overlaps another shift for this employee.",
                    max(collision["firstOverlapUtc"], day_start_utc),
                )

        overlap_start = max(clock_in, week_start_utc)
        overlap_end = min(clock_out, week_end_utc)
        if overlap_end <= overlap_start:
            continue

        employee_result["completedShiftCount"] += 1
        day_map = _payroll_day_map(employee_result)
        day_minutes = _payroll_apply_break_minutes(
            _allocate_payroll_shift_minutes(
                _iter_payroll_local_day_slices(overlap_start, overlap_end)
            ),
            int(shift_row.get("payroll_break_minutes") or 0),
        )
        for local_day, minutes in day_minutes:
            day = day_map.get(local_day.isoformat())
            if day is None:
                continue
            day["totalMinutes"] += minutes
            day["totalHours"] = round(day["totalMinutes"] / 60, 2)
            day["completedShiftCount"] += 1
            employee_result["totalMinutes"] += minutes

    for correction_row in correction_rows:
        employee_id = int(correction_row["employee_id"])
        employee_source = employee_lookup.get(employee_id)
        if employee_source is None:
            continue
        corrected_employee_ids.add(employee_id)
        included.setdefault(
            employee_id,
            _empty_payroll_employee(employee_source, week_start),
        )
        employee_result = included[employee_id]
        correction_date = correction_row["correction_date"]
        if not isinstance(correction_date, date):
            correction_date = datetime.strptime(str(correction_date), "%Y-%m-%d").date()
        day = _payroll_day_map(employee_result).get(correction_date.isoformat())
        if day is None:
            continue
        source_minutes = int(day["totalMinutes"])
        corrected_minutes = int(correction_row["corrected_total_minutes"])
        delta_minutes = corrected_minutes - source_minutes
        day["totalMinutes"] = corrected_minutes
        day["totalHours"] = round(corrected_minutes / 60, 2)
        day["correction"] = {
            "correctionId": int(correction_row["id"]),
            "sourceTotalMinutes": source_minutes,
            "sourceTotalHours": round(source_minutes / 60, 2),
            "correctedTotalMinutes": corrected_minutes,
            "correctedTotalHours": round(corrected_minutes / 60, 2),
            "deltaMinutes": delta_minutes,
            "deltaHours": round(delta_minutes / 60, 2),
            "reason": str(correction_row["reason"]),
        }
        employee_result["totalMinutes"] += delta_minutes
        employee_result["correctionCount"] += 1

    if include_timesheet_adjustments:
        exclusion_rows = _payroll_query_all(
            """
            SELECT exclusion.employee_id, exclusion.id AS overlay_id
            FROM payroll_shift_exclusions exclusion
            WHERE exclusion.week_start = %s
              AND exclusion.status = 'active'
            UNION ALL
            SELECT manual.employee_id, manual.id AS overlay_id
            FROM payroll_manual_shift_versions manual
            WHERE manual.week_start = %s
              AND manual.status = 'current'
              AND manual.included = FALSE
            ORDER BY employee_id, overlay_id
            """,
            (week_start, week_start),
            cursor=cursor,
        )
        for exclusion_row in exclusion_rows:
            employee_id = int(exclusion_row["employee_id"])
            employee_source = employee_lookup.get(employee_id)
            if employee_source is None:
                continue
            corrected_employee_ids.add(employee_id)
            included.setdefault(
                employee_id,
                _empty_payroll_employee(employee_source, week_start),
            )["correctionCount"] += 1

    employees = sorted(included.values(), key=lambda row: (row["employeeName"].lower(), row["employeeId"]))
    for employee in employees:
        employee["totalHours"] = round(employee["totalMinutes"] / 60, 2)
        employee["issueCodes"].sort()
        for day in employee["days"]:
            day["issueCodes"].sort()

    issue_count = sum(len(employee["issues"]) for employee in employees)
    total_minutes = sum(int(employee["totalMinutes"]) for employee in employees)
    total_completed_shift_count = sum(int(employee["completedShiftCount"]) for employee in employees)
    total_overlapping_shift_count = sum(int(employee["overlappingShiftCount"]) for employee in employees)
    total_correction_count = sum(int(employee["correctionCount"]) for employee in employees)
    fingerprint_rows = [
        row
        for row in employee_rows
        if (
            bool(row["active"])
            or int(row["id"]) in shifted_employee_ids
            or int(row["id"]) in corrected_employee_ids
            or (
                selected_employee_id is not None
                and int(row["id"]) == int(selected_employee_id)
            )
        )
    ]
    blocking_issue_digest = sorted(
        (
            {
                "code": str(issue["code"]),
                "rowId": str(issue.get("rowId") or ""),
                "sourceKind": str(issue.get("sourceKind") or "recorded"),
                "shiftId": (
                    int(issue["shiftId"])
                    if issue.get("shiftId") is not None
                    else None
                ),
                "manualShiftId": issue.get("manualShiftId"),
                "date": (
                    issue["date"].isoformat()
                    if isinstance(issue["date"], date)
                    else str(issue["date"])
                ),
            }
            for employee in employees
            for issue in employee["issues"]
        ),
        key=lambda item: (item["date"], item["rowId"], item["code"]),
    )

    return {
        "success": True,
        "period": "week",
        "timezone": TIMEZONE_NAME,
        "weekStart": week_start.isoformat(),
        "weekEnd": week_end.isoformat(),
        "weekEndExclusive": (week_end + timedelta(days=1)).isoformat(),
        "generatedAt": to_utc_iso(utc_now()),
        "sourceFingerprint": _payroll_source_fingerprint(
            week_start=week_start,
            week_end=week_end,
            employees=fingerprint_rows,
            shifts=shift_rows,
            corrections=correction_rows,
            shift_corrections=shift_correction_rows,
            blocking_issues=blocking_issue_digest,
        ),
        "employees": employees,
        "summary": {
            "employeeCount": len(employees),
            "activeEmployeeCount": sum(1 for employee in employees if employee["active"]),
            "employeesWithHours": sum(1 for employee in employees if employee["totalMinutes"] > 0),
            "totalMinutes": total_minutes,
            "totalHours": round(total_minutes / 60, 2),
            "completedShiftCount": total_completed_shift_count,
            "overlappingShiftCount": total_overlapping_shift_count,
            "correctionCount": total_correction_count,
            "issueCount": issue_count,
            "hasBlockingIssues": issue_count > 0,
        },
    }


def _payroll_timesheet_text(value: Any) -> str:
    return str(value or "").strip()


def _payroll_timesheet_location_label(shift_row: Dict[str, Any]) -> str:
    return (
        _payroll_timesheet_text(shift_row.get("location_label"))
        or _payroll_timesheet_text(shift_row.get("location_address"))
    )


def _payroll_timesheet_customer_name(shift_row: Dict[str, Any]) -> str:
    return (
        _payroll_timesheet_text(shift_row.get("location_customer_name"))
        or _payroll_timesheet_text(shift_row.get("customer_name"))
    )


def _payroll_timesheet_datetime(value: Optional[datetime]) -> Optional[Dict[str, str]]:
    if value is None:
        return None
    local_value = to_local(value)
    return {
        "iso": to_utc_iso(value),
        "localIso": local_value.replace(microsecond=0).isoformat(),
        "display": local_clock_string(value),
    }


def _payroll_timesheet_segment_bounds(
    start_utc: datetime,
    end_utc: datetime,
    *,
    break_minutes: int = 0,
) -> List[Dict[str, Any]]:
    segments: List[Dict[str, Any]] = []
    cursor = start_utc
    while cursor < end_utc:
        local_cursor = to_local(cursor)
        local_day = local_cursor.date()
        next_local_midnight = datetime.combine(
            local_day + timedelta(days=1),
            clock_time.min,
            tzinfo=APP_TIMEZONE,
        )
        next_cursor = min(end_utc, next_local_midnight.astimezone(timezone.utc))
        if next_cursor <= cursor:
            break
        seconds = max(0.0, (next_cursor - cursor).total_seconds())
        if seconds > 0:
            segments.append(
                {
                    "date": local_day,
                    "startUtc": cursor,
                    "endUtc": next_cursor,
                    "seconds": seconds,
                }
            )
        cursor = next_cursor
    allocations = _payroll_apply_break_minutes(
        _allocate_payroll_shift_minutes(
            [(segment["date"], float(segment["seconds"])) for segment in segments]
        ),
        break_minutes,
    )
    for segment, (_, minutes) in zip(segments, allocations):
        segment["minutes"] = int(minutes)
    return segments


def _payroll_timesheet_allocation_validity_payload(
    correction_details: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    payload: List[Dict[str, Any]] = []
    for detail in sorted(
        correction_details,
        key=lambda row: int(row.get("correctionId") or 0),
    ):
        allocation_issue = detail.get("allocationIssue") or {}
        payload.append(
            {
                "correction_id": int(detail.get("correctionId") or 0),
                "allocation_status": str(detail.get("allocationStatus") or ""),
                "allocation_valid": detail.get("allocationValid"),
                "allocation_issue_code": str(allocation_issue.get("code") or ""),
                "allocation_issue_message": str(allocation_issue.get("message") or ""),
            }
        )
    return payload


def _payroll_effective_shift_rate_cents(
    shift: Dict[str, Any],
    rate_cents_by_employee: Dict[int, Optional[int]],
) -> Optional[int]:
    """The rate a shift's labor is actually priced at: its stamped snapshot if
    present, else the employee's current live rate. This is what money
    verification signs off -- an UNSTAMPED shift is repriced by a live-rate edit,
    so its effective rate must move the money fingerprint (a stamped shift is
    frozen, so a rate edit correctly does NOT move it)."""
    snapshot = shift.get("hourly_rate_cents")
    if snapshot is not None:
        return int(snapshot)
    return rate_cents_by_employee.get(int(shift["employee_id"]))


def _payroll_timesheet_source_fingerprint(
    *,
    week_start: date,
    week_end: date,
    employees: List[Dict[str, Any]],
    shifts: List[Dict[str, Any]],
    excluded_shifts: List[Dict[str, Any]],
    corrections: List[Dict[str, Any]],
    shift_corrections: List[Dict[str, Any]],
    allocations: List[Dict[str, Any]],
    correction_details: List[Dict[str, Any]],
) -> str:
    rate_cents_by_employee: Dict[int, Optional[int]] = {
        int(row["id"]): (
            int(
                (Decimal(str(row["hourly_rate"])) * 100).to_integral_value(
                    rounding=ROUND_HALF_UP
                )
            )
            if row.get("hourly_rate") is not None
            else None
        )
        for row in employees
    }
    payload = {
        "timezone": TIMEZONE_NAME,
        "weekStart": week_start.isoformat(),
        "weekEnd": week_end.isoformat(),
        "employees": [
            {
                "id": int(row["id"]),
                "name": str(row["name"]),
                "active": bool(row["active"]),
            }
            for row in employees
        ],
        "shifts": [
            {
                "id": int(row["id"]),
                "source_kind": str(row.get("payroll_source_kind") or "recorded"),
                "manual_shift_id": (
                    str(row["manual_shift_id"])
                    if row.get("manual_shift_id") is not None
                    else None
                ),
                "employee_id": int(row["employee_id"]),
                "clock_in": to_utc_iso(row["clock_in"]),
                "clock_out": (
                    to_utc_iso(row["clock_out"]) if row.get("clock_out") else None
                ),
                "total_hours": (
                    str(row["total_hours"]) if row.get("total_hours") is not None else None
                ),
                "effective_hourly_rate_cents": _payroll_effective_shift_rate_cents(
                    row, rate_cents_by_employee
                ),
                "local_date": (
                    row["local_date"].isoformat()
                    if row.get("local_date") is not None
                    else None
                ),
                "location_id": (
                    int(row["location_id"])
                    if row.get("location_id") is not None
                    else None
                ),
                "location_label": _payroll_timesheet_location_label(row),
                "customer_name": _payroll_timesheet_customer_name(row),
                "job_id": int(row["job_id"]) if row.get("job_id") is not None else None,
                "time_category": str(row.get("time_category") or ""),
                "non_productive_type": row.get("non_productive_type"),
            }
            for row in shifts
        ],
        "excludedShifts": [
            {
                "row_id": str(row.get("rowId") or ""),
                "source_kind": str(row.get("sourceKind") or "recorded"),
                "shift_id": (
                    int(row["shiftId"])
                    if row.get("shiftId") is not None
                    else None
                ),
                "manual_shift_id": row.get("manualShiftId"),
                "employee_id": int(row["employeeId"]),
                "date": str(row.get("date") or ""),
                "clock_in": str((row.get("clockIn") or {}).get("iso") or ""),
                "clock_out": str((row.get("clockOut") or {}).get("iso") or ""),
                "total_minutes": int(row.get("totalMinutes") or 0),
                "break_minutes": int(row.get("breakMinutes") or 0),
                "location_id": (
                    int(row["locationId"])
                    if row.get("locationId") is not None
                    else None
                ),
                "exclusion_version": int(
                    (row.get("exclusion") or {}).get("version") or 0
                ),
            }
            for row in excluded_shifts
        ],
        "corrections": [
            {
                "id": int(row["id"]),
                "employee_id": int(row["employee_id"]),
                "correction_date": row["correction_date"].isoformat(),
                "corrected_total_minutes": int(row["corrected_total_minutes"]),
                "reason": str(row["reason"]),
                "created_at": to_utc_iso(row["created_at"]),
            }
            for row in corrections
        ],
        "shiftCorrections": [
            {
                "id": int(row["id"]),
                "employee_id": int(row["employee_id"]),
                "shift_id": int(row["shift_id"]),
                "correction_date": row["correction_date"].isoformat(),
                "corrected_clock_in": to_utc_iso(row["corrected_clock_in"]),
                "corrected_clock_out": to_utc_iso(row["corrected_clock_out"]),
                "corrected_break_minutes": int(row["corrected_break_minutes"]),
                "corrected_total_minutes": int(row["corrected_total_minutes"]),
                "reason": str(row["reason"]),
                "created_at": to_utc_iso(row["created_at"]),
            }
            for row in shift_corrections
        ],
        "allocations": [
            {
                "id": int(row["id"]),
                "correction_id": int(row["correction_id"]),
                "location_id": int(row["location_id"]),
                "location_customer_id": (
                    int(row["location_customer_id"])
                    if row.get("location_customer_id") is not None
                    else None
                ),
                "location_customer_name": str(row.get("location_customer_name") or ""),
                "location_address": str(row.get("location_address") or ""),
                "job_id": int(row["job_id"]) if row.get("job_id") is not None else None,
                "allocated_delta_minutes": int(row["allocated_delta_minutes"]),
                "allocated_labor_cost_cents": row.get("allocated_labor_cost_cents"),
                # Provenance is part of the money truth: a flip between live and
                # frozen valuation changes the payroll dollars this row stands
                # for even when the stored cents are momentarily equal, so the
                # money fingerprint must move when it flips. Without this, a
                # startup reconcile could re-value an already-signed-off week
                # without invalidating its (future) money verification.
                "allocated_labor_cost_is_live": row.get("allocated_labor_cost_is_live"),
                "employee_hourly_rate": (
                    str(row["employee_hourly_rate"])
                    if row.get("employee_hourly_rate") is not None
                    else None
                ),
                "status": str(row["status"]),
            }
            for row in allocations
        ],
        "allocationValidity": _payroll_timesheet_allocation_validity_payload(
            correction_details
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payroll_employee_timesheet_source_fingerprint(
    *,
    employee_id: int,
    week_start: date,
    week_end: date,
    employees: List[Dict[str, Any]],
    shifts: List[Dict[str, Any]],
    excluded_shifts: List[Dict[str, Any]],
    corrections: List[Dict[str, Any]],
    shift_corrections: List[Dict[str, Any]],
    allocations: List[Dict[str, Any]],
    correction_details: List[Dict[str, Any]],
) -> str:
    employee_corrections = [
        row for row in corrections if int(row["employee_id"]) == employee_id
    ]
    correction_ids = {int(row["id"]) for row in employee_corrections}
    return _payroll_timesheet_source_fingerprint(
        week_start=week_start,
        week_end=week_end,
        employees=[row for row in employees if int(row["id"]) == employee_id],
        shifts=[row for row in shifts if int(row["employee_id"]) == employee_id],
        excluded_shifts=[
            row
            for row in excluded_shifts
            if int(row["employeeId"]) == employee_id
        ],
        corrections=employee_corrections,
        shift_corrections=[
            row
            for row in shift_corrections
            if int(row["employee_id"]) == employee_id
        ],
        allocations=[
            row for row in allocations if int(row["correction_id"]) in correction_ids
        ],
        correction_details=[
            detail
            for detail in correction_details
            if int(detail.get("employeeId") or 0) == employee_id
        ],
    )


def _payroll_selected_employee_timesheet_fingerprint(
    timesheet: Dict[str, Any],
    employee_id: int,
) -> str:
    for employee in timesheet.get("employees") or []:
        if int(employee.get("employeeId") or 0) == employee_id:
            return str(employee.get("timesheetSourceFingerprint") or "")
    return ""


def _serialize_payroll_timesheet_shift(
    shift_row: Dict[str, Any],
    *,
    segment: Dict[str, Any],
    segment_index: int,
    segment_count: int,
    issue_codes: List[str],
    week_end_utc: datetime,
) -> Dict[str, Any]:
    clock_in = shift_row["clock_in"].astimezone(timezone.utc)
    clock_out_value = shift_row.get("clock_out")
    clock_out = (
        clock_out_value.astimezone(timezone.utc)
        if clock_out_value is not None
        else None
    )
    minutes = int(segment.get("minutes") or 0)
    correction_row = shift_row.get("payroll_shift_correction")
    # Nonempty issue codes win over "corrected": a correction that still
    # leaves the shift overlapping (or otherwise flagged) needs review.
    status = "needs_review" if issue_codes else ("corrected" if correction_row else "registered")
    location_id = shift_row.get("location_id")
    job_id = shift_row.get("job_id")
    location_label = _payroll_timesheet_location_label(shift_row)
    customer_name = _payroll_timesheet_customer_name(shift_row)
    source_kind = str(shift_row.get("payroll_source_kind") or "recorded")
    source_clock_in = clock_in
    source_clock_out = clock_out
    source_total_minutes = minutes
    source_break_minutes = (
        int(shift_row.get("payroll_break_minutes") or 0)
        if source_kind == "manual"
        else None
    )
    if correction_row:
        source_clock_in = correction_row["source_clock_in"].astimezone(timezone.utc)
        source_clock_out_value = correction_row.get("source_clock_out")
        source_clock_out = (
            source_clock_out_value.astimezone(timezone.utc)
            if source_clock_out_value is not None
            else None
        )
        source_total_minutes = int(correction_row["source_total_minutes"])
        source_break_minutes = correction_row.get("source_break_minutes")
    source_starts_on_segment_date = to_local(source_clock_in).date() == segment["date"]
    source_segment_count = (
        len(
            _payroll_timesheet_segment_bounds(
                source_clock_in,
                source_clock_out,
            )
        )
        if source_clock_out is not None
        else segment_count
    )
    recorded_source_interval_is_editable = (
        source_clock_out is not None
        and source_segment_count <= 2
        and source_clock_out <= week_end_utc
    )
    can_correct_shift = (
        (
            source_kind == "manual"
            or recorded_source_interval_is_editable
            or (source_clock_out is None and source_segment_count == 1)
        )
        and source_starts_on_segment_date
        and (
            source_clock_out is not None
            or "missing_clock_out" in issue_codes
        )
    )
    manual_shift_id = (
        str(shift_row["manual_shift_id"])
        if source_kind == "manual" and shift_row.get("manual_shift_id") is not None
        else None
    )
    public_shift_id = int(shift_row["id"]) if source_kind == "recorded" else None
    stable_row_id = (
        f"manual:{manual_shift_id}"
        if manual_shift_id is not None
        else f"recorded:{public_shift_id}"
    )
    result = {
        "rowId": f"{stable_row_id}:{segment['date'].isoformat()}:{segment_index}",
        "kind": "shift",
        "sourceKind": source_kind,
        "shiftId": public_shift_id,
        "manualShiftId": manual_shift_id,
        "employeeId": int(shift_row["employee_id"]),
        "date": segment["date"].isoformat(),
        "segmentIndex": segment_index,
        "segmentCount": segment_count,
        "spansMultipleDays": segment_count > 1,
        "clockIn": _payroll_timesheet_datetime(clock_in),
        "clockOut": _payroll_timesheet_datetime(clock_out),
        "segmentClockIn": _payroll_timesheet_datetime(segment.get("startUtc")),
        "segmentClockOut": _payroll_timesheet_datetime(segment.get("endUtc")),
        "totalMinutes": minutes,
        "totalHours": round(minutes / 60, 2),
        "breakMinutes": (
            int(correction_row["corrected_break_minutes"])
            if correction_row
            else source_break_minutes
        ),
        "locationId": int(location_id) if location_id is not None else None,
        "locationLabel": location_label,
        "customerName": customer_name,
        "jobId": int(job_id) if job_id is not None else None,
        "timeCategory": str(shift_row.get("time_category") or "productive"),
        "nonProductiveType": shift_row.get("non_productive_type"),
        "status": status,
        "issueCodes": list(issue_codes),
        "fieldSupport": {
            "clockIn": {"display": True, "correction": can_correct_shift},
            "clockOut": {"display": True, "correction": can_correct_shift},
            "breakMinutes": {"display": True, "correction": can_correct_shift},
            "totalHours": {"display": True, "correction": False},
        },
        "canExclude": True,
        "original": {
            "clockIn": _payroll_timesheet_datetime(source_clock_in),
            "clockOut": _payroll_timesheet_datetime(source_clock_out),
            "totalMinutes": source_total_minutes,
            "totalHours": round(source_total_minutes / 60, 2),
            "breakMinutes": source_break_minutes,
            "locationId": int(location_id) if location_id is not None else None,
            "locationLabel": location_label,
            "customerName": customer_name,
            "jobId": int(job_id) if job_id is not None else None,
        },
    }
    if source_kind == "manual":
        result["manualAudit"] = {
            "version": int(shift_row.get("manual_shift_version") or 1),
            "reason": str(shift_row.get("manual_shift_reason") or ""),
            "actorName": str(shift_row.get("manual_shift_created_by_name") or ""),
            "createdAt": _payroll_verification_iso(shift_row.get("manual_shift_created_at")),
        }
    if correction_row:
        result["correction"] = _serialize_payroll_shift_correction(correction_row)
    return result


def _payroll_excluded_timesheet_rows(
    week_start: date,
    *,
    cursor: Optional[Any] = None,
    employee_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    recorded_rows = _payroll_query_all(
        """
        SELECT
            exclusion.id AS exclusion_id,
            exclusion.reason AS exclusion_reason,
            exclusion.created_by_name AS exclusion_actor_name,
            exclusion.created_at AS exclusion_created_at,
            shift_row.*,
            location.address AS location_address,
            location.customer_name AS location_customer_name,
            customer.name AS customer_name,
            correction.id AS correction_id,
            correction.source_clock_in,
            correction.source_clock_out,
            correction.source_total_minutes,
            correction.corrected_clock_in,
            correction.corrected_clock_out,
            correction.corrected_break_minutes,
            correction.corrected_total_minutes
        FROM payroll_shift_exclusions exclusion
        JOIN shifts shift_row ON shift_row.id = exclusion.shift_id
        LEFT JOIN locations location ON location.id = shift_row.location_id
        LEFT JOIN customers customer ON customer.id = location.customer_id
        LEFT JOIN LATERAL (
            SELECT active_correction.*
            FROM payroll_shift_corrections active_correction
            WHERE active_correction.week_start = exclusion.week_start
              AND active_correction.shift_id = exclusion.shift_id
              AND active_correction.status = 'active'
            ORDER BY active_correction.id DESC
            LIMIT 1
        ) correction ON TRUE
        WHERE exclusion.week_start = %s
          AND exclusion.status = 'active'
          AND (%s::integer IS NULL OR exclusion.employee_id = %s)
        ORDER BY shift_row.employee_id, shift_row.clock_in, shift_row.id
        """,
        (week_start, employee_id, employee_id),
        cursor=cursor,
    )
    manual_rows = _payroll_query_all(
        """
        SELECT
            manual.*,
            location.address AS location_address,
            location.customer_name AS location_customer_name,
            customer.name AS customer_name
        FROM payroll_manual_shift_versions manual
        LEFT JOIN locations location ON location.id = manual.location_id
        LEFT JOIN customers customer ON customer.id = location.customer_id
        WHERE manual.week_start = %s
          AND manual.status = 'current'
          AND manual.included = FALSE
          AND (%s::integer IS NULL OR manual.employee_id = %s)
        ORDER BY manual.employee_id, manual.clock_in, manual.id
        """,
        (week_start, employee_id, employee_id),
        cursor=cursor,
    )

    result: List[Dict[str, Any]] = []
    _week_end, week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
    for row in recorded_rows:
        corrected = row.get("correction_id") is not None
        clock_in = row["corrected_clock_in"] if corrected else row["clock_in"]
        clock_out = row["corrected_clock_out"] if corrected else row.get("clock_out")
        overlap_start = max(clock_in.astimezone(timezone.utc), week_start_utc)
        overlap_end = (
            min(clock_out.astimezone(timezone.utc), week_end_utc)
            if clock_out is not None
            else overlap_start
        )
        break_minutes = int(row.get("corrected_break_minutes") or 0)
        segments = (
            _payroll_timesheet_segment_bounds(
                overlap_start,
                overlap_end,
                break_minutes=break_minutes,
            )
            if overlap_end > overlap_start
            else []
        )
        total_minutes = sum(int(segment.get("minutes") or 0) for segment in segments)
        display_date = to_local(overlap_start).date()
        result.append(
            {
                "rowId": f"excluded:recorded:{int(row['id'])}",
                "kind": "shift",
                "sourceKind": "recorded",
                "shiftId": int(row["id"]),
                "manualShiftId": None,
                "employeeId": int(row["employee_id"]),
                "date": display_date.isoformat(),
                "clockIn": _payroll_timesheet_datetime(clock_in),
                "clockOut": _payroll_timesheet_datetime(clock_out),
                "totalMinutes": total_minutes,
                "totalHours": round(total_minutes / 60, 2),
                "breakMinutes": break_minutes,
                "locationId": int(row["location_id"]) if row.get("location_id") else None,
                "locationLabel": _payroll_timesheet_location_label(row),
                "customerName": _payroll_timesheet_customer_name(row),
                "status": "excluded",
                "canRestore": True,
                "exclusion": {
                    "exclusionId": int(row["exclusion_id"]),
                    "reason": str(row["exclusion_reason"]),
                    "actorName": str(row["exclusion_actor_name"]),
                    "createdAt": _payroll_verification_iso(row["exclusion_created_at"]),
                },
            }
        )
    for row in manual_rows:
        result.append(
            {
                "rowId": f"excluded:manual:{row['manual_shift_id']}",
                "kind": "shift",
                "sourceKind": "manual",
                "shiftId": None,
                "manualShiftId": str(row["manual_shift_id"]),
                "employeeId": int(row["employee_id"]),
                "date": row["work_date"].isoformat(),
                "clockIn": _payroll_timesheet_datetime(row["clock_in"]),
                "clockOut": _payroll_timesheet_datetime(row["clock_out"]),
                "totalMinutes": int(row["total_minutes"]),
                "totalHours": round(int(row["total_minutes"]) / 60, 2),
                "breakMinutes": int(row["break_minutes"]),
                "locationId": int(row["location_id"]) if row.get("location_id") else None,
                "locationLabel": _payroll_timesheet_location_label(row),
                "customerName": _payroll_timesheet_customer_name(row),
                "status": "excluded",
                "canRestore": True,
                "exclusion": {
                    "reason": str(row["reason"]),
                    "actorName": str(row["created_by_name"]),
                    "createdAt": _payroll_verification_iso(row["created_at"]),
                    "version": int(row["version"]),
                },
            }
        )
    return result


def _compute_payroll_timesheet(
    week_start_text: Optional[str],
    *,
    employee_id: Optional[int] = None,
    cursor: Optional[Any] = None,
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(week_start_text)
    week_end, week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
    now_utc = utc_now()
    employee_rows = _payroll_query_all(
        """
        SELECT id, name, active, hourly_rate
        FROM employees
        ORDER BY LOWER(name), id
        """,
        cursor=cursor,
    )
    shift_rows = _payroll_overlapping_shift_rows(
        week_start_utc,
        week_end_utc,
        now_utc,
        cursor=cursor,
    )
    excluded_shift_rows = _payroll_excluded_timesheet_rows(
        week_start,
        cursor=cursor,
    )
    correction_rows = _payroll_correction_rows(week_start, cursor=cursor)
    shift_correction_rows = _payroll_active_shift_correction_rows_for_shift_ids(
        [int(row["id"]) for row in shift_rows],
        cursor=cursor,
    )
    shift_corrections_by_shift_id = _payroll_shift_corrections_by_shift_id(
        shift_correction_rows
    )
    overlap_collisions = _payroll_overlapping_shift_collisions(
        shift_rows, shift_corrections_by_shift_id
    )
    allocation_rows = _payroll_correction_allocation_rows(week_start, cursor=cursor)
    allocations_by_correction_id = _payroll_correction_allocations_by_correction_id(
        allocation_rows
    )
    weekly_hours = _compute_payroll_weekly_hours(
        week_start.isoformat(),
        cursor=cursor,
        employee_rows=employee_rows,
        shift_rows=shift_rows,
        correction_rows=correction_rows,
        shift_correction_rows=shift_correction_rows,
        now_utc=now_utc,
        selected_employee_id=employee_id,
    )
    settings = load_settings(cursor=cursor)
    profitability = build_weekly_labor_profitability(
        week_start,
        timezone_name=TIMEZONE_NAME,
        now_provider=utc_now,
        default_target_labor_pct=settings.get(
            "laborPctTarget",
            _SETTINGS_DEFAULTS["laborPctTarget"],
        ),
        default_min_margin_pct=settings.get(
            "grossMarginMin",
            _SETTINGS_DEFAULTS["grossMarginMin"],
        ),
        payroll_week_start=week_start,
        cursor=cursor,
    )
    correction_details_by_id = {
        int(detail["correctionId"]): detail
        for rows in _payroll_correction_details_by_date(
            weekly_hours,
            profitability.pop("_payrollCorrectionCandidateSegments", []),
            allocation_rows,
        ).values()
        for detail in rows
    }
    correction_details = list(correction_details_by_id.values())

    for employee in weekly_hours["employees"]:
        for day in employee["days"]:
            day["shifts"] = []
            day["excludedShifts"] = []
            day["status"] = "no_hours"
            correction = day.get("correction")
            if correction:
                correction_id = int(correction["correctionId"])
                allocation_row = allocations_by_correction_id.get(correction_id)
                correction_detail = correction_details_by_id.get(correction_id)
                if correction_detail:
                    correction["allocationStatus"] = str(
                        correction_detail.get("allocationStatus") or "unallocated"
                    )
                    correction["allocation"] = correction_detail.get("allocation")
                    if "allocationValid" in correction_detail:
                        correction["allocationValid"] = bool(
                            correction_detail["allocationValid"]
                        )
                    if correction_detail.get("allocationIssue"):
                        correction["allocationIssue"] = correction_detail[
                            "allocationIssue"
                        ]
                else:
                    correction["allocationStatus"] = (
                        "allocated" if allocation_row else "unallocated"
                    )
                    correction["allocation"] = (
                        _serialize_payroll_correction_allocation(allocation_row)
                        if allocation_row
                        else None
                    )
                if correction["allocationStatus"] == "unallocated":
                    correction["unallocatedLocationLabel"] = (
                        "Horas corregidas sin ubicación confirmada"
                    )

    employees_by_id = {
        int(employee["employeeId"]): employee
        for employee in weekly_hours["employees"]
    }

    for raw_shift_row in shift_rows:
        shift_row = _effective_payroll_shift_row(
            raw_shift_row,
            shift_corrections_by_shift_id.get(int(raw_shift_row["id"])),
        )
        row_employee_id = int(shift_row["employee_id"])
        employee = employees_by_id.get(row_employee_id)
        if employee is None:
            continue

        clock_in = shift_row["clock_in"].astimezone(timezone.utc)
        clock_out_value = shift_row.get("clock_out")
        issue_at_utc = max(clock_in, week_start_utc)
        if issue_at_utc >= week_end_utc:
            issue_at_utc = week_start_utc

        issue_codes: List[str] = []
        if clock_out_value is None:
            issue_codes.append("missing_clock_out")
            segments = [
                {
                    "date": to_local(issue_at_utc).date(),
                    "startUtc": issue_at_utc,
                    "endUtc": None,
                    "minutes": 0,
                }
            ]
        else:
            clock_out = clock_out_value.astimezone(timezone.utc)
            if clock_out <= clock_in:
                issue_codes.append("invalid_shift_duration")
                segments = [
                    {
                        "date": to_local(issue_at_utc).date(),
                        "startUtc": issue_at_utc,
                        "endUtc": clock_out,
                        "minutes": 0,
                    }
                ]
            else:
                overlap_start = max(clock_in, week_start_utc)
                overlap_end = min(clock_out, week_end_utc)
                if overlap_end <= overlap_start:
                    continue
                segments = _payroll_timesheet_segment_bounds(
                    overlap_start,
                    overlap_end,
                    break_minutes=int(shift_row.get("payroll_break_minutes") or 0),
                )

        # Same code the weekly producer emits, so the two views agree. The
        # collision map only ever contains closed valid-duration shifts, and
        # the code lands on the segment(s) whose date the collision actually
        # covers -- not every day a multi-day shift touches.
        collision = overlap_collisions.get(int(shift_row["id"]))
        collision_dates = collision["overlapDates"] if collision else None

        segment_count = len(segments)
        for index, segment in enumerate(segments, start=1):
            day = _payroll_day_map(employee).get(segment["date"].isoformat())
            if day is None:
                continue
            segment_issue_codes = issue_codes
            if collision_dates and segment["date"] in collision_dates:
                segment_issue_codes = [*issue_codes, "overlapping_shift"]
            day["shifts"].append(
                _serialize_payroll_timesheet_shift(
                    shift_row,
                    segment=segment,
                    segment_index=index,
                    segment_count=segment_count,
                    issue_codes=segment_issue_codes,
                    week_end_utc=week_end_utc,
                )
            )

    for excluded_shift in excluded_shift_rows:
        employee = employees_by_id.get(int(excluded_shift["employeeId"]))
        if employee is None:
            continue
        day = _payroll_day_map(employee).get(str(excluded_shift["date"]))
        if day is not None:
            day["excludedShifts"].append(excluded_shift)

    filtered_employees = weekly_hours["employees"]
    if employee_id is not None:
        filtered_employees = [
            employee
            for employee in weekly_hours["employees"]
            if int(employee["employeeId"]) == int(employee_id)
        ]

    for employee in filtered_employees:
        for day in employee["days"]:
            day["shifts"].sort(
                key=lambda shift: (
                    str((shift.get("segmentClockIn") or {}).get("iso") or ""),
                    int(shift.get("shiftId") or 0),
                    int(shift.get("segmentIndex") or 0),
                )
            )
            day["excludedShifts"].sort(
                key=lambda shift: (
                    str((shift.get("clockIn") or {}).get("iso") or ""),
                    str(shift.get("rowId") or ""),
                )
            )
            if day.get("issueCodes"):
                day["status"] = "needs_review"
            elif day.get("correction") or any(
                shift.get("status") == "corrected" for shift in day["shifts"]
            ):
                day["status"] = "corrected"
            elif day["shifts"] or int(day.get("totalMinutes") or 0) > 0:
                day["status"] = "registered"
        employee["timesheetSourceFingerprint"] = (
            _payroll_employee_timesheet_source_fingerprint(
                employee_id=int(employee["employeeId"]),
                week_start=week_start,
                week_end=week_end,
                employees=employee_rows,
                shifts=shift_rows,
                excluded_shifts=excluded_shift_rows,
                corrections=correction_rows,
                shift_corrections=shift_correction_rows,
                allocations=allocation_rows,
                correction_details=correction_details,
            )
        )

    total_minutes = sum(int(employee["totalMinutes"]) for employee in filtered_employees)
    return {
        "success": True,
        "period": "week",
        "timezone": TIMEZONE_NAME,
        "weekStart": week_start.isoformat(),
        "weekEnd": week_end.isoformat(),
        "weekEndExclusive": (week_end + timedelta(days=1)).isoformat(),
        "generatedAt": to_utc_iso(utc_now()),
        "sourceFingerprint": weekly_hours["sourceFingerprint"],
        "timesheetSourceFingerprint": _payroll_timesheet_source_fingerprint(
            week_start=week_start,
            week_end=week_end,
            employees=employee_rows,
            shifts=shift_rows,
            excluded_shifts=excluded_shift_rows,
            corrections=correction_rows,
            shift_corrections=shift_correction_rows,
            allocations=allocation_rows,
            correction_details=correction_details,
        ),
        "selectedEmployeeId": int(employee_id) if employee_id is not None else None,
        "capabilities": {
            "rawShiftRows": True,
            "dayTotalCorrections": True,
            "shiftClockCorrections": True,
            "breakMinutesTracked": False,
            "shiftBreakCorrections": True,
            "locationAllocatedCorrections": True,
            "atomicTimesheetChanges": True,
            "manualShiftRows": True,
            "shiftExclusions": True,
        },
        "breakPolicy": {
            "tracked": False,
            "correctionSupported": True,
            "label": "Descanso corregible",
            "message": (
                "El reloj actual no guarda minutos de descanso; "
                "Mayra puede registrarlos como corrección."
            ),
        },
        "employees": filtered_employees,
        "summary": {
            "employeeCount": len(filtered_employees),
            "activeEmployeeCount": sum(
                1 for employee in filtered_employees if employee["active"]
            ),
            "employeesWithHours": sum(
                1 for employee in filtered_employees if employee["totalMinutes"] > 0
            ),
            "totalMinutes": total_minutes,
            "totalHours": round(total_minutes / 60, 2),
            "completedShiftCount": sum(
                int(employee["completedShiftCount"])
                for employee in filtered_employees
            ),
            "overlappingShiftCount": sum(
                int(employee["overlappingShiftCount"])
                for employee in filtered_employees
            ),
            "correctionCount": sum(
                int(employee["correctionCount"])
                for employee in filtered_employees
            ),
            "issueCount": sum(len(employee["issues"]) for employee in filtered_employees),
            "hasBlockingIssues": any(
                bool(employee["issues"]) for employee in filtered_employees
            ),
        },
        "weeklyHoursSummary": weekly_hours["summary"],
    }


def _payroll_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _payroll_hours_to_minutes(value: Any) -> int:
    try:
        hours = Decimal(str(value or 0))
    except (InvalidOperation, TypeError, ValueError):
        return 0
    if not hours.is_finite():
        return 0
    return int(
        (hours * Decimal(60)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )


def _payroll_optional_money_total(values: List[Any]) -> Optional[float]:
    cents_values: List[int] = []
    for value in values:
        cents = _profitability_money_cents(value)
        if cents is None:
            return None
        cents_values.append(cents)
    return round(sum(cents_values) / 100, 2)


def _payroll_signed_money(cents: Optional[int]) -> Optional[float]:
    if cents is None:
        return None
    return round(int(cents) / 100, 2)


def _payroll_signed_money_cents(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not amount.is_finite():
        return None
    return int(
        (amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100)
        .to_integral_value()
    )


def _payroll_delta_labor_cost_cents(
    delta_minutes: int,
    hourly_rate: Any,
) -> Optional[int]:
    if hourly_rate is None:
        return None
    try:
        rate = Decimal(str(hourly_rate))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not rate.is_finite() or rate < 0:
        return None
    return int(
        (
            rate
            * Decimal(int(delta_minutes))
            * Decimal(100)
            / Decimal(60)
        ).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )


def _payroll_correction_rate_for_allocation(
    cur: Any,
    employee_id: int,
    correction_date: Any,
    location_id: int,
    live_hourly_rate: Any,
) -> Tuple[Any, bool, bool]:
    """Rate to price a correction at, preferring the rate the work was worked at.

    A correction adjusts hours that were already worked, so pricing it from the
    live employee rate would restate history the moment someone gets a raise --
    the exact defect the per-shift snapshot exists to prevent. Corrections are
    keyed by employee + date (never by shift), so the shift's rate has to be
    resolved from that day's shifts.

    Each overlapping shift contributes its effective rate: a snapshotted shift
    is frozen at its worked rate; a NULL-snapshot shift is not frozen, so it
    follows the live rate (unknown only when the employee has no live rate).

    Precedence, decided over the IN-SCOPE shifts only (the shifts that worked
    this allocation's site if any did, otherwise the whole day -- an out-of-scope
    site's shifts never influence the result):
      1. Mixed frozen + live in scope -> FAIL CLOSED. The delta-minutes cannot
         be attributed to the frozen vs the live shift, and treating it as live
         would let a rate edit restate the frozen shift's portion.
      2. All frozen and agreeing on one rate -> FROZEN at that rate.
      3. All frozen but disagreeing -> FAIL CLOSED.
      4. All live -> LIVE-tracked at the live rate (they all follow the one live
         rate, so they never disagree); when no live rate is configured yet this
         is the rate-less state -- live-tracked and unknown until a rate is set.

    A shift is "on that day" when its effective worked interval OVERLAPS the
    correction's local day, not merely when its clock-in local_date equals it: a
    shift crossing local midnight has its minutes attributed to both day slices
    by weekly payroll (via _iter_payroll_local_day_slices), so a correction on
    the spillover day must see that shift's rate. Corrected clock times take
    precedence over the raw ones, matching _effective_payroll_shift_row.

    Returns (rate, resolved, from_snapshot). ``resolved`` is False only for the
    fail-closed case, which the caller must not paper over with the live rate.
    ``from_snapshot`` is True only when the rate is genuinely frozen -- every
    in-scope shift carried a snapshot. When it is False but ``resolved`` is True,
    the rate came from the live employee rate (no snapshot in scope, or a
    NULL-snapshot shift is in scope), so the caller must NOT freeze the cost:
    such an allocation has to keep tracking the live rate, exactly as the
    NULL-snapshot shift's own labor does, or a later rate edit would move the
    shift labor while the correction stayed frozen.
    """
    if not isinstance(correction_date, date):
        correction_date = datetime.strptime(str(correction_date), "%Y-%m-%d").date()
    # Local-day bounds as UTC instants. A shift overlaps this local day iff it
    # started before the day ended and had not yet ended when the day began --
    # exactly the condition under which _iter_payroll_local_day_slices emits a
    # slice for this day.
    day_start_utc = datetime.combine(
        correction_date, clock_time.min, tzinfo=APP_TIMEZONE
    ).astimezone(timezone.utc)
    day_end_utc = datetime.combine(
        correction_date + timedelta(days=1), clock_time.min, tzinfo=APP_TIMEZONE
    ).astimezone(timezone.utc)
    # Each overlapping shift, its snapshot rate, and the full set of sites it
    # actually worked: its home location plus every visit's location. A
    # multi-stop shift homed at A that visits B genuinely worked at B, and
    # weekly profitability attributes those minutes to the visit sites, so a
    # correction at B must see this shift's rate too -- keying only on the home
    # location_id would miss it.
    # ALL overlapping shifts, snapshot or not. A NULL-snapshot shift is not
    # frozen -- it is priced from the live rate everywhere else -- so it must
    # participate here too: if the employee worked a frozen $20 shift and a
    # NULL-snapshot shift on the same site/day and the live rate has since moved
    # to $25, the day's effective rates disagree and the correction must fail
    # closed rather than confidently return $20.
    cur.execute(
        """
        SELECT s.id,
               s.hourly_rate_cents,
               ARRAY_REMOVE(
                   ARRAY_APPEND(
                       ARRAY_AGG(DISTINCT v.location_id),
                       s.location_id
                   ),
                   NULL
               ) AS worked_location_ids
        FROM shifts s
        LEFT JOIN LATERAL (
            SELECT corrected_clock_in, corrected_clock_out
            FROM payroll_shift_corrections psc
            WHERE psc.shift_id = s.id AND psc.status = 'active'
            LIMIT 1
        ) corr ON TRUE
        LEFT JOIN visits v ON v.shift_id = s.id
        WHERE s.employee_id = %s
          AND COALESCE(corr.corrected_clock_in, s.clock_in) < %s
          AND (
                COALESCE(corr.corrected_clock_out, s.clock_out) IS NULL
                OR COALESCE(corr.corrected_clock_out, s.clock_out) > %s
          )
        GROUP BY s.id, s.hourly_rate_cents, s.location_id
        """,
        (int(employee_id), day_end_utc, day_start_utc),
    )
    rows = cur.fetchall() or []
    if not rows:
        # No shift on that day: live rate, not frozen.
        return live_hourly_rate, True, False

    def _worked_here(row: Any) -> bool:
        return int(location_id) in {
            int(loc) for loc in (row.get("worked_location_ids") or [])
        }

    # Scope FIRST: the shifts that worked this allocation's site when any did;
    # otherwise the whole day. Everything below is decided over this scope only
    # -- an out-of-scope site's shifts must never influence the classification.
    scope = [row for row in rows if _worked_here(row)] or rows

    # Partition the scope into frozen (snapshotted) and live (NULL-snapshot)
    # shifts. A snapshotted shift is frozen at its worked rate; a NULL-snapshot
    # shift is not frozen -- it follows the live rate, so it moves on the next
    # rate edit.
    frozen_rates: set = set()
    has_frozen = False
    has_live = False
    for row in scope:
        cents = row.get("hourly_rate_cents")
        if cents is not None:
            has_frozen = True
            frozen_rates.add(Decimal(int(cents)) / Decimal(100))
        else:
            has_live = True

    # Mixed frozen + live in scope: the correction's delta-minutes cannot be
    # attributed to the frozen vs the live shift, and marking it live-tracked
    # would let a later rate edit restate the frozen shift's portion. Fail
    # closed -- unknown, never a confident guess that moves frozen history.
    if has_frozen and has_live:
        return None, False, False

    # All frozen: genuinely freezable only when the snapshots agree on one rate.
    if has_frozen:
        if len(frozen_rates) == 1:
            return frozen_rates.pop(), True, True
        return None, False, False

    # All live (or empty scope, which cannot happen here since rows is
    # non-empty). Live shifts all follow the one live rate, so they never
    # disagree. When the live rate is unknown (a NULL-snapshot shift and no
    # configured rate) this is the pre-migration / rate-less state: live-tracked
    # and unknown until a rate is set -- resolved True, not frozen, rate may be
    # None, which the caller stores as NULL + is_live and values at the live
    # recompute.
    return live_hourly_rate, True, False


def _payroll_correction_allocation_cost(
    delta_minutes: int,
    rate: Any,
    resolved: bool,
    from_snapshot: bool,
) -> Tuple[Optional[int], bool]:
    """Map a resolver verdict to (stored_labor_cost_cents, is_live).

    - Snapshot rate -> freeze the computed cents (is_live False).
    - Live-rate fallback (resolved but not from a snapshot) -> store NULL and
      mark is_live, so the allocation is valued at the live recompute and tracks
      later rate edits, consistent with its NULL-snapshot shift's own labor.
    - Fail-closed (unresolved) -> store NULL, not live: cost is unknown and the
      allocation reads incomplete for review.
    """
    if resolved and from_snapshot:
        return _payroll_delta_labor_cost_cents(delta_minutes, rate), False
    if resolved:
        return None, True
    return None, False


def _payroll_correction_candidate_sites(
    candidate_segments: List[Dict[str, Any]],
    correction_date: str,
    employee_id: int,
) -> List[Dict[str, Any]]:
    sites_by_key: Dict[Tuple[Any, Any, str, str], Dict[str, Any]] = {}
    for segment in candidate_segments:
        if segment.get("includedInProfitability") is False:
            continue
        if str(segment.get("date") or "") != correction_date:
            continue
        if int(segment.get("employeeId") or 0) != employee_id:
            continue
        location_id = segment.get("locationId")
        if location_id is None:
            continue

        key = (
            location_id,
            segment.get("customerId"),
            str(segment.get("customerName") or ""),
            str(segment.get("siteAddress") or ""),
        )
        site_row = sites_by_key.setdefault(
            key,
            {
                "locationId": location_id,
                "customerId": segment.get("customerId"),
                "customerName": segment.get("customerName"),
                "siteAddress": segment.get("siteAddress"),
                "actualHours": 0.0,
                "_laborValues": [],
                "_siteSegmentKeys": set(),
                "_jobsById": {},
            },
        )
        site_segment_key = str(
            segment.get("siteSegmentKey")
            or segment.get("segmentKey")
            or json.dumps(segment, sort_keys=True, default=str)
        )
        if site_segment_key not in site_row["_siteSegmentKeys"]:
            site_row["_siteSegmentKeys"].add(site_segment_key)
            site_row["actualHours"] += _payroll_float(segment.get("actualHours"))
            site_row["_laborValues"].append(segment.get("actualLaborCost"))

        job_id = segment.get("jobId")
        if job_id is None:
            continue
        job_row = site_row["_jobsById"].setdefault(
            int(job_id),
            {
                "jobId": int(job_id),
                "scheduledDate": segment.get("scheduledDate"),
                "profitabilityDate": segment.get("profitabilityDate"),
                "revenueRecognitionDate": segment.get("revenueRecognitionDate"),
                "actualHours": 0.0,
                "_laborValues": [],
            },
        )
        job_row["actualHours"] += _payroll_float(segment.get("actualHours"))
        job_row["_laborValues"].append(segment.get("actualLaborCost"))

    candidates: List[Dict[str, Any]] = []
    for site_row in sites_by_key.values():
        jobs = []
        for job_row in site_row["_jobsById"].values():
            labor_values = list(job_row.pop("_laborValues"))
            job_row["actualHours"] = round(_payroll_float(job_row["actualHours"]), 2)
            job_row["actualLaborCost"] = _payroll_optional_money_total(labor_values)
            job_row["laborCostComplete"] = all(value is not None for value in labor_values)
            jobs.append(job_row)
        labor_values = list(site_row.pop("_laborValues"))
        site_row.pop("_siteSegmentKeys")
        site_row.pop("_jobsById")
        site_row["actualHours"] = round(_payroll_float(site_row["actualHours"]), 2)
        site_row["actualLaborCost"] = _payroll_optional_money_total(labor_values)
        site_row["laborCostComplete"] = all(value is not None for value in labor_values)
        site_row["jobCount"] = len(jobs)
        site_row["jobs"] = sorted(
            jobs,
            key=lambda job: (
                str(job.get("scheduledDate") or ""),
                int(job.get("jobId") or 0),
            ),
        )
        candidates.append(site_row)
    candidates.sort(
        key=lambda site: (
            str(site.get("customerName") or "").casefold(),
            str(site.get("siteAddress") or "").casefold(),
            int(site.get("locationId") or 0),
        )
    )
    return candidates


def _payroll_correction_details_by_date(
    weekly_hours: Dict[str, Any],
    candidate_segments: List[Dict[str, Any]],
    allocation_rows: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    details_by_date: Dict[str, List[Dict[str, Any]]] = {}
    allocations_by_correction_id = _payroll_correction_allocations_by_correction_id(
        allocation_rows
    )
    for employee in weekly_hours.get("employees") or []:
        employee_id = int(employee.get("employeeId") or 0)
        employee_name = str(employee.get("employeeName") or "")
        for day in employee.get("days") or []:
            correction = day.get("correction")
            if not correction:
                continue
            day_key = str(day.get("date") or "")
            if not day_key:
                continue
            candidate_sites = _payroll_correction_candidate_sites(
                candidate_segments,
                day_key,
                employee_id,
            )
            correction_id = int(correction["correctionId"])
            allocation_row = allocations_by_correction_id.get(correction_id)
            allocation = (
                _serialize_payroll_correction_allocation(allocation_row)
                if allocation_row
                else None
            )
            detail = {
                "correctionId": correction_id,
                "employeeId": employee_id,
                "employeeName": employee_name,
                "date": day_key,
                "allocationStatus": "allocated" if allocation else "unallocated",
                "sourceTotalMinutes": int(correction["sourceTotalMinutes"]),
                "sourceTotalHours": round(
                    int(correction["sourceTotalMinutes"]) / 60,
                    2,
                ),
                "correctedTotalMinutes": int(correction["correctedTotalMinutes"]),
                "correctedTotalHours": round(
                    int(correction["correctedTotalMinutes"]) / 60,
                    2,
                ),
                "deltaMinutes": int(correction["deltaMinutes"]),
                "deltaHours": round(int(correction["deltaMinutes"]) / 60, 2),
                "reason": str(correction["reason"]),
                "candidateSiteCount": len(candidate_sites),
                "candidateSites": candidate_sites,
            }
            if allocation:
                detail["allocation"] = allocation
                allocation_issue = _payroll_correction_allocation_issue(detail)
                detail["allocationValid"] = allocation_issue is None
                if allocation_issue:
                    detail["allocationStatus"] = "invalid"
                    detail["allocationIssue"] = allocation_issue
            details_by_date.setdefault(day_key, []).append(
                detail
            )
    return details_by_date


def _append_allocated_correction_to_profitability_site(
    site: Dict[str, Any],
    correction: Dict[str, Any],
) -> None:
    _append_allocated_correction_to_profitability_target(site, correction)
    allocation = correction.get("allocation") or {}
    job_id = allocation.get("jobId")
    if job_id is None:
        return
    for job in site.get("jobs") or []:
        if int(job.get("jobId") or 0) != int(job_id):
            continue
        _append_allocated_correction_to_profitability_target(job, correction)
        return


def _append_allocated_correction_to_profitability_target(
    target: Dict[str, Any],
    correction: Dict[str, Any],
) -> None:
    target.setdefault("allocatedCorrections", []).append(correction)
    target["allocatedCorrectionCount"] = len(target["allocatedCorrections"])
    _annotate_allocated_correction_adjusted_profitability(
        target,
        target["allocatedCorrections"],
    )


def _payroll_allocation_matches_candidate_target(
    correction: Dict[str, Any],
) -> bool:
    return _payroll_correction_allocation_issue(correction) is None


def _payroll_correction_allocation_issue(
    correction: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    allocation = correction.get("allocation") or {}
    location_id = allocation.get("locationId")
    if location_id is None:
        return {
            "code": "payroll_correction_allocation_target_missing",
            "message": "Payroll correction allocation is missing a selected Site.",
        }
    current_delta_minutes = int(correction.get("deltaMinutes") or 0)
    allocated_delta_minutes = int(allocation.get("allocatedDeltaMinutes") or 0)
    if allocated_delta_minutes != current_delta_minutes:
        return {
            "code": "payroll_correction_allocation_stale_delta",
            "message": (
                "Payroll correction allocation was saved for a different hour "
                "delta than the current clock evidence shows."
            ),
        }
    job_id = allocation.get("jobId")
    for site in correction.get("candidateSites") or []:
        if int(site.get("locationId") or 0) != int(location_id):
            continue
        if job_id is None:
            if _payroll_target_can_absorb_delta(
                target=site,
                delta_minutes=allocated_delta_minutes,
            ):
                return None
            return {
                "code": "payroll_correction_allocation_negative_target",
                "message": (
                    "Payroll correction allocation would make the selected Site "
                    "negative."
                ),
            }
        for job in site.get("jobs") or []:
            if int(job.get("jobId") or 0) != int(job_id):
                continue
            if _payroll_target_can_absorb_delta(
                target=job,
                delta_minutes=allocated_delta_minutes,
            ):
                return None
            return {
                "code": "payroll_correction_allocation_negative_target",
                "message": (
                    "Payroll correction allocation would make the selected job "
                    "negative."
                ),
            }
        return {
            "code": "payroll_correction_allocation_target_not_current_candidate",
            "message": (
                "Payroll correction allocation job is no longer a current "
                "profitability candidate."
            ),
        }
    return {
        "code": "payroll_correction_allocation_target_not_current_candidate",
        "message": (
            "Payroll correction allocation Site is no longer a current "
            "profitability candidate."
        ),
    }


def _payroll_target_can_absorb_delta(
    *,
    target: Dict[str, Any],
    delta_minutes: int,
) -> bool:
    return (
        delta_minutes >= 0
        or _payroll_hours_to_minutes(target.get("actualHours")) + delta_minutes >= 0
    )


def _attach_allocated_corrections_to_profitability_targets(
    result: Dict[str, Any],
    allocated_corrections: List[Dict[str, Any]],
) -> None:
    weekly_sites = {
        int(site.get("locationId") or 0): site
        for site in result.get("bySite") or []
        if site.get("locationId") is not None
    }
    days = {
        str(day.get("date") or ""): day
        for day in result.get("byDay") or []
        if isinstance(day, dict)
    }
    top_level_jobs = {
        int(job.get("jobId") or 0): job
        for job in result.get("jobs") or []
        if job.get("jobId") is not None
    }
    for correction in allocated_corrections:
        allocation = correction.get("allocation") or {}
        location_id = int(allocation.get("locationId") or 0)
        if location_id <= 0:
            continue
        job_id = allocation.get("jobId")
        if job_id is not None:
            top_level_job = top_level_jobs.get(int(job_id))
            if top_level_job:
                _append_allocated_correction_to_profitability_target(
                    top_level_job,
                    correction,
                )
        weekly_site = weekly_sites.get(location_id)
        if weekly_site:
            _append_allocated_correction_to_profitability_site(weekly_site, correction)
        day = days.get(str(correction.get("date") or ""))
        if not day:
            continue
        for site in day.get("sites") or []:
            if int(site.get("locationId") or 0) != location_id:
                continue
            _append_allocated_correction_to_profitability_site(site, correction)
            break


def _payroll_correction_labor_summary(
    corrections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    total_delta_minutes = sum(
        int((correction.get("allocation") or {}).get("allocatedDeltaMinutes") or 0)
        for correction in corrections
    )
    known_labor_cents = 0
    labor_incomplete = False
    for correction in corrections:
        allocation = correction.get("allocation") or {}
        # A frozen allocation (priced from a snapshot) drives the money figure
        # from its STORED cost, so a later rate edit cannot restate it. A
        # live-tracked allocation (its shift carried no snapshot, so its labor
        # follows the live rate) stores NULL and is valued at the live recompute,
        # staying consistent with that shift's own live-rate labor. Anything else
        # with no stored cost is a fail-closed unknown and reads incomplete.
        stored_cost = allocation.get("allocatedLaborCost")
        if stored_cost is not None:
            cost_source = stored_cost
        elif allocation.get("laborCostIsLive"):
            cost_source = allocation.get("currentAllocatedLaborCost")
        else:
            cost_source = None
        cost_cents = _payroll_signed_money_cents(cost_source)
        if cost_cents is None:
            labor_incomplete = True
            continue
        known_labor_cents += cost_cents
    return {
        "allocatedCorrectionDeltaMinutes": total_delta_minutes,
        "allocatedCorrectionDeltaHours": round(total_delta_minutes / 60, 2),
        "knownAllocatedCorrectionLaborCost": _payroll_signed_money(known_labor_cents),
        "allocatedCorrectionLaborCost": (
            None if labor_incomplete else _payroll_signed_money(known_labor_cents)
        ),
        "allocatedCorrectionLaborCostComplete": not labor_incomplete,
    }


def _payroll_signed_percent(
    numerator: Optional[int],
    denominator: Optional[int],
) -> Optional[float]:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator / denominator * 100, 1)


def _annotate_allocated_correction_adjusted_profitability(
    target: Dict[str, Any],
    allocated_corrections: List[Dict[str, Any]],
    *,
    include_correction_summary: bool = True,
) -> None:
    if not allocated_corrections:
        return

    correction_summary = _payroll_correction_labor_summary(allocated_corrections)
    if include_correction_summary:
        target.update(correction_summary)

    adjusted_actual_hours = round(
        _payroll_float(target.get("actualHours"))
        + int(correction_summary["allocatedCorrectionDeltaMinutes"]) / 60,
        2,
    )
    target["adjustedActualHours"] = adjusted_actual_hours

    planned_hours = target.get("plannedHours")
    if planned_hours is not None and bool(target.get("plannedHoursComplete", True)):
        target["adjustedVarianceHours"] = round(
            adjusted_actual_hours - _payroll_float(planned_hours),
            2,
        )
    else:
        target["adjustedVarianceHours"] = None

    known_base_labor_cents = _payroll_signed_money_cents(
        target.get("knownActualLaborCost")
    )
    if known_base_labor_cents is None:
        known_base_labor_cents = (
            _payroll_signed_money_cents(target.get("actualLaborCost")) or 0
        )
    known_correction_labor_cents = (
        _payroll_signed_money_cents(
            correction_summary["knownAllocatedCorrectionLaborCost"]
        )
        or 0
    )
    target["knownAdjustedActualLaborCost"] = _payroll_signed_money(
        known_base_labor_cents + known_correction_labor_cents
    )

    base_labor_cents = _payroll_signed_money_cents(target.get("actualLaborCost"))
    base_labor_complete = (
        base_labor_cents is not None and bool(target.get("laborCostComplete", True))
    )
    correction_labor_cents = _payroll_signed_money_cents(
        correction_summary["allocatedCorrectionLaborCost"]
    )
    adjusted_labor_complete = (
        base_labor_complete
        and correction_labor_cents is not None
        and bool(correction_summary["allocatedCorrectionLaborCostComplete"])
    )
    adjusted_labor_cents: Optional[int] = (
        base_labor_cents + correction_labor_cents
        if adjusted_labor_complete and base_labor_cents is not None
        else None
    )
    target["adjustedActualLaborCost"] = _payroll_signed_money(adjusted_labor_cents)
    target["adjustedLaborCostComplete"] = adjusted_labor_complete

    revenue_cents = _profitability_money_cents(target.get("revenue"))
    adjusted_net_cents = (
        revenue_cents - adjusted_labor_cents
        if revenue_cents is not None and adjusted_labor_cents is not None
        else None
    )
    target["adjustedNetProfit"] = _payroll_signed_money(adjusted_net_cents)
    target["adjustedGrossMarginPct"] = _payroll_signed_percent(
        adjusted_net_cents,
        revenue_cents,
    )
    adjusted_labor_pct = _payroll_signed_percent(
        adjusted_labor_cents,
        revenue_cents,
    )
    target["adjustedActualLaborPct"] = adjusted_labor_pct
    target_labor_pct = target.get("targetLaborPct")
    if adjusted_labor_pct is not None and target_labor_pct is not None:
        target["adjustedLaborTargetVariancePct"] = round(
            adjusted_labor_pct - _payroll_float(target_labor_pct),
            1,
        )
    else:
        target["adjustedLaborTargetVariancePct"] = None


def _payroll_issue_rows_by_date(
    weekly_hours: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    issues_by_date: Dict[str, List[Dict[str, Any]]] = {}
    for employee in weekly_hours.get("employees") or []:
        employee_id = int(employee.get("employeeId") or 0)
        employee_name = str(employee.get("employeeName") or "")
        for issue in employee.get("issues") or []:
            day_key = str(issue.get("date") or "")
            if not day_key:
                continue
            issues_by_date.setdefault(day_key, []).append(
                {
                    "code": str(issue.get("code") or ""),
                    "message": str(issue.get("message") or ""),
                    "shiftId": issue.get("shiftId"),
                    "employeeId": employee_id,
                    "employeeName": employee_name,
                }
            )
    return issues_by_date


def _append_daily_profitability_issue(
    day: Dict[str, Any],
    issue: Dict[str, Any],
) -> None:
    issues = day.setdefault("issues", [])
    issues.append(issue)
    day["issueCount"] = int(day.get("issueCount") or 0) + 1


def _annotate_labor_profitability_daily_payroll_proof(
    result: Dict[str, Any],
    weekly_hours: Dict[str, Any],
    candidate_segments: List[Dict[str, Any]],
    allocation_rows: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    corrections_by_date = _payroll_correction_details_by_date(
        weekly_hours,
        candidate_segments,
        allocation_rows,
    )
    payroll_issues_by_date = _payroll_issue_rows_by_date(weekly_hours)
    all_corrections = [
        correction
        for rows in corrections_by_date.values()
        for correction in rows
    ]
    unallocated_corrections: List[Dict[str, Any]] = [
        correction
        for correction in all_corrections
        if correction.get("allocationStatus") == "unallocated"
    ]
    invalid_allocated_corrections: List[Dict[str, Any]] = [
        correction
        for correction in all_corrections
        if correction.get("allocationStatus") == "invalid"
    ]
    allocated_corrections: List[Dict[str, Any]] = [
        correction
        for correction in all_corrections
        if correction.get("allocationStatus") == "allocated"
    ]
    summary = result.setdefault("summary", {})
    summary["unallocatedCorrectionCount"] = len(unallocated_corrections)
    summary["invalidAllocationCount"] = len(invalid_allocated_corrections)
    summary["allocatedCorrectionCount"] = len(allocated_corrections)
    summary.update(_payroll_correction_labor_summary(allocated_corrections))
    profitability_allocated_corrections = [
        correction
        for correction in allocated_corrections
        if _payroll_allocation_matches_candidate_target(correction)
    ]
    _annotate_allocated_correction_adjusted_profitability(
        summary,
        profitability_allocated_corrections,
        include_correction_summary=False,
    )
    for day in result.get("byDay") or []:
        if not isinstance(day, dict):
            continue
        day_key = str(day.get("date") or "")
        correction_rows = corrections_by_date.get(day_key, [])
        day_unallocated_corrections = [
            correction
            for correction in correction_rows
            if correction.get("allocationStatus") == "unallocated"
        ]
        day_invalid_allocated_corrections = [
            correction
            for correction in correction_rows
            if correction.get("allocationStatus") == "invalid"
        ]
        day_allocated_corrections = [
            correction
            for correction in correction_rows
            if correction.get("allocationStatus") == "allocated"
        ]
        payroll_issues = payroll_issues_by_date.get(day_key, [])
        day["unallocatedCorrectionCount"] = len(day_unallocated_corrections)
        day["unallocatedCorrections"] = day_unallocated_corrections
        day["invalidAllocationCount"] = len(day_invalid_allocated_corrections)
        day["invalidAllocatedCorrections"] = day_invalid_allocated_corrections
        day["allocatedCorrectionCount"] = len(day_allocated_corrections)
        day["allocatedCorrections"] = day_allocated_corrections
        day.update(_payroll_correction_labor_summary(day_allocated_corrections))
        day_profitability_allocated_corrections = [
            correction
            for correction in day_allocated_corrections
            if _payroll_allocation_matches_candidate_target(correction)
        ]
        _annotate_allocated_correction_adjusted_profitability(
            day,
            day_profitability_allocated_corrections,
            include_correction_summary=False,
        )
        day["payrollIssueCount"] = len(payroll_issues)
        for payroll_issue in payroll_issues:
            _append_daily_profitability_issue(day, payroll_issue)
        if day_invalid_allocated_corrections:
            issue_code = "payroll_hour_corrections_invalid_allocations"
            if not any(issue.get("code") == issue_code for issue in day.get("issues") or []):
                _append_daily_profitability_issue(
                    day,
                    {
                        "code": issue_code,
                        "message": (
                            "One or more payroll hour correction allocations no "
                            "longer match the current profitability proof."
                        ),
                    },
                )
        if len(day_unallocated_corrections) <= 0:
            continue
        issue_code = "payroll_hour_corrections_not_allocated_to_sites"
        if not any(issue.get("code") == issue_code for issue in day.get("issues") or []):
            _append_daily_profitability_issue(
                day,
                {
                    "code": issue_code,
                    "message": (
                        "Payroll hour corrections adjust employee/day totals, but "
                        "do not identify which customer or Site should receive the "
                        "labor adjustment yet."
                    ),
                },
            )
    _attach_allocated_corrections_to_profitability_targets(
        result,
        profitability_allocated_corrections,
    )
    return {
        "allocated": allocated_corrections,
        "invalid": invalid_allocated_corrections,
        "unallocated": unallocated_corrections,
    }


def _lock_payroll_verification_week(cur: Any, week_start: date) -> None:
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))",
        (f"{PAYROLL_VERIFICATION_LOCK_PREFIX}:{week_start.isoformat()}",),
    )


def _lock_payroll_source_rows(cur: Any) -> None:
    cur.execute(
        """
        LOCK TABLE
            shifts,
            payroll_shift_corrections,
            payroll_hour_corrections,
            payroll_hour_correction_allocations,
            payroll_timesheet_change_batches,
            payroll_manual_shift_versions,
            payroll_shift_exclusions,
            employees
        IN SHARE MODE
        """
    )


def _lock_payroll_money_source_rows(cur: Any) -> None:
    # Superset of the hours source lock: the money fingerprint also hashes each
    # shift's location/customer LABELS (joined from locations/customers) and the
    # allocation-validity payload derived from job candidates (which reads
    # `jobs`). All of those tables must be locked or a concurrent Site/job edit
    # could commit between the proof read and the verification/finalize commit,
    # persisting an already-stale money proof.
    cur.execute(
        """
        LOCK TABLE
            shifts,
            payroll_shift_corrections,
            payroll_hour_corrections,
            payroll_hour_correction_allocations,
            employees,
            locations,
            customers,
            jobs
        IN SHARE MODE
        """
    )


def _lock_payroll_correction_write_tables(cur: Any) -> None:
    cur.execute(
        """
        LOCK TABLE
            payroll_shift_corrections,
            payroll_hour_corrections,
            payroll_hour_correction_allocations,
            payroll_timesheet_change_batches,
            payroll_manual_shift_versions,
            payroll_shift_exclusions
        IN SHARE ROW EXCLUSIVE MODE
        """
    )


def _get_payroll_verification_batch(
    cur: Any,
    week_start: date,
    *,
    lock: bool = False,
) -> Optional[Dict[str, Any]]:
    lock_clause = " FOR UPDATE" if lock else ""
    cur.execute(
        f"""
        SELECT *
        FROM payroll_verification_batches
        WHERE week_start = %s
        {lock_clause}
        """,
        (week_start,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def _payroll_verification_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return to_utc_iso(value)
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _payroll_verification_state(
    row: Optional[Dict[str, Any]],
    *,
    current_source_fingerprint: Optional[str] = None,
) -> Dict[str, Any]:
    if row is None:
        return {
            "status": "unverified",
            "batchId": None,
            "sourceFingerprint": None,
            "stale": False,
            "verifiedAt": None,
            "verifiedByName": None,
            "reopenedAt": None,
            "reopenedByName": None,
            "reopenedReason": None,
            "finalizedAt": None,
            "finalizedByName": None,
        }

    source_fingerprint = str(row["source_fingerprint"])
    stale = (
        current_source_fingerprint is not None
        and not hmac.compare_digest(source_fingerprint, current_source_fingerprint)
    )
    return {
        "status": str(row["status"]),
        "batchId": int(row["id"]),
        "sourceFingerprint": source_fingerprint,
        "stale": stale,
        "verifiedAt": _payroll_verification_iso(row.get("verified_at")),
        "verifiedByName": str(row["verified_by_name"]),
        "reopenedAt": _payroll_verification_iso(row.get("reopened_at")),
        "reopenedByName": (
            str(row["reopened_by_name"])
            if row.get("reopened_by_name") is not None
            else None
        ),
        "reopenedReason": row.get("reopened_reason"),
        "finalizedAt": _payroll_verification_iso(row.get("finalized_at")),
        "finalizedByName": (
            str(row["finalized_by_name"])
            if row.get("finalized_by_name") is not None
            else None
        ),
    }


def _insert_payroll_verification_event(
    cur: Any,
    *,
    batch_row: Dict[str, Any],
    action: str,
    actor: Dict[str, Any],
    reason: str,
    before_state: Optional[Dict[str, Any]],
    after_state: Dict[str, Any],
) -> None:
    cur.execute(
        """
        INSERT INTO payroll_verification_events (
            batch_id,
            week_start,
            action,
            actor_employee_id,
            actor_name,
            reason,
            source_fingerprint,
            before_state,
            after_state
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
        """,
        (
            int(batch_row["id"]),
            batch_row["week_start"],
            action,
            int(actor["id"]),
            str(actor["name"]),
            reason.strip(),
            str(batch_row["source_fingerprint"]),
            json.dumps(before_state, sort_keys=True) if before_state is not None else None,
            json.dumps(after_state, sort_keys=True),
        ),
    )


def _insert_payroll_verification_batch(
    cur: Any,
    *,
    data: Dict[str, Any],
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        INSERT INTO payroll_verification_batches (
            week_start,
            week_end,
            timezone,
            status,
            source_fingerprint,
            snapshot,
            verified_by_employee_id,
            verified_by_name
        )
        VALUES (%s, %s, %s, 'verified', %s, %s::jsonb, %s, %s)
        RETURNING *
        """,
        (
            data["weekStart"],
            data["weekEnd"],
            data["timezone"],
            data["sourceFingerprint"],
            json.dumps(data, sort_keys=True),
            int(actor["id"]),
            str(actor["name"]),
        ),
    )
    return dict(cur.fetchone())


def _update_payroll_verification_batch(
    cur: Any,
    *,
    batch_id: int,
    data: Dict[str, Any],
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        UPDATE payroll_verification_batches
        SET
            week_end = %s,
            timezone = %s,
            status = 'verified',
            source_fingerprint = %s,
            snapshot = %s::jsonb,
            verified_by_employee_id = %s,
            verified_by_name = %s,
            verified_at = NOW(),
            finalized_by_employee_id = NULL,
            finalized_by_name = NULL,
            finalized_at = NULL,
            updated_at = NOW()
        WHERE id = %s
        RETURNING *
        """,
        (
            data["weekEnd"],
            data["timezone"],
            data["sourceFingerprint"],
            json.dumps(data, sort_keys=True),
            int(actor["id"]),
            str(actor["name"]),
            batch_id,
        ),
    )
    return dict(cur.fetchone())


def _ensure_payroll_snapshot_current(
    payload_fingerprint: str,
    data: Dict[str, Any],
    action: str,
) -> None:
    if not hmac.compare_digest(payload_fingerprint, data["sourceFingerprint"]):
        raise HTTPException(
            status_code=409,
            detail=f"Payroll weekly hours changed; refresh before {action}",
        )


def _ensure_payroll_snapshot_has_no_blocking_issues(data: Dict[str, Any], action: str) -> None:
    if data["summary"]["hasBlockingIssues"]:
        raise HTTPException(
            status_code=409,
            detail=f"Resolve payroll hour issues before {action}",
        )


# --- Money (payroll dollars) verification -----------------------------------
# A second, independent verification truth, mirroring the hours machinery above
# but keyed on the money-inclusive timesheet fingerprint
# (data["timesheetSourceFingerprint"]) and with NO finalized state -- the
# payroll-level FINALIZED lives on the hours batch (gated on a current money
# verification). Staleness is fingerprint-based, exactly like hours.

def _lock_payroll_money_verification_week(cur: Any, week_start: date) -> None:
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))",
        (f"{PAYROLL_MONEY_VERIFICATION_LOCK_PREFIX}:{week_start.isoformat()}",),
    )


def _get_payroll_money_verification_batch(
    cur: Any,
    week_start: date,
    *,
    lock: bool = False,
) -> Optional[Dict[str, Any]]:
    lock_clause = " FOR UPDATE" if lock else ""
    cur.execute(
        f"""
        SELECT *
        FROM payroll_money_verification_batches
        WHERE week_start = %s
        {lock_clause}
        """,
        (week_start,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def _payroll_money_verification_state(
    row: Optional[Dict[str, Any]],
    *,
    current_money_fingerprint: Optional[str] = None,
) -> Dict[str, Any]:
    if row is None:
        return {
            "status": "unverified",
            "batchId": None,
            "moneyFingerprint": None,
            "stale": False,
            "verifiedAt": None,
            "verifiedByName": None,
            "reopenedAt": None,
            "reopenedByName": None,
            "reopenedReason": None,
        }

    money_fingerprint = str(row["source_fingerprint"])
    stale = (
        current_money_fingerprint is not None
        and not hmac.compare_digest(money_fingerprint, current_money_fingerprint)
    )
    return {
        "status": str(row["status"]),
        "batchId": int(row["id"]),
        "moneyFingerprint": money_fingerprint,
        "stale": stale,
        "verifiedAt": _payroll_verification_iso(row.get("verified_at")),
        "verifiedByName": str(row["verified_by_name"]),
        "reopenedAt": _payroll_verification_iso(row.get("reopened_at")),
        "reopenedByName": (
            str(row["reopened_by_name"])
            if row.get("reopened_by_name") is not None
            else None
        ),
        "reopenedReason": row.get("reopened_reason"),
    }


def _insert_payroll_money_verification_event(
    cur: Any,
    *,
    batch_row: Dict[str, Any],
    action: str,
    actor: Dict[str, Any],
    reason: str,
    before_state: Optional[Dict[str, Any]],
    after_state: Dict[str, Any],
) -> None:
    cur.execute(
        """
        INSERT INTO payroll_money_verification_events (
            batch_id,
            week_start,
            action,
            actor_employee_id,
            actor_name,
            reason,
            source_fingerprint,
            before_state,
            after_state
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
        """,
        (
            int(batch_row["id"]),
            batch_row["week_start"],
            action,
            int(actor["id"]),
            str(actor["name"]),
            reason.strip(),
            str(batch_row["source_fingerprint"]),
            json.dumps(before_state, sort_keys=True) if before_state is not None else None,
            json.dumps(after_state, sort_keys=True),
        ),
    )


def _insert_payroll_money_verification_batch(
    cur: Any,
    *,
    data: Dict[str, Any],
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        INSERT INTO payroll_money_verification_batches (
            week_start,
            week_end,
            timezone,
            status,
            source_fingerprint,
            snapshot,
            verified_by_employee_id,
            verified_by_name
        )
        VALUES (%s, %s, %s, 'verified', %s, %s::jsonb, %s, %s)
        RETURNING *
        """,
        (
            data["weekStart"],
            data["weekEnd"],
            data["timezone"],
            data["timesheetSourceFingerprint"],
            json.dumps(data, sort_keys=True),
            int(actor["id"]),
            str(actor["name"]),
        ),
    )
    return dict(cur.fetchone())


def _update_payroll_money_verification_batch(
    cur: Any,
    *,
    batch_id: int,
    data: Dict[str, Any],
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        UPDATE payroll_money_verification_batches
        SET
            week_end = %s,
            timezone = %s,
            status = 'verified',
            source_fingerprint = %s,
            snapshot = %s::jsonb,
            verified_by_employee_id = %s,
            verified_by_name = %s,
            verified_at = NOW(),
            updated_at = NOW()
        WHERE id = %s
        RETURNING *
        """,
        (
            data["weekEnd"],
            data["timezone"],
            data["timesheetSourceFingerprint"],
            json.dumps(data, sort_keys=True),
            int(actor["id"]),
            str(actor["name"]),
            batch_id,
        ),
    )
    return dict(cur.fetchone())


def _ensure_payroll_money_snapshot_current(
    payload_fingerprint: str,
    data: Dict[str, Any],
    action: str,
) -> None:
    if not hmac.compare_digest(payload_fingerprint, data["timesheetSourceFingerprint"]):
        raise HTTPException(
            status_code=409,
            detail=f"Payroll dollars changed; refresh before {action}",
        )


def _ensure_hours_verified_and_current(
    cur: Any,
    week_start: date,
    hours_data: Dict[str, Any],
    action: str,
) -> None:
    """Money can only be signed off on top of a CURRENT hours sign-off. Requires
    the hours batch to be a settled verified state ('verified', or 'finalized' --
    which is only reachable from verified) with a fingerprint matching the freshly
    recomputed hours snapshot; otherwise the dollars would rest on hours nobody
    has reviewed (or that changed since). Accepting 'finalized' lets a settled
    week be money-verified (e.g. back-verifying a week finalized before money
    verification existed) without a needless reopen."""
    hours_row = _get_payroll_verification_batch(cur, week_start)
    if hours_row is None or str(hours_row["status"]) not in ("verified", "finalized"):
        raise HTTPException(
            status_code=409,
            detail=f"Verify the payroll week's hours before {action}",
        )
    if not hmac.compare_digest(
        str(hours_row["source_fingerprint"]), hours_data["sourceFingerprint"]
    ):
        raise HTTPException(
            status_code=409,
            detail=f"Payroll hours changed since they were verified; "
            f"reopen and verify hours before {action}",
        )


def _ensure_payroll_money_signed_off(
    cur: Any,
    week_start: date,
    money_row: Optional[Dict[str, Any]],
) -> None:
    """The whole-payroll FINALIZED state requires a CURRENT money sign-off: money
    must be 'verified' with a fingerprint matching the freshly recomputed payroll
    dollars. Enforced on BOTH the fresh finalize and the idempotent re-finalize of
    an already-finalized week, so a week whose money was reopened (or went stale)
    after finalize is never (re-)reported as settled."""
    timesheet = _compute_payroll_timesheet(week_start.isoformat(), cursor=cur)
    if money_row is None or str(money_row["status"]) != "verified":
        raise HTTPException(
            status_code=409,
            detail="Verify payroll dollars before finalizing",
        )
    if not hmac.compare_digest(
        str(money_row["source_fingerprint"]),
        timesheet["timesheetSourceFingerprint"],
    ):
        raise HTTPException(
            status_code=409,
            detail="Payroll dollars are stale; reopen and verify money before finalizing",
        )


def _parse_payroll_correction_date(date_text: str, week_start: date) -> date:
    try:
        correction_date = datetime.strptime(date_text, "%Y-%m-%d").date()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid correction date, use YYYY-MM-DD") from exc
    if not (week_start <= correction_date < week_start + timedelta(days=7)):
        raise HTTPException(status_code=400, detail="Correction date must fall inside the payroll week")
    return correction_date


def _parse_payroll_shift_correction_datetime(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name}, use ISO datetime",
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=APP_TIMEZONE)
    return parsed.astimezone(timezone.utc)


def _ensure_payroll_shift_correction_dates(
    *,
    week_start: date,
    correction_date: date,
    corrected_clock_in: datetime,
    corrected_clock_out: datetime,
    observed_at: datetime,
) -> None:
    if corrected_clock_out <= corrected_clock_in:
        raise HTTPException(
            status_code=400,
            detail="Corrected clock-out must be after corrected clock-in",
        )
    if corrected_clock_out > observed_at + timedelta(minutes=5):
        raise HTTPException(
            status_code=400,
            detail="Corrected clock-out cannot be in the future",
        )
    local_clock_in_date = to_local(corrected_clock_in).date()
    local_clock_out_date = to_local(corrected_clock_out).date()
    if local_clock_in_date != correction_date:
        raise HTTPException(
            status_code=400,
            detail="Corrected clock-in must stay on the correction date",
        )
    if local_clock_out_date not in {
        correction_date,
        correction_date + timedelta(days=1),
    }:
        raise HTTPException(
            status_code=400,
            detail="Corrected clock-out must fall on the correction date or the next day",
        )
    _week_end, _week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
    if corrected_clock_out > week_end_utc:
        raise HTTPException(
            status_code=400,
            detail="Corrected clock-out must stay inside the selected payroll week",
        )


def _payroll_shift_source_work_date(shift_row: Dict[str, Any]) -> date:
    local_date = shift_row.get("local_date")
    if isinstance(local_date, date):
        return local_date
    if local_date:
        try:
            return datetime.strptime(str(local_date), "%Y-%m-%d").date()
        except ValueError:
            pass
    return to_local(shift_row["clock_in"]).date()


def _payroll_shift_dates_in_week(
    shift_row: Dict[str, Any],
    *,
    week_start_utc: datetime,
    week_end_utc: datetime,
    observed_at: datetime,
) -> set[date]:
    clock_in = shift_row["clock_in"].astimezone(timezone.utc)
    clock_out_value = shift_row.get("clock_out")
    clock_out = (
        clock_out_value.astimezone(timezone.utc)
        if clock_out_value is not None
        else observed_at.astimezone(timezone.utc)
    )
    overlap_start = max(clock_in, week_start_utc)
    overlap_end = min(clock_out, week_end_utc)
    if overlap_end <= overlap_start:
        return set()
    return {
        local_day
        for local_day, _seconds in _iter_payroll_local_day_slices(
            overlap_start,
            overlap_end,
        )
    }


def _ensure_payroll_shift_correction_source_date(
    shift_row: Dict[str, Any],
    correction_date: date,
) -> None:
    source_date = _payroll_shift_source_work_date(shift_row)
    if correction_date != source_date:
        raise HTTPException(
            status_code=400,
            detail="Correction date must match the source shift work date",
        )


def _ensure_shift_correction_void_keeps_single_open_shift(
    cur: Any,
    correction_row: Dict[str, Any],
) -> None:
    if correction_row.get("source_clock_out") is not None:
        return

    cur.execute(
        """
        SELECT id
        FROM shifts
        WHERE id = %s
          AND clock_out IS NULL
        FOR UPDATE
        """,
        (int(correction_row["shift_id"]),),
    )
    if cur.fetchone() is None:
        return

    cur.execute(
        """
        SELECT shift_row.id
        FROM shifts shift_row
        WHERE shift_row.employee_id = %s
          AND shift_row.id <> %s
          AND shift_row.clock_out IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM payroll_shift_corrections active_correction
              WHERE active_correction.shift_id = shift_row.id
                AND active_correction.status = 'active'
          )
        ORDER BY shift_row.clock_in DESC, shift_row.id DESC
        LIMIT 1
        FOR UPDATE OF shift_row
        """,
        (int(correction_row["employee_id"]), int(correction_row["shift_id"])),
    )
    if cur.fetchone() is None:
        return

    raise HTTPException(
        status_code=409,
        detail=(
            "Cannot void this correction while the employee has another open shift; "
            "clock out the current shift or correct it before voiding the older one"
        ),
    )


def _serialize_payroll_correction(row: Dict[str, Any]) -> Dict[str, Any]:
    corrected_minutes = int(row["corrected_total_minutes"])
    return {
        "correctionId": int(row["id"]),
        "weekStart": row["week_start"].isoformat(),
        "date": row["correction_date"].isoformat(),
        "employeeId": int(row["employee_id"]),
        "employeeName": str(row.get("employee_name") or ""),
        "correctedTotalMinutes": corrected_minutes,
        "correctedTotalHours": round(corrected_minutes / 60, 2),
        "reason": str(row["reason"]),
        "status": str(row["status"]),
        "createdByName": str(row["created_by_name"]),
        "createdAt": _payroll_verification_iso(row.get("created_at")),
        "voidedByName": (
            str(row["voided_by_name"])
            if row.get("voided_by_name") is not None
            else None
        ),
        "voidedReason": row.get("voided_reason"),
        "voidedAt": _payroll_verification_iso(row.get("voided_at")),
        "supersededBy": (
            int(row["superseded_by"])
            if row.get("superseded_by") is not None
            else None
        ),
    }


def _serialize_payroll_shift_correction(row: Dict[str, Any]) -> Dict[str, Any]:
    source_minutes = int(row["source_total_minutes"])
    corrected_minutes = int(row["corrected_total_minutes"])
    delta_minutes = corrected_minutes - source_minutes
    return {
        "correctionId": int(row["id"]),
        "weekStart": row["week_start"].isoformat(),
        "date": row["correction_date"].isoformat(),
        "employeeId": int(row["employee_id"]),
        "employeeName": str(row.get("employee_name") or ""),
        "shiftId": int(row["shift_id"]),
        "sourceClockIn": _payroll_timesheet_datetime(row["source_clock_in"]),
        "sourceClockOut": _payroll_timesheet_datetime(row.get("source_clock_out")),
        "sourceBreakMinutes": row.get("source_break_minutes"),
        "sourceTotalMinutes": source_minutes,
        "sourceTotalHours": round(source_minutes / 60, 2),
        "correctedClockIn": _payroll_timesheet_datetime(row["corrected_clock_in"]),
        "correctedClockOut": _payroll_timesheet_datetime(row["corrected_clock_out"]),
        "correctedBreakMinutes": int(row["corrected_break_minutes"]),
        "correctedTotalMinutes": corrected_minutes,
        "correctedTotalHours": round(corrected_minutes / 60, 2),
        "deltaMinutes": delta_minutes,
        "deltaHours": round(delta_minutes / 60, 2),
        "reason": str(row["reason"]),
        "status": str(row["status"]),
        "createdByName": str(row["created_by_name"]),
        "createdAt": _payroll_verification_iso(row.get("created_at")),
        "voidedByName": (
            str(row["voided_by_name"])
            if row.get("voided_by_name") is not None
            else None
        ),
        "voidedReason": row.get("voided_reason"),
        "voidedAt": _payroll_verification_iso(row.get("voided_at")),
        "supersededBy": (
            int(row["superseded_by"])
            if row.get("superseded_by") is not None
            else None
        ),
    }


def _payroll_correction_rows(
    week_start: date,
    *,
    cursor: Optional[Any] = None,
    active_only: bool = True,
) -> List[Dict[str, Any]]:
    status_clause = "AND correction.status = 'active'" if active_only else ""
    return _payroll_query_all(
        f"""
        SELECT
            correction.*,
            employee.name AS employee_name
        FROM payroll_hour_corrections correction
        JOIN employees employee ON employee.id = correction.employee_id
        WHERE correction.week_start = %s
          {status_clause}
        ORDER BY correction.correction_date, LOWER(employee.name), correction.id
        """,
        (week_start,),
        cursor=cursor,
    )


def _serialize_payroll_correction_allocation(row: Dict[str, Any]) -> Dict[str, Any]:
    delta_minutes = int(row["allocated_delta_minutes"])
    stored_labor_cost_cents = row.get("allocated_labor_cost_cents")
    raw_is_live = row.get("allocated_labor_cost_is_live")
    # NULL provenance = not yet reconciled (a row that predates the column or was
    # written by an old instance mid-deploy). Its stored cost is an untrusted
    # live-rate figure, so DO NOT treat it as frozen: value it at the live
    # recompute, exactly like a live-tracked row, until the next boot's reconcile
    # stamps it. Only an explicit FALSE keeps the stored cents authoritative.
    reconcile_pending = raw_is_live is None
    is_live = reconcile_pending or bool(raw_is_live)
    # For a pending row the stored cents are not authoritative, so drop them from
    # the frozen-cost view; the live recompute below carries the money instead.
    frozen_cost_cents = None if reconcile_pending else stored_labor_cost_cents
    current_labor_cost_cents = stored_labor_cost_cents
    if "employee_hourly_rate" in row:
        current_labor_cost_cents = _payroll_delta_labor_cost_cents(
            delta_minutes,
            row.get("employee_hourly_rate"),
        )
    # A frozen allocation is complete when its stored cost is present. A
    # live-tracked (or not-yet-reconciled) allocation stores/shows no frozen cost
    # and is valued at the live recompute, so it is complete whenever the live
    # rate is known. Anything else is a fail-closed unknown.
    effective_complete = (
        frozen_cost_cents is not None
        or (is_live and current_labor_cost_cents is not None)
    )
    return {
        "allocationId": int(row["id"]),
        "correctionId": int(row["correction_id"]),
        "weekStart": row["week_start"].isoformat(),
        "date": row["correction_date"].isoformat(),
        "employeeId": int(row["employee_id"]),
        "locationId": int(row["location_id"]),
        "customerId": (
            int(row["location_customer_id"])
            if row.get("location_customer_id") is not None
            else None
        ),
        "customerName": str(row.get("location_customer_name") or ""),
        "siteAddress": str(row.get("location_address") or ""),
        "jobId": int(row["job_id"]) if row.get("job_id") is not None else None,
        "allocatedDeltaMinutes": delta_minutes,
        "allocatedDeltaHours": round(delta_minutes / 60, 2),
        "allocatedLaborCost": _payroll_signed_money(frozen_cost_cents),
        "laborCostComplete": effective_complete,
        "laborCostIsLive": is_live,
        "currentAllocatedLaborCost": _payroll_signed_money(current_labor_cost_cents),
        "currentLaborCostComplete": current_labor_cost_cents is not None,
        "reason": str(row["reason"]),
        "status": str(row["status"]),
        "createdByName": str(row["created_by_name"]),
        "createdAt": _payroll_verification_iso(row.get("created_at")),
        "voidedByName": (
            str(row["voided_by_name"])
            if row.get("voided_by_name") is not None
            else None
        ),
        "voidedReason": row.get("voided_reason"),
        "voidedAt": _payroll_verification_iso(row.get("voided_at")),
        "supersededBy": (
            int(row["superseded_by"])
            if row.get("superseded_by") is not None
            else None
        ),
    }


def _enrich_payroll_correction_allocation_target_labels(
    row: Dict[str, Any],
    *,
    cursor: Optional[Any] = None,
) -> Dict[str, Any]:
    if (
        row.get("location_customer_id") is not None
        or row.get("location_customer_name") is not None
        or row.get("location_address") is not None
    ):
        return row
    location_id = row.get("location_id")
    if location_id is None:
        return row
    labels = _payroll_query_all(
        """
        SELECT location.customer_id AS location_customer_id
             , COALESCE(location.customer_name, customer.name, '') AS location_customer_name
             , location.address AS location_address
        FROM locations location
        LEFT JOIN customers customer
          ON customer.id = location.customer_id
        WHERE location.id = %s
        """,
        (int(location_id),),
        cursor=cursor,
    )
    if labels:
        row.update(labels[0])
    return row


def _payroll_correction_allocation_rows(
    week_start: date,
    *,
    cursor: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    return _payroll_query_all(
        """
        SELECT allocation.*
             , employee.hourly_rate AS employee_hourly_rate
             , location.customer_id AS location_customer_id
             , COALESCE(location.customer_name, customer.name, '') AS location_customer_name
             , location.address AS location_address
        FROM payroll_hour_correction_allocations allocation
        JOIN payroll_hour_corrections correction
          ON correction.id = allocation.correction_id
        JOIN employees employee
          ON employee.id = allocation.employee_id
        JOIN locations location
          ON location.id = allocation.location_id
        LEFT JOIN customers customer
          ON customer.id = location.customer_id
        WHERE allocation.week_start = %s
          AND allocation.status = 'active'
          AND correction.status = 'active'
        ORDER BY allocation.correction_date, allocation.correction_id, allocation.id
        """,
        (week_start,),
        cursor=cursor,
    )


def _payroll_correction_allocations_by_correction_id(
    rows: List[Dict[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    return {
        int(row["correction_id"]): row
        for row in rows
        if row.get("correction_id") is not None
    }


def _payroll_correction_candidate_detail_for_row(
    cur: Any,
    correction_row: Dict[str, Any],
) -> Dict[str, Any]:
    week_start = correction_row["week_start"]
    weekly_hours = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
    settings = load_settings(cursor=cur)
    result = build_weekly_labor_profitability(
        week_start,
        timezone_name=TIMEZONE_NAME,
        now_provider=utc_now,
        default_target_labor_pct=settings.get(
            "laborPctTarget",
            _SETTINGS_DEFAULTS["laborPctTarget"],
        ),
        default_min_margin_pct=settings.get(
            "grossMarginMin",
            _SETTINGS_DEFAULTS["grossMarginMin"],
        ),
        payroll_week_start=week_start,
        cursor=cur,
    )
    candidate_segments = result.pop("_payrollCorrectionCandidateSegments", [])
    details_by_date = _payroll_correction_details_by_date(
        weekly_hours,
        candidate_segments,
        [],
    )
    correction_id = int(correction_row["id"])
    correction_date = correction_row["correction_date"].isoformat()
    for detail in details_by_date.get(correction_date, []):
        if int(detail.get("correctionId") or 0) == correction_id:
            return detail
    raise HTTPException(
        status_code=409,
        detail="Payroll correction is not present in the current weekly-hours proof",
    )


def _payroll_correction_candidate_target(
    correction_detail: Dict[str, Any],
    *,
    location_id: int,
    job_id: Optional[int],
) -> Dict[str, Any]:
    for site in correction_detail.get("candidateSites") or []:
        if int(site.get("locationId") or 0) != int(location_id):
            continue
        if job_id is None:
            return site
        for job in site.get("jobs") or []:
            if int(job.get("jobId") or 0) == int(job_id):
                return job
        raise HTTPException(
            status_code=409,
            detail="Payroll correction allocation job is not a current candidate",
        )
    raise HTTPException(
        status_code=409,
        detail="Payroll correction allocation Site is not a current candidate",
    )


def _ensure_payroll_correction_allocation_capacity(
    *,
    target: Dict[str, Any],
    delta_minutes: int,
) -> None:
    if _payroll_target_can_absorb_delta(
        target=target,
        delta_minutes=delta_minutes,
    ):
        return
    raise HTTPException(
        status_code=409,
        detail="Payroll correction allocation would make selected profitability target negative",
    )


def _ensure_payroll_week_corrections_editable(cur: Any, week_start: date) -> None:
    batch = _get_payroll_verification_batch(cur, week_start, lock=True)
    if batch and batch["status"] in {"verified", "finalized"}:
        raise HTTPException(
            status_code=409,
            detail="Reopen the payroll week before changing corrections",
        )


def _payroll_week_start_query(
    request: Request,
    week_start: Optional[str],
) -> Optional[str]:
    return week_start or request.query_params.get("week_start")


def _payroll_timesheet_change_request_fingerprint(
    payload: PayrollTimesheetChangesRequest,
) -> str:
    encoded = json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payroll_change_shift_values(
    operation: PayrollTimesheetChangeOperation,
    week_start: date,
    observed_at: datetime,
) -> Tuple[date, datetime, datetime, int, int]:
    if operation.date is None or operation.clockIn is None or operation.clockOut is None:
        raise HTTPException(status_code=400, detail="Shift date and times are required")
    work_date = _parse_payroll_correction_date(operation.date, week_start)
    clock_in = _parse_payroll_shift_correction_datetime(operation.clockIn, "clockIn")
    clock_out = _parse_payroll_shift_correction_datetime(operation.clockOut, "clockOut")
    _ensure_payroll_shift_correction_dates(
        week_start=week_start,
        correction_date=work_date,
        corrected_clock_in=clock_in,
        corrected_clock_out=clock_out,
        observed_at=observed_at,
    )
    break_minutes = int(operation.breakMinutes or 0)
    total_minutes = _payroll_corrected_shift_total_minutes(
        clock_in,
        clock_out,
        break_minutes,
    )
    return work_date, clock_in, clock_out, break_minutes, total_minutes


def _payroll_change_location(
    cur: Any,
    location_id: Optional[int],
    *,
    allowed_inactive_location_id: Optional[int] = None,
) -> Optional[int]:
    if location_id is None:
        return None
    cur.execute(
        "SELECT id, active FROM locations WHERE id = %s FOR SHARE",
        (int(location_id),),
    )
    row = cur.fetchone()
    if row is None or (
        not bool(row["active"])
        and int(location_id) != int(allowed_inactive_location_id or 0)
    ):
        raise HTTPException(status_code=409, detail="Manual shift Site is not active")
    return int(location_id)


def _payroll_current_manual_shift(
    cur: Any,
    *,
    manual_shift_id: UUID,
    week_start: date,
    employee_id: int,
) -> Dict[str, Any]:
    cur.execute(
        """
        SELECT *
        FROM payroll_manual_shift_versions
        WHERE manual_shift_id = %s
          AND week_start = %s
          AND employee_id = %s
          AND status = 'current'
        FOR UPDATE
        """,
        (str(manual_shift_id), week_start, employee_id),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Current manual payroll shift not found")
    return dict(row)


def _payroll_insert_manual_shift_version(
    cur: Any,
    *,
    manual_shift_id: str,
    version: int,
    week_start: date,
    work_date: date,
    employee_id: int,
    clock_in: datetime,
    clock_out: datetime,
    break_minutes: int,
    total_minutes: int,
    location_id: Optional[int],
    included: bool,
    reason: str,
    batch_id: int,
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        INSERT INTO payroll_manual_shift_versions (
            manual_shift_id, version, week_start, work_date, employee_id,
            clock_in, clock_out, break_minutes, total_minutes, location_id,
            included, reason, change_batch_id,
            created_by_employee_id, created_by_name
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        (
            manual_shift_id,
            version,
            week_start,
            work_date,
            employee_id,
            clock_in,
            clock_out,
            break_minutes,
            total_minutes,
            location_id,
            included,
            reason,
            batch_id,
            int(actor["id"]),
            str(actor["name"]),
        ),
    )
    return dict(cur.fetchone())


def _payroll_supersede_manual_shift(
    cur: Any,
    *,
    current: Dict[str, Any],
    values: Dict[str, Any],
    included: bool,
    reason: str,
    batch_id: int,
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    cur.execute(
        """
        UPDATE payroll_manual_shift_versions
        SET status = 'superseded', updated_at = NOW()
        WHERE id = %s AND status = 'current'
        """,
        (int(current["id"]),),
    )
    saved = _payroll_insert_manual_shift_version(
        cur,
        manual_shift_id=str(current["manual_shift_id"]),
        version=int(current["version"]) + 1,
        week_start=current["week_start"],
        work_date=values["work_date"],
        employee_id=int(current["employee_id"]),
        clock_in=values["clock_in"],
        clock_out=values["clock_out"],
        break_minutes=int(values["break_minutes"]),
        total_minutes=int(values["total_minutes"]),
        location_id=values.get("location_id"),
        included=included,
        reason=reason,
        batch_id=batch_id,
        actor=actor,
    )
    cur.execute(
        """
        UPDATE payroll_manual_shift_versions
        SET superseded_by = %s, updated_at = NOW()
        WHERE id = %s
        """,
        (int(saved["id"]), int(current["id"])),
    )
    return saved


def _payroll_manual_values_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "work_date": row["work_date"],
        "clock_in": row["clock_in"],
        "clock_out": row["clock_out"],
        "break_minutes": int(row["break_minutes"]),
        "total_minutes": int(row["total_minutes"]),
        "location_id": int(row["location_id"]) if row.get("location_id") else None,
    }


def _payroll_recorded_shift_for_change(
    cur: Any,
    *,
    shift_id: int,
    employee_id: int,
) -> Dict[str, Any]:
    cur.execute(
        """
        SELECT shift_row.*, employee.name AS employee_name
        FROM shifts shift_row
        JOIN employees employee ON employee.id = shift_row.employee_id
        WHERE shift_row.id = %s
          AND shift_row.employee_id = %s
        FOR SHARE
        """,
        (shift_id, employee_id),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Shift not found")
    return dict(row)


def _retire_payroll_day_total_corrections(
    cur: Any,
    *,
    week_start: date,
    employee_id: int,
    touched_dates: Iterable[date],
    reason: str,
    actor: Dict[str, Any],
) -> None:
    dates = sorted(set(touched_dates))
    if not dates:
        return
    cur.execute(
        """
        UPDATE payroll_hour_corrections
        SET status = 'voided',
            voided_by_employee_id = %s,
            voided_by_name = %s,
            voided_reason = %s,
            voided_at = NOW(),
            updated_at = NOW()
        WHERE week_start = %s
          AND employee_id = %s
          AND correction_date = ANY(%s)
          AND status = 'active'
        RETURNING id
        """,
        (int(actor["id"]), str(actor["name"]), reason, week_start, employee_id, dates),
    )
    correction_ids = [int(row["id"]) for row in cur.fetchall()]
    if not correction_ids:
        return
    cur.execute(
        """
        UPDATE payroll_hour_correction_allocations
        SET status = 'voided',
            voided_by_employee_id = %s,
            voided_by_name = %s,
            voided_reason = %s,
            voided_at = NOW(),
            updated_at = NOW()
        WHERE correction_id = ANY(%s)
          AND status = 'active'
        """,
        (int(actor["id"]), str(actor["name"]), reason, correction_ids),
    )


@app.get("/api/admin/payroll/weekly-hours")
def admin_payroll_weekly_hours(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    data = _compute_payroll_weekly_hours(_payroll_week_start_query(request, week_start))
    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS",
        True,
        f"week={data['weekStart']} employees={data['summary']['employeeCount']} issues={data['summary']['issueCount']}",
    )
    return data


@app.get("/api/admin/payroll/timesheet")
def admin_payroll_timesheet(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    employee_id: Optional[int] = Query(default=None, alias="employeeId", gt=0),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            data = _compute_payroll_timesheet(
                _payroll_week_start_query(request, week_start),
                employee_id=employee_id,
                cursor=cur,
            )
    append_access_log(
        request,
        "PAYROLL_TIMESHEET",
        True,
        f"week={data['weekStart']} selectedEmployee={employee_id or 'all'} employees={data['summary']['employeeCount']} issues={data['summary']['issueCount']}",
    )
    return data


@app.post("/api/admin/payroll/timesheet/changes")
def admin_apply_payroll_timesheet_changes(
    payload: PayrollTimesheetChangesRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    _week_end, week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
    request_fingerprint = _payroll_timesheet_change_request_fingerprint(payload)
    observed_at = utc_now()
    result: Dict[str, Any]

    with timesheet_postgres_advisory_lock():
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                _lock_payroll_verification_week(cur, week_start)

                cur.execute(
                    """
                    SELECT *
                    FROM payroll_timesheet_change_batches
                    WHERE request_id = %s
                    FOR UPDATE
                    """,
                    (str(payload.requestId),),
                )
                existing_batch = cur.fetchone()
                if existing_batch is not None:
                    if not hmac.compare_digest(
                        str(existing_batch["request_fingerprint"]),
                        request_fingerprint,
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail="Timesheet request ID was already used for different changes",
                        )
                    timesheet = _compute_payroll_timesheet(
                        week_start.isoformat(),
                        employee_id=int(payload.employeeId),
                        cursor=cur,
                    )
                    result = {
                        "success": True,
                        "action": "save_timesheet_changes",
                        "idempotent": True,
                        "requestId": str(payload.requestId),
                        "batchId": int(existing_batch["id"]),
                        "operations": existing_batch["operations"],
                        "timesheet": timesheet,
                    }
                else:
                    _ensure_payroll_week_corrections_editable(cur, week_start)
                    _lock_payroll_correction_write_tables(cur)
                    cur.execute(
                        "SELECT id, name FROM employees WHERE id = %s FOR SHARE",
                        (int(payload.employeeId),),
                    )
                    if cur.fetchone() is None:
                        raise HTTPException(status_code=404, detail="Employee not found")

                    before = _compute_payroll_timesheet(
                        week_start.isoformat(),
                        employee_id=int(payload.employeeId),
                        cursor=cur,
                    )
                    employee_source_fingerprint = (
                        _payroll_selected_employee_timesheet_fingerprint(
                            before,
                            int(payload.employeeId),
                        )
                    )
                    batch_source_fingerprint = employee_source_fingerprint or str(
                        before["timesheetSourceFingerprint"]
                    )
                    accepted_source_fingerprints = {
                        employee_source_fingerprint,
                        str(before["timesheetSourceFingerprint"]),
                    }
                    if not any(
                        candidate
                        and hmac.compare_digest(
                            payload.expectedTimesheetSourceFingerprint,
                            candidate,
                        )
                        for candidate in accepted_source_fingerprints
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail="Payroll timesheet changed; refresh before saving",
                        )

                    cur.execute(
                        """
                        INSERT INTO payroll_timesheet_change_batches (
                            request_id, request_fingerprint, week_start, employee_id,
                            reason, operations, before_source_fingerprint,
                            created_by_employee_id, created_by_name
                        )
                        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
                        RETURNING *
                        """,
                        (
                            str(payload.requestId),
                            request_fingerprint,
                            week_start,
                            int(payload.employeeId),
                            payload.reason,
                            json.dumps(payload.model_dump(mode="json")["operations"], sort_keys=True),
                            batch_source_fingerprint,
                            int(current_payroll["id"]),
                            str(current_payroll["name"]),
                        ),
                    )
                    batch = dict(cur.fetchone())
                    batch_id = int(batch["id"])
                    touched_dates: set[date] = set()
                    operation_audit: List[Dict[str, Any]] = []

                    for operation in payload.operations:
                        action = operation.action
                        audit: Dict[str, Any] = {"action": action}

                        if action == "add_manual":
                            work_date, clock_in, clock_out, break_minutes, total_minutes = (
                                _payroll_change_shift_values(operation, week_start, observed_at)
                            )
                            location_id = _payroll_change_location(cur, operation.locationId)
                            manual_shift_id = str(uuid4())
                            saved = _payroll_insert_manual_shift_version(
                                cur,
                                manual_shift_id=manual_shift_id,
                                version=1,
                                week_start=week_start,
                                work_date=work_date,
                                employee_id=int(payload.employeeId),
                                clock_in=clock_in,
                                clock_out=clock_out,
                                break_minutes=break_minutes,
                                total_minutes=total_minutes,
                                location_id=location_id,
                                included=True,
                                reason=payload.reason,
                                batch_id=batch_id,
                                actor=current_payroll,
                            )
                            touched_dates.add(work_date)
                            audit.update(
                                {
                                    "clientRowId": operation.clientRowId,
                                    "manualShiftId": manual_shift_id,
                                    "before": None,
                                    "after": saved,
                                }
                            )

                        elif action in {"edit_manual", "exclude_manual", "restore_manual"}:
                            current = _payroll_current_manual_shift(
                                cur,
                                manual_shift_id=operation.manualShiftId,
                                week_start=week_start,
                                employee_id=int(payload.employeeId),
                            )
                            if action == "edit_manual":
                                if not bool(current["included"]):
                                    raise HTTPException(
                                        status_code=409,
                                        detail="Restore the manual shift before editing it",
                                    )
                                work_date, clock_in, clock_out, break_minutes, total_minutes = (
                                    _payroll_change_shift_values(operation, week_start, observed_at)
                                )
                                location_id = _payroll_change_location(
                                    cur,
                                    operation.locationId,
                                    allowed_inactive_location_id=current.get("location_id"),
                                )
                                values = {
                                    "work_date": work_date,
                                    "clock_in": clock_in,
                                    "clock_out": clock_out,
                                    "break_minutes": break_minutes,
                                    "total_minutes": total_minutes,
                                    "location_id": location_id,
                                }
                                included = True
                            else:
                                expected_included = action == "exclude_manual"
                                if bool(current["included"]) != expected_included:
                                    raise HTTPException(
                                        status_code=409,
                                        detail=(
                                            "Manual shift is already excluded"
                                            if action == "exclude_manual"
                                            else "Manual shift is already restored"
                                        ),
                                    )
                                values = _payroll_manual_values_from_row(current)
                                included = action == "restore_manual"
                            saved = _payroll_supersede_manual_shift(
                                cur,
                                current=current,
                                values=values,
                                included=included,
                                reason=payload.reason,
                                batch_id=batch_id,
                                actor=current_payroll,
                            )
                            touched_dates.update({current["work_date"], saved["work_date"]})
                            audit.update(
                                {
                                    "manualShiftId": str(current["manual_shift_id"]),
                                    "before": current,
                                    "after": saved,
                                }
                            )

                        elif action in {
                            "correct_recorded",
                            "clear_recorded_correction",
                            "exclude_recorded",
                            "restore_recorded",
                        }:
                            shift_row = _payroll_recorded_shift_for_change(
                                cur,
                                shift_id=int(operation.shiftId or 0),
                                employee_id=int(payload.employeeId),
                            )
                            source_date = _payroll_shift_source_work_date(shift_row)
                            if action in {"exclude_recorded", "restore_recorded"}:
                                belongs_to_week = _payroll_shift_overlaps_week(
                                    shift_row,
                                    week_start_utc=week_start_utc,
                                    week_end_utc=week_end_utc,
                                    now_utc=observed_at,
                                )
                            else:
                                belongs_to_week = (
                                    week_start
                                    <= source_date
                                    < week_start + timedelta(days=7)
                                )
                            if not belongs_to_week:
                                raise HTTPException(
                                    status_code=400,
                                    detail="Shift does not belong to the selected payroll week",
                                )
                            cur.execute(
                                """
                                SELECT * FROM payroll_shift_corrections
                                WHERE week_start = %s AND shift_id = %s AND status = 'active'
                                FOR UPDATE
                                """,
                                (week_start, int(shift_row["id"])),
                            )
                            existing_correction_row = cur.fetchone()
                            existing_correction = (
                                dict(existing_correction_row)
                                if existing_correction_row is not None
                                else None
                            )
                            cur.execute(
                                """
                                SELECT * FROM payroll_shift_exclusions
                                WHERE week_start = %s AND shift_id = %s AND status = 'active'
                                FOR UPDATE
                                """,
                                (week_start, int(shift_row["id"])),
                            )
                            active_exclusion_row = cur.fetchone()
                            active_exclusion = (
                                dict(active_exclusion_row)
                                if active_exclusion_row is not None
                                else None
                            )
                            if action in {
                                "correct_recorded",
                                "clear_recorded_correction",
                            } and active_exclusion is not None:
                                raise HTTPException(
                                    status_code=409,
                                    detail="Restore the recorded shift before editing it",
                                )
                            effective_before = _effective_payroll_shift_row(
                                shift_row,
                                existing_correction,
                            )
                            touched_dates.update(
                                _payroll_shift_dates_in_week(
                                    shift_row,
                                    week_start_utc=week_start_utc,
                                    week_end_utc=week_end_utc,
                                    observed_at=observed_at,
                                )
                            )
                            touched_dates.update(
                                _payroll_shift_dates_in_week(
                                    effective_before,
                                    week_start_utc=week_start_utc,
                                    week_end_utc=week_end_utc,
                                    observed_at=observed_at,
                                )
                            )
                            audit.update({"shiftId": int(shift_row["id"]), "before": None})

                            if action == "correct_recorded":
                                work_date, clock_in, clock_out, break_minutes, total_minutes = (
                                    _payroll_change_shift_values(operation, week_start, observed_at)
                                )
                                _ensure_payroll_shift_correction_source_date(shift_row, work_date)
                                audit["before"] = existing_correction
                                if existing_correction:
                                    cur.execute(
                                        """
                                        UPDATE payroll_shift_corrections
                                        SET status = 'superseded', updated_at = NOW()
                                        WHERE id = %s
                                        """,
                                        (int(existing_correction["id"]),),
                                    )
                                cur.execute(
                                    """
                                    INSERT INTO payroll_shift_corrections (
                                        week_start, correction_date, employee_id, shift_id,
                                        source_clock_in, source_clock_out, source_break_minutes,
                                        source_total_minutes, corrected_clock_in, corrected_clock_out,
                                        corrected_break_minutes, corrected_total_minutes, reason,
                                        created_by_employee_id, created_by_name
                                    )
                                    VALUES (%s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s, %s, %s)
                                    RETURNING *
                                    """,
                                    (
                                        week_start,
                                        work_date,
                                        int(payload.employeeId),
                                        int(shift_row["id"]),
                                        shift_row["clock_in"],
                                        shift_row.get("clock_out"),
                                        _payroll_raw_shift_total_minutes(shift_row),
                                        clock_in,
                                        clock_out,
                                        break_minutes,
                                        total_minutes,
                                        payload.reason,
                                        int(current_payroll["id"]),
                                        str(current_payroll["name"]),
                                    ),
                                )
                                saved = dict(cur.fetchone())
                                if existing_correction:
                                    cur.execute(
                                        """
                                        UPDATE payroll_shift_corrections
                                        SET superseded_by = %s, updated_at = NOW()
                                        WHERE id = %s
                                        """,
                                        (
                                            int(saved["id"]),
                                            int(existing_correction["id"]),
                                        ),
                                    )
                                touched_dates.update(
                                    _payroll_shift_dates_in_week(
                                        _effective_payroll_shift_row(shift_row, saved),
                                        week_start_utc=week_start_utc,
                                        week_end_utc=week_end_utc,
                                        observed_at=observed_at,
                                    )
                                )
                                audit["after"] = saved

                            elif action == "clear_recorded_correction":
                                if existing_correction is None:
                                    raise HTTPException(
                                        status_code=404,
                                        detail="Active payroll shift correction not found",
                                    )
                                _ensure_shift_correction_void_keeps_single_open_shift(
                                    cur,
                                    existing_correction,
                                )
                                cur.execute(
                                    """
                                    UPDATE payroll_shift_corrections
                                    SET status = 'voided', voided_by_employee_id = %s,
                                        voided_by_name = %s, voided_reason = %s,
                                        voided_at = NOW(), updated_at = NOW()
                                    WHERE id = %s
                                    RETURNING *
                                    """,
                                    (
                                        int(current_payroll["id"]),
                                        str(current_payroll["name"]),
                                        payload.reason,
                                        int(existing_correction["id"]),
                                    ),
                                )
                                audit.update(
                                    {
                                        "before": existing_correction,
                                        "after": dict(cur.fetchone()),
                                    }
                                )

                            elif action == "exclude_recorded":
                                if active_exclusion is not None:
                                    raise HTTPException(status_code=409, detail="Shift is already excluded")
                                cur.execute(
                                    """
                                    INSERT INTO payroll_shift_exclusions (
                                        week_start, employee_id, shift_id, reason, change_batch_id,
                                        created_by_employee_id, created_by_name
                                    )
                                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                                    RETURNING *
                                    """,
                                    (
                                        week_start,
                                        int(payload.employeeId),
                                        int(shift_row["id"]),
                                        payload.reason,
                                        batch_id,
                                        int(current_payroll["id"]),
                                        str(current_payroll["name"]),
                                    ),
                                )
                                audit["after"] = dict(cur.fetchone())

                            else:
                                if active_exclusion is None:
                                    raise HTTPException(status_code=404, detail="Active shift exclusion not found")
                                cur.execute(
                                    """
                                    UPDATE payroll_shift_exclusions
                                    SET status = 'voided', voided_by_employee_id = %s,
                                        voided_by_name = %s, voided_reason = %s,
                                        voided_by_change_batch_id = %s,
                                        voided_at = NOW(), updated_at = NOW()
                                    WHERE id = %s
                                    RETURNING *
                                    """,
                                    (
                                        int(current_payroll["id"]),
                                        str(current_payroll["name"]),
                                        payload.reason,
                                        batch_id,
                                        int(active_exclusion["id"]),
                                    ),
                                )
                                audit.update(
                                    {
                                        "before": active_exclusion,
                                        "after": dict(cur.fetchone()),
                                    }
                                )

                        operation_audit.append(jsonable_encoder(audit))

                    _retire_payroll_day_total_corrections(
                        cur,
                        week_start=week_start,
                        employee_id=int(payload.employeeId),
                        touched_dates=touched_dates,
                        reason=payload.reason,
                        actor=current_payroll,
                    )
                    timesheet = _compute_payroll_timesheet(
                        week_start.isoformat(),
                        employee_id=int(payload.employeeId),
                        cursor=cur,
                    )
                    after_employee_source_fingerprint = (
                        _payroll_selected_employee_timesheet_fingerprint(
                            timesheet,
                            int(payload.employeeId),
                        )
                    )
                    batch_after_source_fingerprint = (
                        after_employee_source_fingerprint
                        or str(timesheet["timesheetSourceFingerprint"])
                    )
                    cur.execute(
                        """
                        UPDATE payroll_timesheet_change_batches
                        SET operations = %s::jsonb, after_source_fingerprint = %s
                        WHERE id = %s
                        """,
                        (
                            json.dumps(operation_audit, sort_keys=True),
                            batch_after_source_fingerprint,
                            batch_id,
                        ),
                    )
                    result = {
                        "success": True,
                        "action": "save_timesheet_changes",
                        "idempotent": False,
                        "requestId": str(payload.requestId),
                        "batchId": batch_id,
                        "operations": operation_audit,
                        "timesheet": timesheet,
                    }

    append_access_log(
        request,
        "PAYROLL_TIMESHEET_CHANGES",
        True,
        (
            f"week={week_start.isoformat()} employee={payload.employeeId} "
            f"operations={len(payload.operations)} idempotent={result['idempotent']}"
        ),
    )
    return result


@app.post("/api/admin/payroll/timesheet/shift-corrections")
def admin_create_payroll_shift_correction(
    payload: PayrollShiftCorrectionRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    correction_date = _parse_payroll_correction_date(payload.date, week_start)
    corrected_clock_in = _parse_payroll_shift_correction_datetime(
        payload.correctedClockIn,
        "correctedClockIn",
    )
    corrected_clock_out = _parse_payroll_shift_correction_datetime(
        payload.correctedClockOut,
        "correctedClockOut",
    )
    observed_at = utc_now()
    _ensure_payroll_shift_correction_dates(
        week_start=week_start,
        correction_date=correction_date,
        corrected_clock_in=corrected_clock_in,
        corrected_clock_out=corrected_clock_out,
        observed_at=observed_at,
    )
    corrected_total_minutes = _payroll_corrected_shift_total_minutes(
        corrected_clock_in,
        corrected_clock_out,
        int(payload.correctedBreakMinutes),
    )
    result: Dict[str, Any]
    with timesheet_postgres_advisory_lock():
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                _lock_payroll_verification_week(cur, week_start)
                _ensure_payroll_week_corrections_editable(cur, week_start)
                _lock_payroll_correction_write_tables(cur)
                cur.execute(
                    """
                    SELECT shift_row.*, employee.name AS employee_name
                    FROM shifts shift_row
                    JOIN employees employee ON employee.id = shift_row.employee_id
                    WHERE shift_row.id = %s
                      AND shift_row.employee_id = %s
                    FOR SHARE
                    """,
                    (int(payload.shiftId), int(payload.employeeId)),
                )
                shift_row = cur.fetchone()
                if shift_row is None:
                    raise HTTPException(status_code=404, detail="Shift not found")
                _, week_start_utc, week_end_utc = _payroll_week_bounds(week_start)
                if not _payroll_shift_overlaps_week(
                    dict(shift_row),
                    week_start_utc=week_start_utc,
                    week_end_utc=week_end_utc,
                    now_utc=observed_at,
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="Shift does not overlap the selected payroll week",
                    )
                _ensure_payroll_shift_correction_source_date(
                    dict(shift_row),
                    correction_date,
                )
                source_total_minutes = _payroll_raw_shift_total_minutes(dict(shift_row))
                cur.execute(
                    """
                    SELECT *
                    FROM payroll_shift_corrections
                    WHERE week_start = %s
                      AND shift_id = %s
                      AND status = 'active'
                    FOR UPDATE
                    """,
                    (week_start, int(payload.shiftId)),
                )
                existing = cur.fetchone()
                if (
                    existing
                    and existing["corrected_clock_in"].astimezone(timezone.utc)
                    == corrected_clock_in
                    and existing["corrected_clock_out"].astimezone(timezone.utc)
                    == corrected_clock_out
                    and int(existing["corrected_break_minutes"])
                    == int(payload.correctedBreakMinutes)
                    and str(existing["reason"]) == payload.reason
                ):
                    saved = dict(existing)
                    saved["employee_name"] = str(shift_row["employee_name"])
                    idempotent = True
                else:
                    if existing:
                        cur.execute(
                            """
                            UPDATE payroll_shift_corrections
                            SET status = 'superseded', updated_at = NOW()
                            WHERE id = %s
                            """,
                            (int(existing["id"]),),
                        )
                    cur.execute(
                        """
                        INSERT INTO payroll_shift_corrections (
                            week_start,
                            correction_date,
                            employee_id,
                            shift_id,
                            source_clock_in,
                            source_clock_out,
                            source_break_minutes,
                            source_total_minutes,
                            corrected_clock_in,
                            corrected_clock_out,
                            corrected_break_minutes,
                            corrected_total_minutes,
                            reason,
                            created_by_employee_id,
                            created_by_name
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING *
                        """,
                        (
                            week_start,
                            correction_date,
                            int(payload.employeeId),
                            int(payload.shiftId),
                            shift_row["clock_in"],
                            shift_row.get("clock_out"),
                            source_total_minutes,
                            corrected_clock_in,
                            corrected_clock_out,
                            int(payload.correctedBreakMinutes),
                            corrected_total_minutes,
                            payload.reason,
                            int(current_payroll["id"]),
                            str(current_payroll["name"]),
                        ),
                    )
                    saved = dict(cur.fetchone())
                    saved["employee_name"] = str(shift_row["employee_name"])
                    if existing:
                        cur.execute(
                            """
                            UPDATE payroll_shift_corrections
                            SET superseded_by = %s, updated_at = NOW()
                            WHERE id = %s
                            """,
                            (int(saved["id"]), int(existing["id"])),
                        )
                    idempotent = False
                timesheet = _compute_payroll_timesheet(
                    week_start.isoformat(),
                    employee_id=int(payload.employeeId),
                    cursor=cur,
                )
                result = {
                    "success": True,
                    "action": "correct_shift",
                    "idempotent": idempotent,
                    "correction": _serialize_payroll_shift_correction(saved),
                    "timesheet": timesheet,
                }

    append_access_log(
        request,
        "PAYROLL_SHIFT_CORRECTION",
        True,
        f"week={week_start.isoformat()} employee={payload.employeeId} shift={payload.shiftId} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/timesheet/shift-corrections/{correction_id}/void")
def admin_void_payroll_shift_correction(
    correction_id: int,
    payload: PayrollCorrectionVoidRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    with timesheet_postgres_advisory_lock():
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT week_start FROM payroll_shift_corrections WHERE id = %s",
                    (correction_id,),
                )
                identity = cur.fetchone()
                if identity is None:
                    raise HTTPException(status_code=404, detail="Active payroll shift correction not found")
                week_start = identity["week_start"]
                _lock_payroll_verification_week(cur, week_start)
                _ensure_payroll_week_corrections_editable(cur, week_start)
                _lock_payroll_correction_write_tables(cur)
                cur.execute(
                    """
                    SELECT correction.*, employee.name AS employee_name
                    FROM payroll_shift_corrections correction
                    JOIN employees employee ON employee.id = correction.employee_id
                    WHERE correction.id = %s
                      AND correction.status = 'active'
                    FOR UPDATE
                    """,
                    (correction_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Active payroll shift correction not found")
                _ensure_shift_correction_void_keeps_single_open_shift(cur, dict(row))
                cur.execute(
                    """
                    UPDATE payroll_shift_corrections
                    SET
                        status = 'voided',
                        voided_by_employee_id = %s,
                        voided_by_name = %s,
                        voided_reason = %s,
                        voided_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                        payload.reason,
                        correction_id,
                    ),
                )
                saved = dict(cur.fetchone())
                saved["employee_name"] = str(row["employee_name"])
                timesheet = _compute_payroll_timesheet(
                    week_start.isoformat(),
                    employee_id=int(row["employee_id"]),
                    cursor=cur,
                )
                result = {
                    "success": True,
                    "action": "void_shift_correction",
                    "correction": _serialize_payroll_shift_correction(saved),
                    "timesheet": timesheet,
                }

    append_access_log(
        request,
        "PAYROLL_SHIFT_CORRECTION_VOID",
        True,
        f"week={week_start.isoformat()} correction={correction_id}",
    )
    return result


@app.get("/api/admin/payroll/weekly-hours/verification")
def admin_payroll_weekly_hours_verification(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    # Both truths are read from ONE timesheet computation (which internally
    # computes the weekly hours), so the hours and money fingerprints/summary can
    # never be derived from different source snapshots -- otherwise the page
    # could show hours as current while presenting money from a later state.
    timesheet = _compute_payroll_timesheet(_payroll_week_start_query(request, week_start))
    parsed_week_start = _parse_payroll_week_start(timesheet["weekStart"])
    row = db.query_one(
        """
        SELECT *
        FROM payroll_verification_batches
        WHERE week_start = %s
        """,
        (parsed_week_start,),
    )
    money_row = db.query_one(
        """
        SELECT *
        FROM payroll_money_verification_batches
        WHERE week_start = %s
        """,
        (parsed_week_start,),
    )
    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_VERIFICATION",
        True,
        f"week={timesheet['weekStart']} status={row['status'] if row else 'unverified'}"
        f" money={money_row['status'] if money_row else 'unverified'}",
    )
    return {
        "success": True,
        "weekStart": timesheet["weekStart"],
        "weekEnd": timesheet["weekEnd"],
        "timezone": timesheet["timezone"],
        "currentSourceFingerprint": timesheet["sourceFingerprint"],
        "currentMoneyFingerprint": timesheet["timesheetSourceFingerprint"],
        "summary": timesheet["summary"],
        "verification": _payroll_verification_state(
            row,
            current_source_fingerprint=timesheet["sourceFingerprint"],
        ),
        "moneyVerification": _payroll_money_verification_state(
            money_row,
            current_money_fingerprint=timesheet["timesheetSourceFingerprint"],
        ),
    }


@app.get("/api/admin/payroll/weekly-hours/corrections")
def admin_payroll_weekly_hours_corrections(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    parsed_week_start = _parse_payroll_week_start(_payroll_week_start_query(request, week_start))
    rows = _payroll_correction_rows(parsed_week_start)
    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_CORRECTIONS",
        True,
        f"week={parsed_week_start.isoformat()} corrections={len(rows)}",
    )
    return {
        "success": True,
        "weekStart": parsed_week_start.isoformat(),
        "weekEnd": (parsed_week_start + timedelta(days=6)).isoformat(),
        "corrections": [_serialize_payroll_correction(row) for row in rows],
    }


@app.post("/api/admin/payroll/weekly-hours/corrections")
def admin_create_payroll_hour_correction(
    payload: PayrollCorrectionRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    correction_date = _parse_payroll_correction_date(payload.date, week_start)
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_payroll_verification_week(cur, week_start)
            _ensure_payroll_week_corrections_editable(cur, week_start)
            _lock_payroll_correction_write_tables(cur)
            cur.execute(
                "SELECT id, name FROM employees WHERE id = %s FOR SHARE",
                (payload.employeeId,),
            )
            employee = cur.fetchone()
            if employee is None:
                raise HTTPException(status_code=404, detail="Employee not found")
            cur.execute(
                """
                SELECT *
                FROM payroll_hour_corrections
                WHERE week_start = %s
                  AND employee_id = %s
                  AND correction_date = %s
                  AND status = 'active'
                FOR UPDATE
                """,
                (week_start, int(payload.employeeId), correction_date),
            )
            existing = cur.fetchone()
            if (
                existing
                and int(existing["corrected_total_minutes"]) == payload.correctedTotalMinutes
                and str(existing["reason"]) == payload.reason
            ):
                saved = dict(existing)
                saved["employee_name"] = str(employee["name"])
                idempotent = True
            else:
                if existing:
                    cur.execute(
                        """
                        UPDATE payroll_hour_corrections
                        SET status = 'superseded', updated_at = NOW()
                        WHERE id = %s
                        """,
                        (int(existing["id"]),),
                    )
                    cur.execute(
                        """
                        UPDATE payroll_hour_correction_allocations
                        SET status = 'superseded', updated_at = NOW()
                        WHERE correction_id = %s
                          AND status = 'active'
                        """,
                        (int(existing["id"]),),
                    )
                cur.execute(
                    """
                    INSERT INTO payroll_hour_corrections (
                        week_start,
                        correction_date,
                        employee_id,
                        corrected_total_minutes,
                        reason,
                        created_by_employee_id,
                        created_by_name
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        week_start,
                        correction_date,
                        int(payload.employeeId),
                        int(payload.correctedTotalMinutes),
                        payload.reason,
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                    ),
                )
                saved = dict(cur.fetchone())
                saved["employee_name"] = str(employee["name"])
                if existing:
                    cur.execute(
                        """
                        UPDATE payroll_hour_corrections
                        SET superseded_by = %s, updated_at = NOW()
                        WHERE id = %s
                        """,
                        (int(saved["id"]), int(existing["id"])),
                    )
                idempotent = False
            weekly_hours = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
            result = {
                "success": True,
                "action": "correct",
                "idempotent": idempotent,
                "correction": _serialize_payroll_correction(saved),
                "weeklyHours": weekly_hours,
            }

    append_access_log(
        request,
        "PAYROLL_HOUR_CORRECTION",
        True,
        f"week={week_start.isoformat()} employee={payload.employeeId} date={correction_date.isoformat()} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/corrections/{correction_id}/void")
def admin_void_payroll_hour_correction(
    correction_id: int,
    payload: PayrollCorrectionVoidRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT week_start FROM payroll_hour_corrections WHERE id = %s",
                (correction_id,),
            )
            identity = cur.fetchone()
            if identity is None:
                raise HTTPException(status_code=404, detail="Active payroll correction not found")
            week_start = identity["week_start"]
            _lock_payroll_verification_week(cur, week_start)
            _ensure_payroll_week_corrections_editable(cur, week_start)
            _lock_payroll_correction_write_tables(cur)
            cur.execute(
                """
                SELECT correction.*, employee.name AS employee_name
                FROM payroll_hour_corrections correction
                JOIN employees employee ON employee.id = correction.employee_id
                WHERE correction.id = %s
                  AND correction.status = 'active'
                FOR UPDATE
                """,
                (correction_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Active payroll correction not found")
            cur.execute(
                """
                UPDATE payroll_hour_corrections
                SET
                    status = 'voided',
                    voided_by_employee_id = %s,
                    voided_by_name = %s,
                    voided_reason = %s,
                    voided_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *
                """,
                (
                    int(current_payroll["id"]),
                    str(current_payroll["name"]),
                    payload.reason,
                    correction_id,
                ),
            )
            saved = dict(cur.fetchone())
            saved["employee_name"] = str(row["employee_name"])
            cur.execute(
                """
                UPDATE payroll_hour_correction_allocations
                SET
                    status = 'voided',
                    voided_by_employee_id = %s,
                    voided_by_name = %s,
                    voided_reason = %s,
                    voided_at = NOW(),
                    updated_at = NOW()
                WHERE correction_id = %s
                  AND status = 'active'
                """,
                (
                    int(current_payroll["id"]),
                    str(current_payroll["name"]),
                    payload.reason,
                    correction_id,
                ),
            )
            weekly_hours = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
            result = {
                "success": True,
                "action": "void",
                "correction": _serialize_payroll_correction(saved),
                "weeklyHours": weekly_hours,
            }

    append_access_log(
        request,
        "PAYROLL_HOUR_CORRECTION_VOID",
        True,
        f"week={week_start.isoformat()} correction={correction_id}",
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation")
def admin_allocate_payroll_hour_correction(
    correction_id: int,
    payload: PayrollCorrectionAllocationRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT week_start
                FROM payroll_hour_corrections
                WHERE id = %s
                  AND status = 'active'
                """,
                (correction_id,),
            )
            correction_identity = cur.fetchone()
            if correction_identity is None:
                raise HTTPException(status_code=404, detail="Active payroll correction not found")
            week_start = correction_identity["week_start"]
            _lock_payroll_verification_week(cur, week_start)
            _ensure_payroll_week_corrections_editable(cur, week_start)
            _lock_payroll_correction_write_tables(cur)
            cur.execute(
                """
                SELECT correction.*, employee.name AS employee_name, employee.hourly_rate
                FROM payroll_hour_corrections correction
                JOIN employees employee ON employee.id = correction.employee_id
                WHERE correction.id = %s
                  AND correction.status = 'active'
                FOR UPDATE
                """,
                (correction_id,),
            )
            correction_row = cur.fetchone()
            if correction_row is None:
                raise HTTPException(status_code=404, detail="Active payroll correction not found")
            correction_detail = _payroll_correction_candidate_detail_for_row(
                cur,
                dict(correction_row),
            )
            delta_minutes = int(correction_detail["deltaMinutes"])
            if delta_minutes == 0:
                raise HTTPException(
                    status_code=409,
                    detail="Payroll correction has no hour delta to allocate",
                )
            allocation_target = _payroll_correction_candidate_target(
                correction_detail,
                location_id=int(payload.locationId),
                job_id=payload.jobId,
            )
            _ensure_payroll_correction_allocation_capacity(
                target=allocation_target,
                delta_minutes=delta_minutes,
            )
            # Price the correction from the rate the work was worked at, not
            # from whatever the employee earns today.
            correction_rate, rate_resolved, rate_from_snapshot = (
                _payroll_correction_rate_for_allocation(
                    cur,
                    employee_id=int(correction_row["employee_id"]),
                    correction_date=correction_row["correction_date"],
                    location_id=int(payload.locationId),
                    live_hourly_rate=correction_row.get("hourly_rate"),
                )
            )
            labor_cost_cents, labor_cost_is_live = _payroll_correction_allocation_cost(
                delta_minutes,
                correction_rate,
                rate_resolved,
                rate_from_snapshot,
            )
            cur.execute(
                """
                SELECT *
                FROM payroll_hour_correction_allocations
                WHERE correction_id = %s
                  AND status = 'active'
                FOR UPDATE
                """,
                (correction_id,),
            )
            existing = cur.fetchone()
            if (
                existing
                and int(existing["location_id"]) == int(payload.locationId)
                and (
                    (existing.get("job_id") is None and payload.jobId is None)
                    or int(existing.get("job_id") or 0) == int(payload.jobId or 0)
                )
                and int(existing["allocated_delta_minutes"]) == delta_minutes
                and existing.get("allocated_labor_cost_cents") == labor_cost_cents
                # A NULL provenance means the existing row was never reconciled
                # (predates the column, or an old instance wrote it mid-deploy),
                # so it is never idempotent -- fall through and rewrite it with an
                # explicit TRUE/FALSE rather than leave it unstamped.
                and existing.get("allocated_labor_cost_is_live") is not None
                and bool(existing.get("allocated_labor_cost_is_live"))
                    == labor_cost_is_live
                and str(existing["reason"]) == payload.reason
            ):
                saved = dict(existing)
                idempotent = True
            else:
                if existing:
                    cur.execute(
                        """
                        UPDATE payroll_hour_correction_allocations
                        SET status = 'superseded', updated_at = NOW()
                        WHERE id = %s
                        """,
                        (int(existing["id"]),),
                    )
                cur.execute(
                    """
                    INSERT INTO payroll_hour_correction_allocations (
                        correction_id,
                        week_start,
                        correction_date,
                        employee_id,
                        location_id,
                        job_id,
                        allocated_delta_minutes,
                        allocated_labor_cost_cents,
                        allocated_labor_cost_is_live,
                        reason,
                        created_by_employee_id,
                        created_by_name
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        correction_id,
                        correction_row["week_start"],
                        correction_row["correction_date"],
                        int(correction_row["employee_id"]),
                        int(payload.locationId),
                        int(payload.jobId) if payload.jobId is not None else None,
                        delta_minutes,
                        labor_cost_cents,
                        labor_cost_is_live,
                        payload.reason,
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                    ),
                )
                saved = dict(cur.fetchone())
                if existing:
                    cur.execute(
                        """
                        UPDATE payroll_hour_correction_allocations
                        SET superseded_by = %s, updated_at = NOW()
                        WHERE id = %s
                        """,
                        (int(saved["id"]), int(existing["id"])),
                    )
                idempotent = False
            saved["employee_hourly_rate"] = correction_row.get("hourly_rate")
            _enrich_payroll_correction_allocation_target_labels(saved, cursor=cur)
            allocation = _serialize_payroll_correction_allocation(saved)
            correction_detail["allocationStatus"] = "allocated"
            correction_detail["allocation"] = allocation
            result = {
                "success": True,
                "action": "allocate",
                "idempotent": idempotent,
                "allocation": allocation,
                "correction": correction_detail,
            }

    append_access_log(
        request,
        "PAYROLL_HOUR_CORRECTION_ALLOCATION",
        True,
        (
            f"week={result['allocation']['weekStart']} correction={correction_id} "
            f"location={payload.locationId} job={payload.jobId or 'none'} "
            f"idempotent={result['idempotent']}"
        ),
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/corrections/{correction_id}/allocation/void")
def admin_void_payroll_hour_correction_allocation(
    correction_id: int,
    payload: PayrollCorrectionVoidRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT week_start
                FROM payroll_hour_corrections
                WHERE id = %s
                  AND status = 'active'
                """,
                (correction_id,),
            )
            correction_identity = cur.fetchone()
            if correction_identity is None:
                raise HTTPException(status_code=404, detail="Active payroll correction not found")
            week_start = correction_identity["week_start"]
            _lock_payroll_verification_week(cur, week_start)
            _ensure_payroll_week_corrections_editable(cur, week_start)
            _lock_payroll_correction_write_tables(cur)
            cur.execute(
                """
                SELECT *
                FROM payroll_hour_correction_allocations
                WHERE correction_id = %s
                  AND status = 'active'
                FOR UPDATE
                """,
                (correction_id,),
            )
            allocation_row = cur.fetchone()
            if allocation_row is None:
                raise HTTPException(status_code=404, detail="Active payroll correction allocation not found")
            cur.execute(
                """
                UPDATE payroll_hour_correction_allocations
                SET
                    status = 'voided',
                    voided_by_employee_id = %s,
                    voided_by_name = %s,
                    voided_reason = %s,
                    voided_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                RETURNING *
                """,
                (
                    int(current_payroll["id"]),
                    str(current_payroll["name"]),
                    payload.reason,
                    int(allocation_row["id"]),
                ),
            )
            saved = dict(cur.fetchone())
            # A live-tracked allocation stores NULL cost and is only serialized
            # complete when the employee's current rate is present to recompute
            # its live value. RETURNING * has no rate column, so inject it here
            # the same way the allocate endpoint does -- otherwise a voided
            # live-tracked allocation would serialize as incomplete.
            cur.execute(
                "SELECT hourly_rate FROM employees WHERE id = %s",
                (int(saved["employee_id"]),),
            )
            employee_rate_row = cur.fetchone()
            saved["employee_hourly_rate"] = (
                employee_rate_row["hourly_rate"] if employee_rate_row else None
            )
            _enrich_payroll_correction_allocation_target_labels(saved, cursor=cur)
            result = {
                "success": True,
                "action": "void_allocation",
                "allocation": _serialize_payroll_correction_allocation(saved),
            }

    append_access_log(
        request,
        "PAYROLL_HOUR_CORRECTION_ALLOCATION_VOID",
        True,
        f"week={result['allocation']['weekStart']} correction={correction_id}",
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/verify")
def admin_verify_payroll_weekly_hours(
    payload: PayrollVerificationRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_payroll_verification_week(cur, week_start)
            _lock_payroll_source_rows(cur)
            data = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
            _ensure_payroll_snapshot_current(payload.sourceFingerprint, data, "verifying")
            _ensure_payroll_snapshot_has_no_blocking_issues(data, "verifying this week")
            row = _get_payroll_verification_batch(cur, week_start, lock=True)
            if row and row["status"] == "finalized":
                raise HTTPException(
                    status_code=409,
                    detail="Finalized payroll weeks must be reopened before verifying again",
                )
            if row and row["status"] == "verified":
                if hmac.compare_digest(str(row["source_fingerprint"]), data["sourceFingerprint"]):
                    result = {
                        "success": True,
                        "action": "verify",
                        "idempotent": True,
                        "weeklyHours": data,
                        "verification": _payroll_verification_state(
                            row,
                            current_source_fingerprint=data["sourceFingerprint"],
                        ),
                    }
                else:
                    raise HTTPException(
                        status_code=409,
                        detail="Payroll week is already verified from a different source; reopen before verifying again",
                    )
            else:
                before_state = _payroll_verification_state(row) if row else None
                if row is None:
                    saved = _insert_payroll_verification_batch(
                        cur,
                        data=data,
                        actor=current_payroll,
                    )
                else:
                    saved = _update_payroll_verification_batch(
                        cur,
                        batch_id=int(row["id"]),
                        data=data,
                        actor=current_payroll,
                    )
                after_state = _payroll_verification_state(
                    saved,
                    current_source_fingerprint=data["sourceFingerprint"],
                )
                _insert_payroll_verification_event(
                    cur,
                    batch_row=saved,
                    action="verify",
                    actor=current_payroll,
                    reason=payload.reason,
                    before_state=before_state,
                    after_state=after_state,
                )
                result = {
                    "success": True,
                    "action": "verify",
                    "idempotent": False,
                    "weeklyHours": data,
                    "verification": after_state,
                }

    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_VERIFY",
        True,
        f"week={week_start.isoformat()} batch={result['verification']['batchId']} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/reopen")
def admin_reopen_payroll_weekly_hours(
    payload: PayrollReopenRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    reason = payload.reason.strip()
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_payroll_verification_week(cur, week_start)
            row = _get_payroll_verification_batch(cur, week_start, lock=True)
            if row is None:
                raise HTTPException(status_code=404, detail="Payroll week has not been verified")
            if row["status"] == "reopened":
                result = {
                    "success": True,
                    "action": "reopen",
                    "idempotent": True,
                    "verification": _payroll_verification_state(row),
                }
            else:
                before_state = _payroll_verification_state(row)
                cur.execute(
                    """
                    UPDATE payroll_verification_batches
                    SET
                        status = 'reopened',
                        reopened_by_employee_id = %s,
                        reopened_by_name = %s,
                        reopened_reason = %s,
                        reopened_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                        reason,
                        int(row["id"]),
                    ),
                )
                saved = dict(cur.fetchone())
                after_state = _payroll_verification_state(saved)
                _insert_payroll_verification_event(
                    cur,
                    batch_row=saved,
                    action="reopen",
                    actor=current_payroll,
                    reason=reason,
                    before_state=before_state,
                    after_state=after_state,
                )
                result = {
                    "success": True,
                    "action": "reopen",
                    "idempotent": False,
                    "verification": after_state,
                }

    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_REOPEN",
        True,
        f"week={week_start.isoformat()} batch={result['verification']['batchId']} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/money/verify")
def admin_verify_payroll_money(
    payload: PayrollMoneyVerificationRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Fixed lock order (hours week -> money week -> source rows) so the
            # money and finalize flows can never deadlock against each other.
            _lock_payroll_verification_week(cur, week_start)
            _lock_payroll_money_verification_week(cur, week_start)
            _lock_payroll_money_source_rows(cur)
            data = _compute_payroll_timesheet(week_start.isoformat(), cursor=cur)
            _ensure_payroll_money_snapshot_current(payload.moneyFingerprint, data, "verifying")
            # Money can only be signed off on top of a CURRENT hours sign-off.
            hours_data = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
            _ensure_hours_verified_and_current(
                cur, week_start, hours_data, "verifying payroll dollars"
            )
            row = _get_payroll_money_verification_batch(cur, week_start, lock=True)
            if row and row["status"] == "verified":
                if hmac.compare_digest(
                    str(row["source_fingerprint"]), data["timesheetSourceFingerprint"]
                ):
                    result = {
                        "success": True,
                        "action": "verify",
                        "idempotent": True,
                        "timesheet": data,
                        "moneyVerification": _payroll_money_verification_state(
                            row,
                            current_money_fingerprint=data["timesheetSourceFingerprint"],
                        ),
                    }
                else:
                    raise HTTPException(
                        status_code=409,
                        detail="Payroll dollars are already verified from a different source; reopen before verifying again",
                    )
            else:
                before_state = _payroll_money_verification_state(row) if row else None
                if row is None:
                    saved = _insert_payroll_money_verification_batch(
                        cur, data=data, actor=current_payroll
                    )
                else:
                    saved = _update_payroll_money_verification_batch(
                        cur, batch_id=int(row["id"]), data=data, actor=current_payroll
                    )
                after_state = _payroll_money_verification_state(
                    saved, current_money_fingerprint=data["timesheetSourceFingerprint"]
                )
                _insert_payroll_money_verification_event(
                    cur,
                    batch_row=saved,
                    action="verify",
                    actor=current_payroll,
                    reason=payload.reason,
                    before_state=before_state,
                    after_state=after_state,
                )
                result = {
                    "success": True,
                    "action": "verify",
                    "idempotent": False,
                    "timesheet": data,
                    "moneyVerification": after_state,
                }

    append_access_log(
        request,
        "PAYROLL_MONEY_VERIFY",
        True,
        f"week={week_start.isoformat()} batch={result['moneyVerification']['batchId']} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/money/reopen")
def admin_reopen_payroll_money(
    payload: PayrollReopenRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    reason = payload.reason.strip()
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            _lock_payroll_money_verification_week(cur, week_start)
            row = _get_payroll_money_verification_batch(cur, week_start, lock=True)
            if row is None:
                raise HTTPException(
                    status_code=404, detail="Payroll dollars have not been verified"
                )
            if row["status"] == "reopened":
                result = {
                    "success": True,
                    "action": "reopen",
                    "idempotent": True,
                    "moneyVerification": _payroll_money_verification_state(row),
                }
            else:
                before_state = _payroll_money_verification_state(row)
                cur.execute(
                    """
                    UPDATE payroll_money_verification_batches
                    SET
                        status = 'reopened',
                        reopened_by_employee_id = %s,
                        reopened_by_name = %s,
                        reopened_reason = %s,
                        reopened_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                        reason,
                        int(row["id"]),
                    ),
                )
                saved = dict(cur.fetchone())
                after_state = _payroll_money_verification_state(saved)
                _insert_payroll_money_verification_event(
                    cur,
                    batch_row=saved,
                    action="reopen",
                    actor=current_payroll,
                    reason=reason,
                    before_state=before_state,
                    after_state=after_state,
                )
                result = {
                    "success": True,
                    "action": "reopen",
                    "idempotent": False,
                    "moneyVerification": after_state,
                }

    append_access_log(
        request,
        "PAYROLL_MONEY_REOPEN",
        True,
        f"week={week_start.isoformat()} batch={result['moneyVerification']['batchId']} idempotent={result['idempotent']}",
    )
    return result


@app.post("/api/admin/payroll/weekly-hours/finalize")
def admin_finalize_payroll_weekly_hours(
    payload: PayrollVerificationRequest,
    request: Request,
    current_payroll: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    week_start = _parse_payroll_week_start(payload.weekStart)
    result: Dict[str, Any]
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Fixed lock order (hours week -> money week -> source rows), matching
            # the money-verify path so finalize and money verify cannot deadlock.
            _lock_payroll_verification_week(cur, week_start)
            _lock_payroll_money_verification_week(cur, week_start)
            _lock_payroll_money_source_rows(cur)
            data = _compute_payroll_weekly_hours(week_start.isoformat(), cursor=cur)
            _ensure_payroll_snapshot_current(payload.sourceFingerprint, data, "finalizing")
            _ensure_payroll_snapshot_has_no_blocking_issues(data, "finalizing this week")
            row = _get_payroll_verification_batch(cur, week_start, lock=True)
            money_row = _get_payroll_money_verification_batch(cur, week_start, lock=True)
            if row is None:
                raise HTTPException(status_code=409, detail="Verify the payroll week before finalizing")
            if row["status"] == "finalized":
                if hmac.compare_digest(str(row["source_fingerprint"]), data["sourceFingerprint"]):
                    # Re-finalizing an already-finalized week still requires the
                    # money sign-off to be current: reopening money after finalize
                    # must not leave the week reported as settled.
                    _ensure_payroll_money_signed_off(cur, week_start, money_row)
                    result = {
                        "success": True,
                        "action": "finalize",
                        "idempotent": True,
                        "weeklyHours": data,
                        "verification": _payroll_verification_state(
                            row,
                            current_source_fingerprint=data["sourceFingerprint"],
                        ),
                    }
                else:
                    raise HTTPException(
                        status_code=409,
                        detail="Finalized payroll week is stale; reopen before finalizing again",
                    )
            elif row["status"] != "verified":
                raise HTTPException(status_code=409, detail="Verify the payroll week before finalizing")
            elif not hmac.compare_digest(str(row["source_fingerprint"]), data["sourceFingerprint"]):
                raise HTTPException(
                    status_code=409,
                    detail="Verified payroll week is stale; reopen and verify again before finalizing",
                )
            else:
                # FINALIZED is the terminal state of the WHOLE payroll: it requires
                # BOTH truths signed off and current. Hours are verified+current
                # (checked above); the money sign-off must also be current.
                _ensure_payroll_money_signed_off(cur, week_start, money_row)
                before_state = _payroll_verification_state(row)
                cur.execute(
                    """
                    UPDATE payroll_verification_batches
                    SET
                        status = 'finalized',
                        finalized_by_employee_id = %s,
                        finalized_by_name = %s,
                        finalized_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        int(current_payroll["id"]),
                        str(current_payroll["name"]),
                        int(row["id"]),
                    ),
                )
                saved = dict(cur.fetchone())
                after_state = _payroll_verification_state(
                    saved,
                    current_source_fingerprint=data["sourceFingerprint"],
                )
                _insert_payroll_verification_event(
                    cur,
                    batch_row=saved,
                    action="finalize",
                    actor=current_payroll,
                    reason=payload.reason,
                    before_state=before_state,
                    after_state=after_state,
                )
                result = {
                    "success": True,
                    "action": "finalize",
                    "idempotent": False,
                    "weeklyHours": data,
                    "verification": after_state,
                }

    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_FINALIZE",
        True,
        f"week={week_start.isoformat()} batch={result['verification']['batchId']} idempotent={result['idempotent']}",
    )
    return result


@app.get("/api/admin/payroll/labor-profitability")
def admin_payroll_labor_profitability(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Dict[str, Any]:
    parsed_week_start = _parse_payroll_week_start(
        _payroll_week_start_query(request, week_start)
    )
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            weekly_hours = _compute_payroll_weekly_hours(
                parsed_week_start.isoformat(),
                cursor=cur,
            )
            cur.execute(
                """
                SELECT *
                FROM payroll_verification_batches
                WHERE week_start = %s
                """,
                (parsed_week_start,),
            )
            verification_row = cur.fetchone()
            settings = load_settings(cursor=cur)
            allocation_rows = _payroll_correction_allocation_rows(
                parsed_week_start,
                cursor=cur,
            )
            result = build_weekly_labor_profitability(
                parsed_week_start,
                timezone_name=TIMEZONE_NAME,
                now_provider=utc_now,
                default_target_labor_pct=settings.get(
                    "laborPctTarget",
                    _SETTINGS_DEFAULTS["laborPctTarget"],
                ),
                default_min_margin_pct=settings.get(
                    "grossMarginMin",
                    _SETTINGS_DEFAULTS["grossMarginMin"],
                ),
                payroll_week_start=parsed_week_start,
                cursor=cur,
            )
    candidate_segments = result.pop("_payrollCorrectionCandidateSegments", [])
    unallocated_corrections = _annotate_labor_profitability_daily_payroll_proof(
        result,
        weekly_hours,
        candidate_segments,
        allocation_rows,
    )
    payroll_summary = weekly_hours["summary"]
    issues: List[Dict[str, str]] = []
    if payroll_summary["hasBlockingIssues"]:
        issues.append(
            {
                "code": "payroll_weekly_hours_has_blocking_issues",
                "message": (
                    "Resolve payroll weekly-hours issues before relying on "
                    "labor profitability."
                ),
            }
        )
    if unallocated_corrections["unallocated"]:
        issues.append(
            {
                "code": "payroll_hour_corrections_not_allocated_to_sites",
                "message": (
                    "Payroll hour corrections adjust employee/day totals, but "
                    "do not identify which customer or Site should receive the "
                    "labor adjustment yet."
                ),
            }
        )
    if unallocated_corrections["invalid"]:
        issues.append(
            {
                "code": "payroll_hour_corrections_invalid_allocations",
                "message": (
                    "One or more payroll hour correction allocations no longer "
                    "match the current profitability proof."
                ),
            }
        )

    result["payrollHours"] = {
        "sourceFingerprint": weekly_hours["sourceFingerprint"],
        "totalMinutes": payroll_summary["totalMinutes"],
        "totalHours": payroll_summary["totalHours"],
        "correctionCount": payroll_summary["correctionCount"],
        "unallocatedCorrectionCount": result["summary"]["unallocatedCorrectionCount"],
        "invalidAllocationCount": result["summary"]["invalidAllocationCount"],
        "allocatedCorrectionCount": result["summary"]["allocatedCorrectionCount"],
        "allocatedCorrectionDeltaMinutes": result["summary"]["allocatedCorrectionDeltaMinutes"],
        "allocatedCorrectionDeltaHours": result["summary"]["allocatedCorrectionDeltaHours"],
        "allocatedCorrectionLaborCost": result["summary"]["allocatedCorrectionLaborCost"],
        "knownAllocatedCorrectionLaborCost": result["summary"]["knownAllocatedCorrectionLaborCost"],
        "allocatedCorrectionLaborCostComplete": result["summary"]["allocatedCorrectionLaborCostComplete"],
        "unallocatedCorrectionCandidateCount": sum(
            int(row.get("candidateSiteCount") or 0)
            for row in unallocated_corrections["unallocated"]
        ),
        "unallocatedCorrections": unallocated_corrections["unallocated"],
        "invalidAllocatedCorrections": unallocated_corrections["invalid"],
        "allocatedCorrections": unallocated_corrections["allocated"],
        "issueCount": payroll_summary["issueCount"],
        "hasBlockingIssues": payroll_summary["hasBlockingIssues"],
    }
    result["verification"] = _payroll_verification_state(
        verification_row,
        current_source_fingerprint=weekly_hours["sourceFingerprint"],
    )
    result["issues"] = issues
    append_access_log(
        request,
        "PAYROLL_LABOR_PROFITABILITY",
        True,
        (
            f"week={result['weekStart']} jobs={result['summary']['jobCount']} "
            f"unmatched={result['summary']['unmatchedActualSegmentCount']} "
            f"corrections={payroll_summary['correctionCount']}"
        ),
    )
    return result


def _payroll_weekly_hours_verification_for_pdf(
    week_start: date,
    source_fingerprint: str,
) -> Dict[str, Any]:
    row = db.query_one(
        """
        SELECT *
        FROM payroll_verification_batches
        WHERE week_start = %s
        """,
        (week_start,),
    )
    return _payroll_verification_state(
        row,
        current_source_fingerprint=source_fingerprint,
    )


@app.get("/api/admin/payroll/weekly-hours/export")
def admin_payroll_weekly_hours_export(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> StreamingResponse:
    data = _compute_payroll_weekly_hours(_payroll_week_start_query(request, week_start))

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["EOM Payroll Weekly Hours"])
    writer.writerow(["Week Start", data["weekStart"], "Week End", data["weekEnd"]])
    writer.writerow(["Timezone", data["timezone"], "Source Fingerprint", data["sourceFingerprint"]])
    writer.writerow([])
    writer.writerow(["Employee", "Status", "Total Hours", "Total Minutes", "Completed Shifts", "Issues"])
    for employee in data["employees"]:
        writer.writerow(
            [
                employee["employeeName"],
                "Active" if employee["active"] else "Inactive",
                f'{employee["totalHours"]:.2f}',
                employee["totalMinutes"],
                employee["completedShiftCount"],
                "; ".join(employee["issueCodes"]),
            ]
        )

    buf.seek(0)
    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_EXPORT",
        True,
        f"week={data['weekStart']} employees={data['summary']['employeeCount']} issues={data['summary']['issueCount']}",
    )
    filename = f"eom_payroll_weekly_hours_{data['weekStart']}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/admin/payroll/weekly-hours/pdf")
def admin_payroll_weekly_hours_pdf(
    request: Request,
    week_start: Optional[str] = Query(default=None, alias="weekStart"),
    _: Dict[str, Any] = Depends(get_current_payroll),
) -> Response:
    data = _compute_payroll_weekly_hours(_payroll_week_start_query(request, week_start))
    parsed_week_start = _parse_payroll_week_start(data["weekStart"])
    verification = _payroll_weekly_hours_verification_for_pdf(
        parsed_week_start,
        data["sourceFingerprint"],
    )
    pdf_bytes = build_payroll_weekly_hours_pdf(
        data,
        verification=verification,
    )
    append_access_log(
        request,
        "PAYROLL_WEEKLY_HOURS_PDF",
        True,
        f"week={data['weekStart']} employees={data['summary']['employeeCount']} corrections={data['summary'].get('correctionCount', 0)}",
    )
    filename = f"eom_payroll_weekly_hours_{data['weekStart']}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


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
    shift_corrections_by_shift_id = _payroll_shift_corrections_by_shift_id(
        _payroll_active_shift_correction_rows_for_shift_ids(
            _hours_report_shift_ids(timesheet_data["entries"]),
        ),
    )

    rows = []
    emp_totals: Dict[int, Dict[str, Any]] = {}

    for entry in timesheet_data["entries"]:
        shift_id = _hours_report_entry_shift_id(entry)
        shift_correction = (
            shift_corrections_by_shift_id.get(shift_id)
            if shift_id is not None
            else None
        )
        effective_interval = _hours_report_effective_shift_interval(
            entry,
            shift_correction,
            now,
        )
        if effective_interval is None:
            continue
        ci_dt, co_dt, hours = effective_interval

        entry_date = to_local(ci_dt).date()
        if not (start_date <= entry_date <= end_date):
            continue

        emp_id = int(entry.get("employeeId", 0))
        if employee_id and emp_id != employee_id:
            continue

        emp_name = emp_names.get(emp_id, str(entry.get("employeeName", f"Employee {emp_id}")))
        co_display = local_clock_string(co_dt)

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
    total_hours = sum(s["totalHours"] for s in summary)
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
        "totalHours": round(total_hours, 2),
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


@app.get("/api/admin/reports/hours/pdf")
def admin_reports_hours_pdf(
    request: Request,
    period: str = "week",
    date: Optional[str] = None,
    employee_id: Optional[int] = None,
    exceptions_only: bool = False,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Response:
    data = _compute_hours_report(period, date, employee_id, exceptions_only)
    pdf_bytes = build_hours_report_pdf(data, employee_id=employee_id)
    filename_parts = ["eom_hours", period, data["startDate"]]
    if employee_id:
        filename_parts.append(f"employee-{employee_id}")
    if exceptions_only:
        filename_parts.append("gps-exceptions")
    filename = "_".join(filename_parts) + ".pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def load_settings(*, cursor: Optional[Any] = None) -> Dict[str, Any]:
    defaults: Dict[str, Any] = _SETTINGS_DEFAULTS.copy()
    rows = _payroll_query_all("SELECT key, value FROM settings", cursor=cursor)
    # Keys prefixed with "_" are internal state (e.g. one-time migration
    # completion markers) that piggyback on the settings table for atomicity.
    # They must never surface in load_settings() output, which feeds the public
    # GET /api/admin/settings response and the PUT round-trip.
    data: Dict[str, Any] = {
        r["key"]: r["value"] for r in rows if not r["key"].startswith("_")
    }
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
               COALESCE(
                   SUM(
                       GREATEST(
                           0.0,
                           EXTRACT(EPOCH FROM (s.clock_out - s.clock_in)) / 3600.0
                       )
                   ),
                   0
               ) AS actual_hours
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


def _legacy_forecast_value(
    row: Dict[str, Any],
    complete_key: str,
    complete_value_key: str,
    known_value_key: str,
) -> Optional[float]:
    value = row.get(complete_value_key)
    if bool(row.get(complete_key)) or value is not None:
        return value
    return row.get(known_value_key)


def _legacy_forecast_hours(row: Dict[str, Any]) -> Optional[float]:
    return _legacy_forecast_value(
        row,
        "plannedHoursComplete",
        "plannedHours",
        "knownPlannedHours",
    )


def _legacy_forecast_money(
    row: Dict[str, Any],
    complete_key: str,
    complete_value_key: str,
    known_value_key: str,
) -> Optional[float]:
    value = _legacy_forecast_value(
        row,
        complete_key,
        complete_value_key,
        known_value_key,
    )
    return round(float(value), 2) if value is not None else None


def _legacy_forecast_percent(
    numerator: Optional[float],
    denominator: Optional[float],
) -> Optional[float]:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator / denominator * 100, 1)


def _legacy_forecast_by_customer(site_row: Dict[str, Any]) -> Dict[str, Any]:
    forecast_hours = _legacy_forecast_hours(site_row)
    est_labor = _legacy_forecast_money(
        site_row,
        "laborCostComplete",
        "estLaborCost",
        "knownLaborCost",
    )
    est_revenue = _legacy_forecast_money(
        site_row,
        "revenueComplete",
        "estRevenue",
        "knownRevenue",
    )
    customer_name = str(
        site_row.get("customerName")
        or site_row.get("siteAddress")
        or "Unknown"
    )
    return {
        "customerId": site_row.get("customerId"),
        "locationId": site_row.get("locationId"),
        "customer": customer_name,
        "forecastHours": round(float(forecast_hours), 2)
        if forecast_hours is not None
        else None,
        "source": "operations",
        "estLaborCost": est_labor,
        "estRevenue": est_revenue,
        "issues": site_row.get("issues", []),
    }


def _legacy_forecast_week(week: Dict[str, Any]) -> Dict[str, Any]:
    total_hours = _legacy_forecast_hours(week)
    total_labor = _legacy_forecast_money(
        week,
        "laborCostComplete",
        "estLaborCost",
        "knownLaborCost",
    )
    total_revenue = _legacy_forecast_money(
        week,
        "revenueComplete",
        "estRevenue",
        "knownRevenue",
    )
    net = (
        round(total_revenue - total_labor, 2)
        if total_revenue is not None and total_labor is not None
        else None
    )
    by_customer = [
        _legacy_forecast_by_customer(site_row)
        for site_row in week.get("bySite", [])
    ]
    return {
        "weekStart": week["weekStart"],
        "weekEnd": week["weekEnd"],
        "totalHours": round(float(total_hours), 2)
        if total_hours is not None
        else None,
        "estLaborCost": total_labor,
        "estRevenue": total_revenue,
        "estNetProfit": net,
        "estMarginPct": _legacy_forecast_percent(net, total_revenue),
        "estLaborPct": _legacy_forecast_percent(total_labor, total_revenue),
        "byCustomer": sorted(
            by_customer,
            key=lambda row: (
                -(row["forecastHours"] or 0),
                str(row.get("customer") or "").casefold(),
                int(row.get("locationId") or 0),
            ),
        ),
    }


@app.get("/api/admin/analytics/forecast")
def admin_forecast(
    request: Request,
    weeks_ahead: int = 4,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Legacy forecast response backed by the canonical operations forecast."""
    if weeks_ahead < 1:
        raise HTTPException(status_code=400, detail="weeks_ahead must be at least 1")
    settings = load_settings()
    canonical = build_operations_forecast(
        weeks_ahead,
        timezone_name=TIMEZONE_NAME,
        now_provider=utc_now,
    )
    forecasts = [_legacy_forecast_week(week) for week in canonical["weeks"]]

    return {
        "success": True,
        "weeksAhead": weeks_ahead,
        "avgLaborRate": canonical.get("avgLaborRate"),
        "laborPctTarget": settings.get("laborPctTarget", _SETTINGS_DEFAULTS["laborPctTarget"]),
        "issues": canonical.get("issues", []),
        "summary": canonical.get("summary"),
        "weeks": forecasts,
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
    rows = db.query_all(
        """
        SELECT s.id, s.clock_in, s.clock_out,
               GREATEST(
                   0.0,
                   EXTRACT(EPOCH FROM (s.clock_out - s.clock_in)) / 3600.0
               ) AS total_hours,
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
               GREATEST(
                   0.0,
                   EXTRACT(EPOCH FROM (s.clock_out - s.clock_in)) / 3600.0
               ) AS total_hours,
               s.time_category, s.non_productive_type,
               s.notes, s.local_date,
               -- Prefer the rate the shift was worked at; fall back to the live
               -- rate only when the shift carries no snapshot. NULL on both
               -- sides still means "no rate", so the zero-cost +
               -- missingRateCount policy below is unchanged.
               COALESCE(s.hourly_rate_cents::numeric / 100, e.hourly_rate)
                   AS hourly_rate
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
        revenue_gap = (
            round(required_revenue - actual_revenue, 2)
            if required_revenue is not None and actual_revenue is not None
            else None
        )
        pct_increase = (
            round(revenue_gap / actual_revenue * 100, 1)
            if revenue_gap is not None and actual_revenue is not None and actual_revenue > 0
            else None
        )

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
            "knownRevenue": c.get("knownRevenue", actual_revenue),
            "revenueComplete": c.get("revenueComplete", True),
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
            "issues": c.get("issues", []),
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


def _require_manual_job_mutation(row: Dict[str, Any]) -> None:
    if row.get("source_key") is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CALENDAR_JOB_READ_ONLY",
                "message": (
                    "Calendar-owned jobs are read-only; update the Google Calendar "
                    "occurrence instead"
                ),
            },
        )


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
    """Auto-link only when an exact Site/date and timed-window match is unambiguous."""
    jobs = db.query_all(
        """
        SELECT j.id, j.location_id, j.customer_name, j.scheduled_date,
               j.scheduled_start, j.scheduled_end
        FROM jobs j
        WHERE j.status != 'cancelled'
        """
    )

    site_rows = db.query_all(
        """
        SELECT l.id, l.address, l.active,
               COALESCE(c.name, l.customer_name, '') AS customer_name
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        """
    )
    site_id_by_address = {
        str(row["address"]): int(row["id"])
        for row in site_rows
    }
    customer_by_address = {
        str(row["address"]): str(row.get("customer_name") or "")
        for row in site_rows
    }
    active_site_ids_by_customer_name: Dict[str, set[int]] = {}
    for row in site_rows:
        if not bool(row.get("active")):
            continue
        normalized_name = str(row.get("customer_name") or "").strip().casefold()
        if normalized_name:
            active_site_ids_by_customer_name.setdefault(normalized_name, set()).add(
                int(row["id"])
            )

    timed_jobs_by_site: Dict[int, List[Dict[str, Any]]] = {}
    fallback_jobs_by_site_date: Dict[Tuple[int, date], List[Dict[str, Any]]] = {}
    timed_legacy_jobs_by_name: Dict[str, List[Dict[str, Any]]] = {}
    fallback_legacy_jobs_by_name_date: Dict[
        Tuple[str, date], List[Dict[str, Any]]
    ] = {}
    for job in jobs:
        scheduled_date = job.get("scheduled_date")
        if not scheduled_date:
            continue
        scheduled_start = job.get("scheduled_start")
        scheduled_end = job.get("scheduled_end")
        has_valid_window = (
            scheduled_start is not None
            and scheduled_end is not None
            and scheduled_end > scheduled_start
        )
        if job.get("location_id") is not None:
            if has_valid_window:
                timed_jobs_by_site.setdefault(int(job["location_id"]), []).append(job)
            else:
                fallback_jobs_by_site_date.setdefault(
                    (int(job["location_id"]), scheduled_date),
                    [],
                ).append(job)
            continue
        normalized_name = str(job.get("customer_name") or "").strip().casefold()
        if normalized_name:
            if has_valid_window:
                timed_legacy_jobs_by_name.setdefault(normalized_name, []).append(job)
            else:
                fallback_legacy_jobs_by_name_date.setdefault(
                    (normalized_name, scheduled_date),
                    [],
                ).append(job)

    unlinked = db.query_all(
        """
        SELECT s.id, s.local_date, s.location_id, s.clock_in, s.clock_out,
               COALESCE(l.address, s.location_label, '') AS location
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
                    shift_date = shift.get("local_date")
                    location = str(shift.get("location") or "")
                    shift_site_id = (
                        int(shift["location_id"])
                        if shift.get("location_id") is not None
                        else site_id_by_address.get(location)
                    )
                    shift_customer = customer_by_address.get(location, location)
                    normalized_customer = shift_customer.strip().casefold()
                    active_name_site_ids = active_site_ids_by_customer_name.get(
                        normalized_customer,
                        set(),
                    )
                    if shift_site_id is None and len(active_name_site_ids) == 1:
                        shift_site_id = next(iter(active_name_site_ids))

                    def eligible_candidates(
                        timed_candidates: List[Dict[str, Any]],
                        fallback_candidates: List[Dict[str, Any]],
                    ) -> List[Dict[str, Any]]:
                        eligible_by_id = {
                            int(job["id"]): job
                            for job in timed_candidates
                            if (
                                job["scheduled_start"] < shift["clock_out"]
                                and job["scheduled_end"] > shift["clock_in"]
                            )
                        }
                        for job in fallback_candidates:
                            eligible_by_id[int(job["id"])] = job
                        return list(eligible_by_id.values())

                    site_fallback_candidates = (
                        fallback_jobs_by_site_date.get(
                            (shift_site_id, shift_date),
                            [],
                        )
                        if shift_site_id is not None and shift_date is not None
                        else []
                    )
                    candidates = eligible_candidates(
                        (
                            timed_jobs_by_site.get(shift_site_id, [])
                            if shift_site_id is not None
                            else []
                        ),
                        site_fallback_candidates,
                    )
                    if not candidates and len(active_name_site_ids) == 1:
                        if shift_site_id in active_name_site_ids:
                            legacy_fallback_candidates = (
                                fallback_legacy_jobs_by_name_date.get(
                                    (normalized_customer, shift_date),
                                    [],
                                )
                                if shift_date is not None
                                else []
                            )
                            candidates = eligible_candidates(
                                timed_legacy_jobs_by_name.get(
                                    normalized_customer,
                                    [],
                                ),
                                legacy_fallback_candidates,
                            )
                    if len(candidates) != 1:
                        continue
                    cur.execute(
                        "UPDATE shifts SET job_id = %s WHERE id = %s AND job_id IS NULL",
                        (candidates[0]["id"], shift["id"]),
                    )
                    if cur.rowcount > 0:
                        linked += 1

    append_access_log(request, "JOBS_AUTO_LINKED", True, f"{linked} shifts auto-linked")
    return {"success": True, "linkedCount": linked}


def _profitability_nonnegative_decimal(value: Any) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not amount.is_finite() or amount < 0:
        return None
    return amount


def _profitability_money_cents(value: Any) -> Optional[int]:
    amount = _profitability_nonnegative_decimal(value)
    if amount is None:
        return None
    quantized = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int((quantized * 100).to_integral_value())


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
               s.clock_in,
               s.clock_out,
               CASE
                   WHEN s.clock_out IS NULL THEN NULL
                   ELSE GREATEST(
                       0.0,
                       EXTRACT(EPOCH FROM (s.clock_out - s.clock_in)) / 3600.0
                   )
               END AS total_hours,
               s.notes,
               -- Prefer the rate the shift was worked at; fall back to the live
               -- rate only when the shift carries no snapshot. NULL on both
               -- sides still means "no rate", so the silent-zero labor cost
               -- policy below is unchanged.
               COALESCE(s.hourly_rate_cents::numeric / 100, e.hourly_rate)
                   AS hourly_rate
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
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE id = %s FOR UPDATE", (job_id,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Job not found")
            _require_manual_job_mutation(existing)

            sets = []
            params: list = []
            if payload.customerName is not None:
                sets.append("customer_name = %s")
                params.append(payload.customerName.strip())
            if payload.scheduledDate is not None:
                try:
                    datetime.strptime(payload.scheduledDate, "%Y-%m-%d")
                except ValueError:
                    raise HTTPException(
                        status_code=400, detail="scheduledDate must be YYYY-MM-DD"
                    )
                sets.append("scheduled_date = %s")
                params.append(payload.scheduledDate)
            if payload.expectedHours is not None:
                if payload.expectedHours < 0:
                    raise HTTPException(
                        status_code=400, detail="expectedHours cannot be negative"
                    )
                sets.append("expected_hours = %s")
                params.append(payload.expectedHours)
            if payload.revenue is not None:
                if payload.revenue < 0:
                    raise HTTPException(
                        status_code=400, detail="revenue cannot be negative"
                    )
                sets.append("revenue = %s")
                params.append(payload.revenue)
            if payload.notes is not None:
                sets.append("notes = %s")
                params.append(payload.notes)
            if payload.status is not None:
                if payload.status not in (
                    "scheduled",
                    "in_progress",
                    "completed",
                    "cancelled",
                ):
                    raise HTTPException(status_code=400, detail="Invalid status")
                sets.append("status = %s")
                params.append(payload.status)
            if payload.locationId is not None:
                sets.append("location_id = %s")
                params.append(payload.locationId)

            if not sets:
                raise HTTPException(status_code=400, detail="No fields to update")

            params.append(job_id)
            cur.execute(
                f"UPDATE jobs SET {', '.join(sets)} WHERE id = %s RETURNING *",
                tuple(params),
            )
            row = cur.fetchone()
    append_access_log(request, "JOB_UPDATED", True, f"Job {job_id}")
    return {"success": True, "job": _job_row_to_dict(row)}


@app.delete("/api/admin/jobs/{job_id}")
def admin_delete_job(
    job_id: int,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Delete a job. Unlinks any associated shifts first."""
    with TIMESHEET_WRITE_LOCK:
        with db.get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, source_key FROM jobs WHERE id = %s FOR UPDATE",
                    (job_id,),
                )
                existing = cur.fetchone()
                if not existing:
                    raise HTTPException(status_code=404, detail="Job not found")
                _require_manual_job_mutation(existing)
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


def _analytics_entry_job_id(value: Any) -> Optional[int]:
    try:
        job_id = int(value)
    except (TypeError, ValueError):
        return None
    return job_id if job_id > 0 else None


def _analytics_missing_revenue_issue(
    *,
    job_id: Optional[int] = None,
    location: Optional[str] = None,
    customer: Optional[str] = None,
    date_key: Optional[str] = None,
) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "code": "missing_revenue",
        "message": "Revenue cannot be calculated from this linked job's Site rate card."
        if job_id is not None
        else "Revenue cannot be calculated from this location's rate card.",
    }
    if job_id is not None:
        issue["jobId"] = job_id
    if location:
        issue["location"] = location
    if customer:
        issue["customer"] = customer
    if date_key:
        issue["date"] = date_key
    return issue


def _analytics_extend_unique_issues(
    target: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
) -> None:
    for issue in issues:
        if issue not in target:
            target.append(issue)


def _analytics_linked_job_revenue_cents(
    job_ids: set[int],
) -> Tuple[Dict[int, Optional[int]], set[Tuple[str, str]], Dict[int, Dict[str, Any]]]:
    """Return canonical rate-card revenue for linked single-location jobs."""
    if not job_ids:
        return {}, set(), {}

    selected_jobs = db.query_all(
        """
        SELECT j.id, j.location_id, j.scheduled_date, j.scheduled_start,
               j.status, l.address, l.rate, l.rate_type,
               l.expected_hours AS site_expected_hours
        FROM jobs j
        JOIN locations l ON l.id = j.location_id
        WHERE j.id = ANY(%s)
        """,
        (sorted(job_ids),),
    )
    monthly_groups: Dict[Tuple[int, int, int], Any] = {}
    monthly_linked_job_ids: set[int] = set()
    revenue_by_job: Dict[int, Optional[int]] = {}
    canonical_site_months: set[Tuple[str, str]] = set()
    issues_by_job: Dict[int, Dict[str, Any]] = {}
    for row in selected_jobs:
        job_id = int(row["id"])
        rate_type = str(row.get("rate_type") or "")
        if row.get("status") == "cancelled":
            revenue_by_job[job_id] = 0
            continue
        if row.get("location_id") is None:
            revenue_by_job[job_id] = None
            issues_by_job[job_id] = _analytics_missing_revenue_issue(job_id=job_id)
            continue
        rate_cents = _profitability_money_cents(row.get("rate"))
        if rate_cents is None:
            revenue_by_job[job_id] = None
            issues_by_job[job_id] = _analytics_missing_revenue_issue(job_id=job_id)
            continue
        if rate_type == "per_visit":
            revenue_by_job[job_id] = rate_cents
        elif rate_type == "hourly":
            expected = _profitability_nonnegative_decimal(
                row.get("site_expected_hours")
            )
            revenue_by_job[job_id] = (
                int(
                    (Decimal(rate_cents) * expected).quantize(
                        Decimal("1"),
                        rounding=ROUND_HALF_UP,
                    )
                )
                if expected is not None
                else None
            )
            if revenue_by_job[job_id] is None:
                issues_by_job[job_id] = _analytics_missing_revenue_issue(job_id=job_id)
        elif rate_type == "monthly":
            scheduled_date = row["scheduled_date"]
            monthly_linked_job_ids.add(job_id)
            monthly_groups[
                (
                    int(row["location_id"]),
                    scheduled_date.year,
                    scheduled_date.month,
                )
            ] = row.get("rate")
            canonical_site_months.add(
                (
                    str(row["address"] or ""),
                    f"{scheduled_date.year}-{scheduled_date.month:02d}",
                )
            )
        else:
            revenue_by_job[job_id] = None
            issues_by_job[job_id] = _analytics_missing_revenue_issue(job_id=job_id)

    if not monthly_groups:
        return revenue_by_job, canonical_site_months, issues_by_job

    month_starts = [
        date(year, month, 1)
        for _, year, month in monthly_groups
    ]
    month_ends = [
        date(year, month, calendar.monthrange(year, month)[1])
        for _, year, month in monthly_groups
    ]
    candidate_rows = db.query_all(
        """
        SELECT j.id, j.location_id, j.scheduled_date, j.scheduled_start,
               j.status, l.rate, l.rate_type
        FROM jobs j
        JOIN locations l ON l.id = j.location_id
        WHERE j.location_id = ANY(%s)
          AND j.scheduled_date BETWEEN %s AND %s
        ORDER BY j.scheduled_date, j.scheduled_start NULLS FIRST, j.id
        """,
        (
            sorted({group[0] for group in monthly_groups}),
            min(month_starts),
            max(month_ends),
        ),
    )
    app_timezone = ZoneInfo(TIMEZONE_NAME)
    monthly_allocations = monthly_revenue_allocations(
        [dict(row) for row in candidate_rows],
        app_timezone,
    )
    for job_id in monthly_linked_job_ids:
        if job_id in monthly_allocations:
            revenue_by_job[job_id] = monthly_allocations[job_id]
        elif job_id not in revenue_by_job:
            revenue_by_job[job_id] = None
            issues_by_job[job_id] = _analytics_missing_revenue_issue(job_id=job_id)
    return revenue_by_job, canonical_site_months, issues_by_job


def _load_shift_rate_snapshots(
    shift_ids: Optional[Iterable[int]] = None,
) -> Dict[int, float]:
    """Map shift id -> the hourly rate that shift was worked at, in dollars.

    Only shifts that carry a snapshot appear. Callers fall back to the live
    employee rate for shifts that do not, which keeps pre-migration rows and
    rate-less employees behaving exactly as they do today.

    ``cents / 100`` is done in Python from an exact integer, so the resulting
    float is bit-identical to ``float(employees.hourly_rate)`` for the same
    two-decimal rate -- the backfill therefore cannot move any existing figure.
    """
    scoped_ids: Optional[List[int]] = None
    if shift_ids is not None:
        scoped_ids = sorted(
            {
                int(shift_id)
                for shift_id in shift_ids
                if shift_id is not None and int(shift_id) > 0
            }
        )
        if not scoped_ids:
            return {}
        rows = db.query_all(
            """
            SELECT id, hourly_rate_cents
            FROM shifts
            WHERE id = ANY(%s)
              AND hourly_rate_cents IS NOT NULL
            """,
            (scoped_ids,),
        )
        return {
            int(row["id"]): int(row["hourly_rate_cents"]) / 100.0
            for row in rows
        }

    rows = db.query_all(
        "SELECT id, hourly_rate_cents FROM shifts WHERE hourly_rate_cents IS NOT NULL"
    )
    return {int(row["id"]): int(row["hourly_rate_cents"]) / 100.0 for row in rows}


def _entry_shift_id(entry: Dict[str, Any]) -> Optional[int]:
    """Shift id for a timesheet entry -- entries are shifts, keyed by shift id."""
    try:
        shift_id = int(entry.get("id"))
    except (TypeError, ValueError):
        return None
    return shift_id if shift_id > 0 else None


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
    location_rate_types = _historical_location_metadata(
        timesheet_data,
        "location_rate_types",
    )
    location_expected_hours = _historical_location_metadata(
        timesheet_data,
        "location_expected_hours",
    )

    linked_period_job_ids: set[int] = set()
    period_shift_ids: set[int] = set()
    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is None:
            continue
        if entry.get("timeCategory") == "non_productive":
            continue
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
        shift_id = _entry_shift_id(entry)
        if shift_id is not None:
            period_shift_ids.add(shift_id)
        visits = entry.get("visits") or []
        if visits:
            for visit in visits:
                if not isinstance(visit, dict):
                    continue
                job_id = _analytics_entry_job_id(visit.get("jobId"))
                if job_id is not None:
                    linked_period_job_ids.add(job_id)
            continue
        job_id = _analytics_entry_job_id(entry.get("jobId"))
        if job_id is not None:
            linked_period_job_ids.add(job_id)
    (
        linked_job_revenue_cents,
        canonical_monthly_site_months,
        linked_job_revenue_issues,
    ) = _analytics_linked_job_revenue_cents(linked_period_job_ids)

    emp_rates: Dict[int, float] = {}
    for emp in employees_data["employees"]:
        rate = emp.get("hourlyRate")
        if rate is not None:
            emp_rates[emp["id"]] = float(rate)
    # Per-shift snapshot wins over the live employee rate. The employee map is
    # only the fallback for shifts with no snapshot, so a rate edit moves future
    # shifts and leaves worked shifts alone.
    shift_rates = _load_shift_rate_snapshots(period_shift_ids)

    def _effective_rate(shift_id: Optional[int], emp_id: int) -> Optional[float]:
        if shift_id is not None:
            snapshot = shift_rates.get(shift_id)
            if snapshot is not None:
                return snapshot
        # No snapshot and no live rate keeps returning None, which the caller
        # still treats as free labor -- the pre-existing silent-zero policy.
        return emp_rates.get(emp_id)

    linked_jobs_credited: set[int] = set()
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

    def _aggregate(
        customer: str,
        resolved_location: str,
        hours: float,
        emp_id: int,
        entry_date: Any,
        date_key: str,
        is_visit: bool,
        job_id: Optional[int] = None,
        shift_id: Optional[int] = None,
    ) -> None:
        # Determine first-arrival: deduplicates multi-employee same-day visits
        visit_key = (customer, date_key)
        is_new_visit = is_visit and visit_key not in visited_customer_dates
        if is_new_visit:
            visited_customer_dates.add(visit_key)

        linked_cents = (
            linked_job_revenue_cents.get(job_id)
            if job_id is not None
            else None
        )
        revenue_issues: List[Dict[str, Any]] = []
        revenue_complete = True
        if job_id is not None and job_id in linked_job_revenue_cents:
            if job_id not in linked_jobs_credited:
                if linked_cents is not None:
                    revenue = float(Decimal(linked_cents) / Decimal(100))
                else:
                    revenue = 0.0
                    revenue_complete = False
                    issue = linked_job_revenue_issues.get(job_id)
                    if issue:
                        revenue_issues.append(issue)
                linked_jobs_credited.add(job_id)
            else:
                revenue = 0.0
        else:
            rate_type = location_rate_types.get(resolved_location, "per_visit")
            period_month = f"{entry_date.year}-{entry_date.month:02d}"
            site_month_key = (resolved_location, period_month)
            if rate_type == "monthly" and site_month_key in canonical_monthly_site_months:
                revenue = 0.0
            else:
                revenue = 0.0
                revenue_complete = False
                revenue_issues.append(
                    _analytics_missing_revenue_issue(
                        location=resolved_location,
                        customer=customer,
                        date_key=date_key,
                    )
                )

        emp_rate = _effective_rate(shift_id, emp_id)
        labor_cost = (emp_rate * hours) if emp_rate is not None else 0.0

        exp_h = location_expected_hours.get(resolved_location)

        if customer not in customer_agg:
            customer_agg[customer] = {
                "customer": customer, "location": resolved_location,
                "visits": 0, "hours": 0.0, "revenue": 0.0, "laborCost": 0.0,
                "expectedHours": 0.0, "_hasExpected": False,
                "_revenueComplete": True, "issues": [],
            }
        customer_agg[customer]["_revenueComplete"] = (
            bool(customer_agg[customer]["_revenueComplete"]) and revenue_complete
        )
        _analytics_extend_unique_issues(customer_agg[customer]["issues"], revenue_issues)
        if is_new_visit:
            customer_agg[customer]["visits"] += 1
            if exp_h is not None:
                customer_agg[customer]["expectedHours"] += exp_h
                customer_agg[customer]["_hasExpected"] = True
        customer_agg[customer]["hours"] += hours
        customer_agg[customer]["revenue"] += revenue
        customer_agg[customer]["laborCost"] += labor_cost

        if date_key not in day_agg:
            day_agg[date_key] = {
                "date": date_key,
                "visits": 0,
                "hours": 0.0,
                "revenue": 0.0,
                "laborCost": 0.0,
                "_revenueComplete": True,
                "issues": [],
            }
        day_agg[date_key]["_revenueComplete"] = (
            bool(day_agg[date_key]["_revenueComplete"]) and revenue_complete
        )
        _analytics_extend_unique_issues(day_agg[date_key]["issues"], revenue_issues)
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
        # Every visit inside a shift was worked at that shift's rate.
        shift_id = _entry_shift_id(entry)
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
                _aggregate(
                    customer,
                    resolved_location,
                    visit_hours,
                    emp_id,
                    entry_date,
                    date_key,
                    is_visit=True,
                    job_id=_analytics_entry_job_id(visit.get("jobId")),
                    shift_id=shift_id,
                )
        else:
            # Legacy / single-location shift
            hours = entry_hours(entry, now)
            location = entry.get("location", "")
            resolved_location, customer = _resolve_loc(location)
            _aggregate(
                customer,
                resolved_location,
                hours,
                emp_id,
                entry_date,
                date_key,
                is_visit=True,
                job_id=_analytics_entry_job_id(entry.get("jobId")),
                shift_id=shift_id,
            )

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
        known_rev = round(d["revenue"], 2)
        revenue_complete = bool(d.get("_revenueComplete", True))
        rev = known_rev if revenue_complete else None
        lc = d["laborCost"]
        actual_h = round(d["hours"], 2)
        lp = round(lc / rev * 100, 1) if rev is not None and rev > 0 else None
        net = round(rev - lc, 2) if rev is not None else None
        gross_margin = round(net / rev * 100, 1) if rev is not None and rev > 0 and net is not None else None
        has_exp = d.get("_hasExpected", False)
        exp_h = round(d.get("expectedHours", 0.0), 2) if has_exp else None
        variance = round(exp_h - actual_h, 2) if exp_h is not None else None
        rplh = round(rev / actual_h, 2) if rev is not None and actual_h > 0 else None
        flag, flag_reasons = _classify(lp, gross_margin, variance, rplh)
        return {
            "customer": d["customer"],
            "location": d["location"],
            "visits": d["visits"],
            "hours": actual_h,
            "revenue": rev,
            "knownRevenue": known_rev,
            "revenueComplete": revenue_complete,
            "laborCost": round(lc, 2),
            "laborPct": lp,
            "netProfit": net,
            "grossMarginPct": gross_margin,
            "expectedHours": exp_h,
            "varianceHours": variance,
            "rplh": rplh,
            "flag": flag,
            "flagReasons": flag_reasons,
            "issues": list(d.get("issues") or []),
        }

    by_customer = sorted(
        [_finalize(c) for c in customer_agg.values()],
        key=lambda x: x["knownRevenue"],
        reverse=True,
    )
    by_day = sorted(
        [
            {
                "date": d["date"],
                "visits": d["visits"],
                "hours": round(d["hours"], 2),
                "revenue": (
                    round(d["revenue"], 2)
                    if bool(d.get("_revenueComplete", True))
                    else None
                ),
                "knownRevenue": round(d["revenue"], 2),
                "revenueComplete": bool(d.get("_revenueComplete", True)),
                "laborCost": round(d["laborCost"], 2),
                "laborPct": (
                    round(d["laborCost"] / d["revenue"] * 100, 1)
                    if bool(d.get("_revenueComplete", True)) and d["revenue"] > 0
                    else None
                ),
                "netProfit": (
                    round(d["revenue"] - d["laborCost"], 2)
                    if bool(d.get("_revenueComplete", True))
                    else None
                ),
                "issues": list(d.get("issues") or []),
            }
            for d in day_agg.values()
        ],
        key=lambda x: x["date"],
    )

    revenue_complete = all(c.get("revenueComplete", True) for c in by_customer)
    known_total_rev = round(sum(c["knownRevenue"] for c in by_customer), 2)
    total_rev = known_total_rev if revenue_complete else None
    total_lc = sum(c["laborCost"] for c in by_customer)
    total_hours = round(sum(c["hours"] for c in by_customer), 2)
    total_visits = sum(c["visits"] for c in by_customer)
    issues = [
        issue
        for row in by_customer
        for issue in row.get("issues", [])
    ]

    return {
        "success": True,
        "period": period,
        "startDate": start_date.strftime("%Y-%m-%d") if start_date else None,
        "endDate": end_date.strftime("%Y-%m-%d") if end_date else None,
        "laborPctTarget": settings["laborPctTarget"],
        "summary": {
            "revenue": total_rev,
            "knownRevenue": known_total_rev,
            "revenueComplete": revenue_complete,
            "laborCost": round(total_lc, 2),
            "laborPct": round(total_lc / total_rev * 100, 1) if total_rev is not None and total_rev > 0 else None,
            "netProfit": round(total_rev - total_lc, 2) if total_rev is not None else None,
            "grossMarginPct": (
                round((total_rev - total_lc) / total_rev * 100, 1)
                if total_rev is not None and total_rev > 0
                else None
            ),
            "hours": total_hours,
            "visits": total_visits,
        },
        "issues": issues,
        "byCustomer": by_customer,
        "byDay": by_day,
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
        rplh = (
            round(s["revenue"] / s["hours"], 2)
            if s["revenue"] is not None and s["hours"] > 0
            else None
        )
        return {
            "period": label,
            "startDate": data["startDate"],
            "endDate": data["endDate"],
            "revenue": s["revenue"],
            "knownRevenue": s.get("knownRevenue", s["revenue"]),
            "revenueComplete": s.get("revenueComplete", True),
            "laborCost": s["laborCost"],
            "laborPct": s["laborPct"],
            "netProfit": s["netProfit"],
            "grossMarginPct": s["grossMarginPct"],
            "hours": s["hours"],
            "visits": s["visits"],
            "rplh": rplh,
            "issues": data.get("issues", []),
        }

    # Top/bottom 5 by net profit (from month data for meaningful ranking)
    customers = month_data["byCustomer"]
    by_profit = sorted(
        customers,
        key=lambda c: c["netProfit"] if c["netProfit"] is not None else float("-inf"),
        reverse=True,
    )
    top5 = by_profit[:5]
    bottom5 = sorted(
        customers,
        key=lambda c: c["netProfit"] if c["netProfit"] is not None else float("inf"),
    )[:5]

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

    def _csv_money(value: Any) -> str:
        return "N/A" if value is None else f"${value:.2f}"

    w.writerow(["EOM Analytics Export"])
    w.writerow(["Period", data["period"], "From", data["startDate"], "To", data["endDate"]])
    w.writerow(["Revenue", _csv_money(s["revenue"]), "Labor Cost", _csv_money(s["laborCost"]),
                "Labor %", f'{s["laborPct"]}%' if s["laborPct"] is not None else "N/A",
                "Net Profit", _csv_money(s["netProfit"]), "Target", f'{data["laborPctTarget"]}%'])
    w.writerow([])

    w.writerow(["By Customer"])
    w.writerow(["Customer", "Location", "Visits", "Hours", "Revenue", "Labor Cost", "Labor %", "Net Profit"])
    for c in data["byCustomer"]:
        w.writerow([c["customer"], c["location"], c["visits"], f'{c["hours"]:.2f}',
                    _csv_money(c["revenue"]), _csv_money(c["laborCost"]),
                    f'{c["laborPct"]}%' if c["laborPct"] is not None else "N/A",
                    _csv_money(c["netProfit"])])
    w.writerow([])

    w.writerow(["By Day"])
    w.writerow(["Date", "Visits", "Hours", "Revenue", "Labor Cost", "Labor %", "Net Profit"])
    for d in data["byDay"]:
        w.writerow([d["date"], d["visits"], f'{d["hours"]:.2f}',
                    _csv_money(d["revenue"]), _csv_money(d["laborCost"]),
                    f'{d["laborPct"]}%' if d["laborPct"] is not None else "N/A",
                    _csv_money(d["netProfit"])])

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

    linked_period_job_ids: set[int] = set()
    customer_shift_ids: set[int] = set()
    for entry in timesheet_data["entries"]:
        if entry.get("clockOut") is None:
            continue
        if entry.get("timeCategory") == "non_productive":
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
        shift_id = _entry_shift_id(entry)
        visits = entry.get("visits") or []
        if visits:
            for visit in visits:
                if not isinstance(visit, dict):
                    continue
                resolved_location, cust = _resolve_loc(visit.get("location", ""))
                if cust != customer_name:
                    continue
                if shift_id is not None:
                    customer_shift_ids.add(shift_id)
                job_id = _analytics_entry_job_id(visit.get("jobId"))
                if job_id is not None:
                    linked_period_job_ids.add(job_id)
            continue
        resolved_location, cust = _resolve_loc(entry.get("location", ""))
        if cust != customer_name:
            continue
        if shift_id is not None:
            customer_shift_ids.add(shift_id)
        job_id = _analytics_entry_job_id(entry.get("jobId"))
        if job_id is not None:
            linked_period_job_ids.add(job_id)
    (
        linked_job_revenue_cents,
        canonical_monthly_site_months,
        linked_job_revenue_issues,
    ) = _analytics_linked_job_revenue_cents(linked_period_job_ids)
    linked_jobs_credited: set[int] = set()
    # Per-shift snapshot wins; the employee map is only the fallback for shifts
    # with no snapshot. Both None still means "no rate" -> silent zero, as today.
    shift_rates = _load_shift_rate_snapshots(customer_shift_ids)

    def _calc_revenue(
        resolved_location: str,
        cust: str,
        hours: float,
        entry_date: Any,
        is_visit: bool,
        date_key: str,
        job_id: Optional[int] = None,
    ) -> Tuple[float, bool, List[Dict[str, Any]]]:
        linked_cents = (
            linked_job_revenue_cents.get(job_id)
            if job_id is not None
            else None
        )
        if job_id is not None and job_id in linked_job_revenue_cents:
            if job_id not in linked_jobs_credited:
                linked_jobs_credited.add(job_id)
                if linked_cents is not None:
                    return float(Decimal(linked_cents) / Decimal(100)), True, []
                issue = linked_job_revenue_issues.get(job_id)
                return 0.0, False, [issue] if issue else []
            return 0.0, True, []
        rate_type = location_rate_types.get(resolved_location, "per_visit")
        period_month = f"{entry_date.year}-{entry_date.month:02d}"
        site_month_key = (resolved_location, period_month)
        if rate_type == "monthly" and site_month_key in canonical_monthly_site_months:
            return 0.0, True, []
        return (
            0.0,
            False,
            [
                _analytics_missing_revenue_issue(
                    location=resolved_location,
                    customer=cust,
                    date_key=date_key,
                )
            ],
        )

    visits_list: List[Dict[str, Any]] = []
    week_agg: Dict[str, Dict[str, Any]] = {}

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
        job_id: Optional[int] = None,
    ) -> None:
        if cust != customer_name:
            return
        revenue, revenue_complete, revenue_issues = _calc_revenue(
            resolved_location,
            cust,
            hours,
            entry_date,
            is_visit,
            date_key,
            job_id=job_id,
        )
        labor_cost = (emp_rate * hours) if emp_rate is not None else 0.0
        public_revenue = revenue if revenue_complete else None
        lp = (
            round(labor_cost / public_revenue * 100, 1)
            if public_revenue is not None and public_revenue > 0
            else None
        )
        visits_list.append({
            "date": entry_date.strftime("%Y-%m-%d"),
            "weekStart": week_key,
            "employee": emp_name,
            "hours": round(hours, 2),
            "revenue": round(public_revenue, 2) if public_revenue is not None else None,
            "knownRevenue": round(revenue, 2),
            "revenueComplete": revenue_complete,
            "laborCost": round(labor_cost, 2),
            "laborPct": lp,
            "netProfit": (
                round(public_revenue - labor_cost, 2)
                if public_revenue is not None
                else None
            ),
            "issues": revenue_issues,
        })
        if week_key not in week_agg:
            week_agg[week_key] = {
                "weekStart": week_key,
                "visits": 0,
                "hours": 0.0,
                "revenue": 0.0,
                "laborCost": 0.0,
                "_revenueComplete": True,
                "issues": [],
            }
        week_agg[week_key]["_revenueComplete"] = (
            bool(week_agg[week_key]["_revenueComplete"]) and revenue_complete
        )
        _analytics_extend_unique_issues(week_agg[week_key]["issues"], revenue_issues)
        if is_visit:
            week_agg[week_key]["visits"] += 1
        week_agg[week_key]["hours"] += hours
        week_agg[week_key]["revenue"] += revenue
        week_agg[week_key]["laborCost"] += labor_cost

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
        # Every visit inside a shift was worked at that shift's rate.
        shift_id = _entry_shift_id(entry)
        snapshot_rate = shift_rates.get(shift_id) if shift_id is not None else None
        emp_rate = snapshot_rate if snapshot_rate is not None else emp_rates.get(emp_id)

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
                _record(
                    resolved_location,
                    cust,
                    v_hours,
                    True,
                    entry_date,
                    week_key,
                    emp_name,
                    emp_rate,
                    date_key,
                    job_id=_analytics_entry_job_id(visit.get("jobId")),
                )
        else:
            e_hours = entry_hours(entry, now)
            resolved_location, cust = _resolve_loc(entry.get("location", ""))
            _record(
                resolved_location,
                cust,
                e_hours,
                True,
                entry_date,
                week_key,
                emp_name,
                emp_rate,
                date_key,
                job_id=_analytics_entry_job_id(entry.get("jobId")),
            )

    def _fin_week(w: Dict[str, Any]) -> Dict[str, Any]:
        known_rev = round(w["revenue"], 2)
        revenue_complete = bool(w.get("_revenueComplete", True))
        rev = known_rev if revenue_complete else None
        lc = w["laborCost"]
        lp = round(lc / rev * 100, 1) if rev is not None and rev > 0 else None
        return {
            "weekStart": w["weekStart"],
            "visits": w["visits"],
            "hours": round(w["hours"], 2),
            "revenue": rev,
            "knownRevenue": known_rev,
            "revenueComplete": revenue_complete,
            "laborCost": round(lc, 2),
            "laborPct": lp,
            "netProfit": round(rev - lc, 2) if rev is not None else None,
            "issues": list(w.get("issues") or []),
        }

    visits_list_sorted = sorted(visits_list, key=lambda x: x["date"], reverse=True)
    by_week = sorted([_fin_week(w) for w in week_agg.values()], key=lambda x: x["weekStart"])

    revenue_complete = all(v.get("revenueComplete", True) for v in visits_list)
    known_total_rev = round(sum(v["knownRevenue"] for v in visits_list), 2)
    total_rev = known_total_rev if revenue_complete else None
    total_lc = sum(v["laborCost"] for v in visits_list)
    total_hours = round(sum(v["hours"] for v in visits_list), 2)
    total_visits = len(visits_list)
    issues = [
        issue
        for row in visits_list
        for issue in row.get("issues", [])
    ]

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
            "revenue": total_rev,
            "knownRevenue": known_total_rev,
            "revenueComplete": revenue_complete,
            "laborCost": round(total_lc, 2),
            "laborPct": round(total_lc / total_rev * 100, 1) if total_rev is not None and total_rev > 0 else None,
            "netProfit": round(total_rev - total_lc, 2) if total_rev is not None else None,
        },
        "issues": issues,
        "byVisit": visits_list_sorted,
        "byWeek": by_week,
    }


# Canonical operational Schedule, Utilization, and Forecast share one focused
# router. Utilization corrections append reviewed overlays to the existing
# correction ledger; the router receives only the cross-process lock identity
# and never receives a raw timekeeping mutation helper.
from operations_schedule import (
    build_operations_forecast,
    build_operations_schedule_router,
    build_weekly_labor_profitability,
    monthly_revenue_allocations,
)

app.include_router(
    build_operations_schedule_router(
        get_current_admin=get_current_admin,
        timezone_name=TIMEZONE_NAME,
        timesheet_advisory_lock_id=TIMESHEET_PG_ADVISORY_LOCK_ID,
        append_access_log=append_access_log,
    )
)


# Calendar import routes are registered through a focused factory so protocol,
# persistence, and planning rules remain outside this timekeeping module.
from calendar_import_api import (
    CalendarImportConfig,
    CalendarOAuthAccessLogFilter,
    build_calendar_import_router,
)

app.include_router(
    build_calendar_import_router(
        config=CalendarImportConfig(
            client_id=GOOGLE_CALENDAR_CLIENT_ID,
            client_secret=GOOGLE_CALENDAR_CLIENT_SECRET,
            redirect_uri=GOOGLE_CALENDAR_REDIRECT_URI,
            encryption_key=GOOGLE_CALENDAR_TOKEN_ENCRYPTION_KEY,
            portal_url=GOOGLE_CALENDAR_PORTAL_URL,
            timeout_seconds=GOOGLE_CALENDAR_TIMEOUT_SECONDS,
            timezone_name=TIMEZONE_NAME,
        ),
        get_current_admin=get_current_admin,
    )
)


if __name__ == "__main__":
    import copy

    import uvicorn

    host = os.getenv("TIMETRACKER_HOST", "0.0.0.0")
    port = parse_int(os.getenv("PORT") or os.getenv("TIMETRACKER_PORT"), 9000)
    dev = os.getenv("ENV", "production").lower() == "development"
    log_config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    log_config.setdefault("filters", {})["calendar_oauth_redaction"] = {
        "()": CalendarOAuthAccessLogFilter,
    }
    access_handler = log_config["handlers"]["access"]
    access_handler["filters"] = [
        *access_handler.get("filters", []),
        "calendar_oauth_redaction",
    ]
    uvicorn.run(
        "time_tracker_api:app",
        host=host,
        port=port,
        reload=dev,
        log_config=log_config,
    )
