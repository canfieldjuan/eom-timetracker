#!/usr/bin/env python3
"""Unified Python backend for employee timekeeping and dashboard operations."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

import bcrypt
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
_data_dir_env = os.environ.get("DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
BACKEND_DIR = BASE_DIR / "backend"

EMPLOYEES_FILE = DATA_DIR / "employees.json"
TIMESHEETS_FILE = DATA_DIR / "timesheets.json"

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


LOCATION_MATCH_RADIUS_M = 50  # ~165 feet


def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin(math.radians(lat2 - lat1) / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(math.radians(lng2 - lng1) / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def find_nearest_location(lat: float, lng: float, timesheet_data: Dict[str, Any]) -> Optional[str]:
    coords = timesheet_data.get("location_coords", {})
    best_name, best_dist = None, float("inf")
    for name, c in coords.items():
        d = haversine_m(lat, lng, c["lat"], c["lng"])
        if d < best_dist:
            best_name, best_dist = name, d
    if best_name and best_dist <= LOCATION_MATCH_RADIUS_M:
        return best_name
    return None


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

            employee = {
                "id": employee_id,
                "name": name,
                "password": password_hash,
                "active": bool(item.get("active", True)),
                "role": str(item.get("role", "employee")),
                "created": item.get("created"),
                "lastLogin": item.get("lastLogin"),
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

    raw_next_id = raw_data.get("nextId")
    try:
        next_id = int(raw_next_id)
    except (TypeError, ValueError):
        next_id = max_id + 1

    if next_id <= max_id:
        next_id = max_id + 1

    return {"entries": entries, "nextId": next_id, "locations": locations, "location_coords": location_coords}


def load_employees() -> Dict[str, Any]:
    return normalize_employees(read_json_file(EMPLOYEES_FILE, {"employees": [], "nextId": 1}))


def save_employees(employees_data: Dict[str, Any]) -> None:
    normalized = normalize_employees(employees_data)
    with EMPLOYEE_WRITE_LOCK:
        with process_file_lock(EMPLOYEES_FILE):
            write_json_atomic(EMPLOYEES_FILE, normalized)


def update_employees(mutator) -> Tuple[bool, Any]:
    with EMPLOYEE_WRITE_LOCK:
        with process_file_lock(EMPLOYEES_FILE):
            employees_data = load_employees()
            ok, payload = mutator(employees_data)
            if ok:
                write_json_atomic(EMPLOYEES_FILE, normalize_employees(employees_data))
            return ok, payload


def load_timesheets() -> Dict[str, Any]:
    default_value = {"entries": [], "nextId": 1, "locations": DEFAULT_LOCATIONS}
    return normalize_timesheets(read_json_file(TIMESHEETS_FILE, default_value))


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
        with process_file_lock(TIMESHEETS_FILE):
            timesheet_data = load_timesheets()
            changed = False
            if AUTO_CLOSE_STALE_SHIFTS:
                changed = close_stale_open_entries(timesheet_data, utc_now())

            ok, payload = mutator(timesheet_data)
            if ok or changed:
                write_json_atomic(TIMESHEETS_FILE, normalize_timesheets(timesheet_data))
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


def build_public_current_status() -> List[Dict[str, Any]]:
    timesheet_data = load_timesheets()
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

        rows.append(
            {
                "id": int(entry.get("employeeId", 0)),
                "name": str(entry.get("employeeName", "")),
                "clockedInAt": local_clock_string(clock_in_time),
                "hoursWorked": f"{entry_hours(entry, now):.2f}",
                "notes": str(entry.get("notes", "")),
                "location": str(entry.get("location", "")),
                "clockInGps": entry.get("clockInGps"),
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


class ClockInRequest(BaseModel):
    location: str = ""
    notes: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class ClockOutRequest(BaseModel):
    notes: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class ReportGenerateRequest(BaseModel):
    month: int = Field(ge=1, le=12)
    year: int = Field(ge=2000, le=2100)
    emails: List[str] = []
    company_name: str = "Effingham Office Maids"
    send_email: bool = False
    use_mock_data: bool = False


load_local_env()

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be configured with at least 32 characters")

TIMEZONE_NAME = os.getenv("TIMEZONE", "America/New_York")
APP_TIMEZONE = ZoneInfo(TIMEZONE_NAME)

TOKEN_TTL_HOURS = parse_int(os.getenv("TOKEN_TTL_HOURS"), 12)
MAX_ACTIVE_SHIFT_HOURS = float(os.getenv("MAX_ACTIVE_SHIFT_HOURS", "24"))
AUTO_CLOSE_STALE_SHIFTS = parse_bool(os.getenv("AUTO_CLOSE_STALE_SHIFTS"), True)

ACCESS_START_HOUR = parse_int(os.getenv("ACCESS_START_HOUR"), 8)
ACCESS_END_HOUR = parse_int(os.getenv("ACCESS_END_HOUR"), 18)
validate_schedule(ACCESS_START_HOUR, ACCESS_END_HOUR)
ALLOWED_DAYS = parse_allowed_days(os.getenv("ALLOWED_DAYS"))
ALLOWED_IPS = parse_allowed_ips(os.getenv("ALLOWED_IPS"))
TRUST_PROXY = parse_bool(os.getenv("TRUST_PROXY"), False)

app = FastAPI(title="EOM Time Tracker API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    employee_name = payload.name.strip()
    password = payload.password
    if not employee_name or not password:
        append_access_log(request, "LOGIN_FAILED", False, "Missing credentials")
        raise HTTPException(status_code=400, detail="Name and password are required")

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        employee = find_employee_by_name(employees_data["employees"], employee_name)
        if not employee or not verify_password(password, employee["password"]):
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

    def mutator(employees_data: Dict[str, Any]) -> Tuple[bool, Any]:
        emp = find_employee_by_id(employees_data["employees"], employee_id)
        if not emp:
            return False, "Employee not found"
        if new_role:
            emp["role"] = new_role
        if "active" in payload:
            emp["active"] = bool(payload["active"])
        return True, {"id": emp["id"], "name": emp["name"], "role": emp["role"], "active": emp["active"]}

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

    employees_data = load_employees()
    timesheet_data = load_timesheets()
    now = utc_now()
    rows = []

    for emp in employees_data["employees"]:
        emp_entries = [e for e in timesheet_data["entries"] if e.get("employeeId") == emp["id"]]
        total_hours = sum(entry_hours(e, now) for e in emp_entries)
        last_entry = max(emp_entries, key=lambda e: e.get("clockIn", ""), default=None)
        last_gps = None
        if last_entry:
            last_gps = last_entry.get("clockInGps") or last_entry.get("clockOutGps")

        rows.append({
            "id": emp["id"],
            "name": emp["name"],
            "role": emp.get("role", "employee"),
            "active": emp.get("active", True),
            "created": emp.get("created"),
            "lastLogin": emp.get("lastLogin"),
            "totalHours": round(total_hours, 2),
            "totalShifts": len(emp_entries),
            "lastGps": last_gps,
        })

    append_access_log(request, "ADMIN_EMPLOYEES", True, f"{len(rows)} employees")
    return {"success": True, "employees": rows}


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
            "clockOutGps": None,
        }
        if has_gps:
            entry["clockInGps"] = {"lat": payload.latitude, "lng": payload.longitude}
        timesheet_data["entries"].append(entry)
        timesheet_data["nextId"] = entry_id + 1
        return True, entry

    ok, result = update_timesheets(mutator)
    if not ok:
        append_access_log(request, "CLOCK_IN_FAILED", False, str(result))
        raise HTTPException(status_code=400, detail=str(result))

    append_access_log(request, "CLOCK_IN_SUCCESS", True, f"Employee: {employee['name']} at {location}")
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


@app.get("/api/timesheet/my-hours")
def my_timesheet_hours(
    request: Request,
    current_employee: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    timesheet_data = load_timesheets()
    employee_id = current_employee["id"]
    now = utc_now()

    days_since_monday = now.weekday()
    week_start = (now - timedelta(days=days_since_monday)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    today_str = local_date_string(now)

    my_entries = [
        e for e in timesheet_data.get("entries", [])
        if e.get("employeeId") == employee_id
    ]

    weekly_hours = 0.0
    today_hours = 0.0
    recent_shifts: List[Dict[str, Any]] = []

    for entry in my_entries:
        clock_in_str = str(entry.get("clockIn", "")).strip()
        if not clock_in_str:
            continue
        try:
            clock_in_dt = parse_utc_iso(clock_in_str)
        except ValueError:
            continue

        total = float(entry.get("totalHours") or 0)
        entry_date = local_date_string(clock_in_dt)

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

        recent_shifts.append({
            "date": entry_date,
            "clockIn": local_clock_string(clock_in_dt),
            "clockOut": clock_out_display,
            "hours": round(total, 2),
            "location": entry.get("location", ""),
        })

    recent_shifts.sort(key=lambda x: x["date"], reverse=True)
    append_access_log(request, "MY_HOURS_SUCCESS", True, f"Employee: {current_employee['name']}")
    return {
        "success": True,
        "weeklyHours": round(weekly_hours, 2),
        "todayHours": round(today_hours, 2),
        "recentShifts": recent_shifts[:10],
    }


@app.get("/api/timesheet/locations")
def timesheet_locations(
    request: Request,
    _: Dict[str, Any] = Depends(get_current_employee),
) -> Dict[str, Any]:
    payload = load_timesheets()
    append_access_log(request, "LOCATIONS_SUCCESS", True, "Locations fetched")
    return {"success": True, "locations": payload["locations"], "location_coords": payload["location_coords"]}


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
    for item in raw:
        if isinstance(item, dict) and item.get("name", "").strip():
            name = str(item["name"]).strip()
            locations.append(name)
            if item.get("lat") is not None and item.get("lng") is not None:
                try:
                    location_coords[name] = {"lat": float(item["lat"]), "lng": float(item["lng"])}
                except (TypeError, ValueError):
                    pass
        elif isinstance(item, str) and item.strip():
            locations.append(item.strip())

    def mutator(data: Dict[str, Any]) -> Tuple[bool, Any]:
        data["locations"] = locations
        data["location_coords"] = location_coords
        return True, locations

    update_timesheets(mutator)
    append_access_log(request, "LOCATIONS_UPDATED", True, f"{len(locations)} locations, {len(location_coords)} with coords")
    return {"success": True, "locations": locations, "location_coords": location_coords}


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
            "clockInTime": row["clockedInAt"],
            "hoursWorked": row["hoursWorked"],
            "notes": row["notes"],
            "clockInGps": row.get("clockInGps"),
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


@app.post("/api/admin/generate-report")
def admin_generate_report(
    payload: ReportGenerateRequest,
    request: Request,
    _: Dict[str, Any] = Depends(get_current_admin),
) -> Dict[str, Any]:

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
        append_access_log(request, "REPORT_GENERATION_FAILED", False, f"Exit code: {completed.returncode}")
        return {
            "success": False,
            "error": "Report generation failed",
            "details": (stderr_text or stdout_text).strip(),
            "exitCode": completed.returncode,
        }

    report_path = parse_report_path(stdout_text)
    append_access_log(request, "REPORT_GENERATION_SUCCESS", True, f"Generated: {report_path}")
    return {
        "success": True,
        "message": "Report generated successfully",
        "reportPath": report_path,
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


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("TIMETRACKER_HOST", "0.0.0.0")
    port = parse_int(os.getenv("PORT") or os.getenv("TIMETRACKER_PORT"), 9000)
    dev = os.getenv("ENV", "production").lower() == "development"
    uvicorn.run("time_tracker_api:app", host=host, port=port, reload=dev)
