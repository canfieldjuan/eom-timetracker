import json
import math
import time
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from contextlib import contextmanager

from fastapi import Request

import db
from config import (
    APP_TIMEZONE, LOCATION_MATCH_RADIUS_M, LOGS_DIR,
    ACCESS_LOG_WRITE_LOCK, TRUST_PROXY
)

try:
    import fcntl
except ImportError:
    fcntl = None

# --- JSON Helpers ---
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

# --- File Locking ---
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

# --- Datetime Helpers ---
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

# --- Network & IP Helpers ---
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

# --- GPS & Location Logic ---
def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin(math.radians(lat2 - lat1) / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(math.radians(lng2 - lng1) / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))

def find_nearest_location_match(lat: float, lng: float) -> Optional[Dict[str, Any]]:
    rows = db.query_all("SELECT address, lat, lng FROM locations WHERE active = true AND lat IS NOT NULL AND lng IS NOT NULL")
    if not rows:
        return None
    best_name, best_dist = None, float("inf")
    for r in rows:
        d = haversine_m(lat, lng, float(r["lat"]), float(r["lng"]))
        if d < best_dist:
            best_name, best_dist = r["address"], d
    if not best_name:
        return None
    return {
        "location": best_name,
        "distanceM": best_dist,
        "withinRadius": best_dist <= LOCATION_MATCH_RADIUS_M,
    }

def find_nearest_location(lat: float, lng: float) -> Optional[str]:
    nearest = find_nearest_location_match(lat, lng)
    if nearest and nearest["withinRadius"]:
        return str(nearest["location"])
    return None

def build_gps_meta(
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
    override_detail: str = "",
) -> Optional[Dict[str, Any]]:
    reason = str(override_reason or "").strip()
    detail = str(override_detail or "").strip()
    nearest = None
    if latitude is not None and longitude is not None:
        nearest = find_nearest_location_match(latitude, longitude)
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
    latitude: Optional[float],
    longitude: Optional[float],
    override_reason: str = "",
) -> Optional[str]:
    if str(override_reason or "").strip():
        return None
    if latitude is None or longitude is None:
        return None
    nearest = find_nearest_location_match(latitude, longitude)
    if nearest and not nearest["withinRadius"]:
        distance_m = round(float(nearest["distanceM"]))
        return (
            f"GPS is {distance_m}m from the nearest saved site "
            f"({nearest['location']}). Add an override reason to continue."
        )
    return None
