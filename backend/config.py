import os
import threading
from pathlib import Path
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent.parent
_data_dir_env = os.environ.get("DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
BACKEND_DIR = BASE_DIR / "backend"

# --- JSON Files (Legacy/Back-compat) ---
EMPLOYEES_FILE = DATA_DIR / "employees.json"
TIMESHEETS_FILE = DATA_DIR / "timesheets.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

# --- Constants ---
DEFAULT_LOCATIONS = [
    "Office Maids 101, Effingham",
    "Office Maids 102, Effingham",
    "Office Maids 103, Effingham",
]

JWT_ALGORITHM = "HS256"
LOCATION_MATCH_RADIUS_DEFAULT_M = 50

# --- Locks ---
ACCESS_LOG_WRITE_LOCK = threading.Lock()

# --- Helper functions for parsing env vars ---
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
    return days if days else ["1", "2", "3", "4", "5"]

def parse_allowed_ips(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]

def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key: continue
        if value.startswith(('"', "'")) and value.endswith(('"', "'")) and len(value) >= 2:
            value = value[1:-1]
        os.environ.setdefault(key, value)

# --- Load Environment ---
load_env_file(BASE_DIR / ".env")
load_env_file(BACKEND_DIR / ".env")

# --- Config Variables ---
JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
TIMEZONE_NAME = os.getenv("TIMEZONE", "America/New_York")
APP_TIMEZONE = ZoneInfo(TIMEZONE_NAME)

TOKEN_TTL_HOURS = parse_int(os.getenv("TOKEN_TTL_HOURS"), 12)
MAX_ACTIVE_SHIFT_HOURS = float(os.getenv("MAX_ACTIVE_SHIFT_HOURS", "24"))
AUTO_CLOSE_STALE_SHIFTS = parse_bool(os.getenv("AUTO_CLOSE_STALE_SHIFTS"), True)
LOCATION_MATCH_RADIUS_M = parse_int(os.getenv("LOCATION_MATCH_RADIUS_M"), LOCATION_MATCH_RADIUS_DEFAULT_M)

ACCESS_START_HOUR = parse_int(os.getenv("ACCESS_START_HOUR"), 8)
ACCESS_END_HOUR = parse_int(os.getenv("ACCESS_END_HOUR"), 18)
ALLOWED_DAYS = parse_allowed_days(os.getenv("ALLOWED_DAYS"))
ALLOWED_IPS = parse_allowed_ips(os.getenv("ALLOWED_IPS"))
TRUST_PROXY = parse_bool(os.getenv("TRUST_PROXY"), False)
BOOTSTRAP_ADMIN_IDS = [
    int(x) for x in os.getenv("BOOTSTRAP_ADMIN_IDS", "").split(",") if x.strip().isdigit()
]

# --- Business Rules Defaults ---
_SETTINGS_DEFAULTS: Dict[str, Any] = {
    "laborPctTarget":    35.0,
    "laborPctWatch":     40.0,
    "laborPctFix":       55.0,
    "laborPctDrop":      70.0,
    "grossMarginMin":    30.0,
    "grossMarginFix":    15.0,
    "grossMarginDrop":    0.0,
    "hourOverrunWatch":   0.5,
    "hourOverrunFix":     2.0,
    "rplhMin":           25.0,
    "laborRateFallback": 15.0,
    "laborBurdenMultiplier": 1.20,
}
