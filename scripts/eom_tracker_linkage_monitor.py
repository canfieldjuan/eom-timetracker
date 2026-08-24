#!/usr/bin/env python3
"""Deliver the minimal scheduled alert for the existing Tracker linkage audit."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, urlsplit


EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_BREACH = 2
EXIT_UNDELIVERED = 3

LOGIN_PATH = "/api/auth/login"
AUDIT_PATH = "/api/admin/audits/atlas-linkage"
DEFAULT_STATE_FILE = Path(
    os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
) / "eom-tracker-linkage-monitor/state.json"

# CLOSED / ENUMERATED: issue #206's monitor owns these three existing audit
# counts. A missing or invalid member makes the measurement unavailable rather
# than silently clean; new audit signals remain outside this proof slice.
SIGNAL_KEYS = ("unlinkedCustomers", "staleReservations", "danglingLinks")


@dataclass(frozen=True)
class Settings:
    base_url: str
    admin_name: str
    admin_password: str
    ntfy_url: str
    ntfy_topic: str
    state_file: Path


def _setting(name: str) -> str:
    return os.environ.get(name, "").strip()


def _required_setting(name: str) -> str:
    value = _setting(name)
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _https_url(name: str, value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{name} must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{name} must not include credentials, query, or fragment")
    return value.rstrip("/")


def settings_from_environment() -> Settings:
    return Settings(
        base_url=_https_url(
            "EOM_TRACKER_LINKAGE_MONITOR_BASE_URL",
            _required_setting("EOM_TRACKER_LINKAGE_MONITOR_BASE_URL"),
        ),
        admin_name=_required_setting("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_NAME"),
        admin_password=_required_setting("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD"),
        ntfy_url=_https_url(
            "EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL",
            _required_setting("EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL"),
        ),
        ntfy_topic=_required_setting("EOM_TRACKER_LINKAGE_MONITOR_NTFY_TOPIC"),
        state_file=DEFAULT_STATE_FILE,
    )


def _open(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=20)


def _http_json(
    url: str,
    *,
    method: str,
    payload: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json"}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url, data=body, headers=request_headers, method=method
    )
    try:
        with _open(request) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"request failed ({type(exc).__name__})"
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "response was not valid JSON"
    if not isinstance(decoded, dict):
        return None, "response was not a JSON object"
    return decoded, None


def measure(settings: Settings) -> tuple[dict[str, int] | None, str | None]:
    login, error = _http_json(
        f"{settings.base_url}{LOGIN_PATH}",
        method="POST",
        payload={"name": settings.admin_name, "password": settings.admin_password},
    )
    token = login.get("token") if login is not None else None
    if error or not isinstance(token, str) or not token.strip():
        return None, error or "login response did not contain a token"

    audit, error = _http_json(
        f"{settings.base_url}{AUDIT_PATH}",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
    )
    if error or audit is None:
        return None, error or "audit response missing"
    if audit.get("success") is not True:
        return None, "audit did not confirm success"
    verification = audit.get("atlasLinkVerification")
    if not isinstance(verification, Mapping) or verification.get("status") != "ok":
        return None, "Atlas link verification was unavailable"
    summary = audit.get("summary")
    if not isinstance(summary, Mapping):
        return None, "audit summary was missing"

    counts: dict[str, int] = {}
    for key in SIGNAL_KEYS:
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None, f"audit summary {key} was invalid"
        counts[key] = value
    return counts, None


def _load_state(path: Path) -> set[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    signals = value.get("breachedSignals") if isinstance(value, dict) else None
    if not isinstance(signals, list) or not all(isinstance(item, str) for item in signals):
        return set()
    return set(signals)


def _write_state(path: Path, signals: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"breachedSignals": sorted(signals)}, sort_keys=True),
        encoding="utf-8",
    )


def publish(settings: Settings, title: str, body: str) -> bool:
    request = urllib.request.Request(
        f"{settings.ntfy_url}/{quote(settings.ntfy_topic, safe='')}",
        data=body.encode("utf-8"),
        headers={"Title": title, "Priority": "urgent", "Tags": "warning"},
        method="POST",
    )
    try:
        with _open(request) as response:
            return 200 <= int(response.status) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def run_once(
    settings: Settings, notifier: Callable[[Settings, str, str], bool] = publish
) -> int:
    counts, error = measure(settings)
    if error or counts is None:
        delivered = notifier(
            settings,
            "EOM tracker linkage monitor unavailable",
            error or "audit could not be measured",
        )
        return EXIT_ERROR if delivered else EXIT_UNDELIVERED

    current = {key for key, count in counts.items() if count > 0}
    previous = _load_state(settings.state_file)
    if current and current != previous:
        delivered = notifier(
            settings,
            "EOM tracker linkage audit breached",
            ", ".join(f"{key}={counts[key]}" for key in sorted(current)),
        )
        if not delivered:
            return EXIT_UNDELIVERED
    try:
        _write_state(settings.state_file, current)
    except OSError:
        return EXIT_ERROR
    return EXIT_BREACH if current else EXIT_CLEAN


def main(
    argv: Sequence[str] | None = None,
    *,
    notifier: Callable[[Settings, str, str], bool] = publish,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-alert",
        action="store_true",
        help="send a configured notification without logging in or reading the audit",
    )
    args = parser.parse_args(argv)
    settings = settings_from_environment()
    if args.test_alert:
        delivered = notifier(
            settings,
            "EOM tracker linkage monitor test",
            "Test alert from the tracker linkage monitor.",
        )
        return EXIT_CLEAN if delivered else EXIT_UNDELIVERED
    return run_once(settings, notifier)


if __name__ == "__main__":
    sys.exit(main())
