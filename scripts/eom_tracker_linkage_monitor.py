#!/usr/bin/env python3
"""Deliver the minimal scheduled alert for the existing Tracker linkage audit."""
from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time
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
FUNNEL_REVIEW_PATH = "/api/admin/funnel/review?limit=1"
AUDIT_PATH = "/api/admin/audits/atlas-linkage"
DEFAULT_STATE_FILE = Path(
    os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
) / "eom-tracker-linkage-monitor/state.json"

# CLOSED / ENUMERATED: issue #206's monitor owns these three existing audit
# counts. A missing or invalid member makes the measurement unavailable rather
# than silently clean; new audit signals remain outside this proof slice.
SIGNAL_KEYS = ("unlinkedCustomers", "staleReservations", "danglingLinks")

# The tracker marks a read it could not complete upstream as retryable in two
# ways (time_tracker_api.py _atlas_funnel_read): its own HTTP 503 whose detail
# says "retry this request", and any relayed upstream 5xx sent with a
# Retry-After header. Honoring that contract once, for the read-only GETs, is
# the client behaving as the API asks; it is not suppression. A second failure
# is still measured as unavailable, and the login POST is never replayed.
_UNAVAILABLE_STATUS = 503
_UNAVAILABLE_RETRY_ATTEMPTS = 2
_UNAVAILABLE_RETRY_DEFAULT_DELAY_SECONDS = 5.0
_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS = 30.0
# The tracker's HTTPException handler emits {"success": false, "error":
# <detail>}. For the three requests this monitor makes, the detail is one of
# the fixed server literals below, and those are what let an operator tell an
# unconfigured proxy, an upstream transport failure, and a relayed upstream
# refusal apart. A relayed detail is copied from the upstream body, so the
# set is CLOSED / ENUMERATED: only an exact member reaches a notification,
# and anything else is reported as withheld. Lead data, credentials, and
# upstream diagnostics therefore never enter ntfy through this path.
_ERROR_BODY_MAX_BYTES = 65536
_WITHHELD_DETAIL = "unrecognized error detail withheld"
_KNOWN_ERROR_DETAILS = frozenset(
    {
        # Tracker: Atlas funnel proxy (time_tracker_api.py _atlas_funnel_read and
        # _require_atlas_funnel_configuration).
        "EOM customer handoff service is not configured",
        "EOM lead review service is temporarily unavailable; retry this request",
        "EOM lead review service returned an invalid response",
        "EOM lead review service authentication failed",
        "EOM lead review failed",
        # Tracker: login and bearer authentication on the monitored routes.
        "Name and password are required",
        "Invalid name or password",
        "Access token required",
        "Token has expired",
        "Invalid access token",
        "Invalid token payload",
        "Token has been revoked",
        "Employee account not found",
        "Admin access required",
        "Too many requests; try again later",
        # Atlas: the one refusal the leads read relays verbatim
        # (atlas_brain/eom_api/funnel_auth.py require_eom_funnel_api).
        "EOM funnel API is disabled",
    }
)


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


def _required_secret(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
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
        admin_password=_required_secret("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD"),
        ntfy_url=_https_url(
            "EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL",
            _required_setting("EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL"),
        ),
        ntfy_topic=_required_setting("EOM_TRACKER_LINKAGE_MONITOR_NTFY_TOPIC"),
        state_file=DEFAULT_STATE_FILE,
    )


def _open(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=20)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _http_error_detail(exc: urllib.error.HTTPError) -> str | None:
    """Return the known server literal from an error body, withheld, or None.

    Reading the body must never raise past this function: a truncated or
    disconnected error response (http.client.IncompleteRead, socket errors)
    degrades to the bare status code, so the unavailable alert still sends.
    """
    read = getattr(exc, "read", None)
    if not callable(read):
        return None
    try:
        raw = read(_ERROR_BODY_MAX_BYTES)
    except (OSError, ValueError, http.client.HTTPException):
        return None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    detail = decoded.get("error")
    if not isinstance(detail, str):
        detail = decoded.get("detail")
    if not isinstance(detail, str):
        return None
    text = " ".join(detail.split())
    if not text:
        return None
    return text if text in _KNOWN_ERROR_DETAILS else _WITHHELD_DETAIL


def _http_error_message(exc: urllib.error.HTTPError) -> str:
    detail = _http_error_detail(exc)
    return f"HTTP {exc.code} ({detail})" if detail else f"HTTP {exc.code}"


def _retry_after_header(exc: urllib.error.HTTPError) -> str | None:
    headers = getattr(exc, "headers", None)
    value = headers.get("Retry-After") if headers is not None else None
    return value if isinstance(value, str) else None


def _retry_after_seconds(exc: urllib.error.HTTPError) -> float:
    """Bounded Retry-After in seconds; the tracker's own 5s when absent/invalid."""
    value = _retry_after_header(exc)
    if value is None or not value.strip().isdigit():
        return _UNAVAILABLE_RETRY_DEFAULT_DELAY_SECONDS
    return min(float(value.strip()), _UNAVAILABLE_RETRY_MAX_DELAY_SECONDS)


def _retryable(exc: urllib.error.HTTPError) -> bool:
    """The tracker's two retry signals: its own 503, or a relayed 5xx with Retry-After."""
    if exc.code == _UNAVAILABLE_STATUS:
        return True
    return 500 <= exc.code <= 599 and _retry_after_header(exc) is not None


def _http_json_once(
    request: urllib.request.Request,
) -> tuple[dict[str, Any] | None, str | None, urllib.error.HTTPError | None]:
    try:
        with _open(request) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        return None, _http_error_message(exc), exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"request failed ({type(exc).__name__})", None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "response was not valid JSON", None
    if not isinstance(decoded, dict):
        return None, "response was not a JSON object", None
    return decoded, None, None


def _http_json(
    url: str,
    *,
    method: str,
    payload: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    retry_unavailable: bool = False,
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
    attempts = _UNAVAILABLE_RETRY_ATTEMPTS if retry_unavailable else 1
    attempt = 0
    while True:
        attempt += 1
        decoded, error, http_error = _http_json_once(request)
        if http_error is None or not _retryable(http_error) or attempt >= attempts:
            break
        _sleep(_retry_after_seconds(http_error))
    if error is not None and attempt > 1:
        error = f"{error} after {attempt} attempts"
    return decoded, error


def measure(settings: Settings) -> tuple[dict[str, int] | None, str | None]:
    login, error = _http_json(
        f"{settings.base_url}{LOGIN_PATH}",
        method="POST",
        payload={"name": settings.admin_name, "password": settings.admin_password},
    )
    token = login.get("token") if login is not None else None
    if error or not isinstance(token, str) or not token.strip():
        return None, error or "login response did not contain a token"

    funnel_review, error = _http_json(
        f"{settings.base_url}{FUNNEL_REVIEW_PATH}",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
        retry_unavailable=True,
    )
    if error or funnel_review is None:
        return None, f"funnel review {error or 'response missing'}"
    if funnel_review.get("success") is not True:
        return None, "funnel review did not confirm success"

    audit, error = _http_json(
        f"{settings.base_url}{AUDIT_PATH}",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
        retry_unavailable=True,
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
