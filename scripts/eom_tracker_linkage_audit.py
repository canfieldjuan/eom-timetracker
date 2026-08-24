#!/usr/bin/env python3
"""Poll the Tracker's read-only Atlas-linkage audit and alert on drift.

This is intentionally a standalone, standard-library-only monitor.  It runs
outside the Render service through a systemd user timer so it can report when
the deployed API cannot be read.  It does not import the Tracker application,
write customer data, or carry a browser session between runs.

The monitor logs in for each run using a dedicated active Tracker administrator
from a protected environment file.  Tracker's ordinary JWTs expire, and the
Tracker-to-Atlas audit read requires a real authenticated employee actor.

Secrets are environment-only.  There are deliberately no command-line flags
for the monitor account, password, or ntfy topic: command arguments can be
observed by other local processes while a monitor is running.
"""
from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import math
import os
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, urlsplit


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BREACH = 2
EXIT_UNDELIVERED = 3
# CLOSED / DERIVED: these are the only outcomes systemd treats as successful.
# They derive from the monitor's named exit constants; the unit test enforces
# that the separately parsed systemd value has exactly this membership.
SUCCESS_EXIT_STATUSES = frozenset({EXIT_OK, EXIT_BREACH})

LOGIN_PATH = "/api/auth/login"
AUDIT_PATH = "/api/admin/audits/atlas-linkage"

# CLOSED / ENUMERATED: these are every current key in the Tracker audit
# summary.  An added or missing key is treated as an unreadable measurement,
# rather than silently ignoring a new integrity class after the backend schema
# changes.  The five fault keys below are the current zero-tolerance signals;
# the remaining keys are context/derived counts and must still be valid.
EXPECTED_SUMMARY_KEYS = frozenset(
    {
        "duplicateGroups",
        "duplicateExtraCustomers",
        "unlinkedCustomers",
        "unlinkedActiveCustomers",
        "linkedCustomers",
        "handoffOrphans",
        "staleReservations",
        "danglingLinks",
    }
)
# CLOSED / ENUMERATED: these are every direct, zero-tolerance integrity
# signal emitted from the current Tracker audit summary. Each also has an
# identically named top-level detail list whose length is validated below.
# Derived context counts stay out of this list only when their relationship to
# a direct signal is validated below; any future summary key is rejected by
# EXPECTED_SUMMARY_KEYS.
FAULT_SUMMARY_KEYS = (
    "duplicateGroups",
    "unlinkedCustomers",
    "handoffOrphans",
    "staleReservations",
    "danglingLinks",
)
# OPEN / ENUMERATED: Tracker owns this status vocabulary. The standalone
# monitor mirrors the statuses known at this revision because importing Tracker
# code would prevent it from reporting a Tracker failure. Any future,
# unlisted status fails closed as an unreadable measurement below.
KNOWN_VERIFICATION_STATUSES = frozenset({"ok", "unavailable", "unconfigured", "skipped"})

DEFAULT_STATE_DIR = Path(
    os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
) / "eom-tracker-linkage-audit"
DEFAULT_NTFY_URL = "https://ntfy.sh"
DEFAULT_REALERT_EVERY = 24
# Atlas-link verification can make serial 100-ID reads. Keep a safe default
# for normal multi-batch work, while allowing the monitor host to align its
# finite watchdog with the Tracker deployment's configured upstream budget.
DEFAULT_AUDIT_TIMEOUT_SECONDS = 60.0
# The user service caps an entire run at 11 minutes. Login and audit each use
# this value, while the remaining minute covers notification and cleanup.
MAX_AUDIT_TIMEOUT_SECONDS = 240.0

# OPEN / ENUMERATED: these are the deliberately supported local host spellings
# for HTTP-only development. Every unlisted hostname, including other loopback
# aliases and addresses, is rejected rather than silently weakening HTTPS.
LOOPBACK_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# CLOSED / ENUMERATED: the monitor only makes HTTP(S) requests. Every other
# URI scheme is rejected before credentials, audit data, or notification data
# can be sent to it.
ALLOWED_URL_SCHEMES = frozenset({"https", "http"})


@dataclass(frozen=True)
class Settings:
    tracker_base_url: str
    admin_name: str
    admin_password: str
    ntfy_url: str
    ntfy_topic: str
    state_dir: Path
    realert_every: int
    audit_timeout_seconds: float


@dataclass(frozen=True)
class Signal:
    """One measured integrity condition or one failed measurement."""

    name: str
    summary: str
    count: int | None = None
    error: str | None = None

    @property
    def breached(self) -> bool:
        return self.count is None or self.count > 0

    def describe(self) -> str:
        if self.count is None:
            return f"{self.name}: COULD NOT MEASURE ({self.error or 'unknown error'})"
        return f"{self.name}: {self.count} (allowed 0) -- {self.summary}"


@dataclass
class AuditResult:
    signals: list[Signal] = field(default_factory=list)

    @property
    def breaches(self) -> list[Signal]:
        return [signal for signal in self.signals if signal.breached]

    @property
    def ok(self) -> bool:
        return not self.breaches

    def report(self) -> str:
        return "\n".join(signal.describe() for signal in self.signals)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so credentials never cross to a different host."""

    def redirect_request(self, *_args, **_kwargs):
        return None


def _open_no_redirect(
    request: urllib.request.Request,
    *,
    timeout_seconds: float = DEFAULT_AUDIT_TIMEOUT_SECONDS,
):
    return urllib.request.build_opener(_NoRedirect()).open(
        request, timeout=timeout_seconds
    )


def _setting(name: str) -> str:
    return os.environ.get(name, "").strip()


def settings_from_environment(*, state_dir: str | None, realert_every: int | None) -> Settings:
    configured_realert = _setting("EOM_TRACKER_LINKAGE_AUDIT_REALERT_EVERY")
    configured_timeout = _setting("EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS")
    if realert_every is None:
        realert_every = int(configured_realert or DEFAULT_REALERT_EVERY)
    try:
        audit_timeout_seconds = float(configured_timeout or DEFAULT_AUDIT_TIMEOUT_SECONDS)
    except ValueError as exc:
        raise ValueError(
            "EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS must be a positive finite number"
        ) from exc
    return Settings(
        tracker_base_url=_setting("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL"),
        admin_name=_setting("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_NAME"),
        admin_password=os.environ.get("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD", ""),
        ntfy_url=_setting("EOM_TRACKER_LINKAGE_AUDIT_NTFY_URL") or DEFAULT_NTFY_URL,
        ntfy_topic=_setting("EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC"),
        state_dir=Path(
            state_dir
            or _setting("EOM_TRACKER_LINKAGE_AUDIT_STATE_DIR")
            or str(DEFAULT_STATE_DIR)
        ),
        realert_every=realert_every,
        audit_timeout_seconds=audit_timeout_seconds,
    )


def _validate_url(label: str, value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in ALLOWED_URL_SCHEMES or not parsed.netloc:
        raise ValueError(f"{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not include credentials, query, or fragment")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HTTP_HOSTS:
        raise ValueError(f"{label} must use HTTPS outside loopback")


def validate_settings(
    settings: Settings,
    *,
    require_measurement: bool,
    require_notification: bool,
) -> None:
    if settings.realert_every < 0:
        raise ValueError(
            "EOM_TRACKER_LINKAGE_AUDIT_REALERT_EVERY must not be negative"
        )
    if (
        not math.isfinite(settings.audit_timeout_seconds)
        or settings.audit_timeout_seconds <= 0
        or settings.audit_timeout_seconds > MAX_AUDIT_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS must be a positive finite "
            f"number no greater than {MAX_AUDIT_TIMEOUT_SECONDS:g}"
        )
    if not str(settings.state_dir).strip():
        raise ValueError("EOM_TRACKER_LINKAGE_AUDIT_STATE_DIR must not be blank")
    if require_measurement:
        # CLOSED / ENUMERATED: these are every nonblank endpoint or credential
        # setting the current login and audit requests require. Settings is the
        # canonical monitor configuration inventory; timeout validation is above
        # and notification settings are validated in their separate branch below.
        for label, value in (
            ("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL", settings.tracker_base_url),
            ("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_NAME", settings.admin_name),
            ("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD", settings.admin_password),
        ):
            if not value.strip():
                raise ValueError(f"{label} is required for audit measurement")
        _validate_url("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL", settings.tracker_base_url)
    if require_notification:
        if not settings.ntfy_topic.strip():
            raise ValueError(
                "EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC is required for notification"
            )
        _validate_url("EOM_TRACKER_LINKAGE_AUDIT_NTFY_URL", settings.ntfy_url)


def _endpoint(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def _http_json(
    url: str,
    *,
    method: str,
    payload: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_AUDIT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any] | None, str | None]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json"}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    try:
        with _open_no_redirect(request, timeout_seconds=timeout_seconds) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except (http.client.HTTPException, urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"request failed ({type(exc).__name__})"
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "response was not valid JSON"
    if not isinstance(decoded, dict):
        return None, "response was not a JSON object"
    return decoded, None


def _login(settings: Settings) -> tuple[str | None, str | None]:
    response, error = _http_json(
        _endpoint(settings.tracker_base_url, LOGIN_PATH),
        method="POST",
        payload={"name": settings.admin_name, "password": settings.admin_password},
        timeout_seconds=settings.audit_timeout_seconds,
    )
    if error:
        return None, f"login {error}"
    token = response.get("token") if response is not None else None
    if not isinstance(token, str) or not token.strip():
        return None, "login response did not contain an access token"
    return token.strip(), None


def _fetch_audit(settings: Settings, token: str) -> tuple[dict[str, Any] | None, str | None]:
    response, error = _http_json(
        _endpoint(settings.tracker_base_url, AUDIT_PATH),
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
        timeout_seconds=settings.audit_timeout_seconds,
    )
    if error:
        return None, f"audit {error}"
    return response, None


def _unmeasured(error: str) -> AuditResult:
    return AuditResult(
        [
            Signal(
                name="tracker_audit_unavailable",
                summary="Tracker linkage audit could not be measured",
                error=error,
            )
        ]
    )


def build_signals(audit: Mapping[str, Any] | None, error: str | None = None) -> AuditResult:
    """Convert one complete audit response into explicit zero-tolerance signals."""
    if error or audit is None:
        return _unmeasured(error or "audit response missing")
    if audit.get("success") is not True:
        return _unmeasured("audit response did not confirm success")
    if audit.get("databaseReadOnly") is not True:
        return _unmeasured("audit response did not confirm read-only behavior")

    summary = audit.get("summary")
    if not isinstance(summary, Mapping):
        return _unmeasured("audit response summary was missing or invalid")
    actual_summary_keys = set(summary)
    if actual_summary_keys != EXPECTED_SUMMARY_KEYS:
        return _unmeasured("audit response summary schema changed")
    for key in EXPECTED_SUMMARY_KEYS:
        value = summary[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return _unmeasured(f"audit summary value {key} was invalid")

    duplicate_groups = summary["duplicateGroups"]
    duplicate_extra_customers = summary["duplicateExtraCustomers"]
    linked_customers = summary["linkedCustomers"]
    # The Tracker groups every duplicate contact link by contact ID with at
    # least two customer rows. Each group therefore contributes at least one
    # extra customer, and all grouped rows are part of linkedCustomers.
    if (
        (duplicate_groups == 0) != (duplicate_extra_customers == 0)
        or duplicate_extra_customers < duplicate_groups
        or duplicate_extra_customers > linked_customers - duplicate_groups
    ):
        return _unmeasured("audit duplicate summary counts were inconsistent")
    if summary["unlinkedActiveCustomers"] > summary["unlinkedCustomers"]:
        return _unmeasured("audit unlinked customer summary counts were inconsistent")
    for key in FAULT_SUMMARY_KEYS:
        detail_rows = audit.get(key)
        if not isinstance(detail_rows, list) or len(detail_rows) != summary[key]:
            return _unmeasured(f"audit detail list {key} did not match summary")

    verification = audit.get("atlasLinkVerification")
    if not isinstance(verification, Mapping):
        return _unmeasured("Atlas link verification status was missing or invalid")
    verification_status = verification.get("status")
    if (
        not isinstance(verification_status, str)
        or verification_status not in KNOWN_VERIFICATION_STATUSES
    ):
        return _unmeasured("Atlas link verification status was invalid")
    if verification_status == "ok":
        checked = verification.get("checked")
        expected_checked = (
            summary["linkedCustomers"] - summary["duplicateExtraCustomers"]
        )
        if expected_checked < 0:
            return _unmeasured("audit summary link counts were inconsistent")
        if (
            isinstance(checked, bool)
            or not isinstance(checked, int)
            or checked != expected_checked
        ):
            return _unmeasured("Atlas link verification coverage was missing or invalid")

    signals = [
        Signal(
            name=key,
            summary="Tracker linkage audit reported a non-zero integrity count",
            count=summary[key],
        )
        for key in FAULT_SUMMARY_KEYS
    ]
    if verification_status != "ok":
        signals.append(
            Signal(
                name="atlas_link_verification_unavailable",
                summary="Tracker could not verify stored Atlas contact links",
                error=f"status={verification_status}",
            )
        )
    return AuditResult(signals)


def measure(settings: Settings) -> AuditResult:
    token, login_error = _login(settings)
    if login_error or token is None:
        return _unmeasured(login_error or "login did not return a token")
    audit, audit_error = _fetch_audit(settings, token)
    return build_signals(audit, audit_error)


def _previous_breached(previous: Mapping[str, Any] | None) -> set[str] | None:
    if previous is None:
        return None
    recorded = previous.get("breached_signals")
    consecutive = previous.get("consecutive")
    if (
        isinstance(recorded, list)
        and all(isinstance(item, str) for item in recorded)
        and isinstance(consecutive, int)
        and not isinstance(consecutive, bool)
        and consecutive >= 0
    ):
        return set(recorded)
    if previous:
        return None
    return set()


def decide_alert(
    previous: Mapping[str, Any] | None, breached: Sequence[str], realert_every: int
) -> tuple[dict[str, Any], str | None]:
    """Keep each breach class visible rather than collapsing state to a boolean."""
    # OPEN / DERIVED: this is every breach signal measured in the current run.
    # Any future signal name remains in state and differs from the prior set,
    # so it produces a changed-alert rather than being silently ignored.
    current = {str(name) for name in breached}
    before = _previous_breached(previous)
    if not current:
        state = {"breached_signals": [], "consecutive": 0}
        return state, "recovered" if before is None or before else None
    if before is None or current != before:
        return {"breached_signals": sorted(current), "consecutive": 1}, (
            "breach" if not before else "changed"
        )
    consecutive = int(previous.get("consecutive", 0)) + 1
    state = {"breached_signals": sorted(current), "consecutive": consecutive}
    if realert_every > 0 and consecutive % realert_every == 0:
        return state, "reminder"
    return state, None


def read_state(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return {}, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"alert state unreadable ({type(exc).__name__})"
    if not isinstance(value, dict):
        return None, "alert state was not an object"
    return value, None


def write_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="state.", suffix=".tmp", dir=path.parent, text=True
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def publish(
    ntfy_url: str,
    topic: str,
    title: str,
    body: str,
    priority: str,
    tags: str,
) -> bool:
    """Publish without a curl subprocess, keeping the topic out of argv."""
    request = urllib.request.Request(
        f"{ntfy_url.rstrip('/')}/{quote(topic.strip(), safe='')}",
        data=body.encode("utf-8"),
        headers={"Title": title, "Priority": priority, "Tags": tags},
        method="POST",
    )
    try:
        with _open_no_redirect(request) as response:
            return 200 <= int(response.status) < 300
    except (http.client.HTTPException, urllib.error.URLError, OSError, ValueError):
        print("WARNING alert delivery failed", file=sys.stderr)
        return False


def _alert_body(result: AuditResult, consecutive: int) -> str:
    return "\n".join(
        [signal.describe() for signal in result.breaches]
        + [f"\nrun #{consecutive} in breach"]
    )


def _notify_monitor_unavailable(
    settings: Settings, notifier: Callable[..., bool], body: str
) -> int:
    """Notify without relying on local alert state after a monitor failure."""
    delivered = notifier(
        settings.ntfy_url,
        settings.ntfy_topic,
        "EOM tracker linkage audit unavailable",
        body,
        "urgent",
        "rotating_light,warning",
    )
    if not delivered:
        print("WARNING monitor unavailable alert undelivered", file=sys.stderr)
        return EXIT_UNDELIVERED
    return EXIT_ERROR


def _write_state_or_alert(
    settings: Settings,
    state_path: Path,
    state: Mapping[str, Any],
    notifier: Callable[..., bool],
) -> int | None:
    try:
        write_state(state_path, state)
    except OSError:
        return _notify_monitor_unavailable(
            settings,
            notifier,
            "Monitor state storage could not be persisted; audit results may not be "
            "tracked. Correct the local state directory and retry.",
        )
    return None


def _notify_and_record(
    settings: Settings,
    result: AuditResult,
    state_path: Path,
    notifier: Callable[..., bool],
) -> int:
    previous, warning = read_state(state_path)
    if warning:
        print(f"WARNING {warning}", file=sys.stderr)
    next_state, alert = decide_alert(
        previous,
        [signal.name for signal in result.breaches],
        settings.realert_every,
    )
    if alert is None:
        state_failure = _write_state_or_alert(
            settings, state_path, next_state, notifier
        )
        if state_failure is not None:
            return state_failure
        return EXIT_BREACH if not result.ok else EXIT_OK

    if alert == "recovered":
        delivered = notifier(
            settings.ntfy_url,
            settings.ntfy_topic,
            "EOM tracker linkage audit clean",
            "Every tracker-to-Atlas linkage signal is back to zero.",
            "default",
            "white_check_mark",
        )
    else:
        title = (
            "EOM tracker linkage audit: signals changed"
            if alert == "changed"
            else "EOM tracker linkage audit breached"
        )
        delivered = notifier(
            settings.ntfy_url,
            settings.ntfy_topic,
            title,
            _alert_body(result, int(next_state["consecutive"])),
            "urgent",
            "rotating_light,warning",
        )
    if not delivered:
        print(
            "WARNING alert undelivered; state left unchanged so the next run retries",
            file=sys.stderr,
        )
        return EXIT_UNDELIVERED
    state_failure = _write_state_or_alert(settings, state_path, next_state, notifier)
    if state_failure is not None:
        return state_failure
    return EXIT_BREACH if not result.ok else EXIT_OK


def _run_test_alert(settings: Settings, notifier: Callable[..., bool]) -> int:
    delivered = notifier(
        settings.ntfy_url,
        settings.ntfy_topic,
        "EOM tracker linkage audit test",
        "Test notification from the standalone tracker linkage monitor.",
        "default",
        "test_tube",
    )
    if not delivered:
        print("WARNING test alert was not accepted for delivery", file=sys.stderr)
        return EXIT_UNDELIVERED
    print("Test alert accepted for delivery; confirm receipt in the configured channel.")
    return EXIT_OK


def _notify_state_setup_failure(
    settings: Settings, notifier: Callable[..., bool]
) -> int:
    """Alert without state when the normal alert state cannot be prepared."""
    return _notify_monitor_unavailable(
        settings,
        notifier,
        "Monitor state storage could not be prepared; no audit was run. "
        "Correct the local state directory and retry.",
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    notifier: Callable[..., bool] = publish,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-dir",
        help="local state directory; secrets remain environment-only",
    )
    parser.add_argument(
        "--realert-every",
        type=int,
        help="runs between reminders while an unchanged breach remains open",
    )
    parser.add_argument(
        "--no-alert",
        action="store_true",
        help="measure and print without notifying or changing alert state",
    )
    parser.add_argument(
        "--test-alert",
        action="store_true",
        help="send a notification test without logging in or measuring the audit",
    )
    args = parser.parse_args(argv)
    if args.no_alert and args.test_alert:
        parser.error("--no-alert and --test-alert cannot be used together")

    settings = settings_from_environment(
        state_dir=args.state_dir,
        realert_every=args.realert_every,
    )
    if args.test_alert:
        validate_settings(
            settings, require_measurement=False, require_notification=True
        )
        return _run_test_alert(settings, notifier)

    validate_settings(
        settings,
        require_measurement=True,
        require_notification=not args.no_alert,
    )
    if args.no_alert:
        result = measure(settings)
        print(result.report())
        return EXIT_BREACH if not result.ok else EXIT_OK

    state_path = settings.state_dir / "state.json"
    lock_path = state_path.parent / "state.lock"
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        lock = lock_path.open("a", encoding="utf-8")
    except OSError:
        return _notify_state_setup_failure(settings, notifier)
    with lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            return _notify_state_setup_failure(settings, notifier)
        # Measure while locked.  A stale clean measurement must never overwrite
        # a later breach state another invocation just recorded.
        result = measure(settings)
        print(result.report())
        return _notify_and_record(settings, result, state_path, notifier)


if __name__ == "__main__":
    sys.exit(main())
