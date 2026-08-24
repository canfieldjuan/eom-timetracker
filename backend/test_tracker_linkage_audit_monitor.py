"""Regression coverage for the external Tracker Atlas-linkage monitor."""
from __future__ import annotations

import importlib.util
import http.client
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "eom_tracker_linkage_audit.py"
SPEC = importlib.util.spec_from_file_location("eom_tracker_linkage_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
monitor = importlib.util.module_from_spec(SPEC)
sys.modules["eom_tracker_linkage_audit"] = monitor
SPEC.loader.exec_module(monitor)


def _summary(**overrides: int) -> dict[str, int]:
    values = {key: 0 for key in monitor.EXPECTED_SUMMARY_KEYS}
    values.update(overrides)
    return values


def _audit_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "success": True,
        "databaseReadOnly": True,
        "summary": _summary(),
        "atlasLinkVerification": {"status": "ok", "checked": 0, "error": None},
    }
    payload.update(overrides)
    summary = payload.get("summary")
    if isinstance(summary, dict):
        for detail_key, summary_key in monitor.DETAIL_LIST_SUMMARY_KEYS.items():
            count = summary.get(summary_key)
            if (
                isinstance(count, int)
                and not isinstance(count, bool)
                and count >= 0
            ):
                payload.setdefault(detail_key, [{}] * count)
            else:
                payload.setdefault(detail_key, [])
    return payload


def _settings(tmp_path: Path) -> object:
    return monitor.Settings(
        tracker_base_url="https://tracker.example.test",
        admin_name="Audit Monitor",
        admin_password="not-a-real-password",
        ntfy_url="https://ntfy.example.test",
        ntfy_topic="private-topic",
        state_dir=tmp_path,
        realert_every=3,
        audit_timeout_seconds=monitor.DEFAULT_AUDIT_TIMEOUT_SECONDS,
    )


def test_clean_response_is_not_a_breach():
    result = monitor.build_signals(_audit_payload())

    assert result.ok
    assert result.breaches == []


@pytest.mark.parametrize("signal", monitor.FAULT_SUMMARY_KEYS)
def test_each_integrity_count_breaches_independently(signal: str):
    summary = _summary(**{signal: 1})
    if signal == "duplicateGroups":
        summary = _summary(
            duplicateGroups=1,
            duplicateExtraCustomers=1,
            linkedCustomers=2,
        )
    payload = _audit_payload(summary=summary)
    if signal == "duplicateGroups":
        payload["atlasLinkVerification"] = {
            "status": "ok",
            "checked": 1,
            "error": None,
        }
    result = monitor.build_signals(payload)

    assert [item.name for item in result.breaches] == [signal]


@pytest.mark.parametrize(
    ("detail_key", "summary_key"), tuple(monitor.DETAIL_LIST_SUMMARY_KEYS.items())
)
def test_detail_count_mismatch_is_an_unmeasured_breach(
    detail_key: str, summary_key: str
):
    payload = _audit_payload()
    payload[detail_key] = [{}]

    result = monitor.build_signals(payload)

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


@pytest.mark.parametrize("detail_key", monitor.DETAIL_LIST_SUMMARY_KEYS)
@pytest.mark.parametrize("detail_rows", [None, {}, "not-a-list"])
def test_detail_must_be_a_list(detail_key: str, detail_rows: object):
    payload = _audit_payload(**{detail_key: detail_rows})

    result = monitor.build_signals(payload)

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


@pytest.mark.parametrize(
    "payload",
    [
        _audit_payload(success=False),
        _audit_payload(databaseReadOnly=False),
        _audit_payload(summary={"unlinkedCustomers": 0}),
        _audit_payload(summary=_summary(unlinkedCustomers=True)),
        _audit_payload(atlasLinkVerification={"status": ""}),
        _audit_payload(atlasLinkVerification={"status": "unknown-status"}),
        _audit_payload(atlasLinkVerification={"status": []}),
        _audit_payload(atlasLinkVerification={"status": {}}),
    ],
)
def test_incomplete_or_invalid_response_is_an_unmeasured_breach(payload: dict[str, object]):
    result = monitor.build_signals(payload)

    assert not result.ok
    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]
    assert result.breaches[0].count is None


@pytest.mark.parametrize("status", ["unavailable", "unconfigured", "skipped"])
def test_non_ok_atlas_verification_never_reads_as_clean(status: str):
    result = monitor.build_signals(
        _audit_payload(atlasLinkVerification={"status": status, "checked": 0})
    )

    assert [item.name for item in result.breaches] == [
        "atlas_link_verification_unavailable"
    ]


@pytest.mark.parametrize(
    ("summary", "verification"),
    [
        (_summary(), {"status": "ok"}),
        (_summary(), {"status": "ok", "checked": True}),
        (
            _summary(
                duplicateGroups=1,
                linkedCustomers=2,
                duplicateExtraCustomers=1,
            ),
            {"status": "ok", "checked": 0},
        ),
        (_summary(linkedCustomers=1), {"status": "ok", "checked": 2}),
        (
            _summary(linkedCustomers=0, duplicateExtraCustomers=1),
            {"status": "ok", "checked": 0},
        ),
    ],
)
def test_ok_atlas_verification_requires_complete_distinct_link_coverage(
    summary: dict[str, int], verification: dict[str, object]
):
    result = monitor.build_signals(
        _audit_payload(summary=summary, atlasLinkVerification=verification)
    )

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


def test_ok_atlas_verification_accepts_matching_distinct_link_coverage():
    result = monitor.build_signals(
        _audit_payload(
            summary=_summary(
                duplicateGroups=1,
                linkedCustomers=3,
                duplicateExtraCustomers=1,
            ),
            atlasLinkVerification={"status": "ok", "checked": 2},
        )
    )

    assert [item.name for item in result.breaches] == ["duplicateGroups"]


def test_new_summary_key_fails_closed_instead_of_being_ignored():
    result = monitor.build_signals(
        _audit_payload(summary={**_summary(), "futureIntegritySignal": 0})
    )

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


@pytest.mark.parametrize(
    "summary",
    [
        _summary(
            duplicateGroups=0,
            duplicateExtraCustomers=1,
            linkedCustomers=1,
        ),
        _summary(
            duplicateGroups=2,
            duplicateExtraCustomers=1,
            linkedCustomers=3,
        ),
        _summary(
            duplicateGroups=1,
            duplicateExtraCustomers=3,
            linkedCustomers=3,
        ),
    ],
)
def test_inconsistent_duplicate_summary_is_an_unmeasured_breach(summary: dict[str, int]):
    result = monitor.build_signals(_audit_payload(summary=summary))

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


@pytest.mark.parametrize(
    "summary",
    [
        _summary(unlinkedCustomers=1, unlinkedActiveCustomers=0),
        _summary(unlinkedCustomers=1, unlinkedActiveCustomers=1),
    ],
)
def test_valid_active_unlinked_counts_keep_the_direct_unlinked_breach(
    summary: dict[str, int]
):
    result = monitor.build_signals(_audit_payload(summary=summary))

    assert [item.name for item in result.breaches] == ["unlinkedCustomers"]


def test_active_unlinked_count_above_total_is_an_unmeasured_breach():
    result = monitor.build_signals(
        _audit_payload(summary=_summary(unlinkedCustomers=0, unlinkedActiveCustomers=1))
    )

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


def test_current_tracker_endpoint_summary_matches_monitor_contract(client, auth):
    response = client.get("/api/admin/audits/atlas-linkage", headers=auth)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload["summary"]) == monitor.EXPECTED_SUMMARY_KEYS
    for detail_key, summary_key in monitor.DETAIL_LIST_SUMMARY_KEYS.items():
        assert isinstance(payload[detail_key], list)
        assert len(payload[detail_key]) == payload["summary"][summary_key]
    verification = payload["atlasLinkVerification"]
    assert payload["summary"]["unlinkedActiveCustomers"] <= payload["summary"][
        "unlinkedCustomers"
    ]
    if verification["status"] == "ok":
        assert verification["checked"] == (
            payload["summary"]["linkedCustomers"]
            - payload["summary"]["duplicateExtraCustomers"]
        )


def test_state_tracks_each_breach_class_and_announces_changes():
    state, alert = monitor.decide_alert({}, ["unlinkedCustomers"], realert_every=3)
    assert alert is monitor.AlertKind.BREACH

    state, alert = monitor.decide_alert(
        state,
        ["unlinkedCustomers", "danglingLinks"],
        realert_every=3,
    )
    assert alert is monitor.AlertKind.CHANGED
    assert state["breached_signals"] == ["danglingLinks", "unlinkedCustomers"]

    state, alert = monitor.decide_alert(state, [], realert_every=3)
    assert alert is monitor.AlertKind.RECOVERED
    assert state == {"breached_signals": [], "consecutive": 0}


def test_corrupt_state_counter_alerts_as_a_fresh_incident():
    state, alert = monitor.decide_alert(
        {"breached_signals": ["unlinkedCustomers"], "consecutive": "bad"},
        ["unlinkedCustomers"],
        realert_every=3,
    )

    assert alert is monitor.AlertKind.BREACH
    assert state == {"breached_signals": ["unlinkedCustomers"], "consecutive": 1}


@pytest.mark.parametrize(
    "state",
    [
        {},
        {"breached_signals": []},
        {"consecutive": 0},
        {"breached_signals": [], "consecutive": 0, "future": True},
        {"breached_signals": [], "consecutive": 1},
        {"breached_signals": ["unlinkedCustomers"], "consecutive": 0},
        {
            "breached_signals": ["unlinkedCustomers", "unlinkedCustomers"],
            "consecutive": 1,
        },
    ],
)
def test_persisted_state_schema_rejects_incomplete_or_inconsistent_documents(
    state: dict[str, object]
):
    assert monitor.AlertState.from_storage(state) is None

    next_state, alert = monitor.decide_alert(state, ["unlinkedCustomers"], realert_every=3)

    assert alert is monitor.AlertKind.BREACH
    assert next_state == {"breached_signals": ["unlinkedCustomers"], "consecutive": 1}


def test_reminder_uses_the_canonical_alert_kind():
    state, alert = monitor.decide_alert(
        {"breached_signals": ["unlinkedCustomers"], "consecutive": 2},
        ["unlinkedCustomers"],
        realert_every=3,
    )

    assert alert is monitor.AlertKind.REMINDER
    assert state == {"breached_signals": ["unlinkedCustomers"], "consecutive": 3}


def test_alert_delivery_contract_covers_the_canonical_vocabulary():
    assert frozenset(monitor.ALERT_PRESENTATIONS) == frozenset(monitor.AlertKind)


def test_unknown_alert_kind_fails_closed_without_advancing_state(monkeypatch, tmp_path):
    monkeypatch.setattr(
        monitor,
        "decide_alert",
        lambda *_args: ({"breached_signals": ["unlinkedCustomers"], "consecutive": 1}, "future"),
    )
    state_path = tmp_path / "state.json"
    notifications = []

    exit_code = monitor._notify_and_record(
        _settings(tmp_path),
        monitor.AuditResult([monitor.Signal("unlinkedCustomers", "test", count=1)]),
        state_path,
        lambda *args: (notifications.append(args), True)[1],
    )

    assert exit_code == monitor.EXIT_ERROR
    assert notifications[0][2] == "EOM tracker linkage audit unavailable"
    assert "unsupported alert kind" in notifications[0][3]
    assert not state_path.exists()


def test_missing_state_uses_the_canonical_clean_document(tmp_path):
    previous, warning = monitor.read_state(tmp_path / "state.json")

    assert warning is None
    assert previous == {"breached_signals": [], "consecutive": 0}


def test_remote_http_configuration_is_refused_before_credentials_are_sent(tmp_path):
    insecure = replace(_settings(tmp_path), tracker_base_url="http://tracker.example.test")

    with pytest.raises(ValueError, match="HTTPS"):
        monitor.validate_settings(
            insecure, require_measurement=True, require_notification=True
        )


def test_https_configuration_is_accepted():
    monitor._validate_url("test URL", "https://tracker.example.test")


@pytest.mark.parametrize(
    "url",
    ["ftp://tracker.example.test", "file:///tmp/tracker", "tracker.example.test"],
)
def test_non_http_schemes_are_refused_before_a_request(url: str):
    with pytest.raises(ValueError, match="absolute http\\(s\\) URL"):
        monitor._validate_url("test URL", url)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_enumerated_loopback_hosts_allow_local_http(url: str):
    monitor._validate_url("test URL", url)


@pytest.mark.parametrize("url", ["http://127.0.0.2:8000", "http://[::2]:8000"])
def test_unlisted_loopback_hosts_do_not_bypass_https(url: str):
    with pytest.raises(ValueError, match="HTTPS"):
        monitor._validate_url("test URL", url)


def test_monitor_timeout_has_safe_multi_batch_default():
    assert monitor.DEFAULT_AUDIT_TIMEOUT_SECONDS >= 60
    assert monitor.DEFAULT_AUDIT_TIMEOUT_SECONDS <= monitor.MAX_AUDIT_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "bad_timeout",
    [0, -1, float("inf"), float("nan"), monitor.MAX_AUDIT_TIMEOUT_SECONDS + 1],
)
def test_invalid_monitor_timeout_is_refused(tmp_path, bad_timeout: float):
    with pytest.raises(ValueError, match="positive finite"):
        monitor.validate_settings(
            replace(_settings(tmp_path), audit_timeout_seconds=bad_timeout),
            require_measurement=True,
            require_notification=True,
        )


def test_monitor_timeout_can_be_configured_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS", "95")

    settings = monitor.settings_from_environment(
        state_dir=str(tmp_path), realert_every=3
    )

    assert settings.audit_timeout_seconds == 95


def test_malformed_monitor_timeout_environment_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS", "not-a-number")

    with pytest.raises(ValueError, match="positive finite"):
        monitor.settings_from_environment(state_dir=str(tmp_path), realert_every=3)


class _Response:
    def __init__(self, body: dict[str, object], status: int = 200):
        self._body = json.dumps(body).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return self._body


class _ProtocolErrorResponse(_Response):
    def __init__(self, error: Exception):
        self._error = error

    def read(self) -> bytes:
        raise self._error


def test_measure_logs_in_each_run_then_uses_the_returned_bearer(monkeypatch, tmp_path):
    calls = []
    timeouts = []

    def fake_urlopen(request, *, timeout_seconds):
        calls.append(request)
        timeouts.append(timeout_seconds)
        if request.full_url.endswith("/api/auth/login"):
            assert request.get_method() == "POST"
            assert json.loads(request.data.decode("utf-8")) == {
                "name": "Audit Monitor",
                "password": "not-a-real-password",
            }
            return _Response({"token": "fresh-access-token"})
        assert request.full_url.endswith("/api/admin/audits/atlas-linkage")
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer fresh-access-token"
        return _Response(_audit_payload())

    monkeypatch.setattr(monitor, "_open_no_redirect", fake_urlopen)

    result = monitor.measure(
        replace(_settings(tmp_path), audit_timeout_seconds=95)
    )

    assert result.ok
    assert len(calls) == 2
    assert timeouts == [95] * 2


@pytest.mark.parametrize(
    "protocol_error",
    [
        http.client.IncompleteRead(b'{"partial":', 20),
        http.client.BadStatusLine("invalid status line"),
        http.client.LineTooLong("oversized header"),
    ],
)
def test_http_protocol_failure_becomes_an_unmeasured_breach(
    monkeypatch, tmp_path, protocol_error: http.client.HTTPException
):
    monkeypatch.setattr(
        monitor,
        "_open_no_redirect",
        lambda _request, **_kwargs: _ProtocolErrorResponse(protocol_error),
    )

    result = monitor.measure(_settings(tmp_path))

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]
    assert result.breaches[0].count is None
    assert result.breaches[0].error == (
        f"login request failed ({type(protocol_error).__name__})"
    )


def test_undelivered_alert_does_not_advance_state(tmp_path):
    result = monitor.build_signals(
        _audit_payload(summary=_summary(unlinkedCustomers=1))
    )
    state_path = tmp_path / "state.json"

    exit_code = monitor._notify_and_record(
        _settings(tmp_path), result, state_path, lambda *_args: False
    )

    assert exit_code == monitor.EXIT_UNDELIVERED
    assert not state_path.exists()


@pytest.mark.parametrize("invalid_state", ["{", "{}", "[]", b"\xff"])
def test_unknown_prior_state_with_clean_measurement_announces_recovery(
    tmp_path, invalid_state: str | bytes
):
    state_path = tmp_path / "state.json"
    if isinstance(invalid_state, bytes):
        state_path.write_bytes(invalid_state)
    else:
        state_path.write_text(invalid_state, encoding="utf-8")
    notifications = []

    exit_code = monitor._notify_and_record(
        _settings(tmp_path),
        monitor.AuditResult(),
        state_path,
        lambda *args: (notifications.append(args), True)[1],
    )

    assert exit_code == 0
    assert len(notifications) == 1
    assert notifications[0][2] == "EOM tracker linkage audit clean"
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "breached_signals": [],
        "consecutive": 0,
    }


def test_publish_accepts_a_successful_notification_response(monkeypatch):
    monkeypatch.setattr(
        monitor,
        "_open_no_redirect",
        lambda _request, **_kwargs: _Response({}, status=202),
    )

    assert monitor.publish(
        "https://ntfy.example.test",
        "private-topic",
        "Test title",
        "Test body",
        "default",
        "white_check_mark",
    )


def test_http_protocol_failure_during_alert_delivery_is_undelivered(monkeypatch, tmp_path):
    result = monitor.build_signals(
        _audit_payload(summary=_summary(unlinkedCustomers=1))
    )
    state_path = tmp_path / "state.json"

    def fail_open(*_args, **_kwargs):
        raise http.client.BadStatusLine("invalid status line")

    monkeypatch.setattr(monitor, "_open_no_redirect", fail_open)

    exit_code = monitor._notify_and_record(
        _settings(tmp_path), result, state_path, monitor.publish
    )

    assert exit_code == monitor.EXIT_UNDELIVERED
    assert not state_path.exists()


def test_no_alert_does_not_require_notification_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL", "https://tracker.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_NAME", "Audit Monitor")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD", "password")
    monkeypatch.delenv("EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC", raising=False)
    monkeypatch.setattr(monitor, "measure", lambda _settings: monitor.AuditResult())

    exit_code = monitor.main(["--state-dir", str(tmp_path), "--no-alert"])

    assert exit_code == 0
    assert not (tmp_path / "state.json").exists()


def test_test_alert_does_not_measure_or_change_state(monkeypatch, tmp_path):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC", "private-topic")
    monkeypatch.setattr(monitor, "measure", lambda _settings: pytest.fail("must not measure"))

    delivered = []
    exit_code = monitor.main(
        ["--state-dir", str(tmp_path), "--test-alert"],
        notifier=lambda *args: (delivered.append(args), True)[1],
    )

    assert exit_code == 0
    assert len(delivered) == 1
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize(
    "setup_failure",
    ["directory", "lock-open", "lock-acquire"],
)
@pytest.mark.parametrize(
    ("delivered", "expected_exit"), [(True, monitor.EXIT_ERROR), (False, monitor.EXIT_UNDELIVERED)]
)
def test_state_setup_failure_alerts_without_measuring(
    monkeypatch, tmp_path, setup_failure: str, delivered: bool, expected_exit: int
):
    state_dir = tmp_path / "state"
    if setup_failure == "directory":
        state_dir.write_text("file blocks state directory", encoding="utf-8")
    elif setup_failure == "lock-open":
        original_open = Path.open

        def fail_lock_open(path, *args, **kwargs):
            if path.name == "state.lock":
                raise OSError("cannot open state lock")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_lock_open)
    else:
        monkeypatch.setattr(
            monitor.fcntl,
            "flock",
            lambda *_args: (_ for _ in ()).throw(OSError("cannot acquire state lock")),
        )
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL", "https://tracker.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_NAME", "Audit Monitor")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD", "password")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC", "private-topic")
    monkeypatch.setattr(monitor, "measure", lambda _settings: pytest.fail("must not measure"))
    notifications = []

    exit_code = monitor.main(
        ["--state-dir", str(state_dir)],
        notifier=lambda *args: (notifications.append(args), delivered)[1],
    )

    assert exit_code == expected_exit
    assert len(notifications) == 1
    assert notifications[0][2] == "EOM tracker linkage audit unavailable"
    assert "no audit was run" in notifications[0][3]


@pytest.mark.parametrize(
    ("delivered", "expected_exit"), [(True, monitor.EXIT_ERROR), (False, monitor.EXIT_UNDELIVERED)]
)
def test_state_persistence_failure_alerts_after_measurement(
    monkeypatch, tmp_path, delivered: bool, expected_exit: int
):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_BASE_URL", "https://tracker.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_NAME", "Audit Monitor")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD", "password")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_AUDIT_NTFY_TOPIC", "private-topic")
    monkeypatch.setattr(monitor, "measure", lambda _settings: monitor.AuditResult())

    def fail_write_state(*_args, **_kwargs):
        raise OSError("state storage unavailable")

    monkeypatch.setattr(monitor, "write_state", fail_write_state)
    notifications = []

    exit_code = monitor.main(
        ["--state-dir", str(tmp_path)],
        notifier=lambda *args: (notifications.append(args), delivered)[1],
    )

    assert exit_code == expected_exit
    assert len(notifications) == 1
    assert notifications[0][2] == "EOM tracker linkage audit unavailable"
    assert "could not be persisted" in notifications[0][3]


def test_systemd_unit_preserves_failure_and_secret_boundaries():
    service = (REPO_ROOT / "config" / "eom-tracker-linkage-audit.service").read_text(
        encoding="utf-8"
    )
    timer = (REPO_ROOT / "config" / "eom-tracker-linkage-audit.timer").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=%h/.config/eom-tracker-linkage-audit.env" in service
    assert "UMask=0077" in service
    success_status_line = next(
        line
        for line in service.splitlines()
        if line.startswith("SuccessExitStatus=")
    )
    configured_success_statuses = frozenset(
        int(status) for status in success_status_line.partition("=")[2].split()
    )
    assert configured_success_statuses == monitor.SUCCESS_EXIT_STATUSES
    assert "\nEnvironment=EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD=" not in service
    assert "EOM_TRACKER_LINKAGE_AUDIT_TIMEOUT_SECONDS" in service
    assert "TimeoutStartSec=11min" in service
    assert "OnUnitActiveSec=1h" in timer
    assert "Persistent=true" in timer
    assert "loginctl enable-linger <monitor-user>" in timer
