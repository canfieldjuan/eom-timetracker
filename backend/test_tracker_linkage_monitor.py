"""Focused contract tests for the thin Tracker linkage alert monitor."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "eom_tracker_linkage_monitor.py"
INSTALLER_PATH = REPO_ROOT / "scripts" / "install_eom_tracker_linkage_monitor.sh"
SPEC = importlib.util.spec_from_file_location("eom_tracker_linkage_monitor", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
monitor = importlib.util.module_from_spec(SPEC)
sys.modules["eom_tracker_linkage_monitor"] = monitor
SPEC.loader.exec_module(monitor)


def _settings(tmp_path: Path) -> object:
    return monitor.Settings(
        base_url="https://tracker.example.test",
        admin_name="Alert Monitor",
        admin_password="not-a-real-password",
        ntfy_url="https://ntfy.example.test",
        ntfy_topic="private-topic",
        state_file=tmp_path / "state.json",
    )


def _audit_payload(**counts: int) -> dict[str, object]:
    return {
        "success": True,
        "summary": {key: counts.get(key, 0) for key in monitor.SIGNAL_KEYS},
        "atlasLinkVerification": {"status": "ok"},
    }


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


def test_measure_logs_in_then_reads_the_existing_audit(monkeypatch, tmp_path):
    requests = []

    def fake_open(request):
        requests.append(request)
        if request.full_url.endswith(monitor.LOGIN_PATH):
            assert request.get_method() == "POST"
            assert json.loads(request.data) == {
                "name": "Alert Monitor",
                "password": "not-a-real-password",
            }
            return _Response({"token": "test-token"})
        assert request.full_url.endswith(monitor.AUDIT_PATH)
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer test-token"
        return _Response(_audit_payload(unlinkedCustomers=2, danglingLinks=1))

    monkeypatch.setattr(monitor, "_open", fake_open)

    counts, error = monitor.measure(_settings(tmp_path))

    assert error is None
    assert counts == {
        "unlinkedCustomers": 2,
        "staleReservations": 0,
        "danglingLinks": 1,
    }
    assert len(requests) == 2


def test_publish_posts_directly_to_the_configured_topic(monkeypatch, tmp_path):
    requests = []

    def fake_open(request):
        requests.append(request)
        return _Response({}, status=202)

    monkeypatch.setattr(monitor, "_open", fake_open)

    assert monitor.publish(_settings(tmp_path), "Test title", "Test body")

    assert len(requests) == 1
    request = requests[0]
    assert request.full_url == "https://ntfy.example.test/private-topic"
    assert request.get_method() == "POST"
    assert request.data == b"Test body"
    assert request.get_header("Title") == "Test title"


@pytest.mark.parametrize(
    "payload",
    [
        _audit_payload(unlinkedCustomers=-1),
        _audit_payload(unlinkedCustomers=True),
        {"success": True, "summary": {}},
        {
            "success": True,
            "summary": {key: 0 for key in monitor.SIGNAL_KEYS},
            "atlasLinkVerification": {"status": "unavailable"},
        },
    ],
)
def test_invalid_or_unverified_audit_is_not_clean(monkeypatch, tmp_path, payload):
    responses = iter([_Response({"token": "test-token"}), _Response(payload)])
    monkeypatch.setattr(monitor, "_open", lambda _request: next(responses))

    counts, error = monitor.measure(_settings(tmp_path))

    assert counts is None
    assert error


def test_new_breach_notifies_and_tracks_the_signal_set(monkeypatch, tmp_path):
    monkeypatch.setattr(
        monitor,
        "measure",
        lambda _settings: ({"unlinkedCustomers": 1, "staleReservations": 0, "danglingLinks": 0}, None),
    )
    delivered = []

    exit_code = monitor.run_once(
        _settings(tmp_path),
        lambda _settings, title, body: (delivered.append((title, body)), True)[1],
    )

    assert exit_code == monitor.EXIT_BREACH
    assert delivered == [
        ("EOM tracker linkage audit breached", "unlinkedCustomers=1")
    ]
    assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8")) == {
        "breachedSignals": ["unlinkedCustomers"]
    }


def test_undelivered_breach_leaves_state_unchanged(monkeypatch, tmp_path):
    monkeypatch.setattr(
        monitor,
        "measure",
        lambda _settings: ({"unlinkedCustomers": 1, "staleReservations": 0, "danglingLinks": 0}, None),
    )

    exit_code = monitor.run_once(_settings(tmp_path), lambda *_args: False)

    assert exit_code == monitor.EXIT_UNDELIVERED
    assert not (tmp_path / "state.json").exists()


def test_unavailable_measurement_alerts_with_a_distinct_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, "measure", lambda _settings: (None, "login HTTP 503"))
    delivered = []

    exit_code = monitor.run_once(
        _settings(tmp_path),
        lambda _settings, title, body: (delivered.append((title, body)), True)[1],
    )

    assert exit_code == monitor.EXIT_ERROR
    assert delivered == [
        ("EOM tracker linkage monitor unavailable", "login HTTP 503")
    ]


def test_test_alert_does_not_log_in_or_read_the_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, "settings_from_environment", lambda: _settings(tmp_path))
    monkeypatch.setattr(monitor, "measure", lambda _settings: pytest.fail("must not measure"))
    delivered = []

    exit_code = monitor.main(
        ["--test-alert"],
        notifier=lambda _settings, title, body: (delivered.append((title, body)), True)[1],
    )

    assert exit_code == monitor.EXIT_CLEAN
    assert delivered == [
        ("EOM tracker linkage monitor test", "Test alert from the tracker linkage monitor.")
    ]


def test_environment_configuration_rejects_non_https_endpoints(monkeypatch):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_BASE_URL", "http://tracker.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_NAME", "Alert Monitor")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD", "not-a-real-password")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL", "https://ntfy.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_NTFY_TOPIC", "private-topic")

    with pytest.raises(ValueError, match="HTTPS"):
        monitor.settings_from_environment()


def test_systemd_template_preserves_secret_and_breach_exit_boundaries():
    service = (REPO_ROOT / "config" / "eom-tracker-linkage-monitor.service").read_text(
        encoding="utf-8"
    )
    timer = (REPO_ROOT / "config" / "eom-tracker-linkage-monitor.timer").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=%h/.config/eom-tracker-linkage-monitor.env" in service
    assert "UMask=0077" in service
    assert "SuccessExitStatus=0 2" in service
    assert "EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD=" not in service
    assert "OnUnitActiveSec=1h" in timer


def test_installer_places_the_executable_and_unit_templates(tmp_path):
    test_home = tmp_path / "monitor-home"
    result = subprocess.run(
        ["bash", str(INSTALLER_PATH)],
        cwd=REPO_ROOT,
        env={**os.environ, "HOME": str(test_home)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    installed_script = test_home / ".local/bin/eom-tracker-linkage-monitor.py"
    installed_service = (
        test_home / ".config/systemd/user/eom-tracker-linkage-monitor.service"
    )
    installed_timer = (
        test_home / ".config/systemd/user/eom-tracker-linkage-monitor.timer"
    )
    assert installed_script.read_text(encoding="utf-8") == MODULE_PATH.read_text(
        encoding="utf-8"
    )
    assert installed_script.stat().st_mode & 0o111
    assert installed_service.read_text(encoding="utf-8") == (
        REPO_ROOT / "config/eom-tracker-linkage-monitor.service"
    ).read_text(encoding="utf-8")
    assert installed_timer.read_text(encoding="utf-8") == (
        REPO_ROOT / "config/eom-tracker-linkage-monitor.timer"
    ).read_text(encoding="utf-8")
