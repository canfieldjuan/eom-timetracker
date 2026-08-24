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
    )


def test_clean_response_is_not_a_breach():
    result = monitor.build_signals(_audit_payload())

    assert result.ok
    assert result.breaches == []


@pytest.mark.parametrize("signal", monitor.FAULT_SUMMARY_KEYS)
def test_each_integrity_count_breaches_independently(signal: str):
    result = monitor.build_signals(_audit_payload(summary=_summary(**{signal: 1})))

    assert [item.name for item in result.breaches] == [signal]


@pytest.mark.parametrize(
    "payload",
    [
        _audit_payload(success=False),
        _audit_payload(databaseReadOnly=False),
        _audit_payload(summary={"unlinkedCustomers": 0}),
        _audit_payload(summary=_summary(unlinkedCustomers=True)),
        _audit_payload(atlasLinkVerification={"status": ""}),
        _audit_payload(atlasLinkVerification={"status": "unknown-status"}),
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
            _summary(linkedCustomers=2, duplicateExtraCustomers=1),
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
            summary=_summary(linkedCustomers=3, duplicateExtraCustomers=1),
            atlasLinkVerification={"status": "ok", "checked": 2},
        )
    )

    assert result.ok


def test_new_summary_key_fails_closed_instead_of_being_ignored():
    result = monitor.build_signals(
        _audit_payload(summary={**_summary(), "futureIntegritySignal": 0})
    )

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]


def test_current_tracker_endpoint_summary_matches_monitor_contract(client, auth):
    response = client.get("/api/admin/audits/atlas-linkage", headers=auth)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload["summary"]) == monitor.EXPECTED_SUMMARY_KEYS
    verification = payload["atlasLinkVerification"]
    if verification["status"] == "ok":
        assert verification["checked"] == (
            payload["summary"]["linkedCustomers"]
            - payload["summary"]["duplicateExtraCustomers"]
        )


def test_state_tracks_each_breach_class_and_announces_changes():
    state, alert = monitor.decide_alert({}, ["unlinkedCustomers"], realert_every=3)
    assert alert == "breach"

    state, alert = monitor.decide_alert(
        state,
        ["unlinkedCustomers", "danglingLinks"],
        realert_every=3,
    )
    assert alert == "changed"
    assert state["breached_signals"] == ["danglingLinks", "unlinkedCustomers"]

    state, alert = monitor.decide_alert(state, [], realert_every=3)
    assert alert == "recovered"
    assert state == {"breached_signals": [], "consecutive": 0}


def test_corrupt_state_counter_alerts_as_a_fresh_incident():
    state, alert = monitor.decide_alert(
        {"breached_signals": ["unlinkedCustomers"], "consecutive": "bad"},
        ["unlinkedCustomers"],
        realert_every=3,
    )

    assert alert == "breach"
    assert state == {"breached_signals": ["unlinkedCustomers"], "consecutive": 1}


def test_remote_http_configuration_is_refused_before_credentials_are_sent(tmp_path):
    insecure = replace(_settings(tmp_path), tracker_base_url="http://tracker.example.test")

    with pytest.raises(ValueError, match="HTTPS"):
        monitor.validate_settings(
            insecure, require_measurement=True, require_notification=True
        )


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


class _IncompleteResponse(_Response):
    def read(self) -> bytes:
        raise http.client.IncompleteRead(b'{"partial":', 20)


def test_measure_logs_in_each_run_then_uses_the_returned_bearer(monkeypatch, tmp_path):
    calls = []

    def fake_urlopen(request):
        calls.append(request)
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

    result = monitor.measure(_settings(tmp_path))

    assert result.ok
    assert len(calls) == 2


def test_truncated_http_response_becomes_an_unmeasured_breach(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor, "_open_no_redirect", lambda _request: _IncompleteResponse({}))

    result = monitor.measure(_settings(tmp_path))

    assert [item.name for item in result.breaches] == ["tracker_audit_unavailable"]
    assert result.breaches[0].count is None
    assert result.breaches[0].error == "login request failed (IncompleteRead)"


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


def test_systemd_unit_preserves_failure_and_secret_boundaries():
    service = (REPO_ROOT / "config" / "eom-tracker-linkage-audit.service").read_text(
        encoding="utf-8"
    )
    timer = (REPO_ROOT / "config" / "eom-tracker-linkage-audit.timer").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=%h/.config/eom-tracker-linkage-audit.env" in service
    assert "UMask=0077" in service
    assert "SuccessExitStatus=0 2" in service
    assert "\nEnvironment=EOM_TRACKER_LINKAGE_AUDIT_ADMIN_PASSWORD=" not in service
    assert "OnUnitActiveSec=1h" in timer
    assert "Persistent=true" in timer
    assert "loginctl enable-linger <monitor-user>" in timer
