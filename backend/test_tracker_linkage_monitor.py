"""Focused contract tests for the thin Tracker linkage alert monitor."""
from __future__ import annotations

import email.message
import http.client
import importlib.util
import io
import json
import os
import subprocess
import sys
import urllib.error
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


def test_measure_logs_in_then_proves_funnel_review_and_reads_the_existing_audit(
    monkeypatch, tmp_path
):
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
        if request.full_url.endswith(monitor.FUNNEL_REVIEW_PATH):
            assert request.get_method() == "GET"
            assert request.get_header("Authorization") == "Bearer test-token"
            return _Response({"success": True})
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
    assert [request.full_url for request in requests] == [
        "https://tracker.example.test/api/auth/login",
        "https://tracker.example.test/api/admin/funnel/review?limit=1",
        "https://tracker.example.test/api/admin/audits/atlas-linkage",
    ]


@pytest.mark.parametrize("payload", [{"success": False}, {}, {"success": "true"}])
def test_unavailable_funnel_review_is_not_a_clean_measurement(
    monkeypatch, tmp_path, payload
):
    requests = []
    responses = iter(
        [
            _Response({"token": "test-token"}),
            _Response(payload),
        ]
    )

    def fake_open(request):
        requests.append(request)
        return next(responses)

    monkeypatch.setattr(monitor, "_open", fake_open)

    counts, error = monitor.measure(_settings(tmp_path))

    assert counts is None
    assert error == "funnel review did not confirm success"
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
    responses = iter(
        [
            _Response({"token": "test-token"}),
            _Response({"success": True}),
            _Response(payload),
        ]
    )
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


def test_environment_configuration_preserves_admin_password_whitespace(monkeypatch):
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_BASE_URL", "https://tracker.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_NAME", "Alert Monitor")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD", " password ")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_NTFY_URL", "https://ntfy.example.test")
    monkeypatch.setenv("EOM_TRACKER_LINKAGE_MONITOR_NTFY_TOPIC", "private-topic")

    assert monitor.settings_from_environment().admin_password == " password "


def test_systemd_template_preserves_secret_and_breach_exit_boundaries():
    service = (REPO_ROOT / "config" / "eom-tracker-linkage-monitor.service").read_text(
        encoding="utf-8"
    )
    test_service = (
        REPO_ROOT / "config" / "eom-tracker-linkage-monitor-test.service"
    ).read_text(encoding="utf-8")
    timer = (REPO_ROOT / "config" / "eom-tracker-linkage-monitor.timer").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=%h/.config/eom-tracker-linkage-monitor.env" in service
    assert "UMask=0077" in service
    assert "SuccessExitStatus=0 2" in service
    assert "EOM_TRACKER_LINKAGE_MONITOR_ADMIN_PASSWORD=" not in service
    assert "EnvironmentFile=%h/.config/eom-tracker-linkage-monitor.env" in test_service
    assert "ExecStart=%h/.local/bin/eom-tracker-linkage-monitor.py --test-alert" in test_service
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
    installed_test_service = (
        test_home / ".config/systemd/user/eom-tracker-linkage-monitor-test.service"
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
    assert installed_test_service.read_text(encoding="utf-8") == (
        REPO_ROOT / "config/eom-tracker-linkage-monitor-test.service"
    ).read_text(encoding="utf-8")
    assert installed_timer.read_text(encoding="utf-8") == (
        REPO_ROOT / "config/eom-tracker-linkage-monitor.timer"
    ).read_text(encoding="utf-8")
    assert "systemctl --user start eom-tracker-linkage-monitor-test.service" in result.stdout


def _http_error(
    url: str,
    status: int,
    body: object,
    *,
    headers: dict[str, str] | None = None,
) -> urllib.error.HTTPError:
    """Build the HTTPError urllib raises for a non-2xx tracker response."""
    message = email.message.Message()
    for name, value in (headers or {}).items():
        message[name] = value
    raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    return urllib.error.HTTPError(url, status, "error", message, io.BytesIO(raw))


_UNAVAILABLE_DETAIL = "EOM lead review service is temporarily unavailable; retry this request"


def _unavailable(url: str, **headers: str) -> urllib.error.HTTPError:
    return _http_error(
        url,
        503,
        {"success": False, "error": _UNAVAILABLE_DETAIL},
        headers=headers,
    )


def _measure_with(monkeypatch, tmp_path, responses):
    """Drive measure() through a scripted response sequence; return the trace."""
    requests = []
    sleeps = []
    responses = iter(responses)

    def fake_open(request):
        requests.append(request)
        outcome = next(responses)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(monitor, "_open", fake_open)
    monkeypatch.setattr(monitor, "_sleep", sleeps.append)
    counts, error = monitor.measure(_settings(tmp_path))
    return counts, error, requests, sleeps


def test_unavailable_funnel_review_carries_the_tracker_error_detail(
    monkeypatch, tmp_path
):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _unavailable(review_url, **{"Retry-After": "5"}),
            _unavailable(review_url, **{"Retry-After": "5"}),
        ],
    )

    assert counts is None
    assert error == f"funnel review HTTP 503 ({_UNAVAILABLE_DETAIL}) after 2 attempts"
    # Login once, then exactly the contract retry: never a third read.
    assert [request.full_url for request in requests] == [
        "https://tracker.example.test/api/auth/login",
        review_url,
        review_url,
    ]
    assert all(
        request.get_header("Authorization") == "Bearer test-token"
        for request in requests[1:]
    )
    assert sleeps == [5.0]


def test_unavailable_funnel_review_recovers_on_the_contract_retry(
    monkeypatch, tmp_path
):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _unavailable(review_url, **{"Retry-After": "5"}),
            _Response({"success": True}),
            _Response(_audit_payload(danglingLinks=1)),
        ],
    )

    assert error is None
    assert counts == {"unlinkedCustomers": 0, "staleReservations": 0, "danglingLinks": 1}
    assert [request.full_url for request in requests] == [
        "https://tracker.example.test/api/auth/login",
        review_url,
        review_url,
        "https://tracker.example.test/api/admin/audits/atlas-linkage",
    ]
    assert sleeps == [5.0]


def test_unavailable_audit_read_uses_the_same_contract_retry(monkeypatch, tmp_path):
    audit_url = "https://tracker.example.test" + monitor.AUDIT_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _Response({"success": True}),
            _http_error(
                audit_url,
                503,
                {"success": False, "error": "Atlas linkage audit is temporarily unavailable"},
            ),
            _http_error(
                audit_url,
                503,
                {"success": False, "error": "Atlas linkage audit is temporarily unavailable"},
            ),
        ],
    )

    assert counts is None
    # An unlisted server string is never relayed; the status and attempt count
    # still reach the alert.
    assert error == f"HTTP 503 ({monitor._WITHHELD_DETAIL}) after 2 attempts"
    assert [request.full_url for request in requests][2:] == [audit_url, audit_url]
    # No Retry-After on this response: the tracker's own 5s default applies.
    assert sleeps == [5.0]


@pytest.mark.parametrize(
    ("retry_after", "expected_delay"),
    [
        ("12", 12.0),
        (" 7 ", 7.0),
        ("0", 0.0),
        ("600", 30.0),
        ("garbage", 5.0),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 5.0),
        (None, 5.0),
    ],
)
def test_retry_after_is_honored_and_bounded(
    monkeypatch, tmp_path, retry_after, expected_delay
):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    _counts, _error, _requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _unavailable(review_url, **headers),
            _Response({"success": True}),
            _Response(_audit_payload()),
        ],
    )

    assert sleeps == [expected_delay]


@pytest.mark.parametrize(
    ("status", "headers", "body", "expected"),
    [
        # Bearer rejection: a 4xx is never retried, Retry-After or not.
        (
            401,
            {"Retry-After": "5"},
            {"success": False, "error": "Invalid access token"},
            "HTTP 401 (Invalid access token)",
        ),
        (403, {}, {"success": False, "error": "Admin access required"}, "HTTP 403 (Admin access required)"),
        # The tracker's own 502s carry no Retry-After: they are not transient.
        (
            502,
            {},
            {"success": False, "error": "EOM lead review service authentication failed"},
            "HTTP 502 (EOM lead review service authentication failed)",
        ),
        (
            502,
            {},
            {"success": False, "error": "EOM lead review service returned an invalid response"},
            "HTTP 502 (EOM lead review service returned an invalid response)",
        ),
        # A bare 500 without the tracker's retry signal fails immediately, and an
        # unlisted server string is withheld from the alert.
        (
            500,
            {},
            {"success": False, "error": "Internal server error"},
            f"HTTP 500 ({monitor._WITHHELD_DETAIL})",
        ),
    ],
)
def test_non_retryable_http_errors_fail_immediately(
    monkeypatch, tmp_path, status, headers, body, expected
):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(review_url, status, body, headers=headers),
        ],
    )

    assert counts is None
    assert error == f"funnel review {expected}"
    assert len(requests) == 2
    assert sleeps == []


@pytest.mark.parametrize("status", [500, 502, 504])
def test_relayed_upstream_5xx_with_retry_after_is_retried_once(
    monkeypatch, tmp_path, status
):
    # time_tracker_api.py _atlas_funnel_read relays an upstream 5xx with its
    # status and Retry-After: 5; that header is the tracker's retry signal.
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    relayed = {"success": False, "error": "EOM lead review failed"}
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(review_url, status, relayed, headers={"Retry-After": "5"}),
            _http_error(review_url, status, relayed, headers={"Retry-After": "5"}),
        ],
    )

    assert counts is None
    assert error == f"funnel review HTTP {status} (EOM lead review failed) after 2 attempts"
    assert [request.full_url for request in requests][1:] == [review_url, review_url]
    assert sleeps == [5.0]


def test_relayed_upstream_5xx_recovers_on_the_contract_retry(monkeypatch, tmp_path):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(
                review_url,
                502,
                {"success": False, "error": "EOM lead review failed"},
                headers={"Retry-After": "7"},
            ),
            _Response({"success": True}),
            _Response(_audit_payload()),
        ],
    )

    assert error is None
    assert counts == {key: 0 for key in monitor.SIGNAL_KEYS}
    assert len(requests) == 4
    assert sleeps == [7.0]


def test_login_unavailable_is_never_replayed(monkeypatch, tmp_path):
    login_url = "https://tracker.example.test" + monitor.LOGIN_PATH
    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _http_error(
                login_url,
                503,
                {"success": False, "error": "Login is temporarily unavailable"},
                headers={"Retry-After": "5"},
            ),
        ],
    )

    assert counts is None
    assert error == f"HTTP 503 ({monitor._WITHHELD_DETAIL})"
    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "body",
    [
        b"<html><body>Service Unavailable</body></html>",
        b"",
        b"\xff\xfe",
        json.dumps(["not", "an", "object"]).encode("utf-8"),
        json.dumps({"success": False}).encode("utf-8"),
        json.dumps({"success": False, "error": "   "}).encode("utf-8"),
        json.dumps({"success": False, "error": {"nested": "object"}}).encode("utf-8"),
    ],
)
def test_http_error_without_a_server_error_literal_stays_bare(
    monkeypatch, tmp_path, body
):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    _counts, error, _requests, _sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(review_url, 503, body),
            _http_error(review_url, 503, body),
        ],
    )

    assert error == "funnel review HTTP 503 after 2 attempts"


def test_known_detail_matches_after_whitespace_collapse(monkeypatch, tmp_path):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    padded = "  EOM lead review service is temporarily\n\tunavailable; retry this request "
    _counts, error, _requests, _sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(review_url, 502, {"success": False, "error": padded}),
        ],
    )

    assert error == f"funnel review HTTP 502 ({_UNAVAILABLE_DETAIL})"


@pytest.mark.parametrize(
    "detail",
    [
        # Content an upstream body could carry that must never reach ntfy.
        "contact jane@example.com about 555-0100",
        "Bearer eomf_v1_not_a_real_token",
        "psycopg2.OperationalError: connection refused",
        # A known literal with anything appended is no longer the literal.
        "EOM lead review failed for contact 0c7e",
        "eom lead review failed",
        "x" * 5000,
    ],
)
def test_unlisted_server_details_are_withheld_from_the_alert(monkeypatch, tmp_path, detail):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    _counts, error, _requests, _sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [
            _Response({"token": "test-token"}),
            _http_error(review_url, 403, {"success": False, "error": detail}),
        ],
    )

    assert error == f"funnel review HTTP 403 ({monitor._WITHHELD_DETAIL})"
    for fragment in ("example.com", "555", "eomf_v1", "psycopg2", "0c7e", "xxxx"):
        assert fragment not in error


def test_every_allowlisted_detail_is_carried_verbatim(monkeypatch, tmp_path):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    for detail in sorted(monitor._KNOWN_ERROR_DETAILS):
        _counts, error, _requests, _sleeps = _measure_with(
            monkeypatch,
            tmp_path,
            [
                _Response({"token": "test-token"}),
                _http_error(review_url, 403, {"success": False, "error": detail}),
            ],
        )
        assert error == f"funnel review HTTP 403 ({detail})"


def test_truncated_error_body_still_produces_the_alert(monkeypatch, tmp_path):
    # A chunked error response cut off mid-body raises http.client.IncompleteRead
    # from exc.read(); that must degrade to the bare status, never escape and
    # kill the run before the unavailable notification is sent.
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH

    class _TruncatedBody(io.BytesIO):
        def read(self, size=-1):
            raise http.client.IncompleteRead(b'{"success": false, "err')

    def truncated():
        return urllib.error.HTTPError(
            review_url, 503, "error", email.message.Message(), _TruncatedBody()
        )

    counts, error, requests, sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [_Response({"token": "test-token"}), truncated(), truncated()],
    )

    assert counts is None
    assert error == "funnel review HTTP 503 after 2 attempts"
    assert len(requests) == 3
    assert sleeps == [5.0]


def test_http_error_body_is_read_once_and_bounded(monkeypatch, tmp_path):
    review_url = "https://tracker.example.test" + monitor.FUNNEL_REVIEW_PATH
    reads = []

    class _BoundedBody(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    message = email.message.Message()
    exc = urllib.error.HTTPError(
        review_url,
        401,
        "error",
        message,
        _BoundedBody(
            json.dumps({"success": False, "error": "Invalid access token"}).encode("utf-8")
        ),
    )
    _counts, error, _requests, _sleeps = _measure_with(
        monkeypatch,
        tmp_path,
        [_Response({"token": "test-token"}), exc],
    )

    assert error == "funnel review HTTP 401 (Invalid access token)"
    assert reads == [monitor._ERROR_BODY_MAX_BYTES]


def test_unavailable_alert_body_names_the_tracker_detail(monkeypatch, tmp_path):
    monkeypatch.setattr(
        monitor,
        "measure",
        lambda _settings: (
            None,
            f"funnel review HTTP 503 ({_UNAVAILABLE_DETAIL}) after 2 attempts",
        ),
    )
    delivered = []

    exit_code = monitor.run_once(
        _settings(tmp_path),
        lambda _settings, title, body: (delivered.append((title, body)), True)[1],
    )

    assert exit_code == monitor.EXIT_ERROR
    assert delivered == [
        (
            "EOM tracker linkage monitor unavailable",
            f"funnel review HTTP 503 ({_UNAVAILABLE_DETAIL}) after 2 attempts",
        )
    ]
    assert not (tmp_path / "state.json").exists()
