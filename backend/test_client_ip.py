"""Regression tests for get_client_ip: a client must not be able to spoof its
IP (and defeat the login rate limiter / poison audit logs) by prepending fake
X-Forwarded-For entries."""

import re
from pathlib import Path

import time_tracker_api as tta


class _StubClient:
    def __init__(self, host):
        self.host = host


class _StubRequest:
    def __init__(self, xff=None, client_host="10.0.0.9"):
        self.headers = {} if xff is None else {"x-forwarded-for": xff}
        self.client = _StubClient(client_host)


def test_spoofed_leftmost_xff_is_ignored(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 1)
    # Client prepends a fake IP; our proxy appended the real one on the right.
    req = _StubRequest(xff="1.2.3.4, 203.0.113.7")
    assert tta.get_client_ip(req) == "203.0.113.7"


def test_honest_single_hop_unchanged(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 1)
    req = _StubRequest(xff="203.0.113.7")
    assert tta.get_client_ip(req) == "203.0.113.7"


def test_multiple_spoofed_entries_still_take_rightmost(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 1)
    req = _StubRequest(xff="9.9.9.9, 8.8.8.8, 203.0.113.7")
    assert tta.get_client_ip(req) == "203.0.113.7"


def test_render_two_hop_chain_selects_real_caller(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 2)
    req = _StubRequest(xff="66.116.35.247, 104.22.62.111")
    assert tta.get_client_ip(req) == "66.116.35.247"


def test_render_two_hop_chain_ignores_spoofed_prefix(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 2)
    req = _StubRequest(
        xff="203.0.113.77, 198.51.100.88, 66.116.35.247, 104.22.64.149"
    )
    assert tta.get_client_ip(req) == "66.116.35.247"


def test_render_proxy_hop_configuration_matches_live_topology():
    assert tta.DEFAULT_TRUSTED_PROXY_HOPS == 2

    render_config = (Path(__file__).resolve().parents[1] / "render.yaml").read_text()
    configured_hops = re.search(
        r"(?m)^\s*-\s+key:\s+TRUSTED_PROXY_HOPS\s*\n\s+value:\s+[\"']?(\d+)",
        render_config,
    )
    assert configured_hops is not None
    assert int(configured_hops.group(1)) == tta.DEFAULT_TRUSTED_PROXY_HOPS


def test_render_blueprint_declares_atlas_funnel_proxy_environment():
    render_config = (Path(__file__).resolve().parents[1] / "render.yaml").read_text()

    for key in (
        "ATLAS_FUNNEL_BASE_URL",
        "ATLAS_FUNNEL_SERVICE_TOKEN",
        "ATLAS_FUNNEL_TIMEOUT_SECONDS",
    ):
        assert re.search(rf"(?m)^\s*-\s+key:\s+{key}\s*$", render_config)

    assert re.search(
        r"(?m)^\s*-\s+key:\s+ATLAS_FUNNEL_BASE_URL\s*\n\s+sync:\s+false\s*$",
        render_config,
    )
    assert re.search(
        r"(?m)^\s*-\s+key:\s+ATLAS_FUNNEL_SERVICE_TOKEN\s*\n\s+sync:\s+false\s*$",
        render_config,
    )
    assert re.search(
        r"(?m)^\s*-\s+key:\s+ATLAS_FUNNEL_TIMEOUT_SECONDS\s*\n\s+value:\s+[\"']?10[\"']?\s*$",
        render_config,
    )


def test_no_xff_uses_direct_peer(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 1)
    req = _StubRequest(xff=None, client_host="10.0.0.9")
    assert tta.get_client_ip(req) == "10.0.0.9"


def test_trust_proxy_off_ignores_xff(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", False)
    req = _StubRequest(xff="1.2.3.4", client_host="10.0.0.9")
    assert tta.get_client_ip(req) == "10.0.0.9"
