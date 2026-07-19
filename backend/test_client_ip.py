"""Regression tests for get_client_ip: a client must not be able to spoof its
IP (and defeat the login rate limiter / poison audit logs) by prepending fake
X-Forwarded-For entries."""

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


def test_two_trusted_hops(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 2)
    # With two trusted proxies, the client is the 2nd from the right.
    req = _StubRequest(xff="1.2.3.4, 203.0.113.7, 10.0.0.1")
    assert tta.get_client_ip(req) == "203.0.113.7"


def test_no_xff_uses_direct_peer(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", True)
    monkeypatch.setattr(tta, "TRUSTED_PROXY_HOPS", 1)
    req = _StubRequest(xff=None, client_host="10.0.0.9")
    assert tta.get_client_ip(req) == "10.0.0.9"


def test_trust_proxy_off_ignores_xff(monkeypatch):
    monkeypatch.setattr(tta, "TRUST_PROXY", False)
    req = _StubRequest(xff="1.2.3.4", client_host="10.0.0.9")
    assert tta.get_client_ip(req) == "10.0.0.9"
