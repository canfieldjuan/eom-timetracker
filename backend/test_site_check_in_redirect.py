"""Contract tests for the canonical-portal QR check-in redirect (issue #35).

GET / and GET /timetracker-mobile.html must 302 QR deep links
(?checkIn=<token>) to {PUBLIC_APP_URL}/portal when PUBLIC_APP_URL points at
the canonical EOM portal, and keep serving the legacy Firefly page in every
other state (env unset, param absent or empty, self-origin configuration).
The redirect must forward ONLY the checkIn value and must never be cacheable,
so unsetting PUBLIC_APP_URL rolls the cutover back completely.
"""

from __future__ import annotations

import pytest

import time_tracker_api
from test_site_check_in import create_site_qr


PORTAL = "https://portal.example.test"
PAGE_MARKER = "Firefly Time Tracker"


@pytest.fixture
def portal_env(monkeypatch):
    # PUBLIC_APP_URL is read into a module global at import time; patch the
    # global, not os.environ.
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", PORTAL)


def _get(client, path, **kwargs):
    return client.get(path, follow_redirects=False, **kwargs)


def test_redirects_check_in_links_to_portal(client, portal_env):
    for path in ("/", "/timetracker-mobile.html"):
        resp = _get(client, path, params={"checkIn": "eom1.44.abc.def"})
        assert resp.status_code == 302, resp.text
        assert (
            resp.headers["location"] == f"{PORTAL}/portal?checkIn=eom1.44.abc.def"
        )
        assert resp.headers["cache-control"] == "no-store"


def test_redirect_forwards_only_the_check_in_param(client, portal_env):
    resp = _get(
        client,
        "/",
        params={
            "checkIn": "tok",
            "apiBaseUrl": "https://evil.example",
            "extra": "1",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == f"{PORTAL}/portal?checkIn=tok"


def test_redirect_url_encodes_the_token(client, portal_env):
    resp = _get(client, "/", params={"checkIn": "a b/&?#c"})
    assert resp.status_code == 302
    assert resp.headers["location"] == f"{PORTAL}/portal?checkIn=a%20b%2F%26%3F%23c"


def test_without_param_serves_legacy_page(client, portal_env):
    for path in ("/", "/timetracker-mobile.html"):
        resp = _get(client, path)
        assert resp.status_code == 200
        assert PAGE_MARKER in resp.text


def test_empty_param_serves_legacy_page(client, portal_env):
    resp = _get(client, "/?checkIn=")
    assert resp.status_code == 200
    assert PAGE_MARKER in resp.text


def test_unset_public_app_url_serves_legacy_page(client):
    assert time_tracker_api.PUBLIC_APP_URL == ""
    resp = _get(client, "/", params={"checkIn": "tok"})
    assert resp.status_code == 200
    assert PAGE_MARKER in resp.text


def test_self_origin_public_app_url_never_redirects(client, monkeypatch):
    # TestClient requests arrive as http://testserver; a PUBLIC_APP_URL on the
    # same hostname must not bounce the backend to itself. The comparison is
    # hostname-only: behind the proxy the request scheme can differ from the
    # public one, and a scheme-sensitive check would still loop.
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "https://testserver")
    resp = _get(client, "/", params={"checkIn": "tok"})
    assert resp.status_code == 200
    assert PAGE_MARKER in resp.text


def test_generated_qr_url_targets_portal_when_configured(
    client, auth, location_id, portal_env
):
    data = create_site_qr(client, auth, location_id)
    assert data["checkInUrl"] == f"{PORTAL}/portal?checkIn={data['token']}"


def test_generated_qr_url_keeps_legacy_shape_when_unset(client, auth, location_id):
    assert time_tracker_api.PUBLIC_APP_URL == ""
    data = create_site_qr(client, auth, location_id)
    assert data["checkInUrl"] == f"http://testserver/?checkIn={data['token']}"


def test_generated_qr_url_keeps_legacy_shape_for_self_origin(
    client, auth, location_id, monkeypatch
):
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "https://testserver")
    data = create_site_qr(client, auth, location_id)
    assert data["checkInUrl"] == f"https://testserver/?checkIn={data['token']}"
