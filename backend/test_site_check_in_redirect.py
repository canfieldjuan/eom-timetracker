"""Contract tests for the canonical-portal entry cutover (issue #35).

GET / and GET /timetracker-mobile.html must always 302 to
{PUBLIC_APP_URL}/portal when PUBLIC_APP_URL points at the canonical EOM portal.
QR deep links preserve only the non-empty checkIn value. Requests without a
usable external portal fail closed instead of serving the retired Firefly page
or generating a nonfunctional backend QR path. Redirects must never be cacheable.
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


def test_without_param_redirects_to_portal(client, portal_env):
    for path in ("/", "/timetracker-mobile.html"):
        resp = _get(client, path)
        assert resp.status_code == 302
        assert resp.headers["location"] == f"{PORTAL}/portal"
        assert resp.headers["cache-control"] == "no-store"
        assert PAGE_MARKER not in resp.text


def test_empty_or_unrelated_params_are_not_forwarded(client, portal_env):
    for path in ("/", "/timetracker-mobile.html"):
        resp = _get(
            client,
            path,
            params={
                "checkIn": "",
                "apiBaseUrl": "https://evil.example",
                "extra": "1",
            },
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == f"{PORTAL}/portal"
        assert resp.headers["cache-control"] == "no-store"
        assert PAGE_MARKER not in resp.text


def test_unset_public_app_url_fails_closed(client, monkeypatch):
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "")
    for path in ("/", "/timetracker-mobile.html"):
        for params in (None, {"checkIn": "tok"}):
            resp = _get(client, path, params=params)
            assert resp.status_code == 503
            assert resp.json()["error"] == "QR check-in portal is not configured"
            assert resp.headers["cache-control"] == "no-store"
            assert PAGE_MARKER not in resp.text


def test_self_origin_public_app_url_never_redirects(client, monkeypatch):
    # TestClient requests arrive as http://testserver; a PUBLIC_APP_URL on the
    # same hostname must not bounce the backend to itself. The comparison is
    # hostname-only: behind the proxy the request scheme can differ from the
    # public one, and a scheme-sensitive check would still loop.
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "https://testserver")
    for path in ("/", "/timetracker-mobile.html"):
        for params in (None, {"checkIn": "tok"}):
            resp = _get(client, path, params=params)
            assert resp.status_code == 503
            assert resp.json()["error"] == "QR check-in portal is not configured"
            assert resp.headers["cache-control"] == "no-store"
            assert PAGE_MARKER not in resp.text


def test_public_app_url_without_a_hostname_fails_closed(client, monkeypatch):
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "https:///portal")
    for path in ("/", "/timetracker-mobile.html"):
        resp = _get(client, path)
        assert resp.status_code == 503
        assert resp.json()["error"] == "QR check-in portal is not configured"
        assert resp.headers["cache-control"] == "no-store"
        assert PAGE_MARKER not in resp.text


def test_generated_qr_url_targets_portal_when_configured(
    client, auth, location_id, portal_env
):
    data = create_site_qr(client, auth, location_id)
    assert data["checkInUrl"] == f"{PORTAL}/portal?checkIn={data['token']}"


def test_generated_qr_fails_closed_when_unset(client, auth, location_id, monkeypatch):
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "")
    response = client.post(
        f"/api/admin/locations/{location_id}/check-in-qr",
        headers=auth,
        json={"rotate": False},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "QR check-in portal is not configured"
    assert response.headers["cache-control"] == "no-store"


def test_generated_qr_fails_closed_for_self_origin_without_rotating_token(
    client, auth, location_id, monkeypatch
):
    before = time_tracker_api.db.query_one(
        "SELECT check_in_token_nonce FROM locations WHERE id = %s",
        (location_id,),
    )
    monkeypatch.setattr(time_tracker_api, "PUBLIC_APP_URL", "https://testserver")
    response = client.post(
        f"/api/admin/locations/{location_id}/check-in-qr",
        headers=auth,
        json={"rotate": True},
    )
    after = time_tracker_api.db.query_one(
        "SELECT check_in_token_nonce FROM locations WHERE id = %s",
        (location_id,),
    )
    assert response.status_code == 503
    assert response.json()["error"] == "QR check-in portal is not configured"
    assert response.headers["cache-control"] == "no-store"
    assert after == before
