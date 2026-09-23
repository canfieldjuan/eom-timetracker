"""Device-authenticated issued-onboarding-link read: a Local Connect device relays
the same current issued-token evidence the office review shows, authenticated purely
by its per-request Ed25519 proof, with no operator bearer in the request.

Faithful to the office relay (``admin_list_public_onboarding_issued_links``): same
Atlas route gate, same closed page reprojection, same 502 on a mismatched echo. The
generic proof mechanics (wrong signature, expiry, request-target binding) are covered
by ``test_connect_device_access.py``; this exercises the endpoint's relay behavior.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import time_tracker_api as api

_PROOF_CONTEXT = "connect-device-access-v1"
_PATH = "/api/connect/device/funnel/public-onboarding/issued-links"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, _b64u(public_raw)


def _enroll_device(client, headers, *, label="Front desk PC"):
    private_key, public_key = _new_keypair()
    challenge_resp = client.post(
        "/api/admin/connect/devices/enrollment-challenge", headers=headers
    )
    assert challenge_resp.status_code == 200, challenge_resp.text
    challenge = challenge_resp.json()["challenge"]
    signature = _b64u(private_key.sign(challenge.encode("ascii")))
    resp = client.post(
        "/api/admin/connect/devices",
        headers=headers,
        json={
            "label": label,
            "publicKey": public_key,
            "challenge": challenge,
            "signature": signature,
        },
    )
    assert resp.status_code == 201, resp.text
    return private_key, resp.json()["deviceId"]


def _proof_headers(device_id, private_key, *, method="GET", path=_PATH, query="", body=b""):
    timestamp = int(time.time())
    signing_string = "\n".join(
        [
            _PROOF_CONTEXT,
            str(device_id),
            method.upper(),
            path,
            query,
            hashlib.sha256(body).hexdigest(),
            str(timestamp),
        ]
    ).encode("utf-8")
    return {
        "X-Connect-Device": str(device_id),
        "X-Connect-Timestamp": str(timestamp),
        "X-Connect-Signature": _b64u(private_key.sign(signing_string)),
    }


def _public_onboarding_capability_routes() -> list[dict[str, str]]:
    return [
        {"method": "GET", "path": "/eom-funnel/public-onboarding/issued-links"},
        {"method": "POST", "path": "/eom-funnel/onboarding-drafts/{draft_id}/revoke-link"},
        {"method": "POST", "path": "/eom-funnel/public-onboarding/recover"},
    ]


def _issued_link(draft_id: str, *, contact_id: str | None = None) -> dict[str, object]:
    return {
        "draftId": draft_id,
        "contactId": contact_id or str(uuid.uuid4()),
        "fullName": "Issued Customer",
        "recipientEmail": "issued@example.test",
        "status": "issued",
        "issuedAt": "2026-08-19T12:00:00Z",
        # Atlas-private; the tracker must strip it even if upstream leaks it.
        "tokenId": str(uuid.uuid4()),
    }


def _issued_link_page(links, *, limit, cursor=None, has_more=False) -> dict[str, object]:
    return {
        "links": links,
        "limit": limit,
        "cursor": cursor,
        "hasMore": has_more,
        "nextCursor": "cursor-0123456789" if has_more else None,
    }


def _leads_manifest():
    return {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
        "capabilities": [],
        "capabilityRoutes": _public_onboarding_capability_routes(),
    }


def test_device_issued_links_read_succeeds_and_reprojects_only_safe_fields(
    client, auth, monkeypatch
):
    private_key, device_id = _enroll_device(client, auth)
    draft_id = str(uuid.uuid4())
    link = _issued_link(draft_id)
    reads: list[dict[str, object]] = []

    def atlas_read(path, operator, *, params=None):
        reads.append({"path": path, "operator": operator, "params": params})
        if path == "/eom-funnel/leads":
            return _leads_manifest()
        assert path == api._ATLAS_PUBLIC_ONBOARDING_ISSUED_LINKS_PATH
        assert params == {"limit": 2}
        return _issued_link_page([link], limit=2)

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    resp = client.get(
        f"{_PATH}?limit=2", headers=_proof_headers(device_id, private_key, query="limit=2")
    )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "success": True,
        "links": [
            {
                "draftId": draft_id,
                "contactId": link["contactId"],
                "fullName": "Issued Customer",
                "recipientEmail": "issued@example.test",
                "status": "issued",
                "issuedAt": "2026-08-19T12:00:00Z",
            }
        ],
        "limit": 2,
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
    }
    # The Atlas-private token id never reaches the device.
    assert str(link["tokenId"]) not in resp.text
    # The bound operator (not the device) was vouched for on the upstream reads.
    assert reads[0]["path"] == "/eom-funnel/leads"
    assert reads[0]["operator"]["deviceId"] == device_id


def test_device_issued_links_read_relays_the_opaque_next_page_cursor(
    client, auth, monkeypatch
):
    private_key, device_id = _enroll_device(client, auth)
    cursor = "cursor-0123456789"

    def atlas_read(path, operator, *, params=None):
        if path == "/eom-funnel/leads":
            return _leads_manifest()
        assert params == {"limit": 1, "cursor": cursor}
        return _issued_link_page(
            [_issued_link(str(uuid.uuid4()))], limit=1, cursor=cursor, has_more=True
        )

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    query = f"limit=1&cursor={cursor}"
    resp = client.get(
        f"{_PATH}?{query}", headers=_proof_headers(device_id, private_key, query=query)
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["cursor"] == cursor
    assert resp.json()["hasMore"] is True
    assert resp.json()["nextCursor"] == "cursor-0123456789"


def test_device_issued_links_read_refuses_unadvertised_capability_before_upstream_read(
    client, auth, monkeypatch
):
    private_key, device_id = _enroll_device(client, auth)
    reads: list[str] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelRouteUnavailable(
            api._ATLAS_PUBLIC_ONBOARDING_ISSUED_LINK_LIST_ROUTE
        )

    def unexpected_read(path, *_args, **_kwargs):
        reads.append(path)
        raise AssertionError("issued links must not be read after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_route", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_read", unexpected_read)
    resp = client.get(_PATH, headers=_proof_headers(device_id, private_key))

    assert resp.status_code == 501, resp.text
    assert resp.json()["capability"] == "GET /eom-funnel/public-onboarding/issued-links"
    assert reads == []


def test_device_issued_links_read_rejects_malformed_atlas_projection(
    client, auth, monkeypatch
):
    private_key, device_id = _enroll_device(client, auth)

    def malformed_page(path, *_args, **_kwargs):
        if path == "/eom-funnel/leads":
            return _leads_manifest()
        return {"links": [{"status": "issued"}], "limit": 100}

    monkeypatch.setattr(api, "_atlas_funnel_read", malformed_page)
    resp = client.get(_PATH, headers=_proof_headers(device_id, private_key))

    assert resp.status_code == 502, resp.text
    assert "invalid issued-link response" in resp.json()["error"]


def test_device_issued_links_missing_proof_rejected(client):
    resp = client.get(_PATH)
    assert resp.status_code == 401, resp.text
