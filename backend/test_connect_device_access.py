"""Device-authenticated funnel access: the per-request Ed25519 proof of
possession that lets a Local Connect device read the funnel on its bound
operator's behalf, with no operator bearer token in the request.

Exercises ``require_connect_device`` and the device-facing read endpoint against
the running app and the real crypto path (nothing is stubbed but the Atlas HTTP
boundary, which the shared fixture already patches).
"""
from __future__ import annotations

import base64
import hashlib
import time

import bcrypt
import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import TEST_DB_URL

_PROOF_CONTEXT = "connect-device-access-v1"
_READ_PATH = "/api/connect/device/funnel/leads"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, _b64u(public_raw)


def _enroll_device(client, headers, *, label="Front desk PC"):
    """Enroll a device through the real operator-authenticated path and return
    its (private_key, device_id)."""
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


def _proof_headers(
    device_id,
    private_key,
    *,
    method="GET",
    path=_READ_PATH,
    query="",
    body=b"",
    timestamp=None,
):
    if timestamp is None:
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


class _FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


def test_device_read_succeeds_and_threads_bound_operator(client, auth, monkeypatch):
    import time_tracker_api as api

    private_key, device_id = _enroll_device(client, auth)

    # Capture the actor headers the tracker sets when it calls Atlas, and inject
    # one lead so the overlay path (state token) is exercised end to end.
    captured: dict = {}
    lead_contact_id = "11111111-1111-1111-1111-111111111111"

    def _capturing_get(url, *, headers=None, params=None, timeout=None):
        captured["headers"] = dict(headers or {})
        captured["url"] = str(url)
        return _FakeResponse(
            200,
            {
                "leads": [
                    {
                        "contactId": lead_contact_id,
                        "fullName": "Prospective Customer",
                        "email": "prospect@example.test",
                        "createdAt": "2026-09-19T12:00:00Z",
                    }
                ],
                "cursor": None,
                "hasMore": False,
                "nextCursor": None,
                "capabilities": ["lead.lost"],
            },
        )

    monkeypatch.setattr(api.requests, "get", _capturing_get)

    resp = client.get(_READ_PATH, headers=_proof_headers(device_id, private_key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["capabilities"] == ["lead.lost"]
    assert body["capabilitiesDeclared"] is True
    assert len(body["leads"]) == 1
    assert body["leads"][0]["contactId"] == lead_contact_id
    # Overlay applied: an unmarked lead still carries its state token.
    assert body["leads"][0]["stateToken"]
    assert body["workingLeads"] == []

    # The bound operator (the enrolling admin) was vouched for, not the device.
    admin_id = next(
        e["id"]
        for e in client.get("/api/admin/employees", headers=auth).json()["employees"]
        if e["name"] == "Juan Canfield"
    )
    assert captured["headers"]["X-EOM-Actor"] == "Juan Canfield"
    assert captured["headers"]["X-EOM-Actor-ID"] == str(admin_id)
    assert "Authorization" in captured["headers"]  # tracker's own service token


def test_missing_proof_headers_rejected(client):
    resp = client.get(_READ_PATH)
    assert resp.status_code == 401, resp.text


def test_wrong_signature_rejected(client, auth):
    _private_key, device_id = _enroll_device(client, auth)
    other_key, _pub = _new_keypair()
    # A valid-shaped proof signed by a key the device never enrolled.
    headers = _proof_headers(device_id, other_key)
    resp = client.get(_READ_PATH, headers=headers)
    assert resp.status_code == 401, resp.text


def test_expired_timestamp_rejected(client, auth):
    private_key, device_id = _enroll_device(client, auth)
    stale = int(time.time()) - 3600
    resp = client.get(
        _READ_PATH, headers=_proof_headers(device_id, private_key, timestamp=stale)
    )
    assert resp.status_code == 401, resp.text


def test_proof_bound_to_request_target(client, auth):
    # A proof minted for one request target does not authorize a different one:
    # signing an empty query but sending ?limit=5 must fail closed.
    private_key, device_id = _enroll_device(client, auth)
    headers = _proof_headers(device_id, private_key, query="")
    resp = client.get(f"{_READ_PATH}?limit=5", headers=headers)
    assert resp.status_code == 401, resp.text

    # Signing the exact query the server will see succeeds.
    ok_headers = _proof_headers(device_id, private_key, query="limit=5")
    resp_ok = client.get(f"{_READ_PATH}?limit=5", headers=ok_headers)
    assert resp_ok.status_code == 200, resp_ok.text


def test_revoked_device_rejected(client, auth):
    private_key, device_id = _enroll_device(client, auth, label="Retire me")
    revoked = client.post(
        f"/api/admin/connect/devices/{device_id}/revoke", headers=auth
    )
    assert revoked.status_code == 200, revoked.text
    resp = client.get(_READ_PATH, headers=_proof_headers(device_id, private_key))
    assert resp.status_code == 401, resp.text


def _insert_employee(name, role, *, active=True) -> int:
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            pw = bcrypt.hashpw(b"password1", bcrypt.gensalt(10)).decode()
            cur.execute(
                """
                INSERT INTO employees (name, password_hash, role, hourly_rate, active)
                VALUES (%s, %s, %s, 17.00, %s)
                ON CONFLICT (name) DO UPDATE SET role = EXCLUDED.role,
                    active = EXCLUDED.active
                RETURNING id
                """,
                (name, pw, role, active),
            )
            employee_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    return employee_id


def _insert_device(device_id, employee_id, public_key_base64url, *, status="active"):
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO connect_devices
                    (device_id, employee_id, label, public_key_base64url, status)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (device_id, employee_id, "Direct insert", public_key_base64url, status),
            )
        conn.commit()
    finally:
        conn.close()


def test_device_for_non_admin_operator_rejected(client):
    # The per-PC device does not license the caller; a device bound to a
    # non-admin operator cannot reach an admin-scoped funnel read.
    import uuid

    emp_id = _insert_employee("Access Non-Admin", "employee")
    private_key, public_key = _new_keypair()
    device_id = str(uuid.uuid4())
    _insert_device(device_id, emp_id, public_key)
    resp = client.get(_READ_PATH, headers=_proof_headers(device_id, private_key))
    assert resp.status_code == 403, resp.text


def test_device_for_inactive_operator_rejected(client):
    # Deactivating the bound operator immediately stops the device.
    import uuid

    emp_id = _insert_employee("Access Inactive Admin", "admin", active=False)
    private_key, public_key = _new_keypair()
    device_id = str(uuid.uuid4())
    _insert_device(device_id, emp_id, public_key)
    resp = client.get(_READ_PATH, headers=_proof_headers(device_id, private_key))
    assert resp.status_code == 403, resp.text
