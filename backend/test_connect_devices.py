"""Connect device enrollment lifecycle: challenge, enroll, list, revoke.

Exercises the operator-authenticated device registry against the running app
and the real Ed25519 proof-of-possession path (no crypto is stubbed).
"""
from __future__ import annotations

import base64

import bcrypt
import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import TEST_DB_URL


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, _b64u(public_raw)


def _sign(private_key: Ed25519PrivateKey, challenge: str) -> str:
    return _b64u(private_key.sign(challenge.encode("ascii")))


_B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _noncanonical_spelling(public_key: str) -> str:
    """Return a different 43-char base64url spelling that decodes to the same
    32 bytes. The canonical final character has its low two bits zero (they are
    padding for a 32-byte value); flipping one produces a distinct string that
    still decodes identically."""
    last_index = _B64U_ALPHABET.index(public_key[-1])
    assert last_index % 4 == 0, "canonical Ed25519 key spelling expected"
    return public_key[:-1] + _B64U_ALPHABET[last_index + 1]


def _get_challenge(client, headers) -> str:
    resp = client.post(
        "/api/admin/connect/devices/enrollment-challenge", headers=headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["challenge"]
    assert body["expiresAt"]
    return body["challenge"]


def _enroll(client, headers, *, label="Front desk PC", private_key=None):
    if private_key is None:
        private_key, public_key = _new_keypair()
    else:
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_key = _b64u(public_raw)
    challenge = _get_challenge(client, headers)
    resp = client.post(
        "/api/admin/connect/devices",
        headers=headers,
        json={
            "label": label,
            "publicKey": public_key,
            "challenge": challenge,
            "signature": _sign(private_key, challenge),
        },
    )
    return private_key, public_key, resp


def test_enroll_list_and_revoke(client, auth):
    private_key, _public_key, resp = _enroll(client, auth, label="Reception")
    assert resp.status_code == 201, resp.text
    device = resp.json()
    assert device["status"] == "active"
    assert device["label"] == "Reception"
    assert device["revokedAt"] is None
    device_id = device["deviceId"]

    listed = client.get("/api/admin/connect/devices", headers=auth)
    assert listed.status_code == 200, listed.text
    ids = {d["deviceId"] for d in listed.json()["devices"]}
    assert device_id in ids

    revoked = client.post(
        f"/api/admin/connect/devices/{device_id}/revoke", headers=auth
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revokedAt"] is not None

    # Revoking again is idempotent.
    again = client.post(
        f"/api/admin/connect/devices/{device_id}/revoke", headers=auth
    )
    assert again.status_code == 200, again.text
    assert again.json()["status"] == "revoked"


def test_reenroll_same_active_key_is_idempotent(client, auth):
    private_key, _public_key, resp = _enroll(client, auth, label="Kiosk")
    assert resp.status_code == 201, resp.text
    first_id = resp.json()["deviceId"]

    _pk, _pub, resp2 = _enroll(client, auth, label="Kiosk again", private_key=private_key)
    assert resp2.status_code == 200, resp2.text
    assert resp2.json()["deviceId"] == first_id


def test_wrong_signature_is_rejected(client, auth):
    # A signature from a different key never verifies for the submitted key.
    good_private, good_public = _new_keypair()
    other_private, _other_public = _new_keypair()
    challenge = _get_challenge(client, auth)
    resp = client.post(
        "/api/admin/connect/devices",
        headers=auth,
        json={
            "label": "Impostor",
            "publicKey": good_public,
            "challenge": challenge,
            "signature": _sign(other_private, challenge),
        },
    )
    assert resp.status_code == 400, resp.text


def test_tampered_challenge_is_rejected(client, auth):
    private_key, public_key = _new_keypair()
    challenge = _get_challenge(client, auth)
    # Flip the last character of the signed payload; the HMAC no longer matches.
    tampered = challenge[:-1] + ("A" if challenge[-1] != "A" else "B")
    resp = client.post(
        "/api/admin/connect/devices",
        headers=auth,
        json={
            "label": "Tampered",
            "publicKey": public_key,
            "challenge": tampered,
            "signature": _sign(private_key, tampered),
        },
    )
    assert resp.status_code == 400, resp.text


def test_revoked_key_cannot_reenroll(client, auth):
    private_key, _public_key, resp = _enroll(client, auth, label="Retire me")
    assert resp.status_code == 201, resp.text
    device_id = resp.json()["deviceId"]
    revoked = client.post(
        f"/api/admin/connect/devices/{device_id}/revoke", headers=auth
    )
    assert revoked.status_code == 200, revoked.text

    _pk, _pub, resp2 = _enroll(client, auth, private_key=private_key)
    assert resp2.status_code == 409, resp2.text


def test_employee_cannot_enroll(client, emp_auth):
    resp = client.post(
        "/api/admin/connect/devices/enrollment-challenge", headers=emp_auth
    )
    assert resp.status_code == 403, resp.text


def _second_admin_token(client) -> str:
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            pw = bcrypt.hashpw(b"second1", bcrypt.gensalt(10)).decode()
            cur.execute(
                """
                INSERT INTO employees (name, password_hash, role, hourly_rate)
                VALUES ('Second Admin', %s, 'admin', 17.00)
                ON CONFLICT (name) DO NOTHING
                """,
                (pw,),
            )
        conn.commit()
    finally:
        conn.close()
    resp = client.post(
        "/api/auth/login", json={"name": "Second Admin", "password": "second1"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def test_key_owned_by_another_operator_conflicts(client, auth):
    second_auth = {"Authorization": f"Bearer {_second_admin_token(client)}"}
    private_key, _public_key, resp = _enroll(
        client, second_auth, label="Owned by second admin"
    )
    assert resp.status_code == 201, resp.text

    # The first operator cannot claim the same device key.
    _pk, _pub, resp2 = _enroll(client, auth, private_key=private_key)
    assert resp2.status_code == 409, resp2.text


def test_noncanonical_key_spelling_resolves_to_same_device(client, auth):
    # A different base64url spelling of the same key must not create a second
    # device (which would slip past the revoked / cross-operator guards).
    private_key, public_key, resp = _enroll(client, auth, label="Canonical")
    assert resp.status_code == 201, resp.text
    first_id = resp.json()["deviceId"]

    variant = _noncanonical_spelling(public_key)
    assert variant != public_key
    assert base64.urlsafe_b64decode(variant + "=") == base64.urlsafe_b64decode(
        public_key + "="
    )

    challenge = _get_challenge(client, auth)
    resp2 = client.post(
        "/api/admin/connect/devices",
        headers=auth,
        json={
            "label": "Non-canonical spelling",
            "publicKey": variant,
            "challenge": challenge,
            "signature": _sign(private_key, challenge),
        },
    )
    assert resp2.status_code == 200, resp2.text
    assert resp2.json()["deviceId"] == first_id
