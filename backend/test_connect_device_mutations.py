"""Device-authenticated mutations: the single-use operation challenge and the
per-operation confirmation gate, proven end to end on the tracker-local
lead-working claim (no Atlas money path).

Exercises the real crypto and the real single-use token consumption against the
running app; only the Atlas HTTP boundary is stubbed by the shared fixture.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import TEST_DB_URL

_CAP = "funnel.lead.mark_working"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, _b64u(public_raw)


def _enroll_device(client, headers, *, label="Automation PC"):
    private_key, public_key = _new_keypair()
    challenge = client.post(
        "/api/admin/connect/devices/enrollment-challenge", headers=headers
    ).json()["challenge"]
    resp = client.post(
        "/api/admin/connect/devices",
        headers=headers,
        json={
            "label": label,
            "publicKey": public_key,
            "challenge": challenge,
            "signature": _b64u(private_key.sign(challenge.encode("ascii"))),
        },
    )
    assert resp.status_code == 201, resp.text
    return private_key, resp.json()["deviceId"]


def _proof_headers(device_id, private_key, *, method, path, query="", body=b""):
    timestamp = int(time.time())
    signing_string = "\n".join(
        [
            "connect-device-access-v1",
            str(device_id),
            method.upper(),
            path,
            query,
            hashlib.sha256(body).hexdigest(),
            str(timestamp),
        ]
    ).encode("utf-8")
    headers = {
        "X-Connect-Device": str(device_id),
        "X-Connect-Timestamp": str(timestamp),
        "X-Connect-Signature": _b64u(private_key.sign(signing_string)),
    }
    return headers


def _device_post(client, device_id, private_key, path, body_dict=None):
    if body_dict is None:
        body = b""
        headers = _proof_headers(device_id, private_key, method="POST", path=path)
        return client.request("POST", path, headers=headers, content=body)
    body = json.dumps(body_dict).encode("utf-8")
    headers = _proof_headers(device_id, private_key, method="POST", path=path, body=body)
    headers["content-type"] = "application/json"
    return client.request("POST", path, headers=headers, content=body)


def _issue_challenge(client, device_id, private_key) -> str:
    resp = _device_post(
        client, device_id, private_key, "/api/connect/device/operations/challenge"
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["challengeId"]


def _issue_confirmation(
    client, admin_headers, device_id, contact_id, *, capability=_CAP, state_token=None
):
    if state_token is None:
        state_token = _state_token_v0(contact_id)
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={
            "capability": capability,
            "contactId": contact_id,
            "expectedStateToken": state_token,
        },
    )


def _state_token_v0(contact_id: str) -> str:
    return hashlib.sha256(
        f"eom-lead-working-state:v1:{contact_id}:0".encode("utf-8")
    ).hexdigest()


def _op_fingerprint(contact_id: str, state_token=None) -> str:
    if state_token is None:
        state_token = _state_token_v0(contact_id)
    return hashlib.sha256(
        json.dumps(
            {"capability": _CAP, "contactId": contact_id, "expectedStateToken": state_token},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _mark_working(client, device_id, private_key, contact_id, challenge_id, confirmation_id,
                  *, state_token=None):
    if state_token is None:
        state_token = _state_token_v0(contact_id)
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/leads/{contact_id}/working",
        {
            "challengeId": challenge_id,
            "confirmationId": confirmation_id,
            "expectedStateToken": state_token,
        },
    )


def _set_approver(monkeypatch, client, auth):
    """Make the enrolling admin (Juan) the configured funnel approver."""
    import time_tracker_api as api

    juan_id = next(
        e["id"]
        for e in client.get("/api/admin/employees", headers=auth).json()["employees"]
        if e["name"] == "Juan Canfield"
    )
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", juan_id)
    return juan_id


def _fresh_contact() -> str:
    return str(uuid.uuid4())


def test_mark_working_full_flow(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()

    conf = _issue_confirmation(client, auth, device_id, contact_id)
    assert conf.status_code == 201, conf.text
    confirmation_id = conf.json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["workingLead"]["contactId"] == contact_id
    assert body["workingLead"]["stateToken"]


def test_spent_challenge_cannot_drive_new_transition(client, auth, monkeypatch):
    # The anti-replay guarantee that matters: a captured, already-spent token set
    # cannot be reused to drive a NEW state transition on another target.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    first_contact = _fresh_contact()
    second_contact = _fresh_contact()

    confirmation_a = _issue_confirmation(client, auth, device_id, first_contact).json()[
        "confirmationId"
    ]
    challenge = _issue_challenge(client, device_id, private_key)
    first = _mark_working(
        client, device_id, private_key, first_contact, challenge, confirmation_a
    )
    assert first.status_code == 200, first.text

    # Reuse the now-spent challenge for a fresh transition on a different lead
    # (with its own fresh confirmation): the single-use challenge is spent.
    confirmation_b = _issue_confirmation(client, auth, device_id, second_contact).json()[
        "confirmationId"
    ]
    replay = _mark_working(
        client, device_id, private_key, second_contact, challenge, confirmation_b
    )
    assert replay.status_code == 409, replay.text


def test_exact_replay_of_completed_mark_is_idempotent(client, auth, monkeypatch):
    # Replaying the exact same mutation once the lead is already working is a safe
    # no-op: no new transition occurs, so it returns 200 without a fresh token.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    confirmation_id = _issue_confirmation(client, auth, device_id, contact_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)

    first = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert first.status_code == 200, first.text
    replay = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert replay.status_code == 200, replay.text
    # No new transition: the state token is unchanged.
    assert replay.json()["workingLead"]["stateToken"] == (
        first.json()["workingLead"]["stateToken"]
    )


def test_missing_confirmation_is_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    challenge_id = _issue_challenge(client, device_id, private_key)

    # A never-issued confirmation id: the confirmation gate rejects it.
    resp = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, str(uuid.uuid4())
    )
    assert resp.status_code == 403, resp.text


def test_confirmation_for_other_operation_is_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    target = _fresh_contact()
    other = _fresh_contact()
    # Confirmation issued for `other`, but the mutation targets `target`.
    confirmation_id = _issue_confirmation(client, auth, device_id, other).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _mark_working(
        client, device_id, private_key, target, challenge_id, confirmation_id
    )
    assert resp.status_code == 403, resp.text


def test_missing_challenge_is_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    confirmation_id = _issue_confirmation(client, auth, device_id, contact_id).json()[
        "confirmationId"
    ]
    # A never-issued challenge id.
    resp = _mark_working(
        client, device_id, private_key, contact_id, str(uuid.uuid4()), confirmation_id
    )
    assert resp.status_code == 409, resp.text


def test_state_conflict_preserves_tokens(client, auth, monkeypatch):
    # A wrong expectedStateToken must fail BEFORE the tokens are consumed, so the
    # operator does not have to re-confirm after a benign refresh conflict.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    confirmation_id = _issue_confirmation(client, auth, device_id, contact_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)

    conflict = _mark_working(
        client,
        device_id,
        private_key,
        contact_id,
        challenge_id,
        confirmation_id,
        state_token=hashlib.sha256(b"wrong").hexdigest(),
    )
    assert conflict.status_code == 409, conflict.text

    # The tokens survived the conflict: a correct retry with the SAME tokens works.
    ok = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert ok.status_code == 200, ok.text


def test_expired_confirmation_is_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    challenge_id = _issue_challenge(client, device_id, private_key)

    # Plant a confirmation whose expiry is already in the past.
    confirmation_id = str(uuid.uuid4())
    fingerprint = _op_fingerprint(contact_id)
    juan_id = next(
        e["id"]
        for e in client.get("/api/admin/employees", headers=auth).json()["employees"]
        if e["name"] == "Juan Canfield"
    )
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO connect_device_operation_confirmations
                    (confirmation_id, device_id, confirmed_by_employee_id, capability,
                     operation_fingerprint, expires_at)
                VALUES (%s, %s, %s, %s, %s, NOW() - INTERVAL '1 minute')
                """,
                (confirmation_id, device_id, juan_id, _CAP, fingerprint),
            )
        conn.commit()
    finally:
        conn.close()

    resp = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert resp.status_code == 403, resp.text


def test_expired_outstanding_confirmation_can_be_reissued(client, auth, monkeypatch):
    # An unused confirmation that expires must not block future issuance: the
    # partial unique index keys on consumed_at IS NULL, so issuance retires the
    # stale row and mints a fresh, usable confirmation.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    fingerprint = _op_fingerprint(contact_id)
    juan_id = next(
        e["id"]
        for e in client.get("/api/admin/employees", headers=auth).json()["employees"]
        if e["name"] == "Juan Canfield"
    )
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO connect_device_operation_confirmations
                    (confirmation_id, device_id, confirmed_by_employee_id, capability,
                     operation_fingerprint, expires_at)
                VALUES (%s, %s, %s, %s, %s, NOW() - INTERVAL '1 minute')
                """,
                (str(uuid.uuid4()), device_id, juan_id, _CAP, fingerprint),
            )
        conn.commit()
    finally:
        conn.close()

    reissued = _issue_confirmation(client, auth, device_id, contact_id)
    assert reissued.status_code == 201, reissued.text  # fresh, not the dead row
    confirmation_id = reissued.json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)
    ok = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert ok.status_code == 200, ok.text


def test_non_approver_operator_is_rejected(client, auth, monkeypatch):
    # The device acts as its bound operator and must clear the same funnel-approver
    # gate the office path enforces; a non-approver operator is refused.
    import time_tracker_api as api

    private_key, device_id = _enroll_device(client, auth)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    contact_id = _fresh_contact()
    confirmation_id = _issue_confirmation(client, auth, device_id, contact_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _mark_working(
        client, device_id, private_key, contact_id, challenge_id, confirmation_id
    )
    assert resp.status_code == 403, resp.text


def test_duplicate_confirmation_issuance_is_idempotent(client, auth, monkeypatch):
    # A retry / double submit of one human approval must not mint a second
    # independently-consumable token: at most one outstanding confirmation exists
    # per device and operation.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()

    first = _issue_confirmation(client, auth, device_id, contact_id)
    assert first.status_code == 201, first.text
    first_id = first.json()["confirmationId"]

    dup = _issue_confirmation(client, auth, device_id, contact_id)
    assert dup.status_code == 200, dup.text
    assert dup.json()["confirmationId"] == first_id

    # After the single outstanding confirmation is consumed, a new operation needs
    # a fresh confirmation -- issuance mints a distinct one.
    challenge_id = _issue_challenge(client, device_id, private_key)
    assert (
        _mark_working(
            client, device_id, private_key, contact_id, challenge_id, first_id
        ).status_code
        == 200
    )
    reissued = _issue_confirmation(client, auth, device_id, contact_id)
    assert reissued.status_code == 201, reissued.text
    assert reissued.json()["confirmationId"] != first_id


def test_employee_cannot_confirm(client, emp_auth):
    contact_id = _fresh_contact()
    resp = client.post(
        f"/api/admin/connect/devices/{uuid.uuid4()}/operation-confirmations",
        headers=emp_auth,
        json={
            "capability": _CAP,
            "contactId": contact_id,
            "expectedStateToken": _state_token_v0(contact_id),
        },
    )
    assert resp.status_code == 403, resp.text
