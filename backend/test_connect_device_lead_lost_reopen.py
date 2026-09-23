"""Device-authenticated, confirmation-gated lead disposition: mark a lead lost and
reopen a lost lead.

Faithful to the office routes (``admin_mark_funnel_lead_lost`` and
``admin_reopen_funnel_lead``): same approver gate, same ``lead.lost`` /
``lead.reopen`` capability gate, same Atlas relay path, payload, and client
idempotency key, same local marker write, same ``{success, lead}`` body. These tests
exercise the real crypto and the real single-use token consumption; the Atlas request
boundary is stubbed per test. The shared healthy-Atlas fixture advertises both
capabilities, so the capability gate passes unless a test overrides it.
"""
from __future__ import annotations

import uuid

import db
import time_tracker_api as api
from test_connect_device_mutations import (
    _device_post,
    _enroll_device,
    _issue_challenge,
    _set_approver,
)

_LOST_CAP = "funnel.lead.lost"
_REOPEN_CAP = "funnel.lead.reopen"


def _issue_lost_confirmation(
    client, admin_headers, device_id, contact_id, idempotency_key, reason_code
):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={
            "capability": _LOST_CAP,
            "contactId": contact_id,
            "idempotencyKey": idempotency_key,
            "reasonCode": reason_code,
        },
    )


def _issue_reopen_confirmation(client, admin_headers, device_id, contact_id, idempotency_key):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={
            "capability": _REOPEN_CAP,
            "contactId": contact_id,
            "idempotencyKey": idempotency_key,
        },
    )


def _lost(client, device_id, private_key, contact_id, body):
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/leads/{contact_id}/lost",
        body,
    )


def _reopen(client, device_id, private_key, contact_id, body):
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/leads/{contact_id}/reopen",
        body,
    )


def _stub_atlas(monkeypatch, calls, *, lead_stage="lost"):
    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(
            {
                "path": path,
                "admin": admin,
                "payload": payload,
                "idempotencyKey": idempotency_key,
            }
        )
        return {"contact_id": path.split("/")[3], "lead_stage": lead_stage}

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas(monkeypatch, calls):
    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def _marker(contact_id):
    return db.query_one(
        "SELECT state, lost_by_employee_id, reopened_by_employee_id "
        "FROM eom_lead_working WHERE atlas_contact_id = %s",
        (contact_id,),
    )


def test_lost_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict] = []
    _stub_atlas(monkeypatch, calls)

    conf = _issue_lost_confirmation(client, auth, device_id, contact_id, key, "price")
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _lost(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "reasonCode": "price",
            "note": "went with a cheaper quote",
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "success": True,
        "lead": {"contact_id": contact_id, "lead_stage": "lost"},
    }
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == f"/eom-funnel/leads/{contact_id}/lost"
    assert call["payload"] == {"reason_code": "price", "note": "went with a cheaper quote"}
    assert call["idempotencyKey"] == key
    assert call["admin"]["id"] == juan_id
    assert call["admin"]["deviceId"] == device_id
    marker = _marker(contact_id)
    assert marker["state"] == "lost"
    assert int(marker["lost_by_employee_id"]) == juan_id


def test_reopen_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict] = []
    _stub_atlas(monkeypatch, calls, lead_stage="new")

    conf = _issue_reopen_confirmation(client, auth, device_id, contact_id, key)
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _reopen(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["success"] is True
    assert resp.json()["lead"]["lead_stage"] == "new"
    assert len(calls) == 1
    assert calls[0]["path"] == f"/eom-funnel/leads/{contact_id}/reopen"
    assert calls[0]["payload"] == {}
    assert calls[0]["idempotencyKey"] == key
    marker = _marker(contact_id)
    assert marker["state"] == "reopened"
    assert int(marker["reopened_by_employee_id"]) == juan_id


def test_confirmation_for_one_reason_cannot_dispatch_another(client, auth, monkeypatch):
    # The reason code is bound: approving "spam" never authorizes "price".
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list = []
    _forbid_atlas(monkeypatch, calls)

    conf = _issue_lost_confirmation(client, auth, device_id, contact_id, key, "spam")
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _lost(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "reasonCode": "price",
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 403, resp.text
    assert calls == []
    assert _marker(contact_id) is None


def test_lost_confirmation_cannot_authorize_reopen(client, auth, monkeypatch):
    # The fingerprint binds the capability, so the inverse operation is refused.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list = []
    _forbid_atlas(monkeypatch, calls)

    conf = _issue_lost_confirmation(client, auth, device_id, contact_id, key, "other")
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _reopen(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_capability_unavailable_precedes_token_consumption(client, auth, monkeypatch):
    # An Atlas that does not advertise lead.lost is refused (501) BEFORE the tokens
    # are consumed, so the same challenge and confirmation succeed later.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    conf = _issue_lost_confirmation(client, auth, device_id, contact_id, key, "no_response")
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    body = {
        "challengeId": challenge_id,
        "confirmationId": conf.json()["confirmationId"],
        "reasonCode": "no_response",
        "idempotencyKey": key,
    }

    real_gate = api._require_atlas_funnel_capability

    def unavailable(capability, _admin):
        raise api.AtlasFunnelCapabilityUnavailable(capability)

    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    refused = _lost(client, device_id, private_key, contact_id, body)
    assert refused.status_code == 501, refused.text
    assert calls == []

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", real_gate)
    _stub_atlas(monkeypatch, [])
    ok = _lost(client, device_id, private_key, contact_id, body)
    assert ok.status_code == 200, ok.text


def test_atlas_conflict_is_relayed_without_local_marker(client, auth, monkeypatch):
    # Reopening a lead that is not lost is an Atlas 409; it surfaces unchanged and no
    # local reopened marker is written.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())

    def conflict(*_args, **_kwargs):
        raise api.AtlasFunnelRequestError(409, "lead is not lost")

    monkeypatch.setattr(api, "_atlas_funnel_request", conflict)
    conf = _issue_reopen_confirmation(client, auth, device_id, contact_id, key)
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _reopen(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 409, resp.text
    assert _marker(contact_id) is None


def test_non_approver_operator_rejected(client, auth, monkeypatch):
    private_key, device_id = _enroll_device(client, auth)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    calls: list = []
    _forbid_atlas(monkeypatch, calls)

    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _lost(
        client,
        device_id,
        private_key,
        str(uuid.uuid4()),
        {
            "challengeId": challenge_id,
            "confirmationId": str(uuid.uuid4()),
            "reasonCode": "spam",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_confirmation_issuance_validates_reason_code(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    _private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())

    bad_reason = _issue_lost_confirmation(
        client, auth, device_id, contact_id, key, "not_a_reason"
    )
    assert bad_reason.status_code == 422, bad_reason.text

    missing_reason = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={"capability": _LOST_CAP, "contactId": contact_id, "idempotencyKey": key},
    )
    assert missing_reason.status_code == 422, missing_reason.text

    reopen_with_reason = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={
            "capability": _REOPEN_CAP,
            "contactId": contact_id,
            "idempotencyKey": key,
            "reasonCode": "spam",
        },
    )
    assert reopen_with_reason.status_code == 422, reopen_with_reason.text


def test_revoke_during_lead_lock_wait_stops_dispatch(client, auth, monkeypatch):
    # Authorization commits before the lead transition lock, and that wait can be
    # long. A device revoked while the request waits must not dispatch to Atlas
    # under its stale authorization.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    conf = _issue_lost_confirmation(client, auth, device_id, contact_id, key, "spam")
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)

    real_lock = api._lock_funnel_lead_transition

    def lock_then_revoke(cur, contact):
        # Simulates a revoke that commits (in its own transaction) while this
        # request is waiting on the lead lock.
        db.execute(
            "UPDATE connect_devices SET status = 'revoked' WHERE device_id = %s",
            (device_id,),
        )
        real_lock(cur, contact)

    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(api, "_lock_funnel_lead_transition", lock_then_revoke)
    resp = _lost(
        client,
        device_id,
        private_key,
        contact_id,
        {
            "challengeId": challenge_id,
            "confirmationId": conf.json()["confirmationId"],
            "reasonCode": "spam",
            "idempotencyKey": key,
        },
    )
    assert resp.status_code == 403, resp.text
    assert calls == []
    assert _marker(contact_id) is None
