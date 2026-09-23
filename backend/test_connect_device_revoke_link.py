"""Device-authenticated, confirmation-gated revocation of an issued public onboarding
link: the second draft-keyed Atlas mutation after approve-send.

Faithful to the office revoke route (``admin_revoke_public_onboarding_link``): same
approver gate, same exact-route gate, same stable draft-scoped idempotency key, same
closed receipt projection. These tests exercise the real crypto and the real single-use
token consumption; the Atlas request boundary is stubbed per test, and the route gate is
satisfied per test because the shared healthy-Atlas fixture does not advertise the
revoke route.
"""
from __future__ import annotations

import uuid

import time_tracker_api as api
from test_connect_device_mutations import (
    _device_post,
    _enroll_device,
    _issue_challenge,
    _set_approver,
)

_CAP = "funnel.onboarding_draft.revoke_link"
_APPROVE_SEND_CAP = "funnel.onboarding_draft.approve_send"


def _fresh_draft() -> str:
    return str(uuid.uuid4())


def _issue_confirmation(client, admin_headers, device_id, draft_id, *, capability=_CAP):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={"capability": capability, "draftId": draft_id},
    )


def _revoke(client, device_id, private_key, draft_id, challenge_id, confirmation_id):
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/onboarding-drafts/{draft_id}/revoke-link",
        {"challengeId": challenge_id, "confirmationId": confirmation_id},
    )


def _route_available(monkeypatch):
    monkeypatch.setattr(api, "_require_atlas_funnel_route", lambda *_a, **_k: None)


def _stub_atlas_revoke(monkeypatch, *, idempotent=False, calls=None):
    """Return a valid Atlas revocation receipt, recording each relay call."""

    def atlas_request(path, admin, *, payload, idempotency_key):
        if calls is not None:
            calls.append(
                {
                    "path": path,
                    "admin": admin,
                    "payload": payload,
                    "idempotencyKey": idempotency_key,
                }
            )
        return {
            "success": True,
            "token_id": str(uuid.uuid4()),
            "contact_id": str(uuid.uuid4()),
            "status": "revoked",
            "idempotent": idempotent,
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas(monkeypatch, calls):
    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def test_revoke_link_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    calls: list[dict] = []
    _route_available(monkeypatch)
    _stub_atlas_revoke(monkeypatch, calls=calls)

    conf = _issue_confirmation(client, auth, device_id, draft_id)
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _revoke(
        client, device_id, private_key, draft_id, challenge_id, conf.json()["confirmationId"]
    )
    assert resp.status_code == 201, resp.text
    # The closed projection: Atlas's token and contact ids never reach the device.
    assert resp.json() == {
        "success": True,
        "draftId": draft_id,
        "status": "revoked",
        "idempotent": False,
    }
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == f"/eom-funnel/onboarding-drafts/{draft_id}/revoke-link"
    assert call["payload"] == {}
    assert call["idempotencyKey"] == f"eom-public-onboarding-link-revoke:{draft_id}"
    assert call["admin"]["id"] == juan_id
    assert call["admin"]["deviceId"] == device_id


def test_revoke_link_idempotent_replay_returns_200(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    _route_available(monkeypatch)
    _stub_atlas_revoke(monkeypatch, idempotent=True)

    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _revoke(client, device_id, private_key, draft_id, challenge_id, confirmation_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["idempotent"] is True


def test_approve_send_confirmation_cannot_revoke_the_same_draft(client, auth, monkeypatch):
    # The fingerprint binds the capability: an operator's approval to SEND a draft
    # must never authorize REVOKING that draft's link.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    calls: list = []
    _route_available(monkeypatch)
    _forbid_atlas(monkeypatch, calls)

    send_confirmation = _issue_confirmation(
        client, auth, device_id, draft_id, capability=_APPROVE_SEND_CAP
    )
    assert send_confirmation.status_code == 201, send_confirmation.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _revoke(
        client,
        device_id,
        private_key,
        draft_id,
        challenge_id,
        send_confirmation.json()["confirmationId"],
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_route_unavailable_precedes_token_consumption(client, auth, monkeypatch):
    # An Atlas that does not advertise the revoke route is refused (501) BEFORE the
    # tokens are consumed, so the same challenge and confirmation succeed later.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)

    def unavailable(route, _admin):
        raise api.AtlasFunnelRouteUnavailable(route)

    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(api, "_require_atlas_funnel_route", unavailable)
    refused = _revoke(client, device_id, private_key, draft_id, challenge_id, confirmation_id)
    assert refused.status_code == 501, refused.text
    assert calls == []

    _route_available(monkeypatch)
    _stub_atlas_revoke(monkeypatch)
    ok = _revoke(client, device_id, private_key, draft_id, challenge_id, confirmation_id)
    assert ok.status_code == 201, ok.text


def test_non_approver_operator_rejected(client, auth, monkeypatch):
    private_key, device_id = _enroll_device(client, auth)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    calls: list = []
    _route_available(monkeypatch)
    _forbid_atlas(monkeypatch, calls)

    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _revoke(
        client, device_id, private_key, _fresh_draft(), challenge_id, str(uuid.uuid4())
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_invalid_atlas_receipt_is_a_502(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    _route_available(monkeypatch)
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_a, **_k: {"success": True, "status": "revoked"},
    )

    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _revoke(client, device_id, private_key, draft_id, challenge_id, confirmation_id)
    assert resp.status_code == 502, resp.text
    assert "invalid revocation receipt" in resp.json()["error"]
