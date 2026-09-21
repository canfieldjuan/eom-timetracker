"""Device-authenticated Atlas money paths: the confirmation-gated relay proven
end to end on approve-and-send of an onboarding draft.

Unlike the tracker-local mark-working claim, this capability relays to Atlas with
the tracker's service token (the device holds no Atlas credential) and sends a
real customer email, so it is confirmation-required. These tests exercise the
real crypto and the real single-use token consumption against the running app;
the Atlas request boundary is stubbed per test (as the office approve-send tests
do), while the capability read is served by the shared healthy-Atlas fixture.
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

_CAP = "funnel.onboarding_draft.approve_send"
_SENT_AT = "2026-08-16T12:15:00Z"


def _fresh_draft() -> str:
    return str(uuid.uuid4())


def _issue_confirmation(client, admin_headers, device_id, draft_id, *, capability=_CAP):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={"capability": capability, "draftId": draft_id},
    )


def _approve_send(client, device_id, private_key, draft_id, challenge_id, confirmation_id):
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/onboarding-drafts/{draft_id}/approve-send",
        {"challengeId": challenge_id, "confirmationId": confirmation_id},
    )


def _stub_atlas_send(monkeypatch, draft_id, *, idempotent=False, calls=None):
    """Stub the tracker-to-Atlas relay to return a valid sent receipt for one
    draft. Records each call so a test can assert the relay was (or was not)
    reached and what operator identity + idempotency key it forwarded."""

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
            "draft_id": draft_id,
            "status": "sent",
            "sent_at": _SENT_AT,
            "idempotent": idempotent,
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas_send(monkeypatch, calls):
    """Fail loudly if the relay is reached; for tests proving a gate stops the
    request before any Atlas call."""

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def test_approve_send_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    calls: list[dict] = []
    _stub_atlas_send(monkeypatch, draft_id, calls=calls)

    conf = _issue_confirmation(client, auth, device_id, draft_id)
    assert conf.status_code == 201, conf.text
    confirmation_id = conf.json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert resp.status_code == 201, resp.text
    assert resp.json() == {
        "success": True,
        "draftId": draft_id,
        "status": "sent",
        "sentAt": "2026-08-16T12:15:00+00:00",
        "idempotent": False,
    }
    # The relay ran once, vouching for the bound operator and forwarding the
    # stable draft-id idempotency key with no mutable payload.
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == f"/eom-funnel/onboarding-drafts/{draft_id}/approve-send"
    assert call["payload"] == {}
    assert call["idempotencyKey"] == f"eom-onboarding-draft:{draft_id}"
    assert call["admin"]["id"] == juan_id
    assert call["admin"]["role"] == "admin"
    assert call["admin"]["deviceId"] == device_id


def test_approve_send_idempotent_replay_returns_200(client, auth, monkeypatch):
    # A fresh, valid dispatch whose draft Atlas has already sent returns 200: the
    # tracker reflects Atlas's idempotent outcome (the draft-id state machine).
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    _stub_atlas_send(monkeypatch, draft_id, idempotent=True)

    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["idempotent"] is True


def test_spent_challenge_cannot_redispatch(client, auth, monkeypatch):
    # The single-use guarantee on a money path: once consumed, a challenge cannot
    # drive another send even with a fresh confirmation.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    _stub_atlas_send(monkeypatch, draft_id)

    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    first = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert first.status_code == 201, first.text

    other_draft = _fresh_draft()
    _stub_atlas_send(monkeypatch, other_draft)
    confirmation_b = _issue_confirmation(client, auth, device_id, other_draft).json()[
        "confirmationId"
    ]
    replay = _approve_send(
        client, device_id, private_key, other_draft, challenge_id, confirmation_b
    )
    assert replay.status_code == 409, replay.text


def test_missing_confirmation_rejected_before_atlas(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    calls: list = []
    _forbid_atlas_send(monkeypatch, calls)

    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, str(uuid.uuid4())
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_confirmation_for_other_draft_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    target_draft = _fresh_draft()
    other_draft = _fresh_draft()
    calls: list = []
    _forbid_atlas_send(monkeypatch, calls)

    confirmation_id = _issue_confirmation(client, auth, device_id, other_draft).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _approve_send(
        client, device_id, private_key, target_draft, challenge_id, confirmation_id
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_missing_challenge_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    calls: list = []
    _forbid_atlas_send(monkeypatch, calls)

    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    resp = _approve_send(
        client, device_id, private_key, draft_id, str(uuid.uuid4()), confirmation_id
    )
    assert resp.status_code == 409, resp.text
    assert calls == []


def test_non_approver_operator_rejected(client, auth, monkeypatch):
    # The device acts as its bound operator and must clear the same funnel-approver
    # gate the office path enforces; a non-approver is refused before any Atlas call.
    private_key, device_id = _enroll_device(client, auth)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    draft_id = _fresh_draft()
    calls: list = []
    _forbid_atlas_send(monkeypatch, calls)

    # No confirmation needed: the approver gate precedes the token gate.
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, str(uuid.uuid4())
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_capability_unavailable_precedes_token_consumption(client, auth, monkeypatch):
    # If the deployed Atlas does not advertise the capability, the request is
    # refused (501) BEFORE the tokens are consumed, so the operator does not have
    # to re-confirm once the capability is available.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)

    def unavailable(_capability, _admin):
        raise api.AtlasFunnelCapabilityUnavailable(_capability)

    calls: list = []
    _forbid_atlas_send(monkeypatch, calls)
    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    refused = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert refused.status_code == 501, refused.text
    # The 501 names the missing Atlas capability, not the device capability alias.
    assert (
        refused.json()["capability"]
        == api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_APPROVE_SEND
    )
    assert calls == []

    # The tokens survived: with the capability available and a real relay, the
    # SAME challenge and confirmation now complete the send.
    monkeypatch.setattr(api, "_require_atlas_funnel_capability", lambda *_a, **_k: None)
    _stub_atlas_send(monkeypatch, draft_id)
    ok = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert ok.status_code == 201, ok.text


def test_atlas_failure_consumes_tokens_and_surfaces_error(client, auth, monkeypatch):
    # Fail-safe ordering: tokens are consumed BEFORE the send, so a transient Atlas
    # failure surfaces the mapped error AND leaves the tokens spent -- the operator
    # re-confirms to retry, and Atlas's stable idempotency key prevents a
    # double-send across that retry.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    draft_id = _fresh_draft()
    confirmation_id = _issue_confirmation(client, auth, device_id, draft_id).json()[
        "confirmationId"
    ]
    challenge_id = _issue_challenge(client, device_id, private_key)

    def failing(_path, _admin, *, payload, idempotency_key):
        raise api.AtlasFunnelRequestError(502, "atlas boom")

    monkeypatch.setattr(api, "_atlas_funnel_request", failing)
    failed = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert failed.status_code == 502, failed.text

    # The tokens were consumed before the failed send: the identical retry is
    # rejected at the challenge (single-use), forcing a fresh confirmation.
    _stub_atlas_send(monkeypatch, draft_id)
    retry = _approve_send(
        client, device_id, private_key, draft_id, challenge_id, confirmation_id
    )
    assert retry.status_code == 409, retry.text


def test_cross_capability_confirmation_fields_rejected(client, auth, monkeypatch):
    # A confirmation must carry exactly its capability's target fields: an
    # approve_send confirmation carrying mark_working fields (or vice versa) is a
    # 422 at issuance, so a confirmation can never bind a cross-capability target.
    _set_approver(monkeypatch, client, auth)
    _, device_id = _enroll_device(client, auth)

    wrong_fields = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={
            "capability": _CAP,
            "contactId": str(uuid.uuid4()),
            "expectedStateToken": "abc",
        },
    )
    assert wrong_fields.status_code == 422, wrong_fields.text

    mark_working_with_draft = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={"capability": "funnel.lead.mark_working", "draftId": str(uuid.uuid4())},
    )
    assert mark_working_with_draft.status_code == 422, mark_working_with_draft.text


def test_malformed_approve_send_body_returns_structured_422(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    resp = _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/onboarding-drafts/{_fresh_draft()}/approve-send",
        {"challengeId": "x"},  # missing confirmationId
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body.get("code") == "validation_error", body
    assert "confirmationId" in body.get("details", {}).get("fields", {}), body


def test_employee_cannot_confirm_approve_send(client, emp_auth):
    resp = client.post(
        f"/api/admin/connect/devices/{uuid.uuid4()}/operation-confirmations",
        headers=emp_auth,
        json={"capability": _CAP, "draftId": str(uuid.uuid4())},
    )
    assert resp.status_code == 403, resp.text
