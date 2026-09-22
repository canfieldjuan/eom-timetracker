"""Device-authenticated Atlas booking money paths (estimate + first-clean),
dispatched through the durable authorization reservation.

These relay to Atlas with the tracker's service token, carry a client idempotency
key and a scheduled window, and are approver-gated and confirmation-gated. The
reservation lets a retry after an ambiguous Atlas failure replay the frozen
request and key without a fresh confirmation. Real crypto and real single-use
token/reservation consumption run against the app; the Atlas request boundary is
stubbed per test.
"""
from __future__ import annotations

import uuid

import pytest

import time_tracker_api as api
from test_connect_device_mutations import (
    _device_post,
    _enroll_device,
    _issue_challenge,
    _set_approver,
)

_ESTIMATE_CAP = "funnel.lead.estimate_booking"
_FIRST_CLEAN_CAP = "funnel.lead.first_clean_booking"
_START = "2026-10-01T09:00:00+00:00"
_END = "2026-10-01T10:00:00+00:00"
_ESTIMATE_PATH = "/api/connect/device/funnel/leads/{cid}/estimate-bookings"
_FIRST_CLEAN_PATH = "/api/connect/device/funnel/leads/{cid}/first-clean-bookings"


def _fresh_contact() -> str:
    return str(uuid.uuid4())


def _issue_booking_confirmation(
    client, admin_headers, device_id, contact_id, idempotency_key, *,
    capability=_ESTIMATE_CAP, start=_START, end=_END,
):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={
            "capability": capability,
            "contactId": contact_id,
            "scheduledStart": start,
            "scheduledEnd": end,
            "idempotencyKey": idempotency_key,
        },
    )


def _book(client, device_id, private_key, path, contact_id, challenge_id, confirmation_id,
          idempotency_key, *, start=_START, end=_END):
    return _device_post(
        client, device_id, private_key, path.format(cid=contact_id),
        {
            "challengeId": challenge_id,
            "confirmationId": confirmation_id,
            "scheduledStart": start,
            "scheduledEnd": end,
            "idempotencyKey": idempotency_key,
        },
    )


def _stub_atlas_booking(monkeypatch, *, stage, status, idempotent=False, draft=False,
                        calls=None, fail_status=None):
    """Stub the tracker-to-Atlas relay to return a valid booking receipt (or raise
    a mapped error when fail_status is set). Records each call."""

    def atlas_request(path, admin, *, payload, idempotency_key):
        if calls is not None:
            calls.append({"path": path, "admin": admin, "payload": payload,
                          "idempotencyKey": idempotency_key})
        if fail_status is not None:
            raise api.AtlasFunnelRequestError(fail_status, "atlas boom")
        # contact id is the path segment between /leads/ and /<...>-bookings
        contact_id = path.split("/leads/")[1].split("/")[0]
        body = {
            "success": True,
            "contact_id": contact_id,
            "lead_stage": stage,
            "status": status,
            "idempotent": idempotent,
            "calendar_event_id": "evt-abc",
            "expected_calendar_event_id": "evt-abc",
        }
        if draft:
            body["onboarding_draft_id"] = str(uuid.uuid4())
        return body

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas(monkeypatch, calls):
    def unexpected(*_a, **_k):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def test_estimate_booking_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    calls: list[dict] = []
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked",
                        calls=calls)

    conf = _issue_booking_confirmation(client, auth, device_id, contact_id, idem)
    assert conf.status_code == 201, conf.text
    confirmation_id = conf.json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 challenge_id, confirmation_id, idem)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["contactId"] == contact_id
    assert body["status"] == "estimate_booked"
    assert body["idempotent"] is False
    # The relay ran once with the frozen booking body + client idempotency key,
    # vouching for the bound operator.
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == f"/eom-funnel/leads/{contact_id}/estimate-bookings"
    assert call["payload"] == {"scheduled_start": _START, "scheduled_end": _END}
    assert call["idempotencyKey"] == idem
    assert call["admin"]["id"] == juan_id
    assert call["admin"]["deviceId"] == device_id


def test_first_clean_booking_full_flow(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    _stub_atlas_booking(monkeypatch, stage="won", status="first_clean_booked", draft=True)

    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem, capability=_FIRST_CLEAN_CAP
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _book(client, device_id, private_key, _FIRST_CLEAN_PATH, contact_id,
                 challenge_id, confirmation_id, idem)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "first_clean_booked"
    assert "onboardingDraftId" in body


def test_idempotent_atlas_result_returns_200(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked",
                        idempotent=True)
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 challenge_id, confirmation_id, idem)
    assert resp.status_code == 200, resp.text
    assert resp.json()["idempotent"] is True


def test_retry_after_atlas_failure_replays_without_new_confirmation(client, auth, monkeypatch):
    # The reservation's core guarantee: a transient Atlas failure leaves the
    # operation authorized, and a retry with the SAME request (tokens now spent)
    # replays the reservation and succeeds, no fresh confirmation required.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    # First attempt: Atlas fails transiently. Tokens are consumed into the
    # reservation; the mapped error surfaces.
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked",
                        fail_status=503)
    failed = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                   challenge_id, confirmation_id, idem)
    assert failed.status_code == 503, failed.text

    # Retry the identical request (same, now-spent, tokens). Atlas now succeeds; the
    # reservation replays under the original authorization.
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked")
    ok = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
               challenge_id, confirmation_id, idem)
    assert ok.status_code == 201, ok.text
    assert ok.json()["status"] == "estimate_booked"


def test_completed_replay_returns_frozen_receipt_without_calling_atlas(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked")
    first = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                  challenge_id, confirmation_id, idem)
    assert first.status_code == 201, first.text

    # Replay of a completed reservation returns the frozen receipt (200) and does
    # NOT reach Atlas again.
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    replay = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                   challenge_id, confirmation_id, idem)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert calls == []


def test_completed_replay_returns_receipt_even_when_capability_withdrawn(
    client, auth, monkeypatch
):
    # A booking completes. Later the deployed Atlas withdraws the booking
    # capability. Replaying the SAME completed booking must still return its frozen
    # receipt (200), not a 501: the money already moved under this fingerprint, so
    # the capability gate is not consulted for a completed reservation, and Atlas is
    # not called again.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked")
    first = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                  challenge_id, confirmation_id, idem)
    assert first.status_code == 201, first.text

    # Capability withdrawn AND the relay forbidden: a new operation here would 501,
    # but the completed replay bypasses both.
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(
        api, "_require_atlas_funnel_capability",
        lambda cap, _admin: (_ for _ in ()).throw(api.AtlasFunnelCapabilityUnavailable(cap)),
    )
    replay = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                   challenge_id, confirmation_id, idem)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert calls == []


def test_reserved_replay_refuses_after_device_revoked(client, auth, monkeypatch):
    # A booking's first attempt fails at Atlas, leaving a 'reserved' reservation
    # (tokens spent, not completed). If the device is revoked before a retry
    # re-drives it, replaying the reservation must re-assert the operator is active
    # and refuse (403) rather than re-drive the frozen Atlas money call.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked",
                        fail_status=503)
    failed = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                   challenge_id, confirmation_id, idem)
    assert failed.status_code == 503, failed.text

    revoked = client.post(
        f"/api/admin/connect/devices/{device_id}/revoke", headers=auth
    )
    assert revoked.status_code == 200, revoked.text

    # The reserved-replay branch runs inside the reserve lock; it does not go through
    # the endpoint's device auth (which would already reject a revoked device). Call
    # it directly to prove the branch itself re-checks the operator. Fresh (unused)
    # token ids: the reserved-existing branch never consumes tokens.
    fingerprint = api._connect_device_operation_fingerprint(
        _ESTIMATE_CAP,
        {"contactId": contact_id, "scheduledStart": _START,
         "scheduledEnd": _END, "idempotencyKey": idem},
    )
    with pytest.raises(api.HTTPException) as exc_info:
        api._reserve_or_get_connect_device_operation(
            device_id=device_id,
            capability=_ESTIMATE_CAP,
            fingerprint=fingerprint,
            idempotency_key=idem,
            atlas_path=f"/eom-funnel/leads/{contact_id}/estimate-bookings",
            request_body={"scheduled_start": _START, "scheduled_end": _END},
            challenge_id=str(uuid.uuid4()),
            confirmation_id=str(uuid.uuid4()),
        )
    assert exc_info.value.status_code == 403


def _age_reservation(device_id, fingerprint, seconds):
    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE connect_device_operation_reservations
                SET updated_at = NOW() - make_interval(secs => %s)
                WHERE device_id = %s AND operation_fingerprint = %s
                """,
                (seconds, device_id, fingerprint),
            )


def _reservation_exists(device_id, fingerprint):
    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1 FROM connect_device_operation_reservations
                WHERE device_id = %s AND operation_fingerprint = %s
                """,
                (device_id, fingerprint),
            )
            return cur.fetchone() is not None


def test_reserved_replay_refreshes_retention_against_pruner(client, auth, monkeypatch):
    # A still-reserved reservation replayed after aging past the retention window
    # must have its retention clock refreshed by the claim, so the inactivity
    # pruner cannot reap it out from under an in-flight retry (which would drop the
    # frozen request and leave the next retry meeting spent tokens).
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    # First attempt fails at Atlas: a 'reserved' reservation is left behind.
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked",
                        fail_status=503)
    failed = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                   challenge_id, confirmation_id, idem)
    assert failed.status_code == 503, failed.text

    fingerprint = api._connect_device_operation_fingerprint(
        _ESTIMATE_CAP,
        {"contactId": contact_id, "scheduledStart": _START,
         "scheduledEnd": _END, "idempotencyKey": idem},
    )
    # Age it well past the retention window: without the refresh it would now be
    # prunable while a retry is mid-flight.
    _age_reservation(device_id, fingerprint,
                     api.CONNECT_DEVICE_OPERATION_RETENTION_S + 3600)

    # Claim it for replay. The claim refreshes updated_at, so a prune that runs
    # before completion no longer deletes it.
    reservation = api._reserve_or_get_connect_device_operation(
        device_id=device_id,
        capability=_ESTIMATE_CAP,
        fingerprint=fingerprint,
        idempotency_key=idem,
        atlas_path=f"/eom-funnel/leads/{contact_id}/estimate-bookings",
        request_body={"scheduled_start": _START, "scheduled_end": _END},
        challenge_id=str(uuid.uuid4()),
        confirmation_id=str(uuid.uuid4()),
    )
    assert reservation["status"] == "reserved"
    api._prune_connect_device_operation_tokens()
    assert _reservation_exists(device_id, fingerprint), (
        "replay-claim must refresh the retention clock so the pruner spares the "
        "in-flight reservation"
    )

    # The retry then completes normally and returns the receipt.
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked")
    ok = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
               challenge_id, confirmation_id, idem)
    assert ok.status_code == 201, ok.text
    assert ok.json()["status"] == "estimate_booked"


def test_confirmation_for_different_window_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    # Confirmation issued for the 09:00-10:00 window; dispatch a different window.
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 challenge_id, confirmation_id, idem,
                 start="2026-10-02T09:00:00+00:00", end="2026-10-02T10:00:00+00:00")
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_non_approver_rejected_before_atlas(client, auth, monkeypatch):
    private_key, device_id = _enroll_device(client, auth)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    contact_id = _fresh_contact()
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 challenge_id, str(uuid.uuid4()), str(uuid.uuid4()))
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_missing_confirmation_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    challenge_id = _issue_challenge(client, device_id, private_key)
    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 challenge_id, str(uuid.uuid4()), str(uuid.uuid4()))
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_missing_challenge_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    resp = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                 str(uuid.uuid4()), confirmation_id, idem)
    assert resp.status_code == 409, resp.text
    assert calls == []


def test_capability_unavailable_precedes_token_consumption(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    idem = str(uuid.uuid4())
    confirmation_id = _issue_booking_confirmation(
        client, auth, device_id, contact_id, idem
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(
        api, "_require_atlas_funnel_capability",
        lambda cap, _admin: (_ for _ in ()).throw(api.AtlasFunnelCapabilityUnavailable(cap)),
    )
    refused = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
                    challenge_id, confirmation_id, idem)
    assert refused.status_code == 501, refused.text
    assert calls == []

    # Tokens survived: with the capability available and a real relay, the SAME
    # challenge and confirmation now complete the booking.
    monkeypatch.setattr(api, "_require_atlas_funnel_capability", lambda *_a, **_k: None)
    _stub_atlas_booking(monkeypatch, stage="estimate_booked", status="estimate_booked")
    ok = _book(client, device_id, private_key, _ESTIMATE_PATH, contact_id,
               challenge_id, confirmation_id, idem)
    assert ok.status_code == 201, ok.text


def test_cross_capability_confirmation_fields_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    _, device_id = _enroll_device(client, auth)
    # A booking capability confirmation carrying a draftId (approve_send's field).
    bad = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={
            "capability": _ESTIMATE_CAP,
            "contactId": _fresh_contact(),
            "scheduledStart": _START,
            "scheduledEnd": _END,
            "idempotencyKey": str(uuid.uuid4()),
            "draftId": str(uuid.uuid4()),
        },
    )
    assert bad.status_code == 422, bad.text
    # mark_working carrying a booking window is likewise rejected.
    bad2 = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={
            "capability": "funnel.lead.mark_working",
            "contactId": _fresh_contact(),
            "expectedStateToken": "tok",
            "scheduledStart": _START,
        },
    )
    assert bad2.status_code == 422, bad2.text


def test_malformed_booking_body_returns_structured_422(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    resp = _device_post(
        client, device_id, private_key,
        _ESTIMATE_PATH.format(cid=_fresh_contact()),
        {"challengeId": "x", "confirmationId": "y", "scheduledStart": _START},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body.get("code") == "validation_error", body
    fields = body.get("details", {}).get("fields", {})
    assert "scheduledEnd" in fields and "idempotencyKey" in fields, body


def test_employee_cannot_confirm_booking(client, emp_auth):
    resp = client.post(
        f"/api/admin/connect/devices/{uuid.uuid4()}/operation-confirmations",
        headers=emp_auth,
        json={
            "capability": _ESTIMATE_CAP,
            "contactId": str(uuid.uuid4()),
            "scheduledStart": _START,
            "scheduledEnd": _END,
            "idempotencyKey": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 403, resp.text
