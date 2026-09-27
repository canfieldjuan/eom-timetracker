"""Device-authenticated, confirmation-gated contact archive and restore.

Faithful to the office relays (``admin_archive_funnel_contact`` and
``admin_restore_funnel_contact``): the same combined capability+route gate, the same
Atlas path and client idempotency key, and the same closed receipt projection. These
tests exercise the real crypto and the real single-use token consumption; the Atlas
request boundary is stubbed per test, and the route gate is satisfied per test because
the shared healthy-Atlas fixture does not advertise the contact lifecycle routes.
"""
from __future__ import annotations

import uuid

import time_tracker_api as api
from test_connect_device_mutations import (
    _device_post,
    _enroll_device,
    _issue_challenge,
)

_ARCHIVE_CAP = "funnel.contact.archive"
_RESTORE_CAP = "funnel.contact.restore"


def _issue_confirmation(client, admin_headers, device_id, contact_id, key, capability):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=admin_headers,
        json={"capability": capability, "contactId": contact_id, "idempotencyKey": key},
    )


def _call(client, device_id, private_key, contact_id, action, body):
    return _device_post(
        client,
        device_id,
        private_key,
        f"/api/connect/device/funnel/contacts/{contact_id}/{action}",
        body,
    )


def _route_available(monkeypatch):
    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", lambda *_a, **_k: None)


def _stub_atlas(monkeypatch, calls, *, status, idempotent=False, echo_id=None):
    def atlas_request(path, admin, *, payload, idempotency_key):
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
            "contact_id": echo_id or path.split("/")[3],
            "contact_type": "lead",
            "lead_stage": "new",
            "status": status,
            "idempotent": idempotent,
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas(monkeypatch, calls):
    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def _setup(client, auth, capability):
    private_key, device_id = _enroll_device(client, auth)
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    conf = _issue_confirmation(client, auth, device_id, contact_id, key, capability)
    assert conf.status_code == 201, conf.text
    challenge_id = _issue_challenge(client, device_id, private_key)
    body = {
        "challengeId": challenge_id,
        "confirmationId": conf.json()["confirmationId"],
        "idempotencyKey": key,
    }
    return private_key, device_id, contact_id, key, body


def test_archive_full_flow(client, auth, monkeypatch):
    calls: list[dict] = []
    _route_available(monkeypatch)
    _stub_atlas(monkeypatch, calls, status="archived")
    private_key, device_id, contact_id, key, body = _setup(client, auth, _ARCHIVE_CAP)

    resp = _call(client, device_id, private_key, contact_id, "archive", body)
    assert resp.status_code == 201, resp.text
    assert resp.json() == {
        "success": True,
        "contactId": contact_id,
        "contactType": "lead",
        "leadStage": "new",
        "status": "archived",
        "idempotent": False,
    }
    assert len(calls) == 1
    assert calls[0]["path"] == f"/eom-funnel/contacts/{contact_id}/archive"
    assert calls[0]["payload"] == {}
    assert calls[0]["idempotencyKey"] == key
    assert calls[0]["admin"]["deviceId"] == device_id


def test_restore_full_flow_idempotent_replay_is_200(client, auth, monkeypatch):
    calls: list[dict] = []
    _route_available(monkeypatch)
    _stub_atlas(monkeypatch, calls, status="active", idempotent=True)
    private_key, device_id, contact_id, key, body = _setup(client, auth, _RESTORE_CAP)

    resp = _call(client, device_id, private_key, contact_id, "restore", body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "active"
    assert resp.json()["idempotent"] is True
    assert calls[0]["path"] == f"/eom-funnel/contacts/{contact_id}/restore"
    assert calls[0]["idempotencyKey"] == key


def test_archive_confirmation_cannot_restore(client, auth, monkeypatch):
    # The fingerprint binds the capability, so the inverse transition is refused.
    calls: list = []
    _route_available(monkeypatch)
    _forbid_atlas(monkeypatch, calls)
    private_key, device_id, contact_id, _key, body = _setup(client, auth, _ARCHIVE_CAP)

    resp = _call(client, device_id, private_key, contact_id, "restore", body)
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_confirmation_for_another_key_is_refused(client, auth, monkeypatch):
    calls: list = []
    _route_available(monkeypatch)
    _forbid_atlas(monkeypatch, calls)
    private_key, device_id, contact_id, _key, body = _setup(client, auth, _ARCHIVE_CAP)

    resp = _call(
        client,
        device_id,
        private_key,
        contact_id,
        "archive",
        {**body, "idempotencyKey": str(uuid.uuid4())},
    )
    assert resp.status_code == 403, resp.text
    assert calls == []


def test_route_unavailable_precedes_token_consumption(client, auth, monkeypatch):
    # An Atlas that does not advertise the archive route is refused (501) BEFORE the
    # tokens are consumed, so the same challenge and confirmation succeed later.
    private_key, device_id, contact_id, _key, body = _setup(client, auth, _ARCHIVE_CAP)

    def unavailable(capability, _route, _admin):
        raise api.AtlasFunnelCapabilityUnavailable(capability)

    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", unavailable)
    refused = _call(client, device_id, private_key, contact_id, "archive", body)
    assert refused.status_code == 501, refused.text
    assert calls == []

    _route_available(monkeypatch)
    _stub_atlas(monkeypatch, [], status="archived")
    ok = _call(client, device_id, private_key, contact_id, "archive", body)
    assert ok.status_code == 201, ok.text


def test_atlas_conflict_is_relayed(client, auth, monkeypatch):
    # Atlas refuses archiving a won lead (it must go through the lost flow).
    _route_available(monkeypatch)

    def conflict(*_args, **_kwargs):
        raise api.AtlasFunnelRequestError(409, "won lead must be marked lost")

    monkeypatch.setattr(api, "_atlas_funnel_request", conflict)
    private_key, device_id, contact_id, _key, body = _setup(client, auth, _ARCHIVE_CAP)
    resp = _call(client, device_id, private_key, contact_id, "archive", body)
    assert resp.status_code == 409, resp.text


def test_invalid_atlas_echo_is_a_502(client, auth, monkeypatch):
    # The office route's closed receipt validation applies: an echo naming another
    # contact never reaches the device.
    _route_available(monkeypatch)
    _stub_atlas(monkeypatch, [], status="archived", echo_id=str(uuid.uuid4()))
    private_key, device_id, contact_id, _key, body = _setup(client, auth, _ARCHIVE_CAP)
    resp = _call(client, device_id, private_key, contact_id, "archive", body)
    assert resp.status_code == 502, resp.text
