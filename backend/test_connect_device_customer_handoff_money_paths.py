"""Device-authenticated customer-handoff money path.

The heaviest device money path: it creates the operational Customer/Site and
finalizes the Atlas lead link on the bound operator's behalf, reusing the office
conversion handoff reservation so the device produces identical local state and
shares the 202-pending Atlas reconciliation. It is approver-gated and
confirmation-gated, and the confirmation binds the FULL customer/site payload, so
an unattended trigger can never mint operational records without a matching human
authorization. Real crypto and real single-use token consumption run against the
app; the Atlas request boundary is stubbed per test.
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

_HANDOFF_CAP = "funnel.lead.customer_handoff"
_HANDOFF_PATH = "/api/connect/device/funnel/leads/{cid}/customer-handoffs"


@pytest.fixture(autouse=True)
def _clean_created_customer_records(setup_db):
    """Delete exactly the Customer/Site/handoff rows each test creates.

    The handoff money path creates real operational records (customers, locations,
    and eom_office_conversion_handoffs). Without cleanup those rows leak into
    global scans other suites rely on -- e.g. the geofence readiness gate treats
    every eligible site as unready and blocks scope enablement. Snapshot the max
    ids before the test and remove anything created above them afterward, in FK
    order (handoffs and locations reference customers ON DELETE RESTRICT)."""

    def _max(cur, table):
        cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}")
        return int(cur.fetchone()[0])

    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            base_customer = _max(cur, "customers")
            base_location = _max(cur, "locations")
    yield
    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM eom_office_conversion_handoffs WHERE customer_id > %s",
                (base_customer,),
            )
            cur.execute("DELETE FROM locations WHERE id > %s", (base_location,))
            cur.execute("DELETE FROM customers WHERE id > %s", (base_customer,))


def _fresh_contact() -> str:
    return str(uuid.uuid4())


def _payload(contact_id: str, key: str, *, rate: float = 175.0) -> dict:
    """A full office estimate-approval payload (the device submits one too)."""
    suffix = contact_id[:8]
    return {
        "name": f"Approved Estimate {suffix}",
        "primaryContactName": "Estimate Contact",
        "primaryPhone": "217-555-0123",
        "primaryEmail": f"{suffix}@example.test",
        "billingName": f"Approved Estimate {suffix}",
        "billingEmail": f"billing-{suffix}@example.test",
        "billingAddress": f"{suffix} Estimate Lane, Effingham, IL",
        "atlasContactId": contact_id,
        "idempotencyKey": key,
        "primarySite": {
            "address": f"{suffix} Estimate Lane, Effingham, IL",
            "locationType": "Residential",
            "rate": rate,
            "rateType": "per_visit",
            "frequency": "Every two weeks, weekday morning",
            "expectedHours": 3.5,
            "serviceScope": "Kitchen, baths, floors",
            "serviceStartDate": "2026-08-01",
        },
    }


def _issue_handoff_confirmation(client, auth, device_id, payload):
    return client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={"capability": _HANDOFF_CAP, "handoff": payload},
    )


def _submit_handoff(client, device_id, private_key, contact_id, payload,
                    challenge_id, confirmation_id):
    body = dict(payload)
    body["challengeId"] = challenge_id
    body["confirmationId"] = confirmation_id
    return _device_post(
        client, device_id, private_key, _HANDOFF_PATH.format(cid=contact_id), body
    )


def _atlas_success(payload, key):
    return {
        "success": True,
        "handoff_id": str(uuid.uuid4()),
        "contact_id": payload["contact_id"],
        "tracker_customer_id": payload["tracker_customer_id"],
        "tracker_site_id": payload["tracker_site_id"],
        "approval_key": key,
    }


def _stub_atlas_handoff(monkeypatch, *, calls=None, fail_status=None):
    def atlas_request(path, admin, *, payload, idempotency_key):
        if calls is not None:
            calls.append({"path": path, "admin": admin, "payload": payload,
                          "idempotencyKey": idempotency_key})
        if fail_status is not None:
            raise api.AtlasFunnelRequestError(fail_status, "atlas boom")
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


def _forbid_atlas(monkeypatch, calls):
    def unexpected(*_a, **_k):
        calls.append(True)
        raise AssertionError("Atlas must not be called past the gate under test")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)


def _customer_ids_for_contact(contact_id):
    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM customers WHERE atlas_contact_id = %s", (contact_id,)
            )
            return [int(r[0]) for r in cur.fetchall()]


def _handoff_exists(contact_id):
    with api.db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM eom_office_conversion_handoffs WHERE atlas_contact_id = %s",
                (contact_id,),
            )
            return cur.fetchone() is not None


def test_customer_handoff_full_flow(client, auth, monkeypatch):
    juan_id = _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(contact_id, key)
    calls: list = []
    _stub_atlas_handoff(monkeypatch, calls=calls)

    conf = _issue_handoff_confirmation(client, auth, device_id, payload)
    assert conf.status_code == 201, conf.text
    confirmation_id = conf.json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _submit_handoff(client, device_id, private_key, contact_id, payload,
                           challenge_id, confirmation_id)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["handoff"]["status"] == "finalized"
    customer = body["handoff"]["customer"]
    assert customer["atlasContactId"] == contact_id
    assert customer["sites"][0]["rate"] == 175.0
    # Exactly one Customer/Site created, and the relay vouched for the operator with
    # the tracker's service token (the device holds none).
    assert _customer_ids_for_contact(contact_id) == [int(customer["id"])]
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == "/eom-funnel/customer-handoffs"
    assert call["payload"]["contact_id"] == contact_id
    assert call["payload"]["tracker_customer_id"] == int(customer["id"])
    assert call["idempotencyKey"] == key
    assert call["admin"]["id"] == juan_id
    assert call["admin"]["deviceId"] == device_id


def test_handoff_replay_returns_200_without_recreating_or_recalling(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(contact_id, key)
    _stub_atlas_handoff(monkeypatch)
    confirmation_id = _issue_handoff_confirmation(
        client, auth, device_id, payload
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)
    first = _submit_handoff(client, device_id, private_key, contact_id, payload,
                            challenge_id, confirmation_id)
    assert first.status_code == 201, first.text
    first_customer_id = first.json()["handoff"]["customer"]["id"]

    # Replay of the finalized handoff (same body, now-spent tokens) returns 200 and
    # does NOT create a second Customer/Site or re-call Atlas.
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    replay = _submit_handoff(client, device_id, private_key, contact_id, payload,
                             challenge_id, confirmation_id)
    assert replay.status_code == 200, replay.text
    assert replay.json()["idempotent"] is True
    assert replay.json()["handoff"]["customer"]["id"] == first_customer_id
    assert _customer_ids_for_contact(contact_id) == [int(first_customer_id)]
    assert calls == []


def test_handoff_retry_after_atlas_failure_replays_without_new_confirmation(client, auth, monkeypatch):
    # A transient Atlas failure leaves the Customer/Site created and the handoff
    # 202-pending, with tokens spent. A retry with the SAME body (spent tokens)
    # replays the existing reservation and finalizes -- no fresh confirmation, no
    # second Customer/Site.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(contact_id, key)
    confirmation_id = _issue_handoff_confirmation(
        client, auth, device_id, payload
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    _stub_atlas_handoff(monkeypatch, fail_status=503)
    pending = _submit_handoff(client, device_id, private_key, contact_id, payload,
                              challenge_id, confirmation_id)
    assert pending.status_code == 202, pending.text
    assert pending.json()["handoff"]["status"] == "atlas_pending"
    created_ids = _customer_ids_for_contact(contact_id)
    assert len(created_ids) == 1

    _stub_atlas_handoff(monkeypatch)
    ok = _submit_handoff(client, device_id, private_key, contact_id, payload,
                         challenge_id, confirmation_id)
    assert ok.status_code == 200, ok.text
    assert ok.json()["handoff"]["status"] == "finalized"
    assert _customer_ids_for_contact(contact_id) == created_ids


def test_missing_confirmation_creates_no_records_and_calls_no_atlas(client, auth, monkeypatch):
    # An automatic/unattended dispatch with a valid challenge but no matching
    # confirmation must roll back entirely: no Customer/Site, no Atlas call. This is
    # the core guarantee that a device cannot mint operational records unattended.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(contact_id, key)
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _submit_handoff(client, device_id, private_key, contact_id, payload,
                           challenge_id, str(uuid.uuid4()))
    # A missing/mismatched confirmation is refused (403) before any write; the
    # transaction rolls back so no Customer/Site or handoff row is created.
    assert resp.status_code == 403, resp.text
    assert _customer_ids_for_contact(contact_id) == []
    assert not _handoff_exists(contact_id)
    assert calls == []


def test_confirmation_for_different_payload_rejected(client, auth, monkeypatch):
    # The confirmation binds the exact customer/site payload. Dispatching a changed
    # payload (different rate) under it must not match, so nothing is created.
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    confirmed = _payload(contact_id, key, rate=175.0)
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    confirmation_id = _issue_handoff_confirmation(
        client, auth, device_id, confirmed
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    tampered = _payload(contact_id, key, rate=999.0)
    resp = _submit_handoff(client, device_id, private_key, contact_id, tampered,
                           challenge_id, confirmation_id)
    # The changed payload hashes to a different fingerprint, so the confirmation
    # does not match and is refused (403); nothing is created.
    assert resp.status_code == 403, resp.text
    assert _customer_ids_for_contact(contact_id) == []
    assert calls == []


def test_non_approver_rejected_before_reservation(client, auth, monkeypatch):
    import time_tracker_api as api_mod
    monkeypatch.setattr(api_mod, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 9_999_999)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(contact_id, key)
    calls: list = []
    _forbid_atlas(monkeypatch, calls)

    resp = _submit_handoff(client, device_id, private_key, contact_id, payload,
                           str(uuid.uuid4()), str(uuid.uuid4()))
    assert resp.status_code == 403, resp.text
    assert _customer_ids_for_contact(contact_id) == []
    assert calls == []


def test_path_contact_mismatch_rejected(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    body_contact = _fresh_contact()
    path_contact = _fresh_contact()
    key = str(uuid.uuid4())
    payload = _payload(body_contact, key)
    calls: list = []
    _forbid_atlas(monkeypatch, calls)
    # A confirmation for the body's contact, dispatched at a different path contact.
    confirmation_id = _issue_handoff_confirmation(
        client, auth, device_id, payload
    ).json()["confirmationId"]
    challenge_id = _issue_challenge(client, device_id, private_key)

    resp = _submit_handoff(client, device_id, private_key, path_contact, payload,
                           challenge_id, confirmation_id)
    assert resp.status_code == 422, resp.text
    assert _customer_ids_for_contact(body_contact) == []
    assert calls == []


def test_malformed_handoff_body_returns_structured_422(client, auth, monkeypatch):
    _set_approver(monkeypatch, client, auth)
    private_key, device_id = _enroll_device(client, auth)
    contact_id = _fresh_contact()
    # Missing primarySite (required) and the device token fields.
    resp = _device_post(
        client, device_id, private_key, _HANDOFF_PATH.format(cid=contact_id),
        {"name": "No Site", "atlasContactId": contact_id,
         "idempotencyKey": str(uuid.uuid4())},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body.get("code") == "validation_error", body


def test_employee_cannot_confirm_handoff(client, emp_auth, monkeypatch):
    contact_id = _fresh_contact()
    key = str(uuid.uuid4())
    resp = _issue_handoff_confirmation(
        client, emp_auth, str(uuid.uuid4()), _payload(contact_id, key)
    )
    assert resp.status_code in (403, 404), resp.text


def test_confirmation_missing_handoff_field_rejected(client, auth, monkeypatch):
    # A handoff confirmation that carries a booking-style flat target instead of the
    # nested handoff payload is rejected: the capability requires exactly `handoff`.
    _set_approver(monkeypatch, client, auth)
    _, device_id = _enroll_device(client, auth)
    resp = client.post(
        f"/api/admin/connect/devices/{device_id}/operation-confirmations",
        headers=auth,
        json={"capability": _HANDOFF_CAP, "contactId": _fresh_contact()},
    )
    assert resp.status_code == 422, resp.text
