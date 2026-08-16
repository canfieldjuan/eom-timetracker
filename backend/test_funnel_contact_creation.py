"""Manual CRM contact creation is Atlas-backed, bounded, and local-row free."""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api


def _path() -> str:
    return "/api/admin/funnel/contacts"


def _payload(
    key: str,
    *,
    contact_type: str = "lead",
    full_name: str = "Ada Operator",
    email: str | None = "ada@example.test",
    phone: str | None = "217-555-0100",
) -> dict[str, object]:
    return {
        "contactType": contact_type,
        "fullName": full_name,
        "email": email,
        "phone": phone,
        "idempotencyKey": key,
    }


def _operational_counts() -> dict[str, int]:
    return {
        "customers": int(db.query_one("SELECT COUNT(*) AS count FROM customers")["count"]),
        "locations": int(db.query_one("SELECT COUNT(*) AS count FROM locations")["count"]),
        "reservations": int(
            db.query_one(
                "SELECT COUNT(*) AS count FROM eom_customer_atlas_reservations"
            )["count"]
        ),
    }


def _atlas_result(
    contact_id: str,
    *,
    contact_type: str = "lead",
    full_name: str = "Ada Operator",
    operation: str = "contact_created",
    idempotent: bool = False,
) -> dict[str, object]:
    return {
        "success": True,
        "contactId": contact_id,
        "operation": operation,
        "idempotent": idempotent,
        "contact": {
            "contactId": contact_id,
            "fullName": full_name,
            "contactType": contact_type,
        },
    }


def test_review_proves_the_tracker_contact_proxy_only_when_atlas_allows_it(
    client, auth, monkeypatch
):
    def atlas_read_with_contact_capability(*_args, **_kwargs):
        return {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION],
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read_with_contact_capability)
    available = client.get("/api/admin/funnel/review", headers=auth)

    assert available.status_code == 200, available.text
    assert available.json()["contactCreationAvailable"] is True

    def atlas_read_without_contact_capability(*_args, **_kwargs):
        return {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None}

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read_without_contact_capability)
    unavailable = client.get("/api/admin/funnel/review", headers=auth)

    assert unavailable.status_code == 200, unavailable.text
    assert unavailable.json()["contactCreationAvailable"] is False


def test_manual_lead_create_forwards_the_exact_canonical_contract_and_no_local_rows(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(
            {
                "path": path,
                "admin": admin,
                "payload": payload,
                "idempotencyKey": idempotency_key,
            }
        )
        return _atlas_result(contact_id, full_name="Ada Operator")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json=_payload(
            key,
            full_name="  Ada Operator  ",
            email="  ADA@example.test  ",
            phone="  (217) 555-0100  ",
        ),
    )

    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "idempotent": False,
        "operation": "contact_created",
        "contact": {
            "contactId": contact_id,
            "fullName": "Ada Operator",
            "contactType": "lead",
        },
    }
    assert calls == [
        {
            "path": api.ATLAS_OPERATOR_CONTACTS_PATH,
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "payload": {
                "full_name": "Ada Operator",
                "email": "ADA@example.test",
                "phone": "(217) 555-0100",
                "contact_type": "lead",
                "source_channel": "time_tracker",
                "source_ref": f"portal-contact:{key}",
            },
            "idempotencyKey": key,
        }
    ]
    assert _operational_counts() == before


def test_manual_customer_create_omits_blank_optional_fields_and_never_creates_a_tracker_customer(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(
            contact_id,
            contact_type="customer",
            full_name="Customer Contact",
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json=_payload(
            key,
            contact_type="customer",
            full_name="Customer Contact",
            email="   ",
            phone="",
        ),
    )

    assert response.status_code == 201, response.text
    assert calls == [
        {
            "full_name": "Customer Contact",
            "contact_type": "customer",
            "source_channel": "time_tracker",
            "source_ref": f"portal-contact:{key}",
        }
    ]
    assert _operational_counts() == before


def test_manual_contact_replay_preserves_the_operation_key_and_reports_atlas_truth(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    keys: list[str] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        keys.append(idempotency_key)
        return _atlas_result(
            contact_id,
            operation="contact_updated",
            idempotent=len(keys) == 2,
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first = client.post(_path(), headers=auth, json=_payload(key))
    replay = client.post(_path(), headers=auth, json=_payload(key))

    assert first.status_code == 201, first.text
    assert first.json()["operation"] == "contact_updated"
    assert first.json()["idempotent"] is False
    assert replay.status_code == 200, replay.text
    assert replay.json()["operation"] == "contact_updated"
    assert replay.json()["idempotent"] is True
    assert keys == [key, key]


def test_manual_contact_refuses_when_atlas_does_not_advertise_the_capability(
    client, auth, monkeypatch
):
    calls: list[object] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION
        )

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(_path(), headers=auth, json=_payload(str(uuid.uuid4())))

    assert response.status_code == 501, response.text
    assert response.json() == {
        "success": False,
        "error": "atlas_capability_unavailable",
        "capability": "contact.operator_mutation",
        "message": "The EOM funnel service does not yet support this action (contact.operator_mutation)",
    }
    assert calls == []


def test_manual_contact_rejects_an_edit_identifier_or_malformed_atlas_result(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    calls: list[object] = []

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        return {
            "success": True,
            "contactId": str(uuid.uuid4()),
            "operation": "contact_created",
            "idempotent": False,
            "contact": {"fullName": "Wrong Kind", "contactType": "customer"},
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    rejected = client.post(
        _path(),
        headers=auth,
        json={**_payload(key), "contactId": str(uuid.uuid4())},
    )
    malformed = client.post(_path(), headers=auth, json=_payload(str(uuid.uuid4())))

    assert rejected.status_code == 422, rejected.text
    assert malformed.status_code == 502, malformed.text
    assert calls == [True]
