"""Customer create match contract (issue 282), slice B.

A Customer create, a reconcile, or a Leads-page customer create can resolve in
Atlas to a contact it merely matched by email or phone -- possibly one another
Customer already holds. Before this slice Atlas overwrote that contact's name,
email and phone first and the tracker noticed the conflict afterwards. These
requests now send onMatch "return": Atlas leaves a match unchanged, and the
tracker decides. A 0C reservation sends the onMatch it RECORDED, so one created
before this slice retries exactly as it was first sent.

The fake Atlas below answers the way slice A does: with "return" a match is
reported as contact_matched and nothing is written. Each test asserts what the
tracker SENT and what it wrote locally; slice A's tests own the Atlas side.
"""

from __future__ import annotations

import uuid

import psycopg2
import pytest

import db
import time_tracker_api as api

TEST_PREFIX = "ZZ-282-TEST"


def _name(suffix: str) -> str:
    return f"{TEST_PREFIX} {suffix}"


def _clean_test_rows() -> None:
    db.execute(
        "DELETE FROM eom_customer_identity_reservations WHERE customer_id IN "
        "(SELECT id FROM customers WHERE name LIKE %s)",
        (f"{TEST_PREFIX}%",),
    )
    db.execute(
        "DELETE FROM eom_customer_atlas_reservations "
        "WHERE payload ->> 'name' LIKE %s",
        (f"{TEST_PREFIX}%",),
    )
    db.execute(
        "DELETE FROM eom_customer_atlas_reservations WHERE customer_id IN "
        "(SELECT id FROM customers WHERE name LIKE %s)",
        (f"{TEST_PREFIX}%",),
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{TEST_PREFIX}%",))


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean_test_rows()
    yield
    _clean_test_rows()


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


def _customer(name: str):
    return db.query_one(
        "SELECT id, name, atlas_contact_id FROM customers WHERE name = %s", (name,)
    )


def _holder(name: str, contact_id: str) -> int:
    """A Customer that already holds `contact_id`."""
    return int(
        db.execute_returning(
            "INSERT INTO customers (name, atlas_contact_id, active) "
            "VALUES (%s, %s, true) RETURNING id",
            (name, contact_id),
        )
    )


def _reservations(name: str):
    return db.query_all(
        "SELECT * FROM eom_customer_atlas_reservations "
        "WHERE payload ->> 'name' = %s ORDER BY created_at",
        (name,),
    )


def _with_capabilities(monkeypatch, *, add=(), drop=()):
    base_get = api.requests.get

    def _get(url, **kwargs):
        body = base_get(url, **kwargs).json()
        if "capabilities" in body:
            body["capabilities"] = [
                *[name for name in body["capabilities"] if name not in drop],
                *add,
            ]
        return _Response(200, body)

    monkeypatch.setattr(api.requests, "get", _get)


def _matching_atlas(monkeypatch, contact_id: str, *, full_name: str = "Held Customer LLC"):
    """An Atlas whose every create-or-return resolves to `contact_id`.

    With onMatch "return" it answers contact_matched and changes nothing. An
    edit names its contact and is answered about that contact. Every POST is
    recorded so a test can assert exactly what the tracker sent.
    """
    calls: list[dict] = []

    def _post(url, *, headers=None, json=None, timeout=None):
        body = dict(json or {})
        calls.append({"url": str(url), "headers": headers or {}, "json": body})
        assert str(url).endswith(api.ATLAS_OPERATOR_CONTACTS_PATH), url
        edited = body.get("contactId") or body.get("contact_id")
        matched = edited is None and body.get("onMatch") == "return"
        return _Response(
            201,
            {
                "success": True,
                "contactId": edited or contact_id,
                "operation": "contact_matched" if matched else "contact_updated",
                "idempotent": False,
                "contact": {
                    "contactId": edited or contact_id,
                    "fullName": full_name,
                    "contactType": "customer",
                },
            },
        )

    monkeypatch.setattr(api.requests, "post", _post)
    return calls


def _create_matches(calls):
    """The create-or-return requests (no contactId) among recorded POSTs."""
    return [
        call["json"]
        for call in calls
        if not (call["json"].get("contactId") or call["json"].get("contact_id"))
    ]


# --- Customer create and reconcile -------------------------------------------


def test_create_matching_a_held_contact_is_refused_and_writes_nothing(
    client, auth, monkeypatch
):
    """Issue 282: Y's contact must not take X's name, email or phone."""
    held = str(uuid.uuid4())
    holder_name = _name("Holder Y")
    holder_id = _holder(holder_name, held)
    calls = _matching_atlas(monkeypatch, held)
    name = _name("Create X")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": name,
            "primaryEmail": "billing@held.example",
            "primaryPhone": "217-555-0142",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 409, response.text
    refused = response.json()
    assert refused["code"] == "customer_atlas_link_conflict"
    assert refused["details"]["customerIds"] == [holder_id]
    assert len(calls) == 1, "nothing may follow a refused match"
    assert calls[0]["json"]["onMatch"] == "return"
    assert _customer(name) is None
    holder = _customer(holder_name)
    assert (holder["id"], str(holder["atlas_contact_id"])) == (holder_id, held)
    (reservation,) = _reservations(name)
    assert reservation["atlas_on_match"] == "return"
    assert reservation["state"] == "pending"


def test_create_matching_an_unheld_contact_links_and_sends_only_the_bill_to(
    client, auth, monkeypatch
):
    """The rename 0C did inline now happens through the fenced identity sync."""
    _with_capabilities(monkeypatch, add=("contact.bill_to_identity",))
    matched = str(uuid.uuid4())
    calls = _matching_atlas(monkeypatch, matched)
    name = _name("Create Unheld")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": name,
            "primaryEmail": "office@unheld.example",
            "primaryPhone": "217-555-0177",
            "billingAddress": "1 Main St, Effingham, IL 62401",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 201, response.text
    assert str(_customer(name)["atlas_contact_id"]) == matched
    assert [body["onMatch"] for body in _create_matches(calls)] == ["return"]
    follow_ups = [call["json"] for call in calls[1:]]
    assert len(follow_ups) == 1
    sync = follow_ups[0]
    assert sync["contactId"] == matched
    assert sync["full_name"] == name
    assert sync["billing_address"] == "1 Main St, Effingham, IL 62401"
    assert isinstance(sync["identityRevision"], int)
    assert "email" not in sync and "phone" not in sync


def test_reconcile_sends_on_match_and_refuses_a_held_match(client, auth, monkeypatch):
    held = str(uuid.uuid4())
    holder_id = _holder(_name("Holder For Reconcile"), held)
    customer_id = int(
        db.execute_returning(
            "INSERT INTO customers (name, primary_phone, active) "
            "VALUES (%s, %s, true) RETURNING id",
            (_name("Unlinked Z"), "217-555-0142"),
        )
    )
    calls = _matching_atlas(monkeypatch, held)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 409, response.text
    assert response.json()["details"]["customerIds"] == [holder_id]
    assert [call["json"]["onMatch"] for call in calls] == ["return"]
    assert _customer(_name("Unlinked Z"))["atlas_contact_id"] is None


@pytest.mark.parametrize(
    "route", ["create", "reconcile", "leads_customer_create"]
)
def test_each_on_match_request_needs_the_capability(client, auth, monkeypatch, route):
    """A manifest that affirms match_without_write is absent refuses up front."""
    _with_capabilities(monkeypatch, drop=("contact.match_without_write",))
    calls = _matching_atlas(monkeypatch, str(uuid.uuid4()))
    name = _name(f"No Match Capability {route}")
    if route == "create":
        response = client.post(
            "/api/admin/customers",
            headers=auth,
            json={"name": name, "idempotencyKey": str(uuid.uuid4())},
        )
    elif route == "reconcile":
        customer_id = int(
            db.execute_returning(
                "INSERT INTO customers (name, active) VALUES (%s, true) RETURNING id",
                (name,),
            )
        )
        response = client.post(
            f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
        )
    else:
        response = client.post(
            "/api/admin/funnel/contacts",
            headers=auth,
            json={
                "contactType": "customer",
                "fullName": name,
                "idempotencyKey": str(uuid.uuid4()),
            },
        )

    assert response.status_code == 501, response.text
    assert response.json()["capability"] == "contact.match_without_write"
    assert calls == []
    assert _reservations(name) == []
    assert db.query_one(
        "SELECT COUNT(*) AS n FROM eom_customer_atlas_reservations "
        "WHERE customer_id IN (SELECT id FROM customers WHERE name = %s)",
        (name,),
    )["n"] == 0


def test_an_unreadable_manifest_still_reserves_with_the_recorded_on_match(
    client, auth, monkeypatch
):
    import requests

    def _explode(*args, **kwargs):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "get", _explode)
    monkeypatch.setattr(api.requests, "post", _explode)
    name = _name("Manifest Unreadable")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 202, response.text
    (reservation,) = _reservations(name)
    assert reservation["atlas_on_match"] == "return"


# --- Retry across the deploy (review test 15) --------------------------------


def _receipt_atlas(monkeypatch, receipts: dict):
    """An Atlas that holds idempotency receipts keyed by Idempotency-Key.

    The same key with the same request replays its receipt; the same key with
    a different request is refused, exactly as Atlas's fingerprint check does.
    """
    calls: list[dict] = []

    def _post(url, *, headers=None, json=None, timeout=None):
        body = dict(json or {})
        key = (headers or {}).get("Idempotency-Key")
        calls.append({"key": key, "json": body})
        stored = receipts.get(key)
        if stored is None:
            contact_id = str(uuid.uuid4())
            receipts[key] = (body, contact_id)
            return _Response(
                201,
                {"success": True, "contactId": contact_id,
                 "operation": "contact_created", "idempotent": False, "contact": {}},
            )
        stored_body, contact_id = stored
        if stored_body != body:
            return _Response(
                409,
                {"detail": "Idempotency-Key already belongs to a different contact mutation"},
            )
        return _Response(
            200,
            {"success": True, "contactId": contact_id,
             "operation": "contact_created", "idempotent": True, "contact": {}},
        )

    monkeypatch.setattr(api.requests, "post", _post)
    return calls


def _employee_id() -> int:
    return int(
        db.query_one("SELECT id FROM employees WHERE name = %s", ("Juan Canfield",))["id"]
    )


def test_a_reservation_from_before_the_contract_retries_its_original_request(
    client, auth, monkeypatch
):
    """Atlas accepted it before slice B; the local finalize failed; now retried.

    The retry must be byte-for-byte the request that Atlas fingerprinted, or
    Atlas refuses the reused key and the Customer is stuck pending forever.
    """
    name = _name("Pre Contract Reservation")
    reservation_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO eom_customer_atlas_reservations (
            id, idempotency_key, request_fingerprint, payload, mode,
            requested_by_employee_id
        )
        VALUES (%s, %s, %s, %s::jsonb, 'create', %s)
        """,
        (reservation_id, key, "0" * 64, f'{{"name": "{name}"}}', _employee_id()),
    )
    # What the pre-slice-B code built and Atlas stored a receipt for.
    original = {
        "full_name": name,
        "contact_type": "customer",
        "source_channel": "time_tracker",
        "source_ref": reservation_id,
    }
    receipts = {key: (original, str(uuid.uuid4()))}
    calls = _receipt_atlas(monkeypatch, receipts)

    response = client.post(
        f"/api/admin/customers/reservations/{reservation_id}/retry", headers=auth
    )

    assert response.status_code == 200, response.text
    assert [call["json"] for call in calls] == [original]
    assert str(_customer(name)["atlas_contact_id"]) == receipts[key][1]


def test_reposting_a_pre_contract_key_is_gated_on_that_reservation(
    client, auth, monkeypatch
):
    """The create route re-drives an existing pending reservation for its key.

    That reservation sends no onMatch, so an Atlas without
    contact.match_without_write can still serve it; refusing it with 501 would
    break the create-replay path 0C supports.
    """
    from time_tracker_api import CustomerCreateRequest

    name = _name("Pre Contract Repost")
    key = str(uuid.uuid4())
    reservation_id = str(uuid.uuid4())
    request = CustomerCreateRequest(name=name, idempotencyKey=key)
    stored = api._customer_atlas_stored_payload(request)
    db.execute(
        """
        INSERT INTO eom_customer_atlas_reservations (
            id, idempotency_key, request_fingerprint, payload, mode,
            requested_by_employee_id
        )
        VALUES (%s, %s, %s, %s::jsonb, 'create', %s)
        """,
        (
            reservation_id,
            key,
            api._customer_atlas_fingerprint(stored, mode="create", customer_id=None),
            api.json.dumps(stored, sort_keys=True),
            _employee_id(),
        ),
    )
    original = {
        "full_name": name,
        "contact_type": "customer",
        "source_channel": "time_tracker",
        "source_ref": reservation_id,
    }
    receipts = {key: (original, str(uuid.uuid4()))}
    _with_capabilities(monkeypatch, drop=("contact.match_without_write",))
    calls = _receipt_atlas(monkeypatch, receipts)

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )

    assert response.status_code == 200, response.text
    assert [call["json"] for call in calls] == [original]
    assert str(_customer(name)["atlas_contact_id"]) == receipts[key][1]


def test_a_new_reservation_sends_return_on_its_first_attempt_and_its_retry(
    client, auth, monkeypatch
):
    import requests

    attempts: list[dict] = []

    def _record_then_fail(url, *, headers=None, json=None, timeout=None):
        attempts.append(dict(json or {}))
        raise requests.RequestException("timed out")

    monkeypatch.setattr(api.requests, "post", _record_then_fail)
    name = _name("New Reservation Retry")
    pending = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert pending.status_code == 202, pending.text
    (reservation,) = _reservations(name)

    calls = _receipt_atlas(monkeypatch, {})
    retried = client.post(
        f"/api/admin/customers/reservations/{reservation['id']}/retry", headers=auth
    )

    assert retried.status_code == 200, retried.text
    assert attempts and attempts[0]["onMatch"] == "return"
    assert all(body == attempts[0] for body in attempts)
    assert [call["json"] for call in calls] == [attempts[0]], (
        "a retry is the same request"
    )


def test_the_recorded_on_match_admits_only_return(client):
    name = _name("Check Constraint")
    with pytest.raises(psycopg2.Error):
        db.execute(
            """
            INSERT INTO eom_customer_atlas_reservations (
                id, idempotency_key, request_fingerprint, payload, mode,
                requested_by_employee_id, atlas_on_match
            )
            VALUES (%s, %s, %s, %s::jsonb, 'create', %s, 'apply')
            """,
            (str(uuid.uuid4()), str(uuid.uuid4()), "0" * 64,
             f'{{"name": "{name}"}}', _employee_id()),
        )
    assert _reservations(name) == []


# --- Leads page ----------------------------------------------------------------


def test_leads_customer_create_matching_a_contact_is_refused_with_it_named(
    client, auth, monkeypatch
):
    matched = str(uuid.uuid4())
    calls = _matching_atlas(monkeypatch, matched, full_name="Held Customer LLC")

    response = client.post(
        "/api/admin/funnel/contacts",
        headers=auth,
        json={
            "contactType": "customer",
            "fullName": "Another Customer Inc",
            "phone": "217-555-0142",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 409, response.text
    refused = response.json()
    assert refused["code"] == "funnel_contact_exists"
    assert refused["details"] == {"contactId": matched, "fullName": "Held Customer LLC"}
    # The portal shows `error` as the message, so it must name the contact.
    assert "Held Customer LLC" in refused["error"]
    assert [call["json"]["onMatch"] for call in calls] == ["return"]


def test_leads_lead_create_and_every_edit_send_no_on_match(client, auth, monkeypatch):
    calls = _matching_atlas(monkeypatch, str(uuid.uuid4()))

    lead = client.post(
        "/api/admin/funnel/contacts",
        headers=auth,
        json={
            "contactType": "lead",
            "fullName": "A New Lead",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )
    edited_id = str(uuid.uuid4())
    edit = client.post(
        "/api/admin/funnel/contacts",
        headers=auth,
        json={
            "contactId": edited_id,
            "contactType": "customer",
            "fullName": "Edited Customer",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert len(calls) == 2, (lead.text, edit.text)
    assert all("onMatch" not in call["json"] for call in calls)


def test_customer_type_change_body_carries_no_on_match():
    body = api._atlas_customer_type_body(str(uuid.uuid4()), "commercial")
    assert "onMatch" not in body
