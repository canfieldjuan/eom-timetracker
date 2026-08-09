"""Slice 0C: a Customer is created through Atlas, or not at all.

The guarantee under test is negative as much as positive: when Atlas cannot be
reached or refuses, there must be NO local Customer -- only a visible,
retryable reservation. Several tests below assert the absence of rows for that
reason; an assertion that only checked the happy path would pass against the
exact bug this slice exists to remove.
"""

from __future__ import annotations

import uuid

import pytest
import requests

import db
import time_tracker_api as api
from conftest import ATLAS_FULL_CAPABILITIES, fake_atlas_contact_id

TEST_PREFIX = "ZZ-0C-TEST"


def _clean_test_rows() -> None:
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
    db.execute(
        "DELETE FROM locations WHERE address LIKE %s", (f"{TEST_PREFIX}%",)
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{TEST_PREFIX}%",))


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean_test_rows()
    yield
    _clean_test_rows()


def _name(suffix: str) -> str:
    return f"{TEST_PREFIX} {suffix}"


def _customer_rows(name: str):
    return db.query_all(
        "SELECT id, name, atlas_contact_id FROM customers WHERE name = %s",
        (name,),
    )


def _reservation_rows(name: str):
    return db.query_all(
        "SELECT * FROM eom_customer_atlas_reservations "
        "WHERE payload ->> 'name' = %s ORDER BY created_at",
        (name,),
    )


def _capture_atlas_posts(monkeypatch, *, responder=None):
    """Record every Atlas POST while keeping the default fake behavior."""
    calls: list[dict] = []
    real_post = api.requests.post

    def _post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        if responder is not None:
            return responder(url=url, headers=headers or {}, json=json or {})
        return real_post(url, headers=headers, json=json, timeout=timeout)

    monkeypatch.setattr(api.requests, "post", _post)
    return calls


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


# --- happy path --------------------------------------------------------------


def test_customer_create_links_the_atlas_contact_atlas_assigned(
    client, auth, monkeypatch
):
    calls = _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Linked Customer")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "primaryEmail": "linked@example.test", "idempotencyKey": key},
    )

    assert response.status_code == 201, response.text
    customer = response.json()["customer"]
    assert customer["atlasContactId"] == fake_atlas_contact_id(key)

    rows = _customer_rows(name)
    assert len(rows) == 1
    assert str(rows[0]["atlas_contact_id"]) == fake_atlas_contact_id(key)

    reservations = _reservation_rows(name)
    assert len(reservations) == 1
    assert reservations[0]["state"] == "finalized"
    assert reservations[0]["customer_id"] == rows[0]["id"]
    assert len(calls) == 1


def test_customer_create_sends_the_agreed_atlas_contract(client, auth, monkeypatch):
    """Tracker half of the cross-repo contract.

    Atlas declares `extra="forbid"` on EOMOperatorContactRequest, so an
    unexpected key here is a 422 in production. This pins the exact body.
    """
    calls = _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Contract Shape")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": name,
            "primaryPhone": "217-555-0142",
            "primaryEmail": "shape@example.test",
            "idempotencyKey": key,
        },
    )
    assert response.status_code == 201, response.text

    call = calls[0]
    assert call["url"].endswith("/eom-funnel/operator-contacts")
    assert call["headers"]["Idempotency-Key"] == key
    assert call["headers"]["Authorization"].startswith("Bearer ")
    assert call["headers"]["X-EOM-Actor-ID"] == "1"

    body = call["json"]
    assert set(body) == {
        "full_name",
        "email",
        "phone",
        "contact_type",
        "source_channel",
        "source_ref",
    }
    assert body["full_name"] == name
    assert body["contact_type"] == "customer"
    assert body["source_channel"] == "time_tracker"
    # sourceRef is the reservation id, which is what makes a replay resolve to
    # the same Atlas contact.
    assert body["source_ref"] == str(_reservation_rows(name)[0]["id"])


def test_customer_create_omits_fields_the_operator_left_blank(
    client, auth, monkeypatch
):
    """A blank field must not be sent as an explicit null.

    Atlas's operator boundary is create-or-return: when it matches an existing
    contact it applies what it receives, so sending `email: null` would CLEAR
    the email of a contact this customer merely matched on phone.
    """
    calls = _capture_atlas_posts(monkeypatch)
    name = _name("Sparse Fields")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 201, response.text
    assert set(calls[0]["json"]) == {
        "full_name",
        "contact_type",
        "source_channel",
        "source_ref",
    }


# --- Atlas unavailable -------------------------------------------------------


def test_atlas_unreachable_creates_no_customer(client, auth, monkeypatch):
    """The acceptance criterion: no local-only canonical Customer, ever."""

    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    name = _name("Atlas Down")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "customer_atlas_pending"
    assert body["reservation"]["status"] == "atlas_pending"
    assert body["reservation"]["lastError"]

    assert _customer_rows(name) == []
    reservations = _reservation_rows(name)
    assert len(reservations) == 1
    assert reservations[0]["state"] == "pending"
    assert reservations[0]["customer_id"] is None
    assert reservations[0]["last_error"]


def test_atlas_identity_conflict_creates_no_customer(client, auth, monkeypatch):
    """Atlas 409 (identity matched multiple contacts) fails visible, not local."""
    _capture_atlas_posts(
        monkeypatch,
        responder=lambda **_: _Response(
            409, {"detail": "Operator contact identity matched multiple contacts"}
        ),
    )
    name = _name("Ambiguous Identity")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 202, response.text
    assert "matched multiple contacts" in response.json()["reservation"]["lastError"]
    assert _customer_rows(name) == []


def test_atlas_response_without_a_contact_id_creates_no_customer(
    client, auth, monkeypatch
):
    _capture_atlas_posts(
        monkeypatch,
        responder=lambda **_: _Response(201, {"success": True, "operation": "contact_created"}),
    )
    name = _name("No Contact Id")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 202, response.text
    assert _customer_rows(name) == []


def test_capability_unavailable_refuses_before_any_write(client, auth, monkeypatch):
    """A partially-deployed Atlas must not leave a Customer or an Atlas call."""
    reduced = [
        name
        for name in ATLAS_FULL_CAPABILITIES
        if name != "contact.operator_mutation"
    ]
    monkeypatch.setattr(
        api.requests,
        "get",
        lambda url, **_: _Response(200, {"leads": [], "capabilities": reduced}),
    )
    calls = _capture_atlas_posts(monkeypatch)
    name = _name("No Capability")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 501, response.text
    assert response.json()["error"] == "atlas_capability_unavailable"
    assert response.json()["capability"] == "contact.operator_mutation"
    assert _customer_rows(name) == []
    assert _reservation_rows(name) == []
    assert calls == []


# --- replay and retry --------------------------------------------------------


def test_replaying_one_key_never_doubles_the_customer(client, auth, monkeypatch):
    calls = _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Replayed")
    payload = {"name": name, "idempotencyKey": key}

    first = client.post("/api/admin/customers", headers=auth, json=payload)
    assert first.status_code == 201, first.text
    second = client.post("/api/admin/customers", headers=auth, json=payload)
    assert second.status_code == 200, second.text
    assert second.json()["idempotent"] is True

    assert second.json()["customer"]["id"] == first.json()["customer"]["id"]
    assert len(_customer_rows(name)) == 1
    assert len(_reservation_rows(name)) == 1
    # The second request short-circuits on the finalized reservation, so Atlas
    # is not asked again at all.
    assert len(calls) == 1


def test_reusing_one_key_with_different_details_fails_closed(client, auth):
    key = str(uuid.uuid4())
    name = _name("Key Reuse")

    first = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert first.status_code == 201, first.text

    second = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": _name("Key Reuse Other"), "idempotencyKey": key},
    )
    assert second.status_code == 409, second.text
    assert second.json()["code"] == "customer_atlas_retry_mismatch"
    assert _customer_rows(_name("Key Reuse Other")) == []


def test_local_failure_after_atlas_success_recovers_against_the_same_contact(
    client, auth, monkeypatch
):
    """Finalization is forward-recoverable, never compensated.

    Atlas has already created the contact when the local write fails. The retry
    re-sends the same key, so Atlas answers with that same contact rather than
    a second one -- which is why no compensating delete is ever needed.
    """
    calls = _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Finalize Fails")

    real_insert = api._insert_customer
    failures = {"count": 0}

    def _flaky_insert(cur, payload, *, atlas_contact_id=None):
        if failures["count"] == 0:
            failures["count"] += 1
            raise RuntimeError("local insert exploded")
        return real_insert(cur, payload, atlas_contact_id=atlas_contact_id)

    monkeypatch.setattr(api, "_insert_customer", _flaky_insert)

    first = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert first.status_code == 202, first.text
    assert _customer_rows(name) == []

    reservation_id = first.json()["reservation"]["reservationId"]
    retry = client.post(
        f"/api/admin/customers/reservations/{reservation_id}/retry",
        headers=auth,
    )

    assert retry.status_code == 200, retry.text
    customer = retry.json()["customer"]
    assert customer["atlasContactId"] == fake_atlas_contact_id(key)
    assert len(_customer_rows(name)) == 1
    # Two Atlas calls, one contact: the second carried the same key.
    assert len(calls) == 2
    assert calls[0]["headers"]["Idempotency-Key"] == key
    assert calls[1]["headers"]["Idempotency-Key"] == key


def test_retrying_a_finalized_reservation_is_idempotent(client, auth):
    key = str(uuid.uuid4())
    name = _name("Retry After Success")
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert created.status_code == 201, created.text
    reservation_id = _reservation_rows(name)[0]["id"]

    retry = client.post(
        f"/api/admin/customers/reservations/{reservation_id}/retry", headers=auth
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["idempotent"] is True
    assert len(_customer_rows(name)) == 1


def test_unknown_reservation_retry_is_not_found(client, auth):
    response = client.post(
        f"/api/admin/customers/reservations/{uuid.uuid4()}/retry", headers=auth
    )
    assert response.status_code == 404, response.text


def test_identical_payloads_without_a_key_stay_distinct_customers(
    client, auth, monkeypatch
):
    """Equal names are normal here (Edward Jones, Mid Illinois are live cases).

    Two unkeyed creates are two operations, not one: collapsing them would
    silently merge two real customers.
    """
    _capture_atlas_posts(monkeypatch)
    name = _name("Same Name Twice")

    first = client.post("/api/admin/customers", headers=auth, json={"name": name})
    second = client.post("/api/admin/customers", headers=auth, json={"name": name})

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["customer"]["id"] != second.json()["customer"]["id"]
    assert len(_customer_rows(name)) == 2


# --- linkage is system-managed ----------------------------------------------


def test_create_refuses_a_caller_supplied_atlas_contact_id(client, auth):
    name = _name("Supplied Link")
    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "atlasContactId": str(uuid.uuid4())},
    )
    assert response.status_code == 422, response.text
    assert response.json()["details"]["fields"] == {"atlasContactId": "system managed"}
    assert _customer_rows(name) == []


def test_patch_cannot_change_the_atlas_link(client, auth):
    name = _name("Patch Link")
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert created.status_code == 201, created.text
    customer = created.json()["customer"]

    response = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={"atlasContactId": str(uuid.uuid4())},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_atlas_link_system_managed"

    stored = _customer_rows(name)[0]
    assert str(stored["atlas_contact_id"]) == customer["atlasContactId"]


def test_patch_cannot_clear_the_atlas_link(client, auth):
    name = _name("Patch Clear Link")
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert created.status_code == 201, created.text
    customer = created.json()["customer"]

    response = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={"atlasContactId": None},
    )
    assert response.status_code == 409, response.text
    assert _customer_rows(name)[0]["atlas_contact_id"] is not None


def test_patch_tolerates_the_portal_echoing_the_stored_link(client, auth):
    """The deployed portal sends every field on every edit, including this one.

    Echoing the stored value must stay a no-op or ordinary customer edits would
    start failing the moment this slice deploys.
    """
    name = _name("Patch Echo")
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert created.status_code == 201, created.text
    customer = created.json()["customer"]

    response = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={
            "primaryContactName": "Echoed Contact",
            "atlasContactId": customer["atlasContactId"],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["customer"]["primaryContactName"] == "Echoed Contact"
    assert response.json()["customer"]["atlasContactId"] == customer["atlasContactId"]


# --- reconcile an existing unlinked Customer ---------------------------------


def _unlinked_customer(name: str) -> int:
    return int(
        db.execute_returning(
            "INSERT INTO customers (name, active) VALUES (%s, true) RETURNING id",
            (name,),
        )
    )


def test_existing_unlinked_customer_is_reconciled_through_the_same_path(
    client, auth, monkeypatch
):
    calls = _capture_atlas_posts(monkeypatch)
    name = _name("Legacy Unlinked")
    customer_id = _unlinked_customer(name)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 200, response.text
    linked = response.json()["customer"]
    assert linked["atlasContactId"]
    assert str(_customer_rows(name)[0]["atlas_contact_id"]) == linked["atlasContactId"]
    assert calls[0]["json"]["full_name"] == name


def test_reconciling_an_already_linked_customer_fails_closed(client, auth):
    name = _name("Already Linked")
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )
    assert created.status_code == 201, created.text
    customer_id = created.json()["customer"]["id"]

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_already_linked"


def test_reconcile_leaves_the_customer_unlinked_when_atlas_is_down(
    client, auth, monkeypatch
):
    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    name = _name("Reconcile Atlas Down")
    customer_id = _unlinked_customer(name)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 202, response.text
    assert _customer_rows(name)[0]["atlas_contact_id"] is None


def test_reconciling_an_unknown_customer_is_not_found(client, auth):
    response = client.post("/api/admin/customers/99999999/atlas-contact", headers=auth)
    assert response.status_code == 404, response.text


# --- visibility --------------------------------------------------------------


def test_pending_reservations_are_visible_on_the_customers_list(
    client, auth, monkeypatch
):
    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    name = _name("Visible Pending")
    client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    listing = client.get("/api/admin/customers", headers=auth)
    assert listing.status_code == 200, listing.text
    body = listing.json()
    pending = [
        row for row in body["pendingAtlasReservations"] if row["customerName"] == name
    ]
    assert len(pending) == 1
    assert pending[0]["status"] == "pending"
    assert pending[0]["customerId"] is None
    assert name not in [customer["name"] for customer in body["customers"]]


def test_a_local_refusal_after_atlas_success_is_recorded_on_the_reservation(
    client, auth, monkeypatch
):
    """A precise refusal keeps its status, but must not leave a blank error.

    A pending reservation with no `lastError` is unactionable: the operator
    sees an entry in the queue and no reason for it.
    """
    _capture_atlas_posts(monkeypatch)
    name = _name("Local Refusal")

    def _refuse(cur, customer_id, customer_name, site_payload):
        api._raise_conflict(
            "duplicate_site_address", "A job site already uses this address", {}
        )

    monkeypatch.setattr(api, "_insert_site", _refuse)

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": name,
            "idempotencyKey": str(uuid.uuid4()),
            "primarySite": {
                "address": f"{TEST_PREFIX} Refusal Road",
                "locationType": "Residential",
                "rateType": "per_visit",
            },
        },
    )

    assert response.status_code == 409, response.text
    assert _customer_rows(name) == []
    reservation = _reservation_rows(name)[0]
    assert reservation["state"] == "pending"
    assert "duplicate_site_address" in reservation["last_error"]
