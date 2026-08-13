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
from time_tracker_api import CustomerCreateRequest
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

    def _flaky_insert(cur, payload, **kwargs):
        # **kwargs on purpose: this fake stands in for the real signature, and
        # pinning its keywords means a new one silently turns every call into a
        # TypeError that the saga reports as a local failure -- the test would
        # then fail for a reason unrelated to what it is checking.
        if failures["count"] == 0:
            failures["count"] += 1
            raise RuntimeError("local insert exploded")
        return real_insert(cur, payload, **kwargs)

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
    # The same re-drive must be labelled the same way whichever endpoint the
    # caller used to reach it.
    assert retry.json()["idempotent"] is True
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


# --- review round 1 (PR #149): outage, response shape, and two races --------


def test_an_unreadable_capability_manifest_still_leaves_a_reservation(
    client, auth, monkeypatch
):
    """A total Atlas outage must not lose the operator's entry.

    The capability read is a fail-fast optimization. When it cannot be read at
    all that is an outage, not a refusal, so the request must still produce the
    documented pending-and-retryable record instead of a bare 503.
    """

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
    assert response.json()["error"] == "customer_atlas_pending"
    assert _customer_rows(name) == []
    reservations = _reservation_rows(name)
    assert len(reservations) == 1
    assert reservations[0]["state"] == "pending"


def test_a_capability_atlas_denies_is_still_refused_without_a_reservation(
    client, auth, monkeypatch
):
    """The opposite side of the boundary above: a definite no writes nothing."""
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
    name = _name("Denied Capability")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 501, response.text
    assert _reservation_rows(name) == []


def test_a_first_time_create_returns_the_legacy_response_shape(client, auth):
    """Existing consumers keep exactly the body they had before slice 0C."""
    key = str(uuid.uuid4())
    name = _name("Legacy Shape")
    payload = {"name": name, "idempotencyKey": key}

    created = client.post("/api/admin/customers", headers=auth, json=payload)
    assert created.status_code == 201, created.text
    assert set(created.json()) == {"success", "customer"}

    # The replay is where an idempotency indicator carries information the
    # status code does not already give.
    replayed = client.post("/api/admin/customers", headers=auth, json=payload)
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["idempotent"] is True


def test_reconcile_sends_the_identity_the_customer_has_when_it_is_locked(
    client, auth, monkeypatch
):
    """A concurrent edit must not be overwritten by a stale snapshot.

    The capability read sits between the route's unlocked pre-check and the
    locked reservation, so editing the Customer during that call reproduces the
    exact gap. Atlas must receive the CURRENT identity, or it would create a
    contact for the old details and link it to the edited Customer.
    """
    name = _name("Renamed Mid Flight")
    renamed = _name("Renamed Mid Flight NEW")
    customer_id = _unlinked_customer(name)
    calls = _capture_atlas_posts(monkeypatch)
    real_get = api.requests.get

    def _get_then_rename(url, **kwargs):
        db.execute(
            "UPDATE customers SET name = %s, primary_phone = %s WHERE id = %s",
            (renamed, "217-555-0777", customer_id),
        )
        return real_get(url, **kwargs)

    monkeypatch.setattr(api.requests, "get", _get_then_rename)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 200, response.text
    assert calls[0]["json"]["full_name"] == renamed
    assert calls[0]["json"]["phone"] == "217-555-0777"


def test_reconcile_refuses_when_another_writer_wins_the_link(
    client, auth, monkeypatch
):
    """Never record a reservation against a contact the Customer does not have.

    The legacy linkage-backfill endpoint takes the same mutation lock and can
    land while the saga is out at Atlas. Finalizing regardless would leave the
    reservation pointing at contact A and the Customer at contact B.
    """
    name = _name("Link Race")
    customer_id = _unlinked_customer(name)
    other_contact = str(uuid.uuid4())
    real_post = api.requests.post

    def _post_then_link(url, **kwargs):
        response = real_post(url, **kwargs)
        db.execute(
            "UPDATE customers SET atlas_contact_id = %s WHERE id = %s",
            (other_contact, customer_id),
        )
        return response

    monkeypatch.setattr(api.requests, "post", _post_then_link)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_atlas_link_conflict"
    # The other writer's link stands, and our reservation stays pending with
    # the reason recorded rather than claiming a link it never made.
    assert str(_customer_rows(name)[0]["atlas_contact_id"]) == other_contact
    reservation = db.query_one(
        "SELECT * FROM eom_customer_atlas_reservations WHERE customer_id = %s",
        (customer_id,),
    )
    assert reservation["state"] == "pending"
    assert "customer_atlas_link_conflict" in reservation["last_error"]


# --- review round 2 (PR #149) ------------------------------------------------


def test_an_unconfigured_tracker_refuses_before_banking_a_reservation(
    client, auth, monkeypatch
):
    """Missing Atlas credentials are a local certainty, not an outage.

    Reserving would bank an operation that can never succeed on any retry, and
    the mutation call raises HTTPException rather than AtlasFunnelRequestError
    for this case, so it escaped as a bare 503 leaving a reason-less pending row.
    """
    monkeypatch.setattr(api, "ATLAS_FUNNEL_SERVICE_TOKEN", "")
    name = _name("Unconfigured")

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 503, response.text
    assert _customer_rows(name) == []
    assert _reservation_rows(name) == []


def test_a_finalized_key_replays_even_after_atlas_withdraws_the_capability(
    client, auth, monkeypatch
):
    """The Customer already exists, so the replay asks nothing of Atlas."""
    key = str(uuid.uuid4())
    name = _name("Replay After Rollback")
    payload = {"name": name, "idempotencyKey": key}

    created = client.post("/api/admin/customers", headers=auth, json=payload)
    assert created.status_code == 201, created.text

    reduced = [
        capability
        for capability in ATLAS_FULL_CAPABILITIES
        if capability != "contact.operator_mutation"
    ]
    monkeypatch.setattr(
        api.requests,
        "get",
        lambda url, **_: _Response(200, {"leads": [], "capabilities": reduced}),
    )

    replayed = client.post("/api/admin/customers", headers=auth, json=payload)
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["idempotent"] is True
    assert replayed.json()["customer"]["id"] == created.json()["customer"]["id"]
    assert len(_customer_rows(name)) == 1


def test_a_failing_attempt_reports_the_success_a_concurrent_one_committed(
    client, auth, monkeypatch
):
    """Do not tell the operator to retry a Customer that now exists.

    Two attempts drive one reservation; the winner finalizes while the loser is
    still failing. The loser's conditional error update matches nothing, which
    is the signal to re-read rather than report a stale pending outcome.
    """
    _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Concurrent Winner")

    # Bank a pending reservation by failing the first attempt.
    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    first = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert first.status_code == 202, first.text
    reservation_id = first.json()["reservation"]["reservationId"]

    # The retry fails at the transport, but a "concurrent" attempt finalizes
    # the very same reservation first.
    def _finalize_then_fail(url, *, headers=None, json=None, timeout=None):
        api._finalize_customer_atlas_reservation(
            reservation_id,
            fake_atlas_contact_id(key),
            CustomerCreateRequest(name=name),
        )
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _finalize_then_fail)
    retry = client.post(
        f"/api/admin/customers/reservations/{reservation_id}/retry", headers=auth
    )

    assert retry.status_code == 200, retry.text
    assert retry.json()["customer"]["atlasContactId"] == fake_atlas_contact_id(key)
    assert len(_customer_rows(name)) == 1


# --- review round 3 (PR #149) ------------------------------------------------


def test_key_reuse_is_refused_even_when_atlas_withdraws_the_capability(
    client, auth, monkeypatch
):
    """Invalid key reuse is a local fact and must not hide behind Atlas state.

    Both answers for an already-completed key are decidable locally, so neither
    should depend on what the deployed Atlas currently serves.
    """
    key = str(uuid.uuid4())
    name = _name("Reuse Under Rollback")

    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert created.status_code == 201, created.text

    reduced = [
        capability
        for capability in ATLAS_FULL_CAPABILITIES
        if capability != "contact.operator_mutation"
    ]
    monkeypatch.setattr(
        api.requests,
        "get",
        lambda url, **_: _Response(200, {"leads": [], "capabilities": reduced}),
    )

    reused = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": _name("Reuse Under Rollback Other"), "idempotencyKey": key},
    )

    assert reused.status_code == 409, reused.text
    assert reused.json()["code"] == "customer_atlas_retry_mismatch"
    assert _customer_rows(_name("Reuse Under Rollback Other")) == []


def test_a_finalizing_create_is_never_missing_from_the_customers_listing(
    client, auth, monkeypatch
):
    """Reservations are read before customers so nothing can fall between them.

    Finalization inserts the Customer and flips the reservation in one
    transaction. The hook below commits it in the gap BETWEEN the listing's two
    reads, which is the exact interleaving that used to return a response
    showing the operation in neither collection.
    """
    _capture_atlas_posts(monkeypatch)
    key = str(uuid.uuid4())
    name = _name("Finalizing Blink")

    # Bank a pending reservation.
    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    pending = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert pending.status_code == 202, pending.text
    reservation_id = pending.json()["reservation"]["reservationId"]

    real_list = api._list_pending_customer_atlas_reservations
    fired = {"done": False}

    def _finalize_then_list(*args, **kwargs):
        if not fired["done"]:
            fired["done"] = True
            api._finalize_customer_atlas_reservation(
                reservation_id,
                fake_atlas_contact_id(key),
                CustomerCreateRequest(name=name),
            )
        return real_list(*args, **kwargs)

    monkeypatch.setattr(
        api, "_list_pending_customer_atlas_reservations", _finalize_then_list
    )

    listing = client.get("/api/admin/customers", headers=auth)
    assert listing.status_code == 200, listing.text
    body = listing.json()

    in_customers = any(customer["name"] == name for customer in body["customers"])
    in_pending = any(
        row["customerName"] == name for row in body["pendingAtlasReservations"]
    )
    # Briefly in both would be acceptable and self-correcting; in neither is not.
    assert in_customers or in_pending


def test_key_reuse_on_a_pending_reservation_is_refused_under_rollback(
    client, auth, monkeypatch
):
    """A key is just as invalid to reuse while its first attempt is unfinished.

    The reservation path that normally catches this sits behind capability
    negotiation, so with the capability withdrawn it never runs.
    """
    key = str(uuid.uuid4())
    name = _name("Pending Reuse")

    def _explode(url, *, headers=None, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    pending = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": key},
    )
    assert pending.status_code == 202, pending.text

    reduced = [
        capability
        for capability in ATLAS_FULL_CAPABILITIES
        if capability != "contact.operator_mutation"
    ]
    monkeypatch.setattr(
        api.requests,
        "get",
        lambda url, **_: _Response(200, {"leads": [], "capabilities": reduced}),
    )

    reused = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": _name("Pending Reuse Other"), "idempotencyKey": key},
    )

    assert reused.status_code == 409, reused.text
    assert reused.json()["code"] == "customer_atlas_retry_mismatch"
    assert _reservation_rows(_name("Pending Reuse Other")) == []


def _atlas_reporting(monkeypatch, contact: dict) -> None:
    """Point the Atlas operator stub at one versioned source contact payload."""
    from conftest import _FakeAtlasResponse  # type: ignore[attr-defined]

    def _post(url, *, headers=None, json=None, timeout=None):
        assert str(url).endswith(api.ATLAS_OPERATOR_CONTACTS_PATH)
        key = (headers or {}).get("Idempotency-Key", "")
        return _FakeAtlasResponse(
            201,
            {
                "success": True,
                "contactId": fake_atlas_contact_id(key),
                "operation": "contact_created",
                "idempotent": False,
                "contact": contact,
            },
        )

    monkeypatch.setattr(api.requests, "post", _post)
    reported_type = contact.get("customerType")
    if reported_type in api.CUSTOMER_TYPES:
        default_get = api.requests.get

        def _get(url, *, headers=None, params=None, timeout=None):
            if "/known-contacts" in str(url):
                submitted = [
                    str(value) for value in (params or {}).get("contact_id") or []
                ]
                return _FakeAtlasResponse(
                    200,
                    {
                        "knownContactIds": submitted,
                        "customerTypes": {value: reported_type for value in submitted},
                        "customerTypeRevisions": {value: 1 for value in submitted},
                        "checked": len(submitted),
                        "limit": 100,
                    },
                )
            return default_get(url, headers=headers, params=params, timeout=timeout)

        monkeypatch.setattr(api.requests, "get", _get)


def _stored_type(name: str) -> str:
    row = db.query_one(
        "SELECT customer_type FROM customers WHERE name = %s", (name,)
    )
    return row["customer_type"]


def _stored_source_revision(name: str):
    row = db.query_one(
        "SELECT customer_type_source_revision FROM customers WHERE name = %s",
        (name,),
    )
    return row["customer_type_source_revision"]


def test_the_mirror_records_the_type_atlas_reported(client, auth, monkeypatch):
    """The whole point: the tracker can see what Atlas decided."""
    name = f"{TEST_PREFIX} Mirror Commercial"
    _atlas_reporting(monkeypatch, {"customerType": "commercial"})

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 201, response.text
    assert _stored_type(name) == "commercial"
    assert _stored_source_revision(name) == 1
    assert response.json()["customer"]["customerType"] == "commercial"


def test_an_atlas_that_does_not_serve_the_field_yields_unknown(client, auth, monkeypatch):
    """Today's production reality, and it must not break a customer create.

    Atlas deploys by hand and lags this tracker. A build predating ATLAS #2354
    simply omits customerType; recording 'unknown' is true, whereas failing the
    create would take the CRM down over a field the mirror does not need.
    """
    name = f"{TEST_PREFIX} Mirror Absent"
    _atlas_reporting(monkeypatch, {})

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 201, response.text
    assert _stored_type(name) == "unknown"


def test_a_value_atlas_would_refuse_is_not_mirrored(client, auth, monkeypatch):
    """The mirror must never hold a classification the source of truth rejects."""
    name = f"{TEST_PREFIX} Mirror Bogus"
    _atlas_reporting(monkeypatch, {"customerType": "platinum"})

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 201, response.text
    assert _stored_type(name) == "unknown"


def test_the_tracker_refuses_to_edit_the_type_but_tolerates_an_echo(client, auth, monkeypatch):
    """System-managed, exactly like the Atlas contact link.

    An echo has to stay a no-op because the deployed portal round-trips the
    whole record on every edit. A real change is refused loudly rather than
    dropped: a silent discard would read as a successful edit that did nothing,
    and billing shape follows from this value.
    """
    name = f"{TEST_PREFIX} Mirror Locked"
    _atlas_reporting(monkeypatch, {"customerType": "commercial"})
    created = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "idempotencyKey": str(uuid.uuid4())},
    ).json()["customer"]

    echo = client.patch(
        f"/api/admin/customers/{created['id']}",
        headers=auth,
        json={
            "customerType": "commercial",
            "expectedUpdateToken": created["updateToken"],
        },
    )
    assert echo.status_code == 200, echo.text

    refreshed = client.get(f"/api/admin/customers/{created['id']}", headers=auth).json()
    changed = client.patch(
        f"/api/admin/customers/{created['id']}",
        headers=auth,
        json={
            "customerType": "residential",
            "expectedUpdateToken": refreshed["customer"]["updateToken"],
        },
    )
    assert changed.status_code == 409, changed.text
    body = changed.json()
    detail = body.get("detail", body)
    assert detail["code"] == "customer_type_system_managed"
    assert detail["details"]["customerType"] == "commercial"
    assert _stored_type(name) == "commercial", "the refusal must not have written"


def test_reconciling_an_existing_customer_mirrors_the_type_too(
    client, auth, monkeypatch
):
    """The link_existing branch must mirror, not just link.

    Reconciliation runs the same reservation flow as a create and receives the
    same Atlas response, but it updates an existing row rather than inserting
    one. Wiring only the insert leaves every legacy customer reconciled through
    this supported path sitting at the migration default while Atlas has
    already said what it is -- and the API then serves that wrong value.
    """
    name = _name("Reconcile Mirrors Type")
    customer_id = _unlinked_customer(name)
    _atlas_reporting(monkeypatch, {"customerType": "commercial"})

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 200, response.text
    assert _stored_type(name) == "commercial"
    assert response.json()["customer"]["customerType"] == "commercial"


def test_reconciling_against_an_older_atlas_leaves_the_type_alone(
    client, auth, monkeypatch
):
    """No reported type must not clobber a type already mirrored.

    COALESCE, not assignment: an Atlas build that predates ATLAS #2354 reports
    nothing, and overwriting a known classification with 'unknown' would make
    reconciliation destructive.
    """
    name = _name("Reconcile Keeps Type")
    customer_id = _unlinked_customer(name)
    db.execute(
        "UPDATE customers SET customer_type = 'residential' WHERE id = %s",
        (customer_id,),
    )
    _atlas_reporting(monkeypatch, {})

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 200, response.text
    assert _stored_type(name) == "residential"


def test_a_concurrent_link_to_the_same_contact_still_mirrors_the_type(
    client, auth, monkeypatch
):
    """Losing a race must not cost the classification.

    The linkage-backfill endpoint can link the same customer while the Atlas
    call is in flight; it sets only atlas_contact_id. The finalizer's
    conditional UPDATE then matches nothing, and because the winner linked the
    SAME contact there is no conflict to raise -- so without an explicit apply
    the type Atlas just reported is dropped and the customer keeps 'unknown'
    purely because of who won.
    """
    from conftest import _FakeAtlasResponse  # type: ignore[attr-defined]

    name = _name("Race Keeps Type")
    customer_id = _unlinked_customer(name)

    def _post_then_link(url, *, headers=None, json=None, timeout=None):
        assert str(url).endswith(api.ATLAS_OPERATOR_CONTACTS_PATH)
        key = (headers or {}).get("Idempotency-Key", "")
        contact_id = fake_atlas_contact_id(key)
        # The backfill wins the race, linking the SAME contact and setting
        # only atlas_contact_id -- exactly what that endpoint does.
        db.execute(
            "UPDATE customers SET atlas_contact_id = %s WHERE id = %s "
            "AND atlas_contact_id IS NULL",
            (contact_id, customer_id),
        )
        return _FakeAtlasResponse(
            201,
            {
                "success": True,
                "contactId": contact_id,
                "operation": "contact_created",
                "idempotent": False,
                "contact": {"customerType": "commercial"},
            },
        )

    monkeypatch.setattr(api.requests, "post", _post_then_link)
    default_get = api.requests.get

    def _get_versioned_source(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(value) for value in (params or {}).get("contact_id") or []]
            return _FakeAtlasResponse(
                200,
                {
                    "knownContactIds": submitted,
                    "customerTypes": {value: "commercial" for value in submitted},
                    "customerTypeRevisions": {value: 1 for value in submitted},
                    "checked": len(submitted),
                    "limit": 100,
                },
            )
        return default_get(url, headers=headers, params=params, timeout=timeout)

    monkeypatch.setattr(api.requests, "get", _get_versioned_source)

    response = client.post(
        f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth
    )

    assert response.status_code == 200, response.text
    assert _stored_type(name) == "commercial", (
        "the reported type must survive losing the link race"
    )
    assert _stored_source_revision(name) == 1


def test_customer_type_source_revision_is_nullable_positive_bigint():
    """The local source-order watermark preserves legacy rows safely."""
    column = db.query_one(
        """
        SELECT data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'customers'
          AND column_name = 'customer_type_source_revision'
        """
    )
    assert column == {"data_type": "bigint", "is_nullable": "YES"}
    constraint = db.query_one(
        """
        SELECT pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conname = 'chk_customers_customer_type_source_revision'
          AND conrelid = 'customers'::regclass
        """
    )
    assert constraint is not None
    assert "customer_type_source_revision > 0" in constraint["definition"]


def test_the_check_constraint_is_generated_from_the_tuple():
    """One tracker-side source, proven at the database.

    The accepted set is written once as CUSTOMER_TYPES and the CHECK is built
    from it. Asserting the constraint's actual definition -- rather than that
    the interpolation exists -- is what proves the two cannot drift.
    """
    definition = db.query_one(
        """
        SELECT pg_get_constraintdef(oid) AS def
        FROM pg_constraint
        WHERE conname = 'chk_customers_customer_type'
          AND conrelid = 'customers'::regclass
        """
    )
    assert definition is not None, "the CHECK must exist"
    rendered = definition["def"]
    for value in api.CUSTOMER_TYPES:
        assert f"'{value}'" in rendered, f"{value} missing from the CHECK"
    # Exact membership, tested by behaviour rather than by counting casts.
    # Counting "::text" proved nothing: a constraint that also permitted
    # 'platinum' would not necessarily add one, so the assertion passed for
    # constraints it should have rejected.
    import re as _re

    assert set(_re.findall(r"'([^']*)'", rendered)) == set(api.CUSTOMER_TYPES)

    row = db.query_one(
        "INSERT INTO customers (name) VALUES (%s) RETURNING id",
        (f"{TEST_PREFIX} Check Probe",),
    )
    with pytest.raises(Exception) as caught:
        db.execute(
            "UPDATE customers SET customer_type = 'platinum' WHERE id = %s",
            (row["id"],),
        )
    assert "chk_customers_customer_type" in str(caught.value)


def test_the_check_is_rebuilt_when_the_type_set_changes(monkeypatch):
    """A create-once guard would pin production to the old set.

    CUSTOMER_TYPES is expected to gain a value when Atlas adds one. If the
    constraint were only created when absent, the deployed CHECK would stay on
    the old set: the parser would accept the new value and the INSERT would
    then violate a stale constraint, rejecting local finalization AFTER Atlas
    had created the contact.
    """
    def _definition() -> str:
        return db.query_one(
            """
            SELECT pg_get_constraintdef(oid) AS def
            FROM pg_constraint
            WHERE conname = 'chk_customers_customer_type'
              AND conrelid = 'customers'::regclass
            """
        )["def"]

    assert "prospective" not in _definition()

    monkeypatch.setattr(
        api, "CUSTOMER_TYPES", api.CUSTOMER_TYPES + ("prospective",)
    )
    try:
        api._ensure_schema_migrations()
        rebuilt = _definition()
        assert "prospective" in rebuilt, (
            "the constraint must follow the tuple, not the first deployment"
        )
    finally:
        monkeypatch.undo()
        api._ensure_schema_migrations()

    assert "prospective" not in _definition(), "and back again when it shrinks"


def test_an_unchanged_type_set_issues_no_ddl_at_startup():
    """A deploy must not take an exclusive lock for nothing.

    Dropping and re-adding the CHECK on every boot revalidates every row under
    an exclusive table lock, which can block live traffic during a deploy. The
    bootstrap compares the deployed literals against CUSTOMER_TYPES first and
    only issues DDL when they actually differ.
    """
    before = db.query_one(
        """
        SELECT oid, pg_get_constraintdef(oid) AS def
        FROM pg_constraint
        WHERE conname = 'chk_customers_customer_type'
          AND conrelid = 'customers'::regclass
        """
    )

    api._ensure_schema_migrations()

    after = db.query_one(
        """
        SELECT oid, pg_get_constraintdef(oid) AS def
        FROM pg_constraint
        WHERE conname = 'chk_customers_customer_type'
          AND conrelid = 'customers'::regclass
        """
    )
    # A rebuild would give the constraint a new oid; an untouched one keeps it.
    assert after["oid"] == before["oid"], (
        "an unchanged type set must not drop and re-add the constraint"
    )
