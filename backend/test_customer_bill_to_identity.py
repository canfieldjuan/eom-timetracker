"""Bill-to identity, slice B1: the Customer PATCH saga.

EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md, review items 7-10, 11 (the PATCH
sequences), 13 (serialization), 14 and 16 (PATCH half). Atlas slice A (ATLAS PR 2547) is not deployed, so `FakeAtlas`
below models what it serves: one receipt per Idempotency-Key, replayed before
anything else, and the revision fence (a revision not newer than the stored
one is a 409 with code `stale_identity_revision`).

Several assertions check that a row did NOT change or that Atlas was NOT
called: the guarantees here are as much about what is withheld as what is
written.
"""

from __future__ import annotations

import threading
import uuid

import pytest
import requests

import db
import time_tracker_api as api

PREFIX = "ZZ-BTI"
STALE_DETAIL = {
    "code": "stale_identity_revision",
    "message": "identityRevision is not newer than the contact's bill-to revision",
}


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeAtlas:
    """Atlas slice A, as far as the tracker can observe it."""

    def __init__(self, base_get, base_post):
        self._base_get = base_get
        self._base_post = base_post
        self.bill_to_identity = True
        self.down = False
        self.modes: list[str] = []
        self.contacts: dict[str, dict] = {}
        self.receipts: dict[str, _Response] = {}
        self.posts: list[dict] = []
        self.gets = 0
        self.entered = threading.Event()
        self.release: threading.Event | None = None

    def deliver(self, headers, body):
        key = headers["Idempotency-Key"]
        if key in self.receipts:
            return self.receipts[key]
        contact_id = body["contactId"]
        contact = self.contacts.setdefault(
            contact_id, {"full_name": None, "billing_address": None, "revision": None}
        )
        if contact["revision"] is not None and body["identityRevision"] <= contact["revision"]:
            return _Response(409, {"detail": STALE_DETAIL})
        contact.update(
            full_name=body["full_name"],
            billing_address=body["billing_address"],
            revision=body["identityRevision"],
        )
        self.receipts[key] = _Response(
            201,
            {
                "success": True,
                "contactId": contact_id,
                "operation": "contact_updated",
                "idempotent": False,
                "contact": {"contactId": contact_id, "fullName": body["full_name"]},
            },
        )
        return self.receipts[key]

    def get(self, url, *, headers=None, params=None, timeout=None):
        self.gets += 1
        if self.down:
            raise requests.ConnectionError("Atlas is down")
        response = self._base_get(url, headers=headers, params=params, timeout=timeout)
        body = response.json()
        if self.bill_to_identity and "capabilities" in body:
            body = {**body, "capabilities": [*body["capabilities"], "contact.bill_to_identity"]}
        return _Response(response.status_code, body)

    def post(self, url, *, headers=None, json=None, timeout=None):
        if not str(url).endswith(api.ATLAS_OPERATOR_CONTACTS_PATH) or "contactId" not in (json or {}):
            return self._base_post(url, headers=headers, json=json, timeout=timeout)
        call = {"headers": dict(headers), "json": dict(json)}
        self.posts.append(call)
        if self.release is not None:
            self.entered.set()
            assert self.release.wait(timeout=15)
        mode = self.modes.pop(0) if self.modes else "ok"
        if self.down or mode == "unreachable":
            raise requests.ConnectionError("Atlas is down")
        if mode == "refuse":
            return _Response(409, {"detail": "Archived EOM contacts cannot be edited"})
        response = self.deliver(headers, json)
        if mode == "lost_response":
            raise requests.Timeout("response lost after Atlas applied it")
        return response


@pytest.fixture
def atlas(monkeypatch):
    fake = FakeAtlas(api.requests.get, api.requests.post)
    monkeypatch.setattr(api.requests, "get", fake.get)
    monkeypatch.setattr(api.requests, "post", fake.post)
    return fake


def _clean() -> None:
    db.execute(
        "DELETE FROM eom_customer_identity_reservations WHERE customer_id IN "
        "(SELECT id FROM customers WHERE name LIKE %s)",
        (f"{PREFIX}%",),
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{PREFIX}%",))


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean()
    yield
    _clean()


def _customer(suffix, *, contact=None, billing="1 Bill St, Effingham IL") -> int:
    return db.execute_returning(
        "INSERT INTO customers (name, billing_address, billing_email, atlas_contact_id) "
        "VALUES (%s, %s, 'old@example.test', %s) RETURNING id",
        (f"{PREFIX} {suffix}", billing, contact),
    )


def _row(customer_id):
    return db.query_one(
        "SELECT name, billing_address, billing_email FROM customers WHERE id = %s",
        (customer_id,),
    )


def _reservations(customer_id):
    return db.query_all(
        "SELECT * FROM eom_customer_identity_reservations "
        "WHERE customer_id = %s ORDER BY identity_revision",
        (customer_id,),
    )


def _patch(client, auth, customer_id, **fields):
    return client.patch(f"/api/admin/customers/{customer_id}", headers=auth, json=fields)


def _pending_listed(client, auth):
    response = client.get("/api/admin/customers", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()["pendingIdentityReservations"]


def _linked(suffix="Bill-To", billing="1 Bill St, Effingham IL"):
    contact = str(uuid.uuid4())
    return _customer(suffix, contact=contact, billing=billing), contact


# --- item 7: the happy path ------------------------------------------------


def test_patch_name_change_sends_bill_to_identity_and_applies_after_atlas_confirms(
    client, auth, atlas
):
    customer_id, contact = _linked("Person Name")
    new_name = f"{PREFIX} Milano & Grunloh Engineers"

    # The deployed portal sends every field on every edit.
    response = _patch(
        client, auth, customer_id,
        name=new_name,
        billingAddress="1 Bill St, Effingham IL",
        billingEmail="ap@example.test",
        atlasContactId=contact,
    )

    assert response.status_code == 200, response.text
    assert set(response.json()) == {"success", "customer"}
    assert response.json()["customer"]["name"] == new_name
    [reservation] = _reservations(customer_id)
    assert reservation["state"] == "applied"
    [call] = atlas.posts
    assert call["headers"]["Idempotency-Key"] == str(reservation["idempotency_key"])
    assert call["json"] == {
        "contactId": contact,
        "full_name": new_name,
        "billing_address": "1 Bill St, Effingham IL",
        "identityRevision": reservation["identity_revision"],
        "source_channel": "time_tracker",
        "source_ref": f"bill-to-identity:{contact}",
    }
    assert _row(customer_id) == {
        "name": new_name,
        "billing_address": "1 Bill St, Effingham IL",
        "billing_email": "ap@example.test",
    }
    assert atlas.contacts[contact]["full_name"] == new_name


# --- item 8: Atlas unreachable holds the whole save ---------------------------


def test_atlas_unreachable_holds_the_whole_patch(client, auth, atlas):
    customer_id, contact = _linked("Unreachable")
    before = _row(customer_id)
    atlas.down = True  # the manifest read fails too: an outage, not a refusal

    held = _patch(
        client, auth, customer_id,
        name=f"{PREFIX} Renamed While Down",
        billingAddress="9 New Office Rd",
        billingEmail="new@example.test",
    )

    assert held.status_code == 202, held.text
    assert held.json()["error"] == "customer_atlas_pending"
    assert held.json()["reservation"]["status"] == "atlas_pending"
    assert _row(customer_id) == before, "nothing of the save may apply"
    [listed] = _pending_listed(client, auth)
    assert listed["customerId"] == customer_id
    assert listed["atlasContactId"] == contact
    assert listed["requestedChanges"] == {
        "name": f"{PREFIX} Renamed While Down",
        "billingAddress": "9 New Office Rd",
        "billingEmail": "new@example.test",
    }
    assert contact not in atlas.contacts


# --- item 9: the no-op shortcut -----------------------------------------------


def test_patch_echoing_stored_identity_makes_no_atlas_call(client, auth, atlas):
    customer_id, contact = _linked("Echo")

    response = _patch(
        client, auth, customer_id,
        name=f"{PREFIX} Echo",
        billingAddress="1 Bill St, Effingham IL",
        billingEmail="changed@example.test",
        atlasContactId=contact,
    )

    assert response.status_code == 200, response.text
    assert atlas.posts == [] and atlas.gets == 0, "no Atlas call of any kind"
    assert _reservations(customer_id) == []
    assert _row(customer_id)["billing_email"] == "changed@example.test"


def test_unlinked_customer_rename_keeps_todays_behavior(client, auth, atlas):
    customer_id = _customer("Unlinked")

    response = _patch(client, auth, customer_id, name=f"{PREFIX} Unlinked Renamed")

    assert response.status_code == 200, response.text
    assert _row(customer_id)["name"] == f"{PREFIX} Unlinked Renamed"
    assert atlas.posts == [] and atlas.gets == 0
    assert _reservations(customer_id) == []


# --- item 10: A, B, A ----------------------------------------------------------


def test_name_a_then_b_then_a_sends_distinct_keys_and_rising_revisions(
    client, auth, atlas
):
    customer_id, contact = _linked("Start")

    for name in ("A", "B", "A"):
        response = _patch(client, auth, customer_id, name=f"{PREFIX} {name}")
        assert response.status_code == 200, response.text

    keys = [call["headers"]["Idempotency-Key"] for call in atlas.posts]
    revisions = [call["json"]["identityRevision"] for call in atlas.posts]
    assert len(set(keys)) == 3
    assert revisions == sorted(revisions) and len(set(revisions)) == 3
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} A"
    assert _row(customer_id)["name"] == f"{PREFIX} A"


# --- item 11: the worked sequences --------------------------------------------


def test_revert_after_timed_out_apply_supersedes_the_pending_change(
    client, auth, atlas
):
    customer_id, contact = _linked("A")
    atlas.modes = ["lost_response"]  # Atlas applies B; the answer never arrives

    pending = _patch(client, auth, customer_id, name=f"{PREFIX} B")
    assert pending.status_code == 202, pending.text
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} B"

    # The office saves A, the stored value. With B pending it is not a no-op.
    reverted = _patch(client, auth, customer_id, name=f"{PREFIX} A")

    assert reverted.status_code == 200, reverted.text
    assert [r["state"] for r in _reservations(customer_id)] == ["superseded", "applied"]
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} A"
    assert _row(customer_id)["name"] == f"{PREFIX} A"


def test_refused_replacement_keeps_older_pending_until_a_save_applies(
    client, auth, atlas
):
    customer_id, contact = _linked("A")
    atlas.modes = ["lost_response", "refuse"]

    assert _patch(client, auth, customer_id, name=f"{PREFIX} B").status_code == 202
    refused = _patch(client, auth, customer_id, name=f"{PREFIX} C")

    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "customer_atlas_identity_refused"
    assert [r["state"] for r in _reservations(customer_id)] == ["pending", "refused"]
    [still_pending] = _pending_listed(client, auth)
    assert still_pending["name"] == f"{PREFIX} B"
    assert _row(customer_id)["name"] == f"{PREFIX} A"

    saved = _patch(client, auth, customer_id, name=f"{PREFIX} A")

    assert saved.status_code == 200, saved.text
    states = [r["state"] for r in _reservations(customer_id)]
    assert states == ["superseded", "refused", "applied"]
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} A"
    assert _row(customer_id)["name"] == f"{PREFIX} A"


# --- item 13: two concurrent edits serialize ----------------------------------


def test_concurrent_identity_edits_serialize(client, auth, atlas):
    customer_id, contact = _linked("A")
    atlas.release = threading.Event()
    results: dict[str, int] = {}

    def _save(label):
        results[label] = _patch(client, auth, customer_id, name=f"{PREFIX} {label}").status_code

    first = threading.Thread(target=_save, args=("B",))
    first.start()
    assert atlas.entered.wait(timeout=10), "the first save never reached Atlas"
    second = threading.Thread(target=_save, args=("C",))
    second.start()
    second.join(timeout=2)
    try:
        assert second.is_alive(), "the second save did not wait for the first"
        assert len(atlas.posts) == 1
        assert _reservations(customer_id)[0]["full_name"] == f"{PREFIX} B"
        assert len(_reservations(customer_id)) == 1, "no second reservation yet"
    finally:
        atlas.release.set()
        first.join(timeout=15)
        second.join(timeout=15)

    assert results == {"B": 200, "C": 200}
    b, c = _reservations(customer_id)
    assert (b["full_name"], c["full_name"]) == (f"{PREFIX} B", f"{PREFIX} C")
    assert b["identity_revision"] < c["identity_revision"]
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} C"
    assert _row(customer_id)["name"] == f"{PREFIX} C"


# --- item 14: refusal and readiness -------------------------------------------


def test_atlas_refusal_returns_409_and_applies_nothing(client, auth, atlas):
    customer_id, _ = _linked("Refused")
    before = _row(customer_id)
    atlas.modes = ["refuse"]

    response = _patch(
        client, auth, customer_id,
        name=f"{PREFIX} Never Applied", billingEmail="never@example.test",
    )

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "customer_atlas_identity_refused"
    assert body["details"]["reason"] == "Archived EOM contacts cannot be edited"
    assert _row(customer_id) == before
    assert [r["state"] for r in _reservations(customer_id)] == ["refused"]
    assert _pending_listed(client, auth) == []


def test_missing_capability_returns_501_without_atlas_post(client, auth, atlas):
    customer_id, _ = _linked("No Capability")
    before = _row(customer_id)
    atlas.bill_to_identity = False

    response = _patch(client, auth, customer_id, name=f"{PREFIX} Not Sent")

    assert response.status_code == 501, response.text
    assert response.json()["error"] == "atlas_capability_unavailable"
    assert response.json()["capability"] == "contact.bill_to_identity"
    assert atlas.posts == []
    assert _row(customer_id) == before
    assert _reservations(customer_id) == []


def test_missing_atlas_credentials_returns_503_and_applies_nothing(
    client, auth, atlas, monkeypatch
):
    customer_id, _ = _linked("No Credentials")
    before = _row(customer_id)
    monkeypatch.setattr(api, "ATLAS_FUNNEL_SERVICE_TOKEN", "")

    response = _patch(client, auth, customer_id, name=f"{PREFIX} Not Sent")

    assert response.status_code == 503, response.text
    assert atlas.posts == [] and atlas.gets == 0
    assert _row(customer_id) == before
    assert _reservations(customer_id) == []


# --- item 16: a contact shared by two Customers --------------------------------


def test_shared_contact_refuses_identity_patch_without_atlas_call(client, auth, atlas):
    contact = str(uuid.uuid4())
    first = _customer("Shared One", contact=contact)
    second = _customer("Shared Two", contact=contact)
    rows_before = (_row(first), _row(second))

    renamed = _patch(client, auth, first, name=f"{PREFIX} Shared Renamed")
    readdressed = _patch(client, auth, second, billingAddress="5 Other Ave")

    for response, other in ((renamed, second), (readdressed, first)):
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "customer_atlas_contact_shared"
        assert response.json()["details"]["otherCustomerIds"] == [other]
    assert atlas.posts == [] and atlas.gets == 0
    assert _reservations(first) == [] and _reservations(second) == []
    assert (_row(first), _row(second)) == rows_before


def test_shared_contact_still_applies_identity_neutral_patch(client, auth, atlas):
    contact = str(uuid.uuid4())
    first = _customer("Shared Neutral", contact=contact)
    _customer("Shared Neutral Twin", contact=contact)

    response = _patch(
        client, auth, first,
        name=f"{PREFIX} Shared Neutral", billingEmail="ap@example.test",
    )

    assert response.status_code == 200, response.text
    assert _row(first)["billing_email"] == "ap@example.test"
    assert atlas.posts == []
