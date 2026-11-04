"""Bill-to identity, slice B2: retry, post-link syncs, and repair.

EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md review items 8 (retry), 11 (the
retry sequences and create), 12, 13 (repair) and 16 (repair, conversion,
post-create sync). `FakeAtlas` is the slice-A model shared with the PATCH
tests; this module adds the 0C create and customer-handoff routes under it.
"""

from __future__ import annotations

import threading
import uuid

import pytest
import requests

import db
import time_tracker_api as api
from conftest import fake_atlas_contact_id
from test_customer_bill_to_identity import (
    PREFIX,
    STALE_DETAIL,
    FakeAtlas,
    _Response,
    _customer,
    _linked,
    _patch,
    _pending_listed,
    _reservations,
    _row,
)


class _OtherRoutes:
    """The 0C create and the customer handoff, recorded, under FakeAtlas."""

    def __init__(self):
        self.creates: list[dict] = []
        self.create_contact: str | None = None  # force create-or-return's match
        self.create_failures = 0
        self.during_create = None
        self.during_handoff = None
        self.handoffs = 0
        self.handoff_failures = 0

    def post(self, url, *, headers=None, json=None, timeout=None):
        url = str(url)
        key = headers["Idempotency-Key"]
        if url.endswith(api.ATLAS_OPERATOR_CONTACTS_PATH):
            self.creates.append(dict(json))
            if self.create_failures:
                self.create_failures -= 1
                raise requests.ConnectionError("Atlas is down")
            if self.during_create is not None:
                self.during_create()
            contact_id = self.create_contact or fake_atlas_contact_id(key)
            return _Response(201, {"success": True, "contactId": contact_id, "contact": {}})
        if url.endswith("/eom-funnel/customer-handoffs"):
            self.handoffs += 1
            if self.handoff_failures:
                self.handoff_failures -= 1
                raise requests.ConnectionError("Atlas is down")
            if self.during_handoff is not None:
                self.during_handoff()
            return _Response(
                201,
                {
                    "success": True,
                    "handoff_id": str(uuid.uuid4()),
                    "contact_id": json["contact_id"],
                    "tracker_customer_id": json["tracker_customer_id"],
                    "tracker_site_id": json["tracker_site_id"],
                    "approval_key": key,
                },
            )
        raise AssertionError(f"unstubbed Atlas call: {url}")


@pytest.fixture
def routes():
    return _OtherRoutes()


@pytest.fixture
def atlas(monkeypatch, routes):
    fake = FakeAtlas(api.requests.get, routes.post)
    monkeypatch.setattr(api.requests, "get", fake.get)
    monkeypatch.setattr(api.requests, "post", fake.post)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    return fake


def _clean() -> None:
    owned = "(SELECT id FROM customers WHERE name LIKE %s)"
    pattern = (f"{PREFIX}%",)
    for table in (
        "eom_customer_identity_reservations",
        "eom_office_conversion_handoffs",
        "eom_customer_atlas_reservations",
        "locations",
    ):
        db.execute(f"DELETE FROM {table} WHERE customer_id IN {owned}", pattern)
    db.execute(
        "DELETE FROM eom_customer_atlas_reservations WHERE payload ->> 'name' LIKE %s",
        pattern,
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", pattern)


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean()
    yield
    _clean()


def _retry(client, auth, reservation_id):
    return client.post(
        f"/api/admin/customers/identity-reservations/{reservation_id}/retry",
        headers=auth,
    )


def _repair(client, auth, customer_id):
    return client.post(f"/api/admin/customers/{customer_id}/atlas-identity", headers=auth)


def _approve(client, auth, contact_id, name):
    suffix = contact_id[:8]
    return client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json={
            "name": name,
            "primaryContactName": "Lead Person",
            "billingAddress": f"{suffix} Billing Office, Effingham IL",
            "atlasContactId": contact_id,
            "idempotencyKey": str(uuid.uuid4()),
            "primarySite": {
                "address": f"{PREFIX} {suffix} Service Site, Effingham IL",
                "locationType": "Commercial",
                "rate": 150.0,
                "rateType": "per_visit",
                "frequency": "Weekly",
                "expectedHours": 2.0,
                "serviceScope": "Offices",
                "serviceStartDate": "2026-12-01",
            },
        },
    )


# --- item 8: retry ---------------------------------------------------------------


def test_retry_applies_a_held_patch_under_the_same_key(client, auth, atlas):
    customer_id, contact = _linked("Held")
    atlas.down = True
    held = _patch(client, auth, customer_id, name=f"{PREFIX} Renamed", billingEmail="n@example.test")
    assert held.status_code == 202, held.text
    atlas.down = False

    retried = _retry(client, auth, held.json()["reservation"]["reservationId"])

    assert retried.status_code == 200, retried.text
    assert retried.json()["idempotent"] is True
    first, second = atlas.posts
    assert second["headers"]["Idempotency-Key"] == first["headers"]["Idempotency-Key"]
    assert second["json"] == first["json"]
    assert _row(customer_id)["name"] == f"{PREFIX} Renamed"
    assert _row(customer_id)["billing_email"] == "n@example.test"
    assert _pending_listed(client, auth) == []
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} Renamed"


# --- item 11: the retry sequences -----------------------------------------------


def test_pending_superseded_by_newer_apply_is_never_retried_and_is_fenced(
    client, auth, atlas
):
    customer_id, contact = _linked("A")
    atlas.modes = ["hold"]  # B's request is still on its way to Atlas

    assert _patch(client, auth, customer_id, name=f"{PREFIX} B").status_code == 202
    assert _patch(client, auth, customer_id, name=f"{PREFIX} C").status_code == 200
    b, c = _reservations(customer_id)
    assert (b["state"], c["state"]) == ("superseded", "applied")
    assert b["identity_revision"] < c["identity_revision"]

    posts_before = len(atlas.posts)
    retried = _retry(client, auth, b["id"])
    assert retried.status_code == 409, retried.text
    assert retried.json()["code"] == "customer_atlas_identity_superseded"
    assert len(atlas.posts) == posts_before, "a superseded change is never sent again"

    [delayed] = atlas.held
    late = atlas.deliver(delayed["headers"], delayed["json"])
    assert late.status_code == 409 and late.json()["detail"] == STALE_DETAIL
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} C"


def test_atlas_stale_revision_closes_the_reservation_as_superseded(client, auth, atlas):
    customer_id, contact = _linked("A")
    atlas.modes = ["unreachable"]
    assert _patch(client, auth, customer_id, name=f"{PREFIX} B").status_code == 202
    [pending] = _reservations(customer_id)
    atlas.contacts[contact] = {
        "full_name": "newer elsewhere",
        "billing_address": None,
        "revision": pending["identity_revision"] + 10,
    }

    retried = _retry(client, auth, pending["id"])

    assert retried.status_code == 409, retried.text
    assert retried.json()["code"] == "customer_atlas_identity_superseded"
    assert _reservations(customer_id)[0]["state"] == "superseded"
    assert _row(customer_id)["name"] == f"{PREFIX} A"


def test_retry_sends_only_the_newest_pending_reservation(client, auth, atlas):
    customer_id, contact = _linked("A")
    atlas.modes = ["unreachable", "unreachable"]
    assert _patch(client, auth, customer_id, name=f"{PREFIX} B").status_code == 202
    assert _patch(client, auth, customer_id, name=f"{PREFIX} C").status_code == 202
    older, newest = _reservations(customer_id)

    refused = _retry(client, auth, older["id"])
    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "customer_atlas_identity_not_newest"
    assert refused.json()["details"]["newestReservationId"] == str(newest["id"])
    assert len(atlas.posts) == 2, "the older reservation was not sent"

    applied = _retry(client, auth, newest["id"])

    assert applied.status_code == 200, applied.text
    assert atlas.posts[-1]["headers"]["Idempotency-Key"] == str(newest["idempotency_key"])
    assert [r["state"] for r in _reservations(customer_id)] == ["superseded", "applied"]
    assert _row(customer_id)["name"] == f"{PREFIX} C"


# --- item 11: create ---------------------------------------------------------------


def test_create_body_omits_billing_address_and_post_link_sync_sends_it(
    client, auth, atlas, routes
):
    name = f"{PREFIX} Created Business"
    key = str(uuid.uuid4())

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": name, "billingAddress": "7 Billing Way", "idempotencyKey": key},
    )

    assert response.status_code == 201, response.text
    assert set(response.json()) == {"success", "customer"}, "the sync applied"
    [create] = routes.creates
    assert "billing_address" not in create and "billingAddress" not in create
    contact = fake_atlas_contact_id(key)
    [sync] = atlas.posts
    assert sync["json"]["contactId"] == contact
    assert sync["json"]["full_name"] == name
    assert sync["json"]["billing_address"] == "7 Billing Way"
    [reservation] = _reservations(response.json()["customer"]["id"])
    assert (reservation["origin"], reservation["state"]) == ("create", "applied")


def test_create_reports_an_unsent_sync_when_atlas_lacks_the_capability(
    client, auth, atlas
):
    atlas.bill_to_identity = False  # Atlas rolled back, or deployed after B

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": f"{PREFIX} Unsynced", "billingAddress": "8 Lost Ln"},
    )

    assert response.status_code == 201, response.text
    sync = response.json()["identitySync"]
    assert (sync["status"], sync["error"]) == ("not_sent", "atlas_capability_unavailable")
    assert sync["details"] == {"capability": "contact.bill_to_identity"}
    assert atlas.posts == []
    assert _reservations(response.json()["customer"]["id"]) == []


def test_create_matching_a_contact_linked_elsewhere_leaves_its_billing_address(
    client, auth, atlas, routes
):
    other_id, contact = _linked("Already Linked", billing="1 Their Office")
    atlas.contacts[contact] = {"full_name": "x", "billing_address": "1 Their Office", "revision": 3}
    routes.create_contact = contact  # Atlas matched the existing contact by email

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": f"{PREFIX} Newcomer", "billingAddress": "9 Mine St",
              "primaryEmail": "shared@example.test", "idempotencyKey": str(uuid.uuid4())},
    )

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_atlas_link_conflict"
    assert atlas.posts == [], "no identity write reached the matched contact"
    assert atlas.contacts[contact]["billing_address"] == "1 Their Office"
    assert db.query_all("SELECT id FROM customers WHERE name = %s", (f"{PREFIX} Newcomer",)) == []
    assert _reservations(other_id) == []


def test_create_retry_and_reconcile_also_sync_after_linking(client, auth, atlas, routes):
    # A create whose first Atlas attempt failed links on retry.
    routes.create_failures = 1
    pending = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": f"{PREFIX} Retried Create", "billingAddress": "3 Retry Rd"},
    )
    assert pending.status_code == 202, pending.text
    reservation_id = pending.json()["reservation"]["reservationId"]
    retried = client.post(f"/api/admin/customers/reservations/{reservation_id}/retry", headers=auth)
    assert retried.status_code == 200, retried.text
    assert "identitySync" not in retried.json()

    # An existing unlinked Customer reconciled through 0C.
    unlinked = _customer("Reconciled", billing="4 Reconcile Ave")
    reconciled = client.post(f"/api/admin/customers/{unlinked}/atlas-contact", headers=auth)
    assert reconciled.status_code == 200, reconciled.text
    assert "identitySync" not in reconciled.json()

    assert [call["json"]["billing_address"] for call in atlas.posts] == [
        "3 Retry Rd",
        "4 Reconcile Ave",
    ]
    assert [r["origin"] for r in _reservations(unlinked)] == ["create"]


# --- item 12: office conversion ---------------------------------------------------


def test_office_conversion_sends_the_customer_bill_to_identity(client, auth, atlas):
    contact = str(uuid.uuid4())
    name = f"{PREFIX} Converted Business"

    response = _approve(client, auth, contact, name)

    assert response.status_code == 201, response.text
    assert "identitySync" not in response.json()
    [sync] = atlas.posts
    assert sync["json"]["contactId"] == contact
    assert sync["json"]["full_name"] == name
    assert sync["json"]["billing_address"] == f"{contact[:8]} Billing Office, Effingham IL"
    assert atlas.contacts[contact]["full_name"] == name


def test_failed_conversion_sync_leaves_a_visible_pending_reservation(client, auth, atlas):
    contact = str(uuid.uuid4())
    atlas.modes = ["unreachable"]

    response = _approve(client, auth, contact, f"{PREFIX} Pending Business")

    assert response.status_code == 201, response.text
    assert response.json()["handoff"]["status"] == "finalized"
    sync = response.json()["identitySync"]
    assert (sync["status"], sync["error"]) == ("pending", "customer_atlas_pending")
    [listed] = _pending_listed(client, auth)
    assert listed["atlasContactId"] == contact
    assert listed["origin"] == "conversion"
    assert listed["name"] == f"{PREFIX} Pending Business"


def test_conversion_snapshot_waits_for_an_in_flight_identity_save(
    client, auth, atlas, routes
):
    contact = str(uuid.uuid4())
    routes.handoff_failures = 1
    first = _approve(client, auth, contact, f"{PREFIX} Converted A")
    assert first.status_code == 202, first.text  # handoff pending; Customer linked
    customer_id = first.json()["handoff"]["customerId"]
    atlas.release = threading.Event()
    results: dict[str, int] = {}

    def _rename():
        results["patch"] = _patch(client, auth, customer_id, name=f"{PREFIX} Converted B").status_code

    def _retry_handoff():
        results["handoff"] = client.post(
            f"/api/admin/funnel/handoffs/{contact}/retry", headers=auth
        ).status_code

    saver = threading.Thread(target=_rename)
    saver.start()
    assert atlas.entered.wait(timeout=10), "the rename never reached Atlas"
    relay = threading.Thread(target=_retry_handoff)
    relay.start()
    relay.join(timeout=1)
    try:
        assert relay.is_alive(), "the conversion waits for the in-flight save"
        assert routes.handoffs == 1, "and makes no Atlas call while it waits"
    finally:
        atlas.release.set()
        saver.join(timeout=15)
        relay.join(timeout=30)

    assert results == {"patch": 200, "handoff": 200}
    renamed, obligation = _reservations(customer_id)
    assert (obligation["origin"], obligation["state"]) == ("conversion", "applied")
    assert obligation["full_name"] == f"{PREFIX} Converted B", "snapshot follows the save"
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} Converted B"
    assert _row(customer_id)["name"] == f"{PREFIX} Converted B"


def _backfill_link(customer_id, contact):
    """The legacy linkage backfill: links the Customer outside the 0C saga."""
    db.execute(
        "UPDATE customers SET atlas_contact_id = %s WHERE id = %s", (contact, customer_id)
    )


def test_reconcile_holds_the_identity_lock_when_a_backfill_links_mid_flight(
    client, auth, atlas, routes
):
    contact = str(uuid.uuid4())
    routes.create_contact = contact
    customer_id = _customer("Reconciled A")
    results: dict[str, int] = {}
    seen: dict[str, int] = {}

    def _rename():
        results["patch"] = _patch(client, auth, customer_id, name=f"{PREFIX} Reconciled B").status_code

    renamer = threading.Thread(target=_rename)

    def _backfill_then_rename():
        # Linked to the same contact while the reconcile waits on Atlas; an
        # office rename of the now-linked Customer follows at once.
        _backfill_link(customer_id, contact)
        renamer.start()
        renamer.join(timeout=1)
        seen["identity_posts_during_reconcile"] = len(atlas.posts)

    routes.during_create = _backfill_then_rename
    try:
        reconciled = client.post(f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth)
    finally:
        if renamer.ident is not None:
            renamer.join(timeout=30)

    assert reconciled.status_code == 200, reconciled.text
    assert "identitySync" not in reconciled.json()
    assert seen == {"identity_posts_during_reconcile": 0}, "the rename waits for the reconcile"
    assert results == {"patch": 200}
    obligation, renamed = _reservations(customer_id)
    assert (obligation["origin"], obligation["full_name"]) == ("create", f"{PREFIX} Reconciled A")
    assert (renamed["origin"], renamed["full_name"]) == ("patch", f"{PREFIX} Reconciled B")
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} Reconciled B"
    assert _row(customer_id)["name"] == f"{PREFIX} Reconciled B"


def test_link_retry_snapshot_waits_for_an_in_flight_identity_save(
    client, auth, atlas, routes
):
    contact = str(uuid.uuid4())
    routes.create_contact = contact
    routes.create_failures = 1
    customer_id = _customer("Relinked A")
    pending = client.post(f"/api/admin/customers/{customer_id}/atlas-contact", headers=auth)
    assert pending.status_code == 202, pending.text
    reservation_id = pending.json()["reservation"]["reservationId"]
    _backfill_link(customer_id, contact)  # the same contact, by another writer
    atlas.release = threading.Event()
    results: dict[str, int] = {}

    def _rename():
        results["patch"] = _patch(client, auth, customer_id, name=f"{PREFIX} Relinked B").status_code

    def _retry_link():
        results["retry"] = client.post(
            f"/api/admin/customers/reservations/{reservation_id}/retry", headers=auth
        ).status_code

    saver = threading.Thread(target=_rename)
    saver.start()
    assert atlas.entered.wait(timeout=10), "the rename never reached Atlas"
    relink = threading.Thread(target=_retry_link)
    relink.start()
    relink.join(timeout=1)
    try:
        assert relink.is_alive(), "the retry waits for the in-flight save"
        assert len(routes.creates) == 1, "and makes no Atlas call while it waits"
    finally:
        atlas.release.set()
        saver.join(timeout=15)
        relink.join(timeout=30)

    assert results == {"patch": 200, "retry": 200}
    renamed, obligation = _reservations(customer_id)
    assert (obligation["origin"], obligation["state"]) == ("create", "applied")
    assert obligation["full_name"] == f"{PREFIX} Relinked B", "snapshot follows the save"
    assert atlas.contacts[contact]["full_name"] == f"{PREFIX} Relinked B"
    assert _row(customer_id)["name"] == f"{PREFIX} Relinked B"


# --- item 13: repair ----------------------------------------------------------------


def test_repair_sends_the_current_identity(client, auth, atlas):
    customer_id, contact = _linked("Milano", billing="12 Engineers Row")

    response = _repair(client, auth, customer_id)

    assert response.status_code == 200, response.text
    assert set(response.json()) == {"success", "customer"}
    [call] = atlas.posts
    assert call["json"]["contactId"] == contact
    assert call["json"]["full_name"] == f"{PREFIX} Milano"
    assert call["json"]["billing_address"] == "12 Engineers Row"
    [reservation] = _reservations(customer_id)
    assert (reservation["origin"], reservation["state"]) == ("repair", "applied")


def test_repair_refuses_an_unlinked_customer(client, auth, atlas):
    customer_id = _customer("Unlinked Repair")

    response = _repair(client, auth, customer_id)

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_atlas_unlinked"
    assert response.json()["details"]["linkPath"] == f"/api/admin/customers/{customer_id}/atlas-contact"
    assert atlas.posts == [] and atlas.gets == 0


# --- item 16: shared contact ----------------------------------------------------------


def test_shared_contact_refuses_repair_and_post_link_sync(client, auth, atlas, routes):
    contact = str(uuid.uuid4())
    first = _customer("Shared Repair", contact=contact)
    second = _customer("Shared Repair Twin", contact=contact)
    before = (_row(first), _row(second))

    repaired = _repair(client, auth, first)

    assert repaired.status_code == 409, repaired.text
    assert repaired.json()["code"] == "customer_atlas_contact_shared"
    assert repaired.json()["details"]["otherCustomerIds"] == [second]
    assert atlas.posts == [] and atlas.gets == 0
    assert _reservations(first) == [] and (_row(first), _row(second)) == before

    # A duplicate that appears while the conversion's handoff is in flight.
    converted = str(uuid.uuid4())
    planted = {}
    routes.during_handoff = lambda: planted.setdefault(
        "id", _customer("Duplicate Holder", contact=converted)
    )

    response = _approve(client, auth, converted, f"{PREFIX} Converted Shared")

    assert response.status_code == 201, response.text
    sync = response.json()["identitySync"]
    assert (sync["status"], sync["error"]) == ("not_sent", "customer_atlas_contact_shared")
    assert sync["details"]["otherCustomerIds"] == [planted["id"]]
    assert atlas.posts == []
    assert _reservations(planted["id"]) == []
    assert _reservations(response.json()["handoff"]["customerId"]) == []


def test_shared_contact_found_at_send_keeps_the_post_create_obligation_pending(
    client, auth, atlas, monkeypatch
):
    key = str(uuid.uuid4())
    contact = fake_atlas_contact_id(key)
    real_drive = api._drive_customer_identity_reservation
    planted = {}

    def _duplicate_then_drive(reservation_id, admin):
        # Linked after the create committed its obligation, before the send.
        planted["id"] = _customer("Late Duplicate", contact=contact)
        return real_drive(reservation_id, admin)

    monkeypatch.setattr(api, "_drive_customer_identity_reservation", _duplicate_then_drive)

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": f"{PREFIX} Created Then Shared", "idempotencyKey": key},
    )

    assert response.status_code == 201, response.text
    sync = response.json()["identitySync"]
    assert (sync["status"], sync["error"]) == ("not_sent", "customer_atlas_contact_shared")
    assert sync["details"]["otherCustomerIds"] == [planted["id"]]
    assert atlas.posts == [], "no Atlas call while the contact is shared"
    [obligation] = _reservations(response.json()["customer"]["id"])
    assert obligation["state"] == "pending", "kept for a retry once the duplicate is resolved"
    assert sync["reservation"]["reservationId"] == str(obligation["id"])


def test_post_create_obligation_survives_a_worker_lost_after_the_link(
    client, auth, atlas, monkeypatch
):
    key = str(uuid.uuid4())
    payload = {"name": f"{PREFIX} Lost Worker", "billingAddress": "6 Durable Dr", "idempotencyKey": key}
    # The worker dies after the link commits, before it sends anything.
    monkeypatch.setattr(api, "_post_link_identity_sync", lambda *args, **kwargs: None)

    created = client.post("/api/admin/customers", headers=auth, json=payload)
    replayed = client.post("/api/admin/customers", headers=auth, json=payload)

    assert created.status_code == 201, created.text
    assert replayed.status_code == 200 and replayed.json()["idempotent"] is True
    assert atlas.posts == []
    [listed] = _pending_listed(client, auth)
    assert (listed["origin"], listed["billingAddress"]) == ("create", "6 Durable Dr")

    retried = client.post(
        f"/api/admin/customers/identity-reservations/{listed['reservationId']}/retry",
        headers=auth,
    )

    assert retried.status_code == 200, retried.text
    assert atlas.contacts[fake_atlas_contact_id(key)]["billing_address"] == "6 Durable Dr"
    assert _pending_listed(client, auth) == []
