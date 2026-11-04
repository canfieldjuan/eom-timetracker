"""Bill-to identity, slice B3: one writer for the bill-to name.

EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md review item 15. The single-Site
PATCH and the legacy bulk PUT still rename the owning Customer. For an
Atlas-linked Customer they must refuse a changed `customerName` and apply
nothing from the request; the stored name, and every unlinked Customer, keep
today's behavior. No Site route ever calls Atlas.
"""

from __future__ import annotations

import uuid

import pytest

import db
import time_tracker_api as api

PREFIX = "ZZ-BTI-SITE"


def _clean() -> None:
    db.execute("DELETE FROM locations WHERE address LIKE %s", (f"{PREFIX}%",))
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{PREFIX}%",))


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean()
    yield
    _clean()


@pytest.fixture
def atlas_posts(monkeypatch):
    posts: list[str] = []
    real_post = api.requests.post

    def _post(url, **kwargs):
        posts.append(str(url))
        return real_post(url, **kwargs)

    monkeypatch.setattr(api.requests, "post", _post)
    return posts


def _customer_with_site(suffix, *, linked):
    customer_id = db.execute_returning(
        "INSERT INTO customers (name, atlas_contact_id) VALUES (%s, %s) RETURNING id",
        (f"{PREFIX} {suffix}", str(uuid.uuid4()) if linked else None),
    )
    address = f"{PREFIX} {suffix} Site, Effingham IL"
    site_id = db.execute_returning(
        "INSERT INTO locations (customer_id, address, address_key, customer_name, rate) "
        "VALUES (%s, %s, %s, %s, 100) RETURNING id",
        (customer_id, address, api.normalize_site_address(address), f"{PREFIX} {suffix}"),
    )
    return customer_id, site_id, address


def _state(customer_id, site_id):
    return db.query_one(
        "SELECT c.name, c.updated_at, l.customer_name, l.rate "
        "FROM customers c JOIN locations l ON l.customer_id = c.id "
        "WHERE c.id = %s AND l.id = %s",
        (customer_id, site_id),
    )


def test_site_patch_refuses_changed_customer_name_for_linked_customer(
    client, auth, atlas_posts
):
    customer_id, site_id, _ = _customer_with_site("Linked Patch", linked=True)
    before = _state(customer_id, site_id)

    response = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=auth,
        json={"customerName": f"{PREFIX} Renamed On Site", "rate": 999},
    )

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_identity_edit_required"
    assert response.json()["details"]["customerId"] == customer_id
    assert _state(customer_id, site_id) == before, "no Customer or Site change"
    assert atlas_posts == []


def test_bulk_put_refuses_changed_customer_name_for_linked_customer(
    client, auth, atlas_posts
):
    customer_id, site_id, address = _customer_with_site("Linked Put", linked=True)
    other_id, other_site_id, other_address = _customer_with_site("Other", linked=False)
    before = (_state(customer_id, site_id), _state(other_id, other_site_id))

    response = client.put(
        "/api/admin/locations",
        headers=auth,
        json={
            "locations": [
                {"address": other_address, "rate": 321},
                {"address": address, "customerName": f"{PREFIX} Renamed In Bulk"},
            ]
        },
    )

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "customer_identity_edit_required"
    after = (_state(customer_id, site_id), _state(other_id, other_site_id))
    assert after == before, "the whole request applies nothing, earlier entries included"
    assert atlas_posts == []


def test_site_routes_keep_todays_behavior_for_stored_name_or_unlinked(
    client, auth, atlas_posts
):
    linked_id, linked_site, linked_address = _customer_with_site("Kept", linked=True)
    stored = f"{PREFIX} Kept"

    same_patch = client.patch(
        f"/api/admin/locations/{linked_site}",
        headers=auth,
        json={"customerName": stored, "rate": 150},
    )
    same_put = client.put(
        "/api/admin/locations",
        headers=auth,
        json={"locations": [{"address": linked_address, "customerName": stored}]},
    )

    assert same_patch.status_code == 200, same_patch.text
    assert same_put.status_code == 200, same_put.text
    assert _state(linked_id, linked_site)["rate"] == 150
    assert _state(linked_id, linked_site)["name"] == stored

    unlinked_id, unlinked_site, unlinked_address = _customer_with_site("Free", linked=False)
    renamed = client.patch(
        f"/api/admin/locations/{unlinked_site}",
        headers=auth,
        json={"customerName": f"{PREFIX} Free Renamed"},
    )
    assert renamed.status_code == 200, renamed.text
    assert _state(unlinked_id, unlinked_site)["name"] == f"{PREFIX} Free Renamed"

    bulk_renamed = client.put(
        "/api/admin/locations",
        headers=auth,
        json={"locations": [{"address": unlinked_address, "customerName": f"{PREFIX} Free Again"}]},
    )
    assert bulk_renamed.status_code == 200, bulk_renamed.text
    state = _state(unlinked_id, unlinked_site)
    assert (state["name"], state["customer_name"]) == (f"{PREFIX} Free Again",) * 2
    assert atlas_posts == []
