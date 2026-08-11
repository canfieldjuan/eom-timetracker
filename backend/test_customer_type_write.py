"""Slice 1 PR3a: a customer's type is changed in Atlas, or not at all.

The guarantee is negative as much as positive. Atlas is the sole write
authority for customer_type; admin_patch_customer refuses it and keeps
refusing it. This route is the one door, and it writes the local mirror ONLY
from what Atlas echoes back -- never from what the operator asked for. Several
tests below assert the local value did not move, because a test that only
checked the happy path would pass against exactly the bug this exists to
prevent: the tracker asserting a classification on its own authority.
"""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api

TEST_PREFIX = "ZZ-TYPEW-TEST"


def _clean_test_rows() -> None:
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{TEST_PREFIX}%",))


import pytest


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


def _customer(suffix, contact_id=None, customer_type="unknown"):
    new_id = db.execute_returning(
        "INSERT INTO customers (name, active, atlas_contact_id, customer_type) "
        "VALUES (%s, TRUE, %s, %s) RETURNING id",
        (f"{TEST_PREFIX} {suffix}", contact_id, customer_type),
    )
    return int(new_id)


def _type_of(customer_id):
    return db.query_one(
        "SELECT customer_type FROM customers WHERE id = %s", (customer_id,)
    )["customer_type"]


def _path(customer_id):
    return f"/api/admin/customers/{customer_id}/customer-type"


def _atlas_echoing(value, *, calls=None, status=200):
    """Atlas accepts the mutation and echoes a contact carrying `value`."""

    def _post(url, *, headers=None, json=None, timeout=None):
        if calls is not None:
            calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        body = {
            "success": True,
            "contactId": (json or {}).get("contact_id"),
            "operation": "contact_updated",
            "idempotent": False,
            "contact": {} if value is None else {"customerType": value},
        }
        return _Response(status, body)

    return _post


# --- the happy path, and what it is allowed to send --------------------------


def test_the_type_atlas_confirms_is_what_gets_mirrored(client, auth, monkeypatch):
    contact = str(uuid.uuid4())
    customer = _customer("Confirmed", contact, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial"))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["customerType"] == "commercial"
    assert body["atlasContactId"] == contact
    assert _type_of(customer) == "commercial"


def test_the_mutation_carries_the_type_and_no_identity_fields(
    client, auth, monkeypatch
):
    """Atlas applies received fields as operator intent.

    Including full_name/email/phone here would rewrite them on the contact as
    a side effect of a type change, and sending them as null would clear them.
    This operation owns exactly one field.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Minimal Body", contact, "unknown")
    calls = []
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("residential", calls=calls))

    client.patch(_path(customer), headers=auth, json={"customerType": "residential"})
    assert len(calls) == 1
    sent = calls[0]["json"]
    assert sent["contact_id"] == contact
    assert sent["customer_type"] == "residential"
    for forbidden in ("full_name", "email", "phone", "address", "city", "state",
                      "zip", "notes"):
        assert forbidden not in sent, f"{forbidden} must not ride along"


def test_atlas_settling_on_a_different_value_wins_and_is_surfaced(
    client, auth, monkeypatch
):
    """Atlas is the authority; a divergence must be visible, not silently hidden."""
    contact = str(uuid.uuid4())
    customer = _customer("Divergent", contact, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("residential"))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["customerType"] == "residential"
    assert body["requestedCustomerType"] == "commercial"
    assert _type_of(customer) == "residential", "the mirror follows Atlas, not the ask"


def test_a_repeated_transition_can_be_applied_again(client, auth, monkeypatch):
    """commercial -> residential -> commercial must all take.

    A content-derived idempotency key would replay the first mutation on the
    third call -- the trap that made plan_token unusable as a batch identity
    in #163. The key is per-request for that reason.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Flip", contact, "commercial")
    keys = []

    def _post(url, *, headers=None, json=None, timeout=None):
        keys.append((headers or {}).get("Idempotency-Key"))
        return _atlas_echoing((json or {})["customer_type"])(
            url, headers=headers, json=json, timeout=timeout
        )

    monkeypatch.setattr(api.requests, "post", _post)
    for want in ("residential", "commercial", "residential"):
        resp = client.patch(_path(customer), headers=auth,
                            json={"customerType": want})
        assert resp.status_code == 200, resp.text
        assert _type_of(customer) == want
    assert len(set(keys)) == 3, "each attempt needs its own idempotency key"


# --- the negative guarantees -------------------------------------------------


def test_an_unlinked_customer_cannot_be_typed(client, auth, monkeypatch):
    """No Atlas contact means no account to classify."""
    customer = _customer("No Link", None, "unknown")
    calls = []
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial", calls=calls))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 409, resp.text
    assert calls == [], "Atlas must not be called for an unlinked customer"
    assert _type_of(customer) == "unknown"


def test_an_unconfirmed_change_is_never_mirrored_locally(client, auth, monkeypatch):
    """Atlas echoed no usable type, so the tracker must not write `requested`.

    Falling back to the requested value would be the tracker asserting a
    classification on its own authority -- the exact divergence this slice
    prevents. If Atlas did apply it, the #2357 refresh reconciles later; a
    wrong local write would not self-heal.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Unconfirmed", contact, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing(None))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 502, resp.text
    assert _type_of(customer) == "unknown"


def test_a_value_atlas_would_refuse_is_not_mirrored(client, auth, monkeypatch):
    contact = str(uuid.uuid4())
    customer = _customer("Bad Echo", contact, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("enterprise"))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 502, resp.text
    assert _type_of(customer) == "unknown"


def test_an_atlas_failure_leaves_the_mirror_alone(client, auth, monkeypatch):
    contact = str(uuid.uuid4())
    customer = _customer("Atlas Down", contact, "commercial")

    def _explode(url, *, headers=None, json=None, timeout=None):
        raise api.requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "residential"})
    # 503 specifically, not merely >= 500: a transport failure must surface as
    # the controlled retryable error, not as an unhandled 500 that happens to
    # satisfy a loose assertion.
    assert resp.status_code == 503, resp.text
    assert _type_of(customer) == "commercial"


def test_an_unsupported_type_is_rejected_before_atlas_is_called(
    client, auth, monkeypatch
):
    contact = str(uuid.uuid4())
    customer = _customer("Bad Request", contact, "unknown")
    calls = []
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial", calls=calls))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "enterprise"})
    assert resp.status_code == 422, resp.text
    assert calls == [], "an invalid request must not reach Atlas"
    assert _type_of(customer) == "unknown"


def test_a_missing_customer_is_a_404(client, auth):
    resp = client.patch(_path(99999999), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 404, resp.text


def test_the_route_requires_an_admin(client, auth, emp_auth):
    contact = str(uuid.uuid4())
    customer = _customer("Authz", contact, "unknown")
    assert client.patch(_path(customer),
                        json={"customerType": "commercial"}).status_code == 401
    assert client.patch(_path(customer), headers=emp_auth,
                        json={"customerType": "commercial"}).status_code == 403
    assert _type_of(customer) == "unknown"


def test_the_generic_patch_still_refuses_the_type(client, auth, monkeypatch):
    """This route is an ADDITIONAL door, not a replacement for the guard.

    If the generic PATCH stopped refusing customer_type, an ordinary customer
    edit could set it locally and bypass Atlas entirely.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Guard Intact", contact, "commercial")
    resp = client.patch(
        f"/api/admin/customers/{customer}",
        headers=auth,
        json={"customerType": "residential"},
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json().get("detail", resp.json())
    assert detail["code"] == "customer_type_system_managed"
    assert _type_of(customer) == "commercial"
