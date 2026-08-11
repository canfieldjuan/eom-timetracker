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


# --- review round 1 findings --------------------------------------------------


def test_an_unsuccessful_echo_never_writes(client, auth, monkeypatch):
    """A 2xx body is not consent. _atlas_funnel_request accepts any dict under
    HTTP 400, so success:false must be rejected by this route, not assumed away.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Unsuccessful", contact, "unknown")

    def _post(url, *, headers=None, json=None, timeout=None):
        return _Response(200, {
            "success": False,
            "contactId": (json or {}).get("contact_id"),
            "contact": {"customerType": "commercial"},
        })

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 502, resp.text
    assert _type_of(customer) == "unknown"


def test_an_echo_about_a_different_contact_never_writes(client, auth, monkeypatch):
    """Mirroring a mismatched echo would copy one account's type onto another."""
    contact = str(uuid.uuid4())
    other_contact = str(uuid.uuid4())
    customer = _customer("Mismatched", contact, "unknown")

    def _post(url, *, headers=None, json=None, timeout=None):
        return _Response(200, {
            "success": True,
            "contactId": other_contact,
            "contact": {"customerType": "commercial"},
        })

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 502, resp.text
    assert _type_of(customer) == "unknown"


def test_a_malformed_contact_id_is_a_502_not_a_500(client, auth, monkeypatch):
    """The validator raises AtlasFunnelRequestError; uncaught it would be a 500."""
    contact = str(uuid.uuid4())
    customer = _customer("Bad Id", contact, "unknown")

    def _post(url, *, headers=None, json=None, timeout=None):
        return _Response(200, {
            "success": True,
            "contactId": "not-a-uuid",
            "contact": {"customerType": "commercial"},
        })

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 502, resp.text
    assert _type_of(customer) == "unknown"


def test_the_write_completes_under_the_row_lock(client, auth, monkeypatch):
    """The mirror UPDATE must run on the locked transaction's cursor.

    The row is held FOR UPDATE by this request's own transaction, so issuing
    the UPDATE on a second pooled connection would block on the lock this very
    request holds. That deadlock shows up as a hang, not a failure, so assert
    the request actually returns and the value landed.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Locked Write", contact, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial"))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 200, resp.text
    assert _type_of(customer) == "commercial"


def test_a_late_response_cannot_clobber_a_newer_transition(client, auth, monkeypatch):
    """The lost update, prevented WITHOUT holding a lock across the Atlas call.

    A reads the row, calls Atlas, and while it is waiting B completes a
    different transition. A must not then write its stale answer over B's.
    Compare-and-set on the value A read makes A fail loudly instead.

    An earlier revision took the row lock before calling Atlas. That was worse
    than the bug: an ordinary customer edit takes the GLOBAL advisory lock
    before waiting on a row, so one blocked same-customer edit would hold the
    global lock and stall unrelated customers and sites.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Racing", contact, "unknown")
    interfered = {"done": False}

    def _post(url, *, headers=None, json=None, timeout=None):
        want = (json or {})["customer_type"]
        if want == "commercial" and not interfered["done"]:
            interfered["done"] = True
            # B lands while A is still waiting on Atlas. Written directly so the
            # test exercises A's staleness check rather than a second HTTP call.
            db.execute(
                "UPDATE customers SET customer_type = %s WHERE id = %s",
                ("residential", customer),
            )
        return _atlas_echoing(want)(url, headers=headers, json=json, timeout=timeout)

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert interfered["done"], "the test must actually interleave a change"
    assert resp.status_code == 409, resp.text
    assert _type_of(customer) == "residential", (
        "the newer transition must survive; a late answer must not clobber it"
    )


def test_a_rolled_back_atlas_is_refused_before_the_mutation(
    client, auth, monkeypatch
):
    """An Atlas that AFFIRMS it lacks the capability is a definite no.

    Both the customer-create and linkage paths gate on this; skipping it here
    would let a partially-deployed or rolled-back Atlas take an operator
    mutation it cannot serve. An UNREADABLE manifest is an outage rather than a
    refusal and must still fall through -- covered by the tests above, which
    use the default stub.
    """
    from conftest import ATLAS_FULL_CAPABILITIES

    contact = str(uuid.uuid4())
    customer = _customer("No Capability", contact, "unknown")
    reduced = [
        value for value in ATLAS_FULL_CAPABILITIES
        if value != "contact.operator_mutation"
    ]
    monkeypatch.setattr(
        api.requests, "get",
        lambda url, **_: _Response(200, {"leads": [], "capabilities": reduced}),
    )
    calls = []
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial", calls=calls))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 501, resp.text
    assert resp.json()["error"] == "atlas_capability_unavailable"
    assert resp.json()["capability"] == "contact.operator_mutation"
    assert calls == [], "no mutation may be attempted once Atlas has refused"
    assert _type_of(customer) == "unknown"
