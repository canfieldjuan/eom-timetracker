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
from datetime import datetime, timedelta, timezone

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


_ATLAS_CLOCK = {"tick": 0}


def _next_atlas_stamp():
    """A monotonically increasing Atlas updated_at, as an ISO string."""
    _ATLAS_CLOCK["tick"] += 1
    base = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=_ATLAS_CLOCK["tick"])).isoformat()


def _atlas_echoing(value, *, calls=None, status=200, updated_at="auto"):
    """Atlas accepts the mutation and echoes a contact carrying `value`.

    updated_at is Atlas's own ordering token. "auto" advances a fake Atlas
    clock per call; pass an explicit ISO string to model an out-of-order
    answer, or None to model a build that reports no version at all.
    """

    def _post(url, *, headers=None, json=None, timeout=None):
        if calls is not None:
            calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        contact = {} if value is None else {"customerType": value}
        if value is not None:
            stamp = _next_atlas_stamp() if updated_at == "auto" else updated_at
            if stamp is not None:
                contact["updatedAt"] = stamp
        body = {
            "success": True,
            "contactId": (json or {}).get("contact_id"),
            "operation": "contact_updated",
            "idempotent": False,
            "contact": contact,
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


def test_a_relink_in_flight_stops_the_mirror_write(client, auth, monkeypatch):
    """Atlas answered about the contact held at read time.

    If the row is repointed while the request is in flight, mirroring that
    answer would write one account's classification onto a customer now linked
    to a different contact. No application path can currently repoint a
    non-NULL link, so this plants the change directly -- the point is that the
    guard does not depend on that invariant holding in some other function.
    """
    contact = str(uuid.uuid4())
    other_contact = str(uuid.uuid4())
    customer = _customer("Relinked", contact, "unknown")
    moved = {"done": False}

    def _post(url, *, headers=None, json=None, timeout=None):
        if not moved["done"]:
            moved["done"] = True
            db.execute(
                "UPDATE customers SET atlas_contact_id = %s WHERE id = %s",
                (other_contact, customer),
            )
        return _atlas_echoing("commercial")(
            url, headers=headers, json=json, timeout=timeout
        )

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert moved["done"], "the test must actually repoint the link"
    assert resp.status_code == 409, resp.text
    assert _type_of(customer) == "unknown", (
        "a type confirmed for the old contact must not land on the new link"
    )


def test_an_aba_transition_is_detected(client, auth, monkeypatch):
    """A value-only compare cannot see an intermediate state.

    From unknown: this request sets Atlas commercial and stalls; two others
    move the row to residential and back to unknown. Comparing values alone
    matches `unknown` again and writes the stale commercial. updated_at moves
    on every write, so the compare fails even when the value returns.
    """
    contact = str(uuid.uuid4())
    customer = _customer("ABA", contact, "unknown")
    churned = {"done": False}

    def _post(url, *, headers=None, json=None, timeout=None):
        if not churned["done"]:
            churned["done"] = True
            # Away and back again, landing on the ORIGINAL value.
            db.execute(
                "UPDATE customers SET customer_type = %s, updated_at = NOW() "
                "WHERE id = %s",
                ("residential", customer),
            )
            db.execute(
                "UPDATE customers SET customer_type = %s, updated_at = NOW() "
                "WHERE id = %s",
                ("unknown", customer),
            )
        return _atlas_echoing("commercial")(
            url, headers=headers, json=json, timeout=timeout
        )

    monkeypatch.setattr(api.requests, "post", _post)
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert churned["done"], "the test must actually churn the row"
    assert resp.status_code == 409, resp.text
    assert _type_of(customer) == "unknown", (
        "the stale answer must not land just because the value returned"
    )


def test_every_customer_sharing_the_contact_is_mirrored(client, auth, monkeypatch):
    """Duplicate links mirror ONE account and must not disagree.

    Postgres permits several customers to share an atlas_contact_id, the
    linkage audit reports those groups, and live ones exist. Updating only the
    requested row would have this route serve two different types for one Atlas
    contact.
    """
    shared = str(uuid.uuid4())
    other = str(uuid.uuid4())
    primary = _customer("Shared A", shared, "unknown")
    twin = _customer("Shared B", shared, "unknown")
    unrelated = _customer("Unrelated", other, "residential")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial"))

    resp = client.patch(_path(primary), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 200, resp.text
    assert _type_of(primary) == "commercial"
    assert _type_of(twin) == "commercial", (
        "a customer sharing the contact still showed the old type"
    )
    assert _type_of(unrelated) == "residential", (
        "a customer on a different contact must not be touched"
    )


def test_the_mirror_write_serializes_on_the_contact(client, auth, monkeypatch):
    """Two customers of ONE contact must not interleave their mirror writes.

    Without a per-contact lock both requests pass their compare-and-set (they
    target different rows) and then fan out over each other, leaving one
    duplicate at each value for a contact that has a single type in Atlas.

    Proven by holding that exact advisory lock from a separate connection and
    showing the request blocks on it, rather than by racing threads and hoping
    the interleaving reproduces.
    """
    import threading
    import psycopg2

    shared = str(uuid.uuid4())
    primary = _customer("Serialized A", shared, "unknown")
    _customer("Serialized B", shared, "unknown")
    monkeypatch.setattr(api.requests, "post", _atlas_echoing("commercial"))

    import os
    blocker = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="disable")
    blocker.autocommit = False
    try:
        with blocker.cursor() as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (api.CUSTOMER_TYPE_MIRROR_LOCK, shared),
            )

            done = {}

            def _attempt():
                try:
                    done["status"] = client.patch(
                        _path(primary), headers=auth,
                        json={"customerType": "commercial"},
                    ).status_code
                except Exception as exc:  # pragma: no cover - diagnostic
                    done["status"] = repr(exc)

            worker = threading.Thread(target=_attempt)
            worker.start()
            worker.join(timeout=3)
            assert worker.is_alive(), (
                "the request did not block on the contact's mirror lock; "
                f"observed={done}"
            )
            assert _type_of(primary) == "unknown", "nothing may be written yet"
        blocker.rollback()  # releases the advisory lock
        worker.join(timeout=15)
        assert not worker.is_alive(), "the request never completed after release"
        assert done.get("status") == 200, done
        assert _type_of(primary) == "commercial"
    finally:
        blocker.close()


def test_an_out_of_order_atlas_answer_never_wins(client, auth, monkeypatch):
    """The winner is Atlas's LAST mutation, not whoever reaches the DB first.

    Two changes can return to this tracker in the opposite order Atlas applied
    them. Serializing locally only fixes commit order, which can disagree with
    Atlas order -- so the mirror could hold `commercial` while Atlas holds
    `residential`. Ordering comes from Atlas's own updated_at.
    """
    contact = str(uuid.uuid4())
    customer = _customer("Out Of Order", contact, "unknown")

    newer = "2026-08-11T12:00:09+00:00"
    older = "2026-08-11T12:00:04+00:00"

    # B lands first locally, carrying Atlas's LATER timestamp.
    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("residential", updated_at=newer))
    assert client.patch(_path(customer), headers=auth,
                        json={"customerType": "residential"}).status_code == 200
    assert _type_of(customer) == "residential"

    # A now arrives late carrying an EARLIER Atlas timestamp. Atlas's final
    # value is still residential, so this must not overwrite it.
    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("commercial", updated_at=older))
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 409, resp.text
    assert _type_of(customer) == "residential", (
        "a stale Atlas answer overwrote a newer one"
    )


def test_a_repeat_of_the_same_atlas_version_is_not_applied_twice(
    client, auth, monkeypatch
):
    """Equal is not newer. A replayed answer must not reopen the decision."""
    contact = str(uuid.uuid4())
    customer = _customer("Same Version", contact, "unknown")
    stamp = "2026-08-11T12:00:07+00:00"

    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("commercial", updated_at=stamp))
    assert client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"}).status_code == 200

    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("residential", updated_at=stamp))
    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "residential"})
    assert resp.status_code == 409, resp.text
    assert _type_of(customer) == "commercial"


def test_an_atlas_without_a_version_still_applies(client, auth, monkeypatch):
    """An older Atlas reports no updatedAt; the route must not stop working.

    No ordering information is not the same as being out of order. The write
    still applies, and the stored token is left as it was rather than cleared.
    """
    contact = str(uuid.uuid4())
    customer = _customer("No Version", contact, "unknown")
    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("commercial", updated_at=None))

    resp = client.patch(_path(customer), headers=auth,
                        json={"customerType": "commercial"})
    assert resp.status_code == 200, resp.text
    assert _type_of(customer) == "commercial"


def test_siblings_carry_the_atlas_version_too(client, auth, monkeypatch):
    """A duplicate must not look staler than it is.

    If the fan-out left the sibling's token behind, a later out-of-order answer
    naming that sibling would compare against a stale value and be applied.
    """
    shared = str(uuid.uuid4())
    primary = _customer("Version A", shared, "unknown")
    twin = _customer("Version B", shared, "unknown")
    stamp = "2026-08-11T12:00:11+00:00"
    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("commercial", updated_at=stamp))

    assert client.patch(_path(primary), headers=auth,
                        json={"customerType": "commercial"}).status_code == 200

    row = db.query_one(
        "SELECT customer_type_source_at FROM customers WHERE id = %s", (twin,)
    )
    assert row["customer_type_source_at"] is not None, (
        "the sibling kept no ordering token and would accept a stale answer"
    )

    # An older answer naming the SIBLING must now be refused.
    monkeypatch.setattr(api.requests, "post",
                        _atlas_echoing("residential",
                                       updated_at="2026-08-11T12:00:05+00:00"))
    resp = client.patch(_path(twin), headers=auth,
                        json={"customerType": "residential"})
    assert resp.status_code == 409, resp.text
    assert _type_of(twin) == "commercial"
