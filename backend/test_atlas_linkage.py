"""Atlas linkage audit + guarded backfill (issue #54 slice T3a).

The audit is read-only; the backfill only fills NULL links for active
Customers from an explicit operator mapping, guarded by the plan-token /
confirmation-phrase pattern used by the time-data corrections flow.
"""

from __future__ import annotations

import json
import uuid

import pytest

import db
from time_tracker_api import STALE_CUSTOMER_RESERVATION_MINUTES

TEST_PREFIX = "ZZ-LNK-TEST"

AUDIT_PATH = "/api/admin/audits/atlas-linkage"
PREVIEW_PATH = "/api/admin/corrections/atlas-linkage/preview"
APPLY_PATH = "/api/admin/corrections/atlas-linkage/apply"

REASON = "Backfill legacy customer links for the funnel arc"


def _clean_test_rows() -> None:
    db.execute(
        "DELETE FROM eom_office_conversion_handoffs WHERE customer_id IN "
        "(SELECT id FROM customers WHERE name LIKE %s)",
        (f"{TEST_PREFIX}%",),
    )
    db.execute(
        "DELETE FROM eom_customer_atlas_reservations WHERE customer_id IN "
        "(SELECT id FROM customers WHERE name LIKE %s)",
        (f"{TEST_PREFIX}%",),
    )
    db.execute(
        "DELETE FROM eom_customer_atlas_reservations WHERE payload ->> 'name' LIKE %s",
        (f"{TEST_PREFIX}%",),
    )
    db.execute(
        "DELETE FROM atlas_linkage_backfill_batches WHERE snapshot::text LIKE %s",
        (f"%{TEST_PREFIX}%",),
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", (f"{TEST_PREFIX}%",))


@pytest.fixture(autouse=True)
def clean_rows(client):
    _clean_test_rows()
    yield
    _clean_test_rows()


def _create_customer(suffix: str, atlas_contact_id: str | None = None,
                     active: bool = True) -> int:
    new_id = db.execute_returning(
        "INSERT INTO customers (name, active, atlas_contact_id) "
        "VALUES (%s, %s, %s) RETURNING id",
        (f"{TEST_PREFIX} {suffix}", active, atlas_contact_id),
    )
    return int(new_id)


def _create_handoff(contact_id: str, customer_id: int, site_id: int) -> None:
    db.execute(
        """
        INSERT INTO eom_office_conversion_handoffs (
            atlas_contact_id, idempotency_key, request_fingerprint,
            customer_id, site_id, approved_by_employee_id
        )
        VALUES (%s, %s, %s, %s, %s, 1)
        """,
        (contact_id, str(uuid.uuid4()), "f" * 64, customer_id, site_id),
    )


def _customer_link(customer_id: int) -> str | None:
    row = db.query_one(
        "SELECT atlas_contact_id FROM customers WHERE id = %s", (customer_id,)
    )
    value = row["atlas_contact_id"] if row else None
    return str(value) if value else None


def _mapping(customer_id: int, contact_id: str) -> dict:
    return {"customerId": customer_id, "atlasContactId": contact_id}


def _plan_payload(*entries: dict) -> dict:
    return {"reason": REASON, "mappings": list(entries)}


# -- audit ---------------------------------------------------------------------


def test_audit_requires_admin(client, auth, emp_auth):
    assert client.get(AUDIT_PATH).status_code == 401
    assert client.get(AUDIT_PATH, headers=emp_auth).status_code == 403
    resp = client.get(AUDIT_PATH, headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["databaseReadOnly"] is True
    assert len(body["inventoryFingerprint"]) == 64


def test_audit_surfaces_duplicates_unlinked_and_orphans(client, auth, location_id):
    shared = str(uuid.uuid4())
    dup_a = _create_customer("Dup A", shared)
    dup_b = _create_customer("Dup B", shared)
    unlinked = _create_customer("Unlinked")
    orphan_customer = _create_customer("Orphan", str(uuid.uuid4()))
    orphan_contact = str(uuid.uuid4())
    _create_handoff(orphan_contact, orphan_customer, location_id)

    before = db.query_one("SELECT COUNT(*) AS n FROM customers")["n"]
    body = client.get(AUDIT_PATH, headers=auth).json()
    after = db.query_one("SELECT COUNT(*) AS n FROM customers")["n"]
    assert before == after

    groups = {g["atlasContactId"]: g for g in body["duplicateGroups"]}
    assert shared in groups
    assert set(groups[shared]["customerIds"]) >= {dup_a, dup_b}
    assert groups[shared]["copies"] >= 2

    unlinked_ids = {row["customerId"] for row in body["unlinkedCustomers"]}
    assert unlinked in unlinked_ids
    template_ids = {row["customerId"] for row in body["mappingTemplate"]}
    assert unlinked in template_ids

    orphan_contacts = {row["atlasContactId"] for row in body["handoffOrphans"]}
    assert orphan_contact in orphan_contacts

    summary = body["summary"]
    assert summary["duplicateGroups"] >= 1
    assert summary["unlinkedCustomers"] >= 1
    assert summary["handoffOrphans"] >= 1


# -- backfill happy path ---------------------------------------------------------


def test_backfill_preview_and_apply(client, auth):
    customer = _create_customer("Happy")
    contact = str(uuid.uuid4())

    preview = client.post(
        PREVIEW_PATH, headers=auth, json=_plan_payload(_mapping(customer, contact))
    )
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    assert plan["databaseReadOnly"] is True
    assert len(plan["planToken"]) == 64
    assert plan["confirmationPhrase"] == "LINK 1 CUSTOMER TO ATLAS CONTACTS"
    assert "_archiveSnapshot" not in plan
    assert _customer_link(customer) is None

    apply_resp = client.post(
        APPLY_PATH,
        headers=auth,
        json={
            **_plan_payload(_mapping(customer, contact)),
            "planToken": plan["planToken"],
            "confirmation": plan["confirmationPhrase"],
        },
    )
    assert apply_resp.status_code == 200, apply_resp.text
    applied = apply_resp.json()
    assert applied["success"] is True
    assert applied["linkedCustomerIds"] == [customer]
    assert _customer_link(customer) == contact

    batch = db.query_one(
        "SELECT reason, result FROM atlas_linkage_backfill_batches WHERE id = %s",
        (applied["batchId"],),
    )
    assert batch is not None
    assert batch["reason"] == REASON
    assert batch["result"]["linkedCustomerIds"] == [customer]


# -- backfill rejections ----------------------------------------------------------


def test_backfill_rejects_conflicts(client, auth):
    held = str(uuid.uuid4())
    holder = _create_customer("Holder", held)
    target = _create_customer("Target")
    archived = _create_customer("Archived", active=False)

    taken = client.post(
        PREVIEW_PATH, headers=auth, json=_plan_payload(_mapping(target, held))
    )
    assert taken.status_code == 409
    assert str(holder) in taken.json()["error"]

    already = client.post(
        PREVIEW_PATH,
        headers=auth,
        json=_plan_payload(_mapping(holder, str(uuid.uuid4()))),
    )
    assert already.status_code == 409

    inactive = client.post(
        PREVIEW_PATH,
        headers=auth,
        json=_plan_payload(_mapping(archived, str(uuid.uuid4()))),
    )
    assert inactive.status_code == 400

    other = _create_customer("Other")
    same_contact = str(uuid.uuid4())
    duplicated = client.post(
        PREVIEW_PATH,
        headers=auth,
        json=_plan_payload(
            _mapping(target, same_contact), _mapping(other, same_contact)
        ),
    )
    assert duplicated.status_code == 400

    assert _customer_link(target) is None
    assert _customer_link(other) is None


def test_backfill_rejects_reserved_handoff_contact(client, auth, location_id):
    reserved_contact = str(uuid.uuid4())
    handoff_customer = _create_customer("Handoff", reserved_contact)
    _create_handoff(reserved_contact, handoff_customer, location_id)
    target = _create_customer("Reserved Target")

    resp = client.post(
        PREVIEW_PATH,
        headers=auth,
        json=_plan_payload(_mapping(target, reserved_contact)),
    )
    assert resp.status_code == 409
    assert _customer_link(target) is None


def test_backfill_apply_guards(client, auth, emp_auth):
    customer = _create_customer("Guard")
    contact = str(uuid.uuid4())
    plan = client.post(
        PREVIEW_PATH, headers=auth, json=_plan_payload(_mapping(customer, contact))
    ).json()

    assert client.post(APPLY_PATH, json={}).status_code == 401
    assert (
        client.post(
            APPLY_PATH,
            headers=emp_auth,
            json={
                **_plan_payload(_mapping(customer, contact)),
                "planToken": plan["planToken"],
                "confirmation": plan["confirmationPhrase"],
            },
        ).status_code
        == 403
    )

    wrong_phrase = client.post(
        APPLY_PATH,
        headers=auth,
        json={
            **_plan_payload(_mapping(customer, contact)),
            "planToken": plan["planToken"],
            "confirmation": "LINK EVERYTHING",
        },
    )
    assert wrong_phrase.status_code == 400
    assert _customer_link(customer) is None

    tampered = client.post(
        APPLY_PATH,
        headers=auth,
        json={
            **_plan_payload(_mapping(customer, str(uuid.uuid4()))),
            "planToken": plan["planToken"],
            "confirmation": plan["confirmationPhrase"],
        },
    )
    assert tampered.status_code == 409
    assert _customer_link(customer) is None

    good = client.post(
        APPLY_PATH,
        headers=auth,
        json={
            **_plan_payload(_mapping(customer, contact)),
            "planToken": plan["planToken"],
            "confirmation": plan["confirmationPhrase"],
        },
    )
    assert good.status_code == 200, good.text
    assert _customer_link(customer) == contact

    replay = client.post(
        APPLY_PATH,
        headers=auth,
        json={
            **_plan_payload(_mapping(customer, contact)),
            "planToken": plan["planToken"],
            "confirmation": plan["confirmationPhrase"],
        },
    )
    assert replay.status_code == 409
    assert _customer_link(customer) == contact


# -- reconcile through Atlas (slice 0C) -------------------------------------------


def test_reconcile_clears_a_customer_out_of_the_unlinked_audit(client, auth):
    """The audit is how the backfill of the two live unlinked Customers is proved.

    Reconciling through the canonical path must remove the Customer from
    `unlinkedCustomers`, not merely stamp a column.
    """
    unlinked = _create_customer("Reconcile Me")

    before = client.get(AUDIT_PATH, headers=auth).json()
    assert unlinked in {row["customerId"] for row in before["unlinkedCustomers"]}

    linked = client.post(
        f"/api/admin/customers/{unlinked}/atlas-contact", headers=auth
    )
    assert linked.status_code == 200, linked.text

    after = client.get(AUDIT_PATH, headers=auth).json()
    assert unlinked not in {row["customerId"] for row in after["unlinkedCustomers"]}
    assert _customer_link(unlinked) == linked.json()["customer"]["atlasContactId"]


def test_reconcile_refuses_a_second_concurrent_reservation(client, auth, monkeypatch):
    """One open reservation per Customer, so a double click cannot double-create."""
    import requests as _requests

    import time_tracker_api as api

    def _explode(url, *, headers=None, json=None, timeout=None):
        raise _requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "post", _explode)
    unlinked = _create_customer("Reconcile Twice")

    first = client.post(f"/api/admin/customers/{unlinked}/atlas-contact", headers=auth)
    assert first.status_code == 202, first.text

    second = client.post(f"/api/admin/customers/{unlinked}/atlas-contact", headers=auth)
    assert second.status_code == 409, second.text
    assert second.json()["code"] == "customer_atlas_reservation_open"
    assert _customer_link(unlinked) is None


# -- schema ----------------------------------------------------------------------


def test_schema_migration_idempotent(client):
    import time_tracker_api as api

    api._ensure_schema_migrations()
    api._ensure_schema_migrations()

    table = db.query_one(
        "SELECT to_regclass('atlas_linkage_backfill_batches') AS name"
    )
    assert table["name"] == "atlas_linkage_backfill_batches"
    column = db.query_one(
        """
        SELECT data_type FROM information_schema.columns
        WHERE table_name = 'customers' AND column_name = 'atlas_contact_id'
        """
    )
    assert column is not None and column["data_type"] == "uuid"


# -- stale reservations (slice 0F-T, website #167) ---------------------------


def _pending_reservation(customer_id: int | None, *, minutes_old: int, name: str) -> str:
    reservation_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO eom_customer_atlas_reservations (
            id, idempotency_key, request_fingerprint, payload, mode,
            customer_id, requested_by_employee_id, state, updated_at
        ) VALUES (
            %s, %s, %s, %s::jsonb, %s, %s, 1, 'pending',
            NOW() - make_interval(mins => %s)
        )
        """,
        (
            reservation_id,
            str(uuid.uuid4()),
            "f" * 64,
            json.dumps({"name": name}),
            "link_existing" if customer_id is not None else "create",
            customer_id,
            minutes_old,
        ),
    )
    return reservation_id


def test_audit_reports_only_reservations_nobody_came_back_for(client, auth):
    """A fresh pending reservation is normal; an old one means nobody retried.

    Both directions matter: reporting every pending row would fire on the
    ordinary retryable case the saga is designed around, and reporting none
    would hide a customer the operator believes exists.
    """
    fresh = _pending_reservation(None, minutes_old=1, name=f"{TEST_PREFIX} Fresh")
    stale = _pending_reservation(None, minutes_old=180, name=f"{TEST_PREFIX} Stale")

    body = client.get(AUDIT_PATH, headers=auth).json()
    reported = {row["reservationId"] for row in body["staleReservations"]}

    assert stale in reported, "a reservation pending for hours must surface"
    assert fresh not in reported, "a just-failed reservation is retryable, not stale"
    assert body["summary"]["staleReservations"] >= 1

    entry = next(row for row in body["staleReservations"] if row["reservationId"] == stale)
    assert entry["customerName"] == f"{TEST_PREFIX} Stale"
    assert entry["pendingSince"]


def test_a_finalized_reservation_is_never_stale(client, auth):
    """Age alone is not the signal -- only work still waiting counts."""
    # A finalized row must carry both ids: the schema CHECK from slice 0C
    # refuses to record a completed reservation that links nothing.
    customer_id = _create_customer("Finalized Reservation", str(uuid.uuid4()))
    reservation_id = _pending_reservation(
        customer_id, minutes_old=600, name=f"{TEST_PREFIX} Done"
    )
    db.execute(
        """
        UPDATE eom_customer_atlas_reservations
        SET state = 'finalized', atlas_contact_id = %s, finalized_at = NOW()
        WHERE id = %s
        """,
        (str(uuid.uuid4()), reservation_id),
    )

    body = client.get(AUDIT_PATH, headers=auth).json()
    reported = {row["reservationId"] for row in body["staleReservations"]}
    assert reservation_id not in reported


def test_stale_reservations_are_clean_by_default(client, auth):
    """The signal must be silent on a healthy system, or it is noise."""
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert isinstance(body["staleReservations"], list)
    assert body["summary"]["staleReservations"] == len(body["staleReservations"])


def test_crossing_the_staleness_cutoff_moves_the_inventory_fingerprint(client, auth):
    """A poller watching the fingerprint must not miss a reservation going stale.

    Nothing else about the row changes as it ages, so if the fingerprint is
    built from the older defect classes alone it stays identical across the
    cutoff -- and the consumer that exists to notice this signal is the one
    that never sees it.
    """
    reservation_id = _pending_reservation(
        None, minutes_old=1, name=f"{TEST_PREFIX} Ages"
    )
    before = client.get(AUDIT_PATH, headers=auth).json()
    assert reservation_id not in {
        row["reservationId"] for row in before["staleReservations"]
    }

    # Age the row past the cutoff without touching anything else about it.
    db.execute(
        """
        UPDATE eom_customer_atlas_reservations
        SET updated_at = NOW() - make_interval(mins => %s)
        WHERE id = %s
        """,
        (STALE_CUSTOMER_RESERVATION_MINUTES + 30, reservation_id),
    )

    after = client.get(AUDIT_PATH, headers=auth).json()
    assert reservation_id in {
        row["reservationId"] for row in after["staleReservations"]
    }
    assert after["inventoryFingerprint"] != before["inventoryFingerprint"]
