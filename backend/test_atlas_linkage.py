"""Atlas linkage audit + guarded backfill (issue #54 slice T3a).

The audit is read-only; the backfill only fills NULL links for active
Customers from an explicit operator mapping, guarded by the plan-token /
confirmation-phrase pattern used by the time-data corrections flow.
"""

from __future__ import annotations

import uuid

import pytest

import db

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
