"""Atlas linkage audit + guarded backfill (issue #54 slice T3a).

The audit is read-only; the backfill only fills NULL links for active
Customers from an explicit operator mapping, guarded by the plan-token /
confirmation-phrase pattern used by the time-data corrections flow.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

import db
from time_tracker_api import (
    STALE_CUSTOMER_RESERVATION_MINUTES,
    _ATLAS_FUNNEL_READ_PATHS,
    _KNOWN_CONTACTS_PATH,
)

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
    db.execute(
        "DELETE FROM customer_type_refresh_batches WHERE snapshot::text LIKE %s",
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


# -- dangling Atlas links (link verification, website #167 / ATLAS #2352) --------


class _Resp:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self) -> dict:
        return self._body


def _known_contacts_except(omit_ids):
    """A requests.get replacement: Atlas knows every submitted id EXCEPT these.

    Patched over the autouse stub for one test, so a planted customer whose
    atlas_contact_id is in omit_ids reads back as a link Atlas does not resolve.
    """
    omit = {str(value) for value in omit_ids}

    def _get(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(value) for value in (params or {}).get("contact_id") or []]
            known = [value for value in submitted if value not in omit]
            return _Resp(200, {"knownContactIds": known, "checked": len(submitted), "limit": 100})
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None, "capabilities": []})

    return _get


def test_dangling_link_detected_when_atlas_does_not_resolve_the_id(client, auth, monkeypatch):
    import time_tracker_api as api

    good_contact = str(uuid.uuid4())
    dead_contact = str(uuid.uuid4())
    good_customer = _create_customer("Link Resolves", good_contact)
    dangling_customer = _create_customer("Link Dangles", dead_contact)
    # A NULL-linked customer must NOT be reported here -- that is a different class.
    null_customer = _create_customer("No Link At All")
    monkeypatch.setattr(api.requests, "get", _known_contacts_except([dead_contact]))

    before = db.query_one("SELECT COUNT(*) AS n FROM customers")["n"]
    resp = client.get(AUDIT_PATH, headers=auth)
    after = db.query_one("SELECT COUNT(*) AS n FROM customers")["n"]
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["databaseReadOnly"] is True
    assert before == after

    dangling = {row["customerId"]: row for row in body["danglingLinks"]}
    assert dangling_customer in dangling
    assert dangling[dangling_customer]["atlasContactId"] == dead_contact
    assert good_customer not in dangling
    assert null_customer not in dangling  # a missing link != a dangling link
    assert body["summary"]["danglingLinks"] >= 1
    assert body["atlasLinkVerification"]["status"] == "ok"
    # The NULL-linked customer is still reported by the existing signal.
    assert null_customer in {row["customerId"] for row in body["unlinkedCustomers"]}


def test_dangling_links_clean_when_atlas_resolves_every_link(client, auth):
    # Default autouse stub: Atlas recognizes every submitted id.
    linked = _create_customer("All Resolve", str(uuid.uuid4()))
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert linked not in {row["customerId"] for row in body["danglingLinks"]}
    assert body["summary"]["danglingLinks"] == 0
    assert body["atlasLinkVerification"]["status"] == "ok"


def test_atlas_outage_degrades_verification_without_failing_the_audit(client, auth, monkeypatch):
    import time_tracker_api as api
    import requests as _requests

    _create_customer("Linked During Outage", str(uuid.uuid4()))
    unlinked = _create_customer("Unlinked During Outage")

    def _boom(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            raise _requests.RequestException("atlas unreachable")
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _boom)

    resp = client.get(AUDIT_PATH, headers=auth)
    assert resp.status_code == 200, resp.text  # the audit itself must not fail
    body = resp.json()
    # Fail loud, not clean: verification is flagged and the list is withheld.
    assert body["atlasLinkVerification"]["status"] == "unavailable"
    assert body["atlasLinkVerification"]["error"]
    assert body["danglingLinks"] == []
    # The database-only signals are unaffected by an Atlas outage.
    assert unlinked in {row["customerId"] for row in body["unlinkedCustomers"]}


def test_a_dangling_link_moves_the_inventory_fingerprint(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    _create_customer("Fingerprint Subject", contact)
    clean_fp = client.get(AUDIT_PATH, headers=auth).json()["inventoryFingerprint"]

    monkeypatch.setattr(api.requests, "get", _known_contacts_except([contact]))
    dangling_fp = client.get(AUDIT_PATH, headers=auth).json()["inventoryFingerprint"]

    # A customer going dangling must move the change token, or a poller keyed on
    # the fingerprint would sleep through a link that resolves to nothing.
    assert clean_fp != dangling_fp


def test_incomplete_atlas_response_degrades_to_unavailable(client, auth, monkeypatch):
    import time_tracker_api as api

    _create_customer("Incomplete Response Subject", str(uuid.uuid4()))

    def _incomplete(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            # A 200 that omits knownContactIds -- a schema drift or truncation.
            return _Resp(200, {"checked": 0, "limit": 100})
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _incomplete)

    body = client.get(AUDIT_PATH, headers=auth).json()
    # A malformed response must NOT flag every link as dangling.
    assert body["danglingLinks"] == []
    assert body["summary"]["danglingLinks"] == 0
    assert body["atlasLinkVerification"]["status"] == "unavailable"
    assert body["atlasLinkVerification"]["error"]


def test_verification_status_is_recorded_in_the_audit_log(client, auth, monkeypatch):
    import time_tracker_api as api
    import requests as _requests

    _create_customer("Log Status Subject", str(uuid.uuid4()))

    def _boom(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            raise _requests.RequestException("atlas unreachable")
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _boom)

    client.get(AUDIT_PATH, headers=auth)
    row = db.query_one(
        "SELECT reason FROM access_log_entries WHERE action = %s "
        "ORDER BY logged_at DESC, id DESC LIMIT 1",
        ("ATLAS_LINKAGE_AUDIT",),
    )
    assert row is not None
    # The durable record must distinguish "could not verify" from a clean audit.
    assert "atlasVerify=unavailable" in row["reason"]


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


def _pending_reservation(
    customer_id: int | None,
    *,
    minutes_old: int,
    name: str,
    created_minutes_old: int | None = None,
    reservation_id: str | None = None,
) -> str:
    """Seed a pending reservation.

    ``minutes_old`` ages ``updated_at`` (the last attempt, which drives the
    staleness cutoff); ``created_minutes_old`` ages ``created_at``
    independently, so a test can tell the two apart. It defaults to the same
    age, which is what an untouched reservation looks like.
    """
    reservation_id = reservation_id or str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO eom_customer_atlas_reservations (
            id, idempotency_key, request_fingerprint, payload, mode,
            customer_id, requested_by_employee_id, state, created_at, updated_at
        ) VALUES (
            %s, %s, %s, %s::jsonb, %s, %s, 1, 'pending',
            NOW() - make_interval(mins => %s),
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
            minutes_old if created_minutes_old is None else created_minutes_old,
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


def test_pending_since_survives_a_retry_that_failed(client, auth):
    """How long the customer has been missing, not when we last tried.

    `_note_customer_atlas_error` advances `updated_at` on every failed retry.
    Reporting that as `pendingSince` would make a reservation stuck since
    yesterday look minutes old -- the audit would understate exactly the
    reservations that have been ignored longest.
    """
    reservation_id = _pending_reservation(
        None,
        minutes_old=90,
        created_minutes_old=600,
        name=f"{TEST_PREFIX} Retried",
    )

    body = client.get(AUDIT_PATH, headers=auth).json()
    entry = next(
        row
        for row in body["staleReservations"]
        if row["reservationId"] == reservation_id
    )

    pending_since = datetime.fromisoformat(entry["pendingSince"].replace("Z", "+00:00"))
    updated_at = datetime.fromisoformat(entry["updatedAt"].replace("Z", "+00:00"))
    age_minutes = (datetime.now(timezone.utc) - pending_since).total_seconds() / 60

    assert age_minutes > 300, (
        "pendingSince must report creation, not the last failed attempt"
    )
    assert updated_at > pending_since, "the retry is more recent than the start"


def test_a_never_attempted_reservation_claims_no_attempt(client, auth):
    """The audit must not invent an attempt that never happened.

    `updated_at` defaults to NOW() at insert and the reservation commits
    before Atlas is called, so a row that died in that window carries a
    timestamp having never been attempted. Reporting it as a last-attempt time
    would tell the operator a call was made when none was.
    """
    reservation_id = _pending_reservation(
        None, minutes_old=200, name=f"{TEST_PREFIX} Untried"
    )

    body = client.get(AUDIT_PATH, headers=auth).json()
    entry = next(
        row
        for row in body["staleReservations"]
        if row["reservationId"] == reservation_id
    )

    assert "lastAttemptAt" not in entry, (
        "updated_at is 'last touched', not proof an attempt was made"
    )
    assert entry["updatedAt"], "the staleness clock's reference must still be reported"
    assert entry["lastError"] is None, "nothing was attempted, so nothing failed"


def test_reservations_sharing_an_updated_at_hash_the_same_way(client, auth):
    """Unchanged inventory must not churn the fingerprint.

    `updated_at` alone does not order rows: a multi-row update gives several
    reservations the same value, and PostgreSQL is then free to return them in
    any order. Since the list order feeds the fingerprint, that would make
    identical inventory hash differently between polls and report change that
    did not happen.
    """
    shared_age = 240
    # Ids chosen so id-order and insertion-order disagree, which is what an
    # unstable sort would expose.
    first = _pending_reservation(
        None,
        minutes_old=shared_age,
        name=f"{TEST_PREFIX} TieB",
        reservation_id="ffffffff-0000-4000-8000-000000000002",
    )
    second = _pending_reservation(
        None,
        minutes_old=shared_age,
        name=f"{TEST_PREFIX} TieA",
        reservation_id="ffffffff-0000-4000-8000-000000000001",
    )
    # Each INSERT gets its own NOW(), so the rows differ by microseconds and
    # there is no tie to break. Force the collision a multi-row update would
    # produce, which is the case the tie-breaker exists for.
    db.execute(
        """
        UPDATE eom_customer_atlas_reservations
        SET updated_at = NOW() - make_interval(mins => %s)
        WHERE id IN (%s, %s)
        """,
        (shared_age, first, second),
    )

    fingerprints = set()
    orders = set()
    for _ in range(6):
        body = client.get(AUDIT_PATH, headers=auth).json()
        fingerprints.add(body["inventoryFingerprint"])
        orders.add(
            tuple(
                row["reservationId"]
                for row in body["staleReservations"]
                if row["reservationId"] in {first, second}
            )
        )

    assert orders == {(second, first)}, "ties must resolve by id, deterministically"
    assert len(fingerprints) == 1, "unchanged inventory must hash to one value"


def test_the_verified_path_is_the_authorized_path():
    """The path the verifier calls must be the one the allow-list permits.

    These were two copies of the same string. The drift is not cosmetic: an
    unlisted path raises RuntimeError, which is not an HTTPException and so
    escapes the degradation path in _verify_atlas_contact_links -- a rename
    that updated only one copy would turn a degradable outage into a 500 on
    the whole audit. Asserting the derivation holds is what keeps them one
    value rather than two that happen to match today.
    """
    assert _KNOWN_CONTACTS_PATH in _ATLAS_FUNNEL_READ_PATHS


# -- customer_type mirror refresh (ATLAS #2357) ---------------------------------

TYPE_PREVIEW_PATH = "/api/admin/corrections/customer-type/preview"
TYPE_APPLY_PATH = "/api/admin/corrections/customer-type/apply"
TYPE_REASON = "Refresh mirrored customer types from Atlas after backfill"


def _atlas_types(types_by_id, *, omit_ids=(), include_field=True):
    """A requests.get replacement returning known-contacts with customerTypes.

    include_field=False models an Atlas that predates ATLAS #2357 and does not
    report the field at all -- the deployed state at the time this was written.
    """
    omit = {str(value) for value in omit_ids}

    def _get(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            known = [v for v in submitted if v not in omit]
            body = {"knownContactIds": known, "checked": len(submitted), "limit": 100}
            if include_field:
                body["customerTypes"] = {
                    k: v for k, v in types_by_id.items() if k in known
                }
            return _Resp(200, body)
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    return _get


def _set_type(customer_id: int, value) -> None:
    db.execute("UPDATE customers SET customer_type = %s WHERE id = %s",
               (value, customer_id))


def _get_type(customer_id: int):
    return db.query_one(
        "SELECT customer_type FROM customers WHERE id = %s", (customer_id,)
    )["customer_type"]


def test_refresh_applies_the_type_atlas_reports(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Type Refresh", contact)
    _set_type(customer, "unknown")
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))

    plan = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert body["databaseReadOnly"] is True
    assert _get_type(customer) == "unknown", "preview must not write"

    change = next(c for c in body["changes"] if c["customerId"] == customer)
    assert (change["from"], change["to"]) == ("unknown", "commercial")

    applied = client.post(TYPE_APPLY_PATH, headers=auth, json={
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    })
    assert applied.status_code == 200, applied.text
    assert customer in applied.json()["updatedCustomerIds"]
    assert _get_type(customer) == "commercial"


def test_an_atlas_without_the_field_never_blanks_the_mirror(client, auth, monkeypatch):
    """The version-skew case: Atlas predates #2357 and reports no types at all.

    Absent is not "unknown". If a missing field were read as a value, the first
    refresh run against today's deployed Atlas would overwrite every mirrored
    type with unknown -- destroying the very data this feature exists to keep.
    """
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Skew Safe", contact)
    _set_type(customer, "commercial")
    monkeypatch.setattr(api.requests, "get", _atlas_types({}, include_field=False))

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    assert not [c for c in body["changes"] if c["customerId"] == customer]
    assert body["summary"]["skippedTypeNotReported"] >= 1
    assert _get_type(customer) == "commercial"


def test_a_dangling_link_never_changes_the_mirrored_type(client, auth, monkeypatch):
    import time_tracker_api as api

    dead = str(uuid.uuid4())
    customer = _create_customer("Dangles Keeps Type", dead)
    _set_type(customer, "residential")
    # Atlas would report a type, but the id does not resolve at all.
    monkeypatch.setattr(api.requests, "get",
                        _atlas_types({dead: "commercial"}, omit_ids=[dead]))

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    assert not [c for c in body["changes"] if c["customerId"] == customer]
    assert body["summary"]["skippedDanglingLinks"] >= 1
    assert _get_type(customer) == "residential"


def test_atlas_reporting_unknown_is_mirrored_faithfully(client, auth, monkeypatch):
    """Atlas is the authority: a real 'unknown' from Atlas is a value, not a gap."""
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Declassified", contact)
    _set_type(customer, "commercial")
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "unknown"}))

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    change = next(c for c in body["changes"] if c["customerId"] == customer)
    assert (change["from"], change["to"]) == ("commercial", "unknown")

    client.post(TYPE_APPLY_PATH, headers=auth, json={
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    })
    assert _get_type(customer) == "unknown"


def test_refresh_refuses_entirely_when_atlas_cannot_be_reached(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Outage", contact)
    _set_type(customer, "commercial")

    def _boom(url, *, headers=None, params=None, timeout=None):
        raise api.requests.RequestException("connection refused")

    monkeypatch.setattr(api.requests, "get", _boom)
    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert resp.status_code == 503, resp.text
    assert _get_type(customer) == "commercial"


def test_refresh_rejects_a_type_atlas_should_never_send(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    _create_customer("Bad Value", contact)
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "enterprise"}))

    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert resp.status_code == 502, resp.text


def test_apply_refuses_a_stale_plan(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Stale Plan", contact)
    _set_type(customer, "unknown")
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))
    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()

    # Atlas changes its mind after the operator previewed.
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "residential"}))
    resp = client.post(TYPE_APPLY_PATH, headers=auth, json={
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    })
    assert resp.status_code == 409, resp.text
    assert _get_type(customer) == "unknown", "a stale plan must write nothing"


def test_refresh_requires_admin(client, auth, emp_auth):
    assert client.post(TYPE_PREVIEW_PATH, json={"reason": TYPE_REASON}).status_code == 401
    assert client.post(
        TYPE_PREVIEW_PATH, headers=emp_auth, json={"reason": TYPE_REASON}
    ).status_code == 403
    assert client.post(TYPE_APPLY_PATH, json={
        "reason": TYPE_REASON, "planToken": "a" * 64, "confirmation": "x",
    }).status_code == 401


def test_the_audit_never_writes_while_the_refresh_does(client, auth, monkeypatch):
    """The audit shares the Atlas fetch with the refresh but must stay read-only."""
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Audit Read Only", contact)
    _set_type(customer, "unknown")
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))

    audit = client.get(AUDIT_PATH, headers=auth)
    assert audit.status_code == 200, audit.text
    assert audit.json()["databaseReadOnly"] is True
    assert _get_type(customer) == "unknown", "the audit must not refresh the mirror"


# -- review round 1 findings (ATLAS #2357) --------------------------------------


def test_applying_an_empty_plan_is_refused_not_collided(client, auth, monkeypatch):
    """A no-op refresh must not write a batch row.

    The token is derived from the change list and the linked count, so every
    no-op plan at a given count hashes identically. Writing one would take the
    UNIQUE plan_token, and the NEXT no-op apply would surface a raw integrity
    error. An empty plan is also the expected state until ATLAS #2358 deploys,
    so this is the first thing an operator would hit.
    """
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Nothing To Do", contact)
    _set_type(customer, "commercial")
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    assert body["summary"]["customersToUpdate"] == 0

    payload = {
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    }
    first = client.post(TYPE_APPLY_PATH, headers=auth, json=payload)
    assert first.status_code == 409, first.text
    # The second attempt must behave identically, not hit a UNIQUE violation.
    second = client.post(TYPE_APPLY_PATH, headers=auth, json=payload)
    assert second.status_code == 409, second.text
    assert db.query_one(
        "SELECT COUNT(*) AS n FROM customer_type_refresh_batches "
        "WHERE snapshot::text LIKE %s",
        (f"%{TEST_PREFIX}%",),
    )["n"] == 0


def test_a_whitespace_only_reason_is_rejected(client, auth, monkeypatch):
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    _create_customer("Blank Reason", contact)
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))

    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": " " * 20})
    assert resp.status_code == 422, resp.text


def test_a_malformed_type_map_is_refused_not_read_as_version_skew(
    client, auth, monkeypatch
):
    """Present-but-broken is not the same answer as absent.

    Silently dropping a malformed map would look exactly like an Atlas that
    predates #2357, so a broken upstream build would produce a confident
    partial refresh with nothing recording which contacts were skipped.
    """
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Malformed Map", contact)
    _set_type(customer, "commercial")

    def _bad_container(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            return _Resp(200, {
                "knownContactIds": submitted,
                "checked": len(submitted),
                "limit": 100,
                "customerTypes": ["not", "a", "map"],
            })
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _bad_container)
    assert client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).status_code == 503

    def _bad_entry(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            return _Resp(200, {
                "knownContactIds": submitted,
                "checked": len(submitted),
                "limit": 100,
                "customerTypes": {submitted[0]: 17} if submitted else {},
            })
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _bad_entry)
    assert client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).status_code == 503
    assert _get_type(customer) == "commercial"


def test_a_malformed_type_map_does_not_suppress_the_link_audit(
    client, auth, monkeypatch
):
    """Corrects an earlier claim of mine: type faults must NOT degrade the audit.

    The audit reads ids only. knownContactIds is validated independently, so a
    malformed customerTypes map says nothing about whether the id verdict is
    trustworthy. Degrading the audit over it would withhold dangling-link
    detection that every batch supplied the data for.
    """
    import time_tracker_api as api

    dead = str(uuid.uuid4())
    dangling_customer = _create_customer("Audit Malformed", dead)

    def _bad(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            # Ids are well-formed and this one resolves to nothing; only the
            # type map is broken.
            return _Resp(200, {
                "knownContactIds": [v for v in submitted if v != dead],
                "checked": len(submitted),
                "limit": 100,
                "customerTypes": "nonsense",
            })
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _bad)
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert body["atlasLinkVerification"]["status"] == "ok", (
        "a type fault must not withhold the id verdict"
    )
    assert dangling_customer in {row["customerId"] for row in body["danglingLinks"]}

    # The refresh, which does read types, must still refuse.
    assert client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).status_code == 503


def test_apply_does_not_hold_the_mutation_lock_during_atlas_io(
    client, auth, monkeypatch
):
    """Atlas must be read before the global customer/site lock is taken.

    Asserted by observing order: the advisory lock call must not have happened
    when the Atlas request is issued.
    """
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Lock Order", contact)
    _set_type(customer, "unknown")

    events = []
    real_lock = api._lock_customer_site_mutations

    def _watched_lock(cur):
        events.append("lock")
        return real_lock(cur)

    inner = _atlas_types({contact: "commercial"})

    def _watched_get(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            events.append("atlas")
        return inner(url, headers=headers, params=params, timeout=timeout)

    monkeypatch.setattr(api, "_lock_customer_site_mutations", _watched_lock)
    monkeypatch.setattr(api.requests, "get", _watched_get)

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    events.clear()
    applied = client.post(TYPE_APPLY_PATH, headers=auth, json={
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    })
    assert applied.status_code == 200, applied.text
    assert "atlas" in events and "lock" in events
    # Assert on what actually matters: NO Atlas request may be issued once the
    # lock is held. Comparing first-occurrence indices instead would pass even
    # when a second fetch runs inside the critical section -- which is exactly
    # the regression this guards against.
    after_lock = events[events.index("lock"):]
    assert "atlas" not in after_lock, (
        f"no Atlas I/O may happen while the mutation lock is held, got {events}"
    )
    assert _get_type(customer) == "commercial"


# -- review round 2 findings (ATLAS #2357) --------------------------------------


def _refresh_once(client, auth, expect=200):
    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    resp = client.post(TYPE_APPLY_PATH, headers=auth, json={
        "reason": TYPE_REASON,
        "planToken": body["planToken"],
        "confirmation": body["confirmationPhrase"],
    })
    assert resp.status_code == expect, resp.text
    return resp


def test_a_repeated_transition_can_be_applied_again(client, auth, monkeypatch):
    """The same diff legitimately recurs and must not collide on plan_token.

    commercial -> residential -> commercial -> residential produces an
    identical snapshot (and therefore an identical token) on the first and
    third refresh. The empty-plan guard does not cover this: the plan here is
    non-empty. The batch id is the identity; the token is not unique.
    """
    import time_tracker_api as api

    contact = str(uuid.uuid4())
    customer = _create_customer("Flip Flop", contact)
    _set_type(customer, "commercial")

    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "residential"}))
    _refresh_once(client, auth)
    assert _get_type(customer) == "residential"

    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "commercial"}))
    _refresh_once(client, auth)
    assert _get_type(customer) == "commercial"

    # Third refresh reproduces the first plan exactly.
    monkeypatch.setattr(api.requests, "get", _atlas_types({contact: "residential"}))
    _refresh_once(client, auth)
    assert _get_type(customer) == "residential"

    assert db.query_one(
        "SELECT COUNT(*) AS n FROM customer_type_refresh_batches "
        "WHERE snapshot::text LIKE %s",
        (f"%{TEST_PREFIX}%",),
    )["n"] == 3


def test_batches_straddling_an_atlas_deploy_are_refused(client, auth, monkeypatch):
    """Version skew is a property of the whole fetch, not of one batch.

    With more than one batch the reads can straddle an Atlas deployment: an
    early response omits customerTypes, a later one reports it. Judging each
    batch alone would read the omission as skew and still apply the types the
    newer batch returned -- a partial refresh.
    """
    import time_tracker_api as api

    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    a = _create_customer("Straddle A", first)
    b = _create_customer("Straddle B", second)
    _set_type(a, "commercial")
    _set_type(b, "commercial")
    # One id per request, so two linked customers means two batches.
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)

    seen = []

    def _mixed(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            seen.append(submitted)
            body = {"knownContactIds": submitted, "checked": len(submitted),
                    "limit": 100}
            # Only the second request comes from the upgraded Atlas.
            if len(seen) > 1:
                body["customerTypes"] = {v: "residential" for v in submitted}
            return _Resp(200, body)
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _mixed)
    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert len(seen) > 1, "test must exercise more than one batch"
    assert resp.status_code == 503, resp.text
    assert _get_type(a) == "commercial"
    assert _get_type(b) == "commercial"


def test_every_batch_omitting_the_field_is_still_plain_version_skew(
    client, auth, monkeypatch
):
    """The mixed-batch guard must not break the supported skew case."""
    import time_tracker_api as api

    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    a = _create_customer("Skew Multi A", first)
    b = _create_customer("Skew Multi B", second)
    _set_type(a, "commercial")
    _set_type(b, "residential")
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)
    monkeypatch.setattr(api.requests, "get", _atlas_types({}, include_field=False))

    body = client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).json()
    assert body["summary"]["customersToUpdate"] == 0
    assert body["summary"]["skippedTypeNotReported"] >= 2
    assert _get_type(a) == "commercial"
    assert _get_type(b) == "residential"


# -- review round 3 findings (ATLAS #2357) --------------------------------------


def test_a_truncated_type_map_is_refused_not_read_as_skew(client, auth, monkeypatch):
    """A present map must cover every known id in its own batch.

    Round 2 checked that the field was PRESENT per batch; it did not check the
    map was COMPLETE. A map omitting one known contact looked like version skew
    for that contact while the rest were applied -- a partial refresh.
    """
    import time_tracker_api as api

    covered = str(uuid.uuid4())
    omitted = str(uuid.uuid4())
    a = _create_customer("Covered", covered)
    b = _create_customer("Omitted", omitted)
    _set_type(a, "unknown")
    _set_type(b, "commercial")

    def _truncated(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            return _Resp(200, {
                "knownContactIds": submitted,
                "checked": len(submitted),
                "limit": 100,
                # Reports a type for only one of the two known ids.
                "customerTypes": {covered: "residential"},
            })
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _truncated)
    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert resp.status_code == 503, resp.text
    assert _get_type(a) == "unknown"
    assert _get_type(b) == "commercial"


def test_a_deployment_straddle_still_lets_the_audit_report_dangling_links(
    client, auth, monkeypatch
):
    """Round 2's fix suppressed the audit; the id verdict must survive.

    Mixed customerTypes presence is a type-level fault. Every batch supplied a
    valid knownContactIds, so the audit -- which never reads types -- must
    still report dangling links, while the refresh refuses.
    """
    import time_tracker_api as api

    alive = str(uuid.uuid4())
    dead = str(uuid.uuid4())
    _create_customer("Straddle Alive", alive)
    dangling_customer = _create_customer("Straddle Dead", dead)
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)

    seen = []

    def _mixed(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            seen.append(submitted)
            resolved = [v for v in submitted if v != dead]
            body = {"knownContactIds": resolved, "checked": len(submitted),
                    "limit": 100}
            if len(seen) > 1:
                body["customerTypes"] = {v: "residential" for v in resolved}
            return _Resp(200, body)
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _mixed)
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert len(seen) > 1, "test must exercise more than one batch"
    assert body["atlasLinkVerification"]["status"] == "ok"
    assert dangling_customer in {row["customerId"] for row in body["danglingLinks"]}

    seen.clear()
    assert client.post(TYPE_PREVIEW_PATH, headers=auth,
                       json={"reason": TYPE_REASON}).status_code == 503


def test_a_type_fault_never_truncates_the_known_id_set(client, auth, monkeypatch):
    """Recording a type fault must not stop fetching the remaining batches.

    Bailing out of the loop early would leave `known` partial, and a partial
    `known` makes the audit report ids as dangling that were simply never
    asked about -- turning a type-level fault into fabricated link failures.
    """
    import time_tracker_api as api

    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    _create_customer("Batch One", first)
    _create_customer("Batch Two", second)
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)

    def _first_batch_malformed(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            return _Resp(200, {
                "knownContactIds": submitted,
                "checked": len(submitted),
                "limit": 100,
                "customerTypes": {v: 99 for v in submitted},
            })
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _first_batch_malformed)
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert body["atlasLinkVerification"]["status"] == "ok"
    # Both ids resolved, so NEITHER may be reported dangling.
    reported = {row["atlasContactId"] for row in body["danglingLinks"]}
    assert first not in reported and second not in reported, (
        f"a type fault fabricated dangling links: {reported}"
    )


# -- review round 4 finding (ATLAS #2357) ---------------------------------------


def test_a_later_batch_cannot_retype_an_earlier_batchs_contact(
    client, auth, monkeypatch
):
    """Cross-batch key bleed: batch B must not be able to change customer A.

    Matching reported keys against the globally accumulated `known` set instead
    of the batch's own ids let a later response carry an entry for a contact
    resolved earlier and silently overwrite its type -- which the apply route
    would then persist. Keys must equal the batch's knownContactIds.
    """
    import time_tracker_api as api

    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    victim = _create_customer("Batch A Victim", first)
    other = _create_customer("Batch B Other", second)
    _set_type(victim, "commercial")
    _set_type(other, "commercial")
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)

    seen = []

    def _bleeding(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            seen.append(submitted)
            types = {v: "commercial" for v in submitted}
            if len(seen) > 1:
                # The second batch reports a type for the FIRST batch's contact.
                types[first] = "residential"
            return _Resp(200, {"knownContactIds": submitted,
                               "checked": len(submitted), "limit": 100,
                               "customerTypes": types})
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _bleeding)
    resp = client.post(TYPE_PREVIEW_PATH, headers=auth, json={"reason": TYPE_REASON})
    assert len(seen) > 1, "test must exercise more than one batch"
    assert resp.status_code == 503, resp.text
    assert _get_type(victim) == "commercial", "batch B must not retype customer A"
    assert _get_type(other) == "commercial"


def test_the_audit_survives_a_cross_batch_key_bleed(client, auth, monkeypatch):
    """The bleed is type-level; the id verdict must still stand."""
    import time_tracker_api as api

    first = str(uuid.uuid4())
    dead = str(uuid.uuid4())
    _create_customer("Bleed Alive", first)
    dangling_customer = _create_customer("Bleed Dead", dead)
    monkeypatch.setattr(api, "_KNOWN_CONTACTS_BATCH", 1)

    seen = []

    def _bleeding(url, *, headers=None, params=None, timeout=None):
        if "/known-contacts" in str(url):
            submitted = [str(v) for v in (params or {}).get("contact_id") or []]
            seen.append(submitted)
            resolved = [v for v in submitted if v != dead]
            types = {v: "commercial" for v in resolved}
            types[first] = "residential"  # may not belong to this batch
            return _Resp(200, {"knownContactIds": resolved,
                               "checked": len(submitted), "limit": 100,
                               "customerTypes": types})
        return _Resp(200, {"leads": [], "cursor": None, "hasMore": False,
                           "nextCursor": None, "capabilities": []})

    monkeypatch.setattr(api.requests, "get", _bleeding)
    body = client.get(AUDIT_PATH, headers=auth).json()
    assert len(seen) > 1
    assert body["atlasLinkVerification"]["status"] == "ok"
    assert dangling_customer in {row["customerId"] for row in body["danglingLinks"]}
