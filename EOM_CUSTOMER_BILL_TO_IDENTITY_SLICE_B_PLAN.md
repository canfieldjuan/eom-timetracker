# EOM customer bill-to identity: slice B plan (tracker)

Implements slice B of the accepted contract
[`EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md`](./EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md)
(merged in #280 at c8ab6be). The contract is the spec; this plan only records
how the tracker meets it, the decisions the contract left to the
implementation, and which test proves each review-contract item.

Atlas slice A is ATLAS PR 2547 (head 5da26f1), not merged or deployed. Every
test here uses the fake Atlas in `backend/conftest.py`, extended per test.

## PR split

Each PR is about 1,000 lines or fewer including tests, and each is safe to
deploy on its own (Render deploys `main` on merge).

| PR | Branch | Base | Scope | Review items |
|---|---|---|---|---|
| B1 | `agent/bill-to-identity-b1` | `main` | Reservation store, identity write admission (linked, sole holder, Atlas ready), Customer PATCH saga with apply and supersede, `pendingIdentityReservations` on `GET /api/admin/customers` | 7, 8 (held), 9, 10, 11 (revert, refused replacement), 13 (serialization), 14, 16 (PATCH) |
| B2 | `agent/bill-to-identity-b2` | B1 | Retry of the newest pending reservation, stale-revision mapping, identity sync after office conversion and after a 0C link, repair `POST /api/admin/customers/{id}/atlas-identity` | 8 (retry), 11 (never retried and fenced, newest-only retry, create), 12, 13 (repair), 16 (repair, conversion, post-create sync) |
| B3 | `agent/bill-to-identity-b3` | `main` | Site-route guard on `PATCH /api/admin/locations/{site_id}` and `PUT /api/admin/locations` | 15 |

The sole-holder check ships in B1, not with the Site-route guard, because B1
is the first PR that writes a bill-to identity to Atlas; without the check a
B1-only deploy could rename a contact another Customer is billed through. The
stale-revision mapping ships with retry in B2: under the per-Customer lock a
fresh save always carries the Customer's newest revision, so only a retry of
an older reservation can meet Atlas's fence. B3
touches only the Site routes, so it branches from `main` (plus this plan
commit) and gets CI on its own. B2 needs B1's machinery, so it is stacked on
B1; GitHub CI runs only for PRs into `main`, so B2's CI runs when B1 merges
and B2 retargets. Until then the full suite is run locally on B2's head.

**None of these PRs merges yet.** Merging deploys the tracker, and the deploy
order is Atlas A, then the website pending-state slice, then B. A tracker B
deployed before A would answer every identity-changing PATCH on a linked
Customer with 501.

## Decisions the contract left to the implementation

1. **Serialization lock.** The contract serializes identity changes "by
   holding that Customer's row lock from the read, through the Atlas response,
   to the local commit". A `customers` row lock held across HTTP would stall
   every Customer and Site mutation: ordinary edits take the global
   Customer/Site advisory lock first and then wait on the row, so one queued
   edit would hold the global lock for the length of the Atlas call (the
   customer-type route documents the same trap, `admin_set_customer_type`).
   The tracker therefore holds a **per-Customer transaction advisory lock**
   (`eom_customer_identity_v1`, customer id) on its own connection for the
   whole saga, taken before the global lock. Every Customer PATCH takes it,
   so a second edit waits, then compares against the committed values and the
   pending reservations. The reservation insert and the local apply are short
   transactions under the global lock and the row lock, as today. A waiter
   holds no connection: it takes the lock with `pg_try_advisory_xact_lock`
   and returns its connection between attempts, so queued saves cannot
   exhaust the pool the holder needs (#283 review). The wait is bounded by one
   saga (`3 x ATLAS_FUNNEL_TIMEOUT_SECONDS + 5` s); past it the save returns
   409 `customer_identity_save_in_progress` with nothing applied.
2. **Unreadable manifest.** A manifest that affirms `contact.bill_to_identity`
   is absent (or lacks `POST /eom-funnel/operator-contacts`) is a 501 with no
   reservation and no Atlas call. A manifest that cannot be read is an
   outage: the write reserves and attempts, so an unreachable Atlas yields the
   202 pending reservation the contract requires (0C's rule, item 8 of its
   review contract).
3. **Atlas body.** `{"contactId", "full_name", "billing_address",
   "identityRevision", "source_channel", "source_ref"}`, the contract's
   spelling (Atlas admits both casings). `billing_address` is always present:
   a Customer with no billing address sends `null`, which clears Atlas's copy
   so invoices fall back to `address`. `source_ref` is
   `bill-to-identity:{contactId}`: stable per contact, so Atlas records one
   provenance entry per contact rather than one per reservation, and no other
   contact can ever hold it. No `contact_type`, `email`, or `phone`: this write
   owns only the bill-to identity.
4. **Outcome mapping.** Atlas status 500 or above, a transport failure, a
   rejected credential, or a 2xx that is malformed or names another contact
   (all `AtlasFunnelRequestError` with status >= 500) is **pending**. A 409
   whose detail carries `code: stale_identity_revision` is **superseded**.
   Any other 4xx is **refused**. `AtlasFunnelRequestError` gains an optional
   `code` read from Atlas's structured detail; existing callers are unchanged.
5. **What applies.** A PATCH reservation stores every field the PATCH named
   (API names, so the website can start its form from them). On confirm, the
   tracker re-locks the Customer, checks the link still names the same
   contact, writes those fields, marks the reservation applied, and marks every
   older pending reservation superseded, in one transaction. If the link
   changed in flight, nothing is applied, the reservation stays pending with
   the reason, and the PATCH returns 409 `customer_atlas_link_changed`.
6. **Retry** (B2). `POST /api/admin/customers/identity-reservations/{reservation_id}/retry`
   re-runs admission and sends that reservation's stored body under its own
   key. Only the Customer's newest pending reservation can be sent; an older
   one returns 409 `customer_atlas_identity_not_newest` with the newest id.
   A closed reservation answers with its outcome and makes no Atlas call.
7. **Post-link sync** (B2) runs after every 0C link (create, its retry, and
   reconcile of an unlinked Customer) and after an office conversion
   finalizes (office approve, office retry, device handoff). It writes the
   Customer's stored name and billing address. The create, link, and
   conversion responses keep their shape when the sync applies; otherwise they
   gain an additive `identitySync` key carrying the outcome.
8. **Repair** (B2) writes the stored identity. Like any save it supersedes
   older pending reservations when it applies; completing a pending edit
   instead is what retry is for.

## `GET /api/admin/customers`: `pendingIdentityReservations`

Additive sibling key, read before `customers` (the 0C ordering, so a
reservation applying mid-read appears at worst in both, never in neither).
One item per pending reservation, newest revision first:

```json
{
  "reservationId": "uuid",
  "customerId": 42,
  "atlasContactId": "uuid",
  "identityRevision": 17,
  "origin": "patch | repair | conversion | create",
  "status": "pending",
  "name": "Milano & Grunloh Engineers",
  "billingAddress": "1 Main St, Effingham IL",
  "requestedChanges": {"name": "...", "billingAddress": "...", "billingEmail": "..."},
  "lastError": "EOM customer handoff service is temporarily unavailable; ...",
  "createdAt": "2026-11-03T18:00:00+00:00",
  "updatedAt": "2026-11-03T18:00:05+00:00"
}
```

`name` and `billingAddress` are what Atlas was sent. `requestedChanges` is
the whole PATCH the office saved (API field names); the website's edit form
starts from it while the reservation is pending.

## Review contract to tests

B1, `backend/test_customer_bill_to_identity.py`:

| Item | Test |
|---|---|
| 7 | `test_patch_name_change_sends_bill_to_identity_and_applies_after_atlas_confirms` |
| 8 | `test_atlas_unreachable_holds_the_whole_patch` |
| 9 | `test_patch_echoing_stored_identity_makes_no_atlas_call`, `test_unlinked_customer_rename_keeps_todays_behavior` |
| 10 | `test_name_a_then_b_then_a_sends_distinct_keys_and_rising_revisions` |
| 11 | `test_revert_after_timed_out_apply_supersedes_the_pending_change`, `test_refused_replacement_keeps_older_pending_until_a_save_applies` |
| 13 | `test_concurrent_identity_edits_serialize` |
| 14 | `test_atlas_refusal_returns_409_and_applies_nothing`, `test_missing_capability_returns_501_without_atlas_post`, `test_missing_atlas_credentials_returns_503_and_applies_nothing` |
| 16 | `test_shared_contact_refuses_identity_patch_without_atlas_call`, `test_shared_contact_still_applies_identity_neutral_patch` |

B2, `backend/test_customer_bill_to_identity_sync.py`:

| Item | Test |
|---|---|
| 8 | `test_retry_applies_a_held_patch_under_the_same_key` |
| 11 | `test_pending_superseded_by_newer_apply_is_never_retried_and_is_fenced`, `test_atlas_stale_revision_closes_the_reservation_as_superseded`, `test_retry_sends_only_the_newest_pending_reservation`, `test_create_body_omits_billing_address_and_post_link_sync_sends_it`, `test_create_matching_a_contact_linked_elsewhere_leaves_its_billing_address` |
| 12 | `test_office_conversion_sends_the_customer_bill_to_identity`, `test_failed_conversion_sync_leaves_a_visible_pending_reservation` |
| 13 | `test_repair_sends_the_current_identity`, `test_repair_refuses_an_unlinked_customer` |
| 16 | `test_shared_contact_refuses_repair_and_post_link_sync` |

B3, `backend/test_customer_identity_site_guard.py`:

| Item | Test |
|---|---|
| 15 | `test_site_patch_refuses_changed_customer_name_for_linked_customer`, `test_bulk_put_refuses_changed_customer_name_for_linked_customer`, `test_site_routes_keep_todays_behavior_for_stored_name_or_unlinked` |

## Out of scope

Deploying anything, running the Milano repair (needs A deployed and the
operator's go), the website slice, and eom-timetracker issue 282.
