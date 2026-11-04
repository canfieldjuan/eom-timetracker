# EOM customer create match contract

Status: **accepted by the operator on 2026-11-04.** This document is the
contract only; each slice implements it in its own PR.

Closes the gap recorded in eom-timetracker issue 282 and in the Deferred list of
[`EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md`](./EOM_CUSTOMER_BILL_TO_IDENTITY_CONTRACT.md).
Amends one rule of slice 0C
([`EOM_CANONICAL_CUSTOMER_CREATE_CONTRACT.md`](./EOM_CANONICAL_CUSTOMER_CREATE_CONTRACT.md),
"What is sent to Atlas"). Code read for this contract: eom-timetracker
`origin/main` f19fa9cc7 and ATLAS `origin/main` 2e11a5b8d. Line references
below are to those commits.

## Problem-derived contract

### Failure

1. The office creates Customer X with an email or phone that matches Atlas
   contact C. Tracker Customer Y already holds C.
2. The tracker sends `POST /eom-funnel/operator-contacts` without `contactId`,
   carrying `full_name`, `email`, `phone`, and `contact_type`
   (`_atlas_operator_contact_body`, `backend/time_tracker_api.py:23370`; sent at
   `:23919`).
3. Atlas resolves the request to C (`_resolve_target`,
   `atlas_brain/services/crm_provider.py:1525`). `_update_existing` (`:1606`)
   writes every supplied field that differs from C's: the name, the email, and
   the phone.
4. The tracker's finalizer then finds that Y holds C and refuses with 409
   `customer_atlas_link_conflict` (`time_tracker_api.py:23754`). X is not
   created and Y is unchanged in the tracker.
5. In Atlas, Y's contact now carries X's name, which is Y's invoice bill-to
   name, and X's email, which is where Y's invoices are sent.

Issue 282 names only the name. The code writes the email and phone too.

The same write runs through three more doors:

- **Reconcile.** Reconciling an unlinked Customer (`admin_link_customer_to_atlas`,
  `:25865`) uses the same reservation runner.
- **Public onboarding.** A contact reserved by a public onboarding handoff is
  refused at `:23720`, also after Atlas has written it.
- **The Leads page.** `POST /api/admin/funnel/contacts`
  (`admin_create_funnel_contact`, `:28963`) admits `contactType: "customer"`
  and, without `contactId`, sends the same create-or-return
  (`_atlas_funnel_contact_create_body`). A match against a held contact is
  written there with **no error at all**, because that route links nothing.

No held contact is known to have been changed this way. The write itself has
been seen live: on 2026-08-08 an office create matched a calendar-import contact
by phone and rewrote its name (`crm_provider.py:1721`).

### Root cause

The match path writes before the only check that knows who holds the contact.

- **Atlas cannot make the check.** It records a tracker Customer id only on
  handoff rows (`crm_provider.py:4593`). Contacts linked by a 0C create, a
  reconcile, or the legacy backfill have no holder record in Atlas. Several
  Customers can also share one contact (bill-to contract, "Sole holder").
- **The tracker can make the check, but only after Atlas answers.** Only Atlas
  resolves a match, on source ref, provenance, phone last-10, or email (0C
  contract, "What is sent to Atlas"). So any write inside the create-or-return
  call happens before the ownership check, by construction.

Neither shape listed in issue 282 closes it alone:

- **Atlas refusing a match against a handed-off contact** misses every holder
  Atlas has no record of, for the reason above.
- **The tracker no longer sending `full_name`** would break every create of a
  new contact: Atlas requires the name when nothing matches
  (`crm_provider.py:1669`), and the tracker cannot know before the call whether
  Atlas will create or match. It would also leave the email and phone written,
  and it does not reach the Leads page.

### Correct fix

A create-or-return that can reach a customer contact writes a contact only when
it creates it. When it resolves to an existing contact, Atlas returns that
contact unchanged, and the caller decides.

- **Customer create and reconcile.** The tracker's ownership check decides
  whether to link. The only data that then flows to the contact is the bill-to
  identity (name and billing address). It goes through the identity sync that
  already runs after every link (bill-to contract, "Create (0C)"). That path
  admits the write only for the contact's sole holder, and its revision fence
  refuses stale writes. The rename that 0C did inline still happens, but after
  the ownership check, and with that sync's fence and audit trail.
- **A Leads-page customer create.** A match is refused with the existing
  contact named, so the office edits that contact on purpose instead of by
  accident.

**Slice A: Atlas**

- **New request field `onMatch`.**
  - The operator boundary admits `onMatch` on a create-or-return (no
    `contactId`). It is a closed enum: `"apply"` or `"return"`.
  - Absent means `"apply"`, which is today's behavior, so every existing caller
    is unchanged.
  - `null`, any other value, or a non-string is a 422.
  - Any `onMatch` together with `contactId` is a 422, because it has no meaning
    on an edit.
  - Each 422 is returned before the provider runs.
- **Behavior with `"return"`.**
  - **Resolution and refusals are unchanged.** Several matches, an archived
    contact, or a non-editable contact or contact-type mismatch
    (`_assert_contact_type_matches`, `:1609`) are refused with the same 409s as
    today. Each refusal writes nothing.
  - **No match.** Atlas creates the contact exactly as today (`_create_contact`,
    `:1669`). It records the `contact_created` event and returns operation
    `contact_created`.
  - **One match.** Atlas writes no `contacts` column: not the supplied fields,
    and not the provenance metadata, `business_context_id`, `updated_at`, or
    `bill_to_revision` that `_update_existing` would set.
- **The `contact_matched` receipt.**
  - On a match Atlas records one lifecycle event, `contact_matched`, carrying
    the operation key and today's lifecycle metadata (`eom_crm_mutations.py:441`).
    Its `changed_fields` and `previous_values` are empty, because nothing
    changed, and its lead stage is recorded as unchanged.
  - This event is the idempotency receipt: receipts are lifecycle events
    (`crm_provider.py:1776`). So it joins `EOM_OPERATOR_CONTACT_EVENT_TYPES`
    (`eom_crm_mutations.py:25`).
  - The response has operation `contact_matched` and the matched `contactId`.
    It returns 201 the first time and 200 on replay, like the other operations.
  - Atlas returns `contact_matched` only to a request that sent `"return"`. A
    caller that never sends it cannot receive it.
- **Fingerprint.** The request fingerprint includes `onMatch` only when it is
  `"return"`. A request that is absent or `"apply"` hashes exactly as before, so
  a receipt stored before the deploy still replays. This mirrors the
  `identity_revision` rule (`eom_crm_mutations.py:423`).
- **Capability.** The manifest advertises `contact.match_without_write` on
  `POST /eom-funnel/operator-contacts` (`atlas_brain/eom_api/funnel.py:1203`).
- **Receipt index.** The receipt lookup is index-backed by a partial index
  that lists only `contact_created` and `contact_updated` (migration 364).
  Once the lookup also asks for `contact_matched`, that index no longer
  applies and every operator mutation would scan the lifecycle ledger. A new
  index-only migration recreates it over every receipt type. No table changes
  are needed: `eom_lead_lifecycle_events.event_type` is `VARCHAR(64)` with no
  CHECK (migration 351).

**Slice B: tracker**

- **Customer create and reconcile: the request.** Both 0C reservation modes send
  `onMatch: "return"` (`_atlas_operator_contact_body`, `:23370`). Nothing else in
  the body changes.
- **Customer create and reconcile: after Atlas answers.** On `contact_matched`
  the local flow is today's. The finalizer's ownership check
  (`_finalize_customer_atlas_reservation`, `:23657`) decides:
  - **Held by another Customer.** 409 `customer_atlas_link_conflict`, as
    today, but Atlas is now unchanged.
  - **Reserved by a public onboarding handoff.** Refused as today, and Atlas is
    unchanged.
  - **Unheld.** The tracker links, and the post-link identity obligation
    (`:24293`) sends the name and billing address with `contactId` and
    `identityRevision`, under sole-holder admission.
- **Leads-page customer create.** `POST /api/admin/funnel/contacts` with
  `contactType: "customer"` and no `contactId` sends `onMatch: "return"`.
  - On `contact_matched` it returns 409 `funnel_contact_exists`, with the
    matched `contactId` and that contact's name, and a message telling the
    office to open and edit that contact. Atlas is unchanged.
  - On `contact_created` it behaves as today.
- **Capability.** Every request that sends `onMatch` requires
  `contact.match_without_write` as well as the route's existing capability,
  under 0C's rule:
  - A manifest that affirms the capability is absent gets 501 before any local
    write.
  - For the 0C reservation, a manifest that cannot be read is an outage: the
    tracker reserves and attempts, and a failed attempt leaves a 202 pending
    reservation. The Leads page keeps its existing strict gate.
- **Unchanged callers.** These send no `onMatch`:
  - **Leads-page lead create.** A lead create can only match a lead, because the
    type check refuses a customer match. Office conversion turns a held contact
    into a customer (`crm_provider.py:5915`).
  - **Every Leads-page edit**, because it names `contactId`.
  - **Customer-type change** (`_apply_customer_type_change`, `:31979`), which
    names `contactId`.

### Must not change

- Every caller that sends no `onMatch`: same Atlas behavior, same receipts,
  same fingerprints.
- A create for which Atlas creates a new contact, on either door: the same
  fields written and the same success body.
- 0C's statuses and response shapes for create and reconcile, including 409
  `customer_atlas_link_conflict` and the pending-reservation rules.
- The bill-to identity sync, PATCH, office conversion, repair, and every
  Leads-page lead create and edit.

## Concurrency

- **Atlas locks.** A `"return"` request takes the same advisory locks as today
  (operation key, phone, email, source ref; `crm_provider.py:1756-1770`). A
  concurrent write to a contact it matches is therefore serialized with it.
- **A link that lands while Atlas is being called.** Another writer can link C
  between Atlas's answer and the finalizer's lock. The finalizer already
  refuses that (0C, "Another writer linked the Customer first"). Atlas no
  longer carries a write from the refused create.
- **Retry.** A retry reuses its key and gets the same `contact_matched`
  receipt. A reservation runs the ownership check again with the same contact,
  and a Leads-page retry returns the same 409.

## Decisions for operator review

1. **A matched contact keeps its own email and phone.** Today a Customer create
   that matches a contact on its phone overwrites the contact's email with the
   one the office typed, and the reverse for a match on email. After this
   change the tracker writes email and phone only on a contact it creates. This
   retires 0C's rule that matching contacts receive the supplied fields as
   operator intent. Reasons:
   - That write has no ownership check and no stale-write fence.
   - The identity sync carries only the name and billing address. The tracker's
     only other email or phone write to an existing contact is a Leads-page edit
     that names the contact.
   - Atlas `email` is also the invoice recipient. The bill-to contract deferred
     that to its own field and contract, because the email is also a match key.

   The consequence: a Customer linked to an existing contact whose email
   differs is invoiced at the contact's email until it is edited on the Leads
   page, or until the billing-email contract lands.
2. **On the Leads page, creating a customer that matches an existing contact
   no longer updates that contact.** It is refused with the existing contact
   named, and the office's entry stays in the form. Today the page updates the
   matched contact and reports it as updated. The page already shows a
   refusal's message, so no website change is required. Lead creates keep
   today's behavior.

## Deferred (not closed here)

- **A Customer create refused because another Customer holds the contact**
  leaves a pending reservation that no retry can complete (0C, Execution
  model). Closing such a reservation as refused is a separate change.
- **An "open the existing contact" action** on the Leads page for
  `funnel_contact_exists`. Until then the message names the contact.
- **A Leads-page edit of a contact a Customer holds** still changes it directly,
  including its name. That is the bill-to contract's deferred "Atlas-side edits"
  item.
- **Billing email as the invoice recipient** stays as in the bill-to contract.
  Its contract is now also how an existing contact's email follows the
  Customer.

## Slices and order

1. **A (Atlas):** `onMatch`, the `contact_matched` receipt and its index, the
   fingerprint, and the capability. Deployed to the office `atlas-api`.
2. **B (tracker):** Customer create, reconcile, and Leads-page customer create
   send `onMatch: "return"` and require the capability. B merges only after A is
   live, because B's capability rule would otherwise refuse those requests with
   501.

Each slice is its own PR, each under the ~1,000-line cap including tests, with
its plan commit separate from its code.

## Review contract

Atlas (slice A):

1. **Match leaves the contact unchanged.** `onMatch: "return"` with one match
   leaves every column of the matched `contacts` row identical, including
   `metadata`, `updated_at`, `business_context_id`, and `bill_to_revision`. The
   response is `contact_matched` with that `contactId`. Exactly one
   `contact_matched` event exists, carrying the operation key, with empty
   `changed_fields` and `previous_values`. The test is run for a match on email
   and a match on phone last-10.
2. **No match.** `onMatch: "return"` with no match creates the contact as today
   (`contact_created`).
3. **Default and `"apply"` are unchanged.** With `onMatch` absent or `"apply"`,
   a match is overwritten as today, and the fingerprint equals the pre-change
   fingerprint for the same request.
4. **Admission.** `onMatch` with `contactId` (each value), `null`, an unknown
   string, a boolean, and a number are each rejected with 422 before the
   provider runs.
5. **Replay.** A replay of the same key returns the same `contact_matched`
   receipt and records no second event. The same key with `onMatch` changed
   returns 409. The receipt index's predicate lists exactly the operator
   receipt event types.
6. **Refusals.** Under `"return"`, several matches, an archived match, and a
   contact-type mismatch each return today's 409. Each leaves the contact
   unchanged and records no event.
7. **Capability.** The manifest advertises `contact.match_without_write`.

Tracker (slice B):

8. **Held contact.** A Customer create whose email matches a contact held by
   Customer Y:
   - the Atlas request carries `onMatch: "return"`;
   - the response is 409 `customer_atlas_link_conflict` naming Y;
   - no Customer X row exists, and Y's row is unchanged;
   - no further Atlas call is made.
9. **Unheld contact.** A Customer create that matches an unheld contact links
   it. The identity sync then sends `contactId`, `full_name`,
   `billing_address`, and `identityRevision`. No Atlas request after the create
   carries `email` or `phone`.
10. **Reconcile.** Reconciling an unlinked Customer sends `onMatch: "return"`.
    A held match returns the same 409 as test 8.
11. **Leads page.**
    - A customer create without `contactId` sends `onMatch: "return"`.
      `contact_matched` returns 409 `funnel_contact_exists` with the matched
      `contactId`, and `contact_created` returns today's body.
    - A lead create, and any edit naming `contactId`, carry no `onMatch`.
12. **Capability.** For each request that sends `onMatch`, a manifest that
    affirms `contact.match_without_write` is absent returns 501, with no
    reservation and no Atlas call. For the 0C reservation, an unreadable
    manifest leaves a 202 pending reservation.
13. **New contact.** A Customer create for which Atlas creates a new contact
    keeps the legacy 201 body, and the identity sync runs as today.
14. **Customer-type change.** Its body carries no `onMatch`.

Live settle, after A and B deploy:

- **Proof of the change.** The Atlas manifest lists `contact.match_without_write`.
  The next office Customer create shows `onMatch: "return"` in the Atlas
  request log.
- **Past damage audit (read-only, both systems).**
  - For each tracker 0C reservation, list the Atlas `contact_updated` events
    whose `source_ref` is that reservation's id and whose `changed_fields` is
    not empty.
  - For the Leads page, list the `contact_updated` events whose `source_ref`
    starts with `portal-contact:` on a contact a Customer holds now. The event
    does not record whether the request named `contactId`, so this list mixes
    accidental matches with deliberate edits. The office reviews each one.
  - Report each such contact, with the event's `previous_values`, so the office
    can restore it.
  - Also report any Customer that holds a lead-type contact.
  - This audit is the only record of past damage, because the write left the
    tracker unchanged.
