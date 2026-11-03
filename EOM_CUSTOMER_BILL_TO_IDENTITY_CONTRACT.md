# EOM customer bill-to identity contract

Status: **accepted by the operator on 2026-11-03.** This document is the
contract only; each slice implements it in its own PR.

Builds on Decision D1 of website #105 (Atlas is the only write authority for
leads and customers) and on slice 0C
([`EOM_CANONICAL_CUSTOMER_CREATE_CONTRACT.md`](./EOM_CANONICAL_CUSTOMER_CREATE_CONTRACT.md)).
Code read for this contract: eom-timetracker `origin/main` 15ea53f and ATLAS
`origin/main` 00a68be26. Line references below are to those commits.

## Problem-derived contract

### Observed failure

On 2026-11-03 the office converted Milano & Grunloh Engineers from a lead into
a commercial Customer, then set its Customer name and billing address in the
portal and saved. The tracker shows both. The linked Atlas contact still has
the lead's person name as `full_name` and no address, and the Atlas request log
shows no tracker write for that contact after the customer-type change. Atlas
monthly invoicing addresses the invoice from the contact, so the first invoice
(generated 2026-12-01) would be billed to a person with no address.

### Root cause

Three gaps, each independent:

1. **Customer edits never reach Atlas.** `PATCH /api/admin/customers/{id}`
   (`admin_patch_customer`, `backend/time_tracker_api.py:31144`) writes
   `name`, `billingName`, `billingEmail`, and `billingAddress` locally and makes
   no Atlas call. The tracker's only Atlas contact writes are create
   (`_run_customer_atlas_reservation`, `:23788`), funnel-contact create
   (`admin_create_funnel_contact`, `:27984`), customer type
   (`_apply_customer_type_change`, `:31000`), and reconcile of an *unlinked*
   Customer (`admin_link_customer_to_atlas`, `:24937`), which refuses a linked
   one with 409 `customer_already_linked` (`:24956`).
2. **Office conversion links without identity.** The customer handoff sends
   Atlas only `contact_id`, `tracker_customer_id`, and `tracker_site_id`
   (`time_tracker_api.py:25046`; Atlas `EOMCustomerHandoffRequest`,
   `atlas_brain/eom_api/funnel.py:155`). A lead created under a person's name
   keeps that name after it becomes a business Customer. 0C maps Customer
   `name` to `full_name` on create (`_atlas_operator_contact_body`, `:23267`);
   the conversion path has no equivalent.
3. **Atlas has no bill-to address.** 0C deliberately sends no address
   (`:23267`). Atlas has one `contacts.address` field, and it already serves a
   different concept: it is the `location` of EOM booking calendar events
   (`atlas_brain/services/crm_provider.py:2854`) as well as the invoice bill-to
   address (`atlas_brain/autonomous/tasks/monthly_invoice_generation.py:413`).
   Writing a billing address into it would move booking locations to the
   billing office; leaving it empty leaves invoices without an address.

### Correct fix

Name the concept: **bill-to identity** is the name and address an invoice is
addressed to. It is not the service location (tracker Site; Atlas `address`
for bookings) and not the people on the account.

| Bill-to field | Tracker source | Atlas storage |
|---|---|---|
| Name | Customer `name` | `contacts.full_name` (0C's existing mapping) |
| Address | Customer `billingAddress` | new `contacts.billing_address` |

Atlas is written first and the tracker's copy changes only after Atlas
confirms (D1), using 0C's saga shape: durable reservation, Atlas call with the
reservation's Idempotency-Key, local write last. Every path that sets or
changes a linked Customer's bill-to identity sends it: create, office
conversion, PATCH, and an explicit repair action for Customers that already
drifted.

**Slice A: Atlas**

- Additive migration: `contacts.billing_address TEXT NULL`, at most 500
  characters (the tracker's limit), and `contacts.bill_to_revision BIGINT NULL`
  for the revision fence (see Concurrency). Existing rows stay null.
- The operator boundary admits `billing_address` (`billingAddress` on the wire)
  alongside the fields in `EOM_OPERATOR_CONTACT_FIELDS`
  (`atlas_brain/services/eom_crm_mutations.py:108`), **only on an edit that
  names `contactId`** (422 otherwise, whatever the value). Without `contactId`
  the request is create-or-return and can resolve to a contact it merely
  matched on email or phone, possibly one linked to another Customer, so it
  must not change that contact's bill-to address. Absent means untouched; null
  clears it.
- The operator boundary admits `identityRevision`, a positive integer, only
  with `contactId`, and enforces the revision fence in the same transaction as
  the write.
- The capability manifest (`funnel.py:1214`) advertises
  `contact.bill_to_identity` on the operator-contacts route, so a tracker can
  tell whether Atlas accepts `billingAddress` and `identityRevision` (0E
  negotiation). One name covers both, because the tracker needs both before it
  sends either.
- Bill-to address on invoices: monthly generation
  (`monthly_invoice_generation.py:413`) uses `billing_address` when it is set
  and falls back to `address` when it is not. The rule is that a Customer with a
  billing address is billed there; a contact without one (residential and
  legacy) keeps billing to its address, exactly as today. It is the only invoice
  writer that derives the bill-to from the contact: the invoicing MCP
  `create_invoice` takes the address from its caller
  (`atlas_brain/mcp/invoicing_server.py:222`) and stays unchanged.
- Booking calendar events keep `location = address`. Invoices already created
  keep their snapshot; nothing rewrites them.

**Slice B: tracker**

- **PATCH.** When a PATCH changes `name` or `billingAddress` on a linked
  Customer (compared with the stored values, because the deployed portal sends
  every field on every edit), it runs the saga. It reserves the change, sends
  `{contactId, full_name, billing_address, identityRevision}` to
  `POST /eom-funnel/operator-contacts`,
  and applies the **whole** PATCH locally only after Atlas confirms. A PATCH
  that leaves both values unchanged keeps today's behavior and makes no Atlas
  call, but only when the Customer has no pending identity reservation (see
  Concurrency, revision fence rule 3).
- **Office conversion.** After the handoff saga links the Customer, the same
  identity sync runs for it. If that sync fails, the conversion still stands
  (the handoff is its own saga), and the identity reservation stays pending and
  visible.
- **Repair.** `POST /api/admin/customers/{customer_id}/atlas-identity` (new and
  additive) sends a linked Customer's current name and billing address through
  the same saga. An unlinked Customer gets 409 and is pointed at the existing
  `/atlas-contact` reconcile. This is how Milano, and any Customer whose identity
  is pending, gets fixed.
- **Create (0C).** The create body does not carry `billing_address`. Once
  the create has linked the Customer (after the local finalizer's ownership
  check), the identity sync sends the name and billing address with
  `contactId`, as for office conversion. A create that matches a contact linked
  to another Customer therefore cannot change that contact's billing address.
- **Site routes.** The single-Site PATCH and legacy bulk PUT refuse a changed
  `customerName` for an Atlas-linked Customer (see Concurrency, "One writer").

### Must not change

- Booking event locations, tracker Sites, schedules, payroll, shifts, and QR
  check-in.
- The bill-to address of any contact without a billing address, and every
  invoice already created.
- The `{"success": true, "customer": ...}` shape of an applied PATCH. Pending
  uses the 0C 202 shape, and pending reservations appear as an additive sibling
  key on `GET /api/admin/customers`.
- `atlasContactId` and customer type stay system-managed. Unlinked Customers
  keep today's PATCH behavior.

## Execution model

The PATCH or repair outcome when the bill-to identity changes on a linked
Customer:

| Outcome | Status | Local result |
|---|---|---|
| Atlas applied the identity | 200 | PATCH applied, reservation finalized |
| Atlas unreachable, timed out, or 5xx | 202, `error: customer_atlas_pending` | **Nothing applied**; reservation pending, retryable with the same key |
| Atlas refused (archived, identity owned by another contact) | 409 `customer_atlas_identity_refused`, with Atlas's reason | Nothing applied, reservation closed |
| Atlas refused a stale `identityRevision` | 409 `customer_atlas_identity_superseded` | Nothing applied, reservation closed as superseded |
| Deployed Atlas lacks `contact.bill_to_identity` | 501 `atlas_capability_unavailable` | Nothing applied, no Atlas call |
| Tracker has no Atlas credentials | 503 | Nothing applied |
| Name and billing address unchanged | Today's behavior | No Atlas call |

### Concurrency

- Identity changes to one Customer are serialized by holding that Customer's
  row lock from the read, through the Atlas response, to the local commit. 0C
  already does this for reconciliation (its review item 9). The wait is bounded
  by the Atlas client timeout. A second edit waits, then compares against the
  committed values.
- Atlas serializes per contact (`eom-operator-contact:contact:{id}`,
  `crm_provider.py:1740`).
- **Idempotency key.** Each change gets its own reservation and key. A retry of
  a pending change reuses its key. A new change, including a revert to an
  earlier value, gets a new key, so Atlas cannot answer an A to B to A revert
  with a stale replay.
- **Revision fence.** A pending change must never be able to undo a newer one.
  Example: Atlas applies name B but the response times out, so B stays pending;
  the office then saves C and both systems reach C; a later retry of B would put
  Atlas back to B. Two rules close this:
  1. Every identity reservation takes a revision from one tracker sequence, so
     revisions only grow for a Customer. The tracker sends it as
     `identityRevision` alongside `contactId`. Atlas stores the highest applied
     revision on the contact (`contacts.bill_to_revision`) inside the same
     transaction and per-contact lock as the write. A revision that is not
     higher than the stored one, sent under a new Idempotency-Key, is refused
     with 409 and changes nothing. A retry under the original key still gets
     its original receipt. `identityRevision` without `contactId` is rejected
     (422).
  2. Creating a reservation closes the Customer's older pending identity
     reservations as superseded, under the Customer row lock. A superseded
     reservation is never retried. If a stale request still reaches Atlas (for
     example a delayed delivery), rule 1 refuses it, and the tracker closes that
     reservation as superseded without applying anything locally.
  3. The last save wins. While a Customer has a pending identity reservation,
     every PATCH on it creates a new reservation, even when its name and
     billing address equal the stored values. Example: A, then B (Atlas applies
     B but times out, so the tracker stays at A with B pending), then the office
     saves A: that save is not a no-op; it sends A with a higher revision and
     supersedes B, and both systems end at A.
- **One writer for the bill-to name.** Two Site routes also rename the owning
  Customer: `PATCH /api/admin/locations/{site_id}` and the legacy bulk
  `PUT /api/admin/locations` (`time_tracker_api.py:32244` and `:32027`). For an
  Atlas-linked Customer they refuse a `customerName` that differs from the
  stored Customer name with 409 `customer_identity_edit_required`, applying
  nothing from that request; the office renames on the Customer. A
  `customerName` equal to the stored name, and every unlinked Customer, keep
  today's behavior.

## Decisions for operator review

1. **The bill-to name is the Customer name** (the business), not `billingName`
   (the person). `billingName` becomes an "Attn" line later (see Deferred).
2. **When Atlas is unreachable, an edit that changes the name or billing
   address is held whole** (202, nothing applied) rather than applied locally
   and synced later. This follows D1 and 0C. Atlas runs on the office desktop,
   so outages are real. A held edit is visible and retryable, whereas local
   drift is silent until an invoice is wrong.
3. **A new `billing_address` field instead of reusing `address`**, because
   `address` already drives booking locations.

## Deferred (not closed here)

- **Billing email as the invoice recipient.** Atlas `email` is an identity-match
  key for create-or-return, so writing `billingEmail` there can collide with
  another contact. This needs its own field and contract.
- **`billingName` as an "Attn" line.** Invoices already carry `contact_name`,
  which the PDF prints (`atlas_brain/services/invoice_pdf.py:197`).
- **A drift audit across all linked Customers** (an addition to the linkage
  audit).
- **Commercial billing-run invoices carry no address.** The approval path
  (`atlas_brain/services/commercial_billing_approvals.py:914`) takes the bill-to
  name from the tracker's billing-run snapshot, not from the Atlas contact, and
  writes no `customer_address`. Giving those invoices an address is a separate
  change to that snapshot contract.
- **Atlas-side edits mirroring back to the tracker.** The legacy writers stay
  0D's job.
- **A create can still rename a contact linked to another Customer.** 0C's
  create-or-return writes `full_name` onto a matched contact before the
  tracker detects the link conflict. This contract keeps the billing address
  out of that path; the name path predates it and needs its own decision
  (eom-timetracker issue 282).

## Slices and order

1. **A (Atlas):** migration, operator field, revision fence, capability, bill-to
   precedence.
2. **Website:** the portal shows a pending PATCH (202) as pending, not as saved,
   and shows the Site-route 409 `customer_identity_edit_required` as "rename
   this on the Customer". While a Customer has a pending identity change, its
   edit form starts from the pending values, so saving an unrelated field does
   not revert the pending change (rule 3 makes that save win). This must deploy
   before B, or B's 202 reads as a silent success.
3. **B (tracker):** PATCH, conversion, repair, create, supersede, and the Site
   route guard.

Each slice is its own PR of about 1,000 lines or fewer including tests. Each
PR's contract or plan commit lands separately from its code.

**Deadline.** Milano's first invoice is generated 2026-12-01 as a review-gated
draft. If A and B are not live and the repair has not run by then, that draft
is held until they are.

## Review contract

Atlas (slice A):

1. The migration is additive; existing rows read `billing_address IS NULL`.
2. An edit with `contactId` plus `billingAddress` changes only
   `billing_address`. `address` is untouched, and the EOM booking event payload
   still takes `location` from `address`.
3. An absent `billingAddress` leaves it untouched. With `contactId`, a value
   sets it and null clears it. Without `contactId`, any `billingAddress`
   (value, blank, or null) is rejected (422) before the provider runs.
4. Invoice bill-to: a contact with `billing_address` produces
   `customer_address = billing_address`; a contact without one produces
   `customer_address = address`. Both sides are tested, plus
   `customer_name = full_name`.
5. The manifest advertises `contact.bill_to_identity`. A tracker that never
   sends `billingAddress` or `identityRevision` sees no change.
6. Revision fence: with `bill_to_revision` stored as 5, an edit with revision 6
   applies and stores 6; an edit with revision 5 or 4 under a new key returns
   409 and leaves the row unchanged; a retry of the revision-6 edit under its
   original key returns its receipt. `identityRevision` without `contactId`, or
   not a positive integer, is rejected (422).

Tracker (slice B):

7. PATCH changing `name` on a linked Customer with Atlas up: Atlas receives
   `contactId`, `full_name`, `billing_address`, and `identityRevision`; the row
   updates; the response shape is unchanged.
8. Atlas unreachable: 202, and the test asserts the row is **unchanged** (not
   just the status). A retry with the same key applies the change.
9. A PATCH echoing the stored values makes zero Atlas calls when no identity
   reservation is pending.
10. Name A, then B, then A sends three distinct keys and rising revisions, and
    Atlas ends at A.
11. Supersede: B times out (pending), then C applies; the B reservation is
    closed as superseded and a retry of it makes no Atlas call. A B request that
    Atlas receives after C is refused by the fence. Both systems end at C.
    Revert: A, then B (Atlas applies B, response times out), then a save of A
    sends A with a higher revision and supersedes B; both systems end at A.
    Create: the create body carries no `billing_address`; after linking, the
    identity sync sends it. A create whose email matches a contact linked to
    another Customer still returns the link conflict and leaves that contact's
    `billing_address` unchanged.
12. An office conversion sends the Customer name and billing address for the
    converted contact. A failed sync leaves a pending reservation that
    `GET /api/admin/customers` shows.
13. Repair on a linked Customer sends its current identity; on an unlinked one
    it returns 409. Two concurrent identity edits serialize (two-connection
    test).
14. Atlas refusal returns 409 and applies nothing. A missing capability returns
    501, with no Atlas POST and nothing applied.
15. Site routes: the single-Site PATCH and the bulk PUT with a changed
    `customerName` for a linked Customer return 409
    `customer_identity_edit_required` and change no Customer, Site, or Atlas
    row; with the stored name, or for an unlinked Customer, they behave as
    today.

Live settle: after A and B deploy, run the repair for Milano. Confirm in Atlas
that `full_name` is the business name, `billing_address` is set, and `address`
is unchanged. Then confirm that a November invoice dry run for Milano bills the
business at that address, before 2026-12-01.
