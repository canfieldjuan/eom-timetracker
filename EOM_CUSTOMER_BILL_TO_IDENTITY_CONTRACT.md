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
  for the revision fence (Concurrency). Existing rows stay null.
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

Every path below admits the write and runs the reservation through the
Execution model's two rules ("Identity write admission", "Reservation
lifecycle"); the bullets only say when each path writes.

- **PATCH.** A PATCH on a linked Customer writes the identity when it changes
  `name` or `billingAddress` (compared with the stored values, because the
  deployed portal sends every field on every edit), or when the Customer has a
  pending identity reservation. It sends
  `{contactId, full_name, billing_address, identityRevision}` to
  `POST /eom-funnel/operator-contacts` and applies the **whole** PATCH locally
  only after Atlas confirms. Otherwise it keeps today's behavior and makes no
  Atlas call.
- **Office conversion.** After the handoff saga links the Customer, the
  identity sync runs for it. If the sync is pending or refused, the conversion
  still stands (the handoff is its own saga) and the outcome is visible.
- **Repair.** `POST /api/admin/customers/{customer_id}/atlas-identity` (new and
  additive) writes a linked Customer's current name and billing address. This
  is how Milano, and any Customer whose identity is pending, gets fixed.
- **Create (0C).** The create body does not carry `billing_address`. Once the
  create has linked the Customer (after the local finalizer's ownership check),
  the identity sync sends the name and billing address with `contactId`, as for
  office conversion. A create that matches a contact linked to another Customer
  therefore cannot change that contact's billing address.
- **Site routes.** The single-Site PATCH and legacy bulk PUT refuse a changed
  `customerName` for an Atlas-linked Customer (Concurrency, "One writer for the
  bill-to name").

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

Every bill-to identity write (Customer PATCH, office-conversion sync,
post-create sync, repair) goes through the same two rules below. The
per-path bullets in Slice B refer to them and do not restate them.

### Identity write admission

Checked in this order, under the Customer identity lock (Concurrency), before any reservation is
created or Atlas is called:

1. **Linked.** The Customer has an `atlasContactId`. An unlinked Customer's
   PATCH keeps today's behavior; repair returns 409 and points at
   `/atlas-contact`.
2. **Sole holder.** No other Customer holds the same `atlasContactId`. Several
   Customers can share one contact today (the linkage audit reports them as
   duplicate groups, `backend/test_atlas_linkage.py:137-154`), and an identity
   write to a shared contact would change the other Customer's invoice name and
   address too. A shared contact is refused with 409
   `customer_atlas_contact_shared`, listing the other Customer ids: nothing is
   applied and Atlas is not called until the duplicate is resolved. The check
   locks the other holders' rows (`SELECT ... FOR UPDATE`), which is the same
   lock the create finalizer takes (`time_tracker_api.py:23630-23638`), so a
   concurrent link cannot create a duplicate mid-write.
3. **Atlas ready.** Credentials present (else 503) and the deployed Atlas
   advertises `contact.bill_to_identity` (else 501). Nothing applied.

### Reservation lifecycle

An identity reservation is `pending`, `applied`, `refused`, or `superseded`.

- **Created** under the Customer identity lock with the next revision (see the
  revision fence) and its own Idempotency-Key.
- **Applied** when Atlas confirms: the tracker applies the whole PATCH in the
  same transaction and marks every **older** pending reservation of that
  Customer superseded. Only a successful apply supersedes anything.
- **Pending** when Atlas is unreachable, times out, or returns 5xx: nothing is
  applied locally and the reservation is visible on `GET /api/admin/customers`.
- **Refused** when Atlas refuses for any reason other than a stale revision:
  the reservation closes, nothing is applied, and older pending reservations
  stay pending and visible.
- **Superseded** also when Atlas refuses the reservation's revision as stale:
  it closes and nothing is applied.
- **Retry** sends only the Customer's **newest** pending reservation, with its
  own key. Older pending reservations are never sent again; they close when a
  newer one applies.
- **No-op shortcut.** A PATCH whose name and billing address equal the stored
  values makes no Atlas call only when the Customer has **no** pending
  reservation. Otherwise it creates a new reservation: the last save wins.

Worked sequences (each is a review-contract test):

- A, then B (Atlas applies B, the response times out), then the office saves A:
  B is pending, so the save of A is not a no-op; it applies with a higher
  revision and supersedes B. Both systems end at A.
- A, then B (applied in Atlas, timed out), then C refused by Atlas: C closes as
  refused and B stays pending and visible. A later save of A creates a new
  reservation, which applies and supersedes B. Both systems end at A.
- B pending, then C applies: B is superseded and never retried. A delayed B
  request that reaches Atlas after C is refused by the fence.

| Outcome | Status | Local result |
|---|---|---|
| Atlas applied the identity | 200 | PATCH applied, older pending reservations superseded |
| Atlas unreachable, timed out, or 5xx | 202, `error: customer_atlas_pending` | **Nothing applied**; reservation pending |
| Atlas refused (archived, identity owned by another contact) | 409 `customer_atlas_identity_refused`, with Atlas's reason | Nothing applied, reservation refused |
| Atlas refused a stale `identityRevision` | 409 `customer_atlas_identity_superseded` | Nothing applied, reservation superseded |
| Contact shared with another Customer | 409 `customer_atlas_contact_shared` | Nothing applied, no reservation, no Atlas call |
| The Customer's Atlas link changed while Atlas was called | 409 `customer_atlas_link_changed` | Nothing applied; reservation stays pending |
| Another identity save for this Customer is still running past the bounded wait | 409 `customer_identity_save_in_progress` | Nothing applied, no reservation |
| Deployed Atlas's manifest affirms `contact.bill_to_identity` is absent | 501 `atlas_capability_unavailable` | Nothing applied, no Atlas call. A manifest that cannot be read is an outage: the write reserves and attempts, so it ends 202 pending |
| Tracker has no Atlas credentials | 503 | Nothing applied |
| Name and billing address unchanged, nothing pending | Today's behavior | No Atlas call |

### Concurrency

- **Customer identity lock.** Identity changes to one Customer are serialized
  by a per-Customer transaction advisory lock (`eom_customer_identity_v1`,
  customer id), held on its own connection for the whole saga, from the read,
  through the Atlas response, to the local commit. Every Customer PATCH takes
  it, before the global Customer/Site lock. It is deliberately not the
  `customers` row lock: ordinary edits take the global lock first and then
  wait on the row, so a row lock held across the Atlas call would hold every
  Customer and Site edit for the length of that call. The reservation insert
  and the local apply stay short transactions under the global lock and the
  row lock, as today.
- A second edit waits, then compares against the committed values and the
  pending reservations. A waiter holds no connection (it retries
  `pg_try_advisory_xact_lock` and returns its connection between attempts), so
  queued saves cannot exhaust the pool. The wait is bounded by one saga
  (`3 x ATLAS_FUNNEL_TIMEOUT_SECONDS + 5` seconds); past it the save returns
  409 `customer_identity_save_in_progress` and applies nothing.
- Atlas serializes per contact (`eom-operator-contact:contact:{id}`,
  `crm_provider.py:1740`).
- **Idempotency key.** Each reservation has its own key. A retry reuses it. A
  new change, including a revert to an earlier value, gets a new key, so Atlas
  cannot answer an A to B to A revert with a stale replay.
- **Revision fence.** Every identity reservation takes a revision from one
  tracker sequence, so revisions only grow for a Customer. The tracker sends it
  as `identityRevision` alongside `contactId`. Atlas stores the highest applied
  revision on the contact (`contacts.bill_to_revision`) inside the same
  transaction and per-contact lock as the write. A revision that is not higher
  than the stored one, sent under a new Idempotency-Key, is refused with 409
  and changes nothing; a retry under the original key still gets its original
  receipt. `identityRevision` without `contactId` is rejected (422). This is
  what makes a delayed or retried older request harmless once a newer one has
  applied.
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
  (eom-timetracker issue 282). Proposed in
  [`EOM_CUSTOMER_CREATE_MATCH_CONTRACT.md`](./EOM_CUSTOMER_CREATE_MATCH_CONTRACT.md).

## Slices and order

1. **A (Atlas):** migration, operator field, revision fence, capability, bill-to
   precedence.
2. **Website:** the portal shows a pending PATCH (202) as pending, not as saved,
   and shows the Site-route 409 `customer_identity_edit_required` as "rename
   this on the Customer". While a Customer has a pending identity change, its
   edit form starts from the pending values, so saving an unrelated field does
   not revert the pending change (the last save wins). This must deploy
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
11. The three worked sequences in "Reservation lifecycle", each as a test:
    revert after a timed-out apply; refusal of the replacement while B is
    pending (B stays pending and visible, then a save of A applies and
    supersedes it); and B pending then C applied (B superseded, never retried,
    and a delayed B refused by the fence). Retry sends only the newest pending
    reservation. Create: the create body carries no `billing_address`; after
    linking, the identity sync sends it, and a create whose email matches a
    contact linked to another Customer still returns the link conflict and
    leaves that contact's `billing_address` unchanged.
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
16. Shared contact: with two Customers holding one `atlasContactId`, a PATCH
    changing either one's name or billing address, a repair, and a conversion
    or post-create sync each return 409 `customer_atlas_contact_shared` with the
    other Customer id, make no Atlas call, create no reservation, and change no
    row. A PATCH that leaves the identity unchanged still applies as today.

Live settle: after A and B deploy, run the repair for Milano. Confirm in Atlas
that `full_name` is the business name, `billing_address` is set, and `address`
is unchanged. Then confirm that a November invoice dry run for Milano bills the
business at that address, before 2026-12-01.
