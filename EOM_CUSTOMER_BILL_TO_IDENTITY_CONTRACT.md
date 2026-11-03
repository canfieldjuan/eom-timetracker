# EOM customer bill-to identity contract

Status: **proposed, awaiting operator review.** This commit is the contract
only; no implementation lands with it.

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
  characters (the tracker's limit). Existing rows stay null.
- The operator boundary admits `billing_address` (`billingAddress` on the wire)
  alongside the fields in `EOM_OPERATOR_CONTACT_FIELDS`
  (`atlas_brain/services/eom_crm_mutations.py:108`), with the same rules:
  absent means untouched. An explicit null clears it only on an edit that names
  its `contactId`. A create-or-return request never carries a null, because
  that would clear a value on a contact it merely matched (0C's reasoning).
- The capability manifest (`funnel.py:1214`) advertises
  `contact.billing_address`, so a tracker can tell whether Atlas accepts it
  (0E negotiation).
- Bill-to address on invoices: monthly generation and `create_invoice` use
  `billing_address` when it is set and fall back to `address` when it is not.
  The rule is that a Customer with a billing address is billed there; a contact
  without one (residential and legacy) keeps billing to its address, exactly as
  today.
- Booking calendar events keep `location = address`. Invoices already created
  keep their snapshot; nothing rewrites them.

**Slice B: tracker**

- **PATCH.** When a PATCH changes `name` or `billingAddress` on a linked
  Customer (compared with the stored values, because the deployed portal sends
  every field on every edit), it runs the saga. It reserves the change, sends
  `{contactId, full_name, billing_address}` to `POST /eom-funnel/operator-contacts`,
  and applies the **whole** PATCH locally only after Atlas confirms. A PATCH
  that leaves both values unchanged keeps today's behavior and makes no Atlas
  call.
- **Office conversion.** After the handoff saga links the Customer, the same
  identity sync runs for it. If that sync fails, the conversion still stands
  (the handoff is its own saga), and the identity reservation stays pending and
  visible.
- **Repair.** `POST /api/admin/customers/{customer_id}/atlas-identity` (new and
  additive) sends a linked Customer's current name and billing address through
  the same saga. An unlinked Customer gets 409 and is pointed at the existing
  `/atlas-contact` reconcile. This is how Milano, and any Customer whose identity
  is pending, gets fixed.
- **Create (0C).** Adds `billing_address` to the body when it is present.

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
| Deployed Atlas lacks `contact.billing_address` | 501 `atlas_capability_unavailable` | Nothing applied, no Atlas call |
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
- **Atlas-side edits mirroring back to the tracker.** The legacy writers stay
  0D's job.

## Slices and order

1. **A (Atlas):** migration, operator field, capability, bill-to precedence.
2. **Website:** the portal shows a pending PATCH (202) as pending, not as saved.
   This must deploy before B, or B's 202 reads as a silent success.
3. **B (tracker):** PATCH, conversion, repair, and create.

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
3. An absent `billingAddress` leaves it untouched. An explicit null with
   `contactId` clears it. An explicit null without `contactId` is rejected (422).
4. Invoice bill-to: a contact with `billing_address` produces
   `customer_address = billing_address`; a contact without one produces
   `customer_address = address`. Both sides are tested, plus
   `customer_name = full_name`.
5. The manifest advertises `contact.billing_address`. A tracker that never
   sends it sees no change.

Tracker (slice B):

6. PATCH changing `name` on a linked Customer with Atlas up: Atlas receives
   `contactId`, `full_name`, and `billing_address`; the row updates; the
   response shape is unchanged.
7. Atlas unreachable: 202, and the test asserts the row is **unchanged** (not
   just the status). A retry with the same key applies the change.
8. A PATCH echoing the stored values makes zero Atlas calls.
9. Name A, then B, then A sends three distinct keys, and Atlas ends at A.
10. An office conversion sends the Customer name and billing address for the
    converted contact. A failed sync leaves a pending reservation that
    `GET /api/admin/customers` shows.
11. Repair on a linked Customer sends its current identity; on an unlinked one
    it returns 409. Two concurrent identity edits serialize (two-connection
    test).
12. Atlas refusal returns 409 and applies nothing. A missing capability returns
    501, with no Atlas POST and nothing applied.

Live settle: after A and B deploy, run the repair for Milano. Confirm in Atlas
that `full_name` is the business name, `billing_address` is set, and `address`
is unchanged. Then confirm that a November invoice dry run for Milano bills the
business at that address, before 2026-12-01.
