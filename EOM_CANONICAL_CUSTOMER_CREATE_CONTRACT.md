# EOM canonical customer create contract

Slice 0C of the canonical write boundary (website #110, umbrella #105).

## Problem-derived contract

### Root cause

`POST /api/admin/customers` wrote a Customer with zero Atlas calls:
`admin_create_customer` -> `_insert_customer` inserted the row and returned it.
A Customer created in the office was therefore invisible to the CRM, which is
why 2 of 52 live Customers carried `atlas_contact_id IS NULL`. Separately,
`atlas_contact_id` sat in the ordinary `PATCH /api/admin/customers/{id}` field
map, so a routine customer edit could repoint CRM linkage silently.

Decision D1 of #105 is that Atlas is the only write authority for leads and
customers, enforced in the backend -- many doors, one canonical write path.
0A landed the CI guard, 0B landed the Atlas operator-mutation endpoint, and 0E
landed capability negotiation. 0C is the tracker becoming a well-behaved caller.

### Correct fix

The tracker and Atlas are separate databases, so this is a saga, not a
distributed transaction. The ordering is the contract:

1. Validate everything the local insert will validate, then commit a durable
   reservation. **No `customers` row yet.**
2. Call Atlas `POST /eom-funnel/operator-contacts` with the reservation's
   idempotency key, `sourceChannel: time_tracker`, and `sourceRef` = the
   reservation id.
3. Only once Atlas has answered with a contact id, write the Customer (and its
   optional primary Site) with the link already set, and mark the reservation
   finalized.

Because the local row is written last, an unreachable Atlas cannot leave a
canonical Customer behind. That property is structural: it does not depend on
every reader remembering to honor a "pending" flag.

Recovery leans on Atlas's own idempotency receipt rather than local bookkeeping.
Finalization is one local transaction; if any part of it fails, nothing is
written and the reservation stays pending. The retry re-sends the **same**
Idempotency-Key, which Atlas answers with the **same** contact. There is
therefore no window in which a retry produces a second contact, and no
compensating delete is ever issued against a contact Atlas already created.

### Must not change

- The `customers` array shape returned by `GET /api/admin/customers`, or the
  `{"success": true, "customer": ...}` shape returned on a successful create.
  `pendingAtlasReservations` is an additive sibling key.
- The office estimate-approval path (`/api/admin/funnel/approve-estimate`) and
  its `eom_office_conversion_handoffs` saga. That flow converts a lead that
  already exists in Atlas, so it keeps supplying `atlasContactId` itself.
- Calendar import, schedules, payroll, shifts, QR check-in, and receivables.

## Execution model

| Outcome | Status | Local result |
|---|---|---|
| Atlas created or returned the contact | 201 | Customer written and linked |
| Replay of a finalized reservation | 200, `idempotent: true` | Same Customer |
| Atlas unreachable, timed out, or refused | 202, `error: customer_atlas_pending` | **No Customer**; reservation pending and retryable |
| Deployed Atlas lacks the capability | 501, `error: atlas_capability_unavailable` | **No Customer, no reservation, no Atlas call** |
| Same key, different customer details | 409 `customer_atlas_retry_mismatch` | No second Customer |
| Caller supplied `atlasContactId` | 422 | No Customer |

Retry: `POST /api/admin/customers/reservations/{reservation_id}/retry`.
Reconcile an existing unlinked Customer:
`POST /api/admin/customers/{customer_id}/atlas-contact`.

### Idempotency keys

`idempotencyKey` is optional on create. Supplying it is what buys replay
protection: the same key always resolves to the same reservation and therefore
the same Atlas contact. The portal generates one per open form.

When no key is supplied the server mints a fresh one rather than deriving one
from the payload. A derived key looks safer but is not: two genuinely distinct
customers can share every field -- equal names are normal here, and Edward Jones
(46/51) and Mid Illinois (41/42) are live examples -- so a derived key would
silently merge two real customers into one. Losing replay protection for a
caller that opted out of it is visible and recoverable; a silent merge is not.

### What is sent to Atlas

Only non-empty identity fields: `full_name`, `email`, `phone`, plus
`contact_type`, `source_channel`, and `source_ref`.

Atlas's operator boundary is create-**or-return**: when it matches an existing
contact (by source ref, provenance, phone last-10, or email) it applies the
fields it receives as operator intent. Sending an explicit null would therefore
CLEAR a value on a contact this customer merely matched on. Address and notes
are deliberately not mapped: the CRM's copies come from other sources, the
operational address lives on the tracker Site, and overwriting them here would
be silent data loss for no gain in this slice's guarantee.

## Linkage is system-managed

`atlasContactId` is no longer a writable field on create or edit.

- Create rejects a caller-supplied value with 422.
- PATCH refuses a *changed* value with 409 `customer_atlas_link_system_managed`.
  Echoing back the stored value stays a no-op, because the deployed portal sends
  every field on every edit; refusing that would break ordinary customer edits
  the moment this deploys. A silent drop was rejected as the alternative: it
  would look like a successful edit that did nothing.

## Scope this slice does NOT close

After 0C the **operator create path** can no longer produce a canonical Customer
that Atlas does not know about. Three legacy writers still can, and are 0D's job
(#111):

- `POST /api/admin/locations` creates a Customer from `customerName` when no
  `customerId` is given.
- `PUT /api/admin/locations` (legacy bulk update) does the same, in two places.
- The schema-init backfill derives Customers from legacy `locations.customer_name`.

Also out of scope, deliberately:

- **No uniqueness index on `customers.atlas_contact_id`.** Three duplicate-link
  groups exist in production (Mid Illinois 41/42, Kinder Morgan 37/45, Edward
  Jones 46/51); email and phone are not identity here. The linkage audit reports
  them; an index would refuse writes instead.
- No CRM create UI (Slice 2) and no lead promote flow (#104).

## Review contract

1. With Atlas unreachable, a create returns 202 and the `customers` table gains
   no row. The test asserts the absence, not just the status code.
2. A capability-less Atlas is refused before any local write and before any
   Atlas POST.
3. Replaying one key returns the same Customer and does not ask Atlas again.
4. A local failure after Atlas succeeded is recoverable by retry against the
   same contact id, with both calls carrying the same Idempotency-Key.
5. Two unkeyed creates of an identical payload produce two distinct Customers.
6. PATCH cannot change or clear the link; echoing the stored value succeeds.
7. Reconciling an unlinked Customer removes it from the linkage audit's
   `unlinkedCustomers`.

Covered by `backend/test_customer_atlas_creation.py` and the additions to
`backend/test_atlas_linkage.py`.
