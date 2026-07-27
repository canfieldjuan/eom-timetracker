# EOM office conversion handoff contract

## Problem-derived contract

### Root cause

The tracker already owns the structured Customer and Site data needed after a
completed estimate: a Customer can carry `atlas_contact_id`, and a primary Site
can carry rate, rate type, frequency, expected hours, scope, access, preferences,
pet notes, and service start date. The normal admin Customer create route writes
both rows in one local transaction, but accepts any admin and has no
idempotency/cross-system handoff contract. `atlas_contact_id` is not unique in
the current schema. Citations: `backend/schema.sql:17-60`,
`backend/time_tracker_api.py:1966-2029`, `:9079-9145`, `:9173-9192`.

Atlas correctly blocks generic lifecycle promotion after #2216. Therefore an
approved estimate currently has no safe owner for the sequence “Juan approves
completed estimate -> Customer + initial Site -> Atlas contact becomes customer.”
Creating a Customer first and losing the callback, or promoting Atlas first and
losing local creation, would leave two systems disagreeing. The public browser
cannot call Atlas because its service credential must remain on the tracker
server. The existing receivables proxy demonstrates that server-side pattern.
Citation: `backend/time_tracker_api.py:2732-2806`.

### Correct fix

The tracker owns the user-facing command because it can validate the existing
employee session. It must require both the admin role and a configured stable
Juan employee ID; a display name or generic `admin` role alone is insufficient.
Citation for current generic-admin boundary: `backend/time_tracker_api.py:587-594`,
`:639-673`.

The new approval endpoint must accept one completed-estimate payload with:

- the Atlas contact UUID;
- a stable, caller-supplied idempotency key;
- Customer contact/billing fields; and
- exactly one initial Site, including the estimate's price/rate type, preferred
  cleaning frequency/schedule, and other existing Site onboarding fields.

It must write a durable local handoff operation keyed by the Atlas contact and
approval key. Under the existing customer/site mutation lock, the operation
creates or returns exactly one Customer and initial Site. It invokes Atlas only
after the local commit, using a dedicated server-side funnel service token and
the same immutable key. A successful Atlas response marks the local operation
finalized; a transport failure leaves it pending and retryable. A different key
or payload for an existing contact fails closed instead of creating another
Customer.

Atlas owns the receiving finalization. It records only the contact/customer/site
IDs, approval key, and trusted actor evidence; it never copies the price,
frequency, schedule, or cleaning details. It transitions the active EOM
`lead/new` contact to `customer` only in that finalization transaction and
records its lifecycle event. This is the matching Atlas plan:
`plans/PR-EOM-Office-Conversion-Handoff.md`.

### Must not change

- Existing generic Customer/Site CRUD response shapes or current Customers.
- Calendar import, schedules, payroll, shifts, QR check-in, receivables, and
  public/employee portal behavior.
- Public website lead intake, inbound receipt semantics, or generic non-EOM CRM.
- The estimate price, rate type, frequency, service scope, or preferred schedule
  must not be copied into Atlas.
- A declined estimate, reopen, additional Sites, first clean, payment collection,
  and customer self-service onboarding are separate commands.

## Execution model

1. The office portal submits the completed estimate only to the tracker under
   Juan's authenticated employee session.
2. The tracker validates Juan's configured employee ID, the idempotency key,
   the complete Customer/Site payload, and a canonical request fingerprint.
3. In one tracker transaction, it locks the Customer/Site mutation surface and
   any existing handoff. It returns an identical completed operation, rejects a
   changed retry, or creates the Customer, Site, and pending handoff together.
4. After commit, the tracker calls Atlas with only opaque IDs, the approval key,
   and actor evidence using the dedicated funnel service credential.
5. Atlas atomically records the handoff and promotes the valid EOM lead. The
   tracker marks its operation finalized only after receiving that result.
6. If step 4 loses a response, retrying the original key repeats neither local
   creation nor Atlas promotion. If Atlas rejects the finalized payload, the
   tracker preserves the visible pending operation and its error for office repair;
   it never guesses a replacement contact or creates another Customer.

## Scope

1. Add a tracker-owned office approval endpoint, strongly configured
   Juan-employee authorization, dedicated Atlas-funnel proxy configuration,
   and a durable local handoff operation.
2. Reuse the existing Customer/Site insert helpers under their current mutation
   lock; do not invent a parallel Customer/Site model.
3. Add API/database tests for authority, input validation, duplicate retry,
   payload mismatch, callback failure/retry, and one Customer/one Site result.
4. Coordinate the exact JSON contract and finalization behavior with the Atlas
   companion PR before either is published as merge-ready.

## Review contract

1. A non-Juan admin receives a rejection before a Customer, Site, handoff, or
   Atlas request is made. The route test observes no local or remote side effect.
2. A valid completed estimate creates one Customer and initial Site, with rate
   and schedule on the Site only. The database test reads the canonical rows.
3. Repeating an identical idempotency key returns the same Customer/Site and
   reuses the same Atlas finalization key. A changed payload or new key for that
   contact fails closed.
4. A tracker-to-Atlas transport failure leaves one visible pending handoff;
   retry finalizes the same operation without a duplicate Customer, Site, or
   Atlas request identity.
5. The browser request never contains the Atlas funnel service token. Proxy
   tests inspect the upstream headers and the browser-visible error mapping.

## Deferred

- Declined/non-customer and explicit reopen.
- Estimate booking/calendar projection, reschedule/cancel, and first-clean.
- Customer self-service onboarding, payments/card collection, and extra Sites.
- Retrofitting legacy manually linked Customers; if duplicate existing
  `atlas_contact_id` values are found, resolve them by an explicit backfill before
  adding a broad uniqueness constraint to generic Customer CRUD.

## Verification

- `cd backend && pytest` with PostgreSQL on port 5433.
- Focused office-approval route/database tests and Atlas finalization tests.
- A joint test fixture or contract smoke that proves the exact tracker request
  and Atlas result shape, including retry after a lost response.
- `git diff --check` and a cold diff audit against this contract before publish.
