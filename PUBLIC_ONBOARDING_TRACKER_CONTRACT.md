# Public Onboarding Tracker Contract

## Purpose and root cause

Atlas now has a service-only public-onboarding session, private tracker-context,
finalize, and recovery boundary. The Tracker has no corresponding public route
or durable local operation. Its only customer create entry point requires an
authenticated admin and rejects a supplied Atlas contact ID
(`origin/main:backend/time_tracker_api.py:16338-16356`), while the reusable
local insert helpers can create a Customer and Site only after a caller has an
Atlas contact ID (`origin/main:backend/time_tracker_api.py:15161-15247`).

The root cause is therefore a missing **Tracker-owned, durable handoff
boundary**, not a missing form. A raw public bearer can be resolved by Atlas,
but the Tracker neither retains the token/draft/contact identity with the local
Customer/Site IDs nor has a safe, administrator-gated way to finish an
ambiguous handoff after the raw bearer is no longer usable. Reusing the admin
create route would be wrong: it represents a different authority path and
would make the browser supply a system-managed link.

## Correct fix

This slice must add only the Tracker half of that boundary.

1. Add service-only Tracker-to-Atlas request/projection helpers for the closed
   public-onboarding route set: `session`, `tracker-context`, and `finalize`.
   The browser sends an opaque bearer only to Tracker; the Tracker sends the
   Atlas service credential and must never return the private token, draft,
   contact, or local record IDs to the browser. Atlas's existing private
   context is the only source for the durable IDs.
2. Add `POST /api/public/onboarding/session` and
   `POST /api/public/onboarding/complete`. Session relays only the browser-safe
   immutable prefill projection. Complete obtains private context, accepts no
   browser-controlled Customer/Site data, and uses the context to create one
   local Customer plus one Site atomically.
3. Add one additive `eom_public_onboarding_reservations` table. It must retain
   the Atlas `token_id`, `draft_id`, and `contact_id` plus the created Tracker
   Customer/Site IDs, pending/finalized state, timestamps, and bounded error
   text. It must never contain a raw bearer. Creation of the Customer, Site,
   and reservation must be one local transaction under the existing
   customer/site mutation lock; Atlas finalization happens only after that
   transaction commits.
4. Before creating records, fail closed to a browser-safe `review_required`
   conflict when this contact already has any local Customer link or a pending
   Tracker/Atlas customer reservation, when a local Site already owns the
   normalized address, when the address cannot form a Site, or when the Atlas
   customer type is not `residential` or `commercial`. The admitted customer
   type set is **CLOSED / ENUMERATED** as `{residential, commercial}`; every
   other current or future value is **OPEN / DERIVED** from Atlas context and
   takes the safe staff-review default rather than being guessed.
   The existing generic Atlas-customer finalizer must use that same local
   mutation lock to refuse, rather than duplicate, a contact that the public
   handoff has reserved between the generic remote call and its local insert.
5. Finalize the reservation through Atlas with the raw bearer and exact local
   IDs. A confirmed matching completion marks the reservation finalized. A
   transport error, lost response, revoked/invalid bearer after local commit,
   or local-finalization failure leaves the reservation recoverable; it must
   not delete or silently create another Customer/Site. A later completed Atlas
   context with matching local IDs may repair the local finalized marker.
6. Add authenticated admin routes to list local public-onboarding reservations,
   revoke an issued public link by its stored draft ID, and recover a pending
   reservation. Recovery and link revocation must use the existing configured
   Juan approver guard before the Tracker sends Atlas actor headers. Recovery
   calls Atlas's actor-audited recovery route using only stored IDs, validates
   the matching completion receipt, and then finalizes the local reservation.
   Normal admins may inspect the list but cannot mutate these handoff states.
7. Cover the public boundary, the browser/private projection split, recognized
   and review-required contexts, exact local persistence, duplicate/replay and
   mismatch paths, ambiguous finalization and recovery, authorization, raw-token
   non-persistence, and the configured-approver gate with real Tracker
   FastAPI/PostgreSQL tests. Add the new table to the disposable-test teardown.

## Must not change

- Do not change the existing admin Customer/Site, Atlas-contact reservation,
  office-estimate approval, payroll, QR/GPS, scheduling, billing, calendar,
  employee authentication, or correction paths. In particular,
  `POST /api/admin/customers` keeps its admin-only, Atlas-created-contact
  contract and generic customer PATCH keeps Atlas linkage system-managed
  (`origin/main:backend/time_tracker_api.py:16338-16356`,
  `origin/main:backend/time_tracker_api.py:17689-17743`).
  The one permitted interaction with the generic Atlas-customer finalizer is
  the fail-closed conflict check required above; it must not otherwise alter
  that route's request, response, or normal finalization behavior.
- Do not change Atlas source code, Atlas public-token grammar/HMAC policy,
  existing `/public-onboarding/session` response, Atlas finalization semantics,
  or deployed configuration values. This branch consumes the merged Atlas
  service contract only.
- Do not expose `ATLAS_FUNNEL_SERVICE_TOKEN`, a raw onboarding bearer, private
  Atlas IDs, or local Customer/Site IDs in an **unauthenticated public** browser
  response or access-log reason. Authenticated admin recovery/list routes may
  carry the opaque IDs required to operate on their own local queue. Do not add
  a browser direct-to-Atlas call.
- Do not add a unique `customers.atlas_contact_id` migration, perform a
  destructive migration, write production data, or broaden existing admin
  permissions. Preserve the current configured stable-ID approver guard
  (`origin/main:backend/time_tracker_api.py:15250-15263`).
- Do not add the Website no-login page, fragment handling, translations, form
  design, or customer-visible copy in this slice; those are the following
  Website vertical slice.

## Evidence classification before implementation

### Confirmed

- Tracker already has its own Atlas service credential and stable approver (`origin/main:backend/time_tracker_api.py:3786-3793`), and its existing service writer keeps that credential server-side while attaching an authenticated actor (`origin/main:backend/time_tracker_api.py:4071-4095`).
- The local schema already uses additive reservation tables and pending/finalized state for cross-service work (`origin/main:backend/time_tracker_api.py:5049-5086`).
- Existing Customer/Site insertion enforces normalized-address conflict handling inside the local mutation path (`origin/main:backend/time_tracker_api.py:15205-15247`).

### Contradicted

- “The existing admin Customer-create route can safely serve public onboarding”
  is false: it requires `get_current_admin` and rejects caller-provided
  `atlasContactId` (`origin/main:backend/time_tracker_api.py:16338-16356`).

### Could-not-determine

- Whether production has enabled the Atlas public-onboarding authority, whether
  a live public link exists, and whether live data contains historical duplicate
  Atlas links cannot be established from this source checkout. This slice makes
  no production request or mutation to infer them.

## Completion gate

Before opening the PR, reconstruct the implementation diff cold and compare
every changed hunk to this contract. Report all three Audit Protocol buckets,
with `file:line` citations, and lead with any untraced change, missing required
behavior, forbidden touch, failing test, or unresolved actionable review
thread. Do not declare this slice complete while such a gap remains.

## Cold diff audit (after implementation)

### Gaps

None found. `git diff --check` is clean. The diff is limited to this contract,
the Tracker API, the disposable-test teardown, and a new focused PostgreSQL
test module. The only changed pre-existing behavior is the documented
fail-closed public-onboarding conflict in the generic Atlas-customer finalizer
(`backend/time_tracker_api.py:16037`); it is the narrow exception expressly
required at contract lines 51-53 and permitted at lines 82-84. No payroll,
QR/GPS, billing, calendar, customer PATCH, employee-authentication, Atlas, or
Website source file is touched.

### Actual change-by-change traceability

1. Contract requirement 1 (lines 25-30) is implemented by the string-only
   bearer request and bounded server models
   (`backend/time_tracker_api.py:2491`, `backend/time_tracker_api.py:2502`),
   the three-path service-only allow-list and transport
   (`backend/time_tracker_api.py:4192`, `backend/time_tracker_api.py:4212`),
   validated Atlas projection (`backend/time_tracker_api.py:4278`), and the
   public session handler (`backend/time_tracker_api.py:16912`). The public
   error relay discards untrusted upstream text at
   `backend/time_tracker_api.py:16890`.
2. Contract requirements 2-3 (lines 31-42) are implemented by the atomic
   public reservation writer under the existing mutation lock
   (`backend/time_tracker_api.py:16703`) and its additive durable table
   (`backend/time_tracker_api.py:5259`). The complete handler obtains context
   before this writer and finalizes only afterward
   (`backend/time_tracker_api.py:16930`, `backend/time_tracker_api.py:16977`).
3. Contract requirement 4 (lines 43-53) is implemented by the closed
   residential/commercial mapping and review-required response
   (`backend/time_tracker_api.py:16516`, `backend/time_tracker_api.py:16530`),
   local customer/reservation checks (`backend/time_tracker_api.py:16678`),
   normalized-address insertion under the same lock
   (`backend/time_tracker_api.py:16723`), and the reciprocal generic-finalizer
   refusal (`backend/time_tracker_api.py:16037`).
4. Contract requirement 5 (lines 54-59) is implemented by exact completion
   validation (`backend/time_tracker_api.py:16839`), marker finalization
   (`backend/time_tracker_api.py:16788`), completed-context reconciliation
   (`backend/time_tracker_api.py:16859`), and the pending-recovery paths in
   the complete handler (`backend/time_tracker_api.py:16950`,
   `backend/time_tracker_api.py:16992`).
5. Contract requirement 6 (lines 60-66) is implemented by the authenticated
   read-only queue (`backend/time_tracker_api.py:17636`), the configured
   approver-gated revocation route (`backend/time_tracker_api.py:17678`), and
   actor-audited recovery from stored IDs (`backend/time_tracker_api.py:17733`).
6. Contract requirement 7 (lines 67-71) is implemented by the new real
   FastAPI/PostgreSQL tests: public projection and token boundaries
   (`backend/test_public_onboarding_tracker.py:104`), atomic persistence and
   marker repair (`backend/test_public_onboarding_tracker.py:187`), mismatch
   recovery (`backend/test_public_onboarding_tracker.py:291`), review conflicts
   (`backend/test_public_onboarding_tracker.py:340`), the cross-channel race
   (`backend/test_public_onboarding_tracker.py:438`), recovery/list/approver
   behavior (`backend/test_public_onboarding_tracker.py:495`), and revocation
   plus unauthenticated-list rejection
   (`backend/test_public_onboarding_tracker.py:574`,
   `backend/test_public_onboarding_tracker.py:623`). The test schema teardown
   drops the new table at `backend/conftest.py:72`.

### Confirmed

- The browser-visible public path exposes only a selected ready/completed projection (`backend/time_tracker_api.py:16550`), rather than the private Atlas IDs, and the tests pin both private-ID and raw-bearer non-reflection (`backend/test_public_onboarding_tracker.py:127`, `backend/test_public_onboarding_tracker.py:168`).
- A ready context produces one Customer, one Site, and one durable reservation in a single local transaction (`backend/time_tracker_api.py:16721`), while the end-to-end test proves the exact persisted link and no raw-token column (`backend/test_public_onboarding_tracker.py:236`).
- A failed or mismatched finalize leaves the reservation pending, and a completed context or authorized recovery can finish its marker (`backend/time_tracker_api.py:16950`, `backend/time_tracker_api.py:16992`, `backend/test_public_onboarding_tracker.py:291`, `backend/test_public_onboarding_tracker.py:495`).

Local verification passed: focused public/adjacent tests, Ruff, and compilation;
the complete backend suite passed **1238 tests** with only the two existing
FastAPI deprecation warnings.

### Contradicted

- No contract claim is contradicted by the implementation. The initial raw
  upstream-diagnostic path was an implementation gap found during this cold
  read; it is now contradicted by the sanitizing relay at
  `backend/time_tracker_api.py:16890` and its regression test at
  `backend/test_public_onboarding_tracker.py:168`.

### Could-not-determine

- Whether production has the required Atlas authority/configuration, whether a
  live public link exists, and whether production contains historical duplicate
  contact links remains unverified without a production read. This branch made
  no production request or mutation; the earlier boundary remains documented
  at lines 121-126.
