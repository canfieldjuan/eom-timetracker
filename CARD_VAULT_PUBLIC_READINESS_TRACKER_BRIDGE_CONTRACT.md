# Card-vault public-readiness Tracker bridge contract

## Root cause

- Tracker currently admits only Atlas's public session POST and internal
  contact-ID readiness GET in its closed card-vault route set
  (`backend/time_tracker_api.py:5276-5294`).
- The only customer-facing card-vault route therefore starts or reuses a hosted
  setup session (`backend/time_tracker_api.py:22605-22624`), while the read-only
  route requires an authenticated admin and an internal contact UUID
  (`backend/time_tracker_api.py:23546-23575`).
- A public onboarding browser holds the opaque Terms bearer but no contact UUID.
  Without a token-bound read relay, it must either attempt the mutation-capable
  session path or guess whether card setup is required. Atlas now owns and live
  serves the missing `POST /eom-funnel/card-vault/public/readiness` authority.

## Required change surface

- Extend Tracker's closed, enumerated Atlas card-vault allow-list with exactly
  `POST /eom-funnel/card-vault/public/readiness`, classified as public so no
  actor header or path parameter can be forwarded.
- Add `POST /api/public/card-vault/readiness`, reusing the existing opaque token
  request boundary and forwarding only `{ "token": ... }` through the closed
  helper.
- Validate and return exactly `cardRequired`, `cardReady`, and the canonical
  readiness `reason`. Reject unknown fields, unknown reasons, wrong types, and
  inconsistent reason/boolean combinations before responding to the browser.
- Add `cardVaultPublicReadinessAvailable` to the admin review projection. It is
  true only when one Atlas response contains both the exact capability name and
  exact method/path signature.
- Extend the default Atlas test manifest and focused card-vault tests to prove
  the happy states, both guard directions, malformed/mixed manifests, request
  shape rejection before network, no actor forwarding, generic error mapping,
  and transport allow-list closure.

## Explicit non-scope

- Do not change database schemas, migrations, PostgreSQL data, or persistent
  storage.
- Do not change Atlas policy, Terms token grammar, service-commitment decisions,
  first-clean evidence, or card enrollment state.
- Do not create Stripe customers/sessions, handle webhooks, alter return URLs,
  or require Stripe credentials for this read.
- Do not change the existing public card-session response/semantics, internal
  admin readiness response/semantics, admin authentication, CRM, calendar,
  payroll, billing, payment, or onboarding completion behavior.
- Do not add dependencies, broad refactors, renames, generated artifacts, or
  unrelated formatting.

## Assumptions and blockers

- Satisfied dependency: Atlas merge `5ac0fac8c5333e613c31f113e6161f3310da7a34`
  is live on localhost and the ts.net production path; both the exact capability
  name and POST route were observed in one authenticated manifest response.
- Tracker remains a credential-hiding relay and policy consumer. It must not
  reproduce Atlas eligibility queries or persist readiness locally.
- Real Stripe redirect/webhook proof remains separately blocked by production
  provider configuration; it is not required to prove this read-only bridge.

## Verification plan

- Run the focused regression file from `backend/`:
  `pytest -q test_funnel_card_vault.py`.
- Run blocking local quality gates from the repository root:
  `ruff check backend --output-format=github` and
  `node scripts/check_brittle_patterns.mjs --strict backend/time_tracker_api.py`.
- Run `python -m py_compile backend/time_tracker_api.py` and `git diff --check`.
- Let GitHub run the PostgreSQL-backed full pytest job and blocking lint job.
- Before merge, reconstruct the diff against fresh `origin/main`, re-poll the
  exact head's checks/reviews/threads, and require a clean worktree equal to the
  remote branch.

## Boundary declarations

- Atlas route signatures: **CLOSED / ENUMERATED** in Tracker. Any route not in
  the local frozenset fails before configuration or network work.
- Public readiness reasons: **CLOSED / ENUMERATED** from Atlas's published
  customer-safe contract. Cross-repository drift fails closed with 502 rather
  than exposing or guessing a new state.
- Opaque Terms bearer input: **OPEN / DERIVED upstream**. Tracker validates only
  the one-field request container; Atlas remains the canonical token parser and
  rejects every malformed, forged, expired, revoked, or drifted bearer.
- Capability proof: **CLOSED / DERIVED** from a single strict Atlas manifest
  response; either a missing/malformed name half or route half disables the
  advertised Tracker field.
