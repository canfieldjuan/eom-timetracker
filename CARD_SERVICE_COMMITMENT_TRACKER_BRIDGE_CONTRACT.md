# EOM card service-commitment Tracker bridge contract

## Root cause

Atlas owns one immutable residential `recurring` or `one_time` decision and
projects it on post-clean candidates, but Tracker's candidate model omits those
fields and Tracker has no authenticated route for recording the decision. The
Website therefore cannot use its canonical backend to read or write the Atlas
authority without either calling Atlas directly or inferring recurrence from
scheduling data.

The defect is the missing bounded consumer bridge. It is not a card-provider,
Terms, first-clean, calendar, payroll, or local-storage defect.

## Required change surface

1. Extend only the existing candidate projection with optional
   `serviceCommitment`, `serviceCommitmentDecidedBy`, and
   `serviceCommitmentDecidedAt` fields. A legacy all-null tuple remains valid;
   otherwise all three fields must be present, the actor must be nonblank, and
   the timestamp must include a timezone.
2. Admit one closed Atlas signature:
   `POST /eom-funnel/post-clean-onboarding-candidates/{candidate_id}/service-commitment`
   behind the exact published
   `customer.post_clean_service_commitment.decide` capability.
3. Add one authenticated-admin Tracker POST taking only a UUID idempotency key
   and the closed `recurring`/`one_time` value. Reject malformed or extra input
   before the capability check or provider call.
4. Forward only the decision body plus Tracker's authenticated actor headers
   and `Idempotency-Key`. The browser cannot choose an Atlas path, contact,
   actor, or provider identifier.
5. Validate and re-project the Atlas receipt. Bind its candidate UUID and
   decision value to the request, require a nonblank actor and timezone-aware
   decision time, strip extra fields, and return 201 for the first write or 200
   for an exact replay.
6. Add one review-manifest availability field using the same exact
   capability-and-route predicate as the mutation gate.
7. Keep post-provider audit logging best-effort so a local audit diagnostic
   cannot turn an already-recorded immutable Atlas decision into an apparent
   failure.

The capability name, method/path template, request fields, decision values,
candidate aliases, and receipt fields are **CLOSED, ENUMERATED** from the
deployed Atlas contract. Missing legacy candidate aliases default to the
all-null tuple; malformed or contradictory tuples and receipts fail closed.

## Boundary-change enumeration

- Candidate projection: legacy aliases absent -> preserved as null; all three
  decision aliases present and coherent -> exposed; partial, malformed, or
  timezone-naive tuple -> rejected as an invalid upstream response.
- Browser request: exact two-field request -> admitted after admin auth;
  missing, extra, malformed, or out-of-vocabulary fields -> 422 before Atlas.
- Manifest gate: exact capability plus exact POST template in one manifest ->
  mutation may proceed; either half absent/malformed/wrong method -> 501 with
  zero mutation calls.
- Receipt: requested candidate and decision plus valid metadata -> re-projected;
  mismatched identifiers/value, malformed metadata, or non-object response ->
  invalid upstream response.

## Explicit non-scope

- No Tracker database table, migration, persistent decision copy, or local
  recurrence inference.
- No Website files, labels, buttons, cards, email, or customer-facing change.
- No Stripe SDK/key/session/webhook/payment-method behavior and no card-vault
  admission or readiness change.
- No Terms content/invitation/acceptance, first-clean evidence, Customer/Site
  linkage, scheduling, calendar, payroll, attendance, location, billing,
  invoice, ACH/check, or commercial-policy change.
- No public route, employee route, dependency update, broad refactor, response
  rename, or unrelated test rewrite.

## Assumptions and blockers

- Atlas production advertises the exact capability and route and has migrations
  398/399 attested; the Tracker still gates every write from the live manifest.
- The later Website slice chooses the visible manager interaction. This bridge
  does not decide UI copy or workflow placement.

## Verification plan

- Focused candidate-projection and service-commitment bridge tests.
- Boundary probes for legacy/present/partial candidate tuples, request
  validation, both manifest halves, actor/idempotency forwarding, receipt
  binding, upstream errors, and audit failure after provider success.
- Ruff, brittle-pattern scan, audit-format self-test, Python compile, and
  `git diff --check`.
- Full backend test suite before merge when hosted GitHub jobs remain unable to
  produce logs.
- Cold diff reconstruction against `origin/main`, with every changed file and
  line traced to this contract and no non-scope movement.
