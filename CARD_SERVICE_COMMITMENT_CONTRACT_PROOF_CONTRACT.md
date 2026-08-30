# Service-commitment contract proof

## Root cause

Tracker currently publishes only a boolean deployment proof for the Atlas
service-commitment relay. That proves the route and capability are deployed,
but it does not prove that a downstream consumer and Tracker agree on the
closed values accepted by the route. A consumer can therefore remain enabled
after Tracker adds or renames a value while still rejecting that value locally.

## Required change

1. Define the closed `recurring` / `one_time` vocabulary once in
   `backend/time_tracker_api.py` and derive request validation, candidate
   validation, and the advertised review-page value list from that definition.
2. Add an additive `postCleanServiceCommitmentValues` field to the admin review
   response. It must be a JSON array containing the exact canonical values.
3. Preserve the existing boolean availability proof and its exact Atlas
   capability/route gate. The value list describes semantics; it does not make
   an unavailable route available.
4. Add focused tests proving the advertised set and both accepted boundary
   values come from the same canonical definition, while a value outside that
   definition remains rejected before Atlas is called.

The value set is **CLOSED, DERIVED**. Membership is finite and canonical in the
single type alias; every validation and advertised representation is computed
from that alias. A Website with a different set must fail closed.

## Explicit non-scope

- No Atlas source, persistence, capability, route, database, migration, or
  immutable-decision change.
- No new commitment value and no change to the existing mutation request or
  receipt shape.
- No authorization, audit-log, idempotency, card-vault, onboarding, Terms,
  email, calendar, payroll, attendance, billing, or location change.
- No dependency or deployment-configuration change.

## Verification

- Run the focused service-commitment bridge tests.
- Run the relevant backend static checks configured by the repository.
- Run `git diff --check` and reconstruct the diff against `origin/main`.
