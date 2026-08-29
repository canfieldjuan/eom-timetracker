# EOM customer Terms English-only bridge contract

## Root cause

Atlas owns the customer Terms language policy, but Tracker duplicates that
boundary by admitting both `en` and `es` in its invitation request and public
customer projections. That allows Tracker to forward a Spanish
customer-document request and to relay a Spanish Terms snapshot or acceptance
receipt even when the provider supports English only. Historical invitation
records are different: they are employee-facing operational data and must remain
readable and revocable in either previously supported language.

The defect is the duplicated, wider admission boundary. It is not an employee
portal translation defect and it is not a document-content defect.

## Required change surface

1. Define English as the only valid customer Terms locale at Tracker's
   invitation request boundary.
2. Define English as the only valid locale in newly issued invitation,
   public-session, and acceptance response projections so a stale or
   incompatible provider cannot emit new Spanish customer Terms data through
   Tracker.
3. Preserve `en` and `es` in the bounded office projection used to return a
   successful revocation of a historical invitation. Narrowing new customer
   intent must not turn a completed cleanup mutation into a false 502.
4. Preserve the existing endpoint and JSON field shapes while rejecting `es`,
   missing locale values, and other unsupported values through the existing
   validation/error paths for new invitation and public customer requests.
5. Add boundary tests proving:
   - an English invitation is forwarded unchanged;
   - an `es` invitation is rejected before capability checks or provider I/O;
   - a provider response for a newly issued invitation, public session, or
     acceptance carrying `es` is rejected before it reaches the caller;
   - a successful historical Spanish invitation revocation remains visible to
     the employee; and
   - ordinary English Terms requests and responses keep their current behavior.

The new and public customer Terms locale set is **CLOSED, ENUMERATED**: `en` is
its sole member. Atlas is the policy authority; Tracker enforces the same closed
value at customer intent and rendering boundaries while retaining bounded
bilingual historical metadata for office cleanup.

## Explicit non-scope

- Employee and admin interface localization and historical operational data
  remain bilingual English/Spanish.
- Residential and commercial Terms audiences remain distinct.
- Terms prose, versioning, hashes, publication, invitation expiry, acceptance
  meaning, and delivery state do not change.
- Authentication, Juan-only mutation authorization, capability discovery,
  route allowlists, token handling, client-IP normalization, error mapping, and
  response field names do not change.
- General customer onboarding, lead approval, scheduling, billing, payroll,
  email transport, databases, schemas, migrations, and deployment settings do
  not change.
- The Website's visible customer/admin Terms controls are a later consumer
  slice and do not change in this PR.

## Assumptions and blockers

- Atlas's English-only provider contract must merge before this consumer PR is
  published or merged.
- Historical stored `es` records may exist, so this change narrows new/public
  admission without altering persistence or preventing their revocation.

## Verification plan

- Run the focused Terms bridge test module.
- Run the repository's relevant backend test/lint/format checks.
- Probe both request and provider-response sides with English and Spanish
  locale values, including rejection before side effects.
- Reconstruct the final diff from `origin/main`, cite every changed file and
  line, and confirm every hunk traces to this contract with no non-scope change.
