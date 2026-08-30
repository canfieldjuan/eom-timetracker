# EOM card-vault Tracker bridge contract

## Root cause

Atlas owns the token-bound hosted card-setup session and the provider-confirmed
card-readiness state, but Tracker exposes neither operation. The Website cannot
reach that authority through its canonical backend and would otherwise have to
call Atlas directly, duplicate Stripe authority, or infer success from a
redirect marker. All three choices cross the intended trust boundary.

The defect is the missing closed consumer bridge. It is not a Stripe provider,
payment, Terms, first-clean, or onboarding-state defect.

## Required change surface

1. Admit exactly two Atlas method/path signatures: the public token-bound
   card-session POST and the authenticated staff card-readiness GET.
2. Forward the opaque public bearer only in the private service-to-service
   request body. Never parse it, persist it, log it, place it in a URL, or
   reflect it in an error.
3. Require an authenticated Tracker admin for readiness and forward the bounded
   actor headers already used by Atlas staff reads. The public session route
   must never forward an actor.
4. Validate Atlas responses through closed Tracker projections. The public
   projection may expose only status, hosted checkout URL/expiry,
   provider-confirmation time, and idempotency; Atlas enrollment, candidate,
   and contact identifiers remain private. The staff projection may expose the
   contact, audience, required/ready verdict, reason, and provider-confirmation
   time, but not enrollment or candidate identifiers.
5. Keep public invalid-token/state outcomes indistinguishable, map service and
   malformed-response failures to stable non-reflecting errors, and preserve
   retry guidance for temporary failures.
6. Publish two independent deployment proofs on the existing funnel review
   response. Each proof must require both Atlas's exact capability name and its
   exact registered method/path from one strict manifest.
7. Add boundary tests for route/actor/path/payload admission, capability and
   route proof, public success/replay/error non-reflection, malformed upstream
   state, staff authentication, and readiness projection.

The proxy route set, capability names, provider response states, and emitted
browser fields are **CLOSED, ENUMERATED**. Atlas remains the card-vault and
Stripe authority; Tracker is a bounded relay.

## Explicit non-scope

- Tracker and Website do not load the Stripe SDK, hold Stripe keys, create
  SetupIntents, consume webhooks, charge cards, or store payment-method data.
- Terms acceptance, first-clean completion, candidate eligibility, commercial
  exemption, and provider-confirmed readiness semantics do not change.
- No backend schema, migration, payroll, scheduling, billing, save,
  verification, correction, exclusion, or audit behavior changes.
- No trusted exception, reminder automation, or recovery mutation is added.
- No Website files or visible customer/staff UI change in this PR. The later
  Website slice must carry the opaque bearer across the same-tab Stripe
  redirect in session-only storage, consume and delete it on return, and query
  this bridge. A `cardVault=success` query marker is never readiness proof.
- Atlas deployment, migration application, and Stripe credential provisioning
  are separate pre-live gates and are not performed by this Tracker change.

## Verification plan

- Run the focused card-vault bridge test module.
- Run the repository's relevant backend syntax, lint, format, and audit checks.
- Probe both sides of every guard: public/private actor separation,
  missing/extra/wrong-type path parameters, GET payload rejection, malformed
  manifest members, malformed provider state, and secret non-reflection.
- Reconstruct the final diff from `origin/main`, cite every changed file and
  line, and confirm every hunk traces to this contract with no non-scope change.
