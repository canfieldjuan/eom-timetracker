# Audit & Review Protocol

**This is law for any audit, code review, security finding, bug report, or
"claimed fix" against this repository — human- or agent-authored. It is not a
suggestion.** A CI gate (`.github/workflows/audit-format.yml`) enforces the
*form* of this protocol on findings documents and labeled PRs. The *truth* of a
finding is still a reviewer's job — the gate only stops uncited, unstructured
claims from shipping.

It exists because a real audit of this system was weak until challenged: it
asserted conclusions that were true of *a* code path but not *the* default path,
and it cited a tool result from one repo as if it covered another. Both are
banned below.

## The ground rule

**The code is ground truth. Docs, comments, commit messages, PR descriptions,
issue text, prior audits, and this document included, are unverified claims
until checked against the code.** Read the relevant code directly, state what
actually happens, then compare that to what the claim says.

## Every finding must

1. **Cite `file:line` for every claim.** No citation → the claim does not exist.
   A bare `:1234` line reference is acceptable when the file is named in context;
   prefer `path/to/file.py:1234`.
2. **Sort every claim into exactly one of three buckets** — and include all three
   headings even when a bucket is empty (write "None"):
   - **Confirmed** — verified true, with a citation. Never mark Confirmed without one.
   - **Contradicted** — the claim is false or overstated, with the citation that
     disproves it.
   - **Could-not-determine** — cannot be settled from the code alone (e.g. a
     runtime env value, external platform behavior). Say why.
3. **Lead with what's wrong or overstated**, not with a summary. If the finding
   being reviewed is incorrect, the first sentence says so.
4. **Trace the default / actual path before characterizing behavior.** A branch
   that exists is not the branch that runs. Establish which path executes by
   default (flags, checkbox defaults, env, feature gates) before you describe
   what the system "does."
5. **Never cite a tool result you did not produce this session against the exact
   target.** Running a search on repo A does not license a claim about repo B.
   Running it on file X does not license a claim about file Y. If you did not run
   it here, on this, you have not verified it — say "not verified."

## Set-valued dependencies (declare the closure)

When a change adds or edits **a set whose membership a decision depends on** — a
literal list used in a branch, a pattern family, a list duplicating one that
exists elsewhere, or the set of behaviors/callers/fields the change must cover
to be complete — the PR answers two independent questions.

**1. Is the set closed or open?**

- **CLOSED** — membership is finite and fully enumerable here. Cite where the
  canonical list lives.
- **OPEN** — membership is not fully enumerable, so any list is a heuristic.
  State what happens to members not in the list, and make incompleteness err to
  the cheap-error side.

**2. Where does membership come from?**

- **ENUMERATED** — written out in this change.
- **DERIVED** — computed at runtime from a source of truth, so it cannot drift.
  Prefer this wherever a source of truth exists; it is the only sourcing that
  stays correct without maintenance.

**The two questions are independent, and answering the second never discharges
the first.** A DERIVED set can still be open: derivation says where membership
comes from, not what happens to an input outside it — a set derived from a
schema still needs a stated behavior for a key that schema does not carry.
"DERIVED" alone is not a complete declaration.

**Enumerating an open set with no declared default is the defect.** A list that
looks complete today is indistinguishable, in review, from one deliberately
partial with a safe default — the declaration is what makes the difference
visible. Every member found later is a real finding, so the loop cannot be
shortened by relaxing review; it converges only when the PR says what *generates*
membership instead of what is currently in the set.

A list copied from elsewhere is CLOSED only if something enforces the copy.
Otherwise it is a DERIVED candidate that was not derived, and it will drift
silently. Prefer inverting ownership — have the consumer call the canonical
definition — over maintaining two copies.

Observed here: `ALLOWED_ORIGINS = _configured or DEFAULT` (#15) worked only when
the env var was empty, and the deployed value was not — #16 replaced it with a
union that cannot disable first-party origins. The same shape produced the
`DATA_DIR` and `TIMEZONE` findings in #63: the set of deployed configuration
values was assumed rather than read, and `render.yaml` is not truth — it has
drifted from the deployed values more than once. Config-shaped sets are almost
never CLOSED here; read the deployed value, or default explicitly.

Reviewers state each set-valued dependency and both of its answers before
approving. An open set with no declared default is "needs the closure
declaration," even when every listed member behaves correctly.

This rule is stated in full here and governs PRs in this repository. The Atlas
repo carries a longer-form version covering guards over an open input space —
fail-closed choke point, class-closure, and a generative property test — which is
related reading, not an authority over this file. Each repo's protocol governs
its own PRs and they are expected to diverge where the stacks differ. Provenance:
adapted from Atlas `docs/GUARD_CLASS_CLOSURE.md`, 2026-07-26.

## Severity (blast radius, not taste)

- **P1** — exploitable security or realistic data loss/corruption. State the
  concrete input/sequence that triggers it, or downgrade.
- **P2** — breaks a primary or plausible path, silent failure, broken contract,
  or a race under load. State the failure path, or downgrade.
- **P3/P4** — quality/robustness. Non-blocking. "No P1/P2 found" is a complete,
  valid result — do not manufacture severity to have something to say.

## Production-safety (this system is live and in use)

Every fix must be additive and backward-compatible: no destructive migrations,
no writing to or clearing the persistent data disk, no changing response shapes
the running portals read. Merges to `main` auto-deploy. Each PR must be
independently safe to deploy.
