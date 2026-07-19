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
