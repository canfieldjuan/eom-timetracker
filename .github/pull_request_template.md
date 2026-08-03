<!--
  If this PR reports findings, an audit, a review, or a claimed fix, fill in the
  "Findings" section below and add the `audit` or `review` label. The audit-format
  CI gate enforces that findings carry file:line citations and the three-way sort.
  See AUDIT_PROTOCOL.md. If this is a plain code change, delete the Findings block.
-->

## What this changes

<!-- Plain description of the actual diff, in your own words. -->

## Verification

<!-- The tool output that proves it works: passing tests, command output.
     If you have not verified something, say so — do not claim it works. -->

- [ ] `cd backend && pytest` passes (or CI green)
- [ ] Additive / backward-compatible: no destructive migration, no data-disk
      writes, no changed response shapes the portals read
- [ ] Independently safe to deploy (merges to `main` auto-deploy to production)

## Findings (delete if not an audit/review/claimed-fix PR)

> Ground truth is the code. Cite `file:line` for every claim. Include all three
> buckets even if a bucket is "None". Never mark Confirmed without a citation.

### Confirmed

- <!-- claim — `path/to/file:line` -->

### Contradicted

- None

### Could-not-determine

- None
