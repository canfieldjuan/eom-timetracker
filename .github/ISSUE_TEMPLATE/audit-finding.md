---
name: Audit / review finding
about: Report a code-verified finding (follows AUDIT_PROTOCOL.md)
title: "[finding] "
labels: audit
---

> Ground truth is the code. Cite `file:line` for every claim. Sort into the three
> buckets below and keep all three headings even if a bucket is "None". Never mark
> a claim Confirmed without a citation. See AUDIT_PROTOCOL.md.

## Summary

<!-- Lead with what's actually wrong or overstated, not a preamble. -->

## Confirmed

- <!-- claim — `path/to/file:line` -->

## Contradicted

- None

## Could-not-determine

- None <!-- e.g. runtime env value, external platform behavior; say why -->

## Severity & failure path

<!-- P1/P2 must state the concrete input or sequence that triggers the failure. -->

## Proposed fix (must be additive / production-safe)

<!-- No destructive migration, no data-disk writes, no changed response shapes. -->
