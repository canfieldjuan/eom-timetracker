# Example finding — MUST FAIL the audit-format gate

This fixture is intentionally non-compliant. The CI self-test asserts the checker
rejects it. Two violations on purpose:
  1. The Confirmed item below has no file:line citation.
  2. The "Could-not-determine" bucket heading is missing entirely.

## Confirmed

- The monthly report is completely broken and every report ever generated is wrong.

## Contradicted

- None
