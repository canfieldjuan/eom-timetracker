# Example finding — PASSES the audit-format gate

Every Confirmed claim carries a citation, and all three buckets are present.

## Confirmed

- Both retired entry URLs share one redirect handler — `backend/time_tracker_api.py:4837-4842`.
- A non-empty QR token is percent-encoded into the portal redirect — `backend/time_tracker_api.py:4849-4850`.

## Contradicted

- "Ordinary backend entry requests still serve Firefly" is contradicted by the
  unconditional redirect — `backend/time_tracker_api.py:4847-4855`.

## Could-not-determine

- Whether an employee has an old backend URL bookmarked is external usage and
  not observable from repository code.
