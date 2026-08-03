# Arrival Exception Review Contract

This slice turns the read-only arrival-versus-timecard exceptions into an
auditable admin queue. Juan or Mayra can record what they decided without the
review action creating, editing, or deleting a shift, visit, QR check-in, or
payroll record.

## Evidence version

Each reconciliation row receives a server-generated SHA-256 fingerprint over
the evidence that determines its result: scheduled start, outcome, QR identity
and review state, paid-event identity and arrival time, site, and timestamp gap.
Employee and site display names are not part of the fingerprint.

The browser must return that fingerprint with a review. The server rebuilds the
company-date reconciliation and rejects a stale fingerprint with HTTP 409. A
saved disposition applies only while its fingerprint remains current. Changed
QR or timecard evidence automatically reopens the exception instead of hiding
new facts behind an older review.

## Dispositions

- `resolved`: the admin reviewed the current evidence and determined that no
  timecard change is required. The exception leaves the open queue but remains
  visible in resolved history.
- `needs_correction`: the current evidence requires follow-up in the existing
  guarded time-data correction workflow. It remains in the open queue.

Both dispositions require a 3-to-500-character note. Every disposition is an
append-only record containing the occurrence key, evidence fingerprint,
employee, site, scheduled start, outcome and evidence snapshot, authenticated
admin identity, note, and official server timestamp. A later disposition does
not erase an earlier one.

## API and admin view

`GET /api/admin/site-check-in-reconciliation` remains read-only and can filter
the derived rows by open, reopened, resolved, or needs-correction review state.
It returns total exception counts separately from open-review counts.

`POST /api/admin/site-check-in-reconciliation/{occurrenceKey}/review` is
admin-only. It validates the current evidence fingerprint and stores only the
review record. The response explicitly reports that no timecards changed.

The admin **Arrival vs. Timecard** view defaults to open exceptions, shows the
latest disposition and note, and offers **Resolve — no timecard change** and
**Flag timecard correction** actions.
