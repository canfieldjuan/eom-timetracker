# Issue #19 Stage B Weekly Schedule Site-Identity Contract

This is the correct-fix contract for the post-Stage-A weekly-schedule
migration. It is derived from the deployed data model and the remaining
rollout failure, before changing production code.

## Root cause

Stage A made schedule creation resolve and persist a stable `location_id` and
canonical Customer identity. Existing databases still retain the legacy
`UNIQUE (employee_id, customer_name, week_start)` constraint because removing
it during the same rolling deployment could have broken requests served by an
older instance.

That constraint is now the defect. Customer names are mutable display data and
are intentionally non-unique. Two distinct Customers with the same name and
different Sites are valid identities, but the database still treats their
schedules as the same row. The API's `migrationPending` conflict is a temporary
shield around that obsolete arbiter, not the permanent business rule.

## Required fix

- Fresh and upgraded databases must enforce one weekly schedule per employee,
  exact non-null Site, and week.
- Unresolved legacy rows with `location_id IS NULL` must retain their existing
  name/week uniqueness so the migration does not multiply ambiguous history.
- The migration must install the replacement unique indexes before dropping
  the legacy name-based table constraint, perform the change transactionally,
  and be safe to rerun.
- If existing exact-Site duplicates or a conflicting catalog object prevent
  the replacement indexes from being proven correct, the migration must fail
  closed and retain the legacy constraint, old index, and all schedule rows.
- The ordinary non-unique Site/week index made redundant by the replacement
  unique index must be removed.
- Existing schedule rows, IDs, hours, notes, Customer-name snapshots, and Site
  foreign keys must not be rewritten, merged, deleted, or guessed.
- Schedule creation must stop checking for the retired constraint and stop
  returning the temporary `migrationPending` conflict.
- Exact-Site schedule creation for two distinct same-named Customers must
  persist two rows. Repeating a request for either exact Site must update only
  that Site's row.
- The existing ambiguous legacy-row review behavior must remain fail-closed.
- The migration and API behavior must be proven against committed PostgreSQL
  state, including idempotency and database-level duplicate rejection.

## Rollout prerequisite

Stage B must not be merged or deployed until the Stage A Site-aware write path
is confirmed live. Production verification for that prerequisite is read-only.

## Must not change

- A Customer with multiple active Sites remains unavailable for weekly
  scheduling until Issue #20; this slice does not invent visit assignment or
  route semantics.
- Name-only creation still succeeds only when it resolves to exactly one active
  Site. Zero or multiple matches still return `ambiguous_customer_site`.
- Schedule request and response fields, week normalization, archive history,
  reports, forecast, and schedule-versus-actual behavior remain compatible.
- Customer/Site onboarding fields and lifecycle, jobs, QR/check-in behavior,
  shifts, GPS/geofence logic, authentication, admin roles, receivables, and
  billing are untouched.
- Google Calendar, crews, employee assignment, and all Issue #20 work are out
  of scope.
- The website portal and production data mutation are not part of this slice.

## Completion audit

Before completion, reconstruct the base-to-head diff without relying on this
contract or commit messages. Cite every changed hunk by file and line, then
report first:

1. any change that does not trace to this contract;
2. any contract requirement missing from the implementation; and
3. anything touched that this contract says must remain unchanged.

Do not merge or declare the slice complete while any such gap, failing test,
unresolved actionable review thread, or rollout-prerequisite gap remains.
