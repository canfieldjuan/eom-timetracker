# Schedule Contract: Elapsed jobs without finalized actual time

## Root cause

The read-only Schedule projection conflates two different states:

- a service occurrence whose scheduled window has not ended; and
- a service occurrence whose window has ended without finalized paid-time
  evidence.

At base commit `5b92131a0e4e6488e6d96b08112edf45fc441eef`,
the projection derives `executionStatus` from cancellation, current
in-progress evidence, persisted completion, and positive actual hours, then
hard-falls back to `scheduled`
(`backend/operations_schedule.py:1306-1320`). It does not compare the job's
`scheduled_end` to `observed_at`, even though the route already supplies the
observation instant (`backend/operations_schedule.py:1553-1591`) and the
projection already reads the scheduled end
(`backend/operations_schedule.py:1330-1339`).

Canonical Calendar synchronization normally persists the planning status as
`scheduled` (`backend/calendar_import_store.py:3161-3183`,
`backend/calendar_import_store.py:3206-3227`). That durable planning state
therefore does not age into an execution result on its own.

The root defect is the missing elapsed-window branch in the read projection,
not the Calendar data, persistent job status, or actual-time calculation.

## What a correct fix must touch and change

The fix must change only the Schedule read projection.

It must:

1. Return `executionStatus: "no_actual"` for an otherwise scheduled,
   non-cancelled job when:
   - no worker is currently in progress;
   - the persisted job is not completed;
   - finalized `actualHours` is zero;
   - the job has a valid timed window with both start and end, end after start,
     and `source_all_day` false; and
   - `scheduled_end <= observed_at`.
2. Preserve this precedence:
   `cancelled` > `in_progress` > `completed` > elapsed `no_actual` >
   `scheduled`.
3. Use an instant comparison between timezone-aware timestamps so overnight
   and daylight-saving boundaries follow the actual end instant.
4. Keep invalid, missing, reversed, and all-day windows neutral as
   `scheduled`; their existing issues remain the only diagnosis.
5. Keep persisted `status`, workers, intervals, issues, totals, actual hours,
   labor, variance, forecast, and response keys unchanged.
6. Use `no_actual`, not `missed` or `no_show`. The code knows finalized paid
   time is absent; it cannot prove the service was not performed. Accepted
   QR-only presence may correctly coexist with zero finalized hours
   (`backend/test_operations_schedule.py:2534-2624`).
7. Add deterministic regression coverage for:
   - a future window remaining `scheduled`;
   - exact end equality becoming `no_actual`;
   - invalid and all-day windows remaining `scheduled`;
   - cancelled, in-progress, completed, and positive-actual precedence; and
   - accepted QR-only presence remaining visible while the elapsed job becomes
     `no_actual`.

## What must not change

This slice does not depend on and must leave alone:

- Google OAuth, Calendar source configuration, import, synchronization,
  rescheduling, cancellation, or durable `jobs.status`;
- database schema, status constraints, migrations, or historical rows;
- QR resolution, classification, approval, job linking, or retained evidence;
- shift/visit/departure segmentation, paid-time attribution, actual-hours or
  labor calculations;
- Schedule request/response keys, summary totals, unmatched evidence, issue
  generation, or Forecast inclusion and economics;
- portal code or copy, which already maps `no_actual` to a neutral
  operator-facing label;
- employee timekeeping mutations, payroll, time corrections, authentication,
  Customers/Sites, Receivables, Analytics, or Reports.

This change is read-only. It must not insert, update, delete, reconcile, or
otherwise mutate any production record.

## Completion standard

The work is complete only when a cold reconstruction of the final diff shows
that every changed hunk traces to this contract, every required boundary and
precedence case is verified, and no excluded module or behavior moved. Any
untraced change, missing case, or forbidden touch is a blocking gap.
