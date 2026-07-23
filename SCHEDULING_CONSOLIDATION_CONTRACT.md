# Scheduling Consolidation Contract

Status: implementation contract
Product timezone: `America/Chicago`
Portal week: Sunday through Saturday

This contract was derived before implementation code. It is the standard the
backend and portal changes must satisfy; it is not a description of a proposed
diff.

## Root cause

Effingham Office Maids plans customer service as occurrences at Sites. The two
Google Calendars determine when and where work is planned:

- Residential Calendar -> Morning
- Commercial Calendar -> Evening/Night

Employees are intentionally not assigned in advance. The people who worked, and
their actual labor, become known from authenticated clock, visit, departure, and
Site check-in evidence.

The current application has three independent schedule-like models that do not
share one occurrence identity:

- `schedules` requires an employee, a Site/name, a week, and planned weekly
  hours (`backend/time_tracker_api.py:3249-3268`).
- `planned_service_visits` stores Google occurrence times and Site identity,
  with a separate employee/crew assignment model
  (`backend/calendar_import_store.py:196-251`).
- `jobs` stores a Site/date service occurrence and already relates to actual
  shifts, but has no Google identity or service window
  (`backend/time_tracker_api.py:3654-3673`).

Consequently, Calendar changes do not drive the visible employee-week Schedule
or Forecast. Forecast currently reads weekly employee schedules or historical
shift averages (`backend/time_tracker_api.py:9839-9895`), and the visible
Schedule requires planned employees (`EOM -Website/portal.html:5515-5637`).

The defect is therefore duplicated planning authority, not a missing Calendar
widget or a broken approval button.

## Required solution

The completed system must:

1. Make `jobs` the only active operational scheduled-service occurrence.
2. Keep one read-only Google OAuth connection and bind exactly two distinct,
   readable Calendars to the fixed roles above.
3. Synchronize both Calendars idempotently into `jobs`.
4. Treat Google as the authority for source-linked occurrence time,
   rescheduling, and cancellation.
5. Treat Customers/Sites as the authority for Site identity, Residential versus
   Commercial type, price/rate type, expected total labor-hours, GPS, and
   archive state.
6. Use current Site economics for source-linked work so Site edits immediately
   affect future Schedule and Forecast results.
7. Present a Sunday-Saturday agenda grouped by day and source role, without a
   planned employee or crew.
8. Derive the workers present and actual labor from existing time and Site
   evidence. Multi-worker labor must add; multi-stop shifts must not be assigned
   wholly to the first Site.
9. Forecast from future canonical jobs:
   - per-visit revenue = Site rate per job;
   - hourly revenue = Site rate times Site expected labor-hours;
   - monthly revenue = the exact monthly Site rate divided in cents across that
     month's non-cancelled jobs;
   - planned labor = Site expected labor-hours times the average configured
     hourly rate of active employee accounts.
10. Surface missing, ambiguous, wrong-type, archived, all-day, stale, or legacy
    conflicts as explicit exceptions rather than guessing or silently using
    zero.
11. Migrate existing Calendar visits additively and idempotently, preserving
    source identity, status, history, and audit provenance.
12. Reflect Site archival in future scheduled work without deleting historical
    jobs or work evidence.
13. Preserve existing API response keys and retained data throughout the
    staged backend-before-portal rollout.

## Required portal shape

- Rename the existing sidebar label from Locations to Customers while retaining
  its route identifiers.
- Reuse the current Customers & Sites implementation. It already owns Site
  price, rate type, and expected labor-hours
  (`EOM -Website/customer-onboarding.js:648-704`).
- Clarify the Site field as "Expected labor hours per visit."
- Replace the separate Jobs, employee-week Schedule, and Calendar
  preview/crew/approval surfaces with:
  - Weekly Agenda
  - Forecast
  - expandable Calendar Settings
  - exception-only matching
- Healthy Google state shows compact neutral account/last-sync metadata. Only
  disconnected, incomplete, partial, stale, or failed states show a warning.
- A Schedule card shows the Site occurrence and planned/actual labor. Worker
  intervals are expandable. Financial detail belongs in Forecast so the agenda
  remains operational rather than noisy.
- One-offs, reschedules, and cancellations are performed in Google Calendar.
  Source-linked jobs are read-only in the portal.

## Must not change

This work does not depend on, and must leave alone:

- clock-in, clock-out, arrival, departure, and shift mutation semantics;
- authentication, password changes, roles, and access control;
- QR token signing, geofencing, evidence acceptance, and punctuality rules;
- payroll/timecard correction behavior;
- employee wage editing;
- receivables, Atlas contacts, invoices, payments, allocations, deposits, and
  retry/idempotency behavior;
- Customer/Site stable identity, GPS ownership, and historical archive records;
- Google OAuth redirect handling and read-only scopes;
- Dashboard, Pricing, Waste, Analytics, Reports, Payments, Team, and employee
  portal workflows;
- historical `schedules`, `planned_service_visits`, crew assignments, jobs,
  shifts, visits, departures, or check-ins.

Specifically, the implementation must not:

- write Calendar events into employee weekly schedules;
- create shifts, visits, departures, paid time, or employee assignments from
  Calendar data;
- add `job_id` writes to clock/visit/QR mutation paths;
- treat Calendar duration as total labor-hours;
- treat a QR check-in as paid labor;
- add Google write scopes, cron, a background scheduler, or webhooks;
- create another Customer/Site, pricing, Calendar occurrence, or actual-time
  subsystem;
- add portal-created source jobs;
- drop or destructively rewrite retained production tables.

## Interface and calculation invariants

- The two Calendar IDs must be distinct and readable by the existing OAuth
  grant.
- Residential source events may resolve only to active Residential Sites;
  Commercial source events may resolve only to active Commercial Sites.
- A stable Google occurrence key identifies exactly one source-linked job.
- A complete authoritative source fetch is required before inferring deletion.
- Completed jobs or jobs with actual work evidence are never silently moved or
  cancelled.
- Source matching decisions are fingerprint guarded. A stale event cannot be
  approved.
- Closed productive intervals supply finalized actual hours. Open evidence may
  identify who is in progress but cannot enter finalized totals.
- Missing economic inputs remain visibly incomplete. They are not converted to
  zero.
- Monthly allocation operates in integer cents and sums exactly to the Site's
  configured monthly rate.
- No GET request performs synchronization or another mutation.
- Repeated and concurrent synchronization produces one result per occurrence
  and leaves unchanged retries unchanged.

## Rollout and completion gate

Implementation proceeds in this order:

1. additive backend storage and migration;
2. additive backend sync/Schedule/Forecast behavior;
3. portal cutover after the backend capability is live;
4. legacy mutation quarantine only after a production caller audit.

Each deployment must be independently safe. No table or column is removed in
this arc.

Before any slice is called complete, read its exact base-to-head diff cold.
Report, with exact changed-file line citations:

1. every change that does not trace to this contract;
2. every requirement in this contract that is missing;
3. every touched module or behavior listed under "Must not change."

Lead with those gaps under Confirmed, Contradicted, and Could-not-determine.
Then reconstruct the diff change by change and map every hunk to a requirement.
Do not declare completion while any gap remains.

## Exact-head review correction contract

Status: derived before review-correction code on 2026-07-23

### Root causes

Five review findings expose mismatches between canonical service windows and
the evidence reconciled against them:

1. The weekly loader admits jobs only by `scheduled_date`, so a timed job that
   starts before the requested local day but overlaps it is absent before
   actual evidence is reconciled.
2. A sole Site/date candidate is accepted before its service window is tested,
   so non-overlapping labor can be assigned to a timed canonical occurrence.
3. QR presence is suppressed by any overlapping employee shift without
   checking which Site the shift or visit segment represents.
4. Replacing a Calendar source reuses the source row after checking only future
   work, while canonical reconciliation still reads recent identities from its
   lookback window and can interpret them against the replacement Calendar.
5. Unlinked same-Site shift evidence protects every occurrence on the same
   service date, even when the shift does not overlap the occurrence's valid
   service window.

The separate review claim about source-job link and unlink routes does not
identify a Calendar-job mutation. Those routes update the retained
`shifts.job_id` association, and explicit links are authoritative actual-work
evidence. Changing that behavior would cross the existing shift-mutation
boundary rather than repair source-owned job fields.

### Required corrections

The correction must:

1. Load timed jobs for Schedule when their half-open service window overlaps
   the requested local range, while preserving date loading for legacy jobs and
   preserving Forecast's date-based allocation query.
2. Require a valid timed job window to overlap a heuristic labor segment before
   accepting even a sole Site/date candidate. Preserve explicit shift links and
   the sole-candidate fallback for jobs without a valid window.
3. Suppress QR-only presence only when an already-derived segment for the same
   employee and Site covers the scan.
4. Refuse Calendar-source replacement while scheduled identities remain inside
   the exact canonical reconciliation lookback.
5. Treat an unlinked same-Site shift as work evidence for a job with a valid
   window only when the intervals overlap. Preserve explicit links and the
   legacy date fallback for jobs without a valid window.
6. Add focused regressions for every correction and controls for each preserved
   fallback or precedence rule.

### Correction boundaries

This correction must not change:

- source-linked job update/delete ownership or Calendar sync semantics beyond
  preventing source retargeting during the active lookback;
- shift link, unlink, auto-link, clock, visit, departure, or QR evidence-write
  semantics;
- Forecast allocation or economic calculations;
- OAuth, Calendar read scopes, Calendar event mutation, background scheduling,
  portal behavior, authentication, payroll, receivables, or unrelated routes;
- completed-work protection, explicit `shifts.job_id` precedence, Site/type
  matching, historical retained rows, or legacy jobs without usable windows.
