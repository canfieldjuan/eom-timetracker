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

## Second exact-head review correction contract

Status: derived before second-round review-correction code on 2026-07-23

### Root causes

Three remaining paths can turn reviewed or timed source identity into the wrong
canonical result:

1. Job auto-link persists an authoritative `shifts.job_id` after matching only
   Site and local date. It does not load or compare the closed shift interval
   with a timed job's service window, although the Schedule projection later
   trusts that persisted link before heuristic window matching.
2. Saving a mapping for a recurring series supersedes the submitted
   occurrence-level choice only when that occurrence mapping has a different
   fingerprint. A current-fingerprint occurrence override can therefore remain
   ahead of the newly saved series mapping and keep resolving the submitted
   occurrence to the old Site.
3. The retained preview/approval path and mappings created before fingerprint
   support can leave occurrence mappings with a null `source_fingerprint`.
   Canonical sync treats every such value as stale, even when a linked retained
   visit or migrated job proves the exact same reviewed occurrence fingerprint
   and Site.

The first item narrows the earlier correction boundary that left auto-link
unchanged. The defect is in heuristic auto-link candidate eligibility; explicit
operator link and unlink actions remain authoritative.

### Required corrections

The correction must:

1. Make auto-link compare half-open intervals for jobs with a valid timed
   service window, apply the existing uniqueness rule after that filtering, and
   retain the current Site/date fallback for jobs without a usable window.
2. When an operator saves the submitted occurrence as a series decision,
   always supersede that occurrence mapping regardless of fingerprint. Reuse it
   as the series row when no series row exists; otherwise repoint retained visit
   references to the existing series row before deleting only the superseded
   occurrence row.
3. Persist the exact reviewed occurrence fingerprint on retained
   preview/approval mappings going forward. Repair a historical null
   fingerprint only when matching retained source key, connection, Calendar,
   Site, and stored visit/job fingerprint prove it; never treat an unproven null
   or a changed occurrence as current.
4. Add focused regressions for non-overlapping and overlapping timed auto-link,
   date-only auto-link compatibility, occurrence-to-series supersession in both
   row-reuse and existing-series cases, intentional series-to-occurrence
   overrides, new retained mapping fingerprints, safe historical backfill, and
   changed-fingerprint rejection.

### Correction boundaries

This correction must not change:

- explicit job link/unlink behavior or its precedence in Schedule;
- exact-Site and unique-name auto-link resolution, cancelled-job exclusion,
  `job_id IS NULL` overwrite protection, locking, or response shape;
- Calendar occurrence creation, update, cancellation, protected-work, or
  current-snapshot guards;
- occurrence-over-series precedence when an operator deliberately saves a later
  one-off override;
- credential, source, timezone, active-Site, Site-type, fingerprint, or
  non-recurring mapping validation;
- historical planned visits, mappings, jobs, audit provenance, or actual-work
  evidence except for the narrowly proven mapping-reference reconciliation;
- clock, visit, departure, QR, payroll, Forecast economics, authentication,
  receivables, portal behavior, schema constraints, or unrelated routes.

## Third exact-head review correction contract

Status: derived before third-round review-correction code on 2026-07-23

### Root causes

Four remaining paths confuse a range-limited view of canonical identity with
the identity itself:

1. Timed auto-link candidates are admitted through one persisted job date and
   one persisted shift date before their intervals are compared. A job or shift
   that crosses local midnight can therefore overlap without ever becoming a
   candidate.
2. Completed-work protection narrows unlinked shifts to a valid job window but
   narrows visit, departure, and QR point evidence only to the same Site and
   local service date. Unrelated work at that Site can protect a later
   occurrence from a Calendar move or cancellation.
3. Schedule projection loads only jobs in the requested range. When an evidence
   segment carries an explicit `job_id` whose row is outside that range, the
   missing projection row is treated like no link and Site/date heuristics can
   credit the segment to a different visible job.
4. The portal renders Agenda's Previous, This Week, and Next controls in
   Forecast. Those controls mutate the Agenda week and reload Schedule, while
   Forecast is intentionally an as-of-now 4/8/12-week horizon with no selected
   week input. Reloading the same Forecast endpoint would not make the changed
   Agenda label true.

### Required corrections

The correction must:

1. Admit valid timed auto-link candidates by exact Site, or by the existing
   uniquely resolved legacy name, without first requiring one local-date key.
   Apply half-open interval overlap to the entire closed shift and deduplicate
   by job ID before the existing exactly-one rule. Keep invalid or missing job
   windows on the existing Site/name plus `shift.local_date` fallback.
2. For a job with a valid window, require unlinked visit arrivals, departures,
   and QR check-ins to fall within `[scheduled_start, scheduled_end)` before
   they protect the occurrence. Keep the current service-date fallback for a
   job without a usable window, and keep explicit linked shifts authoritative.
3. Resolve metadata for an evidence segment's explicit linked job separately
   from the visible job list. When the link applies to the segment's Site but
   its job is outside the selected Schedule range, emit an unmatched
   explicit-link exception carrying that job ID and never rematch the segment
   to a visible job. Preserve heuristic matching for a proven different-Site
   segment in a multi-stop shift.
4. In Forecast, hide Agenda-only Previous, This Week, and Next controls and
   display the period returned by the Forecast response (with returned week
   buckets as a compatibility fallback). Keep Refresh, Calendar Settings, and
   the 4/8/12-week selector. Returning to Agenda must restore its unchanged
   selected week and controls.
5. Add focused regressions for both directions of cross-midnight overlap,
   de-duplication and boundary non-overlap, inside/outside/boundary point
   evidence across midnight, explicit out-of-range link preservation and
   different-Site multi-stop fallback, and the view-specific Forecast period
   and controls.

### Correction boundaries

This correction must not change:

- explicit link/unlink mutation endpoints, loaded-link precedence, or
  different-Site multi-stop matching;
- cancelled-job exclusion, exact-Site and unique-name resolution,
  `job_id IS NULL` overwrite protection, auto-link locking, or response shape;
- which QR/geofence/review states are accepted or any clock, visit, departure,
  QR, job, or Calendar evidence-write semantics;
- completed or in-progress work protection, invalid-window date fallback,
  Calendar source ownership, snapshot guards, or sync transaction behavior;
- Forecast API parameters, current-relative horizon, Calendar coverage window,
  allocation, economics, or response shape;
- authentication, payroll, receivables, Customers/Sites, Calendar settings,
  legacy planners, schema constraints, or unrelated routes and portal tabs.

## Fourth exact-head review correction contract

Status: derived before fourth-round review-correction code on 2026-07-23

### Root causes

Five remaining fallback paths discard identity or evidence strength before
making a canonical decision:

1. Same-Site shift evidence does not distinguish an unlinked shift from a shift
   explicitly assigned to another job. That lets one occurrence's work protect
   a different occurrence from source reconciliation.
2. A Calendar source is read before the provider fetch, but the fetched source
   identity is not carried into the transactional apply. Per-occurrence checks
   happen to catch a changed source only when the fetched snapshot is nonempty;
   an empty stale snapshot can mark the replacement source successfully synced.
3. Schedule matching counts every active Site/date job when deciding ambiguity,
   even after a valid timed job has failed the interval-overlap requirement.
   An ineligible timed job can therefore hide the sole eligible legacy fallback.
4. Site resolution combines exact address evidence and broader customer-name
   evidence into one unordered candidate set. A unique exact address can be
   diluted into ambiguity by a shared customer name.
5. A Google occurrence key is globally stable across reconnects and globally
   unique in persistence, but canonical mapping lookup scopes that identity to
   the current connection. A retained mapping is missed and then collides when
   the same occurrence is reviewed after reconnect.

### Required corrections

The correction must:

1. Keep an exact `shifts.job_id` link authoritative only for its own job, and
   admit only `job_id IS NULL` shifts through same-Site/date-or-window fallback
   evidence.
2. Carry the expected Calendar ID and timezone from the source snapshot used
   for the provider fetch into canonical apply. After locking the source and
   before any reconciliation or success write, fail closed if either identity
   changed, including for an empty occurrence snapshot.
3. Form heuristic Schedule eligibility in evidence-strength tiers before
   uniqueness. When valid timed jobs overlap the segment, decide only among
   those overlapping windows. Only when no timed window overlaps may
   windowless jobs use the Site/date fallback. Non-overlapping timed jobs never
   create ambiguity. Match one candidate in the winning tier, report ambiguity
   for multiple candidates in that tier, and report no scheduled job when both
   tiers are empty.
4. Prefer exact normalized Site-address matches from Calendar location evidence
   before customer-name fallback. Apply the existing active-Site, expected-type,
   and existing-job Site-change guards to the winning evidence tier, and keep
   name-only multi-Site matches ambiguous.
5. Find occurrence mappings by their global source key across connections,
   reuse the retained row, and rebind its connection and Calendar ownership.
   Apply the same global occurrence reuse when promoting a one-off decision to a
   series decision; do not weaken current source, fingerprint, Site, or type
   validation.
6. Add focused regressions for a shift linked to a different same-Site job; an
   empty stale source snapshot after Calendar or timezone replacement; mixed
   windowless/non-overlapping and windowless/overlapping job candidates,
   including preserved unique timed-window precedence; unique exact address
   versus a shared customer name; name-only ambiguity; and occurrence mapping
   reuse after reconnect.

### Correction boundaries

This correction must not change:

- explicit shift link/unlink endpoints, exact-link precedence for the linked
  job, unlinked shift interval/date fallbacks, or visit/departure/QR evidence;
- Google provider fetch windows, cancellation/update ownership, source status
  meanings, partial-sync isolation, credential fencing, or source replacement
  rules beyond rejecting a stale fetched identity;
- explicit linked-job Schedule matching, cancelled-job treatment, Site/date
  indexing, segment derivation, unmatched evidence shape, or Forecast behavior;
- operator mapping precedence, active/type/Site-change failures, legacy mapping
  fingerprints, series-over-occurrence semantics, audit history, or retained
  planned-visit references;
- schema constraints, OAuth scopes, Calendar writes, shifts/timecards/QR writes,
  payroll, receivables, Customers/Sites, authentication, portal behavior, or
  unrelated routes and modules.

## Fifth exact-head review correction contract

Status: derived before fifth-round review-correction code on 2026-07-23

### Root causes

Three remaining read paths admit identity or evidence outside the boundary that
gives it meaning:

1. Canonical targeted reconciliation reads every scheduled source identity
   after the lookback floor, while the provider list is bounded by both the
   start and end of the current sync window. Once a retained occurrence is
   moved beyond that end, it is absent from later bounded lists but remains a
   targeted-reconciliation candidate on each sync whose rolling lookback still
   precedes that retained future occurrence, and can consume the finite
   reconciliation safety budget.
2. A Google occurrence key is stable across reconnects and stored with a
   global uniqueness constraint, but automatic canonical Site resolution
   filters even an exact occurrence mapping by the current connection before
   consulting it. The existing global upsert can rebind the mapping only after
   an operator repeats the decision, so the retained decision is unavailable
   during the first sync on the replacement connection.
3. Schedule actual projection and Calendar completed-work protection read all
   QR check-ins by Site and time. QR ingestion deliberately marks questionable
   evidence `pending`, and an administrator may reject it; neither state is
   accepted evidence of work.

### Required corrections

The correction must:

1. Bound canonical source identities to half-open overlap with the exact
   current sync window. Preserve the lower overlap condition for an occurrence
   already in progress at the window start, and pass the same provider
   `window_end` used by canonical listing into the identity reader.
2. Resolve an occurrence-scoped mapping by its globally stable `source_key`
   before considering a series mapping scoped to the current connection and
   Calendar. Preserve occurrence-over-series precedence and every existing
   fingerprint, active-Site, Site-type, and existing-job Site-change guard.
3. Admit QR check-ins to Schedule actuals and Calendar work protection only
   when their reachable accepted state pair is either `on_time`/`late` with
   `review_status = 'not_required'`, or `needs_review` with
   `review_status = 'approved'`. Keep accepted needs-review evidence usable
   after approval and fail closed on inconsistent stored state pairs.
4. Add focused regressions for a moved-beyond-horizon identity no longer being
   targeted on the next sync while in-window and window-crossing identities
   remain eligible; automatic reuse of an unchanged occurrence decision on the
   first sync after reconnect; and pending, rejected, approved, and
   not-required QR evidence in both affected projections.

### Correction boundaries

This correction must not change:

- Google list or targeted-fetch windows, reconciliation caps, provider
  deletion/move handling, source status, source replacement, credential
  fencing, or Calendar job create/update/cancel ownership;
- connection-scoped recurring-series decisions, mapping-write/rebind behavior,
  occurrence fingerprints, exact address/name fallback, active/type checks, or
  existing-job Site-change protection;
- QR classification, geofence evaluation, ingestion, review mutations,
  reconciliation outcomes, stored evidence, or accepted evidence semantics;
- shift, visit, departure, clock, timecard, payroll, Forecast economics,
  receivables, authentication, portal behavior, schema constraints, or
  unrelated routes and modules.
