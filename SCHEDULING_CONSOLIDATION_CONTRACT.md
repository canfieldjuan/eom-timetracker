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

## Sixth exact-head review correction contract

Status: derived before sixth-round review-correction code on 2026-07-23;
the cold audit excluded invalid all-day occurrences because they do not resolve
a target Site and must retain their existing invalidation behavior.

### Root causes

Three remaining compatibility boundaries do not consistently apply the
canonical identity and Site-authority rules:

1. Calendar sync checks for an active manual job at the target Site/date only
   when creating a source job. An existing source job can therefore be moved
   or restored onto a Site/date already occupied by a manual job even though
   the create path defines that coexistence as an unresolved legacy collision.
2. Canonical source jobs intentionally do not snapshot Site expected hours or
   revenue into legacy job columns, but the retained Jobs profitability report
   still reads only those legacy columns. During the required backend-first
   rollout it therefore reports configured source work as unknown hours and
   zero revenue instead of projecting current Site economics.
3. The production Google Calendar list request asks Google for
   reader-or-higher calendars, but reconnect installation trusts every returned
   calendar ID instead of enforcing that readable-role policy at the credential
   replacement boundary. A nonconforming provider response or test double can
   therefore replace working credentials with a grant that cannot read the two
   configured sources.

### Required corrections

The correction must:

1. Before applying a valid timed source occurrence to an existing source job,
   run the existing active-manual-job collision check when the occurrence
   changes Site/date or restores a cancelled job. On collision, emit the existing
   `legacy_job_collision` exception with the conflicting job IDs and leave both
   rows unchanged. Preserve ordinary metadata/time updates that remain on the
   same active Site/date.
2. At the retained Jobs profitability read boundary, derive source-job
   expected hours and revenue from the linked current Site while preserving
   manual jobs' stored values. Apply the canonical rate rules: per-visit rate
   per job, hourly rate times Site expected hours, and exact monthly Site rate
   allocated across that Site's non-cancelled jobs for the month. Missing or
   invalid Site inputs remain unknown rather than becoming invented economics.
   Keep source-job economics out of the legacy job columns.
3. Define one readable Calendar role policy and apply it both when configuring
   canonical sources and when constructing the reconnect accessibility set.
   Keep the provider-side `minAccessRole=reader` request as the first filter,
   and reject credential replacement if either configured source is absent
   after the local readable-role filter.
4. Add focused regressions for move and restore collisions; retained
   profitability for manual, per-visit, hourly, monthly, and missing Site
   economics; the provider reader-floor request; and reconnect rejection for
   same-ID free/busy-only Calendar results without changing the retained
   connection.

### Correction boundaries

This correction must not change:

- the manual-job create path, source-key identity, mapping/Site resolution,
  fingerprint and stale-snapshot guards, completed/in-progress work
  protection, source cancellation, or ordinary same-Site/date updates;
- Calendar job ownership or writes to `expected_hours` and `revenue`, canonical
  Schedule/Forecast inclusion, allocation, economics, response shapes, or
  actual-evidence matching;
- retained Jobs list/detail or manual job create/update/delete behavior,
  unrelated analytics and pricing reports, Site economics writes, or response
  keys;
- OAuth scopes, token exchange/revocation, provider pagination, source
  bindings, credential fencing/versioning, sync behavior, or OAuth redirects;
- authentication, payroll, receivables, Customers/Sites, portal behavior,
  schema constraints, legacy planner data, or unrelated routes and modules.

## Post-cutover legacy mutation quarantine contract

Status: derived before implementation on 2026-07-23, after the canonical
backend and portal reached production and an authenticated production Schedule
load produced no legacy planner requests.

### Root cause

The canonical Calendar-backed `jobs` schedule is now the only operator-facing
planning workflow, but the backend still exposes the retired reviewed-preview
planner as a second write authority. A stale client can still select one
Calendar, create and approve a preview, or change crew membership, and startup
can still seed crew membership automatically. Those writes create or modify a
parallel planned-visit model that canonical sync must later migrate into
`jobs`. Removing the old portal controls did not remove that duplicate
authority.

The problem is not the retained historical rows or migration code. Existing
planned visits, previews, assignments, mappings, and audit records are evidence
that canonical sync, disconnect protection, and source reconciliation still
need to read. The correct fix is therefore to close obsolete write entry
points while keeping retained data readable and non-destructive.

### Required changes

The slice must:

1. Stop registering the legacy reviewed-preview creation and approval routes.
   Authenticated requests to those retired paths must return 404 and must not
   create, update, cancel, or approve any planned visit.
2. Stop registering the single-Calendar selection route superseded by the two
   role-bound canonical source configuration. Its retired path must return 404
   without changing connection or source state.
3. Stop registering the legacy crew-list and crew-membership routes. Their
   retired paths must return 404 without changing crew, membership, planned
   visit, or assignment state.
4. Remove automatic Morning Crew membership bootstrap from application
   startup and stop seeding a new default crew in an empty schema. Starting the
   service must not invent a crew or employee membership, while every retained
   crew and membership row remains untouched.
5. Add focused route and startup regressions that prove the retired entry
   points are absent and the canonical status, Calendar listing, two-source
   configuration, sync, mapping, Schedule, Forecast, connection, and
   disconnect boundaries remain registered and protected by their existing
   admin contract.

### Boundaries

This slice must not:

- delete or rewrite any table, column, foreign key, preview, planned visit,
  assignment, crew, membership, mapping, connection, source, job, or audit row;
- remove or change the one-way legacy-to-`jobs` migration, its collision and
  exception reporting, `legacyMigration` response data, disconnect protection,
  canonical mapping reuse, source-key identity, or append-only audit behavior;
- change Google OAuth scopes, connect/callback/reconnect/revoke behavior,
  credential encryption or fencing, Calendar listing, the two canonical source
  roles, matching, synchronization, cancellation, or source configuration;
- change canonical Schedule or Forecast projections, job economics, actual
  shift/visit/QR evidence, timecards, payroll, receivables, Customers/Sites,
  authentication, portal code, schema constraints, or unrelated routes;
- expand into a generalized deletion of now-unreachable legacy helpers or
  storage functions. This slice removes external mutation authority and
  automatic writes; retained internals stay until their historical readers and
  constraints no longer depend on them.

## Canonical QR arrival matching contract

Status: derived before implementation on 2026-07-23, after the two canonical
Calendar sources were configured and synchronized in production.

### Root cause

Canonical Calendar synchronization now creates one Site-based `jobs` service
obligation without employee or crew assignments. QR ingestion still decides
whether evidence is accepted by looking for a second exact or recurring arrival
row keyed to the signed-in employee and Site. A worker who was not separately
preassigned is therefore sent to review even when the canonical schedule says
that Site has work. Pending evidence is then absent from Schedule actuals.

The defect is not missing crew-selection UI. The employee-specific arrival
model is the wrong eligibility authority. The operator intentionally schedules
the customer Site, while each authenticated employee's own QR scan establishes
who actually worked there.

Calendar start and end values remain approximate planning blocks. They may be
used as a bounded association hint, but must not become a flexible employee's
lateness deadline. Retained exact/rule rows may continue to refine punctuality
for an already configured exception, but they must never be required to accept
an otherwise valid employee at a canonical job.

### Required changes

The slice must:

1. Match each new QR submission, using the official server timestamp, to
   canonical Schedule-eligible jobs at the resolved active Site. A candidate
   must have a valid timed, non-all-day occurrence; a readable canonical source
   role compatible with the active Site type; and a status other than
   `cancelled`.
2. Treat Calendar time as an association window rather than a punctuality
   promise. A timed job is a candidate when its interval overlaps the official
   check-in timestamp expanded by the configured twelve-hour arrival-association
   window. Do not select the nearest job when more than one eligible job
   remains.
3. Produce deterministic fail-closed outcomes after geofence and device-skew
   checks: one eligible job is accepted; multiple eligible jobs are
   `needs_review/ambiguous_job`; only cancelled candidates are
   `needs_review/cancelled_job`; and no candidate is
   `needs_review/no_scheduled_job`.
4. For one canonical job, keep any retained matching exact/rule schedule as a
   punctuality refinement, including its stored grace calculation. When no
   retained refinement exists, accept the scan as
   `on_time/verified_scheduled_site/not_required`; this accepted state means
   verified scheduled-Site presence and does not infer punctuality from the
   approximate Calendar block.
5. Add an optional foreign-key link from immutable QR evidence to the matched
   canonical job. Preserve the first stored link on an unchanged retry, clear
   no historical schedule/rule snapshots, and set the link to null rather than
   deleting evidence if a deletable job is removed.
6. Make Schedule actual projection honor that durable QR job link while keeping
   QR evidence presence-only. A QR scan can identify an observed worker and
   attach an otherwise unlinked Site segment, but it must never invent paid
   duration, actual hours, wages, or labor cost.
7. Make accepted job-linked QR evidence protect that exact Calendar occurrence
   from destructive move/cancellation reconciliation even when the scan falls
   outside the approximate provider interval. Preserve the existing accepted
   evidence-state rules.
8. Stop registering the exact-schedule and recurring-rule mutation routes.
   Keep authenticated read-only history, both retained tables, their foreign
   keys, existing rows, and Site-archive soft retirement intact.
9. Stop registering the forward-looking employee-schedule reconciliation and
   review routes. Open-ended retained rules must not keep creating future
   missing-employee exceptions after actual workers are determined by QR
   evidence. Preserve all stored reconciliation review history.
10. Remove the corresponding mutation and employee-schedule reconciliation
    controls/callers from the backend-served legacy page while retaining Site QR
    generation, immutable arrival activity, needs-review decisions, and normal
    time-entry controls.
11. In the canonical portal, display the flexible accepted reason as verified
    on-site presence rather than telling the employee that an approximate
    Calendar time made them on time. Preserve the existing on-time, late, and
    needs-review messages for retained exact-policy and exception outcomes.
12. Add focused PostgreSQL-backed, route-registry, history-preservation,
    projection, and portal regressions for two different employees on one job,
    overnight association, geofence/device-skew precedence, cancelled and
    ambiguous jobs, unchanged retry, retained exact-rule punctuality, durable
    job linking, zero QR-paid duration, retired-route non-mutation, and retained
    history.

### Boundaries

This slice must not:

- create employee or crew assignments, infer a planned worker, consume a job
  after one scan, or prevent multiple authenticated employees from checking in
  to the same service obligation;
- use device time as official time, weaken signed-in employee equality, QR
  signature/nonce rotation, active-Site enforcement, geofence evaluation,
  device-skew precedence, clock-hours gates, idempotency, authentication, or
  admin review authorization;
- rewrite or delete existing QR check-ins, exact schedules, recurring rules,
  reconciliation reviews, audit evidence, shifts, visits, departures, or
  timecards;
- replace retained exact/rule punctuality with a customer-name special case or
  infer a new Site policy from historical rows. The live Firefly rule remains
  effective through retained matching; a generalized fixed/window/flexible/
  after-hours policy editor is a separate product decision;
- change Calendar OAuth, source configuration, provider fetches, Site mapping,
  source identity, synchronization, ordinary reschedule/cancellation handling,
  job economics, Schedule/Forecast response shapes, or Customer/Site writes;
- change clock-in/out, Arrive/Depart, paid-time calculation, wages, payroll,
  time corrections, receivables, invoices, payments, authentication, reports,
  public registration, or unrelated backend/portal modules;
- perform a destructive migration or seed, rewrite, deactivate, reactivate, or
  otherwise reinterpret retained employee schedule/rule rows.

## QR-attributed productive-shift contract

Status: derived before implementation on 2026-07-23, after canonical QR job
matching and its neutral portal confirmation were live in production.

### Root cause

The system already stores the two facts needed for Schedule actuals: a
productive shift supplies the employee's paid clock-in/clock-out bounds, and an
accepted QR row supplies authenticated Site presence plus the exact canonical
job. The read-only Schedule projection does not yet combine those facts.

For a closed shift without a Site or Arrive event, the projection emits the
entire paid interval as an unmatched gap. It separately emits a point-like QR
presence row, and the later job-link pass can attach only an already-existing
same-Site segment. The result is zero actual hours on the job and the whole
productive shift left unmatched even though the employee clocked in, scanned
the canonical Site QR, and clocked out.

The defect is not missing employee scheduling, crew assignment, or another
arrival control. Requiring the employee to tap Arrive after an authenticated QR
scan would duplicate the same Site identity. Clock-in/out and retained
Arrive/Depart rows already define time boundaries; QR must identify one existing
atomic paid segment, not invent a new duration boundary.

### Required changes

The slice must:

1. Build finalized atomic segments from productive shift clock bounds and the
   existing Arrive/Depart boundaries before point-only QR fallbacks are
   materialized. QR timestamps must not split, start, close, shorten, or extend
   those segments.
2. Treat an accepted QR row with a durable `job_id` as Site/job identity for
   exactly one containing atomic segment. Use half-open segment boundaries so a
   scan at a shared boundary selects at most one segment. If corrected data
   leaves multiple containing segments or shifts, fail closed: apply the QR to
   none of them and retain only zero-duration observed presence.
3. Promote a wholly unassigned atomic segment to a QR's Site/job only when all
   accepted job-linked QR rows contained by that segment identify one distinct
   `(Site, job)` pair. Repeated scans for that pair are corroborating evidence,
   not extra time. Two distinct pairs in one atomic segment are ambiguous; keep
   its paid duration unmatched rather than splitting it by scan order.
4. Preserve existing shift, Arrive, and Depart boundaries and Site identity. A
   same-Site QR may add its durable job identity and `qr_check_in` evidence to an
   otherwise unlinked segment without moving the segment's established start or
   end. A different-Site QR must not override an explicit shift or Arrive Site
   and remains point-like observed evidence.
5. Preserve every applicable explicit `shift.job_id`. If an explicit Arrive
   proves that an atomic segment is at a different Site, the inapplicable shift
   link must not prevent one unambiguous same-Site QR job link from identifying
   that segment. Cancelled, unavailable, or out-of-visible-range direct links
   must continue to fail closed instead of silently rematching to another job.
6. Extend the evidence load just enough to include the unique productive shift
   that contains an accepted QR linked to a visible job, even when the configured
   Calendar association margin places that scan and shift across the normal
   Schedule evidence boundary.
7. Keep accepted QR evidence without a containing closed productive shift,
   without a durable job link, outside a unique atomic-segment association, or
   in an ambiguous segment as point-like observed presence with zero finalized
   hours. Keep open and non-productive shifts at zero QR-attributed finalized
   hours, and keep pending and rejected QR evidence excluded under the existing
   accepted-state rules.
8. Keep each employee independent so multiple workers may contribute their own
   non-overlapping intervals to one canonical job. One worker's scan must never
   assign or relink another worker's interval.
9. Preserve the read-only projection invariant for every closed shift before
   visible-range filtering: finalized attributed intervals and finalized
   unmatched intervals are disjoint, stay within the clipped clock-in/clock-out
   bounds, and together cover those bounds exactly once. Their summed duration
   must never exceed or fall short of the existing productive shift duration.
10. Materialize standalone QR presence only after paid and unmatched shift
    segments are complete, and suppress it only when a compatible
    employee/Site/job segment already represents that scan. Do not leave a
    duplicate QR point beside the interval it created.
11. Add focused PostgreSQL-backed regressions for one unassigned closed shift,
    repeated same-job scans, distinct-link ambiguity, explicit Arrive/Depart
    boundaries, applicable and inapplicable shift links, overlapping shifts,
    open/non-productive shifts, two employees on one job,
    pending/rejected/unlinked scans, QR without a shift, cross-boundary and
    cross-midnight evidence, and the exact no-double-count duration invariant.

### Boundaries

This slice may change only
`SCHEDULING_CONSOLIDATION_CONTRACT.md`,
`backend/operations_schedule.py`, and
`backend/test_operations_schedule.py`.

It must not:

- create, extend, shorten, close, relink, or otherwise mutate a shift, visit,
  departure, QR check-in, job, employee, Site, or audit row;
- infer paid time from QR or Calendar data without a containing productive
  shift, count an open shift as finalized, change payroll/timecard totals, or
  change clock-in/out, Arrive/Depart, correction, wage, or labor-cost writes;
- change QR resolution or ingestion, official/device timestamps, durable job
  matching, classification, review, retry idempotency, geofence, clock-skew,
  token/nonce, access-hours, authentication, or authorization behavior;
- change Google OAuth, the two Calendar source roles, event fetching, mapping,
  synchronization, cancellation/reschedule ownership, canonical job planning,
  Site economics, Forecast calculations, receivables, invoices, or payments;
- add employee/crew planning, revive exact or recurring arrival-schedule
  mutations, require a second Arrive action, or add a new portal/admin surface;
- change Schedule or Forecast response shapes, public route contracts, schema,
  startup migrations, or unrelated backend/portal modules.
