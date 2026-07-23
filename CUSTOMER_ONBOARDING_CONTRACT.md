# Issue #19 Customer Onboarding Correct-Fix Contract

This is the implementation contract for GitHub Issue #19, derived from the
reported problem, its acceptance criteria, and backend `main` before writing
solution code. A form that appears to work or a passing mocked test is not
enough: the finished code must satisfy every required behavior below without
crossing the declared boundaries.

## Root cause

The reliability root cause is an address-keyed, whole-list mutation boundary
instead of server-authoritative, ID-based Site operations. The onboarding model
gap is separate but related: there is no stable Customer-to-Job-Site aggregate.

`backend/schema.sql:17-36` uses one `locations` row as the customer identity,
physical site, service/pricing profile, GPS pin, QR configuration, and lifecycle
record. The legacy admin write at `backend/time_tracker_api.py:6082-6175`
replaces address-keyed field maps and relies on the general saver at
`backend/time_tracker_api.py:949-995`. Consequently, address text acts as
identity; omission and explicit clearing are not reliably distinguishable;
omission cannot express durable archive; and one consumer can erase fields it
did not load.

The deployed contract is also split across repositories. The website calls
ID-based `GET`, `POST`, `PATCH`, and `DELETE` location routes, while backend
`main` exposes only whole-list `PUT /api/admin/locations` and pin-only
`PATCH /api/admin/locations/pin`. Its browser test mocks the missing atomic API,
so the passing UI suite does not prove website/backend interoperability.

The importer is another symptom of the same missing authority: it sends
`username` although `LoginRequest` requires `name`, previews only a local
payload, and applies through the unsafe whole-list route.

The reliability fix is therefore not another client-side check, a special-case
archive button, or more mocking. It requires atomic Site APIs and safe legacy
writes. Completing the Issue #19 onboarding acceptance criteria additionally
requires an additive Customer/Job-Site model with stable IDs, server-owned
validation and lifecycle rules, compatible legacy behavior, and real
persistence verification.

## Required model and behavior

### Customer and site identity

- A Customer is a stable record with zero or more Job Sites while it is a
  draft, and requires at least one active Job Site to become ready (`locations`).
- Customer names are not unique.
- Customer-level data is the display name, primary contact name/phone/email,
  billing name/email/address, and optional external Atlas contact ID.
- Site-level data is the existing address, type, pricing, frequency, expected
  hours, profitability targets, GPS/QR state, plus service scope, access
  instructions, service preferences, pet notes, and service start date.
- `locations.customer_name` remains synchronized as a compatibility snapshot.
- Each existing Site with a nonblank `customer_name` receives its own Customer
  during an idempotent additive backfill. Equal names are not evidence that two
  Sites belong to the same Customer. Admins may later reassign a Site to an
  explicitly selected Customer. Blank names remain unlinked and are surfaced
  for review; migration must not invent an identity.

### Atomic persistence

- Admin-only Customer and Site creates, partial updates, soft archives, and
  restores are transactions addressed by stable IDs.
- A Customer may be saved as a resumable draft without a site. If a primary site
  is supplied, both records commit or both roll back.
- PATCH distinguishes omission from explicit `null`: omitted fields retain their
  value; explicit `null` clears only nullable fields. Required identity fields
  cannot be cleared.
- Every mutation returns the canonical persisted record.
- Server validation owns required fields, enums, numeric bounds, coordinate
  pairing/ranges, email/date formats, and maximum lengths. Names are limited to
  200 characters; phone to 50; email to 320; address/billing address to 500;
  frequency to 100; service scope/access/preferences to 4,000 each; pet notes to
  2,000. Rate is `0..999999.99`, expected hours `0..9999.99`, percentages
  `0..100`, latitude `-90..90`, and longitude `-180..180`. Rate type is
  `per_visit`, `hourly`, or `monthly`; Site type is `Residential` or
  `Commercial`; service start date is ISO `YYYY-MM-DD`; Atlas contact ID is a
  UUID.
- Errors retain the existing envelope and add stable codes plus field-level
  details so the portal can present a corrective action.

### Required admin interface

- Customer routes are `GET/POST /api/admin/customers`,
  `GET/PATCH/DELETE /api/admin/customers/{customer_id}`,
  `POST /api/admin/customers/{customer_id}/restore`, and
  `POST /api/admin/customers/{customer_id}/locations`.
- Atomic compatibility Site routes are `GET/POST /api/admin/locations`,
  `PATCH/DELETE /api/admin/locations/{site_id}`, and
  `POST /api/admin/locations/{site_id}/restore`.
- Customer and Site lists default to active records; `includeArchived=true`
  returns both active and archived records. Static `/locations/pin` is declared
  before integer `/{site_id}` PATCH/DELETE routes so it cannot be shadowed.
- Customer create/update fields are `name`, `primaryContactName`,
  `primaryPhone`, `primaryEmail`, `billingName`, `billingEmail`,
  `billingAddress`, `atlasContactId`, and optional nested `primarySite` on
  create.
- Site create/update fields are `customerId`, `customerName`, `address`,
  `locationType`, `rate`, `rateType`, `frequency`, `expectedHours`,
  `targetLaborPct`, `minMarginPct`, `lat`, `lng`, `serviceScope`,
  `accessInstructions`, `servicePreferences`, `petNotes`, and
  `serviceStartDate`.
- Compatibility `POST /api/admin/locations` accepts `customerName` without a
  `customerId` and creates a new Customer rather than guessing by name. Supplying
  `customerId` attaches the Site to that exact Customer. Supplying inconsistent
  `customerId` and `customerName` is rejected.
- Compatibility Site create requires a Customer identity, address, and
  Residential/Commercial type; pricing and GPS may remain incomplete so the
  record can be saved as `needs_setup`.
- Patching `customerName` on a linked Site renames that Customer and updates the
  compatibility snapshot on all its Sites. Patching `customerId` explicitly
  reassigns the Site and refreshes its snapshot; it never matches by name.
- Location responses retain `latitude`/`longitude` and include `id`,
  `customerId`, every supported Site field, `customerName`, `qrConfigured`,
  lifecycle timestamps, and derived onboarding state.
- Customer detail responses include the Customer fields, its Sites, and the
  derived required/optional checklist. List responses include enough Site and
  checklist summary data to render without per-row follow-up requests.
- Create returns `201`; update/archive/restore return `200`; an already archived
  DELETE is idempotent and returns the archived canonical record.
- Stable conflict codes are `duplicate_site_address`,
  `archived_site_address`, `customer_has_active_sites`, and
  `customer_archived`. Validation uses `validation_error`; missing IDs use the
  existing `404` behavior.

### Duplicate identity

- The server normalizes full site addresses by trimming, collapsing whitespace,
  standardizing comma spacing, and case-folding without removing suite/unit
  identity.
- No new Site mutation may create a normalized-address duplicate across active
  or archived Sites. Retained legacy collisions are quarantined exceptions that
  remain reviewable but cannot be copied or expanded.
- An active duplicate returns `409` with the matching Customer and Site IDs.
- An archived duplicate returns `409`, the matching IDs, and an explicit restore
  capability; it is never silently recreated.
- Concurrent creates deterministically yield one record and one conflict.
- `locations.address_key` is nullable for deploy safety. Migration fills it only
  for collision-free legacy rows and applies a partial unique index where the
  key is non-null. Collided rows keep a null key, are returned as review items,
  and are never silently merged/deleted. New writes take a transaction-scoped
  lock, check every normalized legacy row including null-key collisions, and
  always store a non-null key.

### Archive and restore

- Archive is a soft lifecycle change. It never deletes Customer/Site rows or
  nulls historical foreign keys.
- Archived sites disappear from new employee choices and cannot resolve QR
  check-ins.
- Archive lifecycle integration is explicitly in scope. Site archive invalidates
  its QR nonce, soft-ends active recurring QR arrival rules, and marks only
  future exact QR arrivals with `cancelled_at`, `cancelled_by`, and an archive
  reason. Matching ignores cancelled exact arrivals. Past schedules, check-ins,
  reconciliation, shifts, visits, departures, and jobs remain intact and
  readable.
- Restore does not reactivate an old QR code or schedule.
- A Customer with active sites cannot be archived; the conflict lists those
  sites. Restoring a site requires its Customer to be active first.

### Onboarding state

The following readiness/profile rules were explicitly approved for Issue #19;
they are product requirements rather than facts inferred from the old schema.

- Customer states are `draft`, `needs_setup`, `ready`, and `archived`.
- Site states are `needs_setup`, `ready`, and `archived`.
- A Customer is ready only with a nonblank name, at least one active site, and
  every active site having a valid address, Residential/Commercial type,
  configured rate/rate type, and complete GPS pair.
- Contact, billing, frequency, expected hours, profitability targets, service
  details, pets, start date, QR, schedules, jobs, and crew are visible optional
  steps and do not block readiness.
- Status is derived from persisted server data, not a browser-owned flag.

### Import safety

- Authenticate with the current `{name, password}` contract.
- Preview/diff is the default and performs no mutation; apply requires
  `--apply`.
- Preview classifies each source row as create, update, unchanged, or conflict
  and shows field changes without printing secrets.
- Apply uses atomic create/update operations, never archives by omission, and
  never sends absent fields as `null`.
- Failed geocoding cannot clear an existing pin.
- Conflicts abort before mutation. Interrupted/partial failures are safe to
  rerun and return nonzero with an exact summary.

### Portal behavior

- Juan and Mayra can save/resume Customer drafts, manage multiple Sites, edit all
  supported fields, archive/restore, and see required versus optional steps.
- Browser duplicate checks are advisory; server conflicts are authoritative.
- Overlapping Enter/click actions cannot double-submit, and async geocoding or a
  request cannot resume after logout/session replacement.
- Canonical mutation responses update visible state immediately. If the later
  reconciliation refresh fails, the saved record remains visible with a Retry
  action; the UI must not imply the mutation failed.
- Failed mutations retain entered values and show actionable errors.
- QR, job, schedule, crew, and billing connections are explicit next actions;
  Customer creation triggers none automatically.

## Public compatibility invariants

- Preserve authentication/authorization. Juan and Mayra remain the only admins;
  employee registration and role behavior do not change.
- Preserve `GET /api/timesheet/locations` response keys and active-site behavior.
- Preserve legacy `PUT /api/admin/locations` and
  `PATCH /api/admin/locations/pin`. PUT accepts old `name`/`customer`/`type` and
  current `address`/`customerName`/`locationType` aliases; current aliases take
  precedence when both are present. It retains `lat`, `lng`, `rate`, `rateType`,
  `frequency`, `expectedHours`, `targetLaborPct`, and `minMarginPct`. Omitted
  fields and omitted Sites are preserved; explicit null clears only nullable
  fields; string-only entries update/create only the address. Existing response
  maps remain.
- Preserve current location request keys (`lat`, `lng`) and website response
  keys (`latitude`, `longitude`) on the atomic compatibility API.
- Preserve stored jobs/schedules, analytics, reports, check-in classification,
  reconciliation, and receivables contracts. Job or schedule creation with a
  supplied `locationId` validates that exact active Site and derives its
  compatibility customer name. Name-only fallback remains only when it resolves
  to exactly one active Site; otherwise it returns `409 ambiguous_customer_site`
  instead of selecting an arbitrary first row. Weekly scheduling for a Customer
  with multiple active Sites remains unavailable until Issue #20 rather than
  silently conflating Sites under the existing name-based unique constraint.
- Preserve all historical location references and reporting after archive.

## Explicitly out of scope

- PR #23 and its branch/worktree: do not inspect, modify, comment on, resolve, or
  merge it for Issue #19.
- Google Calendar synchronization, approximate morning-shift planning, Issue
  #20, and a named crew-template model.
- Automatic jobs, schedules, QR generation, employee assignment, billing
  records, or Atlas contact creation.
- Clock-in/out, background location polling, GPS evidence, geofence math, QR
  classification, review decisions, or time corrections. The only QR-scheduling
  change allowed is the archive lifecycle behavior explicitly defined above.
- Public marketing, translations, clean URLs, payments, unrelated portal tabs,
  destructive migrations, or rewriting production history.

## Required verification

### Backend/database

- Use actual request fields and assert committed PostgreSQL values.
- Cover Customer draft, transactional Customer-plus-Site creation, multi-site
  linking, partial preservation, explicit clearing, and validation.
- Cover active/archived/legacy/concurrent duplicates.
- Cover archive/reload and restore/reload, retained historical keys, invalid QR,
  ended future rules, cancelled future arrivals, and unchanged past evidence.
- Prove legacy whole-list writes preserve omitted advanced fields and unrelated
  rows.
- Prove backfill is idempotent, creates one Customer per named legacy Site, never
  merges equal names, and leaves blank names unassigned.
- Prove explicit `locationId` job/schedule resolution and ambiguous name-only
  rejection without changing stored historical records.
- Prove admin access and the unchanged employee location contract.

### Importer

- Prove the login body uses `name`, preview makes zero mutations, diffs are
  accurate, conflicts block apply, geocode failure preserves pins, reruns are
  idempotent, and failures exit nonzero.

### Browser/integration

- Cover login, draft, Site create, readiness, refresh, edit, archive, restore,
  validation/conflict recovery, duplicate-submit prevention, session replacement,
  and save-success plus refresh-failure recovery.
- Run the website against real local FastAPI/PostgreSQL; mocked fetch alone is
  insufficient.
- Verify production separately with read-only counts/read-back. The Firefly QR
  verification may authenticate and resolve the existing non-rotated token, but
  it must stop before `POST /api/timesheet/site-check-in`; an actual production
  check-in creates immutable evidence and requires separate explicit
  authorization and an identified employee. Test fixtures are not evidence about
  real customers.

## Completion audit

Before completion, reconstruct every base-to-head diff without using this
contract, Issue #19, PR prose, commits, comments, or claimed tests. Describe each
changed hunk with changed `file:line` citations.

Then compare that cold reconstruction to this contract and lead with:

1. changes that do not trace to a contract requirement;
2. contract requirements missing from the implementation; and
3. anything touched that this contract says must remain unchanged.

Classify evidence as Confirmed, Contradicted, or Could-not-determine. Do not
merge or declare completion while any untraced change, unmet requirement,
forbidden touch, failing test, unresolved actionable thread, or
production-safety gap remains.
