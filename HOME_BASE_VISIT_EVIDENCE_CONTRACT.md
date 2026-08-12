# Home Base and Visit Evidence Contract

## Root cause

The employee portal currently has two arrival mechanisms, but neither encodes
the business rule that gives each one its meaning:

- A normal GPS arrival finds one globally nearest saved location and records
  that location without considering the worker's assigned plan or the Site
  type (`backend/time_tracker_api.py:470-507`, `12500-12506`). A nearby
  residential pin can therefore become the recorded customer when the worker
  explicitly taps arrival at a different nearby home.
- A Site QR token identifies a specific active Site, but QR issuance and action
  resolution do not distinguish Commercial from Residential
  (`backend/time_tracker_api.py:7149-7175`, `9187-9281`, `9408-9487`).
- The only persisted Site model is customer-owned and carries service/rate
  fields; creation requires a Customer (`backend/schema.sql:36-77`,
  `backend/time_tracker_api.py:15809-15848`). It cannot truthfully represent paid internal
  dispatch work at the office.

The result is a category error: a location matcher or customer Site is being
used as an attendance policy and as an internal workplace. That makes correct
customer attribution dependent on physical proximity instead of the planned
work, and makes office time either unmatched or customer-shaped reporting data.

## Correct fix

1. Preserve the two evidence methods and make their intended scopes explicit:
   - Commercial customer visits are QR-first. A QR identifies its exact
     Commercial Site and is geofence-checked against that Site.
   - Residential morning visits are GPS-first but schedule-aware. The worker
     explicitly selects an eligible planned Residential Site; the server
     validates both eligibility and GPS for that selected Site. It never
     silently substitutes the globally nearest pin.
   - A Commercial QR failure may use a selected scheduled Commercial Site only
     with a required `qr_unavailable` reason.
   - An unplanned Residential visit may use an explicitly selected, pinned
     Residential Site only with a required `unplanned_visit` reason and a
     reviewable audit record.
2. Add one internal, non-customer Home Base and a Home Base event ledger. It is
   scoped by policy to the existing effective-dated `Morning Crew`, not to all
   Residential workers. Morning Crew office start/end scans create paid shift
   start/end evidence; a required reasoned exception preserves a shift when a
   scan cannot occur.
3. Model office/load-out/vehicle/return intervals as paid dispatch overhead.
   They are visible separately in profitability reporting but never become a
   Customer/Site revenue, labor, visit, rate, or service job. Canonical and
   legacy analytics must use the same paired arrival/departure interval
   semantics so travel is not credited to the preceding customer.
4. Keep API additions additive. Existing clock-in, clock-out, arrive, depart,
   QR, Customer, Site, payroll-correction, and finalization request/response,
   idempotency, and audit contracts remain compatible. The sole intentional
   behavior change is server-side scan-or-documented-exception enforcement for
   a currently effective Morning Crew member after a Home Base is configured;
   it must not be client opt-in.

## Required touchpoints

- `backend/schema.sql` and the idempotent runtime schema bootstrap add the
  internal base, base policy, base events, and event/review indexes without
  mutating historical Customer/Site/shifts/visits data.
- `backend/time_tracker_api.py` owns policy lookup, candidate derivation,
  selected-Site validation, QR/exception evidence, Home Base start/end state,
  idempotency, and additive employee/admin responses.
- `backend/operations_schedule.py` and the legacy analytics path consume
  paired visit/departure and Home Base evidence consistently. Payroll minute
  calculation remains based on clock intervals (`backend/time_tracker_api.py:19427-19455`,
  `19734-19754`).
- Website portal UI presents the employee only the valid action for their
  current context and preserves keyboard, English/Spanish, GPS, retry, and
  stale-session handling.
- Backend and portal tests prove positive, exception, nearby-site, and
  compatibility paths.

## Invariants and non-scope

- Do not alter existing Customer/Site records, including the current office
  Customer/Site; do not backfill or reclassify historical shifts.
- Do not alter payroll arithmetic, hourly-rate snapshots, corrections,
  verification/finalization, job revenue, invoicing, or employee pay.
- Do not make a missing Home Base scan silently pass, and do not block a paid
  shift when a documented exception is allowed.
- Do not hard-code the 50 m default. Use the deployed configured match/geofence
  radius (`backend/time_tracker_api.py:258-271`, `3290-3301`).
- Do not revoke existing QR tokens. New UI/policy restricts normal QR use to
  Commercial Sites while preserving backward-compatible handling of existing
  tokens.
- Do not introduce broad portal or scheduling refactors, dependencies, or
  unrelated cleanup.

## Set closure

- **Home Base scope:** CLOSED and DERIVED. Membership is the active,
  effective-dated membership of the canonical `Morning Crew` stored in
  `crews`/`crew_memberships`; employees outside that set have no Home Base
  requirement.
- **Residential candidates:** OPEN and DERIVED. They are active planned visits
  on the employee's local workday assigned directly to the employee or through
  their active Morning Crew membership. A planned but unassigned Site is not an
  eligible ordinary GPS choice; an unplanned visit takes the explicit reviewed
  exception path.
- **Commercial fallback candidates:** OPEN and DERIVED. They are active,
  scheduled Commercial jobs for the relevant local service window. Any outside
  the derived set is not eligible for ordinary fallback.
- **Unplanned Residential candidates:** OPEN and DERIVED. They are active,
  pinned Residential Sites whose geofence contains the reported GPS point;
  overlapping pins remain separate choices and an unpinned Site is never
  eligible for this exception.

## Acceptance

- A drive-by alone records nothing. A Residential arrival cannot silently land
  on a nearby wrong home.
- A Commercial QR records the token's Site, not a nearest pin; damaged QR
  fallback is reasoned and schedule-bound.
- A Morning Crew member can start/end at the office; an evening worker is not
  prompted or blocked by Home Base policy.
- Office time remains paid but appears only as dispatch overhead, never as
  customer revenue/labor/profit.
- Existing manual arrivals, QR tokens, clock actions, payroll calculations,
  and historical reports remain readable and compatible.
