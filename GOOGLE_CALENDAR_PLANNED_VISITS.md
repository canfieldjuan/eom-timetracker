# Google Calendar Planned Visits Arc

Issue: `canfieldjuan/eom-timetracker#20`

Status: Active by operator instruction on 2026-07-18. The issue's older
"Deferred" status is superseded for this arc.

## 1. Problem-derived contract

This section was written before inspecting the calendar-related implementation.
It is the standard for the arc, not a prediction of the eventual diff.

### Root cause

The operations system has no authoritative concept for a **planned customer
service obligation** that is separate from employee work evidence. Juan's Google
Calendar currently holds that plan, but its blocks are approximate, may overlap,
and describe customer visits rather than paid shifts or exact arrival promises.

Importing Calendar events as shifts would make planning guesses look like
payroll facts, create false lateness, and couple later Calendar edits to evidence
that must remain immutable. Ignoring Calendar leaves the opposite failure: the
system cannot compare what was supposed to be serviced with what was completed
and eventually billed.

The root fix is therefore a one-way, human-controlled synchronization boundary:
Google occurrences become durable planned-service obligations with source
identity, soft timing semantics, explicit customer/location resolution, crew or
employee assignments, and non-destructive lifecycle history. Timecards, QR
arrivals, and server timestamps remain the only actual-work evidence.

### What a correct fix must touch and change

1. **Planned-visit domain and persistence**
   - Add an additive, rerunnable persistence model for reusable crews,
     effective-dated crew membership, planned service visits, per-visit employee
     assignments/overrides, external Calendar identity, cancellation state, and
     import/audit provenance.
   - Represent one recurring Calendar occurrence as one customer service
     obligation, independently of how many employees work it.
   - Keep approximate start/end values as planning order and capacity hints;
     they must not imply an exact arrival deadline.
   - Seed or create the Morning Crew through current employee identities for
     Carmen, Pamela, and Tina. Missing, inactive, or ambiguous employees must be
     surfaced for operator resolution rather than guessed or silently created.

2. **Read-only Google boundary**
   - Let an authenticated admin authorize one Google Calendar with the narrowest
     read-only Calendar permission, select the source calendar, inspect
     connection state, and disconnect it.
   - Protect the OAuth flow against forged callbacks and store refresh/access
     credentials server-side without exposing them to the browser or logs.
   - Read and normalize the next 30 days of events, including pagination,
     timezones, recurring occurrences, all-day events, event updates, and
     cancellations. No Calendar write operation or write scope may exist.
   - Derive a stable source key from the Calendar plus Google event/occurrence
     identity so unchanged retries and repeated syncs are idempotent.

3. **Deterministic resolution and preview**
   - Match imported events only to unique existing customers and registered
     locations using bounded, explainable identifiers. Unknown or ambiguous
     events must remain unresolved for Juan or Mayra; the system must not guess,
     auto-create a customer/location, or silently choose among matches.
   - Produce an admin-only 30-day preview that classifies each occurrence as a
     create, update, cancellation, unchanged item, or unresolved item before any
     planned visit is changed.
   - Detect overlaps as informational warnings. An overlap must not reject an
     event, infer employee lateness, or convert soft timing into a fixed promise.
   - Allow the operator to resolve customer/location and crew/employee
     assignments in the preview before approval.

4. **Approval and lifecycle safety**
   - Approval must transactionally and idempotently apply the exact reviewed
     preview, or fail closed if the preview/source changed before approval.
   - Future Google edits and cancellations may update or cancel future planned
     visits. They must never delete completed visits or erase timecard, QR,
     billing, or audit history.
   - Every create, update, cancellation, mapping decision, and assignment change
     must retain actor and source provenance.

5. **Reachable operator workflow and proof**
   - Wire the currently used admin portal at
     `https://effinghamofficemaids.com/portal.html` to connection status,
     calendar selection, preview, manual resolution, warnings, and approval.
     That surface lives in the companion website repository and ships through
     [website PR #24](https://github.com/canfieldjuan/Effingham_Office_Maids_Website/pull/24)
     after this backend deploys. The separately backend-served overlapping
     portal is not consolidated or redesigned in this arc.
   - Enforce existing admin authentication/authorization at every new endpoint.
   - Add focused unit tests for normalization, stable identity, matching,
     overlaps, and soft-time semantics; database-backed tests for idempotent
     approval, updates, cancellations, assignments, and historical preservation;
     route tests for auth/OAuth failure boundaries; and a browser-level proof
     through the real admin entrypoint.

### What must not change

- **Timecards, shifts, and payroll:** no Calendar event creates or edits a paid
  shift, clock-in/out record, wage, paid duration, or payroll calculation.
- **QR and actual-work evidence:** QR tokens, geofencing, arrival evidence,
  server timestamps, exception review, and lateness classification remain
  unchanged. In particular, Firefly Grill's existing exact-arrival policy is not
  reinterpreted by approximate Calendar times.
- **Invoices and money:** invoice generation, billing status, receivables,
  payment allocation, deposits, and clearing are read/write independent from
  this arc. No approved visit marks an invoice billed or paid.
- **Customer/location ownership:** existing customer and registered-location
  records are read for matching only. The importer does not create, merge,
  archive, rename, or otherwise mutate them; the open location-persistence PR is
  not modified or absorbed.
- **Google Calendar:** no event creation, edit, deletion, attendee update, or
  write-capable OAuth scope.
- **Existing API and portal contracts:** all changes are additive and backward
  compatible. Existing response shapes, login/password flows, employee
  onboarding, monthly reports, analytics, receivables, and public registration
  behavior remain unchanged.
- **Portal consolidation and downstream products:** this arc does not merge the
  two portals, build employee Today's Work, implement route optimization,
  change arrival-policy classification, or automate scheduled-versus-completed-
  versus-unbilled reconciliation. Those consume the planned-visit domain later.
- **Historical production data:** no destructive migration, table rewrite,
  evidence deletion, or persistent-disk cleanup.

## 2. Arc plan

The contract is completed through deploy-safe vertical slices. The arc is not
done until every requirement above is implemented and cold-audited.

### Slice A — Read-only Calendar connection and 30-day preview

- Add secure, admin-only Google OAuth connection, selected-calendar state, and a
  read-only Google adapter.
- Normalize 30-day occurrences and show them in the real admin portal.
- Resolve only unique customer/location matches; show unresolved items and
  overlap warnings.
- Observable proof: Juan can connect/select a Calendar and see the same
  occurrences in a read-only preview without any timecard, visit, or billing
  write.

### Slice B — Crews, assignments, and approved planned visits

- Add crews, effective membership, planned visits, per-visit assignment
  overrides, import provenance, and audit persistence.
- Establish the Morning Crew from Carmen, Pamela, and Tina when their active
  identities resolve uniquely; otherwise block approval with an actionable
  resolution state.
- Add manual mapping/assignment controls and transactional approval guarded by
  the reviewed preview fingerprint.
- Observable proof: approving a preview creates or updates one obligation per
  occurrence, and repeating the same approval creates no duplicate.

### Slice C — Update/cancellation reconciliation and historical preservation

- Re-preview Google changes as update/cancellation/unchanged classifications.
- Apply future changes idempotently and mark cancellations without deleting
  planned or actual-work history.
- Observable proof: a changed and a cancelled occurrence reconcile while linked
  timecard/QR evidence remains unchanged.

### Deferred follow-on arcs

- Employee Today's Work and approximate route ordering.
- Site-specific fixed, windowed, flexible, and after-hours arrival policy
  classification.
- Route/finish forecasting.
- Scheduled-versus-completed-versus-unbilled reconciliation.

## 3. Build discipline

- Implementation follows the contract above; discoveries may change file
  mapping, but not weaken or silently widen the behavior contract.
- External Google calls are mocked only at the Google HTTP boundary. Domain,
  database, auth, and route behavior use the real in-repo implementations and a
  real test database where the behavior depends on PostgreSQL.
- Before the arc is called done, the complete diff is reconstructed cold with
  `file:line` citations. Gaps lead the report; no untraced change, missing
  contract requirement, or forbidden touch may remain.
