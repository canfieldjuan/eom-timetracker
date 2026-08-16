# Site Customer canonical-boundary contract

Closes Website issue #156. This is a tracker-only write-boundary slice.

## Root cause

The normal operator Customer-create path is a canonical saga: it reserves an
Atlas contact first, then finalizes the local Customer with `atlas_contact_id`
set (base `57ea066`: `backend/time_tracker_api.py:15844-15857`). The
Site-adjacent writers did not use that path. At the base revision, schema
initialization inserted a Customer for each named unassigned legacy Site
(`backend/time_tracker_api.py:4781-4808`); `POST /api/admin/locations`
inserted one when it received a `customerName` without `customerId`
(`backend/time_tracker_api.py:16977-17008`); and the legacy bulk
`PUT /api/admin/locations` did the same for a new Site and for an existing
unassigned Site (`backend/time_tracker_api.py:17125-17171`,
`backend/time_tracker_api.py:17178-17208`). Those inserts left
`customers.atlas_contact_id` null, bypassing the canonical saga.

## Writer-set closure

The target is **CLOSED** and **ENUMERATED** for literal Customer insertion
statements and `_insert_customer` callers in this module: the static search
identifies four null-link-producing branches inside three Site-adjacent entry
points—schema initialization, the standalone Site POST, and the new-Site and
unassigned-Site branches of the legacy bulk PUT. Members outside that set are
deliberately excluded: office conversion requires `atlasContactId` on its
request and the helper copies that value into the new Customer
(`backend/time_tracker_api.py:2491-2495`, `14647-14686`); reservation
finalization passes the Atlas contact id explicitly
(`backend/time_tracker_api.py:15367-15375`).

## Correct change

1. Retire only implicit Customer creation from those three Site-adjacent
   paths. They must not call `_insert_customer` or issue a raw
   `INSERT INTO customers` as a side effect of a Site operation.
2. `POST /api/admin/locations` continues to create a Site for a supplied,
   active `customerId` and continues to validate a supplied matching
   `customerName`. A `customerName` by itself fails as a validation error
   before any Customer or Site is written.
3. The legacy bulk `PUT /api/admin/locations` continues to support unassigned
   Site data and edits to an already-linked Site. It fails as a validation
   error before any write when a new Site or an existing unassigned Site names
   a Customer, because that request would otherwise create one implicitly.
4. Startup schema work preserves existing unassigned legacy Sites and their
   displayed legacy `customer_name`; it no longer manufactures a Customer or
   attaches the Site. Address-key normalization remains independent of this
   contract.
5. The supported explicit path for a new Customer Site remains
   `POST /api/admin/customers/{customer_id}/locations`, which already locks and
   verifies the existing Customer before inserting the Site
   (`backend/time_tracker_api.py:16912-16931`).
6. Test-only fixtures and independent schedule-identity assertions that had
   relied on startup backfill must establish their own explicit Site-to-Customer
   relationship after proving that startup does not do it. The shared fixture
   may remain a deliberately local legacy Customer without an Atlas link, so
   Atlas-linkage tests retain control of their own linked-contact inventory.

## Required proof

1. Existing-`customerId` Site creation still succeeds.
2. `POST /api/admin/locations` with only `customerName` is rejected and leaves
   neither a Customer nor a Site behind.
3. Each legacy bulk implicit-create branch is rejected and leaves no Customer
   behind; an existing unassigned Site remains unassigned.
4. Running schema initialization over named unassigned legacy Sites leaves
   their Customer links null and creates no Customers.
5. The linkage audit cannot gain an unlinked Customer through any closed path.

## Must not change

- The canonical Customer-to-Atlas reservation/finalization saga, Atlas API
  contract, Customer reconciliation route, or historical reconciliation data.
- Database tables, columns, constraints, migration DDL, existing Customer
  rows, or existing linked Customer/Site edit semantics.
- The normal Customer Onboarding flow, which creates Sites through the
  Customer-scoped route; no Website UI change is required.
- Payroll, schedule code or existing schedule records, jobs, QR check-in, Home
  Base, customer-type mirroring, and all unrelated portal behavior. This slice
  does not reconcile unassigned legacy Sites; scheduling one remains guarded
  until it is explicitly assigned to a Customer.
- Runtime Customer creation behavior is the only product behavior in scope;
  test-data setup may change only as required to model the explicit
  Site-to-Customer relationships above.
