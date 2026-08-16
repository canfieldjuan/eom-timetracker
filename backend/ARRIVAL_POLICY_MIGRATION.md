# Arrival-policy migration runbook

This migration is intentionally staged. Deploying the policy schema and APIs
does not authorize a production legacy-data migration.

## Deployment boundary in this change

- Policy revisions are append-only. A Site or canonical appointment owns the
  policy; employee identity is not part of the policy key.
- Appointment policy takes precedence over Site policy.
- When Calendar moves a canonical appointment to another Site, synchronization
  appends an auditable revision that rebinds its active policy to the new Site;
  prior revisions remain unchanged.
- Check-ins store the exact selected policy revision and a JSON snapshot.
- Every stored snapshot records `classifiedBy` as `arrival_policy`,
  `legacy_exact`, `legacy_recurring`, or `implicit_flexible`. When a reviewed
  policy is selected, the request does not consult or persist employee-specific
  legacy schedule fields.
- A Site without a reviewed new policy continues to use the retained legacy
  exact/recurring lookup during this stage. This preserves current production
  classification while owner review is incomplete.
- The legacy mutation routes remain retired.

## Read-only inventory

Run from `backend/` with a read-only database credential when possible:

```bash
python inventory_arrival_policies.py --output arrival-policy-inventory.json
```

The command starts a read-only PostgreSQL transaction and inventories:

- active future exact schedules;
- active/open recurring rules;
- unique or ambiguous canonical appointment matches;
- exact and recurring conflicts;
- check-in history references;
- orphan references;
- invalid time zones; and
- date bounds.

The JSON includes an empty `ownerMappingTemplate`. Every row needs an explicit
disposition:

- `map_to_appointment`
- `promote_to_site`
- `retain_history_only`
- `needs_review`

An exact schedule is eligible for `map_to_appointment` only when the inventory
contains exactly one canonical appointment match. `promote_to_site` additionally
requires `ownerConfirmedSitePromotion: true`. Target policy objects must not
contain employee identity.

Validate a completed file against a fresh inventory:

```bash
python inventory_arrival_policies.py \
  --validate-mapping owner-reviewed-arrival-policy-mapping.json
```

Validation does not apply the mapping. It is the required preflight before the
production apply endpoint below.

## Production apply endpoint

After owner review is complete, an authenticated admin may apply the completed
mapping through the time-tracker API:

```http
POST /api/admin/arrival-policy/legacy-mapping/apply
Content-Type: application/json
Authorization: Bearer <admin token>
```

Use the exact JSON produced by `ownerMappingTemplate` plus the owner review
fields and dispositions. The endpoint rebuilds the live inventory, validates
the submitted `inventoryFingerprint`, rejects incomplete or stale mappings, and
then appends new arrival-policy revisions for `map_to_appointment` and
`promote_to_site` entries. `retain_history_only` and `needs_review` entries are
reported as skipped and do not write a policy.

Expected operator flow:

1. Generate and preserve a fresh inventory.
2. Complete every owner mapping entry.
3. Validate the completed file with `--validate-mapping`.
4. Submit the same JSON body to the admin endpoint.
5. If the endpoint returns `invalid_arrival_policy_legacy_mapping`, reload a
   fresh inventory, review the listed conflicts, and resubmit only after owner
   review is still correct.
6. If the endpoint returns `arrival_policy_mapping_target_conflict`, inspect the
   existing current policy for that target before deciding whether a separate
   policy edit is required.

The apply endpoint is idempotent for an unchanged current policy. It retries
transaction serialization, uniqueness, and advisory-lock deadlock races once
before returning a conflict response.

## Remaining owner-gated stages

1. Obtain and preserve the completed owner-reviewed mapping file.
2. Apply the owner-reviewed mapping through the admin endpoint.
3. Run cutover readiness verification:

   ```bash
   python inventory_arrival_policies.py \
     --cutover-readiness \
     --mapping owner-reviewed-arrival-policy-mapping.json
   ```

   Admins can also inspect the database-only report at:

   ```http
   GET /api/admin/arrival-policy/cutover-readiness
   Authorization: Bearer <admin token>
   ```

   The database-only endpoint proves which active legacy exact/recurring rows
   are already covered by Site or appointment policies. The CLI can additionally
   annotate `retain_history_only` / `needs_review` dispositions from the
   preserved owner mapping file; those dispositions are not stored by the apply
   endpoint.
4. Run parity verification across every policy mode, conflicts, legacy history,
   and duplicate check-in retries.
5. Only after parity is accepted, remove the legacy employee-schedule fallback.
   A Site with no policy then becomes implicit flexible.

Legacy tables remain available for history throughout the migration.
