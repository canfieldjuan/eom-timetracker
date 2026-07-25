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

Validation does not apply the mapping. This repository intentionally has no
production mapping-apply command at this stage.

## Remaining owner-gated stages

1. Obtain and preserve the completed owner-reviewed mapping file.
2. Add and review an idempotent additive apply path keyed by the inventory
   fingerprint.
3. Run parity verification across every policy mode, conflicts, legacy history,
   and duplicate check-in retries.
4. Only after parity is accepted, remove the legacy employee-schedule fallback.
   A Site with no policy then becomes implicit flexible.

Legacy tables remain available for history throughout the migration.
