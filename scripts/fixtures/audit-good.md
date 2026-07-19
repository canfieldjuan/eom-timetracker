# Example finding — PASSES the audit-format gate

Every Confirmed claim carries a citation, and all three buckets are present.

## Confirmed

- Monthly report reads a JSON file, not the runtime Postgres — `backend/monthly_report_main.py:74`.
- The mock-data path is the UI default — `backend/timetracker-mobile.html:684`.

## Contradicted

- "Every report is silently stale" is overstated: the default path produces mock
  data, not stale data — `backend/monthly_report_main.py:205`.

## Could-not-determine

- Whether production `data/timesheets.json` currently exists or is stale — not
  observable from the code alone.
