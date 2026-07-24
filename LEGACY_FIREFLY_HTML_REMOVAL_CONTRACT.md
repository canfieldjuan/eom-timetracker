# Legacy Firefly HTML Removal — Correct-Fix Contract

This contract is the standard for this slice. It was derived before
implementation from backend `main` at
`90c600d06cf63d1793bb1a4f2c686af28e2fb4d5`, after the two compatibility
entry routes were verified in production redirecting to the canonical EOM
portal.

## Root cause

The remaining defect is retained dead implementation, not live routing.
`GET /` and `GET /timetracker-mobile.html` now share one handler that always
returns the guarded canonical-portal redirect at
`backend/time_tracker_api.py:4837-4855`. Nothing in the API module reads or
serves the former frontend file. Nevertheless:

- the complete 2,280-line Firefly application remains tracked as
  `backend/timetracker-mobile.html:1-2280`;
- a dedicated Node script still opens and parses that exact file at
  `backend/check_frontend_js.mjs:1-28`;
- the main test job still installs Node solely to run that obsolete parser at
  `.github/workflows/ci.yml:38-44`;
- the blocking brittle-pattern command still treats the retired HTML as a
  supported source file at `.github/workflows/ci.yml:82-83`; and
- two PostgreSQL test modules still contain static assertions about controls
  inside the unreachable page at `backend/test_site_check_in.py:1488-1538` and
  `backend/test_site_check_in_reconciliation.py:272-279`.

Keeping the file and its bespoke gates makes the repository continue to model
Firefly as a maintained frontend after production traffic has been cut over.
The correct fix is to remove that dead implementation and only the machinery
whose sole subject is that implementation.

## What a correct fix must touch and change

1. Delete the retired frontend source.
   - Remove `backend/timetracker-mobile.html` in full.
   - Do not replace it with a stub, copied portal, embedded redirect, or second
     frontend. The FastAPI compatibility redirects remain the only supported
     behavior for its former URLs.

2. Delete its single-purpose syntax checker and shrink CI precisely.
   - Remove `backend/check_frontend_js.mjs`, whose only input is the deleted
     HTML.
   - Remove the test job's Node setup and `Check frontend JavaScript syntax`
     step because that job has no remaining JavaScript command.
   - Keep the lint job's Node setup because the blocking brittle-pattern checker
     is JavaScript.
   - Remove only `backend/timetracker-mobile.html` from the strict brittle scan;
     keep `backend/time_tracker_api.py`, `backend/monthly_report_main.py`, and
     `backend/report_generator.py` enrolled.

3. Remove static tests whose only subject is the deleted page.
   - Delete the legacy-frontend content test from
     `backend/test_site_check_in.py` and remove its now-unused `Path` import.
   - Delete the legacy reconciliation-caller content test from
     `backend/test_site_check_in_reconciliation.py` and remove its now-unused
     `Path` import.
   - Preserve every API-, PostgreSQL-, QR-, redirect-, history-, and
     route-registry test in those modules.

4. Remove current-maintenance references to the deleted implementation.
   - Update `AGENTS.md` so it identifies the FastAPI backend and the two
     compatibility redirects instead of naming a backend-served portal.
   - Update the dated-log regression comment to identify the canonical admin
     diagnostics consumer rather than the deleted page; the endpoint and test
     remain.
   - Update the audit-format good fixture so its example citations point to
     current tracked source instead of the deleted HTML. Preserve the fixture's
     three required audit buckets and its checker purpose.

5. Verify the deletion boundary.
   - The full backend test suite must pass.
   - Ruff, strict brittle-pattern scanning of the three retained files,
     audit-format self-tests, Python compilation, and diff checks must pass.
   - A repository search must show no current code, test, CI, agent instruction,
     or fixture dependency on the deleted file. References in prior
     slice-specific contract documents and the retained compatibility route
     name are historical or behavioral evidence and must remain.

## What must not change

- Do not change `backend/time_tracker_api.py` or remove `GET /` and
  `GET /timetracker-mobile.html`; both must continue returning the deployed
  canonical redirect.
- Do not change or remove any `/api/*` route, request/response shape, auth or
  role rule, QR token/evidence behavior, GPS/geofence/classification rule,
  employee time action, schedule, Calendar behavior, correction, audit log,
  analytics, or receivables behavior.
- Do not change `backend/monthly_report_main.py`,
  `backend/report_generator.py`, `backend/email_service.py`,
  `POST /api/admin/generate-report`, or
  `GET /api/admin/download-report/{filename}`. Whether the unique report-email
  capability is retired or rebuilt remains a separate operator decision.
- Do not delete, rewrite, or inspect production report artifacts or anything on
  the Render persistent disk. Do not change PostgreSQL schemas or stored data.
- Do not change the canonical website repository or portal UI, add another
  frontend/backend/QR registry, introduce background tracking, or perform a
  production check-in.
- Do not rewrite historical contracts merely because they cite the Firefly file
  as it existed in their recorded base revisions. Specifically leave
  `PORTAL_ENTRY_CUTOVER_CONTRACT.md`,
  `CANONICAL_HOURS_PDF_EXPORT_CONTRACT.md`, and
  `SCHEDULING_CONSOLIDATION_CONTRACT.md` intact.

No implementation is complete unless every required item above appears in the
diff and every changed hunk traces back to this contract.
