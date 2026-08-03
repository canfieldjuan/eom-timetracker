# Legacy Monthly Report Email Retirement — Correct-Fix Contract

This contract is the standard for this slice. It was derived before
implementation from backend `main` at
`d061b4a4219988901c4d7f000cfcc9bf1238b9f1` and from Juan Canfield's
2026-07-24 decision to retire, rather than rebuild, the old monthly-report email
workflow.

## Root cause

The Firefly frontend that owned the monthly-report controls has been removed,
but its backend workflow was left callable and maintained:

- `POST /api/admin/generate-report` still validates an obsolete request,
  launches `monthly_report_main.py` as a subprocess, writes a PDF beneath the
  persistent data directory, and can send it through Resend
  (`backend/time_tracker_api.py:8943-9068`);
- `GET /api/admin/download-report/{filename}` still exposes those generated
  artifacts (`backend/time_tracker_api.py:9071-9089`);
- the exclusive generator, email sender, Render email variables, tests, and CI
  enrollment remain even though current repository source has no caller
  (`backend/monthly_report_main.py`, `backend/report_generator.py`,
  `backend/email_service.py`, `render.yaml:42-47`,
  `backend/test_monthly_report.py`, `.github/workflows/ci.yml:75`); and
- the supported portal uses the separate canonical Hours Report endpoints,
  including an in-memory PDF response
  (`backend/time_tracker_api.py:9092-9277`).

The defect is therefore an incompletely retired product path, not a missing
button. Keeping the raw routes and exclusive implementation preserves unused
attack surface, configuration, disk-writing behavior, and maintenance burden
after the owning UI is gone.

Repository source can establish that no current checked-in caller remains. It
cannot prove that no private external client ever calls these routes. The
operator's explicit retirement decision makes those unsupported callers
out-of-scope; the retired routes must become absent rather than silently
preserved.

## What a correct fix must touch and change

1. Remove the legacy API surface and only its exclusive API support:
   - the downloader-only `FileResponse` import;
   - `ReportGenerateRequest`;
   - report-path parsing, recipient limits, email validation, and the
     disk-backed `REPORTS_DIR` constant;
   - `POST /api/admin/generate-report`; and
   - `GET /api/admin/download-report/{filename}`.
2. Delete the implementation that only those routes used:
   - `backend/monthly_report_main.py`;
   - `backend/report_generator.py`; and
   - `backend/email_service.py`.
3. Delete `backend/test_monthly_report.py` and the legacy email-validation
   cases in `backend/test_regressions.py`. Remove only the deleted
   `REPORTS_DIR` scaffolding from `backend/test_hours_report_pdf.py`, preserving
   its canonical byte/content/header and no-subprocess assertions. Add a
   deterministic regression proving both retired routes are absent from the
   route registry/OpenAPI and return `404`.
4. Preserve focused proof that canonical Hours Report JSON, CSV, and PDF routes
   remain registered and functional. Remove test-only references to the deleted
   `REPORTS_DIR` constant without weakening the in-memory PDF assertions.
5. Remove only the now-unused `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, and
   `RESEND_FROM_NAME` declarations from `render.yaml`, and remove deleted files
   from the brittle-pattern CI command.
6. Leave historical contract documents unchanged. They describe the state and
   scope of earlier slices; this new contract records the later operator
   decision.

## What must not change

- Do not change the canonical Hours Report API, criteria, response data, CSV or
  PDF content, authentication, filenames, or portal controls. In particular,
  keep `GET /api/admin/reports/hours`,
  `GET /api/admin/reports/hours/export`, and
  `GET /api/admin/reports/hours/pdf`, plus
  `backend/hours_report_pdf.py` and the shared ReportLab dependency.
- Do not change the website repository or any employee/admin portal UI.
- Do not change employees, admins, clock-in/out, visits, QR tokens/evidence,
  GPS/geofences, schedules, Google Calendar, jobs, corrections, audits,
  analytics, receivables, settings, CORS, or access-hour behavior.
- Do not change PostgreSQL schemas or stored data, JSON migration behavior, the
  migration subprocess, shared `requests` usage, or any unrelated dependency.
- Do not read, rewrite, or delete existing generated-report artifacts or any
  other file on the Render persistent disk. Removing code is not authorization
  to mutate production data.
- Do not change external Render environment values through the Render API. The
  repository blueprint declarations can be removed because source no longer
  consumes them; deployed secret cleanup is a separate operational action.
- Do not add a replacement email workflow, scheduled report, compatibility
  response, tombstone route, database migration, or generalized cleanup.

## Completion standard

The slice is complete only when:

- repository-wide source search finds no live legacy route, request model,
  generator, downloader, email sender, Resend configuration, or deleted-file CI
  reference outside historical documents and this contract;
- focused retirement and canonical Hours Report tests pass;
- the full backend test suite, Ruff, strict brittle-pattern scan, Python
  compilation, audit-format checks, and `git diff --check` pass; and
- a cold diff reconstruction shows every change traces to this contract, every
  required removal appears, and no protected module or behavior moved.
