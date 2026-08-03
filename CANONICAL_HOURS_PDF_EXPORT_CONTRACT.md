# Canonical Hours PDF Export — Correct-Fix Contract

This contract is the standard for this slice. It was derived before
implementation from backend `main` at
`e446720ff952d64d12c7ebcbe4bcdb5d672025f1` and website `main` at
`ddef4783d3b8f7eb8eeaf5c3d487f3fa52fd5226`.

## Root cause

The consolidation gap is not merely that the canonical website lacks a button.
The only existing PDF route belongs to a separate legacy reporting pipeline that
does not share the canonical Hours Report calculation:

- The canonical JSON report computes period boundaries, employee filtering,
  completed shifts, hours, locations, and GPS exceptions in
  `backend/time_tracker_api.py:9092-9202`; the canonical CSV endpoint reuses that
  exact calculation at `backend/time_tracker_api.py:9217-9248`.
- The legacy monthly loader builds only employee identity, shift times, and hours
  at `backend/monthly_report_main.py:100-152`.
- Despite that limited data, the legacy PDF labels revenue, burdened labor cost,
  gross profit, margin, and per-employee financial values, defaulting every
  unavailable amount to zero at `backend/report_generator.py:88-100` and
  `backend/report_generator.py:125-141`.
- The legacy production UI also permits fabricated employee data at
  `backend/timetracker-mobile.html:573-598` and forwards that choice to report
  generation at `backend/timetracker-mobile.html:2083-2117`.
- The optional legacy email path reports success when only one recipient
  succeeds at `backend/email_service.py:54-60` and sends a real test message
  before delivery at `backend/email_service.py:268-300`.

Therefore, moving the legacy controls into the canonical portal would preserve
the actual defect: two reporting definitions, one of which can produce
financially false or fabricated output. The correct prerequisite is a
trustworthy PDF representation of the already-canonical Hours Report.

## What a correct fix must touch and change

1. Add one additive, admin-authenticated PDF export endpoint beside the existing
   Hours Report JSON and CSV endpoints.
   - It must require `get_current_admin`, like the existing endpoints at
     `backend/time_tracker_api.py:9205-9225`.
   - It must accept the same `period`, `date`, `employee_id`, and
     `exceptions_only` criteria.
   - It must call `_compute_hours_report(...)` exactly once and render that result,
     rather than querying shifts through a second reporting path.

2. Add a focused, testable PDF renderer.
   - It must consume the normalized dictionary returned by
     `_compute_hours_report` plus the original, read-only request criteria needed
     to label the document. It must not query or recompute report data.
   - It must render the reporting range, applied criteria, total hours, total
     shifts, GPS-exception counts, summary by employee, and shift rows with
     employee, date, clock-in, clock-out, hours, location, and GPS exceptions.
   - It must render an honest empty-state document when no rows match.
   - It must not claim revenue, labor cost, profit, margin, payroll amounts, or
     overtime because the canonical Hours Report does not calculate those values.
   - It must preserve the complete employee, location, and exception values
     without truncation and without treating them as ReportLab markup. Characters
     the embedded PDF font cannot render must appear as explicit `[U+XXXX]`
     code-point text instead of being silently dropped or replaced.

3. Return the PDF directly from memory.
   - The response must be `application/pdf` with a deterministic, criteria-based
     attachment filename.
   - It must include `Cache-Control: no-store` and
     `X-Content-Type-Options: nosniff` because the document contains confidential
     employee time data.
   - It must not write an artifact to `DATA_DIR`, return a server path, launch a
     subprocess, or require a later download token.

4. Verify the real success and failure paths.
   - Missing authentication and non-admin authentication are rejected.
   - Invalid dates and periods preserve the canonical report's existing 400
     behavior.
   - Day, week, month, and year criteria, employee filtering, and
     exceptions-only filtering reach the renderer unchanged.
   - Empty and populated reports both return valid PDF bytes and safe headers.
   - Extracted PDF text proves the required content is present, prohibited
     financial claims are absent, markup-like values remain literal, and
     unsupported glyphs retain an explicit lossless code-point representation.
   - Existing JSON and CSV contracts remain unchanged.

## What must not change

- Do not change `_compute_hours_report`, `GET /api/admin/reports/hours`, or
  `GET /api/admin/reports/hours/export`.
- Do not change the legacy `POST /api/admin/generate-report`,
  `GET /api/admin/download-report/{filename}`, `monthly_report_main.py`,
  `report_generator.py`, `email_service.py`, or `timetracker-mobile.html` in this
  slice. Their retirement or hardening remains separately reviewable while the
  legacy portal is still reachable.
- Do not add email delivery, recipient handling, scheduling, report history,
  persistent PDF files, fabricated/mock data, financial calculations, payroll
  calculations, or retry/idempotency behavior.
- Do not change authentication, roles, employees, shifts, time corrections,
  locations, QR check-in, schedules, Calendar integration, analytics, payments,
  or database schemas.
- Do not change the canonical website in this backend prerequisite slice. The
  website PDF control must be independently deployable only after this endpoint
  is merged.

No implementation is complete unless every required item above appears in the
diff and every changed hunk traces back to this contract.
