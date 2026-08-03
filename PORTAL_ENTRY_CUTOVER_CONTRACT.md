# Canonical Portal Entry Cutover — Correct-Fix Contract

This contract is the standard for this slice. It was derived before
implementation from backend `main` at
`773b9dda52769c504e3722026003c8d7b4a5ea64` and canonical website `main` at
`326b9854ed89353ea8fc95105a5a5913b60537d6`.

## Root cause

The remaining two-portal defect is routing, not a missing canonical feature.
The canonical EOM portal already owns employee time actions, admin time views,
site QR management, QR arrival review, audit logs, corrections, and trustworthy
Hours Report CSV/PDF output. However, the backend entry handler redirects only a
request with a non-empty `checkIn` value; every ordinary request to either `/`
or `/timetracker-mobile.html` still returns the Firefly HTML:

- both legacy URLs share one handler at
  `backend/time_tracker_api.py:4838-4843`;
- only the truthy `checkIn` branch redirects at
  `backend/time_tracker_api.py:4844-4855`; and
- the default branch returns the legacy file at
  `backend/time_tracker_api.py:4856`.

Consequently, employees and admins still have two login entry points even
though the supported behavior has already moved. Continuing to port Firefly UI
would preserve that duplication. The correct fix is to cut over the two old
entry routes to the already-deployed canonical portal.

The legacy query-string behavior is not itself a capability to preserve:

- printed QR links require only the opaque `checkIn` value, and the current
  redirect deliberately strips every other parameter at
  `backend/time_tracker_api.py:4844-4855`;
- the Firefly page accepts and persists an arbitrary `apiBaseUrl` from either
  its query string or editable UI at `backend/timetracker-mobile.html:424-429`
  and `backend/timetracker-mobile.html:762-778`; and
- the canonical portal independently restricts its direct development override
  to the production API or localhost. Carrying an arbitrary legacy API host
  through a production cutover would weaken the QR anti-exfiltration boundary,
  not preserve a required timekeeping function.

## What a correct fix must touch and change

1. Replace the default behavior of both backend entry routes.
   - `GET /` and `GET /timetracker-mobile.html` must always return a temporary
     `302` redirect to `{PUBLIC_APP_URL}/portal`.
   - When `checkIn` is non-empty, the destination must be
     `{PUBLIC_APP_URL}/portal?checkIn=<percent-encoded-value>`.
   - `checkIn` must remain the only forwarded query value. Empty `checkIn`,
     `apiBaseUrl`, and unknown parameters must not be carried into the canonical
     employee portal.
   - Every redirect must include `Cache-Control: no-store` so a phone does not
     cache the cutover destination as permanent.

2. Reuse the existing canonical-host guard.
   - An unset `PUBLIC_APP_URL`, an invalid empty host, or a value on the
     backend's own hostname must never create a redirect loop.
   - Those configurations must fail closed with the existing `503` and
     `Cache-Control: no-store` behavior.
   - The canonical destination remains `/portal`, not `/portal.html`, matching
     the deployed website's clean URL.

3. Remove only the dead runtime file reference.
   - Once neither route serves it, `FRONTEND_FILE` must no longer be part of the
     API module's runtime configuration.
   - The Firefly HTML file itself remains in the repository during this
     deployment slice so physical deletion and its CI/static-test cleanup stay
     independently reviewable after the redirect is live.

4. Replace the old route contracts with cutover contracts.
   - Tests must cover both old paths, with and without `checkIn`.
   - Tests must prove exact encoding, `302`, `no-store`, and stripping of
     unrelated parameters.
   - Tests must prove unset and self-origin configuration returns `503` for
     ordinary as well as QR requests and never serves the legacy marker.
   - Existing QR generation fail-closed and no-token-rotation guarantees must
     remain covered.

5. Update the checked-in QR operational description only where it describes
   these two entry routes, so it no longer claims ordinary requests serve the
   Firefly page. All QR evidence, geofence, classification, and review
   descriptions remain unchanged.

## What must not change

- Do not delete or edit `backend/timetracker-mobile.html` in this slice.
- Do not remove or change any `/api/*` route, including the legacy
  generate/download-report endpoints, `/api/hours`, or `/api/current-status`.
- Do not change the canonical website repository, portal UI, authentication,
  sessions, Juan/Mayra admin enforcement, employee roles, clock-in/out,
  arrival/departure, GPS collection, geofences, QR token creation/rotation,
  QR resolution/submission, server timestamps, classification, schedules,
  Calendar integration, corrections, audit history, reports, or receivables.
- Do not change PostgreSQL schemas or stored data, add a second backend or QR
  registry, introduce background tracking, or perform a production check-in.
- Do not add a new runtime cutover flag. `PUBLIC_APP_URL` is already required
  for generated QR destinations and was verified in this session by the live
  backend redirecting a probe to `https://effinghamofficemaids.com/portal`.
- Do not remove the legacy HTML syntax gate, brittle-pattern enrollment, or
  static legacy-page tests yet. They remain valid while the file is retained as
  rollback material; only their route-serving assertions may change.

No implementation is complete unless every required item above appears in the
diff and every changed hunk traces back to this contract.
