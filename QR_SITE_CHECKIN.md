# QR Site Check-In Contract

This slice adds authenticated, evidence-backed site arrival check-ins. It does
not perform continuous tracking and it does not create or modify a paid shift.
The existing clock-in, arrival, departure, and clock-out records remain the
source of paid time until those two workflows are intentionally joined.

## Employee flow

1. An admin prints a QR for a registered site.
2. The employee scans it with the phone's normal Camera app. The QR opens the
   existing web app with an opaque, signed site token.
3. The employee signs in through the normal session if needed. Resolving the QR
   requires that session but does not request location.
4. The employee taps **Check in**. Only then does the browser request one GPS
   reading and submit `employeeId`, `siteId`, the signed QR `token`, `scannedAt`,
   `latitude`, `longitude`, and `accuracy`. The server revalidates the current
   token during this final write instead of trusting the earlier browser-side
   resolve step.
5. The server uses its own receipt time as the official check-in timestamp and
   returns `on_time`, `late`, or `needs_review`.

There is no offline queue. A network failure records nothing and tells the
employee to reconnect and retry. This prevents a device from backdating an
official check-in.

## QR token

The token format is `eom1.<siteId>.<nonce>.<hmac-sha256-signature>`. The HMAC is
derived from the server's configured secret. A token selects a site; it never
authenticates an employee. Each site has a rotatable nonce, so replacing a QR
immediately invalidates older printed copies.

The encoded value is an HTTPS app URL with the token in the `checkIn` query
parameter. This lets iPhone and Android users scan with the built-in Camera
instead of granting the web app continuous camera access.

## Canonical portal destination (issue #35)

`PUBLIC_APP_URL` names the canonical EOM portal origin
(`https://effinghamofficemaids.com`). When it is set to an origin other than
this backend's own host:

- Newly generated QR URLs are `{PUBLIC_APP_URL}/portal?checkIn=<token>`
  (`/portal`, not `/portal.html` — the website deploy uses cleanUrls).
- `GET /` and `GET /timetracker-mobile.html` answer any request carrying a
  non-empty `checkIn` parameter with a `302` to that same portal URL,
  forwarding only the `checkIn` value and marking the response
  `Cache-Control: no-store`. Already-printed QR codes that point at this
  backend therefore land in the canonical portal without reprinting.

When `PUBLIC_APP_URL` is unset (or points at this backend's own host, which
would otherwise redirect the backend to itself), both behaviors fall back to
the legacy shape: generated URLs use `{origin}/?checkIn=<token>` and the
legacy page is served directly. Unsetting the variable is the complete
rollback for the portal cutover; the temporary 302 plus `no-store` means no
phone has cached the redirect.

## Geofence and accuracy policy

- Default site radius: 50 meters (`SITE_CHECK_IN_RADIUS_M`).
- Maximum usable reported accuracy: 100 meters
  (`SITE_CHECK_IN_MAX_ACCURACY_M`).
- `inside`: `distance + accuracy <= radius`.
- `outside`: `distance - accuracy > radius`.
- Otherwise the reading is `uncertain` because its accuracy circle crosses the
  geofence boundary.
- An unpinned site, low-accuracy reading, outside reading, or uncertain reading
  is retained and classified `needs_review`; it is not discarded.

## On-time source

Weekly hour budgets in the existing `schedules` table cannot establish a start
time. QR classification therefore uses either:

- `site_check_in_schedules` for an exact employee, site, timestamp, and grace
  period; or
- `site_check_in_schedule_rules` for durable weekday, local start time, date
  range, company timezone, and grace-period rules.

An exact record is an explicit override when one is within 12 hours. Otherwise,
the server computes the closest weekly-rule occurrence within 12 hours in the
rule's timezone. This keeps a 7:00 AM arrival at 7:00 AM across daylight-saving
changes instead of freezing its UTC offset. A confident in-geofence check-in at
or before scheduled start plus grace is `on_time`; a later one is `late`. No
matching exact schedule or weekly rule is `needs_review`.

The device scan timestamp is stored only as evidence. A difference greater than
10 minutes from the server timestamp triggers `needs_review` and never changes
the official time.

## Admin review

Admins can create or rotate printable site QR codes, create exact arrival
schedules, create or end recurring weekday rules, and browse all arrival
evidence by status, employee, site, and company-local date range. A separate
exception queue lets an admin approve or reject a `needs_review` record with a
required note. Ending a weekly rule is a soft deletion so prior evidence retains
its source. The evidence keeps the employee, site, both timestamps, coordinates,
accuracy, distance, geofence result, exact schedule or weekly-rule ID, schedule
snapshot, classification reason, and review decision.

The separate read-only comparison with paid clock-ins and **Arrived** events is
defined in `ARRIVAL_TIMECARD_RECONCILIATION.md`. It surfaces exceptions for an
admin but does not alter the paid-time source of record.
