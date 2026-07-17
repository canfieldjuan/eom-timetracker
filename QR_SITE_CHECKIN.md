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
   reading and submit `employeeId`, `siteId`, `scannedAt`, `latitude`,
   `longitude`, and `accuracy`.
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
`PUBLIC_APP_URL` should be set to the production HTTPS app origin so printed
codes stay canonical behind a reverse proxy.

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
time. QR classification therefore uses `site_check_in_schedules`, which records
an exact employee, site, scheduled start timestamp, and grace period. The
closest record within 12 hours is used. A confident in-geofence check-in at or
before scheduled start plus grace is `on_time`; a later one is `late`. No
matching exact schedule is `needs_review`.

The device scan timestamp is stored only as evidence. A difference greater than
10 minutes from the server timestamp triggers `needs_review` and never changes
the official time.

## Admin review

Admins can create or rotate printable site QR codes, create exact arrival
schedules, list pending evidence, and approve or reject a `needs_review` record
with a required note. The evidence keeps the employee, site, both timestamps,
coordinates, accuracy, distance, geofence result, schedule snapshot,
classification reason, and review decision.
