# Time-Entry Location Evidence Contract

This contract applies to the existing clock-in, clock-out, arrival, and
departure actions. It does not add continuous/background tracking and does not
govern the separate QR site-arrival evidence flow; see `QR_SITE_CHECKIN.md`.

- The authenticated session identifies the employee; the client cannot choose
  a different employee ID.
- The server sets the official event timestamp.
- Every time action must include a complete latitude/longitude pair or an
  explicit GPS override reason. This rule is enforced by the API, not only by
  the bundled web page.
- Coordinates must be valid geographic values. A partial coordinate pair is
  rejected even when an override reason is present.
- Coordinates inside the configured site radius are accepted. Coordinates
  outside the radius, or coordinates that cannot be compared because no site
  is pinned, require an explicit override reason.
- Override details are accepted only with an explicit override reason.
- The browser sends the device-reported accuracy in meters. The server stores
  any finite, nonnegative value as evidence but does not treat it as proof that
  the device location is genuine and does not apply an accuracy cutoff.
- Administrators can see the latest coordinates, reported accuracy, site-match
  result, and any override reason in the live worker dashboard.

Browser geolocation remains client-reported and can be spoofed by a determined
user. This slice prevents silent GPS omission and makes exceptions visible; it
does not replace a company-vehicle tracker. The QR flow adds signed site
selection and stricter accuracy-aware geofence review, but its phone GPS can
still be spoofed by a determined user.
