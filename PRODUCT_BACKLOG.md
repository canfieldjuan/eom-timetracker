# Product Backlog

This file records approved future product slices. An item listed here is not yet implemented or deployed.

## QR Site Check-In

Status: Core QR check-in and recurring weekly arrival rules are deployed. The
admin Arrival Activity view is in the current implementation slice, pending
review and deployment. See `QR_SITE_CHECKIN.md`.

Add a **Check in** action for employees with this contract:

- Require the employee's normal authenticated session.
- Scan the site's QR code and resolve it to a registered site ID.
- Request device location only after the employee taps **Check in**; do not require continuous or background location tracking for this action.
- Send `employeeId`, `siteId`, the signed QR `token`, `scannedAt`, `latitude`, `longitude`, and `accuracy` to the server; revalidate the token during the write.
- Treat the authenticated session as the employee authority. The server must reject an `employeeId` that does not match the signed-in employee.
- Let the server set the official check-in timestamp rather than trusting the device's `scannedAt` value.
- Let the server validate that the site exists, evaluate the configured geofence using coordinates and reported accuracy, and classify the result as `on_time`, `late`, or `needs_review`.
- Store enough evidence for an admin to review the decision: employee, site, server timestamp, device scan timestamp, coordinates, accuracy, geofence result, and classification reason.

The QR token format, geofence radius/accuracy policy, exact-arrival schedule source, offline behavior, and admin review workflow are defined in `QR_SITE_CHECKIN.md`.
