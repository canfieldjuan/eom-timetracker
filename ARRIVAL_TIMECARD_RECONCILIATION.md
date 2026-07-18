# Arrival vs. Timecard Reconciliation Contract

This slice gives administrators a read-only comparison between scheduled QR
arrivals and the existing paid-time workflow. It never creates, edits, closes,
or deletes a shift, visit, departure, QR check-in, or payroll record.

## Reconciliation unit

Each row represents one scheduled employee, site, and arrival time in a company
date range. One-time schedules override a weekly-rule occurrence for the same
employee and site when they fall within the existing 12-hour schedule window.
This prevents the pilot's backfilled one-time schedules and durable weekly rules
from creating duplicate rows.

An ended weekly rule remains available for occurrences before its recorded end
time, but it does not create future reconciliation rows.

The endpoint accepts employee, site, company-local date, outcome, and
exceptions-only filters. A request is limited to 31 calendar days.

## Evidence matching

For each scheduled row, the server matches at most one QR check-in and one
paid-time arrival within the configured schedule window.

- A QR check-in linked to the exact schedule or weekly rule is preferred, then
  the nearest same-employee, same-site QR record.
- A same-site paid-time event is preferred over an event at another or unknown
  site. Within that group, the event nearest the QR timestamp (or scheduled
  time when QR evidence is missing) is used.
- Paid-time evidence can be an explicit **Arrived** visit or a clock-in whose
  original location label exactly identifies the registered site.
- A shift location that was only auto-linked later by an **Arrived** action is
  not treated as proof that the employee clocked in at that site. The explicit
  visit remains the site-arrival evidence.
- One QR check-in or paid-time event cannot satisfy two scheduled rows.

## Outcomes

- `matched`: QR and paid-time arrivals identify the scheduled site and are no
  more than 15 minutes apart by default.
- `pending`: the scheduled arrival is still inside its grace period and one or
  both evidence sources have not arrived yet.
- `missing_qr`: paid-time site arrival exists after the grace period, but QR
  evidence does not.
- `missing_time_entry`: QR arrival exists after the grace period, but no nearby
  paid clock-in or **Arrived** event exists.
- `missing_both`: neither evidence source exists after the grace period.
- `site_mismatch`: the nearest paid-time evidence identifies another or unknown
  site.
- `time_gap`: both sources identify the site, but their timestamps are farther
  apart than the configured threshold.
- `qr_needs_review`: timecard evidence matches, but the QR geofence evidence has
  not been approved.
- `qr_rejected`: timecard evidence matches, but an admin rejected the QR
  evidence.

The default timestamp threshold is controlled by
`SITE_CHECK_IN_RECONCILIATION_GAP_MINUTES`. An exception is evidence for Juan or
Mayra to review; it is not an automatic wage or disciplinary decision.

## API and admin view

`GET /api/admin/site-check-in-reconciliation` is admin-only and returns the
official as-of time, threshold, summary counts, and evidence rows. The admin
**Arrival vs. Timecard** view uses the same employee, site, and date filters as
**Arrival Activity** and defaults to exceptions only.
