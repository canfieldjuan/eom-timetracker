# Security containment

This slice makes the backend service the source for both the web page and API.
Open the deployed service root (`/`) instead of distributing a separate HTML
file.

## Access boundaries

- `/api/hours` and `/api/current-status` require an administrator token.
- Employees calling `/api/timesheet/current-status` receive only their own
  active-shift record. Administrators may see all active shifts.
- Public registration is disabled unless `ALLOW_PUBLIC_REGISTRATION=true` is
  explicitly configured. Administrators can create accounts with
  `POST /api/admin/employees`.
- Cross-origin browser access is denied when neither `ALLOWED_ORIGINS` nor
  `ALLOWED_ORIGIN_REGEX` is configured. The bundled same-origin page needs no
  CORS configuration.

## Read-only time-data audit

An administrator can run:

```text
GET /api/admin/audits/time-data
Authorization: Bearer <admin token>
```

The response reports exact-time duplicate shift groups, employees with more
than one open shift, and open shifts older than `MAX_ACTIVE_SHIFT_HOURS`.
It performs no shift updates or deletions. Review the reported shift IDs and
back up the database before any later cleanup migration.
