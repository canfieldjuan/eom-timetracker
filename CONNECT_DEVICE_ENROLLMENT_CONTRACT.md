# Connect Device Enrollment Contract

Status: implemented for the device lifecycle (enroll, list, revoke). The
device-authenticated access path that calls the funnel on an operator's behalf
is a separate, later slice and is not part of this contract yet.

## Purpose

A downloadable Local Connect automation runs on an operator's own PC and must
be able to act on that operator's behalf against the EOM funnel without any
Atlas or tracker service credential ever living on the PC. This contract covers
the first half of that: an operator links a device to their own account by
proving the device holds a private key, and can list and revoke their devices.
The tracker remains the only holder of the Atlas funnel service token and the
only party that vouches for an operator via `X-EOM-Actor` headers; a later slice
adds the device-authenticated endpoint that performs the funnel call.

## Identity and trust

- The device generates an Ed25519 keypair locally. The private key never leaves
  the device. Only the base64url public key is sent to the tracker and stored.
- A device is bound to exactly one operator (`connect_devices.employee_id`,
  referencing `employees.id`, which is a SERIAL integer). Binding a device to a
  second operator is a second enrollment producing a second row, never a
  mutation of the first.
- Enrollment is authenticated as the operator through the existing office
  session (`Depends(get_current_admin)`), the same dependency the funnel office
  endpoints use. The device proof rides inside that authenticated request.

## Proof of possession

1. `POST /api/admin/connect/devices/enrollment-challenge` returns a short-lived,
   HMAC-SHA256-signed challenge bound to the calling operator. It is stateless:
   the signature (keyed by `JWT_SECRET`, the same construction the other opaque
   tokens here use) proves the tracker issued it, and an embedded issue time
   bounds its lifetime (`CONNECT_DEVICE_ENROLLMENT_CHALLENGE_TTL_S`, default
   300s). No server-side store is required, because replaying a challenge can
   only re-register the same key (the Ed25519 signature never verifies for a
   different key).
2. `POST /api/admin/connect/devices` accepts `{label, publicKey, challenge,
   signature}`. The tracker verifies the challenge (issuer HMAC, operator
   binding, TTL), then verifies the Ed25519 `signature` over the exact
   `challenge` string with `publicKey`. Only then is the device recorded.

## Status set (closure declaration)

`connect_devices.status` is a **CLOSED, ENUMERATED** set: `{active, revoked}`.
The canonical membership is the `CHECK (status IN ('active','revoked'))`
constraint on the table (created in `_ensure_connect_device_schema`). Revocation
is a one-way flip to `revoked` with a `revoked_at` stamp; a revoked key is never
reactivated. Key rotation is a fresh enrollment with a new keypair, which
supersedes the old device by leaving it revoked.

## Endpoints (all `Depends(get_current_admin)`, operator-scoped)

- `POST /api/admin/connect/devices/enrollment-challenge` -> `{challenge, expiresAt}`.
- `POST /api/admin/connect/devices` -> the device view. `201` on a new device,
  `200` when the same operator re-enrolls the same active key (idempotent).
  `409` when the key belongs to another operator, or was revoked.
- `GET /api/admin/connect/devices` -> `{devices: [...]}`, the caller's own
  devices only, newest first.
- `POST /api/admin/connect/devices/{device_id}/revoke` -> the device view with
  `status = revoked`. `200` (idempotent when already revoked); `404` when the
  device is not the caller's. Revocation is scoped to the owning operator.

The device view is a closed projection: `{deviceId, label, status, createdAt,
lastSeenAt, revokedAt}`. The public key is never returned.

## Production safety

Additive and backward-compatible: one new table created idempotently in the
startup migration path (`_ensure_connect_device_schema`, under an advisory
lock) and new endpoints under a new path prefix. No existing table, response
shape, or code path is changed, so the change is inert to every running portal
until a device is enrolled.

## Deferred to the next slice

- The device-authenticated access endpoint: a device proves possession per
  operation, the tracker verifies it against the stored public key and the
  device's `active` status, updates `last_seen_at`, and performs the funnel call
  with the bound operator's actor headers.
- The per-operation confirmation gate for confirmation-required capabilities.
