# Connect Device Enrollment Contract

Status: implemented for the device lifecycle (enroll, list, revoke), a read-only
device-authenticated funnel access path (see "Device-authenticated access"), a
confirmation-gated tracker-local MUTATION path (the lead-working claim), and the
confirmation-gated Atlas MONEY paths (approve-and-send an onboarding draft, and
estimate / first-clean booking via a durable authorization reservation), all
under "Device-authenticated mutations". Wiring the remaining Atlas money path
(customer handoff) through a device reuses this same gate and is the next slice.

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

## Device-authenticated access

Once enrolled, a device acts on its operator's behalf with no operator bearer
token in the request. Authentication is a per-request Ed25519 proof
(`require_connect_device`), DPoP-style:

- The device sends `X-Connect-Device` (its `device_id`), `X-Connect-Timestamp`
  (unix seconds), and `X-Connect-Signature` (base64url Ed25519 signature).
- It signs a canonical, newline-delimited string that binds a fixed context tag
  (`connect-device-access-v1`), the `device_id`, the HTTP method, the request
  path, the raw query string, the SHA-256 of the body, and the timestamp. The
  server reconstructs the exact same string and verifies it against the stored
  public key. Binding the method, target, and body means a captured proof cannot
  be replayed against a different call; the timestamp freshness window
  (`CONNECT_DEVICE_ACCESS_PROOF_TTL_S`, default 120s, with a 60s negative skew
  tolerance) bounds replay against the same call. The context tag keeps this
  proof disjoint from the enrollment challenge signature.
- The bound operator is resolved from the device row and must still be an active
  admin. The per-PC device does not license the caller: revoking the device, or
  deactivating or demoting the operator, immediately stops access (`401` for a
  missing/invalid/expired proof or a non-active device; `403` for an
  inactive/non-admin bound operator). Each verified request stamps
  `last_seen_at`.

The tracker stays the sole holder of the Atlas funnel service token; the bound
operator is vouched for through the same `X-EOM-Actor` / `X-EOM-Actor-ID`
headers the office endpoints use, so the funnel sees the operator, never the
device.

### Read endpoint (this slice)

- `GET /api/connect/device/funnel/leads` (device proof only) -> the funnel
  work-queue poll: `{success, leads, workingLeads, pendingHandoffs, cursor,
  hasMore, nextCursor, capabilities, capabilitiesDeclared}`. It relays the same
  new/working overlay the office review shows plus the capability names the
  deployed Atlas advertises, so an automation can gate an action instead of
  invoking one Atlas will 404. It performs no mutation and intentionally omits
  the office review's Website-only mutation-affordance flags (the device renders
  no UI). Reads change no state, so they carry no confirmation gate.

## Production safety

Additive and backward-compatible: one new table created idempotently in the
startup migration path (`_ensure_connect_device_schema`, under an advisory
lock) and new endpoints under a new path prefix. No existing table, response
shape, or code path is changed, so the change is inert to every running portal
until a device is enrolled.

## Device-authenticated mutations

A device mutation reuses the `require_connect_device` proof and adds two
single-use, DB-backed, TTL-bounded tokens (both survive a host restart; both
reference `connect_devices` ON DELETE CASCADE):

- **Operation challenge** -- the single-use anti-replay nonce a device mutation
  needs beyond a read's timestamp window. `POST
  /api/connect/device/operations/challenge` (device proof) mints one bound to the
  device; the device references its `challengeId` in the mutation body its
  Ed25519 proof signs, and dispatch consumes it exactly once.
- **Operation confirmation** -- the per-operation human gate. `POST
  /api/admin/connect/devices/{device_id}/operation-confirmations`
  (`Depends(get_current_admin)`) records a fresh operator authorization bound to
  the device and the exact operation fingerprint, single-use with a short TTL.
  The fingerprint is `sha256` of the capability merged with the operation's
  material target parameters, so a confirmation authorizes exactly one concrete
  operation: the contact id and lead state token for `mark_working`, the draft id
  for `approve_send`, and the contact id, scheduled window, and client idempotency
  key for the bookings. A confirmation-required capability cannot dispatch from the
  unattended device without a matching, unconsumed, unexpired confirmation, and a
  confirmation issued for one operation can never authorize another.

Capabilities a device may perform are a **CLOSED** set
(`_CONNECT_DEVICE_CONFIRMATION_REQUIRED_CAPABILITIES`); an unlisted capability is
refused. The implemented capabilities are `funnel.lead.mark_working` (tracker
local), `funnel.onboarding_draft.approve_send` (the first Atlas money path), and
`funnel.lead.estimate_booking` / `funnel.lead.first_clean_booking` (the Atlas
booking money paths).

### Mutation endpoints

- `POST /api/connect/device/funnel/leads/{contact_id}/working` (device proof) ->
  claims a lead as working on the bound operator's behalf via the existing
  tracker-local `_mark_lead_working` (reversible, no Atlas call). It is faithful
  to the office path -- the bound operator must be the configured funnel approver
  (`403` otherwise) -- and, being confirmation-required, requires both a valid
  `challengeId` and a matching `confirmationId`. Both tokens are consumed inside
  the working-state transaction (via `_mark_lead_working`'s `authorize` hook),
  after every conflict/idempotency check has passed: a crash or a state conflict
  never spends a token without the transition, an already-working lead is a safe
  idempotent no-op, and a spent challenge cannot drive a new transition (`409`).
- `POST /api/connect/device/funnel/onboarding-drafts/{draft_id}/approve-send`
  (device proof) -> approves and sends an onboarding draft on the bound
  operator's behalf. This is a real Atlas money path: it relays to Atlas with the
  tracker's service token (the device holds no Atlas credential), faithful to the
  office `approve-send` (approver-gated, and refused `501` when the deployed Atlas
  does not advertise the capability). Being confirmation-required, it needs a
  valid `challengeId` and a `confirmationId` bound to this exact draft. Because
  the effect is an external call rather than a local write, the tokens are
  consumed in their own transaction BEFORE the Atlas call: this is fail-safe. A
  crash after consumption leaves no send (the operator re-confirms), never a
  replayable authorization; and Atlas's draft-id state machine (the stable
  `eom-onboarding-draft:{draft_id}` idempotency key) makes the send idempotent, so
  a transient failure is retried by re-confirming without a double-send. Returns
  `201` on a new send and `200` on Atlas's idempotent replay.
- `POST /api/connect/device/funnel/leads/{contact_id}/estimate-bookings` and
  `POST /api/connect/device/funnel/leads/{contact_id}/first-clean-bookings`
  (device proof) -> book an Atlas estimate or first clean on the bound operator's
  behalf, relaying to Atlas with the tracker's service token. Faithful to the
  office booking helper (same Atlas capability gate, same body, same `200`/`201`
  receipt), and strengthened for the unattended device: the bound operator must be
  the configured approver (the office booking route is only admin-role gated), and
  the operation needs a challenge plus a confirmation bound to the exact booking
  (contact, window, and client `idempotencyKey`). Unlike `approve_send`, the
  booking's idempotency key is client-supplied and the state is richer, so dispatch
  goes through a **durable authorization reservation**: the challenge and
  confirmation are consumed, and the frozen Atlas request and idempotency key are
  recorded, in one transaction (which re-asserts the operator is active first). The
  relay is then driven from that reservation. A retry after an ambiguous Atlas
  failure replays the reservation with the same frozen request and key -- no fresh
  confirmation, and Atlas resolves the key idempotently, so there is no double
  booking. A completed reservation returns its frozen receipt (`200`) without
  re-calling Atlas. The reservation is single per `(device, operation fingerprint)`,
  so a compromised device can only re-drive an already-authorized booking, never
  mint a new one; a new window or key is a new fingerprint that needs a fresh
  confirmation.

## Deferred to a later slice

- Wiring the customer-handoff Atlas money path through the device. It reuses the
  durable-reservation gate above, adds the full customer/site payload to its
  operation fingerprint (the office path already fingerprints those fields), and
  carries the office handoff's `202`-pending reconciliation. The booking paths
  above are the worked template for the reservation dispatch.
