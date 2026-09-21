# Connect Local Provider Credential Contract

Status: design. This resolves the open item the build plan flagged before the
local-provider slice is buildable: how a downloadable, per-PC EOM Connect
provider that fronts the Atlas funnel acquires, stores, rotates, and revokes a
credential WITHOUT the shared Atlas service token ever living on a buyer PC. No
code ships with this document; it pins the design against the current tracker
and host source so the provider slice can be built directly from it.

Citations to the tracker are `backend/time_tracker_api.py:<line>` unless noted.
Citations to the host are relative to the companion repo
`../connect-automate` (the vendor-neutral Connect Automate host core).

## The problem, stated against the code

The tracker is today the sole holder of the Atlas funnel service token and the
sole party that vouches for an operator to Atlas:

- The shared bearer is read once at import: `ATLAS_FUNNEL_SERVICE_TOKEN`
  (`:4962`), with `ATLAS_FUNNEL_BASE_URL` (`:4961`) and a presence gate
  `_require_atlas_funnel_configuration` (`:5298`).
- Every write relay attaches it as `Authorization: Bearer` and adds plaintext
  operator vouching headers `X-EOM-Actor` and `X-EOM-Actor-ID`
  (`_atlas_funnel_request` header block `:5317-5323`); the read relay does the
  same (`_atlas_funnel_read` `:5908-5913`). Atlas takes the operator identity
  from those plaintext headers and trusts the shared bearer; it performs no
  independent operator proof. The tracker is therefore the trust boundary.

A Connect provider is same-PC loopback (connect-contracts ADR-0005): a consumer
can only invoke a provider registered on the same machine, so the remote Atlas
server cannot itself be a Connect provider, and a local provider on the buyer PC
must exist to front it. If that local provider held `ATLAS_FUNNEL_SERVICE_TOKEN`,
the shared bearer would be copied onto every buyer PC, where a single
exfiltration would forge any operator to Atlas (the headers are plaintext). That
is the outcome this contract forbids.

## The credential: the enrolled device key, nothing new

The correct credential already exists. The device access slice (PRs #269, #270,
#271) built a per-PC Ed25519 device identity that authenticates to the tracker
per request and carries no Atlas secret:

- `require_connect_device` (`:28235`) verifies a DPoP-style per-request Ed25519
  proof over a canonical string binding a context tag, the device id, the HTTP
  method, the path, the query, `sha256(body)`, and a timestamp
  (`_connect_device_access_signing_string` `:28134-28153`), inside a freshness
  window (`:28287`, `CONNECT_DEVICE_ACCESS_PROOF_TTL_S` default 120s `:5020`).
- It returns an actor dict shaped exactly like the office `admin` dict
  (`:28227-28232`), which threads straight into the same Atlas relay the office
  path uses. The device-facing read already proves the end-to-end shape: it
  calls `_atlas_funnel_read("/eom-funnel/leads", operator, ...)` at `:28526`,
  so the shared Atlas token stays server-side on the tracker and the device
  authenticates with its key alone (`:28518-28520`).
- The bound operator must resolve to an active admin on every request; a
  revoke, deactivation, or demotion between calls makes the authorizing
  `UPDATE ... last_seen_at` match no row and returns 401 (`:28210-28223`).

So the local provider's credential is its enrolled device Ed25519 private key
plus its `device_id`. The Atlas service token stays on the tracker. The provider
never holds an Atlas secret, only a key that lets it act as one bound operator,
through the tracker's gates, and only until that device or operator is revoked.
This converges on the existing device scheme rather than adding a second
credential type.

## Where the local provider sits

```
Automate host (Connect consumer, buyer PC)
   |  connect.invoke  (same-PC loopback, ADR-0005)
   v
Local EOM Connect provider (buyer PC)
   |  outbound HTTPS, per-request Ed25519 device proof (no Atlas token)
   v
Tracker device endpoints  (holds ATLAS_FUNNEL_SERVICE_TOKEN)
   |  Authorization: Bearer + X-EOM-Actor / X-EOM-Actor-ID
   v
Atlas funnel API
```

The host discovers and invokes the local provider over loopback with a
caller-minted stable `job_id` (the host's Connect v2 client,
`../connect-automate/src/connect_automate/connect.py`). The local provider
translates each invoked capability into a call to the tracker's
device-authenticated endpoint, signing it with the device key. The tracker
resolves the bound operator, applies the office gates, and relays to Atlas with
the shared bearer it alone holds. Atlas sees the operator, never the device and
never a per-PC copy of its token.

## Credential lifecycle

### Acquire (enroll)

Enrollment is the existing operator-authenticated proof-of-possession flow, run
once per PC:

1. The operator authenticates interactively through the office session at
   first run (the same `Depends(get_current_admin)` the enrollment endpoints
   require). This session is used only to enroll and is never persisted to disk.
2. The provider requests an enrollment challenge
   (`POST /api/admin/connect/devices/enrollment-challenge` `:28332`), generates
   an Ed25519 keypair locally, signs the challenge, and enrolls
   (`POST /api/admin/connect/devices` `:28353`). The private key never leaves
   the PC; only the base64url public key is sent and stored
   (`connect_devices.public_key_base64url`).
3. The office session token is discarded. From then on the PC holds only the
   device key. Not even the operator's long-lived bearer remains on the PC, so
   there is no stored credential that can act outside the tracker's per-request
   device gate.

Rationale for the one-time interactive login: enrollment must bind the device to
a real operator, and only the office session authority can make that binding.
Reusing it once, then dropping it, gets the binding without leaving a reusable
secret behind.

### Store

The device key and `device_id` reuse the host's existing, tested per-user
private storage, the same placement the entitlement file uses:

- Windows: under `local_app_data_root() / "LocalConnect"`
  (`../connect-automate/src/connect_automate/entitlement.py:297-315`), created
  with one protected, owner-private DACL
  (`../connect-automate/src/connect_automate/connect_windows.py:244`).
- Unix: under `$XDG_CONFIG_HOME/local-connect` or `~/.config/local-connect`
  with mode `0o700`
  (`../connect-automate/src/connect_automate/entitlement.py:693`, `:701`).

The private key is stored at rest as raw key bytes in that owner-private
directory. No shared secret and no Atlas token is ever written to the PC. The
store holds exactly `{device_id, private_key}`; the public key lives only on the
tracker.

### Rotate

Key rotation is a fresh enrollment with a new keypair that supersedes the old
device, which is the closure rule the enrollment contract already states. The
provider enrolls a new device (new keypair), begins signing with it, then
revokes the old `device_id`. There is no shared secret to rotate and no rotation
window during which two copies of one secret are valid: each device is a
distinct key and a distinct revocable row. Rotation therefore needs no new
endpoint, only the enroll-then-revoke sequence.

### Revoke

Revocation is immediate and one-way, and comes from two independent directions:

- The operator revokes the device
  (`POST /api/admin/connect/devices/{device_id}/revoke` `:28464`). The next
  device request fails the active-device predicate and returns 401
  (`:28210-28223`).
- The operator's own account is deactivated or demoted below admin. The same
  per-request recheck fails and returns 403/401, so losing the operator
  immediately disables every device bound to them, with no revoke call needed.

Because authorization is re-evaluated inside each request's authorizing write,
there is no cached grant to expire and no propagation delay. A compromised buyer
PC is contained by revoking its device (or the operator), not by rotating a
secret that has already been copied.

## Money paths are gated twice, not just authenticated

Authentication (the device key) is separate from authorization of a specific
money operation. The Atlas confirmation-required paths (customer handoff,
estimate and first-clean booking, approve-send, revoke-link, recover) are
office-gated today on the configured approver
(`_require_juan_funnel_approver` `:22926-22935`, enforced on the device write
too at `:28971`). The mutation slice (#271) added the per-operation human gate
that an unattended device needs on top of that: a single-use, TTL-bound
operation confirmation bound to the device and the exact operation fingerprint
(`_CONNECT_DEVICE_CONFIRMATION_REQUIRED_CAPABILITIES` `:28577`,
`_connect_device_operation_fingerprint` `:28582-28604`, issued by
`POST /api/admin/connect/devices/{device_id}/operation-confirmations` `:28775`,
consumed atomically in the transition transaction `:28983-29032`).

So the credential contract and the confirmation gate compose: the device key
authenticates the channel and identifies the operator; a fresh operator
confirmation authorizes each money operation. A stolen device key alone cannot
move money, because every money capability is confirmation-required and a
confirmation is single-use, short-lived, and pinned to one operation
fingerprint. This is the closed extension point the provider slice plugs the
Atlas money paths into (`:28573-28575`).

## What is already built vs. what the provider slice adds

Already built and reusable as the credential substrate:

- The device identity, per-request proof, enrollment, revoke, and the
  operator-active recheck (`:28235`, `:28332`, `:28353`, `:28464`,
  `:28210-28223`).
- The end-to-end relay shape from a device request to Atlas with the token held
  server-side (`:28526`).
- The confirmation gate for confirmation-required capabilities (`:28577`,
  `:28775`, `:28983-29032`).
- The host per-user private storage the key reuses
  (`../connect-automate/src/connect_automate/entitlement.py:297-315`,
  `connect_windows.py:244`).

The provider slice must add (tracked separately, not in this document):

- Device-authenticated tracker endpoints for the Atlas money paths, each
  registering in the closed capability set with its own idempotency key and its
  202-pending handling, mirroring the office relays
  (`_atlas_funnel_request` `:5306`, booking helper `_submit_atlas_funnel_booking`
  `:26328`, the read allow-list `_ATLAS_FUNNEL_READ_PATHS` `:5883` for any new
  read). New reads must be added to that allow-list or they fail closed by
  design.
- The local Connect provider process itself (loopback registration, capability
  manifest, `job_id` idempotent submission) and the adapter that signs tracker
  requests with the device key.

## Security properties

- No Atlas secret on any buyer PC. The shared bearer stays on the tracker
  (`:4962`); the PC holds only a revocable per-device key.
- No stored operator bearer on the PC. The office session is used once at
  enrollment and dropped; steady-state auth is the per-request device proof.
- Immediate containment. Revoking the device or the operator disables access on
  the next request with no secret to rotate (`:28210-28223`).
- Replay resistance. Each request proof binds method, target, body, and a
  freshness window (`:28134-28153`, `:28287`); money operations add a
  single-use confirmation (`:28983-29032`).
- Least privilege. A device can act only as its one bound operator and only
  through the tracker's existing gates (the approver gate `:22926-22935` applies
  to the device identically, `:28971`).

## Production safety

This document is design only and changes no running code, so it is inert to the
live tracker and portal. The provider slice it enables is additive: new
device-authenticated endpoints under the existing `/api/connect/device` prefix
and a new local process on the buyer PC. It introduces no change to the office
API contract or to any Atlas request shape, and it removes the shared Atlas
token from the buyer PC threat surface entirely by never placing it there.

## Deferred

- The provider-side reserve/finalize and 202-pending reconciliation against
  Atlas booking semantics, built when the money-path endpoints land. The tracker
  already implements the local-commit-then-remote-call pending pattern the
  provider mirrors (handoff pending note and retry `:29096-29147`).
- Multi-operator buyer PCs. The device binds one operator; a second operator is
  a second enrollment producing a second device, never a mutation of the first,
  matching the enrollment contract's one-device-one-operator rule.
