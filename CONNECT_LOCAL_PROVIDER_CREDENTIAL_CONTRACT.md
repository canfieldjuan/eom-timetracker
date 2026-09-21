# Connect Local Provider Credential Contract

Status: design. This resolves the open item the build plan flagged before the
local-provider slice is buildable: how a downloadable, per-PC EOM Connect
provider that fronts the Atlas funnel acquires, stores, rotates, and revokes a
credential WITHOUT the shared Atlas service token ever living on a buyer PC. No
code ships with this document; it pins the design against the current tracker
and host source so the provider slice can be built directly from it.

Citations to the tracker are `backend/time_tracker_api.py:<line>` at this PR's
head unless noted. Citations to the host are relative to the companion repo
`../connect-automate` pinned at commit
`bf1cd1de1491601c7570ef72d2037b83a72b63c6`; the line numbers in this document
resolve against that revision, so the security-critical storage guarantees below
can be verified against the exact host implementation reviewed here rather than a
later, moved line. A future host revision that changes those primitives must be
re-pinned here before this design relies on it.

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
- The bound operator must resolve to an active admin on every request, and the
  wire contract distinguishes the failure kinds: a missing, revoked, or
  non-active device row is `401` at the initial device lookup (`:28170-28178`); a
  device whose bound operator is inactive or not an admin is `403` on the default
  path, where the operator is checked before the authorizing write
  (`:28191-28200`); and the authorizing `UPDATE ... last_seen_at` matching no row
  returns `401` only in the narrow case where a revoke or demotion commits
  concurrently, between those checks and the write (`:28202-28223`). So the
  provider reads `401` as an invalid or revoked device credential and `403` as a
  suspended or demoted operator.

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
store holds exactly the current `{device_id, private_key}`; the public key lives
only on the tracker.

### Rotate

Key rotation replaces the keypair and retires the old device. There is no shared
secret to rotate: each device is a distinct key and a distinct revocable row. The
hazard to avoid is a two-step "enroll new, then revoke old" sequence, because
enrollment creates a second active row rather than mutating the first (registry
uniqueness is only on `public_key_base64url`, `:28384-28395`, so the tracker
allows an operator multiple active rows), and a crash between the two steps would
leave the old key active. A device-authenticated revoke that let any of an
operator's devices revoke any other would also be unsafe: an attacker holding the
compromised old key (and the new device id) could revoke the replacement before it
revoked the old one, and because revocation is one-way the operator could no
longer authenticate as the replacement while the compromised old key stayed live.

Rotation is therefore a single atomic, bearer-authenticated operation, which is
available because rotation is inherently interactive (enrollment already requires
`Depends(get_current_admin)`, so the operator is present with a session):

- `POST /api/admin/connect/devices` gains an optional `supersedes: <old device_id>`.
  In one transaction the tracker verifies the caller's operator owns the named
  predecessor, records the new device active, and revokes the predecessor. There
  is no window in which both are active and no separate revoke step, so a crash
  cannot strand the old key: either the whole rotation committed (new active, old
  revoked) or none of it did. Because the operation is bearer-gated, a PC-only
  attacker without an office session cannot invoke it, and no device may revoke a
  peer, so the peer-revocation attack above cannot arise.

Local-store ordering for crash safety: persist the new private key with a
`pending_enroll` intent before the call, then on success record the returned
`device_id` and drop the old key. If the host crashes after the call commits but
before it records the `device_id`, startup lists the operator's devices
(`GET /api/admin/connect/devices`) and matches the stored public key to recover
the `device_id`; re-issuing the same enrollment is the existing idempotent
re-enroll (`200`), so recovery is safe. No device-authenticated revoke and no
unattended reconciliation are needed, because the retire is part of the atomic
enrollment rather than a later step.

### Revoke

Two independent controls stop a device, and they differ in permanence:

- **Permanent, one-way: device revocation.** The operator revokes the device
  (`POST /api/admin/connect/devices/{device_id}/revoke` `:28464`), which flips
  `connect_devices.status` to `revoked` with no path back (`:28490-28497`; the
  status set is closed and a revoked key is never reactivated). The next device
  request fails at the device-row lookup and returns `401` (`:28170-28178`).
- **Temporary, reversible: operator suspension.** Deactivating or demoting the
  bound operator makes the per-request recheck fail: the default path checks the
  operator before the authorizing write and returns `403` (`:28191-28200`), and
  a revoke or demotion racing the write returns `401` at the update-miss
  (`:28202-28223`). Access stops immediately while the operator is inactive. But
  this is a SUSPENSION, not revocation: the employee record can be reactivated or
  re-promoted (`:16846-16849`), and because the device row itself is still
  `active` (only the explicit revoke flips it), every device bound to that
  operator becomes usable again. Deactivating an operator during a security
  incident does not durably contain a device believed compromised.

### Revoke

Two independent controls stop a device, and they differ in permanence:

- **Permanent, one-way: device revocation.** The operator revokes the device
  (`POST /api/admin/connect/devices/{device_id}/revoke` `:28464`), which flips
  `connect_devices.status` to `revoked` with no path back (`:28490-28497`; the
  status set is closed and a revoked key is never reactivated). The next device
  request fails the active-device predicate and returns 401 (`:28210-28223`).
- **Temporary, reversible: operator suspension.** Deactivating or demoting the
  bound operator makes the same per-request recheck fail (it reads the operator's
  current `active` and `role`, `:28210-28223`), so access stops immediately while
  the operator is inactive. But this is a SUSPENSION, not revocation: the employee
  record can be reactivated or re-promoted (`:16846-16849`), and because the
  device row itself is still `active` (only the explicit revoke flips it), every
  device bound to that operator becomes usable again. Deactivating an operator
  during a security incident does not durably contain a device believed
  compromised.

So permanent containment of a compromised buyer PC requires explicitly revoking
its device (the one-way flip); operator deactivation alone is a reversible
suspension. Because authorization is re-evaluated inside each request's
authorizing write, either control takes effect on the next request with no cached
grant to expire and no propagation delay. A future hardening option is to revoke
an operator's devices durably when the operator is deactivated or demoted, so
account containment implies device containment; until then the two controls are
distinct and this contract treats explicit device revocation as the permanent
one.

## Money paths are gated twice, not just authenticated

Authentication (the device key) is separate from authorization of a specific
money operation. The office approver gate is NOT uniform across the money paths,
so the device paths do not inherit it by simply mirroring the office relay: the
handoff and approve-send routes enforce the configured approver
(`_require_juan_funnel_approver` `:22926-22935`, enforced on the device write too
at `:28971`), but the estimate- and first-clean-booking routes are only
admin-role gated (`get_current_admin` `:2423-2430`) and delegate to
`_submit_atlas_funnel_booking`, whose sole authorization check is the Atlas
capability (`:26341-26345`, routes `:26384-26424`). Because an unattended device
is a stronger threat than an operator sitting at the office UI, every device
money path REQUIRES the configured approver explicitly, including the booking
paths, a deliberate strengthening over the office booking routes rather than a
mirror of them.

The mutation slice (#271) added the per-operation human gate an unattended device
needs on top of that: a single-use, TTL-bound operation confirmation bound to the
device and the exact operation fingerprint
(`_CONNECT_DEVICE_CONFIRMATION_REQUIRED_CAPABILITIES` `:28577`,
`_connect_device_operation_fingerprint` `:28582-28604`, issued by
`POST /api/admin/connect/devices/{device_id}/operation-confirmations` `:28775`,
consumed atomically in the transition transaction `:28983-29032`).

The fingerprint must bind EVERY authorization-relevant field of the operation,
not only its target id, or one confirmation could authorize a materially
different action. The implementation computes the fingerprint from a
per-capability canonical target that includes all such fields, and each device
money capability defines its complete target:

- `mark_working`: contact id and lead state token.
- `approve_send`: draft id (its only material field).
- estimate / first-clean booking: contact id, scheduled window
  (`scheduledStart`, `scheduledEnd`) and the client idempotency key
  (`:3150-3184`), so a booking confirmation cannot be redirected to a different
  window.
- customer handoff: the full customer/site payload the office already fingerprints
  for its own idempotency, `_office_conversion_fingerprint` over every
  customer/site field excluding the retry key (`:22949-22953`), plus the contact
  id and idempotency key. Binding the whole payload is required because the
  handoff creates operational Customer/Site records from the request
  (`:23068-23079`), so a confirmation that hashed only the contact id would let a
  compromised device substitute the address, rate, or other approved details.

Confirmation issuance and dispatch compute the same per-capability target, and a
confirmation is refused unless it names exactly its capability's fields, so it
authorizes one concrete operation, never a family of them.

For a money path whose effect is an external Atlas call, consuming the tokens
cannot share a transaction with the effect the way `mark_working` shares the
lead-transition transaction (`:28983-29032`), and the office booking helper makes
its Atlas call with no local transaction at all (`:26328-26360`). Consuming the
confirmation before an ambiguous Atlas timeout would burn the authorization a
retry needs; calling Atlas before consuming would allow concurrent dispatch.
The money-path dispatch protocol therefore consumes the tokens in a tracker-side
transaction that also durably records the authorized operation as a reservation:
the operation fingerprint, the rendered canonical Atlas request, and the exact
idempotency key, keyed so a retry finds it. The remote relay is then called
against that frozen reservation, and every retry or reconciliation replays the
same recorded request and idempotency key rather than re-rendering from current
state or requiring a fresh confirmation. A crash after the reservation commits
but before the relay leaves a durable reservation a retry resumes (never a
replayable raw confirmation); an ambiguous timeout is reconciled by replaying the
frozen idempotency key, which Atlas resolves idempotently. The already-shipped
`approve_send` path uses the simpler safe variant of this (consume the tokens,
then relay) because its idempotency key is fully Atlas-owned and derived from the
draft id, so a re-confirmed retry cannot double-send; the booking and handoff
paths, which carry a client idempotency key and richer state, use the durable
reservation above.

So the credential contract and the confirmation gate compose: the device key
authenticates the channel and identifies the operator; the approver gate confirms
the operator is allowed to move money at all; and a fresh operator confirmation,
pinned to the full operation fingerprint and consumed into a durable
authorization reservation, authorizes each specific money operation exactly once.
A stolen device key alone cannot move money, because every money capability is
approver-gated and confirmation-required, and a confirmation is single-use,
short-lived, and pinned to one complete operation fingerprint. This is the closed
extension point the provider slice plugs the Atlas money paths into
(`:28573-28575`).

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

The first device money path, `funnel.onboarding_draft.approve_send`, is
implemented in the companion PR #273 (not on this branch) as the worked template:
the device endpoint, its place in the closed capability set, the per-capability
fingerprint generalization, and the approver + confirmation gates. This document
does not depend on that PR to be correct; it references it as the concrete
example the follow-ups mirror.

The provider slice must still add (tracked separately, not in this document):

- Device-authenticated tracker endpoints for the remaining Atlas money paths
  (customer handoff, estimate and first-clean booking), each registering in the
  closed capability set with a fingerprint binding its full operation target
  (per the list above), an explicit configured-approver gate (added even where
  the office route has only an admin-role gate, per the section above), and the
  tracker-side durable authorization reservation for its remote call (consume the
  tokens and freeze the fingerprint, rendered request, and idempotency key in one
  transaction; retries and reconciliation replay that reservation), plus its
  `202`-pending handling where the office path has one. These reuse the office
  relays (`_atlas_funnel_request` `:5306`, booking helper
  `_submit_atlas_funnel_booking` `:26328`, the read allow-list
  `_ATLAS_FUNNEL_READ_PATHS` `:5883` for any new read; new reads must be added to
  that allow-list or they fail closed by design).
- The atomic `supersedes` option on enrollment (bearer-authenticated), which in
  one transaction records the new device and revokes the named predecessor of the
  caller's own operator (see Rotate). This is the whole rotation retire path;
  there is deliberately no device-authenticated revoke, so no device can revoke a
  peer. The existing bearer-authenticated revoke route is unchanged.
- The local Connect provider process itself (loopback registration, capability
  manifest, `job_id` idempotent submission), the adapter that signs tracker
  requests with the device key, and the local-store crash-safe rotation ordering
  (persist the new key with a `pending_enroll` intent, recover the `device_id` by
  listing on restart; see Rotate).

## Security properties

- No Atlas secret on any buyer PC. The shared bearer stays on the tracker
  (`:4962`); the PC holds only a revocable per-device key.
- No stored operator bearer on the PC. The office session is used once at
  enrollment and dropped; steady-state auth is the per-request device proof.
- Containment on the next request, with no secret to rotate (`:28210-28223`).
  Permanent containment is the one-way device revoke (`:28490-28497`); operator
  deactivation is a reversible suspension (see Revoke), so a compromised device is
  contained durably by revoking the device, not only the operator.
- Replay resistance. Each request proof binds method, target, body, and a
  freshness window (`:28134-28153`, `:28287`); money operations add a
  single-use confirmation (`:28983-29032`).
- Least privilege. A device can act only as its one bound operator and only
  through the tracker's gates. Every device money path enforces the configured
  approver (`_require_juan_funnel_approver` `:22926-22935`, on the device path at
  `:28971`), including the booking paths whose office routes gate only on the
  admin role, so a device money operation always requires the one approver
  identity in addition to a fresh per-operation confirmation.

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
