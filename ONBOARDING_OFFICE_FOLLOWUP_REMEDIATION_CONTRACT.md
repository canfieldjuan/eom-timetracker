# Onboarding Office Follow-up Remediation Contract

## Root cause

The Tracker treats the Atlas-issued-link read as a single bounded snapshot and
copies three Atlas capability names into local decision gates. It also checks
Atlas availability before asking whether a recovery is already complete
locally. Those choices make an active-link queue incomplete after one page,
make the feature drift-prone across deployments, and reject a no-op finalized
replay that does not need Atlas.

## Correct fix must touch and change

1. Relay Atlas's opaque cursor, `hasMore`, and `nextCursor` through the
   authenticated issued-link endpoint, validating the closed page before
   returning it to the Website.
2. Consume the Atlas-projected registered method/path signatures for the three
   public-onboarding controls and derive their local availability booleans from
   those exact signatures. A missing or malformed signature set is unavailable.
3. Preserve the existing Juan authorization first, then return a finalized
   local recovery replay before requiring Atlas configuration or capabilities.
   Pending recovery mutations retain their existing Atlas guard and contract.
4. Add focused tests for cursor relay, exact signature proof, and a finalized
   replay while Atlas is unavailable.

## Must not change

- No Atlas token grammar, secret/config writes, migrations, public handoff,
  revocation semantics, customer conversion, QR/GPS, Home Base, payroll, or
  portal authentication changes.
- Do not loosen the existing generic Atlas capability parser or add an open
  proxy. Existing unrelated capability names and gates remain intact.
- Do not turn a pending recovery mutation into a local-only action.

## Acceptance evidence

- A second issued-link page is reachable only with the returned opaque cursor.
- Only an Atlas route signature matching the deployed method and path enables
  the corresponding Tracker boolean.
- A finalized local recovery returns its existing idempotent response without
  an Atlas read; a pending recovery still requires one.
