# Agent instructions — eom-timetracker

This file is read automatically by coding agents (Claude Code, Codex, etc.). It
applies to every session that touches this repository.

## Before you audit, review, or claim a fix

**Read and follow [`AUDIT_PROTOCOL.md`](./AUDIT_PROTOCOL.md). It is mandatory, not
advisory.** In short: the code is ground truth; cite `file:line` for every claim;
sort claims into confirmed / contradicted / could-not-determine; never mark
confirmed without a citation; lead with what's wrong; trace the default path
before describing behavior; never cite a tool result you didn't produce this
session against the exact target. A CI gate enforces the form of this on findings
docs and PRs labeled `audit`/`review`.

## This system is live in production

- Backend: FastAPI + PostgreSQL, deployed on Render, auto-deploys on merge to
  `main`. Runtime storage is Postgres, not JSON files.
- Changes must be additive and backward-compatible. No destructive migrations.
  Do not write to or clear the persistent data disk (`/opt/render/project/data`).
  Do not change response shapes the running portals depend on.

## Working here

- `backend/` is the deploy root (see `render.yaml`). The API is
  `backend/time_tracker_api.py`; `/` and `/timetracker-mobile.html` are
  compatibility redirects to the canonical EOM website portal.
- Tests: `cd backend && pytest`. They require PostgreSQL on `:5433` (see
  `backend/conftest.py`); CI provides a service container.
- Branch off `main` (`agent/<topic>`); open a PR; let CI run; merge on green +
  reviewed. Never commit directly to `main`.
- Verify with tool output, not narration. If you have not run the test/command
  that proves a change works, say so plainly.
