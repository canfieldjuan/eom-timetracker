# Time Data Correction Contract

Time-data corrections use three admin-only steps:

1. `GET /api/admin/corrections/time-data` loads complete duplicate and stale-shift metadata without changing shifts.
2. `POST /api/admin/corrections/time-data/preview` validates the selections and returns an HMAC-bound plan token plus an exact confirmation phrase. This step is also read-only.
3. `POST /api/admin/corrections/time-data/apply` requires the unchanged plan token and exact phrase, locks the selected rows, revalidates the plan, archives all before-images, then applies the batch in one database transaction.

Duplicate groups require an explicit canonical shift. All other copies in that exact group are deleted only after the complete shift, visit, and departure records are stored in `time_data_correction_batches.snapshot`.

Stale shifts require a verified clock-out time. The server rejects clock-outs before the original clock-in or in the future and recalculates total hours in the same transaction.

Any selected-row change after preview invalidates the plan with HTTP 409. A failed validation, stale plan, archive failure, update failure, or delete failure rolls back the whole batch.

## Stale-shift prevention contract

An open shift older than `MAX_ACTIVE_SHIFT_HOURS` is unresolved payroll data, not a completed shift:

- No employee or admin action silently invents a clock-out time for it.
- It contributes zero calculated hours until an administrator supplies a verified clock-out through the correction workflow.
- The employee status response identifies the unresolved shift, and the web app disables new time-entry actions with a **Needs review** message.
- Clock-in, clock-out, arrival, and departure endpoints reject the unresolved state with HTTP 409 and `STALE_SHIFT_REQUIRES_REVIEW`.
- Applying a verified correction removes the block and restores normal time-entry actions.
