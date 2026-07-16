# Time Data Correction Contract

Time-data corrections use three admin-only steps:

1. `GET /api/admin/corrections/time-data` loads complete duplicate and stale-shift metadata without changing shifts.
2. `POST /api/admin/corrections/time-data/preview` validates the selections and returns an HMAC-bound plan token plus an exact confirmation phrase. This step is also read-only.
3. `POST /api/admin/corrections/time-data/apply` requires the unchanged plan token and exact phrase, locks the selected rows, revalidates the plan, archives all before-images, then applies the batch in one database transaction.

Duplicate groups require an explicit canonical shift. All other copies in that exact group are deleted only after the complete shift, visit, and departure records are stored in `time_data_correction_batches.snapshot`.

Stale shifts require a verified clock-out time. The server rejects clock-outs before the original clock-in or in the future and recalculates total hours in the same transaction.

Any selected-row change after preview invalidates the plan with HTTP 409. A failed validation, stale plan, archive failure, update failure, or delete failure rolls back the whole batch.
