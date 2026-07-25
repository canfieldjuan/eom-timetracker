"""Guardrails for previewing and applying time-data corrections."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import db


def _insert_shift(employee_id, location_id, clock_in, clock_out=None, notes=""):
    total_hours = None
    if clock_out is not None:
        total_hours = round((clock_out - clock_in).total_seconds() / 3600.0, 2)
    return db.execute_returning(
        """
        INSERT INTO shifts (
            employee_id,
            location_id,
            location_label,
            clock_in,
            clock_out,
            total_hours,
            notes,
            local_date,
            timezone
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'America/Chicago')
        RETURNING id
        """,
        (
            employee_id,
            location_id,
            "123 Main St, Effingham",
            clock_in,
            clock_out,
            total_hours,
            notes,
            clock_in.date(),
        ),
    )


def _seed_correction_candidates(employee_id, location_id):
    duplicate_start = datetime(2023, 2, 3, 15, 0, tzinfo=timezone.utc)
    duplicate_end = duplicate_start + timedelta(hours=2)
    stale_start = datetime.now(timezone.utc) - timedelta(days=10)

    canonical = _insert_shift(
        employee_id,
        location_id,
        duplicate_start,
        duplicate_end,
        notes="canonical details",
    )
    duplicate_with_departure = _insert_shift(
        employee_id,
        location_id,
        duplicate_start,
        duplicate_end,
    )
    duplicate_plain = _insert_shift(
        employee_id,
        location_id,
        duplicate_start,
        duplicate_end,
    )
    stale = _insert_shift(employee_id, location_id, stale_start)

    db.execute(
        """
        INSERT INTO visits (
            shift_id, location_id, location_label, customer_name, arrival_time
        )
        VALUES (%s, %s, %s, 'Test Customer', %s)
        """,
        (canonical, location_id, "123 Main St, Effingham", duplicate_start),
    )
    db.execute(
        """
        INSERT INTO departures (
            shift_id, location_id, location_label, customer_name, departure_time
        )
        VALUES (%s, %s, %s, 'Test Customer', %s)
        """,
        (
            duplicate_with_departure,
            location_id,
            "123 Main St, Effingham",
            duplicate_end,
        ),
    )
    return {
        "canonical": canonical,
        "duplicates": [duplicate_with_departure, duplicate_plain],
        "allDuplicateIds": [canonical, duplicate_with_departure, duplicate_plain],
        "stale": stale,
        "staleStart": stale_start,
    }


def _attach_qr_arrive_depart_receipts(
    employee_id,
    location_id,
    shift_id,
    arrival_time,
    departure_time,
):
    visit_id = db.execute_returning(
        """
        INSERT INTO visits (
            shift_id,
            location_id,
            location_label,
            customer_name,
            arrival_time,
            sequence_version
        )
        VALUES (%s, %s, %s, 'Test Customer', %s, 2)
        RETURNING id
        """,
        (shift_id, location_id, "123 Main St, Effingham", arrival_time),
    )
    departure_id = db.query_one(
        "SELECT id FROM departures WHERE shift_id = %s",
        (shift_id,),
    )["id"]
    db.execute(
        "UPDATE departures SET visit_id = %s WHERE id = %s",
        (visit_id, departure_id),
    )

    receipt_ids = []
    for sequence, (action, recorded_at, linked_departure_id) in enumerate(
        (
            ("arrive", arrival_time, None),
            ("depart", departure_time, departure_id),
        ),
        start=1,
    ):
        receipt_ids.append(
            db.execute_returning(
                """
                INSERT INTO site_qr_action_receipts (
                    employee_id,
                    location_id,
                    shift_id,
                    action,
                    idempotency_key,
                    request_fingerprint,
                    server_recorded_at,
                    device_scanned_at,
                    latitude,
                    longitude,
                    accuracy_m,
                    geofence_radius_m,
                    distance_m,
                    geofence_status,
                    outcome,
                    visit_id,
                    departure_id,
                    response_body
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    39.1203, -88.54335, 8.0, 75, 0.0,
                    'inside', 'recorded', %s, %s, %s::jsonb
                )
                RETURNING id
                """,
                (
                    employee_id,
                    location_id,
                    shift_id,
                    action,
                    str(uuid4()),
                    str(sequence) * 64,
                    recorded_at,
                    recorded_at,
                    visit_id,
                    linked_departure_id,
                    f'{{"action":"{action}","outcome":"recorded"}}',
                ),
            )
        )
    return {
        "visitId": visit_id,
        "departureId": departure_id,
        "receiptIds": receipt_ids,
    }


def _cleanup_candidates(candidate_ids, reason):
    db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (candidate_ids,))
    db.execute("DELETE FROM time_data_correction_batches WHERE reason = %s", (reason,))


def _selection(candidates, reason):
    clock_out = candidates["staleStart"] + timedelta(hours=2)
    return {
        "reason": reason,
        "duplicateResolutions": [
            {
                "canonicalShiftId": candidates["canonical"],
                "duplicateShiftIds": candidates["duplicates"],
            }
        ],
        "staleShiftClosures": [
            {
                "shiftId": candidates["stale"],
                "clockOut": clock_out.isoformat().replace("+00:00", "Z"),
            }
        ],
    }


def test_correction_inventory_and_plan_are_admin_only_and_read_only(
    client,
    auth,
    emp_auth,
    employee_id,
    location_id,
):
    reason = "test preview without production mutation"
    candidates = _seed_correction_candidates(employee_id, location_id)
    candidate_ids = [*candidates["allDuplicateIds"], candidates["stale"]]
    try:
        endpoint = "/api/admin/corrections/time-data"
        assert client.get(endpoint).status_code == 401
        assert client.get(endpoint, headers=emp_auth).status_code == 403

        before_shifts = db.query_one("SELECT COUNT(*) AS count FROM shifts")["count"]
        before_batches = db.query_one(
            "SELECT COUNT(*) AS count FROM time_data_correction_batches"
        )["count"]

        inventory_response = client.get(endpoint, headers=auth)
        assert inventory_response.status_code == 200, inventory_response.text
        inventory = inventory_response.json()
        assert inventory["databaseReadOnly"] is True
        group = next(
            row
            for row in inventory["duplicateGroups"]
            if set(row["shiftIds"]) == set(candidates["allDuplicateIds"])
        )
        assert group["recommendedCanonicalShiftId"] == candidates["canonical"]
        assert group["metadataConsistent"] is False
        assert any(row["visits"] for row in group["shifts"])
        assert any(row["departures"] for row in group["shifts"])

        selection = _selection(candidates, reason)
        assert client.post(
            f"{endpoint}/preview",
            headers=emp_auth,
            json=selection,
        ).status_code == 403
        preview_response = client.post(
            f"{endpoint}/preview",
            headers=auth,
            json=selection,
        )
        assert preview_response.status_code == 200, preview_response.text
        preview = preview_response.json()
        assert preview["databaseReadOnly"] is True
        assert preview["summary"] == {
            "duplicateShiftsToDelete": 2,
            "staleShiftsToClose": 1,
        }
        assert preview["confirmationPhrase"] == "DELETE 2 DUPLICATE SHIFTS AND CLOSE 1 STALE SHIFT"
        assert len(preview["planToken"]) == 64

        assert db.query_one("SELECT COUNT(*) AS count FROM shifts")["count"] == before_shifts
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM time_data_correction_batches"
        )["count"] == before_batches
        assert db.query_one(
            "SELECT clock_out FROM shifts WHERE id = %s",
            (candidates["stale"],),
        )["clock_out"] is None
    finally:
        _cleanup_candidates(candidate_ids, reason)


def test_apply_is_confirmed_atomic_archived_and_stale_plan_safe(
    client,
    auth,
    employee_id,
    location_id,
):
    reason = "test confirmed recoverable correction batch"
    candidates = _seed_correction_candidates(employee_id, location_id)
    candidate_ids = [*candidates["allDuplicateIds"], candidates["stale"]]
    duplicate_start = datetime(2023, 2, 3, 15, 0, tzinfo=timezone.utc)
    qr_events = _attach_qr_arrive_depart_receipts(
        employee_id,
        location_id,
        candidates["duplicates"][0],
        duplicate_start,
        duplicate_start + timedelta(hours=2),
    )
    selection = _selection(candidates, reason)
    try:
        preview = client.post(
            "/api/admin/corrections/time-data/preview",
            headers=auth,
            json=selection,
        ).json()
        apply_payload = {
            **selection,
            "planToken": preview["planToken"],
            "confirmation": "wrong phrase",
        }
        wrong_confirmation = client.post(
            "/api/admin/corrections/time-data/apply",
            headers=auth,
            json=apply_payload,
        )
        assert wrong_confirmation.status_code == 400
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM shifts WHERE id = ANY(%s)",
            (candidate_ids,),
        )["count"] == 4

        db.execute(
            "UPDATE shifts SET notes = %s WHERE id = %s",
            ("changed after preview", candidates["canonical"]),
        )
        stale_plan = client.post(
            "/api/admin/corrections/time-data/apply",
            headers=auth,
            json={
                **apply_payload,
                "confirmation": preview["confirmationPhrase"],
            },
        )
        assert stale_plan.status_code == 409
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM shifts WHERE id = ANY(%s)",
            (candidate_ids,),
        )["count"] == 4

        refreshed_preview_response = client.post(
            "/api/admin/corrections/time-data/preview",
            headers=auth,
            json=selection,
        )
        assert refreshed_preview_response.status_code == 200, refreshed_preview_response.text
        refreshed_preview = refreshed_preview_response.json()
        confirmed = client.post(
            "/api/admin/corrections/time-data/apply",
            headers=auth,
            json={
                **selection,
                "planToken": refreshed_preview["planToken"],
                "confirmation": refreshed_preview["confirmationPhrase"],
            },
        )
        assert confirmed.status_code == 200, confirmed.text
        result = confirmed.json()
        assert result["archiveStored"] is True
        assert result["deletedShiftIds"] == sorted(candidates["duplicates"])
        assert result["closedShiftIds"] == [candidates["stale"]]

        remaining = db.query_all(
            "SELECT id, clock_out FROM shifts WHERE id = ANY(%s) ORDER BY id",
            (candidate_ids,),
        )
        assert [row["id"] for row in remaining] == sorted(
            [candidates["canonical"], candidates["stale"]]
        )
        assert next(
            row["clock_out"] for row in remaining if row["id"] == candidates["stale"]
        ) is not None
        assert db.query_one(
            "SELECT id FROM departures WHERE shift_id = %s",
            (candidates["duplicates"][0],),
        ) is None

        batch = db.query_one(
            "SELECT snapshot, result FROM time_data_correction_batches WHERE id = %s",
            (result["batchId"],),
        )
        archived_by_id = {
            row["id"]: row for row in batch["snapshot"]["shiftsBefore"]
        }
        assert set(archived_by_id) == set(candidate_ids)
        assert archived_by_id[candidates["duplicates"][0]]["departures"]
        archived_qr_shift = archived_by_id[candidates["duplicates"][0]]
        archived_receipts = {
            row["action"]: row for row in archived_qr_shift["siteQrActionReceipts"]
        }
        assert set(archived_receipts) == {"arrive", "depart"}
        assert archived_receipts["arrive"]["visitId"] == qr_events["visitId"]
        assert archived_receipts["arrive"]["departureId"] is None
        assert archived_receipts["depart"]["visitId"] == qr_events["visitId"]
        assert archived_receipts["depart"]["departureId"] == qr_events["departureId"]

        preserved_receipts = db.query_all(
            """
            SELECT id, action, shift_id, visit_id, departure_id
            FROM site_qr_action_receipts
            WHERE id = ANY(%s)
            ORDER BY action
            """,
            (qr_events["receiptIds"],),
        )
        assert len(preserved_receipts) == 2
        assert {row["action"] for row in preserved_receipts} == {"arrive", "depart"}
        assert all(row["shift_id"] is None for row in preserved_receipts)
        assert all(row["visit_id"] is None for row in preserved_receipts)
        assert all(row["departure_id"] is None for row in preserved_receipts)
        assert batch["result"]["deletedShiftIds"] == sorted(candidates["duplicates"])

        repeat = client.post(
            "/api/admin/corrections/time-data/apply",
            headers=auth,
            json={
                **selection,
                "planToken": refreshed_preview["planToken"],
                "confirmation": refreshed_preview["confirmationPhrase"],
            },
        )
        assert repeat.status_code == 409
    finally:
        _cleanup_candidates(candidate_ids, reason)
        db.execute(
            "DELETE FROM site_qr_action_receipts WHERE id = ANY(%s)",
            (qr_events["receiptIds"],),
        )
