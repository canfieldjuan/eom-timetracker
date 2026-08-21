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
                    radius_source,
                    max_accuracy_policy_m,
                    distance_m,
                    geofence_status,
                    outcome,
                    visit_id,
                    departure_id,
                    response_body
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    39.1203, -88.54335, 8.0, 75, 'global_fallback', 100, 0.0,
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
    home_base_id = db.execute_returning(
        """
        INSERT INTO home_bases (label, address, active)
        VALUES ('Correction evidence archive base', '', false)
        RETURNING id
        """
    )
    home_base_event_id = db.execute_returning(
        """
        INSERT INTO home_base_events (
            shift_id, employee_id, home_base_id, action, outcome, recorded_at
        ) VALUES (%s, %s, %s, 'start', 'recorded', %s)
        RETURNING id
        """,
        (
            candidates["duplicates"][0],
            employee_id,
            home_base_id,
            duplicate_start,
        ),
    )
    visit_evidence_id = db.execute_returning(
        """
        INSERT INTO visit_evidence_events (
            visit_id, shift_id, employee_id, location_id,
            evidence_method, exception_reason, exception_detail,
            geofence_status, distance_m, accuracy_m
        ) VALUES (%s, %s, %s, %s, 'residential_gps', '', '', 'inside', 0, 5)
        RETURNING id
        """,
        (
            qr_events["visitId"],
            candidates["duplicates"][0],
            employee_id,
            location_id,
        ),
    )
    correction_week_start = duplicate_start.date() - timedelta(
        days=(duplicate_start.date().weekday() + 1) % 7,
    )
    correction_id = db.execute_returning(
        """
        INSERT INTO payroll_shift_corrections (
            week_start,
            correction_date,
            employee_id,
            shift_id,
            source_clock_in,
            source_clock_out,
            source_break_minutes,
            source_total_minutes,
            corrected_clock_in,
            corrected_clock_out,
            corrected_break_minutes,
            corrected_total_minutes,
            reason,
            status,
            created_by_employee_id,
            created_by_name
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, NULL, 120,
            %s, %s, 15, 105,
            'Mayra correction attached to duplicate shift.',
            'active',
            %s,
            'Payroll Mayra'
        )
        RETURNING id
        """,
        (
            correction_week_start,
            duplicate_start.date(),
            employee_id,
            candidates["duplicates"][0],
            duplicate_start,
            duplicate_start + timedelta(hours=2),
            duplicate_start,
            duplicate_start + timedelta(hours=2),
            employee_id,
        ),
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
        assert result["migratedPayrollShiftCorrectionIds"] == [correction_id]

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
        archived_payroll_corrections = archived_by_id[
            candidates["duplicates"][0]
        ]["payrollShiftCorrections"]
        assert len(archived_payroll_corrections) == 1
        assert archived_payroll_corrections[0]["correctionId"] == correction_id
        assert (
            archived_payroll_corrections[0]["reason"]
            == "Mayra correction attached to duplicate shift."
        )
        archived_qr_shift = archived_by_id[candidates["duplicates"][0]]
        archived_receipts = {
            row["action"]: row for row in archived_qr_shift["siteQrActionReceipts"]
        }
        assert set(archived_receipts) == {"arrive", "depart"}
        # Geofence C2 (#214): the QR receipt's resolved-policy snapshot must survive
        # archival before the corrected shift (and its cascade rows) are deleted.
        assert archived_receipts["arrive"]["geofenceRadiusM"] == 75
        assert archived_receipts["arrive"]["radiusSource"] == "global_fallback"
        assert archived_receipts["arrive"]["maxAccuracyPolicyM"] == 100
        assert archived_receipts["arrive"]["visitId"] == qr_events["visitId"]
        assert archived_receipts["arrive"]["departureId"] is None
        assert archived_receipts["depart"]["visitId"] == qr_events["visitId"]
        assert archived_receipts["depart"]["departureId"] == qr_events["departureId"]
        assert archived_qr_shift["homeBaseEvents"] == [
            {
                "id": home_base_event_id,
                "shiftId": candidates["duplicates"][0],
                "employeeId": employee_id,
                "homeBaseId": home_base_id,
                "homeBasePolicyId": None,
                "action": "start",
                "outcome": "recorded",
                "exceptionReason": "",
                "recordedAt": duplicate_start.isoformat().replace("+00:00", "Z"),
                "latitude": None,
                "longitude": None,
                "accuracyM": None,
                "geofenceRadiusM": None,
                "radiusSource": None,
                "maxAccuracyPolicyM": None,
                "distanceM": None,
                "geofenceStatus": None,
                "idempotencyKey": None,
                "requestFingerprint": None,
                "createdAt": archived_qr_shift["homeBaseEvents"][0]["createdAt"],
            }
        ]
        assert archived_qr_shift["visitEvidenceEvents"] == [
            {
                "id": visit_evidence_id,
                "visitId": qr_events["visitId"],
                "shiftId": candidates["duplicates"][0],
                "employeeId": employee_id,
                "locationId": location_id,
                "plannedVisitId": None,
                "evidenceMethod": "residential_gps",
                "exceptionReason": "",
                "exceptionDetail": "",
                # Empty here by construction: this arrival is INSIDE the
                # geofence, so it was never accepted on a GPS override. The
                # archive still carries the pair, because for an outside or
                # uncertain arrival it holds the entire acceptance rationale
                # and the evidence row cascade-deletes with the shift.
                "gpsOverrideReason": "",
                "gpsOverrideDetail": "",
                "geofenceStatus": "inside",
                "distanceM": 0.0,
                "accuracyM": 5.0,
                # Geofence C2 (#214): resolved-policy snapshot preserved in the archive.
                # This fixture inserts the evidence row directly with only the pre-C2
                # columns, so the new snapshot fields are NULL -- the archive faithfully
                # carries them through (a real arrival would populate them).
                "geofenceRadiusM": None,
                "radiusSource": None,
                "maxAccuracyPolicyM": None,
                "createdAt": archived_qr_shift["visitEvidenceEvents"][0]["createdAt"],
            }
        ]
        assert db.query_one(
            "SELECT shift_id FROM home_base_events WHERE id = %s",
            (home_base_event_id,),
        ) == {"shift_id": candidates["canonical"]}
        assert db.query_one(
            "SELECT id FROM visit_evidence_events WHERE id = %s",
            (visit_evidence_id,),
        ) is None

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
        assert batch["result"]["migratedPayrollShiftCorrectionIds"] == [correction_id]
        migrated_correction = db.query_one(
            """
            SELECT shift_id, status, reason
            FROM payroll_shift_corrections
            WHERE id = %s
            """,
            (correction_id,),
        )
        assert migrated_correction["shift_id"] == candidates["canonical"]
        assert migrated_correction["status"] == "active"
        assert (
            migrated_correction["reason"]
            == "Mayra correction attached to duplicate shift."
        )

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
        db.execute("DELETE FROM home_bases WHERE id = %s", (home_base_id,))
