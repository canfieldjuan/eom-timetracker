"""Regression coverage for issue #19 location persistence failures."""

from __future__ import annotations

from datetime import datetime, timezone

import db


def _delete_test_location(location_id: int, shift_id: int | None = None) -> None:
    if shift_id is not None:
        db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
    db.execute("DELETE FROM locations WHERE id = %s", (location_id,))


def _website_record(location: dict) -> dict:
    return {
        "name": location["address"],
        "customer": location["customerName"],
        "type": location["locationType"] or "Residential",
        "rate": location["rate"],
        "rateType": location["rateType"],
        "frequency": location["frequency"],
        "lat": location["latitude"],
        "lng": location["longitude"],
    }


def test_atomic_update_preserves_advanced_fields_and_archive_keeps_history(
    client,
    auth,
    emp_auth,
    employee_id,
):
    created = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1901 Issue History Rd, Effingham, IL",
            "customerName": "Issue History Customer",
            "locationType": "Residential",
            "rate": 160.0,
            "rateType": "per_visit",
            "frequency": "Biweekly",
            "lat": 39.12,
            "lng": -88.54,
            "expectedHours": 3.5,
            "targetLaborPct": 30.0,
            "minMarginPct": 25.0,
        },
    )
    assert created.status_code == 200, created.text
    location_id = created.json()["location"]["id"]
    shift_id = None

    try:
        shift = db.query_one(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label, clock_in,
                clock_out, total_hours, local_date
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                employee_id,
                location_id,
                "1901 Issue History Rd, Effingham, IL",
                datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
                datetime(2026, 7, 15, 14, tzinfo=timezone.utc),
                2.0,
                "2026-07-15",
            ),
        )
        shift_id = int(shift["id"])

        updated = client.patch(
            f"/api/admin/locations/{location_id}",
            headers=auth,
            json={
                "customerName": "Issue History Customer Updated",
                "locationType": "Commercial",
                "frequency": "Weekly",
                "rate": 175.0,
            },
        )
        assert updated.status_code == 200, updated.text
        location = updated.json()["location"]
        assert location["customerName"] == "Issue History Customer Updated"
        assert location["expectedHours"] == 3.5
        assert location["targetLaborPct"] == 30.0
        assert location["minMarginPct"] == 25.0
        assert location["latitude"] == 39.12
        assert location["longitude"] == -88.54

        archived = client.delete(
            f"/api/admin/locations/{location_id}",
            headers=auth,
        )
        assert archived.status_code == 200, archived.text
        assert archived.json()["historicalReferencesPreserved"] is True

        active = client.get("/api/admin/locations", headers=auth)
        assert all(row["id"] != location_id for row in active.json()["locations"])

        employee_locations = client.get("/api/timesheet/locations", headers=emp_auth)
        assert employee_locations.status_code == 200, employee_locations.text
        assert "1901 Issue History Rd, Effingham, IL" not in employee_locations.json()["locations"]

        all_rows = client.get(
            "/api/admin/locations?includeArchived=true",
            headers=auth,
        )
        archived_row = next(
            row for row in all_rows.json()["locations"] if row["id"] == location_id
        )
        assert archived_row["active"] is False

        historical = db.query_one(
            """
            SELECT s.location_id, l.address
            FROM shifts s
            JOIN locations l ON l.id = s.location_id
            WHERE s.id = %s
            """,
            (shift_id,),
        )
        assert historical == {
            "location_id": location_id,
            "address": "1901 Issue History Rd, Effingham, IL",
        }
    finally:
        _delete_test_location(location_id, shift_id)


def test_legacy_website_list_archives_omitted_row_without_clearing_advanced_fields(
    client,
    auth,
    employee_id,
):
    keep = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1902 Issue Keep Rd, Effingham, IL",
            "customerName": "Issue Keep Customer",
            "locationType": "Residential",
            "rate": 140.0,
            "rateType": "per_visit",
            "expectedHours": 4.25,
            "targetLaborPct": 31.0,
            "minMarginPct": 24.0,
        },
    ).json()["location"]
    archived = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1903 Issue Archive Rd, Effingham, IL",
            "customerName": "Issue Archive Customer",
            "locationType": "Residential",
            "rateType": "per_visit",
        },
    ).json()["location"]
    shift = db.query_one(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in,
            clock_out, total_hours, local_date
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            employee_id,
            archived["id"],
            archived["address"],
            datetime(2026, 7, 16, 12, tzinfo=timezone.utc),
            datetime(2026, 7, 16, 13, tzinfo=timezone.utc),
            1.0,
            "2026-07-16",
        ),
    )
    shift_id = int(shift["id"])

    try:
        current = client.get("/api/admin/locations", headers=auth).json()["locations"]
        payload = []
        for location in current:
            if location["id"] == archived["id"]:
                continue
            item = _website_record(location)
            if location["id"] == keep["id"]:
                item["rate"] = 155.0
            payload.append(item)

        result = client.put(
            "/api/admin/locations",
            headers=auth,
            json={"locations": payload},
        )
        assert result.status_code == 200, result.text
        assert result.json()["archivedCount"] == 1

        kept_row = db.query_one(
            """
            SELECT rate, expected_hours, target_labor_pct, min_margin_pct
            FROM locations WHERE id = %s
            """,
            (keep["id"],),
        )
        assert float(kept_row["rate"]) == 155.0
        assert float(kept_row["expected_hours"]) == 4.25
        assert float(kept_row["target_labor_pct"]) == 31.0
        assert float(kept_row["min_margin_pct"]) == 24.0

        archived_row = db.query_one(
            "SELECT active FROM locations WHERE id = %s",
            (archived["id"],),
        )
        assert archived_row["active"] is False
        historical = db.query_one(
            "SELECT location_id FROM shifts WHERE id = %s",
            (shift_id,),
        )
        assert historical["location_id"] == archived["id"]
    finally:
        _delete_test_location(archived["id"], shift_id)
        _delete_test_location(keep["id"])


def test_normalized_duplicate_address_is_rejected(client, auth):
    created = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1904 Duplicate Ave, Effingham, IL",
            "customerName": "Original Duplicate Customer",
        },
    )
    assert created.status_code == 200, created.text
    location_id = created.json()["location"]["id"]
    try:
        duplicate = client.post(
            "/api/admin/locations",
            headers=auth,
            json={
                "address": "  1904 duplicate ave ,  Effingham, IL  ",
                "customerName": "Second Duplicate Customer",
            },
        )
        assert duplicate.status_code == 409, duplicate.text
        assert "already exists" in duplicate.json()["error"]
    finally:
        _delete_test_location(location_id)


def test_customer_name_and_address_are_required(client, auth):
    missing_customer = client.post(
        "/api/admin/locations",
        headers=auth,
        json={"address": "1905 Validation Rd", "customerName": "   "},
    )
    assert missing_customer.status_code == 422
    assert "customerName is required" in missing_customer.json()["error"]

    missing_address = client.post(
        "/api/admin/locations",
        headers=auth,
        json={"address": "   ", "customerName": "Validation Customer"},
    )
    assert missing_address.status_code == 422
    assert "address is required" in missing_address.json()["error"]


def test_legacy_pin_route_is_not_shadowed_by_id_update(client, auth):
    original = db.query_one(
        "SELECT lat, lng FROM locations WHERE address = %s",
        ("123 Main St, Effingham",),
    )
    try:
        response = client.patch(
            "/api/admin/locations/pin",
            headers=auth,
            json={
                "location": "123 Main St, Effingham",
                "lat": 39.1204,
                "lng": -88.5434,
            },
        )
        assert response.status_code == 200, response.text
    finally:
        db.execute(
            "UPDATE locations SET lat = %s, lng = %s WHERE address = %s",
            (original["lat"], original["lng"], "123 Main St, Effingham"),
        )
