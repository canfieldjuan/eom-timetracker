"""Regression coverage for issue #19 location persistence failures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import db


def _delete_test_location(location_id: int, shift_id: int | None = None) -> None:
    if shift_id is not None:
        db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
    db.execute(
        "DELETE FROM site_check_in_schedule_rules WHERE location_id = %s",
        (location_id,),
    )
    db.execute(
        "DELETE FROM site_check_in_schedules WHERE location_id = %s",
        (location_id,),
    )
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
    old_address = "1901 Issue History Rd, Effingham, IL"
    new_address = "1901 Issue History Blvd, Effingham, IL"

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
                old_address,
                datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
                datetime(2026, 7, 15, 14, tzinfo=timezone.utc),
                2.0,
                "2026-07-15",
            ),
        )
        shift_id = int(shift["id"])
        now = datetime.now(timezone.utc)
        db.execute(
            """
            INSERT INTO site_check_in_schedules (
                employee_id, location_id, scheduled_start, grace_minutes
            )
            VALUES (%s, %s, %s, 10), (%s, %s, %s, 10)
            """,
            (
                employee_id,
                location_id,
                now - timedelta(days=1),
                employee_id,
                location_id,
                now + timedelta(days=1),
            ),
        )
        db.execute(
            """
            INSERT INTO site_check_in_schedule_rules (
                employee_id, location_id, weekdays, local_start_time,
                timezone, starts_on, grace_minutes
            )
            VALUES (%s, %s, %s, %s, %s, %s, 10)
            """,
            (
                employee_id,
                location_id,
                [0, 1, 2, 3, 4],
                "07:00",
                "America/Chicago",
                now.date() - timedelta(days=7),
            ),
        )

        updated = client.patch(
            f"/api/admin/locations/{location_id}",
            headers=auth,
            json={
                "address": new_address,
                "customerName": "Issue History Customer Updated",
                "locationType": "Commercial",
                "frequency": "Weekly",
                "rate": 175.0,
            },
        )
        assert updated.status_code == 200, updated.text
        location = updated.json()["location"]
        assert location["address"] == new_address
        assert location["customerName"] == "Issue History Customer Updated"
        assert location["expectedHours"] == 3.5
        assert location["targetLaborPct"] == 30.0
        assert location["minMarginPct"] == 25.0
        assert location["latitude"] == 39.12
        assert location["longitude"] == -88.54

        from time_tracker_api import load_timesheets

        historical_entry = next(
            entry
            for entry in load_timesheets()["entries"]
            if entry["id"] == shift_id
        )
        assert historical_entry["location"] == old_address

        archived = client.delete(
            f"/api/admin/locations/{location_id}",
            headers=auth,
        )
        assert archived.status_code == 200, archived.text
        assert archived.json()["historicalReferencesPreserved"] is True
        assert archived.json()["scheduleCleanup"] == {
            "futureSchedulesDeleted": 1,
            "scheduleRulesDeactivated": 1,
        }

        active = client.get("/api/admin/locations", headers=auth)
        assert all(row["id"] != location_id for row in active.json()["locations"])

        employee_locations = client.get("/api/timesheet/locations", headers=emp_auth)
        assert employee_locations.status_code == 200, employee_locations.text
        assert new_address not in employee_locations.json()["locations"]

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
            SELECT s.location_id, s.location_label, l.address
            FROM shifts s
            JOIN locations l ON l.id = s.location_id
            WHERE s.id = %s
            """,
            (shift_id,),
        )
        assert historical == {
            "location_id": location_id,
            "location_label": old_address,
            "address": new_address,
        }
        schedule_rows = db.query_all(
            """
            SELECT scheduled_start
            FROM site_check_in_schedules
            WHERE location_id = %s
            ORDER BY scheduled_start
            """,
            (location_id,),
        )
        assert len(schedule_rows) == 1
        assert schedule_rows[0]["scheduled_start"] < datetime.now(timezone.utc)
        rule = db.query_one(
            "SELECT active FROM site_check_in_schedule_rules WHERE location_id = %s",
            (location_id,),
        )
        assert rule["active"] is False

        # A repeated archive also repairs schedules left behind by older code.
        db.execute(
            """
            INSERT INTO site_check_in_schedules (
                employee_id, location_id, scheduled_start, grace_minutes
            )
            VALUES (%s, %s, %s, 10)
            """,
            (employee_id, location_id, datetime.now(timezone.utc) + timedelta(days=3)),
        )
        db.execute(
            """
            UPDATE site_check_in_schedule_rules
            SET active = true
            WHERE location_id = %s
            """,
            (location_id,),
        )
        repeated_archive = client.delete(
            f"/api/admin/locations/{location_id}",
            headers=auth,
        )
        assert repeated_archive.status_code == 200, repeated_archive.text
        assert repeated_archive.json()["alreadyArchived"] is True
        assert repeated_archive.json()["scheduleCleanup"] == {
            "futureSchedulesDeleted": 1,
            "scheduleRulesDeactivated": 1,
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
    now = datetime.now(timezone.utc)
    db.execute(
        """
        INSERT INTO site_check_in_schedules (
            employee_id, location_id, scheduled_start, grace_minutes
        )
        VALUES (%s, %s, %s, 10)
        """,
        (employee_id, archived["id"], now + timedelta(days=2)),
    )
    db.execute(
        """
        INSERT INTO site_check_in_schedule_rules (
            employee_id, location_id, weekdays, local_start_time,
            timezone, starts_on, grace_minutes
        )
        VALUES (%s, %s, %s, %s, %s, %s, 10)
        """,
        (
            employee_id,
            archived["id"],
            [0, 1, 2, 3, 4],
            "18:00",
            "America/Chicago",
            now.date() - timedelta(days=7),
        ),
    )

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
        assert result.json()["scheduleCleanup"] == {
            "futureSchedulesDeleted": 1,
            "scheduleRulesDeactivated": 1,
        }

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
        assert db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM site_check_in_schedules
            WHERE location_id = %s
            """,
            (archived["id"],),
        )["count"] == 0
        assert db.query_one(
            "SELECT active FROM site_check_in_schedule_rules WHERE location_id = %s",
            (archived["id"],),
        )["active"] is False
    finally:
        _delete_test_location(archived["id"], shift_id)
        _delete_test_location(keep["id"])


def test_legacy_string_list_is_accepted_without_clearing_saved_fields(client, auth):
    preserved = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1908 Legacy String Rd, Effingham, IL",
            "customerName": "Legacy String Customer",
            "locationType": "Commercial",
            "rate": 42.0,
            "rateType": "hourly",
            "frequency": "Weekdays",
            "expectedHours": 5.0,
            "targetLaborPct": 32.0,
            "minMarginPct": 23.0,
        },
    ).json()["location"]
    fallback_address = "1909 Legacy New Rd, Effingham, IL"
    fallback_id = None

    try:
        current = client.get("/api/admin/locations", headers=auth).json()["locations"]
        result = client.put(
            "/api/admin/locations",
            headers=auth,
            json={
                "locations": [row["address"] for row in current]
                + ["   ", fallback_address]
            },
        )
        assert result.status_code == 200, result.text

        saved = db.query_one(
            """
            SELECT customer_name, location_type, rate, rate_type, frequency,
                   expected_hours, target_labor_pct, min_margin_pct, active
            FROM locations
            WHERE id = %s
            """,
            (preserved["id"],),
        )
        assert saved["customer_name"] == "Legacy String Customer"
        assert saved["location_type"] == "Commercial"
        assert float(saved["rate"]) == 42.0
        assert saved["rate_type"] == "hourly"
        assert saved["frequency"] == "Weekdays"
        assert float(saved["expected_hours"]) == 5.0
        assert float(saved["target_labor_pct"]) == 32.0
        assert float(saved["min_margin_pct"]) == 23.0
        assert saved["active"] is True

        fallback = db.query_one(
            """
            SELECT id, customer_name, rate_type, active
            FROM locations
            WHERE address = %s
            """,
            (fallback_address,),
        )
        fallback_id = int(fallback["id"])
        assert fallback["customer_name"] == fallback_address
        assert fallback["rate_type"] == "per_visit"
        assert fallback["active"] is True
    finally:
        if fallback_id is not None:
            _delete_test_location(fallback_id)
        _delete_test_location(preserved["id"])


def test_null_rate_type_is_rejected_without_changing_saved_value(client, auth):
    created = client.post(
        "/api/admin/locations",
        headers=auth,
        json={
            "address": "1910 Null Rate Type Rd, Effingham, IL",
            "customerName": "Null Rate Type Customer",
            "rateType": "monthly",
        },
    )
    assert created.status_code == 200, created.text
    location_id = created.json()["location"]["id"]
    try:
        response = client.patch(
            f"/api/admin/locations/{location_id}",
            headers=auth,
            json={"rateType": None},
        )
        assert response.status_code == 422, response.text
        assert "rateType cannot be null" in response.json()["error"]
        saved = db.query_one(
            "SELECT rate_type FROM locations WHERE id = %s",
            (location_id,),
        )
        assert saved["rate_type"] == "monthly"
    finally:
        _delete_test_location(location_id)


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
