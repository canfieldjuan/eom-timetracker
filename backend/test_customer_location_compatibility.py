"""Compatibility contracts for legacy Site writes, jobs, and schedules."""

from __future__ import annotations

from datetime import timedelta

import pytest
from psycopg2.errors import UniqueViolation

from conftest import _raw_conn


TEST_PREFIX = "Issue 19 Compatibility"


def _clean_test_rows() -> None:
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM shifts
                WHERE location_id IN (
                    SELECT id FROM locations WHERE address LIKE %s
                )
                """,
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM jobs WHERE customer_name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM schedules WHERE customer_name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM locations WHERE address LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM eom_customer_atlas_reservations WHERE customer_id IN "
                "(SELECT id FROM customers WHERE name LIKE %s)",
                (f"{TEST_PREFIX}%",),
            )
            cur.execute(
                "DELETE FROM customers WHERE name LIKE %s",
                (f"{TEST_PREFIX}%",),
            )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def isolate_compatibility_rows(setup_db):
    _clean_test_rows()
    yield
    _clean_test_rows()


def _create_customer(client, auth, suffix: str):
    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": f"{TEST_PREFIX} Customer {suffix}"},
    )
    assert response.status_code == 201, response.text
    return response.json()["customer"]


def _create_site(client, auth, customer_id: int, suffix: str, **overrides):
    response = client.post(
        f"/api/admin/customers/{customer_id}/locations",
        headers=auth,
        json={
            "address": f"{TEST_PREFIX} {suffix}, Effingham, IL 62401",
            "locationType": "Commercial",
            **overrides,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["location"]


def _location_row(location_id: int):
    import db

    return db.query_one("SELECT * FROM locations WHERE id = %s", (location_id,))


def test_customer_site_admin_routes_preserve_employee_location_contract(
    client,
    auth,
    emp_auth,
):
    employee_locations = client.get("/api/timesheet/locations", headers=emp_auth)
    assert employee_locations.status_code == 200, employee_locations.text
    assert {
        "success",
        "locations",
        "sites",
        "location_coords",
        "location_customers",
        "location_rates",
        "location_rate_types",
        "location_types",
        "location_frequencies",
        "location_expected_hours",
        "locationMatchRadiusM",
        "siteCheckInPolicy",
    } <= set(employee_locations.json())

    assert client.get("/api/admin/customers", headers=emp_auth).status_code == 403
    assert client.get("/api/admin/locations", headers=emp_auth).status_code == 403
    assert client.post(
        "/api/admin/customers",
        headers=emp_auth,
        json={"name": f"{TEST_PREFIX} Unauthorized"},
    ).status_code == 403

    assert client.get("/api/admin/customers", headers=auth).status_code == 200
    assert client.get("/api/admin/locations", headers=auth).status_code == 200


def test_static_legacy_pin_route_is_not_shadowed_by_the_site_id_route(client, auth):
    customer = _create_customer(client, auth, "Pin Route")
    site = _create_site(client, auth, customer["id"], "90 Pin Route Road")

    response = client.patch(
        "/api/admin/locations/pin",
        headers=auth,
        json={"location": site["address"], "lat": 39.1301, "lng": -88.5502},
    )
    assert response.status_code == 200, response.text
    stored = _location_row(site["id"])
    assert float(stored["lat"]) == pytest.approx(39.1301)
    assert float(stored["lng"]) == pytest.approx(-88.5502)


def test_legacy_put_accepts_aliases_and_current_aliases_take_precedence(client, auth):
    import db

    customer = _create_customer(client, auth, "Alias Original")
    existing = _create_site(
        client,
        auth,
        customer["id"],
        "100 Alias Street",
        rate=100.0,
        rateType="per_visit",
    )
    legacy_address = f"{TEST_PREFIX} 101 Legacy Alias Road, Effingham, IL 62401"
    string_address = f"{TEST_PREFIX} 102 String Only Road, Effingham, IL 62401"
    ignored_legacy_address = f"{TEST_PREFIX} 999 Must Not Exist, Effingham, IL"
    current_customer_name = f"{TEST_PREFIX} Customer Current Alias Wins"

    response = client.put(
        "/api/admin/locations",
        headers=auth,
        json={
            "locations": [
                {
                    "address": existing["address"],
                    "name": ignored_legacy_address,
                    "customerName": current_customer_name,
                    "customer": f"{TEST_PREFIX} Customer Legacy Must Lose",
                    "locationType": "Commercial",
                    "type": "Residential",
                    "rate": 125.0,
                    "rateType": "hourly",
                },
                {
                    "name": legacy_address,
                    "customer": f"{TEST_PREFIX} Customer Legacy Alias",
                    "type": "Residential",
                    "rate": 135.0,
                    "rateType": "per_visit",
                },
                string_address,
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    assert existing["address"] in body["locations"]
    assert legacy_address in body["locations"]
    assert string_address in body["locations"]
    assert body["location_customers"][existing["address"]] == current_customer_name
    assert body["location_types"][existing["address"]] == "Commercial"
    assert body["location_rate_types"][existing["address"]] == "hourly"

    existing_row = _location_row(existing["id"])
    assert existing_row["address"] == existing["address"]
    assert existing_row["customer_name"] == current_customer_name
    assert existing_row["location_type"] == "Commercial"
    assert float(existing_row["rate"]) == pytest.approx(125.0)
    assert existing_row["rate_type"] == "hourly"
    assert db.query_one(
        "SELECT id FROM locations WHERE address = %s",
        (ignored_legacy_address,),
    ) is None

    legacy_row = db.query_one(
        """
        SELECT l.*, c.name AS canonical_customer_name
        FROM locations l
        LEFT JOIN customers c ON c.id = l.customer_id
        WHERE l.address = %s
        """,
        (legacy_address,),
    )
    assert legacy_row["canonical_customer_name"] == (
        f"{TEST_PREFIX} Customer Legacy Alias"
    )
    assert legacy_row["customer_name"] == legacy_row["canonical_customer_name"]
    assert legacy_row["location_type"] == "Residential"
    assert legacy_row["customer_id"] is not None

    string_row = db.query_one(
        "SELECT * FROM locations WHERE address = %s",
        (string_address,),
    )
    assert string_row is not None
    assert string_row["customer_id"] is None
    assert string_row["customer_name"] is None
    assert string_row["location_type"] is None


def test_legacy_put_preserves_omitted_rows_and_fields_but_honors_explicit_null(
    client,
    auth,
):
    customer = _create_customer(client, auth, "Preservation")
    first = _create_site(
        client,
        auth,
        customer["id"],
        "200 First Preserve Lane",
        rate=210.0,
        rateType="monthly",
        frequency="Weekly",
        expectedHours=5.5,
        targetLaborPct=31.0,
        minMarginPct=26.0,
        lat=39.1203,
        lng=-88.54335,
        serviceScope="Full office clean",
        accessInstructions="Use loading entrance",
        servicePreferences="Unscented supplies",
        petNotes="No pets",
        serviceStartDate="2026-08-01",
    )
    second = _create_site(
        client,
        auth,
        customer["id"],
        "201 Omitted Preserve Lane",
        rate=310.0,
        rateType="per_visit",
        frequency="Monthly",
        expectedHours=7.0,
        targetLaborPct=33.0,
        minMarginPct=28.0,
        lat=39.1303,
        lng=-88.55335,
        serviceScope="Warehouse clean",
    )
    qr = client.post(
        f"/api/admin/locations/{first['id']}/check-in-qr",
        headers=auth,
        json={"rotate": False},
    )
    assert qr.status_code == 200, qr.text
    first_before = _location_row(first["id"])
    second_before = _location_row(second["id"])

    partial = client.put(
        "/api/admin/locations",
        headers=auth,
        json={"locations": [{"address": first["address"], "rate": 250.0}]},
    )
    assert partial.status_code == 200, partial.text
    assert second["address"] in partial.json()["locations"]
    first_after_partial = _location_row(first["id"])
    second_after_partial = _location_row(second["id"])
    assert float(first_after_partial["rate"]) == pytest.approx(250.0)
    for column in (
        "customer_id",
        "customer_name",
        "location_type",
        "rate_type",
        "frequency",
        "expected_hours",
        "target_labor_pct",
        "min_margin_pct",
        "lat",
        "lng",
        "service_scope",
        "access_instructions",
        "service_preferences",
        "pet_notes",
        "service_start_date",
        "check_in_token_nonce",
        "active",
    ):
        assert first_after_partial[column] == first_before[column]
    assert second_after_partial == second_before

    cleared = client.put(
        "/api/admin/locations",
        headers=auth,
        json={
            "locations": [
                {
                    "address": first["address"],
                    "rate": None,
                    "frequency": None,
                    "expectedHours": None,
                    "targetLaborPct": None,
                    "minMarginPct": None,
                    "lat": None,
                    "lng": None,
                }
            ]
        },
    )
    assert cleared.status_code == 200, cleared.text
    first_after_clear = _location_row(first["id"])
    for column in (
        "rate",
        "frequency",
        "expected_hours",
        "target_labor_pct",
        "min_margin_pct",
        "lat",
        "lng",
    ):
        assert first_after_clear[column] is None
    for column in (
        "customer_id",
        "customer_name",
        "location_type",
        "rate_type",
        "service_scope",
        "access_instructions",
        "service_preferences",
        "pet_notes",
        "service_start_date",
        "check_in_token_nonce",
        "active",
    ):
        assert first_after_clear[column] == first_after_partial[column]
    assert _location_row(second["id"]) == second_before


def test_job_exact_location_derives_customer_and_name_only_requires_one_site(
    client,
    auth,
):
    import db

    exact_customer = _create_customer(client, auth, "Job Exact")
    exact_site = _create_site(client, auth, exact_customer["id"], "300 Job Exact")
    exact = client.post(
        "/api/admin/jobs",
        headers=auth,
        json={
            "locationId": exact_site["id"],
            "customerName": "Caller supplied stale name",
            "scheduledDate": "2026-08-03",
            "expectedHours": 3.0,
            "revenue": 180.0,
            "notes": "Exact Site",
        },
    )
    assert exact.status_code == 200, exact.text
    exact_job = exact.json()["job"]
    assert exact_job["locationId"] == exact_site["id"]
    assert exact_job["customerName"] == exact_customer["name"]
    assert db.query_one(
        "SELECT location_id, customer_name FROM jobs WHERE id = %s",
        (exact_job["id"],),
    ) == {
        "location_id": exact_site["id"],
        "customer_name": exact_customer["name"],
    }

    unique_customer = _create_customer(client, auth, "Job Unique Name")
    unique_site = _create_site(
        client,
        auth,
        unique_customer["id"],
        "301 Job Unique Name",
    )
    name_only = client.post(
        "/api/admin/jobs",
        headers=auth,
        json={
            "customerName": unique_customer["name"],
            "scheduledDate": "2026-08-04",
            "notes": "Unique fallback",
        },
    )
    assert name_only.status_code == 200, name_only.text
    assert name_only.json()["job"]["locationId"] == unique_site["id"]


def test_job_name_only_zero_or_multiple_active_sites_is_rejected(client, auth):
    import db

    no_site_name = f"{TEST_PREFIX} Customer Job Has No Site"
    no_site_customer = client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": no_site_name},
    )
    assert no_site_customer.status_code == 201
    before_count = db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE customer_name LIKE %s",
        (f"{TEST_PREFIX}%",),
    )["count"]
    zero = client.post(
        "/api/admin/jobs",
        headers=auth,
        json={
            "customerName": no_site_name,
            "scheduledDate": "2026-08-05",
            "notes": "Must reject",
        },
    )
    assert zero.status_code == 409, zero.text
    assert zero.json()["code"] == "ambiguous_customer_site"
    assert zero.json()["details"]["matchingSiteIds"] == []

    multi_customer = _create_customer(client, auth, "Job Multi Site")
    first = _create_site(client, auth, multi_customer["id"], "302 Job Multi A")
    second = _create_site(client, auth, multi_customer["id"], "303 Job Multi B")
    ambiguous = client.post(
        "/api/admin/jobs",
        headers=auth,
        json={
            "customerName": multi_customer["name"],
            "scheduledDate": "2026-08-06",
            "notes": "Must reject",
        },
    )
    assert ambiguous.status_code == 409, ambiguous.text
    assert ambiguous.json()["code"] == "ambiguous_customer_site"
    assert ambiguous.json()["details"]["matchingSiteIds"] == [
        first["id"],
        second["id"],
    ]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM jobs WHERE customer_name LIKE %s",
        (f"{TEST_PREFIX}%",),
    )["count"] == before_count


def test_job_auto_link_uses_exact_site_when_customer_names_are_equal(
    client,
    auth,
    employee_id,
):
    import db

    shared_name = f"{TEST_PREFIX} Customer Auto Link Shared"
    customers = []
    for _ in range(2):
        response = client.post(
            "/api/admin/customers",
            headers=auth,
            json={"name": shared_name},
        )
        assert response.status_code == 201, response.text
        customers.append(response.json()["customer"])
    sites = [
        _create_site(client, auth, customers[0]["id"], "304 Auto Link A"),
        _create_site(client, auth, customers[1]["id"], "305 Auto Link B"),
    ]
    service_date = "2026-08-07"
    jobs = []
    for site in sites:
        response = client.post(
            "/api/admin/jobs",
            headers=auth,
            json={
                "locationId": site["id"],
                "customerName": shared_name,
                "scheduledDate": service_date,
                "notes": f"Exact Site {site['id']}",
            },
        )
        assert response.status_code == 200, response.text
        jobs.append(response.json()["job"])

    shift_ids = []
    for index, site in enumerate(sites):
        shift_ids.append(
            db.execute_returning(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, clock_in,
                    clock_out, total_hours, notes, local_date
                )
                VALUES (
                    %s, %s, %s, %s::date + (%s * INTERVAL '1 hour'),
                    %s::date + ((%s + 1) * INTERVAL '1 hour'), 1.0,
                    'exact Site auto-link proof', %s
                )
                RETURNING id
                """,
                (
                    employee_id,
                    site["id"],
                    site["address"],
                    service_date,
                    9 + index,
                    service_date,
                    9 + index,
                    service_date,
                ),
            )
        )

    linked = client.post("/api/admin/jobs/auto-link", headers=auth)
    assert linked.status_code == 200, linked.text
    assert linked.json()["success"] is True
    persisted = db.query_all(
        """
        SELECT id, location_id, job_id
        FROM shifts WHERE id = ANY(%s)
        ORDER BY id
        """,
        (shift_ids,),
    )
    by_location = {row["location_id"]: row["job_id"] for row in persisted}
    assert by_location == {
        sites[0]["id"]: jobs[0]["id"],
        sites[1]["id"]: jobs[1]["id"],
    }


def test_weekly_schedule_exact_and_unique_name_resolution_persist_site(
    client,
    auth,
    employee_id,
):
    import db

    exact_customer = _create_customer(client, auth, "Schedule Exact")
    exact_site = _create_site(
        client,
        auth,
        exact_customer["id"],
        "400 Schedule Exact",
    )
    exact = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": exact_site["id"],
            "customerName": "Caller supplied stale schedule name",
            "weekStart": "2026-08-02",
            "scheduledHours": 8.0,
            "notes": "Exact Site",
        },
    )
    assert exact.status_code == 200, exact.text
    exact_schedule = exact.json()["schedule"]
    assert exact_schedule["customerName"] == exact_customer["name"]
    assert exact_schedule["locationId"] == exact_site["id"]
    assert db.query_one(
        "SELECT location_id, customer_name FROM schedules WHERE id = %s",
        (exact_schedule["id"],),
    ) == {
        "location_id": exact_site["id"],
        "customer_name": exact_customer["name"],
    }

    unique_customer = _create_customer(client, auth, "Schedule Unique Name")
    unique_site = _create_site(
        client,
        auth,
        unique_customer["id"],
        "401 Schedule Unique Name",
    )
    name_only = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "customerName": unique_customer["name"],
            "weekStart": "2026-08-09",
            "scheduledHours": 6.0,
            "notes": "Unique fallback",
        },
    )
    assert name_only.status_code == 200, name_only.text
    stored = db.query_one(
        "SELECT location_id FROM schedules WHERE id = %s",
        (name_only.json()["schedule"]["id"],),
    )
    assert stored == {"location_id": unique_site["id"]}


def test_weekly_schedule_moves_to_replacement_site_without_creating_a_duplicate(
    client,
    auth,
    employee_id,
):
    import db

    customer = _create_customer(client, auth, "Schedule Replacement")
    retired_site = _create_site(
        client,
        auth,
        customer["id"],
        "404 Schedule Retired Site",
    )
    first = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": retired_site["id"],
            "customerName": customer["name"],
            "weekStart": "2026-08-30",
            "scheduledHours": 5.0,
            "notes": "Original Site",
        },
    )
    assert first.status_code == 200, first.text
    first_schedule = first.json()["schedule"]

    archived = client.delete(
        f"/api/admin/locations/{retired_site['id']}",
        headers=auth,
    )
    assert archived.status_code == 200, archived.text
    replacement_site = _create_site(
        client,
        auth,
        customer["id"],
        "405 Schedule Replacement Site",
    )

    replaced = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": replacement_site["id"],
            "customerName": customer["name"],
            "weekStart": "2026-08-30",
            "scheduledHours": 7.0,
            "notes": "Replacement Site",
        },
    )
    assert replaced.status_code == 200, replaced.text
    replacement_schedule = replaced.json()["schedule"]
    assert replacement_schedule["id"] == first_schedule["id"]
    assert replacement_schedule["locationId"] == replacement_site["id"]
    assert db.query_all(
        """
        SELECT id, location_id, scheduled_hours, notes
        FROM schedules
        WHERE employee_id = %s AND week_start = %s AND customer_name = %s
        """,
        (employee_id, "2026-08-30", customer["name"]),
    ) == [
        {
            "id": first_schedule["id"],
            "location_id": replacement_site["id"],
            "scheduled_hours": 7.0,
            "notes": "Replacement Site",
        }
    ]

    db.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, clock_out,
            total_hours, notes, local_date
        )
        VALUES (
            %s, %s, %s, '2026-09-01T12:00:00Z',
            '2026-09-01T14:00:00Z', 2.0,
            'retired Site actual proof', '2026-09-01'
        )
        """,
        (employee_id, retired_site["id"], retired_site["address"]),
    )
    comparison = client.get(
        "/api/admin/analytics/schedule-vs-actual",
        headers=auth,
        params={"week_start": "2026-08-30"},
    )
    assert comparison.status_code == 200, comparison.text
    customer_rows = [
        row
        for row in comparison.json()["comparisons"]
        if row["customerName"] == customer["name"]
    ]
    assert len(customer_rows) == 1
    customer_row = customer_rows[0]
    assert customer_row["employeeId"] == employee_id
    assert customer_row["customerId"] == customer["id"]
    assert customer_row["locationId"] == replacement_site["id"]
    assert customer_row["scheduledHours"] == 7.0
    assert customer_row["actualHours"] == 2.0
    assert customer_row["driftHours"] == -5.0
    assert customer_row["driftPct"] == -71.4

    legacy_schedule_id = db.execute_returning(
        """
        INSERT INTO schedules (
            employee_id, location_id, customer_name, week_start,
            scheduled_hours, notes
        )
        VALUES (%s, NULL, %s, '2026-09-20', 1.0, 'Legacy replacement row')
        RETURNING id
        """,
        (employee_id, customer["name"]),
    )
    adopted = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": replacement_site["id"],
            "customerName": customer["name"],
            "weekStart": "2026-09-20",
            "scheduledHours": 3.0,
            "notes": "Adopted by stable Customer identity",
        },
    )
    assert adopted.status_code == 200, adopted.text
    assert adopted.json()["schedule"]["id"] == legacy_schedule_id
    assert adopted.json()["schedule"]["locationId"] == replacement_site["id"]


def test_weekly_schedules_keep_equal_named_customers_distinct_by_site(
    client,
    auth,
    employee_id,
):
    import db

    shared_name = f"{TEST_PREFIX} Customer Shared Schedule Name"
    customers = []
    for _ in range(2):
        response = client.post(
            "/api/admin/customers",
            headers=auth,
            json={"name": shared_name},
        )
        assert response.status_code == 201, response.text
        customers.append(response.json()["customer"])

    first_site = _create_site(
        client,
        auth,
        customers[0]["id"],
        "406 Shared A",
        rate=100.0,
        rateType="hourly",
        expectedHours=1.0,
    )
    second_site = _create_site(
        client,
        auth,
        customers[1]["id"],
        "407 Shared B",
        rate=200.0,
        rateType="hourly",
        expectedHours=1.0,
    )
    schedule_ids = []
    for site, hours in ((first_site, 3.0), (second_site, 4.0)):
        response = client.post(
            "/api/admin/schedules",
            headers=auth,
            json={
                "employeeId": employee_id,
                "locationId": site["id"],
                "customerName": shared_name,
                "weekStart": "2026-09-06",
                "scheduledHours": hours,
                "notes": f"Site {site['id']}",
            },
        )
        assert response.status_code == 200, response.text
        schedule = response.json()["schedule"]
        assert schedule["locationId"] == site["id"]
        schedule_ids.append(schedule["id"])

    assert len(set(schedule_ids)) == 2
    persisted = db.query_all(
        """
        SELECT id, location_id, scheduled_hours
        FROM schedules
        WHERE employee_id = %s AND week_start = %s AND customer_name = %s
        ORDER BY id
        """,
        (employee_id, "2026-09-06", shared_name),
    )
    assert persisted == sorted(
        [
            {
                "id": schedule_ids[0],
                "location_id": first_site["id"],
                "scheduled_hours": 3.0,
            },
            {
                "id": schedule_ids[1],
                "location_id": second_site["id"],
                "scheduled_hours": 4.0,
            },
        ],
        key=lambda row: row["id"],
    )
    with pytest.raises(UniqueViolation):
        db.execute(
            """
            INSERT INTO schedules (
                employee_id, location_id, customer_name, week_start,
                scheduled_hours, notes
            )
            VALUES (%s, %s, 'Different snapshot', '2026-09-06', 1.0,
                    'Fresh schema exact Site duplicate')
            """,
            (employee_id, first_site["id"]),
        )

    update_first = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": first_site["id"],
            "customerName": shared_name,
            "weekStart": "2026-09-06",
            "scheduledHours": 6.5,
            "notes": "Only first Site changes",
        },
    )
    assert update_first.status_code == 200, update_first.text
    assert update_first.json()["schedule"]["id"] == schedule_ids[0]
    after_update = db.query_all(
        """
        SELECT id, location_id, scheduled_hours
        FROM schedules
        WHERE id = ANY(%s)
        ORDER BY id
        """,
        (schedule_ids,),
    )
    by_id = {row["id"]: row for row in after_update}
    assert float(by_id[schedule_ids[0]]["scheduled_hours"]) == 6.5
    assert float(by_id[schedule_ids[1]]["scheduled_hours"]) == 4.0
    assert by_id[schedule_ids[0]]["location_id"] == first_site["id"]
    assert by_id[schedule_ids[1]]["location_id"] == second_site["id"]

    name_only = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "customerName": shared_name,
            "weekStart": "2026-09-13",
            "scheduledHours": 2.0,
            "notes": "Ambiguous name",
        },
    )
    assert name_only.status_code == 409, name_only.text
    assert name_only.json()["code"] == "ambiguous_customer_site"
    assert set(name_only.json()["details"]["matchingSiteIds"]) == {
        first_site["id"],
        second_site["id"],
    }

    legacy_schedule_id = db.execute_returning(
        """
        INSERT INTO schedules (
            employee_id, location_id, customer_name, week_start,
            scheduled_hours, notes
        )
        VALUES (%s, NULL, %s, %s, 1.5, 'Legacy name-only row')
        RETURNING id
        """,
        (employee_id, shared_name, "2026-09-13"),
    )
    ambiguous_reassignment = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": first_site["id"],
            "customerName": shared_name,
            "weekStart": "2026-09-13",
            "scheduledHours": 8.0,
            "notes": "Must not claim legacy row",
        },
    )
    assert ambiguous_reassignment.status_code == 409, ambiguous_reassignment.text
    assert ambiguous_reassignment.json()["code"] == "ambiguous_customer_site"
    assert ambiguous_reassignment.json()["details"]["matchingScheduleIds"] == [
        legacy_schedule_id
    ]
    assert db.query_one(
        """
        SELECT location_id, scheduled_hours, notes
        FROM schedules WHERE id = %s
        """,
        (legacy_schedule_id,),
    ) == {
        "location_id": None,
        "scheduled_hours": 1.5,
        "notes": "Legacy name-only row",
    }
    with pytest.raises(UniqueViolation):
        db.execute(
            """
            INSERT INTO schedules (
                employee_id, location_id, customer_name, week_start,
                scheduled_hours, notes
            )
            VALUES (%s, NULL, %s, '2026-09-13', 2.0,
                    'Fresh schema unresolved duplicate')
            """,
            (employee_id, shared_name),
        )

    for site, hours, hour in (
        (first_site, 1.0, 12),
        (second_site, 2.0, 15),
    ):
        db.execute(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label, clock_in, clock_out,
                total_hours, notes, local_date
            )
            VALUES (
                %s, %s, %s, %s::timestamptz,
                %s::timestamptz + (%s * INTERVAL '1 hour'),
                %s, 'equal-name reporting proof', '2026-09-08'
            )
            """,
            (
                employee_id,
                site["id"],
                site["address"],
                f"2026-09-08T{hour:02d}:00:00Z",
                f"2026-09-08T{hour:02d}:00:00Z",
                hours,
                hours,
            ),
        )

    comparison = client.get(
        "/api/admin/analytics/schedule-vs-actual",
        headers=auth,
        params={"week_start": "2026-09-06"},
    )
    assert comparison.status_code == 200, comparison.text
    shared_comparisons = [
        row
        for row in comparison.json()["comparisons"]
        if row["customerName"] == shared_name
    ]
    assert {
        row["locationId"]: row["actualHours"] for row in shared_comparisons
    } == {first_site["id"]: 1.0, second_site["id"]: 2.0}
    assert sum(row["actualHours"] for row in shared_comparisons) == 3.0


def test_weekly_schedule_rejects_zero_or_multi_site_customer(
    client,
    auth,
    employee_id,
):
    import db

    no_site_name = f"{TEST_PREFIX} Customer Schedule Has No Site"
    assert client.post(
        "/api/admin/customers",
        headers=auth,
        json={"name": no_site_name},
    ).status_code == 201
    before_count = db.query_one(
        "SELECT COUNT(*) AS count FROM schedules WHERE customer_name LIKE %s",
        (f"{TEST_PREFIX}%",),
    )["count"]
    zero = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "customerName": no_site_name,
            "weekStart": "2026-08-16",
            "scheduledHours": 4.0,
            "notes": "Must reject",
        },
    )
    assert zero.status_code == 409, zero.text
    assert zero.json()["code"] == "ambiguous_customer_site"
    assert zero.json()["details"]["matchingSiteIds"] == []

    multi_customer = _create_customer(client, auth, "Schedule Multi Site")
    first = _create_site(
        client,
        auth,
        multi_customer["id"],
        "402 Schedule Multi A",
    )
    second = _create_site(
        client,
        auth,
        multi_customer["id"],
        "403 Schedule Multi B",
    )
    exact_but_unsupported = client.post(
        "/api/admin/schedules",
        headers=auth,
        json={
            "employeeId": employee_id,
            "locationId": first["id"],
            "customerName": multi_customer["name"],
            "weekStart": "2026-08-23",
            "scheduledHours": 5.0,
            "notes": "Issue 20 required",
        },
    )
    assert exact_but_unsupported.status_code == 409, exact_but_unsupported.text
    assert exact_but_unsupported.json()["code"] == "ambiguous_customer_site"
    assert exact_but_unsupported.json()["details"]["matchingSiteIds"] == [
        first["id"],
        second["id"],
    ]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM schedules WHERE customer_name LIKE %s",
        (f"{TEST_PREFIX}%",),
    )["count"] == before_count

    legacy_schedule_id = db.execute_returning(
        """
        INSERT INTO schedules (
            employee_id, location_id, customer_name, week_start,
            scheduled_hours, notes
        )
        VALUES (%s, NULL, %s, '2026-08-23', 5.0, 'Legacy Customer total')
        RETURNING id
        """,
        (employee_id, multi_customer["name"]),
    )
    db.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, clock_out,
            total_hours, notes, local_date
        )
        VALUES (
            %s, %s, %s, '2026-08-24T12:00:00Z',
            '2026-08-24T14:00:00Z', 2.0,
            'legacy multi-Site reporting proof', '2026-08-24'
        )
        """,
        (employee_id, first["id"], first["address"]),
    )
    comparison = client.get(
        "/api/admin/analytics/schedule-vs-actual",
        headers=auth,
        params={"week_start": "2026-08-23"},
    )
    assert comparison.status_code == 200, comparison.text
    rows = [
        row
        for row in comparison.json()["comparisons"]
        if row["customerName"] == multi_customer["name"]
    ]
    assert len(rows) == 1
    assert rows[0]["customerId"] == multi_customer["id"]
    assert rows[0]["scheduledHours"] == 5.0
    assert rows[0]["actualHours"] == 2.0
    assert legacy_schedule_id is not None


def test_forecast_no_longer_projects_retired_history_without_source_jobs(
    client,
    auth,
    employee_id,
):
    import db
    import time_tracker_api as api

    customer = _create_customer(client, auth, "Forecast Replacement")
    retired_site = _create_site(
        client,
        auth,
        customer["id"],
        "408 Forecast Retired",
        rate=100.0,
        rateType="hourly",
        expectedHours=1.0,
    )
    historical_date = api.to_local(api.utc_now()).date() - timedelta(days=10)
    db.execute(
        """
        INSERT INTO shifts (
            employee_id, location_id, location_label, clock_in, clock_out,
            total_hours, notes, local_date
        )
        VALUES (%s, %s, %s, %s::date + TIME '12:00',
                %s::date + TIME '14:00', 2.0,
                'forecast replacement proof', %s)
        """,
        (
            employee_id,
            retired_site["id"],
            retired_site["address"],
            historical_date,
            historical_date,
            historical_date,
        ),
    )
    archived = client.delete(
        f"/api/admin/locations/{retired_site['id']}",
        headers=auth,
    )
    assert archived.status_code == 200, archived.text
    _replacement_site = _create_site(
        client,
        auth,
        customer["id"],
        "409 Forecast Active",
        rate=220.0,
        rateType="hourly",
        expectedHours=1.0,
    )

    forecast = client.get(
        "/api/admin/analytics/forecast",
        headers=auth,
        params={"weeks_ahead": 1},
    )
    assert forecast.status_code == 200, forecast.text
    customer_rows = [
        row
        for row in forecast.json()["forecasts"][0]["byCustomer"]
        if row["customerId"] == customer["id"]
    ]
    assert customer_rows == []


def test_forecast_no_longer_projects_history_or_schedules_without_source_jobs(
    client,
    auth,
    employee_id,
):
    import db
    import time_tracker_api as api

    customer = _create_customer(client, auth, "Forecast Multi Site")
    hourly_site = _create_site(
        client,
        auth,
        customer["id"],
        "410 Forecast Hourly",
        rate=100.0,
        rateType="hourly",
        expectedHours=2.0,
    )
    visit_site = _create_site(
        client,
        auth,
        customer["id"],
        "411 Forecast Per Visit",
        rate=150.0,
        rateType="per_visit",
        expectedHours=3.0,
    )
    historical_date = api.to_local(api.utc_now()).date() - timedelta(days=10)
    for site, hours, hour in (
        (hourly_site, 2.0, 9),
        (visit_site, 3.0, 13),
    ):
        db.execute(
            """
            INSERT INTO shifts (
                employee_id, location_id, location_label, clock_in, clock_out,
                total_hours, notes, local_date
            )
            VALUES (
                %s, %s, %s, %s::date + (%s * INTERVAL '1 hour'),
                %s::date + ((%s + %s) * INTERVAL '1 hour'), %s,
                'multi-Site forecast proof', %s
            )
            """,
            (
                employee_id,
                site["id"],
                site["address"],
                historical_date,
                hour,
                historical_date,
                hour,
                hours,
                hours,
                historical_date,
            ),
        )

    historical = client.get(
        "/api/admin/analytics/forecast",
        headers=auth,
        params={"weeks_ahead": 1},
    )
    assert historical.status_code == 200, historical.text
    historical_rows = [
        row
        for row in historical.json()["forecasts"][0]["byCustomer"]
        if row["customerId"] == customer["id"]
    ]
    assert historical_rows == []

    today = api.to_local(api.utc_now()).date()
    current_sunday = today - timedelta(days=(today.weekday() + 1) % 7)
    db.execute(
        """
        INSERT INTO schedules (
            employee_id, location_id, customer_name, week_start,
            scheduled_hours, notes
        )
        VALUES (%s, %s, %s, %s, 6.0, 'scheduled Site override proof')
        """,
        (employee_id, visit_site["id"], customer["name"], current_sunday),
    )
    scheduled = client.get(
        "/api/admin/analytics/forecast",
        headers=auth,
        params={"weeks_ahead": 1},
    )
    assert scheduled.status_code == 200, scheduled.text
    scheduled_rows = [
        row
        for row in scheduled.json()["forecasts"][0]["byCustomer"]
        if row["customerId"] == customer["id"]
    ]
    assert scheduled_rows == []
