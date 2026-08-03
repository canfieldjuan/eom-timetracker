"""High-value API and lifecycle contract tests for Issue #19 Customers/Sites."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import psycopg2.extras
import pytest

from conftest import _raw_conn


TEST_PREFIX = "Issue 19 API"


def _clean_test_rows() -> None:
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT l.id
                FROM locations l
                LEFT JOIN customers c ON c.id = l.customer_id
                WHERE l.address ILIKE %s OR c.name LIKE %s
                """,
                (f"{TEST_PREFIX}%", f"{TEST_PREFIX}%"),
            )
            location_ids = [row[0] for row in cur.fetchall()]
            if location_ids:
                cur.execute(
                    "DELETE FROM site_check_in_reconciliation_reviews "
                    "WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM site_check_ins WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM site_check_in_schedule_rules "
                    "WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM site_check_in_schedules "
                    "WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM visits WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM departures WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM shifts WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM jobs WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM schedules WHERE location_id = ANY(%s)",
                    (location_ids,),
                )
                cur.execute(
                    "DELETE FROM locations WHERE id = ANY(%s)",
                    (location_ids,),
                )
            cur.execute(
                "DELETE FROM shifts WHERE location_label LIKE %s",
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
def isolate_customer_location_contract_rows(setup_db):
    _clean_test_rows()
    yield
    _clean_test_rows()


def _create_customer(client, auth, suffix: str, **overrides):
    payload = {"name": f"{TEST_PREFIX} Customer {suffix}", **overrides}
    response = client.post("/api/admin/customers", headers=auth, json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["success"] is True
    return body["customer"]


def _create_site(client, auth, customer_id: int, suffix: str, **overrides):
    payload = {
        "address": f"{TEST_PREFIX} {suffix}, Effingham, IL 62401",
        "locationType": "Commercial",
        **overrides,
    }
    response = client.post(
        f"/api/admin/customers/{customer_id}/locations",
        headers=auth,
        json=payload,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["success"] is True
    return body["location"]


def _location_row(location_id: int):
    import db

    return db.query_one("SELECT * FROM locations WHERE id = %s", (location_id,))


def _customer_row(customer_id: int):
    import db

    return db.query_one("SELECT * FROM customers WHERE id = %s", (customer_id,))


def test_customer_and_site_readiness_is_derived_from_persisted_checklists(client, auth):
    customer = _create_customer(client, auth, "Readiness")
    assert customer["status"] == "draft"
    assert customer["checklist"]["required"] == {
        "name": True,
        "activeSite": False,
        "allActiveSitesReady": False,
    }

    site = _create_site(client, auth, customer["id"], "50 Readiness Way")
    assert site["status"] == "needs_setup"
    assert site["checklist"]["required"] == {
        "address": True,
        "locationType": True,
        "rate": False,
        "rateType": True,
        "gps": False,
    }
    needs_setup = client.get(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
    ).json()["customer"]
    assert needs_setup["status"] == "needs_setup"

    ready_response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={"rate": 125.0, "lat": 39.1203, "lng": -88.54335},
    )
    assert ready_response.status_code == 200, ready_response.text
    assert ready_response.json()["location"]["status"] == "ready"
    ready_customer = client.get(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
    ).json()["customer"]
    assert ready_customer["status"] == "ready"
    assert all(ready_customer["checklist"]["required"].values())


@pytest.mark.parametrize(
    ("payload", "expected_fields"),
    [
        ({"name": "x" * 201}, {"name"}),
        ({"name": f"{TEST_PREFIX} Invalid Email", "primaryEmail": "bad"}, {"primaryEmail"}),
        (
            {"name": f"{TEST_PREFIX} Invalid UUID", "atlasContactId": "not-a-uuid"},
            {"atlasContactId"},
        ),
        (
            {
                "name": f"{TEST_PREFIX} Invalid Site",
                "primarySite": {
                    "address": f"{TEST_PREFIX} Invalid Site Road",
                    "locationType": "Office",
                    "rate": 1_000_000,
                    "rateType": "weekly",
                    "expectedHours": 10_000,
                    "targetLaborPct": 101,
                    "minMarginPct": -1,
                    "frequency": "x" * 101,
                    "serviceScope": "x" * 4001,
                    "petNotes": "x" * 2001,
                },
            },
            {
                "primarySite.locationType",
                "primarySite.rate",
                "primarySite.rateType",
                "primarySite.expectedHours",
                "primarySite.targetLaborPct",
                "primarySite.minMarginPct",
                "primarySite.frequency",
                "primarySite.serviceScope",
                "primarySite.petNotes",
            },
        ),
    ],
)
def test_customer_site_validation_returns_stable_field_details(
    client,
    auth,
    payload,
    expected_fields,
):
    response = client.post("/api/admin/customers", headers=auth, json=payload)
    assert response.status_code == 422, response.text
    error = response.json()
    assert error["success"] is False
    assert error["code"] == "validation_error"
    assert expected_fields <= set(error["details"]["fields"])


def test_site_coordinate_pair_and_service_date_errors_name_actionable_fields(
    client,
    auth,
):
    customer = _create_customer(client, auth, "Validation Fields")

    missing_lng = client.post(
        f"/api/admin/customers/{customer['id']}/locations",
        headers=auth,
        json={
            "address": f"{TEST_PREFIX} 51 Validation Field Way",
            "locationType": "Commercial",
            "lat": 39.12,
        },
    )
    assert missing_lng.status_code == 422, missing_lng.text
    assert {"lat", "lng"} <= set(
        missing_lng.json()["details"]["fields"]
    )

    bad_date = client.post(
        f"/api/admin/customers/{customer['id']}/locations",
        headers=auth,
        json={
            "address": f"{TEST_PREFIX} 52 Validation Date Way",
            "locationType": "Commercial",
            "serviceStartDate": "2026-08-01T00:00:00",
        },
    )
    assert bad_date.status_code == 422, bad_date.text
    assert "serviceStartDate" in bad_date.json()["details"]["fields"]


def test_customer_patch_distinguishes_omission_from_explicit_null(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Customer Patch",
        primaryContactName="Original Contact",
        primaryPhone="217-555-0110",
        primaryEmail="original@example.test",
        billingName="Original Billing",
        billingEmail="accounts@example.test",
        billingAddress="20 Billing Road, Effingham, IL 62401",
        atlasContactId="11111111-1111-1111-1111-111111111111",
    )
    customer_id = customer["id"]
    preserved_columns = (
        "name",
        "primary_contact_name",
        "primary_email",
        "billing_name",
        "billing_email",
        "billing_address",
        "atlas_contact_id",
        "active",
    )
    before = _customer_row(customer_id)

    patched = client.patch(
        f"/api/admin/customers/{customer_id}",
        headers=auth,
        json={"primaryPhone": "217-555-0199"},
    )
    assert patched.status_code == 200, patched.text
    canonical = patched.json()["customer"]
    assert canonical["primaryPhone"] == "217-555-0199"
    assert canonical["primaryEmail"] == "original@example.test"
    assert canonical["billingEmail"] == "accounts@example.test"
    assert canonical["atlasContactId"] == "11111111-1111-1111-1111-111111111111"
    after_phone = _customer_row(customer_id)
    assert {column: after_phone[column] for column in preserved_columns} == {
        column: before[column] for column in preserved_columns
    }
    assert after_phone["primary_phone"] == "217-555-0199"

    cleared = client.patch(
        f"/api/admin/customers/{customer_id}",
        headers=auth,
        json={"billingEmail": None},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["customer"]["billingEmail"] is None
    after_clear = _customer_row(customer_id)
    assert after_clear["billing_email"] is None
    assert after_clear["primary_phone"] == after_phone["primary_phone"]
    for column in preserved_columns:
        if column != "billing_email":
            assert after_clear[column] == after_phone[column]

    rejected = client.patch(
        f"/api/admin/customers/{customer_id}",
        headers=auth,
        json={"name": None},
    )
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["code"] == "validation_error"
    assert rejected.json()["details"]
    assert _customer_row(customer_id)["name"] == before["name"]


def test_customer_patch_rejects_a_stale_update_token_without_writing(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Customer Update Token",
        primaryPhone="217-555-0100",
        billingName="Original Billing",
    )
    original_token = customer["updateToken"]
    assert len(original_token) == 64
    int(original_token, 16)

    updated = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": original_token,
            "primaryPhone": "217-555-0199",
        },
    )
    assert updated.status_code == 200, updated.text
    updated_customer = updated.json()["customer"]
    assert updated_customer["updateToken"] != original_token
    assert updated_customer["primaryPhone"] == "217-555-0199"

    stale = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": original_token,
            "billingName": "Stale Billing",
        },
    )
    assert stale.status_code == 409, stale.text
    assert stale.json() == {
        "success": False,
        "error": "Customer changed after it was read; reload before retrying",
        "code": "stale_customer_update",
        "details": {"customerId": customer["id"]},
    }
    persisted = _customer_row(customer["id"])
    assert persisted["primary_phone"] == "217-555-0199"
    assert persisted["billing_name"] == "Original Billing"


def test_update_token_distinguishes_changes_within_the_same_second(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Same Second Update Token",
        primaryPhone="217-555-0100",
    )
    timestamps = (
        datetime(2026, 7, 24, 12, 34, 56, 123456, tzinfo=timezone.utc),
        datetime(2026, 7, 24, 12, 34, 56, 123457, tzinfo=timezone.utc),
    )

    tokens = []
    displayed_timestamps = []
    for updated_at in timestamps:
        conn = _raw_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE customers SET updated_at = %s WHERE id = %s",
                    (updated_at, customer["id"]),
                )
            conn.commit()
        finally:
            conn.close()
        current = client.get(
            f"/api/admin/customers/{customer['id']}",
            headers=auth,
        ).json()["customer"]
        tokens.append(current["updateToken"])
        displayed_timestamps.append(current["updatedAt"])

    assert displayed_timestamps[0] == displayed_timestamps[1]
    assert tokens[0] != tokens[1]

    stale = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": tokens[0],
            "primaryPhone": "217-555-0999",
        },
    )
    assert stale.status_code == 409, stale.text
    assert _customer_row(customer["id"])["primary_phone"] == "217-555-0100"


def test_site_patch_distinguishes_omission_from_explicit_null(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Patch",
        primaryContactName="Primary Contact",
        primaryPhone="217-555-0100",
        primaryEmail="primary@example.test",
        billingName="Billing Contact",
        billingEmail="billing@example.test",
        billingAddress="10 Billing Road, Effingham, IL 62401",
    )
    site = _create_site(
        client,
        auth,
        customer["id"],
        "100 Preservation Lane",
        rate=275.50,
        rateType="monthly",
        frequency="Every other week",
        expectedHours=6.25,
        targetLaborPct=32.5,
        minMarginPct=27.5,
        lat=39.1203,
        lng=-88.54335,
        serviceScope="Offices, restrooms, and lobby",
        accessInstructions="Use the north employee entrance",
        servicePreferences="Fragrance-free products",
        petNotes="Office dog may be present",
        serviceStartDate="2026-08-01",
    )
    site_id = site["id"]
    preserved_columns = (
        "customer_id",
        "address",
        "address_key",
        "customer_name",
        "location_type",
        "rate",
        "rate_type",
        "frequency",
        "expected_hours",
        "target_labor_pct",
        "min_margin_pct",
        "service_scope",
        "access_instructions",
        "service_preferences",
        "pet_notes",
        "service_start_date",
        "active",
    )
    before = _location_row(site_id)

    patched = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=auth,
        json={"lat": 39.125, "lng": -88.55},
    )
    assert patched.status_code == 200, patched.text
    canonical = patched.json()["location"]
    assert canonical["latitude"] == pytest.approx(39.125)
    assert canonical["longitude"] == pytest.approx(-88.55)
    assert canonical["rate"] == pytest.approx(275.50)
    assert canonical["targetLaborPct"] == pytest.approx(32.5)
    assert canonical["minMarginPct"] == pytest.approx(27.5)
    assert canonical["servicePreferences"] == "Fragrance-free products"

    after_pin = _location_row(site_id)
    assert {
        column: after_pin[column] for column in preserved_columns
    } == {column: before[column] for column in preserved_columns}
    assert float(after_pin["lat"]) == pytest.approx(39.125)
    assert float(after_pin["lng"]) == pytest.approx(-88.55)

    cleared = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=auth,
        json={"servicePreferences": None},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["location"]["servicePreferences"] is None
    after_clear = _location_row(site_id)
    assert after_clear["service_preferences"] is None
    assert after_clear["lat"] == after_pin["lat"]
    assert after_clear["lng"] == after_pin["lng"]
    for column in preserved_columns:
        if column != "service_preferences":
            assert after_clear[column] == after_pin[column]

    rejected = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=auth,
        json={"address": None},
    )
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["code"] == "validation_error"
    assert rejected.json()["details"]
    assert _location_row(site_id)["address"] == before["address"]


def test_site_patch_rejects_a_stale_update_token_without_writing(client, auth):
    customer = _create_customer(client, auth, "Site Update Token")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "125 Update Token Way",
        rate=97.0,
        rateType="monthly",
        frequency="Monthly",
    )
    original_token = site["updateToken"]
    assert len(original_token) == 64
    int(original_token, 16)

    updated = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": original_token,
            "rate": 247.5,
        },
    )
    assert updated.status_code == 200, updated.text
    updated_site = updated.json()["location"]
    assert updated_site["updateToken"] != original_token
    assert updated_site["rate"] == pytest.approx(247.5)

    stale = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": original_token,
            "frequency": "Stale Frequency",
        },
    )
    assert stale.status_code == 409, stale.text
    assert stale.json() == {
        "success": False,
        "error": "Site changed after it was read; reload before retrying",
        "code": "stale_site_update",
        "details": {"siteId": site["id"]},
    }
    persisted = _location_row(site["id"])
    assert float(persisted["rate"]) == pytest.approx(247.5)
    assert persisted["frequency"] == "Monthly"


def test_site_patch_rejects_stale_owning_customer_token_before_writing(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Owning Customer Token Drift",
        atlasContactId="11111111-1111-1111-1111-111111111111",
    )
    site = _create_site(
        client,
        auth,
        customer["id"],
        "125 Customer Token Drift Way",
        rate=97.0,
        rateType="monthly",
    )
    original_site_row = _location_row(site["id"])

    customer_update = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": customer["updateToken"],
            "atlasContactId": "22222222-2222-2222-2222-222222222222",
        },
    )
    assert customer_update.status_code == 200, customer_update.text
    assert customer_update.json()["customer"]["updateToken"] != customer["updateToken"]
    unchanged_site = client.get(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
    ).json()["customer"]["sites"][0]
    assert unchanged_site["updateToken"] == site["updateToken"]

    stale = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": site["updateToken"],
            "expectedCustomerUpdateToken": customer["updateToken"],
            "rate": 247.5,
        },
    )
    assert stale.status_code == 409, stale.text
    assert stale.json() == {
        "success": False,
        "error": "Customer changed after it was read; reload before retrying",
        "code": "stale_customer_update",
        "details": {"customerId": customer["id"]},
    }
    persisted = _location_row(site["id"])
    assert persisted["rate"] == original_site_row["rate"]
    assert persisted["updated_at"] == original_site_row["updated_at"]


def test_site_patch_accepts_current_site_and_owning_customer_tokens(client, auth):
    customer = _create_customer(
        client,
        auth,
        "Current Owning Customer Token",
        atlasContactId="33333333-3333-3333-3333-333333333333",
    )
    site = _create_site(
        client,
        auth,
        customer["id"],
        "126 Current Customer Token Way",
        rate=97.0,
        rateType="monthly",
    )

    response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedUpdateToken": site["updateToken"],
            "expectedCustomerUpdateToken": customer["updateToken"],
            "rate": 247.5,
            "rateType": "per_visit",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["location"]["rate"] == pytest.approx(247.5)
    assert response.json()["location"]["rateType"] == "per_visit"


def test_site_customer_guard_fails_closed_when_owning_customer_is_missing(
    client,
    auth,
    monkeypatch,
):
    import time_tracker_api as api

    customer = _create_customer(client, auth, "Missing Owning Customer")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "127 Missing Customer Way",
        rate=97.0,
    )
    before = _location_row(site["id"])
    monkeypatch.setattr(api, "_customer_row", lambda *_args, **_kwargs: None)

    response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedCustomerUpdateToken": customer["updateToken"],
            "rate": 247.5,
        },
    )
    assert response.status_code == 409, response.text
    assert response.json() == {
        "success": False,
        "error": "Site's Customer no longer exists; reload before retrying",
        "code": "site_customer_missing",
        "details": {"siteId": site["id"], "customerId": customer["id"]},
    }
    persisted = _location_row(site["id"])
    assert persisted["rate"] == before["rate"]
    assert persisted["updated_at"] == before["updated_at"]


def test_site_customer_guard_fails_closed_for_an_unlinked_site(client, auth):
    customer = _create_customer(client, auth, "Unlinked Customer Guard")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "128 Unlinked Customer Guard Way",
        rate=97.0,
    )
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE locations SET customer_id = NULL WHERE id = %s",
                (site["id"],),
            )
        conn.commit()
    finally:
        conn.close()
    before = _location_row(site["id"])

    response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={
            "expectedCustomerUpdateToken": customer["updateToken"],
            "rate": 247.5,
        },
    )
    assert response.status_code == 409, response.text
    assert response.json() == {
        "success": False,
        "error": "Site is not linked to a Customer; reload before retrying",
        "code": "site_customer_unlinked",
        "details": {"siteId": site["id"], "customerId": None},
    }
    persisted = _location_row(site["id"])
    assert persisted["rate"] == before["rate"]
    assert persisted["updated_at"] == before["updated_at"]


def test_site_patch_without_customer_token_preserves_unlinked_site_compatibility(
    client,
    auth,
):
    customer = _create_customer(client, auth, "Tokenless Unlinked Compatibility")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "129 Tokenless Unlinked Compatibility Way",
        rate=97.0,
    )
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE locations SET customer_id = NULL WHERE id = %s",
                (site["id"],),
            )
        conn.commit()
    finally:
        conn.close()

    response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={"rate": 247.5},
    )
    assert response.status_code == 200, response.text
    assert response.json()["location"]["customerId"] is None
    assert response.json()["location"]["rate"] == pytest.approx(247.5)


def test_patch_treats_an_explicitly_null_update_token_as_unguarded(client, auth):
    customer = _create_customer(client, auth, "Null Update Token")
    site = _create_site(client, auth, customer["id"], "126 Null Update Token Way")

    customer_response = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={"expectedUpdateToken": None, "primaryPhone": "217-555-0166"},
    )
    assert customer_response.status_code == 200, customer_response.text
    assert customer_response.json()["customer"]["primaryPhone"] == "217-555-0166"

    site_response = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={"expectedUpdateToken": None, "frequency": "Every Friday"},
    )
    assert site_response.status_code == 200, site_response.text
    assert site_response.json()["location"]["frequency"] == "Every Friday"

    malformed = client.patch(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
        json={"expectedUpdateToken": "not-a-token"},
    )
    assert malformed.status_code == 422, malformed.text
    assert "expectedUpdateToken" in malformed.json()["details"]["fields"]


def test_concurrent_customer_patches_with_one_update_token_have_one_winner(
    client,
    auth,
):
    customer = _create_customer(
        client,
        auth,
        "Concurrent Update Token",
        primaryPhone="217-555-0100",
    )
    start = Barrier(2)

    def update_phone(phone):
        start.wait(timeout=10)
        return client.patch(
            f"/api/admin/customers/{customer['id']}",
            headers=auth,
            json={
                "expectedUpdateToken": customer["updateToken"],
                "primaryPhone": phone,
            },
        )

    phones = ["217-555-0111", "217-555-0222"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = [
            future.result(timeout=20)
            for future in [pool.submit(update_phone, phone) for phone in phones]
        ]

    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response for response in responses if response.status_code == 200)
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["code"] == "stale_customer_update"
    assert _customer_row(customer["id"])["primary_phone"] == winner.json()["customer"][
        "primaryPhone"
    ]


def test_concurrent_site_patches_with_one_update_token_have_one_winner(client, auth):
    customer = _create_customer(client, auth, "Concurrent Site Update Token")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "127 Concurrent Update Token Way",
        frequency="Original Frequency",
    )
    start = Barrier(2)

    def update_frequency(frequency):
        start.wait(timeout=10)
        return client.patch(
            f"/api/admin/locations/{site['id']}",
            headers=auth,
            json={
                "expectedUpdateToken": site["updateToken"],
                "frequency": frequency,
            },
        )

    frequencies = ["Every Monday", "Every Thursday"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = [
            future.result(timeout=20)
            for future in [
                pool.submit(update_frequency, frequency)
                for frequency in frequencies
            ]
        ]

    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response for response in responses if response.status_code == 200)
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["code"] == "stale_site_update"
    assert _location_row(site["id"])["frequency"] == winner.json()["location"][
        "frequency"
    ]


def test_customer_rename_syncs_all_sites_and_explicit_id_reassigns_one_site(
    client,
    auth,
):
    original = _create_customer(client, auth, "Multi Site Original")
    first = _create_site(client, auth, original["id"], "150 Multi Site First")
    second = _create_site(client, auth, original["id"], "151 Multi Site Second")
    renamed = f"{TEST_PREFIX} Customer Multi Site Renamed"

    rename_response = client.patch(
        f"/api/admin/locations/{first['id']}",
        headers=auth,
        json={"customerName": renamed},
    )
    assert rename_response.status_code == 200, rename_response.text
    assert _customer_row(original["id"])["name"] == renamed
    assert {
        row["customer_name"]
        for row in (
            _location_row(first["id"]),
            _location_row(second["id"]),
        )
    } == {renamed}

    target = _create_customer(client, auth, "Multi Site Target")
    reassign_response = client.patch(
        f"/api/admin/locations/{second['id']}",
        headers=auth,
        json={"customerId": target["id"]},
    )
    assert reassign_response.status_code == 200, reassign_response.text
    reassigned = reassign_response.json()["location"]
    assert reassigned["customerId"] == target["id"]
    assert reassigned["customerName"] == target["name"]
    assert _location_row(first["id"])["customer_id"] == original["id"]
    assert _location_row(second["id"])["customer_id"] == target["id"]

    original_detail = client.get(
        f"/api/admin/customers/{original['id']}",
        headers=auth,
    ).json()["customer"]
    target_detail = client.get(
        f"/api/admin/customers/{target['id']}",
        headers=auth,
    ).json()["customer"]
    assert [site["id"] for site in original_detail["sites"]] == [first["id"]]
    assert [site["id"] for site in target_detail["sites"]] == [second["id"]]


def test_stale_time_save_cannot_recreate_a_renamed_site_or_repoint_history(
    client,
    auth,
):
    import time_tracker_api as api

    customer = _create_customer(client, auth, "Stale Time Save")
    site = _create_site(client, auth, customer["id"], "175 Original Address")
    old_address = site["address"]
    new_address = f"{TEST_PREFIX} 175 Renamed Address, Effingham, IL 62401"

    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM employees WHERE name = 'Catalina Gomez'")
            employee_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, clock_in, clock_out,
                    total_hours, notes, local_date
                )
                VALUES (%s, %s, %s, NOW() - INTERVAL '2 hours', NOW(), 2.0,
                        'stale Site snapshot proof', CURRENT_DATE)
                RETURNING id
                """,
                (employee_id, site["id"], old_address),
            )
            shift_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()

    stale_snapshot = api._load_timesheets_from_db()
    pre_shift_ids = {entry["id"] for entry in stale_snapshot["entries"]}
    pre_visit_counts = {
        entry["id"]: len(entry.get("visits", []))
        for entry in stale_snapshot["entries"]
    }
    pre_departure_counts = {
        entry["id"]: len(entry.get("departures", []))
        for entry in stale_snapshot["entries"]
    }

    renamed = client.patch(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
        json={"address": new_address},
    )
    assert renamed.status_code == 200, renamed.text

    replacement_customer = _create_customer(client, auth, "Stale Replacement")
    replacement_response = client.post(
        f"/api/admin/customers/{replacement_customer['id']}/locations",
        headers=auth,
        json={"address": old_address, "locationType": "Commercial"},
    )
    assert replacement_response.status_code == 201, replacement_response.text
    replacement_site = replacement_response.json()["location"]

    api._save_timesheets_to_db(
        stale_snapshot,
        pre_shift_ids,
        pre_visit_counts,
        pre_departure_counts,
    )

    assert api.db.query_one(
        "SELECT id FROM locations WHERE address = %s",
        (old_address,),
    ) == {"id": replacement_site["id"]}
    assert api.db.query_one(
        "SELECT address FROM locations WHERE id = %s",
        (site["id"],),
    ) == {"address": new_address}
    assert api.db.query_one(
        "SELECT location_id FROM shifts WHERE id = %s",
        (shift_id,),
    ) == {"location_id": site["id"]}


def test_existing_manual_shift_backfills_site_fk_after_site_creation(
    client,
    auth,
    emp_auth,
):
    import db

    address = f"{TEST_PREFIX} 176 Later Site, Effingham, IL 62401"
    clock_in = client.post(
        "/api/timesheet/clock-in",
        headers=emp_auth,
        json={
            "location": address,
            "gpsOverrideReason": "customer_request",
            "gpsOverrideDetail": "Site is not configured yet",
        },
    )
    assert clock_in.status_code == 200, clock_in.text
    shift_id = clock_in.json()["entry"]["id"]
    assert db.query_one(
        "SELECT location_id, location_label FROM shifts WHERE id = %s",
        (shift_id,),
    ) == {"location_id": None, "location_label": address}

    customer = _create_customer(client, auth, "Later Site")
    site = _create_site(client, auth, customer["id"], "176 Later Site")
    assert site["address"] == address

    clock_out = client.post(
        "/api/timesheet/clock-out",
        headers=emp_auth,
        json={
            "gpsOverrideReason": "customer_request",
            "gpsOverrideDetail": "Committed Site FK backfill proof",
        },
    )
    assert clock_out.status_code == 200, clock_out.text
    assert db.query_one(
        "SELECT location_id, location_label FROM shifts WHERE id = %s",
        (shift_id,),
    ) == {"location_id": site["id"], "location_label": address}


def test_customer_with_primary_site_rolls_back_as_one_transaction_on_conflict(
    client,
    auth,
):
    owner = _create_customer(client, auth, "Primary Owner")
    existing = _create_site(
        client,
        auth,
        owner["id"],
        "200 Atomic Road, Suite 4",
    )
    losing_customer_name = f"{TEST_PREFIX} Customer Must Roll Back"

    response = client.post(
        "/api/admin/customers",
        headers=auth,
        json={
            "name": losing_customer_name,
            "primaryEmail": "rollback@example.test",
            "primarySite": {
                "address": "  issue 19 api 200 ATOMIC ROAD , SUITE 4 , EFFINGHAM, IL 62401  ",
                "locationType": "Commercial",
            },
        },
    )
    assert response.status_code == 409, response.text
    error = response.json()
    assert error["code"] == "duplicate_site_address"
    assert error["details"]["siteId"] == existing["id"]
    assert error["details"]["customerId"] == owner["id"]

    import db

    assert db.query_one(
        "SELECT id FROM customers WHERE name = %s",
        (losing_customer_name,),
    ) is None


def test_active_and_archived_duplicate_addresses_return_actionable_conflicts(
    client,
    auth,
):
    owner = _create_customer(client, auth, "Duplicate Owner")
    site = _create_site(
        client,
        auth,
        owner["id"],
        "300 Duplicate Avenue, Unit B",
    )
    duplicate_payload = {
        "customerName": f"{TEST_PREFIX} Duplicate Attempt",
        "address": " issue 19 api 300 DUPLICATE AVENUE , UNIT B , EFFINGHAM, IL 62401 ",
        "locationType": "Commercial",
    }

    active_duplicate = client.post(
        "/api/admin/locations",
        headers=auth,
        json=duplicate_payload,
    )
    assert active_duplicate.status_code == 409, active_duplicate.text
    assert active_duplicate.json()["code"] == "duplicate_site_address"
    assert active_duplicate.json()["details"]["customerId"] == owner["id"]
    assert active_duplicate.json()["details"]["siteId"] == site["id"]

    archived = client.delete(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
    )
    assert archived.status_code == 200, archived.text

    archived_duplicate = client.post(
        "/api/admin/locations",
        headers=auth,
        json=duplicate_payload,
    )
    assert archived_duplicate.status_code == 409, archived_duplicate.text
    assert archived_duplicate.json()["code"] == "archived_site_address"
    assert archived_duplicate.json()["details"]["customerId"] == owner["id"]
    assert archived_duplicate.json()["details"]["siteId"] == site["id"]
    assert archived_duplicate.json()["details"]["canRestore"] is True

    import db

    assert db.query_one(
        "SELECT id FROM customers WHERE name = %s",
        (duplicate_payload["customerName"],),
    ) is None


def test_concurrent_customer_and_primary_site_creates_have_one_winner(
    client,
    auth,
):
    start = Barrier(2)
    payloads = [
        {
            "name": f"{TEST_PREFIX} Race Customer A",
            "primarySite": {
                "address": f"{TEST_PREFIX} 400 Race Street, Suite 9, Effingham, IL",
                "locationType": "Commercial",
            },
        },
        {
            "name": f"{TEST_PREFIX} Race Customer B",
            "primarySite": {
                "address": " issue 19 api 400 RACE STREET , SUITE 9 , EFFINGHAM, IL ",
                "locationType": "Commercial",
            },
        },
    ]

    def create(payload):
        start.wait(timeout=10)
        return client.post("/api/admin/customers", headers=auth, json=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = [future.result(timeout=20) for future in [
            pool.submit(create, payload) for payload in payloads
        ]]

    assert sorted(response.status_code for response in responses) == [201, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["code"] == "duplicate_site_address"

    import db

    customer_rows = db.query_all(
        "SELECT id, name FROM customers WHERE name IN (%s, %s)",
        (payloads[0]["name"], payloads[1]["name"]),
    )
    assert len(customer_rows) == 1
    winner_site = db.query_one(
        "SELECT id, address_key FROM locations WHERE customer_id = %s",
        (customer_rows[0]["id"],),
    )
    assert winner_site is not None
    assert winner_site["address_key"] is not None
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM locations WHERE address_key = %s",
        (winner_site["address_key"],),
    )["count"] == 1


def _seed_historical_site_references(location_id: int, customer_name: str):
    now = datetime.now(timezone.utc)
    past_start = now - timedelta(days=10)
    future_start = now + timedelta(days=10)
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM employees WHERE name = 'Juan Canfield'")
            admin_id = cur.fetchone()[0]
            cur.execute("SELECT id FROM employees WHERE name = 'Catalina Gomez'")
            employee_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date,
                    expected_hours, revenue, notes, status
                ) VALUES (%s, %s, %s, 2.0, 150.0, 'history proof', 'completed')
                RETURNING id
                """,
                (location_id, customer_name, past_start.date()),
            )
            job_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label, clock_in, clock_out,
                    total_hours, notes, local_date, job_id
                ) VALUES (%s, %s, %s, %s, %s, 2.0, 'history proof', %s, %s)
                RETURNING id
                """,
                (
                    employee_id,
                    location_id,
                    f"{TEST_PREFIX} historical site",
                    past_start,
                    past_start + timedelta(hours=2),
                    past_start.date(),
                    job_id,
                ),
            )
            shift_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, job_id
                ) VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    shift_id,
                    location_id,
                    f"{TEST_PREFIX} historical site",
                    customer_name,
                    past_start,
                    job_id,
                ),
            )
            visit_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO departures (
                    shift_id, location_id, location_label, customer_name,
                    departure_time
                ) VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    shift_id,
                    location_id,
                    f"{TEST_PREFIX} historical site",
                    customer_name,
                    past_start + timedelta(hours=2),
                ),
            )
            departure_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO schedules (
                    employee_id, location_id, customer_name, week_start,
                    scheduled_hours, notes
                ) VALUES (%s, %s, %s, %s, 2.0, 'history proof')
                RETURNING id
                """,
                (employee_id, location_id, customer_name, past_start.date()),
            )
            weekly_schedule_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO site_check_in_schedules (
                    employee_id, location_id, scheduled_start,
                    grace_minutes, created_by
                ) VALUES (%s, %s, %s, 10, %s)
                RETURNING id
                """,
                (employee_id, location_id, past_start, admin_id),
            )
            past_schedule_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO site_check_in_schedules (
                    employee_id, location_id, scheduled_start,
                    grace_minutes, created_by
                ) VALUES (%s, %s, %s, 10, %s)
                RETURNING id
                """,
                (employee_id, location_id, future_start, admin_id),
            )
            future_schedule_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO site_check_in_schedule_rules (
                    employee_id, location_id, weekdays, local_start_time,
                    timezone, starts_on, grace_minutes, active, created_by
                ) VALUES (%s, %s, ARRAY[0,1,2,3,4]::SMALLINT[], '07:00',
                          'America/Chicago', %s, 10, true, %s)
                RETURNING id
                """,
                (employee_id, location_id, past_start.date(), admin_id),
            )
            rule_id = cur.fetchone()[0]
            second_rule_ends_on = (future_start + timedelta(days=20)).date()
            cur.execute(
                """
                INSERT INTO site_check_in_schedule_rules (
                    employee_id, location_id, weekdays, local_start_time,
                    timezone, starts_on, ends_on, grace_minutes, active,
                    created_by
                ) VALUES (
                    %s, %s, ARRAY[0,1,2,3,4]::SMALLINT[], '07:00',
                    'America/Chicago', %s, %s, 10, true, %s
                )
                RETURNING id
                """,
                (
                    employee_id,
                    location_id,
                    past_start.date(),
                    second_rule_ends_on,
                    admin_id,
                ),
            )
            second_rule_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO site_check_ins (
                    employee_id, location_id, server_checked_in_at,
                    device_scanned_at, latitude, longitude, accuracy_m,
                    geofence_radius_m, distance_m, geofence_status,
                    classification, classification_reason, schedule_id,
                    scheduled_start, grace_minutes, device_clock_skew_seconds,
                    review_status
                ) VALUES (
                    %s, %s, %s, %s, 39.1203, -88.54335, 5.0,
                    150, 1.0, 'inside', 'on_time', 'within_grace', %s,
                    %s, 10, 0, 'not_required'
                ) RETURNING id
                """,
                (
                    employee_id,
                    location_id,
                    past_start,
                    past_start,
                    past_schedule_id,
                    past_start,
                ),
            )
            check_in_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO site_check_in_reconciliation_reviews (
                    occurrence_key, evidence_fingerprint, employee_id,
                    location_id, scheduled_start, outcome, evidence,
                    disposition, note, reviewed_by, reviewed_by_name
                ) VALUES (
                    %s, %s, %s, %s, %s, 'matched', %s,
                    'resolved', 'Historical evidence retained', %s,
                    'Juan Canfield'
                ) RETURNING id
                """,
                (
                    f"{TEST_PREFIX}-occurrence-{location_id}",
                    "a" * 64,
                    employee_id,
                    location_id,
                    past_start,
                    psycopg2.extras.Json({"checkInId": check_in_id}),
                    admin_id,
                ),
            )
            reconciliation_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    return {
        "admin_id": admin_id,
        "job_id": job_id,
        "shift_id": shift_id,
        "visit_id": visit_id,
        "departure_id": departure_id,
        "weekly_schedule_id": weekly_schedule_id,
        "past_schedule_id": past_schedule_id,
        "future_schedule_id": future_schedule_id,
        "future_start": future_start,
        "employee_id": employee_id,
        "rule_id": rule_id,
        "second_rule_id": second_rule_id,
        "second_rule_ends_on": second_rule_ends_on,
        "past_date": past_start.date(),
        "check_in_id": check_in_id,
        "reconciliation_id": reconciliation_id,
    }


def test_site_archive_restore_preserves_history_and_retires_future_qr_state(
    client,
    auth,
    emp_auth,
):
    import db

    customer = _create_customer(client, auth, "Archive History")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "500 Archive History Drive",
        rate=175.0,
        rateType="per_visit",
        expectedHours=4.0,
        lat=39.1203,
        lng=-88.54335,
    )
    site_id = site["id"]
    qr = client.post(
        f"/api/admin/locations/{site_id}/check-in-qr",
        headers=auth,
        json={"rotate": False},
    )
    assert qr.status_code == 200, qr.text
    old_token = qr.json()["token"]
    old_nonce = db.query_one(
        "SELECT check_in_token_nonce FROM locations WHERE id = %s",
        (site_id,),
    )["check_in_token_nonce"]
    references = _seed_historical_site_references(site_id, customer["name"])

    archived = client.delete(f"/api/admin/locations/{site_id}", headers=auth)
    assert archived.status_code == 200, archived.text
    archived_location = archived.json()["location"]
    assert archived_location["id"] == site_id
    assert archived_location["active"] is False
    assert archived_location["archivedAt"] is not None
    assert archived_location["qrConfigured"] is False

    archived_again = client.delete(
        f"/api/admin/locations/{site_id}",
        headers=auth,
    )
    assert archived_again.status_code == 200, archived_again.text
    assert archived_again.json()["location"] == archived_location

    active_list = client.get("/api/admin/locations", headers=auth)
    assert active_list.status_code == 200, active_list.text
    assert site_id not in {row["id"] for row in active_list.json()["locations"]}
    complete_list = client.get(
        "/api/admin/locations?includeArchived=true",
        headers=auth,
    )
    assert complete_list.status_code == 200, complete_list.text
    assert site_id in {row["id"] for row in complete_list.json()["locations"]}

    employee_locations = client.get("/api/timesheet/locations", headers=emp_auth)
    assert employee_locations.status_code == 200, employee_locations.text
    assert site_id not in {
        row["id"] for row in employee_locations.json()["sites"]
    }
    # Restore only the stale nonce to prove both QR endpoints independently
    # reject an inactive Site instead of relying on archive-time nonce clearing.
    db.execute(
        "UPDATE locations SET check_in_token_nonce = %s WHERE id = %s",
        (old_nonce, site_id),
    )
    expired_qr = client.post(
        "/api/timesheet/site-check-in/resolve",
        headers=emp_auth,
        json={"token": old_token},
    )
    assert expired_qr.status_code == 404
    rejected_check_in = client.post(
        "/api/timesheet/site-check-in",
        headers=emp_auth,
        json={
            "employeeId": references["employee_id"],
            "siteId": site_id,
            "token": old_token,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "latitude": 39.1203,
            "longitude": -88.54335,
            "accuracy": 5.0,
        },
    )
    assert rejected_check_in.status_code == 404, rejected_check_in.text
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM site_check_ins WHERE location_id = %s",
        (site_id,),
    ) == {"count": 1}
    db.execute(
        "UPDATE locations SET check_in_token_nonce = NULL WHERE id = %s",
        (site_id,),
    )

    # An ordinary time write reloads and saves the complete legacy timesheet
    # projection. It must not erase the archived Site FK from older evidence.
    clocked_in = client.post(
        "/api/timesheet/clock-in",
        headers=emp_auth,
        json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1203,
            "longitude": -88.54335,
        },
    )
    assert clocked_in.status_code == 200, clocked_in.text
    clocked_out = client.post(
        "/api/timesheet/clock-out",
        headers=emp_auth,
        json={
            "latitude": 39.1203,
            "longitude": -88.54335,
        },
    )
    assert clocked_out.status_code == 200, clocked_out.text

    persisted_site = db.query_one(
        """
        SELECT active, check_in_token_nonce, archived_at, archived_by
        FROM locations WHERE id = %s
        """,
        (site_id,),
    )
    assert persisted_site["active"] is False
    assert persisted_site["check_in_token_nonce"] is None
    assert persisted_site["archived_at"] is not None
    assert persisted_site["archived_by"] == references["admin_id"]

    exact_schedules = db.query_all(
        """
        SELECT id, cancelled_at, cancelled_by, cancellation_reason
        FROM site_check_in_schedules
        WHERE id IN (%s, %s)
        ORDER BY id
        """,
        (references["past_schedule_id"], references["future_schedule_id"]),
    )
    exact_by_id = {row["id"]: row for row in exact_schedules}
    assert exact_by_id[references["past_schedule_id"]]["cancelled_at"] is None
    future = exact_by_id[references["future_schedule_id"]]
    assert future["cancelled_at"] is not None
    assert future["cancelled_by"] == references["admin_id"]
    assert "archive" in future["cancellation_reason"].lower()
    import time_tracker_api as api

    assert api._matching_site_check_in_schedule(
        references["employee_id"],
        site_id,
        references["future_start"],
    ) is None
    archived_rules = db.query_all(
        """
        SELECT id, active, NULLIF(ends_on, 'infinity'::date) AS ends_on
        FROM site_check_in_schedule_rules
        WHERE id IN (%s, %s)
        ORDER BY id
        """,
        (references["rule_id"], references["second_rule_id"]),
    )
    assert len(archived_rules) == 2
    assert all(row["active"] is False for row in archived_rules)
    assert archived_rules[0]["ends_on"] is None
    assert archived_rules[1]["ends_on"] == references["second_rule_ends_on"]

    for table, row_id in (
        ("jobs", references["job_id"]),
        ("shifts", references["shift_id"]),
        ("visits", references["visit_id"]),
        ("departures", references["departure_id"]),
        ("schedules", references["weekly_schedule_id"]),
        ("site_check_ins", references["check_in_id"]),
        (
            "site_check_in_reconciliation_reviews",
            references["reconciliation_id"],
        ),
    ):
        assert db.query_one(
            f"SELECT location_id FROM {table} WHERE id = %s",
            (row_id,),
        ) == {"location_id": site_id}

    job_detail = client.get(
        f"/api/admin/jobs/{references['job_id']}",
        headers=auth,
    )
    assert job_detail.status_code == 200, job_detail.text
    check_ins = client.get("/api/admin/site-check-ins", headers=auth)
    assert check_ins.status_code == 200, check_ins.text
    assert references["check_in_id"] in {
        row["id"] for row in check_ins.json()["checkIns"]
    }

    hours_report = client.get(
        "/api/admin/reports/hours",
        headers=auth,
        params={"period": "month", "date": references["past_date"].isoformat()},
    )
    assert hours_report.status_code == 200, hours_report.text
    historical_rows = [
        row
        for row in hours_report.json()["rows"]
        if row["location"] == site["address"]
    ]
    assert historical_rows
    assert {row["customer"] for row in historical_rows} == {customer["name"]}

    analytics = client.get(
        "/api/admin/analytics",
        headers=auth,
        params={"period": "all"},
    )
    assert analytics.status_code == 200, analytics.text
    archived_customer_rows = [
        row
        for row in analytics.json()["byCustomer"]
        if row["customer"] == customer["name"]
    ]
    assert archived_customer_rows
    assert archived_customer_rows[0]["revenue"] > 0

    forecast = client.get("/api/admin/analytics/forecast", headers=auth)
    assert forecast.status_code == 200, forecast.text
    forecast_customer_rows = [
        row
        for week in forecast.json()["forecasts"]
        for row in week["byCustomer"]
        if row["customer"] == customer["name"]
    ]
    assert forecast_customer_rows == []

    restored = client.post(
        f"/api/admin/locations/{site_id}/restore",
        headers=auth,
    )
    assert restored.status_code == 200, restored.text
    restored_location = restored.json()["location"]
    assert restored_location["active"] is True
    assert restored_location["qrConfigured"] is False
    assert client.post(
        "/api/timesheet/site-check-in/resolve",
        headers=emp_auth,
        json={"token": old_token},
    ).status_code == 404
    assert db.query_one(
        "SELECT cancelled_at FROM site_check_in_schedules WHERE id = %s",
        (references["future_schedule_id"],),
    )["cancelled_at"] is not None
    assert all(
        row["active"] is False
        for row in db.query_all(
            "SELECT active FROM site_check_in_schedule_rules WHERE id IN (%s, %s)",
            (references["rule_id"], references["second_rule_id"]),
        )
    )


def test_customer_archive_requires_sites_archived_and_restore_order(client, auth):
    customer = _create_customer(client, auth, "Lifecycle")
    site = _create_site(
        client,
        auth,
        customer["id"],
        "600 Lifecycle Court",
    )

    blocked_customer_archive = client.delete(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
    )
    assert blocked_customer_archive.status_code == 409
    assert blocked_customer_archive.json()["code"] == "customer_has_active_sites"
    active_sites = blocked_customer_archive.json()["details"]["activeSites"]
    assert any(
        row["id"] == site["id"] and row["address"] == site["address"]
        for row in active_sites
    )

    assert client.delete(
        f"/api/admin/locations/{site['id']}",
        headers=auth,
    ).status_code == 200
    archived_customer = client.delete(
        f"/api/admin/customers/{customer['id']}",
        headers=auth,
    )
    assert archived_customer.status_code == 200, archived_customer.text
    assert archived_customer.json()["customer"]["active"] is False

    blocked_site_restore = client.post(
        f"/api/admin/locations/{site['id']}/restore",
        headers=auth,
    )
    assert blocked_site_restore.status_code == 409
    assert blocked_site_restore.json()["code"] == "customer_archived"

    restored_customer = client.post(
        f"/api/admin/customers/{customer['id']}/restore",
        headers=auth,
    )
    assert restored_customer.status_code == 200, restored_customer.text
    assert restored_customer.json()["customer"]["active"] is True
    restored_site = client.post(
        f"/api/admin/locations/{site['id']}/restore",
        headers=auth,
    )
    assert restored_site.status_code == 200, restored_site.text
    assert restored_site.json()["location"]["active"] is True
