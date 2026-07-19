"""Safety tests for the customer batch importer tracked by issue #19."""

from __future__ import annotations

import sys

import batch_import_customers as importer


def test_import_plan_updates_only_fields_present_in_source():
    existing = [
        {
            "id": 44,
            "address": "1810 Ave of Mid-America, Effingham, IL",
            "customerName": "Firefly",
            "locationType": "Commercial",
            "rate": 27.0,
            "rateType": "hourly",
            "frequency": "Weekdays",
            "latitude": 39.1,
            "longitude": -88.5,
            "expectedHours": 4.0,
            "targetLaborPct": 30.0,
            "minMarginPct": 25.0,
            "active": True,
        }
    ]
    imported = [
        {
            "address": "1810 ave of mid-america , Effingham, IL",
            "customerName": "Firefly Grill",
            "locationType": "Commercial",
            "rateType": "hourly",
        }
    ]

    plan = importer.build_import_plan(imported, existing)

    assert plan["conflicts"] == []
    operation = plan["operations"][0]
    assert operation["action"] == "update"
    assert operation["locationId"] == 44
    assert operation["payload"] == {"customerName": "Firefly Grill"}
    assert "expectedHours" not in operation["payload"]
    assert "targetLaborPct" not in operation["payload"]
    assert "minMarginPct" not in operation["payload"]
    assert "lat" not in operation["payload"]
    assert "lng" not in operation["payload"]


def test_importer_authenticates_with_name_and_uses_atomic_create(monkeypatch):
    calls = []

    def fake_api_call(url, method, body=None, token=None):
        calls.append((url, method, body, token))
        if url.endswith("/api/auth/login"):
            return {"token": "admin-token"}
        if "/api/admin/locations?" in url:
            return {"locations": []}
        if url.endswith("/api/admin/locations") and method == "POST":
            return {"success": True, "location": {"id": 91}}
        raise AssertionError((url, method, body, token))

    monkeypatch.setattr(importer, "api_call", fake_api_call)
    monkeypatch.setattr(importer, "geocode", lambda _address: (39.12, -88.54))
    monkeypatch.setattr(
        importer,
        "CUSTOMERS",
        [
            {
                "customer": "Importer Test",
                "address": "1906 Importer Rd, Effingham, IL",
                "type": "Residential",
                "rate": 150.0,
                "rateType": "per_visit",
            }
        ],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch_import_customers.py",
            "--url",
            "https://example.test",
            "--username",
            "Juan Canfield",
            "--password",
            "secret",
            "--apply",
        ],
    )

    importer.main()

    login = calls[0]
    assert login[1] == "POST"
    assert login[2] == {"name": "Juan Canfield", "password": "secret"}
    writes = [call for call in calls if call[1] in {"PUT", "POST", "PATCH"}][1:]
    assert len(writes) == 1
    assert writes[0][1] == "POST"
    assert writes[0][0].endswith("/api/admin/locations")
    assert all(call[1] != "PUT" for call in calls)


def test_importer_is_preview_only_without_apply(monkeypatch):
    calls = []

    def fake_api_call(url, method, body=None, token=None):
        calls.append((url, method, body, token))
        if url.endswith("/api/auth/login"):
            return {"token": "admin-token"}
        if "/api/admin/locations?" in url:
            return {"locations": []}
        raise AssertionError("preview attempted to write")

    monkeypatch.setattr(importer, "api_call", fake_api_call)
    monkeypatch.setattr(importer, "geocode", lambda _address: None)
    monkeypatch.setattr(
        importer,
        "CUSTOMERS",
        [
            {
                "customer": "Preview Test",
                "address": "1907 Preview Rd, Effingham, IL",
                "type": "Residential",
            }
        ],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch_import_customers.py",
            "--url",
            "https://example.test",
            "--username",
            "Juan Canfield",
            "--password",
            "secret",
        ],
    )

    importer.main()

    assert [call[1] for call in calls] == ["POST", "GET"]
