"""Focused contract tests for the safe Customer/Site batch importer."""

from __future__ import annotations

from copy import deepcopy
import json

import batch_import_customers as importer
import pytest


def _site(site_id: int, **overrides):
    row = {
        "id": site_id,
        "customerName": "Existing Customer",
        "address": f"{site_id} Test St, Effingham, IL 62401",
        "locationType": "Commercial",
        "rate": 100.0,
        "rateType": "per_visit",
        "frequency": None,
        "expectedHours": None,
        "targetLaborPct": None,
        "minMarginPct": None,
        "latitude": None,
        "longitude": None,
        "serviceScope": None,
        "accessInstructions": None,
        "servicePreferences": None,
        "petNotes": None,
        "serviceStartDate": None,
        "active": True,
        "migrationReview": [],
    }
    row.update(overrides)
    return row


class FakeApi:
    def __init__(
        self,
        locations=(),
        *,
        fail_mutation_number=None,
        fail_message="Site was not saved",
    ):
        self.locations = [deepcopy(row) for row in locations]
        self.calls = []
        self.mutation_count = 0
        self.fail_mutation_number = fail_mutation_number
        self.fail_message = fail_message

    def __call__(self, url, method, body=None, token=None):
        self.calls.append(
            {
                "url": url,
                "method": method,
                "body": deepcopy(body),
                "token": token,
            }
        )
        if url.endswith("/api/auth/login"):
            return {"token": "server-secret-token"}
        if method == "GET" and "/api/admin/locations?" in url:
            return {"success": True, "locations": deepcopy(self.locations)}
        if method not in {"POST", "PATCH"}:
            raise AssertionError(f"unexpected API call: {method} {url}")

        self.mutation_count += 1
        if self.mutation_count == self.fail_mutation_number:
            raise importer.ApiError(503, "write_unavailable", self.fail_message)

        if method == "POST":
            location = _site(max((row["id"] for row in self.locations), default=0) + 1)
        else:
            site_id = int(url.rsplit("/", 1)[-1])
            location = next(row for row in self.locations if row["id"] == site_id)

        for field, value in (body or {}).items():
            if field == "lat":
                location["latitude"] = value
            elif field == "lng":
                location["longitude"] = value
            else:
                location[field] = value
        if method == "POST":
            location.setdefault("rateType", "per_visit")
            self.locations.append(location)
        return {"success": True, "location": deepcopy(location)}


def _source(customer, address, location_type="Commercial", **fields):
    return {
        "customer": customer,
        "address": address,
        "type": location_type,
        **fields,
    }


def test_login_uses_name_and_default_preview_performs_no_mutations():
    existing = _site(
        8,
        customerName="Firefly Grill",
        address="1810 Ave of Mid-America, Effingham, IL 62401",
        locationType="Commercial",
        rate=27.0,
        rateType="hourly",
        latitude=39.12,
        longitude=-88.54,
    )
    api = FakeApi([existing])
    output = []

    result = importer.run_import(
        base_url="https://example.test/",
        name="Juan Canfield",
        password="do-not-print-this",
        apply=False,
        sources=[
            _source(
                "Firefly Grill",
                "1810 Ave of Mid-America, Effingham, IL 62401",
                rate=27.0,
                rateType="hourly",
            )
        ],
        api_client=api,
        geocoder=lambda _address: (_ for _ in ()).throw(
            AssertionError("an existing pin must not be geocoded again")
        ),
        sleep_fn=lambda _seconds: None,
        output=output.append,
    )

    assert result == 0
    assert api.calls[0]["body"] == {
        "name": "Juan Canfield",
        "password": "do-not-print-this",
    }
    assert [call["method"] for call in api.calls] == ["POST", "GET"]
    assert "do-not-print-this" not in "\n".join(output)
    assert "server-secret-token" not in "\n".join(output)
    assert importer.build_parser().parse_args(
        ["--username", "Juan", "--password", "secret"]
    ).apply is False
    assert importer.build_parser().parse_args(
        ["--username", "Juan", "--password", "secret", "--dry-run"]
    ).apply is False


def test_plan_classifies_create_update_unchanged_and_conflict_with_exact_diffs():
    update_site = _site(
        1,
        customerName="Rate Change",
        address="1 Update St, Effingham, IL 62401",
        rate=100.0,
        targetLaborPct=31.0,
        latitude=39.1,
        longitude=-88.5,
    )
    unchanged_site = _site(
        2,
        customerName="No Change",
        address="2 Same St, Effingham, IL 62401",
        rate=125.0,
        rateType="hourly",
        latitude=39.2,
        longitude=-88.6,
    )
    archived_site = _site(
        3,
        customerName="Archived",
        address="3 Old St, Effingham, IL 62401",
        active=False,
    )
    geocoded = []
    plan = importer.build_import_plan(
        [
            _source("Rate Change", update_site["address"], rate=150.0),
            _source(
                "No Change",
                unchanged_site["address"],
                rate=125.0,
                rateType="hourly",
            ),
            _source("Brand New", "4 New St, Effingham, IL 62401"),
            _source("Archived", archived_site["address"]),
        ],
        [update_site, unchanged_site, archived_site],
        geocoder=lambda address: geocoded.append(address) or None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert plan.counts() == {
        "create": 1,
        "update": 1,
        "unchanged": 1,
        "conflict": 1,
    }
    update = plan.actions[0]
    assert update.action == "update"
    assert update.payload == {"rate": 150.0}
    assert update.changes == {"rate": {"from": 100.0, "to": 150.0}}
    assert "targetLaborPct" not in update.payload
    created = plan.actions[2]
    assert created.action == "create"
    assert "rate" not in created.payload
    assert "rateType" not in created.payload
    assert "lat" not in created.payload and "lng" not in created.payload
    assert plan.actions[3].conflict_code == "archived_site_address"
    assert geocoded == ["4 New St, Effingham, IL 62401"]


def test_apply_is_blocked_before_every_mutation_when_preview_has_a_conflict():
    archived = _site(
        5,
        customerName="Archived",
        address="5 Archived Ave, Effingham, IL 62401",
        active=False,
    )
    api = FakeApi([archived])

    result = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[
            _source("New", "6 New Ave, Effingham, IL 62401"),
            _source("Archived", archived["address"]),
        ],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert result == 2
    assert api.mutation_count == 0
    assert [call["method"] for call in api.calls] == ["POST", "GET"]


@pytest.mark.parametrize(
    ("overrides", "error_fragment"),
    [
        ({"customerName": 7}, "customerName must be a string"),
        ({"customerName": "C" * 201}, "customerName must be at most 200"),
        ({"address": 99}, "address must be a string"),
        ({"address": "A" * 501}, "address must be at most 500"),
        ({"locationType": "Warehouse"}, "locationType must be one of"),
        ({"rate": True}, "rate must be a number"),
        ({"rate": float("nan")}, "rate must be finite"),
        ({"rate": 1_000_000}, "rate must be between 0 and 999999.99"),
        ({"rate": 10**1_000}, "rate must be between 0 and 999999.99"),
        ({"rateType": "weekly"}, "rateType must be one of"),
        ({"frequency": 14}, "frequency must be a string"),
        ({"frequency": "F" * 101}, "frequency must be at most 100"),
        ({"expectedHours": 10_000}, "expectedHours must be between 0 and 9999.99"),
        ({"targetLaborPct": -0.01}, "targetLaborPct must be between 0 and 100"),
        ({"minMarginPct": 100.01}, "minMarginPct must be between 0 and 100"),
        ({"serviceScope": "S" * 4_001}, "serviceScope must be at most 4000"),
        (
            {"accessInstructions": "A" * 4_001},
            "accessInstructions must be at most 4000",
        ),
        (
            {"servicePreferences": "P" * 4_001},
            "servicePreferences must be at most 4000",
        ),
        ({"petNotes": "P" * 2_001}, "petNotes must be at most 2000"),
        ({"serviceStartDate": "2026-7-01"}, "must be an ISO YYYY-MM-DD date"),
        ({"serviceStartDate": "2026-02-30"}, "must be a valid calendar date"),
        ({"lat": 91, "lng": -88.5}, "lat must be between -90 and 90"),
        ({"lat": 39.1, "lng": -181}, "lng must be between -180 and 180"),
        ({"lat": 39.1}, "lat and lng must both be populated or both omitted"),
    ],
)
def test_plan_preflights_every_supported_site_field(overrides, error_fragment):
    source = _source("Valid Customer", "40 Validation St, Effingham, IL 62401")
    source.update(overrides)

    plan = importer.build_import_plan(
        [source],
        [],
        geocoder=lambda _address: (_ for _ in ()).throw(
            AssertionError("invalid source rows must not be geocoded")
        ),
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert plan.counts() == {
        "create": 0,
        "update": 0,
        "unchanged": 0,
        "conflict": 1,
    }
    action = plan.actions[0]
    assert action.conflict_code == "invalid_source_row"
    assert error_fragment in (action.conflict_message or "")


@pytest.mark.parametrize(
    "coordinates",
    [
        (90.01, -88.5),
        (39.1, 180.01),
        ("39.1", -88.5),
        (True, -88.5),
        (float("inf"), -88.5),
        (39.1,),
        "39.1,-88.5",
    ],
)
def test_plan_rejects_invalid_geocoder_coordinates(coordinates):
    plan = importer.build_import_plan(
        [_source("Geocode", "41 Geocode St, Effingham, IL 62401")],
        [],
        geocoder=lambda _address: coordinates,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert plan.actions[0].action == "conflict"
    assert plan.actions[0].conflict_code == "invalid_geocode_coordinates"


def test_invalid_later_row_blocks_apply_before_every_mutation():
    api = FakeApi()

    result = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[
            _source("Valid First", "42 Valid First St, Effingham, IL 62401"),
            _source(
                "Invalid Second",
                "43 Invalid Second St, Effingham, IL 62401",
                rateType="not-a-rate-type",
            ),
        ],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert result == 2
    assert api.mutation_count == 0
    assert [call["method"] for call in api.calls] == ["POST", "GET"]


def test_blank_optional_strings_are_omitted_and_reruns_converge():
    api = FakeApi()
    source = _source(
        "  Blank Safe  ",
        "  44 Blank Safe St, Effingham, IL 62401  ",
        rateType="   ",
        frequency="   ",
        serviceScope="   ",
        accessInstructions="   ",
        servicePreferences="   ",
        petNotes="   ",
        serviceStartDate="   ",
    )

    first = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[source],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )
    second = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[source],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    mutations = [
        call
        for call in api.calls
        if call["url"].endswith("/api/admin/locations")
    ]
    assert first == 0
    assert second == 0
    assert api.mutation_count == 1
    assert [call["body"] for call in mutations] == [
        {
            "customerName": "Blank Safe",
            "address": "44 Blank Safe St, Effingham, IL 62401",
            "locationType": "Commercial",
        }
    ]


def test_contract_boundaries_and_exact_valid_date_are_accepted():
    source = _source(
        "C" * 200,
        "A" * 500,
        location_type="Residential",
        rate=999_999.99,
        rateType="monthly",
        frequency="F" * 100,
        expectedHours=9_999.99,
        targetLaborPct=100,
        minMarginPct=0,
        serviceScope="S" * 4_000,
        accessInstructions="A" * 4_000,
        servicePreferences="P" * 4_000,
        petNotes="N" * 2_000,
        serviceStartDate="2028-02-29",
        lat=90,
        lng=180,
    )

    plan = importer.build_import_plan(
        [source],
        [],
        geocoder=lambda _address: (_ for _ in ()).throw(
            AssertionError("explicit valid coordinates must not be geocoded")
        ),
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert plan.actions[0].action == "create"
    assert plan.actions[0].payload["serviceStartDate"] == "2028-02-29"
    assert plan.actions[0].payload["lat"] == 90
    assert plan.actions[0].payload["lng"] == 180


def test_apply_uses_only_atomic_post_and_patch_and_omits_unknown_fields():
    existing = _site(
        10,
        customerName="Existing",
        address="10 Existing Rd, Effingham, IL 62401",
        rate=90.0,
        targetLaborPct=35.0,
    )
    api = FakeApi([existing])

    result = importer.run_import(
        base_url="https://example.test",
        name="Mayra Canfield",
        password="secret",
        apply=True,
        sources=[
            _source("Existing", existing["address"], rate=95.0),
            _source("New", "11 New Rd, Effingham, IL 62401"),
        ],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    mutations = [call for call in api.calls if call["method"] in {"PATCH", "POST"}][1:]
    assert result == 0
    assert [call["method"] for call in mutations] == ["PATCH", "POST"]
    assert all(call["method"] != "PUT" for call in api.calls)
    assert mutations[0]["body"] == {"rate": 95.0}
    assert mutations[1]["body"] == {
        "customerName": "New",
        "address": "11 New Rd, Effingham, IL 62401",
        "locationType": "Commercial",
    }
    assert all(value is not None for call in mutations for value in call["body"].values())
    assert existing["targetLaborPct"] == 35.0


def test_successful_apply_is_idempotent_on_rerun():
    api = FakeApi()
    source = _source(
        "Rerun",
        "20 Rerun Blvd, Effingham, IL 62401",
        rate=140.0,
        rateType="per_visit",
    )
    geocode_calls = []

    first = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[source],
        api_client=api,
        geocoder=lambda address: geocode_calls.append(address) or (39.11, -88.51),
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )
    first_mutation_count = api.mutation_count
    second = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password="secret",
        apply=True,
        sources=[source],
        api_client=api,
        geocoder=lambda _address: (_ for _ in ()).throw(
            AssertionError("rerun must preserve and reuse the existing pin")
        ),
        sleep_fn=lambda _seconds: None,
        output=lambda _line: None,
    )

    assert first == 0
    assert second == 0
    assert first_mutation_count == 1
    assert api.mutation_count == 1
    assert geocode_calls == [source["address"]]


def test_partial_failure_is_nonzero_with_exact_secret_free_summary():
    output = []
    password = "password-must-stay-secret"
    api = FakeApi(
        fail_mutation_number=2,
        fail_message=f"unsafe echo {password} server-secret-token",
    )

    result = importer.run_import(
        base_url="https://example.test",
        name="Juan",
        password=password,
        apply=True,
        sources=[
            _source("First", "30 First St, Effingham, IL 62401"),
            _source("Second", "31 Second St, Effingham, IL 62401"),
        ],
        api_client=api,
        geocoder=lambda _address: None,
        sleep_fn=lambda _seconds: None,
        output=output.append,
    )

    assert result == 1
    summary_line = next(line for line in output if line.startswith("Apply summary: "))
    summary = json.loads(summary_line.removeprefix("Apply summary: "))
    assert summary == {
        "planned": {"create": 2, "update": 0},
        "applied": {"create": 1, "update": 0},
        "unchanged": 0,
        "conflicts": 0,
        "failed": 1,
        "notAttempted": 0,
    }
    rendered = "\n".join(output)
    assert password not in rendered
    assert "server-secret-token" not in rendered
