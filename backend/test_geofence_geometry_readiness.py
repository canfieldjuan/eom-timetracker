"""Geofence C1 (#213): per-site geometry, pin attestation, derived readiness.

Covers the additive schema, the canonical geometry fingerprint (with a hardcoded
golden vector so a refactor cannot silently change attestation validity), derived
readiness, the admin editor + attest endpoints, and the readiness report. No
evaluator / clock-in / enforcement behavior is exercised -- that is #214/#218.
"""

import os
import uuid

import psycopg2
import pytest

import time_tracker_api as t

TEST_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://eom_test:eom_test@localhost:5433/eom_test",
)

# The seeded office coordinates reused across the suite.
LAT = 39.1203
LNG = -88.54335


# --------------------------------------------------------------------------- #
# Pure-function unit tests (no DB)                                             #
# --------------------------------------------------------------------------- #

GOLDEN_INPUT = dict(
    entity_type="location",
    entity_id=42,
    latitude=39.1203,
    longitude=-88.54335,
    resolved_radius_m=75,
    radius_source="per_site",
    max_accuracy_policy_m=100,
    pin_provenance="gps_capture",
    pin_confidence="high",
    pin_capture_accuracy_m=4.5,
    active=True,
    archived=False,
    location_type="Commercial",
    parent_linked=True,
    parent_customer_active=True,
    parent_customer_archived=False,
)

GOLDEN_PAYLOAD = {
    "version": "geofence_geometry_v1",
    "entityType": "location",
    "entityId": 42,
    "latitude": "39.1203000",
    "longitude": "-88.5433500",
    "resolvedRadiusM": 75,
    "radiusSource": "per_site",
    "maxAccuracyPolicyM": 100,
    "pinProvenance": "gps_capture",
    "pinConfidence": "high",
    "pinCaptureAccuracyM": "4.50",
    "active": True,
    "archived": False,
    "locationType": "Commercial",
    "parentLinked": True,
    "parentCustomerActive": True,
    "parentCustomerArchived": False,
}

# Hardcoded golden vector. Recomputed from the production function; if the
# canonicalization ever changes, THIS test must be updated deliberately -- a
# silent change to attestation validity is exactly what it prevents.
GOLDEN_FINGERPRINT = "886671b2d27d5e762cf6268e15d10ec00829d111e018cadb1566ee45a3730b31"
GOLDEN_CANONICAL_JSON = (
    '{"active":true,"archived":false,"entityId":42,"entityType":"location",'
    '"latitude":"39.1203000","locationType":"Commercial","longitude":"-88.5433500",'
    '"maxAccuracyPolicyM":100,"parentCustomerActive":true,'
    '"parentCustomerArchived":false,"parentLinked":true,"pinCaptureAccuracyM":"4.50",'
    '"pinConfidence":"high","pinProvenance":"gps_capture","radiusSource":"per_site",'
    '"resolvedRadiusM":75,"version":"geofence_geometry_v1"}'
)


def test_fingerprint_golden_vector_payload_and_hash():
    import json

    payload = t.geofence_geometry_fingerprint_payload(**GOLDEN_INPUT)
    assert payload == GOLDEN_PAYLOAD
    assert (
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
        == GOLDEN_CANONICAL_JSON
    )
    assert t.geofence_geometry_fingerprint(**GOLDEN_INPUT) == GOLDEN_FINGERPRINT


@pytest.mark.parametrize(
    "value,expected",
    [
        (39.1203, "39.1203000"),
        (-88.54335, "-88.5433500"),
        (0, "0.0000000"),
        (90, "90.0000000"),
        (39.12034567, "39.1203457"),  # rounds at 7 dp
        (None, None),
    ],
)
def test_canonical_coordinate_seven_dp(value, expected):
    assert t._canonical_coordinate(value) == expected


def test_resolve_radius_prefers_per_site_else_global(monkeypatch):
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 50)
    assert t._resolve_geofence_radius_m(None) == (50, "global_fallback")
    assert t._resolve_geofence_radius_m(120) == (120, "per_site")


def test_radius_bounds_are_provisional_and_centralized():
    # Provisional working range; a single edit here retunes admin validation.
    assert t.GEOFENCE_RADIUS_MIN_M == 15
    assert t.GEOFENCE_RADIUS_MAX_M == 500


@pytest.mark.parametrize(
    "field,mutated",
    [
        ("latitude", 39.2000000),
        ("longitude", -88.6000000),
        ("resolved_radius_m", 76),
        ("max_accuracy_policy_m", 101),
        ("pin_provenance", "map_placement"),
        ("pin_confidence", "medium"),
        ("pin_capture_accuracy_m", 9.9),
        ("active", False),
        ("archived", True),
        ("location_type", "Residential"),
        ("parent_customer_active", False),
        ("parent_customer_archived", True),
    ],
)
def test_fingerprint_changes_independently_per_input(field, mutated):
    base = t.geofence_geometry_fingerprint(**GOLDEN_INPUT)
    changed = dict(GOLDEN_INPUT)
    changed[field] = mutated
    assert t.geofence_geometry_fingerprint(**changed) != base


def _synthetic_location_row(**overrides):
    row = {
        "id": 7,
        "lat": LAT,
        "lng": LNG,
        "customer_id": 3,
        "geofence_radius_m": None,
        "pin_provenance": "gps_capture",
        "pin_confidence": "high",
        "pin_capture_accuracy_m": 4.5,
        "active": True,
        "archived_at": None,
        "location_type": "Commercial",
        "customer_active": True,
        "customer_archived_at": None,
        "pin_attested_at": None,
        "pin_attested_by": None,
        "pin_attestation_fingerprint": None,
    }
    row.update(overrides)
    return row


def test_global_fallback_flip_changes_fingerprint_when_using_fallback(monkeypatch):
    row = _synthetic_location_row(geofence_radius_m=None)
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 50)
    fp_a = t._location_geofence_state(row)["currentFingerprint"]
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 200)
    fp_b = t._location_geofence_state(row)["currentFingerprint"]
    assert fp_a != fp_b  # a site on the global fallback tracks the global value


def test_per_site_radius_isolates_from_fallback_change(monkeypatch):
    row = _synthetic_location_row(geofence_radius_m=120)
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 50)
    fp_a = t._location_geofence_state(row)["currentFingerprint"]
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 200)
    fp_b = t._location_geofence_state(row)["currentFingerprint"]
    assert fp_a == fp_b  # an explicit per-site radius ignores the global fallback


def test_readiness_reports_configured_and_effective_clock_radius(monkeypatch):
    row = _synthetic_location_row(geofence_radius_m=250)
    monkeypatch.setattr(t, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        t,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )

    state = t._location_geofence_state(row)

    assert state["geofenceRadiusM"] == 250
    assert state["resolvedRadiusM"] == 250
    assert state["radiusSource"] == "per_site"
    assert state["clockBoundaryEffectiveRadiusM"] == 250
    assert state["clockBoundaryRadiusSource"] == "per_site"
    assert state["clockBoundaryPerSiteRadiusEnabled"] is True


def test_readiness_reports_legacy_radius_for_residential_clock_fallback(monkeypatch):
    row = _synthetic_location_row(
        geofence_radius_m=250,
        location_type="Residential",
    )
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 50)
    monkeypatch.setattr(t, "LOCATION_MATCH_RADIUS_M", 80)
    monkeypatch.setattr(t, "GEOFENCE_PER_SITE_RADIUS_ENABLED", False)
    monkeypatch.setattr(
        t,
        "GEOFENCE_CLOCK_BOUNDARY_PER_SITE_RADIUS_ENABLED",
        True,
    )

    state = t._location_geofence_state(row)

    assert state["geofenceRadiusM"] == 250
    assert state["clockBoundaryEffectiveRadiusM"] == 80
    assert state["clockBoundaryRadiusSource"] == "legacy_location_match"
    assert state["clockBoundaryPerSiteRadiusEnabled"] is False


def _attested_row(**overrides):
    """A synthetic row whose stored fingerprint matches its current geometry."""
    row = _synthetic_location_row(**overrides)
    row["pin_attestation_fingerprint"] = t._location_geofence_state(row)[
        "currentFingerprint"
    ]
    row["pin_attested_at"] = t.utc_now()
    row["pin_attested_by"] = 1
    return row


def test_readiness_is_derived_and_true_only_when_all_conditions_met():
    ready = t._location_geofence_state(_attested_row())
    assert ready["ready"] is True
    assert ready["unreadyReasons"] == []
    assert ready["fingerprintMatch"] is True


@pytest.mark.parametrize(
    "overrides,reason",
    [
        (dict(lat=None, lng=None), "unpinned"),
        (dict(pin_confidence="low"), "low_or_missing_confidence"),
        (dict(pin_confidence=None), "low_or_missing_confidence"),
        (dict(active=False), "inactive"),
        (dict(archived_at=object()), "archived"),
        (dict(customer_active=False), "parent_customer_inactive"),
        (dict(customer_archived_at=object()), "parent_customer_archived"),
    ],
)
def test_each_unready_reason_is_reported(overrides, reason):
    # Start from an attested-ready row, then break exactly one input. Geometry
    # inputs also invalidate the fingerprint, but the specific reason must appear.
    base = _attested_row()
    base.update(overrides)
    state = t._location_geofence_state(base)
    assert state["ready"] is False
    assert reason in state["unreadyReasons"]


def test_unattested_is_unready_with_reason():
    state = t._location_geofence_state(_synthetic_location_row())
    assert state["ready"] is False
    assert "not_attested" in state["unreadyReasons"]
    assert state["attestationFingerprint"] is None


def test_geometry_change_makes_prior_attestation_stale_not_deleted():
    row = _attested_row()
    stored = row["pin_attestation_fingerprint"]
    row["lat"] = 40.0  # move the pin after attestation
    state = t._location_geofence_state(row)
    assert state["fingerprintMatch"] is False
    assert "attestation_stale" in state["unreadyReasons"]
    # The stored attestation fingerprint is preserved (mismatch, not deletion).
    assert state["attestationFingerprint"] == stored


def test_unlinked_legacy_location_is_flagged_but_can_become_ready():
    row = _attested_row(customer_id=None, customer_active=None, customer_archived_at=None)
    state = t._location_geofence_state(row)
    assert state["unlinkedLegacy"] is True
    # An unlinked but pinned+confident+attested legacy site is still ready.
    assert state["ready"] is True


def test_home_base_non_applicable_fields_are_deterministic():
    config = {
        "home_base_id": 5,
        "label": "Office",
        "latitude": LAT,
        "longitude": LNG,
        "active": True,
        "geofence_radius_m": 90,
        "pin_provenance": "map_placement",
        "pin_confidence": "high",
        "pin_capture_accuracy_m": 3.0,
        "pin_attested_at": None,
        "pin_attested_by": None,
        "pin_attestation_fingerprint": None,
    }
    a = t._home_base_geofence_state(config)
    b = t._home_base_geofence_state(dict(config))
    assert a["currentFingerprint"] == b["currentFingerprint"]
    assert a["unlinkedLegacy"] is False


# --------------------------------------------------------------------------- #
# Schema / migration assertions                                               #
# --------------------------------------------------------------------------- #


def _column(cur, table, column):
    cur.execute(
        """
        SELECT is_nullable, data_type
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        """,
        (table, column),
    )
    return cur.fetchone()


def test_migration_is_additive_and_event_snapshots_unchanged(client):
    # client triggers app startup -> runtime migration on top of schema.sql.
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    try:
        with conn.cursor() as cur:
            # New config columns exist on both tables, all nullable (existing rows valid).
            for table in ("locations", "home_bases"):
                for col in (
                    "geofence_radius_m",
                    "pin_provenance",
                    "pin_capture_accuracy_m",
                    "pin_confidence",
                    "pin_attested_at",
                    "pin_attested_by",
                    "pin_attestation_fingerprint",
                ):
                    row = _column(cur, table, col)
                    assert row is not None, f"{table}.{col} missing"
                    assert row[0] == "YES", f"{table}.{col} should be nullable"
            # There is NO stored readiness boolean (readiness is derived).
            assert _column(cur, "locations", "geofence_ready") is None
            assert _column(cur, "home_bases", "geofence_ready") is None
            # The immutable per-event snapshot column is untouched (still NOT NULL).
            assert _column(cur, "site_check_ins", "geofence_radius_m")[0] == "NO"
    finally:
        conn.close()


def test_runtime_migration_adds_columns_on_populated_pre_migration_table(client):
    """Exercise the REAL prod path (the schema.sql path is a no-op in CI).

    conftest rebuilds the schema from the already-updated schema.sql, so the
    columns exist before the runtime migration runs -- every ALTER is a no-op.
    Here we drop the C1 columns, populate a row that predates #213, then run the
    runtime migration twice to prove it is additive on a POPULATED table and
    idempotent. Mirrors the DROP COLUMN-then-re-ensure pattern used elsewhere
    (test_api.py). The finally block guarantees the columns are restored so the
    rest of the session is unaffected even if an assertion fails.
    """
    geofence_cols = (
        "geofence_radius_m",
        "pin_provenance",
        "pin_capture_accuracy_m",
        "pin_confidence",
        "pin_attested_at",
        "pin_attested_by",
        "pin_attestation_fingerprint",
    )
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    conn.autocommit = True
    marker = f"{uuid.uuid4()} PreMig Rd, Effingham"
    row_id = None
    try:
        with conn.cursor() as cur:
            for table in ("locations", "home_bases"):
                for col in geofence_cols:
                    cur.execute(
                        f"ALTER TABLE {table} DROP COLUMN IF EXISTS {col} CASCADE"
                    )
            cur.execute(
                "INSERT INTO locations (address, customer_name, rate_type, active) "
                "VALUES (%s, 'PreMig', 'per_visit', true) RETURNING id",
                (marker,),
            )
            row_id = cur.fetchone()[0]

        # Run twice: additive on a populated table, then a true no-op.
        t._ensure_geofence_pin_columns("locations")
        t._ensure_geofence_pin_columns("home_bases")
        t._ensure_geofence_pin_columns("locations")
        t._ensure_geofence_pin_columns("home_bases")

        with conn.cursor() as cur:
            for table in ("locations", "home_bases"):
                for col in geofence_cols:
                    meta = _column(cur, table, col)
                    assert meta is not None, f"{table}.{col} not re-added"
                    assert meta[0] == "YES", f"{table}.{col} should be nullable"
            # The pre-existing row's new columns are NULL (no default clobber).
            cur.execute(
                "SELECT geofence_radius_m, pin_confidence FROM locations WHERE id = %s",
                (row_id,),
            )
            assert cur.fetchone() == (None, None)
    finally:
        # Always restore the columns for the rest of the session, then clean up.
        t._ensure_geofence_pin_columns("locations")
        t._ensure_geofence_pin_columns("home_bases")
        if row_id is not None:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM locations WHERE id = %s", (row_id,))
        conn.close()


# --------------------------------------------------------------------------- #
# Admin API tests                                                             #
# --------------------------------------------------------------------------- #


@pytest.fixture
def make_location():
    """Create isolated Customer+Site rows for a test and clean them up after."""
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    created_sites: list[int] = []
    created_customers: list[int] = []

    def _make(
        *,
        linked=True,
        customer_active=True,
        customer_archived=False,
        lat=LAT,
        lng=LNG,
        confidence=None,
        provenance=None,
        capture=None,
        radius=None,
        active=True,
        location_type="Commercial",
        location_archived=False,
    ):
        with conn.cursor() as cur:
            customer_id = None
            if linked:
                cur.execute(
                    "INSERT INTO customers (name, active) VALUES (%s, %s) RETURNING id",
                    (f"GC {uuid.uuid4()}", customer_active),
                )
                customer_id = cur.fetchone()[0]
                if customer_archived:
                    cur.execute(
                        "UPDATE customers SET archived_at = NOW(), active = false WHERE id = %s",
                        (customer_id,),
                    )
                created_customers.append(customer_id)
            cur.execute(
                """
                INSERT INTO locations (
                    customer_id, address, customer_name, location_type,
                    rate, rate_type, lat, lng, active,
                    geofence_radius_m, pin_provenance, pin_confidence,
                    pin_capture_accuracy_m
                ) VALUES (%s, %s, %s, %s, 100.00, 'per_visit',
                          %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    customer_id,
                    f"{uuid.uuid4()} Test Rd, Effingham",
                    "GeoCust",
                    location_type,
                    lat,
                    lng,
                    active,
                    radius,
                    provenance,
                    confidence,
                    capture,
                ),
            )
            site_id = cur.fetchone()[0]
            if location_archived:
                # Simulate an active-but-archived row (the leak scenario).
                cur.execute(
                    "UPDATE locations SET archived_at = NOW() WHERE id = %s",
                    (site_id,),
                )
        conn.commit()
        created_sites.append(site_id)
        return site_id

    yield _make

    with conn.cursor() as cur:
        for site_id in created_sites:
            cur.execute("DELETE FROM locations WHERE id = %s", (site_id,))
        for customer_id in created_customers:
            cur.execute("DELETE FROM customers WHERE id = %s", (customer_id,))
    conn.commit()
    conn.close()


def _site_geofence(client, auth, site_id):
    resp = client.get("/api/admin/locations?includeArchived=true", headers=auth)
    assert resp.status_code == 200, resp.text
    site = next(s for s in resp.json()["locations"] if s["id"] == site_id)
    return site["geofence"]


def test_location_response_includes_geofence_block(client, auth, make_location):
    site_id = make_location()
    geo = _site_geofence(client, auth, site_id)
    assert geo["ready"] is False
    assert "not_attested" in geo["unreadyReasons"]
    assert geo["radiusSource"] == "global_fallback"
    assert geo["unlinkedLegacy"] is False


def test_patch_sets_geofence_config(client, auth, make_location):
    site_id = make_location()
    resp = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=auth,
        json={
            "geofenceRadiusM": 120,
            "pinProvenance": "gps_capture",
            "pinConfidence": "high",
            "pinCaptureAccuracyM": 4.5,
        },
    )
    assert resp.status_code == 200, resp.text
    geo = resp.json()["location"]["geofence"]
    assert geo["geofenceRadiusM"] == 120
    assert geo["radiusSource"] == "per_site"
    assert geo["pinConfidence"] == "high"
    assert geo["pinCaptureAccuracyM"] == 4.5


@pytest.mark.parametrize(
    "body,ok",
    [
        ({"geofenceRadiusM": 50}, True),
        ({"geofenceRadiusM": 14}, False),
        ({"geofenceRadiusM": 501}, False),
        ({"pinProvenance": "gps_capture"}, True),
        ({"pinProvenance": "teleport"}, False),
        ({"pinConfidence": "medium"}, True),
        ({"pinConfidence": "perfect"}, False),
    ],
)
def test_patch_validates_geofence_inputs(client, auth, make_location, body, ok):
    site_id = make_location()
    resp = client.patch(
        f"/api/admin/locations/{site_id}", headers=auth, json=body
    )
    assert resp.status_code == (200 if ok else 422), resp.text


def test_attest_uses_server_state_time_and_admin(client, auth, make_location):
    site_id = make_location(confidence="high", provenance="gps_capture", capture=4.5)
    resp = client.post(
        f"/api/admin/locations/{site_id}/attest-geofence", headers=auth, json={}
    )
    assert resp.status_code == 200, resp.text
    geo = resp.json()["location"]["geofence"]
    assert geo["ready"] is True
    assert geo["fingerprintMatch"] is True
    assert geo["attestationFingerprint"] == geo["currentFingerprint"]
    assert geo["pinAttestedByEmployeeId"] is not None
    assert geo["pinAttestedAt"] is not None


def test_attest_rejects_client_supplied_stale_fingerprint(client, auth, make_location):
    site_id = make_location(confidence="high")
    bogus = "0" * 64
    resp = client.post(
        f"/api/admin/locations/{site_id}/attest-geofence",
        headers=auth,
        json={"expectedFingerprint": bogus},
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "stale_geofence_attestation"


def test_editing_geometry_after_attest_makes_it_stale(client, auth, make_location):
    site_id = make_location(confidence="high")
    client.post(
        f"/api/admin/locations/{site_id}/attest-geofence", headers=auth, json={}
    )
    before = _site_geofence(client, auth, site_id)
    assert before["ready"] is True
    # Move the pin -> prior attestation is now stale, but preserved.
    resp = client.patch(
        f"/api/admin/locations/{site_id}", headers=auth, json={"lat": 40.0}
    )
    assert resp.status_code == 200, resp.text
    after = resp.json()["location"]["geofence"]
    assert after["fingerprintMatch"] is False
    assert after["ready"] is False
    assert "attestation_stale" in after["unreadyReasons"]
    assert after["attestationFingerprint"] == before["attestationFingerprint"]


def test_report_separates_ready_from_eligible_unready_and_flags_legacy(
    client, auth, make_location
):
    ready_site = make_location(confidence="high")
    client.post(
        f"/api/admin/locations/{ready_site}/attest-geofence", headers=auth, json={}
    )
    unready_site = make_location()  # pinned but unattested
    legacy_site = make_location(linked=False)

    resp = client.get("/api/admin/geofence-readiness", headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_id = {x["id"]: x for x in body["locations"]}
    assert by_id[ready_site]["geofence"]["ready"] is True
    assert by_id[unready_site]["geofence"]["ready"] is False
    assert by_id[legacy_site]["geofence"]["unlinkedLegacy"] is True
    assert body["summary"]["readyLocations"] >= 1
    assert body["summary"]["eligibleUnreadyLocations"] >= 1
    assert body["summary"]["unlinkedLegacyLocations"] >= 1
    assert body["summary"]["globalFallbackRadiusM"] == int(t.SITE_CHECK_IN_RADIUS_M)


def test_parent_customer_inactive_makes_site_unready(client, auth, make_location):
    site_id = make_location(confidence="high", customer_archived=True)
    client.post(
        f"/api/admin/locations/{site_id}/attest-geofence", headers=auth, json={}
    )
    geo = _site_geofence(client, auth, site_id)
    assert geo["ready"] is False
    assert "parent_customer_archived" in geo["unreadyReasons"]


def test_readiness_report_excludes_active_but_archived_by_default(
    client, auth, make_location
):
    leaked = make_location(active=True, location_archived=True)
    default = client.get("/api/admin/geofence-readiness", headers=auth)
    assert default.status_code == 200, default.text
    assert leaked not in {x["id"] for x in default.json()["locations"]}
    # It still shows when archived rows are explicitly requested.
    incl = client.get(
        "/api/admin/geofence-readiness?includeArchived=true", headers=auth
    )
    assert leaked in {x["id"] for x in incl.json()["locations"]}


def test_eligible_unready_excludes_unauthorized_locations(client, auth, make_location):
    # Business-eligible but unready (pinned, unattested) -> counts.
    eligible = make_location()
    # NOT eligible: no location_type (unauthorized), though active+pinned.
    typeless = make_location(location_type=None)
    # NOT eligible: active Site under an archived Customer.
    bad_parent = make_location(customer_archived=True)

    body = client.get("/api/admin/geofence-readiness", headers=auth).json()
    by_id = {x["id"]: x for x in body["locations"]}
    assert by_id[eligible]["eligible"] is True
    assert by_id[typeless]["eligible"] is False
    assert by_id[bad_parent]["eligible"] is False
    # None of the three is ready, but only the eligible one is eligible-unready.
    assert by_id[eligible]["geofence"]["ready"] is False
    # The unauthorized ones must not be counted as eligible-unready.
    unauthorized_ids = {typeless, bad_parent}
    eligible_unready_ids = {
        x["id"] for x in body["locations"] if x["eligible"] and not x["geofence"]["ready"]
    }
    assert eligible_unready_ids.isdisjoint(unauthorized_ids)
    assert eligible in eligible_unready_ids


@pytest.mark.parametrize("table", ["locations", "home_bases"])
@pytest.mark.parametrize(
    "value,ok",
    [(1, True), (100000, True), (600, True), (0, False), (-5, False), (100001, False), (None, True)],
)
def test_db_enforces_radius_sanity_bounds(client, table, value, ok):
    """The DB enforces only a PERMANENT sanity range (garbage guard). The
    provisional business bounds (15-500) are enforced by request validation, so a
    direct write of 600 is DB-legal (600 <= sanity max) but the API rejects it."""
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            if table == "locations":
                cur.execute(
                    "INSERT INTO locations (address, rate_type, active, geofence_radius_m) "
                    "VALUES (%s, 'per_visit', true, %s) RETURNING id",
                    (f"{uuid.uuid4()} Radius Rd", value),
                )
            else:
                # active=false avoids the one-active-home-base unique index.
                cur.execute(
                    "INSERT INTO home_bases (label, active, geofence_radius_m) "
                    "VALUES (%s, false, %s) RETURNING id",
                    (f"HB {uuid.uuid4()}"[:150], value),
                )
            row_id = cur.fetchone()[0]
            cur.execute(f"DELETE FROM {table} WHERE id = %s", (row_id,))
        assert ok, f"{table} accepted out-of-range radius {value}"
    except psycopg2.errors.CheckViolation:
        assert not ok, f"{table} rejected valid radius {value}"
    finally:
        conn.close()


def test_pin_enum_patterns_derive_from_canonical_tuples():
    assert t._PIN_PROVENANCE_PATTERN == "^(" + "|".join(t.PIN_PROVENANCE_VALUES) + ")$"
    assert t._PIN_CONFIDENCE_PATTERN == "^(" + "|".join(t.PIN_CONFIDENCE_VALUES) + ")$"


@pytest.mark.parametrize("provenance", list(t.PIN_PROVENANCE_VALUES))
def test_api_accepts_every_canonical_provenance(client, auth, make_location, provenance):
    site_id = make_location()
    resp = client.patch(
        f"/api/admin/locations/{site_id}", headers=auth, json={"pinProvenance": provenance}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["location"]["geofence"]["pinProvenance"] == provenance


@pytest.mark.parametrize("table", ["locations", "home_bases"])
def test_enum_validation_is_app_only_no_db_drift(client, table):
    """Enum validation is single-sourced in request validation; the DB carries no
    enum CHECK to drift from it (Codex #220). The API rejects an unknown enum
    (test_patch_validates_geofence_inputs); a direct DB write of a novel value is
    DB-legal, so adding a canonical value never needs a DB migration."""
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass "
                "AND conname IN (%s, %s)",
                (table, f"{table}_pin_provenance_check", f"{table}_pin_confidence_check"),
            )
            assert cur.fetchall() == []  # no DB enum CHECK to drift
            if table == "locations":
                cur.execute(
                    "INSERT INTO locations (address, rate_type, active, pin_provenance) "
                    "VALUES (%s, 'per_visit', true, 'surveyed') RETURNING id",
                    (f"{uuid.uuid4()} Enum Rd",),
                )
            else:
                cur.execute(
                    "INSERT INTO home_bases (label, active, pin_confidence) "
                    "VALUES (%s, false, 'exquisite') RETURNING id",
                    (f"HB {uuid.uuid4()}",),
                )
            row_id = cur.fetchone()[0]
            cur.execute(f"DELETE FROM {table} WHERE id = %s", (row_id,))
    finally:
        conn.close()


def test_radius_out_of_bounds_applies_only_to_per_site_override(monkeypatch):
    """The provisional bounds gate a per-site override only, never the global
    fallback -- so SITE_CHECK_IN_RADIUS_M=10 must not mark fallback Sites unready
    (Codex #220)."""
    monkeypatch.setattr(t, "SITE_CHECK_IN_RADIUS_M", 10)
    fallback = t._location_geofence_state(_synthetic_location_row(geofence_radius_m=None))
    assert "radius_out_of_bounds" not in fallback["unreadyReasons"]
    override = t._location_geofence_state(_synthetic_location_row(geofence_radius_m=600))
    assert "radius_out_of_bounds" in override["unreadyReasons"]


def test_out_of_provisional_radius_is_db_legal_but_unready(client, auth, make_location):
    """A per-site radius above the provisional max (but within DB sanity) is stored
    by the DB, and derived readiness flags it (Codex #220 thread 3)."""
    site_id = make_location(
        radius=600, confidence="high", provenance="gps_capture", capture=4.5
    )
    geo = _site_geofence(client, auth, site_id)
    assert geo["geofenceRadiusM"] == 600  # DB accepted it (600 <= sanity max)
    assert geo["ready"] is False
    assert "radius_out_of_bounds" in geo["unreadyReasons"]


def test_tightening_provisional_bound_marks_unready_without_blocking_edits(
    client, auth, make_location
):
    """Tightening the provisional business bound below a grandfathered override
    marks it unready (thread 3) yet never blocks an unrelated edit (thread 4),
    because the DB holds only the permanent sanity bound."""
    site_id = make_location(
        radius=400, confidence="high", provenance="gps_capture", capture=4.5
    )
    attest = client.post(
        f"/api/admin/locations/{site_id}/attest-geofence", headers=auth, json={}
    )
    assert attest.status_code == 200, attest.text
    assert attest.json()["location"]["geofence"]["ready"] is True

    original_max = t.GEOFENCE_RADIUS_MAX_M
    try:
        t.GEOFENCE_RADIUS_MAX_M = 300  # tighten below the 400 override
        geo = _site_geofence(client, auth, site_id)
        assert geo["ready"] is False
        assert "radius_out_of_bounds" in geo["unreadyReasons"]
        # An UNRELATED edit still succeeds (400 is DB-legal under the sanity bound).
        edit = client.patch(
            f"/api/admin/locations/{site_id}", headers=auth, json={"pinConfidence": "medium"}
        )
        assert edit.status_code == 200, edit.text
    finally:
        t.GEOFENCE_RADIUS_MAX_M = original_max


def test_home_base_attest_honors_update_token(client, auth, morning_crew):
    put = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": "EOM Office",
            "address": "100 Dispatch Lane, Effingham",
            "latitude": LAT,
            "longitude": LNG,
            "pinConfidence": "high",
        },
    )
    assert put.status_code == 200, put.text
    token = put.json()["homeBase"]["updateToken"]
    assert token and len(token) == 64

    # A stale/incorrect token is rejected (no silent success).
    stale = client.post(
        "/api/admin/home-base/attest-geofence",
        headers=auth,
        json={"expectedUpdateToken": "0" * 64},
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["code"] == "stale_home_base_update"

    # The current token succeeds.
    ok = client.post(
        "/api/admin/home-base/attest-geofence",
        headers=auth,
        json={"expectedUpdateToken": token},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["homeBase"]["geofence"]["fingerprintMatch"] is True


def test_non_admin_cannot_edit_or_attest_geofence(client, emp_auth, make_location):
    site_id = make_location()
    patched = client.patch(
        f"/api/admin/locations/{site_id}",
        headers=emp_auth,
        json={"pinConfidence": "high"},
    )
    assert patched.status_code == 403, patched.text
    attested = client.post(
        f"/api/admin/locations/{site_id}/attest-geofence",
        headers=emp_auth,
        json={},
    )
    assert attested.status_code == 403, attested.text
    report = client.get("/api/admin/geofence-readiness", headers=emp_auth)
    assert report.status_code == 403, report.text


@pytest.fixture
def morning_crew():
    """admin_put_home_base requires an active Morning Crew to exist."""
    conn = psycopg2.connect(TEST_DB_URL, sslmode="disable")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO crews (name, active) VALUES ('Morning Crew', true) "
            "ON CONFLICT (name) DO UPDATE SET active = true"
        )
    conn.commit()
    conn.close()
    yield


def test_home_base_geofence_editable_and_attestable(client, auth, morning_crew):
    put = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": "EOM Office",
            "address": "100 Dispatch Lane, Effingham",
            "latitude": LAT,
            "longitude": LNG,
            "geofenceRadiusM": 90,
            "pinProvenance": "map_placement",
            "pinConfidence": "high",
            "pinCaptureAccuracyM": 3.0,
        },
    )
    assert put.status_code == 200, put.text
    geo = put.json()["homeBase"]["geofence"]
    assert geo["geofenceRadiusM"] == 90
    assert geo["ready"] is False  # not attested yet

    attest = client.post(
        "/api/admin/home-base/attest-geofence", headers=auth, json={}
    )
    assert attest.status_code == 200, attest.text
    geo2 = attest.json()["homeBase"]["geofence"]
    assert geo2["ready"] is True
    assert geo2["fingerprintMatch"] is True


def test_home_base_put_without_geofence_preserves_prior_config(client, auth, morning_crew):
    client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": "EOM Office",
            "address": "100 Dispatch Lane, Effingham",
            "latitude": LAT,
            "longitude": LNG,
            "geofenceRadiusM": 77,
            "pinConfidence": "medium",
        },
    )
    # A later PUT that omits the geofence fields must not wipe them.
    resp = client.put(
        "/api/admin/home-base",
        headers=auth,
        json={
            "label": "EOM Office Renamed",
            "address": "100 Dispatch Lane, Effingham",
            "latitude": LAT,
            "longitude": LNG,
        },
    )
    assert resp.status_code == 200, resp.text
    geo = resp.json()["homeBase"]["geofence"]
    assert geo["geofenceRadiusM"] == 77
    assert geo["pinConfidence"] == "medium"
