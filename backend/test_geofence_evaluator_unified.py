"""Geofence C2 (#214): unit tests for the canonical accuracy-aware evaluator,
its full outcome set, the algebraic equivalence with the non-accuracy
nearest-match, and the bounding-box conservative-superset property.

Pure-function tests -- no DB. The evaluator is radius-parameterized; the
enforcement gate is exercised via _effective_geofence_radius /
_max_effective_geofence_radius_m with GEOFENCE_ENFORCEMENT_ENABLED toggled.
"""
from __future__ import annotations

import math

import pytest

import time_tracker_api as api

R_M = 6_371_000.0  # must match haversine_m's sphere radius


def _destination(lat, lng, distance_m, bearing_deg):
    """Point distance_m from (lat,lng) along bearing, on the same sphere as
    haversine_m -- so haversine_m(origin, result) == distance_m."""
    ang = distance_m / R_M
    br = math.radians(bearing_deg)
    lat1 = math.radians(lat)
    lng1 = math.radians(lng)
    lat2 = math.asin(
        math.sin(lat1) * math.cos(ang) + math.cos(lat1) * math.sin(ang) * math.cos(br)
    )
    lng2 = lng1 + math.atan2(
        math.sin(br) * math.sin(ang) * math.cos(lat1),
        math.cos(ang) - math.sin(lat1) * math.sin(lat2),
    )
    return math.degrees(lat2), (math.degrees(lng2) + 540) % 360 - 180


def _eval(**kw):
    base = dict(site_latitude=39.0, site_longitude=-88.0, latitude=39.0, longitude=-88.0, accuracy=5.0)
    base.update(kw)
    return api.evaluate_site_check_in_geofence(**base)


# ---- outcome set -----------------------------------------------------------

def test_inside_outside_uncertain_around_boundary():
    # Radius 100, accuracy 1 -> inside: d+1<=100 (d<=99); outside: d-1>100 (d>101);
    # uncertain: 99 < d <= 101.
    def at(d):
        lat, lng = _destination(39.0, -88.0, d, 90)
        return _eval(latitude=lat, longitude=lng, accuracy=1.0, resolved_radius_m=100)["status"]
    assert at(50) == "inside"
    assert at(90) == "inside"        # 91 <= 100
    assert at(100) == "uncertain"    # 101 not <= 100, 99 not > 100 (mid-band)
    assert at(105) == "outside"      # 104 > 100, strict
    assert at(200) == "outside"


def test_inside_is_non_strict_and_outside_is_strict():
    origin = (39.0, -88.0)
    # distance + accuracy == radius exactly -> inside (<=)
    lat, lng = _destination(*origin, 95.0, 0)
    assert _eval(latitude=lat, longitude=lng, accuracy=5.0, resolved_radius_m=100)["status"] == "inside"
    # distance - accuracy just over radius -> outside (strict >)
    lat, lng = _destination(*origin, 106.0, 0)
    assert _eval(latitude=lat, longitude=lng, accuracy=5.0, resolved_radius_m=100)["status"] == "outside"


def test_min_and_max_radius_boundaries():
    origin = (39.0, -88.0)
    for radius in (api.GEOFENCE_RADIUS_MIN_M, api.GEOFENCE_RADIUS_MAX_M):
        inside_lat, inside_lng = _destination(*origin, radius - 2.0, 0)
        assert _eval(latitude=inside_lat, longitude=inside_lng, accuracy=1.0, resolved_radius_m=radius)["status"] == "inside"
        out_lat, out_lng = _destination(*origin, radius + 5.0, 0)
        assert _eval(latitude=out_lat, longitude=out_lng, accuracy=1.0, resolved_radius_m=radius)["status"] == "outside"


def test_low_accuracy_wins_even_dead_centre():
    # Accuracy above policy -> low_accuracy, even for a point ON the site.
    r = _eval(accuracy=float(api.SITE_CHECK_IN_MAX_ACCURACY_M + 1), resolved_radius_m=100)
    assert r["status"] == "low_accuracy"


def test_site_unpinned():
    r = _eval(site_latitude=None, site_longitude=None, accuracy=5.0)
    assert r["status"] == "site_unpinned"
    assert r["distanceM"] is None
    assert r["accuracyM"] == 5.0


@pytest.mark.parametrize("bad", [
    dict(latitude=None),
    dict(longitude=None),
    dict(accuracy=None),
    dict(accuracy=float("nan")),
    dict(accuracy=float("inf")),
    dict(latitude=float("nan")),
])
def test_missing_or_invalid_gps(bad):
    r = _eval(**bad)
    assert r["status"] == "missing_gps"
    assert r["distanceM"] is None


def test_return_contract_keys_and_rounding():
    r = _eval(resolved_radius_m=120, radius_source="per_site", max_accuracy_policy_m=100)
    assert set(r) == {
        "status", "distanceM", "radiusM", "accuracyM",
        "resolvedRadiusM", "radiusSource", "maxAccuracyPolicyM",
    }
    assert r["radiusM"] == 120 and r["resolvedRadiusM"] == 120
    assert r["radiusSource"] == "per_site"
    assert r["maxAccuracyPolicyM"] == 100
    # 2-dp rounding preserved.
    assert r["accuracyM"] == round(r["accuracyM"], 2)


def test_defaults_reproduce_global_policy():
    # No new kwargs -> global radius + global max-accuracy + global_fallback source.
    r = _eval()
    assert r["radiusM"] == int(api.SITE_CHECK_IN_RADIUS_M)
    assert r["radiusSource"] == "global_fallback"
    assert r["maxAccuracyPolicyM"] == int(api.SITE_CHECK_IN_MAX_ACCURACY_M)


# ---- Area-B algebraic equivalence -----------------------------------------

def test_nearest_match_equals_evaluator_zero_accuracy_projection():
    """find_nearest_location_match's binary withinRadius is exactly the evaluator
    at accuracy=0, radius=LOCATION_MATCH_RADIUS_M for the nearest pin."""
    device = (39.10, -88.54)
    coords = {
        "Site A": {"lat": 39.1002, "lng": -88.5402},   # ~ near
        "Site B": {"lat": 39.20, "lng": -88.60},       # far
    }
    ts = {"location_coords": coords}
    match = api.find_nearest_location_match(device[0], device[1], ts)
    assert match is not None
    ev = api.evaluate_site_check_in_geofence(
        site_latitude=coords[match["location"]]["lat"],
        site_longitude=coords[match["location"]]["lng"],
        latitude=device[0], longitude=device[1], accuracy=0.0,
        resolved_radius_m=api.LOCATION_MATCH_RADIUS_M,
    )
    assert match["withinRadius"] == (ev["status"] == "inside")


# ---- bounding-box conservative-superset property ---------------------------

def _box_contains(bounds, lat, lng):
    lat_lo, lat_hi, lng_lo, lng_hi, wrapped = bounds
    if not (lat_lo <= lat <= lat_hi):
        return False
    if wrapped:
        return lng >= lng_lo or lng <= lng_hi
    return lng_lo <= lng <= lng_hi


@pytest.mark.parametrize("lat", [0.0, 39.10, 71.0, -54.0])
def test_bounding_box_is_conservative_superset_when_enforced(monkeypatch, lat):
    # With enforcement ON, a per-site override up to GEOFENCE_RADIUS_MAX_M must
    # never place an inside/uncertain point outside the candidate box.
    monkeypatch.setattr(api, "GEOFENCE_ENFORCEMENT_ENABLED", True)
    lng = 10.0
    accuracy = 30.0
    envelope = api._max_effective_geofence_radius_m() + accuracy
    bounds = api._site_check_in_coordinate_bounds(lat, lng, accuracy)
    # Every point up to the full envelope (the max non-"outside" distance) is inside.
    for bearing in range(0, 360, 15):
        d_lat, d_lng = _destination(lat, lng, envelope, bearing)
        assert _box_contains(bounds, d_lat, d_lng), (
            f"envelope point at bearing {bearing} (lat {lat}) escaped the box"
        )


def test_bounding_box_unchanged_when_enforcement_off(monkeypatch):
    monkeypatch.setattr(api, "GEOFENCE_ENFORCEMENT_ENABLED", False)
    assert api._max_effective_geofence_radius_m() == int(api.SITE_CHECK_IN_RADIUS_M)
    off = api._site_check_in_coordinate_bounds(39.1, -88.5, 20.0)
    # Envelope is exactly global radius + accuracy, as pre-C2.
    envelope = float(api.SITE_CHECK_IN_RADIUS_M) + 20.0
    expected_lat_delta = envelope / 110_000.0
    assert math.isclose(off[1] - 39.1, expected_lat_delta, rel_tol=1e-9)


# ---- gate helper unit behavior ---------------------------------------------

def test_effective_radius_gate_off_ignores_override(monkeypatch):
    monkeypatch.setattr(api, "GEOFENCE_ENFORCEMENT_ENABLED", False)
    assert api._effective_geofence_radius(200) == (int(api.SITE_CHECK_IN_RADIUS_M), "global_fallback")
    assert api._effective_geofence_radius(None) == (int(api.SITE_CHECK_IN_RADIUS_M), "global_fallback")


def test_effective_radius_gate_on_honors_and_clamps(monkeypatch):
    monkeypatch.setattr(api, "GEOFENCE_ENFORCEMENT_ENABLED", True)
    assert api._effective_geofence_radius(200) == (200, "per_site")
    # Clamp a grandfathered out-of-bounds override to the business max.
    assert api._effective_geofence_radius(10_000) == (api.GEOFENCE_RADIUS_MAX_M, "per_site")
    assert api._effective_geofence_radius(None) == (int(api.SITE_CHECK_IN_RADIUS_M), "global_fallback")
