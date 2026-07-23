#!/usr/bin/env python3
"""Safely preview or apply the built-in EOM customer/site import.

Preview is the default. ``--dry-run`` remains as a backwards-compatible alias
for preview, while mutations require the explicit ``--apply`` flag.
"""

import argparse
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

API_BASE = "https://eom-timetracker.onrender.com"

CUSTOMERS = [
    # ── Residential ─────────────────────────────────────────────────────────────
    {"customer": "Angie",                  "address": "8711 Cumberland Dr, Effingham, IL 62401, USA",           "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Anna McClellan",         "address": "245 County Road 400 E, Sigel, IL 62462",                 "type": "Residential", "rate": 150.00,  "rateType": "per_visit"},
    {"customer": "Cathy Brummer",          "address": "18670 US-40, Teutopolis, IL 62467",                      "type": "Residential", "rate": 115.00,  "rateType": "per_visit"},
    {"customer": "Chris Raney",            "address": "2346 N 1600 St, Dieterich, IL 62424",                    "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Cyndi Weedman",          "address": "1504 Hickory Hill Dr, Effingham, IL 62401, USA",         "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Diane Marie Nazar",      "address": "1007 S 4th St, Effingham, IL 62401, USA",                "type": "Residential", "rate": 28.00,   "rateType": "hourly"},
    {"customer": "Doug Dyer",              "address": "2605 E Campground Rd, Altamont, IL 62411, USA",          "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Douglas Merchant",       "address": "14414 E Persimmon Ave, Effingham, IL 62401, USA",        "type": "Residential", "rate": 180.00,  "rateType": "per_visit"},
    {"customer": "Erin Micinhiemere",      "address": "16847 Willow Rdg Dr, Effingham, IL 62401, USA",          "type": "Residential", "rate": 220.00,  "rateType": "per_visit"},
    {"customer": "Jan Marcott",            "address": "202 W Poplar Dr, Effingham, IL 62401, USA",              "type": "Residential", "rate": 140.00,  "rateType": "per_visit"},
    {"customer": "Janet Nesbit",           "address": "1201 S Park St, Effingham, IL 62401, USA",               "type": "Residential", "rate": 200.00,  "rateType": "monthly"},
    {"customer": "Jaque and Joe Dalton",   "address": "15002 N 16th Ave, Effingham, IL 62401, USA",             "type": "Residential"},  # rate TBD
    {"customer": "Jean Czemski",           "address": "2301 Lilly St, Effingham, IL 62401, USA",                "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Joan Baker",             "address": "2010 Magnolia St, Effingham, IL 62401, USA",             "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Jon Lewis",              "address": "201 E Lawrence Ave, Effingham, IL 62401, USA",           "type": "Residential"},  # rate TBD
    {"customer": "Kathy Furguson",         "address": "15474 E Rd, Effingham, IL 62401, USA",                   "type": "Residential", "rate": 180.00,  "rateType": "per_visit"},
    {"customer": "Kathy Mills",            "address": "525 Interstate Dr, St Elmo, IL 62458, USA",              "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Kyle Williams & Amy",    "address": "8701 N 2300th St, Dieterich, IL 62424, USA",             "type": "Residential", "rate": 200.00,  "rateType": "monthly"},
    {"customer": "Lauren Bilbo",           "address": "1006 Beckman Dr, Effingham, IL 62401, USA",              "type": "Residential", "rate": 140.00,  "rateType": "per_visit"},
    {"customer": "Laurie Ryznyk",          "address": "504 N 2nd St, Effingham, IL 62401, USA",                 "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Lindsey Lingafelter",    "address": "507 Davis St, Newton, IL 62448, USA",                    "type": "Residential"},  # rate TBD
    {"customer": "Lora Hamann",            "address": "15194 Hilltop Cir, Effingham, IL 62401, USA",            "type": "Residential"},  # rate TBD
    {"customer": "Mary Bubash",            "address": "1308 Kollmeyer Lane, Effingham, IL 62401",               "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Pat & Zenda",            "address": "15555 Misty Ln, Effingham, IL 62401, USA",               "type": "Residential", "rate": 180.00,  "rateType": "per_visit"},
    {"customer": "Rachael Boyer",          "address": "8236 E Twin Oaks Dr, Effingham, IL 62401, USA",          "type": "Residential", "rate": 475.00,  "rateType": "per_visit"},
    {"customer": "Rachel Collins",         "address": "203 N Herrin St, Teutopolis, IL 62467, USA",             "type": "Residential", "rate": 135.00,  "rateType": "per_visit"},
    {"customer": "Tahira Kohli",           "address": "708 E Evergreen Ave, Effingham, IL 62401, USA",          "type": "Residential", "rate": 200.00,  "rateType": "per_visit"},
    {"customer": "Teresa Carpenter",       "address": "705 Park Hills Dr, Effingham, IL 62401, USA",            "type": "Residential", "rate": 180.00,  "rateType": "per_visit"},
    # ── Commercial ──────────────────────────────────────────────────────────────
    {"customer": "AKRA Builders",                    "address": "14590 County Rd 1600 E, Teutopolis, IL 62467, USA",       "type": "Commercial", "rate": 160.00,  "rateType": "per_visit"},
    {"customer": "Anthony Acres Resort",             "address": "15286 Resort Rd, Effingham, IL 62401, USA",               "type": "Commercial", "rate": 32.00,   "rateType": "hourly"},
    {"customer": "Brookstone Estates",               "address": "1101 N Maple St, Effingham, IL 62401",                    "type": "Commercial", "rate": 30.00,   "rateType": "hourly"},
    {"customer": "Bruce Lustig",                     "address": "921 E Fayette Ave, Effingham, IL 62401, USA",             "type": "Commercial", "rate": 140.00,  "rateType": "per_visit"},
    {"customer": "Canarm Inc.",                      "address": "709 E Main St, Teutopolis, IL 62467, USA",                "type": "Commercial", "rate": 115.00,  "rateType": "per_visit"},
    {"customer": "David Boyer / McCarthy Improvement", "address": "104 N 2nd St, Effingham, IL 62401, USA",               "type": "Commercial", "rate": 125.00,  "rateType": "per_visit"},
    {"customer": "Firefly Grill",                    "address": "1810 Ave of Mid-America, Effingham, IL 62401, USA",       "type": "Commercial", "rate": 27.00,   "rateType": "hourly"},
    {"customer": "Heartland Human Services",         "address": "1200 N 4th St, Effingham, IL 62401, USA",                "type": "Commercial", "rate": 109.00,  "rateType": "per_visit"},
    {"customer": "Kinder Morgan",                    "address": "2513 N 2125 St, St Elmo, IL 62458, USA",                 "type": "Commercial", "rate": 247.50,  "rateType": "per_visit"},
    {"customer": "Lincare",                          "address": "700 N Henrietta St, Effingham, IL 62401, USA",            "type": "Commercial", "rate": 300.00,  "rateType": "monthly"},
    {"customer": "MediaCom",                         "address": "107 S Henrietta St, Effingham, IL 62401, USA",            "type": "Commercial", "rate": 55.00,   "rateType": "per_visit"},
    {"customer": "Menards",                          "address": "1100 Avenue of Mid-America, Effingham, IL 62401, USA",    "type": "Commercial", "rate": 48.00,   "rateType": "per_visit"},
    {"customer": "Mid Illinois Concrete",            "address": "1300 S Commerce St, Effingham, IL 62401, USA",            "type": "Commercial", "rate": 125.00,  "rateType": "per_visit"},
    {"customer": "Mid Illinois Concrete - Pike & Raney", "address": "1310 Pike Ave, Effingham, IL 62401, USA",            "type": "Commercial", "rate": 100.00,  "rateType": "per_visit"},
    {"customer": "The American Red Cross",           "address": "603 Eden Ave, Effingham, IL 62401, USA",                  "type": "Commercial", "rate": 97.00,   "rateType": "per_visit"},
    {"customer": "Wente Plumbing & Fire Protection", "address": "1700 S Raney St, Effingham, IL 62401, USA",              "type": "Commercial", "rate": 120.00,  "rateType": "per_visit"},
]


SOURCE_FIELD_ALIASES = {
    "customerName": ("customerName", "customer"),
    "address": ("address", "name"),
    "locationType": ("locationType", "type"),
    "rate": ("rate",),
    "rateType": ("rateType",),
    "frequency": ("frequency",),
    "expectedHours": ("expectedHours",),
    "targetLaborPct": ("targetLaborPct",),
    "minMarginPct": ("minMarginPct",),
    "serviceScope": ("serviceScope",),
    "accessInstructions": ("accessInstructions",),
    "servicePreferences": ("servicePreferences",),
    "petNotes": ("petNotes",),
    "serviceStartDate": ("serviceStartDate",),
}
SERVER_FIELD_ALIASES = {
    **{field: (field,) for field in SOURCE_FIELD_ALIASES},
    "lat": ("latitude", "lat"),
    "lng": ("longitude", "lng"),
}
NUMERIC_FIELDS = {
    "rate",
    "expectedHours",
    "targetLaborPct",
    "minMarginPct",
    "lat",
    "lng",
}

REQUIRED_STRING_FIELDS = ("customerName", "address", "locationType")
OPTIONAL_STRING_FIELDS = (
    "rateType",
    "frequency",
    "serviceScope",
    "accessInstructions",
    "servicePreferences",
    "petNotes",
    "serviceStartDate",
)
STRING_MAX_LENGTHS = {
    "customerName": 200,
    "address": 500,
    "frequency": 100,
    "serviceScope": 4_000,
    "accessInstructions": 4_000,
    "servicePreferences": 4_000,
    "petNotes": 2_000,
}
ENUM_FIELDS = {
    "locationType": {"Residential", "Commercial"},
    "rateType": {"per_visit", "hourly", "monthly"},
}
NUMERIC_BOUNDS = {
    "rate": (0.0, 999_999.99),
    "expectedHours": (0.0, 9_999.99),
    "targetLaborPct": (0.0, 100.0),
    "minMarginPct": (0.0, 100.0),
    "lat": (-90.0, 90.0),
    "lng": (-180.0, 180.0),
}


class ApiError(RuntimeError):
    """An API failure containing only response-safe diagnostic fields."""

    def __init__(
        self,
        status: Optional[int],
        code: str,
        message: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = dict(details or {})

    def public_summary(self) -> str:
        status = f"HTTP {self.status}" if self.status is not None else "network"
        return f"{status} {self.code}: {self.message}"


@dataclass(frozen=True)
class ImportAction:
    source_index: int
    action: str
    customer_name: str
    address: str
    payload: dict[str, Any]
    site_id: Optional[int] = None
    changes: Optional[dict[str, dict[str, Any]]] = None
    conflict_code: Optional[str] = None
    conflict_message: Optional[str] = None

    def preview(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "row": self.source_index + 1,
            "action": self.action,
            "customerName": self.customer_name,
            "address": self.address,
        }
        if self.site_id is not None:
            result["siteId"] = self.site_id
        if self.action == "create":
            result["fields"] = self.payload
        if self.changes:
            result["changes"] = self.changes
        if self.conflict_code:
            result["code"] = self.conflict_code
            result["error"] = self.conflict_message
        return result


@dataclass(frozen=True)
class ImportPlan:
    actions: tuple[ImportAction, ...]

    def counts(self) -> dict[str, int]:
        return {
            action: sum(item.action == action for item in self.actions)
            for action in ("create", "update", "unchanged", "conflict")
        }


def normalize_address(address: str) -> str:
    """Mirror the server's documented address identity normalization."""
    collapsed = re.sub(r"\s+", " ", address.strip())
    return re.sub(r"\s*,\s*", ", ", collapsed).casefold()


def _first_source_value(
    source: Mapping[str, Any], aliases: Iterable[str]
) -> tuple[bool, Any]:
    for alias in aliases:
        if alias in source:
            return True, source[alias]
    return False, None


def _server_value(site: Mapping[str, Any], field: str) -> Any:
    for alias in SERVER_FIELD_ALIASES[field]:
        if alias in site:
            return site[alias]
    return None


def _values_equal(field: str, left: Any, right: Any) -> bool:
    if field not in NUMERIC_FIELDS:
        return left == right
    if left is None or right is None:
        return left is right
    try:
        return Decimal(str(left)) == Decimal(str(right))
    except (InvalidOperation, TypeError, ValueError):
        return left == right


def _source_payload(source: Mapping[str, Any]) -> dict[str, Any]:
    """Map only explicitly populated source fields to the atomic Site API."""
    payload: dict[str, Any] = {}
    for target, aliases in SOURCE_FIELD_ALIASES.items():
        present, value = _first_source_value(source, aliases)
        if not present or value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value and target in OPTIONAL_STRING_FIELDS:
                continue
        payload[target] = value
    return payload


def _numeric_validation_error(field: str, value: Any) -> Optional[str]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "must be a number"
    if isinstance(value, float) and not math.isfinite(value):
        return "must be finite"
    numeric = value
    minimum, maximum = NUMERIC_BOUNDS[field]
    if numeric < minimum or numeric > maximum:
        minimum_text = str(int(minimum)) if minimum.is_integer() else str(minimum)
        maximum_text = str(int(maximum)) if maximum.is_integer() else str(maximum)
        return f"must be between {minimum_text} and {maximum_text}"
    return None


def _source_validation_errors(
    source: Mapping[str, Any],
    desired: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []

    for field in ("customerName", "address", "locationType"):
        value = desired.get(field)
        if value is None or value == "":
            errors.append(f"{field} is required")

    for field in (*REQUIRED_STRING_FIELDS, *OPTIONAL_STRING_FIELDS):
        if field not in desired:
            continue
        value = desired[field]
        if not isinstance(value, str):
            errors.append(f"{field} must be a string")

    for field, maximum in STRING_MAX_LENGTHS.items():
        value = desired.get(field)
        if isinstance(value, str) and len(value) > maximum:
            errors.append(f"{field} must be at most {maximum} characters")

    for field, allowed in ENUM_FIELDS.items():
        value = desired.get(field)
        if isinstance(value, str) and value not in allowed:
            errors.append(f"{field} must be one of {', '.join(sorted(allowed))}")

    for field in ("rate", "expectedHours", "targetLaborPct", "minMarginPct"):
        if field not in desired:
            continue
        error = _numeric_validation_error(field, desired[field])
        if error:
            errors.append(f"{field} {error}")

    service_start = desired.get("serviceStartDate")
    if isinstance(service_start, str):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", service_start):
            errors.append("serviceStartDate must be an ISO YYYY-MM-DD date")
        else:
            try:
                parsed_date = date.fromisoformat(service_start)
            except ValueError:
                errors.append("serviceStartDate must be a valid calendar date")
            else:
                if parsed_date.isoformat() != service_start:
                    errors.append("serviceStartDate must be an ISO YYYY-MM-DD date")

    source_has_lat = "lat" in source and source.get("lat") is not None
    source_has_lng = "lng" in source and source.get("lng") is not None
    if source_has_lat != source_has_lng:
        errors.append("lat and lng must both be populated or both omitted")
    elif source_has_lat and source_has_lng:
        for field in ("lat", "lng"):
            error = _numeric_validation_error(field, source[field])
            if error:
                errors.append(f"{field} {error}")

    return errors


def _validated_geocode_coordinates(
    coordinates: Any,
) -> tuple[Optional[tuple[float, float]], Optional[str]]:
    if not isinstance(coordinates, (tuple, list)) or len(coordinates) != 2:
        return None, "geocoder must return a latitude/longitude pair"
    latitude, longitude = coordinates
    for field, value in (("lat", latitude), ("lng", longitude)):
        error = _numeric_validation_error(field, value)
        if error:
            return None, f"geocoder {field} {error}"
    return (float(latitude), float(longitude)), None


def geocode(address: str) -> tuple[float, float] | None:
    """Geocode an address via Nominatim. Returns (lat, lng) or None."""
    query = urllib.parse.urlencode({"q": address, "format": "json", "limit": "1"})
    url = f"https://nominatim.openstreetmap.org/search?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "EOM-Timetracker-Import/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())
        if results:
            return float(results[0]["lat"]), float(results[0]["lon"])
    except Exception:
        # The caller reports the failure without dumping transport internals.
        # Most importantly, a missing result is represented by omission, never
        # by a null coordinate pair that could clear an existing pin.
        pass
    return None


def api_call(
    url: str,
    method: str,
    body: Optional[dict[str, Any]] = None,
    token: Optional[str] = None,
) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        try:
            error_payload = json.loads(exc.read())
        except (json.JSONDecodeError, UnicodeDecodeError):
            error_payload = {}
        if not isinstance(error_payload, dict):
            error_payload = {}
        code = str(error_payload.get("code") or "api_error")
        message = str(error_payload.get("error") or "API request failed")[:500]
        details = error_payload.get("details")
        raise ApiError(
            exc.code,
            code,
            message,
            details if isinstance(details, dict) else None,
        ) from None
    except (urllib.error.URLError, TimeoutError):
        raise ApiError(None, "network_error", "API request could not be completed") from None

    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError(None, "invalid_response", "API returned invalid JSON") from None
    if not isinstance(decoded, dict):
        raise ApiError(None, "invalid_response", "API returned an unexpected response")
    return decoded


def _redact(text: str, *secrets: Optional[str]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def build_import_plan(
    sources: Sequence[Mapping[str, Any]],
    server_locations: Sequence[Mapping[str, Any]],
    *,
    geocoder: Callable[[str], Optional[tuple[float, float]]] = geocode,
    sleep_fn: Callable[[float], None] = time.sleep,
    output: Callable[[str], None] = print,
) -> ImportPlan:
    """Classify every row against a single server snapshot without mutations."""
    prepared_sources = [
        (source, _source_payload(source))
        for source in sources
    ]
    source_keys = [
        normalize_address(desired["address"])
        if isinstance(desired.get("address"), str) and desired["address"]
        else ""
        for _source, desired in prepared_sources
    ]
    duplicate_source_keys = {
        key for key in source_keys if key and source_keys.count(key) > 1
    }
    server_by_key: dict[str, list[Mapping[str, Any]]] = {}
    for site in server_locations:
        key = normalize_address(str(site.get("address") or ""))
        if key:
            server_by_key.setdefault(key, []).append(site)

    actions: list[ImportAction] = []
    geocode_requests = 0
    for index, (source, desired) in enumerate(prepared_sources):
        raw_customer_name = desired.get("customerName")
        raw_address = desired.get("address")
        customer_name = raw_customer_name if isinstance(raw_customer_name, str) else ""
        address = raw_address if isinstance(raw_address, str) else ""
        address_key = normalize_address(address)
        validation_errors = _source_validation_errors(source, desired)
        if validation_errors:
            actions.append(
                ImportAction(
                    index,
                    "conflict",
                    customer_name,
                    address,
                    desired,
                    conflict_code="invalid_source_row",
                    conflict_message="; ".join(validation_errors),
                )
            )
            continue
        if address_key in duplicate_source_keys:
            actions.append(
                ImportAction(
                    index,
                    "conflict",
                    customer_name,
                    address,
                    desired,
                    conflict_code="duplicate_source_address",
                    conflict_message="multiple source rows normalize to this address",
                )
            )
            continue

        matches = server_by_key.get(address_key, [])
        if len(matches) > 1:
            actions.append(
                ImportAction(
                    index,
                    "conflict",
                    customer_name,
                    address,
                    desired,
                    conflict_code="ambiguous_server_address",
                    conflict_message="multiple server Sites normalize to this address",
                )
            )
            continue
        existing = matches[0] if matches else None
        if existing is not None and not bool(existing.get("active", True)):
            actions.append(
                ImportAction(
                    index,
                    "conflict",
                    customer_name,
                    address,
                    desired,
                    site_id=int(existing["id"]),
                    conflict_code="archived_site_address",
                    conflict_message="restore the archived Site instead of recreating it",
                )
            )
            continue
        if existing is not None and "duplicate_normalized_address" in (
            existing.get("migrationReview") or []
        ):
            actions.append(
                ImportAction(
                    index,
                    "conflict",
                    customer_name,
                    address,
                    desired,
                    site_id=int(existing["id"]),
                    conflict_code="legacy_address_review",
                    conflict_message="the server marked this legacy address for review",
                )
            )
            continue

        source_has_lat = "lat" in source and source.get("lat") is not None
        source_has_lng = "lng" in source and source.get("lng") is not None
        if source_has_lat and source_has_lng:
            desired["lat"] = source["lat"]
            desired["lng"] = source["lng"]
        else:
            existing_has_pin = existing is not None and (
                _server_value(existing, "lat") is not None
                and _server_value(existing, "lng") is not None
            )
            if not existing_has_pin:
                if geocode_requests:
                    sleep_fn(1.1)
                geocode_requests += 1
                coords = geocoder(address)
                if coords is not None:
                    validated_coords, geocode_error = _validated_geocode_coordinates(coords)
                    if geocode_error:
                        actions.append(
                            ImportAction(
                                index,
                                "conflict",
                                customer_name,
                                address,
                                desired,
                                site_id=(
                                    int(existing["id"])
                                    if existing is not None
                                    else None
                                ),
                                conflict_code="invalid_geocode_coordinates",
                                conflict_message=geocode_error,
                            )
                        )
                        continue
                    assert validated_coords is not None
                    desired["lat"], desired["lng"] = validated_coords
                else:
                    output(f"Geocode unavailable for row {index + 1}; GPS fields omitted.")

        if existing is None:
            actions.append(
                ImportAction(index, "create", customer_name, address, desired)
            )
            continue

        changes: dict[str, dict[str, Any]] = {}
        patch: dict[str, Any] = {}
        for field, new_value in desired.items():
            old_value = _server_value(existing, field)
            if not _values_equal(field, old_value, new_value):
                patch[field] = new_value
                changes[field] = {"from": old_value, "to": new_value}
        if patch:
            actions.append(
                ImportAction(
                    index,
                    "update",
                    customer_name,
                    address,
                    patch,
                    site_id=int(existing["id"]),
                    changes=changes,
                )
            )
        else:
            actions.append(
                ImportAction(
                    index,
                    "unchanged",
                    customer_name,
                    address,
                    {},
                    site_id=int(existing["id"]),
                )
            )
    return ImportPlan(tuple(actions))


def _print_plan(plan: ImportPlan, output: Callable[[str], None]) -> None:
    for action in plan.actions:
        output(json.dumps(action.preview(), sort_keys=True, default=str))
    output(f"Preview summary: {json.dumps(plan.counts(), sort_keys=True)}")


def _apply_summary(
    plan: ImportPlan,
    applied: Mapping[str, int],
    *,
    failed: int,
    not_attempted: int,
) -> dict[str, Any]:
    counts = plan.counts()
    return {
        "planned": {"create": counts["create"], "update": counts["update"]},
        "applied": {
            "create": int(applied.get("create", 0)),
            "update": int(applied.get("update", 0)),
        },
        "unchanged": counts["unchanged"],
        "conflicts": counts["conflict"],
        "failed": failed,
        "notAttempted": not_attempted,
    }


def run_import(
    *,
    base_url: str,
    name: str,
    password: str,
    apply: bool,
    sources: Sequence[Mapping[str, Any]] = CUSTOMERS,
    api_client: Callable[..., dict[str, Any]] = api_call,
    geocoder: Callable[[str], Optional[tuple[float, float]]] = geocode,
    sleep_fn: Callable[[float], None] = time.sleep,
    output: Callable[[str], None] = print,
) -> int:
    base = base_url.rstrip("/")
    try:
        login = api_client(
            f"{base}/api/auth/login",
            "POST",
            {"name": name, "password": password},
        )
    except ApiError as exc:
        output(f"Authentication failed: {_redact(exc.public_summary(), password)}")
        return 1
    except Exception:
        output("Authentication failed: unexpected client error")
        return 1

    token = login.get("token") or login.get("access_token")
    if not isinstance(token, str) or not token:
        output("Authentication failed: API response did not contain an access token")
        return 1

    try:
        listed = api_client(
            f"{base}/api/admin/locations?includeArchived=true",
            "GET",
            token=token,
        )
    except ApiError as exc:
        output(
            "Could not load server Sites: "
            f"{_redact(exc.public_summary(), password, token)}"
        )
        return 1
    except Exception:
        output("Could not load server Sites: unexpected client error")
        return 1
    server_locations = listed.get("locations")
    if not isinstance(server_locations, list):
        output("Could not load server Sites: API returned an unexpected response")
        return 1

    plan = build_import_plan(
        sources,
        server_locations,
        geocoder=geocoder,
        sleep_fn=sleep_fn,
        output=output,
    )
    _print_plan(plan, output)
    counts = plan.counts()
    if counts["conflict"]:
        output("Apply blocked: resolve every conflict and preview again.")
        return 2
    if not apply:
        output("Preview only; rerun with --apply to perform the planned mutations.")
        return 0

    mutations = [
        action for action in plan.actions if action.action in {"create", "update"}
    ]
    applied = {"create": 0, "update": 0}
    for index, action in enumerate(mutations):
        try:
            if action.action == "create":
                response = api_client(
                    f"{base}/api/admin/locations",
                    "POST",
                    action.payload,
                    token,
                )
            else:
                response = api_client(
                    f"{base}/api/admin/locations/{action.site_id}",
                    "PATCH",
                    action.payload,
                    token,
                )
            if not isinstance(response.get("location"), dict):
                raise ApiError(
                    None,
                    "invalid_response",
                    "mutation response did not contain the canonical Site",
                )
        except ApiError as exc:
            output(
                f"Apply failed for row {action.source_index + 1} "
                f"({action.action}): "
                f"{_redact(exc.public_summary(), password, token)}"
            )
            summary = _apply_summary(
                plan,
                applied,
                failed=1,
                not_attempted=len(mutations) - index - 1,
            )
            output(f"Apply summary: {json.dumps(summary, sort_keys=True)}")
            return 1
        except Exception:
            output(
                f"Apply failed for row {action.source_index + 1} "
                f"({action.action}): unexpected client error"
            )
            summary = _apply_summary(
                plan,
                applied,
                failed=1,
                not_attempted=len(mutations) - index - 1,
            )
            output(f"Apply summary: {json.dumps(summary, sort_keys=True)}")
            return 1
        applied[action.action] += 1

    summary = _apply_summary(plan, applied, failed=0, not_attempted=0)
    output(f"Apply summary: {json.dumps(summary, sort_keys=True)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely import EOM customers and Sites")
    parser.add_argument("--url", default=API_BASE)
    parser.add_argument("--username", "--name", dest="name", required=True)
    parser.add_argument("--password", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview against server state without mutations (the default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply the preview with atomic POST/PATCH requests",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return run_import(
        base_url=args.url,
        name=args.name,
        password=args.password,
        apply=bool(args.apply),
    )


if __name__ == "__main__":
    sys.exit(main())
