#!/usr/bin/env python3
"""
Batch import 45 customers (29 residential + 16 commercial) into the EOM timetracker.

Usage (preview only by default):
    python batch_import_customers.py --url https://eom-timetracker.onrender.com \
        --username "Juan Canfield"

Apply the reviewed preview explicitly:
    python batch_import_customers.py --url https://eom-timetracker.onrender.com \
        --username "Juan Canfield" --apply

Options:
    --url        Base URL of the API (default: https://eom-timetracker.onrender.com)
    --username   Admin username
    --password   Admin password (prompted securely when omitted)
    --apply      Apply the preview with atomic create/update calls
    --dry-run    Deprecated alias for preview-only behavior
"""

import argparse
import getpass
import json
import re
import time
import urllib.request
import urllib.error
import urllib.parse

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
    except Exception as e:
        print(f"    Geocode error for '{address}': {e}")
    return None


def api_call(url: str, method: str, body: dict | None = None, token: str | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
            detail = payload.get("error") or payload.get("detail") or str(payload)
        except Exception:
            detail = exc.reason
        raise RuntimeError(f"{method} {url} failed ({exc.code}): {detail}") from exc


def normalize_address(address: str) -> str:
    collapsed = re.sub(r"\s+", " ", address.strip())
    collapsed = re.sub(r"\s*,\s*", ", ", collapsed)
    return collapsed.casefold()


def build_import_plan(imported: list[dict], existing: list[dict]) -> dict:
    """Return an idempotent plan without inventing values for omitted fields."""
    existing_by_key: dict[str, list[dict]] = {}
    for location in existing:
        existing_by_key.setdefault(normalize_address(location["address"]), []).append(location)

    operations: list[dict] = []
    conflicts: list[dict] = []
    imported_keys: set[str] = set()
    field_map = {
        "customerName": "customerName",
        "locationType": "locationType",
        "rate": "rate",
        "rateType": "rateType",
        "frequency": "frequency",
        "lat": "latitude",
        "lng": "longitude",
        "expectedHours": "expectedHours",
        "targetLaborPct": "targetLaborPct",
        "minMarginPct": "minMarginPct",
    }

    for candidate in imported:
        key = normalize_address(candidate["address"])
        if key in imported_keys:
            conflicts.append(
                {
                    "address": candidate["address"],
                    "reason": "duplicate address in import source",
                }
            )
            continue
        imported_keys.add(key)

        matches = existing_by_key.get(key, [])
        if len(matches) > 1:
            conflicts.append(
                {
                    "address": candidate["address"],
                    "reason": "multiple saved locations match after normalization",
                    "locationIds": [int(match["id"]) for match in matches],
                }
            )
            continue
        if not matches:
            operations.append({"action": "create", "payload": candidate})
            continue

        current = matches[0]
        if not current.get("active", True):
            operations.append(
                {
                    "action": "reactivate",
                    "locationId": int(current["id"]),
                    "payload": candidate,
                }
            )
            continue

        patch: dict = {}
        changes: dict = {}
        for incoming_field, existing_field in field_map.items():
            if incoming_field not in candidate:
                continue
            incoming_value = candidate[incoming_field]
            current_value = current.get(existing_field)
            if isinstance(incoming_value, float) and current_value is not None:
                equal = abs(incoming_value - float(current_value)) < 0.000001
            else:
                equal = incoming_value == current_value
            if not equal:
                patch[incoming_field] = incoming_value
                changes[incoming_field] = {"from": current_value, "to": incoming_value}

        operations.append(
            {
                "action": "update" if patch else "unchanged",
                "locationId": int(current["id"]),
                "address": str(current["address"]),
                "payload": patch,
                "changes": changes,
            }
        )

    return {"operations": operations, "conflicts": conflicts}


def print_import_plan(plan: dict) -> None:
    counts: dict[str, int] = {}
    for operation in plan["operations"]:
        action = operation["action"]
        counts[action] = counts.get(action, 0) + 1
        if action in {"create", "reactivate"}:
            print(f"  {action.upper():10} {operation['payload']['address']}")
        elif action == "update":
            fields = ", ".join(operation["changes"])
            print(f"  UPDATE     {operation['address']} ({fields})")

    print(
        "\nPlan: "
        + ", ".join(
            f"{counts.get(action, 0)} {action}"
            for action in ("create", "reactivate", "update", "unchanged")
        )
    )
    if plan["conflicts"]:
        print(f"Conflicts: {len(plan['conflicts'])}")
        for conflict in plan["conflicts"]:
            print(f"  CONFLICT   {conflict['address']}: {conflict['reason']}")


def apply_import_plan(base: str, token: str, plan: dict) -> None:
    for operation in plan["operations"]:
        action = operation["action"]
        if action == "unchanged":
            continue
        if action in {"create", "reactivate"}:
            api_call(
                f"{base}/api/admin/locations",
                "POST",
                operation["payload"],
                token,
            )
        else:
            api_call(
                f"{base}/api/admin/locations/{operation['locationId']}",
                "PATCH",
                operation["payload"],
                token,
            )


def main():
    parser = argparse.ArgumentParser(description="Batch import EOM customers")
    parser.add_argument("--url", default=API_BASE)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    password = args.password or getpass.getpass("Admin password: ")

    # Step 1 — authenticate before doing slow external work.
    print("Authenticating...")
    resp = api_call(
        f"{base}/api/auth/login",
        "POST",
        {"name": args.username, "password": password},
    )
    token = resp.get("token") or resp.get("access_token")
    if not token:
        raise RuntimeError(f"Login response did not contain an access token: {resp}")
    print("Authenticated.")

    existing_response = api_call(
        f"{base}/api/admin/locations?includeArchived=true",
        "GET",
        token=token,
    )
    existing = existing_response.get("locations", [])

    # Step 2 — geocode all addresses.
    print(f"Geocoding {len(CUSTOMERS)} addresses (1 req/sec to respect Nominatim rate limit)...")
    locations = []
    for i, c in enumerate(CUSTOMERS):
        print(f"  [{i+1}/{len(CUSTOMERS)}] {c['customer']} — {c['address']}")
        coords = geocode(c["address"])
        entry = {
            "address": c["address"],
            "customerName": c["customer"],
            "locationType": c["type"],
        }
        if "rateType" in c:
            entry["rateType"] = c["rateType"]
        if "rate" in c:
            entry["rate"] = c["rate"]
        if coords:
            entry["lat"], entry["lng"] = coords
            print(f"    → {coords[0]:.5f}, {coords[1]:.5f}")
        else:
            print("    → geocode failed; existing GPS data will remain unchanged")
        locations.append(entry)
        if i < len(CUSTOMERS) - 1:
            time.sleep(1.1)  # Nominatim requires ≥1 req/sec

    pinned = sum(1 for location in locations if "lat" in location)
    print(f"\nGeocoded {pinned}/{len(locations)} locations successfully.")

    plan = build_import_plan(locations, existing)
    print_import_plan(plan)
    if plan["conflicts"]:
        raise RuntimeError("Resolve import conflicts before applying changes")

    if args.dry_run or not args.apply:
        print("\nPreview only. Re-run with --apply after reviewing this diff.")
        return

    apply_import_plan(base, token, plan)
    changed = sum(
        operation["action"] != "unchanged" for operation in plan["operations"]
    )
    print(f"\nApplied {changed} atomic location changes. Existing unrelated locations were untouched.")


if __name__ == "__main__":
    main()
