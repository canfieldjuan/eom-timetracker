#!/usr/bin/env python3
"""
Batch import 29 customers into the EOM timetracker.

Usage:
    python batch_import_customers.py --url https://eom-timetracker.onrender.com \
        --username "Juan Canfield" --password "YOUR_PASSWORD"

Options:
    --url        Base URL of the API (default: https://eom-timetracker.onrender.com)
    --username   Admin username
    --password   Admin password
    --dry-run    Print payload without sending
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse

API_BASE = "https://eom-timetracker.onrender.com"

CUSTOMERS = [
    {"customer": "Angie",                  "address": "8711 Cumberland Dr, Effingham, IL 62401, USA",          "type": "Residential"},
    {"customer": "Anna McClellan",         "address": "245 County Road 400 E, Sigel, IL 62462",              "type": "Residential"},
    {"customer": "Cathy Brummer",          "address": "18670 US-40, Teutopolis, IL 62467",                     "type": "Residential"},
    {"customer": "Chris Raney",            "address": "2346 N 1600 St, Dieterich, IL 62424",                   "type": "Residential"},
    {"customer": "Cyndi Weedman",          "address": "1504 Hickory Hill Dr, Effingham, IL 62401, USA",        "type": "Residential"},
    {"customer": "Diane Marie Nazar",      "address": "1007 S 4th St, Effingham, IL 62401, USA",               "type": "Residential"},
    {"customer": "Doug Dyer",              "address": "2605 E Campground Rd, Altamont, IL 62411, USA",         "type": "Residential"},
    {"customer": "Douglas Merchant",       "address": "14414 E Persimmon Ave, Effingham, IL 62401, USA",       "type": "Residential"},
    {"customer": "Erin Micinhiemere",      "address": "16847 Willow Rdg Dr, Effingham, IL 62401, USA",         "type": "Residential"},
    {"customer": "Gieseking Funeral Home", "address": "208 N 2nd St, Altamont, IL 62411, USA",                 "type": "Commercial"},
    {"customer": "Jan Marcott",            "address": "202 W Poplar Dr, Effingham, IL 62401, USA",             "type": "Residential"},
    {"customer": "Janet Nesbit",           "address": "1201 S Park St, Effingham, IL 62401, USA",              "type": "Residential"},
    {"customer": "Jaque and Joe Dalton",   "address": "15002 N 16th Ave, Effingham, IL 62401, USA",            "type": "Residential"},
    {"customer": "Jean Czemski",           "address": "2301 Lilly St, Effingham, IL 62401, USA",               "type": "Residential"},
    {"customer": "Joan Baker",             "address": "2010 Magnolia St, Effingham, IL 62401, USA",            "type": "Residential"},
    {"customer": "Jon Lewis",              "address": "201 E Lawrence Ave, Effingham, IL 62401, USA",          "type": "Residential"},
    {"customer": "Kathy Furguson",         "address": "15474 E Rd, Effingham, IL 62401, USA",                  "type": "Residential"},
    {"customer": "Kathy Mills",            "address": "525 Interstate Dr, St Elmo, IL 62458, USA",             "type": "Residential"},
    {"customer": "Kyle Williams & Amy",    "address": "8701 N 2300th St, Dieterich, IL 62424, USA",            "type": "Residential"},
    {"customer": "Lauren Bilbo",           "address": "1006 Beckman Dr, Effingham, IL 62401, USA",             "type": "Residential"},
    {"customer": "Laurie Ryznyk",          "address": "504 N 2nd St, Effingham, IL 62401, USA",                "type": "Residential"},
    {"customer": "Lindsey Lingafelter",    "address": "507 Davis St, Newton, IL 62448, USA",                   "type": "Residential"},
    {"customer": "Lora Hamann",            "address": "15194 Hilltop Cir, Effingham, IL 62401, USA",           "type": "Residential"},
    {"customer": "Mary Bubash",            "address": "1308 Kollmeyer Lane, Effingham, IL 62401",             "type": "Residential"},
    {"customer": "Pat & Zenda",            "address": "15555 Misty Ln, Effingham, IL 62401, USA",              "type": "Residential"},
    {"customer": "Rachael Boyer",          "address": "8236 E Twin Oaks Dr, Effingham, IL 62401, USA",         "type": "Residential"},
    {"customer": "Rachel Collins",         "address": "203 N Herrin St, Teutopolis, IL 62467, USA",            "type": "Residential"},
    {"customer": "Tahira Kohli",           "address": "708 E Evergreen Ave, Effingham, IL 62401, USA",         "type": "Residential"},
    {"customer": "Teresa Carpenter",       "address": "705 Park Hills Dr, Effingham, IL 62401, USA",           "type": "Residential"},
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
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description="Batch import EOM customers")
    parser.add_argument("--url", default=API_BASE)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    # Step 1 — geocode all addresses
    print(f"Geocoding {len(CUSTOMERS)} addresses (1 req/sec to respect Nominatim rate limit)...")
    locations = []
    for i, c in enumerate(CUSTOMERS):
        print(f"  [{i+1}/{len(CUSTOMERS)}] {c['customer']} — {c['address']}")
        coords = geocode(c["address"])
        entry = {
            "name": c["address"],
            "customer": c["customer"],
            "type": c["type"],
            "lat": coords[0] if coords else None,
            "lng": coords[1] if coords else None,
            "rate": None,
            "rateType": "per_visit",
        }
        if coords:
            print(f"    → {coords[0]:.5f}, {coords[1]:.5f}")
        else:
            print(f"    → geocode failed, will import without GPS pin")
        locations.append(entry)
        if i < len(CUSTOMERS) - 1:
            time.sleep(1.1)  # Nominatim requires ≥1 req/sec

    pinned = sum(1 for l in locations if l["lat"] is not None)
    print(f"\nGeocoded {pinned}/{len(locations)} locations successfully.")

    if args.dry_run:
        print("\n--- DRY RUN PAYLOAD ---")
        print(json.dumps({"locations": locations}, indent=2))
        return

    # Step 2 — authenticate
    print("\nAuthenticating...")
    try:
        resp = api_call(f"{base}/api/auth/login", "POST", {
            "username": args.username,
            "password": args.password,
        })
        token = resp.get("token") or resp.get("access_token")
        if not token:
            print(f"Login failed: {resp}")
            return
        print("Authenticated.")
    except Exception as e:
        print(f"Login error: {e}")
        return

    # Step 3 — push locations
    print(f"Importing {len(locations)} locations...")
    try:
        result = api_call(f"{base}/api/admin/locations", "PUT", {"locations": locations}, token)
        imported = len(result.get("locations", []))
        print(f"Done. {imported} locations now in system.")
    except Exception as e:
        print(f"Import error: {e}")


if __name__ == "__main__":
    main()
