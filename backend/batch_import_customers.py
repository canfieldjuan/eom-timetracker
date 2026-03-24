#!/usr/bin/env python3
"""
Batch import 45 customers (29 residential + 16 commercial) into the EOM timetracker.

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
            "rate": c.get("rate"),
            "rateType": c.get("rateType", "per_visit"),
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
