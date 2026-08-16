#!/usr/bin/env python3
"""Generate a read-only legacy arrival-policy inventory and mapping template."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2

from arrival_policy_inventory import build_inventory, validate_owner_mapping


SITE_CHECK_IN_SCHEDULE_WINDOW_DEFAULT_HOURS = 12


def _configured_schedule_window_hours() -> int:
    raw = os.environ.get(
        "SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS",
        str(SITE_CHECK_IN_SCHEDULE_WINDOW_DEFAULT_HOURS),
    )
    try:
        return max(1, int(raw))
    except ValueError as exc:
        raise ValueError(
            "SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS must be an integer"
        ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read legacy exact/recurring arrival records. This command never "
            "applies a mapping or writes to PostgreSQL."
        )
    )
    parser.add_argument(
        "--db-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL URL (defaults to DATABASE_URL)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the inventory JSON here instead of stdout",
    )
    parser.add_argument(
        "--validate-mapping",
        type=Path,
        help="Validate an owner-completed mapping against the live inventory",
    )
    parser.add_argument(
        "--schedule-window-hours",
        type=int,
        default=None,
        help=(
            "QR schedule matching window in hours "
            "(defaults to SITE_CHECK_IN_SCHEDULE_WINDOW_HOURS or 12)"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.db_url:
        print("DATABASE_URL or --db-url is required", file=sys.stderr)
        return 2
    try:
        schedule_window_hours = (
            max(1, args.schedule_window_hours)
            if args.schedule_window_hours is not None
            else _configured_schedule_window_hours()
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    conn = psycopg2.connect(args.db_url)
    try:
        conn.set_session(readonly=True, autocommit=False)
        inventory = build_inventory(
            conn,
            as_of=datetime.now(timezone.utc),
            schedule_window_hours=schedule_window_hours,
        )
        conn.rollback()
    finally:
        conn.close()

    if args.validate_mapping:
        mapping = json.loads(args.validate_mapping.read_text(encoding="utf-8"))
        errors = validate_owner_mapping(inventory, mapping)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print("Owner mapping is complete and matches the current inventory.")
        return 0

    rendered = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
