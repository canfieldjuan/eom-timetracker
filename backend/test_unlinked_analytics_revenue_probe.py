from __future__ import annotations

from datetime import date

from unlinked_analytics_revenue_probe import (
    build_unlinked_analytics_revenue_fallback_probe,
    main,
)


def _entry(
    shift_id: int,
    *,
    location: str,
    clock_in: str,
    clock_out: str,
    hours: float,
    job_id: int | None = None,
    visits: list[dict] | None = None,
) -> dict:
    return {
        "id": shift_id,
        "employeeId": 1,
        "location": location,
        "clockIn": clock_in,
        "clockOut": clock_out,
        "totalHours": hours,
        "timeCategory": "productive",
        "jobId": job_id,
        "visits": visits or [],
    }


def _timesheet(entries: list[dict]) -> dict:
    return {
        "entries": entries,
        "location_customers": {
            "Hourly Site": "Hourly Customer",
            "Per Visit A": "Visit Customer",
            "Per Visit B": "Visit Customer",
            "Monthly Site": "Monthly Customer",
            "Linked Monthly": "Linked Customer",
            "Missing Rate Site": "Missing Customer",
        },
        "location_rates": {
            "Hourly Site": 50.00,
            "Per Visit A": 80.00,
            "Per Visit B": 80.00,
            "Monthly Site": 310.00,
            "Linked Monthly": 120.00,
        },
        "location_rate_types": {
            "Hourly Site": "hourly",
            "Per Visit A": "per_visit",
            "Per Visit B": "per_visit",
            "Monthly Site": "monthly",
            "Linked Monthly": "monthly",
        },
    }


def test_probe_measures_unlinked_valid_rate_fallback_formula_split():
    timesheet_data = _timesheet(
        [
            _entry(
                1,
                location="Hourly Site",
                clock_in="2026-07-12T14:00:00Z",
                clock_out="2026-07-12T16:00:00Z",
                hours=2.0,
            ),
            _entry(
                2,
                location="Per Visit A",
                clock_in="2026-07-13T14:00:00Z",
                clock_out="2026-07-13T15:00:00Z",
                hours=1.0,
            ),
            _entry(
                3,
                location="Per Visit B",
                clock_in="2026-07-13T16:00:00Z",
                clock_out="2026-07-13T17:00:00Z",
                hours=1.0,
            ),
            _entry(
                4,
                location="Monthly Site",
                clock_in="2026-07-14T14:00:00Z",
                clock_out="2026-07-14T15:00:00Z",
                hours=1.0,
            ),
        ]
    )

    result = build_unlinked_analytics_revenue_fallback_probe(
        reference_date=date(2026, 7, 19),
        timesheet_data=timesheet_data,
        linked_revenue_lookup=lambda _job_ids: ({}, set(), {}),
    )

    assert result["loadedDateRange"] == {
        "start": "2026-07-05",
        "end": "2026-07-18",
    }
    assert result["summary"] == {
        "rowCount": 4,
        "segmentCount": 4,
        "linkedSegmentCount": 0,
        "missingRateSegmentCount": 0,
        "suppressedByLinkedMonthlySiteMonth": 0,
        "hours": 5.0,
        "topLevelLegacyRevenue": 320.0,
        "customerDetailLegacyRevenue": 570.0,
    }
    by_site = {row["siteAddress"]: row for row in result["rows"]}
    assert by_site["Hourly Site"]["topLevelLegacyRevenue"] == 100.0
    assert by_site["Hourly Site"]["customerDetailLegacyRevenue"] == 100.0
    assert by_site["Per Visit A"]["topLevelLegacyRevenue"] == 80.0
    assert by_site["Per Visit A"]["customerDetailLegacyRevenue"] == 80.0
    assert by_site["Per Visit B"]["topLevelLegacyRevenue"] == 0.0
    assert by_site["Per Visit B"]["customerDetailLegacyRevenue"] == 80.0
    assert by_site["Monthly Site"]["topLevelLegacyRevenue"] == 140.0
    assert by_site["Monthly Site"]["customerDetailLegacyRevenue"] == 310.0


def test_probe_keeps_linked_missing_and_suppressed_rows_out_of_fallback_total():
    captured_job_ids = []
    timesheet_data = _timesheet(
        [
            _entry(
                10,
                location="Linked Monthly",
                clock_in="2026-07-12T14:00:00Z",
                clock_out="2026-07-12T15:00:00Z",
                hours=1.0,
                job_id=77,
            ),
            _entry(
                11,
                location="Linked Monthly",
                clock_in="2026-07-13T14:00:00Z",
                clock_out="2026-07-13T15:00:00Z",
                hours=1.0,
            ),
            _entry(
                12,
                location="Missing Rate Site",
                clock_in="2026-07-14T14:00:00Z",
                clock_out="2026-07-14T15:00:00Z",
                hours=1.0,
            ),
        ]
    )

    def fake_lookup(job_ids: set[int]):
        captured_job_ids.append(job_ids)
        return {77: 12000}, {("Linked Monthly", "2026-07")}, {}

    result = build_unlinked_analytics_revenue_fallback_probe(
        reference_date=date(2026, 7, 19),
        timesheet_data=timesheet_data,
        linked_revenue_lookup=fake_lookup,
    )

    assert captured_job_ids == [{77}]
    assert result["summary"] == {
        "rowCount": 1,
        "segmentCount": 1,
        "linkedSegmentCount": 1,
        "missingRateSegmentCount": 1,
        "suppressedByLinkedMonthlySiteMonth": 1,
        "hours": 1.0,
        "topLevelLegacyRevenue": 0.0,
        "customerDetailLegacyRevenue": 0.0,
    }
    assert result["rows"] == [
        {
            "weekStart": "2026-07-12",
            "customerName": "Linked Customer",
            "siteAddress": "Linked Monthly",
            "rateType": "monthly",
            "segmentCount": 1,
            "visitSegmentCount": 0,
            "shiftIds": [11],
            "hours": 1.0,
            "topLevelLegacyRevenue": 0.0,
            "customerDetailLegacyRevenue": 0.0,
            "suppressedByLinkedMonthlySiteMonth": 1,
        }
    ]


def test_cli_requires_database_url(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    exit_code = main(["--reference-date", "2026-07-27"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "DATABASE_URL or --db-url is required" in captured.err
