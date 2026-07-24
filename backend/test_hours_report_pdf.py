"""Contract tests for the canonical in-memory Hours Report PDF export."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Any

import pytest
from pypdf import PdfReader

import hours_report_pdf as pdf
import time_tracker_api as api

PDF_ROUTE = "/api/admin/reports/hours/pdf"


def report_payload(
    *,
    employee_name: str = "Catalina Gomez",
    rows: bool = True,
    exceptions_only: bool = False,
) -> dict[str, Any]:
    summary = [
        {
            "employeeId": 17,
            "employeeName": employee_name,
            "totalHours": 7.5,
            "totalShifts": 1,
        },
    ] if rows else []
    detail = [
        {
            "employeeId": 17,
            "employeeName": employee_name,
            "date": "2026-07-21",
            "dateLabel": "Tue, Jul 21",
            "clockIn": "07:00 AM",
            "clockOut": "02:30 PM",
            "hours": 7.5,
            "location": "Firefly Grill",
            "customer": "Firefly Grill",
            "gpsExceptions": ["clock_in - accuracy 140m"],
            "gpsExceptionsText": "clock_in - accuracy 140m",
        },
    ] if rows else []
    return {
        "success": True,
        "period": "month",
        "startDate": "2026-07-01",
        "endDate": "2026-07-31",
        "exceptionsOnly": exceptions_only,
        "rows": detail,
        "summary": summary,
        "totalHours": 7.5 if rows else 0,
        "totalShifts": 1 if rows else 0,
        "totalGpsExceptionShifts": 1 if rows else 0,
        "totalGpsExceptions": 1 if rows else 0,
    }


def assert_valid_pdf(payload: bytes) -> None:
    assert payload.startswith(b"%PDF-")
    assert b"%%EOF" in payload[-1024:]
    assert len(payload) > 1000


def extract_pdf_text(payload: bytes) -> str:
    return "\n".join(
        page.extract_text() or ""
        for page in PdfReader(BytesIO(payload)).pages
    )


def test_renderer_builds_populated_and_empty_hours_only_documents():
    populated_data = report_payload(
        employee_name="Evidence Employee",
        exceptions_only=True,
    )
    populated_data.update(
        totalHours=123.45,
        totalShifts=41,
        totalGpsExceptionShifts=17,
        totalGpsExceptions=23,
    )
    populated_data["summary"][0].update(totalHours=67.89, totalShifts=29)
    populated_data["rows"][0].update(
        date="2026-07-19",
        clockIn="06:43 AM",
        clockOut="11:17 AM",
        hours=4.56,
        location="Distinctive Location 442",
        gpsExceptionsText="clock_out - outside geofence 314m",
    )
    populated = pdf.build_hours_report_pdf(populated_data, employee_id=17)
    assert_valid_pdf(populated)
    populated_text = extract_pdf_text(populated)
    for expected in (
        "Monthly Hours Report",
        "2026-07-01 through 2026-07-31",
        "Employee filter: Evidence Employee",
        "GPS exceptions only: Yes",
        (
            "Total hours\nCompleted shifts\nEmployees\n"
            "Shifts with GPS exceptions\nGPS exception events\n"
            "123.45\n41\n1\n17\n23"
        ),
        (
            "Summary by employee\nEmployee\nCompleted shifts\nTotal hours\n"
            "Evidence Employee\n29\n67.89"
        ),
        (
            "Shift detail\nEmployee\nDate\nClock in\nClock out\nHours\n"
            "Location\nGPS exceptions\nEvidence Employee\n2026-07-19\n"
            "06:43 AM\n11:17 AM\n4.56\nDistinctive Location 442\n"
            "clock_out - outside geofence 314m"
        ),
    ):
        assert expected in populated_text
    for prohibited in (
        "Revenue",
        "Labor Cost",
        "Gross Profit",
        "Margin",
        "Payroll",
        "Overtime",
    ):
        assert prohibited not in populated_text

    empty = pdf.build_hours_report_pdf(
        report_payload(rows=False),
        employee_id=999,
    )
    assert_valid_pdf(empty)
    empty_text = extract_pdf_text(empty)
    assert "Employee filter: Employee ID 999" in empty_text
    assert "No completed shifts matched these report criteria." in empty_text
    assert "No shift rows are available for this report." in empty_text
    assert "0.00" in empty_text


def test_renderer_escapes_markup_controls_and_bounds_unbroken_text():
    hostile = "<b>A & B</b>\x00<script>alert('x')</script>"
    escaped = pdf._literal_text(hostile)
    assert escaped == (
        "&lt;b&gt;A&#160;&amp;&#160;B&lt;/b&gt;[U+0000]"
        "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
    )

    oversized = "x" * 900
    chunks = pdf._text_chunks(oversized)
    assert len(chunks) > 1
    assert "".join(chunks) == oversized
    assert all(len(chunk) <= pdf.MAX_TABLE_CELL_TEXT_LENGTH for chunk in chunks)

    employee_name = "José   <b>A & B</b> 👷 中文"
    tail_marker = "END-OF-GPS-EVIDENCE"
    data = report_payload(employee_name=employee_name)
    data["rows"][0]["location"] = (
        "<link href='file:///etc/passwd'>"
        + ("\n" * 5000)
        + oversized
    )
    data["rows"][0]["gpsExceptionsText"] = (
        "José 👷 "
        + oversized
        + tail_marker
    )
    rendered = pdf.build_hours_report_pdf(data, employee_id=17)
    assert_valid_pdf(rendered)
    extracted = extract_pdf_text(rendered)
    compact = "".join(extracted.split())
    assert "José   <b>A & B</b>" in extracted
    assert "José<b>A&B</b>[U+1F477][U+4E2D][U+6587]" in compact
    assert "&lt;b&gt;" not in extracted
    assert "<linkhref='file:///etc/passwd'>" in compact
    assert ("x" * len(oversized)) in compact
    assert tail_marker in compact


def test_renderer_isolates_concurrent_request_buffers():
    payloads = [
        report_payload(employee_name=f"Employee {index}")
        for index in range(6)
    ]
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(pdf.build_hours_report_pdf, payloads))

    assert all(result.startswith(b"%PDF-") for result in results)
    assert len(set(results)) == len(results)


def test_pdf_endpoint_requires_admin_before_computing(
    client,
    emp_auth,
    monkeypatch,
):
    calls = 0

    def forbidden_compute(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("unauthorized request reached report computation")

    monkeypatch.setattr(api, "_compute_hours_report", forbidden_compute)

    assert client.get(PDF_ROUTE).status_code == 401
    assert client.get(PDF_ROUTE, headers=emp_auth).status_code == 403
    assert calls == 0


def test_pdf_endpoint_propagates_all_criteria_once_and_sets_private_headers(
    client,
    auth,
    monkeypatch,
):
    compute_calls: list[tuple[Any, ...]] = []
    render_calls: list[tuple[Any, ...]] = []
    generated = b"%PDF-1.4\ncanonical-hours\n%%EOF\n"

    def fake_compute(period, date, employee_id, exceptions_only):
        compute_calls.append((period, date, employee_id, exceptions_only))
        data = report_payload(exceptions_only=exceptions_only)
        data["period"] = period
        return data

    def fake_renderer(data, *, employee_id):
        render_calls.append((data, employee_id))
        return generated

    def forbidden_subprocess(*_args, **_kwargs):
        raise AssertionError("canonical PDF export invoked the legacy subprocess")

    monkeypatch.setattr(api, "_compute_hours_report", fake_compute)
    monkeypatch.setattr(api, "build_hours_report_pdf", fake_renderer)
    monkeypatch.setattr(api.subprocess, "run", forbidden_subprocess)

    for period in ("day", "week", "month", "year"):
        response = client.get(
            PDF_ROUTE,
            headers=auth,
            params={
                "period": period,
                "date": "2026-07-21",
                "employee_id": 17,
                "exceptions_only": "true",
            },
        )
        assert response.status_code == 200
        assert response.content == generated
        assert response.headers["content-type"] == "application/pdf"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-disposition"] == (
            f'attachment; filename="eom_hours_{period}_2026-07-01'
            '_employee-17_gps-exceptions.pdf"'
        )

    assert compute_calls == [
        (period, "2026-07-21", 17, True)
        for period in ("day", "week", "month", "year")
    ]
    assert [call[1] for call in render_calls] == [17, 17, 17, 17]
    assert all(call[0]["exceptionsOnly"] is True for call in render_calls)


@pytest.mark.parametrize(
    ("params", "expected_detail"),
    [
        (
            {"period": "quarter", "date": "2026-07-21"},
            "period must be day, week, month, or year",
        ),
        (
            {"period": "month", "date": "2026-99-99"},
            "Invalid date format, use YYYY-MM-DD",
        ),
    ],
)
def test_pdf_endpoint_preserves_canonical_criteria_errors(
    client,
    auth,
    monkeypatch,
    params,
    expected_detail,
):
    def forbidden_renderer(*_args, **_kwargs):
        raise AssertionError("invalid criteria reached the renderer")

    monkeypatch.setattr(api, "build_hours_report_pdf", forbidden_renderer)

    response = client.get(PDF_ROUTE, headers=auth, params=params)
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": expected_detail}


def test_pdf_endpoint_returns_real_in_memory_pdf_for_empty_report(
    client,
    auth,
    monkeypatch,
):
    monkeypatch.setattr(
        api,
        "_compute_hours_report",
        lambda *_args, **_kwargs: report_payload(rows=False),
    )

    response = client.get(
        PDF_ROUTE,
        headers=auth,
        params={"period": "month", "date": "2026-07-21"},
    )

    assert response.status_code == 200
    assert_valid_pdf(response.content)


def test_employee_id_zero_keeps_canonical_all_employee_semantics(
    client,
    auth,
    monkeypatch,
):
    compute_calls: list[tuple[Any, ...]] = []

    def fake_compute(*args):
        compute_calls.append(args)
        return report_payload()

    monkeypatch.setattr(api, "_compute_hours_report", fake_compute)

    response = client.get(
        PDF_ROUTE,
        headers=auth,
        params={"period": "month", "date": "2026-07-21", "employee_id": 0},
    )

    assert response.status_code == 200
    assert compute_calls == [("month", "2026-07-21", 0, False)]
    assert response.headers["content-disposition"] == (
        'attachment; filename="eom_hours_month_2026-07-01.pdf"'
    )
    assert "Employee filter: All employees" in extract_pdf_text(response.content)


def test_existing_hours_json_and_csv_contracts_remain_available(
    client,
    auth,
    monkeypatch,
):
    data = report_payload()
    monkeypatch.setattr(api, "_compute_hours_report", lambda *_args, **_kwargs: data)

    json_response = client.get("/api/admin/reports/hours", headers=auth)
    assert json_response.status_code == 200
    assert json_response.json() == data

    csv_response = client.get("/api/admin/reports/hours/export", headers=auth)
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert "EOM Hours Report" in csv_response.text
    assert "Catalina Gomez" in csv_response.text
