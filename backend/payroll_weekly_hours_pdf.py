"""Render payroll weekly hours as an in-memory PDF."""

from __future__ import annotations

import io
from typing import Any, Mapping

from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, Table

from hours_report_pdf import (
    COMPANY_NAME,
    HEADER_COLOR,
    HEADER_TEXT_COLOR,
    MUTED_COLOR,
    TEXT_COLOR,
    _integer,
    _number,
    _paragraph,
    _table_style,
    _text_chunks,
)

PAGE_SIZE = landscape(letter)


def _draw_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setTitle("EOM Payroll Weekly Hours")
    canvas.setAuthor(COMPANY_NAME)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED_COLOR)
    canvas.drawString(
        document.leftMargin,
        0.25 * inch,
        "Confidential payroll hours record",
    )
    canvas.drawRightString(
        PAGE_SIZE[0] - document.rightMargin,
        0.25 * inch,
        f"Page {document.page}",
    )
    canvas.restoreState()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _status_label(value: Any) -> str:
    status = str(value or "unavailable").strip().lower()
    return {
        "unverified": "Not verified / No verificado",
        "verified": "Verified / Verificado",
        "reopened": "Reopened / Reabierto",
        "finalized": "Finalized / Finalizado",
    }.get(status, "Unavailable / No disponible")


def _yes_no(value: Any) -> str:
    return "Yes / Si" if bool(value) else "No"


def _hours(value: Any) -> str:
    return f"{_number(value):.2f}h"


def _signed_hours_from_minutes(value: Any) -> str:
    minutes = _number(value)
    sign = "+" if minutes > 0 else "-" if minutes < 0 else ""
    return f"{sign}{abs(minutes) / 60:.2f}h"


def _issue_text(codes: Any) -> str:
    items = [str(code) for code in _list(codes) if str(code).strip()]
    return "; ".join(items) if items else "-"


def _correction_text(day: Mapping[str, Any]) -> str:
    correction = _mapping(day.get("correction"))
    if not correction:
        return ""
    return (
        f"Corrected from {_hours(correction.get('sourceTotalHours'))}; "
        f"change {_signed_hours_from_minutes(correction.get('deltaMinutes'))}; "
        f"reason: {correction.get('reason') or ''}"
    )


def _day_cell_text(day: Any) -> str:
    day_map = _mapping(day)
    value = _hours(day_map.get("totalHours"))
    correction = _correction_text(day_map)
    issues = _issue_text(day_map.get("issueCodes"))
    details = [correction]
    if issues != "-":
        details.append(f"Issues: {issues}")
    return " | ".join([value, *[item for item in details if item]])


def _correction_rows(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for employee in _list(data.get("employees")):
        employee_map = _mapping(employee)
        for day in _list(employee_map.get("days")):
            day_map = _mapping(day)
            correction = _mapping(day_map.get("correction"))
            if not correction:
                continue
            rows.append(
                {
                    "employeeName": employee_map.get("employeeName"),
                    "date": day_map.get("date"),
                    "sourceTotalHours": correction.get("sourceTotalHours"),
                    "correctedTotalHours": correction.get("correctedTotalHours"),
                    "deltaMinutes": correction.get("deltaMinutes"),
                    "reason": correction.get("reason"),
                },
            )
    return rows


def build_payroll_weekly_hours_pdf(
    data: Mapping[str, Any],
    *,
    verification: Mapping[str, Any] | None = None,
) -> bytes:
    """Build a PDF from the payroll weekly-hours read model."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        title="EOM Payroll Weekly Hours",
        author=COMPANY_NAME,
        leftMargin=0.35 * inch,
        rightMargin=0.35 * inch,
        topMargin=0.35 * inch,
        bottomMargin=0.45 * inch,
    )

    sample_styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PayrollWeeklyTitle",
        parent=sample_styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=21,
        alignment=TA_CENTER,
        textColor=HEADER_COLOR,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "PayrollWeeklySubtitle",
        parent=sample_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        alignment=TA_CENTER,
        textColor=MUTED_COLOR,
        spaceAfter=10,
    )
    section_style = ParagraphStyle(
        "PayrollWeeklySection",
        parent=sample_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=12,
        alignment=TA_LEFT,
        textColor=HEADER_COLOR,
        spaceBefore=9,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "PayrollWeeklyBody",
        parent=sample_styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.2,
        leading=8.5,
        textColor=TEXT_COLOR,
        wordWrap="CJK",
    )
    header_style = ParagraphStyle(
        "PayrollWeeklyHeader",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=7.2,
        leading=8.5,
        textColor=HEADER_TEXT_COLOR,
    )

    summary = _mapping(data.get("summary"))
    verification_state = _mapping(verification)
    week_start = str(data.get("weekStart") or "")
    week_end = str(data.get("weekEnd") or "")
    timezone = str(data.get("timezone") or "")

    story: list[Any] = [
        Paragraph("Payroll Weekly Hours / Horas semanales de nomina", title_style),
        _paragraph(f"{COMPANY_NAME} | {week_start} through {week_end} | {timezone}", subtitle_style),
    ]

    summary_table = Table(
        [
            [
                _paragraph("Total hours / Horas", header_style),
                _paragraph("Employees with hours / Empleados", header_style),
                _paragraph("Corrections / Correcciones", header_style),
                _paragraph("Items needing review / Revisar", header_style),
            ],
            [
                f"{_number(summary.get('totalHours')):.2f}",
                str(_integer(summary.get("employeesWithHours"))),
                str(_integer(summary.get("correctionCount"))),
                str(_integer(summary.get("issueCount"))),
            ],
        ],
        colWidths=[2.45 * inch, 2.45 * inch, 2.45 * inch, 2.45 * inch],
        hAlign="LEFT",
    )
    summary_table.setStyle(_table_style(numeric_columns=(0, 1, 2, 3)))
    story.extend([summary_table, Spacer(1, 0.08 * inch)])

    verification_table = Table(
        [
            [
                _paragraph("Verification / Verificacion", header_style),
                _paragraph("Stale / Cambios", header_style),
                _paragraph("Verified by / Verifico", header_style),
                _paragraph("Finalized by / Finalizo", header_style),
            ],
            [
                _paragraph(_status_label(verification_state.get("status")), body_style),
                _paragraph(_yes_no(verification_state.get("stale")), body_style),
                _paragraph(verification_state.get("verifiedByName") or "-", body_style),
                _paragraph(verification_state.get("finalizedByName") or "-", body_style),
            ],
        ],
        colWidths=[2.45 * inch, 2.45 * inch, 2.45 * inch, 2.45 * inch],
        hAlign="LEFT",
    )
    verification_table.setStyle(_table_style())
    story.extend([verification_table, Spacer(1, 0.08 * inch)])

    employees = [_mapping(employee) for employee in _list(data.get("employees"))]
    story.append(Paragraph("Summary by employee / Resumen por empleado", section_style))
    if employees:
        employee_rows: list[list[Any]] = [
            [
                _paragraph("Employee / Empleado", header_style),
                _paragraph("Status / Estado", header_style),
                _paragraph("Total hours / Horas", header_style),
                _paragraph("Minutes / Minutos", header_style),
                _paragraph("Completed shifts / Turnos", header_style),
                _paragraph("Corrections / Correcciones", header_style),
                _paragraph("Issues / Revisar", header_style),
            ],
        ]
        for employee in employees:
            employee_rows.append(
                [
                    _paragraph(employee.get("employeeName"), body_style),
                    _paragraph("Active" if employee.get("active") is not False else "Inactive", body_style),
                    f"{_number(employee.get('totalHours')):.2f}",
                    str(_integer(employee.get("totalMinutes"))),
                    str(_integer(employee.get("completedShiftCount"))),
                    str(_integer(employee.get("correctionCount"))),
                    _paragraph(_issue_text(employee.get("issueCodes")), body_style),
                ],
            )
        employee_table = LongTable(
            employee_rows,
            colWidths=[
                2.4 * inch,
                0.8 * inch,
                0.75 * inch,
                0.75 * inch,
                0.95 * inch,
                0.9 * inch,
                3.25 * inch,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )
        employee_table.setStyle(_table_style(numeric_columns=(2, 3, 4, 5)))
        story.append(employee_table)
    else:
        story.append(Paragraph("No employees matched this payroll week.", body_style))

    story.append(Paragraph("Daily totals / Totales diarios", section_style))
    if employees:
        day_rows: list[list[Any]] = [
            [
                _paragraph("Employee", header_style),
                _paragraph("Sun", header_style),
                _paragraph("Mon", header_style),
                _paragraph("Tue", header_style),
                _paragraph("Wed", header_style),
                _paragraph("Thu", header_style),
                _paragraph("Fri", header_style),
                _paragraph("Sat", header_style),
            ],
        ]
        for employee in employees:
            days = _list(employee.get("days"))
            while len(days) < 7:
                days.append({})
            day_rows.append(
                [
                    _paragraph(employee.get("employeeName"), body_style),
                    *[_paragraph(_day_cell_text(day), body_style) for day in days[:7]],
                ],
            )
        day_table = LongTable(
            day_rows,
            colWidths=[1.35 * inch, *([1.21 * inch] * 7)],
            repeatRows=1,
            hAlign="LEFT",
        )
        day_table.setStyle(_table_style())
        story.append(day_table)
    else:
        story.append(Paragraph("No daily totals are available.", body_style))

    corrections = _correction_rows(data)
    story.append(Paragraph("Correction detail / Detalle de correcciones", section_style))
    if corrections:
        correction_table_rows: list[list[Any]] = [
            [
                _paragraph("Employee", header_style),
                _paragraph("Date", header_style),
                _paragraph("Source", header_style),
                _paragraph("Corrected", header_style),
                _paragraph("Change", header_style),
                _paragraph("Reason", header_style),
            ],
        ]
        for row in corrections:
            reason_chunks = _text_chunks(row.get("reason"))
            for index, chunk in enumerate(reason_chunks):
                correction_table_rows.append(
                    [
                        _paragraph(row.get("employeeName") if index == 0 else "", body_style),
                        _paragraph(row.get("date") if index == 0 else "", body_style),
                        _hours(row.get("sourceTotalHours")) if index == 0 else "",
                        _hours(row.get("correctedTotalHours")) if index == 0 else "",
                        _signed_hours_from_minutes(row.get("deltaMinutes")) if index == 0 else "",
                        _paragraph(chunk, body_style),
                    ],
                )
        correction_table = LongTable(
            correction_table_rows,
            colWidths=[1.7 * inch, 0.85 * inch, 0.75 * inch, 0.75 * inch, 0.75 * inch, 5.0 * inch],
            repeatRows=1,
            hAlign="LEFT",
        )
        correction_table.setStyle(_table_style(numeric_columns=(2, 3, 4)))
        story.append(correction_table)
    else:
        story.append(Paragraph("No active payroll hour corrections for this week.", body_style))

    document.build(
        story,
        onFirstPage=_draw_footer,
        onLaterPages=_draw_footer,
    )
    return buffer.getvalue()
