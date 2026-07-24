"""Render the canonical admin Hours Report as an in-memory PDF."""

from __future__ import annotations

import html
import io
from typing import Any, Mapping

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

COMPANY_NAME = "Effingham Office Maids"
PAGE_SIZE = landscape(letter)
TEXT_COLOR = colors.HexColor("#1f2937")
MUTED_COLOR = colors.HexColor("#64748b")
HEADER_COLOR = colors.HexColor("#17365d")
HEADER_TEXT_COLOR = colors.white
ROW_ALT_COLOR = colors.HexColor("#f8fafc")
GRID_COLOR = colors.HexColor("#cbd5e1")
MAX_TABLE_CELL_TEXT_LENGTH = 240


def _font_safe_tokens(value: Any) -> list[str]:
    """Preserve text using visible code-point escapes for unsupported glyphs."""
    text = str(value if value is not None else "")
    tokens: list[str] = []
    for character in text:
        code_point = ord(character)
        if code_point < 32 or 127 <= code_point < 160:
            tokens.append(f"[U+{code_point:04X}]")
            continue
        try:
            character.encode("cp1252")
        except UnicodeEncodeError:
            tokens.append(f"[U+{code_point:04X}]")
        else:
            tokens.append(character)
    return tokens


def _font_safe_text(value: Any) -> str:
    return "".join(_font_safe_tokens(value))


def _literal_text(value: Any) -> str:
    """Return complete printable text without allowing paragraph markup."""
    escaped = html.escape(_font_safe_text(value))
    # ReportLab Paragraph collapses ordinary whitespace runs. Non-breaking-space
    # entities preserve every stored space while remaining literal text.
    return escaped.replace(" ", "&#160;")


def _text_chunks(
    value: Any,
    *,
    limit: int = MAX_TABLE_CELL_TEXT_LENGTH,
) -> list[str]:
    """Split complete text into row-sized chunks without splitting an escape."""
    chunks: list[str] = []
    current: list[str] = []
    current_length = 0
    for token in _font_safe_tokens(value):
        if current and current_length + len(token) > limit:
            chunks.append("".join(current))
            current = []
            current_length = 0
        current.append(token)
        current_length += len(token)
    if current or not chunks:
        chunks.append("".join(current))
    return chunks


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_literal_text(value), style)


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _period_name(period: Any) -> str:
    value = str(period or "").strip().lower()
    return {
        "day": "Daily",
        "week": "Weekly",
        "month": "Monthly",
        "year": "Yearly",
    }.get(value, value.title() or "Hours")


def _employee_filter_label(data: Mapping[str, Any], employee_id: Any) -> str:
    if not employee_id:
        return "All employees"

    try:
        requested_id = int(employee_id)
    except (TypeError, ValueError):
        return f"Employee ID {employee_id}"

    for collection_name in ("summary", "rows"):
        collection = data.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, Mapping):
                continue
            try:
                item_id = int(item.get("employeeId"))
            except (TypeError, ValueError):
                continue
            if item_id == requested_id:
                name = str(item.get("employeeName") or "").strip()
                if name:
                    return name
    return f"Employee ID {requested_id}"


def _table_style(*, numeric_columns: tuple[int, ...] = ()) -> TableStyle:
    commands: list[tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_COLOR),
        ("TEXTCOLOR", (0, 0), (-1, 0), HEADER_TEXT_COLOR),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT_COLOR]),
    ]
    commands.extend(
        ("ALIGN", (column, 1), (column, -1), "RIGHT")
        for column in numeric_columns
    )
    return TableStyle(commands)


def _draw_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setTitle("EOM Hours Report")
    canvas.setAuthor(COMPANY_NAME)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED_COLOR)
    canvas.drawString(
        document.leftMargin,
        0.25 * inch,
        "Confidential employee time record",
    )
    canvas.drawRightString(
        PAGE_SIZE[0] - document.rightMargin,
        0.25 * inch,
        f"Page {document.page}",
    )
    canvas.restoreState()


def build_hours_report_pdf(
    data: Mapping[str, Any],
    *,
    employee_id: int | None = None,
) -> bytes:
    """Build a PDF from the canonical ``_compute_hours_report`` result."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        title="EOM Hours Report",
        author=COMPANY_NAME,
        leftMargin=0.4 * inch,
        rightMargin=0.4 * inch,
        topMargin=0.4 * inch,
        bottomMargin=0.45 * inch,
    )

    sample_styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "HoursReportTitle",
        parent=sample_styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=22,
        alignment=TA_CENTER,
        textColor=HEADER_COLOR,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "HoursReportSubtitle",
        parent=sample_styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=MUTED_COLOR,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "HoursReportSection",
        parent=sample_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=13,
        alignment=TA_LEFT,
        textColor=HEADER_COLOR,
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "HoursReportBody",
        parent=sample_styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=TEXT_COLOR,
    )
    table_header_style = ParagraphStyle(
        "HoursReportTableHeader",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=9,
        textColor=HEADER_TEXT_COLOR,
    )
    table_cell_style = ParagraphStyle(
        "HoursReportTableCell",
        parent=body_style,
        fontSize=7.5,
        leading=9,
        wordWrap="CJK",
    )

    period = str(data.get("period") or "")
    start_date = str(data.get("startDate") or "")
    end_date = str(data.get("endDate") or "")
    exceptions_only = bool(data.get("exceptionsOnly"))
    employee_label = _employee_filter_label(data, employee_id)

    story: list[Any] = [
        Paragraph(f"{_period_name(period)} Hours Report", title_style),
        _paragraph(
            f"{COMPANY_NAME} | {start_date} through {end_date}",
            subtitle_style,
        ),
        _paragraph(
            "Employee filter: "
            f"{employee_label} | GPS exceptions only: "
            f"{'Yes' if exceptions_only else 'No'}",
            subtitle_style,
        ),
    ]

    summary_data = [
        [
            _paragraph("Total hours", table_header_style),
            _paragraph("Completed shifts", table_header_style),
            _paragraph("Employees", table_header_style),
            _paragraph("Shifts with GPS exceptions", table_header_style),
            _paragraph("GPS exception events", table_header_style),
        ],
        [
            f"{_number(data.get('totalHours')):.2f}",
            str(_integer(data.get("totalShifts"))),
            str(len(data.get("summary", [])) if isinstance(data.get("summary"), list) else 0),
            str(_integer(data.get("totalGpsExceptionShifts"))),
            str(_integer(data.get("totalGpsExceptions"))),
        ],
    ]
    summary_table = Table(
        summary_data,
        colWidths=[1.96 * inch, 1.96 * inch, 1.96 * inch, 1.96 * inch, 1.96 * inch],
        hAlign="LEFT",
    )
    summary_table.setStyle(_table_style(numeric_columns=(0, 1, 2, 3, 4)))
    story.extend([summary_table, Spacer(1, 0.08 * inch)])

    summary = data.get("summary", [])
    if not isinstance(summary, list):
        summary = []
    story.append(Paragraph("Summary by employee", section_style))
    if summary:
        employee_rows: list[list[Any]] = [
            [
                _paragraph("Employee", table_header_style),
                _paragraph("Completed shifts", table_header_style),
                _paragraph("Total hours", table_header_style),
            ],
        ]
        for item in summary:
            row = item if isinstance(item, Mapping) else {}
            for index, employee_chunk in enumerate(
                _text_chunks(row.get("employeeName")),
            ):
                employee_rows.append(
                    [
                        _paragraph(employee_chunk, table_cell_style),
                        str(_integer(row.get("totalShifts"))) if index == 0 else "",
                        f"{_number(row.get('totalHours')):.2f}" if index == 0 else "",
                    ],
                )
        employee_table = LongTable(
            employee_rows,
            colWidths=[6.4 * inch, 1.7 * inch, 1.7 * inch],
            repeatRows=1,
            hAlign="LEFT",
        )
        employee_table.setStyle(_table_style(numeric_columns=(1, 2)))
        story.append(employee_table)
    else:
        story.append(
            Paragraph(
                "No completed shifts matched these report criteria.",
                body_style,
            ),
        )

    rows = data.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    story.append(Paragraph("Shift detail", section_style))
    if rows:
        detail_rows: list[list[Any]] = [
            [
                _paragraph("Employee", table_header_style),
                _paragraph("Date", table_header_style),
                _paragraph("Clock in", table_header_style),
                _paragraph("Clock out", table_header_style),
                _paragraph("Hours", table_header_style),
                _paragraph("Location", table_header_style),
                _paragraph("GPS exceptions", table_header_style),
            ],
        ]
        for item in rows:
            row = item if isinstance(item, Mapping) else {}
            employee_chunks = _text_chunks(row.get("employeeName"))
            location_chunks = _text_chunks(row.get("location"))
            exception_chunks = _text_chunks(row.get("gpsExceptionsText"))
            continuation_rows = max(
                len(employee_chunks),
                len(location_chunks),
                len(exception_chunks),
            )
            for index in range(continuation_rows):
                detail_rows.append(
                    [
                        _paragraph(
                            employee_chunks[index]
                            if index < len(employee_chunks)
                            else "",
                            table_cell_style,
                        ),
                        _paragraph(
                            row.get("date") if index == 0 else "",
                            table_cell_style,
                        ),
                        _paragraph(
                            row.get("clockIn") if index == 0 else "",
                            table_cell_style,
                        ),
                        _paragraph(
                            row.get("clockOut") if index == 0 else "",
                            table_cell_style,
                        ),
                        f"{_number(row.get('hours')):.2f}" if index == 0 else "",
                        _paragraph(
                            location_chunks[index]
                            if index < len(location_chunks)
                            else "",
                            table_cell_style,
                        ),
                        _paragraph(
                            exception_chunks[index]
                            if index < len(exception_chunks)
                            else "",
                            table_cell_style,
                        ),
                    ],
                )
        detail_table = LongTable(
            detail_rows,
            colWidths=[
                1.35 * inch,
                0.8 * inch,
                0.65 * inch,
                0.65 * inch,
                0.55 * inch,
                2.1 * inch,
                3.7 * inch,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )
        detail_table.setStyle(_table_style(numeric_columns=(4,)))
        story.append(detail_table)
    else:
        story.append(
            Paragraph(
                "No shift rows are available for this report.",
                body_style,
            ),
        )

    document.build(
        story,
        onFirstPage=_draw_footer,
        onLaterPages=_draw_footer,
    )
    return buffer.getvalue()
