# File: backend/report_generator.py
"""Monthly hours report generator for employee tracking"""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class MonthlyReportGenerator:
    """Generate monthly employee hours reports"""

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_monthly_report(
        self,
        employee_data: Dict[str, Any],
        month: int,
        year: int,
        company_name: str = "Your Company",
    ) -> str:
        """Generate comprehensive monthly hours report"""

        month_name = datetime(year, month, 1).strftime("%B")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monthly_hours_report_{month_name}_{year}_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)

        try:
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                topMargin=0.8 * inch,
                bottomMargin=0.8 * inch,
                leftMargin=0.8 * inch,
                rightMargin=0.8 * inch,
            )

            styles = getSampleStyleSheet()
            story: List[Any] = []

            title_style = ParagraphStyle(
                "ReportTitle",
                parent=styles["Heading1"],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.HexColor("#2c3e50"),
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )

            section_style = ParagraphStyle(
                "SectionHeader",
                parent=styles["Heading2"],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor("#34495e"),
                fontName="Helvetica-Bold",
            )

            story.append(Spacer(1, 50))
            story.append(Paragraph("MONTHLY HOURS REPORT", title_style))
            story.append(Paragraph(f"{month_name} {year}", title_style))
            story.append(Spacer(1, 30))

            company_info = f"""
            <para align="center" fontSize="14">
            <b>Company:</b> {company_name}<br/>
            <b>Report Generated:</b> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}<br/>
            <b>Reporting Period:</b> {month_name} 1, {year} - {self._get_last_day_of_month(month, year)}, {year}<br/>
            </para>
            """
            story.append(Paragraph(company_info, styles["Normal"]))
            story.append(PageBreak())

            story.append(Paragraph("EXECUTIVE SUMMARY", section_style))
            summary_data = self._calculate_summary_stats(employee_data)

            summary_table_data = [
                ["Metric", "Value"],
                ["Total Employees", str(summary_data["total_employees"])],
                ["Total Hours Worked", f"{summary_data['total_hours']:.1f}"],
                ["Average Hours per Employee", f"{summary_data['avg_hours']:.1f}"],
                ["Total Revenue", f"${summary_data.get('total_revenue', 0.0):,.2f}"],
                ["Total Labor Cost (Burdened)", f"${summary_data.get('total_labor_cost', 0.0):,.2f}"],
                [
                    "Gross Profit",
                    f"${(summary_data.get('total_revenue', 0.0) - summary_data.get('total_labor_cost', 0.0)):,.2f}",
                ],
                ["Overall Margin", f"{summary_data.get('overall_margin', 0.0):.1f}%"],
                ["Most Active Employee", summary_data["top_employee"]],
            ]

            summary_table = Table(summary_table_data, colWidths=[3 * inch, 2.5 * inch])
            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 1), (-1, -1), 10),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                    ]
                )
            )

            story.append(summary_table)
            story.append(Spacer(1, 30))

            story.append(Paragraph("EMPLOYEE PERFORMANCE & COST", section_style))
            employee_table_data = [["Employee Name", "Total Hours", "Labor Cost", "Revenue Gen.", "Margin %"]]

            for emp in employee_data.get("employees", []):
                total_hours = sum(shift["hours"] for shift in emp.get("shifts", []))
                labor_cost = emp.get("totalLaborCost", 0.0)
                revenue = emp.get("totalRevenue", 0.0)
                margin = ((revenue - labor_cost) / revenue * 100) if revenue > 0 else 0.0

                employee_table_data.append(
                    [
                        emp.get("name", "Unknown"),
                        f"{total_hours:.1f}",
                        f"${labor_cost:,.2f}",
                        f"${revenue:,.2f}",
                        f"{margin:.1f}%",
                    ]
                )

            employee_table = Table(
                employee_table_data,
                colWidths=[2.2 * inch, 1 * inch, 1.2 * inch, 1.2 * inch, 1 * inch],
            )
            employee_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                    ]
                )
            )

            story.append(employee_table)
            story.append(PageBreak())

            story.append(Paragraph("DAILY BREAKDOWN", section_style))
            daily_data = self._calculate_daily_breakdown(employee_data, month, year)
            daily_table_data = [["Date", "Total Hours", "Employees Working", "Average Hours/Employee"]]

            for day_data in daily_data:
                daily_table_data.append(
                    [
                        day_data["date"],
                        f"{day_data['total_hours']:.1f}",
                        str(day_data["employee_count"]),
                        f"{day_data['avg_hours']:.1f}",
                    ]
                )

            daily_table = Table(daily_table_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
            daily_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 1), (-1, -1), 8),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                    ]
                )
            )

            story.append(daily_table)
            story.append(Spacer(1, 20))

            story.append(Spacer(1, 30))
            footer_text = f"""
            <para align="center" fontSize="10" textColor="#6c757d">
            This report was generated automatically on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}<br/>
            Report contains confidential employee information - handle according to company policy
            </para>
            """
            story.append(Paragraph(footer_text, styles["Normal"]))

            doc.build(story)
            return filepath

        except Exception as e:
            print(f"Monthly report generation failed: {e}")
            return None

    def _calculate_summary_stats(self, employee_data: Dict[str, Any]) -> Dict[str, Any]:
        employees = employee_data.get("employees", [])

        total_employees = len(employees)
        total_hours = 0.0
        total_revenue = 0.0
        total_labor_cost = 0.0
        top_employee = "N/A"
        top_hours = 0.0

        for emp in employees:
            emp_total = sum(shift["hours"] for shift in emp.get("shifts", []))
            total_hours += emp_total
            total_revenue += emp.get("totalRevenue", 0.0)
            total_labor_cost += emp.get("totalLaborCost", 0.0)

            if emp_total > top_hours:
                top_hours = emp_total
                top_employee = emp.get("name", "Unknown")

        avg_hours = total_hours / total_employees if total_employees > 0 else 0.0
        overall_margin = ((total_revenue - total_labor_cost) / total_revenue * 100) if total_revenue > 0 else 0.0

        return {
            "total_employees": total_employees,
            "total_hours": total_hours,
            "avg_hours": avg_hours,
            "total_revenue": total_revenue,
            "total_labor_cost": total_labor_cost,
            "overall_margin": overall_margin,
            "top_employee": f"{top_employee} ({top_hours:.1f}h)",
        }

    def _calculate_daily_breakdown(self, employee_data: Dict[str, Any], month: int, year: int) -> List[Dict[str, Any]]:
        daily_data: Dict[str, Dict[str, Any]] = {}

        last_day = self._get_last_day_of_month(month, year)
        for day in range(1, last_day + 1):
            date_str = f"{year}-{month:02d}-{day:02d}"
            daily_data[date_str] = {
                "date": date_str,
                "total_hours": 0.0,
                "employees": set(),
            }

        for emp in employee_data.get("employees", []):
            for shift in emp.get("shifts", []):
                date = shift.get("date", "")
                if date in daily_data:
                    daily_data[date]["total_hours"] += float(shift.get("hours", 0) or 0)
                    daily_data[date]["employees"].add(emp.get("name", "Unknown"))

        result: List[Dict[str, Any]] = []
        for date_str in sorted(daily_data.keys()):
            day_data = daily_data[date_str]
            employee_count = len(day_data["employees"])
            avg_hours = day_data["total_hours"] / employee_count if employee_count > 0 else 0.0

            result.append(
                {
                    "date": datetime.strptime(date_str, "%Y-%m-%d").strftime("%m/%d"),
                    "total_hours": day_data["total_hours"],
                    "employee_count": employee_count,
                    "avg_hours": avg_hours,
                }
            )

        return result

    def _get_last_day_of_month(self, month: int, year: int) -> int:
        if month == 12:
            next_month = datetime(year + 1, 1, 1)
        else:
            next_month = datetime(year, month + 1, 1)

        last_day = next_month - timedelta(days=1)
        return last_day.day

