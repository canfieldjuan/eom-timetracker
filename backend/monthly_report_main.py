#!/usr/bin/env python3
# File: backend/monthly_report_main.py
"""Main script for generating and sending monthly employee hours reports"""

import sys
import json
import os
import argparse
from datetime import datetime, timedelta
from typing import Dict, Any, List
from zoneinfo import ZoneInfo

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from report_generator import MonthlyReportGenerator
from email_service import EmailService

REPORT_TIMEZONE_NAME = os.getenv("TIMEZONE", "America/Chicago")
REPORT_TIMEZONE = ZoneInfo(REPORT_TIMEZONE_NAME)


def _calculate_email_summary(employee_data: Dict[str, Any]) -> Dict[str, Any]:
    employees = employee_data.get("employees", []) if isinstance(employee_data, dict) else []
    total_employees = len(employees)

    total_hours = 0.0
    top_employee_name = ""
    top_employee_hours = 0.0

    # Overtime: weekly hours above 40h per employee (Mon-Sun weeks via ISO week).
    overtime_hours = 0.0
    for emp in employees:
        shifts = emp.get("shifts", []) if isinstance(emp, dict) else []
        emp_total_hours = 0.0
        weekly_totals: Dict[tuple[int, int], float] = {}

        for shift in shifts:
            if not isinstance(shift, dict):
                continue
            hours = float(shift.get("hours", 0) or 0)
            emp_total_hours += hours
            date_str = str(shift.get("date", "") or "").strip()
            if date_str:
                try:
                    dt = datetime.strptime(date_str, "%Y-%m-%d")
                    key = dt.isocalendar()[:2]  # (iso_year, iso_week)
                except ValueError:
                    key = None
                if key:
                    weekly_totals[key] = weekly_totals.get(key, 0.0) + hours

        for week_hours in weekly_totals.values():
            overtime_hours += max(0.0, week_hours - 40.0)

        name = str(emp.get("name", "") or "").strip()
        if emp_total_hours > top_employee_hours and name:
            top_employee_hours = emp_total_hours
            top_employee_name = name

        total_hours += emp_total_hours

    avg_hours = (total_hours / total_employees) if total_employees else 0.0
    top_employee = f"{top_employee_name} ({top_employee_hours:.1f}h)" if top_employee_name else ""

    return {
        "total_employees": total_employees,
        "total_hours": total_hours,
        "avg_hours": avg_hours,
        "overtime_hours": overtime_hours,
        "top_employee": top_employee,
    }

def load_employee_data_from_db(month: int, year: int) -> Dict[str, Any]:
    """Load completed-shift data for the given month from PostgreSQL — the same
    store the running API uses. Replaces the old JSON-file loader, which read a
    data/timesheets.json the runtime never writes (so reports were always empty
    or stale). Runs inside the report subprocess, which inherits DATABASE_URL."""
    import db

    if db._pool is None:
        database_url = os.getenv("DATABASE_URL", "").strip()
        if not database_url:
            print("DATABASE_URL is not set; cannot load report data from database")
            return None
        db.init_pool(database_url)

    # Bound the scan to the requested month at the DB level so the query does not
    # read (and the 60s report subprocess does not choke on) all historical shifts
    # as volume grows. The window is the month in the report timezone: shifts whose
    # local clock-in falls in [first-of-month, first-of-next-month). Comparing the
    # tz-aware clock_in against these local midnights is exactly equivalent to the
    # per-row local month/year check below (kept as a defensive guard).
    month_start = datetime(year, month, 1, tzinfo=REPORT_TIMEZONE)
    if month == 12:
        month_end = datetime(year + 1, 1, 1, tzinfo=REPORT_TIMEZONE)
    else:
        month_end = datetime(year, month + 1, 1, tzinfo=REPORT_TIMEZONE)

    rows = db.query_all(
        """
        SELECT s.employee_id, e.name AS employee_name, s.clock_in, s.clock_out
        FROM shifts s
        JOIN employees e ON e.id = s.employee_id
        WHERE s.clock_out IS NOT NULL
          AND s.clock_in >= %s
          AND s.clock_in < %s
        ORDER BY e.name, s.clock_in
        """,
        (month_start, month_end),
    )

    employees_map: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        clock_in = row["clock_in"]
        clock_out = row["clock_out"]
        if clock_in is None or clock_out is None:
            continue

        # clock_in / clock_out are timezone-aware (TIMESTAMPTZ). Bucket by the
        # local month/year and format hours identically to the previous loader.
        clock_in_local = clock_in.astimezone(REPORT_TIMEZONE)
        clock_out_local = clock_out.astimezone(REPORT_TIMEZONE)

        if clock_in_local.month != month or clock_in_local.year != year:
            continue

        hours = round((clock_out - clock_in).total_seconds() / 3600, 2)
        emp_id = int(row["employee_id"])
        emp_name = str(row.get("employee_name") or f"Employee {emp_id}")

        if emp_id not in employees_map:
            employees_map[emp_id] = {"id": emp_id, "name": emp_name, "shifts": []}

        employees_map[emp_id]["shifts"].append({
            "date": clock_in_local.strftime("%Y-%m-%d"),
            "startTime": clock_in_local.strftime("%H:%M"),
            "endTime": clock_out_local.strftime("%H:%M"),
            "hours": hours,
        })

    employees = sorted(employees_map.values(), key=lambda e: e["name"].lower())
    total_hours = sum(sum(s["hours"] for s in emp["shifts"]) for emp in employees)

    return {
        "employees": employees,
        "summary": {
            "totalEmployees": len(employees),
            "totalHours": total_hours,
            "averageHours": total_hours / len(employees) if employees else 0,
        },
    }

def load_mock_monthly_data(month: int, year: int) -> Dict[str, Any]:
    """Generate mock data for the specified month (for testing)"""
    
    # Generate mock shifts for the month
    start_date = datetime(year, month, 1)
    
    if month == 12:
        end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
    else:
        end_date = datetime(year, month + 1, 1) - timedelta(days=1)
    
    employees = [
        {"id": 1, "name": "John Smith"},
        {"id": 2, "name": "Sarah Johnson"},
        {"id": 3, "name": "Mike Davis"},
        {"id": 4, "name": "Emily Rodriguez"},
        {"id": 5, "name": "David Kim"}
    ]
    
    # Generate shifts for each employee
    for emp in employees:
        shifts = []
        current_date = start_date
        
        while current_date <= end_date:
            # Skip weekends for most employees
            if current_date.weekday() < 5:  # Monday = 0, Friday = 4
                # Vary hours worked (7-9 hours typically)
                hours = 8.0 + (current_date.day % 3) * 0.5 - 0.5
                
                # Some employees work overtime occasionally
                if emp["id"] in [1, 2] and current_date.day % 7 == 0:
                    hours += 2.0
                
                shifts.append({
                    "date": current_date.strftime("%Y-%m-%d"),
                    "startTime": "08:00",
                    "endTime": f"{8 + int(hours)}:{int((hours % 1) * 60):02d}",
                    "hours": hours
                })
            
            current_date += timedelta(days=1)
        
        emp["shifts"] = shifts
    
    # Calculate summary
    total_hours = sum(
        sum(shift["hours"] for shift in emp["shifts"])
        for emp in employees
    )
    
    return {
        "employees": employees,
        "summary": {
            "totalEmployees": len(employees),
            "totalHours": total_hours,
            "averageHours": total_hours / len(employees)
        }
    }

def generate_report(month: int, year: int, company_name: str = "Your Company", 
                   output_dir: str = None, use_mock_data: bool = False) -> str:
    """Generate monthly report and return the file path"""
    
    print(f"Generating monthly report for {month}/{year}...")
    
    # Load employee data
    if use_mock_data:
        print("Using mock data for testing...")
        employee_data = load_mock_monthly_data(month, year)
    else:
        print("Loading data from database...")
        employee_data = load_employee_data_from_db(month, year)
    
    if not employee_data:
        print("Failed to load employee data")
        return None
    if not employee_data.get("employees"):
        print(f"No completed shifts found for {month}/{year}")
        return None
    
    # Initialize report generator
    reports_dir = output_dir or "reports"
    generator = MonthlyReportGenerator(reports_dir)
    
    # Generate the report
    report_path = generator.generate_monthly_report(
        employee_data, month, year, company_name
    )
    
    if report_path:
        print(f"Report generated successfully: {report_path}")
    else:
        print("Report generation failed")
    
    return report_path

def send_report(report_path: str, recipient_emails: List[str], 
               month: int, year: int, config: Dict[str, Any] = None) -> bool:
    """Send the report via email"""
    
    if not report_path or not os.path.exists(report_path):
        print("Report file not found, cannot send email")
        return False
    
    if not recipient_emails:
        print("No recipient emails provided")
        return False
    
    print(f"Sending report to {len(recipient_emails)} recipients...")
    
    # Initialize email service
    email_service = EmailService(config)
    
    # Test email configuration
    if not email_service.test_email_configuration():
        print("Email configuration invalid")
        return False
    
    try:
        use_mock_data = bool((config or {}).get("_mock_data", False))
        if use_mock_data:
            employee_data = load_mock_monthly_data(month, year)
        else:
            employee_data = load_employee_data_from_db(month, year) or {}
        summary_data = _calculate_email_summary(employee_data)
        
        success = email_service.send_monthly_report(
            recipient_emails, report_path, month, year, summary_data
        )
        
        if success:
            print("Report sent successfully!")
        else:
            print("Failed to send report")
        
        return success
        
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='Generate and send monthly employee hours reports')
    
    parser.add_argument('--month', type=int, default=None, 
                      help='Month to generate report for (1-12). Default: current month')
    parser.add_argument('--year', type=int, default=None,
                      help='Year to generate report for. Default: current year')
    parser.add_argument('--company', type=str, default='Your Company',
                      help='Company name for the report')
    parser.add_argument('--output-dir', type=str, default='reports',
                      help='Output directory for reports')
    parser.add_argument('--email', type=str, action='append',
                      help='Email addresses to send report to (can specify multiple times)')
    parser.add_argument('--no-email', action='store_true',
                      help='Generate report only, do not send email')
    parser.add_argument('--mock-data', action='store_true',
                      help='Use mock data instead of API data (for testing)')
    parser.add_argument('--config', type=str,
                      help='Path to JSON config file with email settings')
    
    args = parser.parse_args()
    
    # Default to current month/year if not specified
    if args.month is None or args.year is None:
        now = datetime.now()
        # Default to previous month if we're early in the current month
        if now.day <= 5:
            prev_month = now.replace(day=1) - timedelta(days=1)
            default_month = prev_month.month
            default_year = prev_month.year
        else:
            default_month = now.month
            default_year = now.year
        
        month = args.month or default_month
        year = args.year or default_year
    else:
        month = args.month
        year = args.year
    
    # Validate month
    if month < 1 or month > 12:
        print("Error: Month must be between 1 and 12")
        sys.exit(1)
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    config = dict(config or {})
    config["_mock_data"] = bool(args.mock_data)
    
    # Generate report
    report_path = generate_report(
        month, year, args.company, args.output_dir, args.mock_data
    )
    
    if not report_path:
        print("Failed to generate report")
        sys.exit(1)
    
    # Send email if requested
    if not args.no_email and args.email:
        success = send_report(report_path, args.email, month, year, config)
        if not success:
            print("Report generated but email sending failed")
            sys.exit(1)
    elif not args.no_email and not args.email:
        print("Report generated successfully!")
        print("To send via email, use --email parameter or set up automatic delivery")
    
    print(f"Report available at: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    main()
