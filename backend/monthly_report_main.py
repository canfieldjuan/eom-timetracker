#!/usr/bin/env python3
# File: backend/monthly_report_main.py
"""Main script for generating and sending monthly employee hours reports"""

import sys
import json
import os
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from report_generator import MonthlyReportGenerator
from email_service import EmailService


def _read_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            payload = json.load(file)
            if isinstance(payload, dict):
                return payload
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _build_monthly_summary(employees: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_hours = 0.0
    total_overtime = 0.0
    top_employee = "N/A"
    top_hours = 0.0

    for employee in employees:
        emp_hours = round(sum(shift.get("hours", 0) for shift in employee.get("shifts", [])), 2)
        total_hours += emp_hours
        if emp_hours > top_hours:
            top_hours = emp_hours
            top_employee = f"{employee.get('name', 'Unknown')} ({top_hours:.1f}h)"
        if emp_hours > 40:
            total_overtime += emp_hours - 40

    total_employees = len(employees)
    return {
        "total_employees": total_employees,
        "total_hours": round(total_hours, 2),
        "avg_hours": round(total_hours / total_employees, 2) if total_employees else 0.0,
        "overtime_hours": round(total_overtime, 2),
        "top_employee": top_employee,
    }


def _coerce_month_entry(entry: Dict[str, Any], month: int, year: int) -> Optional[Tuple[datetime, datetime, int, str, float]]:
    clock_in_text = str(entry.get("clockIn", "")).strip()
    clock_out_text = str(entry.get("clockOut", "")).strip()
    if not clock_in_text or not clock_out_text:
        return None

    try:
        clock_in = datetime.fromisoformat(clock_in_text.replace("Z", "+00:00"))
        clock_out = datetime.fromisoformat(clock_out_text.replace("Z", "+00:00"))
    except ValueError:
        return None

    if clock_in.year != year or clock_in.month != month:
        return None
    if clock_out <= clock_in:
        return None

    employee_id = int(entry.get("employeeId", 0))
    employee_name = str(entry.get("employeeName", f"Employee {employee_id}"))
    hours = round((clock_out - clock_in).total_seconds() / 3600, 2)
    return clock_in, clock_out, employee_id, employee_name, hours


def load_employee_data_from_files(month: int, year: int) -> Optional[Dict[str, Any]]:
    """Load employee timesheet data directly from JSON files for the specified month."""
    from pathlib import Path

    data_dir_env = os.getenv("DATA_DIR", "")
    if data_dir_env:
        data_dir = Path(data_dir_env)
    else:
        backend_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        data_dir = backend_dir.parent / "data"

    timesheets_file = data_dir / "timesheets.json"
    if not timesheets_file.exists():
        print(f"Timesheets file not found: {timesheets_file}")
        return None

    timesheet_data = _read_json(str(timesheets_file))

    entries = timesheet_data.get("entries", [])
    employees_map: Dict[int, Dict[str, Any]] = {}

    for entry in entries:
        parsed = _coerce_month_entry(entry, month, year)
        if not parsed:
            continue

        clock_in, clock_out, emp_id, emp_name, hours = parsed

        if emp_id not in employees_map:
            employees_map[emp_id] = {"id": emp_id, "name": emp_name, "shifts": []}

        employees_map[emp_id]["shifts"].append({
            "date": clock_in.strftime("%Y-%m-%d"),
            "startTime": clock_in.strftime("%H:%M"),
            "endTime": clock_out.strftime("%H:%M"),
            "hours": hours,
        })

    employees = sorted(employees_map.values(), key=lambda e: e["name"].lower())
    summary = _build_monthly_summary(employees)

    return {
        "employees": employees,
        "summary": summary,
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
    summary = _build_monthly_summary(employees)

    return {
        "employees": employees,
        "summary": summary,
    }

def generate_report(
    month: int,
    year: int,
    company_name: str = "Your Company",
    output_dir: str = None,
    use_mock_data: bool = False,
) -> tuple[Optional[str], Dict[str, Any]]:
    """Generate monthly report and return the file path + summary."""
    
    print(f"Generating monthly report for {month}/{year}...")
    
    # Load employee data
    if use_mock_data:
        print("Using mock data for testing...")
        employee_data = load_mock_monthly_data(month, year)
    else:
        print("Loading data from files...")
        employee_data = load_employee_data_from_files(month, year)
    
    if not employee_data:
        print("Failed to load employee data")
        return None, {}
    if not employee_data.get("employees"):
        print(f"No completed shifts found for {month}/{year}")
        return None, {}
    
    # Initialize report generator
    reports_dir = output_dir or "reports"
    generator = MonthlyReportGenerator(reports_dir)
    
    # Generate the report
    report_path = generator.generate_monthly_report(
        employee_data, month, year, company_name
    )
    
    summary = employee_data.get("summary", {})
    if report_path:
        print(f"Report generated successfully: {report_path}")
    else:
        print("Report generation failed")
    
    return report_path, summary

def send_report(
    report_path: str,
    recipient_emails: List[str],
    month: int,
    year: int,
    config: Dict[str, Any] = None,
    summary_data: Optional[Dict[str, Any]] = None,
) -> bool:
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

    success = email_service.send_monthly_report(
        recipient_emails,
        report_path,
        month,
        year,
        summary_data=summary_data or {
            "total_employees": 0,
            "total_hours": 0.0,
            "avg_hours": 0.0,
            "overtime_hours": 0.0,
            "top_employee": "",
        },
    )

    if success:
        print("Report sent successfully!")
    else:
        print("Failed to send report")
    return success

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
    
    config = _read_json(args.config) if args.config else {}
    
    # Generate report
    report_path, summary_data = generate_report(
        month, year, args.company, args.output_dir, args.mock_data
    )
    
    if not report_path:
        print("Failed to generate report")
        sys.exit(1)
    
    # Send email if requested
    if not args.no_email and args.email:
        success = send_report(
            report_path=report_path,
            recipient_emails=args.email,
            month=month,
            year=year,
            config=config,
            summary_data=summary_data,
        )
        if not success:
            print("Report generated but email sending failed")
            sys.exit(1)
    elif not args.no_email and not args.email:
        print("Report generated successfully!")
        print("To send via email, use --email parameter or set up automatic delivery")
    
    print(f"Report available at: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    main()
