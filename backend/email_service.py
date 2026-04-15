# File: backend/email_service.py
"""Email service for sending monthly reports"""

import os
import requests
import base64
from typing import Dict, Any, List
from datetime import datetime


class EmailService:
    """Email service implementation using Resend API"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.resend_api_key = self.config.get("resend_api_key", os.getenv("RESEND_API_KEY"))
        self.from_email = self.config.get("from_email") or os.getenv("RESEND_FROM_EMAIL")
        self.company_name = self.config.get("company_name") or os.getenv("RESEND_FROM_NAME", "")
    
    def send_monthly_report(self, recipient_emails: List[str],
                          report_path: str, month: int, year: int,
                          summary_data: Dict[str, Any] = None) -> bool:
        """Send monthly hours report via email"""
        
        if not self.resend_api_key or not self.from_email:
            print("Email credentials not configured")
            return False
        
        try:
            month_name = datetime(year, month, 1).strftime("%B")
            subject = f"Monthly Hours Report - {month_name} {year}"
            html_content = self._create_monthly_report_email(month_name, year, summary_data)
            
            # Prepare attachment
            attachments = []
            if report_path and os.path.exists(report_path):
                with open(report_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode()
                    
                attachments.append({
                    "filename": os.path.basename(report_path),
                    "content": content,
                    "content_type": "application/pdf",
                })
            
            # Send to each recipient
            success_count = 0
            for email in recipient_emails:
                if self._send_single_email(email, subject, html_content, attachments):
                    success_count += 1
            
            print(f"Successfully sent report to {success_count}/{len(recipient_emails)} recipients")
            return success_count > 0
        
        except Exception as e:
            print(f"Email error: {e}")
            return False
    
    def _send_single_email(self, email: str, subject: str,
                          html_content: str, attachments: List[Dict]) -> bool:
        """Send email to single recipient"""
        try:
            url = "https://api.resend.com/emails"
            headers = {
                "Authorization": f"Bearer {self.resend_api_key}",
                "Content-Type": "application/json",
            }
            
            data = {
                "from": self.from_email,
                "to": [email],
                "subject": subject,
                "html": html_content,
                "attachments": attachments,
            }
            
            response = requests.post(url, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                print(f"Email sent successfully to {email}")
                return True
            else:
                print(f"Email failed for {email}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"Email error for {email}: {e}")
            return False
    
    def _create_monthly_report_email(self, month_name: str, year: int,
                                   summary_data: Dict[str, Any] = None) -> str:
        """Create HTML email for monthly report"""
        
        summary_data = summary_data or {}
        total_employees = summary_data.get("total_employees", 0)
        total_hours = summary_data.get("total_hours", 0)
        avg_hours = summary_data.get("avg_hours", 0)
        overtime_hours = summary_data.get("overtime_hours", 0)
        top_employee = summary_data.get("top_employee", "")
        total_revenue = summary_data.get("total_revenue")
        net_profit = summary_data.get("net_profit")

        def _fmt_currency(value: Any) -> str:
            if isinstance(value, (int, float)):
                return f"${value:,.2f}"
            return "$0.00"

        total_hours_text = f"{total_hours:.1f}" if isinstance(total_hours, (int, float)) else "0.0"
        avg_hours_text = f"{avg_hours:.1f}" if isinstance(avg_hours, (int, float)) else "0.0"
        overtime_text = f"{overtime_hours:.1f}" if isinstance(overtime_hours, (int, float)) else "0.0"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f8f9fa;
                }}
                .container {{
                    max-width: 600px; 
                    margin: 0 auto; 
                    background: white; 
                    border-radius: 8px; 
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); 
                    color: white; 
                    padding: 30px; 
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0; 
                    font-size: 24px; 
                }}
                .content {{
                    padding: 30px; 
                }}
                .summary-box {{
                    background: #f8f9fa; 
                    border-left: 4px solid #007bff; 
                    padding: 20px; 
                    margin: 20px 0; 
                }}
                .summary-item {{
                    display: flex; 
                    justify-content: space-between; 
                    margin: 10px 0; 
                    padding: 5px 0;
                    border-bottom: 1px solid #dee2e6;
                }}
                .summary-item:last-child {{
                    border-bottom: none;
                }}
                .summary-label {{
                    font-weight: bold; 
                    color: #495057; 
                }}
                .summary-value {{
                    color: #007bff; 
                    font-weight: bold; 
                }}
                .footer {{
                    background: #f8f9fa; 
                    padding: 20px; 
                    text-align: center; 
                    color: #6c757d; 
                    font-size: 14px; 
                }}
                .attachment-note {{
                    background: #d4edda;
                    border: 1px solid #c3e6cb;
                    color: #155724;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class=\"container\">
                <div class=\"header\">
                    <h1>Monthly Hours Report</h1>
                    <p>{month_name} {year} - {self.company_name}</p>
                </div>
                
                <div class=\"content\">
                    <h2>Report Summary</h2>
                    <p>Your monthly employee hours report for {month_name} {year} is ready for review.</p>
                    
                    <div class=\"summary-box\">
                        <h3>Key Metrics</h3>
                        <div class=\"summary-item\">
                            <span class=\"summary-label\">Total Employees:</span>
                            <span class=\"summary-value\">{total_employees}</span>
                        </div>
                        <div class=\"summary-item\">
                            <span class=\"summary-label\">Total Hours Worked:</span>
                            <span class=\"summary-value\">{total_hours_text} hours</span>
                        </div>
                        <div class=\"summary-item\">
                            <span class=\"summary-label\">Average Hours per Employee:</span>
                            <span class=\"summary-value\">{avg_hours_text} hours</span>
                        </div>
                        <div class=\"summary-item\">
                            <span class=\"summary-label\">Overtime Hours:</span>
                            <span class=\"summary-value\">{overtime_text} hours</span>
                        </div>
                        <div class=\"summary-item\">
                            <span class=\"summary-label\">Top Performer:</span>
                            <span class=\"summary-value\">{top_employee}</span>
                        </div>
                    </div>
                    
                    <div class=\"attachment-note\">
                        <strong>Detailed Report Attached</strong><br>
                        The complete PDF report with daily breakdowns, individual employee details, 
                        and comprehensive analytics is attached to this email.
                    </div>
                    
                    <h3>Report Features</h3>
                    <ul>
                        <li><strong>Executive Summary:</strong> Key metrics and performance indicators</li>
                        <li><strong>Employee Details:</strong> Individual hours, overtime, and attendance</li>
                        <li><strong>Daily Breakdown:</strong> Day-by-day hours and staffing levels</li>
                        <li><strong>Professional Formatting:</strong> Print-ready PDF report</li>
                    </ul>
                    
                    <p>If you have any questions about this report or need additional data, 
                    please contact your system administrator.</p>
                </div>
                
                <div class=\"footer\">
                    <p>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                    <p>This email contains confidential employee information. Handle according to company policy.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def test_email_configuration(self) -> bool:
        """Test if email configuration is valid"""
        if not self.resend_api_key:
            print("Missing RESEND_API_KEY")
            return False
        
        if not self.from_email:
            print("Missing from_email configuration")
            return False
        
        try:
            # Test API connection
            url = "https://api.resend.com/emails"
            headers = {
                "Authorization": f"Bearer {self.resend_api_key}",
                "Content-Type": "application/json"
            }
            
            # This will fail but we just want to check if credentials are valid
            test_data = {
                "from": self.from_email,
                "to": [self.from_email],
                "subject": "Test",
                "html": "Test"
            }
            
            response = requests.post(url, headers=headers, json=test_data, timeout=10)
            
            # Any response other than 401/403 means credentials are probably valid
            if response.status_code not in [401, 403]:
                print("Email configuration appears valid")
                return True
            else:
                print(f"Email authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Email configuration test failed: {e}")
            return False
