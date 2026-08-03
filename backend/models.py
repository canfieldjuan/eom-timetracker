from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    name: str = Field(min_length=1)
    password: str = Field(min_length=1)

class RegisterRequest(BaseModel):
    name: str = Field(min_length=1)
    password: str = Field(min_length=4)

class ClockInRequest(BaseModel):
    location: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    notes: str = ""
    gpsOverrideReason: str = ""
    gpsOverrideDetail: str = ""

class ClockOutRequest(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    notes: str = ""
    gpsOverrideReason: str = ""
    gpsOverrideDetail: str = ""

class DepartRequest(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    notes: str = ""
    gpsOverrideReason: str = ""
    gpsOverrideDetail: str = ""

class EntryAdjustRequest(BaseModel):
    clockIn: Optional[str] = None
    clockOut: Optional[str] = None
    notes: Optional[str] = None
    location: Optional[str] = None

class ReportGenerateRequest(BaseModel):
    month: int
    year: int
    send_email: bool = False
    use_mock_data: bool = False

class JobCreateRequest(BaseModel):
    customerName: str = Field(min_length=1)
    scheduledDate: str  # YYYY-MM-DD
    expectedHours: Optional[float] = None
    revenue: Optional[float] = None
    notes: str = ""
    status: str = "scheduled"
    locationId: Optional[int] = None

class JobUpdateRequest(BaseModel):
    customerName: Optional[str] = None
    scheduledDate: Optional[str] = None  # YYYY-MM-DD
    expectedHours: Optional[float] = None
    revenue: Optional[float] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    locationId: Optional[int] = None

class JobLinkShiftsRequest(BaseModel):
    shiftIds: List[int]

class ShiftCategorizeRequest(BaseModel):
    timeCategory: str  # "productive" or "non_productive"
    nonProductiveType: Optional[str] = None
    notes: Optional[str] = None

class ScheduleEntryRequest(BaseModel):
    employeeId: int
    customerName: str = Field(min_length=1)
    weekStart: str  # YYYY-MM-DD (must be a Sunday)
    scheduledHours: float
    notes: str = ""
    locationId: Optional[int] = None
