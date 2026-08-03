from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Header, Request, status

import db
from config import JWT_SECRET, JWT_ALGORITHM, TOKEN_TTL_HOURS
from utils import utc_now

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False

def create_auth_token(employee_id: int, employee_name: str, role: str = "employee") -> str:
    now = utc_now()
    payload = {
        "sub": str(employee_id),
        "name": employee_name,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=TOKEN_TTL_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_auth_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

async def get_current_employee(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    token = authorization[7:]
    try:
        payload = decode_auth_token(token)
        emp_id = int(payload.get("sub", 0))
        # Fetch fresh employee data to ensure they are still active
        row = db.query_one("SELECT id, name, role, active FROM employees WHERE id = %s", (emp_id,))
        if not row or not row["active"]:
            raise HTTPException(status_code=401, detail="Inactive or non-existent account")
        return {"id": row["id"], "name": row["name"], "role": row["role"]}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session")

async def get_current_admin(employee: Dict[str, Any] = Depends(get_current_employee)) -> Dict[str, Any]:
    if employee.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return employee
