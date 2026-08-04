"""
Password-change token revocation.

A password change stamps employees.password_changed_at; any token whose iat
predates the stamp is rejected with 401 "Token has been revoked". The change
response returns a fresh token minted at/after the stamp so the current
session survives. A NULL stamp (deploy day, password never changed) leaves
every existing token valid.

Run:  cd backend && pytest -v test_auth_revocation.py
"""
from __future__ import annotations

from datetime import timedelta

import bcrypt
import jwt

import db
import time_tracker_api


OLD_PASSWORD = "original-password-1"
NEW_PASSWORD = "rotated-password-2"


def _create_employee(name: str, password: str = OLD_PASSWORD) -> int:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(4)).decode("utf-8")
    return int(
        db.execute_returning(
            """
            INSERT INTO employees (name, password_hash, role)
            VALUES (%s, %s, 'employee')
            RETURNING id
            """,
            (name, hashed),
        )
    )


def _delete_employee(employee_id: int) -> None:
    db.execute("DELETE FROM employees WHERE id = %s", (employee_id,))


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _change_password(client, token: str, current: str, new: str):
    return client.post(
        "/api/auth/change-password",
        headers=_headers(token),
        json={"currentPassword": current, "newPassword": new},
    )


def test_change_password_revokes_prior_token(client):
    employee_id = _create_employee("Revoke Prior Token Employee")
    try:
        old_token = time_tracker_api.create_auth_token(
            employee_id, "Revoke Prior Token Employee"
        )
        probe = client.get("/api/timesheet/my-hours", headers=_headers(old_token))
        assert probe.status_code == 200, probe.text

        # No back-dating: the <= comparison revokes tokens issued in the same
        # second as the change, so even this just-minted token dies.
        changed = _change_password(client, old_token, OLD_PASSWORD, NEW_PASSWORD)
        assert changed.status_code == 200, changed.text

        rejected = client.get("/api/timesheet/my-hours", headers=_headers(old_token))
        assert rejected.status_code == 401
        assert rejected.json()["error"] == "Token has been revoked"
    finally:
        _delete_employee(employee_id)


def test_change_password_response_token_is_valid(client):
    employee_id = _create_employee("Fresh Token Employee")
    try:
        old_token = time_tracker_api.create_auth_token(
            employee_id, "Fresh Token Employee"
        )
        changed = _change_password(client, old_token, OLD_PASSWORD, NEW_PASSWORD)
        assert changed.status_code == 200, changed.text
        fresh_token = changed.json()["token"]

        probe = client.get("/api/timesheet/my-hours", headers=_headers(fresh_token))
        assert probe.status_code == 200, probe.text
    finally:
        _delete_employee(employee_id)


def test_other_employees_tokens_unaffected_by_password_change(client):
    changer_id = _create_employee("Password Changer Employee")
    bystander_id = _create_employee("Bystander Token Employee")
    try:
        changer_token = time_tracker_api.create_auth_token(
            changer_id, "Password Changer Employee"
        )
        bystander_token = time_tracker_api.create_auth_token(
            bystander_id, "Bystander Token Employee"
        )

        changed = _change_password(client, changer_token, OLD_PASSWORD, NEW_PASSWORD)
        assert changed.status_code == 200, changed.text

        probe = client.get(
            "/api/timesheet/my-hours", headers=_headers(bystander_token)
        )
        assert probe.status_code == 200, probe.text
    finally:
        _delete_employee(changer_id)
        _delete_employee(bystander_id)


def test_token_without_iat_rejected_after_password_change(client):
    employee_id = _create_employee("Missing Iat Employee")
    try:
        now = time_tracker_api.utc_now()
        no_iat_token = jwt.encode(
            {
                "sub": str(employee_id),
                "name": "Missing Iat Employee",
                "role": "employee",
                "exp": int((now + timedelta(hours=1)).timestamp()),
            },
            time_tracker_api.JWT_SECRET,
            algorithm=time_tracker_api.JWT_ALGORITHM,
        )
        # Valid while the stamp is NULL.
        probe = client.get("/api/timesheet/my-hours", headers=_headers(no_iat_token))
        assert probe.status_code == 200, probe.text

        fresh_token = time_tracker_api.create_auth_token(
            employee_id, "Missing Iat Employee"
        )
        changed = _change_password(client, fresh_token, OLD_PASSWORD, NEW_PASSWORD)
        assert changed.status_code == 200, changed.text

        rejected = client.get(
            "/api/timesheet/my-hours", headers=_headers(no_iat_token)
        )
        assert rejected.status_code == 401
        assert rejected.json()["error"] == "Token has been revoked"
    finally:
        _delete_employee(employee_id)


def test_admin_password_reset_revokes_target_tokens(client, auth):
    employee_id = _create_employee("Admin Reset Target Employee")
    try:
        old_token = time_tracker_api.create_auth_token(
            employee_id, "Admin Reset Target Employee"
        )
        probe = client.get("/api/timesheet/my-hours", headers=_headers(old_token))
        assert probe.status_code == 200, probe.text

        reset = client.patch(
            f"/api/admin/employees/{employee_id}",
            headers=auth,
            json={"password": "admin-reset-password-9"},
        )
        assert reset.status_code == 200, reset.text

        rejected = client.get(
            "/api/timesheet/my-hours", headers=_headers(old_token)
        )
        assert rejected.status_code == 401
        assert rejected.json()["error"] == "Token has been revoked"

        # A token issued after the stamp works. Back-date the stamp (rather
        # than minting a future-iat token, which PyJWT rejects) so a normally
        # minted token deterministically post-dates it.
        assert db.query_one(
            "SELECT password_changed_at FROM employees WHERE id = %s",
            (employee_id,),
        )["password_changed_at"] is not None
        db.execute(
            "UPDATE employees SET password_changed_at = "
            "password_changed_at - INTERVAL '5 seconds' WHERE id = %s",
            (employee_id,),
        )
        later_token = time_tracker_api.create_auth_token(
            employee_id, "Admin Reset Target Employee"
        )
        accepted = client.get(
            "/api/timesheet/my-hours", headers=_headers(later_token)
        )
        assert accepted.status_code == 200, accepted.text
    finally:
        _delete_employee(employee_id)


def test_tokens_valid_when_password_never_changed(client):
    employee_id = _create_employee("Null Stamp Employee")
    try:
        row = db.query_one(
            "SELECT password_changed_at FROM employees WHERE id = %s",
            (employee_id,),
        )
        assert row["password_changed_at"] is None

        token = time_tracker_api.create_auth_token(
            employee_id, "Null Stamp Employee"
        )
        probe = client.get("/api/timesheet/my-hours", headers=_headers(token))
        assert probe.status_code == 200, probe.text
    finally:
        _delete_employee(employee_id)
