"""Regression tests for the last-active-admin lockout guard in
admin_update_employee (PATCH /api/admin/employees/{id})."""


def _admins(client, auth):
    emps = client.get("/api/admin/employees", headers=auth).json()["employees"]
    return emps


def _find(emps, name):
    return next(e for e in emps if e["name"] == name)


def test_cannot_demote_or_deactivate_last_active_admin(client, auth):
    # Reduce to a single active admin (the seeded "Juan Canfield") by deactivating
    # any other active admins a prior test may have created. Deactivating those is
    # allowed because Juan is still active.
    emps = _admins(client, auth)
    juan = _find(emps, "Juan Canfield")
    for e in emps:
        if (
            e["id"] != juan["id"]
            and str(e.get("role") or "").lower() == "admin"
            and e.get("active")
        ):
            r = client.patch(
                f"/api/admin/employees/{e['id']}", headers=auth, json={"active": False}
            )
            assert r.status_code == 200, r.text

    # Demoting the sole active admin must be blocked.
    r = client.patch(
        f"/api/admin/employees/{juan['id']}", headers=auth, json={"role": "employee"}
    )
    assert r.status_code == 409, r.text

    # The new payroll role is non-admin and must hit the same lockout guard.
    r = client.patch(
        f"/api/admin/employees/{juan['id']}", headers=auth, json={"role": "payroll"}
    )
    assert r.status_code == 409, r.text

    # Deactivating the sole active admin must also be blocked.
    r = client.patch(
        f"/api/admin/employees/{juan['id']}", headers=auth, json={"active": False}
    )
    assert r.status_code == 409, r.text

    # And the seeded admin is untouched (guard raised before persisting).
    juan_after = _find(_admins(client, auth), "Juan Canfield")
    assert str(juan_after["role"]).lower() == "admin"
    assert juan_after["active"] is True


def test_can_demote_admin_when_another_active_admin_exists(client, auth):
    # With a second active admin present, demoting one is allowed.
    r = client.post(
        "/api/admin/employees",
        headers=auth,
        json={"name": "Guard Probe Admin", "password": "probe1234", "role": "admin"},
    )
    assert r.status_code == 200, r.text
    probe_id = r.json()["employee"]["id"]

    r = client.patch(
        f"/api/admin/employees/{probe_id}", headers=auth, json={"role": "employee"}
    )
    assert r.status_code == 200, r.text
    assert str(r.json()["employee"]["role"]).lower() == "employee"
