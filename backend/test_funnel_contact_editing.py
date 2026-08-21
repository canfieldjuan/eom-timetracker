"""The contact-edit relay is Atlas-backed, id-targeted, bounded, and mirror-free.

Website #250: editing rides the SAME operator mutation boundary as creation.
Atlas owns validation, tenant pinning, identity conflicts, idempotency, and
the previous-value audit; these tests hold the relay to its own obligations:
a strict deployment proof, exact partial-diff forwarding, closed response
validation where an id-targeted request can never report a create, and zero
tracker operational rows.
"""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api


def _path(contact_id: str) -> str:
    return f"/api/admin/funnel/contacts/{contact_id}"


def _operational_counts() -> dict[str, int]:
    return {
        "customers": int(db.query_one("SELECT COUNT(*) AS count FROM customers")["count"]),
        "locations": int(db.query_one("SELECT COUNT(*) AS count FROM locations")["count"]),
        "reservations": int(
            db.query_one(
                "SELECT COUNT(*) AS count FROM eom_customer_atlas_reservations"
            )["count"]
        ),
    }


def _manifest_content(
    *,
    with_name: bool = True,
    with_route: bool = True,
    declared: bool = True,
    capabilities_malformed: bool = False,
) -> dict[str, object]:
    content: dict[str, object] = {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
    }
    if declared:
        capabilities: list[object] = ["lead.lost"]
        if with_name:
            capabilities.append(api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION)
        if capabilities_malformed:
            capabilities.append(1)
        content["capabilities"] = capabilities
        routes: list[object] = [{"method": "GET", "path": "/eom-funnel/contact-directory"}]
        if with_route:
            routes.append({"method": "POST", "path": "/eom-funnel/operator-contacts"})
        content["capabilityRoutes"] = routes
    return content


def _edit_result(
    contact_id: str,
    *,
    operation: str = "contact_updated",
    idempotent: bool = False,
    contact_type: str = "customer",
    customer_type: str = "commercial",
    echoed_contact_id: str | None = None,
    contact_overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    contact: dict[str, object] = {
        "contactId": echoed_contact_id or contact_id,
        "fullName": "Edited Person",
        "email": "edited@example.test",
        "phone": "2175550177",
        "address": "9 Edited Way",
        "contactType": contact_type,
        "customerType": customer_type,
        "updatedAt": "2026-08-21T05:00:00+00:00",
    }
    if contact_overrides:
        contact.update(contact_overrides)
    return {
        "success": True,
        "contactId": echoed_contact_id or contact_id,
        "operation": operation,
        "idempotent": idempotent,
        "contact": contact,
    }


def _install_atlas(monkeypatch, mutation_result, manifest_content=None, calls=None):
    manifest = manifest_content if manifest_content is not None else _manifest_content()

    def atlas_read(path, admin, *, params=None):
        assert path == "/eom-funnel/leads", path
        return manifest

    def atlas_request(path, admin, *, payload, idempotency_key):
        if calls is not None:
            calls.append(
                {
                    "path": path,
                    "admin": dict(admin),
                    "payload": dict(payload),
                    "idempotencyKey": idempotency_key,
                }
            )
        if isinstance(mutation_result, Exception):
            raise mutation_result
        return mutation_result

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)


# ---------------------------------------------------------------------------
# The deployment proof
# ---------------------------------------------------------------------------


def test_review_proves_editing_only_with_both_name_and_route(client, auth, monkeypatch):
    shapes = [
        (_manifest_content(with_name=True, with_route=True), True),
        (_manifest_content(with_name=True, with_route=False), False),
        (_manifest_content(with_name=False, with_route=True), False),
        (_manifest_content(declared=False), False),
        (_manifest_content(with_name=True, with_route=True, capabilities_malformed=True), False),
    ]
    for manifest, expected in shapes:
        monkeypatch.setattr(api, "_atlas_funnel_read", lambda *_a, _m=manifest, **_k: _m)
        response = client.get("/api/admin/funnel/review", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["contactEditingAvailable"] is expected, manifest


def test_an_edit_against_an_older_atlas_maps_to_typed_501(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(
        monkeypatch,
        _edit_result(str(uuid.uuid4())),
        manifest_content=_manifest_content(with_route=False),
        calls=calls,
    )
    response = client.patch(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={"fullName": "Blocked Edit", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 501, response.text
    assert response.json()["error"] == "atlas_capability_unavailable"
    assert calls == [], "no mutation may be attempted without the route proof"


# ---------------------------------------------------------------------------
# Exact partial-diff forwarding, no local rows
# ---------------------------------------------------------------------------


def test_edit_forwards_the_exact_partial_diff_and_creates_no_rows(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    before = _operational_counts()
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(contact_id), calls=calls)

    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={
            "fullName": "  Edited Person  ",
            "customerType": "Commercial",
            "idempotencyKey": key,
        },
    )

    assert response.status_code == 200, response.text
    assert len(calls) == 1
    assert calls[0]["path"] == api.ATLAS_OPERATOR_CONTACTS_PATH
    assert calls[0]["idempotencyKey"] == key
    assert calls[0]["payload"] == {
        "contact_id": contact_id,
        "full_name": "Edited Person",
        "customer_type": "commercial",
        "source_channel": "time_tracker",
        "source_ref": f"portal-contact:{key}",
    }, "untouched fields must be ABSENT, not null"
    assert calls[0]["admin"]["name"], "actor identity must be forwarded"
    body = response.json()
    assert set(body) == {"success", "idempotent", "operation", "contact"}
    assert body["operation"] == "contact_updated"
    assert set(body["contact"]) == {
        "contactId",
        "fullName",
        "email",
        "phone",
        "address",
        "contactType",
        "customerType",
        "updatedAt",
    }
    assert _operational_counts() == before, "an edit must write nothing locally"


def test_an_idempotent_replay_is_relayed_truthfully(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    _install_atlas(monkeypatch, _edit_result(contact_id, idempotent=True))
    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={"phone": "2175550177", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 200, response.text
    assert response.json()["idempotent"] is True


def test_the_service_credential_never_reaches_the_browser(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    _install_atlas(monkeypatch, _edit_result(contact_id))
    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={"fullName": "Edited Person", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 200, response.text
    assert api.ATLAS_FUNNEL_SERVICE_TOKEN
    assert api.ATLAS_FUNNEL_SERVICE_TOKEN not in response.text


# ---------------------------------------------------------------------------
# Browser-input closure
# ---------------------------------------------------------------------------


def test_an_empty_edit_is_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    response = client.patch(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 422, response.text
    assert calls == []


def test_unknown_fields_are_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    response = client.patch(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={
            "fullName": "Edited",
            "leadStage": "won",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 422, response.text
    assert calls == []


def test_blank_edited_fields_are_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    for field in ("fullName", "email", "phone", "address", "customerType"):
        response = client.patch(
            _path(str(uuid.uuid4())),
            headers=auth,
            json={field: "   ", "idempotencyKey": str(uuid.uuid4())},
        )
        assert response.status_code == 422, (field, response.text)
    assert calls == []


def test_an_explicitly_null_edit_field_is_rejected(client, auth, monkeypatch):
    """A client-serialized null is a clear, not an omission: silently dropping
    it would report success for a change Atlas never received."""
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    response = client.patch(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={
            "email": None,
            "phone": "2175550177",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 422, response.text
    assert calls == []


def test_an_unsupported_customer_type_is_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    response = client.patch(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={"customerType": "franchise", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 422, response.text
    assert calls == []


def test_a_missing_or_malformed_idempotency_key_is_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())), calls=calls)
    for body in (
        {"fullName": "Edited"},
        {"fullName": "Edited", "idempotencyKey": "not-a-uuid"},
    ):
        response = client.patch(_path(str(uuid.uuid4())), headers=auth, json=body)
        assert response.status_code == 422, (body, response.text)
    assert calls == []


def test_the_edit_requires_admin_authentication(client, monkeypatch):
    _install_atlas(monkeypatch, _edit_result(str(uuid.uuid4())))
    response = client.patch(
        _path(str(uuid.uuid4())),
        json={"fullName": "Edited", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code in (401, 403), response.text


# ---------------------------------------------------------------------------
# Upstream validation: an id-targeted edit can never report a create
# ---------------------------------------------------------------------------


def test_a_create_operation_response_is_rejected(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    _install_atlas(monkeypatch, _edit_result(contact_id, operation="contact_created"))
    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={"fullName": "Edited", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 502, response.text


def test_a_mismatched_contact_id_is_rejected(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    _install_atlas(
        monkeypatch,
        _edit_result(contact_id, echoed_contact_id=str(uuid.uuid4())),
    )
    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={"fullName": "Edited", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 502, response.text


def test_junk_response_vocabularies_are_rejected(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    for overrides in (
        {"contactType": "prospect"},
        {"customerType": "franchise"},
        {"contactType": ["customer"]},
        {"fullName": 123},
    ):
        _install_atlas(
            monkeypatch, _edit_result(contact_id, contact_overrides=overrides)
        )
        response = client.patch(
            _path(contact_id),
            headers=auth,
            json={"fullName": "Edited", "idempotencyKey": str(uuid.uuid4())},
        )
        assert response.status_code == 502, (overrides, response.text)


def test_atlas_domain_errors_relay_their_status(client, auth, monkeypatch):
    contact_id = str(uuid.uuid4())
    _install_atlas(
        monkeypatch,
        api.AtlasFunnelRequestError(404, "EOM contact was not found"),
    )
    response = client.patch(
        _path(contact_id),
        headers=auth,
        json={"fullName": "Edited", "idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 404, response.text
    # The tracker's handler reshapes HTTPException detail into {"error": ...}.
    assert "not found" in response.json()["error"]
