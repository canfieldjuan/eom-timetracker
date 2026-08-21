"""Manual CRM contact creation is Atlas-backed, bounded, and local-row free."""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api


def _path() -> str:
    return "/api/admin/funnel/contacts"


def _payload(
    key: str,
    *,
    contact_type: str = "lead",
    full_name: str = "Ada Operator",
    email: str | None = "ada@example.test",
    phone: str | None = "217-555-0100",
) -> dict[str, object]:
    return {
        "contactType": contact_type,
        "fullName": full_name,
        "email": email,
        "phone": phone,
        "idempotencyKey": key,
    }


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


def _atlas_result(
    contact_id: str,
    *,
    contact_type: str = "lead",
    full_name: str = "Ada Operator",
    operation: str = "contact_created",
    idempotent: bool = False,
    email: str | None = None,
    phone: str | None = None,
) -> dict[str, object]:
    return {
        "success": True,
        "contactId": contact_id,
        "operation": operation,
        "idempotent": idempotent,
        "contact": {
            "contactId": contact_id,
            "fullName": full_name,
            "contactType": contact_type,
            "email": email,
            "phone": phone,
        },
    }


def test_review_proves_the_tracker_contact_proxy_only_when_atlas_allows_it(
    client, auth, monkeypatch
):
    def atlas_read_with_contact_capability(*_args, **_kwargs):
        return {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION],
            "capabilityRoutes": [
                {"method": "POST", "path": "/eom-funnel/operator-contacts"},
            ],
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read_with_contact_capability)
    available = client.get("/api/admin/funnel/review", headers=auth)

    assert available.status_code == 200, available.text
    assert available.json()["contactCreationAvailable"] is True
    # Edit rides the same Atlas capability; this tracker build advertises its own
    # deployment proof so the Website can gate the Edit affordance on it.
    assert available.json()["contactEditAvailable"] is True

    def atlas_read_without_contact_capability(*_args, **_kwargs):
        return {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None}

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read_without_contact_capability)
    unavailable = client.get("/api/admin/funnel/review", headers=auth)

    assert unavailable.status_code == 200, unavailable.text
    assert unavailable.json()["contactCreationAvailable"] is False
    assert unavailable.json()["contactEditAvailable"] is False


def test_edit_proof_requires_the_strict_name_and_exact_route(client, auth, monkeypatch):
    """The edit proof gates a MUTATION control, so it holds the strict manifest
    standard: capability name (one malformed member poisons the set) AND the
    exact registered method/path. Name-only, route-only, and junk manifests
    all read false."""
    shapes = [
        # Name present but no route proof: an older Atlas whose manifest
        # predates capabilityRoutes, or a rollback that dropped the route.
        (
            {
                "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION],
            },
            False,
        ),
        # Route present but capability name missing.
        (
            {
                "capabilities": ["lead.lost"],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            False,
        ),
        # One malformed member poisons the whole capability set.
        (
            {
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION,
                    1,
                ],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            False,
        ),
    ]
    for manifest_fields, expected in shapes:
        content = {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            **manifest_fields,
        }
        monkeypatch.setattr(api, "_atlas_funnel_read", lambda *_a, _c=content, **_k: _c)
        response = client.get("/api/admin/funnel/review", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["contactEditAvailable"] is expected, manifest_fields
        # Creation gates a mutation control through the same standard.
        assert response.json()["contactCreationAvailable"] is expected, manifest_fields
        # And the ENDPOINT enforces what the proof advertises: the same
        # manifest that reads unavailable must refuse the mutation itself,
        # for both a create and a contactId-bearing edit.
        for body_extra in ({}, {"contactId": str(uuid.uuid4())}):
            attempt = client.post(
                "/api/admin/funnel/contacts",
                headers=auth,
                json={
                    "contactType": "lead",
                    "fullName": "Gate Probe",
                    "email": None,
                    "phone": None,
                    "idempotencyKey": str(uuid.uuid4()),
                    **body_extra,
                },
            )
            assert attempt.status_code == 501, (manifest_fields, attempt.text)


def test_manual_lead_create_forwards_the_exact_canonical_contract_and_no_local_rows(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(
            {
                "path": path,
                "admin": admin,
                "payload": payload,
                "idempotencyKey": idempotency_key,
            }
        )
        return _atlas_result(contact_id, full_name="Ada Operator")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json=_payload(
            key,
            full_name="  Ada Operator  ",
            email="  ADA@example.test  ",
            phone="  (217) 555-0100  ",
        ),
    )

    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "idempotent": False,
        "operation": "contact_created",
        "contact": {
            "contactId": contact_id,
            "fullName": "Ada Operator",
            "contactType": "lead",
            "email": None,
            "phone": None,
        },
    }
    assert calls == [
        {
            "path": api.ATLAS_OPERATOR_CONTACTS_PATH,
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "payload": {
                "full_name": "Ada Operator",
                "email": "ADA@example.test",
                "phone": "(217) 555-0100",
                "contact_type": "lead",
                "source_channel": "time_tracker",
                "source_ref": f"portal-contact:{key}",
            },
            "idempotencyKey": key,
        }
    ]
    assert _operational_counts() == before


def test_manual_customer_create_omits_blank_optional_fields_and_never_creates_a_tracker_customer(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(
            contact_id,
            contact_type="customer",
            full_name="Customer Contact",
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json=_payload(
            key,
            contact_type="customer",
            full_name="Customer Contact",
            email="   ",
            phone="",
        ),
    )

    assert response.status_code == 201, response.text
    assert calls == [
        {
            "full_name": "Customer Contact",
            "contact_type": "customer",
            "source_channel": "time_tracker",
            "source_ref": f"portal-contact:{key}",
        }
    ]
    assert _operational_counts() == before


def test_manual_contact_replay_preserves_the_operation_key_and_reports_atlas_truth(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    keys: list[str] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        keys.append(idempotency_key)
        return _atlas_result(
            contact_id,
            operation="contact_updated",
            idempotent=len(keys) == 2,
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first = client.post(_path(), headers=auth, json=_payload(key))
    replay = client.post(_path(), headers=auth, json=_payload(key))

    assert first.status_code == 201, first.text
    assert first.json()["operation"] == "contact_updated"
    assert first.json()["idempotent"] is False
    assert replay.status_code == 200, replay.text
    assert replay.json()["operation"] == "contact_updated"
    assert replay.json()["idempotent"] is True
    assert keys == [key, key]


def test_manual_contact_refuses_when_atlas_does_not_advertise_the_capability(
    client, auth, monkeypatch
):
    calls: list[object] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION
        )

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called after capability refusal")

    # The endpoint now applies the strict name+route gate (single-read,
    # multi-capability form).
    monkeypatch.setattr(api, "_require_atlas_funnel_capability_routes", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(_path(), headers=auth, json=_payload(str(uuid.uuid4())))

    assert response.status_code == 501, response.text
    assert response.json() == {
        "success": False,
        "error": "atlas_capability_unavailable",
        "capability": "contact.operator_mutation",
        "message": "The EOM funnel service does not yet support this action (contact.operator_mutation)",
    }
    assert calls == []


def test_manual_contact_rejects_a_malformed_atlas_result(client, auth, monkeypatch):
    calls: list[object] = []

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        return {
            "success": True,
            "contactId": str(uuid.uuid4()),
            "operation": "contact_created",
            "idempotent": False,
            "contact": {"fullName": "Wrong Kind", "contactType": "customer"},
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    malformed = client.post(_path(), headers=auth, json=_payload(str(uuid.uuid4())))

    assert malformed.status_code == 502, malformed.text
    assert calls == [True]


def test_manual_contact_edit_forwards_the_target_id_and_creates_no_local_rows(
    client, auth, monkeypatch
):
    key = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(
            target_id,
            full_name="Ada Edited",
            operation="contact_updated",
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json={
            **_payload(key, full_name="Ada Edited"),
            "contactId": target_id,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["operation"] == "contact_updated"
    assert response.json()["contact"]["contactId"] == target_id
    # The edit names its target as the Atlas body's contact_id; identity fields
    # ride alongside as the new values, and no tracker-local row is written.
    assert calls == [
        {
            "full_name": "Ada Edited",
            "email": "ada@example.test",
            "phone": "217-555-0100",
            "contact_id": target_id,
            "contact_type": "lead",
            "source_channel": "time_tracker",
            "source_ref": f"portal-contact:{key}",
        }
    ]
    assert _operational_counts() == before


def test_manual_contact_edit_relays_the_atlas_identity_collision_409(
    client, auth, monkeypatch
):
    target_id = str(uuid.uuid4())
    before = _operational_counts()

    def atlas_request(*_args, **_kwargs):
        raise api.AtlasFunnelRequestError(
            409, "Operator contact identity belongs to another contact"
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json={**_payload(str(uuid.uuid4())), "contactId": target_id},
    )

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["success"] is False
    assert "another contact" in body["error"]
    # A fail-closed collision must not leave any tracker-local trace behind.
    assert _operational_counts() == before


def test_manual_contact_edit_fails_closed_when_atlas_edits_a_different_contact(
    client, auth, monkeypatch
):
    target_id = str(uuid.uuid4())
    other_id = str(uuid.uuid4())

    def atlas_request(*_args, **_kwargs):
        return _atlas_result(other_id, operation="contact_updated")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _path(),
        headers=auth,
        json={**_payload(str(uuid.uuid4())), "contactId": target_id},
    )

    assert response.status_code == 502, response.text


# -- Slice 5 (website #254): field-clearing tri-state through the proxy --------


def test_manual_contact_edit_clear_forwards_null_and_response_proves_it(
    client, auth, monkeypatch
):
    """Present JSON null on an edit rides the wire untouched: no falsy-value
    filtering between the browser and Atlas, and the widened response
    projection returns the null so the browser can prove the clear persisted."""
    key = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(
            target_id,
            full_name="Ada Cleared",
            operation="contact_updated",
            email=None,
            phone="2175550100",
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    body = _payload(key, full_name="Ada Cleared", email=None)
    body["contactId"] = target_id
    response = client.post(_path(), headers=auth, json=body)

    assert response.status_code == 201, response.text
    assert response.json()["operation"] == "contact_updated"
    assert response.json()["contact"]["email"] is None
    assert response.json()["contact"]["phone"] == "2175550100"
    # The forwarded body carries email as PRESENT null (clear), phone as a
    # value (replace), and contact_id (edit target).
    assert calls == [
        {
            "full_name": "Ada Cleared",
            "phone": "217-555-0100",
            "contact_id": target_id,
            "email": None,
            "contact_type": "lead",
            "source_channel": "time_tracker",
            "source_ref": f"portal-contact:{key}",
        }
    ]
    assert _operational_counts() == before


def test_manual_contact_edit_blank_field_is_rejected_as_ambiguous(
    client, auth, monkeypatch
):
    """On the edit path a blank string is neither keep nor clear -- 422.

    The website never sends blanks (it converts a deliberately emptied field
    to null), so a blank arriving on an edit is a contract violation to
    refuse, not a value to guess about. Both optional fields hold the rule.
    """
    calls: list[object] = []

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("no Atlas call may follow an ambiguous blank")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    for field in ("email", "phone"):
        body = _payload(str(uuid.uuid4()))
        body[field] = "   "
        body["contactId"] = str(uuid.uuid4())
        response = client.post(_path(), headers=auth, json=body)
        assert response.status_code == 422, (field, response.text)
    assert calls == []


def test_manual_contact_create_blank_and_null_still_omit(client, auth, monkeypatch):
    """The create-or-match door is byte-identical to Slice 4: blank AND null
    optional fields are omitted, never forwarded as clears, because a create
    resolving to an existing contact by one identity field must not null the
    other."""
    key = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(contact_id, full_name="Create Omit")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    body = _payload(key, full_name="Create Omit", email=None, phone="   ")
    response = client.post(_path(), headers=auth, json=body)

    assert response.status_code == 201, response.text
    assert calls == [
        {
            "full_name": "Create Omit",
            "contact_type": "lead",
            "source_channel": "time_tracker",
            "source_ref": f"portal-contact:{key}",
        }
    ]


def test_clear_bearing_edit_refuses_without_the_field_clear_capability(
    client, auth, monkeypatch
):
    """contactEditAvailable proves the route exists; it does NOT prove null
    semantics. A clear-bearing edit against an Atlas that advertises only the
    operator mutation must refuse 501 before any mutation call -- and a
    non-clear edit under the same manifest must still work (the new gate must
    not over-fire on ordinary edits)."""
    mutations: list[dict[str, object]] = []

    def atlas_read_without_field_clear(*_args, **_kwargs):
        return {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION],
            "capabilityRoutes": [
                {"method": "POST", "path": "/eom-funnel/operator-contacts"},
            ],
        }

    target_id = str(uuid.uuid4())

    def atlas_request(path, admin, *, payload, idempotency_key):
        mutations.append(payload)
        return _atlas_result(
            target_id,
            full_name="Ada Operator",
            operation="contact_updated",
            phone="2175550100",
        )

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read_without_field_clear)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)

    clear_body = _payload(str(uuid.uuid4()), email=None)
    clear_body["contactId"] = target_id
    refused = client.post(_path(), headers=auth, json=clear_body)
    assert refused.status_code == 501, refused.text
    assert refused.json()["error"] == "atlas_capability_unavailable"
    assert refused.json()["capability"] == "contact.field_clear"
    assert mutations == [], "the refusal must precede any Atlas mutation"

    plain_body = _payload(str(uuid.uuid4()))
    del plain_body["email"]
    plain_body["contactId"] = target_id
    allowed = client.post(_path(), headers=auth, json=plain_body)
    assert allowed.status_code == 201, allowed.text
    assert len(mutations) == 1, "an ordinary edit must not need the clear capability"


def test_manual_contact_edit_fails_closed_when_atlas_does_not_clear(
    client, auth, monkeypatch
):
    """The receipt must POSITIVELY affirm a clear: a success whose cleared
    field still carries a value AND a success whose receipt omits the key
    entirely are both 502, never reported as saved. An absent key reads None
    through .get() exactly like a real null, so without the presence check a
    dropped mutation would synthesize the success shape this guard verifies."""
    target_id = str(uuid.uuid4())
    shapes = []

    still_set = _atlas_result(
        target_id,
        full_name="Ada Operator",
        operation="contact_updated",
        email="still@there.example",
    )
    shapes.append(still_set)

    key_absent = _atlas_result(
        target_id,
        full_name="Ada Operator",
        operation="contact_updated",
    )
    del key_absent["contact"]["email"]
    shapes.append(key_absent)

    for shape in shapes:
        def atlas_request(*_args, _shape=shape, **_kwargs):
            return _shape

        monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
        body = _payload(str(uuid.uuid4()), email=None)
        body["contactId"] = target_id
        response = client.post(_path(), headers=auth, json=body)

        assert response.status_code == 502, response.text
        assert "did not confirm clearing email" in response.json()["error"], response.text


def test_review_advertises_field_clear_only_with_strict_name_and_route(
    client, auth, monkeypatch
):
    """contactFieldClearAvailable holds the strict mutation-proof standard:
    the versioned capability NAME and the exact registered route, together,
    from one manifest read. Edit-available shapes without the name read false."""
    shapes = [
        # Operator mutation only: edit works, clearing must not.
        (
            {
                "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            {"edit": True, "clear": False},
        ),
        # Both names + route: clearing is provably supported.
        (
            {
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION,
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_FIELD_CLEAR,
                ],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            {"edit": True, "clear": True},
        ),
        # Name without the registered route: rollback shape, both false.
        (
            {
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION,
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_FIELD_CLEAR,
                ],
            },
            {"edit": False, "clear": False},
        ),
        # field_clear WITHOUT the base mutation capability: the endpoint
        # would 501 every clear-bearing edit, so the proof must read false --
        # proof and enforcement require the same pair.
        (
            {
                "capabilities": [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_FIELD_CLEAR],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            {"edit": False, "clear": False},
        ),
        # A malformed member poisons the strict set for both proofs.
        (
            {
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION,
                    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_FIELD_CLEAR,
                    7,
                ],
                "capabilityRoutes": [
                    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
                ],
            },
            {"edit": False, "clear": False},
        ),
    ]
    for manifest_fields, expected in shapes:
        content = {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            **manifest_fields,
        }
        monkeypatch.setattr(api, "_atlas_funnel_read", lambda *_a, _c=content, **_k: _c)
        response = client.get("/api/admin/funnel/review", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["contactEditAvailable"] is expected["edit"], manifest_fields
        assert (
            response.json()["contactFieldClearAvailable"] is expected["clear"]
        ), manifest_fields


def test_clear_gate_proves_the_capability_pair_from_one_manifest_read(
    client, auth, monkeypatch
):
    """A pair proven across two manifest fetches is not a pair.

    An Atlas that alternates between advertising only the base mutation and
    only the clear capability (deploy race / rollback flapping) must refuse a
    clear-bearing edit: under a split-read gate the first fetch would prove
    the base name and the second would prove the clear name, admitting a
    mutation no single deployed manifest ever advertised.
    """
    reads: list[int] = []
    mutations: list[object] = []

    def alternating_manifest(*_args, **_kwargs):
        reads.append(len(reads))
        names = (
            [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_OPERATOR_MUTATION]
            if len(reads) % 2 == 1
            else [api.ATLAS_FUNNEL_CAPABILITY_CONTACT_FIELD_CLEAR]
        )
        return {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": names,
            "capabilityRoutes": [
                {"method": "POST", "path": "/eom-funnel/operator-contacts"},
            ],
        }

    def atlas_request(*_args, **_kwargs):
        mutations.append(True)
        raise AssertionError("no mutation may pass a split-read capability pair")

    monkeypatch.setattr(api, "_atlas_funnel_read", alternating_manifest)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)

    body = _payload(str(uuid.uuid4()), email=None)
    body["contactId"] = str(uuid.uuid4())
    response = client.post(_path(), headers=auth, json=body)

    assert response.status_code == 501, response.text
    assert response.json()["capability"] == "contact.field_clear"
    assert mutations == []
    assert len(reads) == 1, "the pair must be proven from exactly one manifest read"


def test_boundary_length_values_with_padding_normalize_instead_of_422(
    client, auth, monkeypatch
):
    """Stripping must precede the length constraints: a boundary-length value
    with surrounding whitespace is the normalize-and-replace case of the
    tri-state contract, not a too-long rejection."""
    key = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    max_phone = "2" * 64
    max_email = ("a" * 246) + "@ex.test"  # 254 chars, under the 256 cap
    assert len(max_email) <= 256

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_result(
            target_id,
            full_name="Padded Target",
            operation="contact_updated",
            email=max_email,
            phone=max_phone,
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    body = _payload(
        key,
        full_name="Padded Target",
        email=f"  {max_email}  ",
        phone=f" {max_phone} ",
    )
    body["contactId"] = target_id
    response = client.post(_path(), headers=auth, json=body)

    assert response.status_code == 201, response.text
    assert calls[0]["email"] == max_email
    assert calls[0]["phone"] == max_phone
