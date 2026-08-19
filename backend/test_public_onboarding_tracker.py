"""Tracker-owned public onboarding bridge and recovery proofs."""

from __future__ import annotations

import uuid

import pytest

import db
import time_tracker_api as api


_PUBLIC_SESSION_PATH = "/api/public/onboarding/session"
_PUBLIC_COMPLETE_PATH = "/api/public/onboarding/complete"
_ADMIN_RESERVATIONS_PATH = "/api/admin/funnel/public-onboarding/reservations"


class _AtlasResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        return self._body


def _ready_context(
    *,
    token_id: str,
    draft_id: str,
    contact_id: str,
    customer_type: str = "residential",
    address: str = "120 Public Onboarding Way",
    city: str | None = "Effingham",
    state: str | None = "IL",
    postal_code: str | None = "62401",
) -> dict[str, object]:
    return {
        "success": True,
        "status": "ready",
        "full_name": "Public Onboarding Customer",
        "email": "public-onboarding@example.test",
        "phone": "555-0100",
        "address": address,
        "city": city,
        "state": state,
        "zip": postal_code,
        "customer_type": customer_type,
        "token_id": token_id,
        "draft_id": draft_id,
        "contact_id": contact_id,
    }


def _completed_context(
    *,
    token_id: str,
    draft_id: str,
    contact_id: str,
    customer_id: int,
    site_id: int,
    idempotent: bool = True,
) -> dict[str, object]:
    return {
        "success": True,
        "status": "completed",
        "token_id": token_id,
        "draft_id": draft_id,
        "contact_id": contact_id,
        "tracker_customer_id": customer_id,
        "tracker_site_id": site_id,
        "idempotent": idempotent,
    }


def _completion(customer_id: int, site_id: int, *, idempotent: bool = False) -> dict[str, object]:
    return {
        "success": True,
        "status": "completed",
        "tracker_customer_id": customer_id,
        "tracker_site_id": site_id,
        "idempotent": idempotent,
    }


@pytest.fixture(autouse=True)
def _clean_public_onboarding_rows(client):
    """Keep this module's durable handoffs separate from the shared test DB."""
    db.execute("DELETE FROM eom_public_onboarding_reservations")
    db.execute(
        "DELETE FROM locations WHERE customer_name LIKE %s",
        ("Public Onboarding%",),
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", ("Public Onboarding%",))
    yield
    db.execute("DELETE FROM eom_public_onboarding_reservations")
    db.execute(
        "DELETE FROM locations WHERE customer_name LIKE %s",
        ("Public Onboarding%",),
    )
    db.execute("DELETE FROM customers WHERE name LIKE %s", ("Public Onboarding%",))


def test_public_session_is_service_mediated_and_never_returns_private_ids(
    client, monkeypatch
):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    raw_token = "eomob1.raw-bearer-must-not-escape-the-tracker"
    calls: list[dict[str, object]] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": url, "headers": headers or {}, "json": json})
        assert str(url).endswith(api._ATLAS_PUBLIC_ONBOARDING_SESSION_PATH)
        body = _ready_context(
            token_id=token_id,
            draft_id=draft_id,
            contact_id=contact_id,
        )
        # Even an accidental upstream over-return must be projected away before
        # the public browser sees it.
        body.update({"tracker_customer_id": 41, "tracker_site_id": 42})
        return _AtlasResponse(200, body)

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_SESSION_PATH, json={"token": raw_token})

    assert response.status_code == 200, response.text
    assert response.json() == {
        "success": True,
        "status": "ready",
        "fullName": "Public Onboarding Customer",
        "email": "public-onboarding@example.test",
        "phone": "555-0100",
        "address": "120 Public Onboarding Way",
        "city": "Effingham",
        "state": "IL",
        "zip": "62401",
        "customerType": "residential",
    }
    assert token_id not in response.text
    assert draft_id not in response.text
    assert contact_id not in response.text
    assert raw_token not in response.text
    assert calls[0]["headers"]["Authorization"] == "Bearer tracker-only-test-token"
    assert "X-EOM-Actor" not in calls[0]["headers"]
    assert "X-EOM-Actor-ID" not in calls[0]["headers"]
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_public_onboarding_reservations"
    )["count"] == 0


def test_public_session_rejects_a_non_string_bearer_before_calling_atlas(
    client, monkeypatch
):
    calls: list[dict[str, object]] = []

    def atlas_post(url, **kwargs):
        calls.append({"url": str(url), **kwargs})
        raise AssertionError("a non-string bearer must not reach Atlas")

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_SESSION_PATH, json={"token": {"value": "bad"}})

    assert response.status_code == 422, response.text
    assert calls == []


def test_public_session_never_reflects_an_upstream_bearer_diagnostic(
    client, monkeypatch
):
    raw_token = "eomob1.upstream-diagnostic-must-not-reach-browser"

    def atlas_post(url, **kwargs):
        return _AtlasResponse(422, {"detail": raw_token})

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_SESSION_PATH, json={"token": raw_token})

    assert response.status_code == 422, response.text
    assert response.json() == {
        "success": False,
        "error": "Public onboarding link is unavailable",
    }
    assert raw_token not in response.text


def test_public_complete_creates_one_durable_handoff_and_repairs_a_lost_marker(
    client, monkeypatch
):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    raw_token = "eomob1.complete-bearer-never-stored"
    calls: list[dict[str, object]] = []
    state: dict[str, object] = {"completed": False}

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": url, "headers": headers or {}, "json": json})
        path = str(url).removeprefix("https://atlas.example.test/api/v1")
        if path == api._ATLAS_PUBLIC_ONBOARDING_TRACKER_CONTEXT_PATH:
            if state["completed"]:
                return _AtlasResponse(
                    200,
                    _completed_context(
                        token_id=token_id,
                        draft_id=draft_id,
                        contact_id=contact_id,
                        customer_id=int(state["customer_id"]),
                        site_id=int(state["site_id"]),
                    ),
                )
            return _AtlasResponse(
                200,
                _ready_context(
                    token_id=token_id,
                    draft_id=draft_id,
                    contact_id=contact_id,
                ),
            )
        assert path == api._ATLAS_PUBLIC_ONBOARDING_FINALIZE_PATH
        state["completed"] = True
        state["customer_id"] = int(json["tracker_customer_id"])
        state["site_id"] = int(json["tracker_site_id"])
        return _AtlasResponse(
            201,
            _completion(int(state["customer_id"]), int(state["site_id"])),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    first = client.post(_PUBLIC_COMPLETE_PATH, json={"token": raw_token})

    assert first.status_code == 201, first.text
    assert first.json() == {
        "success": True,
        "status": "completed",
        "idempotent": False,
    }
    reservation = db.query_one(
        "SELECT * FROM eom_public_onboarding_reservations WHERE token_id = %s",
        (token_id,),
    )
    assert reservation is not None
    assert reservation["state"] == "finalized"
    assert reservation["last_error"] is None
    customer = db.query_one(
        "SELECT * FROM customers WHERE id = %s", (reservation["customer_id"],)
    )
    site = db.query_one("SELECT * FROM locations WHERE id = %s", (reservation["site_id"],))
    assert customer["atlas_contact_id"] == contact_id
    assert site["customer_id"] == customer["id"]
    assert site["location_type"] == "Residential"
    assert site["address"] == "120 Public Onboarding Way, Effingham, IL 62401"
    assert raw_token not in str(reservation)
    columns = db.query_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'eom_public_onboarding_reservations'
        """
    )
    assert "token" not in {row["column_name"] for row in columns}
    assert all(
        "X-EOM-Actor" not in call["headers"]
        and "X-EOM-Actor-ID" not in call["headers"]
        for call in calls
    )

    # Simulate the narrow crash/lost-response window after Atlas has completed
    # but before the local finalized marker was durable. A bearer replay sees
    # completed context and repairs only that marker; it creates no second row.
    db.execute(
        """
        UPDATE eom_public_onboarding_reservations
        SET state = 'pending', finalized_at = NULL, last_error = 'simulated lost marker'
        WHERE token_id = %s
        """,
        (token_id,),
    )
    replay = client.post(_PUBLIC_COMPLETE_PATH, json={"token": raw_token})
    assert replay.status_code == 200, replay.text
    assert replay.json() == {"success": True, "status": "completed", "idempotent": True}
    repaired = db.query_one(
        "SELECT state, last_error FROM eom_public_onboarding_reservations WHERE token_id = %s",
        (token_id,),
    )
    assert repaired == {"state": "finalized", "last_error": None}
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s",
        (contact_id,),
    )["count"] == 1


def test_public_complete_keeps_a_mismatched_completion_recoverable(client, monkeypatch):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        path = str(url).removeprefix("https://atlas.example.test/api/v1")
        if path == api._ATLAS_PUBLIC_ONBOARDING_TRACKER_CONTEXT_PATH:
            return _AtlasResponse(
                200,
                _ready_context(
                    token_id=token_id,
                    draft_id=draft_id,
                    contact_id=contact_id,
                ),
            )
        assert path == api._ATLAS_PUBLIC_ONBOARDING_FINALIZE_PATH
        return _AtlasResponse(
            201,
            _completion(
                int(json["tracker_customer_id"]) + 1,
                int(json["tracker_site_id"]),
            ),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_COMPLETE_PATH, json={"token": "eomob1.mismatch"})

    assert response.status_code == 502, response.text
    assert response.json() == {
        "success": False,
        "error": "Public onboarding completion was not confirmed",
    }
    reservation = db.query_one(
        """
        SELECT state, last_error
        FROM eom_public_onboarding_reservations
        WHERE token_id = %s
        """,
        (token_id,),
    )
    assert reservation == {
        "state": "pending",
        "last_error": "Atlas public onboarding finalization status=502",
    }
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s",
        (contact_id,),
    )["count"] == 1


@pytest.mark.parametrize(
    ("customer_type", "address", "city", "state", "postal_code", "expected_reason"),
    [
        (
            "unknown",
            "120 Public Onboarding Way",
            "Effingham",
            "IL",
            "62401",
            "unsupported_customer_type",
        ),
        (
            "residential",
            "123 Main St",
            "Effingham",
            None,
            None,
            "existing_service_address",
        ),
    ],
)
def test_public_complete_stops_at_safe_review_states(
    client, monkeypatch, customer_type, address, city, state, postal_code, expected_reason
):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    calls: list[str] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append(str(url))
        assert str(url).endswith(api._ATLAS_PUBLIC_ONBOARDING_TRACKER_CONTEXT_PATH)
        return _AtlasResponse(
            200,
            _ready_context(
                token_id=token_id,
                draft_id=draft_id,
                contact_id=contact_id,
                customer_type=customer_type,
                address=address,
                city=city,
                state=state,
                postal_code=postal_code,
            ),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_COMPLETE_PATH, json={"token": "eomob1.review"})

    assert response.status_code == 409, response.text
    assert response.json() == {
        "success": False,
        "status": "review_required",
        "reason": expected_reason,
    }
    assert len(calls) == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_public_onboarding_reservations"
    )["count"] == 0


def test_public_complete_requires_staff_review_for_an_existing_link(client, monkeypatch):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    existing_customer_id = db.execute_returning(
        """
        INSERT INTO customers (name, atlas_contact_id)
        VALUES ('Public Onboarding Existing Customer', %s)
        RETURNING id
        """,
        (contact_id,),
    )
    assert existing_customer_id
    calls: list[str] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append(str(url))
        return _AtlasResponse(
            200,
            _ready_context(
                token_id=token_id,
                draft_id=draft_id,
                contact_id=contact_id,
            ),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(_PUBLIC_COMPLETE_PATH, json={"token": "eomob1.existing"})

    assert response.status_code == 409, response.text
    assert response.json() == {
        "success": False,
        "status": "review_required",
        "reason": "existing_customer",
    }
    assert len(calls) == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_public_onboarding_reservations"
    )["count"] == 0


def test_generic_customer_finalizer_refuses_a_public_onboarding_contact(client):
    """A generic reservation cannot materialize a contact the public path owns.

    The generic Atlas call occurs before its local finalizer takes the shared
    Customer/Site lock. This exercises the exact interleaving where public
    onboarding commits in that gap, so the generic finalizer must leave its
    reservation pending instead of creating a second local link.
    """
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    public_reservation, created = api._reserve_public_onboarding(
        api.AtlasPublicOnboardingProjection.model_validate(
            _ready_context(
                token_id=token_id,
                draft_id=draft_id,
                contact_id=contact_id,
            )
        )
    )
    assert created is True
    generic_payload = api.CustomerCreateRequest(
        name="Public Onboarding Generic Finalizer Guard"
    )
    generic_reservation, generic_created = api._reserve_customer_atlas_creation(
        generic_payload, {"id": 1}
    )
    assert generic_created is True

    try:
        with pytest.raises(api.HTTPException) as error:
            api._finalize_customer_atlas_reservation(
                str(generic_reservation["id"]), contact_id, generic_payload
            )

        assert error.value.status_code == 409
        assert error.value.detail["code"] == (
            "customer_atlas_link_public_onboarding_reserved"
        )
        assert db.query_one(
            "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s",
            (contact_id,),
        )["count"] == 1
        assert db.query_one(
            "SELECT state FROM eom_customer_atlas_reservations WHERE id = %s",
            (str(generic_reservation["id"]),),
        ) == {"state": "pending"}
        assert db.query_one(
            "SELECT state FROM eom_public_onboarding_reservations WHERE token_id = %s",
            (token_id,),
        ) == {"state": "pending"}
        assert public_reservation["atlas_contact_id"] == contact_id
    finally:
        db.execute(
            "DELETE FROM eom_customer_atlas_reservations WHERE id = %s",
            (str(generic_reservation["id"]),),
        )


def test_pending_public_handoff_recovers_only_through_configured_approver(
    client, auth, monkeypatch
):
    token_id, draft_id, contact_id = (str(uuid.uuid4()) for _ in range(3))
    raw_token = "eomob1.pending-bearer-never-stored"
    calls: list[dict[str, object]] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        path = str(url).removeprefix("https://atlas.example.test/api/v1")
        if path == api._ATLAS_PUBLIC_ONBOARDING_TRACKER_CONTEXT_PATH:
            return _AtlasResponse(
                200,
                _ready_context(
                    token_id=token_id,
                    draft_id=draft_id,
                    contact_id=contact_id,
                ),
            )
        if path == api._ATLAS_PUBLIC_ONBOARDING_FINALIZE_PATH:
            return _AtlasResponse(503, {"detail": raw_token})
        assert path == api._ATLAS_PUBLIC_ONBOARDING_RECOVER_PATH
        return _AtlasResponse(
            201,
            _completion(
                int(json["tracker_customer_id"]), int(json["tracker_site_id"])
            ),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    pending = client.post(_PUBLIC_COMPLETE_PATH, json={"token": raw_token})
    assert pending.status_code == 202, pending.text
    assert pending.json() == {"success": True, "status": "pending_recovery"}
    reservation = db.query_one(
        "SELECT * FROM eom_public_onboarding_reservations WHERE token_id = %s",
        (token_id,),
    )
    assert reservation["state"] == "pending"
    assert raw_token not in str(reservation)

    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)
    listed = client.get(_ADMIN_RESERVATIONS_PATH, headers=auth)
    assert listed.status_code == 200, listed.text
    listed_reservations = listed.json()["reservations"]
    assert len(listed_reservations) == 1
    listed_reservation = listed_reservations[0]
    assert listed_reservation["tokenId"] == token_id
    assert listed_reservation["draftId"] == draft_id
    assert listed_reservation["contactId"] == contact_id
    assert listed_reservation["customerId"] == reservation["customer_id"]
    assert listed_reservation["siteId"] == reservation["site_id"]
    assert listed_reservation["status"] == "pending"
    assert (
        listed_reservation["lastError"]
        == "Atlas public onboarding finalization status=503"
    )
    assert isinstance(listed_reservation["createdAt"], str)
    assert isinstance(listed_reservation["updatedAt"], str)
    assert listed_reservation["finalizedAt"] is None
    denied = client.post(f"{_ADMIN_RESERVATIONS_PATH}/{token_id}/recover", headers=auth)
    assert denied.status_code == 403, denied.text
    assert len(calls) == 2

    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    recovered = client.post(f"{_ADMIN_RESERVATIONS_PATH}/{token_id}/recover", headers=auth)
    assert recovered.status_code == 201, recovered.text
    assert recovered.json()["success"] is True
    assert recovered.json()["idempotent"] is False
    assert recovered.json()["reservation"]["status"] == "finalized"
    recovery_call = calls[-1]
    assert recovery_call["headers"]["X-EOM-Actor"] == "Juan Canfield"
    assert recovery_call["headers"]["X-EOM-Actor-ID"] == "1"
    assert raw_token not in str(recovery_call["json"])
    assert db.query_one(
        "SELECT state, last_error FROM eom_public_onboarding_reservations WHERE token_id = %s",
        (token_id,),
    ) == {"state": "finalized", "last_error": None}


def test_admin_link_revocation_is_juan_gated_and_projects_a_bounded_receipt(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())
    token_id = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        assert str(url).endswith(
            api._ATLAS_ONBOARDING_DRAFT_REVOKE_LINK_PATH.format(draft_id=draft_id)
        )
        return _AtlasResponse(
            201,
            {
                "success": True,
                "token_id": token_id,
                "contact_id": contact_id,
                "status": "revoked",
                "idempotent": False,
            },
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)
    denied = client.post(
        f"/api/admin/funnel/onboarding-drafts/{draft_id}/revoke-link", headers=auth
    )
    assert denied.status_code == 403, denied.text
    assert calls == []

    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    response = client.post(
        f"/api/admin/funnel/onboarding-drafts/{draft_id}/revoke-link", headers=auth
    )
    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "draftId": draft_id,
        "status": "revoked",
        "idempotent": False,
    }
    assert calls[0]["headers"]["X-EOM-Actor"] == "Juan Canfield"
    assert calls[0]["headers"]["X-EOM-Actor-ID"] == "1"
    assert token_id not in response.text
    assert contact_id not in response.text


def test_admin_reservation_list_requires_authentication(client):
    response = client.get(_ADMIN_RESERVATIONS_PATH)
    assert response.status_code == 401, response.text
