"""Closed Tracker bridge for Atlas-owned card setup and readiness."""

from __future__ import annotations

import uuid

import pytest

import time_tracker_api as api


class _AtlasResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        if isinstance(self._body, ValueError):
            raise self._body
        return self._body


def _pending_session(*, idempotent: bool = False) -> dict[str, object]:
    return {
        "enrollmentId": str(uuid.uuid4()),
        "contactId": str(uuid.uuid4()),
        "candidateId": str(uuid.uuid4()),
        "status": "pending",
        "checkoutUrl": "https://checkout.stripe.test/setup/cs_test_123",
        "checkoutExpiresAt": "2026-09-01T13:00:00Z",
        "providerConfirmedAt": None,
        "idempotent": idempotent,
    }


def _ready_session() -> dict[str, object]:
    return {
        "enrollmentId": str(uuid.uuid4()),
        "contactId": str(uuid.uuid4()),
        "candidateId": str(uuid.uuid4()),
        "status": "ready",
        "checkoutUrl": None,
        "checkoutExpiresAt": None,
        "providerConfirmedAt": "2026-09-01T12:45:00Z",
        "idempotent": True,
    }


def _readiness(
    contact_id: str,
    *,
    reason: str = "pending",
) -> dict[str, object]:
    ready = reason == "ready"
    return {
        "contactId": contact_id,
        "audience": "residential",
        "cardRequired": True,
        "cardReady": ready,
        "reason": reason,
        "candidateId": str(uuid.uuid4()),
        "enrollmentId": str(uuid.uuid4()),
        "providerConfirmedAt": "2026-09-01T12:45:00Z" if ready else None,
    }


_CARD_VAULT_PROOFS = (
    (
        "cardVaultPublicSessionAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_CARD_VAULT_PUBLIC_SESSION,
        api._ATLAS_CARD_VAULT_PUBLIC_SESSION_ROUTE,
    ),
    (
        "cardVaultReadinessAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_CARD_VAULT_READINESS_READ,
        api._ATLAS_CARD_VAULT_READINESS_ROUTE,
    ),
)


def _manifest(
    capabilities: list[object], routes: list[object]
) -> dict[str, object]:
    return {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
        "capabilities": capabilities,
        "capabilityRoutes": routes,
    }


def _capabilities() -> list[str]:
    return [capability for _field, capability, _route in _CARD_VAULT_PROOFS]


def _routes() -> list[dict[str, str]]:
    return [
        {"method": route[0], "path": route[1]}
        for _field, _capability, route in _CARD_VAULT_PROOFS
    ]


def test_review_proves_both_card_vault_routes_from_one_strict_manifest(
    client, auth, monkeypatch
):
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(_capabilities(), _routes()),
    )

    response = client.get("/api/admin/funnel/review", headers=auth)

    assert response.status_code == 200, response.text
    for field, _capability, _route in _CARD_VAULT_PROOFS:
        assert response.json()[field] is True


@pytest.mark.parametrize(("field", "capability", "route"), _CARD_VAULT_PROOFS)
@pytest.mark.parametrize("missing_half", ("name", "route"))
def test_review_card_vault_proof_fails_closed_when_exact_half_is_missing(
    client, auth, monkeypatch, field, capability, route, missing_half
):
    capabilities = _capabilities()
    routes = _routes()
    if missing_half == "name":
        capabilities.remove(capability)
    else:
        routes.remove({"method": route[0], "path": route[1]})
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(capabilities, routes),
    )

    response = client.get("/api/admin/funnel/review", headers=auth)

    assert response.status_code == 200, response.text
    assert response.json()[field] is False


@pytest.mark.parametrize("malformed_half", ("name", "route"))
def test_review_card_vault_proofs_reject_partially_malformed_manifest(
    client, auth, monkeypatch, malformed_half
):
    capabilities: list[object] = _capabilities()
    routes: list[object] = _routes()
    if malformed_half == "name":
        capabilities.append(42)
    else:
        routes.append(
            {"method": "post", "path": "/eom-funnel/card-vault/public/session"}
        )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(capabilities, routes),
    )

    response = client.get("/api/admin/funnel/review", headers=auth)

    assert response.status_code == 200, response.text
    for field, _capability, _route in _CARD_VAULT_PROOFS:
        assert response.json()[field] is False


def test_public_card_session_forwards_no_actor_strips_ids_and_preserves_replay(
    client, monkeypatch
):
    raw_token = "eomterms1.card-vault-secret"
    calls: list[dict[str, object]] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        return _AtlasResponse(
            201 if len(calls) == 1 else 200,
            {
                **_pending_session(idempotent=len(calls) > 1),
                "debug": raw_token,
            },
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    created = client.post("/api/public/card-vault/session", json={"token": raw_token})
    replayed = client.post("/api/public/card-vault/session", json={"token": raw_token})

    assert created.status_code == 201, created.text
    assert replayed.status_code == 200, replayed.text
    assert created.json()["status"] == "pending"
    assert created.json()["checkoutUrl"].startswith("https://")
    assert replayed.json()["idempotent"] is True
    assert raw_token not in created.text
    for private_field in ("enrollmentId", "contactId", "candidateId", "debug"):
        assert private_field not in created.json()
    assert calls[0] == {
        "url": (
            f"{api.ATLAS_FUNNEL_BASE_URL}"
            "/eom-funnel/card-vault/public/session"
        ),
        "headers": {
            "Authorization": "Bearer tracker-only-test-token",
            "Accept": "application/json",
        },
        "json": {"token": raw_token},
    }


def test_public_card_session_relays_provider_confirmed_ready_state(
    client, monkeypatch
):
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(200, _ready_session()),
    )

    response = client.post(
        "/api/public/card-vault/session", json={"token": "accepted-bearer"}
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": "ready",
        "checkoutUrl": None,
        "checkoutExpiresAt": None,
        "providerConfirmedAt": "2026-09-01T12:45:00Z",
        "idempotent": True,
    }


@pytest.mark.parametrize(
    "changes",
    (
        {"checkoutUrl": "http://checkout.stripe.test/setup"},
        {"checkoutUrl": "https://"},
        {"checkoutUrl": "https:///setup"},
        {"checkoutUrl": "https://?next=setup"},
        {"checkoutUrl": "https://:443/setup"},
        {"checkoutUrl": "https://[::1"},
        {"checkoutExpiresAt": None},
        {"providerConfirmedAt": "2026-09-01T12:45:00Z"},
        {"status": "ready"},
    ),
)
def test_public_card_session_rejects_malformed_provider_state(
    client, monkeypatch, changes
):
    body = _pending_session()
    body.update(changes)
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(200, body),
    )

    response = client.post(
        "/api/public/card-vault/session", json={"token": "opaque"}
    )

    assert response.status_code == 502, response.text
    assert "checkoutUrl" not in response.json()


@pytest.mark.parametrize(
    ("upstream_status", "expected_status"),
    ((404, 404), (409, 404), (422, 422), (401, 502), (403, 502), (500, 500)),
)
def test_public_card_session_errors_are_generic_and_never_reflect_bearer(
    client, monkeypatch, caplog, upstream_status, expected_status
):
    raw_token = f"eomterms1.card-secret-{upstream_status}"
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(
            upstream_status, {"detail": f"invalid {raw_token}"}
        ),
    )

    response = client.post(
        "/api/public/card-vault/session", json={"token": raw_token}
    )

    assert response.status_code == expected_status, response.text
    assert raw_token not in response.text
    assert raw_token not in caplog.text
    assert response.json()["error"] in {
        "Card setup link is unavailable",
        "Card setup service is temporarily unavailable",
    }


def test_public_card_session_transport_and_non_json_errors_stay_generic(
    client, monkeypatch
):
    raw_token = "eomterms1.card-diagnostic-secret"
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(200, ValueError(raw_token)),
    )
    malformed = client.post(
        "/api/public/card-vault/session", json={"token": raw_token}
    )

    def unavailable(*_args, **_kwargs):
        raise api.requests.Timeout(raw_token)

    monkeypatch.setattr(api.requests, "post", unavailable)
    unavailable_response = client.post(
        "/api/public/card-vault/session", json={"token": raw_token}
    )

    assert malformed.status_code == 502, malformed.text
    assert raw_token not in malformed.text
    assert unavailable_response.status_code == 503, unavailable_response.text
    assert unavailable_response.headers["retry-after"] == "5"
    assert raw_token not in unavailable_response.text


@pytest.mark.parametrize("payload", ({}, {"token": "opaque", "extra": True}))
def test_public_card_session_rejects_missing_or_extra_fields_before_network(
    client, monkeypatch, payload
):
    calls: list[object] = []

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("invalid request must not reach Atlas")

    monkeypatch.setattr(api, "_atlas_card_vault_request", unexpected)

    response = client.post("/api/public/card-vault/session", json=payload)

    assert response.status_code == 422, response.text
    assert calls == []


def test_admin_card_readiness_requires_authentication(client):
    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{uuid.uuid4()}"
    )

    assert response.status_code == 401, response.text


def test_admin_card_readiness_uses_exact_proof_actor_and_bounded_projection(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_get(url, *, headers=None, params=None, timeout=None):
        url_value = str(url)
        calls.append({"url": url_value, "headers": headers or {}, "params": params})
        if url_value.endswith("/eom-funnel/leads"):
            return _AtlasResponse(200, _manifest(_capabilities(), _routes()))
        return _AtlasResponse(
            200,
            {
                **_readiness(contact_id),
                "privateProviderCustomerId": "cus_secret",
            },
        )

    monkeypatch.setattr(api.requests, "get", atlas_get)

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{contact_id}", headers=auth
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "contactId": contact_id,
        "audience": "residential",
        "cardRequired": True,
        "cardReady": False,
        "reason": "pending",
        "providerConfirmedAt": None,
    }
    readiness_call = calls[-1]
    assert readiness_call["url"].endswith(
        f"/eom-funnel/card-vault/readiness/{contact_id}"
    )
    assert readiness_call["headers"]["X-EOM-Actor"] == "Juan Canfield"
    assert readiness_call["headers"]["X-EOM-Actor-ID"] == "1"
    assert readiness_call["params"] is None


def test_admin_card_readiness_rejects_response_for_another_contact(
    client, auth, monkeypatch
):
    requested_contact_id = str(uuid.uuid4())
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_card_vault_request",
        lambda *_args, **_kwargs: _readiness(str(uuid.uuid4())),
    )

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{requested_contact_id}",
        headers=auth,
    )

    assert response.status_code == 502, response.text
    assert "contactId" not in response.json()


@pytest.mark.parametrize(
    "reason", ("service_commitment_required", "future_additive_blocker")
)
def test_admin_card_readiness_preserves_additive_fail_closed_blockers(
    client, auth, monkeypatch, reason
):
    contact_id = str(uuid.uuid4())
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_card_vault_request",
        lambda *_args, **_kwargs: _readiness(contact_id, reason=reason),
    )

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{contact_id}", headers=auth
    )

    assert response.status_code == 200, response.text
    assert response.json()["cardReady"] is False
    assert response.json()["reason"] == reason


def test_admin_card_readiness_accepts_residential_one_time_not_required(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    body = _readiness(contact_id)
    body.update(
        {
            "cardRequired": False,
            "cardReady": True,
            "reason": "not_required",
        }
    )
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_card_vault_request",
        lambda *_args, **_kwargs: body,
    )

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{contact_id}", headers=auth
    )

    assert response.status_code == 200, response.text
    assert response.json()["audience"] == "residential"
    assert response.json()["cardRequired"] is False
    assert response.json()["cardReady"] is True
    assert response.json()["reason"] == "not_required"


def test_admin_card_readiness_refuses_missing_capability_before_provider(
    client, auth, monkeypatch
):
    calls: list[object] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_CARD_VAULT_READINESS_READ
        )

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("unproved capability must not reach provider")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", unavailable)
    monkeypatch.setattr(api, "_atlas_card_vault_request", unexpected)

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{uuid.uuid4()}", headers=auth
    )

    assert response.status_code == 501, response.text
    assert response.json()["capability"] == (
        api.ATLAS_FUNNEL_CAPABILITY_CARD_VAULT_READINESS_READ
    )
    assert calls == []


@pytest.mark.parametrize(
    "changes",
    (
        {"cardReady": True},
        {"reason": "ready"},
        {"audience": "commercial"},
        {"providerConfirmedAt": "2026-09-01T12:45:00Z"},
        {"reason": "not_required"},
        {"reason": ""},
        {"reason": "UPPERCASE"},
        {"reason": "_leading"},
        {"reason": "a" * 129},
        {
            "cardReady": True,
            "reason": "future_additive_blocker",
            "providerConfirmedAt": "2026-09-01T12:45:00Z",
        },
    ),
)
def test_admin_card_readiness_rejects_malformed_provider_verdict(
    client, auth, monkeypatch, changes
):
    contact_id = str(uuid.uuid4())
    body = _readiness(contact_id)
    body.update(changes)
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_card_vault_request",
        lambda *_args, **_kwargs: body,
    )

    response = client.get(
        f"/api/admin/funnel/card-vault/readiness/{contact_id}", headers=auth
    )

    assert response.status_code == 502, response.text
    assert "cardReady" not in response.json()


def test_card_vault_transport_rejects_wrong_shapes_before_configuration(
    monkeypatch,
):
    configuration_calls: list[object] = []
    admin = {"id": 1, "name": "Juan Canfield", "role": "admin"}

    def unexpected_configuration():
        configuration_calls.append(True)
        raise AssertionError("invalid route shape must fail before configuration")

    monkeypatch.setattr(
        api, "_require_atlas_funnel_configuration", unexpected_configuration
    )

    invalid_calls = (
        lambda: api._atlas_card_vault_request(
            ("POST", "/eom-funnel/card-vault/other"), payload={}
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_PUBLIC_SESSION_ROUTE,
            admin=admin,
            payload={"token": "x"},
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_READINESS_ROUTE,
            path_params={"contact_id": uuid.uuid4()},
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_READINESS_ROUTE,
            admin=admin,
            path_params={"contact_id": "not-a-uuid"},
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_READINESS_ROUTE,
            admin=admin,
            path_params={
                "contact_id": uuid.uuid4(),
                "enrollment_id": uuid.uuid4(),
            },
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_READINESS_ROUTE,
            admin=admin,
            path_params={"contact_id": uuid.uuid4()},
            payload={},
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_PUBLIC_SESSION_ROUTE
        ),
        lambda: api._atlas_card_vault_request(
            api._ATLAS_CARD_VAULT_PUBLIC_SESSION_ROUTE,
            payload={"token": "x"},
            path_params={"contact_id": uuid.uuid4()},
        ),
    )
    for call in invalid_calls:
        with pytest.raises(RuntimeError):
            call()

    assert configuration_calls == []
