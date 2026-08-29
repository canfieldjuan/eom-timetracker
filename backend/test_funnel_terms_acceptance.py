"""Closed Tracker bridge for Atlas-owned Terms acceptance."""

from __future__ import annotations

import uuid

import pytest

import time_tracker_api as api


class _AtlasResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        return self._body


def _ids(count: int) -> list[str]:
    return [str(uuid.uuid4()) for _ in range(count)]


def _invitation(
    *, idempotent: bool = False, status: str = "issued", locale: str = "en"
) -> dict[str, object]:
    invitation_id, contact_id, version_id, delivery_id = _ids(4)
    return {
        "invitationId": invitation_id,
        "contactId": contact_id,
        "versionId": version_id,
        "versionLabel": "2026-08-29",
        "contentHash": "a" * 64,
        "audience": "residential",
        "locale": locale,
        "recipientEmail": "customer@example.test",
        "status": status,
        "issuedAt": "2026-08-29T12:00:00Z",
        "expiresAt": "2026-09-05T12:00:00Z",
        "revokedAt": "2026-08-29T13:00:00Z" if status == "revoked" else None,
        "acceptanceId": None,
        "deliveryId": delivery_id,
        "deliveryStatus": "sent",
        "deliveryNeedsReconciliation": False,
        "deliveryError": False,
        "idempotent": idempotent,
    }


def _ready_session(*, locale: str = "en") -> dict[str, object]:
    invitation_id, version_id = _ids(2)
    return {
        "status": "ready",
        "invitationId": invitation_id,
        "versionId": version_id,
        "versionLabel": "2026-08-29",
        "contentHash": "b" * 64,
        "audience": "commercial",
        "locale": locale,
        "customerName": "Terms Customer",
        "documents": {
            "terms": "General terms",
            "servicesWeCannotProvide": "Excluded services",
            "additionalWorkAcknowledgement": "Additional work requires approval",
            "privateDraft": "must be stripped",
        },
        "expiresAt": "2026-09-05T12:00:00Z",
        "acceptedAt": None,
    }


def _accepted_session(*, locale: str = "en") -> dict[str, object]:
    invitation_id, version_id = _ids(2)
    return {
        "status": "accepted",
        "invitationId": invitation_id,
        "versionId": version_id,
        "versionLabel": "2026-08-29",
        "contentHash": "b" * 64,
        "audience": "commercial",
        "locale": locale,
        "customerName": None,
        "documents": None,
        "expiresAt": None,
        "acceptedAt": "2026-08-29T14:00:00Z",
    }


def _acceptance(*, idempotent: bool = False, locale: str = "en") -> dict[str, object]:
    acceptance_id, invitation_id, contact_id, version_id, delivery_id = _ids(5)
    return {
        "acceptanceId": acceptance_id,
        "invitationId": invitation_id,
        "contactId": contact_id,
        "versionId": version_id,
        "versionLabel": "2026-08-29",
        "contentHash": "c" * 64,
        "audience": "residential",
        "locale": locale,
        "signerName": "Customer Signer",
        "termsAccepted": True,
        "additionalWorkAccepted": True,
        "acceptedAt": "2026-08-29T14:00:00Z",
        "deliveryId": delivery_id,
        "executedCopyDeliveryStatus": "sent",
        "deliveryNeedsReconciliation": False,
        "deliveryError": False,
        "idempotent": idempotent,
    }


def _readiness(contact_id: str) -> dict[str, object]:
    version_id = str(uuid.uuid4())
    return {
        "contactId": contact_id,
        "audience": "commercial",
        "ready": True,
        "reason": "accepted",
        "currentVersionId": version_id,
        "currentVersionLabel": "2026-08-29",
        "currentContentHash": "d" * 64,
        "acceptedVersionId": version_id,
        "acceptedVersionLabel": "2026-08-29",
        "acceptedAt": "2026-08-29T12:30:00Z",
        "executedCopyDeliveryStatus": "sent",
    }


def _delivery(delivery_id: str) -> dict[str, object]:
    return {
        "deliveryId": delivery_id,
        "kind": "executed_copy",
        "status": "sent",
        "sentAt": "2026-08-29T14:05:00Z",
        "idempotent": False,
    }


_TERMS_PROOFS = (
    (
        "termsInvitationIssueAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_INVITATION_ISSUE,
        api._ATLAS_TERMS_INVITATION_ISSUE_ROUTE,
    ),
    (
        "termsInvitationRevokeAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_INVITATION_REVOKE,
        api._ATLAS_TERMS_INVITATION_REVOKE_ROUTE,
    ),
    (
        "termsReadinessAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_READINESS_READ,
        api._ATLAS_TERMS_READINESS_ROUTE,
    ),
    (
        "termsDeliveryConfirmSentAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_DELIVERY_CONFIRM_SENT,
        api._ATLAS_TERMS_DELIVERY_CONFIRM_SENT_ROUTE,
    ),
    (
        "termsPublicSessionAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_PUBLIC_SESSION,
        api._ATLAS_TERMS_PUBLIC_SESSION_ROUTE,
    ),
    (
        "termsPublicAcceptAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_TERMS_PUBLIC_ACCEPT,
        api._ATLAS_TERMS_PUBLIC_ACCEPT_ROUTE,
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


def _all_terms_capabilities() -> list[str]:
    return [capability for _field, capability, _route in _TERMS_PROOFS]


def _all_terms_routes() -> list[dict[str, str]]:
    return [
        {"method": route[0], "path": route[1]}
        for _field, _capability, route in _TERMS_PROOFS
    ]


def test_review_proves_all_six_terms_routes_from_one_strict_manifest(
    client, auth, monkeypatch
):
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(
            _all_terms_capabilities(), _all_terms_routes()
        ),
    )

    response = client.get("/api/admin/funnel/review", headers=auth)

    assert response.status_code == 200, response.text
    for field, _capability, _route in _TERMS_PROOFS:
        assert response.json()[field] is True


@pytest.mark.parametrize(("field", "capability", "route"), _TERMS_PROOFS)
@pytest.mark.parametrize("missing_half", ("name", "route"))
def test_review_terms_proof_fails_closed_when_either_exact_half_is_missing(
    client, auth, monkeypatch, field, capability, route, missing_half
):
    capabilities = _all_terms_capabilities()
    routes = _all_terms_routes()
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
def test_review_terms_proofs_reject_a_partially_malformed_manifest(
    client, auth, monkeypatch, malformed_half
):
    capabilities: list[object] = _all_terms_capabilities()
    routes: list[object] = _all_terms_routes()
    if malformed_half == "name":
        capabilities.append(42)
    else:
        routes.append({"method": "post", "path": "/eom-funnel/terms/public/session"})
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(capabilities, routes),
    )

    response = client.get("/api/admin/funnel/review", headers=auth)

    assert response.status_code == 200, response.text
    for field, _capability, _route in _TERMS_PROOFS:
        assert response.json()[field] is False


def test_issue_invitation_maps_uuid_request_key_and_preserves_replay_status(
    client, auth, monkeypatch
):
    calls: list[dict[str, object]] = []
    body = _invitation()
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    monkeypatch.setattr(
        api, "_require_atlas_funnel_capability_route", lambda *_args: None
    )

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        return _AtlasResponse(201, {**body, "providerSecret": "must be stripped"})

    monkeypatch.setattr(api.requests, "post", atlas_post)
    contact_id, idempotency_key = _ids(2)
    payload = {
        "contactId": contact_id,
        "locale": "en",
        "idempotencyKey": idempotency_key,
    }

    created = client.post(
        "/api/admin/funnel/terms/invitations", headers=auth, json=payload
    )
    body["idempotent"] = True
    replayed = client.post(
        "/api/admin/funnel/terms/invitations", headers=auth, json=payload
    )

    assert created.status_code == 201, created.text
    assert replayed.status_code == 200, replayed.text
    assert "providerSecret" not in created.json()
    assert calls[0]["url"].endswith("/eom-funnel/terms/invitations")
    assert calls[0]["json"] == {
        "requestKey": idempotency_key,
        "contactId": contact_id,
        "locale": "en",
    }
    assert calls[0]["headers"]["X-EOM-Actor"] == "Juan Canfield"
    assert calls[0]["headers"]["X-EOM-Actor-ID"] == "1"
    assert calls[0]["headers"]["Authorization"] == "Bearer tracker-only-test-token"
    assert "Idempotency-Key" not in calls[0]["headers"]


def test_issue_invitation_rejects_spanish_provider_projection(
    client, auth, monkeypatch
):
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    monkeypatch.setattr(
        api, "_require_atlas_funnel_capability_route", lambda *_args: None
    )
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(
            201, _invitation(locale="es")
        ),
    )

    response = client.post(
        "/api/admin/funnel/terms/invitations",
        headers=auth,
        json={
            "contactId": str(uuid.uuid4()),
            "locale": "en",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 502, response.text


def test_dynamic_admin_terms_routes_use_exact_methods_paths_and_actor_headers(
    client, auth, monkeypatch
):
    invitation_id, contact_id, delivery_id = _ids(3)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)
    monkeypatch.setattr(
        api, "_require_atlas_funnel_capability_route", lambda *_args: None
    )

    def atlas_get(url, *, headers=None, timeout=None):
        calls.append({"method": "GET", "url": str(url), "headers": headers or {}})
        return _AtlasResponse(200, {**_readiness(contact_id), "internal": "strip"})

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append(
            {
                "method": "POST",
                "url": str(url),
                "headers": headers or {},
                "json": json,
            }
        )
        if str(url).endswith("/confirm-sent"):
            return _AtlasResponse(200, {**_delivery(delivery_id), "internal": "strip"})
        return _AtlasResponse(200, {**_invitation(status="revoked"), "internal": "strip"})

    monkeypatch.setattr(api.requests, "get", atlas_get)
    monkeypatch.setattr(api.requests, "post", atlas_post)

    readiness = client.get(
        f"/api/admin/funnel/terms/readiness/{contact_id}", headers=auth
    )
    assert readiness.status_code == 200, readiness.text
    assert "internal" not in readiness.json()
    assert calls[-1]["method"] == "GET"
    assert calls[-1]["url"].endswith(f"/eom-funnel/terms/readiness/{contact_id}")
    assert calls[-1]["headers"]["X-EOM-Actor-ID"] == "1"

    # Readiness is deliberately ordinary-admin. The two following mutations
    # remain Juan-only, so switch the configured stable identity only now.
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    revoked = client.post(
        f"/api/admin/funnel/terms/invitations/{invitation_id}/revoke",
        headers=auth,
    )
    assert revoked.status_code == 200, revoked.text
    assert "internal" not in revoked.json()
    assert calls[-1]["url"].endswith(
        f"/eom-funnel/terms/invitations/{invitation_id}/revoke"
    )
    assert calls[-1]["json"] == {}
    assert calls[-1]["headers"]["X-EOM-Actor-ID"] == "1"

    confirmed = client.post(
        f"/api/admin/funnel/terms/deliveries/{delivery_id}/confirm-sent",
        headers=auth,
    )
    assert confirmed.status_code == 200, confirmed.text
    assert "internal" not in confirmed.json()
    assert calls[-1]["url"].endswith(
        f"/eom-funnel/terms/deliveries/{delivery_id}/confirm-sent"
    )
    assert calls[-1]["json"] == {}
    assert calls[-1]["headers"]["X-EOM-Actor"] == "Juan Canfield"


@pytest.mark.parametrize(
    ("method", "path", "json_body"),
    (
        (
            "post",
            "/api/admin/funnel/terms/invitations",
            {
                "contactId": str(uuid.uuid4()),
                "locale": "en",
                "idempotencyKey": str(uuid.uuid4()),
            },
        ),
        (
            "post",
            f"/api/admin/funnel/terms/invitations/{uuid.uuid4()}/revoke",
            None,
        ),
        (
            "post",
            f"/api/admin/funnel/terms/deliveries/{uuid.uuid4()}/confirm-sent",
            None,
        ),
    ),
)
def test_terms_mutations_refuse_non_juan_before_capability_or_network(
    client, auth, monkeypatch, method, path, json_body
):
    calls: list[object] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Juan refusal must happen before Atlas work")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", unexpected)
    monkeypatch.setattr(api, "_atlas_terms_request", unexpected)

    response = client.request(method, path, headers=auth, json=json_body)

    assert response.status_code == 403, response.text
    assert calls == []


@pytest.mark.parametrize(
    ("method", "path", "json_body"),
    (
        (
            "post",
            "/api/admin/funnel/terms/invitations",
            {
                "contactId": str(uuid.uuid4()),
                "locale": "en",
                "idempotencyKey": str(uuid.uuid4()),
            },
        ),
        ("post", f"/api/admin/funnel/terms/invitations/{uuid.uuid4()}/revoke", None),
        ("get", f"/api/admin/funnel/terms/readiness/{uuid.uuid4()}", None),
        (
            "post",
            f"/api/admin/funnel/terms/deliveries/{uuid.uuid4()}/confirm-sent",
            None,
        ),
    ),
)
def test_admin_terms_routes_require_authentication(client, method, path, json_body):
    response = client.request(method, path, json=json_body)

    assert response.status_code == 401, response.text


def test_admin_terms_route_refuses_missing_capability_before_provider_call(
    client, auth, monkeypatch
):
    calls: list[object] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_TERMS_INVITATION_ISSUE
        )

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("unproved capability must not reach provider")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", unavailable)
    monkeypatch.setattr(api, "_atlas_terms_request", unexpected)
    response = client.post(
        "/api/admin/funnel/terms/invitations",
        headers=auth,
        json={
            "contactId": str(uuid.uuid4()),
            "locale": "en",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 501, response.text
    assert response.json()["capability"] == api.ATLAS_FUNNEL_CAPABILITY_TERMS_INVITATION_ISSUE
    assert calls == []


def test_public_terms_session_has_no_actor_and_strips_unreviewed_fields(
    client, monkeypatch
):
    raw_token = "eomterms1.raw-bearer-must-not-return"
    calls: list[dict[str, object]] = []

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        return _AtlasResponse(
            200,
            {
                **_ready_session(),
                "contactId": str(uuid.uuid4()),
                "debug": raw_token,
            },
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(
        "/api/public/terms/session", json={"token": raw_token}
    )

    assert response.status_code == 200, response.text
    assert raw_token not in response.text
    assert "contactId" not in response.json()
    assert "invitationId" not in response.json()
    assert "versionId" not in response.json()
    assert "privateDraft" not in response.json()["documents"]
    assert calls == [
        {
            "url": f"{api.ATLAS_FUNNEL_BASE_URL}/eom-funnel/terms/public/session",
            "headers": {
                "Authorization": "Bearer tracker-only-test-token",
                "Accept": "application/json",
            },
            "json": {"token": raw_token},
        }
    ]


def test_public_terms_accepted_session_keeps_state_without_internal_ids(
    client, monkeypatch
):
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(200, _accepted_session()),
    )

    response = client.post(
        "/api/public/terms/session", json={"token": "accepted-bearer"}
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "accepted"
    assert response.json()["acceptedAt"] == "2026-08-29T14:00:00Z"
    assert "invitationId" not in response.json()
    assert "versionId" not in response.json()


def test_public_terms_session_rejects_spanish_provider_projection(
    client, monkeypatch
):
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(
            200, _ready_session(locale="es")
        ),
    )

    response = client.post(
        "/api/public/terms/session", json={"token": "english-only-bearer"}
    )

    assert response.status_code == 502, response.text
    assert "documents" not in response.json()


def test_public_terms_accept_forwards_normalized_trusted_ip_only_on_accept(
    client, monkeypatch
):
    raw_token = "eomterms1.accept-bearer"
    calls: list[dict[str, object]] = []
    body = _acceptance()
    monkeypatch.setattr(api, "TRUST_PROXY", True)
    monkeypatch.setattr(api, "TRUSTED_PROXY_HOPS", 2)

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        return _AtlasResponse(201, {**body, "debug": raw_token})

    monkeypatch.setattr(api.requests, "post", atlas_post)
    payload = {
        "token": raw_token,
        "signerName": "Customer Signer",
        "termsAccepted": True,
        "additionalWorkAccepted": True,
    }
    created = client.post(
        "/api/public/terms/accept",
        headers={"X-Forwarded-For": "198.51.100.9, 203.0.113.8, 10.0.0.4"},
        json=payload,
    )
    body["idempotent"] = True
    replayed = client.post(
        "/api/public/terms/accept",
        headers={"X-Forwarded-For": "198.51.100.9, 203.0.113.8, 10.0.0.4"},
        json=payload,
    )

    assert created.status_code == 201, created.text
    assert replayed.status_code == 200, replayed.text
    assert raw_token not in created.text
    for private_id in (
        "acceptanceId",
        "invitationId",
        "contactId",
        "versionId",
        "deliveryId",
    ):
        assert private_id not in created.json()
    assert calls[0]["url"].endswith("/eom-funnel/terms/public/accept")
    assert calls[0]["json"] == payload
    assert calls[0]["headers"]["X-EOM-Client-IP"] == "203.0.113.8"
    assert "X-EOM-Actor" not in calls[0]["headers"]
    assert "X-EOM-Actor-ID" not in calls[0]["headers"]


def test_public_terms_accept_rejects_spanish_provider_projection(
    client, monkeypatch
):
    monkeypatch.setattr(
        api.requests,
        "post",
        lambda *_args, **_kwargs: _AtlasResponse(
            201, _acceptance(locale="es")
        ),
    )

    response = client.post(
        "/api/public/terms/accept",
        json={
            "token": "english-only-bearer",
            "signerName": "Customer Signer",
            "termsAccepted": True,
            "additionalWorkAccepted": True,
        },
    )

    assert response.status_code == 502, response.text
    assert "signerName" not in response.json()


@pytest.mark.parametrize(
    ("upstream_status", "expected_status"),
    ((404, 404), (409, 404), (401, 502), (403, 502), (500, 500)),
)
def test_public_terms_errors_are_generic_and_never_reflect_the_bearer(
    client, monkeypatch, upstream_status, expected_status
):
    raw_token = f"eomterms1.secret-{upstream_status}"

    def atlas_post(*_args, **_kwargs):
        return _AtlasResponse(upstream_status, {"detail": f"invalid {raw_token}"})

    monkeypatch.setattr(api.requests, "post", atlas_post)
    response = client.post(
        "/api/public/terms/session", json={"token": raw_token}
    )

    assert response.status_code == expected_status, response.text
    assert raw_token not in response.text
    assert response.json()["error"] in {
        "Terms link is unavailable",
        "Terms service is temporarily unavailable",
    }


def test_public_terms_malformed_response_and_transport_error_stay_generic(
    client, monkeypatch
):
    raw_token = "eomterms1.not-for-diagnostics"

    def malformed(*_args, **_kwargs):
        return _AtlasResponse(
            200,
            {
                **_ready_session(),
                "documents": None,
                "debug": raw_token,
            },
        )

    monkeypatch.setattr(api.requests, "post", malformed)
    malformed_response = client.post(
        "/api/public/terms/session", json={"token": raw_token}
    )
    assert malformed_response.status_code == 502, malformed_response.text
    assert raw_token not in malformed_response.text

    def unavailable(*_args, **_kwargs):
        raise api.requests.Timeout(raw_token)

    monkeypatch.setattr(api.requests, "post", unavailable)
    unavailable_response = client.post(
        "/api/public/terms/session", json={"token": raw_token}
    )
    assert unavailable_response.status_code == 503, unavailable_response.text
    assert raw_token not in unavailable_response.text


@pytest.mark.parametrize(
    "payload",
    (
        {
            "contactId": "not-a-uuid",
            "locale": "en",
            "idempotencyKey": str(uuid.uuid4()),
        },
        {
            "contactId": str(uuid.uuid4()),
            "locale": "en",
            "idempotencyKey": str(uuid.uuid4()),
            "extra": True,
        },
        {
            "contactId": str(uuid.uuid4()),
            "locale": "es",
            "idempotencyKey": str(uuid.uuid4()),
        },
        {
            "contactId": str(uuid.uuid4()),
            "idempotencyKey": str(uuid.uuid4()),
        },
        {
            "contactId": str(uuid.uuid4()),
            "locale": "fr",
            "idempotencyKey": str(uuid.uuid4()),
        },
    ),
)
def test_invitation_request_rejects_invalid_or_extra_fields_before_network(
    client, auth, monkeypatch, payload
):
    calls: list[object] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("invalid request must not reach Atlas")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability_route", unexpected)
    monkeypatch.setattr(api, "_atlas_terms_request", unexpected)
    response = client.post(
        "/api/admin/funnel/terms/invitations", headers=auth, json=payload
    )

    assert response.status_code == 422, response.text
    assert calls == []


@pytest.mark.parametrize(
    "payload",
    (
        {
            "token": "opaque",
            "signerName": "Customer",
            "termsAccepted": False,
            "additionalWorkAccepted": True,
        },
        {
            "token": "opaque",
            "signerName": "Customer",
            "termsAccepted": True,
            "additionalWorkAccepted": True,
            "extra": True,
        },
        {
            "token": "opaque",
            "signerName": "",
            "termsAccepted": True,
            "additionalWorkAccepted": True,
        },
    ),
)
def test_acceptance_request_rejects_false_extra_or_unbounded_fields(
    client, monkeypatch, payload
):
    calls: list[object] = []

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("invalid acceptance must not reach Atlas")

    monkeypatch.setattr(api, "_atlas_terms_request", unexpected)
    response = client.post("/api/public/terms/accept", json=payload)

    assert response.status_code == 422, response.text
    assert calls == []


def test_terms_transport_rejects_wrong_boundary_shapes_before_configuration(
    monkeypatch,
):
    configuration_calls: list[object] = []
    admin = {"id": 1, "name": "Juan Canfield", "role": "admin"}

    def unexpected_configuration():
        configuration_calls.append(True)
        raise AssertionError("invalid route shape must fail before configuration")

    monkeypatch.setattr(api, "_require_atlas_funnel_configuration", unexpected_configuration)

    invalid_calls = (
        lambda: api._atlas_terms_request(("GET", "/eom-funnel/terms/current")),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_PUBLIC_SESSION_ROUTE, admin=admin, payload={"token": "x"}
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_INVITATION_ISSUE_ROUTE, payload={}
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_INVITATION_REVOKE_ROUTE,
            admin=admin,
            path_params={"invitation_id": "not-a-uuid"},
            payload={},
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_INVITATION_REVOKE_ROUTE,
            admin=admin,
            path_params={
                "invitation_id": uuid.uuid4(),
                "contact_id": uuid.uuid4(),
            },
            payload={},
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_READINESS_ROUTE,
            admin=admin,
            path_params={"contact_id": uuid.uuid4()},
            payload={},
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_PUBLIC_ACCEPT_ROUTE,
            payload={"token": "x"},
        ),
        lambda: api._atlas_terms_request(
            api._ATLAS_TERMS_PUBLIC_SESSION_ROUTE,
            payload={"token": "x"},
            client_ip="203.0.113.8",
        ),
    )
    for call in invalid_calls:
        with pytest.raises(RuntimeError):
            call()

    assert configuration_calls == []
