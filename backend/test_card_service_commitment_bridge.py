"""Tracker relay for Atlas-owned recurring versus one-time decisions."""

from __future__ import annotations

import uuid

import pytest

import time_tracker_api as api


_ROUTE = api._ATLAS_POST_CLEAN_SERVICE_COMMITMENT_ROUTE
_CAPABILITY = api.ATLAS_FUNNEL_CAPABILITY_POST_CLEAN_SERVICE_COMMITMENT_DECIDE


class _AtlasResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        return self._body


def _manifest(
    *,
    include_name: bool = True,
    route: tuple[str, str] | None = _ROUTE,
    malformed_name_member: bool = False,
) -> dict[str, object]:
    capabilities: list[object] = [_CAPABILITY] if include_name else []
    if malformed_name_member:
        capabilities.append({"not": "a capability"})
    routes = [] if route is None else [{"method": route[0], "path": route[1]}]
    return {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
        "capabilities": capabilities,
        "capabilityRoutes": routes,
    }


def _receipt(
    candidate_id: str,
    *,
    contact_id: str | None = None,
    commitment: str = "recurring",
    idempotent: bool = False,
) -> dict[str, object]:
    return {
        "candidateId": candidate_id,
        "contactId": contact_id or str(uuid.uuid4()),
        "serviceCommitment": commitment,
        "decidedByName": "Juan Canfield",
        "decidedAt": "2026-08-30T20:00:00Z",
        "idempotent": idempotent,
        "privateEvidence": "must not relay",
    }


def _path(candidate_id: str) -> str:
    return (
        "/api/admin/funnel/post-clean-onboarding-candidates/"
        f"{candidate_id}/service-commitment"
    )


def test_commitment_route_requires_admin_authentication(client, monkeypatch):
    calls: list[object] = []
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: calls.append(True),
    )

    response = client.post(
        _path(str(uuid.uuid4())),
        json={
            "serviceCommitment": "recurring",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 401, response.text
    assert calls == []


@pytest.mark.parametrize(
    "payload",
    (
        {},
        {"serviceCommitment": "recurring"},
        {"idempotencyKey": str(uuid.uuid4())},
        {
            "serviceCommitment": "weekly",
            "idempotencyKey": str(uuid.uuid4()),
        },
        {"serviceCommitment": "recurring", "idempotencyKey": "not-a-uuid"},
        {
            "serviceCommitment": "recurring",
            "idempotencyKey": str(uuid.uuid4()),
            "candidateId": str(uuid.uuid4()),
        },
    ),
)
def test_commitment_route_rejects_invalid_body_before_atlas(
    client, auth, monkeypatch, payload
):
    calls: list[object] = []

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("invalid browser input must not reach Atlas")

    monkeypatch.setattr(api, "_atlas_funnel_read", unexpected)
    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)

    response = client.post(_path(str(uuid.uuid4())), headers=auth, json=payload)

    assert response.status_code == 422, response.text
    assert calls == []


@pytest.mark.parametrize(
    ("manifest", "available"),
    (
        (_manifest(), True),
        (_manifest(include_name=False), False),
        (_manifest(route=None), False),
        (_manifest(route=("GET", _ROUTE[1])), False),
        (_manifest(malformed_name_member=True), False),
    ),
)
def test_review_and_mutation_share_exact_capability_route_gate(
    client, auth, monkeypatch, manifest, available
):
    candidate_id = str(uuid.uuid4())
    provider_calls: list[object] = []
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: manifest,
    )

    def atlas_request(*_args, **_kwargs):
        provider_calls.append(True)
        return _receipt(candidate_id)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)

    review = client.get("/api/admin/funnel/review", headers=auth)
    mutation = client.post(
        _path(candidate_id),
        headers=auth,
        json={
            "serviceCommitment": "recurring",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert review.status_code == 200, review.text
    assert review.json()["postCleanServiceCommitmentAvailable"] is available
    assert review.json()["postCleanServiceCommitmentValues"] == list(
        api.POST_CLEAN_SERVICE_COMMITMENT_VALUES
    )
    assert mutation.status_code == (201 if available else 501), mutation.text
    assert len(provider_calls) == (1 if available else 0)


def test_commitment_models_and_review_share_one_closed_value_contract(
    client, auth, monkeypatch
):
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(),
    )

    review = client.get("/api/admin/funnel/review", headers=auth)
    request_schema = api.FunnelCardServiceCommitmentRequest.model_json_schema()
    receipt_schema = api.AtlasCardServiceCommitmentReceipt.model_json_schema()
    candidate_schema = api.AtlasPostCleanOnboardingCandidateItem.model_json_schema()

    assert review.status_code == 200, review.text
    assert tuple(review.json()["postCleanServiceCommitmentValues"]) == (
        api.POST_CLEAN_SERVICE_COMMITMENT_VALUES
    )
    assert tuple(request_schema["properties"]["serviceCommitment"]["enum"]) == (
        api.POST_CLEAN_SERVICE_COMMITMENT_VALUES
    )
    assert tuple(receipt_schema["properties"]["serviceCommitment"]["enum"]) == (
        api.POST_CLEAN_SERVICE_COMMITMENT_VALUES
    )
    candidate_value_schema = candidate_schema["properties"]["serviceCommitment"]
    assert tuple(candidate_value_schema["anyOf"][0]["enum"]) == (
        api.POST_CLEAN_SERVICE_COMMITMENT_VALUES
    )


def test_commitment_route_forwards_exact_actor_payload_and_idempotency(
    client, auth, monkeypatch
):
    candidate_id = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    idempotency_key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        api,
        "_atlas_funnel_read",
        lambda *_args, **_kwargs: _manifest(),
    )

    def atlas_post(url, *, headers=None, json=None, timeout=None):
        calls.append({"url": str(url), "headers": headers or {}, "json": json})
        return _AtlasResponse(
            201 if len(calls) == 1 else 200,
            _receipt(
                candidate_id,
                contact_id=contact_id,
                idempotent=len(calls) > 1,
            ),
        )

    monkeypatch.setattr(api.requests, "post", atlas_post)

    payload = {
        "serviceCommitment": "recurring",
        "idempotencyKey": idempotency_key,
    }
    created = client.post(_path(candidate_id), headers=auth, json=payload)
    replayed = client.post(_path(candidate_id), headers=auth, json=payload)

    assert created.status_code == 201, created.text
    assert replayed.status_code == 200, replayed.text
    assert created.json() == {
        "candidateId": candidate_id,
        "contactId": contact_id,
        "serviceCommitment": "recurring",
        "decidedByName": "Juan Canfield",
        "decidedAt": "2026-08-30T20:00:00Z",
        "idempotent": False,
    }
    assert replayed.json()["idempotent"] is True
    assert "privateEvidence" not in created.json()
    expected_url = (
        f"{api.ATLAS_FUNNEL_BASE_URL}"
        f"/eom-funnel/post-clean-onboarding-candidates/{candidate_id}"
        "/service-commitment"
    )
    for call in calls:
        assert call == {
            "url": expected_url,
            "headers": {
                "Authorization": "Bearer tracker-only-test-token",
                "X-EOM-Actor": "Juan Canfield",
                "X-EOM-Actor-ID": "1",
                "Idempotency-Key": idempotency_key,
                "Accept": "application/json",
            },
            "json": {"serviceCommitment": "recurring"},
        }


@pytest.mark.parametrize(
    "changes",
    (
        {"candidateId": str(uuid.uuid4())},
        {"serviceCommitment": "one_time"},
        {"contactId": "not-a-uuid"},
        {"decidedByName": "   "},
        {"decidedAt": "2026-08-30T20:00:00"},
        {"idempotent": 1},
    ),
)
def test_commitment_route_rejects_mismatched_or_malformed_receipt(
    client, auth, monkeypatch, changes
):
    candidate_id = str(uuid.uuid4())
    body = _receipt(candidate_id)
    body.update(changes)
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: body,
    )

    response = client.post(
        _path(candidate_id),
        headers=auth,
        json={
            "serviceCommitment": "recurring",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 502, response.text
    assert response.json()["error"] == (
        "Service commitment service is temporarily unavailable"
    )
    assert "candidateId" not in response.json()


@pytest.mark.parametrize("body", (None, [], "unexpected"))
def test_commitment_route_rejects_non_object_receipt(
    client, auth, monkeypatch, body
):
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: body,
    )

    response = client.post(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={
            "serviceCommitment": "recurring",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 502, response.text
    assert response.json()["error"] == (
        "Service commitment service is temporarily unavailable"
    )


@pytest.mark.parametrize("status_code", (409, 503))
def test_commitment_route_maps_upstream_errors_without_reflection(
    client, auth, monkeypatch, status_code
):
    secret = "atlas-internal-decision-detail"
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )

    def rejected(*_args, **_kwargs):
        raise api.AtlasFunnelRequestError(status_code, secret)

    monkeypatch.setattr(api, "_atlas_funnel_request", rejected)

    response = client.post(
        _path(str(uuid.uuid4())),
        headers=auth,
        json={
            "serviceCommitment": "one_time",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == status_code, response.text
    assert secret not in response.text
    if status_code >= 500:
        assert response.headers["retry-after"] == "5"
    else:
        assert "retry-after" not in response.headers


def test_commitment_success_survives_local_audit_failure(
    client, auth, monkeypatch
):
    candidate_id = str(uuid.uuid4())
    monkeypatch.setattr(
        api,
        "_require_atlas_funnel_capability_route",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_args, **_kwargs: _receipt(candidate_id, commitment="one_time"),
    )
    monkeypatch.setattr(
        api,
        "append_access_log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit down")),
    )

    response = client.post(
        _path(candidate_id),
        headers=auth,
        json={
            "serviceCommitment": "one_time",
            "idempotencyKey": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["serviceCommitment"] == "one_time"
