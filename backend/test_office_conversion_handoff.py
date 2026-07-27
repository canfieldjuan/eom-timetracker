"""Office estimate approval: one local Customer/Site and retryable Atlas link."""

from __future__ import annotations

import uuid

import pytest

import db


def _payload(contact_id: str, key: str, *, rate: float = 175.0) -> dict[str, object]:
    suffix = contact_id[:8]
    return {
        "name": f"Approved Estimate {suffix}",
        "primaryContactName": "Estimate Contact",
        "primaryPhone": "217-555-0123",
        "primaryEmail": f"{suffix}@example.test",
        "billingName": f"Approved Estimate {suffix}",
        "billingEmail": f"billing-{suffix}@example.test",
        "billingAddress": f"{suffix} Estimate Lane, Effingham, IL",
        "atlasContactId": contact_id,
        "idempotencyKey": key,
        "primarySite": {
            "address": f"{suffix} Estimate Lane, Effingham, IL",
            "locationType": "Residential",
            "rate": rate,
            "rateType": "per_visit",
            "frequency": "Every two weeks, weekday morning",
            "expectedHours": 3.5,
            "serviceScope": "Kitchen, baths, floors",
            "serviceStartDate": "2026-08-01",
        },
    }


@pytest.fixture
def configured_office_conversion(monkeypatch):
    import time_tracker_api as api

    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)
    monkeypatch.setattr(api, "ATLAS_FUNNEL_BASE_URL", "https://atlas.example.test")
    monkeypatch.setattr(api, "ATLAS_FUNNEL_SERVICE_TOKEN", "tracker-only-test-token")
    return api


def _atlas_success(payload: dict[str, object], key: str) -> dict[str, object]:
    return {
        "success": True,
        "handoff_id": str(uuid.uuid4()),
        "contact_id": payload["contact_id"],
        "tracker_customer_id": payload["tracker_customer_id"],
        "tracker_site_id": payload["tracker_site_id"],
        "approval_key": key,
    }


def test_estimate_approval_creates_one_customer_site_and_never_sends_rate_or_schedule(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append({"path": path, "admin": admin, "payload": payload, "key": idempotency_key})
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, key),
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["success"] is True
    assert data["handoff"]["status"] == "finalized"
    customer = data["handoff"]["customer"]
    assert customer["atlasContactId"] == contact_id
    assert customer["sites"][0]["rate"] == 175.0
    assert customer["sites"][0]["frequency"] == "Every two weeks, weekday morning"
    assert calls == [
        {
            "path": "/eom-funnel/customer-handoffs",
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "payload": {
                "contact_id": contact_id,
                "tracker_customer_id": data["handoff"]["customerId"],
                "tracker_site_id": data["handoff"]["siteId"],
            },
            "key": key,
        }
    ]


@pytest.mark.parametrize("site_field", ("rate", "rateType", "frequency"))
def test_estimate_approval_requires_completed_estimate_site_fields(
    client, auth, monkeypatch, configured_office_conversion, site_field
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    body = _payload(contact_id, key)
    assert isinstance(body["primarySite"], dict)
    del body["primarySite"][site_field]

    def unexpected(*args, **kwargs):
        raise AssertionError("Atlas must not be called for an incomplete estimate")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)
    response = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=body,
    )

    assert response.status_code == 422
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s", (contact_id,)
    )["count"] == 0


def test_estimate_approval_retry_is_idempotent_and_changed_retry_fails_closed(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first_payload = _payload(contact_id, key)
    first = client.post("/api/admin/funnel/approve-estimate", headers=auth, json=first_payload)
    replay = client.post("/api/admin/funnel/approve-estimate", headers=auth, json=first_payload)
    changed = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, key, rate=200.0),
    )
    different_key = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, str(uuid.uuid4())),
    )

    assert first.status_code == 201, first.text
    assert replay.status_code == 200, replay.text
    assert replay.json()["idempotent"] is True
    assert changed.status_code == 409
    assert different_key.status_code == 409
    assert len(calls) == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s", (contact_id,)
    )["count"] == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM eom_office_conversion_handoffs WHERE atlas_contact_id = %s",
        (contact_id,),
    )["count"] == 1


def test_estimate_approval_reused_key_for_different_contact_fails_closed(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    first_contact_id = str(uuid.uuid4())
    second_contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(payload)
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(first_contact_id, key),
    )
    reused = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(second_contact_id, key),
    )

    assert first.status_code == 201, first.text
    assert reused.status_code == 409
    assert reused.json()["code"] == "office_conversion_approval_key_already_reserved"
    assert len(calls) == 1
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s",
        (second_contact_id,),
    )["count"] == 0
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM eom_office_conversion_handoffs
        WHERE idempotency_key = %s
        """,
        (key,),
    )["count"] == 1


def test_estimate_approval_recovers_after_atlas_failure_without_duplicate_customer_or_site(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    first_attempt = True

    def atlas_request(path, admin, *, payload, idempotency_key):
        nonlocal first_attempt
        if first_attempt:
            first_attempt = False
            raise api.AtlasFunnelRequestError(503, "Atlas is temporarily unavailable")
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    body = _payload(contact_id, key)
    pending = client.post("/api/admin/funnel/approve-estimate", headers=auth, json=body)
    recovered = client.post("/api/admin/funnel/approve-estimate", headers=auth, json=body)

    assert pending.status_code == 202, pending.text
    assert pending.json()["handoff"]["status"] == "atlas_pending"
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["idempotent"] is True
    assert recovered.json()["handoff"]["status"] == "finalized"
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s", (contact_id,)
    )["count"] == 1
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM locations l JOIN customers c ON c.id = l.customer_id
        WHERE c.atlas_contact_id = %s
        """,
        (contact_id,),
    )["count"] == 1


def test_funnel_review_lists_atlas_leads_and_pending_handoffs_without_writes(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())

    def atlas_request(path, admin, *, payload, idempotency_key):
        raise api.AtlasFunnelRequestError(503, "Atlas is temporarily unavailable")

    def atlas_read(path, admin, *, params=None):
        return {
            "leads": [
                {
                    "contactId": contact_id,
                    "fullName": "New Estimate Lead",
                    "email": "lead@example.test",
                    "phone": "217-555-0144",
                    "address": "900 Lead Lane, Effingham, IL",
                    "source": "website",
                    "createdAt": "2026-07-27T12:00:00Z",
                    "internalField": "must not proxy",
                }
            ]
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    pending = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, key),
    )
    before_counts = {
        "customers": db.query_one("SELECT COUNT(*) AS n FROM customers")["n"],
        "sites": db.query_one("SELECT COUNT(*) AS n FROM locations")["n"],
        "handoffs": db.query_one("SELECT COUNT(*) AS n FROM eom_office_conversion_handoffs")["n"],
    }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    response = client.get("/api/admin/funnel/review", headers=auth)
    after_counts = {
        "customers": db.query_one("SELECT COUNT(*) AS n FROM customers")["n"],
        "sites": db.query_one("SELECT COUNT(*) AS n FROM locations")["n"],
        "handoffs": db.query_one("SELECT COUNT(*) AS n FROM eom_office_conversion_handoffs")["n"],
    }

    assert pending.status_code == 202, pending.text
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["success"] is True
    assert data["canApprove"] is True
    assert data["leads"] == [
        {
            "contactId": contact_id,
            "fullName": "New Estimate Lead",
            "email": "lead@example.test",
            "phone": "217-555-0144",
            "address": "900 Lead Lane, Effingham, IL",
            "source": "website",
            "createdAt": "2026-07-27T12:00:00Z",
        }
    ]
    assert data["pendingHandoffs"][0]["contactId"] == contact_id
    assert data["pendingHandoffs"][0]["status"] == "pending"
    assert data["pendingHandoffs"][0]["lastError"] == "Atlas is temporarily unavailable"
    assert before_counts == after_counts


def test_funnel_review_proxy_keeps_service_token_server_side(monkeypatch, configured_office_conversion):
    api = configured_office_conversion
    captured: dict[str, object] = {}

    class _Response:
        status_code = 200

        def json(self):
            return {"leads": []}

    def get(url, *, headers, params, timeout):
        captured.update({"url": url, "headers": headers, "params": params, "timeout": timeout})
        return _Response()

    monkeypatch.setattr(api.requests, "get", get)
    result = api._atlas_funnel_read(
        "/eom-funnel/leads",
        {"id": 1, "name": "Juan Canfield"},
        params={"limit": 25},
    )

    assert result == {"leads": []}
    assert captured["url"] == "https://atlas.example.test/eom-funnel/leads"
    assert captured["headers"] == {
        "Authorization": "Bearer tracker-only-test-token",
        "X-EOM-Actor": "Juan Canfield",
        "X-EOM-Actor-ID": "1",
        "Accept": "application/json",
    }
    assert captured["params"] == {"limit": 25}


def test_pending_handoff_retry_finalizes_without_duplicate_customer_or_site(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    calls: list[dict[str, object]] = []

    def failing_atlas_request(path, admin, *, payload, idempotency_key):
        raise api.AtlasFunnelRequestError(503, "Atlas is temporarily unavailable")

    def successful_atlas_request(path, admin, *, payload, idempotency_key):
        calls.append({"path": path, "payload": payload, "key": idempotency_key})
        return _atlas_success(payload, idempotency_key)

    monkeypatch.setattr(api, "_atlas_funnel_request", failing_atlas_request)
    pending = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, key),
    )
    monkeypatch.setattr(api, "_atlas_funnel_request", successful_atlas_request)
    retried = client.post(
        f"/api/admin/funnel/handoffs/{contact_id}/retry",
        headers=auth,
    )
    replayed = client.post(
        f"/api/admin/funnel/handoffs/{contact_id}/retry",
        headers=auth,
    )

    assert pending.status_code == 202, pending.text
    assert retried.status_code == 200, retried.text
    assert retried.json()["handoff"]["status"] == "finalized"
    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["idempotent"] is True
    assert len(calls) == 1
    assert calls[0]["key"] == key
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s", (contact_id,)
    )["count"] == 1
    assert db.query_one(
        """
        SELECT COUNT(*) AS count
        FROM locations l JOIN customers c ON c.id = l.customer_id
        WHERE c.atlas_contact_id = %s
        """,
        (contact_id,),
    )["count"] == 1


def test_estimate_approval_requires_configured_employee_before_local_or_remote_side_effect(
    client, auth, monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)

    def unexpected(*args, **kwargs):
        raise AssertionError("Atlas must not be called for a non-approver")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)
    response = client.post(
        "/api/admin/funnel/approve-estimate",
        headers=auth,
        json=_payload(contact_id, key),
    )

    assert response.status_code == 403
    assert db.query_one(
        "SELECT COUNT(*) AS count FROM customers WHERE atlas_contact_id = %s", (contact_id,)
    )["count"] == 0


def test_atlas_funnel_proxy_keeps_service_token_server_side_and_forwards_only_handoff_ids(
    monkeypatch, configured_office_conversion
):
    api = configured_office_conversion
    captured: dict[str, object] = {}

    class _Response:
        status_code = 201

        def json(self):
            return {"success": True}

    def post(url, *, headers, json, timeout):
        captured.update({"url": url, "headers": headers, "json": json, "timeout": timeout})
        return _Response()

    monkeypatch.setattr(api.requests, "post", post)
    result = api._atlas_funnel_request(
        "/eom-funnel/customer-handoffs",
        {"id": 1, "name": "Juan Canfield"},
        payload={
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "tracker_customer_id": 12,
            "tracker_site_id": 24,
        },
        idempotency_key="11111111-1111-1111-1111-111111111111",
    )

    assert result == {"success": True}
    assert captured["url"] == "https://atlas.example.test/eom-funnel/customer-handoffs"
    assert captured["headers"] == {
        "Authorization": "Bearer tracker-only-test-token",
        "X-EOM-Actor": "Juan Canfield",
        "X-EOM-Actor-ID": "1",
        "Idempotency-Key": "11111111-1111-1111-1111-111111111111",
        "Accept": "application/json",
    }
    assert captured["json"] == {
        "contact_id": "11111111-1111-1111-1111-111111111111",
        "tracker_customer_id": 12,
        "tracker_site_id": 24,
    }
