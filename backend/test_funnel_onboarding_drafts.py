"""The Atlas-owned onboarding queue stays inspectable and Juan-gated."""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api


_QUEUE_PATH = "/api/admin/funnel/onboarding-drafts"
_ISSUED_LINKS_PATH = "/api/admin/funnel/public-onboarding/issued-links"


def _approve_path(draft_id: str) -> str:
    return f"{_QUEUE_PATH}/{draft_id}/approve-send"


def _operational_counts() -> dict[str, int]:
    return {
        "customers": int(
            db.query_one("SELECT COUNT(*) AS count FROM customers")["count"]
        ),
        "locations": int(
            db.query_one("SELECT COUNT(*) AS count FROM locations")["count"]
        ),
        "reservations": int(
            db.query_one(
                "SELECT COUNT(*) AS count FROM eom_customer_atlas_reservations"
            )["count"]
        ),
        "working": int(
            db.query_one("SELECT COUNT(*) AS count FROM eom_lead_working")["count"]
        ),
    }


def _pending_draft(
    draft_id: str,
    *,
    contact_id: str | None = None,
    blocker: str | None = None,
) -> dict[str, object]:
    return {
        "draftId": draft_id,
        "contactId": contact_id or str(uuid.uuid4()),
        "fullName": "Pending Customer",
        "recipientEmail": None if blocker else "pending@example.test",
        "blocker": blocker,
        "subject": "Welcome to Effingham Office Maids",
        "body": "We are looking forward to your first cleaning.",
        "status": "pending",
        "createdAt": "2026-08-16T12:00:00Z",
        # These upstream fields are deliberately not part of the browser
        # projection. A pending queue action needs no delivery-history detail.
        "approvedByName": None,
    }


def _pending_page(
    draft_id: str,
    *,
    limit: int = 100,
    cursor: str | None = None,
    has_more: bool = False,
) -> dict[str, object]:
    return {
        "drafts": [_pending_draft(draft_id)],
        "status": "pending",
        "limit": limit,
        "cursor": cursor,
        "hasMore": has_more,
        "nextCursor": "cursor-0123456789" if has_more else None,
    }


def _sent_receipt(draft_id: str, *, idempotent: bool = False) -> dict[str, object]:
    return {
        "success": True,
        "draft_id": draft_id,
        "status": "sent",
        "sent_at": "2026-08-16T12:15:00Z",
        "idempotent": idempotent,
        "recipient_email": "pending@example.test",
        "resend_message_id": "ignored-by-tracker",
    }


def _issued_link(draft_id: str, *, contact_id: str | None = None) -> dict[str, object]:
    return {
        "draftId": draft_id,
        "contactId": contact_id or str(uuid.uuid4()),
        "fullName": "Issued Customer",
        "recipientEmail": "issued@example.test",
        "status": "issued",
        "issuedAt": "2026-08-19T12:00:00Z",
        # The Tracker must not pass this Atlas-private field through even if an
        # older or malformed upstream accidentally includes it.
        "tokenId": str(uuid.uuid4()),
    }


def test_review_relays_pending_queue_deployment_proofs(client, auth, monkeypatch):
    def atlas_leads(*_args, **_kwargs):
        return {
            "leads": [],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": [
                api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_LIST,
                api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_APPROVE_SEND,
                api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_ISSUED_LINK_LIST,
                api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_LINK_REVOKE,
                api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_HANDOFF_RECOVER,
            ],
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_leads)
    available = client.get("/api/admin/funnel/review", headers=auth)

    assert available.status_code == 200, available.text
    assert available.json()["onboardingDraftListAvailable"] is True
    assert available.json()["onboardingDraftApproveSendAvailable"] is True
    assert available.json()["publicOnboardingIssuedLinkListAvailable"] is True
    assert available.json()["publicOnboardingLinkRevokeAvailable"] is True
    assert available.json()["publicOnboardingReservationListAvailable"] is True
    assert available.json()["publicOnboardingRecoveryAvailable"] is True

    def no_manifest(*_args, **_kwargs):
        return {"leads": [], "cursor": None, "hasMore": False, "nextCursor": None}

    monkeypatch.setattr(api, "_atlas_funnel_read", no_manifest)
    unavailable = client.get("/api/admin/funnel/review", headers=auth)

    assert unavailable.status_code == 200, unavailable.text
    assert unavailable.json()["onboardingDraftListAvailable"] is False
    assert unavailable.json()["onboardingDraftApproveSendAvailable"] is False
    assert unavailable.json()["publicOnboardingIssuedLinkListAvailable"] is False
    assert unavailable.json()["publicOnboardingLinkRevokeAvailable"] is False
    assert unavailable.json()["publicOnboardingReservationListAvailable"] is True
    assert unavailable.json()["publicOnboardingRecoveryAvailable"] is False


def test_pending_draft_read_is_normal_admin_and_forwards_only_pending_page_query(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())
    cursor = "cursor-0123456789"
    reads: list[dict[str, object]] = []
    before = _operational_counts()
    # The logged-in fixture is still an authenticated admin, but not the
    # configured approver. A read must remain available to both office admins.
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)

    def atlas_read(path, admin, *, params=None):
        reads.append({"path": path, "admin": admin, "params": params})
        if path == "/eom-funnel/leads":
            return {"capabilities": [api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_LIST]}
        assert path == api._ATLAS_ONBOARDING_DRAFTS_PATH
        assert params == {"status": "pending", "limit": 2, "cursor": cursor}
        return _pending_page(draft_id, limit=2, cursor=cursor)

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    response = client.get(f"{_QUEUE_PATH}?limit=2&cursor={cursor}", headers=auth)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    assert body["status"] == "pending"
    assert body["drafts"] == [
        {
            "draftId": draft_id,
            "contactId": body["drafts"][0]["contactId"],
            "fullName": "Pending Customer",
            "recipientEmail": "pending@example.test",
            "blocker": None,
            "subject": "Welcome to Effingham Office Maids",
            "body": "We are looking forward to your first cleaning.",
            "status": "pending",
            "createdAt": "2026-08-16T12:00:00Z",
        }
    ]
    assert len(reads) == 2
    assert reads[0]["path"] == "/eom-funnel/leads"
    assert reads[0]["params"] == {"limit": 1}
    assert reads[0]["admin"] == {"id": 1, "name": "Juan Canfield", "role": "admin"}
    assert _operational_counts() == before


def test_pending_draft_read_refuses_unadvertised_capability_before_queue_read(
    client, auth, monkeypatch
):
    reads: list[str] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_LIST
        )

    def unexpected_read(path, *_args, **_kwargs):
        reads.append(path)
        raise AssertionError("the queue must not be read after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_read", unexpected_read)
    response = client.get(_QUEUE_PATH, headers=auth)

    assert response.status_code == 501, response.text
    assert (
        response.json()["capability"]
        == api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_LIST
    )
    assert reads == []


def test_pending_draft_read_rejects_malformed_atlas_projection(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())

    def malformed_page(path, *_args, **_kwargs):
        if path == "/eom-funnel/leads":
            return {"capabilities": [api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_LIST]}
        broken = _pending_page(draft_id)
        broken["drafts"] = [{"draftId": draft_id, "status": "pending"}]
        return broken

    monkeypatch.setattr(api, "_atlas_funnel_read", malformed_page)
    response = client.get(_QUEUE_PATH, headers=auth)

    assert response.status_code == 502, response.text
    assert "invalid response" in response.json()["error"]


def test_issued_link_read_is_normal_admin_and_reprojects_only_safe_fields(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())
    link = _issued_link(draft_id)
    reads: list[dict[str, object]] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)

    def atlas_read(path, admin, *, params=None):
        reads.append({"path": path, "admin": admin, "params": params})
        if path == "/eom-funnel/leads":
            return {
                "leads": [],
                "cursor": None,
                "hasMore": False,
                "nextCursor": None,
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_ISSUED_LINK_LIST
                ],
            }
        assert path == api._ATLAS_PUBLIC_ONBOARDING_ISSUED_LINKS_PATH
        assert params == {"limit": 2}
        return {"links": [link], "limit": 2}

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)
    response = client.get(f"{_ISSUED_LINKS_PATH}?limit=2", headers=auth)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "success": True,
        "links": [
            {
                "draftId": draft_id,
                "contactId": link["contactId"],
                "fullName": "Issued Customer",
                "recipientEmail": "issued@example.test",
                "status": "issued",
                "issuedAt": "2026-08-19T12:00:00Z",
            }
        ],
        "limit": 2,
    }
    assert str(link["tokenId"]) not in response.text
    assert reads[0]["path"] == "/eom-funnel/leads"
    assert reads[0]["params"] == {"limit": 1}


def test_issued_link_read_refuses_unadvertised_capability_before_upstream_read(
    client, auth, monkeypatch
):
    reads: list[str] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_ISSUED_LINK_LIST
        )

    def unexpected_read(path, *_args, **_kwargs):
        reads.append(path)
        raise AssertionError("issued links must not be read after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_read", unexpected_read)
    response = client.get(_ISSUED_LINKS_PATH, headers=auth)

    assert response.status_code == 501, response.text
    assert (
        response.json()["capability"]
        == api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_ISSUED_LINK_LIST
    )
    assert reads == []


def test_issued_link_read_rejects_malformed_atlas_projection(client, auth, monkeypatch):
    def malformed_page(path, *_args, **_kwargs):
        if path == "/eom-funnel/leads":
            return {
                "leads": [],
                "cursor": None,
                "hasMore": False,
                "nextCursor": None,
                "capabilities": [
                    api.ATLAS_FUNNEL_CAPABILITY_PUBLIC_ONBOARDING_ISSUED_LINK_LIST
                ],
            }
        return {"links": [{"status": "issued"}], "limit": 100}

    monkeypatch.setattr(api, "_atlas_funnel_read", malformed_page)
    response = client.get(_ISSUED_LINKS_PATH, headers=auth)

    assert response.status_code == 502, response.text
    assert "invalid issued-link response" in response.json()["error"]


def test_onboarding_approve_send_forwards_juan_and_never_writes_operational_rows(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())
    calls: list[dict[str, object]] = []
    before = _operational_counts()
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def atlas_request(path, admin, *, payload, idempotency_key):
        calls.append(
            {
                "path": path,
                "admin": admin,
                "payload": payload,
                "idempotencyKey": idempotency_key,
            }
        )
        return _sent_receipt(draft_id)

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(_approve_path(draft_id), headers=auth)

    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "draftId": draft_id,
        "status": "sent",
        "sentAt": "2026-08-16T12:15:00+00:00",
        "idempotent": False,
    }
    assert calls == [
        {
            "path": f"/eom-funnel/onboarding-drafts/{draft_id}/approve-send",
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "payload": {},
            "idempotencyKey": f"eom-onboarding-draft:{draft_id}",
        }
    ]
    assert _operational_counts() == before


def test_onboarding_approve_send_refuses_non_juan_before_any_upstream_post(
    client, auth, monkeypatch
):
    calls: list[object] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 999)

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("non-approver must not reach Atlas")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)
    response = client.post(_approve_path(str(uuid.uuid4())), headers=auth)

    assert response.status_code == 403, response.text
    assert calls == []


def test_onboarding_approve_send_refuses_unadvertised_capability_before_post(
    client, auth, monkeypatch
):
    calls: list[object] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_APPROVE_SEND
        )

    def unexpected(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)
    response = client.post(_approve_path(str(uuid.uuid4())), headers=auth)

    assert response.status_code == 501, response.text
    assert (
        response.json()["capability"]
        == api.ATLAS_FUNNEL_CAPABILITY_ONBOARDING_DRAFT_APPROVE_SEND
    )
    assert calls == []


def test_onboarding_approve_send_rejects_malformed_or_mismatched_sent_receipts(
    client, auth, monkeypatch
):
    requested_draft_id = str(uuid.uuid4())
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def malformed(*_args, **_kwargs):
        return {
            "success": True,
            "draft_id": requested_draft_id,
            "status": "sent",
            "sent_at": None,
            "idempotent": False,
        }

    monkeypatch.setattr(api, "_atlas_funnel_request", malformed)
    malformed_response = client.post(_approve_path(requested_draft_id), headers=auth)

    def mismatched(*_args, **_kwargs):
        return _sent_receipt(str(uuid.uuid4()))

    monkeypatch.setattr(api, "_atlas_funnel_request", mismatched)
    mismatch_response = client.post(_approve_path(requested_draft_id), headers=auth)

    assert malformed_response.status_code == 502, malformed_response.text
    assert "invalid sent receipt" in malformed_response.json()["error"]
    assert mismatch_response.status_code == 502, mismatch_response.text
    assert "mismatched sent receipt" in mismatch_response.json()["error"]


def test_onboarding_approve_send_returns_replayed_sent_receipt(
    client, auth, monkeypatch
):
    draft_id = str(uuid.uuid4())
    keys: list[str] = []
    monkeypatch.setattr(api, "EOM_FUNNEL_APPROVER_EMPLOYEE_ID", 1)

    def replayed(_path, _admin, *, payload, idempotency_key):
        assert payload == {}
        keys.append(idempotency_key)
        return _sent_receipt(draft_id, idempotent=len(keys) == 2)

    monkeypatch.setattr(api, "_atlas_funnel_request", replayed)
    first = client.post(_approve_path(draft_id), headers=auth)
    replay = client.post(_approve_path(draft_id), headers=auth)

    assert first.status_code == 201, first.text
    assert replay.status_code == 200, replay.text
    assert first.json()["idempotent"] is False
    assert replay.json()["idempotent"] is True
    assert keys == [f"eom-onboarding-draft:{draft_id}"] * 2
