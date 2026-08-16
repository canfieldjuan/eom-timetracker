"""Atlas-backed lead booking stays narrow, retry-safe, and local-row free."""

from __future__ import annotations

import uuid

import db
import pytest
import time_tracker_api as api


def _estimate_path(contact_id: str) -> str:
    return f"/api/admin/funnel/leads/{contact_id}/estimate-bookings"


def _first_clean_path(contact_id: str) -> str:
    return f"/api/admin/funnel/leads/{contact_id}/first-clean-bookings"


def _payload(
    key: str, *, start: str = "2026-08-17T09:00:00Z", end: str = "2026-08-17T10:30:00Z"
) -> dict[str, object]:
    return {
        "scheduledStart": start,
        "scheduledEnd": end,
        "idempotencyKey": key,
    }


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


def _atlas_booking_result(
    contact_id: str,
    *,
    first_clean: bool = False,
    idempotent: bool = False,
    onboarding_draft_id: str | None = None,
) -> dict[str, object]:
    event_id = f"event-{uuid.uuid4()}"
    result: dict[str, object] = {
        "success": True,
        "contact_id": contact_id,
        "lead_stage": "won" if first_clean else "estimate_booked",
        "status": "first_clean_booked" if first_clean else "estimate_booked",
        "calendar_event_id": event_id,
        "expected_calendar_event_id": event_id,
        "idempotent": idempotent,
    }
    if first_clean:
        result["onboarding_draft_id"] = onboarding_draft_id or str(uuid.uuid4())
    return result


def test_review_relays_known_atlas_stage_and_booking_proxy_proofs(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())

    def deployed_booking_capabilities(*_args, **_kwargs):
        return {
            "leads": [
                {
                    "contactId": contact_id,
                    "fullName": "Atlas Stage Lead",
                    "createdAt": "2026-08-16T12:00:00Z",
                    "leadStage": "estimate_booked",
                }
            ],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
            "capabilities": [
                api.ATLAS_FUNNEL_CAPABILITY_LEAD_ESTIMATE_BOOKING,
                api.ATLAS_FUNNEL_CAPABILITY_LEAD_FIRST_CLEAN_BOOKING,
            ],
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", deployed_booking_capabilities)
    available = client.get("/api/admin/funnel/review", headers=auth)

    assert available.status_code == 200, available.text
    assert available.json()["leads"][0]["leadStage"] == "estimate_booked"
    assert available.json()["estimateBookingAvailable"] is True
    assert available.json()["firstCleanBookingAvailable"] is True

    def unknown_stage_without_manifest(*_args, **_kwargs):
        return {
            "leads": [
                {
                    "contactId": contact_id,
                    "fullName": "Unknown Stage Lead",
                    "createdAt": "2026-08-16T12:00:00Z",
                    "leadStage": "future_stage",
                }
            ],
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", unknown_stage_without_manifest)
    unavailable = client.get("/api/admin/funnel/review", headers=auth)

    assert unavailable.status_code == 200, unavailable.text
    assert "leadStage" not in unavailable.json()["leads"][0]
    assert unavailable.json()["estimateBookingAvailable"] is False
    assert unavailable.json()["firstCleanBookingAvailable"] is False


def test_estimate_booking_forwards_only_the_window_and_never_writes_local_rows(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
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
        return _atlas_booking_result(contact_id)

    def unexpected_juan_guard(*_args, **_kwargs):
        raise AssertionError("booking must use normal admin authorization")

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    monkeypatch.setattr(api, "_require_juan_funnel_approver", unexpected_juan_guard)
    response = client.post(_estimate_path(contact_id), headers=auth, json=_payload(key))

    assert response.status_code == 201, response.text
    assert response.json() == {
        "success": True,
        "contactId": contact_id,
        "leadStage": "estimate_booked",
        "status": "estimate_booked",
        "idempotent": False,
    }
    assert calls == [
        {
            "path": f"/eom-funnel/leads/{contact_id}/estimate-bookings",
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "payload": {
                "scheduled_start": "2026-08-17T09:00:00Z",
                "scheduled_end": "2026-08-17T10:30:00Z",
            },
            "idempotencyKey": key,
        }
    ]
    assert _operational_counts() == before


def test_first_clean_booking_reports_the_queued_draft_and_replays_the_same_key(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    key = str(uuid.uuid4())
    draft_id = str(uuid.uuid4())
    seen_keys: list[str] = []

    def atlas_request(_path, _admin, *, payload, idempotency_key):
        assert payload == {
            "scheduled_start": "2026-08-17T09:00:00Z",
            "scheduled_end": "2026-08-17T10:30:00Z",
        }
        seen_keys.append(idempotency_key)
        return _atlas_booking_result(
            contact_id,
            first_clean=True,
            idempotent=len(seen_keys) == 2,
            onboarding_draft_id=draft_id,
        )

    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    first = client.post(_first_clean_path(contact_id), headers=auth, json=_payload(key))
    replay = client.post(
        _first_clean_path(contact_id), headers=auth, json=_payload(key)
    )

    assert first.status_code == 201, first.text
    assert replay.status_code == 200, replay.text
    assert first.json() == {
        "success": True,
        "contactId": contact_id,
        "leadStage": "won",
        "status": "first_clean_booked",
        "idempotent": False,
        "onboardingDraftId": draft_id,
    }
    assert replay.json()["idempotent"] is True
    assert replay.json()["onboardingDraftId"] == draft_id
    assert seen_keys == [key, key]


def test_booking_refuses_an_unadvertised_capability_before_the_upstream_write(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())
    calls: list[object] = []

    def unavailable(*_args, **_kwargs):
        raise api.AtlasFunnelCapabilityUnavailable(
            api.ATLAS_FUNNEL_CAPABILITY_LEAD_ESTIMATE_BOOKING
        )

    def atlas_request(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Atlas must not be called after capability refusal")

    monkeypatch.setattr(api, "_require_atlas_funnel_capability", unavailable)
    monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
    response = client.post(
        _estimate_path(contact_id), headers=auth, json=_payload(str(uuid.uuid4()))
    )

    assert response.status_code == 501, response.text
    assert (
        response.json()["capability"]
        == api.ATLAS_FUNNEL_CAPABILITY_LEAD_ESTIMATE_BOOKING
    )
    assert calls == []


@pytest.mark.parametrize(
    "body",
    (
        {
            "scheduledStart": "2026-08-17T09:00:00",
            "scheduledEnd": "2026-08-17T10:30:00Z",
            "idempotencyKey": str(uuid.uuid4()),
        },
        {
            "scheduledStart": "2026-08-17T10:30:00Z",
            "scheduledEnd": "2026-08-17T09:00:00Z",
            "idempotencyKey": str(uuid.uuid4()),
        },
        {
            **_payload(str(uuid.uuid4())),
            "calendarId": "arbitrary-calendar-id",
        },
    ),
)
def test_booking_rejects_invalid_or_unbounded_input_before_the_upstream_write(
    client, auth, monkeypatch, body
):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("Atlas must not receive an invalid booking request")

    monkeypatch.setattr(api, "_atlas_funnel_request", unexpected)
    response = client.post(_estimate_path(str(uuid.uuid4())), headers=auth, json=body)

    assert response.status_code == 422, response.text


def test_first_clean_rejects_a_malformed_upstream_draft_receipt(
    client, auth, monkeypatch
):
    contact_id = str(uuid.uuid4())

    def malformed(_path, _admin, *, payload, idempotency_key):
        result = _atlas_booking_result(contact_id, first_clean=True)
        result["onboarding_draft_id"] = "not-a-uuid"
        return result

    monkeypatch.setattr(api, "_atlas_funnel_request", malformed)
    response = client.post(
        _first_clean_path(contact_id), headers=auth, json=_payload(str(uuid.uuid4()))
    )

    assert response.status_code == 502, response.text
    assert "invalid onboarding draft id" in response.json()["error"]
