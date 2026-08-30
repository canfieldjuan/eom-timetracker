"""Tracker exposes the Atlas-owned post-clean queue without copying its state."""

from __future__ import annotations

import uuid

import time_tracker_api as api


_QUEUE_PATH = "/api/admin/funnel/post-clean-onboarding-candidates"


def _candidate(
    *,
    candidate_id: str | None = None,
    completion_receipt_id: str | None = None,
    blocker: str | None = None,
    tracker_service_kind: str = "planned_visit",
    tracker_service_id: int = 42,
) -> dict[str, object]:
    return {
        "candidateId": candidate_id or str(uuid.uuid4()),
        "completionReceiptId": completion_receipt_id or str(uuid.uuid4()),
        "contactId": str(uuid.uuid4()),
        "handoffId": str(uuid.uuid4()),
        "status": "pending",
        "fullName": "Test Customer",
        "recipientEmail": None if blocker == "no_email" else "candidate@example.test",
        "blocker": blocker,
        "trackerServiceKind": tracker_service_kind,
        "trackerServiceId": tracker_service_id,
        "completedAt": "2026-08-24T17:00:00Z",
        "createdAt": "2026-08-24T17:00:01Z",
        "atlasPrivateEvidence": {"must": "not relay"},
    }


def _page(
    candidates: list[dict[str, object]] | None = None,
    *,
    limit: int = 100,
    cursor: str | None = None,
    has_more: bool = False,
    next_cursor: str | None = None,
) -> dict[str, object]:
    return {
        "candidates": candidates if candidates is not None else [_candidate()],
        "limit": limit,
        "cursor": cursor,
        "hasMore": has_more,
        "nextCursor": next_cursor,
    }


def _manifest(
    *,
    include_name: bool = True,
    route: tuple[str, str] | None = api._ATLAS_POST_CLEAN_ONBOARDING_CANDIDATES_ROUTE,
    malformed_name_member: bool = False,
) -> dict[str, object]:
    capabilities: list[object] = []
    if include_name:
        capabilities.append(
            api.ATLAS_FUNNEL_CAPABILITY_POST_CLEAN_ONBOARDING_CANDIDATE_LIST
        )
    if malformed_name_member:
        capabilities.append({"not": "a capability name"})
    routes = []
    if route is not None:
        routes.append({"method": route[0], "path": route[1]})
    return {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
        "capabilities": capabilities,
        "capabilityRoutes": routes,
    }


def _install_atlas(
    monkeypatch,
    page: dict[str, object],
    *,
    manifest: dict[str, object] | None = None,
    calls: list[dict[str, object]] | None = None,
) -> None:
    manifest = manifest or _manifest()

    def atlas_read(path, admin, *, params=None):
        if calls is not None:
            calls.append({"path": path, "admin": admin, "params": params})
        if path == "/eom-funnel/leads":
            return manifest
        assert path == api._ATLAS_POST_CLEAN_ONBOARDING_CANDIDATES_PATH
        return page

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)


def test_candidate_read_forwards_only_bounded_pagination_and_reprojects_safe_fields(
    client, auth, monkeypatch
):
    cursor = "cursor-0123456789"
    next_cursor = "cursor-9876543210"
    item = _candidate(blocker="no_email")
    calls: list[dict[str, object]] = []
    audit_events: list[tuple[object, ...]] = []
    _install_atlas(
        monkeypatch,
        _page(
            [item],
            limit=2,
            cursor=cursor,
            has_more=True,
            next_cursor=next_cursor,
        ),
        calls=calls,
    )
    monkeypatch.setattr(
        api,
        "append_access_log",
        lambda *args, **_kwargs: audit_events.append(args),
    )

    response = client.get(f"{_QUEUE_PATH}?limit=2&cursor={cursor}", headers=auth)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "success": True,
        "candidates": [
            {
                "candidateId": item["candidateId"],
                "completionReceiptId": item["completionReceiptId"],
                "contactId": item["contactId"],
                "handoffId": item["handoffId"],
                "status": "pending",
                "fullName": "Test Customer",
                "recipientEmail": None,
                "blocker": "no_email",
                "trackerServiceKind": "planned_visit",
                "trackerServiceId": 42,
                "completedAt": "2026-08-24T17:00:00Z",
                "createdAt": "2026-08-24T17:00:01Z",
                "serviceCommitment": None,
                "serviceCommitmentDecidedBy": None,
                "serviceCommitmentDecidedAt": None,
            }
        ],
        "limit": 2,
        "cursor": cursor,
        "hasMore": True,
        "nextCursor": next_cursor,
    }
    assert "atlasPrivateEvidence" not in response.text
    assert calls == [
        {
            "path": "/eom-funnel/leads",
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "params": {"limit": 1},
        },
        {
            "path": api._ATLAS_POST_CLEAN_ONBOARDING_CANDIDATES_PATH,
            "admin": {"id": 1, "name": "Juan Canfield", "role": "admin"},
            "params": {"limit": 2, "cursor": cursor},
        },
    ]
    assert "candidate@example.test" not in repr(audit_events)


def test_candidate_read_projects_one_coherent_service_commitment(
    client, auth, monkeypatch
):
    item = {
        **_candidate(),
        "serviceCommitment": "one_time",
        "serviceCommitmentDecidedBy": "  Juan Canfield  ",
        "serviceCommitmentDecidedAt": "2026-08-30T20:00:00Z",
    }
    _install_atlas(monkeypatch, _page([item]))

    response = client.get(_QUEUE_PATH, headers=auth)

    assert response.status_code == 200, response.text
    candidate = response.json()["candidates"][0]
    assert candidate["serviceCommitment"] == "one_time"
    assert candidate["serviceCommitmentDecidedBy"] == "Juan Canfield"
    assert candidate["serviceCommitmentDecidedAt"] == "2026-08-30T20:00:00Z"


def test_candidate_queue_requires_admin_authentication(client, monkeypatch):
    _install_atlas(monkeypatch, _page())
    response = client.get(_QUEUE_PATH)
    assert response.status_code in (401, 403), response.text


def test_unknown_atlas_classifications_are_preserved_as_opaque_codes(
    client, auth, monkeypatch
):
    _install_atlas(
        monkeypatch,
        _page(
            [
                _candidate(
                    blocker="future_customer_policy",
                    tracker_service_kind="future_service_source",
                )
            ]
        ),
    )

    response = client.get(_QUEUE_PATH, headers=auth)

    assert response.status_code == 200, response.text
    assert response.json()["candidates"][0]["blocker"] == "future_customer_policy"
    assert (
        response.json()["candidates"][0]["trackerServiceKind"]
        == "future_service_source"
    )


def test_candidate_page_accepts_tracker_service_id_boundaries(
    client, auth, monkeypatch
):
    maximum_bigint = 9_223_372_036_854_775_807
    _install_atlas(
        monkeypatch,
        _page(
            [
                _candidate(tracker_service_id=1),
                _candidate(tracker_service_id=maximum_bigint),
            ]
        ),
    )

    response = client.get(_QUEUE_PATH, headers=auth)

    assert response.status_code == 200, response.text
    assert [item["trackerServiceId"] for item in response.json()["candidates"]] == [
        1,
        maximum_bigint,
    ]


def test_review_badge_and_endpoint_share_the_strict_catalog_predicate(
    client, auth, monkeypatch
):
    cases = [
        (_manifest(), True),
        (_manifest(include_name=False), False),
        (_manifest(route=None), False),
        (
            _manifest(route=("POST", api._ATLAS_POST_CLEAN_ONBOARDING_CANDIDATES_PATH)),
            False,
        ),
        (_manifest(malformed_name_member=True), False),
    ]
    for manifest, expected in cases:
        calls: list[dict[str, object]] = []
        _install_atlas(monkeypatch, _page(), manifest=manifest, calls=calls)

        review = client.get("/api/admin/funnel/review", headers=auth)
        queue = client.get(_QUEUE_PATH, headers=auth)

        assert review.status_code == 200, review.text
        assert review.json()["postCleanOnboardingCandidateListAvailable"] is expected, (
            manifest
        )
        assert queue.status_code == (200 if expected else 501), queue.text
        queue_reads = [
            call
            for call in calls
            if call["path"] == api._ATLAS_POST_CLEAN_ONBOARDING_CANDIDATES_PATH
        ]
        assert len(queue_reads) == (1 if expected else 0)


def test_candidate_query_bounds_are_rejected_before_atlas(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _page(), calls=calls)

    for query in ("limit=0", "limit=201", "cursor=short", f"cursor={'x' * 513}"):
        response = client.get(f"{_QUEUE_PATH}?{query}", headers=auth)
        assert response.status_code == 422, (query, response.text)
    assert calls == []


def test_candidate_page_rejects_malformed_or_incoherent_upstream_state(
    client, auth, monkeypatch
):
    candidate_id = str(uuid.uuid4())
    receipt_id = str(uuid.uuid4())
    invalid_pages = [
        _page(limit=99),
        _page(has_more=True, next_cursor=None),
        _page(has_more=False, next_cursor="cursor-0123456789"),
        _page(
            cursor="cursor-0123456789",
            has_more=True,
            next_cursor="cursor-0123456789",
        ),
        _page([_candidate(), _candidate()], limit=1),
        _page(
            [
                _candidate(candidate_id=candidate_id),
                _candidate(candidate_id=candidate_id),
            ]
        ),
        _page(
            [
                _candidate(completion_receipt_id=receipt_id),
                _candidate(completion_receipt_id=receipt_id),
            ]
        ),
        _page([{**_candidate(), "status": "sent"}]),
        _page([{**_candidate(), "blocker": "   "}]),
        _page([{**_candidate(), "blocker": {"not": "a code"}}]),
        _page([{**_candidate(), "trackerServiceKind": "   "}]),
        _page([{**_candidate(), "trackerServiceKind": ["planned_visit"]}]),
        _page([{**_candidate(), "trackerServiceId": True}]),
        _page([{**_candidate(), "trackerServiceId": 0}]),
        _page([{**_candidate(), "trackerServiceId": -1}]),
        _page(
            [
                {
                    **_candidate(),
                    "trackerServiceId": 9_223_372_036_854_775_808,
                }
            ]
        ),
        _page([{**_candidate(), "completedAt": "2026-08-24T17:00:00"}]),
        _page([{**_candidate(), "serviceCommitment": "recurring"}]),
        _page(
            [
                {
                    **_candidate(),
                    "serviceCommitment": "recurring",
                    "serviceCommitmentDecidedBy": "Juan Canfield",
                }
            ]
        ),
        _page(
            [
                {
                    **_candidate(),
                    "serviceCommitment": "future_value",
                    "serviceCommitmentDecidedBy": "Juan Canfield",
                    "serviceCommitmentDecidedAt": "2026-08-30T20:00:00Z",
                }
            ]
        ),
        _page(
            [
                {
                    **_candidate(),
                    "serviceCommitment": "one_time",
                    "serviceCommitmentDecidedBy": "   ",
                    "serviceCommitmentDecidedAt": "2026-08-30T20:00:00Z",
                }
            ]
        ),
        _page(
            [
                {
                    **_candidate(),
                    "serviceCommitment": "one_time",
                    "serviceCommitmentDecidedBy": "Juan Canfield",
                    "serviceCommitmentDecidedAt": "2026-08-30T20:00:00",
                }
            ]
        ),
    ]
    for page in invalid_pages:
        _install_atlas(monkeypatch, page)
        response = client.get(_QUEUE_PATH, headers=auth)
        assert response.status_code == 502, (page, response.text)
        assert "invalid response" in response.json()["error"]
