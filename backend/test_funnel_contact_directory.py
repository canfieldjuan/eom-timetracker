"""The contact-directory proxy is Atlas-backed, bounded, and local-row free.

Website #240: the directory read is how a portal-created Atlas customer stays
discoverable. These tests hold the proxy to the same standards as the contact
creation proxy beside it: exact bounded forwarding, a fail-closed deployment
proof derived from BOTH the capability name and the registered method/path,
complete envelope/item validation before anything reaches a browser, and zero
tracker operational rows touched.
"""

from __future__ import annotations

import uuid

import db
import time_tracker_api as api


def _path() -> str:
    return "/api/admin/funnel/contact-directory"


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
    with_editability_name: bool = False,
    with_route: bool = True,
    declared: bool = True,
    routes_malformed: bool = False,
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
            capabilities.append(api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY)
        if with_editability_name:
            capabilities.append(
                api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY_EDITABILITY
            )
        if capabilities_malformed:
            capabilities.append(1)
        content["capabilities"] = capabilities
        routes: list[object] = [{"method": "POST", "path": "/eom-funnel/operator-contacts"}]
        if with_route:
            routes.append({"method": "GET", "path": "/eom-funnel/contact-directory"})
        if routes_malformed:
            routes.append("not-a-route-object")
        content["capabilityRoutes"] = routes
    return content


def _directory_item(
    contact_id: str | None = None,
    *,
    contact_type: str = "customer",
    customer_type: str = "unknown",
    status: str = "active",
    lead_stage: str | None = None,
) -> dict[str, object]:
    return {
        "contactId": contact_id or str(uuid.uuid4()),
        "fullName": "Directory Person",
        "email": "directory@example.test",
        "phone": "2175550100",
        "address": "1 Directory Way",
        "contactType": contact_type,
        "customerType": customer_type,
        "leadStage": lead_stage,
        "status": status,
        "source": "manual",
        "createdAt": "2026-08-20T12:00:00+00:00",
        "updatedAt": "2026-08-20T12:00:00+00:00",
    }


def _directory_content(
    items: list[dict[str, object]] | None = None,
    *,
    limit: int = 100,
    cursor: str | None = None,
    has_more: bool = False,
    next_cursor: str | None = None,
) -> dict[str, object]:
    return {
        "contacts": items if items is not None else [_directory_item()],
        "limit": limit,
        "cursor": cursor,
        "hasMore": has_more,
        "nextCursor": next_cursor,
    }


def _install_atlas(monkeypatch, directory_content, manifest_content=None, calls=None):
    """One fake `_atlas_funnel_read` serving the manifest and directory paths."""

    manifest = manifest_content if manifest_content is not None else _manifest_content()

    def atlas_read(path, admin, *, params=None):
        if calls is not None:
            calls.append({"path": path, "admin": dict(admin), "params": dict(params or {})})
        if path == "/eom-funnel/leads":
            return manifest
        assert path == api._ATLAS_CONTACT_DIRECTORY_PATH, path
        return directory_content

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)


# ---------------------------------------------------------------------------
# The deployment proof on the review read
# ---------------------------------------------------------------------------


def test_review_proves_the_directory_only_with_both_name_and_route(
    client, auth, monkeypatch
):
    """The proof requires the capability name AND the registered GET signature;
    any weaker evidence -- name only, route only, pre-manifest, malformed --
    must read false."""
    shapes = [
        (_manifest_content(with_name=True, with_route=True), True),
        (_manifest_content(with_name=True, with_route=False), False),
        (_manifest_content(with_name=False, with_route=True), False),
        (_manifest_content(declared=False), False),
        (_manifest_content(with_name=True, with_route=True, routes_malformed=True), False),
        # One junk member in the capability list poisons the whole proof, even
        # though the member the proof needs is present and well-formed.
        (
            _manifest_content(with_name=True, with_route=True, capabilities_malformed=True),
            False,
        ),
    ]
    for manifest, expected in shapes:
        monkeypatch.setattr(
            api, "_atlas_funnel_read", lambda *_a, _m=manifest, **_k: _m
        )
        response = client.get("/api/admin/funnel/review", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["contactDirectoryAvailable"] is expected, manifest


def test_review_proves_directory_editability_only_with_the_versioned_name_and_route(
    client, auth, monkeypatch
):
    """The row verdict needs Atlas's semantic capability, not GET reachability."""
    shapes = [
        (
            _manifest_content(with_name=True, with_editability_name=True, with_route=True),
            True,
        ),
        (_manifest_content(with_name=True, with_editability_name=False), False),
        (_manifest_content(with_name=False, with_editability_name=True), False),
        (
            _manifest_content(
                with_name=True, with_editability_name=True, with_route=False
            ),
            False,
        ),
        (_manifest_content(declared=False), False),
        (
            _manifest_content(
                with_name=True,
                with_editability_name=True,
                capabilities_malformed=True,
            ),
            False,
        ),
    ]
    for manifest, expected in shapes:
        monkeypatch.setattr(
            api, "_atlas_funnel_read", lambda *_a, _m=manifest, **_k: _m
        )
        response = client.get("/api/admin/funnel/review", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["contactDirectoryEditabilityAvailable"] is expected, manifest


# ---------------------------------------------------------------------------
# Bounded forwarding, closed projection, and the no-local-rows guarantee
# ---------------------------------------------------------------------------


def test_directory_forwards_exact_bounded_inputs_and_creates_no_rows(
    client, auth, monkeypatch
):
    before = _operational_counts()
    calls: list[dict[str, object]] = []
    cursor = "b2Zmc2V0LWN1cnNvci1leGFtcGxl"
    _install_atlas(
        monkeypatch,
        _directory_content(limit=25, cursor=cursor),
        calls=calls,
    )

    response = client.get(
        f"{_path()}?limit=25&kind=customer&search=%20Ada%20&cursor={cursor}",
        headers=auth,
    )

    assert response.status_code == 200, response.text
    directory_calls = [
        call for call in calls if call["path"] == api._ATLAS_CONTACT_DIRECTORY_PATH
    ]
    assert len(directory_calls) == 1
    assert directory_calls[0]["params"] == {
        "limit": 25,
        "kind": "customer",
        "search": "Ada",
        "cursor": cursor,
    }
    assert directory_calls[0]["admin"]["name"], "actor identity must be forwarded"
    body = response.json()
    assert set(body) == {"success", "contacts", "limit", "cursor", "hasMore", "nextCursor"}
    assert set(body["contacts"][0]) == {
        "contactId",
        "fullName",
        "email",
        "phone",
        "address",
        "contactType",
        "customerType",
        "leadStage",
        "status",
        "source",
        "createdAt",
        "updatedAt",
    }
    assert _operational_counts() == before, "a directory read must write nothing"


def test_directory_projects_a_coherent_editability_verdict_without_local_policy(
    client, auth, monkeypatch
):
    editable_id = str(uuid.uuid4())
    blocked_id = str(uuid.uuid4())
    _install_atlas(
        monkeypatch,
        _directory_content(
            [
                {
                    **_directory_item(editable_id),
                    "editable": True,
                    "editBlockedReason": None,
                },
                {
                    **_directory_item(blocked_id, contact_type="lead", lead_stage="lost"),
                    "editable": False,
                    # Intentionally not one of the current Atlas names: the
                    # tracker does not duplicate the upstream reason-code set.
                    "editBlockedReason": "future_not_editable_reason",
                },
            ]
        ),
    )

    response = client.get(_path(), headers=auth)

    assert response.status_code == 200, response.text
    contacts = response.json()["contacts"]
    assert contacts[0]["editable"] is True
    assert contacts[0]["editBlockedReason"] is None
    assert contacts[1]["editable"] is False
    assert contacts[1]["editBlockedReason"] == "future_not_editable_reason"


def test_directory_rejects_incoherent_editability_pairs(client, auth, monkeypatch):
    item_pages = [
        [{**_directory_item(), "editable": True}],
        [{**_directory_item(), "editBlockedReason": "not_editable_stage"}],
        [{**_directory_item(), "editable": 1, "editBlockedReason": None}],
        [{**_directory_item(), "editable": False, "editBlockedReason": None}],
        [{**_directory_item(), "editable": True, "editBlockedReason": "not_editable_stage"}],
        [{**_directory_item(), "editable": False, "editBlockedReason": "   "}],
        [{**_directory_item(), "editable": False, "editBlockedReason": ["bad"]}],
    ]
    for items in item_pages:
        _install_atlas(monkeypatch, _directory_content(items))
        response = client.get(_path(), headers=auth)
        assert response.status_code == 502, response.text


def test_the_service_credential_never_reaches_the_browser(client, auth, monkeypatch):
    _install_atlas(monkeypatch, _directory_content())
    response = client.get(_path(), headers=auth)
    assert response.status_code == 200, response.text
    assert api.ATLAS_FUNNEL_SERVICE_TOKEN
    assert api.ATLAS_FUNNEL_SERVICE_TOKEN not in response.text


def test_omitted_optional_filters_are_not_forwarded(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _directory_content(), calls=calls)
    response = client.get(_path(), headers=auth)
    assert response.status_code == 200, response.text
    directory_calls = [
        call for call in calls if call["path"] == api._ATLAS_CONTACT_DIRECTORY_PATH
    ]
    assert directory_calls[0]["params"] == {"limit": 100, "kind": "all"}


# ---------------------------------------------------------------------------
# Browser-input closure
# ---------------------------------------------------------------------------


def test_an_unknown_kind_is_rejected_before_any_atlas_call(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _directory_content(), calls=calls)
    response = client.get(f"{_path()}?kind=prospect", headers=auth)
    assert response.status_code == 422, response.text
    assert calls == [], "a refused kind must never reach Atlas"


def test_a_blank_search_is_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _directory_content(), calls=calls)
    response = client.get(f"{_path()}?search=%20%20", headers=auth)
    assert response.status_code == 422, response.text
    assert calls == []


def test_a_short_cursor_is_rejected(client, auth, monkeypatch):
    calls: list[dict[str, object]] = []
    _install_atlas(monkeypatch, _directory_content(), calls=calls)
    response = client.get(f"{_path()}?cursor=abc", headers=auth)
    assert response.status_code == 422, response.text
    assert calls == []


def test_the_directory_requires_admin_authentication(client, monkeypatch):
    _install_atlas(monkeypatch, _directory_content())
    response = client.get(_path())
    assert response.status_code in (401, 403), response.text


# ---------------------------------------------------------------------------
# Deployment-skew behavior at request time
# ---------------------------------------------------------------------------


def test_a_directory_request_against_an_older_atlas_maps_to_typed_501(
    client, auth, monkeypatch
):
    calls: list[dict[str, object]] = []
    _install_atlas(
        monkeypatch,
        _directory_content(),
        manifest_content=_manifest_content(with_name=True, with_route=False),
        calls=calls,
    )
    response = client.get(_path(), headers=auth)
    assert response.status_code == 501, response.text
    assert response.json()["error"] == "atlas_capability_unavailable"
    assert all(
        call["path"] != api._ATLAS_CONTACT_DIRECTORY_PATH for call in calls
    ), "the directory read must not run without the route proof"


# ---------------------------------------------------------------------------
# Upstream validation: a malformed Atlas answer never reaches the browser
# ---------------------------------------------------------------------------


def test_a_malformed_atlas_envelope_is_rejected(client, auth, monkeypatch):
    envelopes = [
        {"contacts": "not-a-list", "limit": 100, "cursor": None, "hasMore": False, "nextCursor": None},
        _directory_content(limit=50),  # limit echo mismatch (request default 100)
        _directory_content(cursor="unexpected-cursor-echo-value"),
        _directory_content(has_more=True, next_cursor=None),
        # An in-flight continuation cursor outside this route's own 16..512
        # bounds would 422 the very next page request it hands out.
        _directory_content(has_more=True, next_cursor="abc"),
        _directory_content(has_more=True, next_cursor="x" * 513),
        {"limit": 100, "cursor": None, "hasMore": False, "nextCursor": None},
    ]
    for envelope in envelopes:
        _install_atlas(monkeypatch, envelope)
        response = client.get(_path(), headers=auth)
        assert response.status_code == 502, (envelope, response.text)


def test_a_page_larger_than_the_requested_limit_is_rejected(client, auth, monkeypatch):
    """The echoed limit is a claim; the row count is the behavior. Every row
    being individually valid must not launder an oversized page."""
    oversized = _directory_content(
        [
            _directory_item(str(uuid.uuid4())),
            _directory_item(str(uuid.uuid4())),
            _directory_item(str(uuid.uuid4())),
        ],
        limit=2,
    )
    _install_atlas(monkeypatch, oversized)
    response = client.get(f"{_path()}?limit=2", headers=auth)
    assert response.status_code == 502, response.text


def test_a_malformed_atlas_item_is_rejected(client, auth, monkeypatch):
    duplicate_id = str(uuid.uuid4())
    item_pages = [
        [_directory_item("not-a-uuid")],
        [_directory_item(contact_type="prospect")],
        [_directory_item(customer_type="franchise")],
        [_directory_item(status="archived")],
        [{"contactId": str(uuid.uuid4()), "fullName": "", "contactType": "lead",
          "customerType": "unknown", "status": "active",
          "createdAt": "2026-08-20T12:00:00+00:00"}],
        # Required fields must BE strings: str() coercion would otherwise
        # fabricate projection values out of malformed upstream types --
        # including a 32-digit integer whose digits parse as a UUID.
        [{**_directory_item(), "fullName": 123}],
        [{**_directory_item(), "createdAt": {"bad": True}}],
        [{**_directory_item(), "contactId": 11111111222222223333333344444444}],
        [_directory_item(duplicate_id), _directory_item(duplicate_id)],
    ]
    for items in item_pages:
        _install_atlas(monkeypatch, _directory_content(items))
        response = client.get(_path(), headers=auth)
        assert response.status_code == 502, (items, response.text)


def test_a_non_advancing_continuation_cursor_is_rejected(client, auth, monkeypatch):
    """hasMore=true with nextCursor equal to the echoed cursor would loop the
    browser over the same page forever."""
    cursor = "loop-cursor-0123456789abcdef"
    _install_atlas(
        monkeypatch,
        _directory_content(cursor=cursor, has_more=True, next_cursor=cursor),
    )
    response = client.get(f"{_path()}?cursor={cursor}", headers=auth)
    assert response.status_code == 502, response.text


def test_an_out_of_scope_row_on_a_kind_filtered_page_is_rejected(
    client, auth, monkeypatch
):
    """A customer-only request must never relay a lead row Atlas mis-filtered
    into the page -- that is a broken response, not data."""
    _install_atlas(
        monkeypatch,
        _directory_content([
            _directory_item(contact_type="lead", lead_stage="new"),
        ]),
    )
    response = client.get(f"{_path()}?kind=customer", headers=auth)
    assert response.status_code == 502, response.text


def test_unhashable_enum_fields_are_rejected_not_crashed(client, auth, monkeypatch):
    """A list/object contactType or customerType must reach the intended 502,
    not raise TypeError inside a frozenset membership check."""
    for items in (
        [{**_directory_item(), "contactType": ["customer"]}],
        [{**_directory_item(), "customerType": {"value": "unknown"}}],
    ):
        _install_atlas(monkeypatch, _directory_content(items))
        response = client.get(_path(), headers=auth)
        assert response.status_code == 502, (items, response.text)


def test_a_lost_lead_relays_with_its_stage(client, auth, monkeypatch):
    _install_atlas(
        monkeypatch,
        _directory_content([
            _directory_item(contact_type="lead", lead_stage="lost"),
        ]),
    )
    response = client.get(_path(), headers=auth)
    assert response.status_code == 200, response.text
    item = response.json()["contacts"][0]
    assert item["contactType"] == "lead"
    assert item["leadStage"] == "lost"
