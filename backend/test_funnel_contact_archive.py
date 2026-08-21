"""Archive/restore relays and the archived directory view (website #253).

Pure relays over the canonical Atlas transitions: strict deployment proofs
(capability name AND exact registered route, with the endpoint gates applying
the identical predicate), identity+status echo validation before anything
reaches a browser, typed error passthrough, zero tracker rows touched, and a
server-backed archived view that is never a client-side filter.
"""

from __future__ import annotations

import uuid
from itertools import product

import db
import time_tracker_api as api


def _archive_path(contact_id: str) -> str:
    return f"/api/admin/funnel/contacts/{contact_id}/archive"


def _restore_path(contact_id: str) -> str:
    return f"/api/admin/funnel/contacts/{contact_id}/restore"


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


_FULL_ROUTES: list[dict[str, str]] = [
    {"method": "POST", "path": "/eom-funnel/operator-contacts"},
    {"method": "GET", "path": "/eom-funnel/contact-directory"},
    {"method": "POST", "path": "/eom-funnel/contacts/{contact_id}/archive"},
    {"method": "POST", "path": "/eom-funnel/contacts/{contact_id}/restore"},
]
_FULL_CAPABILITIES: list[str] = [
    "lead.lost",
    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY,
    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_ARCHIVE,
    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_RESTORE,
    api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY_ARCHIVED,
]


def _manifest(
    *,
    drop_name: str | None = None,
    drop_route: str | None = None,
    poison_capabilities: bool = False,
    poison_routes: bool = False,
    declared: bool = True,
) -> dict[str, object]:
    content: dict[str, object] = {
        "leads": [],
        "cursor": None,
        "hasMore": False,
        "nextCursor": None,
    }
    if not declared:
        return content
    capabilities: list[object] = [
        name for name in _FULL_CAPABILITIES if name != drop_name
    ]
    if poison_capabilities:
        capabilities.append(1)
    routes: list[object] = [
        route for route in _FULL_ROUTES if route["path"] != drop_route
    ]
    if poison_routes:
        routes.append("not-a-route-object")
    content["capabilities"] = capabilities
    content["capabilityRoutes"] = routes
    return content


def _lifecycle_result(
    contact_id: str,
    *,
    status: str,
    contact_type: str = "customer",
    lead_stage: str | None = None,
    idempotent: bool = False,
) -> dict[str, object]:
    return {
        "success": True,
        "contact_id": contact_id,
        "contact_type": contact_type,
        "lead_stage": lead_stage,
        "status": status,
        "idempotent": idempotent,
    }


def _install_manifest(monkeypatch, manifest) -> None:
    monkeypatch.setattr(api, "_atlas_funnel_read", lambda *_a, _c=manifest, **_k: _c)


# ---------------------------------------------------------------------------
# Strict proofs: name AND route, with the endpoints applying the same predicate
# ---------------------------------------------------------------------------


# Grammar axes for the proof matrix: control families x manifest degradation
# tokens. Every generated case is judged by the same expected verdict: only
# the fully-proven manifest reads available, and the endpoint's gate must
# agree with the advertised proof in every cell.
_PROOF_FAMILIES = [
    (
        "contactArchiveAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_CONTACT_ARCHIVE,
        "/eom-funnel/contacts/{contact_id}/archive",
    ),
    (
        "contactRestoreAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_CONTACT_RESTORE,
        "/eom-funnel/contacts/{contact_id}/restore",
    ),
    (
        "contactDirectoryArchivedAvailable",
        api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY_ARCHIVED,
        "/eom-funnel/contact-directory",
    ),
]
_DEGRADATION_TOKENS = (
    "full",
    "missing-name",
    "missing-route",
    "poisoned-capabilities",
    "poisoned-routes",
    "undeclared",
)


def _degraded_manifest(token: str, capability: str, route_path: str):
    if token == "full":
        return _manifest()
    if token == "missing-name":
        return _manifest(drop_name=capability)
    if token == "missing-route":
        return _manifest(drop_route=route_path)
    if token == "poisoned-capabilities":
        return _manifest(poison_capabilities=True)
    if token == "poisoned-routes":
        return _manifest(poison_routes=True)
    return _manifest(declared=False)


def test_proofs_hold_across_control_families_and_degradation_tokens(
    client, auth, monkeypatch
):
    """Generated over the two grammar axes; the expected verdict is derived
    from the strict-proof contract (full manifest and nothing else), never
    from a per-case fixture list."""
    for (field, capability, route_path), token in product(
        _PROOF_FAMILIES, _DEGRADATION_TOKENS
    ):
        expected = token == "full"
        _install_manifest(
            monkeypatch, _degraded_manifest(token, capability, route_path)
        )
        review = client.get("/api/admin/funnel/review", headers=auth)
        assert review.status_code == 200, review.text
        assert review.json()[field] is expected, (field, token)


def test_the_transition_endpoints_enforce_the_same_predicate_as_the_proofs(
    client, auth, monkeypatch
):
    for (field, capability, route_path), token in product(
        _PROOF_FAMILIES[:2], _DEGRADATION_TOKENS
    ):
        _install_manifest(
            monkeypatch, _degraded_manifest(token, capability, route_path)
        )
        path = (
            _archive_path(str(uuid.uuid4()))
            if field == "contactArchiveAvailable"
            else _restore_path(str(uuid.uuid4()))
        )
        calls: list[str] = []
        monkeypatch.setattr(
            api,
            "_atlas_funnel_request",
            lambda p, *_a, **_k: calls.append(p)
            or _lifecycle_result(
                p.split("/contacts/")[1].split("/")[0],
                status="archived" if "archive" in p else "active",
            ),
        )
        attempt = client.post(
            path, headers=auth, json={"idempotencyKey": str(uuid.uuid4())}
        )
        if token == "full":
            assert attempt.status_code == 201, (field, token, attempt.text)
        else:
            assert attempt.status_code == 501, (field, token, attempt.text)
            assert attempt.json()["error"] == "atlas_capability_unavailable"
            assert calls == [], (field, token)


def test_the_archived_view_requires_the_archived_proof_and_active_does_not(
    client, auth, monkeypatch
):
    manifest = _manifest(
        drop_name=api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY_ARCHIVED
    )
    calls: list[dict[str, object]] = []

    def atlas_read(path, admin, *, params=None):
        calls.append({"path": path, "params": dict(params or {})})
        if path == "/eom-funnel/leads":
            return manifest
        return {
            "contacts": [],
            "limit": (params or {}).get("limit"),
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)

    archived = client.get(
        "/api/admin/funnel/contact-directory?lifecycle=archived", headers=auth
    )
    assert archived.status_code == 501, archived.text
    assert archived.json()["capability"] == (
        api.ATLAS_FUNNEL_CAPABILITY_CONTACT_DIRECTORY_ARCHIVED
    )
    assert all(call["path"] == "/eom-funnel/leads" for call in calls)

    active = client.get("/api/admin/funnel/contact-directory", headers=auth)
    assert active.status_code == 200, active.text
    directory_calls = [
        call for call in calls if call["path"] == api._ATLAS_CONTACT_DIRECTORY_PATH
    ]
    assert len(directory_calls) == 1
    # The active request shape is byte-identical to the pre-#253 proxy: no
    # lifecycle parameter rides along for an older Atlas to 422 on.
    assert "lifecycle" not in directory_calls[0]["params"]


# ---------------------------------------------------------------------------
# Relay behavior: forwarding, echo validation, error passthrough, no local rows
# ---------------------------------------------------------------------------


def test_archive_and_restore_forward_the_exact_transition_and_touch_no_rows(
    client, auth, monkeypatch
):
    _install_manifest(monkeypatch, _manifest())
    before = _operational_counts()
    for action, path_template, expected_status in (
        ("archive", api.ATLAS_CONTACT_ARCHIVE_PATH, "archived"),
        ("restore", api.ATLAS_CONTACT_RESTORE_PATH, "active"),
    ):
        contact_id = str(uuid.uuid4())
        key = str(uuid.uuid4())
        calls: list[dict[str, object]] = []

        def atlas_request(path, admin, *, payload, idempotency_key):
            calls.append(
                {
                    "path": path,
                    "admin": dict(admin),
                    "payload": dict(payload),
                    "idempotencyKey": idempotency_key,
                }
            )
            return _lifecycle_result(
                contact_id,
                status=expected_status,
                contact_type="lead",
                lead_stage="lost",
            )

        monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
        response = client.post(
            f"/api/admin/funnel/contacts/{contact_id}/{action}",
            headers=auth,
            json={"idempotencyKey": key},
        )
        assert response.status_code == 201, (action, response.text)
        assert response.json() == {
            "success": True,
            "contactId": contact_id,
            "contactType": "lead",
            "leadStage": "lost",
            "status": expected_status,
            "idempotent": False,
        }, action
        assert calls == [
            {
                "path": path_template.format(contact_id=contact_id),
                "admin": calls[0]["admin"],
                "payload": {},
                "idempotencyKey": key,
            }
        ], action
        assert calls[0]["admin"]["name"], action
    assert _operational_counts() == before


def test_idempotent_replays_relay_as_200(client, auth, monkeypatch):
    _install_manifest(monkeypatch, _manifest())
    contact_id = str(uuid.uuid4())
    monkeypatch.setattr(
        api,
        "_atlas_funnel_request",
        lambda *_a, **_k: _lifecycle_result(
            contact_id, status="archived", idempotent=True
        ),
    )
    response = client.post(
        _archive_path(contact_id),
        headers=auth,
        json={"idempotencyKey": str(uuid.uuid4())},
    )
    assert response.status_code == 200, response.text
    assert response.json()["idempotent"] is True


def test_wrong_target_wrong_status_and_junk_echoes_are_refused(
    client, auth, monkeypatch
):
    """The echo is the caller's only proof the right contact moved to the
    right state; a mismatched or malformed one must be a 502, never data."""
    _install_manifest(monkeypatch, _manifest())
    contact_id = str(uuid.uuid4())
    bad_echoes = [
        _lifecycle_result(str(uuid.uuid4()), status="archived"),  # wrong target
        _lifecycle_result(contact_id, status="active"),  # wrong resulting status
        _lifecycle_result(contact_id, status="archived", contact_type="vendor"),
        {**_lifecycle_result(contact_id, status="archived"), "idempotent": "yes"},
        {**_lifecycle_result(contact_id, status="archived"), "success": False},
        {**_lifecycle_result(contact_id, status="archived"), "contact_id": 7},
        "not-a-dict",
    ]
    for echo in bad_echoes:
        monkeypatch.setattr(
            api, "_atlas_funnel_request", lambda *_a, _e=echo, **_k: _e
        )
        response = client.post(
            _archive_path(contact_id),
            headers=auth,
            json={"idempotencyKey": str(uuid.uuid4())},
        )
        assert response.status_code == 502, (echo, response.text)


def test_atlas_refusals_pass_through_with_their_status_and_detail(
    client, auth, monkeypatch
):
    _install_manifest(monkeypatch, _manifest())
    contact_id = str(uuid.uuid4())
    for status_code, detail in (
        (404, "EOM contact was not found"),
        (409, "EOM contact is already archived"),
        (409, "EOM won lead must be dispositioned through the lost flow "
              "before it can be archived"),
    ):
        def atlas_request(*_a, _s=status_code, _d=detail, **_k):
            raise api.AtlasFunnelRequestError(_s, _d)

        monkeypatch.setattr(api, "_atlas_funnel_request", atlas_request)
        response = client.post(
            _archive_path(contact_id),
            headers=auth,
            json={"idempotencyKey": str(uuid.uuid4())},
        )
        assert response.status_code == status_code, response.text
        # The tracker's HTTPException handler reshapes detail to `error`.
        assert response.json() == {"success": False, "error": detail}


def test_unauthenticated_and_malformed_requests_never_reach_atlas(
    client, monkeypatch
):
    calls: list[str] = []
    monkeypatch.setattr(
        api, "_atlas_funnel_request", lambda p, *_a, **_k: calls.append(p)
    )
    contact_id = str(uuid.uuid4())
    assert (
        client.post(
            _archive_path(contact_id), json={"idempotencyKey": str(uuid.uuid4())}
        ).status_code
        == 401
    )
    assert (
        client.post(
            _restore_path(contact_id), json={"idempotencyKey": str(uuid.uuid4())}
        ).status_code
        == 401
    )
    assert calls == []


def test_a_junk_idempotency_key_and_unknown_fields_are_rejected(
    client, auth, monkeypatch
):
    _install_manifest(monkeypatch, _manifest())
    calls: list[str] = []
    monkeypatch.setattr(
        api, "_atlas_funnel_request", lambda p, *_a, **_k: calls.append(p)
    )
    contact_id = str(uuid.uuid4())
    for body in (
        {"idempotencyKey": "not-a-uuid"},
        {"idempotencyKey": str(uuid.uuid4()), "surprise": True},
        {},
    ):
        response = client.post(_archive_path(contact_id), headers=auth, json=body)
        assert response.status_code == 422, (body, response.text)
    assert calls == []


# ---------------------------------------------------------------------------
# Archived directory view
# ---------------------------------------------------------------------------


def _archived_item(contact_id: str | None = None, *, status: str = "archived"):
    return {
        "contactId": contact_id or str(uuid.uuid4()),
        "fullName": "Parked Person",
        "email": None,
        "phone": None,
        "address": None,
        "contactType": "customer",
        "customerType": "unknown",
        "leadStage": None,
        "status": status,
        "source": "manual",
        "createdAt": "2026-08-20T12:00:00+00:00",
        "updatedAt": None,
    }


def _install_directory(monkeypatch, items, calls=None):
    def atlas_read(path, admin, *, params=None):
        if calls is not None:
            calls.append({"path": path, "params": dict(params or {})})
        if path == "/eom-funnel/leads":
            return _manifest()
        assert path == api._ATLAS_CONTACT_DIRECTORY_PATH, path
        return {
            "contacts": items,
            "limit": (params or {}).get("limit"),
            "cursor": None,
            "hasMore": False,
            "nextCursor": None,
        }

    monkeypatch.setattr(api, "_atlas_funnel_read", atlas_read)


def test_the_archived_view_forwards_lifecycle_and_relays_archived_rows(
    client, auth, monkeypatch
):
    calls: list[dict[str, object]] = []
    _install_directory(monkeypatch, [_archived_item()], calls)
    response = client.get(
        "/api/admin/funnel/contact-directory?lifecycle=archived&limit=100",
        headers=auth,
    )
    assert response.status_code == 200, response.text
    rows = response.json()["contacts"]
    assert len(rows) == 1 and rows[0]["status"] == "archived"
    directory_calls = [
        call for call in calls if call["path"] == api._ATLAS_CONTACT_DIRECTORY_PATH
    ]
    assert directory_calls[0]["params"]["lifecycle"] == "archived"


def test_a_mixed_lifecycle_page_is_a_broken_response_in_both_directions(
    client, auth, monkeypatch
):
    _install_directory(monkeypatch, [_archived_item(status="active")])
    archived = client.get(
        "/api/admin/funnel/contact-directory?lifecycle=archived", headers=auth
    )
    assert archived.status_code == 502, archived.text

    _install_directory(monkeypatch, [_archived_item(status="archived")])
    active = client.get("/api/admin/funnel/contact-directory", headers=auth)
    assert active.status_code == 502, active.text


def test_an_out_of_set_lifecycle_is_refused_before_any_atlas_call(
    client, auth, monkeypatch
):
    calls: list[dict[str, object]] = []
    _install_directory(monkeypatch, [], calls)
    response = client.get(
        "/api/admin/funnel/contact-directory?lifecycle=deleted", headers=auth
    )
    assert response.status_code == 422, response.text
    assert calls == []
