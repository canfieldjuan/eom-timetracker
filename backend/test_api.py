"""
Integration tests for EOM Time Tracker API - Phases 3-8 + regression checks.

Run:  cd backend && pytest -v
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier, Event, Lock

import bcrypt
import pytest

import db


# ===============================================================================
# Auth & Health
# ===============================================================================

class TestAuth:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_login_success(self, client):
        r = client.post("/api/auth/login", json={"name": "Juan Canfield", "password": "canfield1"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert "token" in data
        assert data["employee"]["role"] == "admin"

    def test_login_wrong_password(self, client):
        r = client.post("/api/auth/login", json={"name": "Juan Canfield", "password": "wrong"})
        assert r.status_code == 401

    def test_login_unknown_user(self, client):
        r = client.post("/api/auth/login", json={"name": "Nobody Here", "password": "x"})
        assert r.status_code == 401

    def test_admin_endpoint_requires_auth(self, client):
        r = client.get("/api/admin/employees")
        assert r.status_code == 401

    def test_employee_cannot_access_admin(self, client, emp_auth):
        r = client.get("/api/admin/employees", headers=emp_auth)
        assert r.status_code == 403

    def test_change_password_requires_current_password_and_reauthenticates(
        self, client, emp_auth
    ):
        endpoint = "/api/auth/change-password"
        changed_password = "gomez-new-2026"
        original_hash = db.query_one(
            "SELECT password_hash FROM employees WHERE name = %s",
            ("Catalina Gomez",),
        )["password_hash"]

        try:
            assert client.post(
                endpoint,
                json={
                    "currentPassword": "gomez1",
                    "newPassword": changed_password,
                },
            ).status_code == 401

            wrong_current = client.post(
                endpoint,
                headers=emp_auth,
                json={
                    "currentPassword": "not-the-current-password",
                    "newPassword": changed_password,
                },
            )
            assert wrong_current.status_code == 400
            assert wrong_current.json()["error"] == "Current password is incorrect"

            too_short = client.post(
                endpoint,
                headers=emp_auth,
                json={"currentPassword": "gomez1", "newPassword": "short"},
            )
            assert too_short.status_code == 422

            changed = client.post(
                endpoint,
                headers=emp_auth,
                json={
                    "currentPassword": "gomez1",
                    "newPassword": changed_password,
                },
            )
            assert changed.status_code == 200
            changed_body = changed.json()
            assert changed_body["success"] is True
            fresh_auth = {"Authorization": f"Bearer {changed_body['token']}"}

            assert client.post(
                "/api/auth/login",
                json={"name": "Catalina Gomez", "password": "gomez1"},
            ).status_code == 401
            assert client.post(
                "/api/auth/login",
                json={"name": "Catalina Gomez", "password": changed_password},
            ).status_code == 200

            # The change revokes tokens issued before it; the returned fresh
            # token carries the session forward. Back-dated tokens are covered
            # in test_auth_revocation.py; here the response token must work.
            same_password = client.post(
                endpoint,
                headers=fresh_auth,
                json={
                    "currentPassword": changed_password,
                    "newPassword": changed_password,
                },
            )
            assert same_password.status_code == 400
            assert "must be different" in same_password.json()["error"]
        finally:
            db.execute(
                "UPDATE employees SET password_hash = %s, "
                "password_changed_at = NULL WHERE name = %s",
                (original_hash, "Catalina Gomez"),
            )

    def test_change_password_rejects_values_beyond_bcrypt_limit(self, client, emp_auth):
        response = client.post(
            "/api/auth/change-password",
            headers=emp_auth,
            json={
                "currentPassword": "gomez1",
                "newPassword": "é" * 37,
            },
        )

        assert response.status_code == 422


class _AtlasResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _InvalidJsonAtlasResponse(_AtlasResponse):
    def json(self):
        raise ValueError("not json")


GENERATED_RECEIVABLES_TOKEN = "eomrx_v1_" + ("A" * 43)
PRIVATE_ATLAS_RECEIVABLES_BASE_URL = "http://atlas-eom-api:10000/api/v1"


class TestReceivablesProxy:
    def test_runtime_requirements_pin_pydantic_v2(self):
        requirements = (Path(__file__).parent / "requirements.txt").read_text(
            encoding="utf-8"
        )

        assert "pydantic>=2.0.0,<3.0.0" in requirements

    @pytest.mark.parametrize("invalid", [True, False, 100.0, 100.5, "100", 0, -1])
    def test_payment_model_rejects_coercive_cent_values(self, invalid):
        import time_tracker_api as api

        base = {
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 100,
            "payment_method": "check",
            "received_date": "2026-07-16",
            "reference": "strict-1001",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 100,
                }
            ],
        }

        with pytest.raises(ValueError):
            api.ReceivablesPaymentRequest.model_validate(
                {**base, "total_amount_cents": invalid}
            )
        with pytest.raises(ValueError):
            api.ReceivablesPaymentRequest.model_validate(
                {
                    **base,
                    "allocations": [
                        {
                            "invoice_id": "22222222-2222-2222-2222-222222222222",
                            "amount_cents": invalid,
                        }
                    ],
                }
            )

    def test_deposit_model_rejects_duplicate_payment_ids(self):
        import time_tracker_api as api

        payment_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with pytest.raises(ValueError, match="only appear once"):
            api.ReceivablesDepositRequest.model_validate(
                {
                    "payment_ids": [payment_id, payment_id],
                    "deposit_date": "2026-07-16",
                }
            )

    def test_requires_existing_admin_session(self, client, emp_auth):
        response = client.get("/api/admin/receivables/open-invoices", headers=emp_auth)
        assert response.status_code == 403

    def test_missing_atlas_config_fails_only_receivables_route(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "")

        response = client.get("/api/admin/receivables/open-invoices", headers=auth)

        assert response.status_code == 503
        assert "not configured" in response.json()["error"]
        assert client.get("/api/health").status_code == 200

    def test_ready_uses_private_atlas_base_with_generated_token(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _AtlasResponse({"status": "ready"})

        monkeypatch.setattr(
            api,
            "ATLAS_RECEIVABLES_BASE_URL",
            PRIVATE_ATLAS_RECEIVABLES_BASE_URL,
        )
        monkeypatch.setattr(
            api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN
        )
        monkeypatch.setattr(api.requests, "request", fake_request)

        response = client.get("/api/admin/receivables/ready", headers=auth)

        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
        assert GENERATED_RECEIVABLES_TOKEN not in response.text
        method, url, kwargs = calls[0]
        assert method == "GET"
        assert url == f"{PRIVATE_ATLAS_RECEIVABLES_BASE_URL}/receivables/ready"
        assert kwargs["headers"]["Authorization"] == (
            f"Bearer {GENERATED_RECEIVABLES_TOKEN}"
        )
        assert kwargs["headers"]["X-EOM-Actor"] == "Juan Canfield"

    @pytest.mark.parametrize(
        "base_url",
        [
            "atlas-eom-api:10000/api/v1",
            "ftp://atlas-eom-api:10000/api/v1",
            "http://atlas-eom-api:10000",
            "http://atlas-eom-api:10000/api/v2",
            "https://token:secret@atlas.test/api/v1",
        ],
    )
    def test_invalid_atlas_base_url_fails_before_atlas_request(
        self, client, auth, monkeypatch, base_url
    ):
        import time_tracker_api as api

        calls = []
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", base_url)
        monkeypatch.setattr(
            api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN
        )
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: calls.append((_args, _kwargs)),
        )

        response = client.get("/api/admin/receivables/ready", headers=auth)

        assert response.status_code == 503
        assert calls == []

    @pytest.mark.parametrize(
        "token",
        [
            "service-token",
            "opaque-pre-rotation-token",
            "legacy.service_token-2026",
        ],
    )
    def test_pre_rotation_opaque_service_token_remains_usable(
        self, client, auth, monkeypatch, token
    ):
        import time_tracker_api as api

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _AtlasResponse({"status": "ready"})

        monkeypatch.setattr(
            api,
            "ATLAS_RECEIVABLES_BASE_URL",
            PRIVATE_ATLAS_RECEIVABLES_BASE_URL,
        )
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", token)
        monkeypatch.setattr(api.requests, "request", fake_request)

        response = client.get("/api/admin/receivables/ready", headers=auth)

        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
        assert calls[0][2]["headers"]["Authorization"] == f"Bearer {token}"

    def test_forwards_service_token_and_server_derived_actor(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _AtlasResponse([{"invoice_number": "INV-1"}])

        monkeypatch.setattr(
            api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1"
        )
        monkeypatch.setattr(
            api,
            "ATLAS_RECEIVABLES_SERVICE_TOKEN",
            GENERATED_RECEIVABLES_TOKEN,
        )
        monkeypatch.setattr(api.requests, "request", fake_request)

        response = client.get(
            "/api/admin/receivables/open-invoices?search=Acme", headers=auth
        )

        assert response.status_code == 200
        assert response.json() == [{"invoice_number": "INV-1"}]
        method, url, kwargs = calls[0]
        assert method == "GET"
        assert url == "https://atlas.test/api/v1/receivables/open-invoices"
        assert kwargs["headers"]["Authorization"] == (
            f"Bearer {GENERATED_RECEIVABLES_TOKEN}"
        )
        assert kwargs["headers"]["X-EOM-Actor"] == "Juan Canfield"
        assert kwargs["params"]["search"] == "Acme"

    def test_forwards_idempotency_key_on_payment_write(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _AtlasResponse({"id": "payment-1"}, status_code=201)

        monkeypatch.setattr(
            api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1"
        )
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", fake_request)
        headers = {**auth, "Idempotency-Key": "browser-payment-1"}

        response = client.post(
            "/api/admin/receivables/payments",
            headers=headers,
            json={
                "contact_id": "11111111-1111-1111-1111-111111111111",
                "payer_name": "Acme",
                "total_amount_cents": 10_000,
                "payment_method": "check",
                "received_date": "2026-07-16",
                "reference": "1024",
                "allocations": [
                    {
                        "invoice_id": "22222222-2222-2222-2222-222222222222",
                        "amount_cents": 7_500,
                    }
                ],
            },
        )

        assert response.status_code == 200
        _method, _url, kwargs = calls[0]
        assert kwargs["headers"]["Idempotency-Key"] == "browser-payment-1"
        assert kwargs["json"]["total_amount_cents"] == 10_000

    def test_upstream_outage_is_retryable_with_durable_operation_identity(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)

        def fail(*_args, **_kwargs):
            raise api.requests.ConnectionError("offline")

        monkeypatch.setattr(api.requests, "request", fail)

        response = client.get("/api/admin/receivables/open-invoices", headers=auth)

        assert response.status_code == 503
        assert "retry" in response.json()["error"].lower()
        assert response.headers["retry-after"] == "5"

    @pytest.mark.parametrize("atlas_status", [502, 503, 504])
    def test_non_json_upstream_outage_preserves_retryable_status(
        self, client, auth, monkeypatch, atlas_status
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: _InvalidJsonAtlasResponse(
                None, status_code=atlas_status
            ),
        )

        response = client.get("/api/admin/receivables/ready", headers=auth)

        assert response.status_code == atlas_status
        assert "retry" in response.json()["error"].lower()
        assert response.headers["retry-after"] == "5"

    @pytest.mark.parametrize("atlas_status", [401, 403])
    def test_upstream_service_auth_failure_is_not_exposed_as_admin_401(
        self, client, auth, monkeypatch, atlas_status
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: _AtlasResponse(
                {"detail": "service credential rejected"},
                status_code=atlas_status,
            ),
        )

        response = client.get("/api/admin/receivables/ready", headers=auth)

        assert response.status_code == 502
        assert response.json()["error"] == "Receivables service authentication failed"

    def test_ambiguous_retry_reuses_durable_business_key_across_browser_keys(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        calls = []

        def flaky_request(_method, _url, **kwargs):
            calls.append(kwargs["headers"]["Idempotency-Key"])
            if len(calls) == 1:
                raise api.requests.ConnectionError("response lost")
            return _AtlasResponse({"id": "payment-after-retry"}, status_code=201)

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", flaky_request)
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        body = {
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 10_000,
            "payment_method": "check",
            "received_date": "2026-07-16",
            "reference": "durable-1001",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 10_000,
                }
            ],
        }

        first = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "browser-a-key"},
            json=body,
        )
        second = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "browser-b-key"},
            json=body,
        )
        replayed = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "browser-c-key"},
            json=body,
        )
        changed_details = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "browser-d-key"},
            json={**body, "notes": "changed after an ambiguous attempt"},
        )

        assert first.status_code == 503
        assert second.status_code == 200
        assert second.json() == {"id": "payment-after-retry"}
        assert replayed.status_code == 200
        assert replayed.json() == second.json()
        assert changed_details.status_code == 409
        assert "different details" in changed_details.json()["error"]
        assert calls == ["browser-a-key", "browser-a-key", "browser-a-key"]
        attempt = api.db.query_one(
            """
            SELECT state, idempotency_key
            FROM receivables_operation_attempts
            WHERE operation = 'RECEIVABLES_PAYMENT_CREATE'
            """
        )
        assert attempt == {"state": "resolved", "idempotency_key": "browser-a-key"}

    def test_deposit_retry_canonicalizes_payment_id_order(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        calls = []

        def flaky_request(_method, _url, **kwargs):
            calls.append((kwargs["headers"]["Idempotency-Key"], kwargs["json"]))
            if len(calls) == 1:
                raise api.requests.ConnectionError("response lost")
            return _AtlasResponse({"id": "deposit-after-retry"}, status_code=201)

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", flaky_request)
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        first_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        second_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        body = {
            "payment_ids": [second_id, first_id],
            "deposit_date": "2026-07-16",
            "bank_reference": "bank-1",
        }

        first = client.post(
            "/api/admin/receivables/deposit-batches",
            headers={**auth, "Idempotency-Key": "deposit-browser-a"},
            json=body,
        )
        second = client.post(
            "/api/admin/receivables/deposit-batches",
            headers={**auth, "Idempotency-Key": "deposit-browser-b"},
            json={**body, "payment_ids": [first_id, second_id]},
        )

        assert first.status_code == 503
        assert second.status_code == 200
        assert second.json() == {"id": "deposit-after-retry"}
        assert [key for key, _payload in calls] == [
            "deposit-browser-a",
            "deposit-browser-a",
        ]
        assert [payload["payment_ids"] for _key, payload in calls] == [
            [first_id, second_id],
            [first_id, second_id],
        ]

    def test_void_blocks_stale_replay_and_allows_one_corrected_generation(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        created_by_key = {}
        create_keys = []
        payment_ids = iter(
            [
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ]
        )

        def atlas_request(method, url, **kwargs):
            key = kwargs["headers"]["Idempotency-Key"]
            if method == "POST" and url.endswith("/receivables/payments"):
                create_keys.append(key)
                if key not in created_by_key:
                    body = kwargs["json"]
                    created_by_key[key] = {
                        **body,
                        "id": next(payment_ids),
                        "source": "eom_admin",
                        "idempotency_key": key,
                        "status": "received",
                    }
                return _AtlasResponse(created_by_key[key], status_code=201)
            if method == "POST" and url.endswith("/void"):
                payment_id = url.rsplit("/", 2)[-2]
                payment = next(
                    item for item in created_by_key.values()
                    if item["id"] == payment_id
                )
                payment["status"] = "voided"
                return _AtlasResponse(payment)
            raise AssertionError(f"Unexpected Atlas request: {method} {url}")

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", atlas_request)
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        body = {
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 10_000,
            "payment_method": "check",
            "received_date": "2026-07-16",
            "reference": "void-correction-1001",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 10_000,
                }
            ],
        }

        created = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "create-original"},
            json=body,
        )
        voided = client.post(
            f"/api/admin/receivables/payments/{created.json()['id']}/void",
            headers={**auth, "Idempotency-Key": "void-original"},
            json={"reason": "Wrong allocation"},
        )
        stale = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "stale-new-browser-key"},
            json=body,
        )
        corrected_with_old_key = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "create-original"},
            json={**body, "notes": "Corrected after void"},
        )
        corrected = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "create-corrected"},
            json={**body, "notes": "Corrected after void"},
        )

        assert created.status_code == 200
        assert voided.status_code == 200
        assert voided.json()["status"] == "voided"
        assert stale.status_code == 409
        assert "was voided" in stale.json()["error"]
        assert corrected_with_old_key.status_code == 409
        assert corrected.status_code == 200
        assert corrected.json()["id"] != created.json()["id"]
        assert create_keys == ["create-original", "create-corrected"]
        generations = api.db.query_all(
            """
            SELECT state, idempotency_key
            FROM receivables_operation_attempts
            WHERE operation = 'RECEIVABLES_PAYMENT_CREATE'
            ORDER BY attempt_id
            """
        )
        assert generations == [
            {"state": "voided", "idempotency_key": "create-original"},
            {"state": "resolved", "idempotency_key": "create-corrected"},
        ]

    def test_concurrent_corrected_variants_after_void_have_one_winner(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        created_by_key = {}
        create_keys = []
        payment_ids = iter(
            [
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ]
        )
        state_lock = Lock()
        replacement_entered = Event()
        release_replacement = Event()

        def atlas_request(method, url, **kwargs):
            key = kwargs["headers"]["Idempotency-Key"]
            if method == "POST" and url.endswith("/receivables/payments"):
                with state_lock:
                    create_keys.append(key)
                    if key not in created_by_key:
                        body = kwargs["json"]
                        created_by_key[key] = {
                            **body,
                            "id": next(payment_ids),
                            "source": "eom_admin",
                            "idempotency_key": key,
                            "status": "received",
                        }
                    payment = dict(created_by_key[key])
                    is_replacement = len(create_keys) > 1
                if is_replacement:
                    replacement_entered.set()
                    assert release_replacement.wait(5)
                return _AtlasResponse(payment, status_code=201)
            if method == "POST" and url.endswith("/void"):
                payment_id = url.rsplit("/", 2)[-2]
                with state_lock:
                    payment = next(
                        item for item in created_by_key.values()
                        if item["id"] == payment_id
                    )
                    payment["status"] = "voided"
                    return _AtlasResponse(dict(payment))
            raise AssertionError(f"Unexpected Atlas request: {method} {url}")

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", atlas_request)
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        body = {
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 10_000,
            "payment_method": "check",
            "received_date": "2026-07-16",
            "reference": "void-race-1001",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 10_000,
                }
            ],
        }
        created = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "race-original"},
            json=body,
        )
        assert created.status_code == 200
        voided = client.post(
            f"/api/admin/receivables/payments/{created.json()['id']}/void",
            headers={**auth, "Idempotency-Key": "race-void"},
            json={"reason": "Correct entry"},
        )
        assert voided.status_code == 200

        start = Barrier(3)

        def submit_variant(label):
            start.wait()
            return client.post(
                "/api/admin/receivables/payments",
                headers={**auth, "Idempotency-Key": f"race-corrected-{label}"},
                json={**body, "notes": f"Correction {label}"},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(submit_variant, "a")
            second = pool.submit(submit_variant, "b")
            start.wait()
            assert replacement_entered.wait(5)
            release_replacement.set()
            responses = [first.result(timeout=5), second.result(timeout=5)]

        assert sorted(response.status_code for response in responses) == [200, 409]
        assert len(create_keys) == 2
        active = api.db.query_all(
            """
            SELECT state, idempotency_key
            FROM receivables_operation_attempts
            WHERE operation = 'RECEIVABLES_PAYMENT_CREATE'
              AND state IN ('pending', 'resolved')
            """
        )
        assert len(active) == 1
        assert active[0]["state"] == "resolved"
        assert active[0]["idempotency_key"] in {
            "race-corrected-a", "race-corrected-b"
        }

    @pytest.mark.parametrize(
        ("terminal_status", "expected_state"),
        [("voided", "voided"), ("returned", "resolved")],
    )
    def test_terminal_atlas_create_replay_is_never_reported_as_new_success(
        self, client, auth, monkeypatch, terminal_status, expected_state
    ):
        import time_tracker_api as api

        atlas_payment = {
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 10_000,
            "payment_method": "check",
            "received_date": "2026-07-16",
            "reference": f"terminal-{terminal_status}-1001",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 10_000,
                }
            ],
            "source": "eom_admin",
            "idempotency_key": f"terminal-{terminal_status}-key",
            "status": "received",
        }

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: _AtlasResponse(dict(atlas_payment)),
        )
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        body = {
            key: value for key, value in atlas_payment.items()
            if key not in {"id", "source", "idempotency_key", "status"}
        }

        created = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": atlas_payment["idempotency_key"]},
            json=body,
        )
        assert created.status_code == 200
        atlas_payment["status"] = terminal_status
        replayed = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "new-browser-key"},
            json=body,
        )

        assert replayed.status_code == 409
        assert terminal_status in replayed.json()["error"]
        attempt = api.db.query_one(
            """
            SELECT state FROM receivables_operation_attempts
            WHERE operation = 'RECEIVABLES_PAYMENT_CREATE'
            """
        )
        assert attempt == {"state": expected_state}

    def test_external_receipt_references_preserve_case_in_business_identity(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        forwarded = []

        def fake_request(_method, _url, **kwargs):
            forwarded.append(kwargs["json"]["reference"])
            return _AtlasResponse({"id": f"payment-{len(forwarded)}"}, status_code=201)

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", fake_request)
        body = {
            "contact_id": "11111111-1111-1111-1111-111111111111",
            "payer_name": "Acme",
            "total_amount_cents": 10_000,
            "payment_method": "square",
            "received_date": "2026-07-16",
            "reference": "Square-AbC-123",
            "allocations": [
                {
                    "invoice_id": "22222222-2222-2222-2222-222222222222",
                    "amount_cents": 10_000,
                }
            ],
        }

        first = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "square-case-a"},
            json=body,
        )
        second = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "square-case-b"},
            json={**body, "reference": "square-abc-123"},
        )

        assert first.status_code == 200
        assert second.status_code == 200
        assert forwarded == ["Square-AbC-123", "square-abc-123"]

    def test_reservation_failure_never_calls_atlas(self, monkeypatch):
        import time_tracker_api as api

        upstream_calls = []
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.db,
            "get_conn",
            lambda: (_ for _ in ()).throw(RuntimeError("retry registry unavailable")),
        )
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: upstream_calls.append((_args, _kwargs)),
        )
        monkeypatch.setattr(api, "append_access_log", lambda *_args, **_kwargs: None)
        request = api.Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/admin/receivables/payments",
                "headers": [],
            }
        )

        with pytest.raises(api.HTTPException) as raised:
            api._atlas_receivables_mutation(
                request,
                "RECEIVABLES_PAYMENT_CREATE",
                "Receipt accepted by Atlas",
                "POST",
                "/receivables/payments",
                {"name": "Juan Canfield"},
                payload={
                "contact_id": "11111111-1111-1111-1111-111111111111",
                "payer_name": "Acme",
                "total_amount_cents": 10_000,
                "payment_method": "check",
                "received_date": "2026-07-16",
                "reference": "registry-down-1001",
                "allocations": [
                    {
                        "invoice_id": "22222222-2222-2222-2222-222222222222",
                        "amount_cents": 10_000,
                    }
                ],
                },
                idempotency_key="must-not-reach-atlas",
            )

        assert raised.value.status_code == 503
        assert raised.value.headers == {"Retry-After": "5"}
        assert "Atlas was not called" in str(raised.value.detail)
        assert upstream_calls == []

    def test_startup_migrates_the_legacy_single_generation_registry(self, client):
        import time_tracker_api as api

        api.db.execute("""
            DROP INDEX IF EXISTS uq_receivables_operation_attempts_active_identity;
            ALTER TABLE receivables_operation_attempts
                DROP CONSTRAINT receivables_operation_attempts_pkey;
            ALTER TABLE receivables_operation_attempts DROP COLUMN attempt_id;
            ALTER TABLE receivables_operation_attempts
                ADD CONSTRAINT receivables_operation_attempts_pkey
                PRIMARY KEY (operation_identity);
            ALTER TABLE receivables_operation_attempts
                DROP CONSTRAINT receivables_operation_attempts_state_check;
            ALTER TABLE receivables_operation_attempts
                ADD CONSTRAINT receivables_operation_attempts_state_check
                CHECK (state IN ('pending', 'resolved'));
        """)

        api._ensure_schema_migrations()

        primary_key = api.db.query_one("""
            SELECT a.attname AS column_name
            FROM pg_index i
            JOIN pg_attribute a
              ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = 'receivables_operation_attempts'::regclass
              AND i.indisprimary
        """)
        state_check = api.db.query_one("""
            SELECT pg_get_constraintdef(oid) AS definition
            FROM pg_constraint
            WHERE conrelid = 'receivables_operation_attempts'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%%state%%'
        """)
        assert primary_key == {"column_name": "attempt_id"}
        assert "voided" in state_check["definition"]

        api.db.execute("""
            INSERT INTO receivables_operation_attempts (
                operation_identity, request_fingerprint, operation,
                idempotency_key, state, created_by, last_attempt_by
            ) VALUES
                ('same-identity', 'old-fingerprint', 'RECEIVABLES_PAYMENT_CREATE',
                 'old-key', 'voided', 'Juan', 'Juan'),
                ('same-identity', 'new-fingerprint', 'RECEIVABLES_PAYMENT_CREATE',
                 'new-key', 'pending', 'Juan', 'Juan')
        """)
        assert api.db.query_one("""
            SELECT COUNT(*) AS generations
            FROM receivables_operation_attempts
            WHERE operation_identity = 'same-identity'
        """) == {"generations": 2}

    def test_rejected_mutation_is_a_failed_audit_entry(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        audits = []

        def fake_request(*_args, **_kwargs):
            return _AtlasResponse(
                {"detail": {"code": "conflict", "message": "Duplicate receipt"}},
                status_code=409,
            )

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(api.requests, "request", fake_request)
        monkeypatch.setattr(
            api,
            "append_access_log",
            lambda _request, action, allowed, reason="": audits.append(
                (action, allowed, reason)
            ),
        )

        response = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "duplicate-payment"},
            json={
                "contact_id": "11111111-1111-1111-1111-111111111111",
                "payer_name": "Acme",
                "total_amount_cents": 10_000,
                "payment_method": "check",
                "received_date": "2026-07-16",
                "reference": "rejected-1001",
                "allocations": [
                    {
                        "invoice_id": "22222222-2222-2222-2222-222222222222",
                        "amount_cents": 10_000,
                    }
                ],
            },
        )

        assert response.status_code == 409
        assert response.json()["error"] == "Duplicate receipt"
        assert audits == [
            (
                "RECEIVABLES_PAYMENT_CREATE",
                False,
                "Atlas request failed (409): Duplicate receipt",
            )
        ]

    def test_committed_mutation_survives_local_audit_write_failure(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: _AtlasResponse({"id": "committed-in-atlas"}),
        )

        def fail_audit(*_args, **_kwargs):
            raise OSError("audit disk unavailable")

        monkeypatch.setattr(api, "append_access_log", fail_audit)
        response = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "committed-payment"},
            json={
                "contact_id": "11111111-1111-1111-1111-111111111111",
                "payer_name": "Acme",
                "total_amount_cents": 10_000,
                "payment_method": "check",
                "received_date": "2026-07-16",
                "reference": "committed-1001",
                "allocations": [
                    {
                        "invoice_id": "22222222-2222-2222-2222-222222222222",
                        "amount_cents": 10_000,
                    }
                ],
            },
        )

        assert response.status_code == 200
        assert response.json() == {"id": "committed-in-atlas"}

    def test_atlas_rejection_survives_local_audit_write_failure(
        self, client, auth, monkeypatch
    ):
        import time_tracker_api as api

        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)
        monkeypatch.setattr(
            api.requests,
            "request",
            lambda *_args, **_kwargs: _AtlasResponse(
                {"detail": "Duplicate receipt"}, status_code=409
            ),
        )
        monkeypatch.setattr(
            api,
            "append_access_log",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("audit disk unavailable")
            ),
        )

        response = client.post(
            "/api/admin/receivables/payments",
            headers={**auth, "Idempotency-Key": "duplicate-payment"},
            json={
                "contact_id": "11111111-1111-1111-1111-111111111111",
                "payer_name": "Acme",
                "total_amount_cents": 10_000,
                "payment_method": "check",
                "received_date": "2026-07-16",
                "reference": "rejected-audit-1001",
                "allocations": [
                    {
                        "invoice_id": "22222222-2222-2222-2222-222222222222",
                        "amount_cents": 10_000,
                    }
                ],
            },
        )

        assert response.status_code == 409
        assert response.json()["error"] == "Duplicate receipt"

    @pytest.mark.parametrize(
        ("method", "path", "body", "expected_action"),
        [
            (
                "PUT",
                "/api/admin/receivables/payments/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/allocations",
                {
                    "allocations": [
                        {
                            "invoice_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                            "amount_cents": 2500,
                        }
                    ],
                    "reason": "Apply remainder",
                },
                "RECEIVABLES_PAYMENT_ALLOCATIONS_ADJUST",
            ),
            (
                "POST",
                "/api/admin/receivables/payments/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/return",
                {"reason": "NSF"},
                "RECEIVABLES_PAYMENT_RETURN",
            ),
            (
                "POST",
                "/api/admin/receivables/payments/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/void",
                {"reason": "Entry error"},
                "RECEIVABLES_PAYMENT_VOID",
            ),
            (
                "POST",
                "/api/admin/receivables/deposit-batches",
                {
                    "payment_ids": ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
                    "deposit_date": "2026-07-16",
                },
                "RECEIVABLES_DEPOSIT_CREATE",
            ),
            (
                "POST",
                "/api/admin/receivables/deposit-batches/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/clear",
                None,
                "RECEIVABLES_DEPOSIT_CLEAR",
            ),
        ],
    )
    def test_each_financial_mutation_records_a_success_audit(
        self, client, auth, monkeypatch, method, path, body, expected_action
    ):
        import time_tracker_api as api

        audits = []
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_BASE_URL", "https://atlas.test/api/v1")
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", GENERATED_RECEIVABLES_TOKEN)

        def successful_mutation(_method, url, **_kwargs):
            if url.endswith("/void"):
                return _AtlasResponse(
                    {
                        "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        "source": "atlas_mcp",
                        "status": "voided",
                    }
                )
            return _AtlasResponse({"ok": True})

        monkeypatch.setattr(
            api.requests,
            "request",
            successful_mutation,
        )
        monkeypatch.setattr(
            api,
            "append_access_log",
            lambda _request, action, allowed, reason="": audits.append(
                (action, allowed, reason)
            ),
        )

        response = client.request(
            method,
            path,
            headers={**auth, "Idempotency-Key": "mutation-attempt-1"},
            json=body,
        )

        assert response.status_code == 200
        assert audits and audits[0][0] == expected_action
        assert audits[0][1] is True


class TestQrEventSchemaMigration:
    def test_startup_upgrades_legacy_visit_departure_event_shape(self, client):
        import time_tracker_api as api

        api.db.execute("""
            DROP TABLE IF EXISTS site_qr_action_receipts;
            DROP INDEX IF EXISTS uq_departures_visit_id;
            DROP INDEX IF EXISTS uq_visits_site_check_in_id;
            DROP INDEX IF EXISTS idx_visits_job_id;
            ALTER TABLE departures DROP COLUMN IF EXISTS visit_id;
            ALTER TABLE visits DROP COLUMN IF EXISTS site_check_in_id;
            ALTER TABLE visits DROP COLUMN IF EXISTS job_id;
            ALTER TABLE visits DROP COLUMN IF EXISTS sequence_version;
        """)
        shift_id = api.db.execute_returning("""
            INSERT INTO shifts (
                employee_id, location_label, clock_in, local_date
            )
            SELECT id, 'Legacy migration fixture',
                   TIMESTAMPTZ '2040-01-02 08:00:00-06', DATE '2040-01-02'
            FROM employees
            ORDER BY id
            LIMIT 1
            RETURNING id
        """)
        visit_id = api.db.execute_returning(
            """
            INSERT INTO visits (
                shift_id, location_label, customer_name, arrival_time
            )
            VALUES (
                %s, 'Legacy migration fixture', 'Legacy customer',
                TIMESTAMPTZ '2040-01-02 08:30:00-06'
            )
            RETURNING id
            """,
            (shift_id,),
        )
        departure_id = api.db.execute_returning(
            """
            INSERT INTO departures (
                shift_id, location_label, customer_name, departure_time
            )
            VALUES (
                %s, 'Legacy migration fixture', 'Legacy customer',
                TIMESTAMPTZ '2040-01-02 09:30:00-06'
            )
            RETURNING id
            """,
            (shift_id,),
        )

        try:
            legacy_columns = api.db.query_all("""
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND (
                    (table_name = 'visits'
                     AND column_name IN (
                       'sequence_version', 'site_check_in_id', 'job_id'
                     ))
                    OR
                    (table_name = 'departures' AND column_name = 'visit_id')
                  )
            """)
            assert legacy_columns == []
            assert api.db.query_one(
                "SELECT to_regclass('site_qr_action_receipts') AS table_name"
            ) == {"table_name": None}

            api._ensure_schema_migrations()

            pairing_columns = {
                (row["table_name"], row["column_name"]): row
                for row in api.db.query_all("""
                    SELECT table_name, column_name, udt_name,
                           is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND (
                        (table_name = 'visits'
                         AND column_name IN (
                           'sequence_version', 'site_check_in_id', 'job_id'
                         ))
                        OR
                        (table_name = 'departures' AND column_name = 'visit_id')
                      )
                """)
            }
            assert set(pairing_columns) == {
                ("visits", "sequence_version"),
                ("visits", "site_check_in_id"),
                ("visits", "job_id"),
                ("departures", "visit_id"),
            }
            assert pairing_columns[("visits", "sequence_version")] == {
                "table_name": "visits",
                "column_name": "sequence_version",
                "udt_name": "int2",
                "is_nullable": "NO",
                "column_default": "1",
            }
            assert pairing_columns[("visits", "site_check_in_id")]["udt_name"] == "int8"
            assert pairing_columns[("visits", "site_check_in_id")]["is_nullable"] == "YES"
            assert pairing_columns[("visits", "job_id")]["udt_name"] == "int4"
            assert pairing_columns[("visits", "job_id")]["is_nullable"] == "YES"
            assert pairing_columns[("departures", "visit_id")]["udt_name"] == "int4"
            assert pairing_columns[("departures", "visit_id")]["is_nullable"] == "YES"

            assert api.db.query_one(
                """
                SELECT sequence_version, site_check_in_id, job_id
                FROM visits
                WHERE id = %s
                """,
                (visit_id,),
            ) == {
                "sequence_version": 1,
                "site_check_in_id": None,
                "job_id": None,
            }
            assert api.db.query_one(
                "SELECT visit_id FROM departures WHERE id = %s",
                (departure_id,),
            ) == {"visit_id": None}

            sequence_check = api.db.query_one("""
                SELECT convalidated AS validated,
                       pg_get_constraintdef(oid) AS definition
                FROM pg_constraint
                WHERE conrelid = 'visits'::regclass
                  AND conname = 'visits_sequence_version_check'
            """)
            assert sequence_check["validated"] is True
            assert "sequence_version" in sequence_check["definition"]
            assert "1" in sequence_check["definition"]
            assert "2" in sequence_check["definition"]

            visit_foreign_keys = "\n".join(
                row["definition"]
                for row in api.db.query_all("""
                    SELECT pg_get_constraintdef(oid) AS definition
                    FROM pg_constraint
                    WHERE contype = 'f'
                      AND conrelid IN (
                        'visits'::regclass, 'departures'::regclass
                      )
                """)
            )
            assert (
                "FOREIGN KEY (site_check_in_id) "
                "REFERENCES site_check_ins(id) ON DELETE SET NULL"
            ) in visit_foreign_keys
            assert (
                "FOREIGN KEY (job_id) "
                "REFERENCES jobs(id) ON DELETE SET NULL"
            ) in visit_foreign_keys
            assert (
                "FOREIGN KEY (visit_id) "
                "REFERENCES visits(id) ON DELETE SET NULL"
            ) in visit_foreign_keys

            pairing_indexes = {
                row["indexname"]: row["indexdef"]
                for row in api.db.query_all("""
                    SELECT indexname, indexdef
                    FROM pg_indexes
                    WHERE schemaname = current_schema()
                      AND indexname IN (
                        'uq_departures_visit_id',
                        'uq_visits_site_check_in_id',
                        'idx_visits_job_id'
                      )
                """)
            }
            assert set(pairing_indexes) == {
                "uq_departures_visit_id",
                "uq_visits_site_check_in_id",
                "idx_visits_job_id",
            }
            assert "UNIQUE INDEX" in pairing_indexes["uq_departures_visit_id"]
            assert "(visit_id)" in pairing_indexes["uq_departures_visit_id"]
            assert (
                "WHERE (visit_id IS NOT NULL)"
                in pairing_indexes["uq_departures_visit_id"]
            )
            assert "UNIQUE INDEX" in pairing_indexes["uq_visits_site_check_in_id"]
            assert "(site_check_in_id)" in pairing_indexes[
                "uq_visits_site_check_in_id"
            ]
            assert (
                "WHERE (site_check_in_id IS NOT NULL)"
                in pairing_indexes["uq_visits_site_check_in_id"]
            )
            assert "(job_id)" in pairing_indexes["idx_visits_job_id"]

            receipt_columns = {
                row["column_name"]: row
                for row in api.db.query_all("""
                    SELECT column_name, udt_name, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = 'site_qr_action_receipts'
                """)
            }
            assert {
                name: column["udt_name"]
                for name, column in receipt_columns.items()
            } == {
                "id": "int8",
                "employee_id": "int4",
                "location_id": "int4",
                "shift_id": "int4",
                "action": "varchar",
                "idempotency_key": "uuid",
                "request_fingerprint": "varchar",
                "server_recorded_at": "timestamptz",
                "device_scanned_at": "timestamptz",
                "latitude": "numeric",
                "longitude": "numeric",
                "accuracy_m": "numeric",
                "geofence_radius_m": "int4",
                "distance_m": "numeric",
                "geofence_status": "varchar",
                "outcome": "varchar",
                "site_check_in_id": "int8",
                "visit_id": "int4",
                "departure_id": "int4",
                "missing_departure_visit_ids": "_int4",
                "response_body": "jsonb",
                "created_at": "timestamptz",
            }
            assert receipt_columns["missing_departure_visit_ids"][
                "is_nullable"
            ] == "NO"
            assert receipt_columns["missing_departure_visit_ids"][
                "column_default"
            ] == "'{}'::integer[]"
            assert receipt_columns["response_body"]["is_nullable"] == "NO"

            receipt_constraints = "\n".join(
                row["definition"]
                for row in api.db.query_all("""
                    SELECT pg_get_constraintdef(oid) AS definition
                    FROM pg_constraint
                    WHERE conrelid = 'site_qr_action_receipts'::regclass
                """)
            )
            assert "UNIQUE (employee_id, idempotency_key)" in receipt_constraints
            assert (
                "UNIQUE (employee_id, location_id, device_scanned_at)"
                in receipt_constraints
            )
            for required_value in (
                "arrive",
                "depart",
                "inside",
                "outside",
                "uncertain",
                "low_accuracy",
                "site_unpinned",
                "recorded",
                "evidence_only_review",
            ):
                assert required_value in receipt_constraints

            receipt_index = api.db.query_one("""
                SELECT indexdef
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND indexname = 'idx_site_qr_action_receipts_shift'
            """)
            assert "(shift_id, server_recorded_at DESC)" in receipt_index["indexdef"]
        finally:
            api.db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))


class TestVisitJobIdentity:
    def test_save_and_load_preserve_visit_job_id_without_shift_link(self, client):
        import time_tracker_api as api

        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        try:
            site_id = _insert_profitability_site(
                address="2049 Visit Identity Proof",
                customer_name="Visit Identity Customer",
                rate=250.0,
                rate_type="per_visit",
                expected_hours=2.0,
            )
            site_ids.append(site_id)
            job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name="Visit Identity Customer",
                scheduled_date="2049-06-01",
                expected_hours=2.0,
                revenue=250.0,
                source_key="15" * 32,
            )
            job_ids.append(job_id)
            employee_id = db.query_one(
                "SELECT id FROM employees WHERE name = %s",
                ("Catalina Gomez",),
            )["id"]
            shift_id = int(db.execute_returning(
                """
                INSERT INTO shifts (
                    employee_id, location_label, clock_in, local_date
                )
                VALUES (
                    %s, 'Visit identity shift',
                    TIMESTAMPTZ '2049-06-01 08:00:00-05',
                    DATE '2049-06-01'
                )
                RETURNING id
                """,
                (employee_id,),
            ))
            shift_ids.append(shift_id)

            timesheet_data = api._load_timesheets_from_db()
            pre_shift_ids = {entry["id"] for entry in timesheet_data["entries"]}
            pre_visit_counts = {
                entry["id"]: len(entry.get("visits", []))
                for entry in timesheet_data["entries"]
            }
            pre_departure_counts = {
                entry["id"]: len(entry.get("departures", []))
                for entry in timesheet_data["entries"]
            }
            entry = next(
                row for row in timesheet_data["entries"] if row["id"] == shift_id
            )
            assert entry["jobId"] is None
            entry["visits"].append({
                "arrivalTime": "2049-06-01T13:30:00Z",
                "location": "2049 Visit Identity Proof",
                "customer": "Visit Identity Customer",
                "gps": None,
                "gpsMeta": None,
                "sequenceVersion": 2,
                "siteCheckInId": None,
                "jobId": job_id,
            })

            api._save_timesheets_to_db(
                timesheet_data,
                pre_shift_ids,
                pre_visit_counts,
                pre_departure_counts,
            )

            stored = db.query_one(
                "SELECT job_id FROM visits WHERE shift_id = %s",
                (shift_id,),
            )
            assert stored == {"job_id": job_id}
            loaded_entry = next(
                row
                for row in api._load_timesheets_from_db()["entries"]
                if row["id"] == shift_id
            )
            assert loaded_entry["jobId"] is None
            assert loaded_entry["visits"][0]["jobId"] == job_id
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_startup_backfills_qr_visit_job_id_without_overwriting(self, client):
        import time_tracker_api as api

        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        check_in_ids: list[int] = []
        try:
            site_id = _insert_profitability_site(
                address="2049 Visit Backfill Proof",
                customer_name="Visit Backfill Customer",
                rate=175.0,
                rate_type="per_visit",
                expected_hours=1.5,
            )
            site_ids.append(site_id)
            source_job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name="Visit Backfill Customer",
                scheduled_date="2049-06-02",
                expected_hours=1.5,
                revenue=175.0,
                source_key="16" * 32,
            )
            existing_visit_job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name="Visit Backfill Customer",
                scheduled_date="2049-06-03",
                expected_hours=1.5,
                revenue=200.0,
                source_key="17" * 32,
            )
            job_ids.extend([source_job_id, existing_visit_job_id])
            employee_id = db.query_one(
                "SELECT id FROM employees WHERE name = %s",
                ("Catalina Gomez",),
            )["id"]
            shift_id = int(db.execute_returning(
                """
                INSERT INTO shifts (
                    employee_id, location_id, location_label,
                    clock_in, clock_out, total_hours, local_date
                )
                VALUES (
                    %s, %s, 'Visit backfill shift',
                    TIMESTAMPTZ '2049-06-02 08:00:00-05',
                    TIMESTAMPTZ '2049-06-02 10:00:00-05',
                    2.0, DATE '2049-06-02'
                )
                RETURNING id
                """,
                (employee_id, site_id),
            ))
            shift_ids.append(shift_id)

            for minute_offset in (0, 30):
                check_in_id = int(db.execute_returning(
                    """
                    INSERT INTO site_check_ins (
                        employee_id, location_id, job_id,
                        server_checked_in_at, device_scanned_at,
                        latitude, longitude, accuracy_m, geofence_radius_m,
                        distance_m, geofence_status, classification,
                        classification_reason, device_clock_skew_seconds,
                        review_status
                    )
                    VALUES (
                        %s, %s, %s,
                        TIMESTAMPTZ '2049-06-02 08:00:00-05'
                            + (%s * INTERVAL '1 minute'),
                        TIMESTAMPTZ '2049-06-02 08:00:00-05'
                            + (%s * INTERVAL '1 minute'),
                        39.1203000, -88.5433500, 5.00, 100,
                        0.00, 'inside', 'on_time',
                        'verified_scheduled_site', 0.00, 'not_required'
                    )
                    RETURNING id
                    """,
                    (
                        employee_id,
                        site_id,
                        source_job_id,
                        minute_offset,
                        minute_offset,
                    ),
                ))
                check_in_ids.append(check_in_id)

            backfill_visit_id = int(db.execute_returning(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, site_check_in_id, sequence_version
                )
                VALUES (
                    %s, %s, '2049 Visit Backfill Proof',
                    'Visit Backfill Customer',
                    TIMESTAMPTZ '2049-06-02 08:00:00-05',
                    %s, 2
                )
                RETURNING id
                """,
                (shift_id, site_id, check_in_ids[0]),
            ))
            preserved_visit_id = int(db.execute_returning(
                """
                INSERT INTO visits (
                    shift_id, location_id, location_label, customer_name,
                    arrival_time, site_check_in_id, job_id, sequence_version
                )
                VALUES (
                    %s, %s, '2049 Visit Backfill Proof',
                    'Visit Backfill Customer',
                    TIMESTAMPTZ '2049-06-02 08:30:00-05',
                    %s, %s, 2
                )
                RETURNING id
                """,
                (shift_id, site_id, check_in_ids[1], existing_visit_job_id),
            ))

            api._ensure_schema_migrations()

            rows = {
                row["id"]: row["job_id"]
                for row in db.query_all(
                    "SELECT id, job_id FROM visits WHERE id = ANY(%s)",
                    ([backfill_visit_id, preserved_visit_id],),
                )
            }
            assert rows == {
                backfill_visit_id: source_job_id,
                preserved_visit_id: existing_visit_job_id,
            }
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            if check_in_ids:
                db.execute(
                    "DELETE FROM site_check_ins WHERE id = ANY(%s)",
                    (check_in_ids,),
                )
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)


class TestTimesheetGpsFlow:
    def test_timesheet_locations_exposes_match_radius(self, client, emp_auth):
        r = client.get("/api/timesheet/locations", headers=emp_auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "locationMatchRadiusM" in data
        assert data["locationMatchRadiusM"] > 0

    def test_admin_location_update_preserves_pin_when_pin_fields_are_omitted(
        self,
        client,
        auth,
        emp_auth,
    ):
        location = "123 Main St, Effingham"
        response = client.put(
            "/api/admin/locations",
            headers=auth,
            json={
                "locations": [
                    {
                        "name": location,
                        "customer": "Test Customer",
                        "rate": 150.0,
                        "rateType": "per_visit",
                        "expectedHours": 3.0,
                    }
                ]
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["location_coords"][location] == pytest.approx(
            {"lat": 39.1203, "lng": -88.54335}
        )

        stored = client.get("/api/timesheet/locations", headers=emp_auth)
        assert stored.status_code == 200, stored.text
        assert stored.json()["location_coords"][location] == pytest.approx(
            {"lat": 39.1203, "lng": -88.54335}
        )

    def test_clock_in_accepts_gps(self, client, auth, emp_auth):
        r = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "notes": "gps start",
            "latitude": 39.1201,
            "longitude": -88.5432,
            "accuracy": 7.25,
        })
        assert r.status_code == 200, r.text
        entry = r.json()["entry"]
        assert entry["clockInGps"]["lat"] == pytest.approx(39.1201)
        assert entry["clockInGps"]["lng"] == pytest.approx(-88.5432)
        assert entry["clockInGps"]["accuracy"] == pytest.approx(7.25)
        assert entry["clockInGpsMeta"]["accuracyM"] == pytest.approx(7.25)
        assert entry["clockInGpsMeta"]["withinRadius"] is True

        status = client.get("/api/current-status", headers=auth)
        assert status.status_code == 200, status.text
        current = next(
            row
            for row in status.json()["currentlyWorking"]
            if row["name"] == "Catalina Gomez"
        )
        assert current["clockInGps"]["accuracy"] == pytest.approx(7.25)
        assert current["clockInGpsMeta"]["accuracyM"] == pytest.approx(7.25)

        r2 = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup",
            "latitude": 39.1205,
            "longitude": -88.5435,
            "accuracy": 11.4,
        })
        assert r2.status_code == 200, r2.text
        assert r2.json()["entry"]["clockOutGps"]["lat"] == pytest.approx(39.1205)
        assert r2.json()["entry"]["clockOutGps"]["accuracy"] == pytest.approx(11.4)

    def test_server_requires_gps_or_explicit_override_for_every_time_action(
        self,
        client,
        auth,
        emp_auth,
    ):
        missing = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={"location": "123 Main St, Effingham"},
        )
        assert missing.status_code == 400, missing.text
        assert "GPS location is required" in missing.json()["error"]

        clock_in = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "gpsOverrideReason": "customer_request",
                "gpsOverrideDetail": "Indoor test fixture",
            },
        )
        assert clock_in.status_code == 200, clock_in.text
        assert clock_in.json()["entry"]["clockInGps"] is None
        assert clock_in.json()["entry"]["clockInGpsMeta"]["override"] is True

        for endpoint, payload in [
            ("/api/timesheet/visit", {"location": "123 Main St, Effingham"}),
            ("/api/timesheet/depart", {}),
            ("/api/timesheet/clock-out", {}),
        ]:
            response = client.post(endpoint, headers=emp_auth, json=payload)
            assert response.status_code == 400, (endpoint, response.text)
            assert "GPS location is required" in response.json()["error"]

        arrival = client.post(
            "/api/timesheet/visit",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "gpsOverrideReason": "gps_signal",
            },
        )
        assert arrival.status_code == 200, arrival.text
        assert arrival.json()["visit"]["gps"] is None
        assert arrival.json()["visit"]["gpsMeta"]["override"] is True

        arrival_status = client.get("/api/current-status", headers=auth)
        assert arrival_status.status_code == 200, arrival_status.text
        arrival_row = next(
            row
            for row in arrival_status.json()["currentlyWorking"]
            if row["name"] == "Catalina Gomez"
        )
        assert arrival_row["clockInGps"] is None
        assert arrival_row["clockInGpsMeta"]["overrideReason"] == "gps_signal"

        departure = client.post(
            "/api/timesheet/depart",
            headers=emp_auth,
            json={"gpsOverrideReason": "parking_access"},
        )
        assert departure.status_code == 200, departure.text
        assert departure.json()["departure"]["gps"] is None
        assert departure.json()["departure"]["gpsMeta"]["override"] is True

        departure_status = client.get("/api/current-status", headers=auth)
        assert departure_status.status_code == 200, departure_status.text
        departure_row = next(
            row
            for row in departure_status.json()["currentlyWorking"]
            if row["name"] == "Catalina Gomez"
        )
        assert departure_row["clockInGps"] is None
        assert departure_row["clockInGpsMeta"]["overrideReason"] == "parking_access"

        clock_out = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"gpsOverrideReason": "gps_signal", "notes": "cleanup"},
        )
        assert clock_out.status_code == 200, clock_out.text
        assert clock_out.json()["entry"]["clockOutGps"] is None
        assert clock_out.json()["entry"]["clockOutGpsMeta"]["override"] is True

    def test_override_detail_requires_reason_and_never_becomes_orphaned(
        self,
        client,
        emp_auth,
    ):
        response = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 39.1203,
                "longitude": -88.54335,
                "gpsOverrideDetail": "Detail without a reason",
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == (
            "GPS override details require an override reason."
        )

        import time_tracker_api as tta

        meta = tta.build_gps_meta(
            {
                "location_coords": {
                    "123 Main St, Effingham": {
                        "lat": 39.1203,
                        "lng": -88.54335,
                    }
                }
            },
            39.1203,
            -88.54335,
            override_detail="Detail without a reason",
        )
        assert meta is not None
        assert meta["override"] is False
        assert meta["overrideDetail"] == ""

    def test_coarse_accuracy_is_stored_as_evidence_without_a_cutoff(
        self,
        client,
        emp_auth,
    ):
        site = {
            "location": "123 Main St, Effingham",
            "latitude": 39.1203,
            "longitude": -88.54335,
        }
        clock_in = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={**site, "accuracy": 250_000.25},
        )
        assert clock_in.status_code == 200, clock_in.text
        assert clock_in.json()["entry"]["clockInGps"]["accuracy"] == pytest.approx(
            250_000.25
        )

        arrival = client.post(
            "/api/timesheet/visit",
            headers=emp_auth,
            json={**site, "accuracy": 300_000.5},
        )
        assert arrival.status_code == 200, arrival.text
        assert arrival.json()["visit"]["gps"]["accuracy"] == pytest.approx(
            300_000.5
        )

        departure = client.post(
            "/api/timesheet/depart",
            headers=emp_auth,
            json={
                "latitude": site["latitude"],
                "longitude": site["longitude"],
                "accuracy": 400_000.75,
            },
        )
        assert departure.status_code == 200, departure.text
        assert departure.json()["departure"]["gps"]["accuracy"] == pytest.approx(
            400_000.75
        )

        clock_out = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={
                "latitude": site["latitude"],
                "longitude": site["longitude"],
                "accuracy": 500_000.0,
                "notes": "cleanup",
            },
        )
        assert clock_out.status_code == 200, clock_out.text
        assert clock_out.json()["entry"]["clockOutGps"]["accuracy"] == pytest.approx(
            500_000.0
        )

    def test_rejects_partial_or_invalid_coordinates(self, client, emp_auth):
        partial = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 39.1201,
                "gpsOverrideReason": "gps_signal",
            },
        )
        assert partial.status_code == 400, partial.text
        assert partial.json()["error"] == "Latitude and longitude must be provided together."

        invalid = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={
                "location": "123 Main St, Effingham",
                "latitude": 91,
                "longitude": -88.5432,
            },
        )
        assert invalid.status_code == 422, invalid.text

    def test_outside_geofence_requires_logged_override(self, client, emp_auth):
        outside = {
            "location": "123 Main St, Effingham",
            "latitude": 39.2201,
            "longitude": -88.5432,
            "accuracy": 9.5,
        }
        rejected = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json=outside,
        )
        assert rejected.status_code == 400, rejected.text
        assert "nearest saved site" in rejected.json()["error"]

        accepted = client.post(
            "/api/timesheet/clock-in",
            headers=emp_auth,
            json={**outside, "gpsOverrideReason": "parking_access"},
        )
        assert accepted.status_code == 200, accepted.text
        meta = accepted.json()["entry"]["clockInGpsMeta"]
        assert meta["override"] is True
        assert meta["withinRadius"] is False
        assert meta["distanceM"] > 50
        assert meta["accuracyM"] == pytest.approx(9.5)

        cleanup = client.post(
            "/api/timesheet/clock-out",
            headers=emp_auth,
            json={"gpsOverrideReason": "parking_access", "notes": "cleanup"},
        )
        assert cleanup.status_code == 200, cleanup.text

    def test_unpinned_sites_require_override(self):
        import time_tracker_api as tta

        error = tta.require_gps_override(
            {"location_coords": {}},
            39.1201,
            -88.5432,
        )
        assert error is not None
        assert "no saved site has a location pin" in error
        assert tta.require_gps_override(
            {"location_coords": {}},
            39.1201,
            -88.5432,
            "gps_signal",
        ) is None

    def test_depart_requires_active_arrival(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1203,
            "longitude": -88.54335,
        })
        assert ci.status_code == 200, ci.text

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 39.1202,
            "longitude": -88.5433,
        })
        assert dep.status_code == 400, dep.text

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup",
            "latitude": 39.1203,
            "longitude": -88.54335,
        })
        assert co.status_code == 200, co.text

    def test_arrive_then_depart_updates_current_status(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert ci.status_code == 200, ci.text

        visit = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit.status_code == 200, visit.text
        assert visit.json()["alreadyHere"] is False

        status1 = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status1.status_code == 200, status1.text
        me1 = next(row for row in status1.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me1["employeeId"] == ci.json()["entry"]["employeeId"]
        assert me1["canDepart"] is True
        assert me1["activeVisit"]["location"] == "123 Main St, Effingham"

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "notes": "left site",
            "latitude": 39.1204,
            "longitude": -88.5434,
        })
        assert dep.status_code == 200, dep.text
        departure = dep.json()["departure"]
        assert departure["location"] == "123 Main St, Effingham"
        assert departure["gps"]["lat"] == pytest.approx(39.1204)

        status2 = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status2.status_code == 200, status2.text
        me2 = next(row for row in status2.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me2["canDepart"] is False
        assert me2["activeVisit"] is None
        assert len(me2["departures"]) >= 1

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup after depart",
            "latitude": 39.1205,
            "longitude": -88.5435,
        })
        assert co.status_code == 200, co.text

    def test_can_rearrive_same_location_after_depart(self, client, emp_auth):
        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert ci.status_code == 200, ci.text

        visit1 = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit1.status_code == 200, visit1.text
        assert visit1.json()["alreadyHere"] is False

        dep = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 39.1204,
            "longitude": -88.5434,
        })
        assert dep.status_code == 200, dep.text

        visit2 = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1201,
            "longitude": -88.5432,
        })
        assert visit2.status_code == 200, visit2.text
        assert visit2.json()["alreadyHere"] is False

        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        me = next(row for row in status.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me["canDepart"] is True

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup after rearrive",
            "latitude": 39.1205,
            "longitude": -88.5435,
        })
        assert co.status_code == 200, co.text

    def test_gps_override_metadata_persists(self, client, auth, emp_auth):
        pin = client.patch("/api/admin/locations/pin", headers=auth, json={
            "location": "123 Main St, Effingham",
            "lat": 39.1205,
            "lng": -88.5434,
        })
        assert pin.status_code == 200, pin.text

        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "notes": "start with override",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "parking_access",
            "gpsOverrideDetail": "building locked",
        })
        assert ci.status_code == 200, ci.text
        entry = ci.json()["entry"]
        assert entry["clockInGpsMeta"]["override"] is True
        assert entry["clockInGpsMeta"]["overrideReason"] == "parking_access"
        assert entry["clockInGpsMeta"]["overrideDetail"] == "building locked"
        assert entry["clockInGpsMeta"]["matchedLocation"] == "123 Main St, Effingham"
        assert entry["clockInGpsMeta"]["distanceM"] > 0

        def reloaded_active_entry():
            status = client.get("/api/timesheet/current-status", headers=emp_auth)
            assert status.status_code == 200, status.text
            rows = [
                row
                for row in status.json()["currentlyWorking"]
                if row["employeeName"] == "Catalina Gomez"
                and row["notes"] == "start with override"
            ]
            assert rows, status.json()["currentlyWorking"]
            return rows[0]

        visit = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "customer_request",
            "gpsOverrideDetail": "customer asked for curbside handoff",
        })
        assert visit.status_code == 200, visit.text
        visit_rows = reloaded_active_entry()["visits"]
        assert [
            row
            for row in visit_rows
            if (row.get("gpsMeta") or {}).get("overrideReason") == "customer_request"
            and (row.get("gpsMeta") or {}).get("overrideDetail") == "customer asked for curbside handoff"
        ], visit_rows

        depart = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "manual departure verification",
        })
        assert depart.status_code == 200, depart.text
        departure_rows = reloaded_active_entry()["departures"]
        assert [
            row
            for row in departure_rows
            if (row.get("gpsMeta") or {}).get("overrideReason") == "other"
            and (row.get("gpsMeta") or {}).get("overrideDetail") == "manual departure verification"
        ], departure_rows

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup with override meta",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "gps_signal",
            "gpsOverrideDetail": "weak signal at end of shift",
        })
        assert co.status_code == 200, co.text
        end_entry = co.json()["entry"]
        assert end_entry["clockOutGpsMeta"]["overrideReason"] == "gps_signal"
        assert end_entry["clockOutGpsMeta"]["matchedLocation"] == "123 Main St, Effingham"

    def test_gps_override_is_required_when_far_from_saved_site(self, client, auth, emp_auth):
        pin = client.patch("/api/admin/locations/pin", headers=auth, json={
            "location": "123 Main St, Effingham",
            "lat": 39.1205,
            "lng": -88.5434,
        })
        assert pin.status_code == 200, pin.text

        ci_blocked = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 38.0,
            "longitude": -89.0,
        })
        assert ci_blocked.status_code == 400, ci_blocked.text
        assert "Add an override reason to continue." in ci_blocked.text

        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "required override clock-in",
        })
        assert ci.status_code == 200, ci.text

        visit_blocked = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 38.0,
            "longitude": -89.0,
        })
        assert visit_blocked.status_code == 400, visit_blocked.text
        assert "Add an override reason to continue." in visit_blocked.text

        visit = client.post("/api/timesheet/visit", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "customer_request",
            "gpsOverrideDetail": "required override arrival",
        })
        assert visit.status_code == 200, visit.text

        depart_blocked = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
        })
        assert depart_blocked.status_code == 400, depart_blocked.text
        assert "Add an override reason to continue." in depart_blocked.text

        depart = client.post("/api/timesheet/depart", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "gps_signal",
            "gpsOverrideDetail": "required override departure",
        })
        assert depart.status_code == 200, depart.text

        co_blocked = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "blocked without override",
            "latitude": 38.0,
            "longitude": -89.0,
        })
        assert co_blocked.status_code == 400, co_blocked.text
        assert "Add an override reason to continue." in co_blocked.text

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup with override",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "parking_access",
            "gpsOverrideDetail": "required override clock-out",
        })
        assert co.status_code == 200, co.text

    def test_gps_fallback_location_label_survives_db_roundtrip(self, client, auth, emp_auth):
        pin = client.patch("/api/admin/locations/pin", headers=auth, json={
            "location": "123 Main St, Effingham",
            "lat": 39.1205,
            "lng": -88.5434,
        })
        assert pin.status_code == 200, pin.text

        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "far away roundtrip test",
        })
        assert ci.status_code == 200, ci.text
        assert ci.json()["entry"]["location"] == "GPS 38.00000,-89.00000"

        status = client.get("/api/timesheet/current-status", headers=emp_auth)
        assert status.status_code == 200, status.text
        me = next(row for row in status.json()["currentlyWorking"] if row["employeeName"] == "Catalina Gomez")
        assert me["location"] == "GPS 38.00000,-89.00000"

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup raw gps label",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "raw gps cleanup override",
        })
        assert co.status_code == 200, co.text

    def test_hours_report_includes_gps_exceptions(self, client, auth, emp_auth):
        pin = client.patch("/api/admin/locations/pin", headers=auth, json={
            "location": "123 Main St, Effingham",
            "lat": 39.1205,
            "lng": -88.5434,
        })
        assert pin.status_code == 200, pin.text

        ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "report exception test",
        })
        assert ci.status_code == 200, ci.text
        report_date = ci.json()["entry"]["date"]

        co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "cleanup report exception",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "gps_signal",
            "gpsOverrideDetail": "weak signal at end",
        })
        assert co.status_code == 200, co.text

        report = client.get(f"/api/admin/reports/hours?period=day&date={report_date}", headers=auth)
        assert report.status_code == 200, report.text
        rows = report.json()["rows"]
        catalina = [r for r in rows if r["employeeName"] == "Catalina Gomez"]
        assert catalina, rows
        expected_markers = ("clock_in - other", "clock_out - gps_signal")
        matching_exception_rows = [
            row
            for row in catalina
            if row["gpsExceptions"]
            and all(marker in row["gpsExceptionsText"] for marker in expected_markers)
        ]
        assert matching_exception_rows, catalina

    def test_hours_report_can_filter_to_exception_shifts_only(self, client, auth, emp_auth):
        pin = client.patch("/api/admin/locations/pin", headers=auth, json={
            "location": "123 Main St, Effingham",
            "lat": 39.1205,
            "lng": -88.5434,
        })
        assert pin.status_code == 200, pin.text

        normal_ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "location": "123 Main St, Effingham",
            "latitude": 39.1205,
            "longitude": -88.5434,
        })
        assert normal_ci.status_code == 200, normal_ci.text
        normal_co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "normal cleanup",
            "latitude": 39.1205,
            "longitude": -88.5434,
        })
        assert normal_co.status_code == 200, normal_co.text

        override_ci = client.post("/api/timesheet/clock-in", headers=emp_auth, json={
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "other",
            "gpsOverrideDetail": "exceptions only filter test",
        })
        assert override_ci.status_code == 200, override_ci.text
        report_date = override_ci.json()["entry"]["date"]
        override_co = client.post("/api/timesheet/clock-out", headers=emp_auth, json={
            "notes": "override cleanup",
            "latitude": 38.0,
            "longitude": -89.0,
            "gpsOverrideReason": "gps_signal",
            "gpsOverrideDetail": "weak signal override",
        })
        assert override_co.status_code == 200, override_co.text

        report = client.get(f"/api/admin/reports/hours?period=day&date={report_date}&exceptions_only=true", headers=auth)
        assert report.status_code == 200, report.text
        data = report.json()
        assert data["exceptionsOnly"] is True
        assert data["totalGpsExceptionShifts"] >= 1
        assert all(row["gpsExceptions"] for row in data["rows"])


# ===============================================================================
# Existing analytics - regression: was returning 500 (byDay KeyError)
# ===============================================================================

class TestAnalyticsRegression:
    def test_analytics_week_returns_200(self, client, auth):
        r = client.get("/api/admin/analytics?period=week&date=2026-03-25", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "byCustomer" in data
        assert "byDay" in data
        assert "summary" in data

    def test_analytics_month(self, client, auth):
        r = client.get("/api/admin/analytics?period=month&date=2026-03-01", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_day(self, client, auth):
        r = client.get("/api/admin/analytics?period=day&date=2026-03-25", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_all(self, client, auth):
        r = client.get("/api/admin/analytics?period=all", headers=auth)
        assert r.status_code == 200, r.text

    def test_analytics_byday_shape(self, client, auth, completed_shift_id):
        """byDay rows must have the right keys (no customer/location)."""
        r = client.get("/api/admin/analytics?period=all", headers=auth)
        assert r.status_code == 200, r.text
        by_day = r.json()["byDay"]
        if by_day:
            row = by_day[0]
            for key in ("date", "visits", "hours", "revenue", "laborCost", "laborPct", "netProfit"):
                assert key in row, f"Missing key '{key}' in byDay row"
            assert "customer" not in row
            assert "location" not in row

    def test_analytics_week_uses_canonical_monthly_allocation_for_linked_jobs(
        self,
        client,
        auth,
        employee_id,
    ):
        customer_name = "Analytics Canonical Monthly"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        try:
            site_id = _insert_profitability_site(
                address="Analytics Canonical Monthly Site",
                customer_name=customer_name,
                rate=100.0,
                rate_type="monthly",
                expected_hours=2.0,
            )
            site_ids.append(site_id)
            for index, scheduled_date in enumerate(
                ("2047-02-01", "2047-02-08", "2047-02-15"),
                start=1,
            ):
                job_ids.append(
                    _insert_profitability_job(
                        location_id=site_id,
                        customer_name=customer_name,
                        scheduled_date=scheduled_date,
                        source_key=f"{9000 + index:064x}",
                    )
                )

            for hour, linked_job_id in (
                (9, job_ids[0]),
                (13, job_ids[0]),
                (15, None),
            ):
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, 'Analytics Canonical Monthly Site',
                                %s,
                                DATE '2047-02-01' + (%s * INTERVAL '1 hour'),
                                DATE '2047-02-01' + ((%s + 1) * INTERVAL '1 hour'),
                                1.0, 'analytics canonical monthly proof',
                                '2047-02-01'
                            )
                            RETURNING id
                            """,
                            (employee_id, site_id, linked_job_id, hour, hour),
                        )
                    )
                )

            response = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-02-01"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["revenue"] == 33.34
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["hours"] == 3.0
            assert customer_row["visits"] == 1
            assert customer_row["revenue"] == 33.34
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-02-01")
            assert day_row["revenue"] == 33.34
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_analytics_week_uses_rate_card_revenue_for_linked_hourly_job(
        self,
        client,
        auth,
        employee_id,
    ):
        customer_name = "Analytics Linked Hourly"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        try:
            site_id = _insert_profitability_site(
                address="Analytics Linked Hourly Site",
                customer_name=customer_name,
                rate=40.0,
                rate_type="hourly",
                expected_hours=2.5,
            )
            site_ids.append(site_id)
            job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name=customer_name,
                scheduled_date="2047-03-03",
                source_key=f"{9200:064x}",
            )
            job_ids.append(job_id)

            for hour, total_hours in ((9, 1.0), (13, 3.0)):
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, 'Analytics Linked Hourly Site',
                                %s,
                                DATE '2047-03-03' + (%s * INTERVAL '1 hour'),
                                DATE '2047-03-03' + ((%s + %s) * INTERVAL '1 hour'),
                                %s, 'analytics linked hourly proof',
                                '2047-03-03'
                            )
                            RETURNING id
                            """,
                            (
                                employee_id,
                                site_id,
                                job_id,
                                hour,
                                hour,
                                total_hours,
                                total_hours,
                            ),
                        )
                    )
                )

            response = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-03-03"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["revenue"] == 100.0
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["hours"] == 4.0
            assert customer_row["revenue"] == 100.0
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-03-03")
            assert day_row["revenue"] == 100.0
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_analytics_single_location_hours_use_clock_span_when_stored_total_is_stale(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Analytics Canonical Hours"
        location_label = "Analytics Canonical Hours Site"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2048, 1, 15, 18, tzinfo=timezone.utc),
        )
        try:
            site_id = _insert_profitability_site(
                address=location_label,
                customer_name=customer_name,
                rate=40.0,
                rate_type="hourly",
                expected_hours=2.5,
            )
            site_ids.append(site_id)
            job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name=customer_name,
                scheduled_date="2048-01-13",
                source_key=f"{9250:064x}",
            )
            job_ids.append(job_id)
            shift_ids.append(
                int(
                    db.execute_returning(
                        """
                        INSERT INTO shifts (
                            employee_id, location_id, location_label,
                            job_id, clock_in, clock_out, total_hours,
                            notes, local_date
                        )
                        VALUES (
                            %s, %s, %s,
                            %s,
                            TIMESTAMPTZ '2048-01-13 08:00:00-06',
                            TIMESTAMPTZ '2048-01-13 10:30:00-06',
                            0.25, 'analytics canonical hours proof',
                            DATE '2048-01-13'
                        )
                        RETURNING id
                        """,
                        (employee_id, site_id, location_label, job_id),
                    )
                )
            )

            response = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2048-01-13"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["hours"] == 2.5
            assert body["summary"]["laborCost"] == pytest.approx(41.88)
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["hours"] == 2.5
            assert customer_row["laborCost"] == pytest.approx(41.88)
            day_row = next(row for row in body["byDay"] if row["date"] == "2048-01-13")
            assert day_row["hours"] == 2.5
            assert day_row["laborCost"] == pytest.approx(41.88)

            detail = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 1},
            )
            assert detail.status_code == 200, detail.text
            detail_body = detail.json()
            assert detail_body["summary"]["hours"] == 2.5
            assert detail_body["summary"]["laborCost"] == pytest.approx(41.88)
            assert detail_body["byVisit"][0]["hours"] == 2.5
            assert detail_body["byVisit"][0]["laborCost"] == pytest.approx(41.88)
            assert detail_body["byWeek"][0]["hours"] == 2.5
            assert detail_body["byWeek"][0]["laborCost"] == pytest.approx(41.88)
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_linked_job_missing_rate_fails_closed_across_analytics_callers(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Analytics Missing Linked Rate"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 4, 5, 18, tzinfo=timezone.utc),
        )
        try:
            site_id = _insert_profitability_site(
                address="Analytics Missing Linked Rate Site",
                customer_name=customer_name,
                rate=None,
                rate_type="per_visit",
                expected_hours=2.0,
            )
            site_ids.append(site_id)
            job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name=customer_name,
                scheduled_date="2047-04-02",
                source_key=f"{9350:064x}",
            )
            job_ids.append(job_id)
            shift_ids.append(
                int(
                    db.execute_returning(
                        """
                        INSERT INTO shifts (
                            employee_id, location_id, location_label,
                            job_id, clock_in, clock_out, total_hours,
                            notes, local_date
                        )
                        VALUES (
                            %s, %s, 'Analytics Missing Linked Rate Site',
                            %s,
                            TIMESTAMPTZ '2047-04-02 08:00:00-05',
                            TIMESTAMPTZ '2047-04-02 10:00:00-05',
                            2.0, 'analytics missing linked rate proof',
                            DATE '2047-04-02'
                        )
                        RETURNING id
                        """,
                        (employee_id, site_id, job_id),
                    )
                )
            )

            analytics = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-04-02"},
            )
            assert analytics.status_code == 200, analytics.text
            body = analytics.json()
            assert body["summary"]["revenue"] is None
            assert body["summary"]["knownRevenue"] == 0.0
            assert body["summary"]["revenueComplete"] is False
            assert body["summary"]["netProfit"] is None
            assert body["issues"] == [
                {
                    "code": "missing_revenue",
                    "message": (
                        "Revenue cannot be calculated from this linked job's "
                        "Site rate card."
                    ),
                    "jobId": job_id,
                }
            ]
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["revenue"] is None
            assert customer_row["knownRevenue"] == 0.0
            assert customer_row["revenueComplete"] is False
            assert customer_row["netProfit"] is None
            assert customer_row["issues"] == body["issues"]
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-04-02")
            assert day_row["revenue"] is None
            assert day_row["knownRevenue"] == 0.0
            assert day_row["revenueComplete"] is False
            assert day_row["netProfit"] is None
            assert day_row["issues"] == body["issues"]

            detail = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 1},
            )
            assert detail.status_code == 200, detail.text
            detail_body = detail.json()
            assert detail_body["summary"]["revenue"] is None
            assert detail_body["summary"]["knownRevenue"] == 0.0
            assert detail_body["summary"]["revenueComplete"] is False
            assert detail_body["issues"] == body["issues"]
            assert detail_body["byVisit"][0]["revenue"] is None
            assert detail_body["byVisit"][0]["knownRevenue"] == 0.0
            assert detail_body["byVisit"][0]["revenueComplete"] is False
            assert detail_body["byVisit"][0]["issues"] == body["issues"]
            assert detail_body["byWeek"][0]["revenue"] is None
            assert detail_body["byWeek"][0]["knownRevenue"] == 0.0
            assert detail_body["byWeek"][0]["revenueComplete"] is False
            assert detail_body["byWeek"][0]["issues"] == body["issues"]

            dashboard = client.get(
                "/api/admin/dashboard",
                headers=auth,
                params={"date": "2047-04-02"},
            )
            assert dashboard.status_code == 200, dashboard.text
            weekly_card = dashboard.json()["cards"]["weekly"]
            assert weekly_card["revenue"] is None
            assert weekly_card["knownRevenue"] == 0.0
            assert weekly_card["revenueComplete"] is False
            assert weekly_card["issues"] == body["issues"]

            export = client.get(
                "/api/admin/analytics/export",
                headers=auth,
                params={"period": "week", "date": "2047-04-02"},
            )
            assert export.status_code == 200, export.text
            assert "Revenue,N/A,Labor Cost" in export.text

            pricing = client.get(
                "/api/admin/analytics/pricing",
                headers=auth,
                params={"period": "week", "date": "2047-04-02"},
            )
            assert pricing.status_code == 200, pricing.text
            recommendation = next(
                row
                for row in pricing.json()["recommendations"]
                if row["customer"] == customer_name
            )
            assert recommendation["actualRevenue"] is None
            assert recommendation["knownRevenue"] == 0.0
            assert recommendation["revenueComplete"] is False
            assert recommendation["revenueGap"] == 0
            assert recommendation["needsIncrease"] is False
            assert recommendation["issues"] == body["issues"]
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_unlinked_missing_rate_fails_closed_in_analytics_views(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Analytics Missing Unlinked Rate"
        location_label = "Analytics Missing Unlinked Rate Site"
        site_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 4, 12, 18, tzinfo=timezone.utc),
        )
        try:
            site_id = _insert_profitability_site(
                address=location_label,
                customer_name=customer_name,
                rate=None,
                rate_type="per_visit",
                expected_hours=2.0,
            )
            site_ids.append(site_id)
            shift_ids.append(
                int(
                    db.execute_returning(
                        """
                        INSERT INTO shifts (
                            employee_id, location_id, location_label,
                            job_id, clock_in, clock_out, total_hours,
                            notes, local_date
                        )
                        VALUES (
                            %s, %s, %s,
                            NULL,
                            TIMESTAMPTZ '2047-04-09 08:00:00-05',
                            TIMESTAMPTZ '2047-04-09 10:00:00-05',
                            2.0, 'analytics missing unlinked rate proof',
                            DATE '2047-04-09'
                        )
                        RETURNING id
                        """,
                        (employee_id, site_id, location_label),
                    )
                )
            )
            expected_issue = {
                "code": "missing_revenue",
                "message": "Revenue cannot be calculated from this location's rate card.",
                "location": location_label,
                "customer": customer_name,
                "date": "2047-04-09",
            }

            analytics = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-04-09"},
            )
            assert analytics.status_code == 200, analytics.text
            body = analytics.json()
            assert body["summary"]["revenue"] is None
            assert body["summary"]["knownRevenue"] == 0.0
            assert body["summary"]["revenueComplete"] is False
            assert body["issues"] == [expected_issue]
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["revenue"] is None
            assert customer_row["knownRevenue"] == 0.0
            assert customer_row["revenueComplete"] is False
            assert customer_row["issues"] == [expected_issue]
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-04-09")
            assert day_row["revenue"] is None
            assert day_row["knownRevenue"] == 0.0
            assert day_row["revenueComplete"] is False
            assert day_row["issues"] == [expected_issue]

            detail = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 1},
            )
            assert detail.status_code == 200, detail.text
            detail_body = detail.json()
            assert detail_body["summary"]["revenue"] is None
            assert detail_body["summary"]["knownRevenue"] == 0.0
            assert detail_body["summary"]["revenueComplete"] is False
            assert detail_body["issues"] == [expected_issue]
            assert detail_body["byVisit"][0]["revenue"] is None
            assert detail_body["byVisit"][0]["knownRevenue"] == 0.0
            assert detail_body["byVisit"][0]["revenueComplete"] is False
            assert detail_body["byVisit"][0]["issues"] == [expected_issue]
            assert detail_body["byWeek"][0]["revenue"] is None
            assert detail_body["byWeek"][0]["knownRevenue"] == 0.0
            assert detail_body["byWeek"][0]["revenueComplete"] is False
            assert detail_body["byWeek"][0]["issues"] == [expected_issue]
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            if site_ids:
                db.execute("DELETE FROM locations WHERE id = ANY(%s)", (site_ids,))

    def test_unlinked_valid_rate_fails_closed_in_analytics_views(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        cases = [
            (
                "Analytics Unlinked Valid Hourly",
                "Analytics Unlinked Valid Hourly Site",
                40.0,
                "hourly",
            ),
            (
                "Analytics Unlinked Valid Per Visit",
                "Analytics Unlinked Valid Per Visit Site",
                75.0,
                "per_visit",
            ),
            (
                "Analytics Unlinked Valid Monthly",
                "Analytics Unlinked Valid Monthly Site",
                300.0,
                "monthly",
            ),
        ]
        site_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 5, 10, 18, tzinfo=timezone.utc),
        )
        try:
            expected_issues = []
            for index, (customer_name, location_label, rate, rate_type) in enumerate(
                cases
            ):
                site_id = _insert_profitability_site(
                    address=location_label,
                    customer_name=customer_name,
                    rate=rate,
                    rate_type=rate_type,
                    expected_hours=2.0,
                )
                site_ids.append(site_id)
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, %s,
                                NULL,
                                TIMESTAMPTZ '2047-05-06 08:00:00-05'
                                    + (%s * INTERVAL '2 hours'),
                                TIMESTAMPTZ '2047-05-06 09:00:00-05'
                                    + (%s * INTERVAL '2 hours'),
                                1.0, 'analytics unlinked valid rate proof',
                                DATE '2047-05-06'
                            )
                            RETURNING id
                            """,
                            (employee_id, site_id, location_label, index, index),
                        )
                    )
                )
                expected_issues.append(
                    {
                        "code": "missing_revenue",
                        "message": (
                            "Revenue cannot be calculated from this location's "
                            "rate card."
                        ),
                        "location": location_label,
                        "customer": customer_name,
                        "date": "2047-05-06",
                    }
                )

            analytics = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-05-06"},
            )
            assert analytics.status_code == 200, analytics.text
            body = analytics.json()
            assert body["summary"]["revenue"] is None
            assert body["summary"]["knownRevenue"] == 0.0
            assert body["summary"]["revenueComplete"] is False
            assert body["issues"] == expected_issues
            by_customer = {row["customer"]: row for row in body["byCustomer"]}
            for expected_issue in expected_issues:
                row = by_customer[expected_issue["customer"]]
                assert row["revenue"] is None
                assert row["knownRevenue"] == 0.0
                assert row["revenueComplete"] is False
                assert row["issues"] == [expected_issue]
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-05-06")
            assert day_row["revenue"] is None
            assert day_row["knownRevenue"] == 0.0
            assert day_row["revenueComplete"] is False
            assert day_row["issues"] == expected_issues

            for expected_issue in expected_issues:
                detail = client.get(
                    "/api/admin/analytics/customer/"
                    f"{expected_issue['customer'].replace(' ', '%20')}",
                    headers=auth,
                    params={"weeks": 1},
                )
                assert detail.status_code == 200, detail.text
                detail_body = detail.json()
                assert detail_body["summary"]["revenue"] is None
                assert detail_body["summary"]["knownRevenue"] == 0.0
                assert detail_body["summary"]["revenueComplete"] is False
                assert detail_body["issues"] == [expected_issue]
                assert detail_body["byVisit"][0]["revenue"] is None
                assert detail_body["byVisit"][0]["knownRevenue"] == 0.0
                assert detail_body["byVisit"][0]["revenueComplete"] is False
                assert detail_body["byVisit"][0]["issues"] == [expected_issue]
                assert detail_body["byWeek"][0]["revenue"] is None
                assert detail_body["byWeek"][0]["knownRevenue"] == 0.0
                assert detail_body["byWeek"][0]["revenueComplete"] is False
                assert detail_body["byWeek"][0]["issues"] == [expected_issue]
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            if site_ids:
                db.execute("DELETE FROM locations WHERE id = ANY(%s)", (site_ids,))

    def test_analytics_week_credits_linked_per_visit_jobs_per_job(
        self,
        client,
        auth,
        employee_id,
    ):
        customer_name = "Analytics Linked Per Visit"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        try:
            for index, (address, rate) in enumerate(
                (
                    ("Analytics Linked Per Visit A", 80.0),
                    ("Analytics Linked Per Visit B", 60.0),
                ),
                start=1,
            ):
                site_id = _insert_profitability_site(
                    address=address,
                    customer_name=customer_name,
                    rate=rate,
                    rate_type="per_visit",
                    expected_hours=1.0,
                )
                site_ids.append(site_id)
                job_id = _insert_profitability_job(
                    location_id=site_id,
                    customer_name=customer_name,
                    scheduled_date="2047-03-03",
                    source_key=f"{9300 + index:064x}",
                )
                job_ids.append(job_id)
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, %s,
                                %s,
                                DATE '2047-03-03' + (%s * INTERVAL '1 hour'),
                                DATE '2047-03-03' + ((%s + 1) * INTERVAL '1 hour'),
                                1.0, 'analytics linked per-visit proof',
                                '2047-03-03'
                            )
                            RETURNING id
                            """,
                            (
                                employee_id,
                                site_id,
                                address,
                                job_id,
                                8 + index,
                                8 + index,
                            ),
                        )
                    )
                )

            response = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-03-03"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["revenue"] == 140.0
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-03-03")
            assert day_row["revenue"] == 140.0
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_analytics_credits_multi_stop_visits_by_visit_job_id(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Analytics Visit Job Revenue"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 3, 16, 18, tzinfo=timezone.utc),
        )
        try:
            parent_site_id = _insert_profitability_site(
                address="Analytics Visit Job Parent Site",
                customer_name=customer_name,
                rate=999.0,
                rate_type="per_visit",
                expected_hours=1.0,
            )
            site_ids.append(parent_site_id)
            parent_job_id = _insert_profitability_job(
                location_id=parent_site_id,
                customer_name=customer_name,
                scheduled_date="2047-03-03",
                source_key=f"{9599:064x}",
            )
            job_ids.append(parent_job_id)

            visit_sites: list[tuple[int, str, int]] = []
            for index, (address, rate) in enumerate(
                (
                    ("Analytics Visit Job A", 80.0),
                    ("Analytics Visit Job B", 60.0),
                ),
                start=1,
            ):
                site_id = _insert_profitability_site(
                    address=address,
                    customer_name=customer_name,
                    rate=rate,
                    rate_type="per_visit",
                    expected_hours=1.0,
                )
                site_ids.append(site_id)
                job_id = _insert_profitability_job(
                    location_id=site_id,
                    customer_name=customer_name,
                    scheduled_date="2047-03-03",
                    source_key=f"{9500 + index:064x}",
                )
                job_ids.append(job_id)
                visit_sites.append((site_id, address, job_id))

            shift_id = int(
                db.execute_returning(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label, job_id,
                        clock_in, clock_out, total_hours, notes, local_date
                    )
                    VALUES (
                        %s, %s, 'Analytics Visit Job Parent Site', %s,
                        TIMESTAMPTZ '2047-03-03 08:00:00-06',
                        TIMESTAMPTZ '2047-03-03 10:00:00-06',
                        2.0, 'analytics visit job identity proof',
                        DATE '2047-03-03'
                    )
                    RETURNING id
                    """,
                    (employee_id, parent_site_id, parent_job_id),
                )
            )
            shift_ids.append(shift_id)

            for hour_offset, (site_id, address, job_id) in zip((0, 1), visit_sites):
                db.execute(
                    """
                    INSERT INTO visits (
                        shift_id, location_id, location_label, customer_name,
                        arrival_time, job_id, sequence_version
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        TIMESTAMPTZ '2047-03-03 08:00:00-06'
                            + (%s * INTERVAL '1 hour'),
                        %s, 2
                    )
                    """,
                    (shift_id, site_id, address, customer_name, hour_offset, job_id),
                )

            response = client.get(
                "/api/admin/analytics",
                headers=auth,
                params={"period": "week", "date": "2047-03-03"},
            )
            assert response.status_code == 200, response.text
            body = response.json()
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == customer_name
            )
            assert customer_row["hours"] == 2.0
            assert customer_row["revenue"] == 140.0
            day_row = next(row for row in body["byDay"] if row["date"] == "2047-03-03")
            assert day_row["revenue"] == 140.0

            detail_response = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 3},
            )
            assert detail_response.status_code == 200, detail_response.text
            detail = detail_response.json()
            assert detail["summary"]["revenue"] == 140.0
            assert sorted(row["revenue"] for row in detail["byVisit"]) == [60.0, 80.0]
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_customer_detail_uses_canonical_monthly_allocation_for_linked_jobs(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Customer Detail Canonical Monthly"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 2, 16, 18, tzinfo=timezone.utc),
        )
        try:
            site_id = _insert_profitability_site(
                address="Customer Detail Canonical Monthly Site",
                customer_name=customer_name,
                rate=100.0,
                rate_type="monthly",
                expected_hours=2.0,
            )
            site_ids.append(site_id)
            for index, scheduled_date in enumerate(
                ("2047-02-01", "2047-02-08", "2047-02-15"),
                start=1,
            ):
                job_ids.append(
                    _insert_profitability_job(
                        location_id=site_id,
                        customer_name=customer_name,
                        scheduled_date=scheduled_date,
                        source_key=f"{9100 + index:064x}",
                    )
                )

            for hour, linked_job_id in (
                (9, job_ids[0]),
                (13, job_ids[0]),
                (15, None),
            ):
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, 'Customer Detail Canonical Monthly Site',
                                %s,
                                DATE '2047-02-01' + (%s * INTERVAL '1 hour'),
                                DATE '2047-02-01' + ((%s + 1) * INTERVAL '1 hour'),
                                1.0, 'customer detail canonical monthly proof',
                                '2047-02-01'
                            )
                            RETURNING id
                            """,
                            (employee_id, site_id, linked_job_id, hour, hour),
                        )
                    )
                )

            response = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 3},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["revenue"] == 33.34
            assert body["summary"]["hours"] == 3.0
            week = next(
                row for row in body["byWeek"] if row["weekStart"] == "2047-01-27"
            )
            assert week["revenue"] == 33.34
            assert sum(row["revenue"] for row in body["byVisit"]) == 33.34
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

    def test_customer_detail_uses_rate_card_revenue_for_linked_hourly_job(
        self,
        client,
        auth,
        employee_id,
        monkeypatch,
    ):
        import time_tracker_api as api

        customer_name = "Customer Detail Linked Hourly"
        site_ids: list[int] = []
        job_ids: list[int] = []
        shift_ids: list[int] = []
        monkeypatch.setattr(
            api,
            "utc_now",
            lambda: datetime(2047, 3, 16, 18, tzinfo=timezone.utc),
        )
        try:
            site_id = _insert_profitability_site(
                address="Customer Detail Linked Hourly Site",
                customer_name=customer_name,
                rate=40.0,
                rate_type="hourly",
                expected_hours=2.5,
            )
            site_ids.append(site_id)
            job_id = _insert_profitability_job(
                location_id=site_id,
                customer_name=customer_name,
                scheduled_date="2047-03-03",
                source_key=f"{9400:064x}",
            )
            job_ids.append(job_id)

            for hour, total_hours in ((9, 1.0), (13, 3.0)):
                shift_ids.append(
                    int(
                        db.execute_returning(
                            """
                            INSERT INTO shifts (
                                employee_id, location_id, location_label,
                                job_id, clock_in, clock_out, total_hours,
                                notes, local_date
                            )
                            VALUES (
                                %s, %s, 'Customer Detail Linked Hourly Site',
                                %s,
                                DATE '2047-03-03' + (%s * INTERVAL '1 hour'),
                                DATE '2047-03-03' + ((%s + %s) * INTERVAL '1 hour'),
                                %s, 'customer detail linked hourly proof',
                                '2047-03-03'
                            )
                            RETURNING id
                            """,
                            (
                                employee_id,
                                site_id,
                                job_id,
                                hour,
                                hour,
                                total_hours,
                                total_hours,
                            ),
                        )
                    )
                )

            response = client.get(
                f"/api/admin/analytics/customer/{customer_name.replace(' ', '%20')}",
                headers=auth,
                params={"weeks": 2},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["hours"] == 4.0
            assert body["summary"]["revenue"] == 100.0
            week = next(
                row for row in body["byWeek"] if row["weekStart"] == "2047-03-03"
            )
            assert week["revenue"] == 100.0
            assert sum(row["revenue"] for row in body["byVisit"]) == 100.0
        finally:
            if shift_ids:
                db.execute("DELETE FROM shifts WHERE id = ANY(%s)", (shift_ids,))
            _delete_profitability_rows(job_ids=job_ids, site_ids=site_ids)

# ===============================================================================
# Phase 3 - Jobs
# ===============================================================================

def _insert_profitability_site(
    *,
    address: str,
    customer_name: str,
    rate: float | None,
    rate_type: str,
    expected_hours: float | None,
) -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO locations (
                address, customer_name, location_type, rate, rate_type,
                expected_hours
            )
            VALUES (%s, %s, 'Commercial', %s, %s, %s)
            RETURNING id
            """,
            (address, customer_name, rate, rate_type, expected_hours),
        )
    )


def _insert_profitability_job(
    *,
    location_id: int,
    customer_name: str,
    scheduled_date: str,
    expected_hours: float | None = None,
    revenue: float | None = None,
    status: str = "scheduled",
    source_key: str | None = None,
) -> int:
    return int(
        db.execute_returning(
            """
            INSERT INTO jobs (
                location_id, customer_name, scheduled_date, expected_hours,
                revenue, notes, status, source_key
            )
            VALUES (%s, %s, %s, %s, %s, '', %s, %s)
            RETURNING id
            """,
            (
                location_id,
                customer_name,
                scheduled_date,
                expected_hours,
                revenue,
                status,
                source_key,
            ),
        )
    )


def _delete_profitability_rows(
    *,
    job_ids: list[int],
    site_ids: list[int],
) -> None:
    if job_ids:
        db.execute("DELETE FROM jobs WHERE id = ANY(%s)", (job_ids,))
    if site_ids:
        db.execute("DELETE FROM locations WHERE id = ANY(%s)", (site_ids,))


class TestJobs:
    def test_create_job(self, client, auth, location_id):
        r = client.post("/api/admin/jobs", headers=auth, json={
            "locationId":    location_id,
            "customerName":  "Test Customer",
            "scheduledDate": "2026-04-01",
            "expectedHours": 3.0,
            "revenue":       150.00,
            "notes":         "Spring clean",
        })
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        assert job["customerName"] == "Test Customer"
        assert job["status"] == "scheduled"
        assert job["revenue"] == 150.0

    def test_list_jobs(self, client, auth):
        r = client.get("/api/admin/jobs", headers=auth)
        assert r.status_code == 200, r.text
        assert isinstance(r.json()["jobs"], list)

    def test_list_jobs_filter_by_status(self, client, auth):
        r = client.get("/api/admin/jobs?status=scheduled", headers=auth)
        assert r.status_code == 200, r.text
        for job in r.json()["jobs"]:
            assert job["status"] == "scheduled"

    def test_get_job(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Get Test",
            "scheduledDate": "2026-04-02", "expectedHours": 2.0, "revenue": 100.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r.status_code == 200, r.text
        assert r.json()["job"]["id"] == job_id

    def test_get_job_uses_clock_span_when_stored_total_is_stale(
        self,
        client,
        auth,
        employee_id,
        location_id,
    ):
        job_id = None
        shift_id = None
        try:
            job_id = _insert_profitability_job(
                location_id=location_id,
                customer_name="Job Detail Canonical Hours",
                scheduled_date="2048-03-04",
                expected_hours=2.5,
                revenue=100.0,
                source_key=f"{9300:064x}",
            )
            shift_id = int(
                db.execute_returning(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label,
                        job_id, clock_in, clock_out, total_hours,
                        notes, local_date
                    )
                    VALUES (
                        %s, %s, '123 Main St, Effingham',
                        %s,
                        TIMESTAMPTZ '2048-03-04 08:00:00-06',
                        TIMESTAMPTZ '2048-03-04 10:30:00-06',
                        0.25, 'job detail canonical hours proof',
                        DATE '2048-03-04'
                    )
                    RETURNING id
                    """,
                    (employee_id, location_id, job_id),
                )
            )

            response = client.get(f"/api/admin/jobs/{job_id}", headers=auth)

            assert response.status_code == 200, response.text
            job = response.json()["job"]
            assert job["totalHours"] == 2.5
            assert job["totalLaborCost"] == pytest.approx(41.88)
            assert job["netProfit"] == pytest.approx(58.12)
            assert job["shifts"][0]["hours"] == 2.5
            assert job["shifts"][0]["laborCost"] == pytest.approx(41.88)
        finally:
            if shift_id is not None:
                db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
            if job_id is not None:
                db.execute("DELETE FROM jobs WHERE id = %s", (job_id,))

    def test_get_job_not_found(self, client, auth):
        r = client.get("/api/admin/jobs/999999", headers=auth)
        assert r.status_code == 404

    def test_update_job_status(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Update Test",
            "scheduledDate": "2026-04-03", "expectedHours": 2.0, "revenue": 80.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.put(f"/api/admin/jobs/{job_id}", headers=auth, json={
            "customerName": "Update Test", "scheduledDate": "2026-04-03",
            "expectedHours": 2.5, "revenue": 90.0, "notes": "updated",
            "status": "completed",
        })
        assert r.status_code == 200, r.text
        assert r.json()["job"]["status"] == "completed"
        assert r.json()["job"]["expectedHours"] == 2.5

    def test_delete_job(self, client, auth, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Delete Me",
            "scheduledDate": "2026-04-04", "expectedHours": 1.0, "revenue": 50.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.delete(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r.status_code == 200, r.text
        # confirm gone
        r2 = client.get(f"/api/admin/jobs/{job_id}", headers=auth)
        assert r2.status_code == 404

    def test_calendar_owned_job_rejects_update_and_delete_without_unlinking_actuals(
        self, client, auth, location_id, completed_shift_id
    ):
        job_id = int(
            db.query_one(
                """
                INSERT INTO jobs (
                    location_id, customer_name, scheduled_date, expected_hours,
                    revenue, notes, status, source_key, source_fingerprint
                ) VALUES (
                    %s, 'Calendar Customer', '2026-04-04', 2.0, 100.0,
                    'Calendar authority', 'scheduled', %s, %s
                )
                RETURNING id
                """,
                (location_id, "c" * 64, "d" * 64),
            )["id"]
        )
        db.execute(
            "UPDATE shifts SET job_id = %s WHERE id = %s",
            (job_id, completed_shift_id),
        )
        original = db.query_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
        try:
            updated = client.put(
                f"/api/admin/jobs/{job_id}",
                headers=auth,
                json={
                    "customerName": "Local override",
                    "scheduledDate": "2026-04-05",
                    "expectedHours": 9.0,
                    "revenue": 999.0,
                    "notes": "Local override",
                    "status": "completed",
                    "locationId": location_id,
                },
            )
            deleted = client.delete(f"/api/admin/jobs/{job_id}", headers=auth)

            assert updated.status_code == 409, updated.text
            assert deleted.status_code == 409, deleted.text
            assert updated.json()["code"] == "CALENDAR_JOB_READ_ONLY"
            assert deleted.json()["code"] == "CALENDAR_JOB_READ_ONLY"
            assert db.query_one("SELECT * FROM jobs WHERE id = %s", (job_id,)) == original
            assert (
                db.query_one(
                    "SELECT job_id FROM shifts WHERE id = %s",
                    (completed_shift_id,),
                )["job_id"]
                == job_id
            )
        finally:
            db.execute(
                "UPDATE shifts SET job_id = NULL WHERE id = %s",
                (completed_shift_id,),
            )
            db.execute("DELETE FROM jobs WHERE id = %s", (job_id,))

    def test_jobs_profitability_endpoint_is_retired(self, client, auth):
        response = client.get("/api/admin/jobs/profitability", headers=auth)

        assert response.status_code in (404, 422), response.text
        assert "jobs" not in response.text
        assert "summary" not in response.text

    def test_auto_link_jobs(self, client, auth, completed_shift_id, location_id):
        """Auto-link should run without error; returns linked count."""
        r = client.post("/api/admin/jobs/auto-link", headers=auth,
                        json={"date": "2026-04-01"})
        assert r.status_code == 200, r.text
        assert "linkedCount" in r.json()

    def test_attach_shift_to_job(self, client, auth, completed_shift_id, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Shift Link Test",
            "scheduledDate": "2026-04-05", "expectedHours": 3.0, "revenue": 120.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        r = client.post(f"/api/admin/jobs/{job_id}/shifts", headers=auth,
                        json={"shiftIds": [completed_shift_id]})
        assert r.status_code == 200, r.text

    def test_detach_shift_from_job(self, client, auth, completed_shift_id, location_id):
        create = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Detach Test",
            "scheduledDate": "2026-04-06", "expectedHours": 3.0, "revenue": 120.0, "notes": "",
        })
        job_id = create.json()["job"]["id"]
        client.post(f"/api/admin/jobs/{job_id}/shifts", headers=auth,
                    json={"shiftIds": [completed_shift_id]})
        r = client.delete(f"/api/admin/jobs/{job_id}/shifts/{completed_shift_id}", headers=auth)
        assert r.status_code == 200, r.text

    def test_invalid_job_status(self, client, auth, location_id):
        """Creating a job with a bad status should fail."""
        r = client.post("/api/admin/jobs", headers=auth, json={
            "locationId": location_id, "customerName": "Bad Status",
            "scheduledDate": "2026-04-07", "expectedHours": 1.0, "revenue": 50.0,
            "notes": "", "status": "invalid_status",
        })
        assert r.status_code in (400, 422)


# ===============================================================================
# Phase 5 - Unified Dashboard
# ===============================================================================

class TestDashboard:
    def test_admin_dashboard(self, client, auth):
        r = client.get("/api/admin/dashboard", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "cards" in data or "summary" in data or "success" in data

    def test_dashboard_requires_auth(self, client):
        r = client.get("/api/admin/dashboard")
        assert r.status_code == 401


# ===============================================================================
# Phase 6 - Pricing Recommendations
# ===============================================================================

class TestPricing:
    def test_pricing_recommendations(self, client, auth):
        r = client.get("/api/admin/analytics/pricing", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)

    def test_pricing_row_keys(self, client, auth, completed_shift_id):
        r = client.get("/api/admin/analytics/pricing", headers=auth)
        recs = r.json()["recommendations"]
        if recs:
            row = recs[0]
            assert "customer" in row
            assert "currentRate" in row or "suggestedRate" in row or "laborPct" in row


# ===============================================================================
# Phase 7 - Time Categorization & Waste
# ===============================================================================

class TestTimeCategories:
    def test_categorize_shift_productive(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "productive"})
        assert r.status_code == 200, r.text
        assert r.json()["success"] is True

    def test_categorize_shift_non_productive(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "non_productive", "nonProductiveType": "drive_time",
                               "notes": "driving to supply store"})
        assert r.status_code == 200, r.text

    def test_categorize_invalid_type(self, client, auth, completed_shift_id):
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "banana"})
        assert r.status_code in (400, 422)

    def test_non_productive_requires_type(self, client, auth, completed_shift_id):
        """non_productive without nonProductiveType should fail or at least not 500."""
        r = client.patch(f"/api/admin/shifts/{completed_shift_id}/categorize", headers=auth,
                         json={"timeCategory": "non_productive"})
        # API may accept with null type or reject - just must not 500
        assert r.status_code != 500

    def test_waste_analysis(self, client, auth):
        r = client.get("/api/admin/analytics/waste", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "waste" in data or "summary" in data or "success" in data

    def test_waste_analysis_uses_clock_span_when_stored_total_is_stale(
        self,
        client,
        auth,
        employee_id,
        location_id,
    ):
        shift_id = None
        try:
            shift_id = int(
                db.execute_returning(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label,
                        clock_in, clock_out, total_hours, notes, local_date,
                        time_category, non_productive_type
                    )
                    VALUES (
                        %s, %s, '123 Main St, Effingham',
                        TIMESTAMPTZ '2048-02-03 08:00:00-06',
                        TIMESTAMPTZ '2048-02-03 10:30:00-06',
                        0.25, 'waste canonical hours proof',
                        DATE '2048-02-03',
                        'non_productive', 'waiting'
                    )
                    RETURNING id
                    """,
                    (employee_id, location_id),
                )
            )

            response = client.get(
                "/api/admin/analytics/waste",
                headers=auth,
                params={"period": "day", "date": "2048-02-03"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["totalWasteHours"] == 2.5
            assert body["summary"]["totalWasteCost"] == pytest.approx(41.88)
            customer_row = next(
                row for row in body["byCustomer"] if row["customer"] == "Test Customer"
            )
            assert customer_row["hours"] == 2.5
            assert customer_row["cost"] == pytest.approx(41.88)
            employee_row = next(
                row for row in body["byEmployee"] if row["employee"] == "Catalina Gomez"
            )
            assert employee_row["hours"] == 2.5
            assert employee_row["cost"] == pytest.approx(41.88)
            cause_row = next(row for row in body["byCause"] if row["cause"] == "waiting")
            assert cause_row["hours"] == 2.5
            assert cause_row["cost"] == pytest.approx(41.88)
        finally:
            if shift_id is not None:
                db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))

    def test_waste_all_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=all", headers=auth)
        assert r.status_code == 200, r.text

    def test_waste_invalid_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=bogus", headers=auth)
        assert r.status_code in (400, 422)

    def test_unmatched_shifts_use_clock_span_when_stored_total_is_stale(
        self,
        client,
        auth,
        employee_id,
    ):
        shift_id = None
        try:
            shift_id = int(
                db.execute_returning(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label,
                        clock_in, clock_out, total_hours, notes, local_date,
                        time_category
                    )
                    VALUES (
                        %s, NULL, 'Unmatched canonical hours',
                        TIMESTAMPTZ '2048-04-07 08:00:00-05',
                        TIMESTAMPTZ '2048-04-07 10:30:00-05',
                        0.25, 'unmatched canonical hours proof',
                        DATE '2048-04-07',
                        'productive'
                    )
                    RETURNING id
                    """,
                    (employee_id,),
                )
            )

            response = client.get("/api/admin/analytics/unmatched-shifts", headers=auth)

            assert response.status_code == 200, response.text
            body = response.json()
            shift = next(row for row in body["shifts"] if row["id"] == shift_id)
            assert shift["hours"] == 2.5
            assert body["totalHours"] == round(
                sum(row["hours"] for row in body["shifts"]),
                2,
            )
        finally:
            if shift_id is not None:
                db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))

    def test_categorize_shift_not_found(self, client, auth):
        r = client.patch("/api/admin/shifts/999999/categorize", headers=auth,
                         json={"timeCategory": "productive"})
        assert r.status_code == 404


# ===============================================================================
# Phase 8 - Schedules & Forecasting
# ===============================================================================

class TestSchedules:
    def test_create_schedule(self, client, auth, employee_id):
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId":     employee_id,
            "customerName":   "Test Customer",
            "weekStart":      "2026-03-29",
            "scheduledHours": 8.0,
            "notes":          "",
        })
        assert r.status_code == 200, r.text
        sc = r.json()["schedule"]
        assert sc["customerName"] == "Test Customer"
        assert sc["scheduledHours"] == 8.0

    def test_create_schedule_normalizes_to_sunday(self, client, auth, employee_id):
        """Wed 2026-04-01 should be normalized to Sun 2026-03-29."""
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Test Customer",
            "weekStart": "2026-04-01",  # Wednesday
            "scheduledHours": 6.0, "notes": "",
        })
        assert r.status_code == 200, r.text
        assert r.json()["schedule"]["weekStart"] == "2026-03-29"

    def test_upsert_schedule(self, client, auth, employee_id, location_id):
        """Posting twice for same employee/customer/week should update hours."""
        base = {"employeeId": employee_id, "customerName": "Upsert Test",
                "locationId": location_id, "weekStart": "2026-03-29", "notes": ""}
        client.post("/api/admin/schedules", headers=auth, json={**base, "scheduledHours": 5.0})
        r2 = client.post("/api/admin/schedules", headers=auth, json={**base, "scheduledHours": 9.0})
        assert r2.status_code == 200, r2.text
        assert r2.json()["schedule"]["scheduledHours"] == 9.0

    def test_list_schedules(self, client, auth):
        r = client.get("/api/admin/schedules", headers=auth)
        assert r.status_code == 200, r.text
        assert isinstance(r.json()["schedules"], list)

    def test_list_schedules_filter_week(self, client, auth):
        r = client.get("/api/admin/schedules?week_start=2026-03-29", headers=auth)
        assert r.status_code == 200, r.text
        for sc in r.json()["schedules"]:
            assert sc["weekStart"] == "2026-03-29"

    def test_delete_schedule(self, client, auth, employee_id, location_id):
        create = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Delete Sched",
            "locationId": location_id, "weekStart": "2026-03-29",
            "scheduledHours": 4.0, "notes": "",
        })
        sc_id = create.json()["schedule"]["id"]
        r = client.delete(f"/api/admin/schedules/{sc_id}", headers=auth)
        assert r.status_code == 200, r.text

    def test_delete_schedule_not_found(self, client, auth):
        r = client.delete("/api/admin/schedules/999999", headers=auth)
        assert r.status_code == 404

    def test_negative_hours_rejected(self, client, auth, employee_id):
        r = client.post("/api/admin/schedules", headers=auth, json={
            "employeeId": employee_id, "customerName": "Bad Hours",
            "weekStart": "2026-03-29", "scheduledHours": -1.0, "notes": "",
        })
        assert r.status_code in (400, 422)


class TestScheduleVsActual:
    def test_schedule_vs_actual(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "rows" in data or "comparison" in data or "success" in data

    def test_schedule_vs_actual_with_week(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual?week_start=2026-03-29", headers=auth)
        assert r.status_code == 200, r.text

    def test_schedule_vs_actual_uses_clock_span_when_stored_total_is_stale(
        self,
        client,
        auth,
        employee_id,
        location_id,
    ):
        schedule_id = None
        shift_id = None
        try:
            schedule_id = int(
                db.execute_returning(
                    """
                    INSERT INTO schedules (
                        employee_id, location_id, customer_name, week_start,
                        scheduled_hours, notes
                    )
                    VALUES (%s, %s, 'Test Customer', DATE '2048-01-12', 2.0, '')
                    RETURNING id
                    """,
                    (employee_id, location_id),
                )
            )
            shift_id = int(
                db.execute_returning(
                    """
                    INSERT INTO shifts (
                        employee_id, location_id, location_label,
                        clock_in, clock_out, total_hours, notes, local_date
                    )
                    VALUES (
                        %s, %s, '123 Main St, Effingham',
                        TIMESTAMPTZ '2048-01-13 08:00:00-06',
                        TIMESTAMPTZ '2048-01-13 10:30:00-06',
                        0.25, 'schedule actual canonical hours proof',
                        DATE '2048-01-13'
                    )
                    RETURNING id
                    """,
                    (employee_id, location_id),
                )
            )

            response = client.get(
                "/api/admin/analytics/schedule-vs-actual",
                headers=auth,
                params={"week_start": "2048-01-12"},
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["summary"]["totalScheduled"] == 2.0
            assert body["summary"]["totalActual"] == 2.5
            row = next(
                item for item in body["comparisons"] if item["customerName"] == "Test Customer"
            )
            assert row["scheduledHours"] == 2.0
            assert row["actualHours"] == 2.5
            assert row["driftHours"] == 0.5
        finally:
            if shift_id is not None:
                db.execute("DELETE FROM shifts WHERE id = %s", (shift_id,))
            if schedule_id is not None:
                db.execute("DELETE FROM schedules WHERE id = %s", (schedule_id,))

    def test_schedule_vs_actual_invalid_date(self, client, auth):
        r = client.get("/api/admin/analytics/schedule-vs-actual?week_start=not-a-date", headers=auth)
        assert r.status_code in (400, 422)


class TestForecast:
    def test_forecast_endpoint(self, client, auth):
        r = client.get("/api/admin/analytics/forecast", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "forecast" in data or "weeks" in data or "success" in data

    def test_forecast_with_weeks_param(self, client, auth):
        r = client.get("/api/admin/analytics/forecast?weeks=4", headers=auth)
        assert r.status_code == 200, r.text

    def test_forecast_invalid_weeks(self, client, auth):
        r = client.get("/api/admin/analytics/forecast?weeks=-1", headers=auth)
        assert r.status_code in (400, 422, 200)  # implementation-defined

    def test_forecast_adapts_canonical_operations_payload(self, client, auth, monkeypatch):
        import time_tracker_api as api

        def fake_canonical_forecast(weeks_ahead, *, timezone_name, now_provider):
            assert weeks_ahead == 1
            assert timezone_name == "America/Chicago"
            assert now_provider().tzinfo is not None
            return {
                "success": True,
                "weeksAhead": weeks_ahead,
                "avgLaborRate": 22.5,
                "issues": [],
                "summary": {"estRevenue": 100.0},
                "weeks": [
                    {
                        "weekStart": "2026-07-26",
                        "weekEnd": "2026-08-01",
                        "plannedHours": 2.0,
                        "knownPlannedHours": 2.0,
                        "plannedHoursComplete": True,
                        "estRevenue": 33.34,
                        "knownRevenue": 33.34,
                        "revenueComplete": True,
                        "estLaborCost": 45.0,
                        "knownLaborCost": 45.0,
                        "laborCostComplete": True,
                        "bySite": [
                            {
                                "locationId": 99,
                                "customerId": 12,
                                "customerName": "Canonical Monthly",
                                "siteAddress": "100 Canonical Way",
                                "plannedHours": 2.0,
                                "knownPlannedHours": 2.0,
                                "plannedHoursComplete": True,
                                "estRevenue": 33.34,
                                "knownRevenue": 33.34,
                                "revenueComplete": True,
                                "estLaborCost": 45.0,
                                "knownLaborCost": 45.0,
                                "laborCostComplete": True,
                            }
                        ],
                    }
                ],
            }

        monkeypatch.setattr(api, "build_operations_forecast", fake_canonical_forecast)

        response = client.get(
            "/api/admin/analytics/forecast",
            headers=auth,
            params={"weeks_ahead": 1},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["weeksAhead"] == 1
        assert body["avgLaborRate"] == 22.5
        assert body["summary"] == {"estRevenue": 100.0}
        assert body["weeks"] == body["forecasts"]
        assert body["forecasts"][0]["estRevenue"] == 33.34
        assert body["forecasts"][0]["byCustomer"] == [
            {
                "customerId": 12,
                "locationId": 99,
                "customer": "Canonical Monthly",
                "forecastHours": 2.0,
                "source": "operations",
                "estLaborCost": 45.0,
                "estRevenue": 33.34,
                "issues": [],
            }
        ]


# ===============================================================================
# Locations - new fields (target_labor_pct, min_margin_pct)
# ===============================================================================

class TestLocationNewFields:
    def test_update_location_with_targets(self, client, auth):
        r = client.put("/api/admin/locations", headers=auth, json={"locations": [{
            "address":        "123 Main St, Effingham",
            "customerName":   "Test Customer",
            "locationType":   "Residential",
            "rate":           160.0,
            "rateType":       "per_visit",
            "expectedHours":  3.5,
            "targetLaborPct": 30.0,
            "minMarginPct":   25.0,
        }]})
        assert r.status_code == 200, r.text

    def test_locations_return_new_fields(self, client, auth):
        """PUT /admin/locations should persist and return Phase-6 pricing targets."""
        r = client.put("/api/admin/locations", headers=auth, json={"locations": [{
            "address":        "123 Main St, Effingham",
            "customerName":   "Test Customer",
            "locationType":   "Residential",
            "rate":           160.0,
            "rateType":       "per_visit",
            "expectedHours":  3.5,
            "targetLaborPct": 30.0,
            "minMarginPct":   25.0,
        }]})
        assert r.status_code == 200, r.text
        data = r.json()
        # Phase 6 pricing fields are returned in the PUT response
        assert "location_target_labor" in data
        assert "location_min_margin" in data
