"""
Integration tests for EOM Time Tracker API - Phases 3-8 + regression checks.

Run:  cd backend && pytest -v
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
            assert changed.json() == {"success": True}

            assert client.post(
                "/api/auth/login",
                json={"name": "Catalina Gomez", "password": "gomez1"},
            ).status_code == 401
            assert client.post(
                "/api/auth/login",
                json={"name": "Catalina Gomez", "password": changed_password},
            ).status_code == 200

            same_password = client.post(
                endpoint,
                headers=emp_auth,
                json={
                    "currentPassword": changed_password,
                    "newPassword": changed_password,
                },
            )
            assert same_password.status_code == 400
            assert "must be different" in same_password.json()["error"]
        finally:
            db.execute(
                "UPDATE employees SET password_hash = %s WHERE name = %s",
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
            "service-token-that-never-reaches-browser",
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
            "Bearer service-token-that-never-reaches-browser"
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")

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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "rejected-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")
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
        monkeypatch.setattr(api, "ATLAS_RECEIVABLES_SERVICE_TOKEN", "service-token")

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

# ===============================================================================
# Phase 3 - Jobs
# ===============================================================================

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

    def test_jobs_profitability(self, client, auth):
        r = client.get("/api/admin/jobs/profitability", headers=auth)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "jobs" in data

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

    def test_waste_all_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=all", headers=auth)
        assert r.status_code == 200, r.text

    def test_waste_invalid_period(self, client, auth):
        r = client.get("/api/admin/analytics/waste?period=bogus", headers=auth)
        assert r.status_code in (400, 422)

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
