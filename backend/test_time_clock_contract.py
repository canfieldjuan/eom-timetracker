"""Shared employee time-clock contract checks.

These tests pin the API surface that the EOM website portal depends on.  The
contract file is intentionally duplicated in the website repository; changes to
the clock workflow should update both copies in the same vertical slice.
"""

from __future__ import annotations

import json
from pathlib import Path

import time_tracker_api as api


CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "eom-time-clock-contract.v1.json"
)


def _contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _model_fields(model: type) -> set[str]:
    fields = getattr(model, "model_fields", None)
    if fields is not None:
        return set(fields)
    return set(getattr(model, "__fields__", {}))


def test_time_clock_contract_routes_are_registered():
    registered = {
        (route.path, method)
        for route in api.app.routes
        for method in getattr(route, "methods", set())
        if method not in {"HEAD", "OPTIONS"}
    }

    missing = [
        f"{endpoint['method']} {endpoint['backendPath']}"
        for endpoint in _contract()["endpoints"]
        if (endpoint["backendPath"], endpoint["method"]) not in registered
    ]

    assert missing == []


def test_time_clock_contract_request_models_include_frontend_fields():
    missing = {}
    for endpoint in _contract()["endpoints"]:
        model_name = endpoint.get("requestModel")
        if not model_name:
            continue

        model = getattr(api, model_name)
        model_fields = _model_fields(model)
        missing_fields = sorted(set(endpoint["requestFields"]) - model_fields)
        if missing_fields:
            missing[endpoint["id"]] = missing_fields

    assert missing == {}


def test_paid_time_actions_keep_shared_gps_override_shape():
    contract = _contract()
    shared = set(contract["sharedRequestFields"]["gpsTimeAction"])
    paid_time_actions = [
        endpoint
        for endpoint in contract["endpoints"]
        if endpoint["workflow"] == "paid-time-action"
    ]

    assert {endpoint["id"] for endpoint in paid_time_actions} == {
        "clock-in",
        "arrive",
        "depart",
        "clock-out",
    }
    for endpoint in paid_time_actions:
        assert shared <= set(endpoint["requestFields"])
        assert endpoint["staleShiftErrorCode"] == api.STALE_SHIFT_REVIEW_CODE


def test_qr_contract_stays_separate_from_paid_time_routes():
    contract = _contract()
    paid_backend_paths = {
        endpoint["backendPath"]
        for endpoint in contract["endpoints"]
        if endpoint["workflow"] == "paid-time-action"
    }
    qr_backend_paths = {
        endpoint["backendPath"]
        for endpoint in contract["endpoints"]
        if endpoint["workflow"] == "qr-site-evidence"
    }

    assert qr_backend_paths == {
        "/api/timesheet/site-check-in/resolve",
        "/api/timesheet/site-check-in",
    }
    assert paid_backend_paths.isdisjoint(qr_backend_paths)
    assert contract["scope"]["qrWorkflow"] == "site-evidence-only"
