"""Regression coverage for the retired Firefly monthly report/email workflow."""

import time_tracker_api as api


RETIRED_ROUTES = {
    ("post", "/api/admin/generate-report"),
    ("get", "/api/admin/download-report/{filename}"),
}

CANONICAL_ROUTES = {
    ("get", "/api/admin/reports/hours"),
    ("get", "/api/admin/reports/hours/export"),
    ("get", "/api/admin/reports/hours/pdf"),
}


def test_legacy_monthly_report_routes_are_absent(client):
    registered_routes = {
        (method.lower(), route.path)
        for route in api.app.routes
        for method in (getattr(route, "methods", None) or ())
        if getattr(route, "path", None)
    }
    assert registered_routes.isdisjoint(RETIRED_ROUTES)
    assert CANONICAL_ROUTES.issubset(registered_routes)

    openapi_paths = client.get("/openapi.json").json()["paths"]
    assert all(path not in openapi_paths for _, path in RETIRED_ROUTES)
    assert all(method in openapi_paths[path] for method, path in CANONICAL_ROUTES)

    generated = client.post(
        "/api/admin/generate-report",
        json={},
    )
    downloaded = client.get(
        "/api/admin/download-report/__retired_report_route_probe__.pdf",
    )
    assert generated.status_code == 404
    assert downloaded.status_code == 404
