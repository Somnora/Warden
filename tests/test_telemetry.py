from __future__ import annotations

import google.auth
from google.adk.telemetry import google_cloud
from google.adk.telemetry import setup

from warden import telemetry


def test_cloud_trace_uses_detected_project_resource(monkeypatch):
    credentials = object()
    hooks = object()
    resource = object()
    configured: dict[str, object] = {}

    monkeypatch.setenv("WARDEN_ENABLE_CLOUD_TRACE", "true")
    monkeypatch.setattr(telemetry, "_configured", False)
    monkeypatch.setattr(
        google.auth,
        "default",
        lambda: (credentials, "somnora-dev-01"),
    )
    def get_exporters(**kwargs):
        configured["exporter_args"] = kwargs
        return hooks

    def get_resource(**kwargs):
        configured["resource_args"] = kwargs
        return resource

    monkeypatch.setattr(google_cloud, "get_gcp_exporters", get_exporters)
    monkeypatch.setattr(google_cloud, "get_gcp_resource", get_resource)

    def configure_provider(**kwargs):
        configured["provider_args"] = kwargs

    monkeypatch.setattr(setup, "maybe_set_otel_providers", configure_provider)

    assert telemetry.configure_cloud_trace() is True
    assert configured["exporter_args"] == {
        "enable_cloud_tracing": True,
        "google_auth": (credentials, "somnora-dev-01"),
    }
    assert configured["resource_args"] == {"project_id": "somnora-dev-01"}
    assert configured["provider_args"] == {
        "otel_hooks_to_setup": [hooks],
        "otel_resource": resource,
    }


def test_cloud_trace_stays_disabled_without_opt_in(monkeypatch):
    monkeypatch.delenv("WARDEN_ENABLE_CLOUD_TRACE", raising=False)
    monkeypatch.setattr(telemetry, "_configured", False)

    assert telemetry.configure_cloud_trace() is False
