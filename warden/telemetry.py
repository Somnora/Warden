"""ADK-native OpenTelemetry configuration for Cloud Trace deployment."""

from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.telemetry")
_configured = False


def configure_cloud_trace() -> bool:
    """Enable ADK's GCP OpenTelemetry exporters once when explicitly requested."""
    global _configured
    if os.environ.get("WARDEN_ENABLE_CLOUD_TRACE", "false").lower() != "true":
        return False
    if _configured:
        return True
    try:
        import google.auth
        from google.adk.telemetry import google_cloud
        from google.adk.telemetry.setup import maybe_set_otel_providers

        credentials, project_id = google.auth.default()
        if not project_id:
            raise RuntimeError("Google Cloud project could not be detected for trace export")
        hooks = google_cloud.get_gcp_exporters(
            enable_cloud_tracing=True,
            google_auth=(credentials, project_id),
        )
        resource = google_cloud.get_gcp_resource(project_id=project_id)
        maybe_set_otel_providers(
            otel_hooks_to_setup=[hooks],
            otel_resource=resource,
        )
        _configured = True
        return True
    except Exception:
        log.exception("Could not configure ADK Cloud Trace exporters")
        return False
