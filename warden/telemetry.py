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
        from google.adk.telemetry import google_cloud
        from google.adk.telemetry.setup import maybe_set_otel_providers

        hooks = google_cloud.get_gcp_exporters(enable_cloud_tracing=True)
        maybe_set_otel_providers(otel_hooks_to_setup=[hooks])
        _configured = True
        return True
    except Exception:
        log.exception("Could not configure ADK Cloud Trace exporters")
        return False
