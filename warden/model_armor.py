"""Optional inline Google Cloud Model Armor prompt screening.

When a template is configured, Warden fails closed on a Model Armor match or
an unavailable screening call. Local demos remain self-contained because no
network call is attempted without an explicit template configuration.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScreeningResult:
    allowed: bool
    state: str
    detail: str


class ModelArmor:
    def __init__(self, *, project: str | None = None, location: str | None = None, template: str | None = None) -> None:
        self.project = project or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.location = location or os.environ.get("WARDEN_MODEL_ARMOR_LOCATION", "us-central1")
        self.template = template or os.environ.get("WARDEN_MODEL_ARMOR_TEMPLATE", "")

    @property
    def enabled(self) -> bool:
        return bool(self.project and self.location and self.template)

    async def screen_prompt(self, text: str) -> ScreeningResult:
        if not self.enabled:
            return ScreeningResult(True, "NOT_CONFIGURED", "Model Armor template is not configured")
        try:
            return await asyncio.to_thread(self._screen_prompt_sync, text)
        except Exception:
            return ScreeningResult(False, "UNAVAILABLE", "Model Armor screening was unavailable; request was not forwarded")

    def _screen_prompt_sync(self, text: str) -> ScreeningResult:
        from google.auth import default
        from google.auth.transport.requests import AuthorizedSession

        credentials, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        session = AuthorizedSession(credentials)
        url = (
            f"https://modelarmor.{self.location}.rep.googleapis.com/v1/projects/{self.project}"
            f"/locations/{self.location}/templates/{self.template}:sanitizeUserPrompt"
        )
        response = session.post(url, json={"userPromptData": {"text": text}}, timeout=8)
        response.raise_for_status()
        return _decision_from_response(response.json())


def _decision_from_response(payload: dict[str, Any]) -> ScreeningResult:
    result = payload.get("sanitizationResult", {})
    invocation = result.get("invocationResult", "UNKNOWN")
    match_state = result.get("filterMatchState", "UNKNOWN")
    if invocation != "SUCCESS":
        return ScreeningResult(False, "UNAVAILABLE", "Model Armor did not complete screening")
    if match_state == "MATCH_FOUND":
        return ScreeningResult(False, "MATCH_FOUND", "Model Armor blocked this request under the configured template")
    return ScreeningResult(True, match_state, "Model Armor completed with no blocking match")
