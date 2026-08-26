"""Operator-selectable Gemini catalog for the Warden fleet.

The control plane only accepts identifiers in this catalog. Aliases such as
``flash-lite`` and shorthand ``3.5`` resolve to one canonical model id.
Default is Gemini 3.5 Flash to match the Devpost "Gemini 3.5 Flash or newer"
rule text; 3.7 Flash and Flash-Lite variants are operator-selectable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class UnknownModelError(ValueError):
    """Raised when an operator asks for a model Warden will not run."""


@dataclass(frozen=True)
class FleetModel:
    id: str
    label: str
    aliases: tuple[str, ...] = ()

    def matches(self, value: str) -> bool:
        needle = _normalize(value)
        names = (_normalize(self.id), _normalize(self.label), *(_normalize(a) for a in self.aliases))
        return needle in names


FLEET_MODELS: tuple[FleetModel, ...] = (
    FleetModel(
        id="gemini-3.5-flash",
        label="Gemini 3.5 Flash",
        aliases=("3.5-flash", "3.5", "flash"),
    ),
    FleetModel(
        id="gemini-3.7-flash",
        label="Gemini 3.7 Flash",
        aliases=("3.7-flash", "3.7"),
    ),
    FleetModel(
        id="gemini-2.5-flash-lite",
        label="Gemini 2.5 Flash Lite",
        aliases=("2.5-flash-lite", "2.5-flash-light", "2.5"),
    ),
    FleetModel(
        id="gemini-3.5-flash-lite",
        label="Gemini 3.5 Flash Lite",
        aliases=("gemini-3.5-flash-light", "3.5-flash-lite", "3.5-flash-light"),
    ),
)

CANONICAL_DEFAULT = "gemini-3.5-flash"


def _normalize(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def catalog() -> list[dict[str, str]]:
    return [{"id": model.id, "label": model.label} for model in FLEET_MODELS]


def resolve_model(value: str | None = None) -> str:
    """Map an operator choice or env override onto a catalog id."""
    raw = (value if value is not None else os.environ.get("WARDEN_MODEL", CANONICAL_DEFAULT)) or CANONICAL_DEFAULT
    for model in FLEET_MODELS:
        if model.matches(raw):
            return model.id
    allowed = ", ".join(model.id for model in FLEET_MODELS)
    raise UnknownModelError(f"unsupported fleet model {raw!r}; choose one of: {allowed}")


DEFAULT_MODEL = CANONICAL_DEFAULT
