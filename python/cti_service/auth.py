"""Minimal auth hook placeholder for the service shell."""

from __future__ import annotations

from typing import Mapping


def is_request_authorized(headers: Mapping[str, str]) -> bool:
    """Placeholder auth check.

    The first implementation slice intentionally keeps this permissive for local
    development. Production integration should replace this with a signed-token
    or service-to-service auth mechanism.
    """
    return True

