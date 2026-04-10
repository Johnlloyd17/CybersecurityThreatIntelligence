"""Severity helpers."""

from __future__ import annotations


def severity_from_risk(risk_score: int) -> str:
    score = max(0, min(100, int(risk_score)))
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"

