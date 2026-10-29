"""Data structures for sanitized messages, bounce diagnostics, and reply classifications."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SanitizedMessage:
    """Result of zero-trust RFC 5322 or MIME payload sanitization."""

    sender: str
    recipient: str
    subject: str
    body_text: str
    removed_links_count: int
    removed_attachments: list[str]
    removed_injections_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BounceReport:
    """Diagnostic result from RFC 3463 / RFC 3464 DSN and SMTP bounce analysis."""

    category: str
    recipient: str
    smtp_code: str
    enhanced_code: str
    permanent_suppression: bool
    diagnostic_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplyClassification:
    """Rule-based classification result for an inbound B2B email reply."""

    category: str
    meeting_signal: bool
    matched_pattern: str
    requires_human_review: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
