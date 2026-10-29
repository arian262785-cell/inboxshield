"""inboxshield package exports."""

from .bounce import (
    CAT_AUTO_REPLY,
    CAT_DOMAIN_UNREACHABLE,
    CAT_HARD_BOUNCE,
    CAT_SOFT_BOUNCE,
    CAT_SPAM_REJECTION,
    CAT_UNKNOWN_BOUNCE,
    CAT_UNSUBSCRIBE,
    SuppressionLedger,
    analyze_bounce_text,
)
from .classifier import classify_reply, has_meeting_signal
from .sanitizer import (
    sanitize_eml_bytes,
    sanitize_file,
    sanitize_mime_dict,
    sanitize_text,
    sanitize_text_with_counts,
)
from .spec import BounceReport, ReplyClassification, SanitizedMessage

__all__ = [
    "BounceReport",
    "CAT_AUTO_REPLY",
    "CAT_DOMAIN_UNREACHABLE",
    "CAT_HARD_BOUNCE",
    "CAT_SOFT_BOUNCE",
    "CAT_SPAM_REJECTION",
    "CAT_UNKNOWN_BOUNCE",
    "CAT_UNSUBSCRIBE",
    "ReplyClassification",
    "SanitizedMessage",
    "SuppressionLedger",
    "analyze_bounce_text",
    "classify_reply",
    "has_meeting_signal",
    "sanitize_eml_bytes",
    "sanitize_file",
    "sanitize_mime_dict",
    "sanitize_text",
    "sanitize_text_with_counts",
]
