"""Zero-trust RFC 5322 and MIME tree sanitizer against attachments, links, and prompt injections."""

from __future__ import annotations

import base64
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path
import re
from typing import Any

from .spec import SanitizedMessage

_URL_RE = re.compile(
    r"(?:https?|ftp|file|javascript|data|mailto|tel)://[^\s<>\"')]+|www\.[^\s<>\"')]+",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt|you\s+are\s+now|"
    r"disregard\s+all|subprocess|os\.system|eval\(|exec\(|curl\s+|wget\s+|"
    r"bash\s+-c|sh\s+-c|/bin/sh|<script|javascript:)",
    re.IGNORECASE,
)


def sanitize_text_with_counts(raw_text: str) -> tuple[str, int, int]:
    """Strip HTML tags, neutralize URLs and prompt/shell injections, and return removal counts."""
    if not raw_text:
        return "", 0, 0
    cleaned = _HTML_TAG_RE.sub(" ", raw_text)
    cleaned, n_links = _URL_RE.subn("[LINK_REMOVED]", cleaned)
    cleaned, n_inj = _INJECTION_RE.subn("[INJECTION_REMOVED]", cleaned)
    cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()
    return cleaned, n_links, n_inj


def sanitize_text(raw_text: str) -> str:
    """Return sanitized plain text with links, HTML tags, and injection patterns removed."""
    cleaned, _, _ = sanitize_text_with_counts(raw_text)
    return cleaned


def sanitize_eml_bytes(raw_bytes: bytes) -> SanitizedMessage:
    """Parse RFC 5322 email bytes, strip non-text parts and attachments, and sanitize text."""
    msg = BytesParser(policy=email_policy.default).parsebytes(raw_bytes)
    sender = str(msg.get("From", "")).strip()
    recipient = str(msg.get("To", "")).strip()
    raw_subject = str(msg.get("Subject", "")).strip()
    clean_subj, subj_links, subj_inj = sanitize_text_with_counts(raw_subject)

    total_links = subj_links
    total_inj = subj_inj
    removed_attachments: list[str] = []
    text_chunks: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type().lower()
            disp = str(part.get_content_disposition() or "").lower()
            filename = part.get_filename()

            if filename or disp == "attachment":
                label = filename or ctype
                removed_attachments.append(label)
                text_chunks.append(f"[ATTACHMENT_REMOVED: {label}]")
                continue

            if ctype in ("text/plain", "message/delivery-status"):
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes:
                    decoded = payload_bytes.decode(
                        part.get_content_charset() or "utf-8",
                        errors="replace",
                    )
                    c_text, n_l, n_i = sanitize_text_with_counts(decoded)
                    total_links += n_l
                    total_inj += n_i
                    if c_text:
                        text_chunks.append(c_text)
            elif ctype != "text/html":
                removed_attachments.append(ctype)
                text_chunks.append(f"[ATTACHMENT_REMOVED: {ctype}]")
    else:
        ctype = msg.get_content_type().lower()
        filename = msg.get_filename()
        if filename or ctype not in ("text/plain", "message/delivery-status"):
            label = filename or ctype
            removed_attachments.append(label)
            text_chunks.append(f"[ATTACHMENT_REMOVED: {label}]")
        else:
            payload_bytes = msg.get_payload(decode=True)
            if payload_bytes:
                decoded = payload_bytes.decode(
                    msg.get_content_charset() or "utf-8",
                    errors="replace",
                )
                c_text, n_l, n_i = sanitize_text_with_counts(decoded)
                total_links += n_l
                total_inj += n_i
                if c_text:
                    text_chunks.append(c_text)

    return SanitizedMessage(
        sender=sender,
        recipient=recipient,
        subject=clean_subj,
        body_text="\n".join(text_chunks),
        removed_links_count=total_links,
        removed_attachments=removed_attachments,
        removed_injections_count=total_inj,
    )


def sanitize_mime_dict(payload: dict[str, Any]) -> SanitizedMessage:
    """Sanitize a structured JSON MIME tree (such as a REST API message payload)."""
    headers = {
        str(h.get("name") or "").lower(): str(h.get("value") or "")
        for h in (payload.get("headers") or [])
    }
    sender = headers.get("from", "")
    recipient = headers.get("to", "")
    clean_subj, total_links, total_inj = sanitize_text_with_counts(headers.get("subject", ""))
    removed_attachments: list[str] = []
    chunks: list[str] = []

    def _walk(node: dict[str, Any]) -> None:
        nonlocal total_links, total_inj
        fn = str(node.get("filename") or "").strip()
        body_obj = node.get("body") or {}
        mime = str(node.get("mimeType") or "").lower().strip()

        if fn or body_obj.get("attachmentId"):
            label = fn or mime or "binary"
            removed_attachments.append(label)
            chunks.append(f"[ATTACHMENT_REMOVED: {label}]")
            return

        if mime in ("text/plain", "message/delivery-status", ""):
            data_b64 = body_obj.get("data")
            if data_b64:
                raw_dec = base64.urlsafe_b64decode(str(data_b64) + "===").decode(
                    "utf-8",
                    errors="replace",
                )
                c_txt, nl, ni = sanitize_text_with_counts(raw_dec)
                total_links += nl
                total_inj += ni
                if c_txt:
                    chunks.append(c_txt)

        for child in node.get("parts") or []:
            _walk(child)

    _walk(payload)
    return SanitizedMessage(
        sender=sender,
        recipient=recipient,
        subject=clean_subj,
        body_text="\n".join(chunks),
        removed_links_count=total_links,
        removed_attachments=removed_attachments,
        removed_injections_count=total_inj,
    )


def sanitize_file(path: str | Path) -> SanitizedMessage:
    """Load an .eml or .json MIME file from disk and return a SanitizedMessage."""
    file_path = Path(path)
    raw = file_path.read_bytes()
    if file_path.suffix.lower() == ".json":
        import json

        data = json.loads(raw.decode("utf-8"))
        payload = data.get("payload", data)
        return sanitize_mime_dict(payload)
    return sanitize_eml_bytes(raw)
