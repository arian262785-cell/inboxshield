"""RFC 3463 / RFC 3464 DSN bounce classifier and SQLite suppression ledger."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
from typing import Any

from .spec import BounceReport

CAT_HARD_BOUNCE = "HARD_BOUNCE"
CAT_SOFT_BOUNCE = "SOFT_BOUNCE"
CAT_DOMAIN_UNREACHABLE = "DOMAIN_UNREACHABLE"
CAT_SPAM_REJECTION = "SPAM_REJECTION"
CAT_AUTO_REPLY = "AUTO_REPLY"
CAT_UNSUBSCRIBE = "UNSUBSCRIBE"
CAT_UNKNOWN_BOUNCE = "UNKNOWN_BOUNCE"

_RE_ENHANCED = re.compile(r"\b([45]\.[0-7]\.[0-9]{1,3})\b")
_RE_BASIC = re.compile(r"\b(55[0-4]|45[0-2]|50[0-3]|421)\b")
_RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

_HARD_PATTERNS = [
    r"user unknown",
    r"no such user",
    r"no such mailbox",
    r"mailbox (?:unavailable|not found|does not exist)",
    r"recipient (?:address rejected|not found|unknown)",
    r"invalid mailbox",
    r"adresse existiert nicht",
    r"empf[aä]nger (?:unbekannt|existiert nicht)",
    r"benutzer existiert nicht",
    r"550 5\.1\.1",
    r"550-5\.1\.1",
    r"550 5\.2\.1",
]

_DOMAIN_PATTERNS = [
    r"nxdomain",
    r"host or domain name not found",
    r"domain (?:does not exist|not found)",
    r"no such domain",
    r"name or service not known",
    r"dns query failed",
    r"server unreachable",
    r"5\.1\.2",
    r"5\.4\.4",
]

_SPAM_PATTERNS = [
    r"spam detected",
    r"blocked by spamhaus",
    r"blacklisted",
    r"rejected due to spam",
    r"message rejected as spam",
    r"spf check failed",
    r"dmarc policy",
    r"554 5\.7\.1",
    r"5\.7\.1",
    r"5\.7\.26",
]

_SOFT_PATTERNS = [
    r"mailbox (?:is )?full",
    r"quota exceeded",
    r"over quota",
    r"temporary failure",
    r"try again later",
    r"temporarily deferred",
    r"resources temporarily unavailable",
    r"4\.2\.2",
    r"4\.4\.1",
]

_SYSTEM_ADDRESSES = {"mailer-daemon", "postmaster", "noreply", "no-reply"}


def analyze_bounce_text(raw_text: str, fallback_recipient: str = "") -> BounceReport:
    """Classify DSN or SMTP bounce text and extract status codes and recipient address."""
    text_low = (raw_text or "").lower()

    enh_match = _RE_ENHANCED.search(raw_text or "")
    enhanced_code = enh_match.group(1) if enh_match else ""

    basic_match = _RE_BASIC.search(raw_text or "")
    smtp_code = basic_match.group(1) if basic_match else ""

    recipient = fallback_recipient.strip().lower()
    if not recipient:
        final_match = re.search(
            r"(?:final-recipient|original-recipient|x-failed-recipients)\s*:[^\n]*?([\w.+-]+@[\w-]+\.[\w.-]+)",
            raw_text or "",
            re.IGNORECASE,
        )
        if final_match:
            recipient = final_match.group(1).lower()
        else:
            for candidate in _RE_EMAIL.findall(raw_text or ""):
                local_part = candidate.split("@", 1)[0].lower()
                if local_part not in _SYSTEM_ADDRESSES:
                    recipient = candidate.lower()
                    break

    category = CAT_UNKNOWN_BOUNCE
    if any(re.search(p, text_low) for p in _SPAM_PATTERNS):
        category = CAT_SPAM_REJECTION
    elif any(re.search(p, text_low) for p in _DOMAIN_PATTERNS):
        category = CAT_DOMAIN_UNREACHABLE
    elif any(re.search(p, text_low) for p in _HARD_PATTERNS):
        category = CAT_HARD_BOUNCE
    elif any(re.search(p, text_low) for p in _SOFT_PATTERNS):
        category = CAT_SOFT_BOUNCE
    elif enhanced_code.startswith("5.") or smtp_code.startswith("5"):
        category = CAT_HARD_BOUNCE
    elif enhanced_code.startswith("4.") or smtp_code.startswith("4"):
        category = CAT_SOFT_BOUNCE

    permanent = category in {
        CAT_HARD_BOUNCE,
        CAT_DOMAIN_UNREACHABLE,
        CAT_SPAM_REJECTION,
        CAT_UNSUBSCRIBE,
    }
    summary = f"{category} (smtp={smtp_code or 'n/a'}, enhanced={enhanced_code or 'n/a'})"
    return BounceReport(
        category=category,
        recipient=recipient,
        smtp_code=smtp_code,
        enhanced_code=enhanced_code,
        permanent_suppression=permanent,
        diagnostic_summary=summary,
    )


class SuppressionLedger:
    """SQLite suppression list for hard bounces, unsubscribes, and repeated soft bounces."""

    def __init__(self, db_path: str | Path, max_soft_bounces: int = 3) -> None:
        self.db_path = Path(db_path)
        self.max_soft_bounces = max_soft_bounces
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS suppression_entries (
                    email TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    smtp_code TEXT NOT NULL,
                    enhanced_code TEXT NOT NULL,
                    soft_count INTEGER NOT NULL DEFAULT 0,
                    suppressed INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def record_bounce(self, report: BounceReport) -> dict[str, Any]:
        """Record a BounceReport in SQLite and escalate soft bounces past max_soft_bounces."""
        if not report.recipient:
            raise ValueError("BounceReport requires a non-empty recipient email address.")
        email_key = report.recipient.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM suppression_entries WHERE email = ?",
                (email_key,),
            ).fetchone()

            if report.permanent_suppression:
                soft_count = int(existing["soft_count"]) if existing else 0
                suppressed = 1
            elif report.category == CAT_SOFT_BOUNCE:
                soft_count = (int(existing["soft_count"]) if existing else 0) + 1
                suppressed = 1 if soft_count >= self.max_soft_bounces else 0
            else:
                soft_count = int(existing["soft_count"]) if existing else 0
                suppressed = int(existing["suppressed"]) if existing else 0

            conn.execute(
                """
                INSERT INTO suppression_entries
                    (email, category, smtp_code, enhanced_code, soft_count, suppressed, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    category = excluded.category,
                    smtp_code = excluded.smtp_code,
                    enhanced_code = excluded.enhanced_code,
                    soft_count = excluded.soft_count,
                    suppressed = excluded.suppressed,
                    updated_at = excluded.updated_at
                """,
                (
                    email_key,
                    report.category,
                    report.smtp_code,
                    report.enhanced_code,
                    soft_count,
                    suppressed,
                    now_iso,
                ),
            )
            conn.commit()

        return {
            "email": email_key,
            "category": report.category,
            "soft_count": soft_count,
            "suppressed": bool(suppressed),
            "updated_at": now_iso,
        }

    def is_suppressed(self, email_address: str) -> bool:
        """Return True when email_address is marked as suppressed in the ledger."""
        key = email_address.strip().lower()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT suppressed FROM suppression_entries WHERE email = ?",
                (key,),
            ).fetchone()
            return bool(row and int(row["suppressed"]) == 1)
