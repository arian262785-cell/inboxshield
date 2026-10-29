"""Command-line interface for inboxshield."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bounce import SuppressionLedger, analyze_bounce_text
from .classifier import classify_reply
from .sanitizer import sanitize_file, sanitize_text


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the inboxshield CLI."""
    parser = argparse.ArgumentParser(
        prog="inboxshield",
        description="Zero-trust RFC 5322 email sanitizer, RFC 3463 DSN bounce parser, and DACH B2B reply classifier.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_san = sub.add_parser("sanitize", help="Sanitize an .eml or .json MIME message file.")
    p_san.add_argument("input", help="Path to the .eml or .json message file.")
    p_san.add_argument("-o", "--output", help="Optional path to write the JSON sanitized result.")

    p_bnc = sub.add_parser("bounce", help="Analyze a DSN bounce file and optionally update a SQLite suppression ledger.")
    p_bnc.add_argument("input", help="Path to a bounce .eml or plain text file.")
    p_bnc.add_argument("--recipient", default="", help="Fallback recipient email address.")
    p_bnc.add_argument("--ledger", help="Optional SQLite database path to record the bounce.")

    p_cls = sub.add_parser("classify", help="Classify a DACH B2B reply (.txt or .eml).")
    p_cls.add_argument("input", help="Path to a reply .txt or .eml file.")

    p_chk = sub.add_parser("suppress-check", help="Check if an email address is suppressed in the SQLite ledger.")
    p_chk.add_argument("email", help="Email address to check.")
    p_chk.add_argument("--ledger", required=True, help="Path to the SQLite suppression ledger.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute the inboxshield CLI command and return an exit status code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sanitize":
        msg = sanitize_file(args.input)
        payload = msg.to_dict()
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "bounce":
        in_path = Path(args.input)
        if in_path.suffix.lower() == ".eml":
            san = sanitize_file(in_path)
            raw_text = f"{san.subject}\n{san.body_text}"
        else:
            raw_text = in_path.read_text(encoding="utf-8", errors="replace")
        report = analyze_bounce_text(raw_text, fallback_recipient=args.recipient)
        result = report.to_dict()
        if args.ledger and report.recipient:
            ledger = SuppressionLedger(args.ledger)
            result["ledger_entry"] = ledger.record_bounce(report)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "classify":
        in_path = Path(args.input)
        if in_path.suffix.lower() in (".eml", ".json"):
            san = sanitize_file(in_path)
            text = f"{san.subject}\n{san.body_text}"
        else:
            text = sanitize_text(in_path.read_text(encoding="utf-8", errors="replace"))
        cls_res = classify_reply(text)
        print(json.dumps(cls_res.to_dict(), indent=2))
        return 0

    if args.command == "suppress-check":
        ledger = SuppressionLedger(args.ledger)
        suppressed = ledger.is_suppressed(args.email)
        print(json.dumps({"email": args.email.lower(), "suppressed": suppressed}, indent=2))
        return 2 if suppressed else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
