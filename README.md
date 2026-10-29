# inboxshield

`inboxshield` is a zero-dependency Python library and CLI for deterministic email preprocessing before downstream automation or LLM ingestion. It strips non-text MIME parts and attachments from RFC 5322 `.eml` and REST API JSON payloads, neutralizes external links and prompt/shell injection strings, parses RFC 3463 / RFC 3464 Delivery Status Notifications (DSN) with SQLite suppression tracking, and classifies German (DACH) B2B replies using ordered precedence rules.

## Package Layout

```text
src/inboxshield/
  __init__.py
  spec.py        # SanitizedMessage, BounceReport, and ReplyClassification dataclasses
  sanitizer.py   # RFC 5322 .eml and JSON MIME tree parser, link and injection filter
  bounce.py      # RFC 3463/3464 DSN bounce analyzer and SQLite SuppressionLedger
  classifier.py  # Deterministic DACH B2B reply and autoresponder classifier
  cli.py         # CLI entry point (sanitize, bounce, classify, suppress-check)
examples/
  sample_dsn_bounce.eml
  sample_dach_replies.json
tests/
  test_inboxshield.py
```

## Installation

```bash
pip install -e .
```

Dependencies: Python `>=3.10` standard library only.

## Usage

Sanitize an untrusted `.eml` or JSON MIME file (strips attachments, HTML, links, and injection strings):

```bash
inboxshield sanitize message.eml -o sanitized.json
```

Parse a DSN bounce message and update a SQLite suppression ledger:

```bash
inboxshield bounce examples/sample_dsn_bounce.eml --ledger suppression.sqlite3
```

Check whether a recipient address is suppressed in the ledger (exits `2` if suppressed, `0` if clear):

```bash
inboxshield suppress-check unknown.recipient@example.de --ledger suppression.sqlite3
```

Classify a German B2B reply message:

```bash
inboxshield classify reply.txt
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
