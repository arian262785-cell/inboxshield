"""Deterministic rule-based DACH B2B reply and autoresponder classifier."""

from __future__ import annotations

import re

from .spec import ReplyClassification

_AUTORESPONDER = [
    r"abwesenheit",
    r"abwesenheitsnotiz",
    r"out of office",
    r"automatische (?:antwort|eingangsbestätigung|eingangsbestaetigung)",
    r"automatic reply",
    r"nicht im (?:büro|buero|hause)",
    r"im urlaub",
    r"außer haus",
    r"ausser haus",
    r"betriebsruhe",
    r"meine e-?mails werden nicht weitergeleitet",
    r"eingangsbestätigung",
    r"eingangsbestaetigung",
    r"bestätigen (?:wir )?den eingang",
    r"ihre (?:nachricht|anfrage|e-?mail|mail) ist (?:bei uns )?eingegangen",
    r"wir haben ihre (?:nachricht|anfrage|e-?mail|mail) erhalten",
    r"diese e-?mail-?adresse ist (?:aktuell|derzeit) nicht erreichbar",
    r"patientinnen und patienten",
    r"tierbesitzerinnen und tierbesitzer",
    r"ihr praxisteam",
    r"planbare termine",
    r"termine.*online buchen",
    r"termine.*(?:vorher|rechtzeitig).*absagen",
    r"ausfallgebühr",
    r"außerhalb unserer öffnungszeiten",
    r"ausserhalb unserer oeffnungszeiten",
]

_UNSUBSCRIBE = [
    r"abmelden",
    r"melden sie (?:uns|mich) ab\b",
    r"bitte keine (?:weitere[nr]? )?werbung",
    r"keine (?:weitere[nr]? )?(?:werbung|mails?|e-?mails?|nachrichten|angebote|kontaktaufnahme)",
    r"nicht mehr kontaktieren",
    r"nicht mehr anschreiben",
    r"aus (?:ihrem|dem|unserem) (?:verteiler|system)",
    r"(?:verteiler|system).*(?:löschen|entfernen|nehmen|rausnehmen|austragen)",
    r"unsubscribe",
    r"opt-?out",
    r"widerspruch",
    r"widerspreche",
    r"art\.?\s*(?:17|21)",
    r"unterlassen sie",
]

_WRONG_CONTACT = [
    r"falsch verbunden",
    r"bin nicht (?:mehr )?zuständig",
    r"nicht der richtige ansprechpartner",
    r"falscher ansprechpartner",
    r"da sind sie bei mir falsch",
]

_REFERRAL = [
    r"wenden sie sich (?:bitte )?an",
    r"zuständig (?:dafür )?ist (?:herr|frau)",
    r"sprechen sie (?:bitte )?mit (?:herr|frau)",
    r"leiten? (?:das|ihre anfrage) weiter an",
]

_CONTACT_LATER = [
    r"aktuell keine zeit",
    r"gerade keine zeit",
    r"melden sie sich (?:in|nach|bitte)",
    r"zu einem späteren zeitpunkt",
    r"in (?:ein paar|einigen|\d+) (?:wochen|monaten)",
    r"nächstes (?:jahr|quartal)",
]

_REJECT = [
    r"kein(?:e|erlei)? interesse",
    r"nicht interessiert",
    r"sind wir nicht interessiert",
    r"kein(?:en)? bedarf",
    r"brauchen wir nicht",
    r"nein,? danke",
    r"danke,? nein",
    r"aus altersgründen",
    r"(?:kanzlei|betrieb).*schließe",
    r"möchten (?:wir )?nicht",
    r"moechten (?:wir )?nicht",
    r"nicht umsteigen",
    r"sind (?:mit (?:unserer|der) .* )?zufrieden",
    r"keine zusammenarbeit",
    r"haben kein budget",
]

_HAS_SOLUTION = [
    r"haben (?:schon|bereits)",
    r"eigene (?:website|homepage|lösung)",
    r"andere agentur",
]

_REFERENCE = [
    r"referenz",
    r"andere kunden",
    r"case ?stud",
    r"beispiele von",
]

_PRICE = [
    r"was kostet",
    r"was würde .* kosten",
    r"was wuerde .* kosten",
    r"wie teuer",
    r"welche kosten",
    r"mit welchen kosten",
    r"wie hoch sind die kosten",
    r"wie sind (?:die|ihre) preise",
    r"haben sie eine preisliste",
    r"(?:schicken|senden|unterbreiten) sie (?:uns|mir) (?:ein|ihr) angebot",
    r"bitte um ein angebot",
]

_INTEREST = [
    r"klingt (?:gut|interessant|spannend)",
    r"(?:haben|hätten|haetten) (?:wir )?interesse",
    r"sind (?:wir )?interessiert",
    r"gerne mehr",
    r"(?:schicken|senden) sie (?:uns|mir) (?:gerne )?(?:mehr|weitere|ein paar) infos",
    r"können wir (?:gerne )?(?:mal )?(?:telefonieren|sprechen|uns unterhalten)",
    r"koennen wir (?:gerne )?(?:mal )?(?:telefonieren|sprechen|uns unterhalten)",
    r"lassen sie uns (?:telefonieren|sprechen)",
    r"schlagen sie (?:einen )?termin vor",
    r"termin (?:vorschlagen|vereinbaren)",
    r"wann (?:passt|hätten sie|haben sie zeit)",
    r"rufen sie mich (?:gerne )?an",
    r"melden sie sich (?:gerne )?telefonisch",
]

_MEETING_SIGNAL = [
    r"termin (?:vorschlagen|vereinbaren|ausmachen|machen|abstimmen|finden)",
    r"(?:schlagen sie|geben sie mir) einen termin vor",
    r"terminvorschlag",
    r"können wir .* (?:telefonieren|sprechen|uns unterhalten)",
    r"koennen wir .* (?:telefonieren|sprechen|uns unterhalten)",
    r"lassen sie uns (?:telefonieren|sprechen)",
    r"\btelefonieren\b",
    r"videocall",
    r"kurzer call",
    r"telefontermin",
    r"erstgespräch",
    r"erstgespraech",
    r"wann (?:passt|hätten sie|haben sie zeit)",
    r"rufen sie mich (?:gerne )?an",
    r"melden sie sich (?:gerne )?telefonisch",
]

_ORDERED_RULES: list[tuple[str, list[str], bool]] = [
    ("autoresponder", _AUTORESPONDER, False),
    ("unsubscribe", _UNSUBSCRIBE, False),
    ("wrong_contact", _WRONG_CONTACT, True),
    ("referral", _REFERRAL, True),
    ("contact_later", _CONTACT_LATER, True),
    ("reject", _REJECT, False),
    ("has_solution", _HAS_SOLUTION, True),
    ("reference_request", _REFERENCE, True),
    ("price_inquiry", _PRICE, True),
    ("interest", _INTEREST, True),
]


def has_meeting_signal(text: str) -> bool:
    """Return True if the message text contains an explicit call or appointment request."""
    lowered = (text or "").lower()
    return any(re.search(pattern, lowered) for pattern in _MEETING_SIGNAL)


def classify_reply(text: str) -> ReplyClassification:
    """Classify an inbound DACH B2B reply according to deterministic priority rules."""
    lowered = (text or "").lower()

    for category, patterns, human_review in _ORDERED_RULES:
        for pattern in patterns:
            if re.search(pattern, lowered):
                meeting = has_meeting_signal(lowered) if category not in ("autoresponder", "unsubscribe", "reject") else False
                return ReplyClassification(
                    category=category,
                    meeting_signal=meeting,
                    matched_pattern=pattern,
                    requires_human_review=human_review,
                )

    return ReplyClassification(
        category="unclear",
        meeting_signal=has_meeting_signal(lowered),
        matched_pattern="",
        requires_human_review=True,
    )
