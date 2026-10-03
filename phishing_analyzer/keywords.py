"""Social-engineering lure heuristics (French + English).

Text is normalised first (lower case, accents removed), so patterns are
written without accents: 'mot de passe', 'immediatement', 'verifier'.
These are heuristics: a legitimate password-reset mail will match too, which
is why they carry moderate weight and are reported with the matched terms.
"""

from __future__ import annotations

import re

from .models import Finding
from .parser import ParsedEmail
from .urls import html_visible_text
from .util import normalize_text

CATEGORIES: dict[str, dict] = {
    "urgency": {
        "title": "Urgency pressure", "severity": "low", "weight": 10, "attack": ["T1566"],
        "why": "Artificial deadlines push the reader to act before thinking or checking with a colleague.",
        "patterns": [
            r"\burgent(e|es|s)?\b", r"\burgence\b", r"\bimmediate(ly)?\b", r"\bimmediatement\b",
            r"\bwithin (24|48|72) ?(hours|hrs|h)\b", r"\b(sous|dans les|d'ici) (24|48|72) ?(h|heures)\b",
            r"\bfinal (notice|warning|reminder)\b", r"\bdernier (avis|rappel|delai)\b",
            r"\bact now\b", r"\bagissez (maintenant|vite)\b", r"\bsans delai\b",
            r"\bas soon as possible\b", r"\bdes que possible\b", r"\bexpires? (today|soon)\b",
            r"\bexpire (aujourd'hui|bientot)\b", r"\baujourd'hui (meme|avant)\b",
        ],
    },
    "threat": {
        "title": "Account threat / fear lure", "severity": "low", "weight": 10, "attack": ["T1566"],
        "why": "Threatening suspension, closure or legal action creates fear so the victim complies.",
        "patterns": [
            r"\b(account|access) (has been |will be )?(suspended|locked|blocked|disabled|closed|limited)\b",
            r"\bcompte (a ete |sera )?(suspendu|bloque|desactive|ferme|verrouille|restreint)\b",
            r"\bunusual (sign-?in )?activity\b", r"\bactivite (inhabituelle|suspecte)\b",
            r"\bunauthori[sz]ed (access|transaction|login)\b", r"\bacces non autorise\b",
            r"\blegal action\b", r"\bpoursuites( judiciaires)?\b",
        ],
    },
    "credential": {
        "title": "Credential / personal-data request", "severity": "medium", "weight": 15, "attack": ["T1598.003"],
        "why": "The message asks the reader to log in, confirm or 'update' secrets. Legitimate services "
               "do not request passwords, OTP codes or card numbers by e-mail.",
        "patterns": [
            r"\bverify (your )?(account|identity|email|information)\b",
            r"\bconfirm (your )?(identity|account|password|details|information|credentials)\b",
            r"\bupdate (your )?(payment|billing|account|banking) (information|details|method)\b",
            r"\bpassword\b", r"\bmot de passe\b", r"\bidentifiants?\b", r"\blogin details\b",
            r"\bsign in to (your )?account\b", r"\bconnectez-vous\b",
            r"\bverifie[rz] (votre|vos) (compte|identite|informations|coordonnees)\b",
            r"\b(confirme[rz]|mettre a jour|mettez a jour) (votre|vos) (identite|compte|informations|coordonnees|identifiants)\b",
            r"\bcode (otp|sms|de verification|de confirmation)\b", r"\bone[- ]time (code|password)\b",
            r"\b(card|carte) (number|bancaire)\b", r"\bnumero de carte\b", r"\bcvv\b",
        ],
    },
    "payment": {
        "title": "Payment / banking change request", "severity": "medium", "weight": 15, "attack": ["T1656"],
        "why": "Requests to pay, wire money or change bank details are the goal of invoice and CEO "
               "fraud. Always confirm by phone using a number you already know.",
        "patterns": [
            r"\bwire transfer\b", r"\bbank transfer\b", r"\bvirements?\b", r"\brib\b", r"\biban\b",
            r"\bswift\b", r"\bnew bank (account|details)\b",
            r"\bnouveaux? (compte|coordonnees bancaires|rib|iban)\b", r"\bchangement de (rib|coordonnees bancaires)\b",
            r"\bgift ?cards?\b", r"\bcartes? cadeaux?\b", r"\bfacture (impayee|en retard)\b",
            r"\b(invoice|payment) (overdue|pending)\b", r"\bfrais de (douane|livraison) (a regler|impayes)\b",
            r"\bpaiement des frais\b",
        ],
    },
    "secrecy": {
        "title": "Secrecy / isolation request", "severity": "low", "weight": 10, "attack": ["T1656"],
        "why": "Asking to keep the request confidential or saying the sender is unreachable stops the "
               "victim from verifying it - a typical BEC / CEO-fraud pattern.",
        "patterns": [
            r"\bconfidential\b", r"\bconfidentiel(le)?s?\b", r"\bstrictly private\b",
            r"\bkeep (this|it) (between us|private|confidential)\b",
            r"\bdiscret(e|ion)?\b", r"\bn'en parle[sz]? a personne\b", r"\bne (le dites|dis|dites|parle[sz]?) (rien|a personne)\b",
            r"\bdon'?t tell\b", r"\bi am in a meeting\b", r"\bi'?m in a meeting\b", r"\bje suis en reunion\b",
            r"\b(pas|plus) joignable\b", r"\binjoignable\b", r"\bcan'?t (talk|call)\b",
        ],
    },
}

_COMPILED = {k: [re.compile(p) for p in v["patterns"]] for k, v in CATEGORIES.items()}


def message_text(email: ParsedEmail) -> str:
    parts = [email.subject, email.text]
    for html in email.html_bodies:
        parts.append(html_visible_text(html))
    return normalize_text(" \n ".join(parts))


def match_categories(text: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for cat, regs in _COMPILED.items():
        found = []
        for r in regs:
            m = r.search(text)
            if m and m.group(0) not in found:
                found.append(m.group(0))
        if found:
            hits[cat] = found
    return hits


def analyze_keywords(email: ParsedEmail) -> tuple[dict[str, list[str]], list[Finding]]:
    hits = match_categories(message_text(email))
    findings = []
    for cat, terms in hits.items():
        c = CATEGORIES[cat]
        findings.append(Finding("kw_" + cat, "content", c["title"], c["severity"], c["weight"], c["why"],
                                "matched: " + ", ".join(f"'{t}'" for t in terms[:6]), c["attack"]))
    return hits, findings
