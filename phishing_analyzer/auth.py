"""SPF / DKIM / DMARC verdicts from Authentication-Results and Received-SPF.

Trust model: these headers are written by *receiving* servers. An attacker can
insert a fake 'Authentication-Results: ... dmarc=pass' header themselves, so we
evaluate only the TOPMOST header (added last, by your own gateway) - or the
first one whose authserv-id matches --authserv-id when the analyst supplies it.
"""

from __future__ import annotations

import re

from .models import Finding
from .parser import ParsedEmail
from .util import org_domain

METHOD_RE = re.compile(r"^\s*(spf|dkim|dmarc|arc|iprev|auth|bimi)\s*=\s*([A-Za-z]+)\b(.*)$", re.I | re.S)
PROP_RE = re.compile(r"\b((?:smtp|header|policy)\.[A-Za-z0-9_\-]+)\s*=\s*(\"?)([^\s;\"]+)\2")
RSPF_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", re.I)

_ALIASES = {"hardfail": "fail", "bestguesspass": "pass"}


def parse_authentication_results(value: str) -> dict:
    """Parse one Authentication-Results header (RFC 8601, tolerant)."""
    text = re.sub(r"\([^()]*\)", " ", value or "")  # drop (comments)
    clauses = text.split(";")
    authserv = ""
    start = 0
    head = clauses[0].strip() if clauses else ""
    if head and not METHOD_RE.match(head):
        authserv = head.split()[0]
        start = 1
    results = []
    for clause in clauses[start:]:
        m = METHOD_RE.match(clause)
        if not m:
            continue
        result = m.group(2).lower()
        results.append({
            "method": m.group(1).lower(),
            "result": _ALIASES.get(result, result),
            "props": {k.lower(): v for k, _, v in PROP_RE.findall(m.group(3))},
        })
    return {"authserv_id": authserv, "results": results}


def summarize_auth(email: ParsedEmail, authserv_id: str | None = None) -> dict:
    summary = {
        "spf": None, "dkim": None, "dmarc": None,
        "source": None, "authserv_id": None,
        "dkim_domains": [], "smtp_mailfrom": None,
        "ignored_headers": 0, "requested_authserv_id": authserv_id,
        "requested_authserv_found": None,
    }
    chosen = None
    for raw in email.auth_results:
        parsed = parse_authentication_results(raw)
        if authserv_id is None or parsed["authserv_id"].lower() == authserv_id.lower():
            chosen = parsed
            break
    if authserv_id is not None:
        summary["requested_authserv_found"] = chosen is not None
    if chosen is not None:
        summary["source"] = "Authentication-Results"
        summary["authserv_id"] = chosen["authserv_id"]
        summary["ignored_headers"] = len(email.auth_results) - 1
        dkim_results = []
        for r in chosen["results"]:
            if r["method"] == "dkim":
                dkim_results.append(r["result"])
                d = r["props"].get("header.d", "")
                if not d:  # header.i = "@example.com" or "user@example.com"
                    d = r["props"].get("header.i", "").rpartition("@")[2]
                if d and r["result"] == "pass":
                    summary["dkim_domains"].append(d.lower())
            elif r["method"] in ("spf", "dmarc") and summary[r["method"]] is None:
                summary[r["method"]] = r["result"]
                if r["method"] == "spf":
                    summary["smtp_mailfrom"] = r["props"].get("smtp.mailfrom")
        if dkim_results:
            summary["dkim"] = "pass" if "pass" in dkim_results else dkim_results[0]
    if summary["spf"] is None and email.received_spf:
        m = RSPF_RE.match(email.received_spf[0])
        if m:
            summary["spf"] = m.group(1).lower()
            summary["source"] = summary["source"] or "Received-SPF"
    return summary


def analyze_auth(email: ParsedEmail, authserv_id: str | None = None) -> tuple[dict, list[Finding]]:
    s = summarize_auth(email, authserv_id)
    f: list[Finding] = []
    spf, dkim, dmarc = s["spf"], s["dkim"], s["dmarc"]
    ev = f"spf={spf} dkim={dkim} dmarc={dmarc} (authserv-id={s['authserv_id']})"

    if authserv_id is not None and not s["requested_authserv_found"]:
        f.append(Finding("auth_untrusted", "auth", "No Authentication-Results from your trusted server",
                         "low", 5,
                         f"No Authentication-Results header carries authserv-id '{authserv_id}'. Any auth "
                         "header present may have been forged by the sender, so it was not trusted.",
                         f"{len(email.auth_results)} Authentication-Results header(s) present"))

    if spf is None and dkim is None and dmarc is None:
        if not email.auth_results and not email.received_spf:
            f.append(Finding("auth_missing", "auth", "No authentication results in headers", "low", 5,
                             "The message carries no Authentication-Results / Received-SPF header, so "
                             "SPF/DKIM/DMARC cannot be verified offline. Export the original message "
                             "(with full headers) from the mailbox, or use --online for DNS context.",
                             "headers absent"))
        return s, f

    if dmarc == "fail":
        f.append(Finding("dmarc_fail", "auth", "DMARC failed", "high", 30,
                         "DMARC checks that the visible From: domain is backed by an aligned SPF or DKIM "
                         "pass. A failure means the sender is very likely NOT the domain shown in From: "
                         "(direct domain spoofing).", ev, ["T1656", "T1566"]))
    if spf in ("fail",):
        f.append(Finding("spf_fail", "auth", "SPF failed", "medium", 15,
                         "The sending server's IP is not authorised by the envelope-sender domain's SPF "
                         "record (-all). The message did not come from that domain's infrastructure.",
                         ev, ["T1566"]))
    elif spf == "softfail":
        f.append(Finding("spf_softfail", "auth", "SPF softfail", "low", 8,
                         "SPF returned softfail (~all): the IP is probably not authorised, but the domain "
                         "owner asked receivers not to reject outright.", ev, ["T1566"]))
    if dkim in ("fail", "permerror"):
        f.append(Finding("dkim_fail", "auth", "DKIM signature invalid", "medium", 10,
                         "A DKIM signature is present but does not verify: the signed headers/body were "
                         "altered in transit or the signature was forged.", ev, ["T1566"]))
    if spf in (None, "none") and dkim in (None, "none") and dmarc in (None, "none"):
        f.append(Finding("auth_none", "auth", "Sender is not authenticated at all", "low", 8,
                         "Neither SPF, DKIM nor DMARC produced a result. Anyone can send mail claiming "
                         "this domain; authenticity is unproven.", ev, ["T1566"]))

    from_dom = email.from_addr.domain if email.from_addr else ""
    if dkim == "pass" and from_dom and dmarc != "pass":
        if not any(org_domain(d) == org_domain(from_dom) for d in s["dkim_domains"]):
            f.append(Finding("dkim_not_aligned", "auth", "DKIM signer does not match From domain", "low", 5,
                             "The valid DKIM signature belongs to a different organisational domain than "
                             "the From: address, so it does not vouch for the visible sender (common with "
                             "bulk-mail providers, but also with spoofing).",
                             f"From={from_dom} DKIM d={','.join(s['dkim_domains'])}", ["T1656"]))

    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        f.append(Finding("auth_pass", "auth", "SPF, DKIM and DMARC all pass", "info", 0,
                         "The message is authenticated for its From: domain. NOTE: this proves only that "
                         "the domain owner sent it - attackers who register a lookalike domain pass all "
                         "three checks too. Check the domain itself (lookalike findings).", ev))
    if s["ignored_headers"] > 0:
        f.append(Finding("auth_extra_headers", "auth", "Additional Authentication-Results headers ignored",
                         "info", 0,
                         "Only the topmost (or --authserv-id matching) header is trusted; lower headers "
                         "can be injected by the sender or by intermediate hops.",
                         f"{s['ignored_headers']} header(s) ignored"))
    return s, f
