"""Orchestrates all detectors and builds the report dictionary."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .attachments import analyze_attachments
from .auth import analyze_auth
from .dns_check import dns_findings, lookup_sender_domain
from .headers import analyze_headers, public_hop_ips
from .keywords import analyze_keywords
from .lookalike import BrandList, check_domain
from .models import ATTACK, Finding
from .parser import ParsedEmail, parse_file
from .scoring import contributions, score, verdict
from .urls import analyze_urls, lookalike_finding
from .util import defang_domain, defang_url, is_ip, safe_display

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sender_lookalikes(email: ParsedEmail, brands: BrandList) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    candidates = []
    if email.from_addr:
        candidates.append(("From", email.from_addr.domain))
    candidates += [("Reply-To", a.domain) for a in email.reply_to]
    if email.return_path:
        candidates.append(("Return-Path", email.return_path.domain))
    for where, dom in candidates:
        if not dom or dom in seen:
            continue
        seen.add(dom)
        for r in check_domain(dom, brands):
            out.append(lookalike_finding(r, f"{where} address"))
    return out


def _bec_pattern(kw_hits: dict, email: ParsedEmail, links: list, findings: list[Finding]) -> list[Finding]:
    """Composite rule: money request + pressure/secrecy, with no link or file
    (BEC mails carry no payload so URL/attachment scanners miss them)."""
    if "payment" not in kw_hits or not ({"secrecy", "urgency"} & kw_hits.keys()):
        return []
    http_links = [lk for lk in links if lk.get("host")]
    if http_links or email.attachments:
        return []
    ids = {f.id for f in findings}
    extra = [i for i in ("reply_to_mismatch", "exec_impersonation", "display_name_spoof") if i in ids]
    return [Finding("bec_pattern", "content", "Business Email Compromise (CEO/invoice fraud) pattern",
                    "high", 15,
                    "Payment request + pressure/secrecy, with no link and no attachment: the attack is the "
                    "conversation itself, which link and attachment scanners cannot catch. Verify out-of-band "
                    "(call the requester on a known number) before any transfer.",
                    f"keyword groups: {', '.join(sorted(kw_hits))}"
                    + (f"; header signals: {', '.join(extra)}" if extra else ""),
                    ["T1684.001", "T1566"])]


def _iocs(email: ParsedEmail, links: list, hops, findings: list[Finding]) -> dict:
    flagged = {i for f in findings if f.weight > 0 for i in f.iocs}
    domains: dict[str, None] = {}
    for a in ([email.from_addr] if email.from_addr else []) + email.reply_to + ([email.return_path] if email.return_path else []):
        if a.domain:
            domains[a.domain] = None
    urls: dict[str, None] = {}
    url_host: dict[str, str] = {}
    ips: dict[str, None] = {}
    for lk in links:
        h = lk.get("host") or ""
        if lk["url"].lower().startswith(("http://", "https://", "www.")):
            urls[lk["url"]] = None
            url_host[lk["url"]] = h
        if h and is_ip(h):
            ips[h] = None
        elif h:
            domains[h] = None
    for ip in public_hop_ips(hops):
        ips[ip] = None
    return {
        "subject": email.subject,
        "sender_addresses": sorted({a.address for a in ([email.from_addr] if email.from_addr else [])
                                    + email.reply_to + ([email.return_path] if email.return_path else [])}),
        "domains": [{"value": d, "defanged": defang_domain(d), "flagged": d in flagged} for d in domains],
        "urls": [{"value": u, "defanged": defang_url(u), "flagged": u in flagged or url_host.get(u) in flagged} for u in urls],
        "ips": [{"value": i, "defanged": defang_domain(i), "flagged": i in flagged,
                 "source": "received-chain" if i in public_hop_ips(hops) else "url"} for i in ips],
        "hashes": [{"filename": safe_display(a.filename), "sha256": a.sha256, "md5": a.md5,
                    "flagged": a.sha256 in flagged} for a in email.attachments],
    }


def analyze_email(email: ParsedEmail, *, source: str = "", brands: BrandList | None = None,
                  online: bool = False, authserv_id: str | None = None,
                  txt_lookup: Callable[[str], list[str]] | None = None) -> dict:
    brands = brands or BrandList.load()
    findings: list[Finding] = []

    auth_summary, f = analyze_auth(email, authserv_id)
    findings += f
    hops, f = analyze_headers(email, brands)
    findings += f
    findings += _sender_lookalikes(email, brands)
    links, f = analyze_urls(email, brands)
    findings += f
    findings += analyze_attachments(email)
    kw_hits, f = analyze_keywords(email)
    findings += f
    findings += _bec_pattern(kw_hits, email, links, findings)

    dns_info = None
    if online:
        dom = email.from_addr.domain if email.from_addr else ""
        dns_info = lookup_sender_domain(dom, txt_lookup)
        findings += dns_findings(dns_info)

    findings.sort(key=lambda x: (-x.weight, SEVERITY_ORDER[x.severity], x.id))
    total = score(findings)
    techniques = sorted({t for x in findings if x.weight > 0 for t in x.attack})
    return {
        "tool": {"name": "phishing-analyzer", "version": __version__},
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "message": {
            "sha256": email.raw_sha256,
            "size": email.raw_size,
            "subject": email.subject,
            "from": email.from_addr.to_dict() if email.from_addr else None,
            "reply_to": [a.to_dict() for a in email.reply_to],
            "return_path": email.return_path.to_dict() if email.return_path else None,
            "to": [a.to_dict() for a in email.to],
            "cc": [a.to_dict() for a in email.cc],
            "date": email.date,
            "message_id": email.message_id,
            "parse_defects": email.defects,
        },
        "authentication": auth_summary,
        "dns": dns_info,
        "received_chain": [h.to_dict() for h in hops],
        "urls": links,
        "attachments": [dict(a.to_dict(), filename=safe_display(a.filename)) for a in email.attachments],
        "keyword_hits": kw_hits,
        "findings": [x.to_dict() for x in findings],
        "score": total,
        "score_breakdown": contributions(findings),
        "verdict": verdict(total, findings),
        "attack_techniques": [{"id": t, "name": ATTACK[t]} for t in techniques],
        "iocs": _iocs(email, links, hops, findings),
    }


def analyze_file(path: str | Path, **kwargs) -> dict:
    p = Path(path)
    return analyze_email(parse_file(p), source=str(p), **kwargs)
