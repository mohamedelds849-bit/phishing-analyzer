"""Header anomalies: sender identity mismatches, display-name spoofing,
executive impersonation, and the Received hop chain."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .lookalike import BrandList
from .models import Finding
from .parser import ParsedEmail
from .util import EMAIL_RE, is_ip, normalize_text, org_domain

EXEC_TITLE_RE = re.compile(
    r"\b(pdg|ceo|cfo|coo|dg|daf|president|presidente|directeur general|directrice generale|"
    r"directeur financier|directrice financiere|managing director|chief executive|"
    r"chief financial|gerant|gerante)\b"
)
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
IPV6_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,})\]")


@dataclass
class Hop:
    index: int
    from_host: str
    from_ip: str
    by_host: str
    timestamp: str
    delay_seconds: float | None
    raw: str

    def to_dict(self) -> dict:
        return asdict(self)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_date(value: str) -> datetime | None:
    try:
        return _to_utc(parsedate_to_datetime(value.strip()))
    except (TypeError, ValueError, IndexError):
        return None


def _first_ip(text: str) -> str:
    candidates = IPV4_RE.findall(text) + IPV6_RE.findall(text)
    for c in candidates:
        try:
            ip = ipaddress.ip_address(c)
        except ValueError:
            continue
        return str(ip)
    return ""


def parse_received(value: str, index: int = 0) -> tuple[Hop, datetime | None]:
    v = " ".join((value or "").split())
    main, ts = v, None
    if ";" in v:
        main, _, dpart = v.rpartition(";")
        ts = _parse_date(dpart)
    m_from = re.search(r"\bfrom\s+(\S+)(.*?)(?=\bby\b|$)", main, re.I)
    m_by = re.search(r"\bby\s+(\S+)", main, re.I)
    from_host = m_from.group(1) if m_from else ""
    from_ip = _first_ip(m_from.group(0)) if m_from else ""
    hop = Hop(index=index, from_host=from_host, from_ip=from_ip,
              by_host=m_by.group(1) if m_by else "",
              timestamp=ts.isoformat() if ts else "", delay_seconds=None, raw=v)
    return hop, ts


def received_chain(email: ParsedEmail) -> tuple[list[Hop], list[datetime | None]]:
    """Hops ordered oldest (origin) first. Received headers are prepended by
    each server, so the file order is reversed."""
    hops, times = [], []
    prev = None
    for i, raw in enumerate(reversed(email.received), start=1):
        hop, ts = parse_received(raw, i)
        if ts is not None and prev is not None:
            hop.delay_seconds = (ts - prev).total_seconds()
        if ts is not None:
            prev = ts
        hops.append(hop)
        times.append(ts)
    return hops, times


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10")]


def public_hop_ips(hops: list[Hop]) -> list[str]:
    """Relay IPs worth putting in a ticket: everything except internal ranges
    (RFC 1918, loopback, link-local, CGNAT). Documentation ranges (RFC 5737)
    are kept on purpose so the synthetic samples show realistic output."""
    out = []
    for h in hops:
        if not h.from_ip:
            continue
        ip = ipaddress.ip_address(h.from_ip)
        if not any(ip in n for n in _INTERNAL_NETS if n.version == ip.version) and h.from_ip not in out:
            out.append(h.from_ip)
    return out


def analyze_headers(email: ParsedEmail, brands: BrandList) -> tuple[list[Hop], list[Finding]]:
    f: list[Finding] = []
    frm = email.from_addr
    hops, times = received_chain(email)

    if frm is None:
        f.append(Finding("from_missing", "header", "No parsable From address", "medium", 10,
                         "A message without a valid From: address is malformed; legitimate mail "
                         "systems always set one.", email.header("from") or "(absent)", ["T1566"]))
    from_dom = frm.domain if frm else ""
    from_org = org_domain(from_dom)

    # --- Reply-To diverts the conversation elsewhere (classic BEC) ---------
    for rt in email.reply_to:
        if from_org and rt.domain and org_domain(rt.domain) != from_org:
            f.append(Finding("reply_to_mismatch", "header", "Reply-To points to a different domain",
                             "medium", 20,
                             "Replies will go to a different organisation than the visible sender. "
                             "Attackers use this so the victim's answer (or payment confirmation) "
                             "reaches a mailbox they control, while From: looks trustworthy.",
                             f"From={from_dom}  Reply-To={rt.address}", ["T1656", "T1566"],
                             iocs=[rt.domain]))
            break

    # --- Return-Path (envelope sender) ----------------------------------
    rp = email.return_path
    if rp and from_org and rp.domain and org_domain(rp.domain) != from_org:
        f.append(Finding("return_path_mismatch", "header", "Return-Path differs from From domain", "low", 5,
                         "The envelope sender (bounce address) belongs to another domain. This is NORMAL "
                         "for newsletters sent through an e-mail service provider, so it is low weight; it "
                         "matters when combined with failed SPF/DMARC.",
                         f"From={from_dom}  Return-Path={rp.address}", ["T1566"]))

    if frm:
        dn = frm.display_name or ""
        ndn = normalize_text(dn)
        # --- Display name contains an address / domain other than the real one
        m = EMAIL_RE.search(dn)
        if m and org_domain(m.group(0).rpartition("@")[2]) != from_org:
            f.append(Finding("display_name_spoof", "header", "Display name shows a different e-mail address",
                             "high", 25,
                             "Most mail clients show only the display name. Here it contains an address "
                             "that is NOT the real sender, so the user sees a trusted address while the "
                             "message actually comes from elsewhere.",
                             f"display='{dn}'  real=<{frm.address}>", ["T1656"], iocs=[from_dom]))
        # --- Display name claims a protected brand from a non-official domain
        for b in brands.brands:
            hit = next((w for w in b.display_names if re.search(r"\b" + re.escape(normalize_text(w)) + r"\b", ndn)), None)
            if hit and not b.is_official(from_dom):
                f.append(Finding("brand_display_name", "header", f"Display name impersonates {b.name}",
                                 "high", 20,
                                 f"The sender name says '{dn}' but the address domain '{from_dom}' is not "
                                 f"one of {b.name}'s official domains ({', '.join(b.domains)}).",
                                 f"display='{dn}'  real=<{frm.address}>", ["T1656"], iocs=[from_dom]))
                break
        # --- Executive title from an external domain (CEO fraud) ------------
        rcpt_orgs = {org_domain(a.domain) for a in email.to + email.cc if a.domain}
        if EXEC_TITLE_RE.search(ndn) and rcpt_orgs and from_org not in rcpt_orgs:
            f.append(Finding("exec_impersonation", "header", "Executive title used by an external sender",
                             "medium", 15,
                             "The display name carries an executive title (CEO/PDG/DG/DAF...) but the "
                             "address is outside the recipient's organisation. Real executives normally "
                             "write from the corporate domain - a hallmark of CEO fraud / BEC.",
                             f"display='{dn}' from={from_dom} recipient domain(s)={', '.join(sorted(rcpt_orgs))}",
                             ["T1656"], iocs=[from_dom]))

    # --- Message-ID domain ---------------------------------------------------
    mid = email.message_id.strip("<> ")
    if mid and "@" in mid and from_org:
        mid_dom = mid.rpartition("@")[2].lower()
        if org_domain(mid_dom) != from_org and not is_ip(mid_dom):
            f.append(Finding("message_id_mismatch", "header", "Message-ID domain differs from From", "low", 3,
                             "The Message-ID was generated by a host of another domain. Common with "
                             "third-party senders; weak signal on its own.",
                             f"Message-ID domain={mid_dom} From={from_dom}"))

    # --- Received chain sanity ---------------------------------------------
    if not hops:
        f.append(Finding("received_missing", "header", "No Received headers", "low", 5,
                         "Every relayed message gains Received headers. None at all suggests the file was "
                         "crafted or stripped - analyse the original from the mailbox.", "0 hops"))
    else:
        for h in hops:
            if h.delay_seconds is not None and h.delay_seconds < -300:
                f.append(Finding("received_time_travel", "header", "Received timestamps go backwards", "low", 5,
                                 "A later hop is timestamped before the previous one. Could be clock skew, "
                                 "but forged Received headers often show impossible timelines.",
                                 f"hop {h.index}: {h.delay_seconds:.0f}s"))
                break
        date_hdr = _parse_date(email.date) if email.date else None
        first_ts = next((t for t in times if t is not None), None)
        if date_hdr and first_ts:
            skew = (first_ts - date_hdr).total_seconds()
            if skew < -3600 or skew > 3 * 86400:
                f.append(Finding("date_anomaly", "header", "Date header inconsistent with Received chain", "low", 5,
                                 "The Date: header is far from when the first server received the message "
                                 "(future-dated or days old). Weak on its own; can indicate a re-sent or "
                                 "crafted message.", f"Date={email.date}  first hop={first_ts.isoformat()}"))
    return hops, f
