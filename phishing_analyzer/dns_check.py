"""Optional live DNS context for the sender domain (--online only).

SPF/DMARC parsing follows the same approach as the rssi-audit project's
modules/email_dns.py (find 'v=spf1' / 'v=DMARC1', read the 'all' qualifier
and the 'p=' policy). Only public DNS TXT records are queried; nothing is
sent to the sender's servers. Requires dnspython.
"""

from __future__ import annotations

import re
from typing import Callable

from .models import Finding
from .util import org_domain


class NXDomain(Exception):
    """The queried name does not exist."""


class NoRecords(Exception):
    """The name exists but has no TXT record."""


def _dnspython_txt(timeout: float = 5.0) -> Callable[[str], list[str]]:
    import dns.exception
    import dns.resolver

    res = dns.resolver.Resolver()
    res.lifetime = timeout

    def lookup(name: str) -> list[str]:
        try:
            answers = res.resolve(name, "TXT")
        except dns.resolver.NXDOMAIN as e:
            raise NXDomain(name) from e
        except dns.resolver.NoAnswer as e:
            raise NoRecords(name) from e
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]

    return lookup


def spf_qualifier(spf: str | None) -> str | None:
    if not spf:
        return None
    m = re.search(r"([-~?+])all\b", spf, re.I)
    if m:
        return m.group(1) + "all"
    if re.search(r"\ball\b", spf, re.I):
        return "+all"
    return None


def dmarc_policy(dmarc: str | None) -> str | None:
    if not dmarc:
        return None
    m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", dmarc)
    return m.group(1).lower() if m else None


def lookup_sender_domain(domain: str, txt_lookup: Callable[[str], list[str]] | None = None) -> dict:
    info = {"domain": domain, "exists": None, "spf": None, "spf_all": None,
            "dmarc": None, "dmarc_policy": None, "error": None}
    if not domain:
        info["error"] = "no sender domain"
        return info
    if txt_lookup is None:
        try:
            txt_lookup = _dnspython_txt()
        except ImportError:
            info["error"] = "dnspython not installed (pip install dnspython)"
            return info
    org = org_domain(domain)
    try:
        try:
            recs = txt_lookup(org)
            info["exists"] = True
        except NoRecords:
            recs, info["exists"] = [], True
        info["spf"] = next((r for r in recs if r.lower().strip().startswith("v=spf1")), None)
        info["spf_all"] = spf_qualifier(info["spf"])
        for name in dict.fromkeys(["_dmarc." + domain, "_dmarc." + org]):
            try:
                d = next((r for r in txt_lookup(name) if r.replace(" ", "").lower().startswith("v=dmarc1")), None)
            except (NXDomain, NoRecords):
                d = None
            if d:
                info["dmarc"], info["dmarc_policy"] = d, dmarc_policy(d)
                break
    except NXDomain:
        info["exists"] = False
    except Exception as e:  # timeout, no nameservers, network down...
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def dns_findings(info: dict) -> list[Finding]:
    d = info.get("domain") or ""
    if info.get("error"):
        return [Finding("dns_error", "dns", "Live DNS lookup unavailable", "info", 0,
                        "The --online lookup could not complete; offline results are unaffected.",
                        info["error"])]
    if info.get("exists") is False:
        return [Finding("sender_domain_nxdomain", "dns", "Sender domain does not exist in DNS", "medium", 15,
                        "The From: organisational domain returns NXDOMAIN: nobody can reply to or "
                        "authenticate it. Either a throw-away/forged domain or one already taken down.",
                        org_domain(d), ["T1566"], [org_domain(d)])]
    out = []
    if not info.get("spf"):
        out.append(Finding("sender_no_spf", "dns", "Sender domain publishes no SPF record", "low", 8,
                           "Without SPF, any server can send mail as this domain, so From: cannot be trusted.",
                           org_domain(d), ["T1566"]))
    elif info.get("spf_all") == "+all":
        out.append(Finding("sender_spf_permissive", "dns", "Sender SPF allows any server (+all)", "medium", 10,
                           "An SPF record ending in +all authorises the whole Internet: a pass means nothing.",
                           info["spf"], ["T1566"]))
    if not info.get("dmarc"):
        out.append(Finding("sender_no_dmarc", "dns", "Sender domain publishes no DMARC record", "low", 8,
                           "Without DMARC, receivers have no instruction to reject mail spoofing this domain.",
                           "_dmarc." + org_domain(d), ["T1566"]))
    elif info.get("dmarc_policy") == "none":
        out.append(Finding("sender_dmarc_none", "dns", "Sender DMARC policy is p=none (monitor only)", "low", 3,
                           "DMARC is in monitoring mode: spoofed mail is still delivered.", info["dmarc"]))
    return out
