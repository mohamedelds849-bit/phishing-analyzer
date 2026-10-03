"""URL extraction (text + HTML) and link-level phishing heuristics.

The HTML body is parsed with html.parser only to *read* tags; it is never
rendered, and no URL is ever fetched.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .lookalike import BrandList, check_domain
from .models import Finding
from .parser import ParsedEmail
from .util import is_ip, normalize_host, org_domain

URL_TEXT_RE = re.compile(r"(?:\b[a-z][a-z0-9+.\-]*://|\bwww\.)[^\s<>\"'`]+", re.I)
DOMAIN_IN_TEXT_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]*://)?((?:[\w\-]+\.)+[^\W\d_]{2,})(?=[/:?#\s]|$)", re.I)
TRAILING = ".,;:!?)]}>'\""

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bl.ink", "s.id", "v.gd", "lnkd.in",
    "shorte.st", "adf.ly", "qrco.de",
}
# TLDs frequently reported as heavily abused in phishing (heuristic list,
# low weight - plenty of legitimate sites use them too).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "rest", "cam", "icu", "monster", "cyou", "sbs", "lol", "quest", "buzz", "bond", "cfd",
}
SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "sms:", "#")
SCRIPT_SCHEMES = ("javascript:", "data:", "vbscript:")


class _HTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self.srcs: list[str] = []
        self.password_inputs = 0
        self.text_parts: list[str] = []
        self._open: list[dict] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a":
            self._open.append({"href": a.get("href", ""), "text": []})
        elif tag == "area" and a.get("href"):
            self.anchors.append((a["href"], a.get("alt", "")))
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        if tag in ("img", "iframe", "script", "embed", "source", "frame") and a.get("src"):
            self.srcs.append(a["src"])
        if tag in ("style", "script"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._open:
            x = self._open.pop()
            self.anchors.append((x["href"], " ".join("".join(x["text"]).split())))
        elif tag in ("style", "script") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        for x in self._open:
            x["text"].append(data)

    def close(self):
        super().close()
        while self._open:
            x = self._open.pop()
            self.anchors.append((x["href"], " ".join("".join(x["text"]).split())))


def html_extract(html: str) -> _HTMLExtractor:
    p = _HTMLExtractor()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # html.parser is tolerant, but never let a body crash triage
        pass
    return p


def html_visible_text(html: str) -> str:
    return " ".join(" ".join(html_extract(html).text_parts).split())


def _clean(url: str) -> str:
    url = url.strip()
    while url and url[-1] in TRAILING:
        url = url[:-1]
    return url


def extract_text_urls(text: str) -> list[str]:
    return [_clean(m.group(0)) for m in URL_TEXT_RE.finditer(text or "")]


def host_of(url: str) -> str:
    u = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
        u = "http://" + u
    try:
        return normalize_host(urlsplit(u).hostname or "")
    except ValueError:
        return ""


def _netloc(url: str) -> str:
    u = url if re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.I) else "http://" + url
    try:
        return urlsplit(u).netloc
    except ValueError:
        return ""


def _obfuscated_ip(host: str) -> bool:
    """Decimal (3232235777) or hex (0xc0a80001) IPv4 encodings."""
    if re.fullmatch(r"\d{8,10}", host):
        return int(host) <= 0xFFFFFFFF
    if re.fullmatch(r"0x[0-9a-f]{1,8}", host):
        return True
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){3}", host)
                and not is_ip(host))


def collect_urls(email: ParsedEmail) -> list[dict]:
    """All links with provenance. Each entry: url, source, anchor_text."""
    out: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(url: str, source: str, text: str = "") -> None:
        url = (url or "").strip()
        if not url or url.lower().startswith(SKIP_SCHEMES):
            return
        key = (url, source, text)
        if key not in seen:
            seen.add(key)
            out.append({"url": url, "source": source, "anchor_text": text})

    for body in email.text_bodies:
        for u in extract_text_urls(body):
            add(u, "text")
    for html in email.html_bodies:
        ex = html_extract(html)
        for href, text in ex.anchors:
            add(href, "html-href", text)
        for action in ex.forms:
            add(action, "html-form")
        for src in ex.srcs:
            add(src, "html-src")
        for u in extract_text_urls(" ".join(ex.text_parts)):
            add(u, "html-text")
    return out


def analyze_urls(email: ParsedEmail, brands: BrandList) -> tuple[list[dict], list[Finding]]:
    links = collect_urls(email)
    findings: list[Finding] = []
    lookalike_cache: dict[str, list[dict]] = {}

    def add(fid, title, sev, weight, why, evidence, attack, iocs):
        findings.append(Finding(fid, "url", title, sev, weight, why, evidence, attack, iocs))

    for link in links:
        url = link["url"]
        low = url.lower()
        flags: list[str] = []
        if low.startswith(SCRIPT_SCHEMES):
            flags.append("url_script_scheme")
            add("url_script_scheme", "Link uses a javascript:/data: scheme", "high", 20,
                "A javascript: or data: link runs code or renders an embedded page when clicked "
                "(used for HTML smuggling and credential pages that never touch a URL filter).",
                url[:120], ["T1027.006", "T1204.001"], [])
            link.update(host="", flags=flags)
            continue
        host = host_of(url)
        link["host"] = host
        netloc = _netloc(url)
        if host and is_ip(host):
            flags.append("url_ip_host")
            add("url_ip_host", "Link points to a raw IP address", "medium", 20,
                "Legitimate brands link to their domain names. A bare IP avoids domain reputation "
                "checks and is typical of phishing kits hosted on compromised servers.",
                url, ["T1566.002", "T1204.001"], [url, host])
        elif host and _obfuscated_ip(host):
            flags.append("url_obfuscated_ip")
            add("url_obfuscated_ip", "Link uses an obfuscated (decimal/hex) IP", "high", 25,
                "The host is an IP written in decimal/hex/octal form to hide it from users and filters.",
                url, ["T1566.002"], [url, host])
        if "@" in netloc:
            flags.append("url_userinfo_at")
            add("url_userinfo_at", "'@' in URL hides the real destination", "medium", 20,
                "Everything before '@' in a URL authority is a username; the browser goes to the "
                "host AFTER the '@'. 'https://www.bank.com@evil.test/' really opens evil.test.",
                url, ["T1566.002"], [url, host])
        if host in SHORTENERS:
            flags.append("url_shortener")
            add("url_shortener", "URL shortener hides the destination", "low", 10,
                "Shorteners mask the final URL; expand it in a sandbox / URL-expander before trusting it.",
                url, ["T1566.002"], [url])
        tld = host.rsplit(".", 1)[-1] if "." in host and not is_ip(host) else ""
        if tld in SUSPICIOUS_TLDS:
            flags.append("url_suspicious_tld")
            add("url_suspicious_tld", f"Frequently abused TLD .{tld}", "low", 8,
                "This top-level domain is cheap and often reported in phishing campaigns. Weak signal "
                "alone - many legitimate sites use it.", url, ["T1566.002"], [host])
        # punycode hosts are reported by the lookalike check below (lookalike_punycode*)
        if link["source"] == "html-form":
            flags.append("html_form")
            add("html_form", "HTML form embedded in the e-mail", "high", 20,
                "A form inside an e-mail can submit typed credentials directly to the attacker's "
                "server. Legitimate services never ask for passwords inside a message.",
                url or "(empty action)", ["T1598.003"], [url, host] if host else [])
        text = link.get("anchor_text") or ""
        if link["source"] == "html-href" and host and text:
            m = DOMAIN_IN_TEXT_RE.search(text.strip())
            if m:
                shown = normalize_host(m.group(1))
                if org_domain(shown) != org_domain(host):
                    flags.append("url_text_mismatch")
                    add("url_text_mismatch", "Link text shows a different domain than its target", "high", 25,
                        "The visible link text displays one domain while the underlying href goes to "
                        "another. This is the core trick of link-based phishing.",
                        f"text='{text[:80]}'  ->  href={url}", ["T1566.002", "T1204.001"], [url, host])
        if host:
            first_time = host not in lookalike_cache
            if first_time:
                lookalike_cache[host] = check_domain(host, brands)
            for r in lookalike_cache[host]:
                flags.append("lookalike_" + r["kind"])
                if first_time:
                    findings.append(lookalike_finding(r, "link"))
        link["flags"] = flags
    return links, findings


def lookalike_finding(r: dict, where: str) -> Finding:
    titles = {
        "homoglyph": "Homoglyph lookalike domain",
        "typosquat": "Typosquatted lookalike domain",
        "brand_wrong_domain": "Brand name on a non-official domain",
        "brand_in_hostname": "Brand name embedded in an unrelated domain",
        "punycode": "Punycode (IDN) domain",
        "punycode_mixed_script": "Mixed-script IDN domain (homograph)",
    }
    attack = ["T1583.001", "T1566.002"] if where == "link" else ["T1583.001", "T1656"]
    return Finding(
        id="lookalike_" + r["kind"], category="lookalike",
        title=f"{titles[r['kind']]} ({where})", severity=r["severity"], weight=r["weight"],
        why=("Attackers register domains that look like a trusted brand so the address passes a quick "
             "glance (and even SPF/DKIM/DMARC, since they own the domain). " + r["detail"] + "."),
        evidence=r["host"] + (f"  (displays as {r['unicode']})" if r["unicode"] != r["host"] else ""),
        attack=attack, iocs=[r["host"]],
    )

