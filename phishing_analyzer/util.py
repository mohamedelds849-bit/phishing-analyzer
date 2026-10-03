"""Small helpers: domain normalisation, defanging, text normalisation."""

from __future__ import annotations

import ipaddress
import re
import unicodedata

# Second-level public suffixes we know about. This is NOT the full Public
# Suffix List (see README limitations) - just the ones relevant to the
# Moroccan / French / common contexts the tool targets.
MULTI_PART_SUFFIXES = {
    "co.ma", "net.ma", "org.ma", "gov.ma", "ac.ma", "press.ma",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.jp", "co.za", "co.in",
    "com.br", "com.tr", "com.cn", "com.mx", "com.sa", "com.eg",
    "gouv.fr", "asso.fr", "co.nz",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")

# Bidirectional / invisible formatting characters abused in file names.
BIDI_CHARS = set("‪‫‬‭‮⁦⁧⁨⁩‎‏")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower().strip(".")
    if h.startswith("[") and "]" in h:
        return h[1:h.index("]")]
    if h.count(":") == 1:  # host:port
        h = h.split(":", 1)[0]
    return h


def org_domain(domain: str) -> str:
    """Approximate the organisational (registrable) domain.

    mail.newsletter.example.com -> example.com ; www.cdm.co.ma -> cdm.co.ma
    """
    d = normalize_host(domain)
    if not d or is_ip(d):
        return d
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def public_suffix(domain: str) -> str:
    org = org_domain(domain)
    return org.split(".", 1)[1] if "." in org else ""


def domain_of(address: str) -> str:
    a = (address or "").strip().strip("<>")
    return normalize_host(a.rpartition("@")[2]) if "@" in a else ""


def normalize_text(s: str) -> str:
    """Lower-case, strip accents, unify apostrophes/spaces (for keyword rules)."""
    s = (s or "").replace("’", "'").replace("‘", "'").replace(" ", " ")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", s.lower()).strip()


def safe_display(s: str) -> str:
    """Make control / bidi characters visible, e.g. RLO -> [U+202E]."""
    out = []
    for c in s or "":
        if c in BIDI_CHARS or (unicodedata.category(c) in ("Cc", "Cf") and c not in "\t"):
            out.append(f"[U+{ord(c):04X}]")
        else:
            out.append(c)
    return "".join(out)


def defang_domain(d: str) -> str:
    return (d or "").replace(".", "[.]")


def defang_url(url: str) -> str:
    """hxxps://evil[.]test/path - safe to paste into a ticket."""
    u = re.sub(r"^http", "hxxp", url or "", flags=re.I)
    m = re.match(r"^([a-z][a-z0-9+.\-]*://)?([^/?#]*)(.*)$", u, re.I | re.S)
    if not m:
        return u
    scheme, netloc, rest = m.groups()
    return (scheme or "") + netloc.replace(".", "[.]") + rest
