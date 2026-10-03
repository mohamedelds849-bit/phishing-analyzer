"""Lookalike-domain detection: homoglyphs, punycode (IDN), typosquatting.

Approach
--------
1. A host that IS an official brand domain (or a sub-domain of one) is never
   flagged.
2. Punycode labels (xn--) are decoded; mixing scripts (e.g. Latin + Cyrillic)
   inside one hostname is a strong homograph signal.
3. Every hostname token (split on . - _) is reduced to a *skeleton*: lower
   case, confusable characters folded (Cyrillic 'а' -> 'a', '0' -> 'o',
   '1' -> 'l', 'rn' -> 'm'...), accents stripped. A token whose skeleton
   equals a brand keyword but whose raw form differs is a homoglyph.
4. Otherwise an optimal-string-alignment (Damerau-Levenshtein) distance of 1
   (keywords >= 6 chars) or 2 (keywords >= 9 chars) is typosquatting.
5. A brand keyword merely contained in a non-official hostname is flagged at
   lower weight (e.g. paypal.com.secure-login.test).
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .util import is_ip, normalize_host, org_domain, public_suffix

DEFAULT_BRANDS_PATH = Path(__file__).parent / "data" / "brands.json"

CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k",
    "м": "m", "т": "t", "в": "b", "н": "h", "ь": "b", "г": "r",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x",
    "ε": "e", "υ": "u", "β": "b",
    # Latin variants / digits commonly swapped in typosquats
    "ı": "i", "ł": "l", "ɡ": "g", "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "4": "a", "$": "s", "@": "a", "|": "l",
}
MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"))


@dataclass
class Brand:
    name: str
    domains: list[str]
    keywords: list[str]
    display_names: list[str]

    def is_official(self, host: str) -> bool:
        h = normalize_host(host)
        return any(h == d or h.endswith("." + d) for d in self.domains)


class BrandList:
    def __init__(self, brands: list[Brand]):
        self.brands = brands

    @classmethod
    def load(cls, path: str | Path | None = None) -> "BrandList":
        p = Path(path) if path else DEFAULT_BRANDS_PATH
        data = json.loads(p.read_text(encoding="utf-8"))
        brands = []
        for b in data["brands"]:
            brands.append(Brand(
                name=b["name"],
                domains=[normalize_host(d) for d in b.get("domains", [])],
                keywords=[k.lower() for k in b.get("keywords", []) if k],
                display_names=[k.lower() for k in b.get("display_names", []) if k],
            ))
        return cls(brands)

    def is_official(self, host: str) -> bool:
        return any(b.is_official(host) for b in self.brands)

    def official_for(self, host: str) -> Brand | None:
        for b in self.brands:
            if b.is_official(host):
                return b
        return None


def skeleton(s: str) -> str:
    s = (s or "").lower()
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    for a, b in MULTI_CONFUSABLES:
        s = s.replace(a, b)
    return s


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transposition)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def to_unicode(host: str) -> str:
    labels = []
    for label in normalize_host(host).split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def scripts_of(s: str) -> set[str]:
    out = set()
    for c in s:
        if c.isalpha():
            try:
                out.add(unicodedata.name(c).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def _typo_threshold(kw: str) -> int:
    if len(kw) >= 9:
        return 2
    if len(kw) >= 6:
        return 1
    return 0


KIND_WEIGHT = {
    "homoglyph": ("high", 30),
    "typosquat": ("high", 25),
    "brand_wrong_domain": ("medium", 20),
    "brand_in_hostname": ("medium", 15),
}


def check_domain(host: str, brands: BrandList) -> list[dict]:
    """Return lookalike results for one hostname (empty list = nothing found)."""
    h = normalize_host(host)
    if not h or is_ip(h) or "." not in h or brands.is_official(h):
        return []
    results: list[dict] = []
    uhost = to_unicode(h)

    if any(label.startswith("xn--") for label in h.split(".")):
        scripts = scripts_of(uhost.replace(".", ""))
        mixed = len(scripts) > 1
        results.append({
            "kind": "punycode_mixed_script" if mixed else "punycode",
            "brand": None, "host": h, "unicode": uhost,
            "severity": "high" if mixed else "medium", "weight": 25 if mixed else 12,
            "detail": f"IDN host {h} renders as '{uhost}' (scripts: {', '.join(sorted(scripts))})",
        })

    suffix = public_suffix(uhost)
    body = uhost[: -(len(suffix) + 1)] if suffix and uhost.endswith("." + suffix) else uhost
    reg_label = org_domain(uhost).split(".")[0]
    tokens = [t for t in re.split(r"[.\-_]", body) if t]
    joined_skel = skeleton("".join(tokens))

    for brand in brands.brands:
        best = None
        for kw in brand.keywords:
            skw = skeleton(kw)
            for t in tokens:
                st = skeleton(t)
                kind = None
                if t == kw:
                    kind = "brand_wrong_domain" if t == reg_label else "brand_in_hostname"
                elif st == skw:
                    kind = "homoglyph"
                elif (_typo_threshold(kw) and st[:1] == skw[:1]
                      and 0 < osa_distance(st, skw) <= _typo_threshold(kw)):
                    # same first letter: avoids e.g. 'cloud' ~ 'icloud' false positives
                    kind = "typosquat"
                if kind and (best is None or KIND_WEIGHT[kind][1] > KIND_WEIGHT[best[0]][1]):
                    best = (kind, kw, t)
            if best is None and len(kw) >= 5 and skw in joined_skel:
                best = ("brand_in_hostname", kw, body)
        if best:
            kind, kw, token = best
            sev, weight = KIND_WEIGHT[kind]
            detail = {
                "homoglyph": f"'{token}' uses look-alike characters to imitate '{kw}' ({brand.name})",
                "typosquat": f"'{token}' is {osa_distance(skeleton(token), skeleton(kw))} edit(s) away from '{kw}' ({brand.name})",
                "brand_wrong_domain": f"'{h}' uses the brand name '{kw}' but is not an official {brand.name} domain",
                "brand_in_hostname": f"'{h}' contains the brand '{kw}' but is not an official {brand.name} domain",
            }[kind]
            results.append({"kind": kind, "brand": brand.name, "host": h, "unicode": uhost,
                            "severity": sev, "weight": weight, "detail": detail})
    if results and results[0]["kind"].startswith("punycode") and len(results) > 1:
        # the brand match already explains the IDN trick: keep the punycode
        # result as context with a reduced weight to avoid double counting
        results[0].update(severity="medium", weight=10)
    return results
