"""Turn findings into a 0-100 risk score and a verdict.

Rules (deliberately simple so an analyst can recompute them by hand):
  * each finding id counts ONCE, with the highest weight seen for that id
    (ten IP-based links are not ten times more phishing than one);
  * the sum is capped at 100;
  * verdict: < 25 Likely safe, 25-59 Suspicious, >= 60 Likely phishing;
  * any 'critical' finding forces at least 'Suspicious'.
"""

from __future__ import annotations

from .models import Finding

SAFE_MAX = 24
SUSPICIOUS_MAX = 59

VERDICT_SAFE = "Likely safe"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_PHISHING = "Likely phishing"


def contributions(findings: list[Finding]) -> dict[str, int]:
    best: dict[str, int] = {}
    for f in findings:
        best[f.id] = max(best.get(f.id, 0), f.weight)
    return best


def score(findings: list[Finding]) -> int:
    return min(100, sum(contributions(findings).values()))


def verdict(score_value: int, findings: list[Finding] | None = None) -> str:
    if score_value > SUSPICIOUS_MAX:
        return VERDICT_PHISHING
    if score_value > SAFE_MAX:
        return VERDICT_SUSPICIOUS
    if findings and any(f.severity == "critical" for f in findings):
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE
