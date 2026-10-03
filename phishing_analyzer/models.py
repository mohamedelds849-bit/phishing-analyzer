"""Shared data model: a Finding is one explained, weighted observation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")

# MITRE ATT&CK techniques referenced by the detectors (Enterprise matrix, v19+).
# Note: ATT&CK v19 (April 2026) revoked T1656 Impersonation and T1672 Email
# Spoofing and re-homed them as T1684.001 / T1684.002 under T1684 Social
# Engineering. Older reports and SIEM rules may still use the old ids.
ATTACK = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1684.001": "Social Engineering: Impersonation",
    "T1684.002": "Social Engineering: Email Spoofing",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
}


@dataclass
class Finding:
    """A single detection result.

    id        stable identifier (scoring counts each id once)
    category  auth | header | lookalike | url | attachment | content | dns
    severity  one of SEVERITIES
    weight    points added to the 0-100 risk score (0 = informational)
    why       plain-language explanation for the analyst
    evidence  the exact value that triggered the rule
    attack    MITRE ATT&CK technique ids
    iocs      observables (domains / urls / ips / hashes) this finding flags
    """

    id: str
    category: str
    title: str
    severity: str
    weight: int
    why: str
    evidence: str = ""
    attack: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        unknown = [t for t in self.attack if t not in ATTACK]
        if unknown:
            raise ValueError(f"unknown ATT&CK id(s) {unknown}")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack"] = [{"id": t, "name": ATTACK[t]} for t in self.attack]
        return d
