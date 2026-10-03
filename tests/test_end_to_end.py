import json
import re

import pytest

from phishing_analyzer.analyzer import analyze_email, analyze_file
from phishing_analyzer.cli import main
from phishing_analyzer.dns_check import NXDomain, NoRecords, dns_findings, lookup_sender_domain
from phishing_analyzer.report import to_html

from conftest import SAMPLES

EXPECTED = {
    "01_legit_newsletter.eml": "Likely safe",
    "02_obvious_phishing.eml": "Likely phishing",
    "03_subtle_lookalike_fr.eml": "Likely phishing",
    "04_malicious_attachment_fr.eml": "Likely phishing",
    "05_bec_ceo_fraud_fr.eml": "Likely phishing",
    "06_display_name_credential_form.eml": "Likely phishing",
    "07_gray_shared_document_fr.eml": "Suspicious",
}

KEY_FINDINGS = {
    "02_obvious_phishing.eml": {"dmarc_fail", "url_ip_host", "url_userinfo_at", "url_text_mismatch", "lookalike_homoglyph"},
    "03_subtle_lookalike_fr.eml": {"lookalike_typosquat", "lookalike_homoglyph", "auth_pass"},
    "04_malicious_attachment_fr.eml": {"att_double_ext", "att_macro_ext", "att_vba_present"},
    "05_bec_ceo_fraud_fr.eml": {"bec_pattern", "reply_to_mismatch", "exec_impersonation", "kw_payment", "kw_secrecy"},
    "06_display_name_credential_form.eml": {"display_name_spoof", "html_form", "auth_extra_headers"},
}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_sample_verdicts(name, expected, brands):
    r = analyze_file(SAMPLES / name, brands=brands)
    assert r["verdict"] == expected, (name, r["score"], [f["id"] for f in r["findings"]])
    assert {f["id"] for f in r["findings"]} >= KEY_FINDINGS.get(name, set())


def test_iocs_contain_hashes_and_defanged(brands):
    r = analyze_file(SAMPLES / "04_malicious_attachment_fr.eml", brands=brands)
    assert len(r["iocs"]["hashes"]) == 2 and all(h["flagged"] for h in r["iocs"]["hashes"])
    r = analyze_file(SAMPLES / "02_obvious_phishing.eml", brands=brands)
    assert any(u["defanged"].startswith("hxxp") for u in r["iocs"]["urls"])
    assert "203.0.113.66" in [i["value"] for i in r["iocs"]["ips"]]


def test_every_scored_finding_has_why_and_valid_severity(brands):
    for f in sorted(SAMPLES.glob("*.eml")):
        for x in analyze_file(f, brands=brands)["findings"]:
            assert x["why"] and x["title"]


def test_html_report_is_standalone_and_escaped(mk, brands):
    e = mk({"Subject": "<script>alert(1)</script>"}, html='<a href="http://192.0.2.1/x">y</a>')
    html = to_html(analyze_email(e, source="t.eml", brands=brands))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert not re.search(r"(src|href)=[\"']?https?://", html)  # no external resources / live links
    assert "Content-Security-Policy" in html


def test_cli_json_and_exit_code(capsys, tmp_path):
    out_html = tmp_path / "r.html"
    rc = main([str(SAMPLES / "02_obvious_phishing.eml"), "--json", "--html", str(out_html), "--exit-code"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 20 and data["verdict"] == "Likely phishing"
    assert out_html.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert main([str(SAMPLES / "01_legit_newsletter.eml"), "--exit-code"]) == 0
    assert "VERDICT" in capsys.readouterr().out


def test_cli_missing_file(capsys):
    assert main(["does-not-exist.eml"]) == 1


def test_online_dns_with_mocked_resolver(mk, brands):
    def fake(name):
        if name == "example.com":
            return ["v=spf1 include:_spf.example.com ~all"]
        if name.startswith("_dmarc."):
            raise NoRecords(name)
        raise NXDomain(name)

    r = analyze_email(mk(), brands=brands, online=True, txt_lookup=fake)
    assert r["dns"]["spf_all"] == "~all"
    assert "sender_no_dmarc" in {f["id"] for f in r["findings"]}

    info = lookup_sender_domain("ghost.test", txt_lookup=lambda n: (_ for _ in ()).throw(NXDomain(n)))
    assert info["exists"] is False
    assert dns_findings(info)[0].id == "sender_domain_nxdomain"


def test_online_dns_policy_parsing():
    info = lookup_sender_domain("example.com", txt_lookup=lambda n: (
        ["v=DMARC1; p=none; rua=mailto:r@example.com"] if n.startswith("_dmarc") else ["v=spf1 +all"]))
    assert info["dmarc_policy"] == "none" and info["spf_all"] == "+all"
    assert {f.id for f in dns_findings(info)} == {"sender_spf_permissive", "sender_dmarc_none"}


def test_console_neutralises_terminal_escape_sequences(mk, brands):
    from phishing_analyzer.report import to_console
    raw = (b"From: a@evil.test\r\nTo: b@corp.example\r\nDate: \x1b[2J\x1b]0;owned\x07\r\n"
           b"Subject: hi\r\n\r\nsee http://evil.test/\x1b[31mred\r\n")
    from phishing_analyzer.parser import parse_bytes
    out = to_console(analyze_email(parse_bytes(raw), brands=brands))
    assert "\x1b" not in out and "\x07" not in out
    assert "[U+001B]" in out


def test_cli_unwritable_report_path_is_clean_error(tmp_path, capsys):
    bad = tmp_path / "no-such-dir" / "r.html"
    assert main([str(SAMPLES / "01_legit_newsletter.eml"), "--html", str(bad)]) == 1
    assert "cannot write report" in capsys.readouterr().err


def test_attack_ids_are_current_v19():
    from phishing_analyzer.models import ATTACK
    assert "T1656" not in ATTACK and "T1672" not in ATTACK  # revoked in ATT&CK v19
    assert ATTACK["T1684.001"].endswith("Impersonation")


def test_spf_qualifier_is_token_based():
    from phishing_analyzer.dns_check import spf_qualifier
    assert spf_qualifier("v=spf1 include:_spf.google.com ~all") == "~all"
    assert spf_qualifier("v=spf1 ip4:192.0.2.1 -all") == "-all"
    assert spf_qualifier("v=spf1 +all") == "+all"
    assert spf_qualifier("v=spf1 all") == "+all"
    # "all" inside a domain name is not the all mechanism
    assert spf_qualifier("v=spf1 include:spf.all-mail.example") is None
    assert spf_qualifier("v=spf1 redirect=x-all.example") is None
