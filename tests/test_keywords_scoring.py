import pytest

from phishing_analyzer.keywords import analyze_keywords, match_categories
from phishing_analyzer.models import Finding
from phishing_analyzer.scoring import score, verdict
from phishing_analyzer.util import normalize_text


def test_french_with_accents():
    hits = match_categories(normalize_text("Votre compte a été suspendu. Vérifiez votre compte immédiatement."))
    assert {"threat", "credential", "urgency"} <= hits.keys()


def test_english_lures():
    hits = match_categories(normalize_text("URGENT: confirm your password within 24 hours"))
    assert {"urgency", "credential"} <= hits.keys()


def test_bec_french():
    hits = match_categories(normalize_text("Je suis en réunion, fais un virement sur le nouveau RIB, c'est confidentiel"))
    assert {"payment", "secrecy"} <= hits.keys()


def test_neutral_text_no_hits():
    assert match_categories(normalize_text("Here are this week's articles about cooking and travel.")) == {}


def test_keywords_read_html_visible_text_not_tags(mk):
    _, f = analyze_keywords(mk(text="hello", html="<p style='password'>Bonjour</p>"))
    assert f == []


def F(fid, w, sev="low"):
    return Finding(fid, "test", fid, sev, w, "why")


def test_score_counts_each_id_once_and_caps():
    assert score([F("a", 20), F("a", 20), F("b", 10)]) == 30
    assert score([F(str(i), 30) for i in range(10)]) == 100


@pytest.mark.parametrize("s,v", [(0, "Likely safe"), (24, "Likely safe"), (25, "Suspicious"),
                                 (59, "Suspicious"), (60, "Likely phishing"), (100, "Likely phishing")])
def test_verdict_thresholds(s, v):
    assert verdict(s, []) == v


def test_critical_forces_suspicious():
    assert verdict(20, [F("x", 20, "critical")]) == "Suspicious"


def test_finding_validation():
    with pytest.raises(ValueError):
        Finding("x", "c", "t", "bogus", 1, "w")
    with pytest.raises(ValueError):
        Finding("x", "c", "t", "low", 1, "w", attack=["T9999"])
