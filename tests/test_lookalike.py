from phishing_analyzer.lookalike import check_domain, osa_distance, skeleton, to_unicode


def kinds(host, brands):
    return {r["kind"] for r in check_domain(host, brands)}


def test_osa_distance():
    assert osa_distance("paypal", "paypal") == 0
    assert osa_distance("paypal", "paypa") == 1
    assert osa_distance("bnak", "bank") == 1  # transposition counts as one edit
    assert osa_distance("kitten", "sitting") == 3


def test_skeleton_folds_confusables():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("micr0soft") == "microsoft"
    assert skeleton("аpple") == "apple"  # Cyrillic a
    assert skeleton("rnicrosoft") == "microsoft"


def test_official_domains_and_subdomains_not_flagged(brands):
    assert check_domain("paypal.com", brands) == []
    assert check_domain("www.paypal.com", brands) == []
    assert check_domain("login.microsoftonline.com", brands) == []
    assert check_domain("www.cdm.co.ma", brands) == []
    assert check_domain("example.com", brands) == []


def test_homoglyph_digit(brands):
    assert "homoglyph" in kinds("paypa1.test", brands)


def test_punycode_mixed_script(brands):
    idn = "cіhbank.test".encode("idna").decode()  # Cyrillic i
    assert idn.startswith("xn--")
    k = kinds(idn, brands)
    assert "homoglyph" in k and "punycode_mixed_script" in k
    assert to_unicode(idn) == "cіhbank.test"


def test_typosquat_transposition_and_omission(brands):
    assert "typosquat" in kinds("attijariwafabnak.test", brands)
    assert "typosquat" in kinds("paypl.test", brands)
    assert "typosquat" in kinds("micosoft-support.test", brands)


def test_brand_in_hostname(brands):
    assert "brand_in_hostname" in kinds("paypal.com.secure-login.test", brands)
    assert "brand_in_hostname" in kinds("cihbank-securite.test", brands)
    assert "brand_wrong_domain" in kinds("paypal.test", brands)


def test_no_false_positive_on_unrelated(brands):
    for host in ("cloud.example.com", "news.example.org", "mycompany.ma", "apply.test", "university.ac.ma"):
        assert check_domain(host, brands) == [], host


def test_short_keywords_only_exact_tokens(brands):
    assert kinds("dhl-livraison.test", brands) == {"brand_in_hostname"}
    assert check_domain("adhlong.test", brands) == []


def test_verified_moroccan_bank_domains_are_official(brands):
    # verified 2026-10 (security review): CDM's site is creditdumaroc.ma,
    # Attijarinet lives on attijariwafa.com, SG Maroc became Saham Bank (2025)
    for host in ("www.creditdumaroc.ma", "attijarinet.attijariwafa.com", "www.sahambank.com",
                 "www.creditagricole.ma", "www.bankofafrica.ma", "www.cihbank.ma", "www.groupebcp.com"):
        assert check_domain(host, brands) == [], host
    assert check_domain("sahambank-securite.test", brands)
