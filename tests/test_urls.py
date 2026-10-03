from phishing_analyzer.urls import analyze_urls, collect_urls, extract_text_urls, host_of


def ids(findings):
    return {f.id for f in findings}


def test_extract_text_urls_strips_punctuation():
    urls = extract_text_urls("see https://a.example.com/x. and (www.b.example.com/y), done")
    assert urls == ["https://a.example.com/x", "www.b.example.com/y"]


def test_collect_from_html_anchor_form_and_text(mk):
    e = mk(text="visit https://t.example.com/1",
           html='<a href="https://h.example.com/2">click</a><form action="https://f.test/p"></form>'
                '<p>raw https://r.example.com/3</p><a href="mailto:x@y.test">mail</a>')
    srcs = {(u["url"], u["source"]) for u in collect_urls(e)}
    assert ("https://t.example.com/1", "text") in srcs
    assert ("https://h.example.com/2", "html-href") in srcs
    assert ("https://f.test/p", "html-form") in srcs
    assert ("https://r.example.com/3", "html-text") in srcs
    assert not any(u.startswith("mailto:") for u, _ in srcs)


def test_ip_and_at_sign(mk, brands):
    e = mk(text="http://192.0.2.4/login and https://www.paypal.com@198.51.100.7/verify")
    _, f = analyze_urls(e, brands)
    assert {"url_ip_host", "url_userinfo_at"} <= ids(f)
    assert host_of("https://www.paypal.com@198.51.100.7/verify") == "198.51.100.7"


def test_obfuscated_ip(mk, brands):
    _, f = analyze_urls(mk(text="http://3232235777/x"), brands)
    assert "url_obfuscated_ip" in ids(f)


def test_shortener_and_tld(mk, brands):
    _, f = analyze_urls(mk(text="https://bit.ly/abc https://promo.example.xyz/a"), brands)
    assert {"url_shortener", "url_suspicious_tld"} <= ids(f)


def test_href_text_mismatch(mk, brands):
    e = mk(html='<a href="https://evil.test/login">https://www.mybank.example/login</a>')
    _, f = analyze_urls(e, brands)
    assert "url_text_mismatch" in ids(f)


def test_href_text_same_org_no_mismatch(mk, brands):
    e = mk(html='<a href="https://click.example.com/r?id=1">www.example.com</a>')
    _, f = analyze_urls(e, brands)
    assert "url_text_mismatch" not in ids(f)


def test_punycode_link_flagged(mk, brands):
    idn = "pаypal.test".encode("idna").decode()
    links, f = analyze_urls(mk(html=f'<a href="https://{idn}/x">open</a>'), brands)
    assert any(x.id.startswith("lookalike_punycode") for x in f)
    assert "lookalike_homoglyph" in links[0]["flags"]


def test_form_and_javascript_scheme(mk, brands):
    e = mk(html='<form action="https://collect.test/p"><input type="password"></form>'
                '<a href="javascript:alert(1)">x</a>')
    _, f = analyze_urls(e, brands)
    assert {"html_form", "url_script_scheme"} <= ids(f)


def test_benign_links_no_findings(mk, brands):
    _, f = analyze_urls(mk(text="https://www.example.com/articles/1"), brands)
    assert f == []
