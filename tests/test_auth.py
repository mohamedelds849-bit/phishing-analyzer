from phishing_analyzer.auth import analyze_auth, parse_authentication_results, summarize_auth


def ids(findings):
    return {f.id for f in findings}


def test_parse_ar_header_with_comments():
    r = parse_authentication_results(
        "mx.corp.example; spf=pass (sender IP is 198.51.100.1; ok) smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com header.s=s1; dmarc=pass (p=REJECT) header.from=example.com")
    assert r["authserv_id"] == "mx.corp.example"
    methods = {x["method"]: x for x in r["results"]}
    assert methods["spf"]["result"] == "pass"
    assert methods["spf"]["props"]["smtp.mailfrom"] == "example.com"
    assert methods["dkim"]["props"]["header.d"] == "example.com"
    assert methods["dmarc"]["result"] == "pass"


def test_fail_results_produce_findings(mk):
    e = mk({"Authentication-Results": "mx.corp.example; spf=fail smtp.mailfrom=x.test; dkim=fail header.d=x.test; dmarc=fail"})
    s, f = analyze_auth(e)
    assert (s["spf"], s["dkim"], s["dmarc"]) == ("fail", "fail", "fail")
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= ids(f)


def test_softfail_and_all_pass(mk):
    _, f = analyze_auth(mk({"Authentication-Results": "mx; spf=softfail; dkim=none; dmarc=none"}))
    assert "spf_softfail" in ids(f)
    _, f = analyze_auth(mk({"Authentication-Results": "mx; spf=pass; dkim=pass header.d=example.com; dmarc=pass"}))
    assert ids(f) == {"auth_pass"}
    assert all(x.weight == 0 for x in f)


def test_only_topmost_header_is_trusted(mk):
    e = mk({"Authentication-Results": ["mx.corp.example; spf=fail; dkim=none; dmarc=fail",
                                       "forged; spf=pass; dkim=pass; dmarc=pass"]})
    s, f = analyze_auth(e)
    assert s["dmarc"] == "fail"
    assert "auth_extra_headers" in ids(f)


def test_authserv_id_selection(mk):
    e = mk({"Authentication-Results": ["forged.test; dmarc=pass", "mx.corp.example; dmarc=fail"]})
    s = summarize_auth(e, authserv_id="mx.corp.example")
    assert s["dmarc"] == "fail"
    _, f = analyze_auth(e, authserv_id="nope.example")
    assert "auth_untrusted" in ids(f)


def test_received_spf_fallback(mk):
    e = mk({"Received-SPF": "SoftFail (domain of x.test does not designate 203.0.113.9)"})
    s, f = analyze_auth(e)
    assert s["spf"] == "softfail" and s["source"] == "Received-SPF"
    assert "spf_softfail" in ids(f)


def test_missing_auth_headers(mk):
    _, f = analyze_auth(mk())
    assert ids(f) == {"auth_missing"}


def test_dkim_not_aligned(mk):
    e = mk({"Authentication-Results": "mx; spf=none; dkim=pass header.d=esp.test; dmarc=none"})
    _, f = analyze_auth(e)
    assert "dkim_not_aligned" in ids(f)
