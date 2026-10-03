from phishing_analyzer.headers import analyze_headers, parse_received, received_chain


def ids(findings):
    return {f.id for f in findings}


def test_reply_to_mismatch(mk, brands):
    _, f = analyze_headers(mk({"Reply-To": "boss@other.test"}), brands)
    assert "reply_to_mismatch" in ids(f)


def test_reply_to_same_org_is_fine(mk, brands):
    _, f = analyze_headers(mk({"Reply-To": "support@help.example.com"}), brands)
    assert "reply_to_mismatch" not in ids(f)


def test_return_path_mismatch_is_low(mk, brands):
    _, f = analyze_headers(mk({"Return-Path": "<b@esp.test>"}), brands)
    rp = [x for x in f if x.id == "return_path_mismatch"]
    assert rp and rp[0].severity == "low"


def test_display_name_contains_other_address(mk, brands):
    _, f = analyze_headers(mk({"From": '"security@paypal.com" <x@evil.test>'}), brands)
    assert {"display_name_spoof", "brand_display_name"} <= ids(f)


def test_brand_display_name_from_official_domain_not_flagged(mk, brands):
    _, f = analyze_headers(mk({"From": "PayPal <service@paypal.com>", "Message-ID": "<1@paypal.com>"}), brands)
    assert "brand_display_name" not in ids(f)


def test_exec_title_external_sender(mk, brands):
    e = mk({"From": "Karim - PDG <ceo@external.test>", "To": "compta@acme.example"})
    _, f = analyze_headers(e, brands)
    assert "exec_impersonation" in ids(f)
    e = mk({"From": "Karim - PDG <ceo@acme.example>", "To": "compta@acme.example", "Message-ID": "<1@acme.example>"})
    _, f = analyze_headers(e, brands)
    assert "exec_impersonation" not in ids(f)


def test_parse_received_hop():
    hop, ts = parse_received("from mail.evil.test (mail.evil.test [203.0.113.5]) by mx.corp.example "
                             "with ESMTPS id ABC; Wed, 16 Sep 2026 02:14:38 +0200")
    assert hop.from_host == "mail.evil.test"
    assert hop.from_ip == "203.0.113.5"
    assert hop.by_host == "mx.corp.example"
    assert hop.timestamp == "2026-09-16T00:14:38+00:00"


def test_received_chain_order_and_delays(mk):
    e = mk({"Received": [
        "from b.test (b.test [198.51.100.2]) by c.test; Tue, 15 Sep 2026 08:00:10 +0000",
        "from a.test (a.test [198.51.100.1]) by b.test; Tue, 15 Sep 2026 08:00:00 +0000",
    ]})
    hops, _ = received_chain(e)
    assert [h.from_host for h in hops] == ["a.test", "b.test"]  # oldest first
    assert hops[1].delay_seconds == 10


def test_time_travel_and_missing_received(mk, brands):
    e = mk({"Received": [
        "from b.test by c.test; Tue, 15 Sep 2026 07:00:00 +0000",
        "from a.test by b.test; Tue, 15 Sep 2026 08:00:00 +0000",
    ]})
    _, f = analyze_headers(e, brands)
    assert "received_time_travel" in ids(f)
    _, f = analyze_headers(mk(), brands)
    assert "received_missing" in ids(f)
