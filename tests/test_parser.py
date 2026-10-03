import hashlib

from phishing_analyzer.parser import parse_bytes, parse_file
from phishing_analyzer.util import defang_url, org_domain, safe_display

from conftest import SAMPLES


def test_parse_basic_headers_and_bodies(mk):
    e = mk({"Reply-To": "other@reply.test"}, text="hi there", html="<p>hello</p>")
    assert e.from_addr.address == "alice@example.com"
    assert e.from_addr.display_name == "Alice"
    assert e.from_addr.domain == "example.com"
    assert e.reply_to[0].domain == "reply.test"
    assert "hi there" in e.text
    assert "<p>hello</p>" in e.html
    assert e.attachments == []


def test_encoded_word_subject_and_display_name_are_decoded():
    raw = (b"From: =?utf-8?q?Service_Cl=C3=A9ints?= <a@b.test>\r\n"
           b"To: x@corp.example\r\nSubject: =?utf-8?b?w4l0YXQgZGUgdm90cmUgY29tcHRl?=\r\n"
           b"Content-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n")
    e = parse_bytes(raw)
    assert e.subject == "État de votre compte"
    assert e.from_addr.display_name == "Service Cléints"


def test_attachment_hash_size_and_mime(mk):
    data = b"dummy-bytes"
    e = mk(attachments=[("report.pdf", data, "application/pdf")])
    a = e.attachments[0]
    assert a.filename == "report.pdf"
    assert a.size == len(data)
    assert a.content_type == "application/pdf"
    assert a.sha256 == hashlib.sha256(data).hexdigest()


def test_rfc2231_filename():
    raw = (b"From: a@b.test\r\nTo: c@d.test\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
           b"--XX\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename*=utf-8''facture%20%C3%A9t%C3%A9.pdf\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\nZHVtbXk=\r\n--XX--\r\n")
    e = parse_bytes(raw)
    assert e.attachments[0].filename == "facture été.pdf"
    assert e.attachments[0].data == b"dummy"


def test_nested_rfc822_attachment_is_walked():
    inner = (b"From: x@inner.test\r\nTo: y@corp.example\r\nSubject: inner\r\n"
             b"Content-Type: text/plain\r\n\r\nhttps://inner.test/login\r\n")
    raw = (b"From: a@b.test\r\nTo: c@d.test\r\nSubject: fwd\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
           b"--XX\r\nContent-Type: message/rfc822\r\n\r\n" + inner + b"\r\n--XX--\r\n")
    e = parse_bytes(raw)
    assert "https://inner.test/login" in e.text


def test_garbage_input_does_not_crash():
    e = parse_bytes(b"\x00\xff not an email at all")
    assert e.from_addr is None


def test_display_name_with_unquoted_at_falls_back():
    raw = b"From: support@microsoft.com <helpdesk@evil.test>\r\nTo: a@b.test\r\nSubject: x\r\n\r\nb\r\n"
    e = parse_bytes(raw)
    # The stdlib's structured header keeps only 'support@microsoft.com' here;
    # the analyzer must report the real <angle-addr> instead.
    assert e.from_addr.address == "helpdesk@evil.test"
    assert e.from_addr.display_name == "support@microsoft.com"


def test_unquoted_display_address_is_flagged(brands):
    from phishing_analyzer.headers import analyze_headers

    raw = b"From: support@microsoft.com <helpdesk@evil.test> (comment)\r\nTo: a@b.test\r\nSubject: x\r\n\r\nb\r\n"
    e = parse_bytes(raw)
    assert e.from_addr.address == "helpdesk@evil.test"
    _, f = analyze_headers(e, brands)
    assert "display_name_spoof" in {x.id for x in f}


def test_quoted_display_name_with_comma():
    e = parse_bytes(b'From: "Doe, John" <john@example.com>\r\nTo: a@b.test, c@d.test\r\nSubject: x\r\n\r\nb\r\n')
    assert e.from_addr.address == "john@example.com" and e.from_addr.display_name == "Doe, John"
    assert [a.address for a in e.to] == ["a@b.test", "c@d.test"]


def test_all_samples_parse():
    files = sorted(SAMPLES.glob("*.eml"))
    assert len(files) >= 6
    for f in files:
        e = parse_file(f)
        assert e.from_addr is not None, f.name
        assert e.received, f.name


def test_util_helpers():
    assert org_domain("a.b.newsletter.example.com") == "example.com"
    assert org_domain("www.cdm.co.ma") == "cdm.co.ma"
    assert org_domain("192.0.2.1") == "192.0.2.1"
    assert defang_url("https://evil.test/a.php") == "hxxps://evil[.]test/a.php"
    assert safe_display("a‮b") == "a[U+202E]b"
