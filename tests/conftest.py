import sys
from email.message import EmailMessage
from email.policy import default
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishing_analyzer.lookalike import BrandList  # noqa: E402
from phishing_analyzer.parser import parse_bytes  # noqa: E402

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def brands():
    return BrandList.load()


def make_email(headers=None, text=None, html=None, attachments=()):
    """Build a ParsedEmail in memory. attachments: (filename, bytes, mime)."""
    msg = EmailMessage()
    base = {"From": "Alice <alice@example.com>", "To": "bob@corp.example", "Subject": "hello",
            "Date": "Tue, 15 Sep 2026 08:00:00 +0000", "Message-ID": "<1@example.com>"}
    base.update(headers or {})
    for k, v in base.items():
        if v is None:
            continue
        if isinstance(v, list):
            for item in v:
                msg[k] = item
        else:
            msg[k] = v
    msg.set_content(text if text is not None else "plain body")
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for name, data, mime in attachments:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return parse_bytes(msg.as_bytes(policy=default))


@pytest.fixture
def mk():
    return make_email
