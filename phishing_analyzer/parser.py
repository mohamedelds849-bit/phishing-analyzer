"""Parse an RFC 5322 / MIME message (.eml) with the standard library only.

Nothing in here executes or renders content: bodies are decoded to text and
attachments are kept as raw bytes in memory so they can be hashed and
inspected statically.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from .util import domain_of

MAX_EML_BYTES = 50 * 1024 * 1024  # refuse absurdly large inputs


@dataclass
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return domain_of(self.address)

    def __str__(self) -> str:
        if self.display_name:
            return f'"{self.display_name}" <{self.address}>'
        return f"<{self.address}>"

    def to_dict(self) -> dict:
        return {"display_name": self.display_name, "address": self.address, "domain": self.domain}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    data: bytes = field(repr=False, default=b"")

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
        }


@dataclass
class ParsedEmail:
    headers: list[tuple[str, str]]
    subject: str
    from_addr: Address | None
    reply_to: list[Address]
    return_path: Address | None
    to: list[Address]
    cc: list[Address]
    date: str
    message_id: str
    received: list[str]          # topmost (most recent) first, as in the file
    auth_results: list[str]      # Authentication-Results, topmost first
    received_spf: list[str]
    text_bodies: list[str]
    html_bodies: list[str]
    attachments: list[Attachment]
    defects: list[str]
    raw_sha256: str
    raw_size: int

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def text(self) -> str:
        return "\n".join(self.text_bodies)

    @property
    def html(self) -> str:
        return "\n".join(self.html_bodies)


def _parse_addresses(value: str | None) -> list[Address]:
    if not value:
        return []
    out: list[Address] = []
    for name, addr in getaddresses([value]):
        if addr and "@" in addr:
            out.append(Address(name.strip(), addr.strip()))
    angle = re.findall(r"<([^<>\s]+@[^<>\s]+)>", value)
    if len(angle) == 1 and "," not in value and [a.address for a in out] != angle:
        # e.g.  From: support@bank.example <x@evil.test>  (unquoted '@' in the
        # display name). Some stdlib versions return the display-name address;
        # mail clients deliver/reply to the <angle-addr>, so that one is real.
        out = []
    if not out and "@" in value:
        # Fallback for headers the stdlib refuses (e.g. unquoted '@' in the
        # display name): take the last <...> as the address.
        if angle:
            name = value[: value.rfind("<" + angle[-1] + ">")]
            out.append(Address(name.strip().strip('"').strip(), angle[-1]))
        else:
            m = re.search(r"[^\s<>\"]+@[^\s<>\"]+", value)
            if m:
                out.append(Address("", m.group(0)))
    return out


ADDRESS_HEADERS = {"from", "sender", "reply-to", "to", "cc", "bcc", "return-path"}


def _decode_raw(raw: str) -> str:
    """Decode RFC 2047 encoded-words of a raw header value, keeping structure."""
    unfolded = re.sub(r"\r?\n[ \t]", " ", raw)
    try:
        return str(make_header(decode_header(unfolded)))
    except Exception:
        return unfolded


def _decode_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # unknown charset, broken transfer encoding...
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def parse_bytes(data: bytes) -> ParsedEmail:
    if len(data) > MAX_EML_BYTES:
        raise ValueError(f"message too large ({len(data)} bytes > {MAX_EML_BYTES})")
    msg = BytesParser(policy=policy.default).parsebytes(data)

    headers: list[tuple[str, str]] = []
    for name, raw in msg.raw_items():
        if name.lower() in ADDRESS_HEADERS:
            # Do NOT use the policy's structured AddressHeader here: for input
            # like  'support@bank.example <x@evil.test>'  its str() keeps only
            # the display-name part and silently drops the real address.
            value = _decode_raw(str(raw))
        else:
            try:
                value = str(msg.policy.header_fetch_parse(name, raw))
            except Exception:
                value = _decode_raw(str(raw))
        headers.append((name, " ".join(value.split())))

    def first(name: str) -> str | None:
        for k, v in headers:
            if k.lower() == name:
                return v
        return None

    def all_of(name: str) -> list[str]:
        return [v for k, v in headers if k.lower() == name]

    text_bodies: list[str] = []
    html_bodies: list[str] = []
    attachments: list[Attachment] = []
    defects = [type(d).__name__ for d in msg.defects]

    for part in msg.walk():
        defects.extend(type(d).__name__ for d in getattr(part, "defects", []) if part is not msg)
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        if disp == "attachment" or filename or not ctype.startswith("text/"):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(payload).hexdigest(),  # noqa: S324 - for TI lookups only
                    data=payload,
                )
            )
        elif ctype == "text/html":
            html_bodies.append(_decode_text(part))
        else:
            text_bodies.append(_decode_text(part))

    from_list = _parse_addresses(first("from"))
    rp_list = _parse_addresses(first("return-path"))
    return ParsedEmail(
        headers=headers,
        subject=first("subject") or "",
        from_addr=from_list[0] if from_list else None,
        reply_to=_parse_addresses(first("reply-to")),
        return_path=rp_list[0] if rp_list else None,
        to=_parse_addresses(first("to")),
        cc=_parse_addresses(first("cc")),
        date=first("date") or "",
        message_id=first("message-id") or "",
        received=all_of("received"),
        auth_results=all_of("authentication-results"),
        received_spf=all_of("received-spf"),
        text_bodies=text_bodies,
        html_bodies=html_bodies,
        attachments=attachments,
        defects=defects,
        raw_sha256=hashlib.sha256(data).hexdigest(),
        raw_size=len(data),
    )


def parse_file(path: str | Path) -> ParsedEmail:
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_EML_BYTES:
        raise ValueError(f"message too large ({size} bytes > {MAX_EML_BYTES})")
    return parse_bytes(p.read_bytes())
