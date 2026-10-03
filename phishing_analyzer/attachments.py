"""Static attachment triage. Attachments are NEVER executed, opened by an
application, or written to disk: we look at the file name, the first bytes
(magic number) and, for ZIP-based files, the archive directory listing."""

from __future__ import annotations

import io
import zipfile

from .models import Finding
from .parser import ParsedEmail, Attachment
from .util import BIDI_CHARS, safe_display

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "dll", "bat", "cmd", "ps1", "psm1", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "inf", "scf", "msc", "url",
    "appx", "msix", "one", "chm", "xll", "application", "gadget", "sh", "apk",
}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm"}
OFFICE_EXT = {"doc", "dot", "xls", "xlt", "ppt", "pps", "docx", "xlsx", "pptx", "rtf"} | MACRO_EXT
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "arj", "ace", "xz", "bz2"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png",
             "gif", "csv", "rtf", "odt", "mp3", "mp4", "zip"}

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _ext_chain(filename: str) -> list[str]:
    name = "".join(c for c in filename if c not in BIDI_CHARS).strip().rstrip(".").lower()
    parts = [p.strip() for p in name.split(".")]
    return parts[1:] if len(parts) > 1 else []


def _zip_names(data: bytes) -> tuple[list[str], bool] | None:
    """Directory listing of a ZIP (names only) + 'any entry encrypted'."""
    if not data.startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            # Every entry is checked: the central directory is already parsed in
            # memory by zipfile, and truncating the list would let an attacker
            # hide 'payload.js' behind thousands of dummy entries. Only NAMES
            # are read - no member is ever decompressed (zip-bomb safe).
            infos = z.infolist()
            return [i.filename for i in infos], any(i.flag_bits & 0x1 for i in infos)
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        return None


def analyze_attachment(att: Attachment) -> list[Finding]:
    f: list[Finding] = []
    name = att.filename
    shown = safe_display(name)
    exts = _ext_chain(name)
    ext = exts[-1] if exts else ""
    iocs = [att.sha256]

    def add(fid, title, sev, weight, why, attack):
        f.append(Finding(fid, "attachment", title, sev, weight, why,
                         f"{shown} ({att.size} bytes, sha256 {att.sha256[:16]}...)", attack, iocs))

    if any(c in BIDI_CHARS for c in name):
        add("att_rtlo", "Right-to-left override in file name", "critical", 35,
            "A Unicode bidi control character reverses how the name is displayed, e.g. "
            "'invoice[RLO]fdp.exe' looks like 'invoiceexe.pdf'. There is no legitimate use in a "
            "file name.", ["T1036.002", "T1566.001"])
    if len(exts) >= 2 and exts[-2] in DECOY_EXT and (ext in EXECUTABLE_EXT or ext in HTML_EXT or ext in DISK_IMAGE_EXT):
        add("att_double_ext", "Double extension (decoy + executable)", "high", 30,
            f"The name ends in '.{exts[-2]}.{ext}': Windows hides known extensions by default, so the "
            f"user sees '.{exts[-2]}' while the file is really '.{ext}'.", ["T1036.007", "T1566.001"])
    if "  " in name or name != name.strip():
        add("att_padding", "Whitespace padding in file name", "medium", 10,
            "Runs of spaces push the real extension out of view in narrow file-name columns.",
            ["T1036.007"])
    if ext in EXECUTABLE_EXT:
        add("att_executable", f"Executable / script attachment (.{ext})", "high", 30,
            "This file type runs code when double-clicked. Businesses do not exchange executables "
            "or scripts by e-mail; most gateways should block them.", ["T1566.001", "T1204.002"])
    elif ext in DISK_IMAGE_EXT:
        add("att_disk_image", f"Disk image attachment (.{ext})", "high", 25,
            "ISO/IMG/VHD containers mount as a drive and historically let payloads escape the "
            "Mark-of-the-Web warning.", ["T1553.005", "T1566.001"])
    elif ext in HTML_EXT:
        add("att_html", f"HTML/SVG attachment (.{ext})", "medium", 20,
            "Local HTML/SVG files open in the browser and are used for credential-harvesting pages "
            "and HTML smuggling (the payload is assembled by JavaScript on the victim's machine).",
            ["T1027.006", "T1566.001"])
    if ext in MACRO_EXT:
        add("att_macro_ext", f"Macro-enabled Office document (.{ext})", "high", 25,
            "The 'm' extensions can carry VBA macros that run when the user clicks 'Enable content'.",
            ["T1566.001", "T1204.002", "T1059.005"])

    data = att.data or b""
    if data.startswith(b"MZ") and ext not in EXECUTABLE_EXT:
        add("att_disguised_exe", "Windows executable disguised under another extension", "critical", 35,
            f"The content starts with the 'MZ' header of a Windows PE executable but the name says "
            f"'.{ext or '(none)'}'.", ["T1036.007", "T1566.001", "T1204.002"])
    listing = _zip_names(data)
    if listing is not None:
        names, encrypted = listing
        has_vba = any(n.lower().endswith("vbaproject.bin") for n in names)
        if has_vba and ext in MACRO_EXT:
            add("att_vba_present", "VBA macro project confirmed inside the document", "medium", 5,
                "The OOXML package listing contains vbaProject.bin, i.e. the document really carries "
                "macro code (listing only - the macro is not extracted or run).",
                ["T1566.001", "T1204.002", "T1059.005"])
        elif has_vba:
            add("att_ooxml_vba", "Office file hides a VBA project", "high", 30,
                "The OOXML package contains vbaProject.bin (macro code) although its extension does "
                "not announce macros - a deliberate disguise.", ["T1566.001", "T1204.002", "T1059.005"])
        if ext in ARCHIVE_EXT or ext not in OFFICE_EXT:
            risky = [n for n in names if _ext_chain(n) and _ext_chain(n)[-1] in (EXECUTABLE_EXT | DISK_IMAGE_EXT | HTML_EXT | MACRO_EXT)]
            if risky:
                add("att_archive_risky", "Archive contains executable/script/macro files", "high", 25,
                    f"Inside the archive: {', '.join(safe_display(r) for r in risky[:5])}. Archives "
                    "are used to slip payloads past extension filters.", ["T1566.001", "T1204.002"])
            if encrypted:
                add("att_archive_encrypted", "Password-protected archive", "medium", 15,
                    "Encrypted archives cannot be scanned by the mail gateway's antivirus; the password "
                    "is usually given in the e-mail body.", ["T1566.001"])
    if data.startswith(OLE_MAGIC) and ext in OFFICE_EXT and ext not in MACRO_EXT:
        add("att_ole_office", "Legacy OLE Office document", "low", 8,
            "Old binary Office formats (.doc/.xls) can embed macros without a special extension. "
            "Inspect with oletools (olevba) in a sandbox - never open it on a workstation.",
            ["T1566.001"])
    if ext in ARCHIVE_EXT and listing is None and not f:
        add("att_archive", f"Archive attachment (.{ext})", "low", 8,
            "Archive content could not be listed statically (non-ZIP format). Extract only inside a "
            "sandbox.", ["T1566.001"])
    return f


def analyze_attachments(email: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for att in email.attachments:
        out.extend(analyze_attachment(att))
    return out
