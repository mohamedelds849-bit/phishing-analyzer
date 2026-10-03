import io
import zipfile

from phishing_analyzer.attachments import analyze_attachment
from phishing_analyzer.parser import Attachment

DUMMY = b"harmless dummy bytes"


def att(name, data=DUMMY, mime="application/octet-stream"):
    return Attachment(name, mime, len(data), "0" * 64, "0" * 32, data)


def ids(name, data=DUMMY):
    return {f.id for f in analyze_attachment(att(name, data))}


def zip_bytes(entries, encrypt_flag=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in entries:
            z.writestr(n, DUMMY)
    data = bytearray(buf.getvalue())
    if encrypt_flag:  # set the 'encrypted' general-purpose bit in every header
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            while i != -1:
                data[i + off] |= 0x01
                i = data.find(sig, i + 4)
    return bytes(data)


def test_benign_pdf():
    assert ids("report.pdf", b"%PDF-1.7 dummy") == set()


def test_double_extension():
    assert {"att_double_ext", "att_executable"} <= ids("invoice.pdf.exe")


def test_rtlo():
    assert "att_rtlo" in ids("invoice‮fdp.exe")


def test_padding():
    assert "att_padding" in ids("invoice.pdf          .exe")


def test_macro_extension_and_vba_listing():
    assert "att_macro_ext" in ids("order.docm")
    assert "att_ooxml_vba" in ids("order.docx", zip_bytes(["word/document.xml", "word/vbaProject.bin"]))
    assert "att_vba_present" in ids("order.xlsm", zip_bytes(["xl/vbaProject.bin"]))


def test_disguised_executable_magic():
    assert "att_disguised_exe" in ids("photo.jpg", b"MZ" + b"\x00" * 64)


def test_zip_with_script_and_encrypted():
    assert "att_archive_risky" in ids("docs.zip", zip_bytes(["readme.txt", "run.js"]))
    assert "att_archive_encrypted" in ids("docs.zip", zip_bytes(["a.txt"], encrypt_flag=True))


def test_disk_image_html_and_ole():
    assert "att_disk_image" in ids("scan.iso")
    assert "att_html" in ids("payment.html")
    assert "att_ole_office" in ids("old.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)


def test_non_zip_archive_low():
    assert ids("files.rar", b"Rar!\x1a\x07\x00") == {"att_archive"}


def test_zip_payload_hidden_behind_many_dummy_entries():
    # review fix: the listing used to stop after 2000 entries, so a payload
    # placed after 5000 dummy files was never seen
    data = zip_bytes([f"f{i}.txt" for i in range(5000)] + ["payload.js"])
    assert "att_archive_risky" in ids("photos.zip", data)
