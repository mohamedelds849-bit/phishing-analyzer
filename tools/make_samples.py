"""Regenerate the SYNTHETIC sample e-mails in samples/.

Everything here is invented: domains use example.com / .example / .test
(reserved by RFC 2606 / RFC 6761), IPs come from the documentation ranges
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737), people are
fictional, and "malicious" attachments are harmless placeholder text.

    python tools/make_samples.py
"""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from email.policy import default
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
DUMMY = (b"HARMLESS DUMMY ATTACHMENT for phishing-analyzer tests.\n"
         b"This file contains no code. It only exists so the analyzer can hash it.\n")


def finalize(msg: EmailMessage, name: str) -> None:
    for i, part in enumerate(p for p in msg.walk() if p.is_multipart()):
        part.set_boundary(f"=_sample_boundary_{i}_=")
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_bytes(msg.as_bytes(policy=default))
    print("wrote", OUT / name)


def base(headers: list[tuple[str, str]]) -> EmailMessage:
    msg = EmailMessage()
    for k, v in headers:
        msg[k] = v
    return msg


def legit_newsletter() -> None:
    msg = base([
        ("Return-Path", "<bounce-7731@mailer.example.net>"),
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Tue, 15 Sep 2026 08:00:09 +0000"),
        ("Received", "from out-12.mailer.example.net (out-12.mailer.example.net [198.51.100.12]) by "
                     "mx-in.corp.example with ESMTPS id 4A1B2C; Tue, 15 Sep 2026 08:00:07 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=pass smtp.mailfrom=mailer.example.net; "
                                   "dkim=pass header.d=example.com header.s=news; dmarc=pass header.from=example.com"),
        ("From", "Example Weekly <news@newsletter.example.com>"),
        ("To", "reader@corp.example"),
        ("Subject", "Example Weekly #142 - five security reads for your coffee break"),
        ("Date", "Tue, 15 Sep 2026 08:00:02 +0000"),
        ("Message-ID", "<142.20260915080002@newsletter.example.com>"),
        ("List-Unsubscribe", "<https://www.example.com/unsubscribe?u=abc123>"),
    ])
    msg.set_content(
        "Hello reader,\n\nThis week's picks:\n"
        "1. How DMARC reporting works - https://www.example.com/articles/dmarc-reports\n"
        "2. Patch Tuesday recap - https://www.example.com/articles/patch-recap\n\n"
        "You receive this because you subscribed on example.com.\n"
        "Unsubscribe: https://www.example.com/unsubscribe?u=abc123\n")
    msg.add_alternative(
        "<html><body><h1>Example Weekly #142</h1><p>This week's picks:</p><ul>"
        "<li><a href=\"https://www.example.com/articles/dmarc-reports\">How DMARC reporting works</a></li>"
        "<li><a href=\"https://www.example.com/articles/patch-recap\">Patch Tuesday recap</a></li></ul>"
        "<img src=\"https://cdn.example.com/logo.png\" alt=\"Example\">"
        "<p><a href=\"https://www.example.com/unsubscribe?u=abc123\">Unsubscribe</a></p></body></html>",
        subtype="html")
    finalize(msg, "01_legit_newsletter.eml")


def obvious_phishing() -> None:
    msg = base([
        ("Return-Path", "<bounce@bulk-sender.test>"),
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Wed, 16 Sep 2026 02:14:40 +0000"),
        ("Received", "from vps-4471.bulk-sender.test (unknown [203.0.113.66]) by mx-in.corp.example "
                     "with ESMTP id 9F8E7D; Wed, 16 Sep 2026 02:14:38 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=fail smtp.mailfrom=bulk-sender.test; "
                                   "dkim=none; dmarc=fail header.from=paypa1.test"),
        ("From", "PayPal Service <service@paypa1.test>"),
        ("Reply-To", "verify-team@mailbox-help.test"),
        ("To", "victim@corp.example"),
        ("Subject", "URGENT: Your account has been suspended"),
        ("Date", "Wed, 16 Sep 2026 02:14:30 +0000"),
        ("Message-ID", "<0001.abc@vps-4471.bulk-sender.test>"),
    ])
    msg.set_content(
        "Dear customer,\n\nWe detected unusual activity. Your account has been suspended.\n"
        "Verify your account within 24 hours or it will be closed permanently.\n"
        "Confirm your password here: https://www.paypal.com@198.51.100.7/verify\n\nPayPal Security\n")
    msg.add_alternative(
        "<html><body><p>Dear customer,</p><p>We detected <b>unusual activity</b>. Your account has been suspended.</p>"
        "<p>Verify your account within 24 hours or it will be closed permanently.</p>"
        "<p><a href=\"http://192.0.2.45/paypal/login.php\">https://www.paypal.com/signin</a></p>"
        "<p>Confirm your password: <a href=\"https://www.paypal.com@198.51.100.7/verify\">secure verification</a></p>"
        "</body></html>", subtype="html")
    finalize(msg, "02_obvious_phishing.eml")


def subtle_lookalike() -> None:
    # 'attijariwafabnak' (letters swapped) + an IDN with a Cyrillic 'а'
    idn = "attijariwafabаnk.test".encode("idna").decode("ascii")
    msg = base([
        ("Return-Path", "<notification@attijariwafabnak.test>"),
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Thu, 17 Sep 2026 09:31:05 +0000"),
        ("Received", "from mail.attijariwafabnak.test (mail.attijariwafabnak.test [203.0.113.21]) by "
                     "mx-in.corp.example with ESMTPS id 1Q2W3E; Thu, 17 Sep 2026 09:31:03 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=pass smtp.mailfrom=attijariwafabnak.test; "
                                   "dkim=pass header.d=attijariwafabnak.test; dmarc=pass header.from=attijariwafabnak.test"),
        ("From", "Attijariwafa bank <notification@attijariwafabnak.test>"),
        ("To", "client@corp.example"),
        ("Subject", "Mise a jour de securite de votre espace client"),
        ("Date", "Thu, 17 Sep 2026 09:31:00 +0000"),
        ("Message-ID", "<20260917093100.77@attijariwafabnak.test>"),
    ])
    msg.set_content(
        "Cher client,\n\nDans le cadre du renforcement de la securite, nous vous invitons a mettre a jour "
        "vos informations avant le 30 septembre.\n"
        "Acceder a mon espace : https://attijariwafabnak.test/espace-client\n\n"
        "Cordialement,\nService Clientele\n")
    msg.add_alternative(
        "<html><body><p>Cher client,</p><p>Dans le cadre du renforcement de la s&eacute;curit&eacute;, nous "
        "vous invitons &agrave; mettre &agrave; jour vos informations avant le 30 septembre.</p>"
        "<p><a href=\"https://attijariwafabnak.test/espace-client\">Acc&eacute;der &agrave; mon espace</a></p>"
        f"<p>Suivi de votre demande : <a href=\"https://{idn}/suivi\">suivi de la demande</a></p>"
        "<p>Cordialement,<br>Service Client&egrave;le</p></body></html>", subtype="html")
    finalize(msg, "03_subtle_lookalike_fr.eml")


def malicious_attachment() -> None:
    docm = io.BytesIO()
    with zipfile.ZipFile(docm, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", DUMMY)  # placeholder bytes, NOT a real macro
    msg = base([
        ("Return-Path", "<noreply@dhl-livraison.test>"),
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Fri, 18 Sep 2026 14:02:11 +0000"),
        ("Received", "from smtp.dhl-livraison.test (unknown [203.0.113.99]) by mx-in.corp.example "
                     "with ESMTP id 5T6Y7U; Fri, 18 Sep 2026 14:02:09 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=softfail smtp.mailfrom=dhl-livraison.test; "
                                   "dkim=none; dmarc=none header.from=dhl-livraison.test"),
        ("From", "DHL Express <noreply@dhl-livraison.test>"),
        ("To", "logistique@corp.example"),
        ("Subject", "Avis de livraison - colis en attente de paiement"),
        ("Date", "Fri, 18 Sep 2026 14:02:00 +0000"),
        ("Message-ID", "<avis-55120@dhl-livraison.test>"),
    ])
    msg.set_content(
        "Bonjour,\n\nVotre colis est bloque en douane. Merci d'ouvrir la facture jointe et de proceder "
        "au paiement des frais sous 48h, sinon le colis sera retourne a l'expediteur.\n\nDHL Express\n")
    msg.add_attachment(DUMMY, maintype="application", subtype="octet-stream",
                       filename="Facture_DHL_0918.pdf.exe")
    msg.add_attachment(docm.getvalue(), maintype="application",
                       subtype="vnd.ms-word.document.macroEnabled.12", filename="Bordereau_livraison.docm")
    finalize(msg, "04_malicious_attachment_fr.eml")


def bec_ceo_fraud() -> None:
    msg = base([
        ("Return-Path", "<karim.testouni.pdg@direction-acme.test>"),
        ("Received", "from mx-in.acme-maroc.example (mx-in.acme-maroc.example [10.1.0.5]) by "
                     "mbox.acme-maroc.example with LMTP; Mon, 21 Sep 2026 10:47:33 +0100"),
        ("Received", "from mail.direction-acme.test (mail.direction-acme.test [198.51.100.140]) by "
                     "mx-in.acme-maroc.example with ESMTPS id 8I9O0P; Mon, 21 Sep 2026 10:47:31 +0100"),
        ("Authentication-Results", "mx-in.acme-maroc.example; spf=pass smtp.mailfrom=direction-acme.test; "
                                   "dkim=pass header.d=direction-acme.test; dmarc=pass header.from=direction-acme.test"),
        ("From", "Karim Testouni - PDG <karim.testouni.pdg@direction-acme.test>"),
        ("Reply-To", "k.testouni@securemail-pdg.test"),
        ("To", "Salma - Comptabilite <comptabilite@acme-maroc.example>"),
        ("Subject", "Demande confidentielle"),
        ("Date", "Mon, 21 Sep 2026 10:47:25 +0100"),
        ("Message-ID", "<CAF-31337@direction-acme.test>"),
    ])
    msg.set_content(
        "Bonjour Salma,\n\n"
        "Je suis en reunion avec nos partenaires et je ne suis pas joignable par telephone.\n"
        "J'ai besoin que tu effectues aujourd'hui meme un virement urgent de 185 000 MAD pour finaliser "
        "une acquisition. Utilise le nouveau RIB ci-dessous :\n\n"
        "IBAN : MA00 0000 0000 0000 0000 0000 000 (fictif)\n\n"
        "Ce dossier est strictement confidentiel, n'en parle a personne pour l'instant.\n"
        "Envoie-moi la confirmation des que possible.\n\nKarim\nEnvoye de mon mobile\n")
    finalize(msg, "05_bec_ceo_fraud_fr.eml")


def display_name_credential_form() -> None:
    msg = base([
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Tue, 22 Sep 2026 07:12:50 +0000"),
        ("Received", "from relay.m365-alerts.test (unknown [192.0.2.200]) by mx-in.corp.example "
                     "with ESMTP id 3E4R5T; Tue, 22 Sep 2026 07:12:48 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=none smtp.mailfrom=m365-alerts.test; "
                                   "dkim=none; dmarc=none header.from=m365-alerts.test"),
        ("Authentication-Results", "attacker.forged; spf=pass; dkim=pass header.d=microsoft.com; dmarc=pass"),
        ("From", "\"support@microsoft.com\" <helpdesk@m365-alerts.test>"),
        ("To", "employee@corp.example"),
        ("Subject", "Action required: password expires today"),
        ("Date", "Tue, 22 Sep 2026 07:12:40 +0000"),
        ("Message-ID", "<pwd-expiry-001@relay.m365-alerts.test>"),
    ])
    msg.set_content("Your mailbox password expires today. Open this message in HTML to keep your access.\n")
    msg.add_alternative(
        "<html><body><p>Your Microsoft 365 password expires today.</p>"
        "<p>Confirm your password below to keep the same password:</p>"
        "<form action=\"https://m365-alerts.test/owa/collect.php\" method=\"post\">"
        "<input type=\"email\" name=\"u\"><input type=\"password\" name=\"p\">"
        "<button type=\"submit\">Keep my password</button></form>"
        "<p><a href=\"https://m365-alerts.test/review\">Review recent sign-in activity</a></p>"
        "</body></html>", subtype="html")
    finalize(msg, "06_display_name_credential_form.eml")


def gray_shared_document() -> None:
    """A 'grey' message: no brand abuse, but weak authentication, a Reply-To
    to another domain and a deadline. Should land in Suspicious, not Phishing."""
    msg = base([
        ("Return-Path", "<notify@partner-docs.test>"),
        ("Received", "from mx-in.corp.example (mx-in.corp.example [10.0.0.5]) by mbox.corp.example "
                     "with LMTP; Wed, 23 Sep 2026 16:20:12 +0000"),
        ("Received", "from out.partner-docs.test (out.partner-docs.test [198.51.100.77]) by "
                     "mx-in.corp.example with ESMTPS id 6Y7U8I; Wed, 23 Sep 2026 16:20:10 +0000"),
        ("Authentication-Results", "mx-in.corp.example; spf=softfail smtp.mailfrom=partner-docs.test; "
                                   "dkim=pass header.d=partner-docs.test; dmarc=none header.from=partner-docs.test"),
        ("From", "Partner Docs <notify@partner-docs.test>"),
        ("Reply-To", "sales-office@freemail-box.test"),
        ("To", "achats@corp.example"),
        ("Subject", "Nouveau document partage : Proposition commerciale Q4"),
        ("Date", "Wed, 23 Sep 2026 16:20:05 +0000"),
        ("Message-ID", "<doc-8812@partner-docs.test>"),
    ])
    msg.set_content(
        "Bonjour,\n\nUn document vous a ete partage : Proposition_Q4.pdf\n"
        "Le lien reste actif sous 72h : https://share.partner-docs.test/d/8812\n\n"
        "Pour toute question, repondez simplement a ce message.\n")
    finalize(msg, "07_gray_shared_document_fr.eml")


if __name__ == "__main__":
    gray_shared_document()
    legit_newsletter()
    obvious_phishing()
    subtle_lookalike()
    malicious_attachment()
    bec_ceo_fraud()
    display_name_credential_form()
