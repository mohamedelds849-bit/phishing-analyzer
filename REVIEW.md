# Security review: phishing-analyzer

Reviewer role: Security Reviewer (SOC analyst / e-mail security engineer + Python code review).
Date: 2026-10-03. Scope: all of `phishing_analyzer/`, `tests/`, `samples/`, `examples/`,
`README.md`, `LEARN.md`, `brands.json`. Baseline: commit `c58b375`.

## Verdict

| Item | Result |
|---|---|
| Technical score | **8.5 / 10** |
| Educational score | **9 / 10** |
| Safety status | **PASS** (after fixes below) |
| Consistency status | **PASS** (after fixes below) |
| Final | **APPROVED** |

The tool is well built for a student portfolio project. Parsing is stdlib-only, nothing is
executed, rendered or fetched, the HTML report escapes everything and ships a strict CSP, and
the limitations section is honest. The problems found were real but small, and all were fixed
in this review.

## What was verified

- `python -m pytest`: 84/84 passed before the review, **92/92** after (8 new tests).
- All 7 samples re-run: the verdicts and scores match the README table exactly
  (5 / 100 / 100 / 100 / 85 / 100 / 38). The BEC console excerpt in the README matches a real run.
- Adversarial inputs tried against the tool itself:
  - **XSS** in the display name, Subject, Message-ID, Received, anchor href/text, and attachment file name. Every value is HTML-escaped (`html.escape` + `safe_display`), no live `href`/`src` appears, and the CSP is `default-src 'none'`. **PASS.**
  - Empty file, random binary, broken headers, unknown charset, invalid base64: no crash. **PASS.**
  - 3000-level nested multipart: **crashed** with a `RecursionError` traceback. Fixed.
  - ANSI/OSC escape sequences in Date and in a URL reached the analyst's terminal raw. Fixed.
  - ZIP with 5000 dummy entries followed by `payload.js`: **not detected**, because the listing was truncated at 2000 entries (evasion). Fixed.
  - Zip bomb: only the central directory is read and no member is decompressed. **PASS.**
  - `--json-out`/`--html` pointing to a missing directory gave a traceback. Fixed.
- Authentication-Results parsing was checked against real-world Gmail and Microsoft 365 header formats. Both parse correctly. M365 has no authserv-id, which is now documented.
- The official domains of Moroccan banks were checked against public sources (see below).

## Problems found

1. **Wrong or outdated brand domains (false positives on real bank mail).**
   - `creditdumaroc.ma` (Crédit du Maroc's actual site) was flagged `brand_wrong_domain` (+20). Only the legacy `cdm.co.ma` was listed.
   - `attijariwafa.com` (it hosts Attijarinet: `attijarinet.attijariwafa.com`, `attijarinet@attijariwafa.com`) was flagged (+20). The listed `attijarinet.com` could not be verified.
   - Société Générale Maroc was renamed **Saham Bank** on 2025-06-18 (`sahambank.com`). The brand was missing, so a `sahambank-securite.test` lookalike went undetected.
   - Crédit Agricole du Maroc (`creditagricole.ma`) was missing.
2. **Free-mail brand impersonation missed.** `"Microsoft Security" <x@outlook.com>` and `"Google Account Team" <x@gmail.com>` scored 10 (*Likely safe*): because outlook.com and gmail.com are listed as official Microsoft/Google domains, the display-name rule never fired.
3. **Free-mail provider flagged as an IOC.** `reply_to_mismatch` (and the brand rule) put the provider domain (e.g. `gmail.com`) into the IOC list marked `*` (flagged). An L1 analyst could end up blocking gmail.com.
4. **Obsolete ATT&CK IDs.** ATT&CK v19 (28 April 2026) revoked **T1656 Impersonation** and **T1672 Email Spoofing** and re-homed them as **T1684.001 / T1684.002** under T1684 *Social Engineering*. The tool used T1656 everywhere and had no email-spoofing mapping for `dmarc_fail` / `spf_fail` / `display_name_spoof`. An interviewer checking the current matrix would notice.
5. **ZIP listing truncation (evasion)**, as described above.
6. **Terminal escape injection** into the console report (Date, From address, hops and URLs were not sanitised; only the Subject was).
7. **Unhandled `RecursionError`** on pathological MIME nesting, and an unhandled `OSError` when writing reports.
8. **Trust-model explanation incomplete.** "Trust the topmost Authentication-Results" was presented as safe on its own. It is only safe if your own gateway always adds a header. Otherwise the topmost header may be the attacker's. The docs did not say that `--authserv-id` should be used in production, or that RFC 8601 §5 expects the gateway to strip inbound headers carrying its own id.
9. **Minor doc gaps.** DMARC relaxed vs strict alignment was not explained. Interview Q10 omitted T1566.003 and T1534. The test count (84) in README, LEARN and the CV line became stale.

## Fixes applied (all covered by tests, 92/92 green)

| # | File(s) | Change |
|---|---|---|
| 1 | `data/brands.json` | Attijariwafa: `attijariwafa.com` replaces unverified `attijarinet.com`; `attijarinet` keyword added. Crédit du Maroc: `creditdumaroc.ma` added. SG Maroc → **Saham Bank (ex-Societe Generale Maroc)**: `sahambank.com` + `sgmaroc.com`, keyword `sahambank`, display name `saham bank`. New brand **Crédit Agricole du Maroc** (`creditagricole.ma`, plus `credit-agricole.fr/.com` so French CA mail is not a false positive). |
| 2 | `util.py`, `headers.py` | New `FREEMAIL_DOMAINS`. `brand_display_name` now fires when a brand display name comes from a consumer free-mail address, with an explanation of why. |
| 3 | `headers.py` | For free-mail senders/Reply-To, the IOC is the **address**, never the provider domain. |
| 4 | `models.py`, all detectors, README, LEARN, examples | T1656 → **T1684.001**. Added **T1684.002 Email Spoofing** to `dmarc_fail`, `spf_fail`, `display_name_spoof`. Added a comment and docs explaining the v19 change. |
| 5 | `attachments.py` | The ZIP check now reads every entry name. Still names only, no decompression. |
| 6 | `report.py` | Every console line goes through `safe_display()`, so ESC/BEL and other control characters become `[U+001B]`. |
| 7 | `parser.py`, `cli.py` | `RecursionError` → clean `ValueError` (CLI prints `error:` and exits 1). Report-write `OSError` → `error: cannot write report`, exit 1. |
| 8 | README, LEARN §3 + Q4 context | Trust-model caveat, `--authserv-id` for production, RFC 8601 §5 stripping, M365 header without authserv-id. |
| 9 | LEARN | DMARC relaxed/strict alignment; Q10 adds T1566.003, T1534, T1684.00x and the v19 note; brand list updated; 84 → 92 tests (also in README and the CV line). README "Tests" now states that the sample-verdict tests are regression tests, not accuracy measurements. |
| 10 | `examples/` | Regenerated from real runs (new ATT&CK ids). |

New tests: ZIP padding evasion, deep MIME nesting, free-mail brand display name, free-mail
Reply-To IOC, verified Moroccan bank domains (official, so not flagged; Saham lookalike
flagged), console escape neutralisation, unwritable report path, ATT&CK v19 ids.

## Test quality assessment

- **Meaningful.** There are unit tests per detector with **negative cases**: official sub-domains, unrelated domains, `adhlong` vs `dhl`, same-org Reply-To, benign links, benign PDF, neutral text, tags not matched as text. There are also scoring-threshold tests, a regression test for the stdlib address-parsing pitfall, an HTML escaping/CSP test, and a mocked DNS test.
- **Partly self-fulfilling.** The 7 sample-verdict tests check weights that were tuned on those same samples. They protect against regressions but say nothing about precision or recall. The README now says this plainly.

## Remaining recommendations (not changed: larger or need verification)

1. **Verify these with the banks' own security pages before relying on them:** whether `chaabibank.fr` (Chaabi Bank, BCP group, Europe) and `chaabinet.ma` belong to BCP. Today `chaabibank.fr` is flagged `brand_in_hostname` (+15). Also re-check BMCI's domain from time to time: BNP Paribas announced it was selling its stake to Holmarcom, so a rebrand may follow (this was not verified in this review).
2. **Use the Public Suffix List** (`tldextract` with an offline snapshot) instead of `MULTI_PART_SUFFIXES`. `org_domain()` is wrong for many ccTLD second levels.
3. **`att_ooxml_vba` wording.** Word/Excel will not run macros from a file with a `.docx/.xlsx` extension, so "deliberate disguise" overstates the danger. Keep the finding as suspicious but consider lowering it to medium.
4. **ARC** (`ARC-Authentication-Results`) and Microsoft's `compauth=` are ignored. Forwarded mail and mailing lists will look like DMARC failures.
5. **DKIM selection.** If any DKIM result passes, `dkim=pass` is reported. It would be better to report the aligned pass separately from the non-aligned one.
6. **`spf_qualifier`** treats any word `all` as `+all`. Use a token-based SPF parser (e.g. split on whitespace and check terms).
7. **Anchor-text mismatch** can fire on text like `invoice.pdf` (treated as a domain). Use a TLD allow-list for the "shown domain".
8. **Calibration.** Measure precision and recall on a labelled public corpus (e.g. the Nazario phishing corpus vs. ham from SpamAssassin's public corpus) before quoting any accuracy number. Until then, the CV line must keep saying "validé sur des échantillons synthétiques".
9. Arabic/Darija lure keywords, and QR-code (quishing) detection, as already listed in the limitations.

## LEARN.md / CV line

- The 15 interview answers are technically correct. After the fixes, Q4 and Q10 are more complete, and the trust-model nuance is a good "trap question" answer to rehearse.
- The CV line is **honest**: it claims synthetic validation only, says "projet personnel", and explicitly warns against claiming production use. The test count has been updated to 92.

## Sources used for domain and ATT&CK checks

- Crédit du Maroc, official site www.creditdumaroc.ma (financial publications hosted there)
- Saham Bank, ex-SG Maroc: https://en.wikipedia.org/wiki/Saham_Bank, https://telquel.ma/instant-t/2025/06/18/societe-generale-maroc-devient-saham-bank_1938355/, https://www.sahambank.com
- Attijarinet on attijariwafa.com: https://www.bladi.net/attijariwafa-escroquerie-phishing.html, https://www.attijariwafabank.com
- Crédit Agricole du Maroc: https://en.wikipedia.org/wiki/Cr%C3%A9dit_Agricole_du_Maroc
- BCP group: groupebcp.com (https://wafir.ma/fr/banques/banque-populaire)
- ATT&CK: https://attack.mitre.org/techniques/T1684/, https://attack.mitre.org/techniques/T1684/001, https://attack.mitre.org/techniques/T1684/002/, https://attack.mitre.org/techniques/T1672
