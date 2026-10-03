"""Renderers: console text, JSON, standalone HTML (no CDN, no JavaScript).

The HTML report never embeds the e-mail's own HTML: every value is escaped
text, and URLs are shown defanged and are not clickable.
"""

from __future__ import annotations

import json
from html import escape

from .util import defang_url, safe_display

VERDICT_COLORS = {"Likely safe": "#1f7a3a", "Suspicious": "#b26a00", "Likely phishing": "#b3261e"}


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def _fmt_delay(d) -> str:
    if d is None:
        return ""
    return f"(+{d:.0f}s)" if d >= 0 else f"({d:.0f}s!)"


def to_console(report: dict) -> str:
    m = report["message"]
    a = report["authentication"]
    L: list[str] = []
    bar = "=" * 72
    L.append(bar)
    L.append(" PHISHING ANALYZER - SOC L1 triage report")
    L.append(bar)
    L.append(f" File        : {report['source']}")
    L.append(f" SHA-256     : {m['sha256']}")
    L.append(f" Subject     : {safe_display(m['subject'])}")
    fr = m["from"]
    L.append(f" From        : \"{safe_display(fr['display_name'])}\" <{fr['address']}>" if fr else " From        : (none)")
    for rt in m["reply_to"]:
        L.append(f" Reply-To    : <{rt['address']}>")
    if m["return_path"]:
        L.append(f" Return-Path : <{m['return_path']['address']}>")
    L.append(f" Date        : {m['date']}")
    L.append(f" Auth        : SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}"
             f"  (source: {a['source']}, authserv-id: {a['authserv_id']})")
    L.append("")
    L.append(f" VERDICT     : {report['verdict'].upper()}   score {report['score']}/100")
    L.append("")
    scored = [f for f in report["findings"] if f["weight"] > 0]
    info = [f for f in report["findings"] if f["weight"] == 0]
    L.append(f"-- Findings ({len(scored)} scored, {len(info)} informational) " + "-" * 20)
    counted: set[str] = set()
    for f in scored + info:
        dup = f["id"] in counted
        counted.add(f["id"])
        att = ", ".join(t["id"] for t in f["attack"])
        pts = "  +0 (already counted)" if dup and f["weight"] else f"+{f['weight']:>2}"
        L.append(f" [{f['severity'].upper():<8} {pts}] {f['title']}" + (f"  [{att}]" if att else ""))
        L.append(f"      why : {f['why']}")
        if f["evidence"]:
            L.append(f"      seen: {safe_display(f['evidence'])}")
    L.append("")
    L.append("-- Received chain (oldest hop first) " + "-" * 34)
    if not report["received_chain"]:
        L.append(" (no Received headers)")
    for h in report["received_chain"]:
        ip = f" [{h['from_ip']}]" if h["from_ip"] else ""
        L.append(f" {h['index']:>2}. from {h['from_host'] or '?'}{ip} by {h['by_host'] or '?'}  "
                 f"{h['timestamp'] or 'no-date'} {_fmt_delay(h['delay_seconds'])}")
    L.append("")
    L.append(f"-- URLs ({len(report['urls'])}) " + "-" * 56)
    for u in report["urls"]:
        flags = ",".join(u.get("flags", [])) or "-"
        L.append(f" {defang_url(u['url'])}  [{u['source']}] flags={flags}")
    L.append("")
    L.append(f"-- Attachments ({len(report['attachments'])}) " + "-" * 49)
    for at in report["attachments"]:
        L.append(f" {at['filename']}  {at['size']} B  {at['content_type']}")
        L.append(f"      sha256 {at['sha256']}")
    L.append("")
    L.append("-- IOCs for the ticket (defanged; * = flagged by a rule) " + "-" * 15)
    i = report["iocs"]
    for d in i["domains"]:
        L.append(f" domain {'*' if d['flagged'] else ' '} {d['defanged']}")
    for u in i["urls"]:
        L.append(f" url    {'*' if u['flagged'] else ' '} {u['defanged']}")
    for ip in i["ips"]:
        L.append(f" ip     {'*' if ip['flagged'] else ' '} {ip['defanged']}  ({ip['source']})")
    for h in i["hashes"]:
        L.append(f" sha256 {'*' if h['flagged'] else ' '} {h['sha256']}  {h['filename']}")
    if report["attack_techniques"]:
        L.append("")
        L.append(" ATT&CK: " + "; ".join(f"{t['id']} {t['name']}" for t in report["attack_techniques"]))
    L.append(bar)
    # Any header/URL/file name may carry ESC or other control characters
    # (ANSI escape injection into the analyst's terminal): make them visible.
    return "\n".join(safe_display(line) for line in L)


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#dde1e6;--code:#eef1f4}
@media (prefers-color-scheme: dark){:root{--bg:#111418;--card:#1a1f25;--fg:#e6e9ed;--muted:#9aa4b0;--line:#2c333b;--code:#232a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1060px;margin:0 auto;padding:24px 16px}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:14px 0;overflow-x:auto}
.muted{color:var(--muted)}.verdict{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.badge{color:#fff;padding:6px 12px;border-radius:999px;font-weight:600}
.gauge{flex:1;min-width:200px;height:12px;background:var(--code);border-radius:6px;overflow:hidden}
.gauge>div{height:100%}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;word-break:break-all}
.sev{font-weight:600;font-size:12px;padding:2px 8px;border-radius:6px;color:#fff;white-space:nowrap}
.sev-critical{background:#7a0d0d}.sev-high{background:#b3261e}.sev-medium{background:#b26a00}.sev-low{background:#5b6470}.sev-info{background:#2f6db3}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
footer{font-size:12px;color:var(--muted);margin-top:20px}
"""


def _e(s) -> str:
    return escape(safe_display(str(s if s is not None else "")))


def to_html(report: dict) -> str:
    m, a, i = report["message"], report["authentication"], report["iocs"]
    color = VERDICT_COLORS.get(report["verdict"], "#5b6470")
    fr = m["from"]
    rows = []
    counted: set[str] = set()
    for f in report["findings"]:
        dup = f["id"] in counted
        counted.add(f["id"])
        pts = "+0 (dup)" if dup and f["weight"] else f"+{f['weight']}"
        att = "<br>".join(f"<code>{_e(t['id'])}</code> {_e(t['name'])}" for t in f["attack"]) or "-"
        rows.append(
            f"<tr><td><span class='sev sev-{_e(f['severity'])}'>{_e(f['severity'])}</span></td>"
            f"<td class='mono'>{pts}</td><td><b>{_e(f['title'])}</b><br><span class='muted'>{_e(f['why'])}</span>"
            f"{'<br><code>' + _e(f['evidence']) + '</code>' if f['evidence'] else ''}</td><td>{att}</td></tr>")
    hops = "".join(
        f"<tr><td>{h['index']}</td><td class='mono'>{_e(h['from_host'])}</td><td class='mono'>{_e(h['from_ip'])}</td>"
        f"<td class='mono'>{_e(h['by_host'])}</td><td class='mono'>{_e(h['timestamp'])}</td><td>{_e(_fmt_delay(h['delay_seconds']))}</td></tr>"
        for h in report["received_chain"]) or "<tr><td colspan='6'>No Received headers</td></tr>"
    urls = "".join(
        f"<tr><td class='mono'>{_e(defang_url(u['url']))}</td><td>{_e(u['source'])}</td>"
        f"<td>{_e(u.get('anchor_text', ''))}</td><td class='mono'>{_e(', '.join(u.get('flags', [])) or '-')}</td></tr>"
        for u in report["urls"]) or "<tr><td colspan='4'>No URLs</td></tr>"
    atts = "".join(
        f"<tr><td class='mono'>{_e(x['filename'])}</td><td>{x['size']}</td><td>{_e(x['content_type'])}</td>"
        f"<td class='mono'>{_e(x['sha256'])}<br><span class='muted'>md5 {_e(x['md5'])}</span></td></tr>"
        for x in report["attachments"]) or "<tr><td colspan='4'>No attachments</td></tr>"

    def ioc_rows(kind, items, key="defanged"):
        return "".join(f"<tr><td>{kind}</td><td class='mono'>{_e(it[key])}</td><td>{'yes' if it['flagged'] else ''}</td></tr>"
                       for it in items)
    iocs = (ioc_rows("domain", i["domains"]) + ioc_rows("url", i["urls"]) + ioc_rows("ip", i["ips"])
            + ioc_rows("sha256", i["hashes"], "sha256")) or "<tr><td colspan='3'>None</td></tr>"
    reply = ", ".join(r["address"] for r in m["reply_to"]) or "-"
    attack = ", ".join(f"{t['id']} {t['name']}" for t in report["attack_techniques"]) or "-"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Phishing triage report</title><style>{_CSS}</style></head><body><main>
<h1>Phishing triage report</h1>
<div class="muted">{_e(report['source'])} &middot; analysed {_e(report['analyzed_at'])} &middot; {_e(report['tool']['name'])} {_e(report['tool']['version'])}</div>
<section class="card verdict"><span class="badge" style="background:{color}">{_e(report['verdict'])}</span>
<b style="font-size:22px">{report['score']}/100</b>
<div class="gauge" aria-label="risk score"><div style="width:{report['score']}%;background:{color}"></div></div></section>
<section class="card"><h2>Message</h2><dl>
<dt>Subject</dt><dd>{_e(m['subject'])}</dd>
<dt>From</dt><dd>{_e(('"' + fr['display_name'] + '" ') if fr and fr['display_name'] else '')}&lt;{_e(fr['address'] if fr else '')}&gt;</dd>
<dt>Reply-To</dt><dd>{_e(reply)}</dd>
<dt>Return-Path</dt><dd>{_e(m['return_path']['address'] if m['return_path'] else '-')}</dd>
<dt>Date</dt><dd>{_e(m['date'])}</dd><dt>Message-ID</dt><dd>{_e(m['message_id'])}</dd>
<dt>SHA-256 (.eml)</dt><dd class="mono">{_e(m['sha256'])}</dd>
<dt>Authentication</dt><dd>SPF <b>{_e(a['spf'])}</b> &middot; DKIM <b>{_e(a['dkim'])}</b> &middot; DMARC <b>{_e(a['dmarc'])}</b>
<span class="muted">(source {_e(a['source'])}, authserv-id {_e(a['authserv_id'])})</span></dd>
<dt>ATT&amp;CK</dt><dd>{_e(attack)}</dd></dl></section>
<section class="card"><h2>Findings</h2><table><tr><th>Severity</th><th>Points</th><th>Finding / why</th><th>ATT&amp;CK</th></tr>
{''.join(rows) or "<tr><td colspan='4'>No findings</td></tr>"}</table></section>
<section class="card"><h2>Received chain (oldest first)</h2><table><tr><th>#</th><th>From</th><th>IP</th><th>By</th><th>Time (UTC)</th><th>Delay</th></tr>{hops}</table></section>
<section class="card"><h2>URLs (defanged, not clickable)</h2><table><tr><th>URL</th><th>Source</th><th>Link text</th><th>Flags</th></tr>{urls}</table></section>
<section class="card"><h2>Attachments (static analysis only)</h2><table><tr><th>File</th><th>Bytes</th><th>MIME</th><th>Hashes</th></tr>{atts}</table></section>
<section class="card"><h2>IOCs for the ticket</h2><table><tr><th>Type</th><th>Value</th><th>Flagged</th></tr>{iocs}</table></section>
<footer>Heuristic triage aid - a score is not proof. Confirm in a sandbox / with threat intelligence before blocking or closing the ticket.</footer>
</main></body></html>
"""
