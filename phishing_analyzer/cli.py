"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze_file
from .lookalike import BrandList
from .report import to_console, to_html, to_json
from .scoring import VERDICT_PHISHING, VERDICT_SUSPICIOUS

EXIT_CODES = {VERDICT_SUSPICIOUS: 10, VERDICT_PHISHING: 20}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Offline SOC L1 triage of a suspicious e-mail (.eml): risk score, findings, IOCs.",
    )
    p.add_argument("eml", help="path to the .eml file (export 'original message' from the mailbox)")
    p.add_argument("--json", action="store_true", help="print the JSON report to stdout instead of the summary")
    p.add_argument("--json-out", metavar="PATH", help="also write the JSON report to PATH")
    p.add_argument("--html", metavar="PATH", help="write a standalone HTML report to PATH")
    p.add_argument("--online", action="store_true",
                   help="query public DNS for the sender domain's SPF/DMARC (needs dnspython). Default: offline")
    p.add_argument("--brands", metavar="PATH", help="custom protected-brands JSON (default: bundled list)")
    p.add_argument("--authserv-id", metavar="ID",
                   help="only trust Authentication-Results written by this server (e.g. mx.yourcompany.ma)")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 0 = likely safe, 10 = suspicious, 20 = likely phishing (for SOAR pipelines)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")  # never crash on exotic characters (Windows consoles)
    except (AttributeError, ValueError):
        pass
    path = Path(args.eml)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    try:
        brands = BrandList.load(args.brands) if args.brands else BrandList.load()
        report = analyze_file(path, brands=brands, online=args.online, authserv_id=args.authserv_id)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(to_json(report))
    else:
        print(to_console(report))
    if args.json_out:
        Path(args.json_out).write_text(to_json(report), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(to_html(report), encoding="utf-8")
        if not args.json:
            print(f"HTML report written to {args.html}")
    return EXIT_CODES.get(report["verdict"], 0) if args.exit_code else 0
