"""
cli.py – Command-line interface for unrealm.

Usage:
    python -m unrealm [OPTIONS]

Options:
    --scan          Scan only, print report (default if no action flag given).
    --neutralize    Apply neutralisation after scanning.
    --remove        Apply full removal after scanning.
    --restore       Restore a prior neutralise (e.g. /bin/sh on Linux).
    --yes           Skip confirmation prompts (for automation).
    --json          Emit report as JSON instead of coloured text.
    --output FILE   Write report to FILE (in addition to stdout).
    --quiet         Suppress informational output, only print findings.
    --verbose       Extra debug output.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import textwrap
from datetime import datetime, timezone
from typing import Optional

from unrealm.findings import Finding, ScanReport, Severity
from unrealm.scanner import run_scan
from unrealm import response


# ── ANSI colour helpers ────────────────────────────────────────────────────────

_COLOUR_ENABLED = sys.stdout.isatty() and os.name != "nt"

_RESET  = "\033[0m"  if _COLOUR_ENABLED else ""
_BOLD   = "\033[1m"  if _COLOUR_ENABLED else ""
_RED    = "\033[31m" if _COLOUR_ENABLED else ""
_YELLOW = "\033[33m" if _COLOUR_ENABLED else ""
_CYAN   = "\033[36m" if _COLOUR_ENABLED else ""
_GREEN  = "\033[32m" if _COLOUR_ENABLED else ""
_DIM    = "\033[2m"  if _COLOUR_ENABLED else ""
_WHITE  = "\033[97m" if _COLOUR_ENABLED else ""

_SEV_COLOUR = {
    Severity.HIGH:   _RED    + _BOLD,
    Severity.MEDIUM: _YELLOW + _BOLD,
    Severity.LOW:    _CYAN,
    Severity.INFO:   _DIM,
}


def _sev_tag(sev: Severity) -> str:
    colour = _SEV_COLOUR.get(sev, "")
    return f"{colour}[{sev.value:^6}]{_RESET}"


# ── Report rendering ───────────────────────────────────────────────────────────

BANNER = r"""
  _   _ _   _ ____  _____    _    _     __  __
 | | | | \ | |  _ \| ____|  / \  | |   |  \/  |
 | | | |  \| | |_) |  _|   / _ \ | |   | |\/| |
 | |_| | |\  |  _ <| |___ / ___ \| |___| |  | |
  \___/|_| \_|_| \_\_____/_/   \_\_____|_|  |_|

 Realm C2 Framework Detector & Response Tool
"""

CATEGORY_ORDER = ["process", "service", "file", "registry", "network"]


def _category_icon(cat: str) -> str:
    icons = {
        "process":  "⚙",
        "service":  "⚡",
        "file":     "📄",
        "registry": "🔑",
        "network":  "🌐",
    }
    return icons.get(cat, "•")


def print_banner(quiet: bool) -> None:
    if not quiet:
        print(f"{_CYAN}{_BOLD}{BANNER}{_RESET}")


def render_report_text(report: ScanReport, quiet: bool = False) -> str:
    lines = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not quiet:
        lines.append(f"{_BOLD}{'─' * 60}{_RESET}")
        lines.append(f"{_BOLD}  Scan completed  |  platform={report.platform}  |  {ts}{_RESET}")
        lines.append(f"{_BOLD}{'─' * 60}{_RESET}")

    if not report.has_detections():
        lines.append(
            f"\n  {_GREEN}{_BOLD}✓  No realm artifacts detected.{_RESET}\n"
        )
        return "\n".join(lines)

    lines.append(
        f"\n  {_RED}{_BOLD}⚠  {report.count()} artifact(s) detected!{_RESET}\n"
    )

    # Group by category in a fixed order
    by_cat = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat in CATEGORY_ORDER + sorted(set(by_cat) - set(CATEGORY_ORDER)):
        findings = by_cat.get(cat)
        if not findings:
            continue
        icon = _category_icon(cat)
        lines.append(f"  {_WHITE}{_BOLD}{icon} {cat.upper()}{_RESET}")
        for f in findings:
            tag = _sev_tag(f.severity)
            title_col = _BOLD + f.title + _RESET
            lines.append(f"    {tag} {title_col}")
            # Wrap detail
            detail_lines = textwrap.wrap(f.detail, width=72)
            for dl in detail_lines:
                lines.append(f"           {_DIM}{dl}{_RESET}")
            if f.path:
                lines.append(f"           {_DIM}path: {f.path}{_RESET}")
        lines.append("")

    # Severity summary
    highs   = len(report.by_severity(Severity.HIGH))
    mediums = len(report.by_severity(Severity.MEDIUM))
    lows    = len(report.by_severity(Severity.LOW))
    infos   = len(report.by_severity(Severity.INFO))
    lines.append(
        f"  Summary: "
        f"{_RED}{_BOLD}{highs} HIGH{_RESET}  "
        f"{_YELLOW}{mediums} MEDIUM{_RESET}  "
        f"{_CYAN}{lows} LOW{_RESET}  "
        f"{_DIM}{infos} INFO{_RESET}"
    )
    lines.append("")
    return "\n".join(lines)


def render_report_json(report: ScanReport) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "timestamp": ts,
        "platform": report.platform,
        "finding_count": report.count(),
        "findings": [
            {
                "category": f.category,
                "severity": f.severity.value,
                "title": f.title,
                "detail": f.detail,
                "path": f.path,
                "extra": f.extra,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2)


def render_remediation_result(res: "response.RemediationResult") -> str:
    lines = [f"\n{_BOLD}── Remediation Log ──{_RESET}"]
    if res.succeeded:
        for msg in res.succeeded:
            lines.append(f"  {_GREEN}✓  {msg}{_RESET}")
    if res.failed:
        for msg in res.failed:
            lines.append(f"  {_RED}✗  {msg}{_RESET}")
    if res.skipped:
        for msg in res.skipped:
            lines.append(f"  {_DIM}–  {msg}{_RESET}")
    lines.append(
        f"\n  {_BOLD}Attempted={len(res.attempted)}  "
        f"OK={_GREEN}{len(res.succeeded)}{_RESET}  "
        f"Failed={_RED}{len(res.failed)}{_RESET}  "
        f"Skipped={len(res.skipped)}{_RESET}\n"
    )
    return "\n".join(lines)


# ── Interactive confirmation ───────────────────────────────────────────────────

def _confirm(prompt: str, auto_yes: bool) -> bool:
    if auto_yes:
        print(f"  {_DIM}(--yes) auto-confirming: {prompt}{_RESET}")
        return True
    try:
        answer = input(f"\n  {_YELLOW}{_BOLD}{prompt} [y/N]: {_RESET}").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


# ── Main ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="unrealm",
        description="Detect and respond to Realm C2 framework artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python -m unrealm                     # scan only
          python -m unrealm --neutralize        # scan + neutralize
          python -m unrealm --remove --yes      # scan + remove (no prompt)
          python -m unrealm --restore           # undo a prior neutralise
          python -m unrealm --json              # machine-readable output
        """),
    )
    action = p.add_mutually_exclusive_group()
    action.add_argument("--scan",        action="store_true", help="Scan only (default)")
    action.add_argument("--neutralize",  action="store_true", help="Neutralize after scan")
    action.add_argument("--remove",      action="store_true", help="Full removal after scan")
    action.add_argument("--restore",     action="store_true",
                        help="Restore prior neutralise (e.g. /bin/sh on Linux)")
    p.add_argument("--yes",     action="store_true", help="Skip confirmation prompts")
    p.add_argument("--json",    action="store_true", help="Output report as JSON")
    p.add_argument("--output",  metavar="FILE",      help="Write report to FILE")
    p.add_argument("--quiet",   action="store_true", help="Suppress banner and info messages")
    p.add_argument("--verbose", action="store_true", help="Extra debug output")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Default action is --scan
    if not any([args.scan, args.neutralize, args.remove, args.restore]):
        args.scan = True

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")

    if not args.quiet and not args.json:
        print_banner(quiet=False)

    # ── Restore-only path ─────────────────────────────────────────────────────
    if args.restore:
        if not _confirm("Restore prior neutralise action? (/bin/sh will be restored)", args.yes):
            print("Aborted.")
            return 0
        res = response.restore_neutralise(report=ScanReport(platform=platform.system()))
        print(render_remediation_result(res))
        return 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    if not args.quiet and not args.json:
        print(f"  {_DIM}Scanning {platform.system()} for realm/imix artifacts…{_RESET}\n")

    report = run_scan(verbose=args.verbose)

    # ── Render report ─────────────────────────────────────────────────────────
    if args.json:
        output_text = render_report_json(report)
        print(output_text)
    else:
        output_text = render_report_text(report, quiet=args.quiet)
        print(output_text)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                if args.json:
                    fh.write(output_text)
                else:
                    fh.write(render_report_json(report))  # always write JSON to file
            if not args.quiet:
                print(f"  {_DIM}Report written to {args.output}{_RESET}")
        except OSError as exc:
            print(f"  {_RED}Failed to write output file: {exc}{_RESET}", file=sys.stderr)

    # Exit early if nothing found and no action requested
    if not report.has_detections():
        return 0

    # ── Neutralize ────────────────────────────────────────────────────────────
    if args.neutralize:
        print(_render_neutralize_info())
        if not _confirm("Apply neutralisation now?", args.yes):
            print("  Neutralisation skipped.")
        else:
            # Windows IFEO is system-wide – require a second explicit confirmation
            # even when --yes is passed, because the blast radius is much larger.
            if platform.system() == "Windows":
                print(_render_ifeo_warning())
                if not _confirm(
                    "CONFIRM: Install IFEO redirect? This breaks ALL cmd.exe on this host",
                    auto_yes=False,   # always prompt – never bypass with --yes
                ):
                    print("  IFEO neutralisation aborted.")
                else:
                    res = response.neutralise(report)
                    print(render_remediation_result(res))
                    return 1 if res.failed else 0
            else:
                res = response.neutralise(report)
                print(render_remediation_result(res))
                return 1 if res.failed else 0

    # ── Remove ────────────────────────────────────────────────────────────────
    if args.remove:
        print(_render_remove_info(report))
        if _confirm("Apply FULL REMOVAL of all detected artifacts?", args.yes):
            res = response.remove(report)
            print(render_remediation_result(res))
            return 1 if res.failed else 0
        else:
            print("  Removal skipped.")

    return 0 if not report.has_detections() else 2  # 2 = detections but no action


def _render_neutralize_info() -> str:
    system = platform.system()
    msgs = {
        "Linux": (
            "  Neutralise on Linux replaces /bin/sh with /bin/true.\n"
            "  The original /bin/sh is saved to /bin/sh.realm_backup.\n"
            "\n"
            "  Effect: Eldritch sys.shell() resolves 'sh' → /bin/true.\n"
            "  Every task exits 0 with empty output. C2 comms stay LIVE.\n"
            "  Operators see task 'success' but nothing actually executes.\n"
            "\n"
            "  Restore with:  python -m unrealm --restore"
        ),
        "Darwin": (
            "  Neutralise on macOS uses a PATH-shadowing shim.\n"
            "\n"
            "  Steps:\n"
            "    1. /usr/local/bin/sh → /usr/bin/true  (noop shim created)\n"
            "    2. Realm LaunchDaemon plists are patched to inject\n"
            "       PATH=/usr/local/bin:... via EnvironmentVariables,\n"
            "       then reloaded (service stays running).\n"
            "    3. If SIP is disabled, /bin/sh is also replaced directly.\n"
            "\n"
            "  Effect: Eldritch sys.shell() resolves 'sh' via the patched\n"
            "  PATH → /usr/local/bin/sh → /usr/bin/true. Every task exits 0\n"
            "  with empty output. C2 comms stay LIVE. Operators see 'success'.\n"
            "\n"
            "  Restore with:  python -m unrealm --restore"
        ),
        "Windows": (
            "  Neutralise on Windows uses Image File Execution Options (IFEO).\n"
            "\n"
            "  Steps:\n"
            "    1. A noop.exe is compiled (C# via PowerShell Add-Type) that\n"
            "       accepts any arguments and always exits 0 with no output.\n"
            "    2. IFEO Debugger is set for cmd.exe → noop.exe.\n"
            "       This intercepts every cmd.exe spawn at the kernel level,\n"
            "       regardless of absolute vs. relative path.\n"
            "\n"
            "  Effect: Eldritch sys.shell() calls 'cmd /c <task>', IFEO\n"
            "  intercepts and runs noop.exe instead → exit 0, empty output.\n"
            "  C2 comms stay LIVE. Operators see task 'success'.\n"
            "\n"
            "  Restore with:  python -m unrealm --restore"
        ),
    }
    return f"\n{_YELLOW}{msgs.get(system, '  Neutralise action will be applied.')}{_RESET}\n"


def _render_ifeo_warning() -> str:
    return (
        f"\n"
        f"  {_RED}{_BOLD}╔══════════════════════════════════════════════════════════╗{_RESET}\n"
        f"  {_RED}{_BOLD}║  ⚠  HIGH-IMPACT WARNING: SYSTEM-WIDE cmd.exe REDIRECT  ║{_RESET}\n"
        f"  {_RED}{_BOLD}╚══════════════════════════════════════════════════════════╝{_RESET}\n"
        f"\n"
        f"  {_RED}The IFEO Debugger redirect affects EVERY cmd.exe invocation\n"
        f"  on this host — not just the realm implant.{_RESET}\n"
        f"\n"
        f"  {_BOLD}Collateral damage includes:{_RESET}\n"
        f"  {_YELLOW}  • Any user or service that runs cmd.exe will get noop.exe\n"
        f"    instead — their commands will silently do nothing.\n"
        f"  • Batch scripts (.bat / .cmd) will stop executing.\n"
        f"  • Windows services that shell out via cmd.exe will break.\n"
        f"  • Administrative tools that use cmd.exe may malfunction.{_RESET}\n"
        f"\n"
        f"  {_BOLD}This prompt is NOT bypassed by --yes.{_RESET}\n"
        f"  {_DIM}Restore with:  python -m unrealm --restore{_RESET}\n"
    )


def _render_remove_info(report: ScanReport) -> str:
    items = [f"    • [{f.category}] {f.title}" for f in report.findings]
    item_str = "\n".join(items)
    return (
        f"\n{_RED}{_BOLD}  ⚠  FULL REMOVAL will act on the following artifacts:{_RESET}\n"
        f"{_DIM}{item_str}{_RESET}\n"
        f"{_RED}  This is irreversible. Running processes will be killed,\n"
        f"  files deleted, and services disabled.{_RESET}\n"
    )


if __name__ == "__main__":
    sys.exit(main())
