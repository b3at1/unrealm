"""
detectors/macos.py – Realm/imix artifact detection for macOS systems.

Checks:
  1.  Running processes named "imix" or "golem" (via ps)
  2.  Host-ID file  /Users/Shared/system-id
  3.  imix/golem Mach-O binary at  /var/root/<name>  (realm install path)
  4.  LaunchDaemon plist in  /Library/LaunchDaemons/  with realm label or
      binary path fingerprints (label pattern: com.testing.*)
  5.  Loaded launchctl services with realm fingerprints
  6.  Temporary Jinja2 staging files  /tmp/plist.j2
  7.  Process binaries containing embedded Rust/imix dependency strings
      (rustc, gimli, addr2line, demangle) – indicates imix compiled binary
"""
from __future__ import annotations

import glob
import os
import plistlib
import re
import subprocess
from typing import List

from unrealm.findings import Finding, Severity, ScanReport

HOST_ID_FILE = "/Users/Shared/system-id"
LAUNCH_DAEMON_DIR = "/Library/LaunchDaemons"
LAUNCH_AGENT_DIRS = [
    "/Library/LaunchAgents",
    os.path.expanduser("~/Library/LaunchAgents"),
]
STAGING_FILES = ["/tmp/plist.j2"]

REALM_FINGERPRINTS = re.compile(
    r"\bimix\b|\bgolem\b|realm\.pub|c2\.C2|ClaimTasks|com\.testing\.",
    re.IGNORECASE,
)

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Rust crate strings embedded in imix binaries by the compiler/debug info
RUST_IMIX_STRINGS: List[bytes] = [b"rustc", b"gimli", b"addr2line", b"demangle"]


def _read_text(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _is_macho(path: str) -> bool:
    """Return True if path starts with a Mach-O magic number."""
    MACHO_MAGIC = {
        b"\xfe\xed\xfa\xce",  # 32-bit big-endian
        b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
        b"\xce\xfa\xed\xfe",  # 32-bit little-endian
        b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
        b"\xca\xfe\xba\xbe",  # Fat binary
    }
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in MACHO_MAGIC
    except OSError:
        return False


def _binary_contains_rust_strings(path: str) -> bool:
    """Return True if the binary at *path* contains all four Rust/imix strings."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return all(s in data for s in RUST_IMIX_STRINGS)
    except OSError:
        return False


def _ps_processes() -> List[dict]:
    try:
        out = subprocess.check_output(
            ["ps", "-axo", "pid,comm,args"], text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []
    procs = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        # argv[0] in the args column is typically the full path to the binary
        args_field = parts[2] if len(parts) > 2 else ""
        exe = args_field.split()[0] if args_field.split() else parts[1]
        procs.append({
            "pid": parts[0],
            "name": os.path.basename(parts[1]),
            "exe": exe,
            "cmdline": args_field,
        })
    return procs


def check_processes(report: ScanReport) -> None:
    for proc in _ps_processes():
        name_lower = proc["name"].lower()
        if "imix" in name_lower or "golem" in name_lower:
            report.add(Finding(
                category="process",
                severity=Severity.HIGH,
                title=f"Realm implant process running: {proc['name']} (PID {proc['pid']})",
                detail=f"cmdline: {proc['cmdline'][:200]}",
                path=proc.get("exe") or None,
                extra={"pid": proc["pid"]},
            ))


def check_rust_imix_strings(report: ScanReport) -> None:
    """
    Detect process binaries that contain all four Rust/imix dependency strings:
    'rustc', 'gimli', 'addr2line', 'demangle'.  The simultaneous presence of
    all four is a strong indicator of an imix compiled binary regardless of
    the process name.
    """
    seen_exes: set = set()
    for proc in _ps_processes():
        exe = proc.get("exe", "")
        if not exe or exe in seen_exes:
            continue
        seen_exes.add(exe)
        if _binary_contains_rust_strings(exe):
            report.add(Finding(
                category="process",
                severity=Severity.HIGH,
                title=f"Process binary contains Rust/imix dependency strings: {proc['name']} (PID {proc['pid']})",
                detail=(
                    f"Binary '{exe}' contains all of: "
                    + ", ".join(s.decode() for s in RUST_IMIX_STRINGS)
                ),
                path=exe,
                extra={"pid": proc["pid"], "exe": exe, "strings_matched": [s.decode() for s in RUST_IMIX_STRINGS]},
            ))


def check_host_id_file(report: ScanReport) -> None:
    if os.path.isfile(HOST_ID_FILE):
        content = _read_text(HOST_ID_FILE).strip()
        uuid_match = UUID_RE.match(content)
        report.add(Finding(
            category="file",
            severity=Severity.HIGH,
            title="Realm host-ID file found",
            detail=(
                f"UUID: {content}" if uuid_match
                else f"Content (truncated): {content[:80]}"
            ),
            path=HOST_ID_FILE,
            extra={"uuid": content if uuid_match else None},
        ))


def check_binaries(report: ScanReport) -> None:
    """Detect Mach-O imix/golem binaries at /var/root/* or common locations."""
    search_dirs = ["/var/root", "/usr/local/bin", "/usr/bin", "/bin"]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except PermissionError:
            continue
        for name in names:
            if "imix" in name.lower() or "golem" in name.lower():
                full = os.path.join(d, name)
                if os.path.isfile(full) and _is_macho(full):
                    report.add(Finding(
                        category="file",
                        severity=Severity.HIGH,
                        title=f"Realm implant binary found: {name}",
                        detail="Mach-O binary at realm install location",
                        path=full,
                    ))


def _scan_plist_dir(directory: str, report: ScanReport) -> None:
    if not os.path.isdir(directory):
        return
    for fname in os.listdir(directory):
        if not fname.endswith(".plist"):
            continue
        full = os.path.join(directory, fname)
        # Quick text fingerprint check first
        content = _read_text(full)
        if not REALM_FINGERPRINTS.search(fname) and not REALM_FINGERPRINTS.search(content):
            continue

        # Parse the plist for richer detail
        label = fname
        prog = ""
        try:
            with open(full, "rb") as fh:
                pl = plistlib.load(fh)
            label = pl.get("Label", fname)
            prog = pl.get("Program", "") or (
                pl.get("ProgramArguments", [""])[0] if pl.get("ProgramArguments") else ""
            )
        except Exception:
            pass

        report.add(Finding(
            category="service",
            severity=Severity.HIGH,
            title=f"Realm LaunchDaemon/Agent plist found: {fname}",
            detail=f"Label: {label}  Program: {prog}",
            path=full,
            extra={"label": label, "program": prog},
        ))


def check_launch_items(report: ScanReport) -> None:
    _scan_plist_dir(LAUNCH_DAEMON_DIR, report)
    for d in LAUNCH_AGENT_DIRS:
        _scan_plist_dir(d, report)

    # Also query launchctl for loaded services with realm patterns
    try:
        out = subprocess.check_output(
            ["launchctl", "list"], text=True, timeout=10
        )
        for line in out.splitlines():
            if REALM_FINGERPRINTS.search(line):
                parts = line.split()
                label = parts[-1] if parts else line
                report.add(Finding(
                    category="service",
                    severity=Severity.HIGH,
                    title=f"Realm launchctl service loaded: {label}",
                    detail=f"launchctl list entry: {line}",
                    path=None,
                    extra={"launchctl_entry": line},
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass


def check_staging_files(report: ScanReport) -> None:
    for path in STAGING_FILES:
        if os.path.isfile(path):
            report.add(Finding(
                category="file",
                severity=Severity.MEDIUM,
                title=f"Realm install staging file found: {os.path.basename(path)}",
                detail="Jinja2 template used during realm persist_service install",
                path=path,
            ))


def scan(report: ScanReport) -> None:
    """Run all macOS-specific realm detection checks."""
    check_processes(report)
    check_rust_imix_strings(report)
    check_host_id_file(report)
    check_binaries(report)
    check_launch_items(report)
    check_staging_files(report)
