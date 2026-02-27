"""
detectors/linux.py – Realm/imix artifact detection for Linux systems.

Checks (in order):
  1.  Running processes named "imix" or "golem"
  2.  Host-ID persistence file  /var/tmp/system-id  (realm beacon UUID)
  3.  imix binary in common install locations  (/bin/*, /usr/bin/*)
  4.  Systemd services whose unit file references "imix", "golem", or the
      realm gRPC port (8000)
  5.  SysVinit scripts  /etc/init.d/*  with the same fingerprints
  6.  Temporary Jinja2 staging files realm uses during installation
  7.  gRPC / HTTP C2 network connections (delegated to net_detector)
  8.  Eldritch shell replacement: /bin/sh → /bin/true  (post-neutralise check)
  9.  Process binaries containing embedded Rust/imix dependency strings
      (rustc, gimli, addr2line, demangle) – indicates imix compiled binary
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
from typing import List

from unrealm.findings import Finding, Severity, ScanReport

# ── Canonical imix install paths ──────────────────────────────────────────────
BINARY_GLOBS: List[str] = [
    "/bin/imix",
    "/usr/bin/imix",
    "/usr/local/bin/imix",
    "/bin/golem",
    "/usr/bin/golem",
    # persist_service copies the binary to /bin/<executable_name>
    # We also do a broader glob for unknown names later.
]

# Realm host-ID file (written by host_unique::File selector)
HOST_ID_FILE = "/var/tmp/system-id"

# Eldritch systemd unit install path
SYSTEMD_UNIT_DIR = "/usr/lib/systemd/system"
SYSVINIT_DIR = "/etc/init.d"

# Jinja2 staging files written (then removed) during install
STAGING_FILES = [
    "/tmp/systemd.service.j2",
    "/tmp/svc.sh.j2",
]

# Strings that indicate a unit / init script is realm-related
REALM_FINGERPRINTS = re.compile(
    r"\bimix\b|\bgolem\b|realm\.pub|c2\.C2|ClaimTasks|ReportOutput|:8000\b",
    re.IGNORECASE,
)

# UUID v4 pattern – what realm writes to the host-ID file
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Rust crate strings embedded in imix binaries by the compiler/debug info
RUST_IMIX_STRINGS: List[bytes] = [b"rustc", b"gimli", b"addr2line", b"demangle"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_text(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _is_elf(path: str) -> bool:
    """Return True if path begins with the ELF magic bytes."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
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


def _process_list() -> List[dict]:
    """
    Return a list of dicts with keys: pid, name, exe, cmdline
    by reading /proc.  No external dependencies needed.
    """
    procs: List[dict] = []
    try:
        for pid_s in os.listdir("/proc"):
            if not pid_s.isdigit():
                continue
            base = f"/proc/{pid_s}"
            name = _read_text(f"{base}/comm").strip()
            cmdline = _read_text(f"{base}/cmdline").replace("\x00", " ").strip()
            try:
                exe = os.readlink(f"{base}/exe")
            except OSError:
                exe = ""
            procs.append({"pid": int(pid_s), "name": name, "exe": exe, "cmdline": cmdline})
    except OSError:
        pass
    return procs


# ── Individual checks ─────────────────────────────────────────────────────────

def check_processes(report: ScanReport) -> None:
    """Detect running imix / golem processes."""
    for proc in _process_list():
        name_lower = proc["name"].lower()
        cmdline_lower = proc["cmdline"].lower()
        if "imix" in name_lower or "golem" in name_lower:
            report.add(Finding(
                category="process",
                severity=Severity.HIGH,
                title=f"Realm implant process running: {proc['name']} (PID {proc['pid']})",
                detail=f"cmdline: {proc['cmdline'][:200]}",
                path=proc["exe"] or f"/proc/{proc['pid']}",
                extra={"pid": proc["pid"], "exe": proc["exe"]},
            ))
        elif ":8000" in cmdline_lower and "grpc" not in name_lower:
            # A process calling back to the C2 default port
            report.add(Finding(
                category="process",
                severity=Severity.MEDIUM,
                title=f"Process communicating on C2 port 8000: {proc['name']} (PID {proc['pid']})",
                detail=f"cmdline: {proc['cmdline'][:200]}",
                path=proc["exe"] or f"/proc/{proc['pid']}",
                extra={"pid": proc["pid"]},
            ))


def check_host_id_file(report: ScanReport) -> None:
    """Detect realm's host-ID persistence file at /var/tmp/system-id."""
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
    """Detect imix / golem ELF binaries in known install locations."""
    # 1. Explicit known paths
    for path in BINARY_GLOBS:
        if os.path.isfile(path) and _is_elf(path):
            report.add(Finding(
                category="file",
                severity=Severity.HIGH,
                title=f"Realm implant binary found: {os.path.basename(path)}",
                detail="ELF binary at realm default install location",
                path=path,
            ))

    # 2. Broader search: any ELF in /bin with "imix" or "golem" anywhere in its
    #    name (catches custom service_config executable_name values)
    for entry in glob.glob("/bin/*") + glob.glob("/usr/bin/*") + glob.glob("/usr/local/bin/*"):
        basename = os.path.basename(entry).lower()
        if ("imix" in basename or "golem" in basename) and os.path.isfile(entry):
            path_already_added = any(
                f.path == entry for f in report.by_category("file")
            )
            if not path_already_added and _is_elf(entry):
                report.add(Finding(
                    category="file",
                    severity=Severity.HIGH,
                    title=f"Realm implant binary found: {os.path.basename(entry)}",
                    detail="ELF binary with realm-related name",
                    path=entry,
                ))


def check_systemd_services(report: ScanReport) -> None:
    """Scan /usr/lib/systemd/system for realm-related unit files."""
    if not os.path.isdir(SYSTEMD_UNIT_DIR):
        return
    for fname in os.listdir(SYSTEMD_UNIT_DIR):
        if not fname.endswith(".service"):
            continue
        full = os.path.join(SYSTEMD_UNIT_DIR, fname)
        content = _read_text(full)
        if REALM_FINGERPRINTS.search(fname) or REALM_FINGERPRINTS.search(content):
            report.add(Finding(
                category="service",
                severity=Severity.HIGH,
                title=f"Realm systemd service unit found: {fname}",
                detail="Unit file contains realm/imix fingerprints",
                path=full,
                extra={"unit": fname},
            ))

    # Also query systemctl for a live service named "imix" or "imixsvc"
    for svc_name in ("imix", "imixsvc", "golem", "golemsvc"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", svc_name],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                report.add(Finding(
                    category="service",
                    severity=Severity.HIGH,
                    title=f"Realm systemd service active: {svc_name}",
                    detail=f"`systemctl is-active {svc_name}` returned active",
                    path=f"{SYSTEMD_UNIT_DIR}/{svc_name}.service",
                    extra={"service_name": svc_name},
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass


def check_sysvinit_scripts(report: ScanReport) -> None:
    """Scan /etc/init.d for realm-related SysVinit scripts."""
    if not os.path.isdir(SYSVINIT_DIR):
        return
    for fname in os.listdir(SYSVINIT_DIR):
        full = os.path.join(SYSVINIT_DIR, fname)
        if not os.path.isfile(full):
            continue
        content = _read_text(full)
        if REALM_FINGERPRINTS.search(fname) or REALM_FINGERPRINTS.search(content):
            report.add(Finding(
                category="service",
                severity=Severity.HIGH,
                title=f"Realm SysVinit script found: {fname}",
                detail="Init script contains realm/imix fingerprints",
                path=full,
                extra={"script": fname},
            ))


def check_staging_files(report: ScanReport) -> None:
    """Check for temporary Jinja2 staging files left by realm's install scripts."""
    for path in STAGING_FILES:
        if os.path.isfile(path):
            report.add(Finding(
                category="file",
                severity=Severity.MEDIUM,
                title=f"Realm install staging file found: {os.path.basename(path)}",
                detail="Jinja2 template used during realm persist_service install",
                path=path,
            ))


def check_neutralised(report: ScanReport) -> None:
    """
    Detect whether /bin/sh has already been replaced with /bin/true
    (the Linux neutralise action).  This is an informational finding only.
    """
    sh_path = "/bin/sh"
    true_path = "/bin/true"
    if not os.path.isfile(sh_path):
        return
    try:
        sh_real = os.path.realpath(sh_path)
        true_real = os.path.realpath(true_path) if os.path.isfile(true_path) else ""
        if sh_real == true_real:
            report.add(Finding(
                category="file",
                severity=Severity.INFO,
                title="/bin/sh is already linked to /bin/true (neutralised state)",
                detail="The shell neutralisation action has previously been applied",
                path=sh_path,
            ))
        # Also catch if /bin/sh is a copy of /bin/true (same inode or content)
        elif (
            os.path.isfile(true_path)
            and os.path.getsize(sh_path) == os.path.getsize(true_path)
        ):
            sh_stat = os.stat(sh_path)
            true_stat = os.stat(true_path)
            if sh_stat.st_ino == true_stat.st_ino:
                report.add(Finding(
                    category="file",
                    severity=Severity.INFO,
                    title="/bin/sh shares inode with /bin/true (neutralised state)",
                    detail="Hardlink neutralisation has previously been applied",
                    path=sh_path,
                ))
    except OSError:
        pass


def check_rust_imix_strings(report: ScanReport) -> None:
    """
    Detect process binaries that contain all four Rust/imix dependency strings:
    'rustc', 'gimli', 'addr2line', 'demangle'.  The simultaneous presence of
    all four is a strong indicator of an imix compiled binary regardless of
    the process name.
    """
    seen_exes: set = set()
    for proc in _process_list():
        exe = proc["exe"]
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


# ── Public entry point ────────────────────────────────────────────────────────

def scan(report: ScanReport) -> None:
    """Run all Linux-specific realm detection checks."""
    check_processes(report)
    check_rust_imix_strings(report)
    check_host_id_file(report)
    check_binaries(report)
    check_systemd_services(report)
    check_sysvinit_scripts(report)
    check_staging_files(report)
    check_neutralised(report)
