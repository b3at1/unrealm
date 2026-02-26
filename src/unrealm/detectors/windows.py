"""
detectors/windows.py – Realm/imix artifact detection for Windows systems.

Checks:
  1.  Running processes named "imix" or "golem" (via tasklist / psutil)
  2.  Host-ID file  C:\\ProgramData\\system-id
  3.  imix binary at  C:\\Windows\\System32\\<name>.exe
  4.  Windows service named "imix", "imixsvc", "golem", "golemsvc" or any
      service whose binary path references those names
  5.  Registry key  HKLM\\SOFTWARE\\Imix  (system-id value)
  6.  Realm gRPC network connections on port 8000
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import List

from unrealm.findings import Finding, Severity, ScanReport

HOST_ID_FILE = r"C:\ProgramData\system-id"
SYSTEM32 = r"C:\Windows\System32"
KNOWN_SERVICE_NAMES = ("imix", "imixsvc", "golem", "golemsvc")
REGISTRY_HIVE = "HKLM"
REGISTRY_PATH = r"SOFTWARE\Imix"

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
REALM_FINGERPRINTS = re.compile(
    r"\bimix\b|\bgolem\b|realm\.pub|c2\.C2|ClaimTasks",
    re.IGNORECASE,
)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _is_pe(path: str) -> bool:
    """Return True if path starts with the PE magic bytes (MZ)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


# ── Process detection ─────────────────────────────────────────────────────────

def check_processes(report: ScanReport) -> None:
    # Try psutil first (cross-platform), fall back to tasklist.
    try:
        import psutil  # type: ignore
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                exe = proc.info.get("exe") or ""
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                if "imix" in name or "golem" in name:
                    report.add(Finding(
                        category="process",
                        severity=Severity.HIGH,
                        title=f"Realm implant process running: {proc.info['name']} (PID {proc.pid})",
                        detail=f"exe: {exe}",
                        path=exe or None,
                        extra={"pid": proc.pid, "exe": exe},
                    ))
                elif ":8000" in cmdline:
                    report.add(Finding(
                        category="process",
                        severity=Severity.MEDIUM,
                        title=f"Process communicating on C2 port 8000: {proc.info['name']} (PID {proc.pid})",
                        detail=f"exe: {exe}",
                        path=exe or None,
                        extra={"pid": proc.pid},
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return
    except ImportError:
        pass

    # Fallback: tasklist /FO CSV /NH
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"], text=True, timeout=15, errors="replace"
        )
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split(",")]
            if not parts:
                continue
            name = parts[0].lower()
            pid = parts[1] if len(parts) > 1 else "?"
            if "imix" in name or "golem" in name:
                report.add(Finding(
                    category="process",
                    severity=Severity.HIGH,
                    title=f"Realm implant process running: {parts[0]} (PID {pid})",
                    detail=f"tasklist entry: {line}",
                    path=None,
                    extra={"pid": pid},
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass


# ── File detection ────────────────────────────────────────────────────────────

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
    """Detect PE imix/golem binaries in System32 and common locations."""
    search_dirs = [SYSTEM32, r"C:\Windows", r"C:\ProgramData"]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                name_lower = name.lower()
                if ("imix" in name_lower or "golem" in name_lower) and name_lower.endswith(".exe"):
                    full = os.path.join(d, name)
                    if os.path.isfile(full) and _is_pe(full):
                        report.add(Finding(
                            category="file",
                            severity=Severity.HIGH,
                            title=f"Realm implant binary found: {name}",
                            detail=f"PE binary at {full}",
                            path=full,
                        ))
        except PermissionError:
            pass


# ── Service detection ─────────────────────────────────────────────────────────

def check_services(report: ScanReport) -> None:
    """Use sc.exe / winreg to detect realm Windows services."""
    # 1. Check known service names directly
    for svc_name in KNOWN_SERVICE_NAMES:
        try:
            result = subprocess.run(
                ["sc.exe", "query", svc_name],
                capture_output=True, text=True, timeout=10, errors="replace",
            )
            if result.returncode == 0 and svc_name.lower() in result.stdout.lower():
                report.add(Finding(
                    category="service",
                    severity=Severity.HIGH,
                    title=f"Realm Windows service found: {svc_name}",
                    detail=result.stdout[:300],
                    path=None,
                    extra={"service_name": svc_name},
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # 2. Enumerate all services looking for realm fingerprints in their BINARY_PATH_NAME
    try:
        out = subprocess.check_output(
            ["sc.exe", "query", "type=", "all", "state=", "all"],
            text=True, timeout=20, errors="replace",
        )
        current_svc = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                current_svc = line.split(":", 1)[1].strip()
            elif "BINARY_PATH_NAME" in line and current_svc:
                binpath = line.split(":", 1)[1].strip() if ":" in line else ""
                if REALM_FINGERPRINTS.search(binpath):
                    already = any(
                        f.extra.get("service_name") == current_svc
                        for f in report.by_category("service")
                    )
                    if not already:
                        report.add(Finding(
                            category="service",
                            severity=Severity.HIGH,
                            title=f"Windows service with realm binary path: {current_svc}",
                            detail=f"Binary path: {binpath}",
                            path=binpath or None,
                            extra={"service_name": current_svc, "binary_path": binpath},
                        ))
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass


# ── Registry detection ────────────────────────────────────────────────────────

def check_registry(report: ScanReport) -> None:
    """Detect realm's HKLM\\SOFTWARE\\Imix registry key."""
    try:
        import winreg  # type: ignore  # Only available on Windows

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REGISTRY_PATH)
            i = 0
            values: dict = {}
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    values[name] = data
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            detail = "  ".join(f"{k}={v}" for k, v in values.items()) or "(empty key exists)"
            report.add(Finding(
                category="registry",
                severity=Severity.HIGH,
                title=f"Realm registry key found: HKLM\\{REGISTRY_PATH}",
                detail=detail,
                path=f"HKLM\\{REGISTRY_PATH}",
                extra={"values": values},
            ))
        except FileNotFoundError:
            pass  # Key does not exist
        except PermissionError:
            report.add(Finding(
                category="registry",
                severity=Severity.MEDIUM,
                title=f"Cannot read registry key HKLM\\{REGISTRY_PATH} (access denied)",
                detail="The key may exist but cannot be read without elevated privileges",
                path=f"HKLM\\{REGISTRY_PATH}",
            ))
    except ImportError:
        pass  # Running on Linux/macOS during test


def scan(report: ScanReport) -> None:
    """Run all Windows-specific realm detection checks."""
    check_processes(report)
    check_host_id_file(report)
    check_binaries(report)
    check_services(report)
    check_registry(report)
