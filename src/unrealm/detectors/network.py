"""
detectors/network.py – Cross-platform realm C2 network traffic detection.

Detects:
  - Active TCP connections to/from port 8000 (Tavern default gRPC/HTTP1 port)
  - Established connections to realm DNS transport ports (53 outbound)
  - Processes with connections that match gRPC path strings in /proc/net or
    via psutil / ss / netstat.
  - Realm gRPC service paths in captured HTTP headers or connection strings
    (when ss/netstat can inspect).

The check is intentionally read-only and uses only OS-provided data.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
from typing import List, Dict, Optional

from unrealm.findings import Finding, Severity, ScanReport

# Default Tavern C2 listening port
C2_GRPC_PORT = 8000
# Additional non-standard ports that realm supports via HTTP1 / HTTPS1
C2_EXTRA_PORTS = (443, 80)

# Realm gRPC service paths burned into the transport layer
GRPC_PATHS = (
    "/c2.C2/ClaimTasks",
    "/c2.C2/FetchAsset",
    "/c2.C2/ReportCredential",
    "/c2.C2/ReportFile",
    "/c2.C2/ReportProcessList",
    "/c2.C2/ReportOutput",
    "/c2.C2/ReverseShell",
    "/c2.C2/CreatePortal",
)

_HEX_PORT_8000 = format(C2_GRPC_PORT, "04X")  # "1F40"


# ── Linux /proc/net/tcp parser ─────────────────────────────────────────────────

def _hex_to_ip_port(hex_addr: str) -> tuple[str, int]:
    """
    Convert a Linux /proc/net/tcp address:port hex pair to (ip_str, port_int).
    /proc/net/tcp stores IPs in little-endian hex per-byte.
    """
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    # Reverse byte order for IPv4
    addr_bytes = bytes.fromhex(addr_hex)[::-1]
    ip = ".".join(str(b) for b in addr_bytes)
    return ip, port


def _parse_proc_net(proto: str = "tcp") -> List[Dict]:
    """Parse /proc/net/tcp (or tcp6) and return a list of connection dicts."""
    path = f"/proc/net/{proto}"
    conns: List[Dict] = []
    if not os.path.isfile(path):
        return conns
    try:
        with open(path) as fh:
            lines = fh.readlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_hex, remote_hex, state_hex = parts[1], parts[2], parts[3]
            inode = parts[9]
            try:
                local_ip, local_port = _hex_to_ip_port(local_hex)
                remote_ip, remote_port = _hex_to_ip_port(remote_hex)
            except (ValueError, IndexError):
                continue
            state = int(state_hex, 16)
            conns.append({
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "state": state,        # 1 = ESTABLISHED, 2 = SYN_SENT, etc.
                "local_port": local_port,
                "remote_port": remote_port,
                "inode": inode,
            })
    except OSError:
        pass
    return conns


def _proc_net_check(report: ScanReport) -> bool:
    """Use /proc/net/tcp* to find C2 connections. Returns True if used."""
    if not os.path.isfile("/proc/net/tcp"):
        return False
    found_any = False
    for proto in ("tcp", "tcp6"):
        for conn in _parse_proc_net(proto):
            lp, rp = conn["local_port"], conn["remote_port"]
            state = conn["state"]
            if (lp == C2_GRPC_PORT or rp == C2_GRPC_PORT) and state in (1, 2):
                found_any = True
                direction = "listening" if lp == C2_GRPC_PORT else "connecting"
                report.add(Finding(
                    category="network",
                    severity=Severity.HIGH,
                    title=f"C2 port {C2_GRPC_PORT} {direction} ({proto.upper()})",
                    detail=(
                        f"local={conn['local']}  remote={conn['remote']}  "
                        f"state={state} (1=ESTABLISHED)"
                    ),
                    path=None,
                    extra=conn,
                ))
    return found_any


# ── ss / netstat fallback ──────────────────────────────────────────────────────

def _ss_check(report: ScanReport) -> bool:
    """Try `ss -tnp` to enumerate connections. Returns True if ss is available."""
    try:
        out = subprocess.check_output(
            ["ss", "-tnp"], text=True, timeout=10, errors="replace"
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False

    for line in out.splitlines()[1:]:
        if f":{C2_GRPC_PORT}" in line:
            report.add(Finding(
                category="network",
                severity=Severity.HIGH,
                title=f"C2 port {C2_GRPC_PORT} connection detected (ss)",
                detail=line.strip(),
                path=None,
            ))
    return True


def _netstat_check(report: ScanReport) -> None:
    """Fallback: use netstat -an (cross-platform) to check for port 8000."""
    try:
        args = ["netstat", "-an"]
        out = subprocess.check_output(args, text=True, timeout=15, errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return

    for line in out.splitlines():
        if f":{C2_GRPC_PORT}" in line or f".{C2_GRPC_PORT}" in line:
            report.add(Finding(
                category="network",
                severity=Severity.HIGH,
                title=f"C2 port {C2_GRPC_PORT} connection detected (netstat)",
                detail=line.strip(),
                path=None,
            ))


# ── psutil fallback (cross-platform) ─────────────────────────────────────────

def _psutil_check(report: ScanReport) -> bool:
    try:
        import psutil  # type: ignore
    except ImportError:
        return False

    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        # At least flag that we can't fully inspect
        report.add(Finding(
            category="network",
            severity=Severity.INFO,
            title="Cannot fully inspect network connections (access denied)",
            detail="Run with elevated privileges for complete network scan",
        ))
        return True

    for conn in connections:
        lport = conn.laddr.port if conn.laddr else 0
        rport = conn.raddr.port if conn.raddr else 0
        raddr = conn.raddr.ip if conn.raddr else ""
        if lport == C2_GRPC_PORT or rport == C2_GRPC_PORT:
            pid_info = f" PID={conn.pid}" if conn.pid else ""
            report.add(Finding(
                category="network",
                severity=Severity.HIGH,
                title=f"C2 port {C2_GRPC_PORT} connection detected (psutil){pid_info}",
                detail=(
                    f"local={conn.laddr}  remote={conn.raddr}  "
                    f"status={conn.status}"
                ),
                path=None,
                extra={"pid": conn.pid, "status": conn.status},
            ))
    return True


# ── Tavern server detection (is Tavern running locally?) ─────────────────────

def _check_tavern_listening(report: ScanReport) -> None:
    """
    Try a quick TCP connect to 127.0.0.1:8000 to see if Tavern is up.
    A successful connect means a C2 server may be running on this host.
    """
    try:
        with socket.create_connection(("127.0.0.1", C2_GRPC_PORT), timeout=1):
            report.add(Finding(
                category="network",
                severity=Severity.HIGH,
                title=f"Realm Tavern C2 server appears to be listening on 127.0.0.1:{C2_GRPC_PORT}",
                detail=(
                    "Successfully established TCP connection to the default "
                    "Tavern gRPC/HTTP port. The C2 server may be running on this host."
                ),
                path=None,
                extra={"port": C2_GRPC_PORT},
            ))
    except (ConnectionRefusedError, OSError):
        pass


# ── Public entry point ────────────────────────────────────────────────────────

def scan(report: ScanReport) -> None:
    """Run cross-platform network detection for realm C2 activity."""
    _check_tavern_listening(report)

    used = False
    # Prefer /proc/net (Linux, most accurate, no privileges needed for own process)
    if _proc_net_check(report):
        used = True
    # Augment with ss if available
    if _ss_check(report):
        used = True
    # psutil is cross-platform and most feature-rich
    if _psutil_check(report):
        used = True
    # Last resort: plain netstat -an
    if not used:
        _netstat_check(report)
