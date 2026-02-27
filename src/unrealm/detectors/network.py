"""
detectors/network.py – Cross-platform Realm C2 network detection.

Two-phase scan
──────────────
Phase 1 – Instant snapshot
  • Tavern server on 127.0.0.1:8000 (TCP connect + gRPC probe)
  • /proc/net/tcp* direct parse          (Linux)
  • ss -tnp / netstat -an fallback
  • psutil.net_connections               (cross-platform)

Phase 2 – OBSERVE_DURATION-second observation window (~60 s)
  • Beaconing detection: endpoints that reconnect at statistically
    regular intervals are flagged regardless of port.  Operators
    routinely move Realm off the default 8000.
  • Persistence detection: endpoints present in ≥80 % of snapshots
    indicate a possible long-lived gRPC streaming session.
  • gRPC fingerprinting: all unique remote endpoints observed during
    the window are probed with an HTTP/2 client-preface (RFC 7540 §3.5).
    A valid SETTINGS frame back confirms HTTP/2 / gRPC transport.
  • Live traffic capture (Scapy): TCP packets are decoded on the fly.
    HTTP/2 HEADERS and DATA frames are scanned for Realm gRPC service
    paths.  Any match emits an immediate HIGH finding without waiting
    for the observation window to close.
"""
from __future__ import annotations

import os
import socket
import statistics
import subprocess
import threading
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from unrealm.findings import Finding, Severity, ScanReport

# ── Tunables ──────────────────────────────────────────────────────────────────
C2_GRPC_PORT       = 8000   # Realm Tavern default; still checked explicitly
POLL_INTERVAL      = 2      # seconds between connection snapshots
OBSERVE_DURATION   = 60     # total observation window in seconds
MIN_BEACON_HITS    = 3      # minimum re-appearances to test for regularity
BEACON_CV_THRESH   = 0.30   # coefficient-of-variation ≤ this → regular beacon
MIN_BEACON_IV      = 3.0    # ignore sub-3 s gaps (TCP retransmit noise)
GRPC_PROBE_TIMEOUT = 2.0    # seconds for HTTP/2 handshake response

# HTTP/2 connection preface (RFC 7540 §3.5)
_H2_PREFACE  = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Empty SETTINGS frame: length=0, type=0x04, flags=0x00, stream-id=0
_H2_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
# Tonic Rust gRPC client user-agent prefix
_TONIC_MARKER = b"tonic"

# Realm gRPC service paths
GRPC_PATHS = (
    "/c2.C2/ClaimTasks",       "/c2.C2/FetchAsset",
    "/c2.C2/ReportCredential", "/c2.C2/ReportFile",
    "/c2.C2/ReportProcessList", "/c2.C2/ReportOutput",
    "/c2.C2/ReverseShell",     "/c2.C2/CreatePortal",
)

# Ports almost certainly unrelated to Realm – skip the gRPC probe for these
_SKIP_GRPC_PORTS = frozenset({
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 27017,
})


# ── /proc/net parser (Linux) ──────────────────────────────────────────────────

def _hex_to_ip_port(hex_addr: str) -> Tuple[str, int]:
    """Convert a Linux /proc/net/tcp hex address:port to (ip_str, port_int)."""
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    addr_bytes = bytes.fromhex(addr_hex)[::-1]
    ip = ".".join(str(b) for b in addr_bytes)
    return ip, port


def _parse_proc_net(proto: str = "tcp") -> List[Dict]:
    """Parse /proc/net/{proto} and return a list of connection dicts."""
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
                local_ip,  local_port  = _hex_to_ip_port(local_hex)
                remote_ip, remote_port = _hex_to_ip_port(remote_hex)
            except (ValueError, IndexError):
                continue
            conns.append({
                "local":       f"{local_ip}:{local_port}",
                "remote":      f"{remote_ip}:{remote_port}",
                "state":       int(state_hex, 16),  # 1=ESTABLISHED, 2=SYN_SENT
                "local_port":  local_port,
                "remote_port": remote_port,
                "inode":       inode,
            })
    except OSError:
        pass
    return conns


# ── Connection snapshot ───────────────────────────────────────────────────────

def _collect_remote_endpoints() -> Set[Tuple[str, int]]:
    """
    Best-effort snapshot of all active outbound TCP (remote_ip, remote_port).
    Tries psutil first, falls back to /proc/net/tcp.
    """
    endpoints: Set[Tuple[str, int]] = set()
    try:
        import psutil  # type: ignore
        for conn in psutil.net_connections(kind="tcp"):
            if conn.raddr and conn.status not in ("LISTEN", "CLOSE_WAIT", "TIME_WAIT"):
                rip = conn.raddr.ip
                if rip and rip not in ("0.0.0.0", "::"):
                    endpoints.add((rip, conn.raddr.port))
        return endpoints
    except Exception:
        pass
    # /proc/net fallback (Linux)
    for proto in ("tcp", "tcp6"):
        for conn in _parse_proc_net(proto):
            if conn["state"] in (1, 2):  # ESTABLISHED or SYN_SENT
                rport = conn["remote_port"]
                rip   = conn["remote"].rsplit(":", 1)[0]
                if rip and rip not in ("0.0.0.0", "::") and rport:
                    endpoints.add((rip, rport))
    return endpoints


# ── gRPC / HTTP-2 probe ───────────────────────────────────────────────────────

def _probe_grpc(host: str, port: int) -> bool:
    """
    Send an HTTP/2 client preface to host:port and return True if the endpoint
    replies with an HTTP/2 SETTINGS frame (frame type byte 0x04).
    A positive response confirms HTTP/2 transport, which gRPC requires.
    """
    try:
        with socket.create_connection((host, port), timeout=GRPC_PROBE_TIMEOUT) as s:
            s.settimeout(GRPC_PROBE_TIMEOUT)
            s.sendall(_H2_PREFACE + _H2_SETTINGS)
            data = b""
            deadline = time.monotonic() + GRPC_PROBE_TIMEOUT
            while len(data) < 9 and time.monotonic() < deadline:
                chunk = s.recv(9 - len(data))
                if not chunk:
                    break
                data += chunk
            # HTTP/2 frame header: bytes[0:3]=length, byte[3]=type, …
            # type 0x04 = SETTINGS
            return len(data) >= 4 and data[3] == 0x04
    except OSError:
        return False


def _scan_h2_frames(data: bytes) -> Tuple[List[str], bool]:
    """
    Walk HTTP/2 frames in *data* and return ``(realm_paths, tonic_ua)`` where
    *realm_paths* is the list of Realm C2 service paths found in HEADERS
    (type 0x01) or DATA (type 0x00) frame payloads, and *tonic_ua* is True if
    any HEADERS frame payload contains the ``tonic`` user-agent marker.

    In cleartext gRPC (h2c), the ``:path`` pseudo-header is HPACK
    literal-encoded, so the path string appears verbatim as ASCII bytes
    inside the HEADERS frame payload.  DATA frame payloads may also carry
    path strings embedded in protobuf metadata or gRPC-Web trailers.
    """
    found: List[str] = []
    tonic_ua = False
    # Skip past the 24-byte HTTP/2 client preface if present in this buffer
    offset = 0
    preface_idx = data.find(b"PRI * HTTP/2.0")
    if preface_idx != -1:
        offset = preface_idx + 24

    while offset + 9 <= len(data):
        f_len  = int.from_bytes(data[offset:offset + 3], "big")
        f_type = data[offset + 3]
        offset += 9
        # Guard against corrupt / truncated frames
        if f_len > 16_777_215 or offset + f_len > len(data):
            break
        if f_type in (0x00, 0x01):  # DATA or HEADERS
            payload = data[offset:offset + f_len]
            for path in GRPC_PATHS:
                if path.encode() in payload and path not in found:
                    found.append(path)
            if f_type == 0x01 and _TONIC_MARKER in payload:  # HEADERS frames only
                tonic_ua = True
        offset += f_len

    return found, tonic_ua


def _sniff_realm_grpc(report: ScanReport, duration: float) -> None:
    """
    Passively capture all TCP traffic for *duration* seconds using Scapy and
    flag any flow whose HTTP/2 or gRPC content contains a known Realm C2
    service path (GRPC_PATHS).  Findings are emitted immediately when a
    match is detected, without waiting for the observation window to close.

    Per-flow TCP payloads are accumulated in memory.  Two complementary
    detection signals are applied on every incoming packet:

      (a) Raw byte scan – search the entire accumulated flow buffer for each
          Realm path as a raw byte string.  Cleartext gRPC (h2c) encodes
          ``:path`` as a literal ASCII string in HPACK, so the method name
          always appears verbatim inside the HEADERS frame payload.

      (b) Structured H2 frame scan via ``_scan_h2_frames`` – walks HTTP/2
          frame boundaries and inspects HEADERS (0x01) and DATA (0x00)
          frame payloads.  Catches paths embedded in protobuf metadata
          fields or gRPC-Web trailers that span a frame-header boundary.

      (c) Tonic user-agent detection – HEADERS frames are scanned for the
          ``tonic`` Rust gRPC client user-agent string.  HTTP/2 POST
          requests from Realm implants (built with the tonic crate) carry
          a ``user-agent: tonic/<version>`` header; any match flags the
          destination endpoint even when the ``:path`` is not yet known.

    Requires ``scapy``.  Emits Severity.INFO when the library is absent or
    when raw socket access is denied (root / CAP_NET_RAW required).
    """
    try:
        from scapy.all import AsyncSniffer, IP, IPv6, TCP  # type: ignore
    except ImportError:
        report.add(Finding(
            category="network",
            severity=Severity.INFO,
            title="Scapy not available – live gRPC traffic capture skipped",
            detail=(
                "Install scapy (pip install scapy) to enable passive in-flight "
                "gRPC service-path detection during the observation window."
            ),
        ))
        return

    # (src_ip, src_port, dst_ip, dst_port) → accumulated TCP payload bytes
    flow_bufs: Dict[Tuple[str, int, str, int], bytes] = defaultdict(bytes)
    # Per-signal flags – suppress duplicate findings of the same type per flow
    flagged_paths: Set[Tuple[str, int, str, int]] = set()
    flagged_tonic: Set[Tuple[str, int, str, int]] = set()

    def _check_and_flag(flow_key: Tuple[str, int, str, int]) -> None:
        """Run all detection signals on the current buffer; emit findings if matched."""
        if flow_key in flagged_paths and flow_key in flagged_tonic:
            return
        buf = flow_bufs[flow_key]
        src_ip, src_port, dst_ip, dst_port = flow_key

        # Shared structured H2 scan – one pass yields both paths and tonic UA flag
        h2_paths, h2_tonic = _scan_h2_frames(buf)

        # ── (a)+(b) Realm gRPC path detection ─────────────────────────────
        if flow_key not in flagged_paths:
            found = [p for p in GRPC_PATHS if p.encode() in buf]
            for p in h2_paths:
                if p not in found:
                    found.append(p)
            if found:
                flagged_paths.add(flow_key)
                report.add(Finding(
                    category="network",
                    severity=Severity.HIGH,
                    title=(
                        f"Realm gRPC service paths in live traffic: "
                        f"{dst_ip}:{dst_port}"
                    ),
                    detail=(
                        f"Live packet capture detected Realm C2 gRPC service paths in "
                        f"traffic from {src_ip}:{src_port} \u2192 {dst_ip}:{dst_port}: "
                        f"{', '.join(found)}. "
                        f"The captured HTTP/2 stream contains Realm C2 method names, "
                        f"confirming active C2 communication."
                    ),
                    path=None,
                    extra={
                        "src":         f"{src_ip}:{src_port}",
                        "dst":         f"{dst_ip}:{dst_port}",
                        "realm_paths": found,
                    },
                ))

        # ── (c) Tonic user-agent detection ────────────────────────────────
        if flow_key not in flagged_tonic:
            if h2_tonic or _TONIC_MARKER in buf:
                flagged_tonic.add(flow_key)
                sev = Severity.HIGH if dst_port == C2_GRPC_PORT else Severity.MEDIUM
                report.add(Finding(
                    category="network",
                    severity=sev,
                    title=(
                        f"Tonic gRPC client user-agent detected: "
                        f"{dst_ip}:{dst_port}"
                    ),
                    detail=(
                        f"Live packet capture found the 'tonic' Rust gRPC client "
                        f"user-agent in HTTP/2 traffic from "
                        f"{src_ip}:{src_port} \u2192 {dst_ip}:{dst_port}. "
                        f"Realm implants built with the tonic crate send a "
                        f"'user-agent: tonic/<version>' header on every POST request."
                    ),
                    path=None,
                    extra={
                        "src": f"{src_ip}:{src_port}",
                        "dst": f"{dst_ip}:{dst_port}",
                    },
                ))

    def _pkt_cb(pkt) -> None:  # type: ignore[no-untyped-def]
        try:
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[TCP].payload)
            if not payload:
                return
            if pkt.haslayer(IP):
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            else:
                return
            flow_key: Tuple[str, int, str, int] = (
                src_ip, int(pkt[TCP].sport), dst_ip, int(pkt[TCP].dport)
            )
            flow_bufs[flow_key] += payload
            _check_and_flag(flow_key)
        except Exception:
            pass

    try:
        sniffer = AsyncSniffer(filter="tcp", prn=_pkt_cb, store=False)
        sniffer.start()
        time.sleep(duration)
        sniffer.stop()
    except Exception as exc:
        report.add(Finding(
            category="network",
            severity=Severity.INFO,
            title="Live gRPC traffic capture failed",
            detail=(
                f"Scapy AsyncSniffer error: {exc}. "
                f"Raw socket access requires elevated privileges "
                f"(root or CAP_NET_RAW)."
            ),
        ))


# ── Observation window (beacon + persistence + gRPC) ─────────────────────────

def _observation_scan(report: ScanReport) -> None:
    """
    Poll TCP connections for OBSERVE_DURATION seconds, then:
      1. Flag endpoints that reconnect at regular intervals (beaconing).
      2. Flag endpoints present in ≥80 % of snapshots (persistent C2 session).
      3. Probe all observed remote endpoints for HTTP/2 / gRPC transport.
      4. Passively capture live TCP traffic (Scapy) concurrent with polling;
         decode HTTP/2 / gRPC frames and flag Realm service paths immediately.

    Blocks for approximately OBSERVE_DURATION seconds.
    """
    n_snapshots = max(1, OBSERVE_DURATION // POLL_INTERVAL)
    persistence_min = int(0.8 * n_snapshots)

    # snapshot_count[ep]    = how many snapshots ep was present in
    # appearance_times[ep]  = timestamps of re-appearances (after an absence)
    snapshot_count:   Dict[Tuple[str, int], int]        = defaultdict(int)
    appearance_times: Dict[Tuple[str, int], List[float]] = defaultdict(list)
    prev: Set[Tuple[str, int]] = set()
    t0 = time.monotonic()

    # ── Launch live gRPC sniffer concurrently with the polling loop ────────
    sniffer_thread = threading.Thread(
        target=_sniff_realm_grpc,
        args=(report, float(OBSERVE_DURATION)),
        daemon=True,
        name="unrealm-grpc-sniffer",
    )
    sniffer_thread.start()

    for i in range(n_snapshots):
        snap = _collect_remote_endpoints()
        t    = time.monotonic() - t0

        for ep in snap:
            snapshot_count[ep] += 1

        # Record re-appearances: present now, absent last snapshot
        if i > 0:
            for ep in snap - prev:
                appearance_times[ep].append(t)

        prev = snap
        if i < n_snapshots - 1:
            time.sleep(POLL_INTERVAL)

    # ── Wait for sniffer to finish before running post-window analysis ─────
    sniffer_thread.join(timeout=OBSERVE_DURATION + 5)

    all_seen: Set[Tuple[str, int]] = set(snapshot_count)

    # ── Persistent connections ─────────────────────────────────────────────
    for (rip, rport), count in snapshot_count.items():
        if rip in ("127.0.0.1", "::1"):
            continue
        if count >= persistence_min:
            sev = Severity.HIGH if rport == C2_GRPC_PORT else Severity.MEDIUM
            report.add(Finding(
                category="network",
                severity=sev,
                title=(
                    f"Persistent outbound connection: {rip}:{rport} "
                    f"({count}/{n_snapshots} snapshots)"
                ),
                detail=(
                    f"TCP connection to {rip}:{rport} was active in {count} of "
                    f"{n_snapshots} snapshots over {OBSERVE_DURATION}s. "
                    f"May indicate a long-lived C2 channel (e.g. Realm gRPC streaming)."
                ),
                path=None,
                extra={"remote_ip": rip, "remote_port": rport, "snapshot_hits": count},
            ))

    # ── Beaconing ──────────────────────────────────────────────────────────
    for (rip, rport), times in appearance_times.items():
        if len(times) < MIN_BEACON_HITS:
            continue
        intervals = [times[j + 1] - times[j] for j in range(len(times) - 1)]
        intervals = [iv for iv in intervals if iv >= MIN_BEACON_IV]
        if len(intervals) < 2:
            continue
        mean_iv  = statistics.mean(intervals)
        stdev_iv = statistics.stdev(intervals)
        cv       = stdev_iv / mean_iv if mean_iv > 0 else float("inf")
        if cv <= BEACON_CV_THRESH:
            sev = Severity.HIGH if rport == C2_GRPC_PORT else Severity.MEDIUM
            report.add(Finding(
                category="network",
                severity=sev,
                title=f"Beaconing: {rip}:{rport} reconnects every ≈{mean_iv:.1f}s (CV={cv:.2f})",
                detail=(
                    f"{len(times)} reconnections to {rip}:{rport} with mean interval "
                    f"{mean_iv:.1f}s (σ={stdev_iv:.1f}s, CV={cv:.2f} ≤ {BEACON_CV_THRESH}). "
                    f"Consistent with C2 callback behaviour regardless of port."
                ),
                path=None,
                extra={
                    "remote_ip":       rip,
                    "remote_port":     rport,
                    "mean_interval_s": round(mean_iv, 2),
                    "stdev_s":         round(stdev_iv, 2),
                    "cv":              round(cv, 4),
                    "hits":            len(times),
                },
            ))

    # ── gRPC / HTTP-2 fingerprinting ───────────────────────────────────────
    probed: Set[Tuple[str, int]] = set()
    for rip, rport in all_seen:
        if rip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            continue
        if rport in _SKIP_GRPC_PORTS and rport != C2_GRPC_PORT:
            continue
        if (rip, rport) in probed:
            continue
        probed.add((rip, rport))
        if _probe_grpc(rip, rport):
            sev = Severity.HIGH if rport == C2_GRPC_PORT else Severity.MEDIUM
            report.add(Finding(
                category="network",
                severity=sev,
                title=f"gRPC/HTTP-2 confirmed: {rip}:{rport}",
                detail=(
                    f"Endpoint {rip}:{rport} replied to an HTTP/2 client-preface "
                    f"with a SETTINGS frame, confirming HTTP/2 transport. "
                    f"Realm uses gRPC (HTTP/2) for its C2 channel regardless of port."
                ),
                path=None,
                extra={"remote_ip": rip, "remote_port": rport},
            ))



# ── Instant snapshot checks ───────────────────────────────────────────────────

def _proc_net_check(report: ScanReport) -> bool:
    """Use /proc/net/tcp* to find port-8000 connections. Returns True if used."""
    if not os.path.isfile("/proc/net/tcp"):
        return False
    found_any = False
    for proto in ("tcp", "tcp6"):
        for conn in _parse_proc_net(proto):
            lp, rp = conn["local_port"], conn["remote_port"]
            if (lp == C2_GRPC_PORT or rp == C2_GRPC_PORT) and conn["state"] in (1, 2):
                found_any = True
                direction = "listening" if lp == C2_GRPC_PORT else "connecting"
                report.add(Finding(
                    category="network",
                    severity=Severity.HIGH,
                    title=f"C2 port {C2_GRPC_PORT} {direction} ({proto.upper()})",
                    detail=(
                        f"local={conn['local']}  remote={conn['remote']}  "
                        f"state={conn['state']} (1=ESTABLISHED)"
                    ),
                    path=None,
                    extra=conn,
                ))
    return found_any


def _ss_check(report: ScanReport) -> bool:
    """Try `ss -tnp` to enumerate port-8000 connections. Returns True if ss available."""
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
    """Fallback: use netstat -an to check for port 8000."""
    try:
        out = subprocess.check_output(
            ["netstat", "-an"], text=True, timeout=15, errors="replace"
        )
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


def _psutil_check(report: ScanReport) -> bool:
    """Use psutil to find port-8000 connections. Returns True if psutil available."""
    try:
        import psutil  # type: ignore
    except ImportError:
        return False
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        report.add(Finding(
            category="network",
            severity=Severity.INFO,
            title="Cannot fully inspect network connections (access denied)",
            detail="Run with elevated privileges for a complete network scan.",
        ))
        return True
    for conn in connections:
        lport = conn.laddr.port if conn.laddr else 0
        rport = conn.raddr.port if conn.raddr else 0
        if lport == C2_GRPC_PORT or rport == C2_GRPC_PORT:
            pid_info = f" PID={conn.pid}" if conn.pid else ""
            report.add(Finding(
                category="network",
                severity=Severity.HIGH,
                title=f"C2 port {C2_GRPC_PORT} connection detected (psutil){pid_info}",
                detail=f"local={conn.laddr}  remote={conn.raddr}  status={conn.status}",
                path=None,
                extra={"pid": conn.pid, "status": conn.status},
            ))
    return True


def _check_tavern_listening(report: ScanReport) -> None:
    """
    TCP-connect to 127.0.0.1:8000, then probe for gRPC in the same step.
    A successful connect means Tavern may be running on this host.
    """
    try:
        with socket.create_connection(("127.0.0.1", C2_GRPC_PORT), timeout=1):
            pass
    except (ConnectionRefusedError, OSError):
        return

    is_grpc   = _probe_grpc("127.0.0.1", C2_GRPC_PORT)
    transport = "gRPC/HTTP-2 handshake confirmed" if is_grpc else "port open, non-gRPC response"
    report.add(Finding(
        category="network",
        severity=Severity.HIGH,
        title=f"Realm Tavern C2 server listening on 127.0.0.1:{C2_GRPC_PORT}",
        detail=(
            f"TCP connection to 127.0.0.1:{C2_GRPC_PORT} succeeded "
            f"({transport}). The C2 server may be running on this host."
        ),
        path=None,
        extra={"port": C2_GRPC_PORT, "grpc_confirmed": is_grpc},
    ))


# ── Public entry point ────────────────────────────────────────────────────────

def scan(report: ScanReport) -> None:
    """
    Run all network checks for Realm C2 activity.

    Phase 1 (instant):  known-port checks via /proc/net, ss, psutil, netstat;
                        probes 127.0.0.1:8000 for gRPC.
    Phase 2 (~60 s):    beaconing analysis + gRPC fingerprinting across all
                        observed endpoints – port-agnostic to catch operators
                        who move Tavern off the default port.
    """
    # Phase 1 – instant snapshot
    _check_tavern_listening(report)
    used = False
    if _proc_net_check(report):
        used = True
    if _ss_check(report):
        used = True
    if _psutil_check(report):
        used = True
    if not used:
        _netstat_check(report)

    # Phase 2 – observation window (blocks ~OBSERVE_DURATION seconds)
    _observation_scan(report)
