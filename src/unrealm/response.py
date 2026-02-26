"""
response.py – Remediation actions for detected realm/imix artifacts.

Two response modes:
  neutralize  – Cripple the C2 while keeping C2 comms alive so operators
                believe everything is working normally.

                Eldritch's sys.shell() resolves the shell via PATH:
                  • Unix  : Command::new("sh")  -c  <cmd>
                  • Windows: Command::new("cmd") /c  <cmd>
                so the deception strategy is to shadow "sh" / "cmd" with a
                noop binary that exits 0 with empty output. Every task the
                operator sends "succeeds" silently — no errors, no output,
                no obvious sign of neutralisation.

                Linux  : /bin/sh → /bin/true (backed up to /bin/sh.realm_backup)
                macOS  : /usr/local/bin/sh → /usr/bin/true (PATH-priority shim)
                         + LaunchDaemon plist patched to inject that PATH so
                           the service picks it up without a full reinstall
                Windows: C:\\ProgramData\\realm_neut\\cmd.exe compiled as noop
                         + IFEO (Image File Execution Options) debugger redirect
                           so every cmd.exe spawn (even from System32 absolute
                           path) calls our noop instead

  remove      – Surgically delete every confirmed realm artifact:
                processes killed, binaries deleted, services disabled,
                host-ID files removed, registry keys purged (Windows).

Both modes write a plain-text action log so the operator can review what
was done. All destructive operations are gated behind the caller's explicit
approval (passed as a boolean flag); this module never prompts on its own.
"""
from __future__ import annotations

import logging
import os
import platform
import plistlib
import shutil
import subprocess
from typing import List, Optional

from unrealm.findings import Finding, ScanReport

log = logging.getLogger("unrealm.response")


class RemediationResult:
    """Tracks what was attempted, what succeeded, and what failed."""

    def __init__(self) -> None:
        self.attempted: List[str] = []
        self.succeeded: List[str] = []
        self.failed: List[str] = []
        self.skipped: List[str] = []

    def ok(self, msg: str) -> None:
        log.info("OK   %s", msg)
        self.succeeded.append(msg)

    def fail(self, msg: str) -> None:
        log.warning("FAIL %s", msg)
        self.failed.append(msg)

    def skip(self, msg: str) -> None:
        log.debug("SKIP %s", msg)
        self.skipped.append(msg)

    def try_op(self, description: str) -> None:
        self.attempted.append(description)


# ── Low-level helpers ──────────────────────────────────────────────────────────

def _kill_pid(pid: int, result: RemediationResult) -> None:
    result.try_op(f"kill PID {pid}")
    try:
        import signal
        os.kill(pid, signal.SIGKILL)
        result.ok(f"Killed PID {pid}")
    except (ProcessLookupError, PermissionError, OSError) as exc:
        result.fail(f"kill PID {pid}: {exc}")


def _remove_file(path: str, result: RemediationResult) -> None:
    result.try_op(f"remove file {path}")
    try:
        os.remove(path)
        result.ok(f"Removed file {path}")
    except (FileNotFoundError, PermissionError, OSError) as exc:
        result.fail(f"remove {path}: {exc}")


def _run(cmd: List[str], result: RemediationResult, desc: str) -> bool:
    result.try_op(desc)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            result.ok(desc)
            return True
        else:
            result.fail(f"{desc}: exit {r.returncode}  stderr={r.stderr.strip()[:200]}")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        result.fail(f"{desc}: {exc}")
        return False


# ── Linux neutralise ───────────────────────────────────────────────────────────

def _neutralise_sh_direct(
    sh: str, backup: str, true_bin: str, result: RemediationResult
) -> None:
    """
    Shared helper: replace `sh` with `true_bin`, backing up to `backup`.
    Used by both Linux (always) and macOS (when SIP is disabled).
    """
    if not os.path.isfile(sh):
        result.skip(f"neutralise: {sh} not found")
        return
    if not os.path.isfile(true_bin):
        result.fail(f"neutralise: {true_bin} not found")
        return

    try:
        if os.path.samefile(sh, true_bin):
            result.skip(f"neutralise: {sh} is already {true_bin}")
            return
    except OSError:
        pass

    result.try_op(f"backup {sh} → {backup}")
    try:
        if not os.path.isfile(backup):
            shutil.copy2(sh, backup)
            result.ok(f"Backed up {sh} → {backup}")
        else:
            result.skip(f"Backup already exists at {backup}")
    except (PermissionError, OSError) as exc:
        result.fail(f"backup {sh}: {exc}")
        return

    result.try_op(f"replace {sh} with {true_bin}")
    try:
        shutil.copy2(true_bin, sh)
        os.chmod(sh, 0o755)
        result.ok(f"Replaced {sh} with {true_bin}")
    except (PermissionError, OSError) as exc:
        result.fail(f"replace {sh}: {exc}")


def _neutralise_linux(result: RemediationResult) -> None:
    """
    Replace /bin/sh with /bin/true.

    After this:
    • imix keeps beaconing to C2 – comms stay live.
    • sys.shell() spawns "sh -c <cmd>", resolves to /bin/true (PATH or
      direct), true exits 0 with no output. Operator sees success + empty
      stdout – consistent with a command that ran but produced nothing.
    • Restore with:  python -m unrealm --restore
    """
    _neutralise_sh_direct("/bin/sh", "/bin/sh.realm_backup", "/bin/true", result)


def _restore_sh_linux(result: RemediationResult) -> None:
    """Undo Linux neutralise: restore /bin/sh from backup."""
    backup = "/bin/sh.realm_backup"
    sh = "/bin/sh"
    if not os.path.isfile(backup):
        result.skip("restore: no /bin/sh.realm_backup found")
        return
    result.try_op(f"restore {sh} from {backup}")
    try:
        shutil.copy2(backup, sh)
        os.chmod(sh, 0o755)
        result.ok(f"Restored {sh} from {backup}")
        os.remove(backup)
    except (PermissionError, OSError) as exc:
        result.fail(f"restore {sh}: {exc}")


# ── Linux full removal ─────────────────────────────────────────────────────────

def _remove_linux(findings: List[Finding], result: RemediationResult) -> None:
    # Kill processes
    for f in findings:
        if f.category == "process":
            pid = f.extra.get("pid")
            if pid:
                _kill_pid(int(pid), result)

    # Disable + stop services (systemd)
    stopped_svcs: set = set()
    for f in findings:
        if f.category == "service":
            svc = f.extra.get("unit") or f.extra.get("service_name")
            if not svc:
                continue
            svc = svc.replace(".service", "")
            if svc in stopped_svcs:
                continue
            stopped_svcs.add(svc)
            _run(["systemctl", "stop", svc], result, f"systemctl stop {svc}")
            _run(["systemctl", "disable", svc], result, f"systemctl disable {svc}")

    # Remove files (host-ID, binaries, unit files, staging files)
    for f in findings:
        if f.category == "file" and f.path:
            if f.path.startswith("/bin/sh"):
                continue  # Never auto-delete /bin/sh
            _remove_file(f.path, result)

    # Remove systemd unit files found in service findings
    for f in findings:
        if f.category == "service" and f.path and f.path.endswith(".service"):
            _remove_file(f.path, result)

    _run(["systemctl", "daemon-reload"], result, "systemctl daemon-reload")


# ── macOS full removal ────────────────────────────────────────────────────────

def _remove_macos(findings: List[Finding], result: RemediationResult) -> None:
    # Kill processes
    for f in findings:
        if f.category == "process":
            pid = f.extra.get("pid")
            if pid:
                _kill_pid(int(pid), result)

    # Unload + remove LaunchDaemon/Agent plists
    for f in findings:
        if f.category == "service" and f.path and f.path.endswith(".plist"):
            _run(["launchctl", "unload", "-w", f.path], result,
                 f"launchctl unload {f.path}")
            _remove_file(f.path, result)
        elif f.category == "service" and f.extra.get("label"):
            # Loaded via launchctl but plist path unknown
            label = f.extra["label"]
            _run(["launchctl", "remove", label], result, f"launchctl remove {label}")

    # Remove files
    for f in findings:
        if f.category == "file" and f.path:
            _remove_file(f.path, result)


# ── Windows full removal ──────────────────────────────────────────────────────

def _remove_windows(findings: List[Finding], result: RemediationResult) -> None:
    # Kill processes
    for f in findings:
        if f.category == "process":
            pid = f.extra.get("pid")
            if pid:
                try:
                    import psutil  # type: ignore
                    p = psutil.Process(int(pid))
                    p.kill()
                    result.ok(f"Killed PID {pid}")
                except Exception as exc:
                    _run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        result, f"taskkill /F /PID {pid}",
                    )

    # Stop + delete services
    for f in findings:
        if f.category == "service":
            svc = f.extra.get("service_name")
            if svc:
                _run(["sc.exe", "stop", svc], result, f"sc stop {svc}")
                _run(["sc.exe", "delete", svc], result, f"sc delete {svc}")

    # Remove files
    for f in findings:
        if f.category == "file" and f.path:
            _remove_file(f.path, result)

    # Remove registry keys
    for f in findings:
        if f.category == "registry" and f.path:
            _run(
                ["reg", "delete", f.path, "/f"],
                result, f"reg delete {f.path}",
            )


# ── macOS neutralise ──────────────────────────────────────────────────────────

# Eldritch sys.shell() on Unix: Command::new("sh").args(["-c", cmd])
# "sh" is resolved via PATH – so if we inject a noop "sh" earlier in PATH
# than the real /bin/sh, every sys.shell() call silently exits 0.
# We do NOT unload the service – C2 comms stay alive and operators see
# successful (but empty) task output.

_MACOS_NEUT_DIR = "/usr/local/bin"
_MACOS_SH_SHIM = "/usr/local/bin/sh"
_MACOS_SH_BACKUP = "/usr/local/bin/sh.realm_backup"

# PATH we inject into the plist EnvironmentVariables so /usr/local/bin
# precedes /bin and /usr/bin (where the real sh lives).
_MACOS_NEUT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# The noop binary: /usr/bin/true exits 0 with no output on every invocation.
_MACOS_TRUE = "/usr/bin/true"


def _sip_enabled() -> bool:
    """Return True if System Integrity Protection is on."""
    try:
        out = subprocess.check_output(
            ["csrutil", "status"], text=True, stderr=subprocess.STDOUT, timeout=5
        )
        return "enabled" in out.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return True  # Assume enabled if we can't tell


def _neutralise_macos(result: RemediationResult, findings: "Optional[List[Finding]]" = None) -> None:
    """
    Deceptive macOS neutralise – keeps C2 comms live while breaking
    every sys.shell() execution.

    Steps:
    1. Create /usr/local/bin/sh → /usr/bin/true  (PATH-shadowing shim)
    2. Patch every detected realm LaunchDaemon/Agent plist to inject
       PATH=/usr/local/bin:... via EnvironmentVariables, then reload it.
    3. If SIP is disabled, also replace /bin/sh directly (same as Linux).

    After this:
    • imix continues beaconing to C2 – operators see a live agent.
    • Every task using sys.shell() returns exit 0 with empty stdout/stderr.
    • sys.exec() with absolute paths still works (different code path),
      but most Eldritch tomes use sys.shell() for their heavy lifting.
    """
    if not os.path.isfile(_MACOS_TRUE):
        result.fail("neutralise (macOS): /usr/bin/true not found")
        return

    os.makedirs(_MACOS_NEUT_DIR, exist_ok=True)

    # ── 1. Create /usr/local/bin/sh noop shim ────────────────────────────
    result.try_op(f"create sh noop shim at {_MACOS_SH_SHIM}")
    try:
        # Check if the shim already points to true
        existing_real = os.path.realpath(_MACOS_SH_SHIM) if os.path.exists(_MACOS_SH_SHIM) else ""
        true_real = os.path.realpath(_MACOS_TRUE)
        if existing_real == true_real:
            result.skip(f"{_MACOS_SH_SHIM} already points to true")
        else:
            # Backup any existing /usr/local/bin/sh
            if os.path.exists(_MACOS_SH_SHIM):
                shutil.copy2(_MACOS_SH_SHIM, _MACOS_SH_BACKUP)
            # Create symlink: /usr/local/bin/sh → /usr/bin/true
            if os.path.islink(_MACOS_SH_SHIM):
                os.unlink(_MACOS_SH_SHIM)
            elif os.path.isfile(_MACOS_SH_SHIM):
                os.remove(_MACOS_SH_SHIM)
            os.symlink(_MACOS_TRUE, _MACOS_SH_SHIM)
            result.ok(f"Created sh noop shim: {_MACOS_SH_SHIM} → {_MACOS_TRUE}")
    except (PermissionError, OSError) as exc:
        result.fail(f"create sh shim: {exc}")

    # ── 2. Patch LaunchDaemon plists to inject PATH ───────────────────────
    plist_paths: List[str] = []
    if findings:
        plist_paths = [
            f.path for f in findings
            if f.category == "service" and f.path and f.path.endswith(".plist")
        ]
    # Also probe default locations in case findings are empty
    for d in ("/Library/LaunchDaemons", "/Library/LaunchAgents"):
        if not os.path.isdir(d):
            continue
        import re as _re
        _realm_re = _re.compile(r"\bimix\b|\bgolem\b|com\.testing\.", _re.IGNORECASE)
        for fname in os.listdir(d):
            full = os.path.join(d, fname)
            if full not in plist_paths and fname.endswith(".plist"):
                try:
                    text = open(full, errors="replace").read()
                    if _realm_re.search(fname) or _realm_re.search(text):
                        plist_paths.append(full)
                except OSError:
                    pass

    for plist_path in plist_paths:
        _patch_plist_path(plist_path, result)

    # ── 3. If SIP disabled, also replace /bin/sh directly ────────────────
    if not _sip_enabled():
        result.try_op("SIP disabled – also replacing /bin/sh directly")
        _neutralise_sh_direct("/bin/sh", "/bin/sh.realm_backup", _MACOS_TRUE, result)
    else:
        result.skip(
            "SIP enabled – /bin/sh cannot be replaced directly; "
            "PATH-shim approach used instead (effective after service reload)"
        )


def _patch_plist_path(plist_path: str, result: RemediationResult) -> None:
    """
    Inject EnvironmentVariables/PATH into a LaunchDaemon plist so that the
    service's child processes find /usr/local/bin/sh (our noop) before the
    real /bin/sh, then reload the service.
    """
    result.try_op(f"patch plist PATH: {plist_path}")
    try:
        with open(plist_path, "rb") as fh:
            pl = plistlib.load(fh)

        env = pl.setdefault("EnvironmentVariables", {})
        current_path = env.get("PATH", "")
        if "/usr/local/bin" in current_path.split(":")[0]:
            result.skip(f"plist already has /usr/local/bin at PATH head: {plist_path}")
        else:
            env["PATH"] = _MACOS_NEUT_PATH
            pl["EnvironmentVariables"] = env
            with open(plist_path, "wb") as fh:
                plistlib.dump(pl, fh)
            result.ok(f"Patched PATH in {plist_path}")

        # Reload the plist so the change takes effect immediately
        label = pl.get("Label", os.path.basename(plist_path))
        _run(["launchctl", "unload", plist_path], result, f"launchctl unload {plist_path}")
        _run(["launchctl", "load", "-w", plist_path], result, f"launchctl load {plist_path}")

    except (PermissionError, OSError, Exception) as exc:
        result.fail(f"patch plist {plist_path}: {exc}")


def _restore_sh_macos(result: RemediationResult) -> None:
    """Remove the /usr/local/bin/sh shim and restore any backed-up copy."""
    if os.path.isfile(_MACOS_SH_BACKUP):
        result.try_op(f"restore {_MACOS_SH_SHIM} from backup")
        try:
            shutil.copy2(_MACOS_SH_BACKUP, _MACOS_SH_SHIM)
            os.remove(_MACOS_SH_BACKUP)
            result.ok(f"Restored {_MACOS_SH_SHIM}")
        except (PermissionError, OSError) as exc:
            result.fail(f"restore {_MACOS_SH_SHIM}: {exc}")
    elif os.path.exists(_MACOS_SH_SHIM):
        result.try_op(f"remove sh noop shim {_MACOS_SH_SHIM}")
        try:
            os.remove(_MACOS_SH_SHIM)
            result.ok(f"Removed sh shim {_MACOS_SH_SHIM}")
        except (PermissionError, OSError) as exc:
            result.fail(f"remove shim: {exc}")
    else:
        result.skip("restore (macOS): no sh shim found")


# ── Windows neutralise ────────────────────────────────────────────────────────

# Eldritch sys.shell() on Windows: Command::new("cmd").args(["/c", cmd])
# "cmd" is resolved by CreateProcess in this order:
#   1. Application directory  2. CWD  3. System32  4. Windows  5. PATH
# Since imix typically lives in System32 (same dir as real cmd.exe), we
# can't beat it with PATH alone. Instead we use Image File Execution Options
# (IFEO) – a Windows kernel mechanism that redirects every cmd.exe spawn
# (regardless of full path) to our noop binary before execution.
#
# The IFEO Debugger value is called with:
#   noop.exe  <original_cmd_path>  <original_args...>
# Our noop.exe ignores all arguments and exits 0.
#
# Result: C2 comms stay live. Operators see tasks "succeed" (exit 0,
# empty stdout) without any actual execution occurring.

_WIN_NEUT_DIR = r"C:\ProgramData\realm_neut"
_WIN_NOOP_PATH = r"C:\ProgramData\realm_neut\noop.exe"

# IFEO registry path for cmd.exe
_IFEO_BASE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_IFEO_CMD = _IFEO_BASE + r"\cmd.exe"

# C# source for the noop binary
_NOOP_CS = """using System;
class RealmNoop {
    static int Main(string[] args) {
        // Silently discard all arguments, return success.
        return 0;
    }
}
"""

# PowerShell one-liner that compiles _NOOP_CS with Add-Type
_NOOP_PS1 = r"""
$src = @'
{src}
'@
Add-Type -TypeDefinition $src `
         -OutputAssembly '{dst}' `
         -OutputType ConsoleApplication `
         -ErrorAction Stop
""".format(src=_NOOP_CS.strip(), dst=_WIN_NOOP_PATH)


def _compile_noop_exe(result: RemediationResult) -> bool:
    """
    Compile a noop.exe that accepts any arguments and exits 0.
    Uses PowerShell Add-Type (C# → PE) – no external tools required.
    Returns True on success.
    """
    result.try_op(f"compile noop.exe at {_WIN_NOOP_PATH}")

    os.makedirs(_WIN_NEUT_DIR, exist_ok=True)

    if os.path.isfile(_WIN_NOOP_PATH):
        result.skip(f"noop.exe already exists at {_WIN_NOOP_PATH}")
        return True

    try:
        r = subprocess.run(
            [
                "powershell.exe", "-NonInteractive", "-NoProfile",
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-Command", _NOOP_PS1,
            ],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0 and os.path.isfile(_WIN_NOOP_PATH):
            result.ok(f"Compiled {_WIN_NOOP_PATH}")
            return True
        else:
            result.fail(
                f"compile noop.exe: exit {r.returncode}  "
                f"stderr={r.stderr.strip()[:300]}"
            )
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        result.fail(f"compile noop.exe: {exc}")
        return False


def _set_ifeo_cmd(result: RemediationResult) -> None:
    """
    Set HKLM\\{_IFEO_CMD}\\Debugger = <path to noop.exe>
    This redirects every cmd.exe spawn (from any path) to our noop binary.
    """
    result.try_op(f"set IFEO debugger for cmd.exe → {_WIN_NOOP_PATH}")
    try:
        import winreg  # type: ignore
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, _IFEO_CMD,
            access=winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, _WIN_NOOP_PATH)
        winreg.CloseKey(key)
        result.ok(
            f"IFEO redirect set: cmd.exe → {_WIN_NOOP_PATH}  "
            f"(all cmd.exe invocations now exit 0 silently)"
        )
    except ImportError:
        # Not on Windows – use reg.exe fallback
        _run(
            [
                "reg", "add",
                f"HKLM\\{_IFEO_CMD}",
                "/v", "Debugger",
                "/t", "REG_SZ",
                "/d", _WIN_NOOP_PATH,
                "/f",
            ],
            result,
            f"reg add IFEO cmd.exe Debugger={_WIN_NOOP_PATH}",
        )
    except (PermissionError, OSError) as exc:
        result.fail(f"set IFEO: {exc}")


def _clear_ifeo_cmd(result: RemediationResult) -> None:
    """Remove the IFEO Debugger redirect for cmd.exe."""
    result.try_op("remove IFEO debugger for cmd.exe")
    try:
        import winreg  # type: ignore
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _IFEO_CMD,
            access=winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, "Debugger")
        winreg.CloseKey(key)
        result.ok("Removed IFEO Debugger for cmd.exe")
    except ImportError:
        _run(
            ["reg", "delete", f"HKLM\\{_IFEO_CMD}", "/v", "Debugger", "/f"],
            result, "reg delete IFEO cmd.exe Debugger",
        )
    except FileNotFoundError:
        result.skip("IFEO Debugger for cmd.exe not set (nothing to restore)")
    except (PermissionError, OSError) as exc:
        result.fail(f"remove IFEO: {exc}")


def _neutralise_windows(result: RemediationResult) -> None:
    """
    Deceptive Windows neutralise – keeps C2 comms live while breaking
    every sys.shell() execution.

    Steps:
    1. Compile a noop.exe (C# via PowerShell Add-Type) that accepts any
       arguments and always exits 0 with no output.
    2. Install it via IFEO (Image File Execution Options) as the debugger
       for cmd.exe, so every cmd.exe spawn – regardless of absolute path –
       is intercepted and replaced by our noop.

    After this:
    • imix continues beaconing to C2 (service still running).
    • Every sys.shell() call: imix spawns "cmd /c <task>", Windows IFEO
      intercepts and runs noop.exe instead → exit 0, no output.
    • Operator sees task "success" with empty stdout – consistent with
      a command that ran but produced no output. Not immediately obvious.
    • Restore with:  python -m unrealm --restore
    """
    if _compile_noop_exe(result):
        _set_ifeo_cmd(result)


# ── Public API ─────────────────────────────────────────────────────────────────

def neutralise(report: ScanReport) -> RemediationResult:
    """
    Cripple the C2's execution capability while keeping C2 comms alive.

    Eldritch's sys.shell() resolves its shell binary via PATH:
      • Unix    : Command::new("sh")  -c  <cmd>
      • Windows : Command::new("cmd") /c  <cmd>

    We shadow / redirect these so every shell invocation silently exits 0
    with no output. Operators see task "success" but nothing is executed.

    Linux  : /bin/sh → /bin/true  (backup at /bin/sh.realm_backup)
    macOS  : /usr/local/bin/sh → /usr/bin/true (PATH-priority shim)
             + LaunchDaemon plist patched with EnvironmentVariables/PATH
    Windows: noop.exe compiled via PowerShell, installed via IFEO as
             cmd.exe Debugger – intercepts all cmd.exe spawns system-wide
    """
    result = RemediationResult()
    system = platform.system()
    if system == "Linux":
        _neutralise_linux(result)
    elif system == "Darwin":
        _neutralise_macos(result, findings=report.findings)
    elif system == "Windows":
        _neutralise_windows(result)
    else:
        result.skip(f"neutralise: unsupported platform {system}")
    return result


def remove(report: ScanReport) -> RemediationResult:
    """
    Surgically remove all detected realm artifacts.
    Kills processes, disables services, deletes binaries and persistence files.
    """
    result = RemediationResult()
    findings = report.findings
    if not findings:
        result.skip("remove: no findings to act on")
        return result

    system = platform.system()
    if system == "Linux":
        _remove_linux(findings, result)
    elif system == "Darwin":
        _remove_macos(findings, result)
    elif system == "Windows":
        _remove_windows(findings, result)
    else:
        result.skip(f"remove: unsupported platform {system}")
    return result


def restore_neutralise(report: ScanReport) -> RemediationResult:
    """
    Undo a prior neutralise action.

    Linux  : restores /bin/sh from /bin/sh.realm_backup
    macOS  : removes /usr/local/bin/sh shim (restores backup if present)
    Windows: removes IFEO Debugger for cmd.exe
    """
    result = RemediationResult()
    system = platform.system()
    if system == "Linux":
        _restore_sh_linux(result)
    elif system == "Darwin":
        _restore_sh_macos(result)
    elif system == "Windows":
        _clear_ifeo_cmd(result)
        if os.path.isfile(_WIN_NOOP_PATH):
            result.skip(
                f"noop.exe left at {_WIN_NOOP_PATH} "
                f"(safe to remove manually: del \"{_WIN_NOOP_PATH}\")"
            )
    else:
        result.skip(f"restore_neutralise: nothing to restore on {system}")
    return result
