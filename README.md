# unrealm

A cross-platform Python agent that detects and responds to the
[Realm C2 framework](https://github.com/spellshift/realm) and its implants.

---

## What it detects

### All platforms
| Artifact | Details |
|---|---|
| `imix` / `golem` process | Running implant processes by name |
| Rust/imix dependency strings in process binary | Binary search for `rustc`, `gimli`, `addr2line`, `demangle` — all four present indicates an imix compiled binary, regardless of process name |
| Port 8000 connections | Realm's default Tavern gRPC/HTTP C2 port |
| Tavern server listening locally | TCP connect to `127.0.0.1:8000` |

### Linux
| Artifact | Path |
|---|---|
| Host-ID beacon UUID | `/var/tmp/system-id` |
| Imix binary | `/bin/imix`, `/usr/bin/imix`, etc. |
| Rust/imix strings in process binary | Enumerates `/proc`, resolves `/proc/<pid>/exe`, reads binary — requires root for cross-user processes |
| Systemd service unit | `/usr/lib/systemd/system/imixsvc.service` (or custom name) |
| SysVinit script | `/etc/init.d/imixsvc` (or custom name) |
| Install staging files | `/tmp/systemd.service.j2`, `/tmp/svc.sh.j2` |
| Neutralised `/bin/sh` | Detects if `/bin/sh → /bin/true` already applied |

### macOS
| Artifact | Path |
|---|---|
| Host-ID beacon UUID | `/Users/Shared/system-id` |
| Imix Mach-O binary | `/var/root/imix` (or custom name) |
| Rust/imix strings in process binary | Enumerates via `ps`, resolves exe from argv[0], reads binary — best-effort without sudo |
| LaunchDaemon plist | `/Library/LaunchDaemons/imixsvc.plist` (label `com.testing.*`) |
| Install staging file | `/tmp/plist.j2` |

### Windows
| Artifact | Location |
|---|---|
| Host-ID beacon UUID | `C:\ProgramData\system-id` |
| Imix PE binary | `C:\Windows\System32\imix.exe` (or custom name) |
| Rust/imix strings in process binary | Enumerates via `psutil` (preferred) or WMIC, reads PE binary — system/SYSTEM processes may be skipped without Administrator |
| Windows service | Service named `imix`, `imixsvc`, `golem`, `golemsvc` |
| Registry key | `HKLM\SOFTWARE\Imix` → `system-id` value |

---

## Usage
Some features require administrator/sudo so you'd want to run `sudo .venv/bin/python -m unrealm --remove` in that case.
```
# Scan only (default)
python -m unrealm

# Scan + print JSON report
python -m unrealm --json

# Scan and neutralise
python -m unrealm --neutralize

# Scan and fully remove (prompts for confirmation)
python -m unrealm --remove

# Scan, remove, no prompts (for automated use)
python -m unrealm --remove --yes

# Write report to file
python -m unrealm --output report.json

# Restore /bin/sh after a prior neutralise (Linux)
python -m unrealm --restore
```

---

## Response modes

### `--neutralize`
Cripples shell execution **while keeping C2 comms fully alive**.

Eldritch's `sys.shell()` resolves its shell binary via `PATH`:
- Unix: `Command::new("sh") -c <cmd>`
- Windows: `Command::new("cmd") /c <cmd>`

Every task the operator sends "succeeds" (exit 0, empty stdout) — consistent with a command that ran but produced no output. Not immediately obvious to the operator.

| Platform | Mechanism | C2 comms |
|---|---|---|
| **Linux** | `/bin/sh` replaced with `/bin/true`. Backup at `/bin/sh.realm_backup`. | ✅ Live |
| **macOS** | `/usr/local/bin/sh` → `/usr/bin/true` shim created. Realm LaunchDaemon plists patched with `EnvironmentVariables/PATH=/usr/local/bin:...` and reloaded (service stays running). If SIP is disabled, `/bin/sh` is also replaced directly. | ✅ Live |
| **Windows** | A noop `cmd.exe` is compiled (C# via PowerShell `Add-Type`). Installed via **IFEO (Image File Execution Options)** as `cmd.exe` Debugger — intercepts every `cmd.exe` spawn at the kernel level regardless of absolute path. | ✅ Live |

Restore any neutralise action with `python -m unrealm --restore`.

### `--remove`
Surgically removes all detected artifacts.

- Kills implant processes (`SIGKILL` / `taskkill /F`).
- Stops and disables/deletes services (`systemctl disable`, `launchctl unload`, `sc delete`).
- Deletes binary files, host-ID files, and persistence files.
- Removes registry keys (Windows).

---

## Installation

```bash
# 1. Git clone the repo (or download the zip)
git clone https://github.com/b3at1/unrealm.git
# 2. Create and activate a virtual environment
cd /unrealm
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. Install the package and all dependencies
pip install .
```

Requires **Python 3.9+**.

Required dependencies (installed automatically):

| Package | Purpose |
|---|---|
| `psutil >= 5.9` | Rich process and network connection enumeration |
| `scapy >= 2.5` | Live TCP packet capture for in-flight gRPC service-path detection |

> **Note:** live packet capture (`scapy`) requires elevated privileges — run as
> `root` on Linux/macOS or as Administrator on Windows, or grant
> `CAP_NET_RAW` to the Python executable. Without root the sniffer step will
> be skipped and a `Severity.INFO` finding will be emitted instead.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No detections, or detections fully resolved |
| `1` | Remediation attempted but one or more actions failed |
| `2` | Detections present, no action taken |

---

## Notes

- **Elevated privileges** (`root` / Administrator) are required for some checks
  (reading `/proc/<pid>/exe`, listing all services, deleting system files).
- The **Rust/imix dependency string check** enumerates all running processes and
  reads each unique executable binary. Without elevated privileges:
  - **Linux** — `/proc/<pid>/exe` is unreadable for processes owned by other users;
    those processes are silently skipped. Run as `root` for full coverage.
  - **macOS** — exe path is inferred from `ps` argv[0]; most processes are covered
    without `sudo`, but some system processes may report misleading paths.
  - **Windows** — `psutil` raises `AccessDenied` for SYSTEM/other-user processes
    (skipped gracefully); WMIC may omit `ExecutablePath` for protected processes
    without Administrator. Run as Administrator for full coverage.
- The tool is **read-only by default**; destructive operations only run when
  `--neutralize` or `--remove` is explicitly passed and confirmed.
- Always test in a non-production environment first.
