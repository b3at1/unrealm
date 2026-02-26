# unrealm

A cross-platform Python agent that detects and responds to the
[Realm C2 framework](https://github.com/spellshift/realm) and its implants.

---

## What it detects

### All platforms
| Artifact | Details |
|---|---|
| `imix` / `golem` process | Running implant processes by name |
| Port 8000 connections | Realm's default Tavern gRPC/HTTP C2 port |
| Tavern server listening locally | TCP connect to `127.0.0.1:8000` |

### Linux
| Artifact | Path |
|---|---|
| Host-ID beacon UUID | `/var/tmp/system-id` |
| Imix binary | `/bin/imix`, `/usr/bin/imix`, etc. |
| Systemd service unit | `/usr/lib/systemd/system/imixsvc.service` (or custom name) |
| SysVinit script | `/etc/init.d/imixsvc` (or custom name) |
| Install staging files | `/tmp/systemd.service.j2`, `/tmp/svc.sh.j2` |
| Neutralised `/bin/sh` | Detects if `/bin/sh → /bin/true` already applied |

### macOS
| Artifact | Path |
|---|---|
| Host-ID beacon UUID | `/Users/Shared/system-id` |
| Imix Mach-O binary | `/var/root/imix` (or custom name) |
| LaunchDaemon plist | `/Library/LaunchDaemons/imixsvc.plist` (label `com.testing.*`) |
| Install staging file | `/tmp/plist.j2` |

### Windows
| Artifact | Location |
|---|---|
| Host-ID beacon UUID | `C:\ProgramData\system-id` |
| Imix PE binary | `C:\Windows\System32\imix.exe` (or custom name) |
| Windows service | Service named `imix`, `imixsvc`, `golem`, `golemsvc` |
| Registry key | `HKLM\SOFTWARE\Imix` → `system-id` value |

---

## Usage

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
# Minimal (stdlib only)
pip install .

# Full (psutil for richer process/network inspection)
pip install ".[full]"
```

Requires **Python 3.9+**. No external dependencies are needed for basic scanning.
`psutil` is optional but recommended for the most complete results.

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
- The tool is **read-only by default**; destructive operations only run when
  `--neutralize` or `--remove` is explicitly passed and confirmed.
- Always test in a non-production environment first.
