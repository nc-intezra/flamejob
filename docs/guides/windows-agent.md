# Windows agent (NVIDIA)

The flamejob worker agent (`fj-agent`) runs on Windows as a native service and
behaves exactly like the Linux agent: it enrolls with the control plane, opens
the WebSocket task stream, runs hashcat chunks, and streams progress, cracked
hashes and GPU/host telemetry. It is the same binary and the same version as the
Linux build; only the packaging and service host differ.

This guide covers the NVIDIA GPU worker. CPU-only hosts work too (telemetry
degrades to CPU/RAM), but the target here is an NVIDIA box.

## Prerequisites

- **Windows 10/11 or Windows Server 2019/2022**, 64-bit.
- **NVIDIA driver** installed. The agent reads GPU telemetry with `nvidia-smi`,
  which the driver installs (usually on `PATH` as
  `C:\Windows\System32\nvidia-smi.exe`). Verify with `nvidia-smi` in a terminal.
- **hashcat for Windows** extracted somewhere on the machine (e.g.
  `C:\tools\hashcat\hashcat.exe`). Download it from https://hashcat.net. Confirm
  it sees the GPU with `hashcat -I`.
- Administrator rights to install the MSI (it registers a service).

## Install (interactive)

1. Run `flamejob-agent-<version>-x64.msi` and accept the UAC prompt. It installs
   `fj-agent.exe` to `C:\Program Files\flamejob`, creates
   `C:\ProgramData\flamejob-agent`, and registers the **flamejob-agent** service
   (startup type Automatic). The service is **not started yet** — it needs its
   configuration first.
2. Mint a one-time enrollment token on the control plane (needs the
   **ManageAgents** capability), e.g. `POST /admin/agent-claims {"name":"gpu-box-1"}`.
3. Edit `C:\ProgramData\flamejob-agent\agent.env` (as Administrator) and set:
   - `FJ_AGENT_SERVER` — the control-plane URL, e.g. `https://control-plane:8443`
   - `FJ_AGENT_NAME` — a name for this worker
   - `FJ_AGENT_CLAIM_TOKEN` — the token from step 2 (uncomment the line)
   - `FJ_AGENT_HASHCAT` — the full path to `hashcat.exe` (or leave `hashcat.exe`
     if it is on `PATH`)
4. Start the service:

   ```
   sc start flamejob-agent
   ```

   (or `"C:\Program Files\flamejob\fj-agent.exe" service start`, or start it from
   `services.msc`).

After the first successful start the agent enrolls (CSR → CA-signed client
certificate, saved under `C:\ProgramData\flamejob-agent\pki`). You can then clear
`FJ_AGENT_CLAIM_TOKEN` from `agent.env`; the certificate is reused on every
subsequent start. The worker appears in `GET /agents` and the dashboard.

## Install (unattended / Group Policy / Intune)

Install silently, bake the configuration with the agent itself, then start the
service:

```bat
msiexec /i flamejob-agent-<version>-x64.msi /qn
"%ProgramFiles%\flamejob\fj-agent.exe" service write-env ^
  --server https://control-plane:8443 --name %COMPUTERNAME% ^
  --claim-token <one-time-token> --hashcat "C:\tools\hashcat\hashcat.exe" --force
sc start flamejob-agent
```

`service write-env` writes `C:\ProgramData\flamejob-agent\agent.env` from the
values given (omit a flag to keep the template placeholder). Without `--force`
it will not overwrite an existing file, so it is safe to re-run.

For a fleet, a unique claim token per host is recommended; a shared token works
if the control plane permits reuse.

## Configuration

`agent.env` uses the same `FJ_AGENT_*` keys as the Linux systemd
`EnvironmentFile`. The agent loads this file first and then its environment, so
an explicitly set machine/environment variable overrides the file. Common keys:

| Key | Meaning | Default |
| --- | --- | --- |
| `FJ_AGENT_SERVER` | control-plane base URL | `http://127.0.0.1:8099` |
| `FJ_AGENT_NAME` | worker name | `agent` |
| `FJ_AGENT_CLAIM_TOKEN` | one-time enrollment token (first start only) | — |
| `FJ_AGENT_HASHCAT` | hashcat executable | `hashcat.exe` (on `PATH`) |
| `FJ_AGENT_WORKLOAD` | hashcat workload profile 1–4 | `3` |
| `FJ_AGENT_DATA_DIR` | cert/scratch dir | `%ProgramData%\flamejob-agent` |
| `FJ_AGENT_METRICS_INTERVAL_SECS` | idle telemetry interval | `5` |

After editing `agent.env`, restart the service (`sc stop flamejob-agent &&
sc start flamejob-agent`).

## Service management

```
sc start   flamejob-agent          # start
sc stop    flamejob-agent          # stop
sc query   flamejob-agent          # status
```

Equivalent agent commands (run from an elevated prompt):

```
fj-agent service start
fj-agent service stop
fj-agent service install     # register the service manually (the MSI does this)
fj-agent service uninstall   # stop and remove the service
```

Logs are written to `C:\ProgramData\flamejob-agent\logs\agent.log` (daily
rolled). Set `FJ_LOG=debug` in `agent.env` for verbose logging.

The service is installed with startup type **Automatic**, so it starts at boot.
To also have Windows restart it after a crash (the equivalent of systemd's
`Restart=on-failure`), configure recovery once:

```
sc failure flamejob-agent reset= 86400 actions= restart/5000/restart/5000/restart/5000
```

## GPU fan control — not available on Windows

The closed-loop fan controller is **Linux-only**. It drives `nvidia-settings`,
which is an Xorg/Coolbits mechanism with no Windows counterpart, so
`FJ_AGENT_FAN_CONTROL` is ignored on Windows and a one-time warning is logged if
it is set. GPU telemetry (temperature, utilization, power, fan speed, clocks,
per-card hashrate) is read via `nvidia-smi` and works normally — only *driving*
the fans is unavailable. Manage fan curves with the driver or a vendor utility
(e.g. MSI Afterburner) instead. Overheat protection that stops a job therefore
does not apply on Windows; rely on the driver's thermal throttling and a sane
fan curve.

## Uninstall

Uninstall from *Apps & features* or `msiexec /x flamejob-agent-<version>-x64.msi
/qn`. This stops and removes the service and deletes the program files. The data
directory `C:\ProgramData\flamejob-agent` (including the enrolled certificate) is
left in place, mirroring the Linux package; delete it manually to fully remove
the worker's identity.
