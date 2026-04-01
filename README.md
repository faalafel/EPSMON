# EPSMON — Syslog Event Stream Monitor

**Version 1.1**

A Python-based interactive tool for assessing whether a Linux host is receiving syslog messages from remote machines, and for measuring the volume and characteristics of that traffic in real time.

---

## Overview

EPSMON monitors incoming syslog events and produces a statistical summary including Events Per Second (EPS) rates, reporting host counts, observed syslog facilities, average event size, and projected storage requirements. It is intended for use by security operations and infrastructure teams when sizing SIEM ingestion capacity or validating syslog forwarding pipelines.

The tool operates in one of two modes:

- **rsyslog mode** — monitors the system syslog file (`/var/log/syslog` or `/var/log/messages`) for new entries in real time
- **tcpdump mode** — captures raw UDP/TCP packets on port 514 directly off the wire

---

## Compatibility

| Platform | Version |
|---|---|
| Ubuntu | 24 LTS |
| RHEL / CentOS | 8, 9 |
| Python | 3.6+ |

---

## Requirements

| Requirement | Purpose |
|---|---|
| `rsyslog` | Log file monitoring mode (typically pre-installed) |
| `tcpdump` | Packet capture mode (installed on demand if missing) |
| Root / sudo | Modifying rsyslog config, restarting services, running tcpdump |

No external Python packages are required. The script uses only the Python standard library.

---

## Installation

No installation is required. Copy the script to the target host and run it directly.

```bash
# Copy to target host (example)
scp epsmon.py user@host:/opt/epsmon/

# Make executable
chmod +x /opt/epsmon/epsmon.py
```

---

## Usage

```bash
python3 epsmon.py
```

Or, if running tasks that require system changes (rsyslog config, tcpdump):

```bash
sudo python3 epsmon.py
```

The script is fully interactive. No command-line arguments are required.

---

## Startup Sequence

On launch, the script steps through three checks before presenting the monitoring menu:

### Step 1 — Dependency Check
Verifies that rsyslog is installed and active. Reports any missing dependencies before attempting to install them. The user is prompted to accept or deny installation. If denied, the script exits cleanly with a message.

### Step 2 — rsyslog Remote Reception Check
Inspects `/etc/rsyslog.conf` and all files under `/etc/rsyslog.d/` for `imudp` or `imtcp` input module configuration (both RainerScript and legacy `$ModLoad` formats).

- If remote reception is already configured, monitoring proceeds.
- If not configured, the user is offered the option to apply the change automatically. The script writes a drop-in config to `/etc/rsyslog.d/99-epsmon-remote.conf` and restarts rsyslog.
- If the user declines or root privileges are unavailable, the script offers to fall back to tcpdump mode.

### Step 3 — Mode Prerequisites
Confirms the syslog log file is accessible (rsyslog mode) or that tcpdump is available (tcpdump mode), offering to install tcpdump if missing.

---

## Monitoring Duration Options

| Option | Duration |
|---|---|
| 1 | 1 minute |
| 2 | 2 minutes |
| 3 | 5 minutes |
| 4 | 15 minutes |
| 5 | 60 minutes (1 hour) |
| 6 | 6 hours |
| 7 | 24 hours |

Press **Ctrl+C** at any time to stop the monitor early. The session summary is always shown regardless of how monitoring ends.

---

## Live Display

The display refreshes every second in place without scrolling:

```
────────────────────────────────────────────────────────
  Mode: rsyslog (/var/log/syslog)     [Ctrl+C to stop]
  Duration: 5 minutes           Elapsed: 00:02:14
────────────────────────────────────────────────────────
  Current EPS    (last sec)  :       47
  Average EPS                :    38.52
  Peak EPS                   :       94
  Total Events               :    5,183
  Avg Event Size             :   204 B
────────────────────────────────────────────────────────
  Reporting Hosts            :       12
  Facilities Seen            :  auth, cron, daemon, kern
────────────────────────────────────────────────────────
```

---

## Session Summary

At the end of every session, a full summary is printed to the terminal and saved to a timestamped log file:

```
==========================================================
  MONITORING SESSION SUMMARY
==========================================================
  Monitoring Mode       : rsyslog  (/var/log/syslog)
  Selected Duration     : 5 minutes
  Actual Elapsed        : 00:05:00
  Session End           : 2026-03-31 14:30:22
----------------------------------------------------------
  Total Events          : 11,556
  Average EPS           : 38.52
  Peak EPS              : 94
  Avg Event Size        : 204 B
----------------------------------------------------------
  Reporting Hosts       : 12
    10.0.0.1
    10.0.0.5
    ...
----------------------------------------------------------
  Facilities Seen       : auth, cron, daemon, kern, syslog
----------------------------------------------------------
  STORAGE CAPACITY ESTIMATE  (raw / uncompressed)
----------------------------------------------------------
  Avg Event Size        : 204 B  (204 bytes)
  Projected EPS         : 38.52
  Storage  -   1 day    : 643.12 MB
  Storage  -  31 days   : 19.45 GB
  Note: actual storage with compression is typically 5-10x smaller.
==========================================================
```

---

## Log File Output

The session summary is automatically saved to the same directory as the script:

```
log_epsmon_20260331_143022.log
```

The file is plain text with no ANSI color codes, suitable for archiving, email, or ticket attachments.

---

## rsyslog Drop-in Configuration

When EPSMON applies the rsyslog remote reception change, it creates the following file:

**`/etc/rsyslog.d/99-epsmon-remote.conf`**
```
# Enabled by epsmon - accept syslog messages from remote hosts
module(load="imudp")
input(type="imudp" port="514")
```

To revert: delete the file and restart rsyslog.

```bash
sudo rm /etc/rsyslog.d/99-epsmon-remote.conf
sudo systemctl restart rsyslog
```

---

## Syslog Facilities Detected

EPSMON identifies the following standard syslog facilities:

`kern` `user` `mail` `daemon` `auth` `syslog` `lpr` `news` `uucp` `cron` `authpriv` `ftp` `local0` – `local7`

In rsyslog mode, facilities are derived from the PRI value in the log line if present, or inferred from the program name. In tcpdump mode, they are parsed from the PRI byte in the raw syslog payload.

---

## Disclaimer

This script is provided as-is, without warranty of any kind, express or implied. It is unsupported and intended for informational and diagnostic purposes only. The author assumes no liability for damages arising from its use. Use at your own risk.
