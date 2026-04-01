#!/usr/bin/env python3
"""
################################################################################
# Log EPS (Events Per Second) Monitor
# Assesses incoming syslog traffic on this Linux host
#
# Author: Security Operations
# Version: 1.1
#
################################################################################
#
# DESCRIPTION:
#   Monitors syslog events received by this host and reports statistics:
#     - Average EPS over the monitoring period
#     - Highest (peak) EPS observed
#     - Number of unique hosts reporting
#     - Syslog facilities seen
#     - Average log event size (bytes / KB)
#     - Storage capacity estimates (1-day and 31-day projections)
#
#   Two monitoring modes:
#     rsyslog mode  - monitors the system syslog file for new entries
#     tcpdump mode  - captures raw packets on UDP/TCP port 514
#
# COMPATIBILITY:
#   Ubuntu 24, RHEL 8/9 | Python 3.6+
#
# REQUIREMENTS:
#   - rsyslog (for log file mode) or tcpdump (for packet capture mode)
#   - Root / sudo privileges recommended for tcpdump and rsyslog changes
#
# USAGE:
#   python3 epsmon.py
#
# STOP / SHORTCUT:
#   Press Ctrl+C at any time to stop monitoring and display the session summary.
#
################################################################################
"""

import os
import sys
import re
import time
import signal
import subprocess
import threading
import shutil
import glob
from datetime import datetime, timedelta
from collections import defaultdict

# =============================================================================
# ANSI Color Codes 
# =============================================================================
class C:
    GREEN  = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN   = '\033[0;36m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    NC     = '\033[0m'

    @staticmethod
    def disable():
        for attr in ('GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC'):
            setattr(C, attr, '')


if not sys.stdout.isatty():
    C.disable()

# =============================================================================
# Constants
# =============================================================================
VERSION              = "1.1"
SYSLOG_FILES         = ["/var/log/syslog", "/var/log/messages"]
RSYSLOG_CONF         = "/etc/rsyslog.conf"
RSYSLOG_CONF_DIR     = "/etc/rsyslog.d"
REMOTE_CONF_PATH     = "/etc/rsyslog.d/99-epsmon-remote.conf"
SYSLOG_PORT          = 514
SEP_HEAVY            = "=" * 58
SEP_LIGHT            = "-" * 58
SEP_MID              = "\u2500" * 58      # box-drawing horizontal line

FACILITY_MAP = {
     0: "kern",      1: "user",      2: "mail",      3: "daemon",
     4: "auth",      5: "syslog",    6: "lpr",       7: "news",
     8: "uucp",      9: "cron",     10: "authpriv", 11: "ftp",
    16: "local0",   17: "local1",   18: "local2",   19: "local3",
    20: "local4",   21: "local5",   22: "local6",   23: "local7",
}

# Best-effort mapping from program name to syslog facility
PROG_FACILITY = {
    "kernel": "kern",      "klogd": "kern",
    "sendmail": "mail",    "postfix": "mail",    "dovecot": "mail",
    "exim": "mail",        "exim4": "mail",
    "sshd": "auth",        "sudo": "auth",       "login": "auth",
    "su": "auth",          "passwd": "auth",
    "cron": "cron",        "crond": "cron",      "anacron": "cron",
    "atd": "cron",
    "lpd": "lpr",          "cups": "lpr",        "cupsd": "lpr",
    "rsyslogd": "syslog",  "syslogd": "syslog",
    "NetworkManager": "daemon", "systemd": "daemon",
    "systemd-networkd": "daemon", "named": "daemon",
    "ntpd": "daemon",      "chronyd": "daemon",  "dhcpd": "daemon",
    "firewalld": "daemon", "auditd": "daemon",
}

DURATION_MENU = [
    (1,    "1 minute"),
    (2,    "2 minutes"),
    (5,    "5 minutes"),
    (15,   "15 minutes"),
    (60,   "60 minutes  (1 hour)"),
    (360,  "6 hours"),
    (1440, "24 hours"),
]

# Syslog line regex: [<PRI>]Mmm [D]D HH:MM:SS hostname [program[pid]:] ...
_SYSLOG_RE = re.compile(
    r'^(?:<(\d+)>)?'                           # group 1: PRI (optional)
    r'\w{3}\s{1,2}\d{1,2}\s+'                 # timestamp Month Day
    r'\d{2}:\d{2}:\d{2}\s+'                   # timestamp HH:MM:SS
    r'(\S+)'                                    # group 2: hostname
    r'(?:\s+([\w][\w.\-]*)(?:\[\d+\])?:)?'    # group 3: program (optional)
)

# tcpdump packet header line  (captures source IP and optional payload length)
_TCPDUMP_PKT_RE = re.compile(
    r'^\d{2}:\d{2}:\d{2}\.\d+\s+IP(?:6)?\s+(\S+?)\.\d+\s+>'
)
_TCPDUMP_LEN_RE = re.compile(r'length\s+(\d+)')

# PRI value anywhere in a line (syslog payload)
_PRI_RE = re.compile(r'<(\d{1,3})>')

# =============================================================================
# Global monitoring state  (all writes protected by _lock)
# =============================================================================
_lock          = threading.Lock()
_stop_event    = threading.Event()
_total_events  = 0
_total_bytes   = 0                  # cumulative raw bytes of all events
_peak_eps      = 0
_hosts         = set()
_facilities    = set()
_second_counts = defaultdict(int)   # epoch-second -> event count
_start_time    = 0.0
_mode_label    = ""

# =============================================================================
# Signal handler  -  Ctrl+C sets the stop event
# =============================================================================
def _on_signal(_signum, _frame):
    _stop_event.set()

signal.signal(signal.SIGINT,  _on_signal)
signal.signal(signal.SIGTERM, _on_signal)

# =============================================================================
# Statistics helpers
# =============================================================================
def record_event(host=None, facility=None, size=0):
    global _total_events, _total_bytes, _peak_eps
    with _lock:
        _total_events += 1
        _total_bytes  += size
        sec = int(time.time())
        _second_counts[sec] += 1
        if _second_counts[sec] > _peak_eps:
            _peak_eps = _second_counts[sec]
        if host:
            _hosts.add(host)
        if facility:
            _facilities.add(facility)


def note_facility(facility):
    if facility:
        with _lock:
            _facilities.add(facility)


def get_snapshot():
    with _lock:
        elapsed  = max(1.0, time.time() - _start_time)
        sec      = int(time.time())
        cur_eps  = _second_counts.get(sec - 1, 0)
        avg_size = (_total_bytes / _total_events) if _total_events else 0
        return {
            "total":      _total_events,
            "avg_eps":    _total_events / elapsed,
            "peak_eps":   _peak_eps,
            "cur_eps":    cur_eps,
            "hosts":      sorted(_hosts),
            "facilities": sorted(_facilities),
            "elapsed":    elapsed,
            "avg_size":   avg_size,     # average event size in bytes
        }

# =============================================================================
# Utility
# =============================================================================
def confirm(prompt):
    """Prompt the user for a yes/no answer. Returns True for y/yes."""
    try:
        ans = input(f"{prompt} [y/N]: ").strip().lower()
        return ans in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def run_cmd(cmd, capture=True):
    """Run a command. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=15
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 1, "", str(exc)


def is_root():
    return os.geteuid() == 0


def cmd_exists(name):
    return shutil.which(name) is not None


def format_elapsed(secs):
    td  = timedelta(seconds=int(secs))
    h, rem = divmod(td.seconds, 3600)
    m, s   = divmod(rem, 60)
    if td.days:
        return f"{td.days}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"


def format_bytes(n):
    """Return a human-readable byte size string."""
    if n < 1024:
        return f"{n:.0f} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / 1024 ** 2:.2f} MB"
    else:
        return f"{n / 1024 ** 3:.2f} GB"


def term_width():
    return shutil.get_terminal_size((80, 24)).columns


def print_disclaimer():
    w = min(term_width(), 58)
    print(f"{SEP_LIGHT[:w]}")
    print(f"  DISCLAIMER")
    print(f"{SEP_LIGHT[:w]}")
    print(f"  This script is provided as-is, without warranty of any")
    print(f"  kind, express or implied. It is unsupported and intended")
    print(f"  for informational and diagnostic purposes only. The")
    print(f"  author assumes no liability for damages arising from its")
    print(f"  use. Use at your own risk.")
    print(f"{SEP_LIGHT[:w]}")
    print()
    try:
        input("  Press Enter to continue or Ctrl+C to exit...  ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    print()


def print_header():
    w = term_width()
    print()
    print(f"{C.BOLD}{SEP_HEAVY[:w]}{C.NC}")
    print(f"{C.BOLD}{'EPSMON':^{min(w, 58)}}{C.NC}")
    print(f"{'Syslog Event Stream Monitor':^{min(w, 58)}}")
    print(f"{'Version ' + VERSION:^{min(w, 58)}}")
    print(f"{SEP_HEAVY[:w]}")
    print()

# =============================================================================
# rsyslog configuration detection and modification
# =============================================================================
def _rsyslog_all_config():
    """Return combined text of all rsyslog config files (comments stripped)."""
    raw = ""
    targets = [RSYSLOG_CONF] + sorted(
        glob.glob(os.path.join(RSYSLOG_CONF_DIR, "*.conf"))
    )
    for path in targets:
        try:
            with open(path) as fh:
                raw += fh.read() + "\n"
        except OSError:
            pass
    return re.sub(r'#.*', '', raw)          # strip comments


def check_rsyslog_remote():
    """
    Return True if rsyslog is configured to receive remote syslog messages
    (imudp or imtcp input module loaded and an input port configured).
    """
    cfg = _rsyslog_all_config()

    has_udp = bool(
        re.search(r'module\s*\(\s*load\s*=\s*"imudp"', cfg, re.I) or
        re.search(r'\$ModLoad\s+imudp',                 cfg, re.I)
    )
    has_udp_port = bool(
        re.search(r'input\s*\(\s*type\s*=\s*"imudp"',  cfg, re.I) or
        re.search(r'\$UDPServerRun\s+\d+',              cfg, re.I)
    )
    has_tcp = bool(
        re.search(r'module\s*\(\s*load\s*=\s*"imtcp"', cfg, re.I) or
        re.search(r'\$ModLoad\s+imtcp',                 cfg, re.I)
    )
    has_tcp_port = bool(
        re.search(r'input\s*\(\s*type\s*=\s*"imtcp"',  cfg, re.I) or
        re.search(r'\$InputTCPServerRun\s+\d+',         cfg, re.I)
    )

    return (has_udp and has_udp_port) or (has_tcp and has_tcp_port)


def enable_rsyslog_remote():
    """
    Write a drop-in rsyslog config to accept UDP syslog from remote hosts,
    then restart rsyslog. Returns True on success.
    """
    content = (
        "# Enabled by epsmon - accept syslog messages from remote hosts\n"
        'module(load="imudp")\n'
        'input(type="imudp" port="514")\n'
    )
    try:
        with open(REMOTE_CONF_PATH, "w") as fh:
            fh.write(content)
    except OSError as exc:
        print(f"  ERROR: Could not write {REMOTE_CONF_PATH}: {exc}")
        return False

    rc, _, err = run_cmd(["systemctl", "restart", "rsyslog"])
    if rc != 0:
        print(f"  ERROR: rsyslog restart failed: {err.strip()}")
        return False

    return True

# =============================================================================
# Dependency verification
# =============================================================================
def check_dependencies(need_tcpdump=False):
    """
    Verify required packages are present. Offer to install if missing.
    Returns True if all dependencies are satisfied.
    """
    missing = []

    if need_tcpdump and not cmd_exists("tcpdump"):
        missing.append("tcpdump")

    if not missing:
        return True

    print(f"\n{C.YELLOW}The following dependencies are missing:{C.NC}")
    for dep in missing:
        print(f"  - {dep}")

    if not confirm("\nInstall missing dependencies now?"):
        print(
            f"\n{C.YELLOW}Dependencies not installed. "
            f"Script cannot continue.{C.NC}"
        )
        return False

    if cmd_exists("apt-get"):
        pkg_mgr = ["apt-get", "install", "-y"]
    elif cmd_exists("dnf"):
        pkg_mgr = ["dnf", "install", "-y"]
    elif cmd_exists("yum"):
        pkg_mgr = ["yum", "install", "-y"]
    else:
        print("  ERROR: No supported package manager found (apt-get / dnf / yum).")
        return False

    cmd = (["sudo"] if not is_root() else []) + pkg_mgr + missing
    print(f"\n  Installing: {', '.join(missing)} ...")

    rc, _, _ = run_cmd(cmd, capture=False)
    if rc != 0:
        print("  ERROR: Installation failed.")
        return False

    print(f"  {C.GREEN}Installation complete.{C.NC}")
    return True

# =============================================================================
# Log file tail monitor  (rsyslog mode)
# =============================================================================
def _find_syslog_file():
    for path in SYSLOG_FILES:
        if os.path.isfile(path):
            return path
    return None


def _parse_syslog_line(line):
    """
    Parse one syslog line. Returns (host, facility_name | None).
    """
    m = _SYSLOG_RE.match(line)
    if not m:
        return None, None

    pri_str, host, prog = m.group(1), m.group(2), m.group(3)

    facility = None
    if pri_str is not None:
        pri = int(pri_str)
        facility = FACILITY_MAP.get(pri >> 3)
    elif prog:
        base = prog.split(".")[0].split("/")[-1].lower()
        facility = PROG_FACILITY.get(base)

    return host, facility


def tail_syslog(syslog_file):
    """
    Thread target: follow syslog_file from its current end, recording each
    new line as an event.
    """
    try:
        fh = open(syslog_file, "r", errors="replace")
        fh.seek(0, 2)               # seek to EOF - monitor only new lines
    except OSError as exc:
        print(f"\n  ERROR: Cannot open {syslog_file}: {exc}")
        _stop_event.set()
        return

    while not _stop_event.is_set():
        line = fh.readline()
        if line:
            host, facility = _parse_syslog_line(line.rstrip())
            record_event(host=host, facility=facility,
                         size=len(line.encode("utf-8")))
        else:
            time.sleep(0.05)

    fh.close()

# =============================================================================
# tcpdump packet capture monitor
# =============================================================================
def run_tcpdump():
    """
    Thread target: run tcpdump on port 514 and count incoming packets,
    extracting source IPs and syslog facility (PRI) from packet payloads.
    """
    cmd = (
        (["sudo"] if not is_root() else []) +
        ["tcpdump", "-n", "-l", "-i", "any", "-A",
         "dst", "port", str(SYSLOG_PORT)]
    )

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except (FileNotFoundError, OSError) as exc:
        print(f"\n  ERROR: Cannot start tcpdump: {exc}")
        _stop_event.set()
        return

    pending_ip   = None
    pending_size = 0
    pkt_counted  = False

    for raw_line in proc.stdout:
        if _stop_event.is_set():
            break

        line = raw_line.rstrip()

        # Packet header line  -  new packet, count as one event
        m = _TCPDUMP_PKT_RE.match(line)
        if m:
            pending_ip  = m.group(1)
            pkt_counted = False
            # Extract UDP/TCP payload length from "length N" in header
            lm = _TCPDUMP_LEN_RE.search(line)
            pending_size = int(lm.group(1)) if lm else 0
            record_event(host=pending_ip, size=pending_size)
            pkt_counted = True
            continue

        # ASCII payload lines  -  look for <PRI> to identify facility
        if pending_ip and pkt_counted:
            stripped = line.strip()
            if stripped:
                pm = _PRI_RE.search(stripped)
                if pm:
                    try:
                        pri = int(pm.group(1))
                        if 0 <= pri <= 191:
                            note_facility(FACILITY_MAP.get(pri >> 3))
                    except ValueError:
                        pass
                pending_ip   = None  # stop examining this packet
                pending_size = 0
                pkt_counted  = False

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

# =============================================================================
# Live display  (updates every second, overwrites previous output in-place)
# =============================================================================
_DISPLAY_LINES = 13    # must equal the number of print() calls in _draw_block


def _draw_block(snap, dur_label, first=False):
    """
    Print (or overwrite) the live statistics block.
    On first call, simply print. On subsequent calls, move the cursor up
    _DISPLAY_LINES rows before reprinting.
    """
    w  = min(term_width(), 60)
    el = format_elapsed(snap["elapsed"])

    fac_str = ", ".join(snap["facilities"]) if snap["facilities"] else "none detected"
    if len(fac_str) > w - 26:
        fac_str = fac_str[: w - 29] + "..."

    if not first:
        sys.stdout.write(f"\033[{_DISPLAY_LINES}A")

    size_str = format_bytes(snap["avg_size"]) if snap["avg_size"] else "n/a"

    lines = [
        f"{SEP_MID[:w]}",
        (f"  {C.BOLD}Mode:{C.NC} {_mode_label:<28} "
         f"{C.DIM}[Ctrl+C to stop]{C.NC}"),
        f"  Duration: {dur_label:<20} Elapsed: {el}",
        f"{SEP_MID[:w]}",
        f"  {C.CYAN}Current EPS    (last sec){C.NC}  : {snap['cur_eps']:>8}",
        f"  {C.CYAN}Average EPS               {C.NC}  : {snap['avg_eps']:>8.2f}",
        f"  {C.CYAN}Peak EPS                  {C.NC}  : {snap['peak_eps']:>8}",
        f"  {C.CYAN}Total Events              {C.NC}  : {snap['total']:>8,}",
        f"  {C.CYAN}Avg Event Size            {C.NC}  : {size_str:>8}",
        f"{SEP_MID[:w]}",
        f"  {C.CYAN}Reporting Hosts           {C.NC}  : {len(snap['hosts']):>8}",
        f"  {C.CYAN}Facilities Seen           {C.NC}  : {fac_str}",
        f"{SEP_MID[:w]}",
    ]

    for line in lines:
        print(f"{line:<{w}}")


# =============================================================================
# Final summary
# =============================================================================
def print_summary(dur_label):
    snap = get_snapshot()
    w    = min(term_width(), 60)

    avg_size  = snap["avg_size"]
    avg_eps   = snap["avg_eps"]
    # Storage projections (raw, uncompressed)
    bytes_1d  = avg_eps * 86400 * avg_size
    bytes_31d = bytes_1d * 31

    print(f"\n{C.BOLD}{SEP_HEAVY[:w]}{C.NC}")
    print(f"{C.BOLD}  MONITORING SESSION SUMMARY{C.NC}")
    print(f"{SEP_HEAVY[:w]}")
    print(f"  Monitoring Mode       : {_mode_label}")
    print(f"  Selected Duration     : {dur_label}")
    print(f"  Actual Elapsed        : {format_elapsed(snap['elapsed'])}")
    print(f"  Session End           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{SEP_LIGHT[:w]}")
    print(f"  Total Events          : {snap['total']:,}")
    print(f"  Average EPS           : {avg_eps:.2f}")
    print(f"  Peak EPS              : {snap['peak_eps']}")
    print(f"  Avg Event Size        : "
          f"{format_bytes(avg_size) if avg_size else 'n/a'}")
    print(f"{SEP_LIGHT[:w]}")
    print(f"  Reporting Hosts       : {len(snap['hosts'])}")
    if snap["hosts"]:
        display_hosts = snap["hosts"][:25]
        for host in display_hosts:
            print(f"    {host}")
        remaining = len(snap["hosts"]) - len(display_hosts)
        if remaining > 0:
            print(f"    ... and {remaining} more")
    print(f"{SEP_LIGHT[:w]}")
    print(f"  Facilities Seen       : "
          f"{', '.join(snap['facilities']) if snap['facilities'] else 'none detected'}")
    print(f"{SEP_LIGHT[:w]}")
    print(f"{C.BOLD}  STORAGE CAPACITY ESTIMATE  (raw / uncompressed){C.NC}")
    print(f"{SEP_LIGHT[:w]}")
    if avg_size and avg_eps:
        print(f"  Avg Event Size        : {format_bytes(avg_size)}"
              f"  ({avg_size:.0f} bytes)")
        print(f"  Projected EPS         : {avg_eps:.2f}")
        print(f"  Storage  -   1 day    : {format_bytes(bytes_1d)}")
        print(f"  Storage  -  31 days   : {format_bytes(bytes_31d)}")
        print(f"  {C.DIM}Note: actual storage with compression is typically"
              f" 5-10x smaller.{C.NC}")
    else:
        print("  Insufficient data to calculate storage estimates.")
    print(f"{SEP_HEAVY[:w]}\n")


# =============================================================================
# Save summary to log file
# =============================================================================
def save_summary_to_file(dur_label):
    """
    Write a plain-text copy of the session summary to a timestamped log file
    in the same directory as this script.
    """
    snap     = get_snapshot()
    avg_size = snap["avg_size"]
    avg_eps  = snap["avg_eps"]
    bytes_1d  = avg_eps * 86400 * avg_size
    bytes_31d = bytes_1d * 31

    sep_h = "=" * 58
    sep_l = "-" * 58
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = "log_epsmon_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fpath = os.path.join(script_dir, fname)

    lines = [
        sep_h,
        "  EPSMON  -  Syslog Event Stream Monitor",
        f"  Session Log  |  {ts}",
        sep_h,
        f"  Monitoring Mode       : {_mode_label}",
        f"  Selected Duration     : {dur_label}",
        f"  Actual Elapsed        : {format_elapsed(snap['elapsed'])}",
        f"  Session End           : {ts}",
        sep_l,
        f"  Total Events          : {snap['total']:,}",
        f"  Average EPS           : {avg_eps:.2f}",
        f"  Peak EPS              : {snap['peak_eps']}",
        f"  Avg Event Size        : "
            + (format_bytes(avg_size) if avg_size else "n/a"),
        sep_l,
        f"  Reporting Hosts       : {len(snap['hosts'])}",
    ]

    for host in snap["hosts"][:50]:
        lines.append(f"    {host}")
    if len(snap["hosts"]) > 50:
        lines.append(f"    ... and {len(snap['hosts']) - 50} more")

    lines += [
        sep_l,
        "  Facilities Seen       : "
            + (", ".join(snap["facilities"]) if snap["facilities"]
               else "none detected"),
        sep_l,
        "  STORAGE CAPACITY ESTIMATE  (raw / uncompressed)",
        sep_l,
    ]

    if avg_size and avg_eps:
        lines += [
            f"  Avg Event Size        : {format_bytes(avg_size)}"
                f"  ({avg_size:.0f} bytes)",
            f"  Projected EPS         : {avg_eps:.2f}",
            f"  Storage  -   1 day    : {format_bytes(bytes_1d)}",
            f"  Storage  -  31 days   : {format_bytes(bytes_31d)}",
            "  Note: actual storage with compression is typically 5-10x smaller.",
        ]
    else:
        lines.append("  Insufficient data to calculate storage estimates.")

    lines.append(sep_h)

    try:
        with open(fpath, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"  Session log saved to: {fpath}\n")
    except OSError as exc:
        print(f"  WARNING: Could not save log file: {exc}\n")


# =============================================================================
# Duration selection menu
# =============================================================================
def select_duration():
    print(f"\n{C.BOLD}Select monitoring duration:{C.NC}")
    for idx, (_, label) in enumerate(DURATION_MENU, 1):
        print(f"  [{idx}] {label}")
    print()

    while True:
        try:
            choice = input(
                f"Enter selection [1-{len(DURATION_MENU)}]: "
            ).strip()
            n = int(choice) - 1
            if 0 <= n < len(DURATION_MENU):
                return DURATION_MENU[n]
        except (ValueError, KeyboardInterrupt):
            pass
        print(f"  Invalid selection. Enter a number from 1 to {len(DURATION_MENU)}.")

# =============================================================================
# Main
# =============================================================================
def main():
    global _start_time, _mode_label

    os.system("clear")
    print_header()
    print_disclaimer()

    # -------------------------------------------------------------------------
    # Step 1: Dependency pre-check
    # -------------------------------------------------------------------------
    print(f"{C.BOLD}[1/3]  Dependency check{C.NC}")

    rsyslog_active = False
    rc, _, _ = run_cmd(["systemctl", "is-active", "--quiet", "rsyslog"])
    if rc == 0:
        rsyslog_active = True
        print(f"  {C.GREEN}rsyslog service is active.{C.NC}")
    else:
        print(f"  {C.YELLOW}rsyslog service does not appear to be running.{C.NC}")

    # -------------------------------------------------------------------------
    # Step 2: rsyslog remote reception check
    # -------------------------------------------------------------------------
    print(f"\n{C.BOLD}[2/3]  rsyslog remote reception configuration{C.NC}")

    use_tcpdump = False

    if check_rsyslog_remote():
        print(
            f"  {C.GREEN}rsyslog is configured to accept remote "
            f"syslog messages.{C.NC}"
        )
    else:
        print(
            f"  {C.YELLOW}rsyslog is NOT configured to accept remote "
            f"syslog messages.{C.NC}"
        )
        print("  (No imudp / imtcp input modules detected)\n")

        if confirm(
            "  Configure rsyslog to accept remote messages on UDP port 514?"
        ):
            if not is_root():
                print(
                    f"\n  {C.YELLOW}Root privileges required to modify "
                    f"rsyslog configuration.{C.NC}"
                )
                print(
                    "  Re-run with sudo, or apply the configuration change manually."
                )
                use_tcpdump = confirm(
                    "\n  Fall back to tcpdump packet capture instead?"
                )
                if not use_tcpdump:
                    print("\nExiting.")
                    sys.exit(0)
            else:
                print(f"\n  Writing {REMOTE_CONF_PATH} and restarting rsyslog ...")
                if enable_rsyslog_remote():
                    print(
                        f"  {C.GREEN}rsyslog configured successfully.{C.NC}"
                    )
                else:
                    use_tcpdump = confirm(
                        "\n  Configuration failed. "
                        "Fall back to tcpdump instead?"
                    )
                    if not use_tcpdump:
                        print("\nExiting.")
                        sys.exit(0)
        else:
            use_tcpdump = confirm(
                "\n  Monitor with tcpdump on port 514 instead?"
            )
            if not use_tcpdump:
                print("\nExiting.")
                sys.exit(0)

    # -------------------------------------------------------------------------
    # Step 3: Mode-specific dependency and file check
    # -------------------------------------------------------------------------
    print(f"\n{C.BOLD}[3/3]  Verifying mode prerequisites{C.NC}")

    syslog_file = None

    if use_tcpdump:
        if not check_dependencies(need_tcpdump=True):
            sys.exit(1)
        _mode_label = f"tcpdump  (port {SYSLOG_PORT})"
        print(f"  {C.GREEN}tcpdump is available.{C.NC}")
    else:
        syslog_file = _find_syslog_file()
        if syslog_file:
            print(f"  {C.GREEN}Syslog file: {syslog_file}{C.NC}")
            _mode_label = f"rsyslog  ({syslog_file})"
        else:
            print(
                f"  {C.YELLOW}No syslog file found at: "
                f"{', '.join(SYSLOG_FILES)}{C.NC}"
            )
            use_tcpdump = confirm(
                "\n  Fall back to tcpdump packet capture instead?"
            )
            if not use_tcpdump:
                print("\nExiting.")
                sys.exit(0)
            if not check_dependencies(need_tcpdump=True):
                sys.exit(1)
            _mode_label = f"tcpdump  (port {SYSLOG_PORT})"

    # -------------------------------------------------------------------------
    # Duration selection
    # -------------------------------------------------------------------------
    dur_mins, dur_label = select_duration()
    duration_secs = dur_mins * 60

    # -------------------------------------------------------------------------
    # Start monitoring
    # -------------------------------------------------------------------------
    print(f"\n{C.BOLD}Initializing monitor...{C.NC}")
    time.sleep(0.4)

    _start_time = time.time()
    end_time    = _start_time + duration_secs

    if use_tcpdump:
        monitor_thread = threading.Thread(target=run_tcpdump, daemon=True)
    else:
        monitor_thread = threading.Thread(
            target=tail_syslog, args=(syslog_file,), daemon=True
        )

    monitor_thread.start()

    # Initial display block
    snap = get_snapshot()
    print()
    _draw_block(snap, dur_label, first=True)

    # Live update loop (runs on main thread)
    try:
        while not _stop_event.is_set():
            time.sleep(1.0)
            snap = get_snapshot()
            _draw_block(snap, dur_label, first=False)
            if time.time() >= end_time:
                _stop_event.set()
                break
    except KeyboardInterrupt:
        _stop_event.set()

    print()
    print_summary(dur_label)
    save_summary_to_file(dur_label)


if __name__ == "__main__":
    main()
