#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                       THE REAL WORLD                            ║
║           Physical Layer Anomaly Detection Engine               ║
║                   macOS Edition v1.0.3                          ║
╚══════════════════════════════════════════════════════════════════╝

Changelog:
  v1.0.3 — Added baseline warmup guard (no alerts until history window is 50%
             full) and absolute minimum byte thresholds for DISK_IO_BURST and
             NET_BURST to eliminate false positives from low-average early runs
             and the tool's own polling I/O.
  v1.0.2 — Added APPLE_VIRTUAL_IFACES allowlist to NetworkInterfaceMonitor.
             Suppresses false-positive MAC_CHANGE / IP_ADDED / IP_REMOVED alerts
             on llw0 (Low Latency WLAN), awdl0 (AirDrop), utun* (VPN tunnels),
             anpi* (internal NICs), and bridge* — all of which rotate MACs by
             design on macOS. Real physical interfaces (en0, en1, …) are still
             fully monitored.
  v1.0.1 — Tightened KernelLogMonitor USB_KLOG_ATTACH / USB_KLOG_DETACH regex
             patterns to skip internal IOKit ref-count churn messages
             ("Detaching, ref count = N") which were causing false positives.
             Now only fires on real device-level events from the Apple USB stack.
  v1.0.0 — Initial release


  - RF / 802.11 (WiFi signal, BSSID, channel, RSSI drift)
  - Ethernet (link state, speed negotiation, duplex changes)
  - USB / HID (device attach / detach, VID:PID inventory)
  - Bluetooth (device appearances, RSSI anomalies)
  - Thunderbolt / PCIe (DMA-capable device events)
  - Audio I/O (unexpected microphone / speaker attach)
  - Display (external monitor attach / detach)
  - Power / Battery (source switches, voltage drift)
  - Thermal / Fan (temperature spikes, fan ramp)
  - CPU / Memory / Disk I/O (statistical baseline deviation)
  - Network Interface (new interfaces, MAC changes, ARP anomalies)
  - IOKit hardware registry (unexpected driver loads)

All anomalies are logged silently to /var/log/the_real_world.log
Requires: pip install psutil (all other deps are stdlib or OS binaries)
Run with sudo for full sensor access.

Usage:
  sudo python3 the_real_world.py [--interval SECONDS] [--verbose]
"""

import argparse
import collections
import json
import logging
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

# ── Optional dependency ────────────────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ══════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════

TOOL_NAME    = "THE REAL WORLD"
VERSION      = "1.0.3"
LOG_PATH     = Path("/var/log/the_real_world.log")
FALLBACK_LOG = Path(os.path.expanduser("~/the_real_world.log"))

# How many historical samples to keep for baseline statistics
BASELINE_WINDOW = 60

# Default poll interval in seconds (override via --interval)
DEFAULT_INTERVAL = 5

# Network interfaces whose MAC addresses rotate by design on macOS.
# Changes on these are suppressed to avoid false positives.
APPLE_VIRTUAL_IFACES = re.compile(
    r"^(?:llw\d+|awdl\d+|utun\d+|anpi\d+|bridge\d+|ap\d+|p2p\d+|ipsec\d+)$"
)

# RSSI drop (dBm) considered anomalous in one poll cycle
WIFI_RSSI_DROP_THRESHOLD = 15

# Percentage CPU delta that triggers an anomaly
CPU_SPIKE_THRESHOLD = 40.0

# Percentage memory jump that triggers an anomaly
MEM_JUMP_THRESHOLD = 20.0

# Disk I/O burst multiplier vs rolling average
DISK_IO_MULTIPLIER = 5.0

# Absolute minimum bytes for a DISK_IO_BURST alert (filters tool's own polling I/O)
DISK_IO_MIN_BYTES = 100 * 1024 * 1024       # 100 MB

# Network throughput burst multiplier vs rolling average
NET_BURST_MULTIPLIER = 10.0

# Absolute minimum bytes for a NET_BURST alert (filters small-average noise)
NET_BURST_MIN_BYTES = 10 * 1024 * 1024      # 10 MB

# Temperature delta (°C) in one cycle considered anomalous
THERMAL_JUMP_THRESHOLD = 15.0

# Path to the Apple airport binary
AIRPORT_BIN = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)

# ══════════════════════════════════════════════════════════════════
#  LOGGING SETUP
# ══════════════════════════════════════════════════════════════════

def _setup_logger(verbose: bool) -> logging.Logger:
    """Configure the structured anomaly logger."""
    logger = logging.getLogger("the_real_world")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d UTC | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Override default local time with UTC
    fmt.converter = time.gmtime  # type: ignore[assignment]

    # Attempt privileged log location first
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(LOG_PATH), encoding="utf-8")
        log_dest = LOG_PATH
    except PermissionError:
        fh = logging.FileHandler(str(FALLBACK_LOG), encoding="utf-8")
        log_dest = FALLBACK_LOG

    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    if verbose:
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    logger.info(
        f"[INIT] {TOOL_NAME} v{VERSION} started | PID={os.getpid()} "
        f"| log={log_dest} | platform={platform.platform()}"
    )
    return logger


# ══════════════════════════════════════════════════════════════════
#  UTILITY HELPERS
# ══════════════════════════════════════════════════════════════════

def _run(cmd: List[str], timeout: int = 8) -> Optional[str]:
    """Run a subprocess and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _run_json(cmd: List[str], timeout: int = 12) -> Optional[Any]:
    """Run a subprocess and parse JSON output."""
    raw = _run(cmd, timeout=timeout)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _mean_safe(data: Deque) -> float:
    return statistics.mean(data) if len(data) >= 2 else 0.0


def _stdev_safe(data: Deque) -> float:
    return statistics.stdev(data) if len(data) >= 2 else 0.0


def _zscore(value: float, data: Deque) -> float:
    sd = _stdev_safe(data)
    if sd == 0:
        return 0.0
    return abs(value - _mean_safe(data)) / sd


# ══════════════════════════════════════════════════════════════════
#  BASE MONITOR CLASS
# ══════════════════════════════════════════════════════════════════

class BaseMonitor:
    """Abstract monitor.  Each subclass implements `poll()` and emits
    anomaly strings via `self._anomalies`."""

    name: str = "BASE"

    def __init__(self, logger: logging.Logger) -> None:
        self.log = logger
        self._anomalies: List[str] = []

    def poll(self) -> None:
        raise NotImplementedError

    def _emit(self, msg: str, level: str = "WARNING") -> None:
        tag = f"[{self.name}] {msg}"
        if level == "CRITICAL":
            self.log.critical(tag)
        elif level == "ERROR":
            self.log.error(tag)
        else:
            self.log.warning(tag)


# ══════════════════════════════════════════════════════════════════
#  MONITOR: WiFi / 802.11
# ══════════════════════════════════════════════════════════════════

class WiFiMonitor(BaseMonitor):
    """
    Tracks 802.11 physical-layer indicators:
      • BSSID change (potential evil-twin / MITM AP)
      • Channel change (potential deauth + channel-switch attack)
      • RSSI sudden drop (jamming / deauth flood)
      • Security mode downgrade (WPA2→WPA1/OPEN)
      • MCS / PHY mode downgrade (rate-forcing attack)
      • Noise floor spike (RF jamming)
    """
    name = "WIFI"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev: Dict[str, Any] = {}
        self._rssi_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._noise_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._has_airport = shutil.which(AIRPORT_BIN) or os.path.exists(AIRPORT_BIN)

    def _get_airport_info(self) -> Dict[str, str]:
        if not self._has_airport:
            return {}
        raw = _run([AIRPORT_BIN, "-I"])
        if not raw:
            return {}
        info: Dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return info

    def poll(self) -> None:
        info = self._get_airport_info()
        if not info:
            return

        ssid     = info.get("SSID", "")
        bssid    = info.get("BSSID", "")
        channel  = info.get("channel", "")
        security = info.get("link auth", "")
        mcs      = info.get("MCS", "")
        phy_mode = info.get("PHY Mode", "")

        try:
            rssi  = float(info.get("agrCtlRSSI", info.get("RSSI", "0")))
            noise = float(info.get("agrCtlNoise", info.get("Noise", "0")))
            snr   = rssi - noise
        except ValueError:
            rssi = noise = snr = 0.0

        prev = self._prev

        if prev:
            # ── BSSID change ──────────────────────────────────────
            if bssid and prev.get("bssid") and bssid != prev["bssid"]:
                self._emit(
                    f"BSSID_CHANGE ssid={ssid!r} "
                    f"old={prev['bssid']} new={bssid} "
                    f"channel={channel} rssi={rssi}dBm"
                )

            # ── Channel change ────────────────────────────────────
            if channel and prev.get("channel") and channel != prev["channel"]:
                self._emit(
                    f"CHANNEL_CHANGE ssid={ssid!r} "
                    f"old={prev['channel']} new={channel}"
                )

            # ── RSSI sudden drop (jamming / deauth flood) ─────────
            if rssi and prev.get("rssi"):
                delta = prev["rssi"] - rssi          # positive = drop
                if delta >= WIFI_RSSI_DROP_THRESHOLD:
                    self._emit(
                        f"RSSI_DROP ssid={ssid!r} bssid={bssid} "
                        f"drop={delta:.1f}dBm rssi={rssi}dBm"
                    )

            # ── Statistical RSSI anomaly (sustained jamming) ──────
            if self._rssi_history and rssi:
                z = _zscore(rssi, self._rssi_history)
                if z > 3.5 and rssi < _mean_safe(self._rssi_history) - 10:
                    self._emit(
                        f"RSSI_ANOMALY ssid={ssid!r} rssi={rssi}dBm "
                        f"mean={_mean_safe(self._rssi_history):.1f}dBm z={z:.2f}"
                    )

            # ── Security downgrade ────────────────────────────────
            if security and prev.get("security"):
                sec_rank = {"none": 0, "open": 0, "wep": 1, "wpa": 2, "wpa2": 3}
                old_rank = sec_rank.get(prev["security"].lower().split("-")[0], -1)
                new_rank = sec_rank.get(security.lower().split("-")[0], -1)
                if 0 <= new_rank < old_rank:
                    self._emit(
                        f"SECURITY_DOWNGRADE ssid={ssid!r} bssid={bssid} "
                        f"old={prev['security']!r} new={security!r}",
                        level="CRITICAL",
                    )

            # ── PHY mode downgrade (rate-forcing) ─────────────────
            phy_rank = {"a": 1, "b": 0, "g": 2, "n": 3, "ac": 4, "ax": 5}
            old_phy = phy_rank.get(str(prev.get("phy_mode", "")).lower(), -1)
            new_phy = phy_rank.get(str(phy_mode).lower(), -1)
            if 0 <= new_phy < old_phy:
                self._emit(
                    f"PHY_DOWNGRADE ssid={ssid!r} bssid={bssid} "
                    f"old={prev.get('phy_mode')!r} new={phy_mode!r}"
                )

            # ── Noise floor spike (RF jamming) ────────────────────
            if self._noise_history and noise:
                z = _zscore(noise, self._noise_history)
                if z > 3.5 and noise > _mean_safe(self._noise_history) + 10:
                    self._emit(
                        f"NOISE_SPIKE ssid={ssid!r} noise={noise}dBm "
                        f"mean={_mean_safe(self._noise_history):.1f}dBm z={z:.2f} snr={snr:.1f}dB"
                    )

        # ── Update state ──────────────────────────────────────────
        self._prev = {
            "ssid": ssid, "bssid": bssid, "channel": channel,
            "security": security, "mcs": mcs, "phy_mode": phy_mode,
            "rssi": rssi, "noise": noise,
        }
        if rssi:
            self._rssi_history.append(rssi)
        if noise:
            self._noise_history.append(noise)


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Network Interfaces & ARP
# ══════════════════════════════════════════════════════════════════

class NetworkInterfaceMonitor(BaseMonitor):
    """
    Tracks:
      • New/removed network interfaces (rogue USB-NIC / hotspot)
      • MAC address changes on existing interfaces (spoofing)
      • IP address changes (DHCP hijack)
      • ARP table anomalies (ARP poisoning / gratuitous ARP flood)
      • Promiscuous mode activation (sniffing)
      • Network throughput bursts (data exfiltration)
    """
    name = "NETIF"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_ifaces: Dict[str, Dict] = {}
        self._prev_arp: Dict[str, str] = {}          # ip → mac
        self._tx_history: Dict[str, Deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=BASELINE_WINDOW)
        )
        self._rx_history: Dict[str, Deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=BASELINE_WINDOW)
        )
        self._prev_io: Optional[Any] = None

    def _parse_ifconfig(self) -> Dict[str, Dict]:
        raw = _run(["ifconfig", "-a"])
        if not raw:
            return {}
        ifaces: Dict[str, Dict] = {}
        current = None
        for line in raw.splitlines():
            m = re.match(r"^(\S+):", line)
            if m:
                current = m.group(1)
                ifaces[current] = {"mac": "", "ips": [], "flags": ""}
                continue
            if current is None:
                continue
            # Flags
            fm = re.search(r"flags=\w+<([^>]*)>", line)
            if fm:
                ifaces[current]["flags"] = fm.group(1)
            # MAC (ether line)
            em = re.search(r"ether\s+([0-9a-f:]{17})", line)
            if em:
                ifaces[current]["mac"] = em.group(1)
            # IPv4
            im = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if im:
                ifaces[current]["ips"].append(im.group(1))
            # IPv6
            i6 = re.search(r"inet6\s+([0-9a-f:]+)", line)
            if i6:
                ifaces[current]["ips"].append(i6.group(1))
        return ifaces

    def _parse_arp(self) -> Dict[str, str]:
        raw = _run(["arp", "-an"])
        if not raw:
            return {}
        table: Dict[str, str] = {}
        for line in raw.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
            if m:
                table[m.group(1)] = m.group(2)
        return table

    def _check_promisc(self, name: str, flags: str) -> None:
        if "PROMISC" in flags:
            self._emit(
                f"PROMISC_MODE iface={name} flags={flags!r}",
                level="CRITICAL",
            )

    def poll(self) -> None:
        ifaces = self._parse_ifconfig()
        prev   = self._prev_ifaces

        # ── New interfaces ────────────────────────────────────────
        for name, info in ifaces.items():
            if name not in prev:
                if prev:                               # skip very first poll
                    # Only alert on real physical interfaces
                    if not APPLE_VIRTUAL_IFACES.match(name):
                        self._emit(
                            f"NEW_INTERFACE iface={name} mac={info['mac']!r} "
                            f"ips={info['ips']} flags={info['flags']!r}"
                        )
            else:
                old = prev[name]
                # Skip MAC/IP change checks for Apple virtual interfaces that
                # intentionally rotate their MAC (llw0, awdl0, utun*, anpi*, …)
                if APPLE_VIRTUAL_IFACES.match(name):
                    pass
                else:
                    # MAC change
                    if info["mac"] and old["mac"] and info["mac"] != old["mac"]:
                        self._emit(
                            f"MAC_CHANGE iface={name} "
                            f"old={old['mac']!r} new={info['mac']!r}",
                            level="CRITICAL",
                        )
                    # IP change
                    new_ips = set(info["ips"])
                    old_ips = set(old["ips"])
                    for ip in new_ips - old_ips:
                        self._emit(f"IP_ADDED iface={name} ip={ip!r}")
                    for ip in old_ips - new_ips:
                        self._emit(f"IP_REMOVED iface={name} ip={ip!r}")
                # Promisc check applies to all interfaces
                self._check_promisc(name, info["flags"])

        # ── Removed interfaces ────────────────────────────────────
        for name in set(prev) - set(ifaces):
            self._emit(f"INTERFACE_GONE iface={name}")

        # ── ARP anomalies ─────────────────────────────────────────
        arp = self._parse_arp()
        for ip, mac in arp.items():
            if ip in self._prev_arp and self._prev_arp[ip] != mac:
                self._emit(
                    f"ARP_CHANGE ip={ip} "
                    f"old_mac={self._prev_arp[ip]!r} new_mac={mac!r}",
                    level="CRITICAL",
                )
        self._prev_arp = arp

        # ── Network throughput burst detection ────────────────────
        if HAS_PSUTIL:
            io_now = psutil.net_io_counters(pernic=True)
            if self._prev_io:
                for nic, counters in io_now.items():
                    old = self._prev_io.get(nic)
                    if not old:
                        continue
                    tx_delta = counters.bytes_sent - old.bytes_sent
                    rx_delta = counters.bytes_recv - old.bytes_recv
                    for direction, delta, history in [
                        ("TX", tx_delta, self._tx_history[nic]),
                        ("RX", rx_delta, self._rx_history[nic]),
                    ]:
                        if len(history) < BASELINE_WINDOW // 2:
                            history.append(float(delta))
                            continue                   # still warming up
                        if history:
                            avg = _mean_safe(history)
                            if (avg > 0
                                    and delta > avg * NET_BURST_MULTIPLIER
                                    and delta > NET_BURST_MIN_BYTES):
                                self._emit(
                                    f"NET_BURST iface={nic} dir={direction} "
                                    f"delta={delta//1024}KB avg={avg//1024:.0f}KB "
                                    f"ratio={delta/avg:.1f}x"
                                )
                        history.append(float(delta))
            self._prev_io = io_now

        self._prev_ifaces = ifaces


# ══════════════════════════════════════════════════════════════════
#  MONITOR: USB Devices
# ══════════════════════════════════════════════════════════════════

class USBMonitor(BaseMonitor):
    """
    Tracks USB device attach/detach events.
    Flags of interest:
      • Any new HID device (keyboard, mouse — potential BadUSB)
      • New mass-storage device
      • New network adapter (USB-NIC / LTE dongle)
      • High-speed device suddenly appearing (USB 3.x DMA risk)
    """
    name = "USB"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_devices: Set[str] = set()
        self._initialized = False

    def _get_usb_devices(self) -> Dict[str, Any]:
        data = _run_json(["system_profiler", "SPUSBDataType", "-json"], timeout=15)
        if not data:
            return {}
        devices: Dict[str, Any] = {}
        self._walk_usb(data.get("SPUSBDataType", []), devices)
        return devices

    def _walk_usb(self, nodes: List[Any], out: Dict[str, Any]) -> None:
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if not isinstance(node, dict):
                continue
            name     = node.get("_name", "")
            vid      = node.get("vendor_id", "")
            pid      = node.get("product_id", "")
            serial   = node.get("serial_num", "")
            speed    = node.get("device_speed", "")
            bcd      = node.get("bcd_device", "")
            key      = f"{vid}:{pid}:{serial}:{name}"
            out[key] = {
                "name": name, "vid": vid, "pid": pid,
                "serial": serial, "speed": speed, "bcd": bcd,
            }
            # Recurse into hubs
            for child_key in ("_items", "items"):
                if child_key in node:
                    self._walk_usb(node[child_key], out)

    def _classify(self, info: Dict[str, Any]) -> str:
        name_low = info["name"].lower()
        if any(k in name_low for k in ("keyboard", "hid", "input")):
            return "HID"
        if any(k in name_low for k in ("storage", "disk", "flash", "drive")):
            return "STORAGE"
        if any(k in name_low for k in ("ethernet", "network", "rndis", "lan")):
            return "NETWORK"
        if any(k in name_low for k in ("webcam", "camera", "capture")):
            return "CAPTURE"
        if any(k in name_low for k in ("audio", "microphone", "speaker")):
            return "AUDIO"
        return "DEVICE"

    def poll(self) -> None:
        devices = self._get_usb_devices()
        current = set(devices.keys())

        if not self._initialized:
            self._prev_devices = current
            self._initialized  = True
            self.log.info(f"[{self.name}] Baseline: {len(current)} USB device(s) enumerated")
            return

        # ── Newly attached ────────────────────────────────────────
        for key in current - self._prev_devices:
            info  = devices[key]
            dtype = self._classify(info)
            sev   = "CRITICAL" if dtype in ("HID", "NETWORK") else "WARNING"
            self._emit(
                f"USB_ATTACH type={dtype} name={info['name']!r} "
                f"vid={info['vid']} pid={info['pid']} speed={info['speed']!r} "
                f"serial={info['serial']!r}",
                level=sev,
            )

        # ── Detached ──────────────────────────────────────────────
        for key in self._prev_devices - current:
            parts = key.split(":")
            self._emit(f"USB_DETACH vid={parts[0]} pid={parts[1]} serial={parts[2]!r}")

        self._prev_devices = current


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Bluetooth
# ══════════════════════════════════════════════════════════════════

class BluetoothMonitor(BaseMonitor):
    """
    Tracks:
      • New paired/connected BT devices
      • BT device disappearances
      • BT controller state (off/on cycling — indicator of BT jamming)
    """
    name = "BT"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_devices: Set[str] = set()
        self._bt_was_on: Optional[bool] = None
        self._initialized = False

    def _get_bt_devices(self) -> Tuple[bool, Set[str]]:
        data = _run_json(["system_profiler", "SPBluetoothDataType", "-json"], timeout=15)
        devices: Set[str] = set()
        bt_on  = False
        if not data:
            return bt_on, devices
        bt_data = data.get("SPBluetoothDataType", [{}])
        if not bt_data:
            return bt_on, devices
        bt_info = bt_data[0] if isinstance(bt_data, list) else bt_data
        state   = bt_info.get("controller_state", {})
        if isinstance(state, dict):
            bt_on = state.get("controller_bluetooth_enabled", "attrib_No") != "attrib_No"
        # Enumerate all sub-sections for device entries
        for section_key in ("device_connected", "device_not_connected", "device_title"):
            section = bt_info.get(section_key, {})
            if isinstance(section, list):
                for item in section:
                    if isinstance(item, dict):
                        for dev_name in item:
                            devices.add(dev_name)
            elif isinstance(section, dict):
                for dev_name in section:
                    devices.add(dev_name)
        return bt_on, devices

    def poll(self) -> None:
        bt_on, devices = self._get_bt_devices()

        # ── BT power state change ─────────────────────────────────
        if self._bt_was_on is not None and bt_on != self._bt_was_on:
            state_str = "ENABLED" if bt_on else "DISABLED"
            self._emit(f"BT_STATE_CHANGE new_state={state_str}")
        self._bt_was_on = bt_on

        if not self._initialized:
            self._prev_devices = devices
            self._initialized  = True
            self.log.info(f"[{self.name}] Baseline: {len(devices)} BT device(s)")
            return

        for dev in devices - self._prev_devices:
            self._emit(f"BT_DEVICE_APPEARED name={dev!r}")
        for dev in self._prev_devices - devices:
            self._emit(f"BT_DEVICE_GONE name={dev!r}")

        self._prev_devices = devices


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Thunderbolt / PCIe (DMA attack surface)
# ══════════════════════════════════════════════════════════════════

class ThunderboltMonitor(BaseMonitor):
    """
    Tracks Thunderbolt / PCIe device events.
    Thunderbolt devices have direct memory access (DMA) capability and are
    a well-known physical attack vector (Thunderspy, Thunderclap, etc.).
    """
    name = "TBT"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_devices: Set[str] = set()
        self._initialized = False

    def _get_tbt_devices(self) -> Set[str]:
        data = _run_json(["system_profiler", "SPThunderboltDataType", "-json"], timeout=15)
        if not data:
            return set()
        devices: Set[str] = set()
        self._walk(data.get("SPThunderboltDataType", []), devices)
        return devices

    def _walk(self, nodes: Any, out: Set[str]) -> None:
        if isinstance(nodes, list):
            for n in nodes:
                self._walk(n, out)
        elif isinstance(nodes, dict):
            name = nodes.get("_name", "")
            vid  = nodes.get("vendor_name", "")
            uid  = nodes.get("uid", nodes.get("device_id", ""))
            if name:
                out.add(f"{name}|{vid}|{uid}")
            for v in nodes.values():
                if isinstance(v, (list, dict)):
                    self._walk(v, out)

    def poll(self) -> None:
        devices = self._get_tbt_devices()

        if not self._initialized:
            self._prev_devices = devices
            self._initialized  = True
            self.log.info(f"[{self.name}] Baseline: {len(devices)} Thunderbolt device(s)")
            return

        for dev in devices - self._prev_devices:
            parts = dev.split("|")
            self._emit(
                f"TBT_ATTACH name={parts[0]!r} vendor={parts[1]!r}",
                level="CRITICAL",           # TBT attach is always high-priority
            )
        for dev in self._prev_devices - devices:
            parts = dev.split("|")
            self._emit(f"TBT_DETACH name={parts[0]!r} vendor={parts[1]!r}")

        self._prev_devices = devices


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Audio Devices
# ══════════════════════════════════════════════════════════════════

class AudioMonitor(BaseMonitor):
    """
    Tracks unexpected audio device appearances (covert microphone attach,
    virtual audio loopback drivers, etc.)
    """
    name = "AUDIO"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_devices: Set[str] = set()
        self._initialized = False

    def _get_audio_devices(self) -> Set[str]:
        data = _run_json(["system_profiler", "SPAudioDataType", "-json"], timeout=12)
        if not data:
            return set()
        devices: Set[str] = set()
        for item in data.get("SPAudioDataType", []):
            if isinstance(item, dict):
                for k, v in item.items():
                    if k.startswith("_"):
                        continue
                    if isinstance(v, dict):
                        devices.add(k)
        return devices

    def poll(self) -> None:
        devices = self._get_audio_devices()
        if not self._initialized:
            self._prev_devices = devices
            self._initialized  = True
            return

        for dev in devices - self._prev_devices:
            self._emit(f"AUDIO_DEVICE_ADDED name={dev!r}")
        for dev in self._prev_devices - devices:
            self._emit(f"AUDIO_DEVICE_REMOVED name={dev!r}")

        self._prev_devices = devices


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Displays
# ══════════════════════════════════════════════════════════════════

class DisplayMonitor(BaseMonitor):
    """
    Tracks external display attach/detach events (video interposer devices,
    HDMI capture dongles, display-sniffing hardware).
    """
    name = "DISPLAY"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_displays: Set[str] = set()
        self._initialized = False

    def _get_displays(self) -> Set[str]:
        data = _run_json(["system_profiler", "SPDisplaysDataType", "-json"], timeout=12)
        if not data:
            return set()
        displays: Set[str] = set()
        for item in data.get("SPDisplaysDataType", []):
            if isinstance(item, dict):
                name = item.get("_name", "")
                for disp in item.get("spdisplays_ndrvs", []):
                    if isinstance(disp, dict):
                        dname = disp.get("_name", "")
                        displays.add(f"{name}|{dname}")
        return displays

    def poll(self) -> None:
        displays = self._get_displays()
        if not self._initialized:
            self._prev_displays = displays
            self._initialized   = True
            return

        for d in displays - self._prev_displays:
            self._emit(f"DISPLAY_ATTACHED identifier={d!r}")
        for d in self._prev_displays - displays:
            self._emit(f"DISPLAY_DETACHED identifier={d!r}")

        self._prev_displays = displays


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Power / Battery
# ══════════════════════════════════════════════════════════════════

class PowerMonitor(BaseMonitor):
    """
    Tracks:
      • Power source switches (AC ↔ Battery — indicates physical access)
      • Sudden battery drain (parasitic device drawing power)
      • Multiple charge cycles in short window (test-bed indicator)
    """
    name = "POWER"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_source: Optional[str] = None
        self._prev_pct: Optional[float]  = None
        self._drain_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)

    def _get_power(self) -> Dict[str, Any]:
        raw = _run(["pmset", "-g", "batt"])
        if not raw:
            return {}
        result: Dict[str, Any] = {}
        for line in raw.splitlines():
            if "AC Power" in line or "Battery Power" in line:
                result["source"] = "AC" if "AC Power" in line else "Battery"
            m = re.search(r"(\d+)%", line)
            if m:
                result["pct"] = float(m.group(1))
            if "discharging" in line.lower():
                result["charging"] = False
            elif "charging" in line.lower() or "charged" in line.lower():
                result["charging"] = True
        return result

    def poll(self) -> None:
        info = self._get_power()
        if not info:
            return

        source = info.get("source")
        pct    = info.get("pct")

        if source and self._prev_source and source != self._prev_source:
            self._emit(
                f"POWER_SOURCE_CHANGE old={self._prev_source!r} new={source!r}"
            )

        if pct is not None and self._prev_pct is not None:
            delta = self._prev_pct - pct          # positive = drain
            if delta > 5 and not info.get("charging"):
                self._emit(
                    f"RAPID_BATTERY_DRAIN delta={delta:.1f}% "
                    f"current={pct:.0f}%"
                )
            if self._drain_history:
                z = _zscore(delta, self._drain_history)
                if z > 4 and delta > 0:
                    self._emit(
                        f"BATTERY_DRAIN_ANOMALY delta={delta:.1f}% z={z:.2f}"
                    )
            self._drain_history.append(delta)

        self._prev_source = source
        self._prev_pct    = pct


# ══════════════════════════════════════════════════════════════════
#  MONITOR: Thermal / Fan (via powermetrics — requires sudo)
# ══════════════════════════════════════════════════════════════════

class ThermalMonitor(BaseMonitor):
    """
    Tracks CPU/GPU temperature spikes and fan ramp events.
    A sudden thermal spike with no corresponding workload can indicate
    hardware implants drawing power or covert compute activity.
    """
    name = "THERMAL"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._temp_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._prev_temp: Optional[float] = None
        self._has_powermetrics = shutil.which("powermetrics") is not None

    def _get_temperature(self) -> Optional[float]:
        if not self._has_powermetrics:
            return None
        # Single 100ms sample is enough for a spot read
        raw = _run(
            ["powermetrics", "-n", "1", "-i", "100",
             "--samplers", "smc", "--format", "plist"],
            timeout=10,
        )
        if not raw:
            return None
        # Extract die temperature from plist text (avoid full plist parse)
        m = re.search(r"<key>CPU die temperature</key>\s*<real>([\d.]+)</real>", raw)
        if m:
            return float(m.group(1))
        # Fallback: look for any temperature-like value
        m = re.search(r"temperature[^<]*<real>([\d.]+)</real>", raw, re.IGNORECASE)
        if m:
            return float(m.group(1))
        return None

    def poll(self) -> None:
        temp = self._get_temperature()
        if temp is None:
            return

        if self._prev_temp is not None:
            delta = temp - self._prev_temp
            if delta >= THERMAL_JUMP_THRESHOLD:
                self._emit(
                    f"THERMAL_SPIKE delta=+{delta:.1f}°C current={temp:.1f}°C"
                )
            if self._temp_history:
                z = _zscore(temp, self._temp_history)
                if z > 3.5 and delta > 5:
                    self._emit(
                        f"THERMAL_ANOMALY temp={temp:.1f}°C "
                        f"mean={_mean_safe(self._temp_history):.1f}°C z={z:.2f}"
                    )

        self._temp_history.append(temp)
        self._prev_temp = temp


# ══════════════════════════════════════════════════════════════════
#  MONITOR: CPU / Memory / Disk I/O (psutil)
# ══════════════════════════════════════════════════════════════════

class SystemResourceMonitor(BaseMonitor):
    """
    Baseline-aware detection of:
      • CPU usage spikes (covert compute / crypto mining)
      • Memory jumps (large injection / exfiltration buffer)
      • Disk I/O bursts (rapid exfiltration / covert write)
    """
    name = "SYSRES"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._cpu_history:  Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._mem_history:  Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._disk_r_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._disk_w_history: Deque[float] = collections.deque(maxlen=BASELINE_WINDOW)
        self._prev_disk: Optional[Any] = None
        self._prev_cpu: Optional[float] = None
        self._prev_mem: Optional[float] = None

    def poll(self) -> None:
        if not HAS_PSUTIL:
            return

        # ── CPU ───────────────────────────────────────────────────
        cpu = psutil.cpu_percent(interval=None)
        if self._prev_cpu is not None:
            delta_cpu = cpu - self._prev_cpu
            if delta_cpu >= CPU_SPIKE_THRESHOLD:
                self._emit(
                    f"CPU_SPIKE delta=+{delta_cpu:.1f}% current={cpu:.1f}%"
                )
            if self._cpu_history:
                z = _zscore(cpu, self._cpu_history)
                if z > 4 and cpu > 80:
                    self._emit(
                        f"CPU_ANOMALY cpu={cpu:.1f}% "
                        f"mean={_mean_safe(self._cpu_history):.1f}% z={z:.2f}"
                    )
        self._cpu_history.append(cpu)
        self._prev_cpu = cpu

        # ── Memory ────────────────────────────────────────────────
        mem_pct = psutil.virtual_memory().percent
        if self._prev_mem is not None:
            delta_mem = mem_pct - self._prev_mem
            if delta_mem >= MEM_JUMP_THRESHOLD:
                self._emit(
                    f"MEMORY_JUMP delta=+{delta_mem:.1f}% current={mem_pct:.1f}%"
                )
        self._mem_history.append(mem_pct)
        self._prev_mem = mem_pct

        # ── Disk I/O ──────────────────────────────────────────────
        disk_io = psutil.disk_io_counters()
        if disk_io and self._prev_disk:
            r_delta = disk_io.read_bytes  - self._prev_disk.read_bytes
            w_delta = disk_io.write_bytes - self._prev_disk.write_bytes
            for direction, delta, history in [
                ("READ",  r_delta, self._disk_r_history),
                ("WRITE", w_delta, self._disk_w_history),
            ]:
                if len(history) < BASELINE_WINDOW // 2:
                    history.append(float(delta))
                    continue                           # still warming up
                if history:
                    avg = _mean_safe(history)
                    if (avg > 0
                            and delta > avg * DISK_IO_MULTIPLIER
                            and delta > DISK_IO_MIN_BYTES):
                        self._emit(
                            f"DISK_IO_BURST dir={direction} "
                            f"delta={delta//1024}KB avg={avg//1024:.0f}KB "
                            f"ratio={delta/avg:.1f}x"
                        )
                history.append(float(delta))
        self._prev_disk = disk_io


# ══════════════════════════════════════════════════════════════════
#  MONITOR: IOKit Hardware Registry (kernel driver loads)
# ══════════════════════════════════════════════════════════════════

class IOKitMonitor(BaseMonitor):
    """
    Monitors the IOKit hardware registry for unexpected driver / kext
    loads that could indicate hardware implants or rootkit activity.
    Tracks the set of loaded IOKit service names.
    """
    name = "IOKIT"

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._prev_services: Set[str] = set()
        self._initialized = False

    def _get_services(self) -> Set[str]:
        raw = _run(["ioreg", "-l", "-w", "0", "-p", "IOService"], timeout=20)
        if not raw:
            return set()
        services: Set[str] = set()
        for line in raw.splitlines():
            m = re.search(r'<class\s+(\w+),', line)
            if m:
                services.add(m.group(1))
        return services

    def poll(self) -> None:
        services = self._get_services()
        if not self._initialized:
            self._prev_services = services
            self._initialized   = True
            self.log.info(f"[{self.name}] Baseline: {len(services)} IOKit service class(es)")
            return

        for svc in services - self._prev_services:
            self._emit(f"IOKIT_NEW_SERVICE class={svc!r}")
        for svc in self._prev_services - services:
            self._emit(f"IOKIT_SERVICE_GONE class={svc!r}")

        self._prev_services = services


# ══════════════════════════════════════════════════════════════════
#  MONITOR: System Log (hardware kernel events)
# ══════════════════════════════════════════════════════════════════

class KernelLogMonitor(BaseMonitor):
    """
    Tails the macOS unified log for physical-layer kernel messages:
      • Kernel panics
      • IOKit attach/detach error messages
      • Suspicious hardware-level assertions
    """
    name = "KLOG"

    # Patterns that indicate physical-layer events in kernel logs
    PATTERNS = [
        (re.compile(r"kernel\[0\].*panic",       re.IGNORECASE), "KERNEL_PANIC",   "CRITICAL"),
        (re.compile(r"IOKit.*attach",             re.IGNORECASE), "IOKIT_ATTACH",   "WARNING"),
        (re.compile(r"IOKit.*terminate",          re.IGNORECASE), "IOKIT_TERM",     "WARNING"),
        # Tightened: skip internal IOKit ref-count churn ("Detaching, ref count = N")
        # Only fire on real device-level USB events from the Apple USB stack
        (re.compile(
            r"AppleUSBDevice.*start|USB.*[Dd]evice.*attach"
            r"|USB.*[Dd]evice.*connected|New USB device found",
            re.IGNORECASE,
        ), "USB_KLOG_ATTACH", "WARNING"),
        (re.compile(
            r"AppleUSBDevice.*terminated|USB.*[Dd]evice.*disconnect"
            r"|USB.*[Dd]evice.*detach|USB.*[Dd]evice.*removed",
            re.IGNORECASE,
        ), "USB_KLOG_DETACH", "WARNING"),
        (re.compile(r"Bluetooth.*error",          re.IGNORECASE), "BT_ERROR",       "WARNING"),
        (re.compile(r"ARP.*conflict",             re.IGNORECASE), "ARP_CONFLICT",   "CRITICAL"),
        (re.compile(r"en\d.*promiscuous",         re.IGNORECASE), "NET_PROMISC",    "CRITICAL"),
        (re.compile(r"[Ii]nterface.*down",        re.IGNORECASE), "IFACE_DOWN",     "WARNING"),
        (re.compile(r"(?:PCIe|PCI).*error",       re.IGNORECASE), "PCIE_ERROR",     "WARNING"),
        (re.compile(r"IOMMU.*violation|DMA.*err", re.IGNORECASE), "DMA_VIOLATION",  "CRITICAL"),
        (re.compile(r"SMC.*error|SMC.*fail",      re.IGNORECASE), "SMC_ERROR",      "WARNING"),
        (re.compile(r"NVMe.*error|disk.*error",   re.IGNORECASE), "STORAGE_ERROR",  "WARNING"),
    ]

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(logger)
        self._last_check: Optional[str] = None

    def poll(self) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cmd = [
            "log", "show",
            "--style", "syslog",
            "--info",
            "--last", "30s",          # look at last 30 seconds of logs
            "--predicate",
            '(subsystem == "com.apple.iokit" OR category == "Hardware" '
            'OR process == "kernel" OR subsystem == "com.apple.network.statistics")',
        ]
        raw = _run(cmd, timeout=15)
        if not raw:
            return
        seen: Set[str] = set()
        for line in raw.splitlines():
            for pattern, tag, level in self.PATTERNS:
                if pattern.search(line):
                    # Deduplicate identical lines within one poll
                    sig = f"{tag}:{line[:120]}"
                    if sig not in seen:
                        seen.add(sig)
                        snippet = line.strip()[:200]
                        self._emit(f"{tag} log={snippet!r}", level=level)


# ══════════════════════════════════════════════════════════════════
#  SCAN ENGINE
# ══════════════════════════════════════════════════════════════════

class RealWorldEngine:
    """Orchestrates all monitors and runs them on a fixed poll interval."""

    def __init__(self, interval: int, logger: logging.Logger) -> None:
        self.interval = interval
        self.log      = logger
        self._running = True
        self._lock    = threading.Lock()

        self._monitors: List[BaseMonitor] = [
            WiFiMonitor(logger),
            NetworkInterfaceMonitor(logger),
            USBMonitor(logger),
            BluetoothMonitor(logger),
            ThunderboltMonitor(logger),
            AudioMonitor(logger),
            DisplayMonitor(logger),
            PowerMonitor(logger),
            ThermalMonitor(logger),
            SystemResourceMonitor(logger),
            IOKitMonitor(logger),
            KernelLogMonitor(logger),
        ]

        # Stagger slow monitors to avoid I/O pileup
        self._slow_monitors: Set[str] = {
            "IOKIT", "KLOG", "USB", "BT", "TBT", "DISPLAY", "AUDIO"
        }
        self._slow_divisor = 4          # run slow monitors every N cycles
        self._cycle        = 0

    def _poll_monitor(self, monitor: BaseMonitor) -> None:
        try:
            monitor.poll()
        except Exception as exc:
            self.log.error(
                f"[ENGINE] Monitor {monitor.name} raised: {type(exc).__name__}: {exc}"
            )

    def _run_cycle(self) -> None:
        threads = []
        for monitor in self._monitors:
            is_slow = monitor.name in self._slow_monitors
            if is_slow and self._cycle % self._slow_divisor != 0:
                continue
            t = threading.Thread(
                target=self._poll_monitor,
                args=(monitor,),
                daemon=True,
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=25)          # hard timeout per poll cycle

    def run(self) -> None:
        self.log.info(
            f"[ENGINE] Poll interval={self.interval}s | "
            f"Monitors={len(self._monitors)} | "
            f"psutil={'available' if HAS_PSUTIL else 'MISSING — install with: pip install psutil'}"
        )
        try:
            while self._running:
                start = time.monotonic()
                self._run_cycle()
                self._cycle += 1
                elapsed = time.monotonic() - start
                sleep_for = max(0, self.interval - elapsed)
                time.sleep(sleep_for)
        except KeyboardInterrupt:
            pass
        finally:
            self.log.info("[ENGINE] Shutdown requested — stopping.")

    def stop(self) -> None:
        self._running = False


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def _check_platform() -> None:
    if platform.system() != "Darwin":
        print(
            "[WARNING] This edition targets macOS (Darwin). "
            "Some monitors will be unavailable on other platforms.",
            file=sys.stderr,
        )


def _signal_handler(engine: RealWorldEngine):
    def _handler(signum, frame):
        engine.stop()
    return _handler


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="the_real_world",
        description="Physical layer anomaly detection engine",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Poll interval in seconds (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Also print log output to stdout",
    )
    args = parser.parse_args()

    _check_platform()

    if not HAS_PSUTIL:
        print(
            "[WARNING] psutil not found. Install with: pip install psutil\n"
            "         CPU/Memory/Disk/Network monitors will be disabled.",
            file=sys.stderr,
        )

    logger = _setup_logger(args.verbose)
    engine = RealWorldEngine(interval=args.interval, logger=logger)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _signal_handler(engine))

    engine.run()


if __name__ == "__main__":
    main()
