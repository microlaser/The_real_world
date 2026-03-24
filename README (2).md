# The Real World
### Physical Layer Anomaly Detection for macOS

```
╔══════════════════════════════════════════════════════════════════╗
║                       THE REAL WORLD                            ║
║           Physical Layer Anomaly Detection Engine               ║
║                     macOS Edition v1.0.3                        ║
╚══════════════════════════════════════════════════════════════════╝
```

> *"You can fake a screenshot. You cannot fake the kernel."*

The Real World silently monitors the physical layer of a Mac and logs all anomalies with UTC timestamps to `/var/log/the_real_world.log`. It does not block, alert, or interfere — it only records.

---

## Why These Logs Cannot Be Faked

This is the core principle of the tool. Every metric it collects originates **below the application layer** — at the hardware, kernel, and driver level. By the time data reaches any user-space application, it is already too late to intercept and forge it. The Real World reads directly from the sources that user-space software cannot touch.

### The Trust Hierarchy of a Mac

```
┌─────────────────────────────────────────────────────┐
│        USER SPACE  (apps, browsers, malware)        │  ← can be faked
├─────────────────────────────────────────────────────┤
│        KERNEL / XNU  (macOS core)                   │  ← cannot be faked
├─────────────────────────────────────────────────────┤
│        IOKit  (hardware driver registry)            │  ← cannot be faked
├─────────────────────────────────────────────────────┤
│        SMC / PMU  (power, thermal, sensors)         │  ← cannot be faked
├─────────────────────────────────────────────────────┤
│        PHYSICAL HARDWARE                            │  ← ground truth
└─────────────────────────────────────────────────────┘
```

The Real World reads exclusively from the kernel layer and below. Here is what that means for each monitor:

---

### 1. WiFi — `airport -I` (Apple80211 private framework)

The `airport` binary reads directly from the **802.11 hardware radio driver** via Apple's private `Apple80211` framework. This is the same interface the kernel itself uses to control the WiFi chip.

What this means:
- The **BSSID** (access point hardware address) is reported by the radio chip firmware, not by any software on your machine. A rogue access point (evil twin) cannot instruct your chip to lie about what BSSID it sees — it can only broadcast a different one, which is exactly what the tool detects.
- **RSSI and noise floor** are analog measurements taken by the radio's physical receiver. They reflect real electromagnetic conditions. No software running on the Mac can alter these readings.
- **Security mode** (WPA2, WPA, OPEN) is negotiated at the 802.11 association layer. A downgrade is a physical-layer event recorded by the driver before any encryption stack is involved.
- **PHY mode** (802.11a/b/g/n/ac/ax) is determined by the hardware handshake between your radio and the access point. It cannot be spoofed by software on either end without the other party detecting it.

---

### 2. IOKit Hardware Registry — `ioreg`

IOKit is Apple's kernel framework for hardware device management. Every physical device connected to a Mac — USB, Thunderbolt, PCIe, internal sensors — exists as an entry in the IOKit registry. The registry is maintained exclusively by the kernel and its drivers.

What this means:
- A new entry in IOKit means a **kernel driver loaded for a real piece of hardware**. You cannot create an IOKit service class without kernel-level code signing and driver entitlements. User-space malware cannot inject entries into the IOKit registry.
- If a new USB device appears, it is because the USB controller's hardware interrupt fired, the kernel's USB stack enumerated it, and IOKit registered the driver. This chain is entirely in the kernel. The log entry is evidence that something physically connected to the machine.
- Thunderbolt devices have **DMA (Direct Memory Access)** capability. IOKit is the only place this is recorded. A Thunderbolt attach event in this log means a device with access to raw system memory was physically plugged in.

---

### 3. USB Device Inventory — `system_profiler SPUSBDataType`

`system_profiler` aggregates USB device information directly from IOKit. Every device entry includes a **Vendor ID (VID)** and **Product ID (PID)** that are baked into the device's USB descriptor by its manufacturer. These cannot be changed by software on your Mac.

What this means:
- A BadUSB device (a USB device that masquerades as a keyboard to inject keystrokes) will appear in this log with its real hardware VID:PID the moment it is plugged in — before it types a single character. The log is forensic evidence of physical access.
- The **attach timestamp** is recorded by the kernel's USB interrupt handler. It reflects the moment electricity began flowing through the USB port. It cannot be backdated by any software running on the machine.

---

### 4. ARP Table — `arp -an`

The ARP (Address Resolution Protocol) table maps IP addresses to MAC addresses on the local network. It is maintained by the kernel's networking stack and populated by frames arriving at the **network interface hardware**.

What this means:
- An ARP table change means the kernel received a real ARP frame from the physical network. This is a hardware-level event. No software on your Mac can inject an entry without sending an actual Ethernet frame through the network stack.
- An **ARP poisoning attack** — where an attacker maps a router's IP to their own MAC to intercept traffic — is detectable here because it produces a real ARP frame that the kernel processes and records. The attacker has no way to hide this from the kernel without also owning the kernel.
- The **old MAC and new MAC** are both logged, providing a before/after record of exactly whose hardware address replaced whose.

---

### 5. Network Interface State — `ifconfig -a`

`ifconfig` reads network interface state directly from the kernel's network interface layer (BSD socket layer in XNU). MAC addresses, link state, and IP assignments all come from the kernel.

What this means:
- A **MAC address change** on a physical interface (e.g., `en0`) is recorded by the kernel when it happens. The kernel owns the network stack — user-space software can request a MAC change via `ifconfig`, but that request is logged as a system call and the resulting change is immediately visible in the kernel's interface table.
- **Promiscuous mode** is a kernel-level flag set on a network interface. When active, the kernel passes all frames to the sniffing process regardless of destination MAC. The flag cannot be set without a privileged system call, and it is immediately visible in the interface flags. The log entry is evidence that someone placed a sniffer on the network interface.
- **New interface appearances** are kernel events. A new `en2` or `utun4` means the kernel registered a new network interface — either because hardware was attached or because a VPN or tunneling process made a privileged system call to create one.

---

### 6. Thermal and Power — `powermetrics` / `pmset`

`powermetrics` reads from the **System Management Controller (SMC)** — a dedicated coprocessor on every Mac that is entirely separate from the main CPU. The SMC manages power, thermal sensors, fans, and battery state. It runs its own firmware and communicates with the kernel via a dedicated low-speed bus.

What this means:
- CPU die temperature is measured by **on-die thermal sensors** read by the SMC. No software can falsify this. A temperature spike means transistors are actually switching faster and generating real heat.
- A **power source switch** (AC to battery or back) is a hardware interrupt from the SMC to the kernel. It reflects the physical state of the power connector. It cannot be faked by software.
- **Rapid battery drain** with no corresponding workload is a physically-grounded anomaly. Energy is conserved — if the battery is draining, something is drawing power. The SMC measures this at the hardware level.

---

### 7. Kernel Log — `log show` with hardware predicates

The macOS unified logging system captures kernel messages written by drivers via `os_log`. These messages originate in kernel space and are written before any user-space process can observe them.

What this means:
- A kernel panic, PCIe error, or DMA violation in this log is a message written by kernel code in response to a real hardware event. User-space processes cannot write to the kernel log subsystem or forge entries under the `kernel[0]` process.
- **DMA violations** and **IOMMU errors** are recorded when a device attempts to access memory outside its permitted range — a known hardware implant and Thunderbolt attack technique. These are caught at the silicon level by the IOMMU before any software can respond.

---

## What the Logs Prove

When a security incident is being investigated, the logs produced by The Real World provide **hardware-grounded evidence** that is independent of anything running in user space:

| Log Entry | What It Proves |
|---|---|
| `USB_ATTACH type=HID` | A physical device was plugged into a USB port at this exact time |
| `TBT_ATTACH` | A DMA-capable device was connected to a Thunderbolt port |
| `BSSID_CHANGE` | The machine associated with a different physical access point |
| `SECURITY_DOWNGRADE` | The 802.11 association security was weakened at the radio level |
| `ARP_CHANGE` | A real Ethernet frame was received that remapped a network address |
| `MAC_CHANGE` (en0) | The kernel's network interface MAC was changed via a privileged syscall |
| `PROMISC_MODE` | A process placed a physical network interface into promiscuous mode |
| `IOKIT_NEW_SERVICE` | The kernel loaded a driver for a new hardware device |
| `THERMAL_SPIKE` | The CPU's on-die sensors recorded a real temperature increase |
| `POWER_SOURCE_CHANGE` | The SMC hardware detected a physical power state change |

None of these entries can be written to the log by user-space software. They are all downstream consequences of real physical events that the kernel observed and recorded first.

---

## Install

```bash
pip3 install psutil
chmod +x the_real_world.py
```

## Run

```bash
# Full access (recommended)
sudo python3 the_real_world.py

# Verbose — also prints to stdout
sudo python3 the_real_world.py --verbose

# Custom poll interval
sudo python3 the_real_world.py --interval 10
```

## View Logs

```bash
sudo tail -f /var/log/the_real_world.log
```

Falls back to `~/the_real_world.log` if run without `sudo`.

---

## Requirements

- macOS 12 Monterey or later (tested on Sonoma 14.x and Sequoia 15.x)
- Python 3.9+
- `pip install psutil`
- `sudo` for full sensor access (thermal, kernel log, SMC)

---

## Porting to Linux

All `psutil`-based monitors are already cross-platform. The macOS-specific binaries (`airport`, `system_profiler`, `ioreg`, `pmset`, `powermetrics`) each have Linux equivalents (`iw`, `lsusb`, `lspci`, `/sys/class/power_supply/`, `lm-sensors`). The physical-layer trust properties described above apply equally on Linux — the kernel is still the ground truth, and the log entries are still hardware-grounded.

---

## License

MIT
