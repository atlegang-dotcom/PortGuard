# PortGuard

A command-line tool that detects TCP port scanning against your device. It monitors incoming SYN packets and tracks how many distinct ports each source IP touches within a rolling time window — the more ports touched in a shorter window, the more aggressive the scan is classified as.

Some legitimate applications do check for open ports as part of normal operation — checking for port 443 to see if you're running a web server, or port 22 before attempting SSH. This kind of legitimate check typically touches only one or two ports, rarely more than 3–5, because a normal application already knows which specific service it needs and has no reason to probe broadly. A device touching many distinct ports on you in a short window has no such legitimate reason — that pattern is reconnaissance, not service discovery, and is the behavior this tool is built to catch.

---

## Requirements

- Python 3.10+
- [scapy](https://scapy.net/)
- **Npcap** (Windows only) — see below for why this is required
- Root (Linux/Mac) or, depending on your Npcap install configuration, Administrator (Windows) privileges to run a live capture

### Why Npcap is required

PortGuard captures raw packets directly off your network interfaces in order to see incoming SYN traffic before your operating system's own TCP stack has processed it. Reading traffic at this level is a privileged operation, and on Windows, Python has no built-in way to do it — the OS doesn't expose raw packet capture through a normal socket. **Npcap** is the driver that provides this capability; it's the same driver Wireshark and Nmap rely on for the same reason. `pip install scapy` only installs the Python library that talks to this driver — it does not install the driver itself, so Npcap must be downloaded and installed separately from [npcap.com](https://npcap.com) before PortGuard can run.

During installation, select **"Install Npcap in WinPcap API-compatible Mode"** if offered — this is the mode scapy (and most other packet-capture libraries) expect.

**On privileges:** Npcap has an install-time option, "Restrict Npcap driver's access to Administrators only." Whether PortGuard needs to be run from an Administrator terminal depends on whether that option was enabled when Npcap was installed on your machine — it is not a fixed requirement of PortGuard itself, but of how Npcap was configured. If you get a permissions-related error on startup, try running from an elevated (Administrator) terminal.

Linux and Mac don't need Npcap — raw packet capture is available natively via `libpcap`, and running with `sudo` is sufficient.

---

## Installation & Usage

1. **Clone the repository**
   ```
   git clone <your-repo-url>
   cd portguard
   ```

2. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```
   (Windows users: also install Npcap separately from [npcap.com](https://npcap.com) — see Requirements above. `pip install` does not install it for you.)

3. **View available options**
   ```
   python -m port_guard.main -h
   ```
   This prints the full list of flags, their defaults, and short descriptions — useful to check before your first run, and any time you forget a flag name.

4. **Run**
   ```
   python -m port_guard.main
   ```
   With no arguments, PortGuard runs with its defaults: threshold `15`, window `10.0` seconds, no allowlist, no log file, listening across every interface on the machine. Add flags to override any of these:

   | Flag | Description | Default |
   |---|---|---|
   | `-n`, `--threshold` | distinct ports required to trigger an alert | `15` |
   | `-w`, `--window` | tracking window, in seconds | `10.0` |
   | `--allowlist` | path to a file of known-safe IPs, one per line | none |
   | `--log` | path to append JSON-lines alerts to | none |

   Example, more sensitive threshold with logging enabled:
   ```
   python -m port_guard.main -n 5 -w 5 --log alerts.jsonl
   ```

   The tool runs continuously once started — it does not exit on its own. Press `Ctrl+C` to stop it.

5. **(Optional) Run the test suite**
   ```
   pytest -v
   ```

---

## Module Walkthrough

### 1. `detector.py`

The core detection logic — two functions.

**`is_scan(port_count, threshold)`**
Decides whether a distinct-port count within a time window counts as a scan. Takes:
- `port_count` — number of distinct ports scanned within the tracking window
- `threshold` — the minimum distinct-port count that counts as scanning behaviour

The threshold is set by the user (admin) depending on what they consider a potential threat: if `port_count` is greater than or equal to `threshold`, the function returns `True` (a valid reconnaissance scan detected), otherwise `False`.

A normal service would typically use no more than 3–5 ports on a device — most legitimate applications touch far fewer, since they already know which specific service they need and have no reason to probe broadly. That said, some legitimate multi-service applications (e.g. a web server that also handles SSH-based messaging and FTP-based media storage) could reasonably use several ports at once — the threshold is left tunable by the user rather than hardcoded, to account for this.

**`classify_severity(port_count, window_seconds)`**
Classifies how aggressive a detected scan is, based on **ports-per-second** — not raw port count and not raw time independently, but the ratio of the two. Takes:
- `port_count` — distinct ports scanned within the window
- `window_seconds` — the amount of time it took to scan them

Severity is classified into three categories using `port_count / window_seconds` = ports/second:
- **aggressive** — a high rate: many ports scanned in a short space of time
- **moderate** — a medium rate
- **slow** — a low rate: ports scanned over a comparatively long period

The time taken for a scan does not rule out malicious intent — a slow scan simply reflects a more careful attacker. Note, however, that a sufficiently slow scan (spread beyond the configured tracking window) may not be classified as a scan at all, since PortGuard only evaluates activity within its rolling window — see **Limitations**.

`detector.py` acts as the decision-making module: given a threshold and the number of ports hit, it determines whether a threat exists, and how urgent that threat is based on how quickly the ports were hit.

### 2. `allowlist.py`

Two functions, used to suppress false positives.

**`load_allowlist(filepath)`**
Loads a newline-separated file of IP addresses into a set. Takes `filepath`, the path to the file containing IPs considered not a threat to the system.

**`is_allowlisted(ip, allowlist)`**
Checks whether `ip` is present in `allowlist`. Takes:
- `ip` — the address being checked
- `allowlist` — the set of addresses known to be safe

`allowlist.py` acts as a filter: it prevents the system from flagging non-malicious scans (e.g. your own monitoring tools) as threats, and also allows a more aggressive (tighter) threshold to be used elsewhere, since known-safe IPs can be explicitly excluded rather than relied upon to stay under a looser threshold.

### 3. `alerting.py`

Three functions, responsible for building, formatting, and logging alerts — never for detection logic itself.

**`build_alert(src_ip, ports, severity, window_seconds)`**
Assembles a structured alert dictionary from a detected scan. Takes:
- `src_ip` — the address that carried out the scan
- `ports` — the set of ports it hit
- `severity` — `"aggressive"`, `"moderate"`, or `"slow"`, from `classify_severity`
- `window_seconds` — the time window used for detection
- `interface` - the interface the threat was detected from

**`format_alert_text(alert)`**
Renders an alert dictionary as a human-readable, one-line string suitable for printing to the terminal in real time. Takes `alert`, the dictionary produced by `build_alert`.

**`log_alert_json(alert, filepath)`**
Appends an alert to a JSON-lines log file (one JSON object per line). Takes:
- `alert` — the alert dictionary
- `filepath` — the file to append to

Saving alerts to a log file is optional, controlled via command-line arguments — printing to the terminal always happens; logging to disk only happens if a log path is provided.

### 4. `tracker.py`

A single class, `PortActivityTracker`, responsible for recording and maintaining the port-hit history that detection is based on.

**`record_hit(self, src_ip, port, timestamp)`**
Records that `src_ip` sent a SYN to `port` at `timestamp`.

**`get_ports_in_window(self, src_ip, window_seconds, now)`**
Returns the set of distinct ports `src_ip` has hit within the last `window_seconds`, relative to `now`.

**`prune(self, now, max_age_seconds)`**
Housekeeping: discards hits older than `max_age_seconds` so memory doesn't grow unbounded during a long-running capture. If an IP has no remaining hits after pruning, it's removed from internal state entirely. Called periodically during a live capture (not per-packet) to keep memory usage stable over time.

### 5. `capture.py`

Three functions, responsible for recognising SYN packets and listening for live traffic.

**`is_syn_packet(packet)`**
Determines whether a scapy packet is a bare SYN — the first packet of a TCP handshake attempt, not a SYN-ACK or anything else.

**`extract_syn_info(packet)`**
Pulls the fields PortGuard cares about out of a confirmed SYN packet — source IP, destination port, and timestamp — after confirming via `is_syn_packet` that it's worth processing. Address resolution (covering both IPv4 and IPv6 traffic) is handled via a shared `ip_filter` helper, so scans from either address family are captured under the same pipeline.

**`start_capture(on_packet)`**
Begins a live, blocking packet capture, calling `on_packet(packet)` for every packet seen. Requires root/admin, per the Requirements section above. PortGuard listens across **every** network interface found on the device (via scapy's `get_if_list()`), so scans arriving over Wi-Fi, Ethernet, or the loopback interface are all detected under a single running process — there's no need to specify an interface manually.

### 6. `guard.py`

A single function, `handle_packet`, which is the core detection pipeline — the point where every other module is wired together.

Takes:
- `packet` — a scapy packet object (a real captured packet, or in tests, one built in memory)
- `tracker` — a `PortActivityTracker` instance; the caller (`main.py`) owns one long-lived instance for the whole capture session
- `threshold` — distinct-port threshold, passed to `detector.is_scan`
- `window_seconds` — tracking window, passed to both the tracker and the detector
- `allowlist` — set of IPs to ignore, from `allowlist.load_allowlist`

Pipeline, run once per captured packet:
1. `capture.extract_syn_info(packet)` — bail (return `None`) if this isn't a SYN packet
2. `allowlist.is_allowlisted(src_ip, allowlist)` — bail if the source is allowlisted
3. `tracker.record_hit(src_ip, dst_port, timestamp)`
4. `tracker.get_ports_in_window(src_ip, window_seconds, timestamp)`
5. `detector.is_scan(len(ports), threshold)` — bail if below threshold
6. `detector.classify_severity(len(ports), window_seconds)`
7. `alerting.build_alert(...)` — return the alert

Returns an alert dictionary if a threat was found, or `None` otherwise.

### 7. `cli.py`

Two functions, defining the command-line interface.

**`build_arg_parser()`**
Constructs (but does not invoke) the `argparse.ArgumentParser`.

**`parse_args(argv=None)`**
Parses command-line arguments using `build_arg_parser()`, returning the resulting `args` object used throughout `main.py`.

### 8. `main.py`

Three functions — the orchestration layer that wires everything above together.

**`print_welcome()`**
Prints the welcome message shown when the application starts.

**`print_status(args, interfaces, allowlist)`**
Prints the active run configuration: which interfaces are being listened on, the threshold, the window (in seconds), whether an allowlist is loaded (and how many IPs it contains), and whether alerts are being logged to a file.

**`run(argv=None)`**
The CLI entry point: parses arguments, sets up the tracker and allowlist, prints the startup banner and status, and starts the live capture. Alerts are printed to the terminal as they occur, and optionally appended to a log file.

---

## Limitations

1. **Detection only, not prevention.** PortGuard can only detect SYN packets sent from another device — it cannot block them. Its purpose is to alert on potential malicious port scans, not to stop them.

2. **Threshold and window dependent.** PortGuard will only detect port scans that meet or exceed the configured threshold within the configured window. Scans below the threshold, or spread out beyond the window, will not be detected. Use the allowlist to reduce false positives from known-safe sources, and be aware that a sufficiently slow scan can fall outside the detection window entirely by design.

3. **Distributed/coordinated scans.** Unless each individual source IP independently crosses the configured threshold, PortGuard cannot detect a scan carefully distributed across multiple devices (e.g. many machines each scanning a handful of ports, coordinated by a single attacker). Each source IP is tracked independently, so distributed activity below the per-IP threshold looks like ordinary, unrelated traffic from separate clients.

4. **Flag-evasion scan types.** `is_syn_packet` requires exactly a bare SYN flag. Scan types that deliberately use different flag combinations to evade SYN-based detection (FIN, NULL, XMAS scans) are not SYN packets at all, and pass through undetected by design.

5. **UDP scans are not detected.** PortGuard's packet filter is TCP-only; UDP traffic is dropped before it ever reaches the detection pipeline.

6. **NAT - Network Address Translation** Not necessarily a limitation, but worth noting: PortGuard is most reliably tested and used within your own local network. This is due to NAT (Network Address Translation) — your device's actual address on your network is a private IP (e.g. 192.168.x.x), which is never routed on the public internet at all; only your router's single public IP is visible externally. When an outside scanner sends traffic to that public IP, your router has no way to know which internal device it's meant for — unless a prior outbound connection from that device created a matching entry, the router simply drops it. So a remote scan against your public IP will not reach your actual machine, unless port forwarding or UPnP has explicitly opened a path to a specific device.

---

## Disclaimer

This tool is intended for use on devices and networks you own or have explicit permission to monitor. Running any packet-capture tool, including this one, on networks you do not have authorization to monitor may be illegal depending on your jurisdiction.
