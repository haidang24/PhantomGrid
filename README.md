# Phantom Grid – eBPF-Powered Active Defense Platform

> "The best defense is not just blocking – it is confusing, deceiving, and recording."

**Phantom Grid** is a kernel-level active defense system built on **eBPF (Extended Berkeley Packet Filter)**.  
It turns a normal Linux server into a controlled, deceptive attack surface that:

- Exposes a matrix of fake open ports,
- Silently redirects suspicious traffic into an internal honeypot, and
- Records attacker activity in real time for forensics and threat intelligence.

![Phantom Grid Dashboard](assets/dashboard.png)

---

## Features

- **Ghost Grid (Port Virtualization)**  
  Dynamically presents a wide range of seemingly open ports. Reconnaissance tools (for example, Nmap) see a noisy, misleading surface instead of your real services.

- **Transparent eBPF Redirection (XDP Layer)**  
  Uses an XDP hook to intercept TCP traffic at the NIC driver level and transparently redirect non-SSH ports to an internal honeypot (port `9999`) without changing the destination IP. **Production-ready**: TCP checksum is automatically recalculated after port modification to ensure packets are not dropped by NIC or OS.

- **Stealth Scan Detection & Dropping**  
  Automatically detects and silently drops malicious scan types (Xmas, Null, FIN, ACK scans) at the kernel level, saving honeypot resources and preventing reconnaissance. Statistics are tracked in real-time via BPF maps.

- **OS Personality Mutation (OS Fingerprint Spoofing)**  
  **Kernel-level OS deception**: Mutates IP TTL and TCP Window Size in real-time to confuse fingerprinting tools like Nmap. Attackers scanning the server will see inconsistent OS fingerprints (Windows TTL=128, Linux TTL=64, FreeBSD, Solaris) and use wrong exploits. For example, if Nmap sees TTL=128, it thinks the server is Windows and uses Windows exploits, which are useless against a Linux server. This is implemented at the kernel level using eBPF, ensuring wire-speed performance.

- **Egress Containment (DLP - Data Loss Prevention)**  
  **Kernel-level DLP**: TC eBPF program monitors **outbound traffic** from honeypot connections. Detects and blocks suspicious data patterns (password files, SSH keys, credit cards, database dumps) before they leave the server. Even if an attacker gains access, **data never leaves the server**. This implements enterprise-grade Data Loss Prevention at the kernel layer.

- **Single Packet Authorization (SPA) - "Giao thức cửa hậu"**  
  **Zero Trust Access Control**: Server is **completely invisible** by default. All ports (including SSH port 22) are closed, and the server appears "dead" to scanners (no ping response, no open ports). Admin sends a **Magic Packet** (UDP packet with secret token) to port 1337. eBPF validates the token and automatically whitelists the admin's IP for 30 seconds, allowing SSH access. **Result**: Hackers see a "dead host" while admins can still access the server. This is the highest level of Zero Trust security - the server doesn't exist until authorized.

- **The Mirage: Randomized Service Fingerprints**  
  Each connection receives a **randomized banner and service type** (SSH, HTTP, MySQL, Redis, FTP) with different OS fingerprints. This creates the "Ghost Grid" effect where attackers see inconsistent, confusing responses across multiple scans, making it impossible to reliably identify real services.

- **Stealth Honeypot with Multi-Service Emulation**  
  Attackers connecting to random ports are silently dropped into randomized fake services (SSH shells, HTTP servers, MySQL, Redis, FTP) that mimic real environments. Their commands and interactions are captured and streamed to the dashboard.

- **Real-Time Forensics Dashboard (TUI)**  
  A terminal-based dashboard (TermUI) shows live events:

  - Incoming connections and trap hits
  - Commands executed by attackers
  - A dynamic threat level gauge and total blocked or redirected attempts

- **High Performance**  
  Built on eBPF/XDP, traffic decisions are made in kernel space with minimal overhead, suitable for modern high-throughput environments.

---

## Architecture

- **Kernel Space (`bpf/phantom.c`)**

  - XDP program attached to a chosen network interface (for example, `eth0` or `lo` for demo).
  - Intercepts IPv4 TCP/UDP packets at the NIC driver level (wire-speed processing).
  - **Single Packet Authorization (SPA)**:
    - **Magic Packet Detection**: Listens for UDP packets on port 1337 containing secret token `PHANTOM_GRID_SPA_2025`
    - **Automatic Whitelisting**: Validates token and whitelists source IP for 30 seconds
    - **SSH Port Protection**: SSH port 22 is **completely closed** unless source IP is whitelisted
    - **Server Invisibility**: All traffic to SSH port from non-whitelisted IPs is dropped, making server appear "dead"
    - Maintains BPF maps:
      - `spa_whitelist`: LRU hash map of whitelisted IPs
      - `spa_auth_success`: Counts successful SPA authentications
      - `spa_auth_failed`: Counts failed authentication attempts
  - **Stealth Scan Detection**: Automatically detects and drops malicious scan types:
    - **Xmas Scan** (FIN + URG + PSH flags)
    - **Null Scan** (no flags set)
    - **FIN Scan** (FIN flag only)
    - **ACK Scan** (ACK flag without SYN)
  - **Transparent Redirection**: If the destination port is not SSH (`22`) and not the honeypot (`9999`), the packet's destination port is rewritten to `9999`.
  - **OS Personality Mutation**: Mutates IP TTL and TCP Window Size to spoof OS fingerprints:
    - **TTL Mutation**: Changes TTL to mimic different OS (Windows=128, Linux=64, FreeBSD=64, Solaris=255)
    - **Window Size Mutation**: Changes TCP window size to match OS characteristics (Windows=65535, Linux=29200, FreeBSD=65535)
    - Uses source port hash to ensure consistent OS fingerprint per connection
    - **Result**: Nmap and other fingerprinting tools see inconsistent OS signatures, causing attackers to use wrong exploits
  - **Production-Ready Checksum Recalculation**: Both IP and TCP checksums are automatically recalculated after any header modification using `bpf_l3_csum_replace` and `bpf_l4_csum_replace` to ensure packets are not dropped by NIC or OS.
  - Maintains BPF maps for statistics:
    - `attack_stats`: Counts redirected connections
    - `stealth_drops`: Counts stealth scans dropped
    - `os_mutations`: Counts OS fingerprint mutations applied

- **Kernel Space (`bpf/phantom_egress.c`) - TC Egress Module**

  - TC (Traffic Control) eBPF program attached to **egress** (outbound) traffic.
  - Monitors packets **leaving** the honeypot (source port `9999`).
  - **Pattern Detection**: Scans payload for suspicious data patterns:
    - Password file contents (`/etc/passwd` format)
    - SSH private keys (`-----BEGIN`)
    - Base64-encoded data (common exfiltration method)
    - SQL database dumps (`INSERT INTO`)
    - Credit card numbers (13+ consecutive digits)
  - **Automatic Blocking**: Drops packets containing suspicious patterns using `TC_ACT_SHOT`.
  - Maintains BPF maps:
    - `egress_blocks`: Counts blocked exfiltration attempts
    - `suspicious_patterns`: Tracks pattern types detected

- **User Space Agent (`cmd/agent/main.go`)**

  - Loads and attaches both **XDP** (ingress) and **TC** (egress) eBPF programs using the Cilium eBPF library.
  - Starts a lightweight TCP honeypot on port `9999`.
  - Implements **"The Mirage"** module: randomizes service banners and fingerprints for each connection:
    - **SSH banners**: 8 different OpenSSH versions across various Linux distributions (Ubuntu, Debian, CentOS, RedHat, Arch, FreeBSD)
    - **HTTP banners**: Multiple web server signatures (nginx, Apache, IIS)
    - **Database banners**: MySQL and MariaDB versions, Redis responses
    - **FTP banners**: Various FTP server implementations
  - Each connection randomly selects a service type and banner, creating inconsistent scan results that confuse reconnaissance tools.
  - Exposes a TUI dashboard (TermUI) that visualizes logs and metrics in real time, including **egress blocks** (DLP statistics).

---

## Tech Stack

- **Kernel Space:** C, eBPF/XDP
- **User Space:** Go (Golang)
- **eBPF Runtime:** `github.com/cilium/ebpf`
- **TUI Dashboard:** `github.com/gizak/termui/v3`

---

## Getting Started

### 1. Prerequisites

- Linux kernel version 5.4 or later (Ubuntu 20.04/22.04 recommended)
- `clang`, `llvm`, `libbpf-dev` (or equivalent eBPF build toolchain)
- `golang` 1.21 or later
- Root privileges (required to load and attach eBPF programs)

Example for Ubuntu:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev golang make git
```

### 2. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
```

### 3. Install Go Dependencies

```bash
go mod tidy
```

### 4. Build and Run

The project includes a `Makefile` for a one-command workflow:

**Quick Start (Auto-detect interface):**

```bash
make run
```

**Run with specific interface:**

```bash
# List available interfaces
ip link show

# Run with specific interface (e.g., ens33, eth0, wlx00127b2163a6)
make run-interface INTERFACE=ens33

# Or directly:
sudo ./phantom-grid -interface ens33
```

This will:

1. Run `go generate` to compile the eBPF program via `bpf2go`.
2. Build the Go user-space agent into a binary named `phantom-grid`.
3. Build the SPA client tool `spa-client`.
4. Execute `sudo ./phantom-grid` to:
   - Auto-detect or use specified network interface
   - Attach the XDP program to the interface
   - Start the honeypot and dashboard

> **Important**: For production deployment, specify the external interface using `-interface` flag. The system will auto-detect if not specified, but may default to loopback (`lo`) which won't capture external traffic.

---

## Demo: How to Test Phantom Grid

Assume `PHANTOM_IP` is the IP address of the machine running Phantom Grid.

1. **Reconnaissance (attacker machine): scan all ports**

```bash
nmap -p- PHANTOM_IP
```

Many ports will appear open or responsive, forming the deceptive "ghost" grid.

2. **Connect to a random port (for example, 3306)**

```bash
nc PHANTOM_IP 3306
```

- You will be transparently redirected to the internal honeypot on port `9999`.
- **"The Mirage" effect**: Each connection receives a **randomized service banner**. You might see:
  - An SSH banner (one of 8 different versions): `SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7`
  - An HTTP response: `HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)`
  - A MySQL handshake packet
  - A Redis response
  - An FTP banner: `220 ProFTPD 1.3.6 Server`
- **Try connecting multiple times** – you will see different banners each time, demonstrating the randomization.

3. **Interact with the fake service**

Depending on the randomized service type:

- **If SSH**: Try basic commands (`whoami`, `ls`, `pwd`, `exit`)
- **If HTTP**: Send an HTTP request (`GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`)
- **If MySQL**: Attempt authentication (will be logged)
- **If Redis**: Send Redis commands (`PING`, `INFO`)
- **If FTP**: Send FTP commands (`USER test`, `PASS test`)

- All interactions are simulated to look like real services.
- All commands and requests are logged and streamed to the real-time forensics panel in the TUI.

4. **Monitor the defender dashboard**

- Watch new connections, commands, and the threat level gauge increase.
- Use this view during a demo or interview to show live attacker interaction.

### Single Packet Authorization (SPA) - Zero Trust Access

**Scenario**: Server is completely invisible. SSH port 22 is closed by default.

1. **Verify server is invisible (attacker perspective)**:

```bash
# Ping - no response
ping PHANTOM_IP

# Port scan - SSH port appears closed
nmap -p 22 PHANTOM_IP
# Result: Port 22 is filtered/closed - server appears "dead"
```

2. **Admin authentication (send Magic Packet)**:

From admin machine, send Magic Packet to whitelist your IP:

```bash
# Build SPA client tool
make build

# Send Magic Packet
./spa-client PHANTOM_IP
```

Output:

```
[*] Sending Magic Packet to PHANTOM_IP:1337...
[+] Magic Packet sent successfully!
[+] Your IP has been whitelisted for 30 seconds
[+] You can now SSH to the server:
    ssh user@PHANTOM_IP
```

3. **Access SSH (now whitelisted)**:

```bash
# SSH access is now allowed (for 30 seconds)
ssh user@PHANTOM_IP
```

4. **Verify SPA in dashboard**:

- Watch for `[SPA] Successful authentication` messages
- Server remains invisible to non-whitelisted IPs
- Whitelist expires automatically after 30 seconds

**Key Point**: This demonstrates **Zero Trust** - the server doesn't exist until authorized via Magic Packet.

---

## Development Notes

- **Regenerating eBPF bindings**

If you modify `bpf/phantom.c`, regenerate the Go bindings:

```bash
go generate ./...
```

- **Running tests**

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage
```

- **Cleaning build artifacts**

```bash
make clean
```

This removes the `phantom-grid` binary and generated BPF output files.

---

## Roadmap Ideas

- Multi-interface support and dynamic interface selection
- Persistent storage for attacker session logs (for example, SQLite or JSON)
- Integration with SIEM platforms (ELK, Splunk, OpenSearch)
- Support for additional protocols (UDP, HTTP fingerprinting, TLS SNI baiting)
- Web-based dashboard on top of the TUI view

---

## License

This project is released under the MIT License. See `LICENSE` (to be added) for details.

---

## Author

**Mai Hai Dang – HD24SecurityLabs**  
Focus areas: system programming, eBPF, and active defense.
