# SUPERNOVA - Internal Vulnerability Scanner

SUPERNOVA is a lightweight, Python-based command-line internal vulnerability scanner designed for lab environments. It performs host discovery, smart port scanning, service enumeration with active probing, and security misconfiguration detection.

Developed as a modular and extensible tool, it maps detected services to known CVEs and generates structured, machine-readable JSON reports.

---

## Key Features

* **Versatile Targeting:** Scan a single host (IP/Hostname) or an entire subnet (CIDR notation).
* **Smart Port Parsing:** Supports flexible port selection (`-p top100`, `-p all`, `-p 22,80,443`, or ranges like `-p 1-1000`).
* **Active Service Fingerprinting:** Utilizes "Double Tap" and protocol-specific probes (HTTP, FTP, SMTP, POP3) to wake up silent ports and verify services with a high Confidence Level (Verified vs. Maybe).
* **Security Checks:** Detects common misconfigurations:
  - **FTP:** Anonymous login detection (Code 230)
  - **SMB:** Guest/null session access and share enumeration
  - **HTTP:** Unencrypted service detection and missing security headers (X-Content-Type-Options, X-Frame-Options, HSTS, CSP)
  - **Telnet:** Cleartext protocol detection
  - **RDP:** Open port and NLA enforcement check
* **CVE Correlation:** Maps identified service versions to documented CVEs to assess risk.
* **Structured Reporting:** Outputs a clear terminal summary and a detailed `report.json` file with both scan data and security check results.

---

## Dependencies & Requirements

This tool is built primarily using Python's standard library to ensure a lightweight footprint. However, a few specific modules are required for advanced security checks.

| Package | Purpose | Required |
|---------|---------|----------|
| `pysmb` | SMB Guest access & share enumeration checks | Optional (SMB checks gracefully skip if missing) |

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ya7ya-geronimo/SUPERNOVA.git
   cd SUPERNOVA/SUPERNOVA
   ```

2. Run the automated installer (Linux/Kali):
   ```bash
   sudo bash install.sh
   ```
   This will:
   - Clean Windows CRLF line endings
   - Install Python dependencies (`pysmb`)
   - Set execution permissions
   - Create a global `supernova` command via symlink

3. Or install manually:
   ```bash
   pip install -r requirements.txt
   chmod +x main.py
   ```

*(Note: For Kali Linux users, use an isolated environment or the `--break-system-packages` flag if necessary.)*

---

## Usage Examples

SUPERNOVA provides a user-friendly CLI with various flags to customize your scan.

**1. Basic Scan (Default Top 15 Ports):**
```bash
supernova -t 192.168.1.100
```

**2. Subnet Scan with Specific Ports:**
```bash
supernova -t 10.48.170.0/24 -p 22,80,111,2049
```

**3. Deep Scan (Top 100 Ports) with Faster Timeout:**
```bash
supernova -t 10.48.155.187 -p top100 --speed 0.5
```

**4. Run All Security Checks:**
```bash
supernova -t 192.168.1.50 --all
```

**5. Run Specific Security Checks Only:**
```bash
supernova -t 192.168.1.50 --ftp --smb
supernova -t 192.168.1.50 --http
```

**6. Custom Output File:**
```bash
supernova -t 10.10.10.5 --all -o my_scan.json
```

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP or Subnet CIDR (required) | - |
| `-p, --ports` | Ports: `top100`, `all`, `1-1000`, or `22,80` | Top 15 |
| `--speed` | Timeout in seconds per port | 1.0 |
| `-o, --output` | Output JSON filename | `report.json` |
| `--all` | Run all security checks (FTP + SMB + HTTP) | Off |
| `--ftp` | Run FTP checks only | Off |
| `--smb` | Run SMB checks only | Off |
| `--http` | Run HTTP/HTTPS + security headers checks | Off |

---

## Security Checks Architecture

The `checks/` module uses a **plugin-based architecture** with auto-discovery:

```
checks/
├── __init__.py              # Package exports
├── runner.py                # CheckRunner - auto-discovers *_checks.py files
├── network_checks.py        # FTP, SMB, Telnet, RDP checks
├── web_checks.py            # HTTP banner + security headers checks
├── verify_checks.py         # Integration test suite with mock servers
└── CODE_EXPLANATION.md      # Detailed check logic documentation
```

**Key Design Decisions:**
- **Graceful Degradation:** If `pysmb` is not installed, only SMB checks are skipped — all other checks (FTP, Telnet, HTTP, RDP) continue to work normally.
- **Auto-Discovery:** New check files matching `*_checks.py` with functions prefixed `check_` are automatically registered by the `CheckRunner`.
- **Consistent Output:** Every check returns a standardized dict with `service`, `port`, `status`, `vulnerable`, and `description` fields.

---

## Sample Output

### Terminal Output
```
==================== TARGET: 10.129.201.127 ====================
[10.129.201.127] Step 1: Checking if host is UP...
[+] Host 10.129.201.127 is UP!
[10.129.201.127] Step 2: Scanning ports...
[+] Found 3 open ports: [22, 53, 110]
[10.129.201.127] Step 3: Detecting Services and Versions...
-------------------------------------------------------
PORT     | SERVICE    | VERSION
-------------------------------------------------------
22       | SSH (Verified) | OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
53       | Unknown (Maybe: DNS?) | Unknown (No Banner)
110      | POP3 (Verified) | +OK Dovecot (Ubuntu) ready.
-------------------------------------------------------

[*] Running Security Checks...
  [10.129.201.127] FTP port 21 not open, skipping FTP check.
  [10.129.201.127] SMB port 445 not open, skipping SMB check.
  [10.129.201.127] HTTP port 80/8080 not open, skipping HTTP checks.

[+] Scan report successfully saved to: report.json
```

### JSON Report Structure
```json
{
    "metadata": {
        "team": "SUPERNOVA",
        "scope": "10.129.201.127",
        "time": "2026-02-22 13:51:58",
        "user": "tpain"
    },
    "hosts": {
        "10.129.201.127": {
            "status": "up",
            "ports": [
                {"port": 22, "service": "SSH (Verified)", "version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.4"},
                {"port": 110, "service": "POP3 (Verified)", "version": "+OK Dovecot (Ubuntu) ready."}
            ],
            "security_checks": [
                {"service": "FTP", "port": 21, "status": "Closed", "vulnerable": false, "description": "Port is closed"},
                {"service": "SMB", "port": 445, "status": "Closed", "vulnerable": false, "description": "Port is closed"}
            ]
        }
    }
}
```

---

## Assumptions and Limitations

* **Lab Environment Only:** This tool is strictly designed for authorized internal lab testing. It does not employ evasion techniques.
* **Non-Destructive:** The scanner identifies vulnerabilities and misconfigurations but does not exploit them (No privilege escalation, malware-like behavior, or lateral movement).
* **Banner Reliance:** While active probing is implemented, highly obfuscated services or custom ports without banners may still return as `Unknown`.
* **Subnet Scanning Time:** Scanning a full `/24` subnet across all 65,535 ports without tweaking the timeout setting (`--speed`) may take a considerable amount of time.

---

## Changelog

### v2.0 — Bug Fixes & Security Checks Integration
- **Fixed:** `-s` shorthand for `--speed` conflicted with `--smb` (argparse parsed `-smb` as `-s mb`). Renamed to `--speed` (long flag only).
- **Fixed:** `--all`, `--smb`, `--ftp`, `--http` flags were parsed but never executed. Security checks are now fully integrated into the scan pipeline.
- **Fixed:** `target_ip` was not passed to active probing function, preventing fallback service detection from working.
- **Fixed:** Invisible Unicode character (`\u064d`) in JSON report team name removed.
- **Fixed:** `pysmb` import crash — if `pysmb` wasn't installed, ALL checks (FTP, Telnet, RDP) would crash, not just SMB. Now gracefully handled.
- **Added:** POP3/Dovecot service detection (port 110 `+OK` banners).
- **Added:** POP3S (port 995) to common ports map.
- **Added:** `pysmb` to `requirements.txt`.
- **Added:** Automatic dependency installation in `install.sh`.
- **Added:** Security check results now included in JSON report under `security_checks` key.

---

## The SUPERNOVA Team

This project was designed and developed from scratch as a graduation project for the Green Circle PenTest Internship.

* **Core Engine, CLI Architecture, `main.py`, README.md.
* **Security Checks & Vulnerability Assessment** — `checks/` module: FTP, SMB, HTTP, Telnet, RDP checks, CheckRunner, integration tests.
* **CVE Correlation & Reporting Logic** — CVE mapping and report generation.
