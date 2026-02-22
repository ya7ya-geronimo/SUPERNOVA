# SUPERNOVA:
```markdown
#  SUPERNOVA - Internal Vulnerability Scanner

SUPERNOVA is a lightweight, Python-based command-line internal vulnerability scanner designed for lab environments. It performs host discovery,
smart port scanning, service enumeration with active probing, and security misconfiguration detection. 

Developed as a modular and extensible tool, it maps detected services to known CVEs and generates structured, machine-readable JSON reports.

---

##  Key Features
* **Versatile Targeting:** Scan a single host (IP/Hostname) or an entire subnet (CIDR notation).
* **Smart Port Parsing:** Supports flexible port selection (`-p top100`, `-p all`, `-p 22,80,443`, or ranges like `-p 1-1000`).
* **Active Service Fingerprinting:** Utilizes "Double Tap" and protocol-specific probes (HTTP, FTP, SMTP) to wake up silent ports and
    verify services with a high Confidence Level (Verified vs. Maybe).
* **Security Checks:** Detects common misconfigurations (e.g., FTP Anonymous Access, SMB Guest Access, Cleartext HTTP).
* **CVE Correlation:** Maps identified service versions to documented CVEs to assess risk.
* **Structured Reporting:** Outputs a clear terminal summary and a detailed `report.json` file for further processing.

---

##  Dependencies & Requirements
This tool is built primarily using Python's standard library to ensure a lightweight footprint. However,
a few specific modules are required for advanced security checks.
---

##  Installation

1. Clone the repository or extract the project folder:
   ```bash
   git clone [https://github.com/ya7ya-geronimo/SUPERNOVA.git](https://github.com/ya7ya-geronimo/SUPERNOVA.git)
   cd SUPERNOVA

```

2. Make the script executable (Linux/macOS):
```bash
chmod +x SUPERNOVA

```


3. Install the required dependencies:
```bash
pip install -r requirements.txt

```


*(Note: For Kali Linux users, use an isolated environment or the `--break-system-packages` flag if necessary).*

---

##  Usage Examples

SUPERNOVA provides a user-friendly CLI with various flags to customize your scan.

**1. Basic Scan (Default Top 15 Ports):**

```bash
SUPERNOVA -t 192.168.1.100

```

**2. Subnet Scan with Specific Ports:**

```bash
SUPERNOVA -t 10.48.170.0/24 -p 22,80,111,2049

```

**3. Deep Scan (Top 100 Ports) with Faster Timeout:**

```bash
SUPERNOVA -t 10.48.155.187 -p top100 -s 0.5

```

**4. Run Specific Security Checks Only:**

```bash
SUPERNOVA -t 192.168.1.50 --ftp --smb

```

---

## Assumptions and Limitations

* **Lab Environment Only:** This tool is strictly designed for authorized internal lab testing. It does not employ evasion techniques.
* **Non-Destructive:** The scanner identifies vulnerabilities and misconfigurations but does not exploit them (No privilege escalation, malware-like behavior, or lateral movement).
* **Banner Reliance:** While active probing is implemented, highly obfuscated services or custom ports without banners may still return as `Unknown`.
* **Subnet Scanning Time:** Scanning a full `/24` subnet across all 65,535 ports without tweaking the timeout setting (`-s`) may take a considerable amount of time.

---

## The SUPERNOVA Team

This project was designed and developed from scratch as a graduation project for Green Circle PenTest Internship **.

* **  ** .
* **Malek Al Zaben** Core Engine, CLI Architecture, main.py, README.md.
* ** ** - Security Checks Vulnerability Assessment.
* ** ** - CVE Correlation  Reporting Logic.
