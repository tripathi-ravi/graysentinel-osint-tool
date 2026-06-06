# graysentinel-osint-tool
Day-2 Cybersecurity task
# GraySentinel – Domain Profiler
### OSINT Automation Tool | Day 2 Submission

---

**Tool Name:** Domain Profiler  
**Author:** Ravi Tripathi  
**Date:** 2026-06-06  
**Description:** A command-line Python tool that automatically collects WHOIS data, IP resolution, SSL certificate details, DNS records, and VirusTotal reputation for any given domain.

---

## Requirements

- Python 3.8 or above
- Internet connection
- A free VirusTotal API key (optional but recommended)
- `whois` system command installed

**No third-party Python libraries are required.** The script uses only the Python standard library (`socket`, `ssl`, `json`, `subprocess`, `urllib`).

---

## Installation

### Step 1 – Clone or download the script

```bash
git clone https://github.com/tripathi-ravi/graysentinel-osint-tool
cd graysentinel-osint-tool
```

Or just download `script.py` directly.

### Step 2 – Install the `whois` system command (if not already installed)

On Ubuntu / Debian:
```bash
sudo apt install whois
```

On macOS:
```bash
brew install whois
```

On Windows: Install via [Chocolatey](https://chocolatey.org/) – `choco install whois`  
Or use Windows Subsystem for Linux (WSL).

### Step 3 – Get a free VirusTotal API key

1. Go to https://www.virustotal.com
2. Create a free account
3. Navigate to your profile → API Key
4. Copy the key

You can either:
- Paste it when the tool prompts you, OR
- Set it as an environment variable so you do not need to paste it every time:

```bash
export VT_API_KEY="your_key_here"
```

On Windows (Command Prompt):
```
set VT_API_KEY=your_key_here
```

---

## Usage

```bash
python script.py
```

The tool will prompt you for:
1. The domain you want to scan
2. Your VirusTotal API key (only if not set as environment variable)

---

## Example Input

```
Enter domain to analyse: google.com
VirusTotal API key (leave blank to skip): [paste key here]
```

---

## Example Output

```
──────────────────────────────────────────────────
  IP Resolution
──────────────────────────────────────────────────
  Domain                 google.com
  Resolved IP            142.250.77.206

──────────────────────────────────────────────────
  WHOIS Information
──────────────────────────────────────────────────
  Registrar              MarkMonitor Inc.
  Creation Date          1997-09-15T04:00:00Z
  Expiry Date            2028-09-14T04:00:00Z
  Registrant Country     US

──────────────────────────────────────────────────
  SSL Certificate
──────────────────────────────────────────────────
  Subject CN             *.google.com
  Issued By              Google Trust Services
  Valid From             May 19 08:22:58 2026 GMT
  Valid Until            Aug 11 08:22:57 2026 GMT
  SANs                   *.google.com, google.com

──────────────────────────────────────────────────
  DNS Records
──────────────────────────────────────────────────
  A                      142.250.77.206
  MX                     10 smtp.google.com.
  NS                     ns1.google.com.
  TXT                    v=spf1 include:_spf.google.com ~all

──────────────────────────────────────────────────
  VirusTotal Reputation
──────────────────────────────────────────────────
  Malicious              0
  Suspicious             0
  Harmless               84
  Verdict                CLEAN

──────────────────────────────────────────────────
  Saving Report
──────────────────────────────────────────────────
  Report saved to: report_google_com_2026-06-06.txt
```

Results are colour-coded:
- Green = Clean / safe
- Red = Malicious / suspicious
- Yellow = Field labels

---

## Additional Features Implemented

Beyond the base requirements, two extra features were added:

1. **SSL Certificate Information** – Pulls the full certificate chain details including issuer, expiry, and Subject Alternative Names (SANs).
2. **DNS Record Lookup** – Queries A, MX, NS, and TXT records using Google's DNS-over-HTTPS API (no extra libraries needed).
3. **Save Report to File** – Automatically saves a plain-text version of the output to a `.txt` file with the domain name and date in the filename.
4. **Color-Coded Output** – Terminal output is colour-coded for quick visual interpretation.

---

## Known Limitations

- WHOIS data is rate-limited by registrars. Running the tool repeatedly against the same domain in a short window may return restricted results.
- VirusTotal free API is limited to 4 requests per minute and 500 per day. If you exceed this, the tool will display an error and continue without reputation data.
- SSL check will fail for domains that do not support HTTPS or use self-signed certificates – the tool handles this gracefully and continues.
- The `whois` command is a system dependency. On Windows without WSL, this section may not work without additional setup.
- Some TXT DNS records can be very long. The tool truncates to the first 5 entries per record type.

---

## License

For GraySentinel Internal Use Only.
