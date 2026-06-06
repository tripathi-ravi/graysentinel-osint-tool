#!/usr/bin/env python3
"""
GraySentinel Day 2 OSINT Tool – Domain Profiler
Author: Ravi Tripathi
Date: 2026-06-06
"""

import socket
import ssl
import json
import sys
import os
import datetime
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import base64

# ── colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def red(t):    return f"{RED}{t}{RESET}"
def green(t):  return f"{GREEN}{t}{RESET}"
def yellow(t): return f"{YELLOW}{t}{RESET}"
def cyan(t):   return f"{CYAN}{t}{RESET}"
def bold(t):   return f"{BOLD}{t}{RESET}"

# ── banner ────────────────────────────────────────────────────────────────────
def banner():
    print(cyan("""
╔══════════════════════════════════════════════╗
║        GraySentinel – Domain Profiler        ║
║           OSINT Automation Tool v1.0         ║
╚══════════════════════════════════════════════╝
"""))

# ── ip resolution ─────────────────────────────────────────────────────────────
def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        return None

# ── whois (uses system whois command) ────────────────────────────────────────
def get_whois(domain):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.splitlines()
        info = {}
        for line in lines:
            l = line.lower()
            if "registrar:" in l and "registrar" not in info:
                info["Registrar"] = line.split(":", 1)[-1].strip()
            if "creation date" in l and "Creation Date" not in info:
                info["Creation Date"] = line.split(":", 1)[-1].strip()
            if "expir" in l and "Expiry Date" not in info:
                info["Expiry Date"] = line.split(":", 1)[-1].strip()
            if "registrant country" in l and "Registrant Country" not in info:
                info["Registrant Country"] = line.split(":", 1)[-1].strip()
        return info if info else {"Note": "WHOIS data unavailable or restricted"}
    except FileNotFoundError:
        return {"Note": "whois command not installed on this system"}
    except Exception as e:
        return {"Note": f"WHOIS lookup failed: {e}"}

# ── ssl certificate info ──────────────────────────────────────────────────────
def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        return {
            "Subject CN":    subject.get("commonName", "N/A"),
            "Issued By":     issuer.get("organizationName", "N/A"),
            "Valid From":    cert.get("notBefore", "N/A"),
            "Valid Until":   cert.get("notAfter", "N/A"),
            "SANs":          [v for t, v in cert.get("subjectAltName", []) if t == "DNS"][:5],
        }
    except ssl.SSLCertVerificationError:
        return {"Error": "SSL certificate verification failed – cert may be self-signed"}
    except ConnectionRefusedError:
        return {"Error": "Port 443 is closed – no HTTPS"}
    except Exception as e:
        return {"Error": str(e)}

# ── dns records ───────────────────────────────────────────────────────────────
def get_dns_records(domain):
    """Uses Google's DNS-over-HTTPS API – no extra library needed."""
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            req = Request(url, headers={"User-Agent": "GraySentinel-OSINT/1.0"})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            answers = [a.get("data", "") for a in data.get("Answer", [])]
            if answers:
                records[rtype] = answers[:5]
        except Exception:
            pass
    return records if records else {"Note": "DNS query failed"}

# ── virustotal reputation ─────────────────────────────────────────────────────
def check_virustotal(domain, api_key):
    if not api_key:
        return {"Note": "No VirusTotal API key provided – skipping reputation check"}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = Request(url, headers={"x-apikey": api_key})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        verdict    = "CLEAN" if malicious == 0 and suspicious == 0 else "SUSPICIOUS / MALICIOUS"
        return {
            "Malicious":  malicious,
            "Suspicious": suspicious,
            "Harmless":   harmless,
            "Verdict":    verdict
        }
    except HTTPError as e:
        if e.code == 401:
            return {"Error": "Invalid VirusTotal API key"}
        if e.code == 404:
            return {"Note": "Domain not yet in VirusTotal database"}
        return {"Error": f"HTTP {e.code}"}
    except Exception as e:
        return {"Error": str(e)}

# ── save report ───────────────────────────────────────────────────────────────
def save_report(domain, report_lines):
    filename = f"report_{domain.replace('.', '_')}_{datetime.date.today()}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # strip ANSI colour codes before saving
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            for line in report_lines:
                f.write(ansi_escape.sub("", line) + "\n")
        return filename
    except Exception as e:
        return None

# ── display helpers ───────────────────────────────────────────────────────────
def section(title):
    print()
    print(cyan("─" * 50))
    print(bold(cyan(f"  {title}")))
    print(cyan("─" * 50))

def kv(key, value, colorize=False):
    if colorize and isinstance(value, str):
        val_str = green(value) if "CLEAN" in value.upper() else red(value)
    else:
        val_str = str(value)
    print(f"  {YELLOW}{key:<22}{RESET} {val_str}")

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()

    domain = input(bold("  Enter domain to analyse: ")).strip().lower()
    if not domain:
        print(red("  No domain entered. Exiting."))
        sys.exit(1)

    # strip http/https if accidentally pasted
    for prefix in ["https://", "http://", "www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if not vt_key:
        vt_key = input(bold("  VirusTotal API key (leave blank to skip): ")).strip()

    report_lines = []

    def log(line=""):
        print(line)
        report_lines.append(line)

    # ── IP ──
    section("IP Resolution")
    ip = resolve_ip(domain)
    if not ip:
        print(red(f"  Could not resolve '{domain}'. Check the domain and try again."))
        sys.exit(1)
    kv("Domain", domain)
    kv("Resolved IP", ip)

    # ── WHOIS ──
    section("WHOIS Information")
    whois = get_whois(domain)
    for k, v in whois.items():
        kv(k, v)

    # ── SSL ──
    section("SSL Certificate")
    ssl_info = get_ssl_info(domain)
    for k, v in ssl_info.items():
        if isinstance(v, list):
            kv(k, ", ".join(v))
        else:
            kv(k, v)

    # ── DNS ──
    section("DNS Records")
    dns = get_dns_records(domain)
    for rtype, values in dns.items():
        if isinstance(values, list):
            kv(rtype, values[0])
            for extra in values[1:]:
                kv("", extra)
        else:
            kv(rtype, values)

    # ── VirusTotal ──
    section("VirusTotal Reputation")
    vt = check_virustotal(domain, vt_key)
    for k, v in vt.items():
        colorize = (k == "Verdict")
        kv(k, v, colorize=colorize)

    # ── save ──
    section("Saving Report")
    saved = save_report(domain, report_lines)
    if saved:
        print(green(f"  Report saved to: {saved}"))
    else:
        print(yellow("  Could not save report to file."))

    print()
    print(cyan("═" * 50))
    print(bold(cyan("  Scan complete.")))
    print(cyan("═" * 50))
    print()

if __name__ == "__main__":
    main()
