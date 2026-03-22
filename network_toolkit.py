"""
Network Diagnostic & Troubleshooting Toolkit
=============================================
A Python-based tool that performs network diagnostics including:
- Host reachability (ping)
- DNS resolution
- Port scanning
- Route tracing
- NFS/SMB share connectivity testing
- Full report generation saved to file

Author: Akhila Bollu
"""

import os
import sys
import csv
import json
import socket
import struct
import logging
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("network_toolkit.log"),
    ],
)
logger = logging.getLogger(__name__)

# ── Common ports to scan ──────────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    111:  "RPC (NFS)",
    135:  "MS-RPC",
    139:  "NetBIOS (SMB)",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB/CIFS",
    465:  "SMTPS",
    587:  "SMTP (TLS)",
    993:  "IMAPS",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "Custom/App",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ping / Reachability
# ══════════════════════════════════════════════════════════════════════════════

def ping_host(host: str, count: int = 4) -> dict:
    """
    Ping a host and return reachability info.
    Works on both Mac and Linux.
    """
    logger.info("Pinging %s ...", host)
    param = "-c" if sys.platform != "win32" else "-n"
    cmd = ["ping", param, str(count), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        reachable = result.returncode == 0

        # Parse packet loss
        loss_pct = "N/A"
        avg_rtt  = "N/A"
        for line in output.splitlines():
            if "packet loss" in line:
                parts = line.split(",")
                for p in parts:
                    if "packet loss" in p:
                        loss_pct = p.strip().split()[0]
            if "avg" in line or "Average" in line:
                # Mac: round-trip min/avg/max/stddev
                if "/" in line:
                    nums = line.strip().split("=")[-1].strip().split("/")
                    if len(nums) >= 2:
                        avg_rtt = nums[1] + " ms"

        return {
            "host":      host,
            "reachable": reachable,
            "loss":      loss_pct,
            "avg_rtt":   avg_rtt,
            "raw":       output,
        }
    except subprocess.TimeoutExpired:
        return {"host": host, "reachable": False, "loss": "100%",
                "avg_rtt": "N/A", "raw": "Timeout"}
    except Exception as exc:
        return {"host": host, "reachable": False, "loss": "N/A",
                "avg_rtt": "N/A", "raw": str(exc)}


# ══════════════════════════════════════════════════════════════════════════════
# 2. DNS Resolution
# ══════════════════════════════════════════════════════════════════════════════

def resolve_dns(host: str) -> dict:
    """
    Resolve a hostname to IP addresses (forward DNS).
    Also performs reverse DNS on each IP found.
    """
    logger.info("Resolving DNS for %s ...", host)
    result = {"host": host, "ips": [], "reverse": {}, "error": None}
    try:
        info = socket.getaddrinfo(host, None)
        ips  = list({i[4][0] for i in info})   # deduplicate
        result["ips"] = ips

        for ip in ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result["reverse"][ip] = hostname
            except socket.herror:
                result["reverse"][ip] = "No reverse record"

    except socket.gaierror as exc:
        result["error"] = str(exc)
        logger.error("DNS resolution failed for %s: %s", host, exc)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 3. Port Scanner
# ══════════════════════════════════════════════════════════════════════════════

def _scan_single_port(host: str, port: int, timeout: float = 1.5) -> dict:
    """Try to TCP-connect to one port. Returns status dict."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "status": "OPEN",
                    "service": COMMON_PORTS.get(port, "Unknown")}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"port": port, "status": "CLOSED",
                "service": COMMON_PORTS.get(port, "Unknown")}


def scan_ports(host: str, ports: list[int] | None = None,
               workers: int = 50) -> list[dict]:
    """
    Scan a list of TCP ports concurrently.
    Defaults to COMMON_PORTS if no list given.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    logger.info("Scanning %d ports on %s ...", len(ports), host)
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_single_port, host, p): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["status"] == "OPEN"]
    logger.info("Found %d open ports on %s", len(open_ports), host)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# 4. Traceroute
# ══════════════════════════════════════════════════════════════════════════════

def trace_route(host: str) -> dict:
    """Run traceroute/tracert and capture hop-by-hop output."""
    logger.info("Tracing route to %s ...", host)
    cmd = ["traceroute", host] if sys.platform != "win32" else ["tracert", host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        hops = []
        for line in result.stdout.splitlines()[1:]:   # skip header
            line = line.strip()
            if line:
                hops.append(line)
        return {"host": host, "hops": hops, "raw": result.stdout}
    except subprocess.TimeoutExpired:
        return {"host": host, "hops": [], "raw": "Traceroute timed out"}
    except FileNotFoundError:
        return {"host": host, "hops": [],
                "raw": "traceroute not found — install via: brew install traceroute"}
    except Exception as exc:
        return {"host": host, "hops": [], "raw": str(exc)}


# ══════════════════════════════════════════════════════════════════════════════
# 5. NFS / SMB Connectivity Test
# ══════════════════════════════════════════════════════════════════════════════

def test_nfs_connectivity(host: str) -> dict:
    """
    Test NFS connectivity by checking if the RPC portmapper (111)
    and NFS port (2049) are reachable.
    """
    logger.info("Testing NFS connectivity to %s ...", host)
    rpc  = _scan_single_port(host, 111)
    nfs  = _scan_single_port(host, 2049)
    ok   = rpc["status"] == "OPEN" and nfs["status"] == "OPEN"
    return {
        "host":           host,
        "nfs_reachable":  ok,
        "rpc_port_111":   rpc["status"],
        "nfs_port_2049":  nfs["status"],
        "recommendation": "NFS ports open — share likely mountable" if ok
                          else "NFS ports blocked — check firewall rules (UFW/iptables)",
    }


def test_smb_connectivity(host: str) -> dict:
    """
    Test SMB/CIFS connectivity by checking ports 139 and 445.
    """
    logger.info("Testing SMB/CIFS connectivity to %s ...", host)
    netbios = _scan_single_port(host, 139)
    smb     = _scan_single_port(host, 445)
    ok      = smb["status"] == "OPEN"
    return {
        "host":              host,
        "smb_reachable":     ok,
        "netbios_port_139":  netbios["status"],
        "smb_port_445":      smb["status"],
        "recommendation":    "SMB port open — CIFS share accessible" if ok
                             else "SMB port 445 blocked — check Windows firewall or Samba config",
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6. Report Generator
# ══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Compiles all diagnostic results into a human-readable text report."""

    def __init__(self, output_file: str = "diagnostic_report.txt"):
        self.output_file = output_file
        self.sections: list[str] = []

    def _divider(self, title: str = "") -> str:
        line = "═" * 60
        return f"\n{line}\n  {title}\n{line}" if title else f"\n{line}"

    def add_ping(self, result: dict):
        status = "✅ REACHABLE" if result["reachable"] else "❌ UNREACHABLE"
        self.sections.append(
            self._divider(f"PING — {result['host']}") +
            f"\n  Status   : {status}"
            f"\n  Avg RTT  : {result['avg_rtt']}"
            f"\n  Pkt Loss : {result['loss']}\n"
        )

    def add_dns(self, result: dict):
        if result["error"]:
            body = f"\n  ERROR: {result['error']}"
        else:
            ips  = "\n    ".join(result["ips"]) or "None"
            revs = "\n    ".join(
                f"{ip} → {name}" for ip, name in result["reverse"].items()
            ) or "None"
            body = f"\n  Resolved IPs:\n    {ips}\n  Reverse DNS:\n    {revs}"
        self.sections.append(
            self._divider(f"DNS — {result['host']}") + body + "\n"
        )

    def add_ports(self, host: str, results: list[dict]):
        open_ports = [r for r in results if r["status"] == "OPEN"]
        lines = "\n    ".join(
            f"Port {r['port']:5d} — {r['service']}" for r in open_ports
        ) or "No open ports found"
        self.sections.append(
            self._divider(f"PORT SCAN — {host}") +
            f"\n  Open Ports ({len(open_ports)} found):\n    {lines}\n"
        )

    def add_trace(self, result: dict):
        hops = "\n    ".join(result["hops"]) if result["hops"] else result["raw"]
        self.sections.append(
            self._divider(f"TRACEROUTE — {result['host']}") +
            f"\n  Hops:\n    {hops}\n"
        )

    def add_nfs(self, result: dict):
        status = "✅ REACHABLE" if result["nfs_reachable"] else "❌ UNREACHABLE"
        self.sections.append(
            self._divider(f"NFS — {result['host']}") +
            f"\n  NFS Status  : {status}"
            f"\n  RPC (111)   : {result['rpc_port_111']}"
            f"\n  NFS (2049)  : {result['nfs_port_2049']}"
            f"\n  Advice      : {result['recommendation']}\n"
        )

    def add_smb(self, result: dict):
        status = "✅ REACHABLE" if result["smb_reachable"] else "❌ UNREACHABLE"
        self.sections.append(
            self._divider(f"SMB/CIFS — {result['host']}") +
            f"\n  SMB Status  : {status}"
            f"\n  NetBIOS(139): {result['netbios_port_139']}"
            f"\n  SMB  (445)  : {result['smb_port_445']}"
            f"\n  Advice      : {result['recommendation']}\n"
        )

    def save(self):
        header = (
            f"╔{'═'*58}╗\n"
            f"║{'NETWORK DIAGNOSTIC REPORT':^58}║\n"
            f"║  Generated: {datetime.now():%Y-%m-%d %H:%M:%S}{' '*26}║\n"
            f"╚{'═'*58}╝\n"
        )
        report = header + "".join(self.sections)
        with open(self.output_file, "w") as fh:
            fh.write(report)
        print(report)
        logger.info("Report saved to %s", self.output_file)
        return self.output_file


# ══════════════════════════════════════════════════════════════════════════════
# 7. CLI Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Diagnostic & Troubleshooting Toolkit"
    )
    parser.add_argument("hosts", nargs="+",
                        help="One or more hostnames or IPs to diagnose")
    parser.add_argument("--ping",     action="store_true", help="Run ping test")
    parser.add_argument("--dns",      action="store_true", help="Run DNS resolution")
    parser.add_argument("--ports",    action="store_true", help="Run port scan")
    parser.add_argument("--trace",    action="store_true", help="Run traceroute")
    parser.add_argument("--nfs",      action="store_true", help="Test NFS connectivity")
    parser.add_argument("--smb",      action="store_true", help="Test SMB/CIFS connectivity")
    parser.add_argument("--all",      action="store_true", help="Run ALL diagnostics")
    parser.add_argument("--output",   default="diagnostic_report.txt",
                        help="Output report filename (default: diagnostic_report.txt)")
    return parser.parse_args()


def main():
    args = parse_args()
    run_all = args.all or not any(
        [args.ping, args.dns, args.ports, args.trace, args.nfs, args.smb]
    )

    report = ReportGenerator(args.output)

    for host in args.hosts:
        print(f"\n🔍 Diagnosing: {host}")

        if run_all or args.ping:
            report.add_ping(ping_host(host))

        if run_all or args.dns:
            report.add_dns(resolve_dns(host))

        if run_all or args.ports:
            report.add_ports(host, scan_ports(host))

        if run_all or args.trace:
            report.add_trace(trace_route(host))

        if run_all or args.nfs:
            report.add_nfs(test_nfs_connectivity(host))

        if run_all or args.smb:
            report.add_smb(test_smb_connectivity(host))

    report.save()


if __name__ == "__main__":
    main()
