# Network Diagnostic & Troubleshooting Toolkit

## What Does This Project Do?
This is a Python tool that acts like having tcpdump, ping, nslookup, 
and a port scanner all in one place. It is designed to help diagnose 
and troubleshoot network issues the same way a Technical Support Engineer 
would in a real company.

It checks:
- Whether a server or website can be reached (ping)
- How a hostname gets converted to an IP address (DNS)
- Which ports are open or blocked on a server (port scanning)
- The path your data takes to reach a server (traceroute)
- Whether NFS file share ports are reachable (port 111 and 2049)
- Whether SMB/CIFS file share ports are reachable (port 139 and 445)

All results are saved into a diagnostic report text file automatically.

---

## Why This Matters (Real World Use)
At companies like Cohesity, Technical Support Engineers diagnose 
customer issues every day such as:
- "I cannot connect to my backup server"
- "My NFS share is not mounting"
- "I cannot access files over the network"

This tool automates those exact diagnostic steps.

---

## Real Output Example
```
╔══════════════════════════════════════════════════════════╗
║                NETWORK DIAGNOSTIC REPORT                 ║
║  Generated: 2026-03-22 10:45:00                          ║
╚══════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════
  PING — google.com
══════════════════════════════════════════════════════════════
  Status   : ✅ REACHABLE
  Avg RTT  : 12.4 ms
  Pkt Loss : 0%

══════════════════════════════════════════════════════════════
  DNS — google.com
══════════════════════════════════════════════════════════════
  Resolved IPs:
    142.250.80.46
  Reverse DNS:
    142.250.80.46 → lax17s55-in-f14.1e100.net

══════════════════════════════════════════════════════════════
  PORT SCAN — google.com
══════════════════════════════════════════════════════════════
  Open Ports (3 found):
    Port    80 — HTTP
    Port   443 — HTTPS
    Port  8080 — HTTP-Alt
```

---

## What You Need Before Starting
- A Mac, Windows, or Linux computer
- Python 3 installed
- No extra libraries needed (uses only built-in Python)

---

## Step 1 - Check Python is installed
Open Terminal and type:
```
python3 --version
```
You should see Python 3.x.x

---

## Step 2 - Download the Project
Save the network_toolkit.py file into a folder on your Desktop called:
network_diagnostic_toolkit

---

## Step 3 - Go Into the Project Folder
In Terminal type:
```
cd ~/Desktop/network_diagnostic_toolkit
```

---

## Step 4 - Run the Program

### Quick test (ping + DNS only on google.com):
```
python3 network_toolkit.py google.com --ping --dns
```

### Full diagnostic on one host:
```
python3 network_toolkit.py google.com --all
```

### Diagnose multiple hosts at once:
```
python3 network_toolkit.py google.com github.com --all
```

### Only scan ports:
```
python3 network_toolkit.py google.com --ports
```

### Only test NFS connectivity:
```
python3 network_toolkit.py 192.168.1.100 --nfs
```

### Only test SMB/CIFS connectivity:
```
python3 network_toolkit.py 192.168.1.100 --smb
```

### Save report to a custom file name:
```
python3 network_toolkit.py google.com --all --output my_report.txt
```

---

## All Available Options
| Option | What it does |
|---|---|
| --ping | Test if the host is reachable |
| --dns | Resolve hostname to IP address |
| --ports | Scan common TCP ports (21 ports checked) |
| --trace | Trace the network route hop by hop |
| --nfs | Test if NFS file share ports are open |
| --smb | Test if SMB/CIFS file share ports are open |
| --all | Run all of the above together |
| --output | Name of the report file to save |

---

## Ports This Tool Checks
| Port | Service |
|---|---|
| 22 | SSH |
| 53 | DNS |
| 80 | HTTP |
| 111 | RPC (needed for NFS) |
| 139 | NetBIOS (needed for SMB) |
| 443 | HTTPS |
| 445 | SMB/CIFS |
| 2049 | NFS |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |

---

## Where Are My Results Saved?
After running, you will find these files in your project folder:
- diagnostic_report.txt — Full diagnostic report
- network_toolkit.log — Log of everything the program did

---

## How the Program is Built
| Part | What it does |
|---|---|
| ping_host() | Runs system ping and parses the result |
| resolve_dns() | Converts hostname to IP, does reverse lookup |
| scan_ports() | Scans 21 common TCP ports using threads (fast) |
| trace_route() | Runs traceroute and captures each hop |
| test_nfs_connectivity() | Checks ports 111 and 2049 for NFS |
| test_smb_connectivity() | Checks ports 139 and 445 for SMB |
| ReportGenerator | Compiles everything into a readable report |

---

## How to Add to GitHub
```
cd ~/Desktop/network_diagnostic_toolkit
git init
git add .
git commit -m "Initial commit - Network Diagnostic Toolkit"
git branch -M main
git remote add origin https://github.com/Akhi0119/network-diagnostic-toolkit.git
git push -u origin main
```

---

## Author
Akhila Bollu
akhilab0119@gmail.com
GitHub: https://github.com/Akhi0119
