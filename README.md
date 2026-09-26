# Enma - Recon Snapshot Diff & Change Detector

**Platform:** Kali/Linux · **Language:** Python · **Type:** Recon Tool · **License:** MIT

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/tests-7%2F7%20passing-brightgreen)
![nmap](https://img.shields.io/badge/scanner-nmap-red)

Enma takes two reconnaissance snapshots of a target over time and diffs them, so you can see exactly what changed — new subdomains, new/closed ports, service version updates, anything that moved between scans.

built this because i kept forgetting what changed between my recon scans lol.

## 📥 Download

```bash
git clone https://github.com/KavySec/Enma.git
cd Enma
pip install -e .
```

or grab the source from the **Code** tab above.

## 🖥️ CLI Interface

Running `enma` with no arguments shows the banner and usage:

```
 _____ _   _ __  __    _    
| ____| \ | |  \/  |  / \   
|  _| |  \| | |\/| | / _ \  
| |___| |\  | |  | |/ ___ \ 
|_____|_| \_|_|  |_/_/   \_\
   [ Red Team ReconDiff v1.0 ]

usage: enma [-h] {scan,diff} ...

ReconDiff - Compare reconnaissance results over time

positional arguments:
  {scan,diff}  Mode to run
    scan       Run a new recon scan
    diff       Compare two scans

options:
  -h, --help   show help and exit
```

## ⚙️ Command Reference

| Command | Arguments | Description |
|---------|-----------|-------------|
| `scan` | `<target>` | Full recon scan (all 65535 ports, slow) |
| `scan` | `<target> --fast` | Scan only top 1000 ports (quick) |
| `scan` | `<target> -p 80,443,8080` | Scan specific ports |
| `scan` | `<target> -o file.json` | Custom output filename |
| `diff` | `<old.json> <new.json>` | Compare two scans, print report |
| `diff` | `<old.json> <new.json> --json` | JSON output for scripting |
| `diff` | `<old.json> <new.json> -o file.txt` | Save report to file |

## 💻 Usage Examples

### A. Take a first snapshot

```console
$ enma scan scanme.nmap.org --fast -o scan1.json

[*] Port range: 1-1000
[*] Scanning scanme.nmap.org...
[*] Enumerating subdomains...
[*] Found 0 subdomains
[*] Scanning ports (1-1000)...
[*] Found 2 open ports
[*] Detecting services...
[*] Detected 2 services
[+] Results saved to scan1.json
```

### B. Scan again later (days/weeks later)

```console
$ enma scan scanme.nmap.org --fast -o scan2.json
```

### C. Compare the two snapshots

```console
$ enma diff scan1.json scan2.json

============================================================
ENMA REPORT
============================================================
Target: scanme.nmap.org
Scan 1: 2026-09-25T03:50:36
Scan 2: 2026-09-25T03:50:41
============================================================

[SUBDOMAINS]
  Added (1):
    + api.scanme.nmap.org
  Removed (1):
    - test.scanme.nmap.org

[PORTS]
  Added (1):
    + 8443
  Removed (1):
    - 8080

[SERVICES]
  Changed (1):
    ~ 443: nginx 1.24 -> Apache 2.4

============================================================
```

### D. JSON output (for scripting)

```console
$ enma diff scan1.json scan2.json --json
{
  "metadata": {
    "target": "scanme.nmap.org",
    "scan1_time": "2026-09-25T03:50:36",
    "scan2_time": "2026-09-25T03:50:41",
    "generated_at": "2026-09-25T03:51:02"
  },
  "diff": { ... }
}
```

## 🔬 How It Works

```
enma scan target.com
        ↓
   Scanner
   ├── subdomain enum (DNS resolution, ~65 common names)
   ├── port scan (nmap -p <range> --open -oG)
   └── service detection (nmap -sV)
        ↓
   JSON snapshot (scan_target_timestamp.json)
        ↓
enma diff old.json new.json
        ↓
   Differ
   ├── subdomains → set difference
   ├── ports → set difference
   └── services → dict compare (added / removed / changed)
        ↓
   Reporter → text report or JSON
```

**Key features:**

- **Same-line nmap parsing** — handles modern nmap grepable output where `Host:` and `Ports:` sit on one line
- **Version detection** — service versions compared between scans, so you catch `nginx 1.24 → Apache 2.4` style changes
- **Change detection** — not just added/removed, also flags services that changed on the same port
- **Graceful errors** — clean messages if nmap is missing, scan times out, or save fails

## 🛠️ Build & Installation

### Requirements

- Python 3.8+
- nmap (`sudo apt install nmap`)

### Steps

```bash
git clone https://github.com/KavySec/Enma.git
cd Enma
pip install -e .
```

Verify:

```console
$ enma --help
$ which enma
/usr/local/bin/enma
```

## 🧪 Testing

7 tests covering the differ, the nmap grepable parser (both multi-line and same-line formats), version field extraction, and save/load:

```console
$ python3 -m pytest tests/ -v

tests/test_recondiff.py::test_subdomain_diff PASSED
tests/test_recondiff.py::test_no_changes PASSED
tests/test_recondiff.py::test_nmap_grepable_parser PASSED
tests/test_recondiff.py::test_nmap_grepable_parser_same_line PASSED
tests/test_recondiff.py::test_nmap_grepable_parser_version_fields PASSED
tests/test_recondiff.py::test_nmap_grepable_parser_no_open_ports PASSED
tests/test_recondiff.py::test_save_and_load PASSED

7 passed in 0.02s
```

## ⚠️ Troubleshooting

| Problem | Fix |
|---------|-----|
| `[!] nmap not found` | `sudo apt install nmap` |
| Found 0 open ports on a live host | run with `sudo` — some scans need root |
| `Could not save results: Permission denied` | use `-o /tmp/scan.json` or run from a writable folder |
| `Port scan timed out` | use `--fast` or `-p` to narrow the port range |
| Diff says `Invalid JSON file` | make sure both args are actual scan JSONs, not reports |

## ⚡ Roadmap

- **v1.1** — HTTP status/title changes, tech fingerprint, CSV export
- **v2.0** — scheduled scans, SQLite history, change severity scoring, notifications

## ⚖️ Disclaimer

FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY. This tool is meant for scanning systems you own or have explicit permission to test. The author assumes no liability for misuse, damage, or legal consequences resulting from use of this software. Always get proper authorization before scanning any target.

## 📄 License

MIT — see [LICENSE](LICENSE)

## 👤 Author

**KavySec**
