# Enma

basically i got tired of running nmap/subdomain stuff every week and forgetting what changed between scans. so this takes two scan snapshots and tells me whats new, whats gone, etc.

## what it does

- subdomain enum (just DNS resolution, nothing fancy)
- port scan + service/version detection (uses nmap under the hood)
- diff two scans so you can see what changed

## requirements

- python 3.8+
- nmap (`sudo apt install nmap`)

## install

```bash
git clone https://github.com/KavyaSharma/Enma.git
cd Enma
pip install -e .
```

## usage

```bash
# full scan (all ports, takes a while)
enma scan example.com

# fast scan (top 1000 ports)
enma scan example.com --fast

# specific ports
enma scan example.com -p 80,443,8080

# custom output file
enma scan example.com -o first_scan.json

# compare two scans
enma diff old_scan.json new_scan.json

# json output for scripting
enma diff old_scan.json new_scan.json --json

# save report
enma diff old_scan.json new_scan.json -o report.txt
```

## tips

- use `sudo` if you want faster/more accurate nmap results
- `--fast` is good for quick checks
- scan once, wait a few days, scan again, diff to see changes

## example

```
$ enma scan example.com
[*] Scanning example.com...
[*] Enumerating subdomains...
[*] Found 5 subdomains
[*] Scanning ports (1-1000)...
[*] Found 3 open ports
[*] Detecting services...
[*] Detected 3 services
[+] Results saved to scan_example.com_20260315_103000.json

$ enma diff scan1.json scan2.json
============================================================
ENMA REPORT
============================================================
Target: example.com
Scan 1: 2026-03-15T10:30:00
Scan 2: 2026-03-22T14:45:00
============================================================

[SUBDOMAINS]
  Added (2):
    + api.example.com
    + staging.example.com
  Removed (1):
    - test.example.com

[PORTS]
  Added (1):
    + 8443

[SERVICES]
  Changed (1):
    ~ 443: nginx 1.24 -> Apache 2.4

============================================================
```

## how it works

```
scan1.json + scan2.json
        ↓
   Differ (set diff for subs/ports, dict compare for services)
        ↓
   Reporter (text or json)
```

## roadmap

- v1.1: http status/title changes, tech fingerprint, csv export
- v2.0: scheduled scans, sqlite history, notifications

## license

MIT

## author

Kavya Sharma
