import subprocess
import json
import re
import socket
from datetime import datetime


class Scanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "ports": [],
            "services": []
        }

    def scan_subdomains(self, wordlist=None):
        # just checking which common subdomains resolve, nothing crazy
        common_subdomains = [
            "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
            "dns", "webmail", "email", "vpn", "remote", "portal",
            "admin", "test", "dev", "staging", "api", "app", "blog",
            "shop", "store", "cdn", "media", "static", "img", "images",
            "beta", "alpha", "demo", "sandbox", "docs", "wiki", "git",
            "jenkins", "ci", "monitor", "grafana", "kibana", "status",
            "mx", "mx1", "mx2", "imap", "pop3", "ldap", "sso",
            "auth", "login", "dashboard", "panel", "cp", "cpanel",
            "direct", "gateway", "proxy", "load", "lb", "db", "mysql",
            "redis", "mongo", "elastic", "search", "cache", "queue"
        ]

        if wordlist:
            with open(wordlist, "r") as f:
                common_subdomains = [line.strip() for line in f if line.strip()]

        found = []
        for sub in common_subdomains:
            domain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(domain)
                found.append(domain)
            except socket.gaierror:
                pass  # doesnt exist, skip

        self.results["subdomains"] = sorted(set(found))
        return self

    def scan_ports(self, ports="1-65535"):
        try:
            cmd = ["nmap", "-p", ports, "--open", "-oG", "-", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            parsed_ports, _ = self._parse_nmap_grepable(result.stdout)
            self.results["ports"] = sorted(set(parsed_ports))
        except FileNotFoundError:
            print("[!] nmap not found. Install: sudo apt install nmap")
        except subprocess.TimeoutExpired:
            print("[!] Port scan timed out")
        return self

    def scan_services(self, ports="1-65535"):
        try:
            # -sV for version detection, only looking at open ports
            cmd = ["nmap", "-sV", "-p", ports, "--open", "-oG", "-", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            _, services = self._parse_nmap_grepable(result.stdout)
            self.results["services"] = sorted(services, key=lambda x: x["port"])
        except FileNotFoundError:
            print("[!] nmap not found")
        except subprocess.TimeoutExpired:
            print("[!] Service scan timed out")
        return self

    def _parse_nmap_grepable(self, output):
        # nmap -oG format puts Host and Ports on same line nowadays
        # format per port: port/state/proto/owner/service/rpc/version
        ports = []
        services = []
        current_host = None

        for line in output.split("\n"):
            if line.startswith("Host:"):
                host_match = re.match(r"Host:\s+(\S+)", line)
                if host_match:
                    current_host = host_match.group(1)

            if current_host and "Ports:" in line:
                ports_match = re.search(r"Ports: (.+)", line)
                if not ports_match:
                    continue

                ports_str = ports_match.group(1)
                for entry in ports_str.split(","):
                    entry = entry.strip()
                    parts = entry.split("/")
                    if len(parts) < 3:
                        continue

                    try:
                        port_num = int(parts[0])
                    except ValueError:
                        continue
                    state = parts[1]
                    service = parts[4] if len(parts) > 4 else "unknown"
                    # version field position varies a bit depending on nmap version
                    if len(parts) > 7 and parts[7]:
                        version = parts[7]
                    elif len(parts) > 6 and parts[6]:
                        version = parts[6]
                    else:
                        version = ""

                    if state == "open":
                        ports.append(port_num)
                        services.append({
                            "port": port_num,
                            "service": service,
                            "version": version.strip()
                        })

                current_host = None

        return ports, services

    def run_all(self, ports="1-65535", wordlist=None):
        print(f"[*] Scanning {self.target}...")
        print("[*] Enumerating subdomains...")
        self.scan_subdomains(wordlist)
        print(f"[*] Found {len(self.results['subdomains'])} subdomains")

        print(f"[*] Scanning ports ({ports})...")
        self.scan_ports(ports)
        print(f"[*] Found {len(self.results['ports'])} open ports")

        print("[*] Detecting services...")
        self.scan_services(ports)
        print(f"[*] Detected {len(self.results['services'])} services")

        return self.results

    def save(self, filename):
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results saved to {filename}")
        return filename

    def load(self, filename):
        with open(filename, "r") as f:
            self.results = json.load(f)
        return self.results
