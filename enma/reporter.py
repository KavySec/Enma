import json
from datetime import datetime


class Reporter:
    def __init__(self, diff, scan1, scan2):
        self.diff = diff
        self.scan1 = scan1
        self.scan2 = scan2

    def text_report(self):
        lines = []
        lines.append("=" * 60)
        lines.append("ENMA REPORT")
        lines.append("=" * 60)
        lines.append(f"Target: {self.scan1.get('target', 'Unknown')}")
        lines.append(f"Scan 1: {self.scan1.get('timestamp', 'Unknown')}")
        lines.append(f"Scan 2: {self.scan2.get('timestamp', 'Unknown')}")
        lines.append("=" * 60)
        
        lines.append("\n[SUBDOMAINS]")
        if self.diff["subdomains"]["added"]:
            lines.append(f"  Added ({len(self.diff['subdomains']['added'])}):")
            for s in self.diff["subdomains"]["added"]:
                lines.append(f"    + {s}")
        if self.diff["subdomains"]["removed"]:
            lines.append(f"  Removed ({len(self.diff['subdomains']['removed'])}):")
            for s in self.diff["subdomains"]["removed"]:
                lines.append(f"    - {s}")
        if not self.diff["subdomains"]["added"] and not self.diff["subdomains"]["removed"]:
            lines.append("  no changes here")
        
        lines.append("\n[PORTS]")
        if self.diff["ports"]["added"]:
            lines.append(f"  Added ({len(self.diff['ports']['added'])}):")
            for p in self.diff["ports"]["added"]:
                lines.append(f"    + {p}")
        if self.diff["ports"]["removed"]:
            lines.append(f"  Removed ({len(self.diff['ports']['removed'])}):")
            for p in self.diff["ports"]["removed"]:
                lines.append(f"    - {p}")
        if not self.diff["ports"]["added"] and not self.diff["ports"]["removed"]:
            lines.append("  no changes here")
        
        lines.append("\n[SERVICES]")
        if self.diff["services"]["added"]:
            lines.append(f"  Added ({len(self.diff['services']['added'])}):")
            for s in self.diff["services"]["added"]:
                ver = f" {s.get('version', '')}" if s.get('version') else ""
                lines.append(f"    + {s['port']}/{s['service']}{ver}")
        if self.diff["services"]["removed"]:
            lines.append(f"  Removed ({len(self.diff['services']['removed'])}):")
            for s in self.diff["services"]["removed"]:
                ver = f" {s.get('version', '')}" if s.get('version') else ""
                lines.append(f"    - {s['port']}/{s['service']}{ver}")
        if self.diff["services"]["changed"]:
            lines.append(f"  Changed ({len(self.diff['services']['changed'])}):")
            for c in self.diff["services"]["changed"]:
                old = c["old"]
                new = c["new"]
                old_str = f"{old['service']} {old['version']}".strip()
                new_str = f"{new['service']} {new['version']}".strip()
                lines.append(f"    ~ {c['port']}: {old_str} -> {new_str}")
        if not any([self.diff["services"]["added"], self.diff["services"]["removed"], self.diff["services"]["changed"]]):
            lines.append("  no changes here")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def json_report(self):
        return json.dumps({
            "metadata": {
                "target": self.scan1.get("target"),
                "scan1_time": self.scan1.get("timestamp"),
                "scan2_time": self.scan2.get("timestamp"),
                "generated_at": datetime.now().isoformat()
            },
            "diff": self.diff
        }, indent=2)

    def summary(self):
        total = (
            len(self.diff["subdomains"]["added"]) +
            len(self.diff["subdomains"]["removed"]) +
            len(self.diff["ports"]["added"]) +
            len(self.diff["ports"]["removed"]) +
            len(self.diff["services"]["added"]) +
            len(self.diff["services"]["removed"]) +
            len(self.diff["services"]["changed"])
        )
        
        if total == 0:
            return "[=] no changes detected"
        
        return (
            f"[+] changes: "
            f"{len(self.diff['subdomains']['added'])} subdomains added, "
            f"{len(self.diff['subdomains']['removed'])} removed, "
            f"{len(self.diff['ports']['added'])} ports added, "
            f"{len(self.diff['ports']['removed'])} removed, "
            f"{len(self.diff['services']['changed'])} services changed"
        )
