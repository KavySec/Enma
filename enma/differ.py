# just comparing two dicts/sets, nothing fancy


class Differ:
    def __init__(self, scan1, scan2):
        self.scan1 = scan1
        self.scan2 = scan2
        self.diff = {
            "subdomains": {"added": [], "removed": []},
            "ports": {"added": [], "removed": []},
            "services": {"added": [], "removed": [], "changed": []}
        }

    def compare_subdomains(self):
        subs1 = set(self.scan1.get("subdomains", []))
        subs2 = set(self.scan2.get("subdomains", []))
        
        self.diff["subdomains"]["added"] = sorted(subs2 - subs1)
        self.diff["subdomains"]["removed"] = sorted(subs1 - subs2)
        return self

    def compare_ports(self):
        ports1 = set(self.scan1.get("ports", []))
        ports2 = set(self.scan2.get("ports", []))
        
        self.diff["ports"]["added"] = sorted(ports2 - ports1)
        self.diff["ports"]["removed"] = sorted(ports1 - ports2)
        return self

    def compare_services(self):
        services1 = {s["port"]: s for s in self.scan1.get("services", [])}
        services2 = {s["port"]: s for s in self.scan2.get("services", [])}
        
        ports1 = set(services1.keys())
        ports2 = set(services2.keys())
        
        self.diff["services"]["added"] = [services2[p] for p in sorted(ports2 - ports1)]
        self.diff["services"]["removed"] = [services1[p] for p in sorted(ports1 - ports2)]
        
        # check if service/version changed on same port
        for port in sorted(ports1 & ports2):
            s1 = services1[port]
            s2 = services2[port]
            if s1["service"] != s2["service"] or s1["version"] != s2["version"]:
                self.diff["services"]["changed"].append({
                    "port": port,
                    "old": s1,
                    "new": s2
                })
        
        return self

    def compare_all(self):
        self.compare_subdomains()
        self.compare_ports()
        self.compare_services()
        return self.diff

    def has_changes(self):
        for category in self.diff.values():
            for change_type, items in category.items():
                if items:
                    return True
        return False
