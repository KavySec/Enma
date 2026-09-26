import os
import tempfile
from enma.differ import Differ
from enma.scanner import Scanner


def test_subdomain_diff():
    scan1 = {
        "target": "example.com",
        "timestamp": "2026-01-01T00:00:00",
        "subdomains": ["www.example.com", "mail.example.com", "old.example.com"],
        "ports": [80, 443],
        "services": [
            {"port": 80, "service": "http", "version": "nginx"},
            {"port": 443, "service": "https", "version": "nginx"}
        ]
    }

    scan2 = {
        "target": "example.com",
        "timestamp": "2026-01-02T00:00:00",
        "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
        "ports": [80, 443, 8443],
        "services": [
            {"port": 80, "service": "http", "version": "nginx"},
            {"port": 443, "service": "https", "version": "apache"},
            {"port": 8443, "service": "https-alt", "version": ""}
        ]
    }

    differ = Differ(scan1, scan2)
    diff = differ.compare_all()

    assert diff["subdomains"]["added"] == ["api.example.com"]
    assert diff["subdomains"]["removed"] == ["old.example.com"]
    assert diff["ports"]["added"] == [8443]
    assert diff["ports"]["removed"] == []
    assert len(diff["services"]["changed"]) == 1
    assert diff["services"]["changed"][0]["port"] == 443


def test_no_changes():
    scan1 = {
        "target": "example.com",
        "timestamp": "2026-01-01T00:00:00",
        "subdomains": ["www.example.com"],
        "ports": [80],
        "services": [{"port": 80, "service": "http", "version": ""}]
    }

    scan2 = scan1.copy()

    differ = Differ(scan1, scan2)
    diff = differ.compare_all()

    assert differ.has_changes() is False


def test_nmap_grepable_parser():
    scanner = Scanner("example.com")

    sample_output = """# Nmap 7.94 scan initiated
Host: 192.168.1.1 ()
	Host is up (0.0023s latency).
	Ports: 22/open/tcp//ssh///OpenSSH 8.9, 80/open/tcp//http///nginx 1.18, 443/open/tcp//https///nginx 1.18
"""

    ports, services = scanner._parse_nmap_grepable(sample_output)

    assert ports == [22, 80, 443]
    assert len(services) == 3
    assert services[0]["port"] == 22
    assert services[0]["service"] == "ssh"
    assert services[0]["version"] == "OpenSSH 8.9"
    assert services[1]["service"] == "http"
    assert services[1]["version"] == "nginx 1.18"
    assert services[2]["service"] == "https"
    assert services[2]["version"] == "nginx 1.18"


def test_nmap_grepable_parser_same_line():
    """Real nmap -oG output puts Host and Ports on the same line."""
    scanner = Scanner("example.com")

    sample_output = (
        "# Nmap 7.99 scan initiated\n"
        "Host: 142.250.67.174 (174.67.250.142.in-addr.arpa)\tStatus: Up\n"
        "Host: 142.250.67.174 (174.67.250.142.in-addr.arpa)\t"
        "Ports: 80/open/tcp//http///, 443/open/tcp//https///, "
        "22/closed/tcp//ssh///\n"
    )

    ports, services = scanner._parse_nmap_grepable(sample_output)

    assert ports == [80, 443]
    assert len(services) == 2
    assert services[0] == {"port": 80, "service": "http", "version": ""}
    assert services[1] == {"port": 443, "service": "https", "version": ""}


def test_nmap_grepable_parser_version_fields():
    """nmap -sV puts version after service/rpc fields; may be at index 6 or 7."""
    scanner = Scanner("example.com")
    sample = (
        "Host: 1.2.3.4\tPorts: "
        "22/open/tcp//ssh///OpenSSH 8.9, "
        "80/open/tcp//http//gws/, "
        "443/open/tcp//ssl|https//gws/\n"
    )
    ports, services = scanner._parse_nmap_grepable(sample)
    assert ports == [22, 80, 443]
    by_port = {s["port"]: s for s in services}
    assert by_port[22]["version"] == "OpenSSH 8.9"
    assert by_port[80]["version"] == "gws"
    assert by_port[443]["service"] == "ssl|https"
    assert by_port[443]["version"] == "gws"


def test_nmap_grepable_parser_no_open_ports():
    scanner = Scanner("example.com")
    ports, services = scanner._parse_nmap_grepable(
        "Host: 1.2.3.4\tPorts: 80/closed/tcp//http///\n"
    )
    assert ports == []
    assert services == []


def test_save_and_load():
    scanner = Scanner("example.com")
    scanner.results = {
        "target": "example.com",
        "timestamp": "2026-01-01T00:00:00",
        "subdomains": ["www.example.com"],
        "ports": [80],
        "services": [{"port": 80, "service": "http", "version": ""}]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        scanner.save(temp_path)

        scanner2 = Scanner("example.com")
        loaded = scanner2.load(temp_path)

        assert loaded["target"] == "example.com"
        assert loaded["subdomains"] == ["www.example.com"]
        assert loaded["ports"] == [80]
    finally:
        os.unlink(temp_path)


if __name__ == "__main__":
    test_subdomain_diff()
    print("test_subdomain_diff passed")

    test_no_changes()
    print("test_no_changes passed")

    test_nmap_grepable_parser()
    print("test_nmap_grepable_parser passed")

    test_nmap_grepable_parser_same_line()
    print("test_nmap_grepable_parser_same_line passed")

    test_nmap_grepable_parser_version_fields()
    print("test_nmap_grepable_parser_version_fields passed")

    test_nmap_grepable_parser_no_open_ports()
    print("test_nmap_grepable_parser_no_open_ports passed")

    test_save_and_load()
    print("test_save_and_load passed")

    print("\nAll tests passed!")