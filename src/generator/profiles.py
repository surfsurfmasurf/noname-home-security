"""Normal traffic behavior profiles for different device types."""

import random
import uuid

# Common User-Agent strings per device type
USER_AGENTS = {
    "browser": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "MyApp/3.2.1 (iOS 17.2; iPhone15,2)",
        "MyApp/3.2.0 (Android 14; Pixel 8)",
    ],
    "iot": [
        "SmartPlug/1.0 (ESP32)",
        "ESP32-HTTPClient/2.0",
        "HomeAssistant/2024.1",
        "SmartCamera/2.1 (ARM; Linux 5.15)",
        "Tasmota/13.3.0 (ESP8266)",
    ],
    "api_client": [
        "python-requests/2.31.0",
        "axios/1.6.2",
        "curl/8.4.0",
        "Go-http-client/2.0",
        "node-fetch/3.3.2",
        "okhttp/4.12.0",
    ],
}

# API endpoint definitions — expanded for realistic traffic
ENDPOINTS = {
    "auth": [
        {"method": "POST", "path": "/api/v1/auth/login", "normal_codes": [200, 401]},
        {"method": "POST", "path": "/api/v1/auth/logout", "normal_codes": [200, 204]},
        {"method": "POST", "path": "/api/v1/auth/refresh", "normal_codes": [200, 401]},
        {"method": "POST", "path": "/api/v1/auth/register", "normal_codes": [201, 409]},
        {"method": "POST", "path": "/api/v1/auth/forgot-password", "normal_codes": [200, 404]},
        {"method": "POST", "path": "/api/v1/auth/verify-email", "normal_codes": [200, 400]},
    ],
    "users": [
        {"method": "GET", "path": "/api/v1/users/me", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/users/{id}", "normal_codes": [200, 404]},
        {"method": "PUT", "path": "/api/v1/users/me", "normal_codes": [200]},
        {"method": "PATCH", "path": "/api/v1/users/me/settings", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/users/me/notifications", "normal_codes": [200]},
        {"method": "DELETE", "path": "/api/v1/users/me/sessions/{id}", "normal_codes": [204, 404]},
        {"method": "GET", "path": "/api/v1/users/me/activity", "normal_codes": [200]},
        {"method": "POST", "path": "/api/v1/users/me/avatar", "normal_codes": [200, 413]},
    ],
    "products": [
        {"method": "GET", "path": "/api/v1/products", "normal_codes": [200], "has_pagination": True},
        {"method": "GET", "path": "/api/v1/products/{id}", "normal_codes": [200, 404]},
        {"method": "GET", "path": "/api/v1/products/search", "normal_codes": [200], "has_search": True},
        {"method": "GET", "path": "/api/v1/products/{id}/reviews", "normal_codes": [200], "has_pagination": True},
        {"method": "POST", "path": "/api/v1/products/{id}/reviews", "normal_codes": [201, 400]},
        {"method": "GET", "path": "/api/v1/products/categories", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/products/featured", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/products/{id}/related", "normal_codes": [200]},
    ],
    "orders": [
        {"method": "POST", "path": "/api/v1/orders", "normal_codes": [201, 400]},
        {"method": "GET", "path": "/api/v1/orders/{id}", "normal_codes": [200, 404]},
        {"method": "GET", "path": "/api/v1/orders", "normal_codes": [200], "has_pagination": True},
        {"method": "PUT", "path": "/api/v1/orders/{id}/cancel", "normal_codes": [200, 400, 404]},
        {"method": "GET", "path": "/api/v1/orders/{id}/tracking", "normal_codes": [200, 404]},
        {"method": "POST", "path": "/api/v1/orders/{id}/refund", "normal_codes": [200, 400]},
        {"method": "GET", "path": "/api/v1/cart", "normal_codes": [200]},
        {"method": "POST", "path": "/api/v1/cart/items", "normal_codes": [200, 400]},
        {"method": "DELETE", "path": "/api/v1/cart/items/{id}", "normal_codes": [204, 404]},
    ],
    "iot_telemetry": [
        {"method": "POST", "path": "/api/v1/telemetry/report", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/telemetry/status", "normal_codes": [200]},
        {"method": "POST", "path": "/api/v1/telemetry/heartbeat", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/telemetry/config", "normal_codes": [200, 304]},
        {"method": "POST", "path": "/api/v1/telemetry/events", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/telemetry/firmware/check", "normal_codes": [200]},
    ],
    "admin": [
        {"method": "GET", "path": "/api/v1/admin/dashboard", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/admin/users", "normal_codes": [200], "has_pagination": True},
        {"method": "GET", "path": "/api/v1/admin/logs", "normal_codes": [200], "has_pagination": True},
        {"method": "POST", "path": "/api/v1/admin/settings", "normal_codes": [200]},
    ],
    "system": [
        {"method": "GET", "path": "/health", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/status", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/version", "normal_codes": [200]},
        {"method": "OPTIONS", "path": "/api/v1/products", "normal_codes": [204]},
        {"method": "GET", "path": "/.well-known/openid-configuration", "normal_codes": [200]},
    ],
    "files": [
        {"method": "POST", "path": "/api/v1/files/upload", "normal_codes": [200, 413]},
        {"method": "GET", "path": "/api/v1/files/{id}", "normal_codes": [200, 404]},
        {"method": "GET", "path": "/api/v1/files/{id}/download", "normal_codes": [200, 404]},
        {"method": "DELETE", "path": "/api/v1/files/{id}", "normal_codes": [204, 404]},
    ],
    "webhooks": [
        {"method": "POST", "path": "/api/v1/webhooks", "normal_codes": [201]},
        {"method": "GET", "path": "/api/v1/webhooks", "normal_codes": [200]},
        {"method": "DELETE", "path": "/api/v1/webhooks/{id}", "normal_codes": [204, 404]},
        {"method": "POST", "path": "/webhooks/stripe", "normal_codes": [200]},
        {"method": "POST", "path": "/webhooks/github", "normal_codes": [200]},
    ],
}

# Search terms for realistic query generation
_SEARCH_TERMS = [
    "shoes", "laptop", "wireless headphones", "usb cable", "monitor",
    "keyboard", "mouse", "phone case", "charger", "backpack",
    "camera", "tablet", "smartwatch", "speaker", "router",
]

_SORT_FIELDS = ["price", "rating", "created_at", "name", "popularity"]
_SORT_ORDERS = ["asc", "desc"]

# Realistic error responses that happen occasionally
ERROR_CODES_WEIGHTED = [
    (429, 0.02),   # Rate limited
    (500, 0.005),  # Internal error
    (502, 0.003),  # Bad gateway
    (503, 0.002),  # Service unavailable
    (504, 0.001),  # Gateway timeout
]


class DeviceProfile:
    """Defines normal behavior patterns for a device type."""

    def __init__(self, name: str, device_type: str, src_ip: str,
                 endpoint_groups: list[str], req_per_min: tuple[float, float],
                 active_hours: tuple[int, int], payload_size: tuple[int, int],
                 response_time: tuple[int, int]):
        self.name = name
        self.device_type = device_type
        self.src_ip = src_ip
        self.endpoint_groups = endpoint_groups
        self.req_per_min = req_per_min       # (min, max) requests per minute
        self.active_hours = active_hours     # (start, end) hours
        self.payload_size = payload_size     # (min, max) bytes
        self.response_time = response_time   # (min, max) ms

    def get_user_agent(self) -> str:
        return random.choice(USER_AGENTS[self.device_type])

    def get_endpoint(self) -> dict:
        group = random.choice(self.endpoint_groups)
        endpoint = random.choice(ENDPOINTS[group])
        path = endpoint["path"].replace("{id}", str(random.randint(1, 1000)))

        # Build realistic query params
        query_params = self._build_query_params(endpoint)

        # Occasional error response (rate limit, 5xx)
        response_code = self._maybe_error(endpoint)

        return {
            "method": endpoint["method"],
            "path": path,
            "query_params": query_params,
            "response_code": response_code,
        }

    def _build_query_params(self, endpoint: dict) -> str:
        params = []
        if endpoint.get("has_pagination"):
            params.append(f"page={random.randint(1, 20)}")
            params.append(f"limit={random.choice([10, 20, 25, 50, 100])}")
            if random.random() < 0.3:
                params.append(f"sort={random.choice(_SORT_FIELDS)}")
                params.append(f"order={random.choice(_SORT_ORDERS)}")
        if endpoint.get("has_search"):
            params.append(f"q={random.choice(_SEARCH_TERMS)}")
            if random.random() < 0.4:
                params.append(f"category={random.choice(['electronics', 'clothing', 'home', 'sports'])}")
        return "&".join(params)

    def _maybe_error(self, endpoint: dict) -> int:
        """Small chance of realistic error responses."""
        for code, probability in ERROR_CODES_WEIGHTED:
            if random.random() < probability:
                return code
        return random.choice(endpoint["normal_codes"])

    def get_headers(self) -> dict:
        """Generate realistic request headers."""
        headers = {
            "User-Agent": self.get_user_agent(),
            "Content-Type": "application/json",
            "Accept": random.choice([
                "application/json",
                "application/json, text/plain, */*",
                "*/*",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "X-Request-ID": str(uuid.uuid4()),
        }
        # Most requests include auth token
        if random.random() < 0.85:
            headers["Authorization"] = f"Bearer eyJ{random.randbytes(20).hex()}"
        # Browser-specific headers
        if self.device_type == "browser":
            headers["Accept-Language"] = random.choice([
                "en-US,en;q=0.9", "ko-KR,ko;q=0.9,en;q=0.8",
                "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9",
            ])
            if random.random() < 0.3:
                headers["Referer"] = random.choice([
                    "https://myapp.com/dashboard",
                    "https://myapp.com/products",
                    "https://myapp.com/search",
                ])
        # Mobile app version header
        if self.device_type == "mobile":
            headers["X-App-Version"] = random.choice(["3.2.1", "3.2.0", "3.1.5"])
            headers["X-Platform"] = random.choice(["iOS", "Android"])
        # IoT devices send minimal headers
        if self.device_type == "iot":
            headers = {
                "User-Agent": self.get_user_agent(),
                "Content-Type": "application/json",
                "X-Device-ID": f"dev-{random.randint(1000, 9999)}",
            }
        return headers

    def get_payload_size(self) -> int:
        return random.randint(*self.payload_size)

    def get_response_time(self, hour: int | None = None) -> int:
        """Response time varies with server load (peak hours = slower)."""
        base = random.randint(*self.response_time)
        if hour is not None:
            # Peak hours: 9-12, 14-17 → 1.5x slower
            if hour in range(9, 12) or hour in range(14, 17):
                base = int(base * random.uniform(1.2, 1.8))
            # Night: faster
            elif hour in range(0, 6):
                base = int(base * random.uniform(0.5, 0.8))
        return base

    def get_response_size(self, method: str = "GET") -> int:
        """Response size varies by method."""
        if method in ("DELETE", "OPTIONS"):
            return random.randint(0, 64)
        if method == "POST":
            return random.randint(64, 2048)
        return random.randint(128, 8192)

    def is_active(self, hour: int) -> bool:
        start, end = self.active_hours
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end  # wraps midnight


# Pre-defined device profiles representing a typical home network
DEFAULT_PROFILES = [
    DeviceProfile(
        name="desktop_browser",
        device_type="browser",
        src_ip="192.168.0.10",
        endpoint_groups=["auth", "users", "products", "orders", "files", "system"],
        req_per_min=(2, 15),
        active_hours=(8, 23),
        payload_size=(64, 2048),
        response_time=(20, 200),
    ),
    DeviceProfile(
        name="mobile_app",
        device_type="mobile",
        src_ip="192.168.0.20",
        endpoint_groups=["auth", "users", "products", "orders", "system"],
        req_per_min=(1, 8),
        active_hours=(7, 24),
        payload_size=(32, 1024),
        response_time=(50, 300),
    ),
    DeviceProfile(
        name="smart_plug",
        device_type="iot",
        src_ip="192.168.0.30",
        endpoint_groups=["iot_telemetry"],
        req_per_min=(1, 3),
        active_hours=(0, 24),  # 24h
        payload_size=(16, 128),
        response_time=(10, 50),
    ),
    DeviceProfile(
        name="smart_camera",
        device_type="iot",
        src_ip="192.168.0.31",
        endpoint_groups=["iot_telemetry"],
        req_per_min=(2, 5),
        active_hours=(0, 24),
        payload_size=(64, 512),
        response_time=(10, 80),
    ),
    DeviceProfile(
        name="backend_service",
        device_type="api_client",
        src_ip="192.168.0.100",
        endpoint_groups=["users", "orders", "admin", "webhooks", "system"],
        req_per_min=(5, 30),
        active_hours=(0, 24),
        payload_size=(128, 4096),
        response_time=(5, 50),
    ),
]
