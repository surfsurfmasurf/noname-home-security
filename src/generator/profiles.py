"""Normal traffic behavior profiles for different device types."""

import random

# Common User-Agent strings per device type
USER_AGENTS = {
    "browser": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile",
    ],
    "iot": [
        "SmartPlug/1.0",
        "ESP32-HTTPClient/2.0",
        "HomeAssistant/2024.1",
    ],
    "api_client": [
        "python-requests/2.31.0",
        "axios/1.6.2",
        "curl/8.4.0",
    ],
}

# API endpoint definitions
ENDPOINTS = {
    "auth": [
        {"method": "POST", "path": "/api/v1/auth/login", "normal_codes": [200, 401]},
        {"method": "POST", "path": "/api/v1/auth/logout", "normal_codes": [200]},
        {"method": "POST", "path": "/api/v1/auth/refresh", "normal_codes": [200, 401]},
    ],
    "users": [
        {"method": "GET", "path": "/api/v1/users/me", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/users/{id}", "normal_codes": [200, 404]},
        {"method": "PUT", "path": "/api/v1/users/me", "normal_codes": [200]},
    ],
    "products": [
        {"method": "GET", "path": "/api/v1/products", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/products/{id}", "normal_codes": [200, 404]},
        {"method": "GET", "path": "/api/v1/products/search", "normal_codes": [200]},
    ],
    "orders": [
        {"method": "POST", "path": "/api/v1/orders", "normal_codes": [201]},
        {"method": "GET", "path": "/api/v1/orders/{id}", "normal_codes": [200, 404]},
        {"method": "GET", "path": "/api/v1/orders", "normal_codes": [200]},
    ],
    "iot_telemetry": [
        {"method": "POST", "path": "/api/v1/telemetry/report", "normal_codes": [200]},
        {"method": "GET", "path": "/api/v1/telemetry/status", "normal_codes": [200]},
    ],
}


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
        return {
            "method": endpoint["method"],
            "path": path,
            "response_code": random.choice(endpoint["normal_codes"]),
        }

    def get_payload_size(self) -> int:
        return random.randint(*self.payload_size)

    def get_response_time(self) -> int:
        return random.randint(*self.response_time)

    def get_response_size(self) -> int:
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
        endpoint_groups=["auth", "users", "products", "orders"],
        req_per_min=(2, 15),
        active_hours=(8, 23),
        payload_size=(64, 2048),
        response_time=(20, 200),
    ),
    DeviceProfile(
        name="mobile_app",
        device_type="mobile",
        src_ip="192.168.0.20",
        endpoint_groups=["auth", "users", "products"],
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
        endpoint_groups=["users", "orders"],
        req_per_min=(5, 30),
        active_hours=(0, 24),
        payload_size=(128, 4096),
        response_time=(5, 50),
    ),
]
