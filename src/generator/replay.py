"""Replay real-world traffic datasets (CICIDS2017, CSE-CIC-IDS2018, etc.).

Converts CSV rows from standard IDS datasets into our event format so they
can be fed into the same Collector → Detector → Analyst pipeline.

Usage:
    from src.generator.replay import DatasetReplayer
    replayer = DatasetReplayer("data/cicids/Friday-WorkingHours.csv", queue, config)
    replayer.run(max_events=1000)
"""

import csv
import logging
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..queue import MessageQueue

logger = logging.getLogger(__name__)

# Common field name mappings across CICIDS variants
_CICIDS_LABEL_MAP = {
    "BENIGN": "normal",
    "Web Attack – Brute Force": "brute_force",
    "Web Attack – XSS": "xss",
    "Web Attack – Sql Injection": "sqli",
    "SSH-Patator": "brute_force",
    "FTP-Patator": "brute_force",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "slow_post",
    "DoS Slowhttptest": "slow_post",
    "DDoS": "dos",
    "Heartbleed": "exploit",
    "PortScan": "port_scan",
    "Bot": "c2",
    "Infiltration": "c2",
}


class DatasetReplayer:
    """Reads a CICIDS-format CSV and emits events in our pipeline format."""

    def __init__(self, csv_path: str, queue: MessageQueue, config: dict):
        self.csv_path = Path(csv_path)
        self.queue = queue
        self.config = config
        self.container_id = os.environ.get("CONTAINER_ID", "default")

        if not self.csv_path.exists():
            raise FileNotFoundError(f"Dataset not found: {self.csv_path}")

    def _map_label(self, raw_label: str) -> str:
        """Map dataset label to our label taxonomy."""
        raw_label = raw_label.strip()
        return _CICIDS_LABEL_MAP.get(raw_label, "unknown")

    def _row_to_event(self, row: dict) -> dict | None:
        """Convert a CSV row to our event format."""
        try:
            # CICIDS common columns (handle whitespace in headers)
            row = {k.strip(): v.strip() for k, v in row.items() if k}

            src_ip = row.get("Source IP", row.get("Src IP", "0.0.0.0"))
            dst_ip = row.get("Destination IP", row.get("Dst IP", "0.0.0.0"))
            dst_port = int(float(row.get("Destination Port", row.get("Dst Port", 0))))
            protocol = row.get("Protocol", "6")  # 6=TCP

            # Map numeric protocol to HTTP method (approximation)
            method = "GET" if dst_port in (80, 443, 8080) else "POST"

            # Use flow-level features
            fwd_packets = int(float(row.get("Total Fwd Packets",
                                            row.get("Total Fwd Packet", 0))))
            bwd_packets = int(float(row.get("Total Backward Packets",
                                            row.get("Total Bwd packets", 0))))
            flow_duration = float(row.get("Flow Duration", 0))
            fwd_bytes = int(float(row.get("Total Length of Fwd Packets",
                                          row.get("Total Length of Fwd Packet", 0))))
            bwd_bytes = int(float(row.get("Total Length of Bwd Packets",
                                          row.get("TotalLength of Bwd Packet", 0))))

            label_col = row.get("Label", row.get("label", "BENIGN"))
            label = self._map_label(label_col)

            # Synthesize a plausible HTTP path from port
            path = "/api/v1/data" if dst_port in (80, 443, 8080) else f"/port/{dst_port}"

            # Approximate response time from flow duration (microseconds → ms)
            response_time = max(1, int(flow_duration / 1000))

            return {
                "request_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "method": method,
                "path": path,
                "query_params": "",
                "headers": {
                    "User-Agent": "dataset-replay/1.0",
                    "Content-Type": "application/json",
                },
                "payload_size": fwd_bytes,
                "response_code": 200 if label == "normal" else random.choice([200, 400, 403, 500]),
                "response_size": bwd_bytes,
                "response_time_ms": min(response_time, 60000),
                "label": label,
                "container_id": self.container_id,
                "_dataset_meta": {
                    "fwd_packets": fwd_packets,
                    "bwd_packets": bwd_packets,
                    "flow_duration_us": flow_duration,
                    "original_label": label_col,
                },
            }
        except (KeyError, ValueError) as e:
            logger.debug(f"Skipping malformed row: {e}")
            return None

    def run(self, max_events: int = 0) -> int:
        """Read CSV and emit events. Returns count emitted."""
        count = 0
        with open(self.csv_path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = self._row_to_event(row)
                if event:
                    self.queue.put(event)
                    count += 1
                if max_events and count >= max_events:
                    break

        logger.info(f"Replayed {count} events from {self.csv_path.name}")
        return count
