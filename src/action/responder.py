"""Action Agent — executes responses to detected threats."""

import json
import logging
from datetime import datetime, timezone

from ..queue import MessageQueue

logger = logging.getLogger(__name__)

# Severity color codes for console output
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",      # yellow
    "MEDIUM": "\033[94m",    # blue
    "LOW": "\033[92m",       # green
}
RESET = "\033[0m"


class Responder:
    """Executes response actions based on analyst results."""

    def __init__(self, input_queue: MessageQueue, es_client=None,
                 config: dict | None = None):
        self.input_queue = input_queue
        self.es_client = es_client
        self.mode = (config or {}).get("action", {}).get("mode", "log")
        self._actions_taken = 0
        self._blocked_ips: set[str] = set()

    def _log_action(self, result: dict) -> None:
        """Log the action to console with color-coded severity."""
        severity = result.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(severity, "")
        score = result.get("anomaly_score", 0)
        ip = result.get("src_ip", "?")
        action = result.get("recommended_action", "monitor")
        analysis = result.get("llm_analysis", "")[:150]

        print(
            f"\n{color}[{severity}]{RESET} "
            f"Score: {score} | IP: {ip} | Action: {action}\n"
            f"  Analysis: {analysis}\n"
        )

    def _execute_action(self, result: dict) -> None:
        """Execute the recommended action."""
        action = result.get("recommended_action", "monitor")
        ip = result.get("src_ip", "")

        if action == "block_ip" and ip:
            self._blocked_ips.add(ip)
            logger.warning(f"BLOCKED IP: {ip}")
        elif action == "rate_limit":
            logger.info(f"RATE LIMITED: {ip}")
        elif action == "investigate":
            logger.info(f"FLAGGED FOR INVESTIGATION: {ip}")

    def process_one(self) -> dict | None:
        """Process a single action from the queue."""
        result = self.input_queue.get(timeout=2.0)
        if result is None:
            return None

        self._log_action(result)
        self._execute_action(result)

        # Store in ES if available
        if self.es_client is not None:
            try:
                self.es_client.index_alert(result)
            except Exception as e:
                logger.error(f"Failed to index alert to ES: {e}")

        self._actions_taken += 1
        return result

    def run(self, max_events: int | None = None) -> int:
        """Process actions continuously or up to max_events."""
        count = 0
        while max_events is None or count < max_events:
            result = self.process_one()
            if result is not None:
                count += 1
            elif max_events is not None and self.input_queue.empty():
                break
        return count

    @property
    def stats(self) -> dict:
        return {
            "actions_taken": self._actions_taken,
            "blocked_ips": list(self._blocked_ips),
        }
