"""Collector Agent — reads raw traffic, extracts features, forwards to detector."""

import logging

from ..queue import MessageQueue
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class Collector:
    """Reads from raw_traffic queue, extracts features, puts on features queue."""

    def __init__(self, input_queue: MessageQueue, output_queue: MessageQueue,
                 config: dict):
        window = config.get("collector", {}).get("window_seconds", 300)
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.extractor = FeatureExtractor(window_seconds=window)
        self._processed = 0

    def process_one(self) -> dict | None:
        """Process a single event from input queue. Returns extracted features or None."""
        event = self.input_queue.get(timeout=1.0)
        if event is None:
            return None

        features = self.extractor.extract(event)
        self.output_queue.put(features)
        self._processed += 1

        if self._processed % 100 == 0:
            logger.info(f"Collector processed {self._processed} events")

        return features

    def run(self, max_events: int | None = None) -> int:
        """Process events continuously or up to max_events.

        Returns total events processed.
        """
        count = 0
        while max_events is None or count < max_events:
            result = self.process_one()
            if result is not None:
                count += 1
            elif max_events is not None:
                # Queue empty and we have a target — check if input is done
                if self.input_queue.empty():
                    break
        return count

    @property
    def processed_count(self) -> int:
        return self._processed
