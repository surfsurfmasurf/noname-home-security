"""Run the full detection pipeline — generates traffic, detects, analyzes.

Usage:
    python -m scripts.run_pipeline [--events 100] [--no-llm] [--no-es]
"""

import argparse
import logging
import sys
import threading
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.collector import Collector
from src.detector import Detector
from src.analyst import LLMAnalyst
from src.action import Responder
from src.storage import ESClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pipeline")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Run full detection pipeline")
    parser.add_argument("--events", type=int, default=100,
                        help="Number of events to generate")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis (no Claude API calls)")
    parser.add_argument("--no-es", action="store_true",
                        help="Skip Elasticsearch storage")
    parser.add_argument("--config", type=str, default="config/settings.yaml")
    args = parser.parse_args()

    config = load_config(args.config)

    # --- Initialize queues ---
    raw_queue = LocalQueue()
    features_queue = LocalQueue()
    alerts_queue = LocalQueue()
    actions_queue = LocalQueue()
    es_queue = LocalQueue() if not args.no_es else None

    # --- Initialize ES ---
    es_client = None
    if not args.no_es:
        try:
            es_client = ESClient(config)
            if es_client.ping():
                es_client.init_indices()
                logger.info("Elasticsearch connected")
            else:
                logger.warning("Elasticsearch not reachable, continuing without ES")
                es_client = None
                es_queue = None
        except Exception as e:
            logger.warning(f"Elasticsearch setup failed: {e}, continuing without ES")
            es_client = None
            es_queue = None

    # --- Initialize agents ---
    generator = TrafficGenerator(raw_queue, config)
    collector = Collector(raw_queue, features_queue, config)
    detector = Detector(features_queue, alerts_queue, es_queue, config)

    # Load trained models
    try:
        detector.load_models()
        logger.info("Models loaded successfully")
    except FileNotFoundError:
        logger.error("Models not found! Run 'python -m scripts.train' first.")
        sys.exit(1)

    # --- Generate traffic ---
    logger.info(f"=== Generating {args.events} traffic events ===")
    generator.run(args.events)

    # --- Process through pipeline ---
    logger.info("=== Processing through Collector ===")
    collector.run(max_events=args.events)

    logger.info("=== Running Detector ===")
    detector.run(max_events=args.events)

    logger.info(f"Detector stats: {detector.stats}")

    # --- ES indexing (background) ---
    if es_client and es_queue:
        indexed = 0
        while not es_queue.empty():
            result = es_queue.get(timeout=0.1)
            if result:
                try:
                    es_client.index_traffic(result)
                    indexed += 1
                except Exception as e:
                    logger.error(f"ES indexing error: {e}")
        logger.info(f"Indexed {indexed} events to Elasticsearch")

    # --- LLM Analysis ---
    if not args.no_llm and not alerts_queue.empty():
        logger.info("=== Running LLM Analyst ===")
        analyst = LLMAnalyst(alerts_queue, actions_queue, config)
        alert_count = alerts_queue.size()
        analyzed = analyst.run(max_events=alert_count)
        logger.info(f"Analyzed {analyzed} alerts with LLM")
    elif alerts_queue.empty():
        logger.info("No alerts to analyze")
    else:
        # Without LLM, pass alerts directly to responder
        while not alerts_queue.empty():
            alert = alerts_queue.get(timeout=0.1)
            if alert:
                alert["llm_analysis"] = "(LLM skipped)"
                alert["severity"] = "HIGH" if alert.get("anomaly_score", 0) >= 80 else "MEDIUM"
                alert["recommended_action"] = "investigate"
                actions_queue.put(alert)

    # --- Responder ---
    if not actions_queue.empty():
        logger.info("=== Running Responder ===")
        responder = Responder(actions_queue, es_client=es_client, config=config)
        responder.run(max_events=actions_queue.size())
        logger.info(f"Responder stats: {responder.stats}")

    # --- Final stats ---
    if es_client:
        logger.info(f"Elasticsearch stats: {es_client.get_stats()}")

    logger.info("=== Pipeline complete ===")


if __name__ == "__main__":
    main()
