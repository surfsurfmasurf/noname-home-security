"""Continuous monitoring mode — generates and analyzes traffic in real-time.

Runs indefinitely until Ctrl+C. Generates traffic at a configurable rate,
processes through the full pipeline, and stores results in Elasticsearch.

Usage:
    python -m scripts.run_continuous [--rate 5] [--no-llm] [--no-es]
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.generator.profiles import DEFAULT_PROFILES
from src.collector import Collector
from src.detector import Detector
from src.analyst import LLMAnalyst
from src.action import Responder
from src.storage import ESClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("continuous")

# Graceful shutdown
shutdown_event = threading.Event()


def signal_handler(sig, frame):
    logger.info("Shutdown signal received, stopping...")
    shutdown_event.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def generator_loop(generator: TrafficGenerator, rate: int):
    """Generate traffic at a steady rate."""
    interval = 1.0 / rate if rate > 0 else 1.0
    while not shutdown_event.is_set():
        generator.run(1)
        shutdown_event.wait(timeout=interval)
    logger.info("Generator stopped")


def collector_loop(collector: Collector):
    """Continuously collect and extract features."""
    while not shutdown_event.is_set():
        collector.process_one()
    logger.info("Collector stopped")


def detector_loop(detector: Detector, es_client: ESClient | None):
    """Continuously detect anomalies and index to ES."""
    while not shutdown_event.is_set():
        result = detector.process_one()
        if result and es_client:
            try:
                es_client.index_traffic(result)
            except Exception as e:
                logger.error(f"ES indexing error: {e}")
    logger.info("Detector stopped")


def analyst_loop(analyst: LLMAnalyst):
    """Continuously analyze alerts with LLM."""
    while not shutdown_event.is_set():
        analyst.process_one()
    logger.info("Analyst stopped")


def responder_loop(responder: Responder):
    """Continuously respond to analyzed alerts."""
    while not shutdown_event.is_set():
        responder.process_one()
    logger.info("Responder stopped")


def stats_loop(detector: Detector, es_client: ESClient | None, interval: int = 30):
    """Print stats periodically."""
    while not shutdown_event.is_set():
        shutdown_event.wait(timeout=interval)
        if shutdown_event.is_set():
            break
        stats = detector.stats
        msg = (f"[STATS] Processed: {stats['processed']}, "
               f"Alerts: {stats['alerts']}, "
               f"Alert rate: {stats['alert_rate']:.1%}")
        if es_client:
            try:
                es_stats = es_client.get_stats()
                msg += f", ES docs: {es_stats}"
            except Exception:
                pass
        logger.info(msg)


def main():
    parser = argparse.ArgumentParser(description="Continuous monitoring mode")
    parser.add_argument("--rate", type=int, default=5,
                        help="Events per second to generate")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis")
    parser.add_argument("--llm-threshold", type=float, default=50,
                        help="Min anomaly score to send to LLM (default: 50)")
    parser.add_argument("--no-es", action="store_true",
                        help="Skip Elasticsearch")
    parser.add_argument("--config", type=str, default="config/settings.yaml")
    args = parser.parse_args()

    config = load_config(args.config)

    # --- Container / Profile from env ---
    container_id = os.environ.get("CONTAINER_ID", "default")
    profile_name = os.environ.get("PROFILE", "")

    profiles = None
    if profile_name:
        profiles = [p for p in DEFAULT_PROFILES if p.name == profile_name]
        if not profiles:
            available = [p.name for p in DEFAULT_PROFILES]
            logger.error(f"Unknown profile: {profile_name}. Available: {available}")
            sys.exit(1)
        logger.info(f"Using profile: {profile_name}")

    logger.info(f"Container ID: {container_id}")

    # --- Queues ---
    raw_queue = LocalQueue()
    features_queue = LocalQueue()
    alerts_queue = LocalQueue()
    actions_queue = LocalQueue()

    # --- Elasticsearch ---
    es_client = None
    if not args.no_es:
        try:
            es_client = ESClient(config)
            if es_client.ping():
                es_client.init_indices()
                logger.info("Elasticsearch connected")
            else:
                logger.warning("ES not reachable, continuing without")
                es_client = None
        except Exception as e:
            logger.warning(f"ES setup failed: {e}")
            es_client = None

    # --- Agents ---
    generator = TrafficGenerator(raw_queue, config, profiles=profiles)
    collector = Collector(raw_queue, features_queue, config)
    detector = Detector(features_queue, alerts_queue, None, config)

    try:
        detector.load_models()
        logger.info("Models loaded")
    except FileNotFoundError:
        logger.error("Models not found! Run 'python -m scripts.train' first.")
        sys.exit(1)

    responder = Responder(actions_queue, es_client=es_client, config=config)

    # --- Start threads ---
    threads = [
        threading.Thread(target=generator_loop, args=(generator, args.rate),
                         name="generator", daemon=True),
        threading.Thread(target=collector_loop, args=(collector,),
                         name="collector", daemon=True),
        threading.Thread(target=detector_loop, args=(detector, es_client),
                         name="detector", daemon=True),
        threading.Thread(target=responder_loop, args=(responder,),
                         name="responder", daemon=True),
        threading.Thread(target=stats_loop, args=(detector, es_client),
                         name="stats", daemon=True),
    ]

    if not args.no_llm:
        llm_queue = LocalQueue()  # filtered queue for LLM
        analyst = LLMAnalyst(llm_queue, actions_queue, config)
        llm_threshold = args.llm_threshold

        def llm_filter_loop():
            """Route alerts: high-score → LLM, low-score → passthrough."""
            while not shutdown_event.is_set():
                alert = alerts_queue.get(timeout=1.0)
                if alert is None:
                    continue
                score = alert.get("anomaly_score", 0)
                if score >= llm_threshold:
                    logger.info(f"Sending to LLM (score={score:.1f}): {alert.get('src_ip')}")
                    llm_queue.put(alert)
                else:
                    alert["llm_analysis"] = "(Below LLM threshold)"
                    alert["severity"] = (
                        "HIGH" if score >= 70 else "MEDIUM"
                    )
                    alert["recommended_action"] = "investigate"
                    actions_queue.put(alert)

        threads.append(
            threading.Thread(target=llm_filter_loop, name="llm_filter", daemon=True)
        )
        threads.append(
            threading.Thread(target=analyst_loop, args=(analyst,),
                             name="analyst", daemon=True)
        )
        logger.info(f"LLM enabled for alerts with score >= {llm_threshold}")
    else:
        # Without LLM, pass alerts directly to actions queue
        def passthrough_loop():
            while not shutdown_event.is_set():
                alert = alerts_queue.get(timeout=1.0)
                if alert:
                    alert["llm_analysis"] = "(LLM skipped)"
                    alert["severity"] = (
                        "CRITICAL" if alert.get("anomaly_score", 0) >= 90
                        else "HIGH" if alert.get("anomaly_score", 0) >= 70
                        else "MEDIUM"
                    )
                    alert["recommended_action"] = "investigate"
                    actions_queue.put(alert)

        threads.append(
            threading.Thread(target=passthrough_loop, name="passthrough", daemon=True)
        )

    logger.info(f"Starting continuous monitoring at {args.rate} events/sec")
    logger.info("Press Ctrl+C to stop")

    for t in threads:
        t.start()

    # Wait for shutdown signal
    try:
        while not shutdown_event.is_set():
            shutdown_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass

    shutdown_event.set()
    logger.info("Waiting for threads to finish...")
    for t in threads:
        t.join(timeout=5.0)

    logger.info(f"Final stats: {detector.stats}")
    if es_client:
        logger.info(f"ES stats: {es_client.get_stats()}")
    logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
