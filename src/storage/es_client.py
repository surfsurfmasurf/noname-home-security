"""Elasticsearch client for storing and querying security events."""

import logging
import os
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

# Index mappings for structured data
INDEX_MAPPINGS = {
    "noname-alerts": {
        "properties": {
            "request_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "src_ip": {"type": "ip"},
            "raw_summary": {"type": "text"},
            "anomaly_score": {"type": "float"},
            "model_scores": {
                "properties": {
                    "isolation_forest": {"type": "float"},
                    "autoencoder": {"type": "float"},
                    "signature": {"type": "keyword"},
                }
            },
            "features": {"type": "object", "enabled": False},
            "label": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "llm_analysis": {"type": "text"},
            "recommended_action": {"type": "keyword"},
            "is_threat": {"type": "boolean"},
            "attack_type": {"type": "keyword"},
            "llm_analyzed": {"type": "boolean"},
            "container_id": {"type": "keyword"},
        }
    },
    "noname-all-traffic": {
        "properties": {
            "request_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "src_ip": {"type": "ip"},
            "raw_summary": {"type": "text"},
            "anomaly_score": {"type": "float"},
            "label": {"type": "keyword"},
            "container_id": {"type": "keyword"},
        }
    },
}


class ESClient:
    """Elasticsearch helper for indexing and querying security events."""

    def __init__(self, config: dict):
        es_cfg = config.get("elasticsearch", {})
        self.host = es_cfg.get("host", "http://localhost:9200")
        self.index_prefix = es_cfg.get("index_prefix", "noname")
        self.es = Elasticsearch(self.host)
        self._initialized = False

    def init_indices(self) -> None:
        """Create indices with mappings if they don't exist."""
        for index_name, mappings in INDEX_MAPPINGS.items():
            if not self.es.indices.exists(index=index_name):
                self.es.indices.create(
                    index=index_name,
                    mappings=mappings,
                )
                logger.info(f"Created index: {index_name}")
            else:
                logger.info(f"Index already exists: {index_name}")
        self._initialized = True

    def index_alert(self, alert: dict) -> None:
        """Index an alert document."""
        doc = {**alert}
        # Remove feature_vector (not needed in ES, large)
        doc.pop("feature_vector", None)
        if "timestamp" not in doc:
            doc["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.es.index(index="noname-alerts", document=doc)

    def index_traffic(self, result: dict) -> None:
        """Index a traffic analysis result (all traffic, not just alerts)."""
        doc = {
            "request_id": result.get("request_id"),
            "timestamp": result.get("timestamp",
                                    datetime.now(timezone.utc).isoformat()),
            "src_ip": result.get("src_ip"),
            "raw_summary": result.get("raw_summary"),
            "anomaly_score": result.get("anomaly_score"),
            "label": result.get("label"),
            "container_id": result.get("container_id",
                                       os.environ.get("CONTAINER_ID", "default")),
        }
        self.es.index(index="noname-all-traffic", document=doc)

    def update_mappings(self) -> None:
        """Add new fields to existing indices (safe to call multiple times)."""
        new_fields = {
            "container_id": {"type": "keyword"},
            "is_threat": {"type": "boolean"},
            "attack_type": {"type": "keyword"},
            "llm_analyzed": {"type": "boolean"},
        }
        for index_name in INDEX_MAPPINGS:
            try:
                if self.es.indices.exists(index=index_name):
                    self.es.indices.put_mapping(
                        index=index_name,
                        properties=new_fields,
                    )
                    logger.info(f"Updated mapping for {index_name}")
            except Exception as e:
                logger.debug(f"Mapping update for {index_name}: {e}")

    def search_alerts(self, min_score: float = 0, size: int = 100) -> list[dict]:
        """Query alerts above a minimum anomaly score."""
        result = self.es.search(
            index="noname-alerts",
            query={"range": {"anomaly_score": {"gte": min_score}}},
            sort=[{"timestamp": "desc"}],
            size=size,
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def get_stats(self) -> dict:
        """Get basic statistics from indices."""
        stats = {}
        for index in ["noname-alerts", "noname-all-traffic"]:
            try:
                count = self.es.count(index=index)["count"]
                stats[index] = count
            except Exception:
                stats[index] = 0
        return stats

    def ping(self) -> bool:
        """Check if Elasticsearch is reachable."""
        try:
            return self.es.ping()
        except Exception:
            return False
