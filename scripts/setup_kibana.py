"""Set up Kibana data views and import dashboard via NDJSON.

Usage:
    python -m scripts.setup_kibana [--kibana-url http://172.233.75.253:5601]
"""

import argparse
import json
import sys
import requests


KIBANA_HEADERS = {"kbn-xsrf": "true"}


def create_data_view(kibana_url: str, view_id: str, title: str, index: str):
    """Create a Kibana data view (index pattern)."""
    url = f"{kibana_url}/api/data_views/data_view"
    payload = {
        "data_view": {
            "id": view_id,
            "title": index,
            "timeFieldName": "timestamp",
        }
    }
    resp = requests.post(url, json=payload,
                         headers={**KIBANA_HEADERS, "Content-Type": "application/json"})
    if resp.status_code in (200, 409):
        print(f"  [OK] Data view '{title}' ({index})")
    elif "Duplicate" in resp.text or "exists" in resp.text:
        print(f"  [OK] Data view '{title}' already exists")
    else:
        print(f"  [WARN] {resp.status_code}: {resp.text[:200]}")


def delete_old_dashboard(kibana_url: str):
    """Delete the broken dashboard if it exists."""
    url = f"{kibana_url}/api/saved_objects/dashboard/noname-security-overview"
    resp = requests.delete(url, headers=KIBANA_HEADERS)
    if resp.status_code == 200:
        print("  Deleted old broken dashboard")


def build_ndjson():
    """Build NDJSON saved objects for import.

    Uses TSVB (Time Series Visual Builder) and legacy visualizations
    which have a stable API format across Kibana 8.x versions.
    """
    objects = []

    # --- Visualization 1: Anomaly Score Over Time (TSVB) ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-score-timeline",
        "attributes": {
            "title": "Anomaly Score Over Time",
            "visState": json.dumps({
                "title": "Anomaly Score Over Time",
                "type": "metrics",
                "aggs": [],
                "params": {
                    "id": "noname-score-timeline",
                    "type": "timeseries",
                    "series": [
                        {
                            "id": "avg-score",
                            "color": "#FF6B6B",
                            "split_mode": "everything",
                            "label": "Avg Anomaly Score",
                            "metrics": [{"id": "m1", "type": "avg", "field": "anomaly_score"}],
                            "separate_axis": 0,
                            "axis_position": "right",
                            "formatter": "number",
                            "chart_type": "line",
                            "line_width": 2,
                            "point_size": 1,
                            "fill": 0.1,
                        },
                        {
                            "id": "max-score",
                            "color": "#FF0000",
                            "split_mode": "everything",
                            "label": "Max Anomaly Score",
                            "metrics": [{"id": "m2", "type": "max", "field": "anomaly_score"}],
                            "chart_type": "line",
                            "line_width": 1,
                            "point_size": 0,
                            "fill": 0,
                        }
                    ],
                    "time_field": "timestamp",
                    "index_pattern": {"id": "noname-all-traffic-view"},
                    "use_kibana_indexes": False,
                    "interval": "auto",
                    "axis_position": "left",
                    "axis_formatter": "number",
                    "show_legend": 1,
                    "show_grid": 1,
                    "tooltip_mode": "show_all",
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        },
        "references": []
    })

    # --- Visualization 2: Attack Types (Pie chart) ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-attack-types",
        "attributes": {
            "title": "Attack Types Distribution",
            "visState": json.dumps({
                "title": "Attack Types Distribution",
                "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "label",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10,
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "noname-alerts-view"}
        ]
    })

    # --- Visualization 3: Top Attacking IPs (Data Table) ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-top-ips",
        "attributes": {
            "title": "Top Attacking IPs",
            "visState": json.dumps({
                "title": "Top Attacking IPs",
                "type": "table",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "3", "enabled": True, "type": "avg", "params": {"field": "anomaly_score"}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "src_ip",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 15,
                    }, "schema": "bucket"}
                ],
                "params": {
                    "perPage": 15,
                    "showPartialRows": False,
                    "showTotal": True,
                    "totalFunc": "sum",
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "noname-alerts-view"}
        ]
    })

    # --- Visualization 4: Traffic Volume (Histogram) ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-traffic-volume",
        "attributes": {
            "title": "Traffic Volume (Normal vs Attack)",
            "visState": json.dumps({
                "title": "Traffic Volume",
                "type": "histogram",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "params": {
                        "field": "timestamp",
                        "useNormalizedEsInterval": True,
                        "scaleMetricValues": False,
                        "interval": "auto",
                        "used_interval": "auto",
                    }, "schema": "segment"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {
                        "field": "label",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10,
                    }, "schema": "group"}
                ],
                "params": {
                    "type": "histogram",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "seriesParams": [
                        {"show": True, "type": "histogram", "mode": "stacked",
                         "valueAxis": "ValueAxis-1", "data": {"label": "Count", "id": "1"}}
                    ],
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "noname-all-traffic-view"}
        ]
    })

    # --- Visualization 5: Alert Count Metric ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-alert-count",
        "attributes": {
            "title": "Total Alerts",
            "visState": json.dumps({
                "title": "Total Alerts",
                "type": "metric",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}
                ],
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "colorSchema": "Green to Red",
                        "metricColorMode": "None",
                        "style": {"bgFill": "#000", "bgColor": False,
                                  "labelColor": False, "subText": "", "fontSize": 60},
                    }
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "noname-alerts-view"}
        ]
    })

    # --- Visualization 6: Avg Score Metric ---
    objects.append({
        "type": "visualization",
        "id": "noname-viz-avg-score",
        "attributes": {
            "title": "Avg Anomaly Score",
            "visState": json.dumps({
                "title": "Avg Anomaly Score",
                "type": "metric",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "avg",
                     "params": {"field": "anomaly_score"}, "schema": "metric"}
                ],
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "colorSchema": "Green to Red",
                        "style": {"fontSize": 60},
                    }
                }
            }),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "noname-all-traffic-view"}
        ]
    })

    # --- Dashboard ---
    panels = [
        {"panelIndex": "1", "gridData": {"x": 0, "y": 0, "w": 12, "h": 6, "i": "1"},
         "panelRefName": "panel_0", "type": "visualization"},
        {"panelIndex": "2", "gridData": {"x": 12, "y": 0, "w": 12, "h": 6, "i": "2"},
         "panelRefName": "panel_1", "type": "visualization"},
        {"panelIndex": "3", "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "3"},
         "panelRefName": "panel_2", "type": "visualization"},
        {"panelIndex": "4", "gridData": {"x": 0, "y": 6, "w": 24, "h": 6, "i": "4"},
         "panelRefName": "panel_3", "type": "visualization"},
        {"panelIndex": "5", "gridData": {"x": 0, "y": 12, "w": 48, "h": 10, "i": "5"},
         "panelRefName": "panel_4", "type": "visualization"},
        {"panelIndex": "6", "gridData": {"x": 0, "y": 22, "w": 48, "h": 12, "i": "6"},
         "panelRefName": "panel_5", "type": "visualization"},
    ]

    objects.append({
        "type": "dashboard",
        "id": "noname-security-overview",
        "attributes": {
            "title": "Noname Security - Overview",
            "description": "API Security Monitoring Dashboard",
            "panelsJSON": json.dumps(panels),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": json.dumps({"pause": False, "value": 10000}),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {"name": "panel_0", "type": "visualization", "id": "noname-viz-alert-count"},
            {"name": "panel_1", "type": "visualization", "id": "noname-viz-avg-score"},
            {"name": "panel_2", "type": "visualization", "id": "noname-viz-top-ips"},
            {"name": "panel_3", "type": "visualization", "id": "noname-viz-attack-types"},
            {"name": "panel_4", "type": "visualization", "id": "noname-viz-traffic-volume"},
            {"name": "panel_5", "type": "visualization", "id": "noname-viz-score-timeline"},
        ]
    })

    # Convert to NDJSON
    lines = []
    for obj in objects:
        lines.append(json.dumps(obj))
    return "\n".join(lines) + "\n"


def import_ndjson(kibana_url: str, ndjson: str):
    """Import saved objects via Kibana bulk import API."""
    url = f"{kibana_url}/api/saved_objects/_import?overwrite=true"
    files = {"file": ("export.ndjson", ndjson, "application/ndjson")}
    resp = requests.post(url, files=files, headers=KIBANA_HEADERS)

    if resp.status_code == 200:
        result = resp.json()
        if result.get("success"):
            print(f"  [OK] Imported {result.get('successCount', 0)} objects")
        else:
            errors = result.get("errors", [])
            print(f"  Imported with {len(errors)} errors:")
            for err in errors[:5]:
                print(f"    - {err.get('id')}: {err.get('error', {}).get('message', 'unknown')}")
    else:
        print(f"  [ERROR] Import failed: {resp.status_code}")
        print(f"  {resp.text[:300]}")


def main():
    parser = argparse.ArgumentParser(description="Setup Kibana dashboards")
    parser.add_argument("--kibana-url", type=str,
                        default="http://172.233.75.253:5601")
    args = parser.parse_args()

    kibana_url = args.kibana_url.rstrip("/")
    print(f"Setting up Kibana at {kibana_url}")

    # Check connectivity
    try:
        resp = requests.get(f"{kibana_url}/api/status", timeout=5)
        if resp.status_code != 200:
            print(f"Warning: Kibana returned {resp.status_code}")
    except requests.ConnectionError:
        print(f"ERROR: Cannot reach Kibana at {kibana_url}")
        sys.exit(1)

    # Step 1: Data views
    print("\n1. Creating data views...")
    create_data_view(kibana_url, "noname-all-traffic-view",
                     "All Traffic", "noname-all-traffic")
    create_data_view(kibana_url, "noname-alerts-view",
                     "Alerts", "noname-alerts")

    # Step 2: Delete old broken dashboard
    print("\n2. Cleaning up old dashboard...")
    delete_old_dashboard(kibana_url)

    # Step 3: Import visualizations + dashboard via NDJSON
    print("\n3. Importing visualizations and dashboard...")
    ndjson = build_ndjson()
    import_ndjson(kibana_url, ndjson)

    print(f"\nDone! Open dashboard:")
    print(f"  {kibana_url}/app/dashboards#/view/noname-security-overview")
    print(f"\nExplore raw data:")
    print(f"  {kibana_url}/app/discover")


if __name__ == "__main__":
    main()
