"""Set up Kibana dashboards and visualizations for Noname Security.

Creates index patterns, visualizations, and a dashboard via Kibana API.

Usage:
    python -m scripts.setup_kibana [--kibana-url http://172.233.75.253:5601]
"""

import argparse
import json
import sys
import requests


def create_data_view(kibana_url: str, view_id: str, title: str, index: str,
                     time_field: str = "timestamp"):
    """Create a Kibana data view (index pattern)."""
    url = f"{kibana_url}/api/data_views/data_view"
    payload = {
        "data_view": {
            "id": view_id,
            "title": index,
            "timeFieldName": time_field,
        }
    }
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    resp = requests.post(url, json=payload, headers=headers)
    if resp.status_code in (200, 409):
        print(f"  Data view '{title}' created/exists")
    else:
        print(f"  Data view '{title}' failed: {resp.status_code} {resp.text[:200]}")


def create_dashboard(kibana_url: str):
    """Create the main security dashboard via saved objects API."""
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}

    # Dashboard definition using Kibana saved objects
    dashboard = {
        "attributes": {
            "title": "Noname Security - Overview",
            "description": "API Security Monitoring Dashboard",
            "panelsJSON": json.dumps([
                {
                    "version": "8.0.0",
                    "type": "lens",
                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 8, "i": "1"},
                    "panelIndex": "1",
                    "embeddableConfig": {
                        "attributes": {
                            "title": "Anomaly Score Over Time",
                            "visualizationType": "lnsXY",
                            "state": {
                                "datasourceStates": {
                                    "formBased": {
                                        "layers": {
                                            "layer1": {
                                                "columns": {
                                                    "col1": {
                                                        "operationType": "date_histogram",
                                                        "sourceField": "timestamp",
                                                        "params": {"interval": "auto"}
                                                    },
                                                    "col2": {
                                                        "operationType": "average",
                                                        "sourceField": "anomaly_score"
                                                    }
                                                },
                                                "columnOrder": ["col1", "col2"]
                                            }
                                        }
                                    }
                                },
                                "visualization": {
                                    "layers": [{
                                        "layerId": "layer1",
                                        "accessors": ["col2"],
                                        "xAccessor": "col1",
                                        "seriesType": "line"
                                    }]
                                }
                            },
                            "references": [{
                                "type": "index-pattern",
                                "id": "noname-all-traffic-view",
                                "name": "indexpattern-datasource-layer-layer1"
                            }]
                        }
                    }
                },
                {
                    "version": "8.0.0",
                    "type": "lens",
                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 8, "i": "2"},
                    "panelIndex": "2",
                    "embeddableConfig": {
                        "attributes": {
                            "title": "Alerts by Severity",
                            "visualizationType": "lnsPie",
                            "state": {
                                "datasourceStates": {
                                    "formBased": {
                                        "layers": {
                                            "layer1": {
                                                "columns": {
                                                    "col1": {
                                                        "operationType": "terms",
                                                        "sourceField": "severity",
                                                        "params": {"size": 5}
                                                    },
                                                    "col2": {
                                                        "operationType": "count"
                                                    }
                                                },
                                                "columnOrder": ["col1", "col2"]
                                            }
                                        }
                                    }
                                }
                            },
                            "references": [{
                                "type": "index-pattern",
                                "id": "noname-alerts-view",
                                "name": "indexpattern-datasource-layer-layer1"
                            }]
                        }
                    }
                },
                {
                    "version": "8.0.0",
                    "type": "lens",
                    "gridData": {"x": 0, "y": 8, "w": 24, "h": 8, "i": "3"},
                    "panelIndex": "3",
                    "embeddableConfig": {
                        "attributes": {
                            "title": "Top Attacking IPs",
                            "visualizationType": "lnsDatatable",
                            "state": {
                                "datasourceStates": {
                                    "formBased": {
                                        "layers": {
                                            "layer1": {
                                                "columns": {
                                                    "col1": {
                                                        "operationType": "terms",
                                                        "sourceField": "src_ip",
                                                        "params": {"size": 10}
                                                    },
                                                    "col2": {
                                                        "operationType": "count"
                                                    },
                                                    "col3": {
                                                        "operationType": "average",
                                                        "sourceField": "anomaly_score"
                                                    }
                                                },
                                                "columnOrder": ["col1", "col2", "col3"]
                                            }
                                        }
                                    }
                                }
                            },
                            "references": [{
                                "type": "index-pattern",
                                "id": "noname-alerts-view",
                                "name": "indexpattern-datasource-layer-layer1"
                            }]
                        }
                    }
                },
                {
                    "version": "8.0.0",
                    "type": "lens",
                    "gridData": {"x": 24, "y": 8, "w": 24, "h": 8, "i": "4"},
                    "panelIndex": "4",
                    "embeddableConfig": {
                        "attributes": {
                            "title": "Attack Types Distribution",
                            "visualizationType": "lnsPie",
                            "state": {
                                "datasourceStates": {
                                    "formBased": {
                                        "layers": {
                                            "layer1": {
                                                "columns": {
                                                    "col1": {
                                                        "operationType": "terms",
                                                        "sourceField": "label",
                                                        "params": {"size": 10}
                                                    },
                                                    "col2": {
                                                        "operationType": "count"
                                                    }
                                                },
                                                "columnOrder": ["col1", "col2"]
                                            }
                                        }
                                    }
                                }
                            },
                            "references": [{
                                "type": "index-pattern",
                                "id": "noname-alerts-view",
                                "name": "indexpattern-datasource-layer-layer1"
                            }]
                        }
                    }
                },
                {
                    "version": "8.0.0",
                    "type": "lens",
                    "gridData": {"x": 0, "y": 16, "w": 48, "h": 10, "i": "5"},
                    "panelIndex": "5",
                    "embeddableConfig": {
                        "attributes": {
                            "title": "Traffic Volume (Normal vs Attack)",
                            "visualizationType": "lnsXY",
                            "state": {
                                "datasourceStates": {
                                    "formBased": {
                                        "layers": {
                                            "layer1": {
                                                "columns": {
                                                    "col1": {
                                                        "operationType": "date_histogram",
                                                        "sourceField": "timestamp",
                                                        "params": {"interval": "auto"}
                                                    },
                                                    "col2": {
                                                        "operationType": "count"
                                                    },
                                                    "col3": {
                                                        "operationType": "terms",
                                                        "sourceField": "label",
                                                        "params": {"size": 10}
                                                    }
                                                },
                                                "columnOrder": ["col1", "col3", "col2"]
                                            }
                                        }
                                    }
                                },
                                "visualization": {
                                    "layers": [{
                                        "layerId": "layer1",
                                        "accessors": ["col2"],
                                        "xAccessor": "col1",
                                        "splitAccessor": "col3",
                                        "seriesType": "bar_stacked"
                                    }]
                                }
                            },
                            "references": [{
                                "type": "index-pattern",
                                "id": "noname-all-traffic-view",
                                "name": "indexpattern-datasource-layer-layer1"
                            }]
                        }
                    }
                }
            ]),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-1h",
            "refreshInterval": {"pause": False, "value": 10000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        }
    }

    url = f"{kibana_url}/api/saved_objects/dashboard/noname-security-overview"
    resp = requests.post(url, json=dashboard, headers=headers)
    if resp.status_code in (200, 409):
        print("  Dashboard 'Noname Security - Overview' created")
    else:
        # Try PUT for update
        resp = requests.put(url, json=dashboard, headers=headers)
        if resp.status_code == 200:
            print("  Dashboard updated")
        else:
            print(f"  Dashboard creation failed: {resp.status_code}")
            print(f"  Response: {resp.text[:300]}")


def main():
    parser = argparse.ArgumentParser(description="Setup Kibana dashboards")
    parser.add_argument("--kibana-url", type=str,
                        default="http://172.233.75.253:5601",
                        help="Kibana URL")
    args = parser.parse_args()

    kibana_url = args.kibana_url.rstrip("/")

    print(f"Setting up Kibana at {kibana_url}")

    # Check connectivity
    try:
        resp = requests.get(f"{kibana_url}/api/status", timeout=5)
        if resp.status_code != 200:
            print(f"Warning: Kibana returned status {resp.status_code}")
    except requests.ConnectionError:
        print(f"ERROR: Cannot reach Kibana at {kibana_url}")
        print("Is Kibana running? Check with: curl -s http://172.233.75.253:5601/api/status")
        sys.exit(1)

    # Step 1: Create data views (index patterns)
    print("\n1. Creating data views...")
    create_data_view(kibana_url, "noname-all-traffic-view",
                     "All Traffic", "noname-all-traffic")
    create_data_view(kibana_url, "noname-alerts-view",
                     "Alerts", "noname-alerts")

    # Step 2: Create dashboard
    print("\n2. Creating dashboard...")
    create_dashboard(kibana_url)

    print(f"\nDone! Open Kibana:")
    print(f"  {kibana_url}/app/dashboards#/view/noname-security-overview")
    print(f"\nOr explore raw data:")
    print(f"  {kibana_url}/app/discover")


if __name__ == "__main__":
    main()
