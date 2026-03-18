"""LLM Analyst Agent — uses Claude API to interpret anomaly detections."""

import json
import logging

import anthropic

from ..queue import MessageQueue

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """You are a network security analyst. Analyze the following anomalous API traffic event detected by our monitoring system.

## Event Details
- **Source IP:** {src_ip}
- **Timestamp:** {timestamp}
- **Request:** {raw_summary}
- **Anomaly Score:** {anomaly_score}/100

## Model Scores
- Isolation Forest: {if_score}
- Autoencoder: {ae_score}
- Signature Matches: {signatures}

## Features
{features_text}

## Instructions
1. Determine if this is a TRUE THREAT or FALSE POSITIVE
2. If a threat, classify the attack type
3. Assess severity: LOW / MEDIUM / HIGH / CRITICAL
4. Recommend a specific action: monitor / block_ip / rate_limit / investigate
5. Explain your reasoning in 2-3 sentences

Respond in JSON format:
{{
  "is_threat": true/false,
  "attack_type": "string or null",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommended_action": "monitor|block_ip|rate_limit|investigate",
  "explanation": "string"
}}"""


class LLMAnalyst:
    """Analyzes anomalous events using Claude API."""

    def __init__(self, input_queue: MessageQueue, output_queue: MessageQueue,
                 config: dict):
        self.input_queue = input_queue
        self.output_queue = output_queue

        analyst_cfg = config.get("analyst", {})
        self.model = analyst_cfg.get("model", "claude-sonnet-4-20250514")
        self.max_tokens = analyst_cfg.get("max_tokens", 1024)

        self.client = anthropic.Anthropic()  # uses ANTHROPIC_API_KEY env var
        self._analyzed = 0

    def _build_prompt(self, alert: dict) -> str:
        """Build the analysis prompt from alert data."""
        model_scores = alert.get("model_scores", {})
        features = alert.get("features", {})

        features_text = "\n".join(
            f"  - {k}: {v}" for k, v in features.items()
        )

        return ANALYSIS_PROMPT.format(
            src_ip=alert.get("src_ip", "unknown"),
            timestamp=alert.get("timestamp", "unknown"),
            raw_summary=alert.get("raw_summary", "unknown"),
            anomaly_score=alert.get("anomaly_score", 0),
            if_score=model_scores.get("isolation_forest", 0),
            ae_score=model_scores.get("autoencoder", 0),
            signatures=model_scores.get("signature", []),
            features_text=features_text,
        )

    def analyze_one(self, alert: dict) -> dict:
        """Analyze a single alert using Claude API."""
        prompt = self._build_prompt(alert)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = response.content[0].text

        # Parse JSON response
        try:
            # Find JSON in response (handles markdown code blocks)
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            analysis = json.loads(response_text[json_start:json_end])
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"Failed to parse LLM response: {response_text[:200]}")
            analysis = {
                "is_threat": True,
                "attack_type": "unknown",
                "severity": "MEDIUM",
                "recommended_action": "investigate",
                "explanation": response_text[:500],
            }

        return {
            "request_id": alert.get("request_id", ""),
            "timestamp": alert.get("timestamp", ""),
            "src_ip": alert.get("src_ip", ""),
            "anomaly_score": alert.get("anomaly_score", 0),
            "llm_analysis": analysis.get("explanation", ""),
            "severity": analysis.get("severity", "MEDIUM"),
            "recommended_action": analysis.get("recommended_action", "investigate"),
            "is_threat": analysis.get("is_threat", True),
            "attack_type": analysis.get("attack_type"),
            "label": alert.get("label", "unknown"),
        }

    def process_one(self) -> dict | None:
        """Process a single alert from the input queue."""
        alert = self.input_queue.get(timeout=2.0)
        if alert is None:
            return None

        try:
            result = self.analyze_one(alert)
            self.output_queue.put(result)
            self._analyzed += 1

            logger.info(
                f"Analyst [{result['severity']}] {result['src_ip']}: "
                f"{result['llm_analysis'][:100]}"
            )
            return result
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return None

    def run(self, max_events: int | None = None) -> int:
        """Process alerts continuously or up to max_events."""
        count = 0
        while max_events is None or count < max_events:
            result = self.process_one()
            if result is not None:
                count += 1
            elif max_events is not None and self.input_queue.empty():
                break
        return count
