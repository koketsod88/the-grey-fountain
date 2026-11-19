import json
import os
from typing import Any
import httpx
from app.models import Tier2HandoffBrief
from app.prompts import SYSTEM_PROMPT, build_triage_prompt


class OllamaTriageError(Exception):
    """Raised when Ollama is unreachable or returns an invalid triage payload."""


def get_ollama_config() -> tuple[str, str, float]:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "qwen3:4b")
    timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "45"))
    return base_url, model, timeout


def _parse_json_content(raw_content: str) -> dict[str, Any]:
    cleaned = raw_content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise OllamaTriageError("LLM response JSON is not an object.")
    return parsed


def triage_with_ollama(
    sanitized_alert: dict[str, Any],
    extracted_iocs: list[str],
    fallback_brief: Tier2HandoffBrief,
) -> Tier2HandoffBrief:
    base_url, model, timeout = get_ollama_config()
    url = f"{base_url}/api/chat"

    request_body = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_triage_prompt(sanitized_alert, extracted_iocs)},
        ],
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=request_body)
            response.raise_for_status()
            data = response.json()

        content = (data.get("message") or {}).get("content", "")
        if not content:
            raise OllamaTriageError("Empty message content from Ollama.")

        parsed = _parse_json_content(content)
        merged = {
            "verdict": parsed.get("verdict", fallback_brief.verdict),
            "confidence": parsed.get("confidence", fallback_brief.confidence),
            "recommended_severity": parsed.get(
                "recommended_severity", fallback_brief.recommended_severity
            ),
            "false_positive_reason": parsed.get("false_positive_reason"),
            "executive_summary": parsed.get("executive_summary", fallback_brief.executive_summary),
            "key_iocs": parsed.get("key_iocs") or fallback_brief.key_iocs,
            "tier2_next_steps": parsed.get("tier2_next_steps") or fallback_brief.tier2_next_steps,
            "data_protection_notes": (
                f"Sanitized pre-inference; analyzed locally via Ollama ({model})."
            ),
        }
        return Tier2HandoffBrief.model_validate(merged)
    except Exception as exc:
        raise OllamaTriageError(f"Ollama triage failed ({model} @ {base_url}): {exc}") from exc
