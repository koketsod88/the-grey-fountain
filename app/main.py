import os
import re
from pathlib import Path
from typing import Any
import yaml
from fastapi import FastAPI
from app.llm_client import OllamaTriageError, triage_with_ollama
from app.models import Tier2HandoffBrief, WazuhAlertInput
from app.sanitizer import sanitize_payload

app = FastAPI(title="The Grey Fountain", version="0.2.0")
ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_allowlist() -> dict[str, Any]:
    if not ALLOWLIST_PATH.exists():
        return {}
    with ALLOWLIST_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def extract_candidate_iocs(alert_dict: dict[str, Any]) -> list[str]:
    iocs: list[str] = []
    seen: set[str] = set()

    def add_ioc(val: Any) -> None:
        if isinstance(val, str):
            item = val.strip()
            if item and item not in {"N/A", "none", "null"} and item not in seen:
                seen.add(item)
                iocs.append(item)

    agent = alert_dict.get("agent") or {}
    if isinstance(agent, dict):
        add_ioc(agent.get("ip"))

    data = alert_dict.get("data") or {}
    if isinstance(data, dict):
        for field in ("srcip", "dstip", "src_ip", "dst_ip", "url", "dstuser", "srcuser"):
            add_ioc(data.get(field))

    full_log = alert_dict.get("full_log")
    if isinstance(full_log, str):
        for ip in IPV4_PATTERN.findall(full_log):
            add_ioc(ip)

    return iocs


def build_fallback_brief(
    rule_id: str,
    rule_desc: str,
    rule_level: Any,
    agent_name: str,
    iocs: list[str],
    reason_note: str,
) -> Tier2HandoffBrief:
    level_num = rule_level if isinstance(rule_level, int) else 0
    if level_num >= 12:
        severity = "High"
    elif level_num >= 7:
        severity = "Medium"
    else:
        severity = "Low"

    return Tier2HandoffBrief(
        verdict="Suspicious - Needs Investigation",
        confidence="Low",
        recommended_severity=severity,  # type: ignore[arg-type]
        executive_summary=(
            f"Wazuh rule {rule_id} ({rule_desc}, level {level_num}) triggered on {agent_name}. "
            f"Deterministic fallback triage generated."
        ),
        key_iocs=iocs,
        tier2_next_steps=[
            f"Inspect Wazuh alert details and surrounding events for rule {rule_id} on {agent_name}.",
            "Verify whether involved IPs, accounts, or processes match authorized administrative activity.",
        ],
        data_protection_notes=reason_note,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "agent": "The Grey Fountain",
        "ollama_model": os.getenv("OLLAMA_MODEL", "qwen3:4b"),
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "[http://127.0.0.1:11434](http://127.0.0.1:11434)"),
    }


@app.post("/triage/wazuh", response_model=Tier2HandoffBrief)
def triage_wazuh_alert(alert: WazuhAlertInput) -> Tier2HandoffBrief:
    cleaned = sanitize_payload(alert.model_dump())
    alert_dict = cleaned if isinstance(cleaned, dict) else {}

    rule = alert_dict.get("rule") if isinstance(alert_dict.get("rule"), dict) else {}
    agent = alert_dict.get("agent") if isinstance(alert_dict.get("agent"), dict) else {}
    allowlist = load_allowlist()

    rule_id = str(rule.get("id", "unknown"))
    rule_desc = str(rule.get("description", "Wazuh alert"))
    rule_level = rule.get("level", 0)
    agent_name = str(agent.get("name", "unknown-agent"))
    agent_ip = str(agent.get("ip", "N/A"))

    noisy_rules = {str(r) for r in allowlist.get("noisy_rule_ids", [])}
    trusted_ips = {str(ip) for ip in allowlist.get("trusted_ips", [])}
    trusted_agents = {str(a) for a in allowlist.get("trusted_agents", [])}
    iocs = extract_candidate_iocs(alert_dict)

    if rule_id in noisy_rules or agent_ip in trusted_ips or agent_name in trusted_agents:
        return Tier2HandoffBrief(
            verdict="Likely False Positive",
            confidence="High",
            recommended_severity="Low",
            false_positive_reason=(
                f"Matched baseline allowlist (rule_id={rule_id}, agent={agent_name}, ip={agent_ip})."
            ),
            executive_summary=(
                f"Rule {rule_id} ({rule_desc}) on {agent_name} matched a configured allowlist baseline; "
                "suppressed from Tier 2 escalation."
            ),
            key_iocs=iocs,
            tier2_next_steps=["No immediate Tier 2 action required unless recurrence or scope changes."],
            data_protection_notes="Sanitized prior to baseline allowlist check; no external LLM call needed.",
        )

    fallback = build_fallback_brief(
        rule_id=rule_id,
        rule_desc=rule_desc,
        rule_level=rule_level,
        agent_name=agent_name,
        iocs=iocs,
        reason_note="Sanitized prior to triage; deterministic fallback used (Ollama unavailable).",
    )

    try:
        return triage_with_ollama(
            sanitized_alert=alert_dict,
            extracted_iocs=iocs,
            fallback_brief=fallback,
        )
    except OllamaTriageError as err:
        fallback.data_protection_notes = (
            f"Sanitized prior to triage; fallback used because {err}"
        )
        return fallback
