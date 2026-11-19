from pathlib import Path
import yaml
from fastapi import FastAPI
from app.models import Tier2HandoffBrief, WazuhAlertInput
from app.sanitizer import sanitize_payload

app = FastAPI(title="The Grey Fountain", version="0.1.0")
ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


def load_allowlist() -> dict:
    if not ALLOWLIST_PATH.exists():
        return {}
    with ALLOWLIST_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "The Grey Fountain"}


@app.post("/triage/wazuh", response_model=Tier2HandoffBrief)
def triage_wazuh_alert(alert: WazuhAlertInput) -> Tier2HandoffBrief:
    cleaned = sanitize_payload(alert.model_dump())
    rule = cleaned.get("rule", {}) if isinstance(cleaned, dict) else {}
    agent = cleaned.get("agent", {}) if isinstance(cleaned, dict) else {}
    allowlist = load_allowlist()

    rule_id = str(rule.get("id", "unknown"))
    rule_desc = str(rule.get("description", "Wazuh alert"))
    rule_level = rule.get("level", 0)
    agent_name = str(agent.get("name", "unknown-agent"))
    agent_ip = str(agent.get("ip", "N/A"))

    noisy_rules = {str(r) for r in allowlist.get("noisy_rule_ids", [])}
    trusted_ips = {str(ip) for ip in allowlist.get("trusted_ips", [])}

    if rule_id in noisy_rules or agent_ip in trusted_ips:
        return Tier2HandoffBrief(
            verdict="Likely False Positive",
            confidence="High",
            recommended_severity="Low",
            false_positive_reason=f"Matched baseline allowlist (rule={rule_id}, ip={agent_ip}).",
            executive_summary=(
                f"Alert for rule {rule_id} ({rule_desc}) on {agent_name} matched a configured allowlist baseline."
            ),
            key_iocs=[ip for ip in [agent_ip] if ip not in {"", "N/A"}],
            tier2_next_steps=["No escalation required unless repeated anomalies occur outside baseline."],
        )

    severity = "High" if isinstance(rule_level, int) and rule_level >= 12 else "Medium"

    return Tier2HandoffBrief(
        verdict="Suspicious - Needs Investigation",
        confidence="Medium",
        recommended_severity=severity,  # type: ignore[arg-type]
        executive_summary=(
            f"Rule {rule_id} ({rule_desc}, level {rule_level}) triggered on "
            f"{agent_name} ({agent_ip}). Sensitive tokens redacted prior to triage."
        ),
        key_iocs=[ip for ip in [agent_ip] if ip not in {"", "N/A"}],
        tier2_next_steps=[
            f"Review authentication and process logs around rule {rule_id} on {agent_name}.",
            "Validate whether activity aligns with authorized maintenance or admin tasks.",
        ],
    )
