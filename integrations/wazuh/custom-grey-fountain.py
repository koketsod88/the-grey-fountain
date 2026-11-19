#!/usr/bin/env python3
import json
import sys
import urllib.request


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]
    hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "http://10.0.2.15:8088/triage/wazuh"

    with open(alert_file, "r", encoding="utf-8") as fh:
        raw_alert = json.load(fh)

    payload = {
        "id": raw_alert.get("id"),
        "timestamp": raw_alert.get("timestamp"),
        "rule": raw_alert.get("rule") or {},
        "agent": raw_alert.get("agent") or {},
        "data": raw_alert.get("data") or {},
        "full_log": raw_alert.get("full_log"),
        "decoder": raw_alert.get("decoder") or {},
    }

    req = urllib.request.Request(
        hook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(resp.read().decode("utf-8"))


if __name__ == "__main__":
    main()
