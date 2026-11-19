import urllib.request
import json


def test_health_endpoint():
    with urllib.request.urlopen("http://127.0.0.1:8088/health", timeout=5) as resp:
        assert resp.status == 200
        body = json.loads(resp.read().decode("utf-8"))
        assert body.get("status") == "ok"


def test_triage_wazuh_redacts_secret():
    payload = {
        "rule": {"id": "5710", "level": 10, "description": "sshd: brute force trying to get access"},
        "agent": {"id": "001", "name": "ubuntu-web-01"},
        "data": {"srcip": "198.51.100.42", "api_key": "DUMMY_SECRET_TOKEN_12345"},
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8088/triage/wazuh",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        raw_text = resp.read().decode("utf-8")
        assert "DUMMY_SECRET_TOKEN_12345" not in raw_text
