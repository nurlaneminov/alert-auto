import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from parse_alerts import parse

def test_syslog():
    r = parse({"alert_id": "T1", "source": "syslog", "raw":
        "Nov 16 10:15:00 vpn01 sshd[1]: Failed password for admin from 203.0.113.5 port 22 ssh2 [attempts=9 window=5m]"})
    assert r["observables"]["ip"] == ["203.0.113.5"] and r["observables"]["user"] == ["admin"]
    assert r["timestamp"] == "2026-11-16T10:15:00Z" and r["extra"]["attempts"] == 9

def test_edr():
    r = parse({"alert_id": "T2", "source": "edr", "raw": json.dumps(
        {"host": "WS-01", "severity": "high", "timestamp": "2026-11-16T10:00:00Z", "sha256": "ab" * 32})})
    assert r["observables"]["hash"] == ["ab" * 32] and r["severity"] == "high"

def test_proxy():
    r = parse({"alert_id": "T3", "source": "proxy", "raw":
        'ts=2026-11-16T10:00:00Z src=10.0.0.5 domain=google.com url=https://google.com/login user_agent="Mozilla 5.0"'})
    assert r["observables"]["domain"] == ["google.com"] and r["alert_type"] == "suspicious_url"

def test_bad_input_does_not_crash():
    assert parse({"alert_id": "T4", "source": "edr", "raw": "not json"})["parse_error"]
    assert parse({"alert_id": "T5", "source": "xyz", "raw": ""})["parse_error"]
