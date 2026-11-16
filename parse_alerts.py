"""Qarisiq formatli xam alert -> vahid sxem. (n8n Code node-un Python ekvivalenti)"""
import json, re, sys
from datetime import datetime, timezone

def empty_obs():
    return {"ip": [], "hash": [], "domain": [], "url": [], "user": [], "host": []}

def parse(payload):
    raw, src = payload["raw"], payload["source"]
    out = {"alert_id": payload["alert_id"], "timestamp": None, "alert_type": None,
           "source": src, "severity": "medium", "observables": empty_obs(),
           "extra": {}, "raw": raw, "parse_error": None}
    try:
        if src == "syslog":
            out["alert_type"] = "suspicious_login"
            m = re.match(r"^(\w{3}\s+\d+\s[\d:]+)\s(\S+)", raw)
            if m:
                dt = datetime.strptime(f"2026 {' '.join(m.group(1).split())}", "%Y %b %d %H:%M:%S")
                out["timestamp"] = dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                out["observables"]["host"].append(m.group(2))
            u = re.search(r"for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", raw)
            if u:
                out["observables"]["user"].append(u.group(1))
                out["observables"]["ip"].append(u.group(2))
            a = re.search(r"attempts=(\d+)", raw)
            if a:
                out["extra"]["attempts"] = int(a.group(1))
        elif src == "edr":
            out["alert_type"] = "malicious_hash"
            j = json.loads(raw)
            out["timestamp"] = j.get("timestamp")
            if j.get("host"): out["observables"]["host"].append(j["host"])
            if j.get("sha256"): out["observables"]["hash"].append(j["sha256"])
            out["severity"] = j.get("severity", "medium")
        elif src == "proxy":
            out["alert_type"] = "suspicious_url"
            kv = {m.group(1): m.group(2).strip('"') for m in re.finditer(r'(\w+)=("[^"]*"|\S+)', raw)}
            out["timestamp"] = kv.get("ts")
            if kv.get("src"): out["observables"]["ip"].append(kv["src"])
            if kv.get("domain"): out["observables"]["domain"].append(kv["domain"])
            if kv.get("url"): out["observables"]["url"].append(kv["url"])
        else:
            out["parse_error"] = f"namelum source: {src}"
    except Exception as e:  # parser cokmesin, xeta qeyd olunsun
        out["parse_error"] = f"{type(e).__name__}: {e}"
    return out

if __name__ == "__main__":
    payloads = json.load(open("dataset/payloads.json", encoding="utf-8"))
    expected = {e["alert_id"]: e for e in json.load(open("dataset/expected.json", encoding="utf-8"))}
    parsed = [parse(p) for p in payloads]
    json.dump(parsed, open("dataset/parsed.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    ok = 0
    for p in parsed:
        e = expected[p["alert_id"]]
        key, val = next(iter(e["indicators"].items()))
        found = val in p["observables"][key]
        good = found and not p["parse_error"] and e["alert_type"] == p["alert_type"] and p["timestamp"]
        ok += bool(good)
        if not good:
            print("PROBLEM:", p["alert_id"], p["parse_error"])
    print(f"Parse nəticəsi: {ok}/{len(parsed)} düzgün")
    sys.exit(0 if ok == len(parsed) else 1)
