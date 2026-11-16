"""Sintetik dataset yaradir: 3 tip x 12 = 36 alert (4 zererli / 4 temiz / 4 qeyri-mueyyen).
Cixis:
  dataset/payloads.json  - webhook-a gonderilen alert-ler (expected YOXDUR)
  dataset/expected.json  - gozlenilen netice (yalniz olcme ucun)
  dataset/mock_intel.json - lokal mock intelligence (B modulu ucun deterministik netice)
"""
import json, hashlib, random
from datetime import datetime, timedelta, timezone

random.seed(42)
BASE = datetime(2026, 11, 16, 8, 0, 0, tzinfo=timezone.utc)
OUTCOME = {  # verdict -> (action, severity)
    "malicious": ("escalate", "high"),
    "benign": ("auto_close", "low"),
    "uncertain": ("analyst_review", "medium"),
}
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

items = []   # (alert_type, source, verdict, raw, indicators)
intel = {}

def ts(i):
    return BASE + timedelta(minutes=7 * i + random.randint(0, 5))

# --- 1. Suspicious login (syslog) ---
logins = [
    ("malicious", "admin", "203.0.113.5", 120), ("malicious", "root", "203.0.113.9", 85),
    ("malicious", "svc_backup", "203.0.113.14", 60), ("malicious", "administrator", "203.0.113.22", 200),
    ("benign", "emil", "192.0.2.11", 1), ("benign", "aysel", "192.0.2.12", 1),
    ("benign", "leman", "192.0.2.13", 2), ("benign", "oguz", "192.0.2.14", 1),
    ("uncertain", "nilufer", "198.51.100.7", 5), ("uncertain", "fexri", "198.51.100.23", 4),
    ("uncertain", "hesenali", "198.51.100.41", 6), ("uncertain", "murad", "198.51.100.60", 3),
]
for v, user, ip, n in logins:
    intel[ip] = {"verdict": v, "score": {"malicious": 90, "benign": 0, "uncertain": 40}[v]}
    items.append(("suspicious_login", "syslog", v, ("LOGIN", user, ip, n), {"ip": ip, "user": user}))

# --- 2. Malicious hash (EDR JSON) ---
hashes = [
    ("malicious", EICAR), ("malicious", sha("synthetic-malware-1")),
    ("malicious", sha("synthetic-malware-2")), ("malicious", sha("synthetic-malware-3")),
    ("benign", EMPTY), ("benign", sha("clean-1")), ("benign", sha("clean-2")), ("benign", sha("clean-3")),
    ("uncertain", sha("unknown-1")), ("uncertain", sha("unknown-2")),
    ("uncertain", sha("unknown-3")), ("uncertain", sha("unknown-4")),
]
for k, (v, h) in enumerate(hashes):
    intel[h] = {"verdict": v, "score": {"malicious": 95, "benign": 0, "uncertain": 35}[v]}
    items.append(("malicious_hash", "edr", v, ("HASH", f"WS-{k+1:02d}", h, None), {"hash": h}))

# --- 3. Suspicious URL/domain (proxy key=value) ---
domains = [
    ("malicious", "secure-login-bank.test"), ("malicious", "paypa1-verify.test"),
    ("malicious", "office365-update.test"), ("malicious", "free-gift-claim.test"),
    ("benign", "google.com"), ("benign", "microsoft.com"),
    ("benign", "github.com"), ("benign", "wikipedia.org"),
    ("uncertain", "newly-registered-shop.test"), ("uncertain", "cdn-static-files.test"),
    ("uncertain", "file-share-temp.test"), ("uncertain", "promo-offers-2026.test"),
]
for k, (v, d) in enumerate(domains):
    intel[d] = {"verdict": v, "score": {"malicious": 92, "benign": 0, "uncertain": 45}[v]}
    items.append(("suspicious_url", "proxy", v, ("URL", f"10.0.0.{k+10}", d, None), {"domain": d}))

random.shuffle(items)  # qarisiq gelsin

payloads, expected = [], []
for i, (atype, src, v, data, ind) in enumerate(items, 1):
    t = ts(i)
    aid = f"A-{i:03d}"
    kind, a, b, c = data
    if kind == "LOGIN":
        raw = (f"{t:%b %d %H:%M:%S} vpn01 sshd[{random.randint(1000,9999)}]: Failed password for "
               f"{a} from {b} port 22 ssh2 [attempts={c} window=5m]")
    elif kind == "HASH":
        sev = OUTCOME[v][1]
        raw = json.dumps({"event": "file_detected", "host": a, "severity": sev,
                          "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "sha256": b,
                          "file": "invoice.exe" if v != "benign" else "notes.txt"})
    else:
        raw = (f'ts={t:%Y-%m-%dT%H:%M:%SZ} src={a} domain={b} url=https://{b}/login '
               f'action=allowed user_agent="Mozilla/5.0 (Windows NT 10.0)"')
    payloads.append({"alert_id": aid, "source": src, "raw": raw})
    action, sev = OUTCOME[v]
    expected.append({"alert_id": aid, "alert_type": atype, "indicators": ind,
                     "expected_verdict": v, "expected_action": action, "expected_severity": sev})

for name, obj in [("payloads", payloads), ("expected", expected), ("mock_intel", intel)]:
    with open(f"dataset/{name}.json", "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
print(f"{len(payloads)} alert yaradildi")
