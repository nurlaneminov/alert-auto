"""dataset/payloads.json-dakı alert-leri n8n webhook-una gonderir.
Istifade: python send_alerts.py http://localhost:5678/webhook-test/alerts [--delay 0.5]"""
import json, sys, time, urllib.request

url = sys.argv[1]
delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 0.3
for p in json.load(open("dataset/payloads.json", encoding="utf-8")):
    req = urllib.request.Request(url, data=json.dumps(p).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(p["alert_id"], p["source"], r.status)
    except Exception as e:
        print(p["alert_id"], "XETA:", e)
    time.sleep(delay)
