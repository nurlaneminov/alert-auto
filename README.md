# Layihə 3 / Modul A: Alert mənbəyi və dataset

## Axın
build_dataset.py -> dataset/payloads.json -> send_alerts.py -> n8n Webhook -> Code (parser) -> vahid JSON -> (C: qərar/case)

## Fayllar
- `build_dataset.py` – 36 sintetik alert (3 tip x 4 zərərli/4 təmiz/4 qeyri-müəyyən), qarışıq formatda
- `dataset/payloads.json` – webhook-a gedən alert-lər (expected yoxdur)
- `dataset/expected.json` – gözlənilən nəticə (yalnız D-nin ölçməsi üçün)
- `dataset/mock_intel.json` – lokal mock intelligence (B üçün deterministik nəticə)
- `parse_alerts.py` – Python parser (n8n Code node ilə eyni məntiq)
- `send_alerts.py` – alert-ləri webhook-a göndərir
- `tests/test_parser.py` – pytest

## İşlətmə
    python build_dataset.py
    python parse_alerts.py
    pytest -q tests
    python send_alerts.py http://localhost:5678/webhook-test/alerts

## Vahid sxem
alert_id, timestamp (ISO), alert_type, source, severity, observables{ip,hash,domain,url,user,host}, extra, raw, parse_error

Yalnız sintetik data: IP-lər 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; domenlər `.test`; hash-lər sintetik, EICAR test faylı istisna.
