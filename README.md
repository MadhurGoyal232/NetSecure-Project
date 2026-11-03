# NetSecure - Network Vulnerability Scanner & Security Risk Analyzer

## Run
    pip install -r requirements.txt
    python app.py          # open http://127.0.0.1:5000
Optional: install Nmap (better service detection) and set NVD_API_KEY (higher NVD rate limit).

## Demo (no network needed)
New scan -> tick the consent box -> "Run demo lab".

## Files
- engine.py   discovery, Nmap/TCP scan, NVD CVE lookup + cache, rules, CVSS-style score, Isolation Forest
- report.py   PDF generation (ReportLab)
- app.py      Flask routes (JSON API + page)
- templates/index.html   dashboard UI (Chart.js)

Use only on systems you own or are authorised to test.
