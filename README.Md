# Weekly Threat Intelligence Aggregator

Python-based **Weekly Threat Intelligence Aggregator** that collects, normalizes, deduplicates, and visualizes cyber threat indicators (IOCs) and CVEs from multiple public intelligence sources. It compiles data into structured **HTML, CSV, and Excel reports**, automatically saving and opening results on the user's machine.

---

## Environment

Create a `.env` file in the project root (placeholders shown):
```
OTX_API_KEY=your-otx-key
NVD_API_KEY=your-nvd-key
URLHAUS_AUTH_KEY=your-urlhaus-key
```
Notes:
- Keys are optional per source; missing keys simply skip that source.
- Keep `.env` out of version control.

## Features
- Aggregates threat intelligence from:
  - **NVD (NIST CVE Database)** – latest vulnerabilities in the past 7 days
  - **AlienVault OTX** – IOC data from subscribed pulses
  - **URLHaus** – malicious URLs and related metadata
  - **Israel National Cyber Directorate (INCD)** – CVE advisories (requests with Selenium fallback)
- Normalizes to a unified schema, deduplicates, sorts newest-first
- Generates HTML (auto-open), CSV, and Excel (copied to Downloads and auto-opened on Windows)

## Project Structure
Single Python script for simplicity:
- Source fetchers
- Normalization/deduplication
- HTML rendering
- Reporting (CSV/HTML/Excel)
- Main program flow

## Security Considerations
- API keys loaded from `.env`; do not commit this file.

## Requirements
- Python 3.9+
- Google Chrome installed (Selenium scraping)
- Chromedriver handled automatically via `webdriver-manager`

Install dependencies:
```bash
pip install -r requirements.txt  # or install individually
pip install requests pandas beautifulsoup4 python-dotenv selenium webdriver-manager lxml openpyxl
```

## Running
```bash
python threat_aggregator.py
```

Behavior:
- Uses a 7-day window ending at run time.
- Sources: NVD, AlienVault OTX, URLHaus, INCD (requests with Selenium fallback).
- Generates CSV, HTML, and Excel reports; copies Excel to Downloads and auto-opens HTML/Excel on Windows.