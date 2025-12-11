# Weekly Threat Intelligence Aggregator

This project is a Python-based **Weekly Threat Intelligence Aggregator** that collects, normalizes, deduplicates, and visualizes cyber threat indicators (IOCs) and CVEs from multiple public intelligence sources.  
The tool compiles all collected data into structured **HTML, CSV, and Excel reports**, including automatic opening and saving the results to the user's machine.

---

### API Keys

The `.env` file included in this submission contains placeholder values only.  
Please insert your own API keys to enable data collection from OTX, NVD, and URLHaus.

##  Features

- Aggregates threat intelligence from:
  - **NVD (NIST CVE Database)** – latest vulnerabilities in the past 7 days  
  - **AlienVault OTX** – IOC data from subscribed pulses  
  - **URLHaus** – malicious URLs and related metadata  
  - **Israel National Cyber Directorate (INCD)** – CVE advisories (via scraping fallback)  

- Normalizes all sources into a unified schema  
- Removes duplicates across sources  
- Sorts indicators by time (newest first)  
- Generates:
  - **Beautiful HTML Report** (automatically opened)  
  - **CSV Report**  
  - **Excel Report** (auto-generated, copied to *Downloads*, and auto-opened)  

---

##  Project Structure

The tool is implemented in a single Python script for simplicity (suitable for a home assignment), containing:

- Fetching functions for each source  
- Normalization and deduplication logic  
- HTML rendering engine with UI styling  
- Reporting engine (CSV, HTML, Excel)  
- Main program flow  

---
## Security Considerations

- API keys are stored in a `.env` file and loaded securely at runtime.  
  The `.env` file must not be committed to version control.





##  Requirements
Python 3.9+
for Selenium support:
Google Chrome browser installed
Chromedriver is handled automatically via webdriver-manager

Install dependencies:

```bash
pip install requests pandas beautifulsoup4 python-dotenv selenium webdriver-manager lxml openpyxl
```

## Running the Program
Simply run:

```bash
python threat_aggregator.py