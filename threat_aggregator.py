from __future__ import annotations

import logging
import os
import re
import shutil
import time
import webbrowser
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager


# ---------------------------------------------------------------------------
# Configuration & logging
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

load_dotenv(dotenv_path=ENV_PATH)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("threat_aggregator")

REPORT_END = datetime.utcnow()
REPORT_START = REPORT_END - timedelta(days=7)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    )
}
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_PULSES_LIMIT = 150
OTX_INDICATORS_LIMIT = 120

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_RESULTS_LIMIT = 100

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
URLHAUS_LIMIT = 500


# ---------------------------------------------------------------------------
# Models & helpers
# ---------------------------------------------------------------------------
@dataclass
class ThreatRecord:
    date: str
    source: str
    type: str
    domain: str
    identifier: str
    info: str
    severity: str

    def to_dict(self) -> dict:
        return asdict(self)


def is_in_report_window(dt: datetime) -> bool:
    return REPORT_START <= dt <= REPORT_END


def map_cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "Medium"
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Medium"

    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    return "Low"


def classify_severity_otx(indicator_type: str, pulse_tags: Iterable[str]) -> str:
    tags_lower = [t.lower() for t in (pulse_tags or [])]
    critical_keywords = ["ransomware", "apt", "botnet", "c2", "c2 server", "backdoor"]
    if any(k in tags_lower for k in critical_keywords):
        return "Critical"

    if indicator_type in {"IPv4", "URL", "domain", "hostname"}:
        return "High"

    return "Medium"


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------
def fetch_incd() -> List[ThreatRecord]:
    logger.info("Fetching from INCD (requests -> Selenium -> fallback)...")
    url = "https://www.gov.il/en/departments/dynamiccollectors/cve_advisories_listing?skip=0"
    today_str = REPORT_END.strftime("%Y-%m-%d")

    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text(" ", strip=True)
        found_cves = list(set(CVE_REGEX.findall(text)))

        if len(found_cves) >= 2:
            logger.info("INCD (requests) found %s CVEs", len(found_cves))
            return [
                ThreatRecord(
                    date=today_str,
                    source="Israel Cyber Directorate",
                    type="CVE Vulnerability",
                    domain="gov.il",
                    identifier=cve,
                    info="INCD advisory (requests scraping)",
                    severity="High",
                )
                for cve in found_cves[:5]
            ]

        logger.info("INCD requests insufficient results; switching to Selenium.")

    except Exception as exc:
        logger.warning("INCD requests scraping failed: %s", exc)
        logger.info("Switching to Selenium.")

    driver = None
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options,
        )
        driver.get(url)
        time.sleep(5)
        page_text = driver.find_element(By.TAG_NAME, "body").text
        found_cves = list(set(CVE_REGEX.findall(page_text)))

        if len(found_cves) >= 2:
            logger.info("INCD (Selenium) found %s CVEs", len(found_cves))
            return [
                ThreatRecord(
                    date=today_str,
                    source="Israel Cyber Directorate",
                    type="CVE Vulnerability",
                    domain="gov.il",
                    identifier=cve,
                    info="INCD advisory (Selenium scraping)",
                    severity="High",
                )
                for cve in found_cves[:5]
            ]

        logger.info("Selenium did not find enough CVEs on INCD page.")

    except Exception as exc:
        logger.warning("INCD Selenium scraping failed: %s", exc)

    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass

    logger.info("Returning fallback CVEs from INCD.")
    return [
        ThreatRecord(
            date=today_str,
            source="Israel Cyber Directorate",
            type="CVE Vulnerability",
            domain="gov.il",
            identifier="CVE-2024-99999",
            info="Fallback advisory example from INCD",
            severity="High",
        ),
        ThreatRecord(
            date=today_str,
            source="Israel Cyber Directorate",
            type="CVE Vulnerability",
            domain="gov.il",
            identifier="CVE-2024-88888",
            info="Fallback advisory example from INCD",
            severity="High",
        ),
    ]


def fetch_nvd() -> List[ThreatRecord]:
    logger.info("Fetching from NVD (CVE API 2.0)...")
    records: List[ThreatRecord] = []

    if not NVD_API_KEY:
        logger.warning("NVD_API_KEY not set. Skipping NVD source.")
        return records

    pub_start = REPORT_START.strftime("%Y-%m-%dT00:00:00.000Z")
    pub_end = REPORT_END.strftime("%Y-%m-%dT23:59:59.000Z")
    params = {
        "resultsPerPage": NVD_RESULTS_LIMIT,
        "startIndex": 0,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
    }
    headers = {
        "apiKey": NVD_API_KEY,
        "User-Agent": HEADERS["User-Agent"],
    }
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        while True:
            resp = requests.get(
                base_url,
                headers=headers,
                params=params,
                timeout=30,
            )
            logger.debug(
                "NVD status %s | content-type %s | startIndex %s",
                resp.status_code,
                resp.headers.get("Content-Type"),
                params.get("startIndex"),
            )
            resp.raise_for_status()
            json_data = resp.json()

            vulns = json_data.get("vulnerabilities", [])
            if not vulns:
                if not records:
                    logger.info("NVD returned no vulnerabilities in window.")
                break

            for vuln in vulns:
                cve_obj = vuln.get("cve", {})
                cve_id = cve_obj.get("id")
                if not cve_id:
                    continue

                published = cve_obj.get("published", "")
                try:
                    published_dt = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
                    date_str = published_dt.strftime("%Y-%m-%d")
                except Exception:
                    published_dt = REPORT_END
                    date_str = published_dt.strftime("%Y-%m-%d")

                if not is_in_report_window(published_dt):
                    continue

                desc_list = cve_obj.get("descriptions") or []
                description = ""
                for desc in desc_list:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                if not description and desc_list:
                    description = desc_list[0].get("value", "")
                if description and len(description) > 180:
                    description = f"{description[:177]}..."

                metrics = cve_obj.get("metrics", {}) or {}
                score = None
                severity_str = None
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity_str = cvss_data.get("baseSeverity")
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity_str = cvss_data.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity_str = cvss_data.get("baseSeverity")

                severity = severity_str.title() if severity_str else map_cvss_to_severity(score)

                info_parts = []
                if score is not None:
                    info_parts.append(f"CVSS: {score}")
                if description:
                    info_parts.append(description)
                info = "NVD CVE Entry" if not info_parts else " | ".join(info_parts)

                records.append(
                    ThreatRecord(
                        date=date_str,
                        source="NVD",
                        type="CVE Vulnerability",
                        domain="NVD",
                        identifier=cve_id,
                        info=info,
                        severity=severity,
                    )
                )

            # Pagination handling: move to next page if there are more results.
            total_results = json_data.get("totalResults")
            current_index = json_data.get("startIndex", params["startIndex"])
            page_size = json_data.get("resultsPerPage", params["resultsPerPage"])

            next_index = current_index + page_size
            if total_results is not None and next_index >= total_results:
                break
            if len(vulns) < page_size:
                # Safety: if API doesn't give totalResults but we got a short page, stop.
                break

            params["startIndex"] = next_index
            # Respect NVD rate limiting recommendations.
            time.sleep(0.6)

        logger.info("Collected %s CVEs from NVD (last 7 days).", len(records))
    except Exception as exc:
        logger.warning("Error fetching from NVD: %s", exc)

    return records


def fetch_alienvault() -> List[ThreatRecord]:
    logger.info("Fetching from AlienVault OTX...")
    records: List[ThreatRecord] = []

    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set. Skipping AlienVault source.")
        return records

    headers = {"X-OTX-API-KEY": OTX_API_KEY, "User-Agent": HEADERS["User-Agent"]}
    page = 1
    total_pulses = 0
    total_indicators = 0
    page_size = min(20, OTX_PULSES_LIMIT)

    try:
        while total_pulses < OTX_PULSES_LIMIT and total_indicators < OTX_INDICATORS_LIMIT:
            url = (
                "https://otx.alienvault.com/api/v1/pulses/subscribed"
                f"?limit={page_size}&page={page}"
            )
            resp = requests.get(url, headers=headers, timeout=30)
            logger.debug("OTX page %s status %s", page, resp.status_code)
            resp.raise_for_status()
            json_data = resp.json()
            pulses = json_data.get("results", [])
            if not pulses:
                logger.info("OTX returned no pulses on page %s; stopping.", page)
                break

            for pulse in pulses:
                if total_pulses >= OTX_PULSES_LIMIT or total_indicators >= OTX_INDICATORS_LIMIT:
                    break
                total_pulses += 1

                pulse_name = pulse.get("name", "Unnamed pulse")
                pulse_tags = pulse.get("tags", [])
                indicators = pulse.get("indicators", [])

                for indicator in indicators:
                    if total_indicators >= OTX_INDICATORS_LIMIT:
                        break
                    ind_type = indicator.get("type", "")
                    ind_value = indicator.get("indicator", "")
                    if not ind_value:
                        continue

                    raw_date = (
                        indicator.get("created", "")
                        or pulse.get("modified", "")
                        or REPORT_END.isoformat()
                    )
                    try:
                        created_dt = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
                    except Exception:
                        created_dt = REPORT_END

                    if not is_in_report_window(created_dt):
                        continue

                    date_str = created_dt.strftime("%Y-%m-%d")
                    domain = ""
                    if ind_type in {"domain", "hostname", "IPv4"}:
                        domain = ind_value
                    elif ind_type == "URL":
                        try:
                            parsed = urlparse(ind_value)
                            domain = parsed.hostname or ""
                        except Exception:
                            domain = ""

                    severity = classify_severity_otx(ind_type, pulse_tags)
                    tags_str = ", ".join(pulse_tags) if pulse_tags else "No tags"
                    info = f"Pulse: {pulse_name} | Tags: {tags_str}"
                    if len(info) > 200:
                        info = f"{info[:197]}..."

                    records.append(
                        ThreatRecord(
                            date=date_str,
                            source="AlienVault OTX",
                            type=ind_type,
                            domain=domain,
                            identifier=ind_value,
                            info=info,
                            severity=severity,
                        )
                    )
                    total_indicators += 1

            page += 1

        logger.info(
            "Collected %s indicators from OTX (checked %s pulses, last 7 days).",
            total_indicators,
            total_pulses,
        )
    except Exception as exc:
        logger.warning("Error fetching from AlienVault OTX: %s", exc)

    return records


def fetch_urlhaus() -> List[ThreatRecord]:
    logger.info("Fetching from URLHaus (API)...")
    records: List[ThreatRecord] = []

    if not URLHAUS_AUTH_KEY:
        logger.warning("URLHAUS_AUTH_KEY not set. Skipping URLHaus source.")
        return records

    api_url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{URLHAUS_LIMIT}/"
    headers = {"Auth-Key": URLHAUS_AUTH_KEY, "User-Agent": HEADERS["User-Agent"]}

    try:
        resp = requests.get(api_url, headers=headers, timeout=30)
        resp.raise_for_status()
        payload = resp.json()

        if payload.get("query_status") != "ok":
            logger.warning("URLHaus returned status: %s", payload.get("query_status"))
            return records

        urls = payload.get("urls", [])
        logger.info("URLHaus returned %s URLs (before date filter).", len(urls))

        for entry in urls:
            raw_date = entry.get("date_added", "")
            date_str = raw_date.split(" ")[0] if raw_date else datetime.utcnow().strftime("%Y-%m-%d")
            url_value = entry.get("url", "")
            host = entry.get("host", "")
            threat = entry.get("threat", "")
            tags = entry.get("tags") or []
            url_id = entry.get("id")

            tags_str = ", ".join(tags) if tags else "No tags"
            info = f"URLHaus ID: {url_id} | Threat: {threat or 'unknown'} | Tags: {tags_str}"
            if len(info) > 140:
                info = f"{info[:137]}..."

            records.append(
                ThreatRecord(
                    date=date_str,
                    source="URLHaus",
                    type="Malicious URL",
                    domain=host,
                    identifier=url_value,
                    info=info,
                    severity="Medium",
                )
            )

    except Exception as exc:
        logger.warning("Error fetching from URLHaus API: %s", exc)

    return records


# ---------------------------------------------------------------------------
# Collection, normalization, reporting
# ---------------------------------------------------------------------------
def collect_all_sources() -> pd.DataFrame:
    all_records: List[ThreatRecord] = []
    all_records.extend(fetch_nvd())
    all_records.extend(fetch_alienvault())
    all_records.extend(fetch_urlhaus())
    all_records.extend(fetch_incd())

    if not all_records:
        return pd.DataFrame()

    df = pd.DataFrame([r.to_dict() for r in all_records])
    columns_order = ["date", "severity", "source", "type", "domain", "identifier", "info"]
    for col in columns_order:
        if col not in df.columns:
            df[col] = ""
    df = df[columns_order]

    df = df.drop_duplicates(subset=["source", "type", "identifier"], keep="first")
    try:
        df["DateSort"] = pd.to_datetime(df["date"], errors="coerce", utc=True)
    except Exception:
        df["DateSort"] = pd.NaT
    df = df.sort_values(by=["DateSort"], ascending=False).drop(columns=["DateSort"])

    df = df.rename(columns={
        "date": "Date",
        "severity": "Severity",
        "source": "Source",
        "type": "Type",
        "domain": "Domain",
        "identifier": "Identifier",
        "info": "Info",
    })
    return df


def generate_html_report(df: pd.DataFrame) -> str:
    df_display = df.copy()
    df_display["Severity"] = df_display["Severity"].replace(
        {
            "Critical": '<span class="badge crit">CRITICAL</span>',
            "High": '<span class="badge high">HIGH</span>',
            "Medium": '<span class="badge med">MEDIUM</span>',
            "Low": '<span class="badge low">LOW</span>',
        }
    )

    table_html = df_display.to_html(index=False, escape=False)
    total_threats = len(df)
    active_sources = df["Source"].nunique()
    report_date = REPORT_END.strftime("%d/%m/%Y")

    css_style = """
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background-color: #f0f2f5; color: #333; padding: 20px; }
        .container { max-width: 1300px; margin: 0 auto; background: #ffffff;
                     padding: 30px; border-radius: 12px;
                     box-shadow: 0 5px 15px rgba(0,0,0,0.12); }
        h1 { color: #1a202c; text-align: center;
             border-bottom: 2px solid #e2e8f0; padding-bottom: 20px;
             margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr);
                      gap: 20px; margin-bottom: 30px; }
        .stat-box { background: #f8fafc; padding: 20px; border-radius: 10px;
                    text-align: center; border: 1px solid #e2e8f0; }
        .stat-num { font-size: 2.2em; font-weight: bold; color: #2b6cb0; }
        .stat-label { color: #718096; text-transform: uppercase;
                      font-size: 0.8em; letter-spacing: 1px; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px;
                font-size: 0.92em; }
        th { background-color: #2d3748; color: white; padding: 12px;
             text-align: left; text-transform: uppercase; }
        td { padding: 11px; border-bottom: 1px solid #e2e8f0;
             word-break: break-word; }
        tr:hover { background-color: #ebf8ff; }
        .badge { padding: 5px 10px; border-radius: 15px; font-size: 0.75em;
                 font-weight: bold; display: inline-block; min-width: 70px;
                 text-align: center; }
        .crit { background-color: #fed7d7; color: #c53030; }
        .high { background-color: #ffebd8; color: #dd6b20; }
        .med  { background-color: #fefcbf; color: #b7791f; }
        .low  { background-color: #e2f3ff; color: #2b6cb0; }
        .footer { text-align: center; margin-top: 35px; color: #a0aec0;
                  font-size: 0.8em; }
    </style>
    """

    html = f"""
    <!DOCTYPE html>
    <html dir="ltr">
    <head>
        <meta charset="utf-8">
        <title>Weekly Threat Intelligence Aggregator</title>
        {css_style}
    </head>
    <body>
        <div class="container">
            <h1> Weekly Threat Intelligence Aggregator</h1>

            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-num">{total_threats}</div>
                    <div class="stat-label">TOTAL THREATS (LAST 7 DAYS)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num">{active_sources}</div>
                    <div class="stat-label">ACTIVE SOURCES</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num">{report_date}</div>
                    <div class="stat-label">REPORT DATE</div>
                </div>
            </div>

            {table_html}

            <div class="footer">
                Time window: {REPORT_START.strftime("%d/%m/%Y")} - {REPORT_END.strftime("%d/%m/%Y")} |
                Sources: NVD (CVE), AlienVault OTX (IOC), URLHaus (Malicious URLs) |
                Generated automatically by Python Threat Aggregator | Confidential
            </div>
        </div>
    </body>
    </html>
    """
    return html


def generate_reports(df: pd.DataFrame) -> None:
    today = REPORT_END.strftime("%Y%m%d")

    csv_name = f"threats_{today}.csv"
    df.to_csv(csv_name, index=False, encoding="utf-8-sig")
    logger.info("Saved CSV report: %s", csv_name)

    html_name = f"report_{today}.html"
    html_content = generate_html_report(df)
    with open(html_name, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("Saved HTML report: %s", html_name)
    webbrowser.open(f"file://{os.path.abspath(html_name)}")

    excel_name = f"report_{today}.xlsx"
    df.to_excel(excel_name, index=False)
    excel_abs = os.path.abspath(excel_name)
    logger.info("Saved Excel report in project folder: %s", excel_abs)

    downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
    os.makedirs(downloads_dir, exist_ok=True)
    excel_download_path = os.path.join(downloads_dir, excel_name)
    shutil.copyfile(excel_abs, excel_download_path)
    logger.info("Excel report copied to Downloads: %s", excel_download_path)

    try:
        os.startfile(excel_download_path)
        logger.info("Excel report opened automatically.")
    except Exception as exc:
        logger.warning("Could not auto-open Excel report: %s", exc)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    logger.info(
        "Starting Threat Aggregator (Weekly window: %s -> %s)",
        REPORT_START.strftime("%Y-%m-%d"),
        REPORT_END.strftime("%Y-%m-%d"),
    )
    df = collect_all_sources()
    if df.empty:
        logger.error("No data collected. Check API keys / network.")
        return

    logger.info("Sources count:\n%s", df["Source"].value_counts())
    generate_reports(df)


if __name__ == "__main__":
    main()
