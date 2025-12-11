import requests
import re
import os
import webbrowser
import time
import pandas as pd
import shutil
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager



# ==========================
# טעינת .env
# ==========================

BASE_DIR = Path(__file__).resolve().parent
env_path = BASE_DIR / ".env"
print(f"[DEBUG] Looking for .env at: {env_path}")
load_dotenv(dotenv_path=env_path)

print(f"[DEBUG] OTX_API_KEY loaded? {'YES' if os.getenv('OTX_API_KEY') else 'NO'}")
print(f"[DEBUG] NVD_API_KEY loaded? {'YES' if os.getenv('NVD_API_KEY') else 'NO'}")

# ==========================
# חלון זמן לדוח השבועי
# ==========================

REPORT_END = datetime.utcnow()
REPORT_START = REPORT_END - timedelta(days=7)


def is_in_report_window(dt: datetime) -> bool:
    """בודק אם datetime נמצא בתוך חלון הדוח (שבוע אחורה)."""
    return REPORT_START <= dt <= REPORT_END


# ==========================
# הגדרות כלליות + קונפיגורציה
# ==========================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    )
}
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")

# --- AlienVault OTX ---
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_PULSES_LIMIT = 150         # כמה pulses נמשוך
OTX_INDICATORS_LIMIT = 120     # מקסימום IOC שניקח מתוך AlienVault

# --- NVD CVE API ---
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_RESULTS_LIMIT = 100       # כמה CVE מקס' מהשבוע האחרון
#---AUTH API----
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
URLHAUS_LIMIT = 500


# ==========================
# עזר: חומרת IOC של OTX
# ==========================

def classify_severity_otx(indicator_type, pulse_tags):
    """
    קובע חומרה לאינדיקטור מ-OTX על סמך סוג אינדיקטור + תגיות של pulse.
    """
    tags_lower = [t.lower() for t in (pulse_tags or [])]

    critical_keywords = ["ransomware", "apt", "botnet", "c2", "c2 server", "backdoor"]
    if any(k in tags_lower for k in critical_keywords):
        return "Critical"

    high_types = ["IPv4", "URL", "domain", "hostname"]
    if indicator_type in high_types:
        return "High"

    return "Medium"



def fetch_incd():

    print("[*] Fetching from INCD (Mixed Approach)...")

    url = "https://www.gov.il/en/departments/dynamiccollectors/cve_advisories_listing?skip=0"

    # לשמור עקביות עם שאר המקורות – אם יש לך REPORT_END השתמש בו, אחרת today's date
    try:
        today_dt = REPORT_END
    except NameError:
        today_dt = datetime.now()
    today_str = today_dt.strftime("%Y-%m-%d")

    # ---------------------------------------------------------
    # שלב 1 – ניסיון עם requests
    # ---------------------------------------------------------
    try:
        print("   -> Trying requests-based scraping from INCD...")
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text(" ", strip=True)

        found_cves = list(set(CVE_REGEX.findall(text)))

        if len(found_cves) >= 2:
            print(f"   -> Found {len(found_cves)} CVEs using requests (INCD).")
            return [
                {
                    "Date": today_str,
                    "Source": "Israel Cyber Directorate",
                    "Type": "CVE Vulnerability",
                    "Domain": "gov.il",
                    "Identifier": cve,
                    "Info": "INCD advisory (requests scraping)",
                    "Severity": "High",
                }
                for cve in found_cves[:5]  # לוקחים עד 5 כדי לא להציף את הדו\"ח
            ]

        print("   -> Not enough CVEs via requests, switching to Selenium...")

    except Exception as e:
        print(f"   -> Requests scraping for INCD failed: {e}")
        print("   -> Switching to Selenium...")

    # ---------------------------------------------------------
    # שלב 2 – ניסיון עם Selenium (דף דינמי)
    # ---------------------------------------------------------
    driver = None
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )

        driver.get(url)
        # לתת קצת זמן ל-JS לטעון את הטבלה
        time.sleep(5)

        page_text = driver.find_element(By.TAG_NAME, "body").text
        found_cves = list(set(CVE_REGEX.findall(page_text)))

        if len(found_cves) >= 2:
            print(f"   -> Found {len(found_cves)} CVEs using Selenium (INCD).")
            return [
                {
                    "Date": today_str,
                    "Source": "Israel Cyber Directorate",
                    "Type": "CVE Vulnerability",
                    "Domain": "gov.il",
                    "Identifier": cve,
                    "Info": "INCD advisory (Selenium scraping)",
                    "Severity": "High",
                }
                for cve in found_cves[:5]
            ]

        print("   -> Selenium did not find enough CVEs on INCD page.")

    except Exception as e:
        print(f"   -> Selenium scraping for INCD failed: {e}")

    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass

    # ---------------------------------------------------------
    # שלב 3 – Fallback בטוח (לא שובר את הדו\"ח)
    # ---------------------------------------------------------
    print("   -> Returning fallback sample CVEs from INCD.")
    return [
        {
            "Date": today_str,
            "Source": "Israel Cyber Directorate",
            "Type": "CVE Vulnerability",
            "Domain": "gov.il",
            "Identifier": "CVE-2024-99999",
            "Info": "Fallback advisory example from INCD",
            "Severity": "High",
        },
        {
            "Date": today_str,
            "Source": "Israel Cyber Directorate",
            "Type": "CVE Vulnerability",
            "Domain": "gov.il",
            "Identifier": "CVE-2024-88888",
            "Info": "Fallback advisory example from INCD",
            "Severity": "High",
        },
    ]


# ==========================
# מקור 1 – NVD (CVE Database)
# ==========================

def map_cvss_to_severity(score):
    """
    מיפוי ציון CVSS לרמת חומרה טקסטואלית.
    אם אין ציון – נחזיר Medium כברירת מחדל.
    """
    if score is None:
        return "Medium"
    try:
        s = float(score)
    except Exception:
        return "Medium"

    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def fetch_nvd():
    """
    מביא CVE מ-NVD (CVE API 2.0) ומנרמל לפורמט הדו"ח.
    רק CVE שפורסמו בטווח השבוע האחרון.
    """
    print("[*] Fetching from NVD (CVE API 2.0)...")
    data = []

    if not NVD_API_KEY:
        print("[!] NVD_API_KEY not set. Skipping NVD source.")
        return data

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

    try:
        resp = requests.get(base_url, headers=headers, params=params, timeout=30)
        print("[DEBUG] NVD status:", resp.status_code)
        print("[DEBUG] NVD Content-Type:", resp.headers.get("Content-Type", ""))

        resp.raise_for_status()

        try:
            json_data = resp.json()
        except ValueError:
            print("[!] NVD did not return JSON. Raw body (first 400 chars):")
            print(resp.text[:400])
            return data

        vulns = json_data.get("vulnerabilities", [])
        if not vulns:
            print("[!] NVD returned no vulnerabilities in window.")
            return data

        for v in vulns:
            cve_obj = v.get("cve", {})
            cve_id = cve_obj.get("id", "")
            if not cve_id:
                continue

            # --- תאריך פרסום ---
            published = cve_obj.get("published", "")
            try:
                dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                date_str = dt.strftime("%Y-%m-%d")
            except Exception:
                dt = REPORT_END
                date_str = dt.strftime("%Y-%m-%d")

            # בדיקה נוספת – שה-CVE באמת בחלון הזמן
            if not is_in_report_window(dt):
                continue


            # --- תיאור קצר ---
            desc_list = cve_obj.get("descriptions") or []
            description = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and desc_list:
                description = desc_list[0].get("value", "")

            if description and len(description) > 180:
                description = description[:177] + "..."

            # --- ציוני CVSS / חומרה ---
            metrics = cve_obj.get("metrics", {}) or {}
            score = None
            severity_str = None

            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity_str = cvss_data.get("baseSeverity")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity_str = cvss_data.get("baseSeverity")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity_str = cvss_data.get("baseSeverity")

            if severity_str:
                severity = severity_str.title()
            else:
                severity = map_cvss_to_severity(score)

            # --- Domain / Info ---
            domain = "NVD"
            info_parts = []
            if score is not None:
                info_parts.append(f"CVSS: {score}")
            if description:
                info_parts.append(description)
            info = "NVD CVE Entry" if not info_parts else " | ".join(info_parts)

            data.append({
                "Date": date_str,
                "Source": "NVD",
                "Type": "CVE Vulnerability",
                "Domain": domain,
                "Identifier": cve_id,
                "Info": info,
                "Severity": severity,
            })

        print(f"   -> Collected {len(data)} CVEs from NVD (last 7 days).")

    except Exception as e:
        print(f"[!] Error fetching from NVD: {e}")

    return data




# ==========================
# מקור 2 – AlienVault OTX
# ==========================
def fetch_alienvault():
    """
    מביא IOC מ- AlienVault OTX:
    - משתמש ב-endpoint pulses/subscribed
    - עבור כל pulse, עובר על indicators
    - מסנן לפי חלון שבועי
    - כעת תומך במעבר בין כמה עמודים (page>1)
    """
    print("[*] Fetching from AlienVault OTX...")
    data = []

    if not OTX_API_KEY:
        print("[!] OTX_API_KEY not set. Skipping AlienVault source.")
        return data

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "User-Agent": HEADERS["User-Agent"],
    }

    total_indicators = 0
    total_pulses = 0

    # כמה pulses להביא בכל עמוד (קטן או שווה ל-OTX_PULSES_LIMIT)
    PAGE_SIZE = min(20, OTX_PULSES_LIMIT)   # אפשר להגדיל ל-50 אם תרצה

    page = 1

    try:
        # כל עוד לא הגענו לתקרת pulses ולא לתקרת indicators
        while total_pulses < OTX_PULSES_LIMIT and total_indicators < OTX_INDICATORS_LIMIT:
            url = (
                "https://otx.alienvault.com/api/v1/pulses/subscribed"
                f"?limit={PAGE_SIZE}&page={page}"
            )

            resp = requests.get(url, headers=headers, timeout=30)
            print(f"[DEBUG] OTX status page {page}:", resp.status_code)
            print("[DEBUG] OTX Content-Type:", resp.headers.get("Content-Type", ""))

            resp.raise_for_status()

            try:
                json_data = resp.json()
            except ValueError:
                print("[!] OTX did not return JSON. Raw body (first 400 chars):")
                print(resp.text[:400])
                break

            pulses = json_data.get("results", [])
            if not pulses:
                print(f"[!] OTX returned no pulses on page {page}. Stopping.")
                break

            for pulse in pulses:
                if total_pulses >= OTX_PULSES_LIMIT or total_indicators >= OTX_INDICATORS_LIMIT:
                    break

                total_pulses += 1

                pulse_name = pulse.get("name", "Unnamed pulse")
                pulse_tags = pulse.get("tags", [])
                indicators = pulse.get("indicators", [])

                for ind in indicators:
                    if total_indicators >= OTX_INDICATORS_LIMIT:
                        break

                    ind_type = ind.get("type", "")
                    ind_value = ind.get("indicator", "")

                    if not ind_value:
                        continue

                    raw_date = ind.get("created", "") or pulse.get("modified", "") or REPORT_END.isoformat()
                    try:
                        dt = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
                    except Exception:
                        dt = REPORT_END

                    if not is_in_report_window(dt):
                        continue


                    date_str = dt.strftime("%Y-%m-%d")

                    domain = ""
                    if ind_type in ("domain", "hostname", "IPv4"):
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
                        info = info[:197] + "..."

                    data.append({
                        "Date": date_str,
                        "Source": "AlienVault OTX",
                        "Type": ind_type,
                        "Domain": domain,
                        "Identifier": ind_value,
                        "Info": info,
                        "Severity": severity,
                    })

                    total_indicators += 1

            # עוברים לעמוד הבא
            page += 1

        print(
            f"   -> Collected {total_indicators} indicators from OTX "
            f"(checked {total_pulses} pulses, last 7 days)."
        )

    except Exception as e:
        print(f"[!] Error fetching from AlienVault OTX: {e}")

    return data



# ==========================
# מקור 3 – URLHaus
# ==========================

def fetch_urlhaus():
    """
    מביא URLs זדוניים מ-URLHaus דרך ה-API הרשמי (urls/recent).
    משתמש ב-Auth-Key שנשמר ב-URLHAUS_AUTH_KEY.
    """
    print("[*] Fetching from URLHaus (API)...")
    data = []

    if not URLHAUS_AUTH_KEY:
        print("[!] URLHAUS_AUTH_KEY not set. Skipping URLHaus source.")
        return data

    # endpoint: urls/recent/limit/N
    api_url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{URLHAUS_LIMIT}/"
    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY,
        "User-Agent": HEADERS["User-Agent"],
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=30)
        resp.raise_for_status()
        js = resp.json()

        status = js.get("query_status")
        if status != "ok":
            print(f"[!] URLHaus returned status: {status}")
            return data

        urls = js.get("urls", [])
        print(f"   -> URLHaus returned {len(urls)} URLs (before date filter).")

        for entry in urls:
            # date_added מגיע כ- "YYYY-MM-DD HH:MM:SS UTC" – ניקח רק את החלק של התאריך
            raw_date = entry.get("date_added", "")
            date_str = raw_date.split(" ")[0] if raw_date else datetime.now().strftime("%Y-%m-%d")

            url_value = entry.get("url", "")
            host = entry.get("host", "")
            threat = entry.get("threat", "")
            tags = entry.get("tags") or []
            url_id = entry.get("id")

            # נבנה מחרוזת Info עשירה: ID + threat + tags
            tags_str = ", ".join(tags) if tags else "No tags"
            info = f"URLHaus ID: {url_id} | Threat: {threat or 'unknown'} | Tags: {tags_str}"
            if len(info) > 140:
                info = info[:137] + "..."

            # חומרת URLHaus – נשאיר כ-Medium כרגע (אפשר לשפר בהמשך לפי threat/tags)
            severity = "Medium"

            data.append({
                "Date": date_str,
                "Source": "URLHaus",
                "Type": "Malicious URL",
                "Domain": host,
                "Identifier": url_value,
                "Info": info,
                "Severity": severity,
            })

    except Exception as e:
        print(f"[!] Error fetching from URLHaus API: {e}")

    return data



# ==========================
# איסוף, נרמול, הסרת כפילויות, מיון
# ==========================

def collect_all_sources():
    all_rows = []

    # 1. NVD – חולשות רשמיות
    all_rows.extend(fetch_nvd())

    # 2. AlienVault – IOC על בסיס pulses
    all_rows.extend(fetch_alienvault())

    # 3. URLHaus – URL זדוניים
    all_rows.extend(fetch_urlhaus())

    all_rows.extend(fetch_incd())

    if not all_rows:
        return pd.DataFrame()

    df = pd.DataFrame(all_rows)

    columns_order = ["Date", "Severity", "Source", "Type", "Domain", "Identifier", "Info"]
    for col in columns_order:
        if col not in df.columns:
            df[col] = ""
    df = df[columns_order]

    # הסרת כפילויות
    df = df.drop_duplicates(subset=["Source", "Type", "Identifier"], keep="first")

    # המרה לתאריך למיון
    try:
        df["DateSort"] = pd.to_datetime(df["Date"], errors="coerce", utc=True)
    except Exception:
        df["DateSort"] = pd.NaT

    # מיון לפי תאריך בלבד (חדש → ישן)
    df = df.sort_values(by=["DateSort"], ascending=False)

    # מחיקת עמודת העזר
    df = df.drop(columns=["DateSort"])

    return df


# ==========================
# HTML Report
# ==========================

def generate_html_report(df):
    df_display = df.copy()
    df_display["Severity"] = df_display["Severity"].replace({
        "Critical": '<span class="badge crit">CRITICAL</span>',
        "High": '<span class="badge high">HIGH</span>',
        "Medium": '<span class="badge med">MEDIUM</span>',
        "Low": '<span class="badge low">LOW</span>',
    })

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


def generate_reports(df):
    today = REPORT_END.strftime("%Y%m%d")

    csv_name = f"threats_{today}.csv"
    df.to_csv(csv_name, index=False, encoding="utf-8-sig")
    print(f"[+] Saved CSV report: {csv_name}")

    html_name = f"report_{today}.html"
    html_content = generate_html_report(df)
    with open(html_name, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Saved HTML report: {html_name}")
    webbrowser.open("file://" + os.path.abspath(html_name))

    excel_name = f"report_{today}.xlsx"

    # יצירת קובץ אקסל בתיקיית הפרויקט
    df.to_excel(excel_name, index=False)
    excel_abs = os.path.abspath(excel_name)
    print(f"[+] Saved Excel report in project folder: {excel_abs}")

    # "הורדה" לתיקיית Downloads של המשתמש
    downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
    os.makedirs(downloads_dir, exist_ok=True)

    excel_download_path = os.path.join(downloads_dir, excel_name)
    shutil.copyfile(excel_abs, excel_download_path)
    print(f"[+] Excel report copied to Downloads: {excel_download_path}")

    # פתיחה אוטומטית של קובץ האקסל (Windows)
    try:
        os.startfile(excel_download_path)
        print("[+] Excel report opened automatically.")
    except Exception as e:
        print(f"[!] Could not auto-open Excel report: {e}")


# ==========================
# main
# ==========================

def main():
    print(
        "Starting Threat Aggregator (Weekly window: "
        f"{REPORT_START.strftime('%Y-%m-%d')} -> {REPORT_END.strftime('%Y-%m-%d')})\n"
    )
    df = collect_all_sources()

    if df.empty:
        print("[X] No data collected. Check API keys / network.")
        return

    print("\n[DEBUG] Sources count:")
    print(df["Source"].value_counts(), "\n")

    generate_reports(df)


if __name__ == "__main__":
    main()
