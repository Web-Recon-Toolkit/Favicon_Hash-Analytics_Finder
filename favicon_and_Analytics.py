#!/usr/bin/env python3
import os
import re
import sys
import codecs
import base64
import argparse
from urllib.parse import urljoin, urlparse

try:
    import mmh3
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] Missing required libraries. Run: pip install mmh3 beautifulsoup4 requests urllib3")
    sys.exit(1)

# HTTP headers used for web requests.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

# Tracker patterns used to identify analytics IDs and generate FOFA queries.
# Expanded tracking / analytics patterns
ANALYTICS_PATTERNS = {
    "Google Analytics 4 (GA4)": {
        "pattern": r"\b(G-[A-Z0-9]{8,12})\b",
        "fofa_param": "body"
    },
    "Google Analytics (Universal)": {
        "pattern": r"\b(UA-\d+-\d+)\b",
        "fofa_param": "body"
    },
    "Google Tag Manager (GTM)": {
        "pattern": r"\b(GTM-[A-Z0-9]{4,10})\b",
        "fofa_param": "body"
    },
    "Google Ads / AdWords": {
        "pattern": r"\b(AW-\d{9,11})\b",
        "fofa_param": "body"
    },
    "Facebook Pixel": {
        "pattern": r"(?:fbq\(['\"]init['\"],\s*['\"]|fbq\.init\(['\"])(\d{14,16})['\"]",
        "fofa_param": "body"
    },
    "Microsoft Clarity": {
        "pattern": r"clarity\(['\"]tag['\"],\s*['\"]([a-z0-9]{8,12})['\"]|clarity\.ms/tag/([a-z0-9]{8,12})",
        "fofa_param": "body"
    },
    "Hotjar Site ID": {
        "pattern": r"(?:hjid|hotjar\.com/c/hotjar-)(\d{6,9})",
        "fofa_param": "body"
    },
    "LinkedIn Insight Tag": {
        "pattern": r"_linkedin_partner_id\s*=\s*['\"]?(\d{6,9})['\"]?",
        "fofa_param": "body"
    },
    "HubSpot Analytics": {
        "pattern": r"hs-scripts\.com/(\d{6,10})\.js|js\.hs-analytics\.net/analytics/\d+/(\d{6,10})\.js",
        "fofa_param": "body"
    },
    "TikTok Pixel": {
        "pattern": r"ttq\.load\(['\"]([A-Z0-9]{15,25})['\"]",
        "fofa_param": "body"
    },
    "Yandex Metrika": {
        "pattern": r"ym\((\d{7,10}),\s*['\"]init['\"]",
        "fofa_param": "body"
    },
    "Matomo / Piwik": {
        "pattern": r"_paq\.push\(\[['\"]setSiteId['\"],\s*['\"]?(\d+)['\"]?\]\)",
        "fofa_param": "body"
    },
    "New Relic Browser": {
        "pattern": r"applicationID:['\"](\d+)['\"]",
        "fofa_param": "body"
    }
}
def print_banner():
    banner = r"""
       Tool By
     ____ ___ _  _ _  _    _    ____
    |  _ \_ _| |/ / |/ /  / \  |  _ \
    | |_) | || ' /| ' /  / _ \ | |_) |
    |  __/| || . \| . \ / ___ \|  __/
    |_|  |___|_|\_\_|\_/_/   \_\_|
    """
    print("\033[96m" + banner + "\033[0m")

# Normalize the target into a URL.
def get_base_url(domain: str) -> str:
    domain = domain.strip()
    if not domain.startswith("http://") and not domain.startswith("https://"):
        return f"https://{domain}"
    return domain

# Fetch a URL and return the response when it succeeds.
def fetch_content(url: str, session: requests.Session):
    try:
        resp = session.get(url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
        if resp.status_code == 200:
            return resp
        else:
            print(f"[!] Warning: Got status {resp.status_code} from {url}")
    except requests.exceptions.Timeout:
        print(f"[!] Warning: Timeout while fetching {url}")
    except requests.exceptions.RequestException:
        pass
    return None

# Find the favicon, save it locally, and calculate its MMH3 hash.
def extract_favicon_and_hash(base_url: str, html_text: str, output_name: str, session: requests.Session):
    favicon_url = None
    if html_text:
        soup = BeautifulSoup(html_text, "html.parser")
        icon_tag = soup.find("link", rel=lambda x: x and any(val in str(x).lower() for val in ["icon", "shortcut icon"]))
        if icon_tag and icon_tag.get("href"):
            favicon_url = urljoin(base_url, icon_tag["href"])

    if not favicon_url:
        favicon_url = urljoin(base_url, "/favicon.ico")

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", output_name)
    saved_filename = f"{safe_name}_favicon.ico"

    resp = fetch_content(favicon_url, session)
    if resp and resp.content:
        with open(saved_filename, "wb") as f:
            f.write(resp.content)

        b64_content = codecs.encode(resp.content, "base64")
        fav_hash = mmh3.hash(b64_content)

        return {
            "url": favicon_url,
            "saved_file": saved_filename,
            "hash": fav_hash,
            "fofa_syntax": f'icon_hash="{fav_hash}"'
        }
    return None

# Search text for known analytics and tracking identifiers.
def scan_text_for_trackers(text: str, collected_findings: dict):
    """Scans any text/code block using all regex patterns."""
    if not text:
        return

    for tech, config in ANALYTICS_PATTERNS.items():
        matches = re.findall(config["pattern"], text, re.IGNORECASE)
        for match in matches:
            tracker_id = None
            if isinstance(match, tuple):
                for group in match:
                    if group:
                        tracker_id = group
                        break
            else:
                tracker_id = match

            if tracker_id and tracker_id not in collected_findings:
                param = config["fofa_param"]

                # Make FOFA syntax more strict for short numbers to avoid false positives
                if tech == "HubSpot Analytics":
                    fofa_query = f'{param}="{tracker_id}.js"'
                elif tech == "Hotjar Site ID":
                    fofa_query = f'{param}="hjid:{tracker_id}" || {param}="hotjar-{tracker_id}"'
                else:
                    fofa_query = f'{param}="{tracker_id}"'

                collected_findings[tracker_id] = {
                    "technology": tech,
                    "id": tracker_id,
                    "fofa_syntax": fofa_query
                }
# Scan the page, selected JavaScript files, and GTM containers for trackers.
def extract_all_analytics(base_url: str, html_text: str, session: requests.Session):
    """Scans initial HTML, linked script files, and dynamic GTM containers."""
    collected_findings = {}

    # 1. Scan the base HTML
    scan_text_for_trackers(html_text, collected_findings)

    if not html_text:
        return list(collected_findings.values())

    soup = BeautifulSoup(html_text, "html.parser")
    base_domain = urlparse(base_url).netloc

    # 2. Extract external script tags (e.g. bundle.js, vendor.js)
    script_urls = set()
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "").strip()
        if src:
            full_src = urljoin(base_url, src)
            # Scan same-domain scripts and common analytics providers
            parsed_src = urlparse(full_src)
            if (base_domain in parsed_src.netloc or not parsed_src.netloc) and not full_src.endswith((".png", ".jpg", ".css")):
                script_urls.add(full_src)

    # Scan up to 15 key JS files to keep recon fast
    for s_url in list(script_urls)[:15]:
        js_resp = fetch_content(s_url, session)
        if js_resp and js_resp.text:
            scan_text_for_trackers(js_resp.text, collected_findings)

    # 3. If GTM is found, inspect GTM's actual container bundle for nested tags
    gtm_ids = [item["id"] for item in collected_findings.values() if item["technology"] == "Google Tag Manager (GTM)"]
    for gtm_id in gtm_ids:
        gtm_url = f"https://www.googletagmanager.com/gtm.js?id={gtm_id}"
        gtm_resp = fetch_content(gtm_url, session)
        if gtm_resp and gtm_resp.text:
            scan_text_for_trackers(gtm_resp.text, collected_findings)

    return list(collected_findings.values())

# Parse arguments and run the favicon and analytics scans.
def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()

    parser = argparse.ArgumentParser(description="Deep Favicon & Multi-Analytics Tracker Extractor")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-org", "--org-name", default="",required=True, help="Organization name (for file labeling)")
    args = parser.parse_args()

    org_label = args.org_name if args.org_name else args.domain
    base_url = get_base_url(args.domain)

    print(f"\n[*] Target Domain: {args.domain} ({base_url})")
    print(f"[*] Organization : {org_label}")
    print("[*] Fetching root page and associated scripts...")

    resp = fetch_content(base_url, session)
    html_content = resp.text if resp else ""

    # Extract and hash the target favicon.
    print("\n" + "=" * 50)
    print("[+] FAVICON & FOFA HASH")
    print("=" * 50)
    fav_result = extract_favicon_and_hash(base_url, html_content, org_label, session)
    if fav_result:
        print(f"Favicon Found At : {fav_result['url']}")
        print(f"Saved Locally As : {fav_result['saved_file']}")
        print(f"Favicon MMH3 Hash: {fav_result['hash']}")
        print(f"\n>> FOFA Syntax:\n   {fav_result['fofa_syntax']}")
    else:
        print("[-] Favicon could not be retrieved.")

    # Extract analytics and tracking identifiers.
    print("\n" + "=" * 50)
    print("[+] ANALYTICS & TRACKING TAGS (DEEP SCAN)")
    print("=" * 50)
    findings = extract_all_analytics(base_url, html_content, session)

    if findings:
        print(f"Found {len(findings)} tracker(s) across target assets:\n")
        for item in findings:
            print(f"[-] Technology   : {item['technology']}")
            print(f"    ID / Token   : {item['id']}")
            print(f"    FOFA Syntax  : {item['fofa_syntax']}\n")
    else:
        print("[-] No recognized analytics/tracking tags found.")

    print("=" * 50 + "\n")

if __name__ == "__main__":
    print_banner()
    main()
