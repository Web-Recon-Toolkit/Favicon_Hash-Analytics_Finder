# Deep Favicon Hash Finder  & Multi-Analytics Tracker Extractor

A robust reconnaissance tool designed to extract favicons and tracking/analytics identifiers from a target domain. It automatically generates [FOFA](https://fofa.info/) queries based on identifiers and MMH3 hashes to help security researchers and bug bounty hunters discover related organizational infrastructure.

## Features
- **Favicon Hashing**: Automatically locates, downloads, and calculates the MMH3 hash of a target's favicon for FOFA `icon_hash` searches.
- **Multi-Analytics Extraction**: Identifies 10+ trackers including Google Analytics (GA4/Universal), Google Tag Manager (GTM), Facebook Pixel, HubSpot, Hotjar, TikTok Pixel, Yandex, Matomo, and New Relic.
- **Deep Scanning**: Inspects initial HTML, parses same-domain linked JavaScript files (up to 15 key scripts), and dynamically extracts nested tags from actual GTM containers.
- **FOFA Query Generation**: Instantly generates ready-to-use FOFA syntax for footprinting and asset correlation.

## Prerequisites
This script requires **Python 3.x**.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Web-Recon-Toolkit/Favicon_Hash-Analytics_Finder.git
   cd Favicon_Hash-Analytics_Finder
   ```

2. Install the required dependencies:
   ```bash
   pip install mmh3 beautifulsoup4 requests
   ```
   *(Note: `urllib3` is installed automatically with `requests`)*

## Usage

```bash
python3 favicon_and_Analytics.py -d <target_domain> [-org <organization_name>]
```

### Arguments
- `-d`, `--domain`: **(Required)** The target domain or URL to scan (e.g., `example.com` or `https://example.com`).
- `-org`, `--org-name`: *(Required)* Custom organization name used for labeling the saved favicon file (e.g., saving as `OrgName_favicon.ico`).

### Example
```bash
python3 favicon_and_Analytics.py -d example.com -org ExampleInc
```

### Example Output
```text
[*] Target Domain: example.com (https://example.com)
[*] Organization : ExampleInc
[*] Fetching root page and associated scripts...

==================================================
[+] FAVICON & FOFA HASH
==================================================
Favicon Found At : https://example.com/favicon.ico
Saved Locally As : ExampleInc_favicon.ico
Favicon MMH3 Hash: -1234567890

>> FOFA Syntax:
   icon_hash="-1234567890"

==================================================
[+] ANALYTICS & TRACKING TAGS (DEEP SCAN)
==================================================
Found 2 tracker(s) across target assets:

[-] Technology   : Google Tag Manager (GTM)
    ID / Token   : GTM-XXXXXXX
    FOFA Syntax  : body="GTM-XXXXXXX"

[-] Technology   : Facebook Pixel
    ID / Token   : 123456789012345
    FOFA Syntax  : body="123456789012345"

==================================================
```

## Disclaimer
This tool is intended for educational purposes, authorized security testing, and bug bounty reconnaissance. Users are fully responsible for their actions and must ensure they have authorization to scan and analyze target domains.
