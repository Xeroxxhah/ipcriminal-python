<div align="center">

# 🚨 ipcriminal-python

**A Python wrapper for the Criminal IP Cyber Threat Intelligence (CTI) API**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Criminal IP API](https://img.shields.io/badge/API-Criminal--IP-orange.svg)](https://www.criminalip.io/)

---

[Key Features](#-key-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[API Reference](#-api-reference) •
[Error Handling](#-error-handling) •
[Contributing](#-contributing)

</div>

---

## 📖 Overview

`ipcriminal-python` is an easy-to-use, feature-packed Python SDK for interacting with the **[Criminal IP](https://search.criminalip.io/developer/api/post-user-me)** Threat Intelligence search engine. It empowers security analysts, red teamers, and threat intelligence practitioners to automate asset discovery, IP reputation scoring, domain threat scanning, exploit lookup, and banner searching directly within their Python workflows.

---

## ✨ Key Features

- **🌐 IP & Asset Intelligence:** Query comprehensive reports, open ports, VPN detection, hosting status, malicious histories, and privacy threats.
- **🔍 Domain Security Analysis:** Perform Full and Lite domain scans, retrieve scan progress, check malicious vs. trusted domain hashes, and list historical scan reports.
- **🛡️ Exploit & Banner Search:** Search exposed services across global network banners and look up CVE vulnerability data.
- **🔄 Automated Pagination:** Built-in offset management for endpoints like `assest_search`, `banner_search`, `domain_reports`, and `exploit_search`.
- **🔑 Clean Authentication:** Seamless API key management with header-based request handling.

---

## 🚀 Installation

Install directly from GitHub via `pip`:

```bash
pip install git+https://github.com/Xeroxxhah/ipcriminal-python.git

```

Or clone the repository locally and install the dependencies:

```bash
git clone https://github.com/Xeroxxhah/ipcriminal-python.git
cd ipcriminal-python
pip install .

```

---

## 🛠️ Quick Start

### 1. Obtain Your API Key

Sign up or log into your account at [Criminal IP](https://www.criminalip.io/) and grab your API Key from the developer dashboard.

### 2. Initialize the Client

```python
from criminalip.criminalip import CriminalIP

# Initialize the API client with your token
client = CriminalIP(api_token="YOUR_CRIMINAL_IP_API_KEY")

```

### 3. Usage Examples

```python
# Check credit balance and subscription tier
account_data = client.account_info()
print(account_data)

```

```python
# Get a comprehensive report on a target IP
ip_report = client.ip_asset_report(ip_address="1.1.1.1", full=True)

# Fetch summarized security issues, open ports, and risk score
summary = client.ip_assest_report_summary(ip_address="1.1.1.1")

# Check if an IP is a known VPN, hosting server, or privacy threat
is_vpn = client.ip_vpn(ip_address="1.1.1.1")
privacy_threat = client.ip_privacy_threats(ip_address="1.1.1.1")

print(f"VPN Status: {is_vpn}")

```

```python
# Initiate a private domain scan
scan_response = client.domain_scan(domain="example.com")

# Request a fast 2-5 second Lite Scan
lite_scan = client.domain_lite_scan(domain="example.com")

# Check if a domain is connected to a malicious website
quick_mal_check = client.domain_quick_mal_view(domain="example.com")
print(quick_mal_check)

```

```python
# Search banners with automatic pagination (fetches up to offset count)
banners = client.banner_search(query="port: 22", offset=20)

# Search CVE exploit details
exploits = client.exploit_search(query="CVE-2023-23397", offset=10)
print(exploits)

```

---

## 📚 API Reference

### 👤 Account Management

| Method | Description | Endpoint |
| --- | --- | --- |
| `account_info()` | Retrieves account details, tier, and remaining search credits. | `POST /v1/user/me` |

---

### 🌐 IP & Asset Intelligence

| Method | Parameters | Description | Endpoint |
| --- | --- | --- | --- |
| `ip_asset_report()` | `ip_address` *(str)*, `full` *(bool)* | Comprehensive IP report (VPN, ports, vulnerabilities). | `GET /v1/asset/ip/report` |
| `ip_assest_report_summary()` | `ip_address` *(str)* | Summary of issues, risks, open ports, and detections. | `GET /v1/asset/ip/report/summary` |
| `ip_assest_summary()` | `ip_address` *(str)* | Location, ISP, owner, and ASN metadata. | `GET /v1/asset/ip/summary` |
| `assest_search()` | `query` *(str)*, `offset` *(int)* | Searches assets using Criminal IP filter syntax with pagination. | `GET /v1/asset/search` |
| `ip_vpn()` | `ip_address` *(str)* | Inquires if an IP is associated with a VPN provider. | `GET /v1/ip/vpn` |
| `ip_hosting()` | `ip_address` *(str)*, `full` *(bool)* | Checks if an IP is hosted in a cloud/hosting datacenter. | `GET /v1/ip/hosting` |
| `ip_mal_info()` | `ip_address` *(str)* | Inquires whether an IP address is flagged as malicious. | `GET /v2/feature/ip/malicious-info` |
| `ip_suspicious_info()` | `ip_address` *(str)* | Inquires data suspected to be malicious. | `GET /v2/feature/ip/suspicious-info` |
| `ip_privacy_threats()` | `ip_address` *(str)* | Detects exposed webcams or IoT devices on the IP. | `GET /v1/feature/ip/privacy-threat` |
| `is_safe_dns_server()` | `ip_address` *(str)* | Verifies whether the DNS service on an IP is secure. | `GET /v1/feature/ip/is_safe_dns_server` |

---

### 🌐 Domain Intelligence

| Method | Parameters | Description | Endpoint |
| --- | --- | --- | --- |
| `domain_scan()` | `domain` *(str)* | Initiates a confidential private domain threat scan. | `POST /v1/domain/scan/private` |
| `domain_reports()` | `query` *(str)*, `offset` *(int)* | Retrieves fully scanned domain reports matching a query. | `GET /v1/domain/reports` |
| `get_domain_reports_by_id()` | `id` *(str)* | Fetches detailed domain scan findings for a specific `scan_id`. | `GET /v1/domain/reports/{id}` |
| `get_domain_status_by_id()` | `id` *(str)* | Checks scan status/history for a given domain ID. | `GET /1/domain/status/{id}` |
| `domain_lite_scan()` | `domain` *(str)* | Triggers a fast (2–5s) OSINT Lite Scan for a domain. | `POST /v1/domain/lite/scan` |
| `domain_lite_progress()` | `scan_id` *(str)* | Checks progress state (-1, -2, 0 to 100) of a Lite Scan. | `GET /v1/domain/lite/progress` |
| `domain_lite_report_by_id()` | `scan_id` *(str)* | Fetches Lite Scan results by `scan_id`. | `GET /v1/domain/lite/report/{scan_id}` |
| `domain_lite_report()` | `query` *(str)*, `offset` *(int)* | Searches Lite Scan domain reports with pagination. | `GET /v1/domain/lite/reports` |
| `domain_quick_view()` | `domain` *(str)* | Classifies if a URL is connected to a malicious or legitimate site. | `GET /v1/domain/quick/hash/view` |
| `domain_quick_mal_view()` | `domain` *(str)* | Specifically verifies if a URL is connected to a malicious site. | `GET /v1/domain/quick/malicious/view` |
| `domain_quick_trusted_view()` | `domain` *(str)* | Specifically verifies if a URL is connected to a legitimate site. | `GET /v1/domain/quick/trusted/view` |

---

### 💥 Exploits, Banners & Threat Intelligence

| Method | Parameters | Description | Endpoint |
| --- | --- | --- | --- |
| `banner_search()` | `query` *(str)*, `offset` *(int)* | Searches banner data across open ports with auto-pagination. | `GET /v1/banner/search` |
| `banner_stats()` | `query` *(str)* | Retrieves statistical aggregations for a banner query. | `GET /v1/banner/stats` |
| `exploit_search()` | `query` *(str)*, `offset` *(int)* | Searches CVE vulnerability details and exploit references. | `GET /v1/exploit/search` |
| `feed_status()` | `key` *(str)* | Queries status, staleness, and count for Threat Intel feeds. | `GET /ti/v1/feed/status` |

---

## 🛡️ Error Handling

If an API call is made without providing an API key, the SDK raises a custom `ApiKeyError`:

```python
from criminalip import CriminalIP
from criminalip.exceptions import ApiKeyError

try:
    client = CriminalIP()  # No token passed
    client.account_info()
except ApiKeyError as e:
    print(f"Authentication Error: {e}")

```

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are very welcome!

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/NewEndpoint`)
3. **Commit** your changes (`git commit -m 'Add support for missing endpoint'`)
4. **Push** to the branch (`git push origin feature/NewEndpoint`)
5. **Open** a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.
