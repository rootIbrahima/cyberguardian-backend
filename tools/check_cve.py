import re
import httpx

TLS_CVES = {
    "TLSv1": [
        {"id": "CVE-2014-3566", "severity": "HIGH",   "cvss": 3.4, "title": "POODLE — Attaque par oracle de bourrage sur TLS 1.0"},
        {"id": "CVE-2011-3389", "severity": "MEDIUM",  "cvss": 4.3, "title": "BEAST — Exploitation du chiffrement CBC en TLS 1.0"},
    ],
    "TLSv1.1": [
        {"id": "CVE-2015-0204", "severity": "MEDIUM",  "cvss": 4.3, "title": "FREAK — Degradation vers les suites de chiffrement RSA export"},
    ],
}

CIPHER_CVES = {
    "RC4":  {"id": "CVE-2015-2808", "severity": "MEDIUM", "cvss": 4.3, "title": "Bar Mitzvah — Biais statistiques exploitables dans RC4"},
    "DES":  {"id": "CVE-2016-2183", "severity": "HIGH",   "cvss": 7.5, "title": "SWEET32 — Attaque par anniversaire sur DES/3DES (64 bits)"},
    "NULL": {"id": "CVE-2014-0224", "severity": "HIGH",   "cvss": 6.8, "title": "CCS Injection — Negociation de chiffrement NULL exploitable"},
}


def check_tls_cves(tls_version: str, cipher_suite: str) -> list:
    cves = []
    if tls_version and tls_version in TLS_CVES:
        cves.extend(TLS_CVES[tls_version])
    if cipher_suite:
        suite_upper = cipher_suite.upper()
        for keyword, cve in CIPHER_CVES.items():
            if keyword in suite_upper:
                cves.append(cve)
    return cves


def _get_server_banner(target: str) -> str:
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    for scheme in ("https", "http"):
        try:
            resp = httpx.get(
                f"{scheme}://{host}",
                timeout=5,
                follow_redirects=True,
                verify=False,
            )
            banner = resp.headers.get("server", "")
            if banner:
                return banner
        except Exception:
            continue
    return ""


def _parse_banner(banner: str) -> str:
    match = re.match(r'([A-Za-z][A-Za-z\-]+)/(\d+\.\d+[\.\d]*)', banner)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return banner.split()[0] if banner else ""


def _search_nvd(keyword: str, max_results: int = 5) -> list:
    if not keyword or len(keyword) < 4:
        return []
    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=10,
        )
        resp.raise_for_status()
        cves = []
        for item in resp.json().get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            desc     = next(
                (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
                "",
            )
            metrics  = cve_data.get("metrics", {})
            cvss     = None
            severity = "MEDIUM"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    d        = metrics[key][0].get("cvssData", {})
                    cvss     = d.get("baseScore")
                    severity = d.get("baseSeverity", "MEDIUM")
                    break
            if cve_id:
                cves.append({
                    "id":       cve_id,
                    "severity": severity,
                    "cvss":     cvss,
                    "title":    desc[:140] + "..." if len(desc) > 140 else desc,
                    "source":   "nvd",
                })
        return cves
    except Exception:
        return []


def check_service_cves(target: str) -> tuple:
    banner = _get_server_banner(target)
    if not banner:
        return "", []
    keyword = _parse_banner(banner)
    cves    = _search_nvd(keyword)
    return banner, cves
