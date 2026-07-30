"""Config + env loading."""
import os
from pathlib import Path

ENV_PATH = Path("/root/.hermes/.env")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def get_env(name: str, default: str = "") -> str:
    """Read from process env first, then from /root/.hermes/.env."""
    val = os.environ.get(name)
    if val:
        return val
    if not ENV_PATH.exists():
        return default
    for line in ENV_PATH.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            return v.strip().strip("\"'")
    return default


def project_root() -> Path:
    return PROJECT_ROOT


# Source catalog — slug → fetch config. Single source of truth.
# kind: json_feed | rest_api | rss | csaf (CSAF 2.0 JSON files at a provider's distribution URL)
# domain (config-side, not column-side): IT or OT — set on the source row at insert time.
SOURCES = {
    # ---- IT sources (existing) ----
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "kind": "json_feed",
    },
    "epss": {
        "name": "FIRST EPSS",
        "url": "https://api.first.org/data/v1/epss",
        "kind": "rest_api",
    },
    "ghsa": {
        "name": "GitHub Security Advisories",
        "url": "https://api.github.com/advisories",
        "kind": "rest_api",
    },
    "nvd": {
        "name": "NIST NVD",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "kind": "rest_api",
    },
    "msrc": {
        "name": "Microsoft MSRC",
        "url": "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        "kind": "rest_api",
    },
    # ---- Public OT sources (all free / no account) ----
    "abb_psirt": {
        "name": "ABB PSIRT (RSS)",
        "url": "https://psirt.abb.com/rss/abbrssfeed.xml",
        "kind": "rss", "domain": "OT", "vendor": "abb",
    },
    "abb_csaf": {
        "name": "ABB PSIRT (CSAF)",
        "url": "https://psirt.abb.com/csaf/abb-csaf-feed-tlp-white.json",
        "kind": "csaf", "domain": "OT", "vendor": "abb",
    },
    "rockwell": {
        "name": "Rockwell Automation Security Advisories",
        "url": "https://www.rockwellautomation.com/bin/rss/security-advisories.xml",
        "kind": "rss", "domain": "OT", "vendor": "rockwell",
    },
    "cert_vde": {
        "name": "CERT@VDE Advisories",
        "url": "https://certvde.com/en/advisories/feeds/rss/",
        "kind": "rss", "domain": "OT", "vendor": "cert_vde",
    },
    "fortinet": {
        "name": "Fortinet PSIRT",
        "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "kind": "rss", "domain": "OT", "vendor": "fortinet",
    },
    "siemens": {
        "name": "Siemens ProductCERT",
        "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json",
        "kind": "csaf", "domain": "OT", "vendor": "siemens",
    },
    "cisco_psirt": {
        "name": "Cisco PSIRT",
        "url": "https://sec.cloudapps.cisco.com/security/center/publicationService.x?publicationTypeIDs=1&offset=0&limit=200&sort=-last_published&criteria=exact",
        "kind": "json_feed", "domain": "OT", "vendor": "cisco",
    },
    "nvd_ics": {
        "name": "NIST NVD (ICS-filtered)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ics&resultsPerPage=2000",
        "kind": "rest_api", "domain": "OT", "vendor": "nvd",
    },
    "paloalto": {
        "name": "Palo Alto Networks Security Advisories",
        "url": "https://security.paloaltonetworks.com/json",
        "kind": "json_feed", "domain": "OT", "vendor": "paloalto",
    },
    # CISA's site RSS is blocked at this VPS; this is CISA's official CSAF GitHub mirror.
    "cisa_ics": {
        "name": "CISA ICS Advisories (official CSAF mirror)",
        "url": "https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1",
        "kind": "csaf_tree", "domain": "OT", "vendor": "cisa",
    },
    # Schneider's canonical index is WAF-blocked from this VPS. Do not bypass it.
    # Its CISA republications arrive through the cisa_ics source above.
    "moxa": {
        "name": "Moxa Security Advisories",
        "url": "https://www.moxa.com/en/support/product-support/security-advisory/security-advisories-all",
        "kind": "html", "domain": "OT", "vendor": "moxa",
    },
}