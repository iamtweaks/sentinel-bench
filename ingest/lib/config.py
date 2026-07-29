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
SOURCES = {
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
}