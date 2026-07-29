#!/usr/bin/env python3
"""Parse MSRC CVRF XML docs (v1.1 schema) for CVE-level enrichment.

Each Vulnerability element has:
  - CVE (string)
  - Title
  - Notes/Summary, Description
  - CVSSScoreSets (nested ScoreSet with BaseScore + Vector + ProductFamilies)
  - ProductStatuses (Affected/Unaffected per product)

Returns normalized records matching normalize_msrc_to_vuln() shape.
"""
import xml.etree.ElementTree as ET
from typing import Iterator

NS = {
    "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
    "prod": "http://www.icasi.org/CVRF/schema/prod/1.1",
    "cvssv2": "https://scap.nist.gov/schema/cvss-v2/1.0",
}


def _sev_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def parse_cvrf(xml_bytes: bytes) -> Iterator[dict]:
    """Yield normalized vuln records from a CVRF XML doc."""
    import re
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return
    for v in root.findall(".//vuln:Vulnerability", NS):
        cve = v.findtext(".//vuln:CVE", namespaces=NS)
        if not cve:
            continue
        cve = cve.strip()
        if not CVE_RE.match(cve):
            continue  # skip placeholder entries like "CVE-2023-38039 mariner - ..."
        title = v.findtext(".//vuln:Title", namespaces=NS) or ""
        # Best CVSS score across all sets
        best_score = None
        best_vector = None
        for ss in v.findall(".//cvrf:CVSSScoreSets/cvrf:ScoreSet", NS):
            b = ss.findtext("cvrf:BaseScore", namespaces=NS)
            if b:
                try:
                    s = float(b)
                    if best_score is None or s > best_score:
                        best_score = s
                        best_vector = ss.findtext("cvrf:Vector", namespaces=NS)
                except ValueError:
                    pass
        # Affected products (first few)
        prods = set()
        for ps in v.findall(".//prod:ProductStatuses/prod:Status", NS):
            pid = ps.get("ProductID") or ""
            if pid:
                prods.add(pid.split(":")[4] if ":" in pid else pid)
        yield {
            "cve_id": cve.strip(),
            "title": title[:300],
            "cvss_v3_score": best_score,
            "cvss_v3_vector": best_vector,
            "severity": _sev_from_score(best_score),
            "products": sorted(prods)[:10],
            "vendors": ["microsoft"],
            "refs": [],
        }


if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "rb") as f:
        for rec in parse_cvrf(f.read()):
            print(rec)
