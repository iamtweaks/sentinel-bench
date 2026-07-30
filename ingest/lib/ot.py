"""OT feed normalization: public RSS/CSAF/HTML sources.

No external dependencies. RSS parsing is stdlib XML; CVEs extracted with regex.
All output matches Sentinel's existing advisory contract and adds domain='OT'.
"""
from __future__ import annotations

import hashlib
import re
from html import unescape
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _severity(text: str) -> str:
    text = (text or "").upper()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in text:
            return level
    return "unknown"


def normalize_rss_ot(xml_text: str, vendor: str, source: str) -> list[dict]:
    """RSS 2.0 -> OT advisories. Invalid items are skipped, never kill an ingest."""
    root = ET.fromstring(xml_text)
    out: list[dict] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        pubdate = _iso_date(item.findtext("pubDate"))
        guid = (item.findtext("guid") or link or title).strip()
        if not guid or not title:
            continue
        cves = sorted(set(x.upper() for x in CVE_RE.findall(f"{title} {description}")))
        # RSS GUID can be a giant URL. Stable SHA only when no advisory ID is present.
        external_id = guid if len(guid) <= 250 else hashlib.sha256(guid.encode()).hexdigest()
        raw = {"title": title, "link": link, "description": description, "pubDate": item.findtext("pubDate"), "guid": guid}
        out.append({
            "external_id": external_id,
            "url": link or None,
            "title": title,
            "summary": re.sub(r"<[^>]+>", " ", description)[:4000],
            "severity": _severity(f"{title} {description}"),
            "published_at": pubdate,
            "cve_ids": cves,
            "vendors": [vendor],
            "products": [],
            "is_kev": False,
            "exploitation_status": "unknown",
            "domain": "OT",
            "raw": raw,
        })
    return out


def normalize_moxa_html(html: str) -> list[dict]:
    """Parse Moxa's server-rendered advisory table with stdlib regex only."""
    rows = re.findall(r'<tr class="border-table__tr">(.*?)</tr>', html, re.S)
    out = []
    for row in rows:
        ident = re.search(r'\b(MPSA-\d+)\b', row)
        link = re.search(r'href="([^"]*mpsa-[^"]+)"[^>]*>\s*(.*?)\s*</a>', row, re.S | re.I)
        date = re.search(r'<span class="date-short hide">([^<]+)</span>', row)
        if not ident or not link:
            continue
        title = re.sub(r'\s+', ' ', unescape(re.sub(r'<[^>]+>', '', link.group(2)))).strip()
        cves = sorted(set(CVE_RE.findall(title)))
        published = datetime.strptime(date.group(1).strip(), '%b %d, %Y').replace(tzinfo=timezone.utc).isoformat() if date else None
        raw = {'id': ident.group(1), 'title': title, 'date': date.group(1).strip() if date else None}
        out.append({'external_id': ident.group(1), 'url': 'https://www.moxa.com' + unescape(link.group(1)), 'title': title,
                    'summary': title, 'severity': 'unknown', 'published_at': published, 'cve_ids': cves,
                    'vendors': ['moxa'], 'products': [], 'is_kev': False, 'exploitation_status': 'unknown',
                    'domain': 'OT', 'raw': raw})
    return out


def normalize_fortinet_html(html: str) -> list[dict]:
    """Parse FortiGuard's public PSIRT list (server-rendered HTML, no dependency)."""
    out: list[dict] = []
    blocks = re.split(r'<div class="row" onclick="location\.href = \'/psirt/', html)[1:]
    for block in blocks:
        ident = re.match(r'(FG-IR-\d{2}-\d+)\'">', block)
        if not ident:
            continue
        advisory_id = ident.group(1)
        text = unescape(re.sub(r'<[^>]+>', ' ', block[:6000]))
        text = re.sub(r'\s+', ' ', text).strip()
        title_match = re.search(rf'{re.escape(advisory_id)}\s+(.+?)\s+CVE-', text)
        cves = sorted(set(CVE_RE.findall(text)))
        published = re.search(r'Published:\s*([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})', text)
        severity = next((x.upper() for x in ('Critical', 'High', 'Medium', 'Low') if re.search(rf'\b{x}\b\s+Severity', text, re.I)), 'unknown')
        products = re.findall(r'\b(Forti[A-Za-z0-9-]+)\b', text)
        raw = {'id': advisory_id, 'text': text[:5000]}
        out.append({
            'external_id': advisory_id,
            'url': f'https://www.fortiguard.com/psirt/{advisory_id}',
            'title': title_match.group(1).strip() if title_match else advisory_id,
            'summary': text[:2000],
            'severity': severity,
            'published_at': datetime.strptime(published.group(1), '%b %d, %Y').replace(tzinfo=timezone.utc).isoformat() if published else None,
            'cve_ids': cves,
            'vendors': ['fortinet'],
            'products': sorted(set(products)),
            'is_kev': False,
            'exploitation_status': 'unknown',
            'domain': 'OT',
            'raw': raw,
        })
    return out


def normalize_csaf_ot(doc: dict, vendor: str) -> list[dict]:
    """One CSAF 2.0 document -> one advisory per CVE, preserving product/remediation context."""
    document = doc.get("document") or {}
    tracking = document.get("tracking") or {}
    advisory_id = tracking.get("id") or document.get("title") or "csaf"
    products: dict[str, str] = {}

    def walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        product = node.get("product") or {}
        if product.get("product_id") and product.get("name"):
            products[product["product_id"]] = product["name"]
        for branch in node.get("branches") or []:
            walk(branch)
        for rel in node.get("relationships") or []:
            full = rel.get("full_product_name") or {}
            if full.get("product_id") and full.get("name"):
                products[full["product_id"]] = full["name"]

    walk(doc.get("product_tree") or {})
    out: list[dict] = []
    for vuln in doc.get("vulnerabilities") or []:
        cve = (vuln.get("cve") or "").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        affected_ids = ((vuln.get("product_status") or {}).get("known_affected") or [])
        affected = sorted(products[x] for x in affected_ids if x in products)
        descriptions = [n.get("text", "") for n in vuln.get("notes") or [] if n.get("category") == "description"]
        remediations = [r.get("details", "") for r in vuln.get("remediations") or [] if r.get("details")]
        cvss = [s.get("cvss_v3") or s.get("cvss_v4") or {} for s in vuln.get("scores") or []]
        severity = next((str(s.get("baseSeverity", "")).upper() for s in cvss if s.get("baseSeverity")), "unknown")
        refs = [r.get("url") for r in vuln.get("references") or [] if r.get("url")]
        raw = {"advisory_id": advisory_id, "cve": cve, "title": vuln.get("title"), "notes": descriptions, "affected": affected, "remediations": remediations, "scores": cvss, "references": refs}
        out.append({
            "external_id": f"{advisory_id}:{cve}",
            "url": refs[0] if refs else None,
            "title": f"{document.get('title') or advisory_id} — {cve}",
            "summary": "\n".join(descriptions + remediations)[:4000],
            "severity": severity,
            "published_at": tracking.get("initial_release_date") or tracking.get("current_release_date"),
            "cve_ids": [cve],
            "vendors": [vendor],
            "products": affected,
            "is_kev": False,
            "exploitation_status": "unknown",
            "domain": "OT",
            "raw": raw,
        })
    return out


def demo() -> None:
    xml = """<rss><channel><item><title>ABB critical CVE-2026-12345</title><link>https://example.test/a</link><guid>SA-1</guid><pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate><description>High severity flaw</description></item></channel></rss>"""
    rows = normalize_rss_ot(xml, "abb", "abb_psirt")
    assert len(rows) == 1 and rows[0]["domain"] == "OT"
    assert rows[0]["cve_ids"] == ["CVE-2026-12345"]


if __name__ == "__main__":
    demo()
    print("ok")
