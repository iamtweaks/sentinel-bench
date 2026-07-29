"""Risk scoring v1 — deterministic, explainable, no LLM.

Formula (sum clipped to 0..100):
  30 * kev_present
+ 25 * (1 if epss_percentile >= 0.99 else 0)
+ 15 * (epss_score if epss_score >= 0.5 else 0)   # 0..0.15
+ 12 * cvss_v3 / 10                                # 0..12
+  8 * exploitation_factor                         # 0..1
+  5 * recency_factor                              # 0..1
+  3 * source_diversity_factor                     # 0..1
+  2 * vendor_exposure_factor                      # 0..1
"""
from datetime import datetime, timezone


HIGH_EXPOSURE_VENDORS = {
    "microsoft", "apple", "google", "linux", "cisco", "adobe", "oracle",
    "ibm", "sap", "vmware", "fortinet", "paloaltonetworks", "citrix", "juniper",
}


def exploitation_factor(status: str | None) -> float:
    if not status: return 0.0
    s = status.lower()
    if s == "confirmed": return 1.0
    if s == "poc": return 0.6
    if s == "probable": return 0.3
    return 0.0


def recency_factor(published_at: str | None) -> float:
    if not published_at: return 0.0
    try:
        dt = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
        if days < 7: return 1.0
        if days < 30: return 0.5
        if days < 90: return 0.2
        return 0.0
    except Exception:
        return 0.0


def source_diversity_factor(distinct_sources: int) -> float:
    return min(distinct_sources / 4.0, 1.0)


def vendor_exposure_factor(vendors: list[str]) -> float:
    if not vendors: return 0.0
    v_low = {v.lower() for v in vendors}
    return 1.0 if v_low & HIGH_EXPOSURE_VENDORS else 0.0


def compute_score(vuln: dict, *, distinct_sources: int = 1) -> tuple[float, dict]:
    """Return (score 0..100, factors jsonb-ready dict with explicit nulls for unknowns)."""
    cvss = vuln.get("cvss_v3_score")
    epss = vuln.get("epss_score")
    epss_pct = vuln.get("epss_percentile")

    factors = {
        "kev_present": bool(vuln.get("is_kev")),
        "epss_top1pct": bool(epss_pct is not None and epss_pct >= 0.99),
        "epss_score": float(epss) if epss is not None else None,
        "epss_score_used": (float(epss) if epss is not None and epss >= 0.5 else 0.0),
        "cvss_v3_score": float(cvss) if cvss is not None else None,
        "cvss_v3_used": (float(cvss) / 10.0) if cvss is not None else 0.0,
        "exploitation_status": vuln.get("exploitation_status") or "unknown",
        "exploitation_factor": exploitation_factor(vuln.get("exploitation_status")),
        "recency_factor": recency_factor(vuln.get("published_at")),
        "source_diversity_factor": source_diversity_factor(distinct_sources),
        "vendor_exposure_factor": vendor_exposure_factor(vuln.get("vendors", [])),
    }
    raw = (
        30 * (1.0 if factors["kev_present"] else 0.0)
        + 25 * (1.0 if factors["epss_top1pct"] else 0.0)
        + 15 * factors["epss_score_used"]
        + 12 * factors["cvss_v3_used"]
        +  8 * factors["exploitation_factor"]
        +  5 * factors["recency_factor"]
        +  3 * factors["source_diversity_factor"]
        +  2 * factors["vendor_exposure_factor"]
    )
    score = max(0.0, min(100.0, raw))
    factors["total_raw"] = round(raw, 2)
    return round(score, 2), factors


def score_breakdown(score: float, factors: dict) -> str:
    """Human-readable one-liner for the briefing."""
    bits = []
    if factors.get("kev_present"): bits.append("KEV")
    if factors.get("epss_top1pct"): bits.append("EPSS≥99pct")
    if factors.get("exploitation_status") in ("confirmed", "poc"):
        bits.append(f"exploit={factors['exploitation_status']}")
    if factors.get("cvss_v3_score"): bits.append(f"CVSS={factors['cvss_v3_score']}")
    if factors.get("vendor_exposure_factor"): bits.append("high-exposure vendor")
    return " · ".join(bits) if bits else "baseline"