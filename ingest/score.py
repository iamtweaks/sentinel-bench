#!/usr/bin/env python3
"""sentinel-bench score — recompute risk scores for current vulnerabilities.

Idempotent: appends a new risk_scores row per CVE every run. The dashboard reads
the latest per CVE.

Optional arg --only=KEV to recompute only a subset.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ingest.lib import (
    sb_headers, sb_url, sb_patch_run, sb_record_run,
    compute_score, score_breakdown,
)

PROJECT_REF = open("/root/projects/sentinel-bench/.supabase-creds").readline().split("=",1)[1].strip()


def fetch_all_vulns() -> list[dict]:
    headers = sb_headers()
    out = []
    offset = 0
    while True:
        req = urllib.request.Request(
            sb_url(PROJECT_REF, f"/vulnerabilities?select=cve_id,cvss_v3_score,is_kev,exploited_in_wild,poc_public,first_seen_at,vendors,epss_score,epss_percentile,description&order=cve_id&offset={offset}&limit=500"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            chunk = json.loads(resp.read())
        if not chunk:
            break
        out.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500
    return out


def count_distinct_sources_for(cve_id: str) -> int:
    headers = sb_headers()
    req = urllib.request.Request(
        sb_url(PROJECT_REF, f"/advisories?cve_ids=cs.{{{cve_id}}}&select=source_id&limit=20"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            rows = json.loads(resp.read())
        return len({r["source_id"] for r in rows})
    except Exception:
        return 1


def insert_risk_scores(rows: list[dict]) -> int:
    if not rows:
        return 0
    headers = {**sb_headers(), "Prefer": "return=minimal"}
    total = 0
    for i in range(0, len(rows), 500):
        chunk = rows[i:i+500]
        req = urllib.request.Request(
            sb_url(PROJECT_REF, "/risk_scores"),
            data=json.dumps(chunk).encode(),
            headers=headers,
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=60).read()
            total += len(chunk)
        except urllib.error.HTTPError as e:
            print(f"risk_scores insert error {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="Only score CVEs matching substring (e.g. KEV)")
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    started = datetime.now(timezone.utc)
    run_id = ""
    try:
        run_id = sb_record_run(PROJECT_REF, {"started_at": started.isoformat(), "sources_attempted": 0})
    except Exception as e:
        print(f"warn: delivery_run create: {e}", file=sys.stderr)

    vulns = fetch_all_vulns()
    print(f"fetched {len(vulns)} vulnerabilities")
    if args.only:
        vulns = [v for v in vulns if (args.only == "KEV" and v.get("is_kev"))]
        print(f"filtered to {len(vulns)} with is_kev=true")
    vulns = vulns[:args.limit]

    rows = []
    for v in vulns:
        cve = v["cve_id"]
        distinct = count_distinct_sources_for(cve)
        vuln_for_score = {
            "cvss_v3_score": v.get("cvss_v3_score"),
            "epss_score": v.get("epss_score"),
            "epss_percentile": v.get("epss_percentile"),
            "is_kev": v.get("is_kev", False),
            "exploitation_status": "confirmed" if v.get("exploited_in_wild") else ("poc" if v.get("poc_public") else "unknown"),
            "published_at": v.get("first_seen_at"),
            "vendors": v.get("vendors") or [],
        }
        score, factors = compute_score(vuln_for_score, distinct_sources=distinct)
        rows.append({
            "cve_id": cve,
            "computed_at": started.isoformat(),
            "score": score,
            "factors": factors,
            "rationale": score_breakdown(score, factors),
            "model_version": "v1",
        })

    n = insert_risk_scores(rows)
    print(f"inserted {n} risk_scores rows")

    finished = datetime.now(timezone.utc)
    if run_id:
        try:
            sb_patch_run(PROJECT_REF, run_id, {
                "finished_at": finished.isoformat(),
                "sources_ok": 0,
                "scores_recomputed": n,
                "briefing_sent": False,
                "briefing_reason": "score_only",
            })
        except Exception as e:
            print(f"warn: delivery_run patch: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()