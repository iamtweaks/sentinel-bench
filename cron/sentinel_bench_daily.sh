#!/bin/bash
# sentinel-bench daily cron: ingest NVD (24h window) + MSRC + score + diff → Telegram
# Triggered at 11 UTC (7am ARG / 8am ART).
# Idempotent, silent if no change (no LLM call, no telegram message).

set -e
cd /root/projects/sentinel-bench

# Ingest last 24h of NVD (CVEs modified since yesterday)
YESTERDAY=$(date -u -d 'yesterday' +%Y-%m-%d)
python3 -m ingest.ingest --source=NVD --nvd-since "$YESTERDAY" --limit=500 2>&1 | tail -5

# Ingest latest MSRC security updates (last 3 months)
python3 -m ingest.ingest --source=MSRC --limit=3 2>&1 | tail -5

# Recompute scores (silent if no change)
python3 -m ingest.score --limit=2000 2>&1 | tail -5

# Diff + Telegram (silent if no change)
python3 -m ingest.diff 2>&1 | tail -5