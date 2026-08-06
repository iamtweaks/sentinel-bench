#!/bin/bash
# sentinel-bench weekly cron: EPSS incremental + score + prune.
# Sundays 13 UTC = 10am ARG / 11am ART.
# No Telegram output — the dashboard is the only read path now.

set -e
cd /root/projects/sentinel-bench

# EPSS for known CVEs (only changes periodically)
python3 -m ingest.ingest --source=EPSS --limit=2000 2>&1 | tail -3

# Score recompute
python3 -m ingest.score --limit=2000 2>&1 | tail -3

# Prune advisories not seen in 90 days — keeps the corpus tight.
python3 -m ingest.prune --days 90 2>&1 | tail -3
