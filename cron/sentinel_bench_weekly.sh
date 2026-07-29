#!/bin/bash
# sentinel-bench weekly cron: EPSS incremental + force briefing (always sends).
# Sundays 13 UTC = 10am ARG / 11am ART.

set -e
cd /root/projects/sentinel-bench

# EPSS for known CVEs (only changes periodically)
python3 -m ingest.ingest --source=EPSS --limit=2000 2>&1 | tail -3

# Score recompute
python3 -m ingest.score --limit=2000 2>&1 | tail -3

# Force weekly briefing (always sends, regardless of diff hash)
python3 -m ingest.diff --force 2>&1 | tail -5