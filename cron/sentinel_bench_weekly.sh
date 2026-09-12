#!/bin/bash
# sentinel-bench weekly cron: EPSS incremental + score + prune.
# Sundays 13 UTC = 10am ARG / 11am ART.
# No Telegram output — the dashboard is the only read path now.

set -e
# ponytail: hermes-workspace moved to /root/hermes-workspace/projects in 2026-09.
# Both paths kept for backwards compat — first one wins.
for candidate in /root/hermes-workspace/projects/sentinel-bench /root/projects/sentinel-bench; do
  if [ -d "$candidate" ]; then
    cd "$candidate"
    break
  fi
done

# EPSS for known CVEs (only changes periodically)
python3 -m ingest.ingest --source=EPSS --limit=2000 2>&1 | tail -3

# Score recompute
python3 -m ingest.score --limit=2000 2>&1 | tail -3

# Prune advisories not seen in 90 days — keeps the corpus tight.
python3 -m ingest.prune --days 90 2>&1 | tail -3
