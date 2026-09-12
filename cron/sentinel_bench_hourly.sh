#!/bin/bash
# sentinel-bench hourly cron: KEV (latest) + GHSA (latest 30).
# Cheap (no LLM, no NVD), idempotent. Runs every 30 min between 8 and 22 ARG,
# or via the cron tool with a 30-minute schedule.

set -e
# ponytail: hermes-workspace moved to /root/hermes-workspace/projects in 2026-09.
# Both paths kept for backwards compat — first one wins.
for candidate in /root/hermes-workspace/projects/sentinel-bench /root/projects/sentinel-bench; do
  if [ -d "$candidate" ]; then
    cd "$candidate"
    break
  fi
done

python3 -m ingest.ingest --source=KEV 2>&1 | tail -3
python3 -m ingest.ingest --source=GHSA --limit=30 2>&1 | tail -3