#!/bin/bash
# sentinel-bench hourly cron: KEV (latest) + GHSA (latest 30).
# Cheap (no LLM, no NVD), idempotent. Runs every 30 min between 8 and 22 ARG,
# or via the cron tool with a 30-minute schedule.

set -e
cd /root/projects/sentinel-bench

python3 -m ingest.ingest --source=KEV 2>&1 | tail -3
python3 -m ingest.ingest --source=GHSA --limit=30 2>&1 | tail -3