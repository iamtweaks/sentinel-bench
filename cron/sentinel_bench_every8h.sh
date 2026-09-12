#!/bin/bash
# sentinel-bench every-8h cron: full ingest of all 16 sources (5 IT + 11 OT)
# plus score recompute. Runs at 0,8,16 UTC = 21,5,13 ART.
# Cheap (no LLM, no Telegram). Idempotent. Silent if no change.

set -e

# ponytail: hermes-workspace moved to /root/hermes-workspace/projects in 2026-09.
# Both paths kept for backwards compat — first one wins.
for candidate in /root/hermes-workspace/projects/sentinel-bench /root/projects/sentinel-bench; do
  if [ -d "$candidate" ]; then
    cd "$candidate"
    break
  fi
done

# Full pull from all configured sources (IT + OT).
python3 -m ingest.ingest --source=all 2>&1 | tail -10

# Recompute scores so the dashboard reflects new vulnerabilities.
python3 -m ingest.score --limit=2000 2>&1 | tail -5
