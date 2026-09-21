#!/usr/bin/env python3
"""Validate the latest evidence package without silently accepting missing artifacts."""
import json
from pathlib import Path


def main():
    evidence = Path(__file__).resolve().parents[1] / "evidence"
    latest = evidence / "latest_run.txt"
    if not latest.exists():
        raise SystemExit("No evidence exists. Run make test first.")
    run_id = latest.read_text().strip()
    if not run_id or Path(run_id).name != run_id:
        raise SystemExit("Invalid latest run identifier")
    run_dir = evidence / run_id
    required = ("manifest.json", "report.md", "assertions.json", "events.jsonl", "source-files.json")
    missing = [name for name in required if not (run_dir / name).is_file()]
    if missing:
        raise SystemExit("Incomplete package: " + ", ".join(missing))
    manifest = json.loads((run_dir / "manifest.json").read_text())
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines() if line]
    if manifest["run_id"] != run_id or any(event["run_id"] != run_id for event in events):
        raise SystemExit("Evidence belongs to a different run")
    snapshot = json.loads((run_dir / "source-files.json").read_text())
    if snapshot["sha256"] != manifest.get("source_snapshot_sha256"):
        raise SystemExit("Source snapshot does not match manifest")
    print(f"Evidence package: {run_dir}")
    print(f"Correlated events: {len(events)}; scenario results remain as recorded, including failures/incomplete checks.")


if __name__ == "__main__":
    main()
