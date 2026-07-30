#!/usr/bin/env python3
"""Run Phase 2 feature extraction against live MongoDB data.

Usage:
    python scripts/run_feature_extraction.py
    python scripts/run_feature_extraction.py --limit 5
"""

import sys
import argparse
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)

from honeypot_ml.db.mongo_client import ping, get_collection
from honeypot_ml.features.extract import extract_all, print_features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    print("\n Adaptive IoT Honeypot — Phase 2: Feature Extraction")
    print("─" * 55)

    print("\n[1/3]  Checking MongoDB connection...")
    try:
        ping()
        print("       OK — MongoDB is reachable")
    except Exception as e:
        print(f"       FAILED — {e}")
        sys.exit(1)

    print(f"\n[2/3]  Extracting features (limit={args.limit or 'all'})...")
    results = extract_all(limit=args.limit)

    if not results:
        print("       No sessions found. Run: telnet 10.0.2.15 2223")
        sys.exit(0)

    print(f"\n[3/3]  Results — {len(results)} session(s):\n")
    for f in results:
        print_features(f)

    stored = get_collection("features").count_documents({})
    print(f"  Features stored in MongoDB: {stored} document(s)")
    print("\n  Phase 2 complete. Ready for Phase 3.\n")


if __name__ == "__main__":
    main()
