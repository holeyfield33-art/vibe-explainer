"""Verify an unsigned analyst review packet's integrity and scope identity."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vibe_explainer.review_packet import verify_review_packet


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify_review_packet(args.packet)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"INVALID review packet: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": manifest["status"], "integrity": "VERIFIED", "customer_delivery_approved": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
