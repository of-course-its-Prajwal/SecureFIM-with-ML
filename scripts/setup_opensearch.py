#!/usr/bin/env python3
"""
SecureFIM Pro — OpenSearch Index Setup
Creates all required indices. Run once before first use,
or the server will create them automatically on startup.

Usage:
    python scripts/setup_opensearch.py [--host localhost] [--port 9200]
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.opensearch import OpenSearchClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=9200)
    args = parser.parse_args()

    os.environ["OPENSEARCH_HOST"] = args.host
    os.environ["OPENSEARCH_PORT"] = str(args.port)

    # Re-import to pick up env
    from importlib import reload
    import server.config
    reload(server.config)

    client = OpenSearchClient()
    print(f"Connecting to OpenSearch at {args.host}:{args.port} ...")

    if not client.wait_for_cluster(retries=10, delay=2):
        print("ERROR: Cannot connect to OpenSearch")
        sys.exit(1)

    print("Creating indices...")
    client.ensure_indices()
    print("Done! All indices are ready.")


if __name__ == "__main__":
    main()
