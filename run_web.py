#!/usr/bin/env python3
"""Launcher script for Ghost Data Still Exists Web Application.

Usage:
    python run_web.py [--port 5000] [--host 127.0.0.1]
"""

import argparse
import os
import sys

# Locate web app package
current_dir = os.path.dirname(os.path.abspath(__file__))
web_dir_candidates = [
    os.path.join(current_dir, "web"),
    os.path.join(current_dir, "hackerrank-orchestrate-october26-main", "web"),
]

web_dir = None
for candidate in web_dir_candidates:
    if os.path.isdir(candidate):
        web_dir = candidate
        break

if not web_dir:
    raise RuntimeError("Could not locate web application directory.")

if web_dir not in sys.path:
    sys.path.insert(0, web_dir)

from app import app


def main():
    parser = argparse.ArgumentParser(description="Ghost Audit OS Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    print("=" * 70)
    print("  GHOST DATA STILL EXISTS — ENTERPRISE DELETION-AUDIT PLATFORM")
    print("  HackerRank Orchestrate October 2026 Challenge")
    print("=" * 70)
    print(f"  * Web Application running at: http://{args.host}:{args.port}")
    print(f"  * Backend: Python Standard Library + Flask 3.1")
    print(f"  * Audit Engine: 100% Deterministic (Zero API Tokens)")
    print("=" * 70)
    print("Press Ctrl+C to terminate the server.\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
