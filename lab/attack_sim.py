#!/usr/bin/env python3
"""
HydraX Lab — benign attack simulation script.

Sends scripted HTTP requests to TARGET_URL that contain attack-like strings
in paths/params (path traversal, UNION SELECT, <script>, scanner UAs).
All requests are self-contained lab traffic against your own vulnerable app —
no real exploitation, no third-party targets.

Usage:
    python attack_sim.py [--once] [--src-ip IP] [--target URL]

Options:
    --once        Send the batch once and exit (default: loop every 10s).
    --src-ip      Override X-Forwarded-For header (for S6 allowlist test).
    --target      Override TARGET_URL env var.
    --count N     Number of each signal type to send (default: 5).
"""
import argparse
import os
import sys
import time

import requests

DEFAULT_TARGET = os.environ.get("TARGET_URL", "http://connector")

# Benign request patterns that trigger brain signal detection.
# Each is a tuple of (path, user_agent, label).
SIGNALS = [
    # Path traversal
    ("/../etc/passwd",       "Mozilla/5.0",                     "path_traversal"),
    ("/..%2Fetc%2Fshadow",   "Mozilla/5.0",                     "path_traversal_encoded"),
    ("/%2e%2e/etc/hosts",    "Mozilla/5.0",                     "path_traversal_pct"),
    # SQLi hints
    ("/search?q=' UNION SELECT 1,2,3--", "Mozilla/5.0",         "sqli_union"),
    ("/items?id=1' OR '1'='1",           "Mozilla/5.0",         "sqli_boolean"),
    ("/page?id=1; SELECT * FROM users--","Mozilla/5.0",         "sqli_stacked"),
    # XSS hints
    ("/search?q=<script>alert(1)</script>", "Mozilla/5.0",      "xss_script"),
    ("/page?name=%3cscript%3e",             "Mozilla/5.0",      "xss_encoded"),
    # Scanner UAs
    ("/",                   "sqlmap/1.7",                        "scanner_ua_sqlmap"),
    ("/",                   "Nikto/2.1",                         "scanner_ua_nikto"),
    ("/",                   "gobuster/3.0",                      "scanner_ua_gobuster"),
]


def send_signals(target: str, src_ip: str, count: int, verbose: bool) -> int:
    sent = 0
    session = requests.Session()
    for _ in range(count):
        for path, ua, label in SIGNALS:
            url = target.rstrip("/") + path
            headers = {"User-Agent": ua}
            if src_ip:
                headers["X-Forwarded-For"] = src_ip
            try:
                resp = session.get(url, headers=headers, timeout=5, allow_redirects=False)
                if verbose:
                    print(f"  [{label}] {url} → {resp.status_code}")
                sent += 1
            except requests.RequestException as exc:
                if verbose:
                    print(f"  [{label}] {url} → ERROR: {exc}", file=sys.stderr)
                sent += 1  # still counts as a sent attempt
    return sent


def main():
    ap = argparse.ArgumentParser(description="HydraX lab attack simulator")
    ap.add_argument("--once",    action="store_true", help="Send once and exit")
    ap.add_argument("--src-ip",  default="",          help="Override X-Forwarded-For (S6 test)")
    ap.add_argument("--target",  default=DEFAULT_TARGET, help="Target URL")
    ap.add_argument("--count",   type=int, default=5,    help="Repetitions per signal")
    ap.add_argument("--verbose", action="store_true",    help="Print each request")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    print(f"[attack_sim] target={target} src_ip={args.src_ip or '(real)'} count={args.count}")

    if args.once:
        n = send_signals(target, args.src_ip, args.count, args.verbose)
        print(f"[attack_sim] done: sent {n} requests")
    else:
        iteration = 0
        while True:
            iteration += 1
            n = send_signals(target, args.src_ip, args.count, args.verbose)
            print(f"[attack_sim] iteration {iteration}: sent {n} requests")
            time.sleep(10)


if __name__ == "__main__":
    main()
