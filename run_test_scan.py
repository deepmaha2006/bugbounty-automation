#!/usr/bin/env python3
"""
Test scan script for HydraX - runs a quick scan on a test target
"""

import sys
import os
import time

# Add the current directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scan_engine import ScanEngine
from core.storage import ReportStore
from config.settings import resolve_target_url, DEFAULT_SCANNER_KEYS
from ui.theme import configure_app
import queue

def test_scan():
    """Run a test scan on a safe target"""
    print("🧪 HydraX Test Scan")
    print("=" * 50)

    # Configure app theme
    configure_app()

    # Create event queue for communication
    events = queue.Queue()

    # Initialize scan engine
    scan_engine = ScanEngine(events)
    report_store = ReportStore()

    # Use a safe test target (httpbin.org is a testing service)
    target = "https://httpbin.org"
    print(f"🎯 Target: {target}")

    # Normalize the URL
    try:
        target = resolve_target_url(target)
        print(f"🔗 Normalized target: {target}")
    except ValueError as e:
        print(f"❌ Invalid target: {e}")
        return False

    # Use a subset of scanners for quick testing
    scanner_keys = ["sqli", "xss"]  # Just test a couple of scanners
    print(f"🔍 Scanners: {', '.join(scanner_keys)}")

    # Event handler to process scan events
    def handle_event(event):
        if not event:
            return

        event_type = event[0]

        if event_type == "status":
            print(f"📢 {event[1] if len(event) > 1 else ''}")
        elif event_type == "error":
            print(f"❌ Error: {event[1] if len(event) > 1 else 'Unknown error'}")
        elif event_type == "report_saved":
            print(f"💾 Report saved: {event[1] if len(event) > 1 else ''}")
        elif event_type == "progress":
            progress = event[1] if len(event) > 1 else 0
            print(f"📊 Progress: {progress}%")
        elif event_type == "discovery":
            print(f"🔎 Discovery: {event[1] if len(event) > 1 else ''}")

    print("\n🚀 Starting scan...")
    start_time = time.time()

    # Start the scan
    scan_engine.scan(target, scanner_keys)

    # Process events for up to 30 seconds
    timeout = 30
    while timeout > 0:
        try:
            # Process events without blocking
            while not events.empty():
                event = events.get_nowait()
                handle_event(event)

            # Check if scan is complete by looking for completion events
            # In a real implementation, we'd have a better way to detect completion
            time.sleep(0.1)
            timeout -= 0.1

        except KeyboardInterrupt:
            print("\n⏹️  Scan interrupted by user")
            scan_engine.stop()
            break
        except Exception as e:
            print(f"⚠️  Event processing error: {e}")
            time.sleep(0.1)

    elapsed_time = time.time() - start_time
    print(f"\n⏱️  Scan completed in {elapsed_time:.1f} seconds")

    # Check if any reports were generated
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if os.path.exists(reports_dir):
        reports = [f for f in os.listdir(reports_dir) if f.endswith(('.html', '.json'))]
        if reports:
            print(f"📄 Generated reports: {', '.join(reports[-3:])}")  # Show last 3 reports
        else:
            print("📄 No reports generated")
    else:
        print("📄 Reports directory not found")

    print("\n✅ Test scan finished")
    return True

if __name__ == "__main__":
    try:
        success = test_scan()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"💥 Test scan failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)