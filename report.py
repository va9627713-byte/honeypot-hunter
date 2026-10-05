#!/usr/bin/env python3
"""
report.py — Generate a threat intelligence report from honeypot logs.

Usage:
  python3 report.py                 # print summary to terminal
  python3 report.py --json out.json # also export IOC feed as JSON
"""

import argparse
import json

from ti_logger import ThreatIntelLogger


def _safe_terminal_text(value, width):
    text = "".join(char if char.isprintable() else f"\\x{ord(char):02x}" for char in str(value))
    return text[:width]


def print_report(ti: ThreatIntelLogger):
    print("=" * 60)
    print("  HONEYPOT THREAT INTELLIGENCE REPORT")
    print("=" * 60)

    print("\n[Events by service]")
    for service, count in ti.event_counts_by_service():
        print(f"  {service:<10} {count}")

    print("\n[Top scored source IPs]")
    print(f"  {'IP':<18}{'Score':<8}{'Events':<8}{'First seen':<33} {'Last seen'}")
    for ip, score, count, first, last in ti.top_offenders():
        print(f"  {ip:<18}{score:<8}{count:<8}{first:<33} {last}")
        assessment = ti.source_risk_analysis(ip)
        signals = ", ".join(
            f"{signal['count']} {signal['label']}" for signal in assessment["signals"]
        )
        print(f"    Risk: {assessment['level'].upper()} — {signals}")
        print(f"    {assessment['caveat']}")

    print("\n[Common behavior clusters]")
    for fingerprint, behavior, sessions, sources, first, last in ti.top_behavior_clusters():
        categories = ", ".join(json.loads(behavior))
        print(f"  {fingerprint}  {sources} source(s) / {sessions} session(s) "
              f"({first} to {last}): {categories}")

    print("\n[Most common credentials attempted]")
    print(f"  {'Username':<20}{'Attempts'}")
    for user, tries in ti.top_credentials():
        username = _safe_terminal_text(user or "(not captured)", 20)
        print(f"  {username:<20}{tries}")

    ioc = ti.export_ioc_feed(min_score=5)
    print(f"\n[IOC feed] {len(ioc)} IP(s) crossed the malicious-activity threshold (score >= 5)")
    for entry in ioc[:10]:
        signals = ", ".join(
            signal["event_type"] for signal in entry["risk_signals"][:3]
        )
        print(
            f"  {entry['ip']}  {entry['risk_level'].upper()} "
            f"risk={entry['risk_score']}  events={entry['event_count']} "
            f"signals={signals}"
        )
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Export IOC feed to this JSON file")
    parser.add_argument("--min-score", type=int, default=5)
    parser.add_argument(
        "--include-non-global",
        action="store_true",
        help="Include private, loopback, and reserved IPs in the IOC export",
    )
    args = parser.parse_args()

    ti = ThreatIntelLogger()
    print_report(ti)

    if args.json:
        ioc = ti.export_ioc_feed(
            min_score=args.min_score,
            include_non_global=args.include_non_global,
        )
        with open(args.json, "w") as f:
            json.dump(ioc, f, indent=2)
        print(f"IOC feed exported to {args.json}")


if __name__ == "__main__":
    main()
