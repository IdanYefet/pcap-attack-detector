"""Command-line entry point.

Usage:
    python -m detector capture.pcap
    python -m detector capture.pcap --report findings.md
    python -m detector capture.pcap --ssh-attempts 5 --scan-ports 20
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .analyzer import AnalysisResult, Thresholds, analyze_pcap


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detector",
        description="Detect port scans and SSH brute-force attempts in a pcap.",
    )
    p.add_argument("pcap", help="path to the .pcap / .pcapng file to analyze")
    p.add_argument(
        "--report",
        metavar="FILE.md",
        help="also write a Markdown report to this file",
    )
    p.add_argument(
        "--scan-ports",
        type=int,
        default=Thresholds.scan_distinct_ports,
        help="distinct ports from one source that count as a scan "
        f"(default: {Thresholds.scan_distinct_ports})",
    )
    p.add_argument(
        "--ssh-attempts",
        type=int,
        default=Thresholds.ssh_min_attempts,
        help="connections to the SSH port that count as brute force "
        f"(default: {Thresholds.ssh_min_attempts})",
    )
    p.add_argument(
        "--ssh-port",
        type=int,
        default=Thresholds.ssh_port,
        help=f"TCP port treated as SSH (default: {Thresholds.ssh_port})",
    )
    return p


def _print_console(result: AnalysisResult) -> None:
    print(f"\n  pcap-attack-detector  —  {result.pcap_path}")
    print(f"  packets: {result.total_packets}  (tcp: {result.tcp_packets})")
    print("  " + "-" * 56)

    if not result.findings:
        print("  No attack patterns detected.\n")
        return

    for f in result.findings:
        tag = "[HIGH]" if f.severity == "high" else "[MED] "
        print(f"  {tag} {f.technique}  {f.name}")
        print(f"         {f.src}  ->  {f.dst}")
        print(f"         {f.evidence}\n")


def _render_markdown(result: AnalysisResult) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# pcap-attack-detector — findings",
        "",
        f"- **Capture:** `{result.pcap_path}`",
        f"- **Generated:** {now}",
        f"- **Packets:** {result.total_packets} (TCP: {result.tcp_packets})",
        f"- **Findings:** {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No attack patterns detected.")
        return "\n".join(lines) + "\n"

    lines += [
        "| Severity | ATT&CK | Technique | Source | Target | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in result.findings:
        lines.append(
            f"| {f.severity.upper()} | {f.technique} | {f.name} "
            f"| `{f.src}` | `{f.dst}` | {f.evidence} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    thresholds = Thresholds(
        scan_distinct_ports=args.scan_ports,
        ssh_min_attempts=args.ssh_attempts,
        ssh_port=args.ssh_port,
    )

    try:
        result = analyze_pcap(args.pcap, thresholds)
    except FileNotFoundError:
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 2

    _print_console(result)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(_render_markdown(result))
        print(f"  report written to {args.report}\n")

    # Exit code 1 if anything was detected — handy for automation / CI.
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
