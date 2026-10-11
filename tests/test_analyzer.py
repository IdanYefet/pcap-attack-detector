"""Unit tests for the detector.

Packets are crafted in memory and written to a temporary pcap, so the tests
need no live capture and no network access.
"""

from __future__ import annotations

import os
import sys

import pytest
from scapy.all import IP, TCP, wrpcap

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.analyzer import Thresholds, analyze_pcap  # noqa: E402

ATTACKER = "10.0.0.5"
TARGET = "10.0.0.20"


def _write(tmp_path, pkts):
    path = str(tmp_path / "t.pcap")
    wrpcap(path, pkts)
    return path


def _syn(dport, sport):
    return IP(src=ATTACKER, dst=TARGET) / TCP(sport=sport, dport=dport, flags="S")


def test_port_scan_detected(tmp_path):
    pkts = [_syn(port, 40000 + port) for port in range(1, 31)]
    path = _write(tmp_path, pkts)

    result = analyze_pcap(path, Thresholds(scan_distinct_ports=15))
    techniques = {f.technique for f in result.findings}
    assert "T1046" in techniques


def test_ssh_bruteforce_detected(tmp_path):
    pkts = [_syn(22, 50000 + i) for i in range(20)]
    path = _write(tmp_path, pkts)

    result = analyze_pcap(path, Thresholds(ssh_min_attempts=10))
    findings = [f for f in result.findings if f.technique == "T1110"]
    assert findings
    assert findings[0].severity == "high"


def test_benign_traffic_is_clean(tmp_path):
    # A normal client touching a few ports should trigger nothing.
    pkts = [_syn(443, 60000), _syn(80, 60001), _syn(22, 60002)]
    path = _write(tmp_path, pkts)

    result = analyze_pcap(path)
    assert result.findings == []


def test_thresholds_are_respected(tmp_path):
    # 12 SSH attempts: below a threshold of 20, above a threshold of 10.
    pkts = [_syn(22, 50000 + i) for i in range(12)]
    path = _write(tmp_path, pkts)

    assert analyze_pcap(path, Thresholds(ssh_min_attempts=20)).findings == []
    assert analyze_pcap(path, Thresholds(ssh_min_attempts=10)).findings


def test_syn_ack_is_not_counted(tmp_path):
    # Reply packets (SYN+ACK) are server responses, not connection attempts.
    pkts = [
        IP(src=TARGET, dst=ATTACKER) / TCP(sport=22, dport=50000 + i, flags="SA")
        for i in range(30)
    ]
    path = _write(tmp_path, pkts)

    result = analyze_pcap(path, Thresholds(ssh_min_attempts=10))
    assert result.findings == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
