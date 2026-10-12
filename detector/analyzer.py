"""Core detection logic.

Reads a packet capture (.pcap / .pcapng) and flags two classic attack
patterns on an isolated lab network:

  * Port scan (reconnaissance)  -> MITRE ATT&CK T1046 / T1595
  * SSH brute force             -> MITRE ATT&CK T1110

The detection is purely passive: it only reads a capture file that you
already recorded. It performs no scanning and sends no packets.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

try:
    from scapy.all import IP, TCP, PcapReader
except ImportError as exc:  # pragma: no cover - friendly message if scapy missing
    raise SystemExit(
        "scapy is required. Install it with:  pip install -r requirements.txt"
    ) from exc


# TCP flag bits we care about.
SYN = 0x02
ACK = 0x10


@dataclass
class Thresholds:
    """Tunable detection thresholds."""

    # A source that sends SYNs to at least this many distinct ports on one
    # host is treated as a port scan.
    scan_distinct_ports: int = 15
    # A source that opens at least this many connections to port 22 on one
    # host is treated as an SSH brute-force attempt.
    ssh_min_attempts: int = 5
    # TCP port considered "SSH".
    ssh_port: int = 22


@dataclass
class Finding:
    technique: str          # MITRE ATT&CK technique id
    name: str               # human readable name
    src: str                # attacker IP
    dst: str                # target IP
    evidence: str           # one-line explanation
    severity: str           # "high" / "medium"


@dataclass
class FlowStats:
    """Per (source -> destination) accumulator."""

    syn_ports: set[int] = field(default_factory=set)      # distinct dst ports SYN'd
    ssh_syn_count: int = 0                                 # SYNs to the SSH port
    first_ts: float | None = None
    last_ts: float | None = None
    total_packets: int = 0

    def observe(self, ts: float) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        self.total_packets += 1

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts


@dataclass
class AnalysisResult:
    pcap_path: str
    total_packets: int
    tcp_packets: int
    findings: list[Finding]


def analyze_pcap(path: str, thresholds: Thresholds | None = None) -> AnalysisResult:
    """Read *path* and return the detected findings."""

    th = thresholds or Thresholds()
    flows: dict[tuple[str, str], FlowStats] = defaultdict(FlowStats)

    total_packets = 0
    tcp_packets = 0

    # Stream the file packet-by-packet so large captures stay memory-friendly.
    with PcapReader(path) as reader:
        for pkt in reader:
            total_packets += 1
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            tcp_packets += 1

            ip = pkt[IP]
            tcp = pkt[TCP]
            flags = int(tcp.flags)

            # We only score connection *initiations*: SYN set, ACK not set.
            is_syn = (flags & SYN) and not (flags & ACK)
            if not is_syn:
                continue

            key = (ip.src, ip.dst)
            stats = flows[key]
            stats.observe(float(pkt.time))
            stats.syn_ports.add(int(tcp.dport))
            if int(tcp.dport) == th.ssh_port:
                stats.ssh_syn_count += 1

    findings = _score(flows, th)
    return AnalysisResult(
        pcap_path=path,
        total_packets=total_packets,
        tcp_packets=tcp_packets,
        findings=findings,
    )


def _score(flows: dict[tuple[str, str], FlowStats], th: Thresholds) -> list[Finding]:
    findings: list[Finding] = []

    for (src, dst), stats in flows.items():
        # --- Port scan ---------------------------------------------------
        distinct = len(stats.syn_ports)
        if distinct >= th.scan_distinct_ports:
            rate = distinct / stats.duration if stats.duration else distinct
            findings.append(
                Finding(
                    technique="T1046",
                    name="Network Service Discovery (port scan)",
                    src=src,
                    dst=dst,
                    evidence=(
                        f"{distinct} distinct ports SYN'd in "
                        f"{stats.duration:.1f}s (~{rate:.0f} ports/s)"
                    ),
                    severity="medium",
                )
            )

        # --- SSH brute force ---------------------------------------------
        if stats.ssh_syn_count >= th.ssh_min_attempts:
            rate = stats.ssh_syn_count / stats.duration if stats.duration else stats.ssh_syn_count
            findings.append(
                Finding(
                    technique="T1110",
                    name="Brute Force (SSH)",
                    src=src,
                    dst=dst,
                    evidence=(
                        f"{stats.ssh_syn_count} connections to tcp/{th.ssh_port} in "
                        f"{stats.duration:.1f}s (~{rate:.1f} attempts/s)"
                    ),
                    severity="high",
                )
            )

    # Highest severity first, then by technique id for stable output.
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.technique))
    return findings
