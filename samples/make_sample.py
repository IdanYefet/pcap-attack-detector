"""Generate a synthetic sample capture for the demo.

This only *writes packets to a file* — it never sends anything on the network.
Run it to recreate `samples/attack.pcap` so the README demo works out of the box:

    python samples/make_sample.py
"""

from __future__ import annotations

import os

from scapy.all import IP, TCP, wrpcap

ATTACKER = "192.168.56.5"
TARGET = "192.168.56.20"
BENIGN = "192.168.56.30"

OUT = os.path.join(os.path.dirname(__file__), "attack.pcap")


def build() -> list:
    pkts = []
    t = 1000.0

    # 1) Port scan: SYN to 200 distinct ports on the target.
    for port in range(1, 201):
        p = IP(src=ATTACKER, dst=TARGET) / TCP(sport=40000 + port, dport=port, flags="S")
        p.time = t
        t += 0.01
        pkts.append(p)

    # 2) SSH brute force: 40 fresh connections to tcp/22.
    for i in range(40):
        p = IP(src=ATTACKER, dst=TARGET) / TCP(sport=50000 + i, dport=22, flags="S")
        p.time = t
        t += 0.1
        pkts.append(p)

    # 3) Benign background traffic (must NOT trigger a finding).
    for i in range(20):
        p = IP(src=BENIGN, dst=TARGET) / TCP(sport=60000 + i, dport=443, flags="S")
        p.time = t
        t += 1.0
        pkts.append(p)

    return pkts


if __name__ == "__main__":
    pkts = build()
    wrpcap(OUT, pkts)
    print(f"wrote {len(pkts)} packets to {OUT}")
