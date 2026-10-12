# pcap-attack-detector

A small **blue-team / SOC** tool that passively analyses a network capture
(`.pcap`) and flags two classic attack patterns:

| Pattern | What it looks for | MITRE ATT&CK |
| --- | --- | --- |
| **Port scan** (reconnaissance) | one source SYN-ing many distinct ports on a host | [T1046](https://attack.mitre.org/techniques/T1046/) · [T1595](https://attack.mitre.org/techniques/T1595/) |
| **SSH brute force** | one source opening many connections to `tcp/22` | [T1110](https://attack.mitre.org/techniques/T1110/) |

It was built and then **validated against a real attack** captured in an
isolated VirtualBox lab (Kali → Ubuntu). See [Lab exercise results](#lab-exercise-results)
and the full write-up in [`REPORT.md`](REPORT.md).

> **Legal & scope notice**
> This project is a self-contained lab exercise. The tool itself is **passive** —
> it only reads a capture file you already recorded; it never scans or sends
> packets. Record traffic only on an **isolated lab network you own** (see
> [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md)). Never capture or test against
> systems or networks you do not own or have written permission to test.

## Why this project

It mirrors what a SOC analyst actually does: capture traffic, recognise the
signature of an attack, and map it to a known framework (MITRE ATT&CK). The
detector is passive and deterministic, so the output is easy to explain in an
interview.

## Install

```bash
cd pcap-attack-detector
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

## Usage

```bash
# analyse a capture and print findings
python -m detector samples/attack.pcap

# also write a Markdown report
python -m detector samples/attack.pcap --report findings.md

# tune the thresholds
python -m detector samples/attack.pcap --ssh-attempts 5 --scan-ports 20
```

Example output:

```
  pcap-attack-detector  —  samples/attack.pcap
  packets: 4821  (tcp: 4780)
  --------------------------------------------------------
  [HIGH] T1110  Brute Force (SSH)
         10.10.10.5  ->  10.10.10.20
         63 connections to tcp/22 in 8.4s (~7.5 attempts/s)

  [MED]  T1046  Network Service Discovery (port scan)
         10.10.10.5  ->  10.10.10.20
         1000 distinct ports SYN'd in 2.1s (~476 ports/s)
```

The process exit code is `1` when anything is detected and `0` when the
capture is clean — convenient for scripting or CI.

## How it works

The analyser streams the pcap with [scapy](https://scapy.net/) and only scores
**connection initiations** (TCP packets with `SYN` set and `ACK` clear),
grouped per *source → destination*:

- **Port scan** — a source that SYNs ≥ *N* distinct destination ports on one
  host in a short window. A scanner sprays many ports fast; a normal client
  touches a handful.
- **SSH brute force** — a source that opens ≥ *M* connections to `tcp/22` on
  one host. Note that SSH allows several password attempts per TCP connection
  (sshd `MaxAuthTries`), so a brute-force tool makes *fewer* connections than
  guesses — the default threshold is kept low on purpose (see
  [Lab exercise results](#lab-exercise-results)).

Thresholds are configurable on the command line (see Usage).

## Lab exercise results

The detector was validated end-to-end against a **real attack** in an isolated
lab: a Kali attacker (`10.0.2.4`) scanned an Ubuntu Server target (`10.0.2.3`)
with `nmap`, then brute-forced SSH with `hydra`. Traffic was captured on the
target with `tcpdump` (2,516 packets) and analysed with this tool:

```
  pcap-attack-detector  —  attack.pcap
  packets: 2516  (tcp: 2163)
  --------------------------------------------------------
  [HIGH] T1110  Brute Force (SSH)
         10.0.2.4  ->  10.0.2.3
         6 connections to tcp/22 in 680.1s

  [MED]  T1046  Network Service Discovery (port scan)
         10.0.2.4  ->  10.0.2.3
         1000 distinct ports SYN'd in 680.1s
```

**A limitation found and fixed.** The brute force was missed on the first run:
20 password guesses produced only **6 TCP connections**, because SSH packs
multiple auth attempts into one connection. A detector that keys purely on
connection count under-counts SSH brute force — so the default SSH threshold was
lowered (and the nuance documented). A production detector would also correlate
with authentication-failure logs (the `fail2ban` approach).

Full write-up: [`REPORT.md`](REPORT.md) · lab build: [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md).

## Project layout

```
pcap-attack-detector/
├── detector/
│   ├── analyzer.py       # detection logic (pure, testable)
│   └── __main__.py       # CLI + report rendering
├── tests/
│   └── test_analyzer.py  # unit tests (synthetic packets, no capture needed)
├── samples/
│   └── make_sample.py    # regenerate the demo capture
├── docs/
│   └── LAB_SETUP.md      # how the isolated lab is built
├── MITRE_MAPPING.md      # each lab step mapped to ATT&CK
├── REPORT.md             # incident report from the live lab exercise
├── report_template.md    # SOC-style write-up template
└── requirements.txt
```

## Tests

```bash
python samples/make_sample.py     # (re)create samples/attack.pcap
python -m pytest tests/ -v        # run the unit tests
```

## Roadmap

- [x] Unit tests with synthetic packets (no live capture needed)
- [x] Validated against a real captured attack (see Lab exercise results)
- [ ] Detect the SYN/SYN-ACK completion ratio (half-open scans)
- [ ] JSON output mode
```
