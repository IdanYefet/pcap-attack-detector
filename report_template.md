# Incident Analysis Report — Lab Exercise

> Fill this in with your own captured data. This is the deliverable that
> demonstrates SOC-analyst thinking: observation → analysis → recommendation.

## 1. Summary

- **Analyst:** <your name>
- **Date:** <YYYY-MM-DD>
- **Environment:** Isolated VirtualBox host-only lab (no internet exposure)
- **Capture file:** `<file>.pcap`  (`<N>` packets)
- **One-line summary:** A single source host performed a port scan followed by
  an SSH brute-force attempt against the target.

## 2. Lab topology

```
+------------------+        host-only network        +------------------+
|  Attacker VM     |  10.10.10.5                      |  Target VM       |
|  (Kali / Linux)  | <------------------------------> |  Ubuntu + SSH    |
|                  |        192.168.56.0/24           |  10.10.10.20     |
+------------------+                                   +------------------+
```

(Replace IPs with your actual lab addresses — see `docs/LAB_SETUP.md`.)

## 3. Timeline of events

| Time (capture) | Event | Source → Target | Evidence |
| --- | --- | --- | --- |
| t+0.0s | Port scan begins | 10.10.10.5 → 10.10.10.20 | SYN to many ports |
| t+2.1s | Scan completes | | <N> ports probed |
| t+4.0s | SSH brute force begins | 10.10.10.5 → 10.10.10.20:22 | repeated tcp/22 connects |
| t+12s | Brute force ends | | <N> attempts |

## 4. Findings

Paste the detector output here:

```
<output of: python -m detector capture.pcap>
```

### 4.1 Reconnaissance — Port scan (T1046 / T1595)
- **Observation:** <what you saw in the pcap>
- **Analysis:** <why it is a scan, not normal traffic>

### 4.2 Credential Access — SSH brute force (T1110)
- **Observation:** <connection count / rate to tcp/22>
- **Analysis:** <why this is brute force>

## 5. MITRE ATT&CK mapping

See [`MITRE_MAPPING.md`](MITRE_MAPPING.md). Key techniques observed:
`T1046`, `T1110`.

## 6. Recommendations

- Restrict SSH exposure (firewall, key-only auth, non-default port where appropriate)
- Deploy `fail2ban` / connection rate limiting on `tcp/22`
- Alert on N+ distinct ports from one source in a short window (IDS rule)
- Network segmentation to limit lateral discovery

## 7. Lessons learned

<what you learned building and running this exercise>
