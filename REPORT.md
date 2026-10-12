# Incident Analysis Report — SSH Reconnaissance & Brute Force

**Lab exercise — purple-team / SOC detection**

| | |
| --- | --- |
| **Analyst** | Idan Yefet |
| **Date** | 2026-10-12 |
| **Environment** | Isolated VirtualBox lab (`lab-net`, no access to the internet-facing LAN) |
| **Capture** | `attack.pcap` — 2,516 packets (2,163 TCP) |
| **Detector** | [`pcap-attack-detector`](https://github.com/IdanYefet/pcap-attack-detector) (own tool) |

## 1. Executive summary

A single host on the lab network (`10.0.2.4`) performed a full TCP port scan of
the target server (`10.0.2.3`), discovered an exposed SSH service on `tcp/22`,
and then launched an SSH brute-force attack against the `labuser` account. The
attack succeeded because the account used a weak password. Both stages were
captured passively and detected by `pcap-attack-detector`, and mapped to MITRE
ATT&CK techniques **T1046** and **T1110**.

## 2. Lab topology

```
            VirtualBox NAT network "lab-net" (10.0.2.0/24, isolated)
   +----------------------+                         +----------------------+
   |  Attacker            |                         |  Target              |
   |  Kali Linux          |  10.0.2.4  --------->   |  Ubuntu Server 26.04 |
   |  nmap, hydra         |                         |  OpenSSH on tcp/22   |
   +----------------------+                         |  10.0.2.3            |
                                                    +----------------------+
```

- The lab is fully self-contained: both VMs talk only over `lab-net`.
- `labuser` is a deliberately weak throwaway account that exists only in the lab.

## 3. Tools used

| Role | Tool | Purpose |
| --- | --- | --- |
| Attacker | `nmap` | TCP port scan (reconnaissance) |
| Attacker | `hydra` | SSH password brute force |
| Target | `tcpdump` | Passive packet capture to `attack.pcap` |
| Analyst | `pcap-attack-detector` | Offline detection + MITRE mapping |

## 4. Timeline of events

| Stage | Source → Target | Observable | ATT&CK |
| --- | --- | --- | --- |
| Reconnaissance | `10.0.2.4 → 10.0.2.3` | SYN packets to 1,000 distinct ports | T1046 |
| Service discovery | `10.0.2.4 → 10.0.2.3` | `22/tcp open ssh` identified | T1046 |
| Credential access | `10.0.2.4 → 10.0.2.3:22` | repeated SSH connections, 20 password guesses | T1110 |
| Compromise | `10.0.2.4 → 10.0.2.3:22` | `labuser:password123` accepted | T1110 |

## 5. Findings

Output of `pcap-attack-detector` on the captured traffic:

```
  pcap-attack-detector  —  /home/idan/attack.pcap
  packets: 2516  (tcp: 2163)
  --------------------------------------------------------
  [HIGH] T1110  Brute Force (SSH)
         10.0.2.4  ->  10.0.2.3
         6 connections to tcp/22 in 680.1s (~0.0 attempts/s)

  [MED]  T1046  Network Service Discovery (port scan)
         10.0.2.4  ->  10.0.2.3
         1000 distinct ports SYN'd in 680.1s (~1 ports/s)
```

### 5.1 Reconnaissance — Port scan (T1046)
- **Observation:** `10.0.2.4` sent SYN packets to 1,000 distinct ports on
  `10.0.2.3`.
- **Analysis:** A normal client contacts a handful of ports. Touching 1,000
  distinct ports from one source is a clear port scan — the attacker mapping the
  target's exposed services. This is how `22/tcp (ssh)` was discovered.

### 5.2 Credential Access — SSH brute force (T1110)
- **Observation:** `10.0.2.4` opened 6 connections to `tcp/22`, carrying 20
  password guesses against `labuser`, ending in a successful login.
- **Analysis:** Repeated authentication attempts against SSH from one source is
  brute force. The weak password (`password123`) made the account trivial to
  compromise.

## 6. Detection limitation discovered (and fixed)

While validating the detector against this real capture, the brute force was
**not** flagged at first. Root cause:

> SSH allows several password attempts inside a single TCP connection (sshd
> `MaxAuthTries`). `hydra` exploits this, so **20 password guesses produced only
> 6 TCP connections** to `tcp/22`.

The original heuristic required ≥10 connections to `tcp/22`, so it missed a real
brute-force attack. This is a genuine SOC lesson: a detector that keys purely on
*connection count* under-counts SSH brute force.

**Fix applied:** the default SSH threshold was lowered to 5 connections (a few
rapid SSH connections from one source already imply many auth attempts). After
the fix the attack is detected at the default settings. A production-grade
detector would additionally correlate with authentication-failure logs (the
approach `fail2ban` and host IDS use).

## 7. MITRE ATT&CK mapping

| Technique | ID | Tactic |
| --- | --- | --- |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Discovery |
| Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | Reconnaissance |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access |

## 8. Recommendations

- **Disable SSH password authentication**; use key-based auth only.
- **Deploy `fail2ban`** or SSH connection rate-limiting to block repeated
  attempts from one source.
- **Enforce strong passwords / MFA** — a weak password was the root cause of
  compromise.
- **Network segmentation and firewall default-deny** to limit port-scan
  reconnaissance.
- **Alert on N+ distinct ports from one source** in a short window (IDS rule).

## 9. Lessons learned

- Built a passive detector, then **validated it against real captured traffic**,
  which exposed a blind spot (SSH connection reuse) that synthetic tests had not.
- Iterated on the detector based on that evidence and re-verified the fix.
- Reinforced the core SOC loop: **capture → detect → analyse → map → recommend**,
  and the value of testing detections against realistic adversary behaviour.
