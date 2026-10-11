# MITRE ATT&CK mapping

Each stage of the lab exercise is mapped to the technique a SOC analyst would
record in a real incident. This is the "so what" layer that turns raw packets
into analysis.

| # | Lab stage | ATT&CK tactic | Technique | ID | What the detector sees |
| - | --- | --- | --- | --- | --- |
| 1 | Host discovery / port scan of the target | Reconnaissance | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | one source SYN-ing many ports |
| 2 | Enumerating open services on the target | Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | same SYN-spray pattern, internal |
| 3 | Repeated SSH login attempts | Credential Access | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | many connections to `tcp/22` |
| 3a | — specifically guessing passwords | Credential Access | Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | high-rate `tcp/22` connections |

## Notes for the write-up

- **T1595 vs T1046** — both are "scanning". T1595 (Reconnaissance) is the
  adversary's intent; T1046 (Discovery) is the observed behaviour once on/near
  the network. In a lab on an internal segment, T1046 is usually the better
  label; cite T1595 to show you understand the kill-chain context.
- **T1110 sub-techniques** — plain `T1110` is the family. For an SSH password
  spray against one account, `T1110.001 Password Guessing` is more precise.
- A capture only shows TCP connection behaviour, not the authentication result.
  The detector infers brute force from *connection volume to the SSH port*,
  which is exactly what a network-level IDS (e.g. Suricata/Zeek) keys on.

## Suggested detections / mitigations to mention

| Technique | Detection | Mitigation |
| --- | --- | --- |
| T1046 | IDS signature for N+ distinct ports/source/window | network segmentation, firewall default-deny |
| T1110 | rate of failed logins / `tcp/22` connections per source | `fail2ban`, key-only auth, rate limiting, MFA |
