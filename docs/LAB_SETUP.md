# Lab setup — isolated test environment

This describes the **self-contained, offline lab** used to generate the sample
traffic the detector analyses. Everything runs on your own machine in
VirtualBox on an **isolated host-only network** with no route to the internet
or your home LAN. Nothing here touches any system you do not own.

## 1. Topology

```
                 VirtualBox "Host-Only" network  (e.g. 192.168.56.0/24)
   +------------------+                                  +------------------+
   |  Attacker VM     |                                  |  Target VM       |
   |  Kali Linux      | <------------------------------> |  Ubuntu Server   |
   |  192.168.56.5    |         (no internet)            |  + OpenSSH       |
   +------------------+                                  |  192.168.56.20   |
                                                         +------------------+
```

## 2. Create the isolated network

In VirtualBox: **File → Tools → Network Manager → Host-only Networks → Create**.
This network connects only your VMs (and your host) — it has no gateway to the
internet. Attach both VMs' network adapter to this Host-Only adapter.

> Keeping the lab host-only is the single most important safety step: even a
> mistake cannot reach anything outside the lab.

## 3. Target VM — Ubuntu Server + SSH

1. Install Ubuntu Server (minimal) in a new VM.
2. Install and enable the SSH service:
   ```bash
   sudo apt update && sudo apt install -y openssh-server
   sudo systemctl enable --now ssh
   ```
3. Note its lab IP: `ip a` (e.g. `192.168.56.20`).
4. Create a throwaway test account with a deliberately weak password **so the
   lab is self-contained** — this account exists only inside the offline lab:
   ```bash
   sudo adduser labuser
   ```

## 4. Capture the traffic (this is the data the detector reads)

On the **target VM** (or a VM mirroring the link), record while you run the test:

```bash
# capture all traffic on the lab interface to a file
sudo tcpdump -i <iface> -w ~/attack.pcap
```

Stop with `Ctrl-C` when done, then copy `attack.pcap` into the detector's
`samples/` folder. You can also open it in **Wireshark** to eyeball the
SYN flood of a scan and the repeated `tcp/22` connections of a brute force.

## 5. Generate the test traffic (attacker VM)

These are the standard tools used to *produce* the signatures the detector is
built to catch. Run them **only against your own Target VM on the host-only
network.**

- **Port scan** (reconnaissance) with `nmap`:
  ```bash
  nmap -sS 192.168.56.20
  ```
- **SSH connection attempts** (brute force): use a standard auditing tool
  (e.g. `hydra` or `ncrack`) against the `labuser` account **on your lab VM
  only**, with a small wordlist you create yourself. The goal is simply to
  generate many rapid `tcp/22` connections for the capture — not to break into
  anything. Keep the attempt count small; a few dozen is plenty to trigger the
  detector.

## 6. Analyse

```bash
cd pcap-attack-detector
python -m detector samples/attack.pcap --report findings.md
```

Then write up what you found using [`../report_template.md`](../report_template.md)
and map it with [`../MITRE_MAPPING.md`](../MITRE_MAPPING.md).

## 7. Tear down

When finished, power off and optionally delete the VMs. Because the lab is
host-only, there is nothing to clean up on your real network.
