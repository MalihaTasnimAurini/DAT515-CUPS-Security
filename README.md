# CUPS Printer Discovery: Traffic Generation and Detection

**Course:** DAT515  
**Institution:** University of Stavanger  
**Author:** Maliha Tasnim Aurini

## 1. Project overview

This project investigates legacy CUPS printer-discovery traffic in an isolated Docker-based laboratory. It contains:

- A Scapy-based tool for generating controlled legacy CUPS browse-style UDP packets.
- A detector for analysing offline PCAP files or live network traffic.
- Test PCAP files and CSV/JSON detection results.
- An experiment that disables the legacy `cups` browse protocol in `cups-browsed`.

All testing must be performed only in an isolated environment that you own or are authorised to test.

## 2. Final source files

| File | Purpose |
|---|---|
| `cups_attack.py` | Current Scapy packet-generation tool. Supports target/source/port options, dry-run mode, logging, and PCAP output. |
| `cups_detector.py` | Current detector. Supports offline PCAP analysis, live capture, trusted-source configuration, and CSV/JSON exports. |
| `requirements.txt` | Python dependencies. |
| `pcap_files/` | Selected input and experiment packet captures. |
| `detector_results/` | Selected detector outputs in CSV and JSON formats. |
| `evidence/` | Screenshots organised by assignment task. |

Older files such as `cups_attack_lab.py`, `cups_detector_lab.py`, and `cups_detector_v1.py` are earlier iterations. The experiments documented in the current report use **`cups_attack.py` and `cups_detector.py`**. Do not use the older `_lab.py` files as the final implementation unless the submitted report is changed to match them.

## 3. Laboratory environment

The experiments were performed using Kali Linux and a Docker CUPS target.

| Component | Configuration used in the experiments |
|---|---|
| Attacker / analysis host | Kali Linux |
| CUPS target container | `cups-victim` |
| Target
