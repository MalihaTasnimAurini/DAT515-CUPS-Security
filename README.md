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
| Target container IP during the recorded tests | `172.18.0.2` |
| Trusted test source / Docker bridge gateway | `172.18.0.1` |
| Legacy browse traffic | UDP destination port `631` |
| Detector interface used for bridge capture | `br-e286751a311b` |
| Virtual IPP test service | `ippeveprinter` on port `8631` |
| IPP test endpoint | `ipp://172.18.0.1:8631/ipp/print` |

**Important:** Docker addresses and bridge interface names can change after a network or container is recreated. Check the current values before running commands:

```bash
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cups-victim
ip -br link
ip route
```

The values above describe the recorded experiment, not permanent addresses.

## 4. Requirements

- Kali Linux or another authorised Linux environment.
- Python 3.
- Scapy (the version used in the lab was Scapy 2.8).
- Docker and the CUPS target image/container used for the assignment.
- `tcpdump` for packet inspection.
- `ippeveprinter` / CUPS IPP tools if reproducing the virtual printer endpoint.

Install the Python dependency:

```bash
python3 -m pip install -r requirements.txt
```

If the project uses a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

Some packet-capture and packet-transmission operations require elevated privileges, so use `sudo` for those commands where necessary.

## 5. Attack tool: `cups_attack.py`

The sender constructs three controlled UDP/631 browse-style test advertisements. The recorded test cases vary printer/queue information and the advertised URI. The tool writes a PCAP file and logs its activity.

Show command-line options:

```bash
python3 cups_attack.py --help
```

Run a dry-run first:

```bash
sudo python3 cups_attack.py \
  --target 172.18.0.2 \
  --source 172.18.0.1 \
  --port 631 \
  --pcap pcap_files/crafted_browse_tests.pcap \
  --dry-run
```

Transmit the controlled lab packets:

```bash
sudo python3 cups_attack.py \
  --target 172.18.0.2 \
  --source 172.18.0.1 \
  --port 631 \
  --pcap pcap_files/crafted_browse_tests.pcap
```

Verify the saved capture:

```bash
sudo tcpdump -nn -r pcap_files/crafted_browse_tests.pcap
```

The recorded bridge capture confirmed that three UDP datagrams were delivered to `172.18.0.2:631`. CUPS processed the advertisements, but the printer queue was **not** successfully created: the advertised `/printers/<queue>` URI did not match the virtual IPP service endpoint `/ipp/print`. Therefore, the demonstrated result is packet construction, transmission, capture, and browse processing—not successful end-to-end printer installation.

## 6. Detector: `cups_detector.py`

The detector can analyse a saved PCAP or capture live traffic. It supports a trusted-source allowlist and exports alerts to CSV and JSON.

Show command-line options:

```bash
python3 cups_detector.py --help
```

### 6.1 Offline PCAP analysis

Example: analyse the crafted advertisements and trust the lab source `172.18.0.1`:

```bash
sudo python3 cups_detector.py \
  --pcap pcap_files/crafted_browse_tests.pcap \
  --trusted 172.18.0.1 \
  --csv detector_results/task3_crafted_results.csv \
  --json detector_results/task3_crafted_results.json
```

Example: analyse malformed advertisements:

```bash
sudo python3 cups_detector.py \
  --pcap pcap_files/malformed_test.pcap \
  --trusted 172.18.0.1 \
  --csv detector_results/task4_untrusted_malformed.csv \
  --json detector_results/task4_untrusted_malformed.json
```

Example: test the R5 marker:

```bash
sudo python3 cups_detector.py \
  --pcap pcap_files/r5_lab_marker.pcap \
  --trusted 172.18.0.1 \
  --csv detector_results/task4_r5_marker.csv \
  --json detector_results/task4_r5_marker.json
```

### 6.2 Live capture

Use the current Docker bridge interface (check it with `ip -br link`):

```bash
sudo python3 cups_detector.py \
  --iface br-e286751a311b \
  --trusted 172.18.0.1 \
  --timeout 30 \
  --csv detector_results/live_results.csv \
  --json detector_results/live_results.json
```

The live capture observes traffic visible on the selected interface. The total packet count can include unrelated bridge traffic, not only the test packets.

## 7. Detection rules

| Rule | Severity | Description |
|---|---|---|
| R1 – Untrusted source | HIGH | Flags UDP/631 traffic from a source not present in the trusted-source allowlist. |
| R2 – Malformed payload | HIGH | Flags payloads that fail the detector's basic legacy browse-format validation. |
| R3 – Repeated advertisements | MEDIUM | Flags repeated UDP/631 traffic from the same source when the configured threshold is reached. |
| R4 – TCP/631 review | INFO | Generates an informational review alert for TCP traffic to destination port 631. |
| R5 – Lab test marker | INFO | Recognises the configured harmless `LAB-TEST` marker in a UDP/631 payload. |

These are heuristic detection rules, not a complete implementation of the CUPS browsing or IPP specifications. R3 can flag repeated traffic from a trusted source. R4 is informational and does not independently indicate an attack. R5 is a laboratory marker rule, not a production security signature.

## 8. Experiments and recorded results

The current report uses the following test scenarios:

| Scenario | Capture / output | Recorded result |
|---|---|---|
| Normal mDNS discovery | `normal_discovery.pcap` / `task4_normal_discovery.csv` | 14 packets analysed; no alerts. |
| Normal TCP/631 traffic | `normal_tcp631.pcap` / `task4_normal_tcp631.csv` | 21 packets analysed; 12 INFO review alerts. |
| Trusted browse advertisements | `crafted_browse_tests.pcap` / `task4_authorised_browse.csv` | 3 packets; 1 MEDIUM R3 alert. |
| Untrusted malformed advertisements | `malformed_test.pcap` / `task4_untrusted_malformed.csv` | 3 packets; 6 HIGH alerts from R1/R2 and 1 MEDIUM R3 alert. |
| Untrusted valid-format advertisements | `untrusted_valid_browse.pcap` / `task4_untrusted_valid.csv` | 3 packets; 3 HIGH R1 alerts and 1 MEDIUM R3 alert. |
| R5 marker test | `r5_lab_marker.pcap` / `task4_r5_marker.csv` | 1 packet; 1 INFO R5 alert. |
| Post-mitigation replay | `post_mitigation_delivery.pcap` / `task5_post_mitigation.csv` | 3 packets captured; 1 MEDIUM R3 alert. |

Alert totals count rule activations, not unique packets. A packet can trigger more than one rule. R4 INFO notices are review signals and are not classified as malicious detections.

## 9. Mitigation experiment

The original active `cups-browsed` configuration included:

```text
BrowseRemoteProtocols dnssd cups
```

A backup was created, and the active directive was changed to:

```text
BrowseRemoteProtocols dnssd
```

This removed the legacy `cups` browse protocol while retaining DNS-SD. The container was restarted and the configuration was checked again.

The post-change socket inspection found no UDP socket bound to port 631 in `/proc/net/udp`, while `/proc/net/tcp` still showed TCP port 631 in the LISTEN state. A post-mitigation replay was captured on the Docker bridge. The packets remained visible at the bridge, which is distinct from whether the CUPS application accepted or processed them.

The recorded checks do not constitute a complete end-to-end IPP printing test after mitigation. Do not claim that printing functionality was verified after the change.

## 10. Known limitations

- The project uses a controlled lab and a small number of packets; results should not be generalised to production networks.
- The crafted advertisements were transmitted and observed, but successful queue creation was not achieved.
- The detector uses simplified payload validation rather than a complete CUPS browse protocol parser.
- R3 can flag legitimate repeated advertisements from trusted sources.
- R4 is informational and should not be treated as a malicious-activity verdict.
- The live capture packet count can include unrelated traffic on the selected interface.
- The mitigation evidence supports the configuration change and the observed absence of a UDP/631 socket; it does not prove that packets cannot reach the Docker bridge or that post-mitigation printing works.
- No remote code execution was attempted.

## 11. Security recommendations

- Disable legacy CUPS browsing when it is not required.
- Restrict access to printer services using host and network firewall rules.
- Limit printer discovery to trusted network segments.
- Keep CUPS and related components updated.
- Monitor unexpected printer-discovery traffic.
- Segment printer services from untrusted networks.

## 12. Suggested submission contents

Include only the current implementation and the files needed to reproduce the experiments:

```text
cups-security-lab-submission/
├── cups_attack.py
├── cups_detector.py
├── README.md
├── requirements.txt
├── pcap_files/
│   ├── crafted_browse_tests.pcap
│   ├── malformed_test.pcap
│   ├── untrusted_valid_browse.pcap
│   └── r5_lab_marker.pcap
├── detector_results/
│   ├── task3_crafted_results.csv
│   ├── task4_normal_discovery.csv
│   ├── task4_normal_tcp631.csv
│   ├── task4_authorised_browse.csv
│   ├── task4_untrusted_malformed.csv
│   ├── task4_untrusted_valid.csv
│   ├── task4_r5_marker.csv
│   └── task5_post_mitigation.csv
└── evidence/
    ├── task1_environment/
    ├── task2_attack/
    ├── task3_detection/
    ├── task4_experiments/
    └── task5_mitigation/
```

Do not include the Python virtual environment (`venv/`), `__pycache__/`, Docker image layers, credentials, private keys, or unrelated temporary files. Confirm the assignment instructions before deciding whether to submit PCAPs and screenshots separately or inside the archive.

## Author

Maliha Tasnim Aurini

## Disclaimer

This project is for academic research and authorised security testing only. Run experiments exclusively against systems you own or have explicit permission to test.
