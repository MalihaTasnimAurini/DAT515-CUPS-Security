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
| `generate_test_pcap.py` | Generates `pcap_files/malformed_test.pcap` (three malformed advertisements from an untrusted source) for offline detector testing. Writes a PCAP only; it does not transmit packets. |
| `requirements.txt` | Python dependencies. |
| `pcap_files/` | Selected input and experiment packet captures. |
| `detector_results/` | Selected detector outputs in CSV and JSON formats. |
| `evidence/` | Screenshots (numbered in experiment order), browse-processing logs and supplementary alert outputs. |
| `archive/` | Earlier, partially completed implementation kept for reference. Not part of the final implementation (see Section 13). |

An earlier, partially completed implementation (`cups_attack_lab.py`, `cups_detector_lab.py`, `cups_detector_v1.py`) and its outputs are kept in `archive/` for reference only (see Section 13). The experiments documented in the current report use **`cups_attack.py` and `cups_detector.py`**.

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

The sender constructs three controlled UDP/631 browse-style test advertisements. The recorded test cases vary printer/queue information and the advertised URI. The tool writes a PCAP file and logs its activity to `cups_attack.log` in the current working directory.

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

The recorded bridge capture confirmed that three UDP datagrams were delivered to `172.18.0.2:631`. The victim log (`evidence/08_live_variation_processing.log`) shows that `cups-browsed` accepted the unauthenticated advertisement and initiated its own connection to the advertised printer:

- it reported `Found CUPS queue/class: LabPrinter on host 172.18.0.1`;
- the advertisement passed the `BrowseFilter` checks;
- it sent an IPP Get-Printer-Attributes request to `ipp://172.18.0.1:8631/printers/LabPrinter`.

This victim-initiated connection to an attacker-chosen endpoint is the network-facing weakness described by CVE-2024-47176. The local print queue was **not** created: the advertised `/printers/<queue>` path did not match the virtual IPP service endpoint `/ipp/print`, so the request returned "not found" and the log records `Unable to create print queue`. The demonstrated result is therefore victim-initiated communication, not successful printer installation or code execution.

A separate manual control test advertised the `/ipp/print` path directly. `cups-browsed` rejected it (`Don't understand URI`, see `evidence/07_browse_processing.log`), confirming that the accepted browse form is `/printers/<name>`. This control test was not produced by `cups_attack.py`.

**Note on addresses:** `--source` sets only the IP source address. The printer URI inside each advertisement is fixed in the script as `ipp://172.18.0.1:8631/printers/...`. If the Docker gateway address changes, edit the `tests` list in `cups_attack.py` so that the URI points to the current virtual printer.

## 6. Detector: `cups_detector.py`

The detector can analyse a saved PCAP or capture live traffic. It supports a trusted-source allowlist and exports alerts to CSV and JSON.

Show command-line options:

```bash
python3 cups_detector.py --help
```

### 6.1 Test captures

| Capture | Contents | How it was created |
|---|---|---|
| `crafted_browse_tests.pcap` | 3 valid-format advertisements from the trusted source `172.18.0.1`, source ports 40000–40002 | `cups_attack.py` |
| `malformed_test.pcap` | 3 non-browse payloads (`UNRECOGNISED-PRINTER-TEST-1..3`) from untrusted `192.0.2.50`, source ports 41000–41002 | `generate_test_pcap.py` |
| `untrusted_valid_browse.pcap` | 3 valid-format advertisements from untrusted `192.0.2.50`, source ports 42000–42002 | Created separately with Scapy during the lab session (no generator script is included) |
| `r5_lab_marker.pcap` | 1 packet containing the `LAB-TEST` marker from `192.0.2.60`, source port 43000 | Created separately with Scapy during the lab session (no generator script is included) |
| `normal_discovery.pcap`, `normal_tcp631.pcap` | Captured normal mDNS and TCP/631 traffic | Captured with `tcpdump` |
| `post_mitigation_delivery.pcap` | Replay of the 3 crafted advertisements after mitigation | Captured on the Docker bridge |

The R5 marker packet comes from an untrusted address but produces only the R5 notice, because R5 is evaluated first and stops further UDP rule checks for that packet.

### 6.2 Offline PCAP analysis

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

### 6.3 Live capture

Use the current Docker bridge interface (check it with `ip -br link`):

```bash
sudo python3 cups_detector.py \
  --iface br-e286751a311b \
  --trusted 172.18.0.1 \
  --timeout 30 \
  --csv detector_results/live_results.csv \
  --json detector_results/live_results.json
```

The example writes new files; the recorded live run (87 packets analysed, one R3 MEDIUM alert) is saved as `detector_results/task3_live_results.csv` and `.json`.

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
| Live bridge capture | live capture on `br-e286751a311b` / `task3_live_results.csv` | 87 packets analysed; 1 MEDIUM R3 alert. |
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
- The victim initiated an IPP connection to the advertised printer, but no print queue was created because the advertised path did not match the virtual printer's `/ipp/print` endpoint.
- The advertisements varied only the queue name in the URI path; the advertised printer address and port were not varied.
- The detector does not monitor the virtual printer's TCP/8631 endpoint, so the victim-initiated IPP connection itself is not detected.
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

## 12. Repository structure

```text
DAT515-CUPS-Security/
├── README.md                  # This file
├── requirements.txt           # Python dependencies
├── cups_attack.py             # Final packet-generation tool
├── cups_detector.py           # Final detector (offline PCAP and live capture)
├── generate_test_pcap.py      # Generates malformed_test.pcap for offline testing
├── pcap_files/                # Input and experiment packet captures
│   ├── normal_discovery.pcap
│   ├── normal_tcp631.pcap
│   ├── crafted_browse_tests.pcap
│   ├── malformed_test.pcap
│   ├── untrusted_valid_browse.pcap
│   ├── r5_lab_marker.pcap
│   ├── post_mitigation_delivery.pcap
│   └── ...                    # Baseline and supporting captures
├── detector_results/          # Detector outputs (CSV and JSON) for Tasks 3–5
│   ├── task3_*_results.csv/.json
│   ├── task4_*.csv/.json
│   └── task5_post_mitigation.csv/.json
├── evidence/
│   ├── 07_browse_processing.log          # Victim log: /ipp/print control test
│   ├── 08_live_variation_processing.log  # Victim log: accepted advertisement and IPP request
│   ├── screenshots/           # Numbered experiment screenshots
│   │   └── Report_screenshots/  # Figures used in the report
│   └── *_alerts.csv/.json     # Supplementary detector outputs
├── report/                    # Final assignment report
└── archive/                   # Earlier, partially completed implementation (see Section 13)
```

The experiment scenarios in Section 8 use the captures listed under `pcap_files/` and the matching files in `detector_results/`.

## 13. Archive: earlier implementation

The `archive/` folder contains an earlier version of this project. It was a partial implementation, put together to meet the original assignment deadline. After that deadline, the project was restructured and the attack tool and detector were reimplemented as `cups_attack.py` and `cups_detector.py`. Compared with the earlier scripts, the new implementation adds source-address and dry-run options to the attack tool, a numbered R1–R5 rule set with a configurable repeat threshold in the detector, and one consistent CSV/JSON output format. All experiments documented in this README were run with the new implementation.

The archived files are kept for transparency, so that the development history of the project remains visible. They are not used in the final experiments, and their outputs use an older format that does not match the current detector.

| Archived item | What it was |
|---|---|
| `archive/scripts/cups_attack_lab.py` | Earlier packet-generation script |
| `archive/scripts/cups_detector_lab.py`, `cups_detector_v1.py` | Earlier detector versions |
| `archive/scripts/make_test_traffic.py` | Earlier synthetic test-traffic generator (older 172.19.0.x addresses) |
| `archive/scripts/README_QUICKSTART.md` | Quick-start guide for the earlier scripts |
| `archive/detector_results/`, `archive/evidence/detector-results/` | Outputs from the earlier detectors (older CSV/JSON format) |
| `archive/captures/`, `archive/evidence/pcaps/` | Duplicate copies of captures that are also in `pcap_files/` |
| `archive/logs/` | Log written by the earlier packet-generation script |

The earlier scripts use different command-line options and addresses from those in this README. To reproduce the results, use the current files described in Sections 5 and 6.

## Author

Maliha Tasnim Aurini

## Disclaimer

This project is for academic research and authorised security testing only. Run experiments exclusively against systems you own or have explicit permission to test.
