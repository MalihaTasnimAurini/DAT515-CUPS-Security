# CUPS Printer Discovery: Traffic Analysis and Attack Detection

A laboratory project exploring CUPS printer-discovery traffic, packet generation, and suspicious-traffic detection using Python and Scapy.

## Project objectives

- Inspect network traffic associated with CUPS printer discovery.
- Generate controlled UDP test traffic using Scapy.
- Analyse packet captures (PCAP files).
- Detect suspicious or unexpected traffic targeting UDP port 631.
- Evaluate basic detection rules using normal and synthetic test traffic.
- Examine the effect of restricting legacy CUPS browsing.

## Laboratory environment

| Component | Configuration |
|---|---|
| Attacker | Kali Linux |
| Target | Docker-based CUPS environment |
| Printer service | Virtual IPP printer |
| Packet analysis | Scapy, tcpdump, Wireshark |
| Programming language | Python |
| Target service port | UDP/TCP 631 |

All experiments are intended for an isolated, authorised laboratory environment.

## Project structure

```text
cups-security-lab/
├── cups_attack.py
├── cups_detector.py
├── cups_detector_v1.py
├── generate_test_pcap.py
├── requirements.txt
├── .gitignore
├── captures/
│   ├── udp_test.pcap
│   ├── kali_udp_test.pcap
│   └── unauthorised_test.pcap
├── detector_results/
│   ├── alerts.csv
│   └── alerts.json
├── evidence/
└── report.pdf
```

The `evidence/` directory and `report.pdf` should be added when the corresponding files are ready.

## Requirements

- Python 3
- Scapy 2.7 or later
- Kali Linux or another authorised Linux testing environment
- Docker for the isolated CUPS laboratory
- Wireshark or tcpdump for packet inspection

Install the Python dependency:

```bash
python3 -m pip install -r requirements.txt
```

## Running the tools

### Packet generation

```bash
sudo python3 cups_attack.py
```

The script generates controlled laboratory UDP test traffic and saves packet captures. Review the script's options and destination settings before execution.

### Offline traffic detection

Analyse a PCAP file:

```bash
python3 cups_detector.py --pcap captures/kali_udp_test.pcap
```

Specify a trusted source address:

```bash
python3 cups_detector.py \
  --pcap captures/kali_udp_test.pcap \
  --trusted 172.19.0.1
```

### Synthetic test traffic

Generate the offline synthetic test capture:

```bash
python3 generate_test_pcap.py
```

Analyse it:

```bash
python3 cups_detector.py \
  --pcap captures/unauthorised_test.pcap \
  --trusted 172.19.0.1
```

The detector writes CSV and JSON results under `detector_results/`.

## Experiments

The laboratory work includes:

1. Baseline TCP connectivity testing between the CUPS service and virtual IPP printer.
2. Scapy-generated UDP connectivity testing targeting port 631.
3. Verification of UDP packet delivery using a target-side packet capture.
4. Offline detection of synthetic unauthorised-source traffic.
5. Evaluation of repeated UDP traffic alerts.
6. Examination of CUPS browsing configuration and a mitigation test that removes the legacy `cups` browsing protocol from `BrowseRemoteProtocols`.

## Important experimental limitations

- The initial UDP connectivity payload is not a valid CUPS printer-browse advertisement.
- The synthetic unauthorised traffic is generated for offline detector testing; it was not transmitted as a real printer advertisement.
- Detection rules are heuristic and do not fully parse or validate the CUPS browsing protocol.
- The mitigation experiment does not establish that UDP port 631 was closed or that all unauthorised advertisements were blocked.
- Baseline TCP connectivity is not evidence of a complete IPP printing transaction.

These distinctions are important when interpreting the results.

## Security recommendations

- Disable legacy CUPS browsing when it is not required.
- Restrict access to UDP and TCP port 631 using firewall rules.
- Allow discovery only from trusted network segments.
- Maintain updated CUPS and cups-browsed versions.
- Monitor unexpected printer-discovery traffic.
- Segment printer services from untrusted networks.

## Author

Maliha Tasnim Aurini

## Disclaimer

This project is for academic research and authorised security testing only. Run experiments exclusively against systems you own or have explicit permission to test.
