# CUPS Printer Discovery: Traffic Analysis and Attack Detection

A laboratory project investigating CUPS printer-discovery traffic, Scapy-based packet
generation, and suspicious-traffic detection, carried out against an isolated vulnerable
CUPS (`cups-browsed`) environment. Developed for the DAT505 individual assignment,
University of Stavanger.

## Primary tools

| Script | Purpose |
|---|---|
| `cups_attack_lab.py` | Scapy attack tool — constructs and transmits a crafted printer advertisement with an attacker-controlled IPP URI; CLI args, logging, PCAP export. |
| `cups_detector_lab.py` | Scapy detector — protocol-aware triage (trusted-source allowlist, legacy-browse prefix / printer-URI validation, repeated-traffic), CSV/JSON output, offline PCAP or live capture. |

Earlier iterations (`cups_attack.py`, `cups_detector.py`, `cups_detector_v1.py`,
`generate_test_pcap.py`, `make_test_traffic.py`) are retained in the repository as
development history. The `_lab` scripts above are the final versions used in the report.

## Laboratory environment

| Component | Configuration |
|---|---|
| Attacker | Kali Linux (VirtualBox), Python 3, Scapy 2.8 |
| Target | Vulhub `cups-browsed:2.0.1` Docker container (CVE-2024-47177 lab dir) |
| Printer service | Virtual IPP printer (`ippeveprinter`) in a separate container |
| Packet analysis | Scapy, tcpdump, Wireshark |
| Target service port | UDP/TCP 631 |

All experiments are conducted in an isolated, authorised laboratory environment only.

## Requirements

```bash
python3 -m pip install -r requirements.txt   # scapy
```

- Python 3, Scapy 2.5+ (tested on 2.8)
- Kali Linux or another authorised Linux testing environment
- Docker for the isolated CUPS laboratory
- Wireshark or tcpdump for packet inspection

## Detection rules (`cups_detector_lab.py`)

- **Trusted-source allowlist** — UDP/631 from a source not on the allowlist is flagged (HIGH).
- **Recognised connectivity-test payload** — a known lab test payload is classified INFO.
- **Malformed / unexpected fields** — a payload that is empty, lacks a valid legacy-browse
  prefix, or has no printer URI is flagged as unexpected/malformed.
- **Possible printer advertisement** — a payload containing an IPP URI is flagged for review.
- **Repeated traffic** — repeated UDP/631 packets from the same source (MEDIUM).
- TCP connections to the CUPS port are also flagged for review.

The rules provide heuristic triage rather than a complete CUPS/IPP protocol parser.

## Running the tools

### Crafted printer advertisement (attack tool)

```bash
sudo python3 cups_attack_lab.py \
  --target 10.0.2.2 \
  --printer-uri ipp://172.19.0.3:8631/ipp/print \
  --count 3
```

Transmits a crafted advertisement, saves `pcap_files/crafted_browse_tests.pcap`, and logs
to `logs/cups_attack.log`. UDP transmission alone does not prove the service accepted the
advertisement; verify a victim-initiated TCP connection to the advertised printer.

### Offline detection

```bash
python3 cups_detector_lab.py --pcap captures/unauthorised_test.pcap --out detector_results/final_test
```

### Live detection

```bash
sudo python3 cups_detector_lab.py --iface eth0
```

## Experiments and results

1. Baseline TCP connectivity between the CUPS service and the virtual IPP printer.
2. Scapy-generated UDP traffic targeting port 631, with target-side capture verifying delivery.
3. Inspection of the `cups-browsed` service, configuration, and version.
4. Crafted printer advertisement transmitted to the service (acceptance not confirmed).
5. Offline detection of unauthorised traffic — three crafted packets from an untrusted source
   produced **four alerts** (three HIGH: untrusted source + unexpected prefix / no URI; one
   MEDIUM: repeated traffic). Results exported to CSV and JSON.
6. Mitigation: removing the legacy `cups` protocol from `BrowseRemoteProtocols`, compared
   before and after.

## Experimental limitations

- A crafted advertisement was transmitted, but acceptance by `cups-browsed` and a resulting
  victim-initiated callback to the advertised printer were **not** observed.
- The unauthorised traffic was analysed offline; it was not confirmed accepted by the service.
- Detection rules are heuristic and do not fully parse the CUPS browsing protocol.
- The mitigation did not close UDP/631 or block network-level delivery; it removed the legacy
  browsing protocol from the configuration.
- No remote code execution was attempted (CVE-2024-47177 / FoomaticRIPCommandLine).

## Security recommendations

- Disable legacy CUPS browsing when it is not required.
- Restrict access to UDP and TCP port 631 using firewall rules.
- Allow discovery only from trusted network segments (`BrowseAllow` / `BrowseDeny`).
- Keep CUPS and `cups-browsed` updated (OpenPrinting 2.1.0 removes legacy CUPS browsing).
- Monitor for unexpected printer-discovery traffic.
- Segment printer services from untrusted networks.

## Author

Maliha Tasnim Aurini

## Disclaimer

This project is for academic research and authorised security testing only. Run experiments
exclusively against systems you own or have explicit permission to test.
