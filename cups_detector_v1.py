#!/usr/bin/env python3
"""
CUPS Printer Discovery Detector
Offline PCAP analysis using Scapy.
"""

from scapy.all import rdpcap, IP, UDP, Raw
import argparse
import csv
import json
import os
from datetime import datetime


def analyse_packet(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return None

    udp = packet[UDP]

    if udp.dport != 631:
        return None

    source = packet[IP].src
    destination = packet[IP].dst
    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

    alert = "UDP traffic to CUPS port 631"
    severity = "INFO"

    if not payload:
        alert = "Empty UDP packet to CUPS port 631"
        severity = "MEDIUM"

    elif payload == b"CUPS-LAB-UDP-CONNECTIVITY-TEST":
        alert = "Known laboratory connectivity test"
        severity = "INFO"

    elif len(payload) < 10:
        alert = "Short or potentially malformed discovery packet"
        severity = "MEDIUM"

    elif b"ipp://" in payload.lower():
        alert = "Possible printer discovery advertisement"
        severity = "REVIEW"

    else:
        alert = "Unrecognised UDP payload on port 631"
        severity = "REVIEW"

    return {
        "timestamp": datetime.fromtimestamp(
            float(packet.time)
        ).isoformat(timespec="seconds"),
        "source_ip": source,
        "destination_ip": destination,
        "source_port": udp.sport,
        "destination_port": udp.dport,
        "payload_length": len(payload),
        "severity": severity,
        "alert": alert,
        "payload": payload[:200].decode("utf-8", errors="replace")
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline CUPS printer discovery detector"
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Input PCAP file"
    )

    parser.add_argument(
        "--output",
        default="detector_results",
        help="Output directory"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[-] PCAP file not found: {args.pcap}")
        return

    os.makedirs(args.output, exist_ok=True)

    packets = rdpcap(args.pcap)
    alerts = []

    print(f"[+] Analysing {len(packets)} packets...")

    for packet in packets:
        result = analyse_packet(packet)

        if result:
            alerts.append(result)

    json_file = os.path.join(args.output, "alerts.json")
    csv_file = os.path.join(args.output, "alerts.csv")

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        if alerts:
            writer = csv.DictWriter(
                file,
                fieldnames=alerts[0].keys()
            )
            writer.writeheader()
            writer.writerows(alerts)

    print(f"\n[+] Analysis complete")
    print(f"[+] Packets analysed: {len(packets)}")
    print(f"[+] Port 631 alerts: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['source_ip']} -> "
            f"{alert['destination_ip']}:631 "
            f"| {alert['alert']}"
        )

    print(f"\n[+] JSON report: {json_file}")
    print(f"[+] CSV report:  {csv_file}")


if __name__ == "__main__":
    main()
