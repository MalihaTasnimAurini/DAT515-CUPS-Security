#!/usr/bin/env python3
"""
CUPS Printer Discovery Detector
Offline PCAP analysis using Scapy.
"""

from scapy.all import rdpcap, IP, UDP, TCP, Raw
import argparse
import csv
import json
import os
from datetime import datetime
from collections import Counter


def analyse_packets(packets, trusted_sources):
    alerts = []
    source_counts = Counter()

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(UDP) and packet[UDP].dport == 631:
            udp = packet[UDP]
            payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

            source_counts[src] += 1

            severity = "INFO"
            message = "UDP traffic to CUPS port 631"

            if payload == b"CUPS-LAB-UDP-CONNECTIVITY-TEST":
                message = "Known laboratory connectivity test"

            elif not payload:
                severity = "MEDIUM"
                message = "Empty UDP packet to CUPS port 631"

            elif b"ipp://" in payload.lower():
                severity = "REVIEW"
                message = "Possible printer advertisement"

            elif len(payload) < 10:
                severity = "MEDIUM"
                message = "Short or malformed UDP payload"

            else:
                severity = "REVIEW"
                message = "Unrecognised UDP payload on port 631"

            if trusted_sources and src not in trusted_sources:
                severity = "HIGH"
                message = "UDP discovery traffic from untrusted source"

            alerts.append({
                "timestamp": datetime.fromtimestamp(
                    float(packet.time)
                ).isoformat(timespec="seconds"),
                "source_ip": src,
                "destination_ip": dst,
                "source_port": udp.sport,
                "destination_port": udp.dport,
                "protocol": "UDP",
                "payload_length": len(payload),
                "severity": severity,
                "alert": message,
                "payload": payload[:200].decode(
                    "utf-8", errors="replace"
                )
            })

        elif packet.haslayer(TCP) and packet[TCP].dport == 631:
            tcp = packet[TCP]

            alerts.append({
                "timestamp": datetime.fromtimestamp(
                    float(packet.time)
                ).isoformat(timespec="seconds"),
                "source_ip": src,
                "destination_ip": dst,
                "source_port": tcp.sport,
                "destination_port": tcp.dport,
                "protocol": "TCP",
                "payload_length": len(
                    bytes(packet[Raw].load)
                ) if packet.haslayer(Raw) else 0,
                "severity": "REVIEW",
                "alert": "TCP connection to CUPS IPP port 631",
                "payload": ""
            })

    # Report repeated UDP discovery traffic.
    for source, count in source_counts.items():
        if count >= 3:
            alerts.append({
                "timestamp": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "source_ip": source,
                "destination_ip": "multiple",
                "source_port": "",
                "destination_port": 631,
                "protocol": "UDP",
                "payload_length": "",
                "severity": "MEDIUM",
                "alert": f"Repeated UDP port 631 traffic: {count} packets",
                "payload": ""
            })

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="CUPS printer discovery detector"
    )

    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", default="detector_results")
    parser.add_argument(
        "--trusted",
        default="",
        help="Comma-separated trusted source IP addresses"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[-] PCAP file not found: {args.pcap}")
        return

    trusted_sources = {
        ip.strip()
        for ip in args.trusted.split(",")
        if ip.strip()
    }

    packets = rdpcap(args.pcap)

    print(f"[+] Analysing {len(packets)} packets...")

    alerts = analyse_packets(packets, trusted_sources)

    os.makedirs(args.output, exist_ok=True)

    json_path = os.path.join(args.output, "alerts.json")
    csv_path = os.path.join(args.output, "alerts.csv")

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        fields = [
            "timestamp", "source_ip", "destination_ip",
            "source_port", "destination_port", "protocol",
            "payload_length", "severity", "alert", "payload"
        ]

        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    print("\n[+] Analysis complete")
    print(f"[+] Packets analysed: {len(packets)}")
    print(f"[+] Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['source_ip']} -> "
            f"{alert['destination_ip']}:{alert['destination_port']} "
            f"| {alert['alert']}"
        )

    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] CSV report: {csv_path}")


if __name__ == "__main__":
    main()
