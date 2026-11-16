#!/usr/bin/env python3
"""
make_test_traffic.py - build a synthetic PCAP to evaluate cups_detector.py OFFLINE.
Nothing is transmitted; packets are written to a file for analysis only (detector QA).
"""
import argparse
from scapy.all import IP, UDP, TCP, Raw, wrpcap

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="captures/synthetic_eval.pcap")
    ap.add_argument("--victim", default="172.19.0.2")
    ap.add_argument("--trusted", default="172.19.0.3")
    ap.add_argument("--untrusted", default="192.0.2.50")
    args = ap.parse_args()

    good = f'0 3 ipp://{args.trusted}:8631/printers/lab "Lab" "Lab Printer" "Generic"'.encode()
    pkts = []

    # 1. benign, trusted source, valid format  -> should NOT alert (false-positive check)
    pkts.append(IP(src=args.trusted,  dst=args.victim)/UDP(sport=40000, dport=631)/Raw(load=good))
    # 2. untrusted source, valid format        -> R1
    pkts.append(IP(src=args.untrusted,dst=args.victim)/UDP(sport=40001, dport=631)/Raw(load=good))
    # 3. malformed text payload                -> R2
    pkts.append(IP(src=args.untrusted,dst=args.victim)/UDP(sport=40002, dport=631)/Raw(load=b"not a browse packet"))
    # 4. malformed binary payload              -> R2
    pkts.append(IP(src=args.untrusted,dst=args.victim)/UDP(sport=40003, dport=631)/Raw(load=b"\xff\xff\x00\x01bad"))
    # 5-7. repeated from same untrusted source -> R3
    for i in range(3):
        pkts.append(IP(src=args.untrusted,dst=args.victim)/UDP(sport=41000+i, dport=631)/Raw(load=good))
    # 8. TCP/631                               -> R4
    pkts.append(IP(src=args.untrusted,dst=args.victim)/TCP(sport=50000, dport=631, flags="S"))

    wrpcap(args.out, pkts)
    print(f"[+] Wrote {len(pkts)} synthetic packets to {args.out} (not transmitted)")

if __name__ == "__main__":
    main()
