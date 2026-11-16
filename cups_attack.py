
#!/usr/bin/env python3

"""
CUPS Security Lab
Controlled UDP packet sender using Scapy.
"""

from scapy.all import IP, UDP, Raw, send, wrpcap
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(
        description="CUPS isolated lab packet sender"
    )

    parser.add_argument(
        "--target",
        default="10.0.2.2",
        help="Lab CUPS gateway IP"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=631,
        help="Target UDP port"
    )

    parser.add_argument(
        "--pcap",
        default="captures/udp_test.pcap",
        help="PCAP output path"
    )

    args = parser.parse_args()

    # Harmless test datagram, not a printer advertisement
    payload = b"CUPS-LAB-UDP-CONNECTIVITY-TEST"

    packet = (
        IP(dst=args.target) /
        UDP(dport=args.port) /
        Raw(load=payload)
    )

    print(f"[+] Target: {args.target}:{args.port}/UDP")
    print(f"[+] Time: {datetime.now()}")
    print("[+] Sending one harmless test datagram...")

    send(packet, count=1, verbose=False)

    import os
    os.makedirs("captures", exist_ok=True)
    wrpcap(args.pcap, packet)

    print(f"[+] Packet saved to {args.pcap}")
    print("[+] Test completed.")

if __name__ == "__main__":
    main()
