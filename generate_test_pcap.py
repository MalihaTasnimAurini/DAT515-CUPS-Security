#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, wrpcap

packets = []

for i in range(3):
    payload = f"UNRECOGNISED-PRINTER-TEST-{i+1}".encode()

    packet = (
        IP(src="192.0.2.50", dst="172.19.0.2") /
        UDP(sport=40000 + i, dport=631) /
        Raw(load=payload)
    )

    packets.append(packet)

wrpcap("captures/unauthorised_test.pcap", packets)

print("[+] Created three controlled test packets")
print("[+] Saved to captures/unauthorised_test.pcap")
