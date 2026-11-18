#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, wrpcap

packets = []

for i in range(3):
    payload = f"UNRECOGNISED-PRINTER-TEST-{i+1}".encode()

    packet = (
        IP(src="192.0.2.50", dst="172.18.0.2")
        / UDP(sport=41000 + i, dport=631)
        / Raw(load=payload)
    )

    packets.append(packet)

wrpcap("pcap_files/malformed_test.pcap", packets)

print("[+] Created three controlled malformed test packets")
print("[+] Destination: 172.18.0.2:631")
print("[+] Saved to pcap_files/malformed_test.pcap")
