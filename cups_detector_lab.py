#!/usr/bin/env python3
"""Heuristic educational CUPS traffic triage; not a full protocol parser."""
import argparse, csv, json
from collections import Counter
from pathlib import Path
from scapy.all import IP, UDP, TCP, Raw, rdpcap, sniff

def analyse(packets, trusted):
    alerts, counts = [], Counter()
    for n, pkt in enumerate(packets, 1):
        if IP not in pkt: continue
        src, dst = pkt[IP].src, pkt[IP].dst
        if UDP in pkt and pkt[UDP].dport == 631:
            counts[src] += 1
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            text = payload.decode("utf-8", errors="replace")
            reasons = []
            if not payload: reasons.append("empty UDP/631 payload")
            elif len(payload) < 8: reasons.append("very short UDP/631 payload")
            if not (text.startswith("00 03 ") or text.startswith("0 3 ")):
                reasons.append("unexpected legacy-browse prefix")
            if not any(s in text for s in ("ipp://", "ipps://", "http://", "https://")):
                reasons.append("no printer URI found")
            if src not in trusted: reasons.append("source not in trusted-source allowlist")
            if reasons:
                alerts.append(dict(packet=n, severity="HIGH" if src not in trusted else "MEDIUM",
                    src=src, dst=dst, protocol="UDP", dport=631,
                    description="; ".join(reasons), payload=text[:300]))
        elif TCP in pkt and pkt[TCP].dport == 631:
            alerts.append(dict(packet=n, severity="REVIEW", src=src, dst=dst,
                protocol="TCP", dport=631,
                description="TCP/631 connection; inspect whether expected IPP traffic", payload=""))
    for src, count in counts.items():
        if count >= 3:
            alerts.append(dict(packet="", severity="MEDIUM", src=src, dst="",
                protocol="UDP", dport=631,
                description=f"repeated UDP/631 traffic: {count} packets", payload=""))
    return alerts

def main():
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap"); g.add_argument("--live", action="store_true")
    p.add_argument("--interface"); p.add_argument("--duration", type=int, default=30)
    p.add_argument("--trusted", action="append", default=[])
    p.add_argument("--out", default="detector_results")
    a=p.parse_args()
    packets=rdpcap(a.pcap) if a.pcap else sniff(iface=a.interface, timeout=a.duration,
                                                filter="udp port 631 or tcp port 631")
    alerts=analyse(packets, set(a.trusted))
    out=Path(a.out); out.mkdir(parents=True, exist_ok=True)
    fields=["packet","severity","src","dst","protocol","dport","description","payload"]
    with (out/"alerts.csv").open("w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(alerts)
    (out/"alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"Packets analysed: {len(packets)}; alerts: {len(alerts)}")
    for x in alerts: print(f"[{x['severity']}] {x['src']} -> {x['dst']}: {x['description']}")
    print(f"Saved {out}/alerts.csv and {out}/alerts.json")
    print("NOTE: heuristic triage only; no complete CUPS/IPP protocol validation.")

if __name__ == "__main__": main()
