#!/usr/bin/env python3
"""
cups_detector.py - CUPS printer-discovery traffic detector (DAT505)
Offline PCAP analysis or live capture of suspicious UDP/631 (cups-browsed) activity.

Rules:
  R1 HIGH   UDP/631 from a source not in the trusted allowlist
  R2 HIGH   UDP/631 payload that is not a valid legacy CUPS browse packet (malformed)
  R3 MEDIUM Repeated UDP/631 from the same source (>= repeat-threshold)
  R4 INFO   TCP/631 traffic (flagged for review)
  R5 INFO   Recognised lab connectivity-test payload

Isolated-lab use only.
"""
import argparse, csv, json
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap, sniff, IP, IPv6, TCP, UDP, Raw

CUPS_PORT = 631
LAB_TEST_MARKER = b"LAB-TEST"   # <-- change to match your harmless test payload, or remove R5


def is_valid_browse(payload: bytes) -> bool:
    """Legacy CUPS browse packet = '<type-hex> <state-hex> <uri> ...'"""
    try:
        text = payload.decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    parts = text.split(None, 2)
    if len(parts) < 3:
        return False
    ptype, pstate, rest = parts
    try:
        int(ptype, 16); int(pstate, 16)
    except ValueError:
        return False
    return rest.startswith(("ipp://", "ipps://", "http://", "https://"))


class Detector:
    def __init__(self, trusted, port=CUPS_PORT, repeat_threshold=3):
        self.trusted = set(trusted)
        self.port = port
        self.repeat_threshold = repeat_threshold
        self.udp_counts = defaultdict(int)
        self.alerts = []
        self.total = 0

    def _add(self, severity, rule, detail, src, dst, sport, dport, proto):
        self.alerts.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "severity": severity, "rule": rule, "proto": proto,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "detail": detail,
        })

    def inspect(self, pkt):
        self.total += 1
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        if UDP in pkt and pkt[UDP].dport == self.port:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""

            if LAB_TEST_MARKER in payload:
                self._add("INFO", "R5-lab-test",
                          "Recognised lab connectivity-test payload",
                          src, dst, sport, dport, "UDP")
                return

            if src not in self.trusted:
                self._add("HIGH", "R1-untrusted-source",
                          f"UDP/{self.port} from untrusted source {src}",
                          src, dst, sport, dport, "UDP")

            if not is_valid_browse(payload):
                self._add("HIGH", "R2-malformed",
                          "Payload is not a valid legacy CUPS browse packet",
                          src, dst, sport, dport, "UDP")

            self.udp_counts[src] += 1
            if self.udp_counts[src] == self.repeat_threshold:
                self._add("MEDIUM", "R3-repeated",
                          f"Repeated UDP/{self.port} from {src} (>= {self.repeat_threshold})",
                          src, dst, sport, dport, "UDP")

        elif TCP in pkt and pkt[TCP].dport == self.port:
            self._add("INFO", "R4-tcp-review",
                      f"TCP/{self.port} connection (review)",
                      src, dst, pkt[TCP].sport, pkt[TCP].dport, "TCP")

    def run_pcap(self, path):
        for pkt in rdpcap(path):
            self.inspect(pkt)

    def run_live(self, iface, count=0, timeout=None):
        sniff(iface=iface, prn=self.inspect, store=False, count=count, timeout=timeout)

    def export_csv(self, path):
        fields = ["timestamp","severity","rule","proto","src","dst","sport","dport","detail"]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader(); w.writerows(self.alerts)

    def export_json(self, path):
        with open(path, "w") as f:
            json.dump({"total_packets": self.total,
                       "alert_count": len(self.alerts),
                       "alerts": self.alerts}, f, indent=2)

    def summary(self):
        by_sev = defaultdict(int)
        for a in self.alerts:
            by_sev[a["severity"]] += 1
        print(f"[+] Packets analysed : {self.total}")
        print(f"[+] Alerts generated : {len(self.alerts)}")
        for sev in ("HIGH", "MEDIUM", "INFO"):
            if by_sev[sev]:
                print(f"      {sev:<7}: {by_sev[sev]}")


def main():
    ap = argparse.ArgumentParser(description="CUPS printer-discovery traffic detector")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap", help="offline PCAP file to analyse")
    g.add_argument("--iface", help="interface for live capture (e.g. eth0)")
    ap.add_argument("--trusted", default="172.18.0.1",
                    help="comma-separated trusted source IPs (default: virtual printer)")
    ap.add_argument("--port", type=int, default=CUPS_PORT)
    ap.add_argument("--repeat-threshold", type=int, default=3)
    ap.add_argument("--count", type=int, default=0, help="live: stop after N packets")
    ap.add_argument("--timeout", type=int, default=None, help="live: stop after N seconds")
    ap.add_argument("--csv", help="write alerts to CSV")
    ap.add_argument("--json", help="write alerts to JSON")
    args = ap.parse_args()

    trusted = [x.strip() for x in args.trusted.split(",") if x.strip()]
    det = Detector(trusted, port=args.port, repeat_threshold=args.repeat_threshold)

    if args.pcap:
        print(f"[+] Offline analysis: {args.pcap}")
        det.run_pcap(args.pcap)
    else:
        print(f"[+] Live capture on {args.iface} (Ctrl+C to stop)")
        det.run_live(args.iface, count=args.count, timeout=args.timeout)

    det.summary()
    if args.csv:
        det.export_csv(args.csv);  print(f"[+] CSV  written: {args.csv}")
    if args.json:
        det.export_json(args.json); print(f"[+] JSON written: {args.json}")


if __name__ == "__main__":
    main()
