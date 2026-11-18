# CUPS lab quick-start add-on

For an isolated, authorised lab only. These scripts send benign printer-discovery metadata and perform heuristic PCAP analysis. They do not send print jobs, malicious PPD content, shell commands, or attempt remote code execution.

## Before running
1. Confirm the CUPS and virtual IPP printer containers are running.
2. Confirm Kali can reach the Docker host UDP port 631.
3. Confirm the printer container is reachable from CUPS. Use its current container IP and port.
4. Your mitigation changed `BrowseRemoteProtocols` to `dnssd`. To test legacy browsing, temporarily restore the baseline `dnssd cups` setting only in the disposable lab, restart CUPS, then reapply the mitigation after baseline testing.
5. Never target public, university, or third-party systems.

## Install
```bash
python3 -m pip install -r requirements.txt
```

## Send three benign metadata variations
Replace the addresses with the current addresses in your lab:
```bash
sudo python3 cups_attack_lab.py --target 10.0.2.2 --printer-uri ipp://172.19.0.3:8631/ipp/print --count 3
```
Outputs: `pcap_files/crafted_browse_tests.pcap` and `logs/cups_attack.log`.

## Verify victim-initiated communication
While sending, capture traffic at the virtual printer/container. Look for a connection from the CUPS container to the printer on TCP/8631. Sending UDP alone does not prove successful discovery. If no connection appears, report the result as unsuccessful or inconclusive.

## Analyse a PCAP
```bash
python3 cups_detector_lab.py --pcap pcap_files/crafted_browse_tests.pcap
python3 cups_detector_lab.py --pcap pcap_files/crafted_browse_tests.pcap --trusted 172.19.0.1
```

## Limitations
The sender uses the basic legacy browse datagram field layout and varies location/information metadata. The detector is heuristic and does not fully validate CUPS browse or IPP messages. Its output is not a measured accuracy score.
