# CUPS Security Experiment – Screenshot Evidence

## 1. Overview

This directory contains the visual evidence collected during the DAT515 assignment:

**CUPS Printer Discovery Exploitation and Attack Detection Using Scapy**

The screenshots document the laboratory environment, network configuration, attack simulations, detection experiments, victim-side observations, and mitigation evaluation.

Evidence was captured across multiple laboratory sessions. Some screenshots were regenerated after restarting the system or recreating Docker containers. Consequently, certain screenshots may show different container or bridge IP addresses. These differences reflect changes in the laboratory environment between sessions.

## 2. Screenshot Categories

The screenshots cover the following stages of the project:

| Category | Description |
|---|---|
| Laboratory Setup | Kali Linux, Docker containers, Compose configuration and CUPS services |
| Network Configuration | Container connectivity, port mappings and UDP/TCP port inspection |
| Baseline Traffic | Normal printer-discovery traffic, PCAP captures and Wireshark analysis |
| Attack Development | Scapy attack script, crafted packets and packet variations |
| Victim-Side Observations | CUPS logs, received browse packets and IPP communication |
| Detection Implementation | Detector source code, execution and output files |
| Detection Experiments | Normal traffic, unauthorised advertisements, malformed packets and security alerts |
| Mitigation | CUPS configuration changes, socket inspection and before/after comparison |
| Post-Mitigation Testing | Packet delivery and detector results after mitigation |

## 3. Report Screenshots

The `report_screenshots/` subdirectory contains the original screenshots selected for inclusion in the final assignment report.

These screenshots provide direct visual support for the figures, experimental observations, implementation details and mitigation results discussed in the report.

The main `evidence/screenshots/` directory contains the broader screenshot collection, while `report_screenshots/` provides a focused collection of the images used in the written report.

## 4. Evidence Interpretation

- Screenshots should be interpreted in the context of the corresponding experiment.
- Docker container and bridge IP addresses may differ between sessions because the environment was restarted or recreated.
- Victim-side logs and attacker-side packet captures provide different perspectives of the same general testing process.
- Detection alerts represent rule activations, not necessarily unique malicious packets.
- Post-mitigation packet delivery confirms that packets reached the Docker bridge interface; it does not by itself prove that the CUPS application processed them.
