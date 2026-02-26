# IP Spoofing Example

This directory contains an educational example demonstrating IP spoofing techniques using the Scapy library.

## Description

IP spoofing is a technique used to create IP packets with a forged fake source IP address. This example demonstrates how an attacker could send DNS queries with a spoofed source IP address.

## Prerequisites

- Python 3.6+
- Scapy library (`pip install scapy`)
- Root/administrator privileges (required for raw socket access)

## Installation

```bash
pip install scapy
```

## Usage

Warning: This script requires root/administrator privileges to send raw network packets.

```bash
sudo python ip_spoof_example.py
```

## Security Disclaimer

This code is provided for **educational purposes only**. Intended use includes:

- Security research and vulnerability assessment
- Learning about network protocols and security
- Testing in controlled environments

**Do not use this code for malicious purposes or against systems you do not own or have express permission to test.**

## Legal Notice

Unauthorized IP spoofing may be illegal in many jurisdictions. Always ensure you have proper authorization before testing network-related code.