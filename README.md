# ARP Spoofing Defense System

A Python-based network security tool for detecting and responding to ARP cache poisoning attacks (Man-in-the-Middle) with optional active defense through cyber deception.

## Features

- **Detection** - Real-time ARP spoofing detection
- **Passive Defense** - ARP table restoration, logging, alerts
- **Active Defense** - Honeytoken injection to trap and track attackers

## How It Works

### Detection
The system monitors ARP reply packets on the network. It compares the MAC address claiming to be the gateway against the legitimate gateway MAC (resolved at startup). A mismatch indicates an ARP spoofing attack.

### Passive Response
When an attack is detected:
1. **Alert** - Console notification with attack details
2. **Log** - Persistent record to file for forensics
3. **ARP Restoration** - Broadcasts correct ARP entries to counter the poisoning

### Active Defense (Cyber Deception)
When enabled with `--deception`, the system injects honeytokens into network traffic. These are fake but realistic-looking credentials and API keys that contain tracking beacons.

**Why this works:**
- Attacker intercepts traffic via MITM
- They capture what looks like valuable credentials
- If they use the fake credentials, beacon URLs are triggered
- You get alerted and can identify the attacker

**The deterrent effect:** Attackers cannot trust ANY captured data. Using stolen credentials might expose them. This increases attack cost and creates uncertainty.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run with administrator/root privileges:

```bash
# Basic detection and defense
sudo python main.py

# With active defense (honeytoken injection)
sudo python main.py --deception

# Custom beacon domain for tracking
sudo python main.py --deception --beacon canary.mycompany.com
```

### Setting Up Beacon Tracking

To fully utilize active defense, set up a simple canary server:

1. Register a domain or use a service like Canarytokens.org
2. Point `--beacon` to your tracking domain
3. Any HTTP request to that domain from attacker = confirmed breach

## Architecture

The system follows SOLID principles:

- `IDetector` / `IResponder` - Abstract interfaces (Dependency Inversion)
- `ArpSpoofDetector` - Detection implementation (Single Responsibility)
- `LogResponder`, `AlertResponder`, `ArpRestorationResponder` - Passive defense
- `DeceptionResponder` - Active defense with honeytokens
- `CompositeResponder` - Chains responders (Open/Closed Principle)
- `DefenseSystem` - Orchestration with injected dependencies

## File Structure

```
arp_defense/
├── main.py              # Entry point with CLI
├── interfaces.py        # Abstract base classes
├── detector.py          # ARP spoof detection
├── responders.py        # Passive defense (log, alert, restore)
├── deception.py         # Active defense (honeytokens)
├── defense_system.py    # Main orchestrator
├── config.py            # Configuration
├── requirements.txt
└── README.md
```

## Testing

To test detection, use `arpspoof` from the `dsniff` package on a separate machine:

```bash
# On attacker machine (Linux)
sudo arpspoof -i eth0 -t <target_ip> <gateway_ip>
```

## Requirements

- Python 3.8+
- Scapy
- Administrator/root privileges