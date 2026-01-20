# ARP Spoofing Defense System

A Python-based network security tool for detecting and responding to ARP cache poisoning attacks (Man-in-the-Middle) with active defense through cyber deception.

## Features

- **Detection** - Real-time ARP spoofing detection
- **Passive Defense** - ARP table restoration, logging, alerts
- **Active Defense** - Honeytoken injection to trap and track attackers
- **Canary Server** - Catches attackers who use stolen credentials

## Quick Start

```bash
# 1. Install dependencies
pip install scapy

# 2. Run setup to check configuration
python setup.py

# 3. Start defense (as administrator/root)
python main.py --deception
```

## How It Works

### Detection
Monitors ARP reply packets. Compares MAC addresses claiming to be the gateway against the legitimate gateway MAC. A mismatch = attack detected.

### Passive Defense
1. **Alert** - Console notification
2. **Log** - Record to file
3. **ARP Restoration** - Broadcasts correct ARP entries

### Active Defense (Honeytokens)
When `--deception` is enabled, the system injects fake credentials into network traffic:
- Fake API keys
- Fake database credentials  
- Fake AWS keys

Each contains a tracking beacon URL. If attacker uses them → you catch them.

## Usage

### Basic (Detection + Passive Defense)
```bash
# Windows (Admin)
python main.py

# Linux
sudo python main.py
```

### With Active Defense
```bash
python main.py --deception
```

### With Canary Server (Full Demo)
```bash
# Terminal 1: Start canary server
python canary_server.py --port 8080

# Terminal 2: Start defense with your IP as beacon
python main.py --deception --beacon 192.168.0.103:8080
```

## Testing

### Local Test (No Kali Needed)
```bash
# Terminal 1: Defense
python main.py --deception

# Terminal 2: Simulate attack
python test_detection.py
```

### With Kali Linux
```bash
# On Kali (attacker)
sudo arpspoof -i eth0 -t <defender_ip> <gateway_ip>

# To see captured honeytokens on Kali
sudo tcpdump -i eth0 -A | grep -E "(API_KEY|Password|aws_)"
```

### Demonstrate the Trap
```bash
# Show what attacker sees
python attacker_sim.py --demo

# Simulate attacker using stolen token (gets caught)
python attacker_sim.py --beacon-url http://192.168.0.103:8080/webhook/test123
```

## File Structure

```
arp_defense/
├── main.py              # Entry point
├── setup.py             # Configuration helper
├── interfaces.py        # Abstract base classes
├── detector.py          # ARP spoof detection
├── responders.py        # Passive defense
├── deception.py         # Active defense (honeytokens)
├── defense_system.py    # Orchestrator
├── canary_server.py     # Catches attackers
├── test_detection.py    # Local testing
├── attacker_sim.py      # Demo attacker perspective
├── config.py            # Configuration
└── requirements.txt
```

## Demo Scenario

1. **Defender** runs `python main.py --deception`
2. **Attacker** does ARP spoof, captures traffic
3. **Attacker** sees fake AWS credentials with health_check URL
4. **Attacker** tries to verify credentials, hits the URL
5. **Defender's** canary server logs attacker's IP → CAUGHT

The attacker cannot know which credentials are real. Using ANY captured data might expose them.

## Requirements

- Python 3.8+
- Scapy
- Administrator/root privileges
- Npcap (Windows) or libpcap (Linux)