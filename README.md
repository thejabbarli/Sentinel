# ARP Spoofing Defense System

A Python-based network security tool for detecting and responding to ARP cache poisoning attacks (Man-in-the-Middle).

## How It Works

### Detection
The system monitors ARP reply packets on the network. It compares the MAC address claiming to be the gateway against the legitimate gateway MAC (resolved at startup). A mismatch indicates an ARP spoofing attack.

### Response
When an attack is detected, the system executes a chain of responses:

1. **Alert** - Console notification with attack details
2. **Log** - Persistent record to file for forensics
3. **ARP Restoration** - Broadcasts correct ARP entries to counter the poisoning

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run with administrator/root privileges:

```bash
# Windows (Admin PowerShell)
python main.py

# Linux
sudo python main.py
```

## Architecture

The system follows SOLID principles with dependency injection:

- `IDetector` / `IResponder` - Abstract interfaces
- `ArpSpoofDetector` - Concrete detection implementation
- `LogResponder`, `AlertResponder`, `ArpRestorationResponder` - Modular response handlers
- `CompositeResponder` - Chains multiple responders
- `DefenseSystem` - Orchestrates detection and response

## Testing

To test detection, you can use `arpspoof` from the `dsniff` package on a separate machine:

```bash
# On attacker machine (Linux)
sudo arpspoof -i eth0 -t <target_ip> <gateway_ip>
```

## Requirements

- Python 3.8+
- Scapy
- Administrator/root privileges
- Network interface in promiscuous mode (handled by Scapy)