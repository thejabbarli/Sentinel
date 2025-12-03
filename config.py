# Shared constants for the Defense System

class Config:
    TRIPWIRE_PORT = 9999          # The port that triggers the alarm
    BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
    FAKE_SRC_IP = "45.33.32.156"  # The IP we pretend to send to
    PAYLOAD_FILE = "secret_assets.txt"
    INTERFACE = None              # None = Scapy chooses default