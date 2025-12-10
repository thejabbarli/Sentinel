from config import Config
from detector import ArpSpoofDetector
from transmitter import HoneypotTransmitter
from defense_system import DefenseSystem

if __name__ == "__main__":
    # Dependency Injection

    # 1. Create the MITM Detector
    # FIX: ArpSpoofDetector does NOT take a port argument. It finds the Gateway automatically.
    my_detector = ArpSpoofDetector()

    # 2. Create the specific responder (Honeypot Broadcast)
    my_responder = HoneypotTransmitter()

    # 3. Inject them into the system
    # FIX: We MUST provide the IP so DefenseSystem finds the correct Wi-Fi adapter
    # Check your ipconfig to confirm this is your Windows IP
    my_ip = "192.168.0.104"

    system = DefenseSystem(my_detector, my_responder, listen_ip=my_ip)

    try:
        system.start_surveillance()
    except PermissionError:
        print("[Error] Access Denied. Please run as Administrator/Root.")
    except Exception as e:
        print(f"[Error] System Failure: {e}")