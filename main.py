from config import Config
from detector import TripwireDetector
from transmitter import HoneypotTransmitter
from defense_system import DefenseSystem

if __name__ == "__main__":
    # Dependency Injection
    # 1. Create the specific detector we want (Tripwire on port 9999)
    my_detector = TripwireDetector(port=Config.TRIPWIRE_PORT)

    # 2. Create the specific responder we want (Honeypot Broadcast)
    my_responder = HoneypotTransmitter()

    # 3. Inject them into the system
    system = DefenseSystem(my_detector, my_responder)

    try:
        system.start_surveillance()
    except PermissionError:
        print("[Error] Access Denied. Please run as Administrator/Root.")
    except Exception as e:
        print(f"[Error] System Failure: {e}")