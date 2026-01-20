from detector import ArpSpoofDetector
from responders import (
    LogResponder,
    AlertResponder,
    ArpRestorationResponder,
    CompositeResponder
)
from defense_system import DefenseSystem


def main():
    detector = ArpSpoofDetector()

    responder = CompositeResponder([
        AlertResponder(),
        LogResponder("attack_log.txt"),
        ArpRestorationResponder()
    ])

    system = DefenseSystem(
        detector=detector,
        responder=responder,
        listen_ip=None,
        continuous=True
    )

    try:
        system.start()
    except PermissionError:
        print("[Error] Run as Administrator/root")
    except Exception as e:
        print(f"[Error] {e}")


if __name__ == "__main__":
    main()