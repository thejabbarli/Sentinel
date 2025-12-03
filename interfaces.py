from abc import ABC, abstractmethod

class IAttackDetector(ABC):
    """Interface for any logic that detects an intrusion."""
    @abstractmethod
    def analyze_packet(self, packet) -> bool:
        """Returns True if the packet is considered an attack."""
        pass

class IResponder(ABC):
    """Interface for any action taken after detection."""
    @abstractmethod
    def execute(self):
        """Executes the counter-measure."""
        pass