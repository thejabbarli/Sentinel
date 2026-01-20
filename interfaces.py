from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatInfo:
    threat_type: str
    source_ip: str
    source_mac: str
    expected_mac: Optional[str] = None
    timestamp: Optional[str] = None
    raw_packet: Optional[object] = None


class IDetector(ABC):
    @abstractmethod
    def analyze(self, packet) -> Optional[ThreatInfo]:
        pass


class IResponder(ABC):
    @abstractmethod
    def respond(self, threat: ThreatInfo) -> bool:
        pass