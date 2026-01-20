from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    log_file: str = "defense_log.txt"
    alert_on_detection: bool = True
    restore_arp_on_detection: bool = True
    interface: Optional[str] = None
    listen_ip: Optional[str] = None