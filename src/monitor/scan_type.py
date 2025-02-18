from enum import Enum

class ScanType(Enum):
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    SERVICE = "service"
    OS = "os"
    UDP = "udp"
    AGGRESSIVE = "aggressive"