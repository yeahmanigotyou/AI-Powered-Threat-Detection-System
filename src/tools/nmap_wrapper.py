import nmap
from src.monitor.utils.utils import setup_logger

class NmapWrapper:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.logger = setup_logger("Nmap")
        
    def scan_network(self, target_network):
        try:
            return self.scanner.scan(
                hosts=target_network,
                arguments='-sS -sV -O --script=default'
            )
        except Exception as e:
            self.logger.error(f"Network Scan Failed: {str(e)}")
            raise