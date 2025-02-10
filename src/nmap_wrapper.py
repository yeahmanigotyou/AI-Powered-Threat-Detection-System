import nmap
import logging

class NmapWrapper:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
        
    def scan_network(self, target_network):
        try:
            return self.scanner.scan(
                hosts=target_network,
                arguments='-sS -sV -O --script=default'
            )
        except Exception as e:
            self.logger.error(f"Scan Failed: {e}")
            raise