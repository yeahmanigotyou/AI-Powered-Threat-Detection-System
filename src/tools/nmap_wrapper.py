import nmap
from typing import Dict
from src.monitor.utils.utils import setup_logger

class NmapWrapper:
    def __init__(self, sudo: bool = True):
        self.scanner = nmap.PortScanner()
        self.sudo = sudo
        self.logger = setup_logger("NmapWrapper")
        
    def scan_network(self, target: str, ports: str='1-1024'):
        try:
            self.logger.info(f"Starting SCAN TYPE scan of {target} on ports {ports}")
            self.scanner.scan(
                hosts=target,
                ports=ports,
                arguments='-sV -T4',
                sudo=self.sudo 
            )
            results = self._process_scan_results()
            
            return results
        
        except Exception as e:
            self.logger.error(f"Network Scan Failed: {str(e)}")
            raise

    def _process_scan_results(self) -> Dict:
        """Process and structure the scan results."""
        results = {}
        
        for host in self.scanner.all_hosts():
            host_data = {
                'status': self.scanner[host].state()
                #'hostname': self._get_hostname(host),
                #'os': self._get_os_info(host),
                #'ports': self._get_port_info(host),
                #'services': self._get_service_info(host),
                #'vulnerabilities': self._check_common_vulnerabilities(host)
            }
            results[host] = host_data
            
        return results
    
#Add more varity of scans as well types