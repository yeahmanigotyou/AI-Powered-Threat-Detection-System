import nmap
from typing import Dict, List, Any
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
                'host': host,
                'status': self.scanner[host].state(),
                'hostname': self._get_hostname(host),
                'os': self._get_os_info(host),
                'protocols': self._get_protocols_info(host),
                'vulnerabilities': self._check_common_vulnerabilities(host)
            }
            results[host] = host_data
            
        return results
    
    def _get_hostname(self, host: str) -> str:
        hostname = self.scanner[host].hostname()
        return hostname if hostname else "N/A"
    
    def _get_os_info(self, host: str) -> Dict:
        os_info = {}
        if 'osmatch' in self.scanner[host]:
            os_info = self.scanner[host]['osmatch'][0] if self.scanner[host]['osmatch'] else {}
        return os_info
    
    def _get_protocols_info(self, host: str) -> Dict:
        protocols_info = {}
        for protocol in self.scanner[host].all_protocols():
            protocols_info[protocol] = {}
            ports = self.scanner[host][protocol].keys()
            for port in ports:
                protocols_info[protocol][port] = self.scanner[host][protocol][port]
        return protocols_info
    
    def _check_common_vulnerabilities(self, host: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if 'script' in self.scanner[host]:
            for script_id, script_output, in self.scanner[host]['script'].items():
                vulnerabilities.append({
                    'id': script_id,
                    'output': script_output
                })
        
        return vulnerabilities
    
    
    
#Add more varity of scans as well types