import nmap
import concurrent.futures
import re
import json
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from src.monitor.utils.utils import setup_logger
from src.monitor.scan_type import ScanType


"""
TO DO:
-Add the ability to check if service version is outdated:
    _check_service_version
    _is_version_outdated
-Add target validation
"""

class NmapWrapper:
    def __init__(self, sudo: bool = True, max_workers: int = 5):
        self.scanner = nmap.PortScanner()
        self.sudo = sudo
        self.logger = setup_logger("NmapWrapper")
        self.max_workers = max_workers
        self.scan_profiles = {
            ScanType.QUICK: {
                'arguments': '-sS -T4 -n -Pn',
                'description': 'Fast SYN scan'
            },
            ScanType.COMPREHENSIVE: {
                'arguments': '-sS -sV -sC -O -T4 -A',
                'description': 'Comprehensive scan with service detection and OS fingerprinting'
            },
            ScanType.STEALTH: {
                'arguments': '-sS -T2 -f -D RND:5',
                'description': 'Stealth scan with decoy IPs'
            },
            ScanType.VULNERABILITY: {
                'arguments': '-sV --script vuln',
                'description': 'Vulnerability detection scan'
            },
            ScanType.SERVICE: {
                'arguments': '-sV --version-intensity 3 --host-timeout 30s',
                'description': 'Detailed service version detection'
            },
            ScanType.OS: {
                'arguments': '-O --osscan-guess',
                'description': 'OS detection with aggressive guess'
            },
            ScanType.UDP: {
                'arguments': '-sU -T4',
                'description': 'UDP port scan'
            },
            ScanType.AGGRESSIVE: {
                'arguments': '-A -T4 -v',
                'description': 'Aggressive scan with all features'
            }
        }
        
    def scan_network(self,
                    target: str,
                    scan_type: Union[ScanType, List[ScanType]] = ScanType.QUICK, 
                    ports: str = '1-1024',
                    timeout: int = 3600,
                    exclude_hosts: Optional[List[str]] = None) -> Dict:
        """Perform network Scan with specified parameters"""
        try:
            self._validate_targets(target, exclude_hosts)
            scan_types = [scan_type] if isinstance(scan_type, ScanType) else scan_type
            
            results = {}
            for current_scan_type in scan_types:
                self.logger.info(f"Starting {current_scan_type.value} scan of {target} on ports {ports}")
                
                arguments = self.scan_profiles[current_scan_type]['arguments']
                if exclude_hosts:
                    arguments += f" -- exclude {','.join(exclude_hosts)}"
                    
                self.scanner.scan(
                    hosts=target,
                    ports=ports,
                    arguments=arguments,
                    sudo=self.sudo,
                    timeout=timeout
                )
                
                scan_results = self._process_scan_results(current_scan_type)
                results[current_scan_type.value] = scan_results
                
            return results
        
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            raise
        
    def parallel_scan(self, 
                      targets: List[str], 
                      scan_type: ScanType = ScanType.QUICK, 
                      ports: str = '1-1024') -> Dict:
        """Perform parallel scans on multiple targets"""
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_worker = self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.scan_network, target, scan_type, ports): target
                for target in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results[target] = future.results()
                except Exception as e: 
                    self.logger.error(f"Scan failed for target {target}: {str(e)}")
                    results[target] = {"error": str(e)}
                
        return results

    def _process_scan_results(self, scan_type: ScanType) -> Dict:
        """Process and structure the scan results."""
        results = {}
        
        for host in self.scanner.all_hosts():
            host_data = {
                'host': host,
                'status': self.scanner[host].state(),
                'scan_type': scan_type.value,
                'timestamp': datetime.now().isoformat(),
                'hostname': self._get_hostname(host),
                'os': self._get_os_info(host),
                'protocols': self._get_protocols_info(host),
                'services': self._get_services_info(host),
                'vulnerabilities': self._check_vulnerabilities(host),
                'security_issues': self._check_security_issues(host)
            }
            results[host] = host_data
            
        return results
    
    def _validate_targets(self, target, exclude_hosts):
        pass
    
    def _get_hostname(self, host: str) -> Dict:
        """Get detailed hostname information"""
        hostname_data = {
            'name': self.scanner[host].hostname(),
            'ptr': None,
            'dns_records': []
        }
        
        if 'hostnames' in self.scanner[host]:
            hostname_data['dns_records'] = self.scanner[host]['hostnames']
            
        return hostname_data
    
    def _get_os_info(self, host: str) -> Dict:
        """Get detailed OS information"""
        os_info = {
            'matches': [],
            'accuracy': None,
            'family': None
        }
        
        if 'osmatch' in self.scanner[host]:
            matches = self.scanner[host]['osmatch']
            if matches:
                os_info['matches'] = matches
                os_info['accuracy'] = matches[0].get('accuracy', None)
                os_info['family'] = matches[0].get('osclass', [{}])[0].get('osfamily', None)
                
        return os_info
    
    def _get_protocols_info(self, host: str) -> Dict:
        """Get detailed protocol information"""
        protocols_info = {}
        for protocol in self.scanner[host].all_protocols():
            protocols_info[protocol] = {
                'ports': {},
                'status': 'open'
            }
            
            ports = self.scanner[host][protocol].keys()
            for port in ports:
                port_info = self.scanner[host][protocol][port]
                protocols_info[protocol]['ports'][port] = {
                    'state': port_info.get('state', 'unknown'),
                    'reason': port_info.get('reason', 'unknown'),
                    'name': port_info.get('name', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'extrainfo': port_info.get('extrainfo', ''),
                    'conf': port_info.get('conf', ''),
                    'cpe': port_info.get('cpe', '')
                }
                
        return protocols_info
    
    def _get_services_info(self, host: str) -> Dict:
        """Get detailed service information"""
        services_info = {}
        if 'tcp' in self.scanner[host]:
            for port, data in self.scanner[host]['tcp'].items():
                if data['state'] == 'open':
                    services_info[port] = {
                        'name': data.get('name', 'unknown'),
                        'product': data.get('product', ''),
                        'version': data.get('version', ''),
                        'extrainfo': data.get('extrainfo', ''),
                        'cpe': data.get('cpe', ''),
                        'scripts': data.get('script', {})
                    }
        return services_info
    
    def _check_vulnerabilities(self, host: str) -> List[Dict[str, Any]]:
        """Check for vulnerabilities using NSE scripts"""
        vulnerabilities = []
        
        if 'script' in self.scanner[host]:
            for script_id, script_output in self.scanner[host]['script'].items():
                if 'vuln' in script_id:
                    vulnerability = {
                        'id': script_id,
                        'output': script_output,
                        'severity': self._determine_severity(script_output),
                        'references': self._extract_references(script_output)
                    }
                    vulnerabilities.append(vulnerability)
                    
        return vulnerabilities
    
    def _check_security_issues(self, host: str) -> List[Dict[str, Any]]:
        """Check for common security issues"""
        security_issues = []
        
        # Check for common misconfigurations
        if 'tcp' in self.scanner[host]:
            self._check_common_ports(host, security_issues)
            
        return security_issues
    
    def _check_common_ports(self, host: str, issues: List) -> None:
        """Check for commonly exploited ports"""
        common_dangerous_ports = {
            21: 'FTP',
            23: 'Telnet',
            445: 'SMB',
            3389: 'RDP'
        }
        
        for port, service in common_dangerous_ports.items():
            if port in self.scanner[host]['tcp']:
                if self.scanner[host]['tcp'][port]['state'] == 'open':
                    issues.append({
                        'type': 'open_dangerous_port',
                        'details': f'Potentially dangerous {service} port {port} is open',
                        'severity': 'HIGH'
                    })
    
    def _determine_severity(self, script_output: str) -> str:
        """Determine vulnerability severity based on script output"""
        if any(high_risk in script_output.lower() for high_risk in ['critical', 'high']):
            return 'HIGH'
        elif any(medium_risk in script_output.lower() for medium_risk in ['medium', 'moderate']):
            return 'MEDIUM'
        return 'LOW'
    
    def _extract_references(self, script_output: str) -> List[str]:
        """Extract reference URLs from script output"""
        references = []
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        matches = re.finditer(url_pattern, script_output)
        for match in matches:
            references.append(match.group())
        return references
    
    def _validate_targets(self, targets: Union[str, List[str]], exclude_hosts: Optional[List[str]] = None) -> None:
        """Validate target IP addresses and ranges"""
        try:
            if isinstance(targets, str):
                targets = [targets]
                
            for target in targets:
                if '/' in target:  # CIDR notation
                    ipaddress.ip_network(target)
                else:
                    ipaddress.ip_address(target)
                    
            if exclude_hosts:
                for host in exclude_hosts:
                    ipaddress.ip_address(host)
                    
        except ValueError as e:
            raise ValueError(f"Invalid target specification: {str(e)}")
    
    def export_results(self, results: Dict, filepath: str) -> None:
        """Export scan results to file"""
        try:
            output_path = Path(filepath)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=4)
                
            self.logger.info(f"Results exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to export results: {str(e)}")
            raise