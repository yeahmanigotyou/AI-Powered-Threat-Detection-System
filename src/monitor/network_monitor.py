from src.tools.tshark_wrapper import TsharkWrapper
from src.tools.nmap_wrapper import NmapWrapper
#from src.monitor.packet_analysis import PacketAnalyzer
from src.monitor.utils.utils import setup_logger, save_json_data

class NetworkMonitor:
    def __init__(self, interface: str, target: str):
        self.interface = interface
        self.target = target
        self.tshark = TsharkWrapper()
        self.nmap = NmapWrapper()
        #self.analyzer = PacketAnalyzer()
        self.logger = setup_logger("NetworkMonitor")
    
        
    def start_monitoring(self):
        #Run Tshark Network Traffic Scan for Packet Capturing and Network Mapping Scan for Active Hosts and Open Ports
        try:
            self.logger.info(f"Starting network monitoring on interface: {self.interface}")
            packets = self.tshark.capture_packets(self.interface)
            
            self.logger.info(f'Saving packet data in json form.')
            save_json_data(packets, 'captured_packets')
        
            self.logger.info(f"Starting network scan on target: {self.target}")
            scan_results = self.nmap.scan_network(self.target)
            
            self.logger.info(f'Saving network scan in json form.')
            save_json_data(scan_results, 'nmap_scan')
            
        except Exception as e:
            self.logger.error(f'Error during monitoring: {str(e)}')
            raise
        #Analyize the Results