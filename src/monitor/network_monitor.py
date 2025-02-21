from src.tools.tshark_wrapper import TsharkWrapper
from src.tools.nmap_wrapper import NmapWrapper
from src.monitor.utils.privilege_manager import PrivilegeManager
#from src.monitor.packet_analysis import PacketAnalyzer
from src.monitor.utils.utils import setup_logger, save_json_data

class NetworkMonitor:
    def __init__(self, interface: str, target: str):
        self.interface = interface
        self.target = target
        self.tshark = TsharkWrapper()
        self.nmap = NmapWrapper()
        self.privilege_manager = PrivilegeManager()
        #self.analyzer = PacketAnalyzer()
        self.logger = setup_logger("NetworkMonitor")
    
        
    def start_monitoring(self):
        #Run Tshark Network Traffic Scan for Packet Capturing and Network Mapping Scan for Active Hosts and Open Ports
        try:
            self.logger.info(f"Starting network monitoring on interface: {self.interface}")
            if not self.privilege_manager.is_admin():
                self.logger.info("Elevating privileges for packet capture...")
                self.privilege_manager.elevate_if_needed()
            
            self.logger.info('Starting Packet Capture')    
            packets = self.tshark.capture_packets(self.interface)
            self.privilege_manager.register_process(packets)
            
            self.logger.info(f'Finished. Saving packet data in json format.')
            save_json_data(packets, 'captured_packets')
        
            self.logger.info(f"Starting network scan on target: {self.target}")
            scan_results = self.nmap.scan_network(self.target)
            self.privilege_manager.register_process(scan_results)
            
            self.logger.info(f'Finished. Saving network scan in json format.')
            save_json_data(scan_results, 'nmap_scan')
            
        except Exception as e:
            self.logger.error(f'Error during monitoring: {str(e)}')
            raise
        #Analyize the Results