from pathlib import Path
import logging
from datetime import datetime
from src.tools.tshark_wrapper import TsharkWrapper
from src.tools.nmap_wrapper import NmapWrapper
from src.monitor.packet_analysis import PacketAnalyzer

class NetworkMonitor:
    def __init__(self, interface="eth0", output_dir="logs"):
        self.interface = interface
        self.output_dir = Path(output_dir)
        
        self.tshark = TsharkWrapper(interface)
        self.nmap = NmapWrapper()
        self.analyzer = PacketAnalyzer()
        
    def start_monitoring(self, target_network, duration="300"):
        #Run Tshark Network Traffic Scan for Packet Capturing
        pcap_file = self.tshark.capture_traffic(duration)
        
        #Run Nmap Network Mapping Scan for Active Hosts and Open Ports
        scan_results = self.nmap.scan_network(target_network)
        
        #Analyize the Results
        
        return pcap_file, scan_results