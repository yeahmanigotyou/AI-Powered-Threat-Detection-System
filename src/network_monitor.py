from pathlib import Path
import logging
from tshark_wrapper import TsharkWrapper
from nmap_wrapper import NmapWrapper
from packet_analysis import PacketAnalyzer

class NetworkMonitor:
    def __init__(self, interface="eth0", output_dir="logs"):
        self.interface = interface
        self.output_dir = Path(output_dir)
        
        self.tshark = TsharkWrapper(interface)
        self.nmap = NmapWrapper()
        self.analyzer = PacketAnalyzer()