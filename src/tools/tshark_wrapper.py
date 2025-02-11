import pyshark
from typing import List, Dict 
from monitor.utils.utils import PacketFormatter
from src.monitor.utils.utils import setup_logger

class TsharkWrapper:
     def __init__(self):
          self.default_options = ['-T', 'json']
          self.format = PacketFormatter()
          self.logger = setup_logger("Tshark")

     def capture_packets(self, interface: str) -> List[Dict]:
         try:
              capture = pyshark.LiveCapture(interface=interface)
              packets = []
              
              for packet in capture.sniff_continuously(packet_count=1000):
                   packet_dict = self.format._convert_packet_to_dict_(packet)
                   packets.append(packet_dict)
                   
                   if len(packets) >= 1000:
                        break
                   
              return packets
         except Exception as e:
               self.logger.error(f"Failed to Capture Packets: {str(e)}")
               raise