import pyshark
from typing import List, Dict 
from utils.packet_formatting import PacketFormatter

class TsharkWrapper:
     def __init__(self):
          self.default_options = ['-T', 'json']
          self.format = PacketFormatter()

     def capture_packets(self, interface: str, duration: int = 60) -> List[Dict]:
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
              raise Exception(f"Failed to Capture Packets: {str(e)}")