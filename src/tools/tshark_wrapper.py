import pyshark
from typing import List, Dict 
from src.monitor.utils.utils import setup_logger

class TsharkWrapper:
     def __init__(self):
          self.default_options = ['-T', 'json']
          self.logger = setup_logger("TsharkWrapper")

     def capture_packets(self, interface: str) -> List[Dict]:
         try:
              self.logger.info("Capturing Packets...")
              capture = pyshark.LiveCapture(interface=interface)
              packets = []
              
              for packet in capture.sniff_continuously(packet_count=500):                # Might be better to grab all data then convert instead of grab,convert,grab,convert... 
                   packet_dict = self._convert_packet_to_dict_(packet)
                   packets.append(packet_dict)
                   
                   if len(packets) >= 500:
                        break
                   
              self.logger.info(f"{len(packets)} packets captured.")
              return packets
         except Exception as e:
               self.logger.error(f"Failed to Capture Packets: {str(e)}")
               raise
         
    
     def _convert_packet_to_dict_(self, packet) -> Dict:
          try:
               packet_dict = {
                    'timestamp': float(packet.sniff_timestamp),
                    'length': int(packet.length),
                    'protocol': packet.highest_layer,
                    'source_ip': packet.ip.src if hasattr(packet,'ip') else None,
                    'dest_ip':packet.ip.dst if hasattr(packet, 'ip') else None
               }
               
               if hasattr(packet, 'tcp'):
                    packet_dict.update({
                         'source_port': int(packet.tcp.srcport),
                         'dest_port': int(packet.tcp.dstport),
                         'tcp_flags': {
                         'SYN': bool(int(packet.tcp.flags_syn)),
                         'ACK': bool(int(packet.tcp.flags_ack)),
                         'FIN': bool(int(packet.tcp.flags_fin)),
                         'RST': bool(int(packet.tcp.flags_reset)),
                         'PSH': bool(int(packet.tcp.flags_push)),
                         'URG': bool(int(packet.tcp.flags_urg))
                         }
                    })
               elif hasattr(packet, 'udp'):
                    packet_dict.update({
                         'source_port': int(packet.udp.srcport),
                         'dest_port': int(packet.udp.dstport)
                    })
               
               return packet_dict
          except Exception as e:
               return {
                    'timestamp': float(packet.sniff_timestamp),
                    'length': int(packet.length),
                    'protocol': 'unknown'
               }