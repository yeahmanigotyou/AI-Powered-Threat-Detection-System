import logging
import os
from typing import Dict, Any
from datetime import datetime
import json
import numpy as np

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(f"logs/{name}.log")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def ensure_directories():
    directories = ['logs','data','models']
    for directory in directories:
        os.mkdirs(directory, exists_ok=True)

def save_json_data(data: Dict[str, Any], filename: str):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    full_filename = f'date/{filename}_{timestamp}.json'
    
    with open(full_filename, 'w') as f:
        json.dump(data, f, indent=4)
        
def load_json_data(filepath: str) -> Dict:
    with open(filepath, 'r') as f:
        return json.load(f)
    

class NumpyEncoder(json.JSONEncoder):
    
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)
    
class PacketFormatter:
    
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