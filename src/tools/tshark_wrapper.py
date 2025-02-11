import subprocess
from pathlib import Path
import logging

class TsharkWrapper:
    def __init__(self, interface):
        self.interface = interface
        self.logger = logging.getLogger(__name__)
        
    def capture_traffic(self, duration):
            output_file = Path(f"data/capture_{datetime.now():%Y%m%d_%H%M%S}.pcap")
            
            cmd = [
                 "tshark",
                 "-i", self.interface,
                 "-w", str(output_file),
                 "-a", f"duration:{duration}"
            ]
            
            try:
                 subprocess.run(cmd, check=True)
                 return output_file
            except subprocess.CalledProcessError as e:
                 self.logger.error(f"Captured Failed: {e}")
                 raise