from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime
import threading
import queue
import time
from pathlib import Path
import asyncio

from src.tools.tshark_wrapper import TsharkWrapper
from src.tools.nmap_wrapper import NmapWrapper
from src.monitor.utils.privilege_manager import PrivilegeManager
#from src.monitor.packet_analysis import PacketAnalyzer
from src.monitor.utils.utils import setup_logger, save_json_data, ensure_directory
from src.monitor.scan_type import ScanType

@dataclass
class MonitoringConfig:
    packet_buffer_size: int = 100000
    scan_interval: int = 300
    max_packet_count: Optional[int] = None
    ports_to_monitor: str = '1-1024'
    save_interval: int = 60
    scan_types: List[ScanType] = None
    
    def __port_init__(self):
        if self.scan_types is None:
            self.scan_types = [ScanType.QUICK, ScanType.SERVICE]


class NetworkMonitor:
    def __init__(self, interface: str, target: str, config: Optional[MonitoringConfig] = None):
        self.interface = interface
        self.target = target
        self.config = config or MonitoringConfig()
        self.tshark = TsharkWrapper(buffer_size = self.config.packet_buffer_size)
        self.nmap = NmapWrapper()
        self.privilege_manager = PrivilegeManager()
        #self.analyzer = PacketAnalyzer()
        self.logger = setup_logger("NetworkMonitor")
        self.is_monitoring = False
        self.packet_queue = queue.Queue(maxsize = self.config.packet_buffer_size)
        self.scan_results_queue = queue.Queue()
        self.last_scan_time = 0
        self.monitoring_threads = []

    
        
    def start_monitoring(self, duration: Optional[int] = None):
        """Start network monitoring with optional duration"""
        try:
            self.logger.info(f"Starting network monitoring on interface: {self.interface}")
            self._check_privileges()
            
            self.is_monitoring = True
            
            self._start_packet_capture()
            self._start_network_scanning()
            self._start_data_processing()
            
            if duration:
                time.sleep(duration)
                self.stop_monitoring()
            
        except Exception as e:
            self.logger.error(f'Error during monitoring startup: {str(e)}')
            self.stop_monitoring()
            raise

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        self.logger.info("Stopping network monitoring...")
        self.is_monitoring = False
        
        # Stop all threads
        for thread in self.monitoring_threads:
            thread.join()
            
        self.monitoring_threads.clear()
        
        # Final data save
        self._save_monitoring_data()
        
    def _check_privileges(self):
        """Check and elevate privileges if needed"""
        if not self.privilege_manager.is_admin():
            self.logger.info("Elevating privileges for packet capture...")
            self.privilege_manager.elevate_if_needed()
            
    def _start_packet_capture(self):
        """Start packet capture thread"""
        capture_thread = threading.Thread(
            target=self._packet_capture_worker,
            name="PacketCapture",
            daemon=True
        )
        capture_thread.start()
        self.monitoring_threads.append(capture_thread)
        
    def _start_network_scanning(self):
        """Start network scanning thread"""
        scan_thread = threading.Thread(
            target=self._network_scan_worker,
            name="NetworkScan",
            daemon=True
        )
        scan_thread.start()
        self.monitoring_threads.append(scan_thread)
        
    def _start_data_processing(self):
        """Start data processing thread"""
        process_thread = threading.Thread(
            target=self._data_processing_worker,
            name="DataProcessing",
            daemon=True
        )
        process_thread.start()
        self.monitoring_threads.append(process_thread)
        
    def _packet_capture_worker(self):
        """Worker function for continuous packet capture"""
        try:
            self.logger.info('Starting Packet Capture...')
            asyncio.set_event_loop(asyncio.new_event_loop())
            self.tshark.clear_buffer()
            self.tshark.start_capture(
                interface=self.interface,
                packet_count=self.config.max_packet_count
            )
            
            while self.is_monitoring:
                packets = self.tshark.get_packets(batch_size=100)
                if packets:
                    self._process_packets(packets)
                time.sleep(0.1)  # Prevent CPU overuse
                    
        except Exception as e:
            self.logger.error(f'Error in packet capture: {str(e)}')
            self.stop_monitoring()
            
    def _network_scan_worker(self):
        """Worker function for periodic network scanning"""
        try:
            while self.is_monitoring:
                current_time = time.time()
                if current_time - self.last_scan_time >= self.config.scan_interval:
                    self.logger.info(f"Starting network scan on target: {self.target}")
                    
                    for scan_type in self.config.scan_types:
                        scan_results = self.nmap.scan_network(
                            target=self.target,
                            scan_type=scan_type,
                            ports=self.config.ports_to_monitor
                        )
                        self.scan_results_queue.put({
                            'timestamp': datetime.now().isoformat(),
                            'scan_type': scan_type.value,
                            'results': scan_results
                        })
                        
                    self.last_scan_time = current_time
                    
                time.sleep(1)  # Check every second
                
        except Exception as e:
            self.logger.error(f'Error in network scanning: {str(e)}')
            self.stop_monitoring()
            
    def _data_processing_worker(self):
        """Worker function for processing and saving monitoring data"""
        last_save_time = time.time()
        
        try:
            while self.is_monitoring:
                current_time = time.time()
                
                # Regular data saving
                if current_time - last_save_time >= self.config.save_interval:
                    self._save_monitoring_data()
                    last_save_time = current_time
                    
                time.sleep(1)  # Check every second
                
        except Exception as e:
            self.logger.error(f'Error in data processing: {str(e)}')
            self.stop_monitoring()
            
    def _process_packets(self, packets: List[Dict]):
        """Process captured packets"""
        try:
            # Add timestamp and metadata
            processed_packets = []
            for packet in packets:
                processed_packet = {
                    'timestamp': datetime.now().isoformat(),
                    'data': packet,
                    'metadata': self._extract_packet_metadata(packet)
                }
                processed_packets.append(processed_packet)
                
            # Add to processing queue
            for packet in processed_packets:
                try:
                    self.packet_queue.put_nowait(packet)
                except queue.Full:
                    self.logger.warning("Packet queue full, dropping oldest packets")
                    while not self.packet_queue.empty():
                        try:
                            self.packet_queue.get_nowait()
                        except queue.Empty:
                            break
                    self.packet_queue.put_nowait(packet)
                    
        except Exception as e:
            self.logger.error(f"Error processing packets: {str(e)}")
            
    def _extract_packet_metadata(self, packet: Dict) -> Dict:
        """Extract metadata from packet"""
        metadata = {
            'size': packet.get('length', 0),
            'protocol': packet.get('protocol', 'unknown'),
        }
        
        # Add protocol-specific metadata
        if 'tcp' in packet:
            metadata['service'] = self._identify_service(packet['tcp'])
        elif 'udp' in packet:
            metadata['service'] = self._identify_service(packet['udp'])
            
        return metadata
    
    def _identify_service(self, protocol_data: Dict) -> str:
        """Identify service based on port numbers"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            53: 'DNS',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
        
        source_port = protocol_data.get('srcport')
        dest_port = protocol_data.get('dstport')
        
        if source_port in common_ports:
            return common_ports[source_port]
        elif dest_port in common_ports:
            return common_ports[dest_port]
            
        return 'unknown'
    
    def _save_monitoring_data(self):
        """Save accumulated monitoring data"""
        try:
            timestamp = datetime.now().strftime('%Y.%m.%d_%H.%M.%S')
            
            # Save packets
            packets = self._get_queue_contents(self.packet_queue)
            if packets:
                packet_file = Path ('data') / f'packets_{timestamp}.json'
                ensure_directory()
                save_json_data(packets, packet_file)
                
            # Save scan results
            scan_results = self._get_queue_contents(self.scan_results_queue)
            if scan_results:
                scan_file = Path ('data') / f'scan_{timestamp}.json'
                ensure_directory()
                save_json_data(scan_results, scan_file)
                
        except Exception as e:
            self.logger.error(f"Error saving monitoring data: {str(e)}", exc_info=True)
            
    def _get_queue_contents(self, q: queue.Queue) -> List:
        """Safely get all contents from a queue"""
        contents = []
        while True:
            try:
                contents.append(q.get_nowait())
            except queue.Empty:
                break
        return contents
            
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        try:
            status = {
                'is_monitoring': self.is_monitoring,
                'packet_queue_size': self.packet_queue.qsize(),
                'scan_results_queue_size': self.scan_results_queue.qsize(),
                'last_scan_time': datetime.fromtimestamp(self.last_scan_time) if self.last_scan_time else None,
                'active_threads': [thread.name for thread in self.monitoring_threads if thread.is_alive()],
                'config': vars(self.config)
            }
            return status
        except Exception as e:
            self.logger.error(f'Error getting monitoring status: {str(e)}')
            return {'error': str(e)}