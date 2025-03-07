import argparse
import logging
import atexit
import ctypes
import sys
import os
import time
from pathlib import Path
import yaml
import json
from datetime import datetime
import threading
from dataclasses import dataclass

from src.monitor.network_monitor_worker import NetworkMonitor, MonitoringConfig
from src.monitor.utils.utils import ensure_directory, CustomEncoder
from src.monitor.scan_type import ScanType

@dataclass
class ApplicationConfig:
    log_level: str = 'INFO'
    log_format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_directory: str = 'logs'
    log_max_size: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5
    config_file: str = 'config/monitor_config.yaml'
    pid_file: str = 'run/monitor.pid'

class NetworkMonitorApp:
    def __init__(self):
        self.config = ApplicationConfig()
        self.logger = self.monitor = None
        self.monitor = None
        self.stop_event = threading.Event()
        self.mutex = None
        
        self.setup_logging()
        self.args = self.parse_arguments()
        self.file_config = self.load_config(self.args.config)
        self.monitor_config = self.create_monitoring_config(self.args, self.file_config)
        self.ui_callback = None
        self.monitor_thread = None
        self.stop_event = threading.Event()
        
        atexit.register(self.cleanup_pid)
        
    def set_ui_callback(self, callback):
        self.logger.info("Setting UI callback")
        self.ui_callback = callback
        
    def setup_logging(self):
        """Configure logging with rotation and multiple handlers"""
        from logging.handlers import RotatingFileHandler
        
        log_dir = Path(self.config.log_directory)
        log_dir.mkdir(parents = True, exist_ok = True)
        
        formatter = logging.Formatter(self.config.log_format)
        
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config.log_level))
        
        file_handler = RotatingFileHandler(
            log_dir / 'system.log',
            maxBytes = self.config.log_max_size,
            backupCount = self.config.log_backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        self.logger = logging.getLogger('NetworkMonitorApp')
        
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments with extended options"""
        parser = argparse.ArgumentParser(
            description='Advanced Network Monitoring Tool',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Basic arguments
        parser.add_argument('--interface', '-i', 
                          default='Ethernet',
                          help='Network interface to monitor')
        parser.add_argument('--target', '-t',
                          default='192.168.1.0/24',
                          help='Target network to scan')
        
        # Configuration arguments
        parser.add_argument('--config', '-c',
                          default='config/monitor_config.yaml',
                          help='Path to configuration file')
        parser.add_argument('--log-level',
                          choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                          default='INFO',
                          help='Set the logging level')
        
        # Monitoring control arguments
        parser.add_argument('--duration', '-d',
                          type=int,
                          help='Duration to monitor in seconds')
        parser.add_argument('--scan-interval',
                          type=int,
                          default=300,
                          help='Interval between network scans in seconds')
        parser.add_argument('--packet-buffer',
                          type=int,
                          default=1000,
                          help='Size of packet buffer')
        
        # Output control arguments
        parser.add_argument('--output-dir',
                          default='data',
                          help='Directory for output files')
        parser.add_argument('--save-interval',
                          type=int,
                          default=60,
                          help='Interval between saving data in seconds')
        
        return parser.parse_args()

    def load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load config file: {e}")
            return {}
        
    def save_pid(self):
        """Handle PID file (mutex moved to main.py)"""
        if sys.platform == 'win32':
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            self.logger.info(f"Running as admin: {is_admin}")
        else:
            pid_path = Path(self.config.pid_file)
            pid_path.parent.mkdir(parents=True, exist_ok=True)
            pid_path.write_text(str(os.getpid()))

    def cleanup_pid(self):
        """Remove PID file (no mutex handling here)"""
        try:
            Path(self.config.pid_file).unlink(missing_ok=True)
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")        

    def create_monitoring_config(self, args: argparse.Namespace, 
                               file_config: dict) -> MonitoringConfig:
        """Create monitoring configuration from arguments and config file"""
        # Combine file config with command line arguments, preferring arguments
        config = MonitoringConfig(
            packet_buffer_size=args.packet_buffer or file_config.get('packet_buffer_size', 1000),
            scan_interval=args.scan_interval or file_config.get('scan_interval', 300),
            save_interval=args.save_interval or file_config.get('save_interval', 60),
            ports_to_monitor=file_config.get('ports_to_monitor', '1-1024'),
            scan_types=[ScanType[st] for st in file_config.get('scan_types', ['QUICK', 'SERVICE'])]
        )
        
        return config
    
    def save_monitoring_status(self, status: dict):
        """Save monitoring status to file"""
        status_file = Path('data/status.json')
        ensure_directory()
        
        status['timestamp'] = datetime.now().isoformat()
        
        with open(status_file, 'w') as f:
            json.dump(status, f, indent=2, cls = CustomEncoder)
            
    def status_monitoring_thread(self):
        """Thread to periodically save monitoring status"""
        while not self.stop_event.is_set():
            if self.monitor:
                status = self.monitor.get_monitoring_status()
                self.save_monitoring_status(status)
            time.sleep(10)  # Update status every minute
            
    def start_monitoring(self):
        """Starts the network monitoring"""
        self.logger.info("Start monitoring called")
        if not self.monitor:
            self.logger.info("Initializing NetworkMonitor")
            ensure_directory()
            self.monitor = NetworkMonitor(
                interface=self.args.interface,
                target=self.args.target,
                config=self.monitor_config 
            )
            # Pass UI callback to monitor
            if self.ui_callback:
                self.logger.info("Setting status callback (start_monitoring)")
                self.monitor.set_status_callback(self.ui_callback)
            status_thread = threading.Thread(target=self.status_monitoring_thread, daemon=True)
            status_thread.start()
            self.monitor_thread = threading.Thread(target=self._run_monitoring, daemon=True)
            self.logger.info("Starting monitor thread (start_monitoring)")
            self.monitor_thread.start()
        else:
            self.logger.info("Monitoring already in progress (start_monitoring)")
            
    def _run_monitoring(self):
        """Run monitoring and log conclusion when stopped"""
        try:
            self.logger.info("Running NetworkMonitor.start_monitoring")
            self.monitor.start_monitoring()
            self.logger.info("Monitoring started, waiting for completion")
            while self.monitor.is_monitoring and not self.stop_event.is_set():
                time.sleep(0.1)
            self.logger.info("Monitoring stopped, finalizing")
            self.stop_monitoring(internal_call = True)  # Ensure cleanup
            self.logger.info("Network Monitoring has concluded")  # Log here
        except Exception as e:
            self.logger.error(f"Error in _run_monitoring: {str(e)}", exc_info=True)
            self.stop_monitoring(internal_call = True)
            
    def _monitor_state(self):
        """Poll monitor state and update UI when stopped"""
        while not self.stop_event.is_set():
            if self.monitor and not self.monitor.is_monitoring:
                if self.ui_callback:
                    self.ui_callback("Stopped")
                self.logger.info("Network Monitoring has concluded (internal stop)")
                break 
            time.sleep(0.1)
    
    def stop_monitoring(self, internal_call=False):
        """Stops the network monitoring"""
        if not self.stop_event.is_set():
            self.stop_event.set()
            if self.monitor:
                self.monitor.stop_monitoring()
            self.cleanup_pid()
            if not internal_call:  # Only log and join for manual/UI stop
                self.logger.info("Network Monitoring has concluded")
                if self.ui_callback:
                    self.ui_callback("Stopped")
                if self.monitor_thread and self.monitor_thread.is_alive():
                    self.logger.info("Joining monitor thread from UI stop")
                    self.monitor_thread.join()
            elif self.ui_callback:  # Ensure UI updates for internal stop
                self.ui_callback("Stopped")