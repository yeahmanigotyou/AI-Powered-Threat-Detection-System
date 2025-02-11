from src.monitor.network_monitor import NetworkMonitor
import logging
import argparse

def setup_logging ():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/network_monitor.log'),
            logging.StreamHandler()
        ]
    )
    
def main():
    parser = argparse.ArgumentParser(description='Network Monitoring Tools')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--target', default='192.168.1.0/24', help='Target network to scan')
    parser.add_argument('--duration', type=int, default=300, help="Duration of monitoring in seconds")
    
    args = parser.parse_args()
    
    setup_logging()
    
    try:
        monitor = NetworkMonitor(interface=args.interface)
        results = monitor.start_monitoring(
            target_network=args.target,
            duration=args.duration
        )
        print("Monitoring is complete. Results are saved in logs.")
    except Exception as e:
        logging.error(f'Monitoring failed: {e}')
        raise
    
if __name__ == "__main__":
    main()