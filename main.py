from src.monitor.network_monitor import NetworkMonitor
from src.monitor.utils.utils import ensure_directories
import logging
import argparse
import sys

def setup_logging ():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/system.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
def parse_arguments():
    parser = argparse.ArgumentParser(description='Network Monitoring Tools')
    parser.add_argument('--interface', '-i', default='Ethernet', help='Network interface to monitor')
    parser.add_argument('--target', '-t', default='192.168.1.0/24', help='Target network to scan')
    return parser.parse_args()
 
def main():       
    setup_logging()
    logger = logging.getLogger('main')
    
    ensure_directories()
    
    args = parse_arguments()
    
    try:
        monitor = NetworkMonitor(
            interface=args.interface,
            target=args.target,
        )
        monitor.start_monitoring()
    except KeyboardInterrupt as e:
        logger.info(f'Monitoring stopped by user.')
        sys.exit(0)
    except Exception as e:
        logger.error(f'Monitoring failed (ERROR): {e}')
        sys.exit(0)
    
if __name__ == "__main__":
    main()