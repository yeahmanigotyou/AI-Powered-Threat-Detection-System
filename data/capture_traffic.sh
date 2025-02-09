#!/bin/bash
# capture_traffic.sh
# Capture network traffic on interface eth0 for 300 seconds and save to a timestamped file.

OUTPUT_DIR="/data"
FILENAME="$OUTPUT_DIR/traffic_$(date +'%Y-%m-%d_%H-%M-%S').pcap"

echo "Starting packet capture on interface eth0 for 300 seconds..."
tshark -i eth0 -a duration:300 -w "$FILENAME"

echo "Capture complete. File saved as: $FILENAME"
