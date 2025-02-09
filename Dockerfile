# Dockerfile
FROM ubuntu:25.04

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install Tshark (and iproute2 for network utilities)
RUN apt-get update && \
    apt-get install -y tshark iproute2 && \
    rm -rf /var/lib/apt/lists/*

# Create a directory to store capture files
RUN mkdir -p /data

# Set the working directory
WORKDIR /data

# Copy the capture script into the container and make it executable
COPY capture_traffic.sh /data/capture_traffic.sh
RUN chmod +x /data/capture_traffic.sh

# Set the default command to run the capture script

#CMD ["/bin/bash", "/data/capture_traffic.sh"]

CMD ["bash", "-c", "exec /data/capture_traffic.sh"]

