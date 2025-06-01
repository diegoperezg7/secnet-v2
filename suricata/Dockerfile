FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:oisf/suricata-stable && \
    apt-get update && \
    apt-get install -y suricata

# Create log directory
RUN mkdir -p /var/log/suricata

# Copy default configuration
COPY suricata.yaml /etc/suricata/suricata.yaml

# Set permissions
RUN chmod 644 /etc/suricata/suricata.yaml

# Command to run Suricata
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
