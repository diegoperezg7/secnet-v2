FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Instalar Suricata desde PPA oficial
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:oisf/suricata-stable -y && \
    apt-get update && \
    apt-get install -y suricata

# 2. Crear directorios necesarios
RUN mkdir -p /etc/suricata/rules /var/log/suricata

# 3. Copiar configuración y reglas desde el contexto
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

# 4. Ajustar permisos
RUN chmod 644 /etc/suricata/suricata.yaml && \
    chmod 644 /etc/suricata/rules/local.rules

# 5. Arrancar Suricata en modo IDS escuchando en eth0
ENTRYPOINT ["suricata"]
CMD ["-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
