FROM python:3.12.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

ARG INSTALL_GEOIP=false
COPY requirements.txt requirements-geoip.txt ./
RUN if [ "$INSTALL_GEOIP" = "true" ]; then \
		pip install --no-cache-dir -r requirements-geoip.txt; \
	else \
		pip install --no-cache-dir -r requirements.txt; \
	fi
COPY honeypot.py ti_logger.py system_state.py artifact_analysis.py local_llm.py report.py dashboard.py simulate_attacks.py check_ports.py config.yaml docker-config.yaml ./
RUN mkdir -p /app/logs && chown -R 10001:10001 /app
USER 10001:10001

EXPOSE 2222 2323 2121 8080 13306 16379 12525 2375 6443 1502 1883 8765

# Health check for honeypot service
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 8080)); s.close()" || exit 1

CMD ["python", "honeypot.py", "--config", "docker-config.yaml"]