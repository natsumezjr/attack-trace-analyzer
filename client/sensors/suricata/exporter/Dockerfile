FROM ubuntu:22.04

WORKDIR /app

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py

ENV EVE_FILE=/data/eve.json \
    OUTPUT_DIR=/data/output \
    STATE_DIR=/data/state \
    AGENT_NAME=netflow-exporter \
    AGENT_VERSION=0.1.0

EXPOSE 8080
CMD ["python3", "-m", "waitress", "--listen=0.0.0.0:8080", "app:app"]
