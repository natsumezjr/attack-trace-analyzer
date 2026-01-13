FROM ubuntu:24.04

# 设置非交互式安装
ENV DEBIAN_FRONTEND=noninteractive

# 安装基础依赖
RUN apt-get update && apt-get install -y \
    python3 \
    python3-yaml \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 Filebeat
RUN wget -q https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb && \
    dpkg -i filebeat-8.11.0-amd64.deb && \
    rm filebeat-8.11.0-amd64.deb

# 创建工作目录
WORKDIR /app

# 复制项目文件
COPY filebeat-docker.yml /etc/filebeat/filebeat.yml
COPY rules/ /app/rules/
COPY detector.py /app/
COPY requirements.txt /app/

# 创建必要的目录
RUN mkdir -p /tmp/filebeat-output /app/output /var/log/host

# 设置权限
RUN chmod 644 /etc/filebeat/filebeat.yml && \
    chmod +x /app/detector.py

# 复制启动脚本
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# 暴露卷以便挂载宿主机日志
VOLUME ["/var/log/host", "/app/output"]

# 入口点
ENTRYPOINT ["/app/docker-entrypoint.sh"]
