FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/library/python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir pika==1.3.2
COPY falco_json_to_ecs.py /app/falco_json_to_ecs.py
COPY rule_to_attack.json /app/rule_to_attack.json

ENTRYPOINT ["python", "/app/falco_json_to_ecs.py"]
