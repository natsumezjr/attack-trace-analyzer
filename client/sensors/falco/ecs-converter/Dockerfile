FROM python:3.11-slim

WORKDIR /app
COPY falco_json_to_ecs.py /app/falco_json_to_ecs.py

ENTRYPOINT ["python", "/app/falco_json_to_ecs.py"]
