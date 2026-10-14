# SmartSwitch coordinator image, built from this repository (only "cryptography" comes from PyPI).
# Pin the base image by digest for production:
#   docker buildx imagetools inspect python:3.12-slim   -> use python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 smartswitch && mkdir -p /data /mirror && chown smartswitch /data /mirror
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . && rm -rf /src

USER smartswitch
WORKDIR /data
EXPOSE 8720
# Tokens come from the environment (SMARTSWITCH_AGENT_TOKEN, SMARTSWITCH_OPERATOR_TOKEN); the coordinator
# refuses to start without them. The fleet document and the coordinator key are mounted at /config.
HEALTHCHECK --interval=10s --timeout=2s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8720/healthz', timeout=2)"
ENTRYPOINT ["sf-smartswitch", "serve", "--host", "0.0.0.0", "--port", "8720", "--fleet", "/config/fleet.json", \
            "--key", "/config/coordinator.key", "--log", "/data/switch.jsonl", "--mirror", "/mirror/switch.jsonl"]
