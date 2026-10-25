# One image for every TRA role; TRA_ROLE picks the role at run time.
#
# AgentCore Runtime needs linux/arm64, Foundry hosted agents need linux/amd64:
#   docker build --platform linux/arm64 --build-arg ENTRY=tra_platform.agentcore -t tra-agent:agentcore .
#   docker build --platform linux/amd64 --build-arg ENTRY=tra_platform.foundry  -t tra-agent:foundry .
# Pin the base image by digest in your registry mirror before production use.
FROM python:3.13-slim AS build
ARG EXTRAS=agentcore,foundry
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[${EXTRAS}]"

FROM python:3.13-slim
ARG ENTRY=tra_platform.agentcore
ENV TRA_ENTRY=${ENTRY} \
    TRA_MODELS_FILE=/app/config/models.yaml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /install /usr/local
COPY config /app/config
# pip is not needed at run time, and its vendored copies of urllib3, msgpack and
# pkg_resources lag the releases the app itself installs. Remove it and ensurepip.
RUN python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3.13/ensurepip \
 && useradd --uid 10001 --no-create-home tra
USER 10001
WORKDIR /app
# 8080 orchestrator and 9000 specialists on AgentCore, 8000 MCP, 8088 Foundry.
EXPOSE 8000 8080 8088 9000
CMD ["sh", "-c", "exec python -m ${TRA_ENTRY}"]
