FROM python:3.12-alpine

ARG UID=10001
ARG GID=10001
RUN addgroup -g ${GID} -S osint && adduser -u ${UID} -S -D -G osint osint \
    && mkdir -p /app /data \
    && chown -R osint:osint /app /data

WORKDIR /app
COPY --chown=osint:osint pyproject.toml README.md ./
COPY --chown=osint:osint src ./src
RUN pip install --no-cache-dir .

USER osint
ENV PYTHONUNBUFFERED=1 \
    OSINT_TOOLS_HOST=0.0.0.0 \
    OSINT_TOOLS_PORT=8080 \
    OSINT_TOOLS_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
CMD ["python", "-m", "osint_tools.server"]
