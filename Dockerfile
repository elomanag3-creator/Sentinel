FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_DB=/data/sentinel.db SENTINEL_MODEL=/data/model.npz
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[ml,web]" && mkdir -p /data /etc/sentinel
VOLUME /data
# Runs as root on purpose: reading /etc/shadow and other root-only files is the point of the audit.
ENTRYPOINT ["sentinel"]
CMD ["daemon"]
