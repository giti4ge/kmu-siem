# KMU-SIEM Control-Plane (API). Läuft als uid 2100, read-only, im Host-Netz auf 127.0.0.1:8000.
FROM python:3.12-slim-trixie AS build
WORKDIR /src
COPY pyproject.toml ./
COPY siem_api ./siem_api
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim-trixie
LABEL org.opencontainers.image.source="https://github.com/giti4ge/kmu-siem" \
      org.opencontainers.image.title="kmu-siem-api"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SIEM_DB_URL=sqlite:////data/config-db/siem.db \
    SIEM_SECRETS_DIR=/data/secrets
COPY --from=build /install /usr/local
USER 2100:2100
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]
CMD ["uvicorn", "siem_api.main:app", "--host", "127.0.0.1", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-server-header"]
