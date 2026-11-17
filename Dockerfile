# STIG Explorer - searchable DISA STIG configurations with 3-level explanations
# For a reproducible release build, override with a verified digest, e.g.
# --build-arg PYTHON_BASE_IMAGE=python:3.12-slim-bookworm@sha256:<approved-manifest-digest>
ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STIGX_HOST=0.0.0.0 \
    STIGX_PORT=8080

WORKDIR /app

# The runtime server uses only Python's standard library. Do not install
# python-docx (or its native transitive dependencies) into the service image.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin stigx

COPY stig_explorer/ ./stig_explorer/
COPY web/ ./web/

# Data is baked into the image; to refresh, rebuild data on the host
# (python -m stig_explorer.build --fetch) and then rebuild the image.
RUN mkdir -p data/raw docs && chown -R stigx:stigx /app/data /app/docs

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "stig_explorer.server"]
