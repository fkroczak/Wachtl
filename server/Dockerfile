FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY wachtl ./wachtl
COPY wsgi.py docker-entrypoint.sh ./

RUN useradd --system --uid 10001 --home /app wachtl \
    && mkdir -p /rules /amconfig \
    && chown wachtl /rules /amconfig \
    && chmod 755 docker-entrypoint.sh
USER wachtl

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["./docker-entrypoint.sh"]
