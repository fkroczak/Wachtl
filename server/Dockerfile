FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# ping und iperf3 für die Server-Probe (der Server misst selbst, Dienst "serverprobe")
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY wachtl ./wachtl
COPY wsgi.py docker-entrypoint.sh ./

RUN useradd --system --uid 10001 --home /app wachtl \
    && mkdir -p /rules /amconfig /serverprobe \
    && chown wachtl /rules /amconfig /serverprobe \
    && chmod 700 /serverprobe \
    && chmod 755 docker-entrypoint.sh
USER wachtl

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["./docker-entrypoint.sh"]
