# iperf3-Gegenstelle für Bandbreitenmessungen der Probes (Check „Bandbreite intern“ → Wachtl-Server)
ARG ALPINE_VERSION=3.20
FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache iperf3 && adduser -D -H iperf
USER iperf
EXPOSE 5201/tcp 5201/udp
ENTRYPOINT ["iperf3", "-s"]
CMD ["-p", "5201"]
