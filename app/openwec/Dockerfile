# KMU-SIEM – OpenWEC (Windows Event Collector). Läuft als uid 2200, read-only, Host-Netz (5985/tcp).
# Offizielles Release-Paket (cea-sec/openwec), per SHA-256 festgeschrieben.
FROM debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG OPENWEC_VERSION=0.3.0
ARG OPENWEC_DEB_SHA256=8fba1b772a4df5e0e6a83cf968a12e18e2b06f76e70d85ae2049a8c82cc93031
LABEL org.opencontainers.image.source="https://github.com/giti4ge/kmu-siem" \
      org.opencontainers.image.title="kmu-siem-openwec"
RUN apt-get update  && apt-get install -y --no-install-recommends ca-certificates curl  && curl -fsSL -o /tmp/openwec.deb       "https://github.com/cea-sec/openwec/releases/download/v${OPENWEC_VERSION}/openwec_${OPENWEC_VERSION}-1_amd64_deb12.deb"  && echo "${OPENWEC_DEB_SHA256}  /tmp/openwec.deb" | sha256sum -c -  && apt-get install -y --no-install-recommends /tmp/openwec.deb  && rm -f /tmp/openwec.deb  && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*  && command -v openwec && command -v openwecd  && ln -s /etc/openwec/openwec.conf.toml /etc/openwec.conf.toml
COPY entrypoint.sh /usr/local/bin/siem-openwec-entrypoint
RUN chmod 0755 /usr/local/bin/siem-openwec-entrypoint
USER 2200:2100
ENTRYPOINT ["/usr/local/bin/siem-openwec-entrypoint"]
