# Sinkhole: answers every DNS name with its own address, terminates TLS with the throwaway test CA,
# records every request and never connects anywhere (docs/ARCHITECTURE.md section 6).
# Verify the tag exists on Docker Hub on day 1; any recent mitmproxy release with gosu works.
ARG MITMPROXY_VERSION=12.1.1
FROM mitmproxy/mitmproxy:${MITMPROXY_VERSION}

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends dnsmasq-base iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=mitmproxy:mitmproxy ca/mitmproxy-ca.pem /opt/firstrun/ca/mitmproxy-ca.pem
COPY addon/ /opt/firstrun/addon/
COPY canned/ /opt/firstrun/canned/
COPY tcpsink.py entrypoint.sh /opt/firstrun/
RUN chmod 0400 /opt/firstrun/ca/mitmproxy-ca.pem \
 && chmod 0755 /opt/firstrun/entrypoint.sh /opt/firstrun/tcpsink.py

ENTRYPOINT ["/opt/firstrun/entrypoint.sh"]
