# "Developer workstation" image that runs untrusted commands under gVisor (docs/ARCHITECTURE.md 5.2).
# HOME is a tmpfs seeded per run from /seed; nothing in this image is secret.
FROM ubuntu:24.04

ARG INSTALL_PWSH=0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash dash zsh coreutils procps file less ca-certificates curl wget git jq openssl \
      python3 nodejs npm tar gzip bzip2 xz-utils unzip zip netcat-openbsd iproute2 \
 && rm -rf /var/lib/apt/lists/*

# PowerShell is only needed for the harness loop on PowerShell layers (behind the cut line, 14.3).
RUN if [ "$INSTALL_PWSH" = "1" ]; then \
      curl -fsSL -o /tmp/ms.deb https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb \
      && dpkg -i /tmp/ms.deb && rm /tmp/ms.deb \
      && apt-get update && apt-get install -y --no-install-recommends powershell \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY build/firstrun-test-ca.crt /usr/local/share/ca-certificates/firstrun-test-ca.crt
RUN update-ca-certificates

# ubuntu:24.04 already has uid 1000 "ubuntu"; the decoy workstation user is "dev".
RUN (userdel -r ubuntu 2>/dev/null || true) && useradd -u 1000 -s /bin/bash -M -d /home/dev dev

COPY shims/ /opt/firstrun/shims/
COPY fast/ /opt/firstrun/fast/
COPY entry.sh launch /opt/firstrun/
RUN cd /opt/firstrun/shims \
 && while read -r name; do [ -z "$name" ] || ln -sf _shim "$name"; done < names.txt \
 && rm names.txt \
 && chmod 0755 /opt/firstrun/shims/_shim /opt/firstrun/entry.sh /opt/firstrun/launch /opt/firstrun/fast/sleep

WORKDIR /home/dev
USER 1000:1000
ENTRYPOINT ["/opt/firstrun/entry.sh"]
