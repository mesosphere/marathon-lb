FROM debian:stretch

# runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        openssl \
        procps \
        python3 \
        runit \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt build-haproxy.sh \
    /marathon-lb/

RUN set -x \
    && buildDeps=' \
        gcc \
        libc6-dev \
        libffi-dev \
        libpcre3-dev \
        libreadline-dev \
        libssl1.0-dev \
        zlib1g-dev \
        make \
        python3-dev \
        python3-pip \
        python3-setuptools \
        wget \
    ' \
    && apt-get update \
        && apt-get install -y --no-install-recommends $buildDeps \
        && rm -rf /var/lib/apt/lists/* \
# Install Python packages with --upgrade so we get new packages even if a system
# package is already installed. Combine with --force-reinstall to ensure we get
# a local package even if the system package is up-to-date as the system package
# will probably be uninstalled with the build dependencies.
    && pip3 install --no-cache --upgrade --force-reinstall -r /marathon-lb/requirements.txt \
    && /marathon-lb/build-haproxy.sh \
    && wget -O - https://github.com/prometheus/haproxy_exporter/releases/download/v0.7.1/haproxy_exporter-0.7.1.linux-amd64.tar.gz | tar zxf - \
    && mv haproxy_exporter-0.7.1.linux-amd64/haproxy_exporter /marathon-lb/haproxy_exporter \
    && rm -rf haproxy_exporter-0.7.1.linux-amd64 \
    && apt-get purge -y --auto-remove $buildDeps

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "/marathon-lb/run" ]

CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091 9101
