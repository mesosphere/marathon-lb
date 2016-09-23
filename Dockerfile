FROM debian:stretch

# runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        openssl \
        procps \
        python3 \
        python3-setuptools \
        runit \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /marathon-lb/requirements.txt
COPY build-haproxy.sh /marathon-lb/build-haproxy.sh

RUN set -x \
    && buildDeps=' \
        gcc \
        libc6-dev \
        libffi-dev \
        libpcre3-dev \
        libreadline-dev \
        libssl-dev \
        make \
        python3-dev \
        python3-pip \
        wget \
    ' \
    && apt-get update \
        && apt-get install -y --no-install-recommends $buildDeps \
        && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache -r /marathon-lb/requirements.txt \
    && /marathon-lb/build-haproxy.sh \
    && apt-get purge -y --auto-remove $buildDeps

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "/marathon-lb/run" ]

CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091
