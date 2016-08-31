FROM debian:stretch

COPY requirements.txt /marathon-lb/requirements.txt
COPY build-haproxy.sh /marathon-lb/build-haproxy.sh

RUN set -x \
    && buildDeps=" \
        gcc \
        libc6-dev \
        libffi-dev \
        libpcre3-dev \
        libreadline-dev \
        libssl-dev \
        make \
        python3-dev \
        python3-pip \
        python3-wheel \
        wget \
    " \
    && runDeps=" \
        iptables \
        libpcre3 \
        openssl \
        procps \
        python3 \
        python3-setuptools \
        runit \
        socat \
    " \
    && apt-get update && apt-get install -y --no-install-recommends $buildDeps $runDeps \
    && pip3 install -r /marathon-lb/requirements.txt \
    && rm -rf /root/.cache \
    && /marathon-lb/build-haproxy.sh \
    && apt-get remove -yf $buildDeps \
    && apt-get autoremove -yf \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "/marathon-lb/run" ]

CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091
