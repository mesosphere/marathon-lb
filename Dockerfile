FROM debian:stretch

# runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        openssl \
        libssl1.0.2 \
        procps \
        python3 \
        runit \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt build-haproxy.sh \
    /marathon-lb/

ENV TINI_VERSION v0.13.1
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini.asc /tini.asc

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
        gpg \
        dirmngr \
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
    && gpg --keyserver ha.pool.sks-keyservers.net --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 \
    && gpg --verify /tini.asc \
    && chmod +x /tini \
    && apt-get purge -y --auto-remove $buildDeps

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "/tini", "-g", "--", "/marathon-lb/run" ]
CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091
