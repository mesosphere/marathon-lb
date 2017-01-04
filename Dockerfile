FROM debian:stretch

# runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        procps \
        python3 \
        runit \
        socat \
    && rm -rf /var/lib/apt/lists/*

ENV TINI_VERSION=v0.13.1 \
    TINI_GPG_KEY=595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7
RUN set -x \
    && apt-get update && apt-get install -y --no-install-recommends dirmngr gpg wget \
        && rm -rf /var/lib/apt/lists/* \
    && wget -O tini "https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini-amd64" \
    && wget -O tini.asc "https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini-amd64.asc" \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$TINI_GPG_KEY" \
    && gpg --batch --verify tini.asc tini \
    && rm -r "$GNUPGHOME" tini.asc \
    && mv tini /usr/bin/tini \
    && chmod +x /usr/bin/tini \
    && tini -- true \
    && apt-get purge -y --auto-remove dirmngr gpg wget

COPY requirements.txt build-haproxy.sh \
    /marathon-lb/

RUN set -x \
    && buildDeps=' \
        gcc \
        libc6-dev \
        libffi-dev \
        libpcre3-dev \
        libreadline-dev \
        libssl-dev \
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
    && apt-get purge -y --auto-remove $buildDeps

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "tini", "-g", "--", "/marathon-lb/run" ]
CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091
