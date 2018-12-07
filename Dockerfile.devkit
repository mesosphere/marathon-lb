FROM debian:buster

ENV LANG=C.UTF-8

RUN set -x \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        docker.io \
        gcc \
        git \
        jq \
        libcurl4-openssl-dev \
        libssl-dev \
        python3-dev \
        python3-pip \
        python3-setuptools

COPY requirements-dev.txt /marathon-lb/requirements-dev.txt
COPY requirements.txt /marathon-lb/requirements.txt

# NOTE(jkoelker) dcos-e2e has a large list of strict requrements (== vs >=)
#                that creates conflicts preventing the command line from
#                running. By installing it in its own pip transaction, then
#                allowing subsequent pip to use the existing requirements
#                (no --upgrade or --force-reinstall) the command line is
#                available
RUN set -x \
    && pip3 install \
        --no-cache \
        --upgrade \
        https://github.com/dcos/dcos-e2e/archive/2018.12.10.0.zip \
    && pip3 install \
        --no-cache \
        -r /marathon-lb/requirements-dev.txt

CMD ["/bin/bash"]
