FROM debian:stretch

COPY requirements.txt /marathon-lb/requirements.txt
COPY build-haproxy.sh /marathon-lb/build-haproxy.sh

RUN apt-get update && apt-get install -y python3 python3-pip openssl libssl-dev runit procps \
    wget build-essential libpcre3 libpcre3-dev python3-dateutil socat iptables libreadline-dev \
    libffi-dev \
    && pip3 install -r /marathon-lb/requirements.txt \
    && rm -rf /root/.cache \
    && /marathon-lb/build-haproxy.sh \
    && apt-get remove -yf wget libssl-dev build-essential libpcre3-dev libreadline-dev \
    && apt-get autoremove -yf \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY  . /marathon-lb

WORKDIR /marathon-lb

ENTRYPOINT [ "/marathon-lb/run" ]

CMD [ "sse", "--health-check", "--group", "external" ]

EXPOSE 80 443 9090 9091
