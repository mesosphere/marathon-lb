FROM debian

ENTRYPOINT [ "/marathon-lb/run" ]
CMD        [ "sse", "-m", "http://leader.mesos:8080", "--health-check", "--group", "external" ]
EXPOSE     80 443 8080

RUN apt-get update && apt-get install -y python3 python3-pip haproxy openssl runit \
    && pip3 install requests sseclient \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY  . /marathon-lb
WORKDIR /marathon-lb
