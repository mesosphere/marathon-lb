FROM debian

ENTRYPOINT [ "/marathon-lb/run" ]
CMD        [ "sse", "-m", "http://leader.mesos:8080", "--health-check" ]
EXPOSE     80 443 8080

RUN apt-get update && apt-get install -y python python-pip haproxy openssl runit \
    && pip install requests sseclient \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY  . /marathon-lb
WORKDIR /marathon-lb
