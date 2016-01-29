FROM debian:jessie

COPY  . /marathon-lb

RUN apt-get update && apt-get install -y ruby apache2 vim curl ruby-dev build-essential \
    && echo "deb http://debian.datastax.com/community stable main" | tee -a /etc/apt/sources.list.d/cassandra.sources.list \
    && curl -L http://debian.datastax.com/debian/repo_key | apt-key add - \
    && apt-get update && apt-get install -y cassandra \
    && gem install --no-ri --no-rdoc cassandra-driver \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /marathon-lb
