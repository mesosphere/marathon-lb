#!/usr/bin/env ruby

# Note: before you run this test, make sure you set:
#   sysctl -w net.ipv4.tcp_max_syn_backlog=20000
# To make sure that all the TCP connections are retried correctly.

require 'cassandra'
require 'securerandom'

output = `ab -r -s 60 -c 1000 -n 50000 http://marathon-lb.marathon.mesos:10000/`
exit_code = $?.to_i
puts output

CASSANDRA_HOSTS = ['cassandra-dcos-node.cassandra.dcos.mesos']
CASSANDRA_PORT = 9042

cluster = Cassandra.cluster(hosts: CASSANDRA_HOSTS, port: CASSANDRA_PORT)

session = cluster.connect

session.execute("CREATE KEYSPACE IF NOT EXISTS " +
                "benchmark WITH REPLICATION = " +
                "{ 'class' : 'SimpleStrategy', 'replication_factor' : 1 }")
session.execute("USE benchmark")

session.execute("CREATE TABLE IF NOT EXISTS results (" +
                "id uuid PRIMARY KEY," +
                "ts timestamp," +
                "req_completed int," +
                "req_failed int," +
                "non_2xxresponses int," +
                "failed_on_connect int," +
                "failed_on_receive int," +
                "failed_on_length int," +
                "failed_on_exception int," +
                "ab_exit_code int)"
)

lines = output.split(/\r?\n/)

result = {
  :req_completed => 0,
  :req_failed => 0,
  :non_2xxresponses => 0,
  :failed_on_connect => 0,
  :failed_on_receive => 0,
  :failed_on_length => 0,
  :failed_on_exception => 0,
  :ab_exit_code => 0,
}

result[:ab_exit_code] = exit_code

lines.each do |line|
  /Complete requests:\s+(\d+)/.match(line) do |m|
    result[:req_completed] = m[1].to_i
  end
  /Failed requests:\s+(\d+)/.match(line) do |m|
    result[:req_failed] = m[1].to_i
  end
  /Connect: (\d+), Receive: (\d+), Length: (\d+), Exceptions: (\d+)/.match(line) do |m|
    result[:failed_on_connect] = m[1].to_i
    result[:failed_on_receive] = m[2].to_i
    result[:failed_on_length] = m[3].to_i
    result[:failed_on_exception] = m[4].to_i
  end
  /Failed requests:\s+(\d+)/.match(line) do |m|
    result[:req_failed] = m[1].to_i
  end
end

statement = session.prepare('INSERT INTO results ' +
                            '(id, ts, req_completed, req_failed, non_2xxresponses,' +
                            ' failed_on_connect, failed_on_receive,' +
                            ' failed_on_length, failed_on_exception, ab_exit_code)' +
                            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')

session.execute(statement, arguments: [
  Cassandra::Uuid::Generator.new.uuid,
  Time.now,
  result[:req_completed],
  result[:req_failed],
  result[:non_2xxresponses],
  result[:failed_on_connect],
  result[:failed_on_receive],
  result[:failed_on_length],
  result[:failed_on_exception],
  result[:ab_exit_code],
])

session.close

exit exit_code
