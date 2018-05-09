@rest
Feature: Installation testing with marathon-lb-sec

  Scenario: Install marathon-lb-sec
    Given I open a ssh connection to '${BOOTSTRAP_IP}' with user '${REMOTE_USER:-operador}' using pem file 'src/test/resources/credentials/${PEM_FILE:-key.pem}'
    And I run 'grep -Po '"root_token":"(\d*?,|.*?[^\\]")' /stratio_volume/vault_response | awk -F":" '{print $2}' | sed -e 's/^"//' -e 's/"$//'' in the ssh connection and save the value in environment variable 'vaultToken'
    And I authenticate to DCOS cluster '${DCOS_IP}' using email '${DCOS_USER:-admin}' with user '${REMOTE_USER:-operador}' and pem file 'src/test/resources/credentials/${PEM_FILE:-key.pem}'
    And I open a ssh connection to '${DCOS_CLI_HOST:-dcos-cli.demo.labs.stratio.com}' with user '${CLI_USER:-root}' and password '${CLI_PASSWORD:-stratio}'
    And I securely send requests to '${DCOS_IP}:443'
    And I create file 'config.json' based on 'schemas/marathon-lb-sec-config.json' as 'json' with:
      | $.marathon-lb.auto-assign-service-ports      | REPLACE | ${AUTO_ASSIGN_SERVICE_PORTS:-false}                                                                                                                                                                 | boolean |
      | $.marathon-lb.bind-http-https                | REPLACE | ${BIND_HTTP_HTTPS:-true}                                                                                                                                                                            | boolean |
      | $.marathon-lb.cpus                           | REPLACE | ${CPUS:-2}                                                                                                                                                                                          | number  |
      | $.marathon-lb.haproxy_global_default_options | UPDATE  | ${HAPROXY_GLOBAL_DEFAULT_OPTIONS:-redispatch,http-server-close,dontlognull}                                                                                                                         | n/a     |
      | $.marathon-lb.haproxy-group                  | UPDATE  | ${HAPROXY_GROUP:-external}                                                                                                                                                                          | n/a     |
      | $.marathon-lb.haproxy-map                    | REPLACE | ${HAPROXY_MAP:-true}                                                                                                                                                                                | boolean |
      | $.marathon-lb.instances                      | REPLACE | ${INSTANCES:-1}                                                                                                                                                                                     | number  |
      | $.marathon-lb.mem                            | REPLACE | ${MEM:-1024.0}                                                                                                                                                                                      | number  |
      | $.marathon-lb.minimumHealthCapacity          | REPLACE | ${MINIMUN_HEALTH_CAPACITY:-0.5}                                                                                                                                                                     | number  |
      | $.marathon-lb.maximumOverCapacity            | REPLACE | ${MAXIMUN_OVER_CAPACITY:-0.2}                                                                                                                                                                       | number  |
      | $.marathon-lb.name                           | UPDATE  | ${SERVICE:-marathon-lb-sec}                                                                                                                                                                         | n/a     |
      | $.marathon-lb.role                           | UPDATE  | ${ROLE:-slave_public}                                                                                                                                                                               | n/a     |
      | $.marathon-lb.strict-mode                    | REPLACE | ${STRICT_MODE:-false}                                                                                                                                                                               | boolean |
      | $.marathon-lb.sysctl-params                  | UPDATE  | ${SYSCTL_PARAMS:-net.ipv4.tcp_tw_reuse=1 net.ipv4.tcp_fin_timeout=30 net.ipv4.tcp_max_syn_backlog=10240 net.ipv4.tcp_max_tw_buckets=400000 net.ipv4.tcp_max_orphans=60000 net.core.somaxconn=10000} | n/a     |
      | $.marathon-lb.marathon-uri                   | UPDATE  | ${MARATHON_URI:-http://marathon.mesos:8080}                                                                                                                                                         | n/a     |
      | $.marathon-lb.vault_host                     | UPDATE  | ${VAULT_HOST:-vault.service.paas.labs.stratio.com}                                                                                                                                                  | n/a     |
      | $.marathon-lb.vault_port                     | REPLACE | ${VAULT_PORT:-8200}                                                                                                                                                                                 | number  |
      | $.marathon-lb.use_dynamic_authentication     | REPLACE | ${USE_DYNAMIC_AUTHENTICATION:-true}                                                                                                                                                                 | boolean |
      | $.marathon-lb.vault_token                    | UPDATE  | !{vaultToken}                                                                                                                                                                                       | n/a     |
      | $.marathon-lb.instance_app_role              | UPDATE  | ${INSTANCE_APP_ROLE:-open}                                                                                                                                                                          | n/a     |

    And I outbound copy 'target/test-classes/config.json' through a ssh connection to '/tmp'
    When I run 'dcos package install --yes --app --options=/tmp/config.json ${PACKAGE:-marathon-lb-sec}' in the ssh connection
    Then the command output contains 'Marathon-lb DC/OS Service has been successfully installed!'
    And in less than '300' seconds, checking each '20' seconds, the command output 'dcos task | grep -w ${SERVICE:-marathon-lb-sec}. | wc -l' contains '1'
    When I run 'dcos marathon task list ${SERVICE:-marathon-lb-sec} | awk '{print $5}' | grep ${SERVICE:-marathon-lb-sec}' in the ssh connection and save the value in environment variable 'marathonTaskId'
    # DCOS dcos marathon task show check healtcheck status
    Then in less than '300' seconds, checking each '10' seconds, the command output 'dcos marathon task show !{marathonTaskId} | grep TASK_RUNNING | wc -l' contains '1'
    And in less than '300' seconds, checking each '10' seconds, the command output 'dcos marathon task show !{marathonTaskId} | grep '"alive": true' | wc -l' contains '1'

  Scenario: Obtain node where marathon-lb-sec is running
    Given I open a ssh connection to '${DCOS_CLI_HOST:-dcos-cli.demo.labs.stratio.com}' with user '${CLI_USER:-root}' and password '${CLI_PASSWORD:-stratio}'
    When I run 'dcos task | grep ${SERVICE:-marathon-lb-sec}. | awk '{print $2}'' in the ssh connection and save the value in environment variable 'publicHostIP'

  Scenario: Make sure service is ready
    Given I send requests to '!{publicHostIP}:9090'
    When I send a 'GET' request to '/_haproxy_health_check'
    Then the service response status must be '200'

