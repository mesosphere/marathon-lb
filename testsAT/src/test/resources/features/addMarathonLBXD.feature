@rest
Feature: Adding marathon-lb XD

  Scenario: Add XD-Viewer marathon-lb
    Given I authenticate to DCOS cluster '${DCOS_IP}' using email '${DCOS_USER}' with user '${REMOTE_USER}' and password '${REMOTE_PASSWORD}'
    And I securely send requests to '${DCOS_IP}:443'
    Given I open a ssh connection to '${BOOTSTRAP_IP}' with user '${REMOTE_USER}' and password '${REMOTE_PASSWORD}'
    And I run 'jq .root_token /stratio_volume/vault_response | sed -e 's/^"//' -e 's/"$//'' in the ssh connection and save the value in environment variable 'token'
    When I send a 'POST' request to '/marathon/v2/apps' based on 'schemas/marathon-lb-XD.json' as 'json' with:
      | $.env.VAULT_HOST | UPDATE | ${VAULT_HOST} |
      | $.env.VAULT_PORT | UPDATE | ${VAULT_PORT} |
      | $.env.VAULT_TOKEN | UPDATE | !{token} |
    Then the service response status must be '201'.
    Given I open a ssh connection to '${DCOS_CLI_HOST}' with user '${DCOS_CLI_USER}' and password '${DCOS_CLI_PASSWORD}'
    When in less than '200' seconds, checking each '20' seconds, the command output 'dcos task | grep crossdata | grep R | wc -l' contains '1'
    And I wait '200' seconds
    And I send a 'GET' request to '/mesos/frameworks'
    Then the service response status must be '200'.
    And I save element '$' in environment variable 'coordinator'
    And 'coordinator' matches the following cases:
      | $.frameworks[?(@.name == "marathon")].tasks[?(@.name == "crossdata")].statuses[*].state           | contains   | TASK_RUNNING          |
