@rest
Feature: [QATM-100]Adding marathon-lb Default

  Scenario: [QATM-100]Add Default marathon-lb
    Given I authenticate to DCOS cluster '${DCOS_IP}' using email '${DCOS_USER}' with user '${REMOTE_USER}' and password '${REMOTE_PASSWORD}'
    And I securely send requests to '${DCOS_IP}:443'
    Given I open a ssh connection to '${BOOTSTRAP_IP}' with user '${REMOTE_USER}' and password '${REMOTE_PASSWORD}'
    And I run 'jq .root_token /stratio_volume/vault_response | sed -e 's/^"//' -e 's/"$//'' in the ssh connection and save the value in environment variable 'token'
    When I send a 'POST' request to '/marathon/v2/apps' based on 'schemas/marathon-lb-Default.json' as 'json' with:
    | $.env.VAULT_HOST | UPDATE | ${VAULT_HOST} |
    | $.env.VAULT_PORT | UPDATE | ${VAULT_PORT} |
    | $.env.VAULT_TOKEN | UPDATE | !{token} |
    Then the service response status must be '201'.
    Given I open a ssh connection to '${DCOS_CLI_HOST}' with user '${DCOS_CLI_USER}' and password '${DCOS_CLI_PASSWORD}'
    Then in less than '300' seconds, checking each '20' seconds, the command output 'dcos task | grep marathon-lb-sec | grep R | wc -l' contains '1'
    #Find task-id if from DCOS-CLI
    And in less than '300' seconds, checking each '20' seconds, the command output 'dcos marathon task list marathon-lb-sec | grep marathon-lb-sec | awk '{print $2}'' contains 'True'
    And I run 'dcos marathon task list marathon-lb-sec | awk '{print $5}' | grep marathon-lb-sec' in the ssh connection and save the value in environment variable 'marathonTaskId'
    #DCOS dcos marathon task show check healtcheck status
    Then in less than '300' seconds, checking each '10' seconds, the command output 'dcos marathon task show !{marathonTaskId} | grep TASK_RUNNING | wc -l' contains '1'
    Then in less than '300' seconds, checking each '10' seconds, the command output 'dcos marathon task show !{marathonTaskId} | grep healthCheckResults | wc -l' contains '1'
    Then in less than '300' seconds, checking each '10' seconds, the command output 'dcos marathon task show !{marathonTaskId} | grep  '"alive": true' | wc -l' contains '1'