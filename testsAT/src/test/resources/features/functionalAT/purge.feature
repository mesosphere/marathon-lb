@rest
Feature: Uninstalling marathon-lb-sec

  Scenario: marathon-lb-sec can be uninstalled using cli
    Given I open a ssh connection to '${DCOS_CLI_HOST:-dcos-cli.demo.labs.stratio.com}' with user '${CLI_USER:-root}' and password '${CLI_PASSWORD:-stratio}'
    When I run 'dcos package uninstall --app-id=/${SERVICE:-marathon-lb-sec} ${PACKAGE:-marathon-lb-sec}' in the ssh connection
    Then the command output contains 'Marathon-lb DC/OS Service has been uninstalled and will no longer run.'
    Then in less than '300' seconds, checking each '20' seconds, the command output 'dcos task | grep ${PACKAGE:-marathon-lb-sec} | wc -l' contains '0'
