@rest
Feature: Removing marathon-lb XD

  Background: marathon-lb functional tests
    Given I open a ssh connection to '${DCOS_CLI_HOST}' with user '${DCOS_CLI_USER}' and password '${DCOS_CLI_PASSWORD}'

  Scenario: Remove XD-Viewer marathon-lb
    Given I run 'dcos package uninstall --app-id=crossdata marathon-lb-sec' in the ssh connection with exit status '0'
    Then the command output contains 'Uninstalled package [marathon-lb-sec] version [1.5.1]'
    And the command output contains 'Marathon-lb-sec DC/OS Service has been uninstalled and will no longer run.'
    And in less than '30' seconds, checking each '5' seconds, the command output 'dcos task | grep crossdata | wc -l' contains '0'