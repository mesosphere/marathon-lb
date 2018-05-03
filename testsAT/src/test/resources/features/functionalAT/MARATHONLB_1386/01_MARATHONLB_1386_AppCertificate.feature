@rest

Feature: [MARATHONLB-1386] Deploying marathon-lb-sec with an nginx certificate
#Installing marathon-lb-sec with Nginx certificate
  @runOnEnv(INSTALL_MARATHON=true)
  @include(feature:../010_installation.feature,scenario:Install marathon-lb-sec)
  @include(feature:../010_installation.feature,scenario:Obtain node where marathon-lb-sec is running)
  @include(feature:../010_installation.feature,scenario:Make sure service is ready)
  Scenario: Prueba install
    Then I wait '5' seconds

  @skipOnEnv(INSTALL_MARATHON=true)
  @include(feature:../010_installation.feature,scenario:Obtain node where marathon-lb-sec is running)
  Scenario: Prueba install
    Then I wait '5' seconds

#Deploying marathon with an app certificate
  Scenario: Deploying marathon-lb-sec with an nginx certificate
    Given I run 'cat /etc/hosts | grep nginx-qa.labs.stratio.com || echo "!{publicHostIP} nginx-qa.labs.stratio.com" | sudo tee -a /etc/hosts' locally
    Then I open a ssh connection to '${BOOTSTRAP_IP}' with user 'root' and password 'stratio'
    And I outbound copy 'src/test/resources/scripts/marathon-lb-app-certs.sh' through a ssh connection to '/tmp'
    And I run 'cp /stratio_volume/certs.list certs_custom_app_marathonlb.list' in the ssh connection
    And I run 'cd /tmp && sudo chmod +x marathon-lb-app-certs.sh' in the ssh connection
    And I run 'sudo mv /tmp/marathon-lb-app-certs.sh /stratio_volume/marathon-lb-app-certs.sh' in the ssh connection
    And I run 'docker ps | grep eos-installer | awk '{print $1}'' in the ssh connection and save the value in environment variable 'containerId'
    And I run 'sudo docker exec -t !{containerId} /stratio_volume/marathon-lb-app-certs.sh' in the ssh connection
    And I wait '60' seconds
    And I open a ssh connection to '${DCOS_CLI_HOST:-dcos-cli.demo.labs.stratio.com}' with user '${CLI_USER:-root}' and password '${CLI_PASSWORD:-stratio}'
    And I outbound copy 'src/test/resources/schemas/nginx-qa-config.json' through a ssh connection to '/tmp'
    And I run 'dcos marathon app add /tmp/nginx-qa-config.json' in the ssh connection

#Uninstalling marathon

  @include(feature:../purge.feature,scenario:marathon-lb-sec can be uninstalled using cli)
  Scenario: Prueba borrado
  Then I wait '5' seconds