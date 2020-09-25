#!/bin/bash

# Do not fail upon error
set -exo pipefail

if [ "$(uname)" = "Linux" ]; then
    CLI_OS="linux"
elif [ "$(uname)" = "Darwin" ]; then
    CLI_OS="darwin"
fi


export CLUSTER_URL=${CLUSTER_URL:="uninitialized"}
export PUBLIC_AGENT_IP=${PUBLIC_AGENT_IP:="uninitialized"}

DCOS_USERNAME=${DCOS_USERNAME:="bootstrapuser"}
DCOS_PASSWORD=${DCOS_PASSWORD:="deleteme"}

TERRAFORM_VERSION=${TERRAFORM_VERSION:="0.11.14"}
TERRAFORM_ZIP="terraform_${TERRAFORM_VERSION}_${CLI_OS}_amd64.zip"
TERRAFORM_PATH="${TERRAFORM_VERSION}/${TERRAFORM_ZIP}"
TERRAFORM_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_PATH}"

DCOS_IO="https://downloads.dcos.io"
MESOSPHERE="https://downloads.mesosphere.com"
OSS_MASTER_PATH="testing/master/dcos_generate_config.sh"
EE_MASTER_PATH="testing/master/dcos_generate_config.ee.sh"
OSS_MASTER_URL="${DCOS_IO}/dcos/${OSS_MASTER_PATH}"
EE_MASTER_URL="${MESOSPHERE}/dcos-enterprise/${EE_MASTER_PATH}"

GIT_SHA_10=$(echo "$GIT_COMMIT" | cut -c 1-10)

DOCKER_IMAGE="mesosphere/marathon-lb-dev:$GIT_SHA_10"
echo "DOCKER_IMAGE=$DOCKER_IMAGE"

MLB_VERSION="dev-$GIT_SHA_10"
echo "MLB_VERSION=$MLB_VERSION"

WORKING_DIRECTORY=$(pwd)


status_line() {
    printf "\n### %s ###\n\n" "$1"
}


# Downloading CLI.
download_dcos_cli() {
    curl --output "bin/dcos" \
        "${DCOS_IO}/cli/releases/binaries/dcos/${CLI_OS}/x86-64/latest/dcos"
    chmod +x bin/dcos

    dcos
}


download_tf_cli() {
    if [ "${CLUSTER_URL}" == "uninitialized" ]; then
        curl --output terraform.zip "${TERRAFORM_URL}"
        unzip -o -d ./bin terraform.zip
        chmod +x bin/terraform
    fi
}


download_cli() {
    mkdir -p bin
    PATH="$(pwd)/bin:${PATH}"
    export PATH

    download_dcos_cli
    download_tf_cli
}


# Launching cluster using dcos-launch.
launch_cluster() {
    status_line "Launching cluster."

    if [ "${CLUSTER_URL}" != "uninitialized" ]; then
        echo "Using provided CLUSTER_URL as cluster: ${CLUSTER_URL}"
        return
    fi

    echo "CLUSTER_URL is empty/unset, launching new cluster."

    local _variant
    if [ "${VARIANT}" == 'open' ]; then
        _variant="  dcos_variant                 = \"open\""
    elif [ "${VARIANT}" == 'ee' ]; then
        _variant="\
  dcos_variant                 = \"ee\"
  dcos_security                = \"permissive\"
  dcos_license_key_contents    = \"${DCOS_LICENSE}\""
    fi

    local _version
    if [ "${DCOS_VERSION}" == 'master' ]; then
        if [ "${VARIANT}" == 'open' ]; then
            _version="  custom_dcos_download_path = \"${OSS_MASTER_URL}\""
        elif [ "${VARIANT}" == 'ee' ]; then
            _version="  custom_dcos_download_path = \"${EE_MASTER_URL}\""
        fi
    else
        _version="  dcos_version              = \"${DCOS_VERSION}\""
    fi

    echo "Generating SSH keypair 'cluster-key'."
    < /dev/zero ssh-keygen -b 2048 -t rsa -f cluster-key -q -N '' || true
    ssh-add cluster-key

    echo "Generating terraform config."
    envsubst <<EOF > main.tf
provider "aws" {
  region = "us-west-2"
}
data "http" "whatismyip" {
  url = "http://whatismyip.akamai.com/"
}
module "dcos" {
  source  = "dcos-terraform/dcos/aws"
  version = "~> 0.2.0"
  providers = {
    aws = "aws"
  }
  cluster_name                   = "mlb-${VARIANT}"
  cluster_name_random_string     = true
  ssh_public_key_file            = "cluster-key.pub"
  admin_ips                      = ["\${data.http.whatismyip.body}/32"]
  num_masters                    = 1
  num_private_agents             = 1
  num_public_agents              = 1
  dcos_instance_os               = "centos_7.6"
  bootstrap_instance_type        = "t2.medium"
  masters_instance_type          = "m5.xlarge"
  private_agents_instance_type   = "m5.xlarge"
  public_agents_instance_type    = "m5.xlarge"
  public_agents_additional_ports = [ 81 ]
  public_agents_allow_registered = true
  public_agents_allow_dynamic    = true
  tags = {
    "expiration" = "1h"
    "owner" = "jenkins-mlb"
   }
${_version}
${_variant}
}
output "cluster-url" {
  value = "https://\${module.dcos.masters-loadbalancer}"
}
output "public-ip" {
  value = "\${module.dcos.infrastructure.public_agents.public_ips[0]}"
}
EOF

    pushd "${WORKING_DIRECTORY}"
    terraform init
    terraform plan -out=plan.out
    time terraform apply plan.out
    CLUSTER_URL="$(terraform output cluster-url)"
    PUBLIC_AGENT_IP="$(terraform output public-ip)"
    popd

    echo "CLUSTER_URL=${CLUSTER_URL}"
    echo "PUBLIC_AGENT_IP=${PUBLIC_AGENT_IP}"
}


# Setting up cluster.
configure_cluster() {
    status_line "Configuring cluster."

    if [ "${VARIANT}" == 'open' ]; then
        oss_authentication
    else
        enterprise_authentication
    fi
}


oss_authentication() {
    echo "Removing old clusters."
    dcos cluster remove --all

cat <<EOF | expect -
spawn dcos cluster setup --provider=dcos-oidc-auth0 --insecure "${CLUSTER_URL}"
expect "Enter OpenID Connect ID Token:"
send "${DCOS_OAUTH_TOKEN}\n"
expect eof
EOF

echo "Verifying cluster authentication:"
dcos config show
}


enterprise_authentication() {
    echo "Removing old clusters."
    dcos cluster remove --all

    echo "Authenticating"
    dcos cluster setup \
        --no-check \
        --insecure \
        --username "${DCOS_USERNAME}" \
        --password "${DCOS_PASSWORD}" \
        "${CLUSTER_URL}"

    echo "Verifying cluster authentication:"
    dcos cluster list
}


# cd into MLB directory.
change_into_mlb_dir() {
    status_line "Changing into cloned MLB directory."
    cd dcos-marathon-lb
}


# Building docker image based on git SHA.
docker_build() {
    status_line "Building docker image."
    docker build -t "${DOCKER_IMAGE}" .
}


# Logging into Mesosphere docker account.
docker_login() {
    status_line "Logging into Mesosphere docker account."
    docker login -u "${DOCKER_HUB_USERNAME}" -p "${DOCKER_HUB_PASSWORD}"
}


# Pushing docker image to mesosphere/marathon-lb-dev.
docker_push() {
    status_line "Pushing docker image."
    docker push "${DOCKER_IMAGE}"
}


# Launching MLB through docker image.
launch_marathonlb() {
    status_line "Launching Marathon-lb"

    echo "Retrieving authentication token for cluster."
    AUTH_TOKEN=$(dcos config show core.dcos_acs_token)

    MLB_OPTIONS_JSON="mlb-options.json"
    RENDER_RESPONSE_JSON="response.json"
    MLB_JSON="mlb.json"

    # Strict mode requires having a service account.
    if [ "${SECURITY_MODE}" == 'strict' ]; then
        echo "Installing DC/OS Enterprise CLI."
        dcos package install dcos-enterprise-cli --yes

        echo "Creating a key pair."
        dcos security org service-accounts keypair \
            mlb-private-key.pem \
            mlb-public-key.pem

        echo "Creating a service account: mlb-principal."
        dcos security org service-accounts create \
            -p mlb-public-key.pem \
            -d "Marathon-LB service account" \
            mlb-principal || true

        echo "Verifying service account creation:"
        dcos security org service-accounts show mlb-principal

        echo "Adding mlb-principal as a superuser."
        dcos security org groups add_user superusers mlb-principal

        echo "Creating new secret: mlb-secret."
        dcos security secrets create-sa-secret \
            --strict mlb-private-key.pem \
            mlb-principal mlb-secret || true

        echo "Verfiying secret creation:"
        dcos security secrets list /

tee $MLB_OPTIONS_JSON <<EOF
{
    "marathon-lb": {
        "secret_name": "mlb-secret",
        "marathon-uri": "https://master.mesos:8443",
        "strict-mode": true
    }
}
EOF
        dcos package describe marathon-lb \
            --app \
            --render \
            --options="${MLB_OPTIONS_JSON}" > "${RENDER_RESPONSE_JSON}"

        local _cluster_url
        _cluster_url="$(dcos config show core.dcos_url)"

        # Giving root permissions to dcos_marathon service account.
        echo "Giving root permissions to dcos_marathon service account."
        local _acl
        _acl="dcos:mesos:master:task:user:root"
        curl -X PUT -k \
            -H "Authorization: token=$(dcos config show core.dcos_acs_token)" \
            -H "Content-Type: application/json" \
            -d '{"description":"dcos:mesos:master:task:user:root"}' \
            "${_cluster_url}/acs/api/v1/acls/${_acl}"

        curl -X PUT -k \
            -H "Authorization: token=$(dcos config show core.dcos_acs_token)" \
            -H "Content-Type: application/json" \
            -d '{"description":"dcos:mesos:master:task:user:root"}' \
            "${_cluster_url}/acs/api/v1/acls/${_acl}/users/dcos_marathon/full"

    else
        dcos package describe marathon-lb \
            --app \
            --render > "${RENDER_RESPONSE_JSON}"
    fi

    local _image_filter
    # shellcheck disable=SC2016
    _image_filter='.container.docker.image=$DOCKER_IMAGE'

    local _package_filter
    # shellcheck disable=SC2016
    _package_filter='.labels.DCOS_PACKAGE_VERSION=$MLB_VERSION'

    jq \
        --arg DOCKER_IMAGE "${DOCKER_IMAGE}" \
        --arg MLB_VERSION "${MLB_VERSION}" \
        "${_image_filter} | ${_package_filter}" \
        < "${RENDER_RESPONSE_JSON}" > "${MLB_JSON}"
    cat "${RENDER_RESPONSE_JSON}" > "${MLB_JSON}"
    cat "${MLB_JSON}"

    echo "Launching Marathon-lb."
    dcos marathon app add "${MLB_JSON}"

    # Sleeping to wait for MLB to deploy.
    until ! dcos marathon deployment list > /dev/null 2>&1; do
        sleep 1
    done

    # Verify that MLB deployed healthy.
    check_marathonlb_health "${AUTH_TOKEN}"
}


# Verify MLB launched healthy.
check_marathonlb_health() {
    local _response_file
    _response_file="curl_response.json"

    local _auth_header
    _auth_header="Authorization: token=${1}"

    local _cluster_url
    _cluster_url="$(dcos config show core.dcos_url)"

    local _mlb_url
    _mlb_url="${_cluster_url/}/service/marathon/v2/apps/marathon-lb"

    local _code
    _code=$(curl -X GET -s -k -o ${_response_file} \
            -H "$_auth_header" \
            -w "%{http_code}" \
            -H "Accept: application/json" \
            "${_mlb_url}")

    local _healthy_tasks
    local _instances
    _healthy_tasks=$(jq -r '.app.tasksHealthy' < "${_response_file}")
    _instances=$(jq -r '.app.instances' < "${_response_file}")

    if [[ "${_code}" -eq "200" ]] && \
            [[ "${_healthy_tasks}" -eq "${_instances}" ]]; then
        echo
        echo "Marathon-lb launched healthy."
        echo
    else
        echo
        echo "Marathon-lb failed to launch healthy."

        status_line "Marathon-lb stdout:"
        dcos task log marathon-lb stdout --lines=50

        status_line "Marathon-lb stderr:"
        dcos task log marathon-lb stderr --lines=50

        exit 1
    fi
}


run_integration_tests() {
    status_line "Running integration tests."

    cd ci/
    pytest -s -vv test_marathon_lb.py
}


delete_cluster() {
    pushd "${WORKING_DIRECTORY}"
    if [ -f main.tf ]; then
        status_line "Deleting cluster."
        time terraform destroy --auto-approve
    fi
    popd
}


trap delete_cluster EXIT


# Launching cluster through terraform & setting up the CLI.
download_cli
launch_cluster

# Wait 10 seconds after to allow the cluster launch to settle
sleep 10
configure_cluster

# Building MLB Docker image.
change_into_mlb_dir
docker_build
docker_login
docker_push

# Launching MLB and running integration tests.
launch_marathonlb
run_integration_tests
