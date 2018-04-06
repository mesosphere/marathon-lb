#!/bin/bash

# Do not fail upon error
set +eo pipefail

export LC_ALL="en_US.UTF-8"

export CLUSTER_URL=${CLUSTER_URL:="uninitialized"}
export PUBLIC_AGENT_IP=${PUBLIC_AGENT_IP:="uninitialized"}

DCOS_USERNAME=${DCOS_USERNAME:="bootstrapuser"}
DCOS_PASSWORD=${DCOS_PASSWORD:="deleteme"}

GIT_SHA_10=$(echo $GIT_COMMIT | cut -c 1-10)

DOCKER_IMAGE="mesosphere/marathon-lb-dev:$GIT_SHA_10"
echo "DOCKER_IMAGE=$DOCKER_IMAGE"

MLB_VERSION="dev-$GIT_SHA_10"
echo "MLB_VERSION=$MLB_VERSION"

WORKING_DIRECTORY=$(pwd)


status_line() {
    printf "\n### $1 ###\n\n"
}


random_string() {
    num_chars=$1

    # Use a subshell so that the `set` commands do not pollute the parent shell
    (
        set +e +o pipefail

        # Warning: this will error out on linux if set -o pipefail and set -e
        # LC_CTYPE=C is needed on macOS
        random_id=$(cat /dev/urandom | LC_CTYPE=C tr -dc 'a-z0-9' | fold -w "$num_chars" | head -n 1)
        echo "$random_id"
    )
}


cluster_ids() {
    # dcos cluster command was added into the CLI starting in DC/OS 1.10
    if [ "${DCOS_VERSION}" != '1.9' ]; then 
        if ! dcos cluster list >/dev/null 2>&1; then
            return
        fi

        dcos cluster list | tail -n +2 | tr -s ' ' | sed -e "s/^ *//" |  cut -d' ' -f2
    fi
}


wrapped_dcos_launch() {
    # Use a subshell so `cd` doesn't pollute the environment
    (
        cd "$WORKING_DIRECTORY"
        ./dcos-launch $@
    )
}


# Setting DC/OS template.
dcos_template() {
    if [ "${VARIANT}" == 'open' ]; then
        template_url="http://s3.amazonaws.com/downloads.dcos.io/dcos/testing/${DCOS_VERSION}/cloudformation/single-master.cloudformation.json"
    elif [ "${VARIANT}" == 'ee' ]; then
        template_url="http://s3.amazonaws.com/downloads.mesosphere.io/dcos-enterprise-aws-advanced/testing/${DCOS_VERSION}/${SECURITY_MODE}/cloudformation/ee.single-master.cloudformation.json"
    fi

    echo "$template_url"
}


# Downloading CLI.
download_cli() {
    if [ "$(uname)" = "Linux" ]; then
        local _cli_os="linux"
    elif [ "$(uname)" = "Darwin" ]; then
        local _cli_os="darwin"
    fi

    if [ "${DCOS_VERSION}" == 'master' ]; then
        local cli_version="dcos-1.12"
    else
        local cli_version="dcos-${DCOS_VERSION}"
    fi

    mkdir bin
    export PATH=$PATH:$(pwd)/bin

    curl -O "https://downloads.dcos.io/binaries/cli/${_cli_os}/x86-64/${cli_version}/dcos"

    mv "dcos" "bin/dcos"
    chmod +x "bin/dcos"

    dcos
}


# Launching cluster using dcos-launch.
launch_cluster() {
    status_line "Launching cluster."

    if [ "$CLUSTER_URL" != "uninitialized" ]; then
        echo "Using provided CLUSTER_URL as cluster: $CLUSTER_URL"
        return
    fi

    wget 'https://downloads.dcos.io/dcos/testing/master/dcos-launch' && chmod +x dcos-launch

    echo "CLUSTER_URL is empty/unset, launching new cluster."

    random_id="$(random_string 10)"
    dcos_template_url="$(dcos_template)"

    echo "DC/OS Template:"
    echo $dcos_template_url

    envsubst <<EOF > config.yaml
---
launch_config_version: 1
template_url: $dcos_template_url
deployment_name: dcos-ci-test-marathon-lb-$random_id
provider: aws
aws_region: us-west-2
aws_access_key_id: ${AWS_ACCESS_KEY_ID}
aws_secret_access_key: ${AWS_SECRET_ACCESS_KEY}
ssh_user: core
template_parameters:
    KeyName: default
    AdminLocation: 0.0.0.0/0
    PublicSlaveInstanceCount: 1
    SlaveInstanceCount: 1
EOF
    
    # DefaultInstanceType parameter has not been backported into 1.9 CF templates.
    # The templates actually hardcode in this parameter instead.
    if [ "${DCOS_VERSION}" != '1.9' ]; then
        echo "    DefaultInstanceType: m4.large" >> config.yaml
    fi

    if [ "${VARIANT}" == 'ee' ]; then
        if [ "${DCOS_VERSION}" == '1.11' ] || [ "${DCOS_VERSION}" == 'master' ]; then
            echo "    LicenseKey: ${DCOS_LICENSE}" >> config.yaml
        fi
    fi

    time wrapped_dcos_launch create
    time wrapped_dcos_launch wait
    wrapped_dcos_launch describe

    CLUSTER_URL=http://$(wrapped_dcos_launch describe | jq -r .masters[0].public_ip)
    PUBLIC_AGENT_IP=$(wrapped_dcos_launch describe | jq -r .public_agents[0].public_ip)

    echo "CLUSTER_URL=$CLUSTER_URL"
    echo "PUBLIC_AGENT_IP=$PUBLIC_AGENT_IP"
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
    # Authentication is slightly different for DC/OS 1.9.
    if [ "${DCOS_VERSION}" == '1.9' ]; then
        status_line "Authenticating DC/OS OSS"
        dcos config set core.dcos_url $CLUSTER_URL

cat <<EOF | expect -
spawn dcos auth login
expect "Enter OpenID Connect ID Token:"
send "$DCOS_OAUTH_TOKEN\n"
expect eof
EOF
    else
        echo "Removing old clusters."
        for id in $(cluster_ids); do
            echo "remove $id"
            dcos cluster remove $id
        done

cat <<EOF | expect -
spawn dcos cluster setup "$CLUSTER_URL"
expect "Enter OpenID Connect ID Token:"
send "$DCOS_OAUTH_TOKEN\n"
expect eof
EOF
    fi

echo "Verifying cluster authentication:"
dcos config show
}


enterprise_authentication() {
    # Authentication is slightly different for DC/OS 1.9.
    if [ "${DCOS_VERSION}" == '1.9' ]; then
        status_line "Authenticating DC/OS Enterprise"
        dcos config set core.dcos_url $CLUSTER_URL
        dcos auth login --username=$DCOS_USERNAME --password=$DCOS_PASSWORD
    else
        echo "Removing old clusters."
        for id in $(cluster_ids); do
            echo "remove $id"
            dcos cluster remove $id
        done

        echo "Authenticating"
        dcos cluster setup --no-check --username=$DCOS_USERNAME --password=$DCOS_PASSWORD $CLUSTER_URL

        echo "Verifying cluster authentication:"
        dcos cluster list
    fi
}


# cd into MLB directory.
change_into_mlb_dir() {
    status_line "Changing into cloned MLB directory."
    cd dcos-marathon-lb/
}


# Building docker image based on git SHA.
docker_build() {
    status_line "Building docker image."
    docker build -t $DOCKER_IMAGE .
}


# Logging into Mesosphere docker account.
docker_login() {
    status_line "Logging into Mesosphere docker account."
    docker login -u "${DOCKER_HUB_USERNAME}" -p "${DOCKER_HUB_PASSWORD}"
}


# Pushing docker image to mesosphere/marathon-lb-dev.
docker_push() {
    status_line "Pushing docker image."
    docker push $DOCKER_IMAGE
}


# Launching MLB through docker image.
launch_marathonlb() {
    status_line "Launching Marathon-lb"

    echo "Retrieving authentication token for cluster."
    AUTH_TOKEN=$(dcos config show core.dcos_acs_token)

    PAYLOAD="{\"packageName\": \"marathon-lb\"}"

    RESPONSE="response.json"
    JSON_TEMPLATE="template.json"
    MLB_JSON="mlb_json.json"

    CODE=$(curl -X POST -s -k -o $RESPONSE -H "Authorization: token=$AUTH_TOKEN" -w "%{http_code}" -H "Content-Type: application/vnd.dcos.package.render-request+json;charset=utf-8;version=v1" -H "Accept: application/vnd.dcos.package.render-response+json;charset=utf-8;version=v1" -d "$PAYLOAD" $CLUSTER_URL/package/render)

    if [ "$CODE" -eq "200" ]; then
        echo " "
        cat $RESPONSE | jq -r ".marathonJson" > $JSON_TEMPLATE
        cat $JSON_TEMPLATE | jq --arg DOCKER_IMAGE "$DOCKER_IMAGE"  '.container.docker.image=$DOCKER_IMAGE' | jq --arg MLB_VERSION "$MLB_VERSION" '.labels.DCOS_PACKAGE_VERSION=$MLB_VERSION' > $MLB_JSON
        cat $MLB_JSON
        echo " "
    else
        echo " "
        echo "POST to package/render endpoint failed: $CODE"
        delete_cluster
        exit 1
    fi

    # Launch MLB app.
    dcos marathon app add $MLB_JSON

    # Sleeping to wait for MLB to deploy.
    sleep 60s

    # Verify that MLB deployed healthy.
    check_marathonlb_health $AUTH_TOKEN
}


# Verify MLB launched healthy.
check_marathonlb_health() {

    RESPONSE_FILE="curl_response.json"
    CODE=$(curl -X GET -s -k -o $RESPONSE_FILE -H "Authorization: token=$1" -w "%{http_code}" -H "Accept: application/json" $CLUSTER_URL/service/marathon/v2/apps/marathon-lb)
    NUM_OF_HEALTHY_TASKS=($(jq -r '.app.tasksHealthy' $RESPONSE_FILE))
    NUM_OF_INSTANCES=($(jq -r '.app.instances' $RESPONSE_FILE))

    if [[ "$CODE" -eq "200" ]] && [[ "$NUM_OF_HEALTHY_TASKS" -eq "$NUM_OF_INSTANCES" ]]; then
        echo " "
        echo "Marathon-lb launched healthy."
        echo " "
    else
        echo " "
        echo "Marathon-lb failed to launch healthy."

        status_line "Marathon-lb stdout:"
        dcos task log marathon-lb stdout --lines=50

        status_line "Marathon-lb stderr:"        
        dcos task log marathon-lb stderr --lines=50

        delete_cluster
        exit 1
    fi
}


run_integration_tests() {
    status_line "Running integration tests."

    cd ci/
    pytest -s -vv test_marathon_lb.py
}


delete_cluster() {
    status_line "Deleting cluster."
    time wrapped_dcos_launch delete
}


# Launching cluster through dcos-launch & setting up the CLI.
dcos_template
download_cli
launch_cluster
configure_cluster

# Building MLB Docker image.
change_into_mlb_dir
docker_build
docker_login
docker_push

# Launching MLB and running integration tests.
launch_marathonlb
run_integration_tests

# Deleting cluster through dcos-launch.
delete_cluster