#
# To start a DCOS cluster with the defaults (OSS edition):
#	make dcos
#
# To start a DCOS cluster with EE:
#	DCOS_LICENSE_KEY_PATH=${HOME}/license.txt \
#   DCOS_E2E_VARIANT=enterprise \
#   make dcos
#
# By default the installers are kept in ./.cache which is removed
# during `make clean`. Specifying a location outside this repo for
# `DCOS_E2E_INSTALLERS_DIR` prevents redownloading:
#
#  DCOS_E2E_INSTALLERS_DIR=${HOME}/dcos/installers make dcos
#
# To start a shell with the env pointing to a dcos cluster
#  make cluster-env shell

THIS_PATH := $(strip $(realpath $(dir $(realpath \
	$(lastword $(MAKEFILE_LIST))))))

# Default overridable varables
MLB_VERSION ?= $(shell git rev-parse --short HEAD || echo dev)
CONTAINTER_REPO ?= mesosphere-ci/marathon-lb
CONTAINER_TAG ?= $(MLB_VERSION)

DEVKIT_CONTAINTER_REPO ?= mesosphere/marathon-lb-devkit
DEVKIT_CONTAINER_TAG ?= latest
DEVKIT_CONTAINER_NAME ?= marathon-lb-devkit

DCOS_E2E_WORKSPACE_DIR ?= $(THIS_PATH)/.cache/dcos-e2e/workspace
DCOS_E2E_INSTALLERS_DIR ?= $(THIS_PATH)/.cache/dcos-e2e/installers
DCOS_E2E_CLUSTER_ID ?= marathon-lb-devkit
DCOS_E2E_CHANNEL ?= stable
DCOS_E2E_VERSION ?= 1.12.0
DCOS_E2E_VARIANT ?= oss

CLUSTER_URL ?=
PUBLIC_AGENT_IP ?=
DCOS_USERNAME ?= admin
DCOS_PASSWORD ?= admin
DCOS_VERSION ?= $(shell echo '$(DCOS_E2E_VERSION)' | cut -d. -f -2)

DOCKER_SOCKET ?= /var/run/docker.sock
DOCKER_HUB_USERNAME ?=
DOCKER_HUB_PASSWORD ?=

# Internal variables
MLB_PATH := $(THIS_PATH)
IMG := $(CONTAINTER_REPO):$(CONTAINER_TAG)
DEVKIT_IMG := $(DEVKIT_CONTAINTER_REPO):$(DEVKIT_CONTAINER_TAG)


MLB_CONTAINER_PATH := /marathon-lb
DEVKIT_VOL_ARGS := -v $(MLB_PATH):$(MLB_CONTAINER_PATH)
DOCKER_VOL_ARGS := -v $(DOCKER_SOCKET):/var/run/docker.sock

DCOS_E2E_INSTALLER_VOL := \
	-v $(DCOS_E2E_INSTALLERS_DIR):$(DCOS_E2E_INSTALLERS_DIR)
DCOS_E2E_WORKSPACE_VOL := \
	-v $(DCOS_E2E_WORKSPACE_DIR):$(DCOS_E2E_WORKSPACE_DIR)
DCOS_E2E_VOL_ARGS := \
	$(DCOS_E2E_INSTALLER_VOL) \
	$(DCOS_E2E_WORKSPACE_VOL)

#(TODO) Support overriding backend to use any backend
DCOS_E2E_BACKEND := docker
DCOS_E2E_NODE_TRANSPORT := docker-exec


JQ_FIND_CLUSTER_URL := jq -r -e '."Web UI" // empty'
JQ_FIND_PUBLIC_IP := jq -r -e '.Nodes.public_agents[0].ip_address // empty'


CLUSTER_ENV_ARGS = \
	--env CLUSTER_URL="$(CLUSTER_URL)" \
	--env PUBLIC_AGENT_IP="$(PUBLIC_AGENT_IP)" \
	--env DCOS_USERNAME="$(DCOS_USERNAME)" \
	--env DCOS_LOGIN_UNAME="$(DCOS_USERNAME)" \
	--env DCOS_PASSWORD="$(DCOS_PASSWORD)" \
	--env DCOS_LOGIN_PW="$(DCOS_PASSWORD)" \
	--env DCOS_VERSION="$(DCOS_VERSION)" \
	--env DCOS_E2E_BACKEND="$(DCOS_E2E_BACKEND)" \
	--env DCOS_E2E_NODE_TRANSPORT="$(DCOS_E2E_NODE_TRANSPORT)" \
	--env DCOS_E2E_CLUSTER_ID="$(DCOS_E2E_CLUSTER_ID)" \
	--env DCOS_E2E_VARIANT="$(DCOS_E2E_VARIANT)" \
	--env MARATHON_LB_IMAGE="$(IMG)" \
	--env MARATHON_LB_VERSION="$(MLB_VERSION)"

CLUSTER_RUNNING := 0
ifneq ($(strip $(shell docker ps -q -f 'name=$(DCOS_E2E_CLUSTER_ID)')),)
	CLUSTER_RUNNING := 1
endif

ifeq ($(strip $(CLUSTER_URL)),)
	CLUSTER_TARGET := dcos
endif

ifeq ($(strip $(PUBLIC_AGENT_IP)),)
	CLUSTER_TARGET := dcos
endif

DCOS_E2E_DOWNLOAD_SITE := https://downloads.dcos.io/dcos

ifeq ($(strip $(DCOS_E2E_VARIANT)), enterprise)
	DCOS_E2E_DOWNLOAD_SITE := $(strip \
		https://downloads.mesosphere.com/dcos-enterprise)
	DCOS_E2E_FILE_TAG := .ee
	DCOS_LICENSE_KEY_PATH ?=
	DCOS_E2E_VOL_ARGS := \
		$(DCOS_E2E_VOL_ARGS) \
		-v $(DCOS_LICENSE_KEY_PATH):$(DCOS_LICENSE_KEY_PATH)
	DCOS_E2E_ENV_ARGS := \
		--env DCOS_LICENSE_KEY_PATH="$(DCOS_LICENSE_KEY_PATH)"
endif

DCOS_E2E_FILE := $(DCOS_E2E_VERSION)$(DCOS_E2E_FILE_TAG).sh
DCOS_E2E_DOWNLOAD_URL := $(DCOS_E2E_DOWNLOAD_SITE)/$(DCOS_E2E_CHANNEL)
DCOS_E2E_DOWNLOAD_URL := $(DCOS_E2E_DOWNLOAD_URL)/$(DCOS_E2E_VERSION)
DCOS_E2E_DOWNLOAD_URL := $(strip \
	$(DCOS_E2E_DOWNLOAD_URL)/dcos_generate_config$(DCOS_E2E_FILE_TAG).sh)


.DEFAULT_GOAL := help


.PHONY: help
help:
	@echo "Targets: "
	@echo "    clean"
	@echo "        Remove all artifacts/files/containers"
	@echo ""
	@echo "    image, devkit"
	@echo "        Build the marathon-lb/devkit images"
	@echo ""
	@echo "    dcos"
	@echo "        Start a dcos cluster with dcos-e2e"
	@echo ""
	@echo "    shell"
	@echo "        Run /bin/bash in a devkit container"
	@echo ""
	@echo "    test"
	@echo "        Run unit/integration tests"


.PHONY: clean-dcos-container
clean-dcos-container:
ifeq ($(CLUSTER_RUNNING), 1)
	@echo "+ Cleaning up DCOS cluster-id $(DCOS_E2E_CLUSTER_ID)"
	-@docker run \
		--rm  \
		--tty \
		--interactive \
		$(DEVKIT_VOL_ARGS) \
		$(DOCKER_VOL_ARGS) \
		$(DCOS_E2E_VOL_ARGS) \
		$(DEVKIT_IMG) \
		minidcos \
			$(DCOS_E2E_BACKEND) \
			destroy --cluster-id $(DCOS_E2E_CLUSTER_ID)
endif

.PHONY: clean-devkit-container
clean-devkit-container:
ifneq ($(strip $(shell docker ps -q -f 'name=$(DEVKIT_CONTAINER_NAME)')),)
	@echo "+ Cleaning up $(DEVKIT_CONTAINER_NAME) container"
	-@docker rm \
		--force \
		--volumes \
		$(DEVKIT_CONTAINER_NAME) > /dev/null 2>&1 || true
endif


.PHONY: clean
clean: clean-devkit-container \
	   clean-dcos-container
	@echo "+ Remove files left behind"
	@find . -type f -name '*.pyc' -delete
	@find . -type f -name '.coverage.*' -delete
	@find . -name ".pytest_cache" -type d -prune -exec rm -r "{}" \;
	@find . -name "__pycache__" -type d -prune -exec rm -r "{}" \;
	@rm -rf .cache


.PHONY: cluster-env
cluster-env: cluster-url cluster-public-ip


.PHONY: cluster-public-ip
cluster-public-ip: devkit $(CLUSTER_TARGET)
ifeq ($(strip $(PUBLIC_AGENT_IP)),)
	@echo "+ Discovering Public Node IP"
	$(eval PUBLIC_AGENT_IP := $(shell \
		docker run \
			--rm  \
			--tty \
			--interactive \
			$(DEVKIT_VOL_ARGS) \
			$(DOCKER_VOL_ARGS) \
			$(DCOS_E2E_VOL_ARGS) \
			$(DEVKIT_IMG) \
			minidcos \
				$(DCOS_E2E_BACKEND) \
				inspect --cluster-id $(DCOS_E2E_CLUSTER_ID) \
					| $(JQ_FIND_PUBLIC_IP)))
endif
	@echo "+ Public Node IP: $(PUBLIC_AGENT_IP)"


.PHONY: cluster-url
cluster-url: devkit $(CLUSTER_TARGET)
ifeq ($(strip $(CLUSTER_URL)),)
	@echo "+ Discovering Cluster URL"
	$(eval CLUSTER_URL := $(shell \
		docker run \
			--rm  \
			--tty \
			--interactive \
			$(DEVKIT_VOL_ARGS) \
			$(DOCKER_VOL_ARGS) \
			$(DCOS_E2E_VOL_ARGS) \
			$(DEVKIT_IMG) \
			minidcos \
				$(DCOS_E2E_BACKEND) \
				inspect --cluster-id $(DCOS_E2E_CLUSTER_ID) \
					| $(JQ_FIND_CLUSTER_URL)))
endif
	@echo "+ Cluster URL: $(CLUSTER_URL)"


.PHONY: devkit
devkit: image
	@echo "+ Build devkit image $(DEVKIT_IMG)"
	@docker build \
		--rm \
		--quiet \
		--force-rm \
		--file $(MLB_PATH)/Dockerfile.devkit \
		--tag $(DEVKIT_IMG) \
		$(MLB_PATH) > /dev/null 2>&1


$(DCOS_E2E_WORKSPACE_DIR):
	@echo "+ Creating DCOS E2E Workspace"
	@mkdir -p $(DCOS_E2E_WORKSPACE_DIR)


$(DCOS_E2E_INSTALLERS_DIR):
	@echo "+ Creating DCOS E2E Installer Cache"
	@mkdir -p $(DCOS_E2E_WORKSPACE_DIR)


$(DCOS_E2E_INSTALLERS_DIR)/$(DCOS_E2E_FILE): $(DCOS_E2E_INSTALLERS_DIR)
ifeq ($(strip $(DCOS_E2E_VERSION)), master)
	@echo '+ Removing existing master installer'
	-@rm -f $@.tmp $@
endif
	@echo "+ Downloading $(DCOS_E2E_VERSION)$(DCOS_E2E_FILE_TAG) installer"
	@curl \
			--show-error \
			--location \
			--fail \
			--continue-at - \
			--output $@.tmp \
			$(DCOS_E2E_DOWNLOAD_URL) \
		&& mv -f $@.tmp $@ 2>/dev/null \
		&& touch $@


.PHONY: dcos
dcos: devkit \
	  $(DCOS_E2E_WORKSPACE_DIR) \
	  $(DCOS_E2E_INSTALLERS_DIR)/$(DCOS_E2E_FILE)
ifeq ($(CLUSTER_RUNNING), 0)
	@echo "+ Starting DCOS $(DCOS_E2E_VARIANT)" \
		"cluster: $(DCOS_E2E_CLUSTER_ID)"
	@docker run \
		--rm  \
		--tty \
		$(DEVKIT_VOL_ARGS) \
		$(DOCKER_VOL_ARGS) \
		$(DCOS_E2E_VOL_ARGS) \
		$(DCOS_E2E_ENV_ARGS) \
		$(DEVKIT_IMG) \
		minidcos \
			$(DCOS_E2E_BACKEND) \
			create \
			    --cluster-id $(DCOS_E2E_CLUSTER_ID) \
				--workspace-dir $(DCOS_E2E_WORKSPACE_DIR) \
				--variant $(DCOS_E2E_VARIANT) \
				--wait-for-dcos \
				$(DCOS_E2E_INSTALLERS_DIR)/$(DCOS_E2E_FILE)
endif


.PHONY: image
image:
	@echo "+ Build container image $(IMG)"
	@docker build \
		--rm \
		--quiet \
		--force-rm \
		--file $(MLB_PATH)/Dockerfile \
		--tag $(IMG) \
		$(MLB_PATH) > /dev/null 2>&1 || true


.PHONY: image-push
image-push: image
	@echo "+ Pushing image to hub"
	docker push $(IMG)


.PHONY: shell
shell: devkit
	@echo "+ Running $(DEVKIT_IMG) container"
	-@docker run \
		--rm  \
		--tty \
		--interactive \
		$(CLUSTER_ENV_ARGS) \
		$(DEVKIT_VOL_ARGS) \
		$(DOCKER_VOL_ARGS) \
		$(DCOS_E2E_VOL_ARGS) \
		$(DCOS_E2E_ENV_ARGS) \
		$(DEVKIT_IMG) \
		/bin/bash -l || true


.PHONY: test-integration
test-integration: image-push devkit cluster-url cluster-public-ip
	@echo "+ Integration Testng with image $(IMG)"
	@docker run \
		--rm  \
		--tty \
		$(CLUSTER_ENV_ARGS) \
		$(DEVKIT_VOL_ARGS) \
		$(DOCKER_VOL_ARGS) \
		$(DCOS_E2E_VOL_ARGS) \
		$(DCOS_E2E_ENV_ARGS) \
		$(DEVKIT_IMG) \
		/bin/bash -c " \
			cd $(MLB_CONTAINER_PATH)/ci \
			&& pytest -p no:warnings -v test_marathon_lb_dcos_e2e.py \
			"

.PHONY: test-unit
test-unit: devkit
	@echo "+ Unit Testing with image $(DEVKIT_IMG)"
	@docker run \
		--rm  \
		--tty \
		$(DEVKIT_VOL_ARGS) \
		$(DEVKIT_IMG) \
		/bin/bash -c " \
			echo -n 'flake8...' \
			&& flake8 $(MLB_CONTAINER_PATH) \
			&& echo ' OK' \
			&& echo -n 'nosetests' \
			&& cd $(MLB_CONTAINER_PATH) \
			&& nosetests --with-coverage --cover-package=. \
			"


.PHONY: test
test: test-unit test-integration
