#!/bin/bash

set -e # Exit in case of any error

err_report() {
    echo "$2 -> Error on line $1 with $3"
}
trap 'err_report $LINENO ${BASH_SOURCE[$i]} ${BASH_COMMAND}' ERR


cat << EOF | tee -a /stratio_volume/certs_client_marathonlb.list > /dev/null
marathon-lb | "DNS:nginx-qa.labs.stratio.com" | client-server | userland/certificates/marathon-lb
EOF

VAULT_TOKEN=$(grep -Po '"root_token":"(\d*?,|.*?[^\\]")' /stratio_volume/vault_response | awk -F":" '{print $2}' | sed -e 's/^"//' -e 's/"$//')
INTERNAL_DOMAIN=$(grep -Po '"internalDomain":\s"(\d*?,|.*?[^\\]")' /stratio_volume/descriptor.json | awk -F":" '{print $2}' | sed -e 's/^\s"//' -e 's/"$//')
CONSUL_DATACENTER=$(grep -Po '"consulDatacenter":\s"(\d*?,|.*?[^\\]")' /stratio_volume/descriptor.json | awk -F":" '{print $2}' | sed -e 's/^\s"//' -e 's/"$//')

curl -k -s -GET -H "X-Vault-Token:${VAULT_TOKEN}" "https://vault.service.${INTERNAL_DOMAIN}:8200/v1/userland/certificates/marathon-lb" | jq .data > /stratio_volume/marathon-lb-cert-backup.json

cd /stratio/paas-secret-utils/
bash -e gencerts -l /stratio_volume/certs_client_marathonlb.list -w -v vault.service.$INTERNAL_DOMAIN -o 8200 -t $VAULT_TOKEN -d $INTERNAL_DOMAIN -c $CONSUL_DATACENTER

