#!/usr/bin/env bash
set -ex

: "${ACTION:=${1}}"

#############
# VARIABLES #
#############
TMPDIR=$(mktemp -d)

#############
# FUNCTIONS #
#############

function install_helm {
  curl https://baltocdn.com/helm/signing.asc | sudo apt-key add -
  sudo apt-get install apt-transport-https --yes
  echo "deb https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
  sudo apt-get update
  sudo apt-get install helm
}

function deploy_vault {
  
  # Install Vault with Helm
  helm repo add hashicorp https://helm.releases.hashicorp.com
  # helm install vault hashicorp/vault --values "${TMPDIR}/"custom-values.yaml
  helm install vault hashicorp/vault
  timeout 120 sh -c 'until kubectl get pods -l app.kubernetes.io/name=vault --field-selector=status.phase=Running|grep vault-0; do sleep 5; done'
  
  # Unseal Vault
  VAULT_INIT_TEMP_DIR=$(mktemp)
  kubectl exec -ti vault-0 -- vault operator init -format "json" | tee -a "$VAULT_INIT_TEMP_DIR"
  for i in $(seq 0 2); do
    kubectl exec -ti vault-0 -- vault operator unseal "$(jq -r ".unseal_keys_b64[$i]" "$VAULT_INIT_TEMP_DIR")"
  done
  kubectl get pods -l app.kubernetes.io/name=vault
  
  # Wait for vault to be ready once unsealed
  while [[ $(kubectl get pods -l app.kubernetes.io/name=vault -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting vault to be ready" && sleep 1; done
  
  # Configure Vault
  ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_INIT_TEMP_DIR")
  kubectl exec -it vault-0 -- vault login "$ROOT_TOKEN"
  #enable kv engine v1 for osd and v2 for rgw encryption respectively in different path
  kubectl exec -ti vault-0 -- vault secrets enable -path=secret/ver1 kv
  kubectl exec -ti vault-0 -- vault secrets enable -path=secret/ver2 kv-v2
  kubectl exec -ti vault-0 -- vault secrets enable -path=test/secret kv
  kubectl exec -ti vault-0 -- vault kv list || true # failure is expected
  kubectl exec -ti vault-0 -- vault kv list || true # failure is expected
  
  # Configure Vault Policy
  echo '
  path "secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
  }
  path "test/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
  }
  path "sys/mounts" {
  capabilities = ["read"]
  }'| kubectl exec -i vault-0 -- vault policy write secret -
  
  # Create a token for the integration test
  kubectl exec vault-0 -- vault token create -policy=secret -format json |jq -r '.auth.client_token' > vault-token

  # setup approle
  kubectl exec -ti vault-0 -- vault auth enable approle
  # create a new role with correct policy
  kubectl exec -ti vault-0 -- vault write auth/approle/role/my-role token_policies=secret

  kubectl exec -ti vault-0 -- vault read auth/approle/role/my-role/role-id -format=json | jq -r .data.role_id > vault-role_id
  kubectl exec -ti vault-0 -- vault write auth/approle/role/my-role/secret-id -format=json | jq -r .data.secret_id > vault-secret_id

}

function validate_list_secrets {
  for path in ver1 ver2; do
    if  kubectl -n default exec -ti vault-0 -- vault kv list secret/"$path" |grep -oqEq "No value found at"; then
      echo "$path is not empty!"
      exit 1
    fi
  done
}

########
# MAIN #
########

case "$ACTION" in
  deploy)
    if [[ "$(uname)" == "Linux" ]]; then
      sudo apt-get install jq socat -y
      install_helm
    fi
    
    deploy_vault
  ;;
  validate)
    shift
    validate_list_secrets
  ;;
  *)
    echo "invalid action $ACTION" >&2
    exit 1
esac
