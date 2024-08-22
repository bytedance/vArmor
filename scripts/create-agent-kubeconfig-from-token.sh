#!/usr/bin/env bash

# Copyright 2022 vArmor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The script returns a kubeconfig for the service account given
# you need to have kubectl on PATH with the context set to the cluster you want to create the config for

set -o errexit

# Cosmetics for the created config
clusterName=kubernetes

# Retrieve server address
if [ -f ~/.kube/config ]; then
  server=$(cat ~/.kube/config | grep server: | awk '{print $2}')
  ca=$(cat ~/.kube/config | grep certificate-authority-data: | awk '{print $2}')
elif [ $KUBECONFIG ]; then
  server=$(cat $KUBECONFIG | grep server: | awk '{print $2}')
  ca=$(cat $KUBECONFIG | grep certificate-authority-data: | awk '{print $2}')
else
  echo "[!] Can't find kubeconfig file in ~/.kube/config or $KUBECONFIG."
  exit 1
fi

# The Namespace and ServiceAccount name that is used for the config
namespace=varmor
serviceAccount=varmor-agent

# Create token
minor_version=$(kubectl version -o json 2>/dev/null | jq -r '.serverVersion.minor')
if [[ $minor_version == 22* || $minor_version == 3* ]]; then
  token=$(kubectl --namespace $namespace --duration 720h create token $serviceAccount)
else
  secretName=$(kubectl --namespace $namespace get serviceAccount $serviceAccount -o jsonpath='{.secrets[0].name}')
  if [[ -z $secretName ]]; then
    echo "[!] Can't retrieve the secret name of varmor-agent ServiceAccount"
    exit 1
  fi
  token=$(kubectl --namespace $namespace get secret/$secretName -o jsonpath='{.data.token}' | base64 --decode)
fi

# Craft kubeconfig
echo "
---
apiVersion: v1
kind: Config
clusters:
  - name: ${clusterName}
    cluster:
      certificate-authority-data: ${ca}
      server: ${server}
contexts:
  - name: ${serviceAccount}@${clusterName}
    context:
      cluster: ${clusterName}
      namespace: ${namespace}
      user: ${serviceAccount}
users:
  - name: ${serviceAccount}
    user:
      token: ${token}
current-context: ${serviceAccount}@${clusterName}
"
