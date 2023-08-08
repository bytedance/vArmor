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

usage()
{
    echo "Usage: ./test.sh COMMAND KUBECONFIG_PATH
    COMMAND: start or delete
    KUBECONFIG_PATH: The kubeconfig with admin rights for accessing the APIServer.

    Example: ./test.sh start ~/.kube/config
    "
}

if [[ $# -ne 2 ]]
then
   usage
   exit 1
fi

if [[ "$1" == "start" ]]; then

echo "[+] Generating testcases..."
./test/benchmark/v0.4.0/manager-bpf/testcases.sh > deploy.yaml

echo "[+] Deploying testcases..."
kubectl create -f deploy.yaml --kubeconfig=$2 1>/dev/null

echo "[+] Done."

elif [[ "$1" == "delete" ]]; then

echo "[+] Deleting testcases..."

kubectl delete -f deploy.yaml --kubeconfig=$2 2>/dev/null 1>/dev/null
rm deploy.yaml

echo "[+] Done."

fi
