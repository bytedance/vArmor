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

if [[ "$1" == "deploy" ]]; then
    kubectl delete -f config/k8s-resource/rbac 2>/dev/null
    kubectl delete -f config/crds 2>/dev/null
    kubectl create -f config/crds
    kubectl create -f config/k8s-resource/rbac
elif [[ "$1" == "test" ]]; then
    kubectl delete -f config/k8s-resource/rbac 2>/dev/null
    kubectl delete -f config/crds 2>/dev/null
    kubectl create -f config/crds
    kubectl create -f config/k8s-resource/rbac
    ./scripts/create-manager-kubeconfig-from-token.sh > varmor-manager.kubeconfig
    ./scripts/create-agent-kubeconfig-from-token.sh > varmor-agent.kubeconfig
elif [[ "$1" == "uninstall" ]]; then
    kubectl delete -f config/k8s-resource/rbac 2>/dev/null
    kubectl delete -f config/crds 2>/dev/null
fi
