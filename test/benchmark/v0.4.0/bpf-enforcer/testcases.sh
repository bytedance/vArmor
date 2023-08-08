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

for n in {1..12800}; do
echo "apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-$n
  namespace: test
  labels:
    app: test-$n
    varmor-protect: enable
    sandbox.varmor.org/enable: 'true'
spec:
  replicas: 0
  selector:
    matchLabels:
      app: test-$n
  template:
    metadata:
      labels:
        app: test-$n
    spec:
      containers:
      - name: test
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
---"
done
