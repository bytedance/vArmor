#!/usr/bin/env bash

DIR="$( cd "$( dirname "$0"  )" && pwd  )"
Data=$(cat $DIR/varmor.test.profile | base64 -w 0)

echo "---
apiVersion: crd.varmor.org/v1beta1
kind: ArmorProfile
metadata:
  name: test
  namespace: varmor
spec:
  nodeNumber: 1
  profile:
    name: varmor.test.profile
    content: ${Data}
    mode: enforce" > ${DIR}/varmor_test_armorprofile.yaml
