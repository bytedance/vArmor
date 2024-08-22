// Copyright 2022-2023 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webhooks

import (
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
	"gotest.tools/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

func Test_buildPatch(t *testing.T) {
	testCases := []struct {
		name             string
		kind             string
		enforcer         string
		mode             varmor.VarmorPolicyMode
		bpfExclusiveMode bool
		apparmorGA       bool
		expectedResult   string
		rawTarget        []byte
		rawResource      []byte
	}{
		{
			name:             "patchDeploymentAllContainersConfined",
			kind:             "Deployment",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test2", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentPartContainerConfined",
			kind:             "Deployment",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.kubernetes.io/test2: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentAllContainersAppArmorUnconfined",
			kind:             "Deployment",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.kubernetes.io/test1: unconfined
            container.apparmor.security.beta.kubernetes.io/test2: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentNoContainersConfined",
			kind:             "Deployment",
			mode:             varmortypes.EnhanceProtectMode,
			enforcer:         "AppArmor",
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test
    containers:
    - test1`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.kubernetes.io/test1: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchPodAllContainersConfined",
			kind:             "Pod",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchPodPartContainerConfined",
			kind:             "Pod",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          container.apparmor.security.beta.kubernetes.io/test1: unconfined
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchPodNoContainersConfined",
			kind:             "Pod",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   "",
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test
    containers:
    - test1`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          container.apparmor.security.beta.kubernetes.io/test1: unconfined
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchDeploymentPartContainerConfinedWithBPFAndExclusiveMode",
			kind:             "Deployment",
			enforcer:         "BPF",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: true,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1c1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1c1", "value": "unconfined"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: 4.1-test
        namespace: demo
        labels:
          sandbox.varmor.org/enable: "true"
          environment: production
          app: demo
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: demo
        template:
          metadata:
            labels:
              app: demo
            annotations:
              container.bpf.security.beta.varmor.org/c0: unconfined
          spec:
            containers:
            - name: c0
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity"]
            - name: c1
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity"]
      `),
		},
		{
			name:             "patchDeploymentPartContainerConfinedWithBPF",
			kind:             "Deployment",
			enforcer:         "BPF",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1c1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: 4.1-test
        namespace: demo
        labels:
          sandbox.varmor.org/enable: "true"
          environment: production
          app: demo
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: demo
        template:
          metadata:
            labels:
              app: demo
            annotations:
              container.bpf.security.beta.varmor.org/c0: unconfined
          spec:
            containers:
            - name: c0
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity"]
            - name: c1
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity"]
      `),
		},
		{
			name:             "patchPodAllContainersSeccomp",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "overridePodAllContainersSeccomp",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
            seccompProfile:
              type: RuntimeDefault
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "overridePodAllContainersSeccompInRuntimeDefault",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.RuntimeDefaultMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
            seccompProfile:
              type: RuntimeDefault
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchPodOneContainerSeccomp",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
            seccompProfile:
              type: Unconfined
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
      `),
		},
		{
			name:             "notPatchPrivilegedContainerSeccomp",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            privileged: true
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
      `),
		},
		{
			name:             "patchDeploymentOneContainerSeccomp",
			kind:             "Deployment",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: 4.1-test
        namespace: test
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: demo
        template:
          metadata:
            labels:
              app: demo
            annotations:
              b: v
          spec:
            containers:
            - name: test
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
                seccompProfile:
                  type: Unconfined
            - name: test1
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
      `),
		},
		{
			name:             "patchSeccompWithAlwaysAllowMode",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.AlwaysAllowMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchSeccompWithRuntimeDefaultMode",
			kind:             "Pod",
			enforcer:         "Seccomp",
			mode:             varmortypes.RuntimeDefaultMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
            seccompProfile:
              type: RuntimeDefault
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            seccompProfile:
              type: Unconfined
      `),
		},
		{
			name:             "onlyPatchDeploymentPartContainerConfinedWithAppArmorSeccomp",
			kind:             "Deployment",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test2", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.kubernetes.io/test1: unconfined
            container.seccomp.security.beta.varmor.org/test1: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentPartContainerConfinedWithAppArmorSeccomp",
			kind:             "Deployment",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/0/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.kubernetes.io/test2: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentAllContainersSeccompUnconfined",
			kind:             "Deployment",
			enforcer:         "Seccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       false,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.seccomp.security.beta.varmor.org/test1: unconfined
            container.seccomp.security.beta.varmor.org/test2: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchPodAllContainersAppArmorOnK8s130",
			kind:             "Pod",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.varmor.org~1test", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/1/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
      `),
		},
		{
			name:             "patchPodOneContainerAppArmorOnK8s130",
			kind:             "Pod",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/1/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: v1
      kind: Pod
      metadata:
        name: 4.1-test
        namespace: test
        labels:
          varmor: enable
          varmor-policy: demo-v0.3.0
        annotations:
          b: v
      spec:
        containers:
        - name: test
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
            appArmorProfile:
              type: Unconfined
        - name: test1
          image: debian:10
          command: ["/bin/sh", "-c", "sleep infinity", "1"]
          securityContext:
            runAsUser: 1001
      `),
		},
		{
			name:             "patchDeploymentOneContainerAppArmorOnK8s130",
			kind:             "Deployment",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: 4.1-test
        namespace: test
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: demo
        template:
          metadata:
            labels:
              app: demo
            annotations:
              b: v
          spec:
            containers:
            - name: test
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
                appArmorProfile:
                  type: Unconfined
            - name: test1
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
      `),
		},
		{
			name:             "patchDeploymentOneContainerAppArmorOnK8s1302",
			kind:             "Deployment",
			enforcer:         "AppArmor",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 4.1-test`),
			rawResource: []byte(`
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: 4.1-test
        namespace: test
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: demo
        template:
          metadata:
            labels:
              app: demo
            annotations:
              b: v
              container.apparmor.security.beta.varmor.org/test: unconfined
          spec:
            containers:
            - name: test
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
            - name: test1
              image: debian:10
              command: ["/bin/sh", "-c", "sleep infinity", "1"]
              securityContext:
                runAsUser: 1001
      `),
		},
		{
			name:             "onlyPatchDeploymentPartContainerConfinedWithAppArmorSeccompOnK8s130",
			kind:             "Deployment",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.varmor.org/test1: unconfined
            container.seccomp.security.beta.varmor.org/test1: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentPartContainerConfinedWithAppArmorSeccompOnK8s130",
			kind:             "Deployment",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/0/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/1/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
          annotations:
            container.apparmor.security.beta.varmor.org/test2: unconfined
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000`),
		},
		{
			name:             "patchDeploymentPartContainerConfinedWithAppArmorSeccompOnK8s1302",
			kind:             "Deployment",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/template/spec/containers/0/securityContext", "value": {}},{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/template/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Deployment
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: 1.1-test
      template:
        metadata:
          labels:
            app: 1.1-test
        spec:
          containers:
          - name: test1
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
          - name: test2
            image: schindler36/peer-server:v1.0
            ports:
            - containerPort: 5000
            securityContext:
              appArmorProfile:
                type: Unconfined`),
		},
		{
			name:             "patchPodPartContainerConfinedWithAppArmorSeccompOnK8s130",
			kind:             "Pod",
			enforcer:         "AppArmorSeccomp",
			mode:             varmortypes.EnhanceProtectMode,
			bpfExclusiveMode: false,
			apparmorGA:       true,
			expectedResult:   `[{"op": "add", "path": "/metadata/annotations", "value": {}},{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "add", "path": "/spec/containers/0/securityContext", "value": {}},{"op": "replace", "path": "/spec/containers/0/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test1", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/0/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1test2", "value": "localhost/varmor-testns-test"},{"op": "replace", "path": "/spec/containers/1/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "varmor-testns-test"}},{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "TIME_STRING"}]`,
			rawTarget: []byte(`
    kind: Pod
    name: 1.1-test`),
			rawResource: []byte(`
    apiVersion: v1
    kind: Pod
    metadata:
      name: 1.1-test
      namespace: test
      labels:
        app: 1.1-test
        environment: dev
        varmor: enable
        varmor-version: v0.3.0
        varmor-protect: enable        
    spec:
      containers:
      - name: test1
        image: schindler36/peer-server:v1.0
        ports:
        - containerPort: 5000
      - name: test2
        image: schindler36/peer-server:v1.0
        ports:
        - containerPort: 5000
        securityContext:
          appArmorProfile:
            type: Unconfined`),
		},
	}

	profileName := "varmor-testns-test"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var target varmor.Target
			err := yaml.Unmarshal(tc.rawTarget, &target)
			assert.NilError(t, err)

			switch tc.kind {
			case "Deployment":
				decode := scheme.Codecs.UniversalDeserializer().Decode
				obj, _, err := decode(tc.rawResource, nil, nil)
				assert.NilError(t, err)

				deploy := obj.(*appsv1.Deployment)
				patch, err := buildPatch(deploy, tc.enforcer, tc.mode, target, profileName, tc.bpfExclusiveMode, tc.apparmorGA)
				if err != nil {
					assert.Assert(t, err != nil)
				}

				if strings.Contains(patch, "1mutatedAt") {
					index := strings.Index(patch, `1mutatedAt", "value": `)
					patch = patch[:index+len(`1mutatedAt", "value": `)] + `"TIME_STRING"}]`
				}
				assert.Equal(t, patch, tc.expectedResult)
			case "Pod":
				decode := scheme.Codecs.UniversalDeserializer().Decode
				obj, _, err := decode(tc.rawResource, nil, nil)
				assert.NilError(t, err)

				pod := obj.(*corev1.Pod)
				patch, err := buildPatch(pod, tc.enforcer, tc.mode, target, profileName, tc.bpfExclusiveMode, tc.apparmorGA)
				if err != nil {
					assert.Assert(t, err != nil)
				}

				if strings.Contains(patch, "1mutatedAt") {
					index := strings.Index(patch, `1mutatedAt", "value": `)
					patch = patch[:index+len(`1mutatedAt", "value": `)] + `"TIME_STRING"}]`
				}
				assert.Equal(t, patch, tc.expectedResult)
			}
		})
	}
}
