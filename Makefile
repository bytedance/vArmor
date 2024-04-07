PWD := $(CURDIR)
GIT_VERSION := $(shell git describe --tags --match "v[0-9]*")
VARMOR_PATH := cmd/varmor
CLASSIFIER_PATH := cmd/classifier

REGISTRY_AP ?= elkeid-ap-southeast-1.cr.volces.com
REGISTRY_DEV ?= elkeid-ap-southeast-1.cr.volces.com

NAMESPACE ?= varmor
NAMESPACE_DEV ?= varmor-test
REPO_AP = $(REGISTRY_AP)/$(NAMESPACE)
REPO_DEV = $(REGISTRY_DEV)/$(NAMESPACE_DEV)

VARMOR_IMAGE_NAME := varmor
VARMOR_IMAGE_TAG := $(shell VERSION=$(GIT_VERSION); echo $${VERSION%-*-*})
VARMOR_IMAGE_TAG_DEV := $(GIT_VERSION)
CLASSIFIER_IMAGE_NAME := classifier
CLASSIFIER_IMAGE_TAG := $(VARMOR_IMAGE_TAG)
CLASSIFIER_IMAGE_TAG_DEV := $(VARMOR_IMAGE_TAG_DEV)

VARMOR_IMAGE_AP ?= $(REPO_AP)/$(VARMOR_IMAGE_NAME):$(VARMOR_IMAGE_TAG)
VARMOR_IMAGE_DEV ?= $(REPO_DEV)/$(VARMOR_IMAGE_NAME):$(VARMOR_IMAGE_TAG_DEV)
CLASSIFIER_IMAGE_AP ?= $(REPO_AP)/$(CLASSIFIER_IMAGE_NAME):$(CLASSIFIER_IMAGE_TAG)
CLASSIFIER_IMAGE_DEV ?= $(REPO_DEV)/$(CLASSIFIER_IMAGE_NAME):$(CLASSIFIER_IMAGE_TAG_DEV)

CHART_APP_VERSION := $(VARMOR_IMAGE_TAG)
CHART_APP_VERSION_DEV := $(GIT_VERSION)
CHART_VERSION := $(shell echo $(CHART_APP_VERSION)| sed 's/^v//')
CHART_VERSION_DEV := $(shell echo $(CHART_APP_VERSION_DEV)| sed 's/^v//')

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.20

KERNEL_RELEASE = $(shell uname -r)
APPARMOR_ABI_NAME = kernel-$(KERNEL_RELEASE)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

# Download controller-gen locally if necessary.
CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen:
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.11.3)

# Download envtest-setup locally if necessary.
ENVTEST = $(shell pwd)/bin/setup-envtest
envtest:
	$(call go-get-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)


.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


##@ Development
.PHONY: generate-apparmor-abi
generate-apparmor-abi: ## Generate the AppArmor feature ABI of development environment. All policy must be developed and tested under this ABI.
	@echo "[+] Generate the AppArmor feature ABI of development environment."
	rm -rf config/apparmor.d/abi/*
	aa-features-abi -x -w config/apparmor.d/abi/$(APPARMOR_ABI_NAME)
	cp config/apparmor.d/abi/$(APPARMOR_ABI_NAME) config/apparmor.d/abi/varmor

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	@echo "[+] Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects"
	$(CONTROLLER_GEN) crd paths="./apis/varmor/..." output:crd:artifacts:config=config/crds
	cp config/crds/* manifests/varmor/templates/crds/

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	@echo "[+] Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations."
	$(CONTROLLER_GEN) object:headerFile="scripts/boilerplate.go.txt" paths="./..."
	@echo "[+] Patch zz_generated.deepcopy.go to add custom deepcopy for SyscallRawRules"
	sed -i '/\tif in.SyscallRawRules != nil {/,/\t}/c\\tif in.SyscallRawRules != nil {\n\t\tin, out := &in.SyscallRawRules, &out.SyscallRawRules\n\t\t*out = make([]specs_go.LinuxSyscall, len(*in))\n\t\tlinuxSyscallDeepCopyInto(in, out)' apis/varmor/v1beta1/zz_generated.deepcopy.go

.PHONY: build-ebpf
build-ebpf: ## Generate the ebpf code and lib.
	@echo "[+] Generate the ebpf code and lib."
	make -C ./vArmor-ebpf generate-ebpf

.PHONY: copy-ebpf
copy-ebpf: ## Copy the ebpf code and lib.
	@echo "[+] Copy the ebpf code and lib."
	cp vArmor-ebpf/pkg/tracer/bpf_bpfel.go internal/behavior/tracer
	cp vArmor-ebpf/pkg/tracer/bpf_bpfel.o internal/behavior/tracer
	cp vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.go pkg/lsm/bpfenforcer
	cp vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.o pkg/lsm/bpfenforcer

goimports:
ifeq (, $(shell which goimports))
	@{ \
	echo "goimports not found!";\
	echo "installing goimports...";\
	go install golang.org/x/tools/cmd/goimports;\
	}
else
GO_IMPORTS=$(shell which goimports)
endif

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "[+] Run go fmt against code."
	go fmt ./... && $(GO_IMPORTS) -w ./

.PHONY: vet
vet: ## Run go vet against code.
	@echo "[+] Run go vet against code."
	go vet ./...

.PHONY: test-unit
test-unit: ## Run unit tests.
	@echo "[+] Running unit tests."
	go test ./... -coverprofile coverage.out

.PHONY: test
test: manifests generate fmt vet test-unit ## Run tests.


##@ Build
.PHONY: local
local: ## Build local binary.
	@echo "[+] Build local binary."
	go build -o bin/vArmor $(PWD)/$(VARMOR_PATH)

.PHONY: build
build: manifests generate build-ebpf copy-ebpf vet local ## Build local binary when apis or bpf code were modified.

.PHONY: docker-build
docker-build: docker-build-varmor-amd64 docker-build-varmor-arm64 docker-build-classifier-amd64 docker-build-classifier-arm64 ## Build container images. 

.PHONY: docker-build-dev
docker-build-dev: docker-build-varmor-amd64-dev docker-build-varmor-arm64-dev docker-build-classifier-amd64-dev docker-build-classifier-arm64-dev ## Build container images without check, only for development.

.PHONY: docker-build-dev-ci
docker-build-dev: docker-build-varmor-amd64-dev docker-build-varmor-arm64-dev docker-build-classifier-amd64-dev docker-build-classifier-arm64-dev docker-save-ci-dev ## Build container images without check, only for development.


docker-build-varmor-amd64:
	@echo "[+] Build varmor-amd64 image for release version"
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_AP)-amd64 --platform linux/amd64 --build-arg TARGETPLATFORM="linux/amd64" --load .

docker-build-varmor-arm64:
	@echo "[+] Build varmor-arm64 image for the release version"
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_AP)-arm64 --platform linux/arm64 --build-arg TARGETPLATFORM="linux/arm64" --load .

docker-build-classifier-amd64:
	@echo "[+] Build classifier-amd64 image for the release version"
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_AP)-amd64 --platform linux/amd64 --load .

docker-build-classifier-arm64:
	@echo "[+] Build classifier-arm64 image for the release version"
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_AP)-arm64 --platform linux/arm64 --load .

docker-build-varmor-amd64-dev:
	@echo "[+] Build varmor-amd64 image for the development version"
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_DEV)-amd64 --platform linux/amd64 --build-arg TARGETPLATFORM="linux/amd64" --load .

docker-build-varmor-arm64-dev:
	@echo "[+] Build varmor-arm64 image for the development version"
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_DEV)-arm64 --platform linux/arm64 --build-arg TARGETPLATFORM="linux/arm64" --load .

docker-build-classifier-amd64-dev:
	@echo "[+] Build classifier-amd64 image for the development version"
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_DEV)-amd64 --platform linux/amd64 --load .

docker-build-classifier-arm64-dev:
	@echo "[+] Build classifier-arm64 image for the development version"
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_DEV)-arm64 --platform linux/arm64 --load .
docker-save-ci-dev:
	@echo "[+] Saving varmor-amd64 image to varmor-amd64.tar"
	@docker save $(VARMOR_IMAGE_DEV)-amd64 -o varmor-amd64.tar
	@echo "[+] Saving varmor-arm64 image to varmor-arm64.tar"
	@docker save $(VARMOR_IMAGE_DEV)-arm64 -o varmor-arm64.tar
	@echo "[+] Saving classifier-amd64 image to classifier-amd64.tar"
	@docker save $(CLASSIFIER_IMAGE_DEV)-amd64 -o classifier-amd64.tar
	@echo "[+] Saving classifier-arm64 image to classifier-arm64.tar"
	@docker save $(CLASSIFIER_IMAGE_DEV)-arm64 -o classifier-arm64.tar


##@ Package
.PHONY: helm-package
helm-package: ## Package helm chart.
	helm package manifests/varmor --version $(CHART_VERSION) --app-version $(CHART_APP_VERSION)

helm-package-dev: ## Package helm chart for development.
	helm package manifests/varmor --version $(CHART_VERSION_DEV) --app-version $(CHART_APP_VERSION_DEV)

.PHONY: demo-package
demo-package: ## Package the demo resources.
	tar -C ../ -czf vArmor-test.tar.gz ./vArmor/config ./vArmor/test


##@ Push artifacts (Note: Logging in to the registry is required beforehand.)
.PHONY: push
push-dev: ## Push images and chart to the private repository for development.
	docker push $(VARMOR_IMAGE_DEV)-amd64
	@echo "----------------------------------------"
	docker push $(VARMOR_IMAGE_DEV)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(VARMOR_IMAGE_DEV)
	@echo "----------------------------------------"
	docker manifest create $(VARMOR_IMAGE_DEV) $(VARMOR_IMAGE_DEV)-amd64 $(VARMOR_IMAGE_DEV)-arm64
	@echo "----------------------------------------"
	docker manifest push $(VARMOR_IMAGE_DEV)
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE_DEV)-amd64
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE_DEV)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(CLASSIFIER_IMAGE_DEV)
	@echo "----------------------------------------"
	docker manifest create $(CLASSIFIER_IMAGE_DEV) $(CLASSIFIER_IMAGE_DEV)-amd64 $(CLASSIFIER_IMAGE_DEV)-arm64
	@echo "----------------------------------------"
	docker manifest push $(CLASSIFIER_IMAGE_DEV)
	@echo "----------------------------------------"
	helm push varmor-$(CHART_VERSION_DEV).tgz oci://$(REPO_DEV)

.PHONY: manifests-dev
manifests-dev:
	-docker manifest rm $(VARMOR_IMAGE_DEV)
	@echo "----------------------------------------"
	docker manifest create $(VARMOR_IMAGE_DEV) $(VARMOR_IMAGE_DEV)-amd64 $(VARMOR_IMAGE_DEV)-arm64
	-docker manifest rm $(VARMOR_IMAGE_DEV)
	@echo "----------------------------------------"
	docker manifest create $(VARMOR_IMAGE_DEV) $(VARMOR_IMAGE_DEV)-amd64 $(VARMOR_IMAGE_DEV)-arm64
push: ## Push images and chart to the public repository for release.
	docker push $(VARMOR_IMAGE_AP)-amd64
	@echo "----------------------------------------"
	docker push $(VARMOR_IMAGE_AP)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(VARMOR_IMAGE_AP)
	@echo "----------------------------------------"
	docker manifest create $(VARMOR_IMAGE_AP) $(VARMOR_IMAGE_AP)-amd64 $(VARMOR_IMAGE_AP)-arm64
	@echo "----------------------------------------"
	docker manifest push $(VARMOR_IMAGE_AP)
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE_AP)-amd64
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE_AP)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(CLASSIFIER_IMAGE_AP)
	@echo "----------------------------------------"
	docker manifest create $(CLASSIFIER_IMAGE_AP) $(CLASSIFIER_IMAGE_AP)-amd64 $(CLASSIFIER_IMAGE_AP)-arm64
	@echo "----------------------------------------"
	docker manifest push $(CLASSIFIER_IMAGE_AP)
	@echo "----------------------------------------"
	helm push varmor-$(CHART_VERSION).tgz oci://$(REPO_AP)
