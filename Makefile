PWD := $(CURDIR)
GIT_VERSION := $(shell git describe --tags --match "v[0-9]*")
VARMOR_PATH := cmd/varmor
CLASSIFIER_PATH := cmd/classifier

REGISTRY ?= elkeid-cn-beijing.cr.volces.com
REGISTRY_DEV ?= elkeid-test-cn-beijing.cr.volces.com
NAMESPACE ?= varmor
VARMOR_IMAGE_NAME := varmor
CLASSIFIER_IMAGE_NAME := classifier

REPO = $(REGISTRY)/$(NAMESPACE)
VARMOR_IMAGE_TAG := $(shell VERSION=$(GIT_VERSION); echo $${VERSION%%-*})
VARMOR_IMAGE ?= $(REPO)/$(VARMOR_IMAGE_NAME):$(VARMOR_IMAGE_TAG)
CLASSIFIER_IMAGE_TAG := $(shell VERSION=$(GIT_VERSION); echo $${VERSION%%-*})
CLASSIFIER_IMAGE ?= $(REPO)/$(CLASSIFIER_IMAGE_NAME):$(CLASSIFIER_IMAGE_TAG)
CHART_APP_VERSION := $(shell VERSION=$(GIT_VERSION); echo $${VERSION%%-*})
CHART_VERSION := $(shell VERSION=$(CHART_APP_VERSION); echo $${VERSION\#v})

REPO_DEV = $(REGISTRY_DEV)/$(NAMESPACE)
VARMOR_IMAGE_TAG_DEV := $(GIT_VERSION)
VARMOR_IMAGE_DEV ?= $(REPO_DEV)/$(VARMOR_IMAGE_NAME):$(VARMOR_IMAGE_TAG_DEV)
CLASSIFIER_IMAGE_TAG_DEV := $(GIT_VERSION)
CLASSIFIER_IMAGE_DEV ?= $(REPO_DEV)/$(CLASSIFIER_IMAGE_NAME):$(CLASSIFIER_IMAGE_TAG_DEV)
CHART_APP_VERSION_DEV := $(GIT_VERSION)
CHART_VERSION_DEV := $(shell VERSION=$(CHART_APP_VERSION_DEV); echo $${VERSION\#v})

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
	rm -rf config/apparmor.d/abi/*
	aa-features-abi -x -w config/apparmor.d/abi/$(APPARMOR_ABI_NAME)
	cp config/apparmor.d/abi/$(APPARMOR_ABI_NAME) config/apparmor.d/abi/varmor

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) crd paths="./apis/varmor/..." output:crd:artifacts:config=config/crds
	cp config/crds/* manifests/varmor/templates/crds/

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="scripts/boilerplate.go.txt" paths="./..."

.PHONY: copy-ebpf
copy-ebpf: ## Generate the ebpf code and lib.
	cp vArmor-ebpf/pkg/behavior/bpf_bpfel.go internal/behavior
	cp vArmor-ebpf/pkg/behavior/bpf_bpfel.o internal/behavior
	cp vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.go pkg/lsm/bpfenforcer
	cp vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.o pkg/lsm/bpfenforcer

goimports:
ifeq (, $(shell which goimports))
	@{ \
	echo "goimports not found!";\
	echo "installing goimports...";\
	go get golang.org/x/tools/cmd/goimports;\
	}
else
GO_IMPORTS=$(shell which goimports)
endif

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./... && $(GO_IMPORTS) -w ./

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test-unit
test-unit: ## Run unit tests.
	@echo "	running unit tests"
	go test ./... -coverprofile coverage.out

.PHONY: test
test: manifests generate fmt vet test-unit ## Run tests.


##@ Build
.PHONY: local
local: ## Build local binary.
	go build -o bin/vArmor $(PWD)/$(VARMOR_PATH)

.PHONY: build
build: manifests generate copy-ebpf fmt vet local ## Build local binary when apis were modified.

.PHONY: docker-build
docker-build: docker-build-varmor-amd64 docker-build-varmor-arm64 docker-build-classifier-amd64 docker-build-classifier-arm64 ## Build container images. 

.PHONY: docker-build-dev
docker-build-dev: docker-build-varmor-amd64-dev docker-build-varmor-arm64-dev docker-build-classifier-amd64-dev docker-build-classifier-arm64-dev ## Build container images without check, only for development.

docker-build-varmor-amd64:
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE)-amd64 --platform linux/amd64 --build-arg TARGETPLATFORM="linux/amd64" --build-arg MAKECHECK="check" .

docker-build-varmor-arm64:
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE)-arm64 --platform linux/arm64 --build-arg TARGETPLATFORM="linux/arm64" --build-arg MAKECHECK="check" .

docker-build-classifier-amd64:
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE)-amd64 --platform linux/amd64 .

docker-build-classifier-arm64:
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE)-arm64 --platform linux/arm64 .

docker-build-varmor-amd64-dev:
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_DEV)-amd64 --platform linux/amd64 --build-arg TARGETPLATFORM="linux/amd64" .

docker-build-varmor-arm64-dev:
	@docker buildx build --file $(PWD)/$(VARMOR_PATH)/Dockerfile --tag $(VARMOR_IMAGE_DEV)-arm64 --platform linux/arm64 --build-arg TARGETPLATFORM="linux/arm64" . 

docker-build-classifier-amd64-dev:
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_DEV)-amd64 --platform linux/amd64 .

docker-build-classifier-arm64-dev:
	@docker buildx build --file $(PWD)/$(CLASSIFIER_PATH)/Dockerfile --tag $(CLASSIFIER_IMAGE_DEV)-arm64 --platform linux/arm64 .


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
	helm push varmor-$(CHART_VERSION_DEV).tgz oci://elkeid-test-cn-beijing.cr.volces.com/varmor


push: ## Push images and chart to the public repository for release.
	docker push $(VARMOR_IMAGE)-amd64
	@echo "----------------------------------------"
	docker push $(VARMOR_IMAGE)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(VARMOR_IMAGE)
	@echo "----------------------------------------"
	docker manifest create $(VARMOR_IMAGE) $(VARMOR_IMAGE)-amd64 $(VARMOR_IMAGE)-arm64
	@echo "----------------------------------------"
	docker manifest push $(VARMOR_IMAGE)
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE)-amd64
	@echo "----------------------------------------"
	docker push $(CLASSIFIER_IMAGE)-arm64
	@echo "----------------------------------------"
	-docker manifest rm $(CLASSIFIER_IMAGE)
	@echo "----------------------------------------"
	docker manifest create $(CLASSIFIER_IMAGE) $(CLASSIFIER_IMAGE)-amd64 $(CLASSIFIER_IMAGE)-arm64
	@echo "----------------------------------------"
	docker manifest push $(CLASSIFIER_IMAGE)
	@echo "----------------------------------------"
	helm push varmor-$(CHART_VERSION).tgz oci://elkeid-cn-beijing.cr.volces.com/varmor
