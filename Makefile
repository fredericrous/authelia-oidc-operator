# Version from git tags (with fallback to "dev" if no tags exist)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/fredericrous/authelia-oidc-operator:$(VERSION)
# Kubernetes version for code generation
KUBE_VERSION ?= 1.29.0

# ENVTEST binary versions
ENVTEST_K8S_VERSION = $(KUBE_VERSION)

# Pin the Go toolchain to go.mod's `go` line for every target below. This is
# Go's equivalent of a virtualenv: with GOTOOLCHAIN set to an exact version the
# go command downloads that release once (into the module cache) and uses it,
# whatever `go` on PATH happens to be. Without the pin a NEWER local go is used
# silently — `go 1.25.13` in go.mod only forbids OLDER ones — so a workstation
# on 1.27 tested code that CI (setup-go, go-version-file: go.mod) builds on
# 1.25. Exported, so it also reaches the tools installed with `go install`.
GO_VERSION := $(shell awk '/^go /{print $$2}' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

# Get platform info
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

all: build

##@ General

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object paths="./..."

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

lint: golangci-lint ## Run golangci-lint at the pinned version, exactly as CI does.
	$(GOLANGCI_LINT) run --timeout 5m

test: manifests generate fmt vet envtest ## Run tests.
	@echo "Setting up envtest binaries..."
	@test -d $(LOCALBIN) || mkdir -p $(LOCALBIN)
	@test -f $(ENVTEST) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

test-unit: fmt vet ## Run unit tests only.
	go test ./api/... ./pkg/... -coverprofile cover.out

test-integration: manifests generate fmt vet envtest ## Run integration tests.
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./controllers -v -ginkgo.v

test-coverage: test ## Generate test coverage report.
	go tool cover -html=cover.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

##@ Build

build: ## Build manager binary.
	go build -o bin/manager main.go

run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

docker-build: ## Build docker image with the manager.
	docker build -t ${IMG} .
	docker tag ${IMG} ghcr.io/fredericrous/authelia-oidc-operator:latest

docker-push: ## Push docker image with the manager.
	docker push ${IMG}
	docker push ghcr.io/fredericrous/authelia-oidc-operator:latest

##@ Deployment

install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	kubectl apply -f config/crd/bases/

uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/crd/bases/

deploy: manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	kubectl apply -k config/

undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	kubectl delete -k config/

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.19.0
# The one place the linter version is pinned; .github/workflows/pr.yml runs
# `make lint` so CI and a workstation cannot drift apart. A golangci-lint
# release is built against one Go minor and must not lag go.mod's: when the
# `go` line moves to a new minor, bump this alongside it.
GOLANGCI_LINT_VERSION ?= v2.4.0
# setup-envtest tracks controller-runtime's minor (go.mod has v0.22.0), and its
# own tagged releases need a newer Go than this module's `go` line — v0.25.1,
# which `@latest` resolved to, requires Go 1.26. Before the toolchain pin above
# go would quietly fetch a 1.26 toolchain just to build a test helper for a
# 1.25 project; that is the drift the pin exists to stop. So pin the matching
# release-0.22 branch head as its pseudo-version (it requires only go 1.24.0),
# which also makes the build reproducible.
SETUP_ENVTEST_VERSION ?= v0.0.0-20260125163108-a19ec76a3c5d

controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)

golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary (the release binary, as its authors recommend over `go install`).
$(GOLANGCI_LINT): $(LOCALBIN)
	test -s $(GOLANGCI_LINT) && $(GOLANGCI_LINT) --version | grep -q "version $(GOLANGCI_LINT_VERSION:v%=%) " || \
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LOCALBIN) $(GOLANGCI_LINT_VERSION)

.PHONY: all help manifests generate fmt vet lint test test-unit test-integration test-coverage build run docker-build docker-push install uninstall deploy undeploy controller-gen envtest golangci-lint

test-coverage-meaningful: test ## Print coverage excluding generated code + main.go.
	@head -1 cover.out > cover.filtered.out
	@grep -v 'zz_generated' cover.out | grep -v '/main.go:' | tail -n +2 >> cover.filtered.out
	@echo "--- coverage (meaningful: excludes zz_generated.*.go and main.go) ---"
	@go tool cover -func cover.filtered.out | tail -1
