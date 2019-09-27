GO = go
GO_FLAGS =
GOFMT = gofmt
DOCKER = docker
EGRESSIP_CONTROLLER_IMAGE = static-egressip-controller
EGRESSIP_GATEWAY_MANAGER_IMAGE = static-egressip-gateway-manager
OS = linux
ARCH = amd64
BUNDLES = bundles
GO_PACKAGES = ./cmd/... ./pkg/...
GO_FILES := $(shell find $(shell $(GO) list -f '{{.Dir}}' $(GO_PACKAGES)) -name \*.go)

all: controller-container manager-container

default: binary

controller-binary:
	CGO_ENABLED=1 ./script/controller-binary

manager-binary:
	CGO_ENABLED=1 ./script/gateway-manager-binary

update:
	./hack/update-codegen.sh

controller-container:
	docker build -t jmalmeid/$(EGRESSIP_CONTROLLER_IMAGE):1.1 -f Dockerfile.controller .
	docker push docker.io/jmalmeid/$(EGRESSIP_CONTROLLER_IMAGE):1.1
	docker tag docker.io/jmalmeid/$(EGRESSIP_CONTROLLER_IMAGE):1.1 docker.io/jmalmeid/$(EGRESSIP_CONTROLLER_IMAGE):latest
	docker push docker.io/jmalmeid/$(EGRESSIP_CONTROLLER_IMAGE):latest

manager-container:
	docker build -t jmalmeid/$(EGRESSIP_GATEWAY_MANAGER_IMAGE):latest -f Dockerfile.manager .
	docker push docker.io/jmalmeid/$(EGRESSIP_GATEWAY_MANAGER_IMAGE):1.1
	docker tag docker.io/jmalmeid/$(EGRESSIP_GATEWAY_MANAGER_IMAGE):1.1 jmalmeid/$(EGRESSIP_GATEWAY_MANAGER_IMAGE):latest
	docker push docker.io/jmalmeid/$(EGRESSIP_GATEWAY_MANAGER_IMAGE):latest
