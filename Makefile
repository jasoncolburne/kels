LIBS_PACKAGES := libkels libkels-derive libkels-ffi
LIBS_DIR := lib
LIBS_SUBDIRS := kels kels-derive kels-ffi

SERVICE_PACKAGES := kels
SERVICES_DIR := services

CLIENT_PACKAGES := kels-bench
CLIENTS_DIR := clients

PACKAGES := $(LIBS_PACKAGES) $(SERVICE_PACKAGES) $(CLIENT_PACKAGES)

# Read registry prefix from file (required for CLI builds)
REGISTRY_PREFIX_FILE := .kels/registry_prefix
REGISTRY_PREFIX := $(shell cat $(REGISTRY_PREFIX_FILE) 2>/dev/null || echo "")
export REGISTRY_PREFIX

.PHONY: all build clean clippy deny fmt fmt-check install-deny test kels-client-simulator

all: fmt-check deny clippy test build

build:
	cargo build --workspace --all-features

clean:
	@echo "Cleaning workspace..."
	cargo clean
	find . -type d -name "target" -exec rm -rf {} +

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

deny:
	@if ! command -v cargo-deny &> /dev/null; then \
		echo "cargo-deny not installed. Install with: cargo install cargo-deny"; \
		exit 1; \
	fi
	@for lib in $(LIBS_SUBDIRS); do \
		echo "Checking lib/$$lib..."; \
		(cd $(LIBS_DIR)/$$lib && cargo deny check -A no-license-field) || exit 1; \
	done
	@for service in hsm identity kels kels-gossip kels-registry; do \
		echo "Checking services/$$service..."; \
		(cd $(SERVICES_DIR)/$$service && cargo deny check -A no-license-field) || exit 1; \
	done
	@for client in kels-cli kels-bench; do \
		echo "Checking clients/$$client..."; \
		(cd $(CLIENTS_DIR)/$$client && cargo deny check -A no-license-field) || exit 1; \
	done
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

install-deny:
	cargo install cargo-deny

test:
	cargo test --workspace

kels-client-simulator:
	$(MAKE) -C clients/kels-client simulator DEV_TOOLS=1

test-comprehensive:
	touch .kels/registry_prefix

	garden cleanup deploy && garden cleanup deploy --env=node-b && garden cleanup deploy --env=node-c && garden cleanup deploy --env=registry
	garden deploy --env=registry && garden run fetch-registry-prefix --env=registry

	garden deploy --env node-a && garden run add-node-a --env registry
	kubectl rollout restart deployment/kels-gossip -n kels-node-a && kubectl rollout status deployment/kels-gossip -n kels-node-a
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh

	garden deploy --env=node-c && garden run add-node-c --env registry
	kubectl rollout restart deployment/kels-gossip -n kels-node-c && kubectl rollout status deployment/kels-gossip -n kels-node-c
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh

	garden deploy --env=node-b && garden run add-node-b --env registry
	kubectl rollout restart deployment/kels-gossip -n kels-node-b && kubectl rollout status deployment/kels-gossip -n kels-node-b
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh
	kubectl exec -it test-client -- ./test-kels.sh
	kubectl exec -it test-client -- ./test-adversarial.sh

	kubectl exec -it test-client -- ./test-gossip.sh
	kubectl exec -it test-client -- ./test-bootstrap.sh
