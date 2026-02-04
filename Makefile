LIBS_PACKAGES := libkels libkels-derive libkels-ffi
LIBS_DIR := lib
LIBS_SUBDIRS := kels kels-derive kels-ffi

SERVICE_PACKAGES := kels
SERVICES_DIR := services

CLIENT_PACKAGES := kels-bench
CLIENTS_DIR := clients

PACKAGES := $(LIBS_PACKAGES) $(SERVICE_PACKAGES) $(CLIENT_PACKAGES)

# Read federated registries - just the prefixes (for compile-time trust anchor)
TRUSTED_REGISTRY_PREFIXES := $(shell jq -r '[.[] | values] | join(",")' .kels/federated-registries.json 2>/dev/null || echo "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
export TRUSTED_REGISTRY_PREFIXES

.PHONY: all build clean clean-docker clippy coverage deny fmt fmt-check install-deny test kels-client-simulator

all: fmt-check deny clippy test build

build:
	cargo build --workspace --all-features

clean:
	@echo "Cleaning workspace..."
	cargo clean
	find . -type d -name "target" -exec rm -rf {} +
	make -C clients/kels-client clean

clean-docker:
	@echo "Cleaning docker caches..."
	docker system prune -af --volumes && docker builder prune -af

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

# Files excluded from coverage (can't be meaningfully unit tested):
# - Binary mains (main.rs, admin.rs) - entry points only
# - FFI code (kels-ffi) - C bindings
# - Server setup (server.rs in services) - integration code
# - Federation orchestration (federation/mod.rs, federation/sync.rs) - requires Raft cluster
COV_EXCLUDES := --ignore-filename-regex '(main\.rs|admin\.rs|kels-ffi|services/.*/server\.rs|federation/mod\.rs|federation/sync\.rs)'

coverage:
	@if ! command -v cargo-llvm-cov &> /dev/null; then \
		echo "cargo-llvm-cov not installed. Install with: cargo install cargo-llvm-cov"; \
		exit 1; \
	fi
	@printf "%-60s %8s %8s\n" "File" "Coverage" "Missed"
	@echo ""
	@cargo llvm-cov --workspace $(COV_EXCLUDES) 2>&1 | awk '\
		NR == 1 { next } \
		/^-+$$/ { next } \
		/^TOTAL/ { print $$10 > "/tmp/cov_total"; next } \
		NF >= 13 && $$10 ~ /%$$/ { printf "%-60s %8s %8d\n", $$1, $$10, $$9 }' \
		| sort -k3 -rn
	@echo ""
	@echo "TOTAL: $$(cat /tmp/cov_total)"
	@cargo llvm-cov --workspace $(COV_EXCLUDES) --html --no-run >/dev/null 2>&1
	@echo ""
	@echo "Full report: target/llvm-cov/html/index.html"

kels-client-simulator:
	$(MAKE) -C clients/kels-client simulator DEV_TOOLS=1

test-comprehensive:
	echo '{}' > .kels/federated-registries.json

	# Cleanup all environments
	garden cleanup deploy --env=registry-a && garden cleanup deploy --env=registry-b && garden cleanup deploy --env=registry-c
	garden cleanup deploy --env=node-a && garden cleanup deploy --env=node-b && garden cleanup deploy --env=node-c && garden cleanup deploy --env=node-d && garden cleanup deploy --env=node-e

	# Deploy registries and fetch prefixes
	garden deploy --env=registry-a && garden run fetch-registry-prefix --env=registry-a
	garden deploy --env=registry-b && garden run fetch-registry-prefix --env=registry-b
	garden deploy --env=registry-c && garden run fetch-registry-prefix --env=registry-c

	# Redeploy registries with federation config (now that all prefixes are known)
	garden deploy --env=registry-a
	garden deploy --env=registry-b
	garden deploy --env=registry-c

	# Wait for federation leader election
	sleep 3

	# Deploy nodes and add as core peers to leader - federation replicates to other registries
	garden deploy --env=node-a && garden run add-node-a
	kubectl rollout restart deployment/kels-gossip -n kels-node-a && kubectl rollout status deployment/kels-gossip -n kels-node-a
	kubectl exec -n kels-node-a -it test-client -- ./test-kels.sh

	garden deploy --env=node-b && garden run add-node-b
	kubectl rollout restart deployment/kels-gossip -n kels-node-b && kubectl rollout status deployment/kels-gossip -n kels-node-b
	kubectl exec -n kels-node-a -it test-client -- ./test-kels.sh

	garden deploy --env=node-c && garden run add-node-c
	kubectl rollout restart deployment/kels-gossip -n kels-node-c && kubectl rollout status deployment/kels-gossip -n kels-node-c
	kubectl exec -n kels-node-a -it test-client -- ./test-kels.sh

	# Deploy node-d as regional to registry-a only (not replicated via federation)
	garden deploy --env=node-d && garden run add-node-d --env=registry-a
	kubectl rollout restart deployment/kels-gossip -n kels-node-d && kubectl rollout status deployment/kels-gossip -n kels-node-d
	kubectl exec -n kels-node-a -it test-client -- ./test-kels.sh

	# Deploy node-d as regional to registry-a only (not replicated via federation)
	garden deploy --env=node-e && garden run add-node-e --env=registry-c
	kubectl rollout restart deployment/kels-gossip -n kels-node-e && kubectl rollout status deployment/kels-gossip -n kels-node-e
	kubectl exec -n kels-node-a -it test-client -- ./test-kels.sh

	kubectl exec -n kels-node-a -it test-client -- ./bench-kels.sh 40 3
	kubectl exec -n kels-node-a -it test-client -- ./test-adversarial.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-gossip.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-bootstrap.sh