SHELL := /bin/bash

LIBS_PACKAGES := kels-core kels-derive kels-creds kels-policy kels-exchange kels-ffi kels-mock-hsm
LIBS_DIR := lib
LIBS_SUBDIRS := kels derive creds policy exchange ffi mock-hsm

SERVICE_PACKAGES := kels
SERVICES_DIR := services

CLIENT_PACKAGES := bench
CLIENTS_DIR := clients

PACKAGES := $(LIBS_PACKAGES) $(SERVICE_PACKAGES) $(CLIENT_PACKAGES)

# Read federated registries - just the prefixes (for compile-time trust anchor)
TRUSTED_REGISTRY_PREFIXES := $(shell jq -r '[.[].prefix] | join(",")' .kels/federated-registries.json 2>/dev/null || echo "KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
export TRUSTED_REGISTRY_PREFIXES

TRUSTED_REGISTRY_MEMBERS := $(shell jq -c '[.[] | {id, prefix, active}]' .kels/federated-registries.json 2>/dev/null || echo '[{"id":0,"prefix":"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","active":true}]')
export TRUSTED_REGISTRY_MEMBERS

.PHONY: all build check clean clean-docker clean-test-containers clippy clippy-fix coverage deny fmt fmt-check install-deny lint-terminology test ios-simulator redeploy-registries restart-gossip-services test-resync test-grow-federation test-shrink-federation test-peer-lifecycle test-rotation test-node test-federation test-kels-suite test-sad-suite test-exchange-suite test-creds-suite wait-for-gossip

all: fmt-check lint-terminology deny check clippy test build

benchmark: clean-garden
	scripts/coredns.sh reset
	garden deploy test-client --env=node-a
	kubectl exec -n kels-node-a -it test-client -- ./bench-kels.sh 40 5

# Optional passthrough: set BUILD_ARGS to forward flags to cargo build.
# Examples:
#   make build BUILD_ARGS="-p kels-core"             # build one package
#   make build BUILD_ARGS="-p kels-core --tests"     # include test binaries
# When unset, builds the full workspace as before.
build:
	cargo build --workspace --all-features $(BUILD_ARGS)

clean:
	@echo "Cleaning workspace..."
	cargo clean
	find . -type d -name "target" -exec rm -rf {} +
	make -C clients/ios clean

clean-registries:
	garden cleanup namespace --env=registry-a
	garden cleanup namespace --env=registry-b
	garden cleanup namespace --env=registry-c
	garden cleanup namespace --env=registry-d

clean-nodes:
	garden cleanup namespace --env=node-a
	garden cleanup namespace --env=node-b
	garden cleanup namespace --env=node-c
	garden cleanup namespace --env=node-d
	garden cleanup namespace --env=node-e
	garden cleanup namespace --env=node-f

clean-standalone:
	garden cleanup namespace --env=standalone

clean-garden: clean-standalone clean-nodes clean-registries

clean-docker:
	@echo "Cleaning docker caches..."
	docker system prune -af --volumes && docker builder prune -af

clean-test-containers:
	@echo "Stopping and removing test containers..."
	@docker ps -q --filter "label=kels-test=true" | xargs -r docker stop 2>/dev/null || true
	@docker ps -aq --filter "label=kels-test=true" | xargs -r docker rm 2>/dev/null || true

# Optional passthrough: set CHECK_ARGS to forward flags to cargo check.
# Examples:
#   make check CHECK_ARGS="-p kels-core"             # check one package
# When unset, checks the full workspace.
check:
	cargo check --workspace --all-targets --all-features $(CHECK_ARGS)

# Optional passthrough: set CLIPPY_ARGS to forward flags to cargo clippy.
# Examples:
#   make clippy CLIPPY_ARGS="-p kels-core"           # lint one package
# When unset, lints the full workspace.
clippy:
	cargo clippy --workspace --all-targets --all-features $(CLIPPY_ARGS) -- -D warnings

clippy-fix:
	cargo clippy --fix --workspace --all-targets --all-features $(CLIPPY_ARGS) --allow-dirty --allow-staged

deny:
	@if ! command -v cargo-deny &> /dev/null; then \
		echo "cargo-deny not installed. Install with: cargo install cargo-deny"; \
		exit 1; \
	fi
	@for lib in $(LIBS_SUBDIRS); do \
		echo "Checking lib/$$lib..."; \
		(cd $(LIBS_DIR)/$$lib && cargo deny check -A no-license-field) || exit 1; \
	done
	@for service in identity kels gossip registry sadstore mail; do \
		echo "Checking services/$$service..."; \
		(cd $(SERVICES_DIR)/$$service && cargo deny check -A no-license-field) || exit 1; \
	done
	@for client in cli bench; do \
		echo "Checking clients/$$client..."; \
		(cd $(CLIENTS_DIR)/$$client && cargo deny check -A no-license-field) || exit 1; \
	done
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

install-deny:
	cargo install cargo-deny

lint-terminology:
	@if git ls-files -z \
			':!:docs/claudit' \
			':!:.terminology-forbidden' \
			':!:Makefile' \
		| xargs -0 grep -nE -f <(grep -vE '^(#|$$)' .terminology-forbidden); then \
		echo "ERROR: forbidden terminology found (see .terminology-forbidden)"; \
		exit 1; \
	fi

# Optional passthrough: set TEST_ARGS to forward flags to cargo test.
# Examples:
#   make test TEST_ARGS="--test sad_builder_tests"   # run one test binary
#   make test TEST_ARGS="-p kels-core"               # run one package
#   make test TEST_ARGS="some_test_name"             # filter by name
# When unset, runs the full workspace suite as before.
test:
	cargo test --workspace --all-features $(TEST_ARGS)

test-verbose:
	cargo test --workspace --all-features $(TEST_ARGS) -- --nocapture

# Files excluded from coverage (can't be meaningfully unit tested):
# - Binary mains (main.rs, admin.rs) - entry points only
# - FFI code (kels-ffi) - C bindings
# - Server setup (server.rs in services) - integration code
# - Federation orchestration (federation/mod.rs, federation/sync.rs) - requires Raft cluster
COV_EXCLUDES := --ignore-filename-regex '(main\.rs|admin\.rs|lib/ffi|services/.*/server\.rs|federation/mod\.rs|federation/sync\.rs|raft_store\.rs|peer_store\.rs|repository_store\.rs|identity_client\.rs)'

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

ios-simulator:
	$(MAKE) -C clients/ios simulator DEV_TOOLS=1

configure-dns:
	scripts/coredns.sh apply

# Garden's bundled traefik uses ClusterIP, but Docker Desktop needs LoadBalancer to expose ports.
fix-ingress:
	kubectl patch svc garden-traefik -n garden-system -p '{"spec": {"type": "LoadBalancer"}}'

reset-federation-json:
	# Reset federation prefixes
	echo '[]' > .kels/federated-registries.json

deploy-registry-identities:
	# Deploy registry identities
	garden deploy identity --env=registry-a
	garden deploy identity --env=registry-b
	garden deploy identity --env=registry-c


deploy-registries:
	# Deploy registries
	garden deploy --env=registry-a
	garden deploy --env=registry-b
	garden deploy --env=registry-c

fetch-prefixes:
	# Fetch prefixes
	garden run federation-fetch --env=registry-a
	garden run federation-fetch --env=registry-b
	garden run federation-fetch --env=registry-c

test-voting:
	scripts/test-voting.sh

deploy-nodes:
	scripts/deploy-nodes.sh node-a node-b node-c node-d node-e node-f

vote-nodes:
	scripts/vote-nodes.sh registry-a registry-b registry-c -- node-a node-b node-c node-d node-e node-f

restart-gossip-services:
	scripts/restart-gossip.sh

restart-gossip-services-staggered:
	@for node in a b c d e f; do \
		echo "Restarting gossip on node-$$node..."; \
		kubectl rollout restart deployment/gossip -n kels-node-$$node; \
		kubectl rollout status deployment/gossip -n kels-node-$$node; \
		sleep 10; \
	done
	scripts/dump-gossip-logs.sh
	! grep -R ERROR logs

test-resync:
	scripts/coredns.sh apply
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh seed
	scripts/coredns.sh break-node-b
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh setup
	scripts/coredns.sh apply
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh verify

test-grow-federation:
	scripts/test-grow-federation.sh

test-shrink-federation:
	scripts/test-shrink-federation.sh

seed-kels:
	kubectl exec -n kels-node-a -it test-client -- ./load-kels.sh 500 5 ml-dsa-65 50 

seed-sads:
	kubectl exec -n kels-node-a -it test-client -- ./load-sad.sh 553 50

wait-for-gossip:
	scripts/wait-for-gossip.sh 180 node-a node-b node-c node-d node-e node-f

test-rotation:
	# Run scheduled-rotate 4 times on registry-a identity
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	# Verify KEL event types from test-client (identity-admin is synchronous, no wait needed)
	kubectl exec -n kels-node-a -it test-client -- bash -c 'IDENTITY_NS=registry-a ./test-scheduled-rotation.sh'
	# Rotate on node-a identity — test-gossip.sh has its own convergence polling
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	# Verify cross-node ops still work after rotation (no restarts)
	kubectl exec -n kels-node-a -it test-client -- ./test-gossip.sh

rotate-registry-b:
	# If there are issues with verification after rotation, this will break voting
	kubectl exec -n kels-registry-b deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	# Wait for sync loop to pick up rotation (not required due to upcoming vote which will sync)
	# sleep 30

test-kels-suite:
	$(MAKE) wait-for-gossip
	DNS_CACHE_TTL=2 scripts/coredns.sh apply
	kubectl exec -n kels-node-a -it test-client -- ./test-redis-acl.sh
	# 60 concurrency / 5s duration more or less saturates the primary developer's laptop
	kubectl exec -n kels-node-a -it test-client -- ./bench-kels.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-adversarial.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-adversarial-advanced.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-reconciliation.sh
	kubectl exec -n kels-node-a -it test-client -- ./test-gossip.sh
	$(MAKE) test-rotation
	kubectl exec -n kels-node-a -it test-client -- ./test-bootstrap.sh
	DNS_CACHE_TTL=2 $(MAKE) test-resync
	scripts/coredns.sh apply

test-sad-suite:
	kubectl exec -n kels-node-a -it test-client -- ./test-sadstore.sh

test-exchange-suite:
	kubectl exec -n kels-node-a -it test-client -- ./test-exchange.sh

test-creds-suite:
	kubectl exec -n kels-node-a -it test-client -- ./test-creds.sh

test-grow-shrink:
	$(MAKE) test-grow-federation
	$(MAKE) test-shrink-federation

test-peer-lifecycle:
	scripts/test-peer-lifecycle.sh node-f registry-a registry-c registry-d

test-kel-consistency:
	kubectl exec -n kels-node-a -it test-client -- ./test-kel-consistency.sh

test-sad-consistency:
	kubectl exec -n kels-node-a -it test-client -- ./test-sad-consistency.sh

deploy-fresh-node:
	garden deploy --env=standalone

deploy-fresh-federation: configure-dns reset-federation-json deploy-registry-identities fetch-prefixes deploy-registries deploy-nodes vote-nodes restart-gossip-services

test-node: clean-standalone deploy-fresh-node
	kubectl exec -n kels-standalone -it test-client -- ./test-kels.sh
	kubectl exec -n kels-standalone -it test-client -- ./test-adversarial.sh
	kubectl exec -n kels-standalone -it test-client -- env FEDERATED=false ./test-sadstore.sh
	kubectl exec -n kels-standalone -it test-client -- env FEDERATED=false ./test-exchange.sh
	kubectl exec -n kels-standalone -it test-client -- env FEDERATED=false ./test-creds.sh
	kubectl exec -n kels-standalone -it test-client -- ./bench-kels.sh

test-federation: clean-garden configure-dns reset-federation-json deploy-registry-identities fetch-prefixes deploy-registries test-voting deploy-nodes seed-kels seed-sads rotate-registry-b vote-nodes restart-gossip-services-staggered test-kels-suite test-sad-suite test-exchange-suite test-creds-suite test-grow-shrink test-peer-lifecycle test-sad-consistency test-kel-consistency

test-all-deployments: clean-garden test-node test-federation
