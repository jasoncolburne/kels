LIBS_PACKAGES := kels-core kels-derive kels-creds kels-policy kels-ffi kels-mock-hsm
LIBS_DIR := lib
LIBS_SUBDIRS := kels derive creds policy ffi mock-hsm

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

.PHONY: all build clean clean-docker clean-test-containers clippy coverage deny fmt fmt-check install-deny test kels-client-simulator redeploy-registries restart-gossip-services test-resync test-removal test-grow-federation test-shrink-federation test-rotation test-kem-upgrade test-node test-federation test-kels-suite test-sad-suite wait-for-gossip

all: fmt-check deny clippy test build

benchmark: clean-garden
	scripts/coredns.sh reset
	garden deploy test-client --env=node-a
	kubectl exec -n kels-node-a -it test-client -- ./bench-kels.sh 40 5

build:
	cargo build --workspace --all-features

clean:
	@echo "Cleaning workspace..."
	cargo clean
	find . -type d -name "target" -exec rm -rf {} +
	make -C clients/kels-client clean

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
	@for service in identity kels gossip registry sadstore; do \
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

test:
	cargo test --workspace --all-features

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

kels-client-simulator:
	$(MAKE) -C clients/kels-client simulator DEV_TOOLS=1

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
	# Test voting
	garden deploy --env=node-a

	garden run propose-add-peer --var node=node-a 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-a.txt

	# Test 1a: unauthenticated GET to federation proposals endpoint should succeed (read-only)
	kubectl exec -n kels-node-a test-client -- curl -sf http://registry.kels-registry-a.kels/api/v1/federation/proposals/$$(cat /tmp/proposal-a.txt)

	# Test 1b: POST to federation proposals endpoint should fail (method not allowed)
	! kubectl exec -n kels-node-a test-client -- curl -sf -X POST -H 'Content-Type: application/json' -d '{}' http://registry.kels-registry-a.kels/api/v1/federation/proposals/$$(cat /tmp/proposal-a.txt)

	# Test 1c: proposal-status via admin CLI should succeed
	garden run proposal-status --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a

	# Test 2: propose and propose again (same node, should fail)
	! garden run propose-add-peer --var node=node-a 2>&1

	# Test 3: propose then withdraw (no votes — should succeed)
	garden run withdraw-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a

	# Re-propose (same node, previous proposal was withdrawn)
	garden run propose-add-peer --var node=node-a 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-a.txt

	# Test 4: two rejections kill the proposal, further votes fail
	garden run reject-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a
	garden run reject-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-b
	! garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-c

	# Re-propose (same node, previous proposal was rejected)
	garden run propose-add-peer --var node=node-a 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-a.txt

	# Test 5: vote then try to withdraw (has votes — should fail)
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a
	! garden run withdraw-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a

	# Continue voting to approve
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-c
	kubectl rollout restart deployment/gossip -n kels-node-a && kubectl rollout status deployment/gossip -n kels-node-a

	# Remove
	garden run propose-remove-peer --var node=node-a 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/removal-a.txt
	# Vote from all registries
	garden run vote-peer --var proposal=$$(cat /tmp/removal-a.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/removal-a.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/removal-a.txt) --env=registry-c

	# Clean up
	garden cleanup deploy --env node-a

deploy-nodes:
	garden deploy --env=node-a
	garden deploy --env=node-b
	garden deploy --env=node-c
	garden deploy --env=node-d
	garden deploy --env=node-e
	garden deploy --env=node-f

vote-nodes:
	garden run propose-add-peer --var node=node-a 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-a.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-a.txt) --env=registry-c

	garden run propose-add-peer --var node=node-b 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-b.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-b.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-b.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-b.txt) --env=registry-c

	garden run propose-add-peer --var node=node-c 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-c.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-c.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-c.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-c.txt) --env=registry-c

	garden run propose-add-peer --var node=node-d 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-d.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-d.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-d.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-d.txt) --env=registry-c

	garden run propose-add-peer --var node=node-e 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-e.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-e.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-e.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-e.txt) --env=registry-c

	garden run propose-add-peer --var node=node-f 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep "roposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1 > /tmp/proposal-f.txt
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-f.txt) --env=registry-a
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-f.txt) --env=registry-b
	garden run vote-peer --var proposal=$$(cat /tmp/proposal-f.txt) --env=registry-c

restart-gossip-services:
	kubectl rollout restart deployment/gossip -n kels-node-a
	kubectl rollout restart deployment/gossip -n kels-node-b
	kubectl rollout restart deployment/gossip -n kels-node-c
	kubectl rollout restart deployment/gossip -n kels-node-d
	kubectl rollout restart deployment/gossip -n kels-node-e
	kubectl rollout restart deployment/gossip -n kels-node-f
	kubectl rollout status deployment/gossip -n kels-node-a
	kubectl rollout status deployment/gossip -n kels-node-b
	kubectl rollout status deployment/gossip -n kels-node-c
	kubectl rollout status deployment/gossip -n kels-node-d
	kubectl rollout status deployment/gossip -n kels-node-e
	kubectl rollout status deployment/gossip -n kels-node-f

test-resync:
	scripts/coredns.sh apply
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh seed
	scripts/coredns.sh break-node-b
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh setup
	scripts/coredns.sh apply
	kubectl exec -n kels-node-a -it test-client -- ./test-resync.sh verify

test-grow-federation:
	# Deploy 4th registry standalone (generates identity)
	garden deploy identity --env=registry-d
	# Fetch its prefix (auto-assigns id=3)
	garden run federation-fetch --env=registry-d
	# Recompile and redeploy ALL 4 registries with updated trust anchors
	garden deploy --env=registry-a
	garden deploy --env=registry-b
	garden deploy --env=registry-c
	garden deploy --env=registry-d
	# Wait for Raft init + sync_membership
	sleep 15
	# Verify 4-member federation from test-client pod
	kubectl exec -n kels-node-a -it test-client -- ./test-grow-federation.sh

test-shrink-federation:
	# Deactivate registry-b in federation config
	scripts/federation-deactivate.sh registry-b .
	# Tear down registry-b
	garden cleanup namespace --env=registry-b
	# Recompile and redeploy remaining active registries (a, c, d)
	garden deploy --env=registry-a
	garden deploy --env=registry-c
	garden deploy --env=registry-d
	# Wait for Raft init + sync_membership
	sleep 15
	# Redeploy nodes so they pick up the new federation config
	$(MAKE) deploy-nodes
	$(MAKE) wait-for-gossip
	# Verify 3-member federation and gossip from test-client pod
	kubectl exec -n kels-node-a -it test-client -- ./test-shrink-federation.sh

seed-kels:
	kubectl exec -n kels-node-a -it test-client -- ./load-kels.sh 500 5 ml-dsa-65 50 

seed-sads:
	kubectl exec -n kels-node-a -it test-client -- ./load-sads.sh 774 50

wait-for-gossip:
	@echo "Waiting for all gossip nodes to be ready (timeout: 120s)..."
	@kubectl exec -n kels-node-a test-client -- sh -c '\
		elapsed=0; \
		while [ $$elapsed -lt 120 ]; do \
			all_ready=true; \
			for node in a b c d e f; do \
				status=$$(curl -s -o /dev/null -w "%{http_code}" http://gossip.kels-node-$$node.kels/ready 2>/dev/null); \
				if [ "$$status" != "200" ]; then \
					all_ready=false; \
					break; \
				fi; \
			done; \
			if $$all_ready; then \
				echo "All gossip nodes ready"; \
				exit 0; \
			fi; \
			sleep 2; \
			elapsed=$$((elapsed + 2)); \
		done; \
		echo "Timeout waiting for gossip nodes"; \
		exit 1'

test-rotation:
	# Run scheduled-rotate 4 times on registry-a identity
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	kubectl exec -n kels-registry-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	# Wait for sync loop to pick up rotations
	sleep 30
	# Verify KEL event types from test-client
	kubectl exec -n kels-node-a -it test-client -- bash -c 'IDENTITY_NS=kels-registry-a ./test-scheduled-rotation.sh'
	# Rotate on node-a identity and let gossip propagate
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json scheduled-rotate
	sleep 10
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
	kubectl exec -n kels-node-a -it test-client -- ./test-bootstrap.sh || { scripts/dump-gossip; false; }
	DNS_CACHE_TTL=2 $(MAKE) test-resync
	$(MAKE) test-kem-upgrade
	scripts/coredns.sh apply

test-sad-suite:
	kubectl exec -n kels-node-a -it test-client -- ./test-sadstore.sh

test-grow-shrink:
	$(MAKE) test-grow-federation
	$(MAKE) test-shrink-federation

test-kel-consistency:
	kubectl exec -n kels-node-a -it test-client -- ./test-kel-consistency.sh

test-sad-consistency:
	kubectl exec -n kels-node-a -it test-client -- ./test-sad-consistency.sh

test-kem-upgrade:
	# Upgrade node-a identity to ML-DSA-87: first rotation commits the new algorithm,
	# second rotation makes it the current signing key
	kubectl set env deploy/identity -n kels-node-a NEXT_SIGNING_ALGORITHM=ml-dsa-87
	kubectl rollout status deployment/identity -n kels-node-a
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json rotate
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json rotate
	# Restart all gossip pods so they re-handshake with the correct KEM algorithm
	$(MAKE) restart-gossip-services
	$(MAKE) wait-for-gossip
	# Verify gossip mesh reforms with ML-KEM-1024
	kubectl exec -n kels-node-a -it test-client -- ./test-gossip.sh
	# Restore node-a to ML-DSA-65: same two-rotation pattern
	kubectl set env deploy/identity -n kels-node-a NEXT_SIGNING_ALGORITHM=ml-dsa-65
	kubectl rollout status deployment/identity -n kels-node-a
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json rotate
	kubectl exec -n kels-node-a deploy/identity -c identity -- /app/identity-admin --json rotate
	# Restart gossip pods again to switch back to ML-KEM-768
	$(MAKE) restart-gossip-services
	$(MAKE) wait-for-gossip

deploy-fresh-node:
	garden deploy --env=standalone

deploy-fresh-federation: configure-dns reset-federation-json deploy-registry-identities fetch-prefixes deploy-registries deploy-nodes vote-nodes restart-gossip-services

test-node: clean-standalone deploy-fresh-node
	kubectl exec -n kels-standalone -it test-client -- ./test-kels.sh
	kubectl exec -n kels-standalone -it test-client -- ./test-adversarial.sh
	kubectl exec -n kels-standalone -it test-client -- ./bench-kels.sh

test-federation: clean-garden configure-dns reset-federation-json deploy-registry-identities fetch-prefixes deploy-registries test-voting deploy-nodes seed-kels seed-sads rotate-registry-b vote-nodes restart-gossip-services test-kels-suite test-sad-suite test-grow-shrink test-sad-consistency test-kel-consistency
