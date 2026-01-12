LIBS_PACKAGES := libkels libkels-derive
LIBS_DIR := lib
LIBS_SUBDIRS := kels kels-derive

SERVICE_PACKAGES := kels
SERVICES_DIR := services

CLIENT_PACKAGES := kels-bench
CLIENTS_DIR := clients

PACKAGES := $(LIBS_PACKAGES) $(SERVICE_PACKAGES) $(CLIENT_PACKAGES)

.PHONY: all build clean clippy deny fmt fmt-check install-deny test

all: fmt-check deny clippy test build

build:
	@for pkg in $(PACKAGES); do \
		echo "Building $$pkg..."; \
		cargo build -p $$pkg --release || exit 1; \
	done

clean:
	@echo "Cleaning workspace..."
	cargo clean
	find . -type d -name "target" -exec rm -rf {} +

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

deny:
	@if ! command -v cargo-deny &> /dev/null; then \
		echo "cargo-deny not installed. Install with: cargo install cargo-deny"; \
		exit 1; \
	fi
	@for lib in $(LIBS_SUBDIRS); do \
		echo "Checking lib/$$lib..."; \
		(cd $(LIBS_DIR)/$$lib && cargo deny check -A no-license-field) || exit 1; \
	done
	@for service in kels; do \
		echo "Checking services/$$service..."; \
		(cd $(SERVICES_DIR)/$$service && cargo deny check -A no-license-field) || exit 1; \
	done
	@for client in kels-bench; do \
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
