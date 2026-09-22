TARGET := wasm32-wasip1
CARGO_ANYPOINT_VERSION := 1.10.0

.DEFAULT_GOAL := help

.PHONY: help
help: ## List all available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: install-cargo-anypoint ## Setup all required tools to build
	cargo fetch

.PHONY: install-cargo-anypoint
install-cargo-anypoint: ## Install the cargo-anypoint plugin
	cargo install cargo-anypoint@$(CARGO_ANYPOINT_VERSION)

.PHONY: build-asset-files
build-asset-files: ## Generate policy asset files and update src/generated/config.rs from definition/gcl.yaml
	cargo anypoint build-asset-files

.PHONY: build
build: build-asset-files ## Build the policy WebAssembly binary
	cargo build --target $(TARGET) --release

.PHONY: run
run: build ## Run the policy locally with Docker (requires playground/conf.d/registration.yaml)
	docker compose -f playground/docker-compose.yaml up --build

.PHONY: test
test: ## Run integration tests
	cargo test

.PHONY: publish
publish: build ## Publish the policy to Anypoint Exchange (development version)
	cargo anypoint publish

.PHONY: release
release: build ## Release the policy to Anypoint Exchange (production version)
	cargo anypoint release

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
