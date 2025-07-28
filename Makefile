SHELL:=bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

default: help

.PHONY: help
help:     ## Show this help.
	@clear
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[0;33m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""

##@ Formatting

.PHONY: format-go
format-go: ## Format the golang lib.
	@echo "Formatting golang lib"
    # Only the sds-go folder needs to be checked since generation-checks takes care of the generated code
	$(shell gofmt -s -w sds-go/go && git diff --exit-code)

.PHONY: format-rust
format-rust: ## Format the rust lib.
	@echo "Formatting rust lib"
	cargo fmt --manifest-path="sds/Cargo.toml" --all
	cargo fmt --manifest-path="sds-go/rust/Cargo.toml" --all

##@ Checks

.PHONY: check-go
check-go: ## Check the golang lib.
	@echo "Checking golang lib"
	make format-go
	make test-go

.PHONY: check-rust
check-rust: ## Check the rust lib.
	@echo "Checking rust lib"
	bash ./scripts/rust_checks.sh
	
##@ Testing

.PHONY: test-go
test-go: ## Test the golang lib.
	@echo "Testing golang lib"
	cd sds-go/go && go test ./...
	
.PHONY: test-rust
test-rust: ## Test the rust lib.
	@echo "Testing rust lib"
	cargo test --manifest-path="sds/Cargo.toml" --workspace
	cargo test --manifest-path="sds-go/rust/Cargo.toml" --workspace

.PHONY: test-all
test-all: test-rust test-go ## Test the rust lib and golang libs.

.PHONY: test
test: test-all ## Alias for test-all

##@ Build sds-go

.PHONY: build-sds-go
build-sds-go: ## Build the sds-go lib.
	@echo "Building sds-go lib"
	cargo build --manifest-path="sds-go/rust/Cargo.toml" --release

##@ Licenses generation

.PHONY: update-licenses
update-licenses: ## Generate licenses for the project.
	@echo "Updating licenses"
	bash ./scripts/generate_license_3rdparty.sh

.PHONY: check-licenses
check-licenses: ## Check licenses for the project.
	@echo "Checking licenses"
	bash ./scripts/generate_license_3rdparty.sh check
