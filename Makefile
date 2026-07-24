SHELL:=bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

default: help

.PHONY: help
help:     ## Show this help.
	@clear
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[0;33m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""


##@ Build sds-go

.PHONY: build-sds-go
build-sds-go: ## Build the sds-go lib (third-party active checkers included by default).
	@echo "Building sds-go lib"
	cd sds && cargo build --release --features dd_sds_go

.PHONY: build-sds-go-no-third-party-active-checkers
build-sds-go-no-third-party-active-checkers: ## Build the sds-go lib without third-party active checkers (drops reqwest/aws-sign-v4).
	@echo "Building sds-go lib without third-party active checkers"
	cd sds && cargo build --release --no-default-features --features dd_sds_go

.PHONY: update-sds-go-header
update-sds-go-header: ## Regenerate the C header used by the Go bindings.
	cd sds && cbindgen --quiet --config cbindgen.toml --crate dd-sensitive-data-scanner --output ../sds-go/go/dd_sds.h .

##@ Formatting

.PHONY: format-go
format-go: ## Format the golang lib.
	@echo "Formatting golang lib"
    # Only the sds-go folder needs to be checked since generation-checks takes care of the generated code
	$(shell gofmt -s -w sds-go/go && git diff --exit-code)

.PHONY: format-rust
format-rust: ## Format the rust lib.
	@echo "Formatting rust lib"
	cd sds && cargo fmt --all

.PHONY: format-all
format-all: format-rust format-go ## Format the rust lib and golang libs.

##@ Testing

.PHONY: test-go
test-go: ## Test the golang lib.
	@echo "Testing golang lib"
	cd sds-go/go && LD_LIBRARY_PATH="$(ROOT_DIR)/sds/target/release" DYLD_LIBRARY_PATH="$(ROOT_DIR)/sds/target/release" go test ./...
	
.PHONY: test-rust
test-rust: ## Test the rust lib.
	@echo "Testing rust lib"
	cd sds && cargo test --lib --all-features

.PHONY: test-all
test-all: test-rust test-go ## Test the rust lib and golang libs.

.PHONY: test
test: test-all ## Alias for test-all

##@ Checks (format + test)

.PHONY: check-go
check-go: ## Check the golang lib.
	@echo "Checking golang lib"
	make format-go
	make test-go

.PHONY: check-rust
check-rust: ## Check the rust lib.
	@echo "Checking rust lib"
	bash ./scripts/rust_checks.sh

.PHONY: check-sds-go-bindings
check-sds-go-bindings: ## Build and test the Go bindings against the Rust library.
	cd sds && cbindgen --quiet --config cbindgen.toml --crate dd-sensitive-data-scanner --verify --output ../sds-go/go/dd_sds.h .
	$(MAKE) build-sds-go
	$(MAKE) test-go

##@ Licenses generation

.PHONY: update-licenses
update-licenses: ## Generate licenses for the project.
	@echo "Updating licenses"
	bash ./scripts/generate_license_3rdparty.sh

.PHONY: check-licenses
check-licenses: ## Check licenses for the project.
	@echo "Checking licenses"
	bash ./scripts/generate_license_3rdparty.sh check
