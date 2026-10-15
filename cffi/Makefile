# ja3-client shared library
#
#   make host            build for the machine you are on (default)
#   make test            go test for the FFI contract (offline, httptest based)
#   make smoke           load the host library and check the ABI, no network
#   make check           host build + go tests + smoke + every binding with a runtime here
#   make darwin          both macOS arches;  make linux / make windows likewise
#   make all             everything this machine can reach
#   make docker          the full matrix through build-docker.sh (needs Docker)
#   make package         zip build/ into dist/ the way the release workflow does
#   make clean           remove build/ and dist/
#
# Cross-compiler requirements:
#   linux-amd64/arm64 on macOS: brew install filosottile/musl-cross/musl-cross
#                     on Linux: native, nothing to install
#   windows-amd64/386:          brew install mingw-w64 / apt install gcc-mingw-w64
#   darwin-*:                   macOS host only
# Anything the host cannot reach belongs in CI (`make docker` or the release
# workflow), which is also where musl/arm-7 builds are reproducible.
#
# File names are part of the contract: the bindings under bindings/ search for
# exactly these, so renaming here has to be matched there.
#   darwin   build/darwin/ja3_client_<arch>.dylib
#   linux    build/linux/libja3_client_<arch>.so
#   windows  build/windows/ja3_client_<arch>.dll  (+ .lib import library, + .h)
#   <arch>   amd64 | arm64 | 386

NAME       := ja3_client
BUILD_DIR  := build
VERSION    ?= $(patsubst v%,%,$(shell git describe --tags --abbrev=0 2>/dev/null))
VERSION    := $(if $(VERSION),$(VERSION),dev)
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Stamped into ja3_version(): a library that cannot say which release it is makes
# fingerprint bug reports untriageable.
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

# cffi is a main module with its own go.mod. The repository's go.work would take
# over module resolution, so it has to be switched off here.
export GOWORK := off
export CGO_ENABLED := 1

HOST_OS   := $(shell go env GOOS)
HOST_ARCH := $(shell go env GOARCH)

# The one library this machine can dlopen, for `make smoke`.
ifeq ($(HOST_OS),darwin)
HOST_LIB := $(BUILD_DIR)/darwin/$(NAME)_$(HOST_ARCH).dylib
else ifeq ($(HOST_OS),linux)
HOST_LIB := $(BUILD_DIR)/linux/lib$(NAME)_$(HOST_ARCH).so
else
HOST_LIB := $(BUILD_DIR)/windows/$(NAME)_$(HOST_ARCH).dll
endif

# Native toolchain on Linux, musl cross elsewhere.
LINUX_NATIVE := $(filter linux,$(HOST_OS))

.PHONY: host test lint smoke node-smoke check all docker package \
        python-check node-check csharp-check clean help
.PHONY: darwin darwin-amd64 darwin-arm64 linux linux-amd64 linux-arm64 \
        windows windows-amd64 windows-386

host:
	@$(MAKE) --no-print-directory $(HOST_OS)-$(HOST_ARCH)

check: host test smoke node-smoke python-check node-check csharp-check

test:
	go test -count=1 ./...

# Loads the built library and asserts the ABI contract without making a request,
# so it works in CI and on a machine with no route to the internet. bindings/
# python/smoke.py and bindings/node/smoke.js are also the scripts to hand a user
# who downloaded a release artifact and is not sure the file is good - each release
# archive ships smoke.py next to the library.
smoke:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 missing; skipping" >&2; exit 0; }
	@test -f $(HOST_LIB) || { echo "$(HOST_LIB) is missing - run 'make host' first" >&2; exit 1; }
	cd bindings/python && python3 smoke.py ../../$(HOST_LIB)

node-smoke:
	@command -v node >/dev/null 2>&1 || { echo "node missing; skipping" >&2; exit 0; }
	@test -f $(HOST_LIB) || { echo "$(HOST_LIB) is missing - run 'make host' first" >&2; exit 1; }
	cd bindings/node && { test -d node_modules/koffi || npm install --no-audit --no-fund; } && node smoke.js ../../$(HOST_LIB)

lint:
	@test -z "$(shell gofmt -l .)" || (echo "run gofmt on:" && gofmt -l . && exit 1)
	go vet ./...

# --- macOS ---------------------------------------------------------------
# GOARCH has to be spelled out: without it the "amd64" target builds the host
# arch twice, and an Apple Silicon machine ships an arm64 file named amd64.
darwin: darwin-amd64 darwin-arm64

darwin-amd64:
	@mkdir -p $(BUILD_DIR)/darwin
	GOOS=darwin GOARCH=amd64 go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,-install_name,@rpath/$(NAME)_amd64.dylib" \
		-o $(BUILD_DIR)/darwin/$(NAME)_amd64.dylib .

darwin-arm64:
	@mkdir -p $(BUILD_DIR)/darwin
	GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,-install_name,@rpath/$(NAME)_arm64.dylib" \
		-o $(BUILD_DIR)/darwin/$(NAME)_arm64.dylib .

# --- Linux ---------------------------------------------------------------
# The soname equals the file name: a versioned file claiming to be
# libja3-client.so makes every consumer resolve a library that is not on disk.
linux: linux-amd64 linux-arm64

linux-amd64:
	@mkdir -p $(BUILD_DIR)/linux
	GOOS=linux GOARCH=amd64 \
		$(if $(LINUX_NATIVE),,CC=x86_64-linux-musl-gcc HOSTCC=x86_64-linux-musl-gcc) \
		go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,-soname,lib$(NAME)_amd64.so" \
		-o $(BUILD_DIR)/linux/lib$(NAME)_amd64.so .

linux-arm64:
	@mkdir -p $(BUILD_DIR)/linux
	GOOS=linux GOARCH=arm64 \
		$(if $(LINUX_NATIVE),,CC=aarch64-linux-musl-gcc HOSTCC=aarch64-linux-musl-gcc) \
		go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,-soname,lib$(NAME)_arm64.so" \
		-o $(BUILD_DIR)/linux/lib$(NAME)_arm64.so .

# --- Windows -------------------------------------------------------------
# mingw is told to write the import library next to the dll: MSVC cannot link
# against a .dll alone, and without the .lib a C++ consumer has to LoadLibrary.
# The path has to be absolute - go runs the C linker from a temporary directory,
# so a relative -o style path lands in "can't open .lib file".
windows: windows-amd64 windows-386

windows-amd64:
	@mkdir -p $(BUILD_DIR)/windows
	GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,--out-implib,$(CURDIR)/$(BUILD_DIR)/windows/$(NAME)_amd64.lib" \
		-o $(BUILD_DIR)/windows/$(NAME)_amd64.dll .

windows-386:
	@mkdir -p $(BUILD_DIR)/windows
	GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc \
		go build -buildmode=c-shared \
		-ldflags="$(LDFLAGS) -extldflags=-Wl,--out-implib,$(CURDIR)/$(BUILD_DIR)/windows/$(NAME)_386.lib" \
		-o $(BUILD_DIR)/windows/$(NAME)_386.dll .

all: darwin linux windows

docker:
	./build-docker.sh $(VERSION)

# Zip everything under build/ the way the release workflow does, so a local
# `make docker && make package` produces the same archives as a GitHub release.
package:
	./package-release.sh dist $(VERSION)

# --- bindings ------------------------------------------------------------
# Each binding locates the library on its own, so these also exercise the search
# paths, not just the ABI.
python-check:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 missing; skipping" >&2; exit 0; }
	cd bindings/python && python3 example.py

node-check:
	@command -v node >/dev/null 2>&1 || { echo "node missing; skipping" >&2; exit 0; }
	cd bindings/node && { test -d node_modules/koffi || npm install --no-audit --no-fund; } && node example.js

csharp-check:
	@command -v dotnet >/dev/null 2>&1 || test -x /usr/local/share/dotnet/dotnet || \
		{ echo "dotnet missing; skipping" >&2; exit 0; }
	cd bindings/csharp/example && PATH="/usr/local/share/dotnet:$$PATH" dotnet run

clean:
	rm -rf $(BUILD_DIR) dist
	rm -rf bindings/python/__pycache__ bindings/node/node_modules
	rm -rf bindings/csharp/example/bin bindings/csharp/example/obj

help:
	@awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' Makefile
