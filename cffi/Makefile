# define the supported platforms and architectures
PLATFORMS = linux/amd64 windows/amd64 darwin/amd64 linux/arm64

# define the shared library prefix and extension
LIB_PREFIX = ja3_client
LIB_EXT_linux = .so
LIB_EXT_windows = .dll
LIB_EXT_darwin = .dylib

# default target
all: $(PLATFORMS)

$(PLATFORMS):
	@echo "Building for $@"
	@$(MAKE) build-platform GOOS=$(word 1, $(subst /, ,$@)) GOARCH=$(word 2, $(subst /, ,$@))

build-platform:
	@echo "Building for $(GOOS)/$(GOARCH)"
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(LIB_PREFIX)_$(GOOS)_$(GOARCH)$(LIB_EXT_$(GOOS)) -buildmode=c-shared main.go

clean:
	@rm -f $(LIB_PREFIX)_*
	@echo "Cleaned up all generated files."