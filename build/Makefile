# 定义支持的平台和架构
PLATFORMS = linux/amd64 windows/amd64 darwin/amd64 linux/arm64

# 定义共享库的前缀和扩展名
LIB_PREFIX = ja3-client
LIB_EXT_linux = .so
LIB_EXT_windows = .dll
LIB_EXT_darwin = .dylib

# 默认目标：编译所有平台的共享库
all: $(PLATFORMS)

# 遍历平台并编译
$(PLATFORMS):
	@echo "Building for $@"
	@$(MAKE) build-platform GOOS=$(word 1, $(subst /, ,$@)) GOARCH=$(word 2, $(subst /, ,$@))

# 编译单个平台的共享库
build-platform:
	@echo "Building for $(GOOS)/$(GOARCH)"
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(LIB_PREFIX)_$(GOOS)_$(GOARCH)$(LIB_EXT_$(GOOS)) -buildmode=c-shared .

# 清理生成的文件
clean:
	@rm -f $(LIB_PREFIX)_*
	@echo "Cleaned up all generated files."

# 帮助信息
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all       Build shared libraries for all platforms (default)"
	@echo "  clean     Remove all generated files"
	@echo "  help      Show this help message"