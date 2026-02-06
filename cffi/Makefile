NAME=ja3_client
BUILD_DIR=build
SOURCE=main.go

LDFLAGS=-ldflags="-s -w"

.PHONY: all windows linux darwin clean help

all: clean linux windows darwin

## Linux (x86_64)
## if your system is mac , you need to install musl-gcc :
## brew install FiloSottile/musl-cross/musl-cross
linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)/linux
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
	CC=x86_64-linux-musl-gcc \
	go build $(LDFLAGS) \
		-buildmode=c-shared \
		-o $(BUILD_DIR)/linux/$(NAME).so $(SOURCE)

## Windows (x86_64)

## if your system is mac , you need to install mingw-w64 :
## brew install mingw-w64

windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)/windows
	# 注意：跨平台编译需要指定 CC (C 编译器)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
	CC=x86_64-w64-mingw32-gcc \
	go build $(LDFLAGS) \
		-buildmode=c-shared \
		-o $(BUILD_DIR)/windows/$(NAME).dll $(SOURCE)

## macOS (支持 Intel 和 Apple Silicon)
darwin: darwin-amd64 darwin-arm64

darwin-amd64:
	@echo "Building for macOS (Intel)..."
	@mkdir -p $(BUILD_DIR)/darwin
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) \
		-buildmode=c-shared \
		-o $(BUILD_DIR)/darwin/$(NAME)_amd64.dylib $(SOURCE)

darwin-arm64:
	@echo "Building for macOS (M1/M2/M3)..."
	@mkdir -p $(BUILD_DIR)/darwin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) \
		-buildmode=c-shared \
		-o $(BUILD_DIR)/darwin/$(NAME)_arm64.dylib $(SOURCE)

# 清理构建目录
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)

# 帮助信息
help:
	@echo "Usage:"
	@echo "  make all      - Build for all platforms"
	@echo "  make linux    - Build for Linux"
	@echo "  make windows  - Build for Windows (requires mingw-w64)"
	@echo "  make darwin   - Build for macOS (Intel & M-Series)"
	@echo "  make clean    - Remove build directory"