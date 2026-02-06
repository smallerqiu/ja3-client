# 编译 Linux 版本 (在 Docker 中执行)
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.24.1 \
    sh -c "apt-get update && apt-get install -y gcc-multilib && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -buildmode=c-shared -o build/linux/ja3_client.so main.go"

# 编译 Windows 版本 (在 Docker 中执行)
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.24.1 \
    sh -c "apt-get update && apt-get install -y mingw-w64 && \
    CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -ldflags='-s -w' -buildmode=c-shared -o build/windows/ja3_client.dll main.go"

# 编译 macOS 版本 (直接在你的 Mac 宿主机执行)
go build -ldflags="-s -w" -buildmode=c-shared -o build/darwin/ja3_client.dylib main.go