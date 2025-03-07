import ctypes

# 加载 Go 生成的动态库
lib = ctypes.CDLL('./ja3-client-darwin-arm64.dylib')

# 调用 SayHello 函数

req = {
    "host": "www.baidu.com",
}

lib.request(b"Python")