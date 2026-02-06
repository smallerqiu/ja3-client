import ctypes
import platform
import json
import os
from typing import Dict, Any


class JA3Client:
    _instance = None

    def __new__(cls, lib_dir="./build"):
        if cls._instance is None:
            cls._instance = super(JA3Client, cls).__new__(cls)
            cls._instance._load_library(lib_dir)
        return cls._instance

    def _load_library(self, lib_dir: str):
        # 1. 识别操作系统与架构
        system = platform.system()
        arch = platform.machine().lower()  # x86_64, arm64, amd64

        if system == "Windows":
            lib_file = "windows/ja3_client.dll"
        elif system == "Darwin":  # macOS
            # 根据架构加载对应的 dylib
            suffix = (
                "arm64" if "arm" in arch or "m1" in arch or "m2" in arch else "amd64"
            )
            lib_file = f"darwin/ja3_client_{suffix}.dylib"
        else:  # Linux
            lib_file = "linux/ja3_client.so"

        lib_path = os.path.join(lib_dir, lib_file)
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"找不到库文件: {lib_path}. 请先执行 make 编译。")

        # 2. 加载动态库
        self.lib = ctypes.CDLL(os.path.abspath(lib_path))

        # 3. 定义 Go 函数的参数与返回类型
        self.lib.request.argtypes = [ctypes.c_char_p]
        self.lib.request.restype = ctypes.c_void_p

        self.lib.Free.argtypes = [ctypes.c_void_p]
        self.lib.Free.restype = None

    def request(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        发起 JA3 请求
        :param config: 包含 url, ja3, ua 等字段的字典
        """
        # 将 Python 字典转为 JSON 字节流
        json_payload = json.dumps(config).encode("utf-8")

        # 调用 Go 函数
        res_ptr = self.lib.request(json_payload)

        if not res_ptr:
            return {"error": "Go library returned null pointer", "StatusCode": 0}

        try:
            # 读取指针指向的字符串
            raw_bytes = ctypes.string_at(res_ptr)
            raw_data = raw_bytes.decode("utf-8")
            return json.loads(raw_data)
        except Exception as e:
            return {"error": f"Python parse error: {str(e)}", "StatusCode": 0}
        finally:
            # --- 极其重要：手动触发 Go 端的内存释放 ---
            if res_ptr:
                self.lib.Free(res_ptr)


# --- 使用示例 ---
if __name__ == "__main__":
    client = JA3Client()

    payload = {
        "url": "https://onlyfans.com/",
        "method": "GET",
        # "proxy": "http://127.0.0.1:7890",
        "headers": {
            "User-Agent": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"]
        },
        "impersonate": "chrome_136",
    }

    result = client.request(payload)
    # print(f"Status: {result}")
    # print(f"Status: {result.get('StatusCode')}")
    print(f"Body: {result.get('Body','')[:200]}...")  # 打印前200个字符
