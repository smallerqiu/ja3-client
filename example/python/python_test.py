import ctypes
import unittest
import json

lib = ctypes.CDLL('./ja3-client-darwin-arm64.dylib')

# todo:
def test_request():
    req = {
        "url": "https://www.google.com",
        "method": "GET",
        "proxy": "http://127.0.0.1:7890",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
        },
        "impersonate": "chrome_133"
    }
    requestStr = json.dumps(req)
    # print(requestStr)
    res = lib.request("requestStr")
    print(res)


if __name__ == '__main__':
    # unittest.main()
    test_request()
