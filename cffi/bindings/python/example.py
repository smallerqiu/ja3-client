"""Run me after `make host` in cffi/: python3 example.py

Mirrors the Node and C# examples so the three bindings can be compared line by line.
"""

from __future__ import annotations

import json

from ja3_client import Ja3, Ja3Error


def main() -> int:
    ja3 = Ja3()
    print(f"library {ja3.version()} from {ja3.path}")

    report = ja3.get(
        "https://tls.browserleaks.com/json",
        impersonate="chrome_133",
        timeout=20,
    )
    print("browserleaks", report.status_code, report.protocol, report.json()["ja3n_hash"],
          "warnings=", report.warnings)

    with ja3.session(impersonate="chrome_126", timeout=20) as session:
        first = session.get("https://httpbin.org/get")
        print("session", session.handle, first.status_code,
              first.json()["headers"]["User-Agent"][:30])

        posted = session.post(
            "https://httpbin.org/post",
            body={"k": "中文"},
            headers={"content-type": "application/json"},
        )
        print("post", posted.status_code, json.dumps(posted.json()["json"], ensure_ascii=False))

        dropped = session.get("https://httpbin.org/headers", headers={"user-agent": None})
        print("user-agent removed ->", dropped.json()["headers"], dropped.warnings)

    binary = ja3.get("https://www.google.com/favicon.ico")
    print("favicon", binary.status_code, len(binary.content), "bytes",
          binary.header("content-type"), binary.content[:4].hex())

    typo = ja3.get("https://httpbin.org/get", impersonate="chrome_133", with_http4=True)
    print("unknown option is reported, not dropped:", typo.warnings, typo.status_code)

    try:
        ja3.get("", impersonate="chrome_133")
    except Ja3Error as error:
        print("missing url ->", error.name, error)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
