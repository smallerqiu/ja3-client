"""Check a built libja3-client shared library without touching the network.

    python3 smoke.py [path/to/library]        # or set JA3_CLIENT_LIB

This is what CI runs on every release artifact and what to run after downloading
one: it proves the file loads on this machine, speaks the ABI this binding
expects, and gets the envelope contract right. It deliberately makes no request,
so it works offline and never depends on a third-party site.

Run it from anywhere; the library is located by argument, then JA3_CLIENT_LIB,
then the usual build/ and dist/ directories.
"""

from __future__ import annotations

import ctypes
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ja3_client import ABI_VERSION, ERROR_CODES, Ja3, Ja3Error  # noqa: E402


class Check:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def expect(self, label: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  ok   {label}")
            return

        self.failures.append(label)
        print(f"  FAIL {label}{f': {detail}' if detail else ''}")


def raw_call(ja3: Ja3, export: str, payload: bytes) -> dict:
    """Call an export with a raw byte payload, honouring the free rule."""
    pointer = getattr(ja3._lib, export)(payload)

    if not pointer:
        raise AssertionError(f"{export} returned NULL")

    try:
        return json.loads(ctypes.string_at(pointer).decode("utf-8"))
    finally:
        ja3._lib.ja3_free(ctypes.c_void_p(pointer))


def main() -> int:
    check = Check()

    library = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        ja3 = Ja3(library)
    except Ja3Error as error:
        print(f"cannot load library: {error}")
        return 1

    print(f"library: {ja3.path}")

    # -- ja3_version: the export the bindings negotiate against --------------
    info = raw_call(ja3, "ja3_version", b"")
    print(f"version: {info.get('version')}  abi: {info.get('abi')}  "
          f"build_time: {info.get('build_time')}")

    check.expect("abi matches this binding", info.get("abi") == ABI_VERSION,
                 f"library says {info.get('abi')}, binding expects {ABI_VERSION}")
    check.expect("version is stamped", info.get("version") not in (None, "", "dev"),
                 'built without -X main.Version, so bug reports cannot name a release')
    check.expect("ok flag set", info.get("ok") is True, json.dumps(info)[:120])

    # -- error channel: bad JSON must come back as an envelope, not a crash ---
    bad_json = raw_call(ja3, "ja3_request", b"{not json")
    check.expect("malformed payload -> BAD_JSON",
                 bad_json.get("error_code") == 2, json.dumps(bad_json)[:120])

    # -- error channel: a missing required argument ---------------------------
    try:
        ja3.get("", impersonate="chrome_133")
        check.expect("empty url -> NIL_ARGUMENT", False, "no error raised")
    except Ja3Error as error:
        check.expect("empty url -> NIL_ARGUMENT", error.error_code == 1, error.name)

    # -- session handle table: open, close, close again -----------------------
    session = ja3.session(impersonate="chrome_140")
    check.expect("session_new returns a handle", session.handle > 0, str(session.handle))

    session.close()
    check.expect("session_close marks the binding handle closed", session.closed)

    try:
        ja3._call("ja3_session_close", None, session.handle)
        check.expect("second close is rejected", False, "closed handle answered again")
    except Ja3Error as error:
        check.expect("second close is rejected", error.error_code == 4,
                     f"{ERROR_CODES.get(error.error_code, error.name)}: {error}")

    if check.failures:
        print(f"\n{len(check.failures)} check(s) failed: " + ", ".join(check.failures))
        return 1

    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
