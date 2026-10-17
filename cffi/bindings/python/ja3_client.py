"""Python bindings for the ja3-client shared library (``libja3-client``).

Pure standard library: ``ctypes`` + ``json`` + ``base64``. No build step, no
third-party packages.

    from ja3_client import Ja3

    ja3 = Ja3()                       # finds and loads the library
    print(ja3.version())
    resp = ja3.request("https://tls.browserleaks.com/json", impersonate="chrome_133")
    print(resp.status_code, resp.json()["ja3n_hash"])

    with ja3.session(impersonate="chrome_133") as session:
        session.get("https://example.com/")
        session.get("https://example.com/about")   # same connection pool + cookies

Every call crosses the ABI as one JSON string, so the payload keys and the response
keys are documented in ``cffi/README.md`` (the ``snake_case`` contract). Unknown keys
come back in ``Response.warnings`` instead of being dropped.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import platform
from typing import Any, Iterable, Iterator, Mapping

__all__ = [
    "Ja3",
    "Ja3Error",
    "Response",
    "Session",
    "ABI_VERSION",
    "ERROR_CODES",
]

ABI_VERSION = 2

#: ``error_code`` -> name. Mirrors the Go constants in cffi/ffi.go.
ERROR_CODES = {
    0: "OK",
    1: "NIL_ARGUMENT",
    2: "BAD_JSON",
    3: "SESSION_INIT",
    4: "INVALID_HANDLE",
    5: "REQUEST",
    6: "READ_BODY",
    7: "MARSHAL",
    8: "PANIC",
}

def _default_library_names() -> Iterator[str]:
    """Candidate file names for the current platform, most specific first."""
    system = platform.system()
    machine = platform.machine().lower()

    arch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "i386": "386",
        "i686": "386",
    }.get(machine, machine)

    if system == "Darwin":
        yield f"ja3_client_{arch}.dylib"
        yield "libja3-client.dylib"
    elif system == "Windows":
        yield f"ja3_client_{arch}.dll"
        yield "ja3-client.dll"
    else:
        yield f"libja3_client_{arch}.so"

        if machine.startswith("arm"):
            # 32-bit ARM reports armv6l/armv7l; the release names them armv7/arm.
            yield "libja3_client_armv7.so"
            yield "libja3_client_arm.so"

        yield "libja3-client.so"


#: The installer module, or None when it is not installed. Undefined = not tried yet;
#: release archives ship ja3_client.py alone, so its absence is normal, not an error.
_installer: Any = None
_installer_tried = False


def _through_installer() -> str | None:
    """Reuse the shared cache, then fetch, through ja3_client_binaries if installed.

    A failed fetch raises with the installer's own three-line recipe: when the problem
    is a 404 on a release asset, "I looked at these twelve paths" is not the message
    that helps.
    """
    global _installer, _installer_tried

    if not _installer_tried:
        _installer_tried = True

        try:
            import ja3_client_binaries as module

            _installer = module
        except Exception:
            _installer = None

    if _installer is None:
        return None

    cached = _installer.find_cached_library(list(_default_library_names()))

    if cached:
        return cached

    try:
        return _installer.ensure_library()
    except Exception as err:
        raise Ja3Error(str(err), error_code=1) from err


#: Options the library only reads when it builds the client. Re-sending them on a
#: session request would be ignored, so the binding drops them there.
_CLIENT_ONLY_KEYS = (
    "impersonate", "ja3", "akamai", "client_data", "proxy", "source_ip", "timeout",
    "force_http1", "with_http3", "random_extension_order", "with_debug",
    "not_follow_redirects",
)


class Ja3Error(RuntimeError):
    """Raised when the library reports a non-zero ``error_code``."""

    def __init__(self, message: str, error_code: int, payload: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.name = ERROR_CODES.get(error_code, f"UNKNOWN_{error_code}")
        self.payload = dict(payload or {})


class Response:
    """One successful library call, decoded from the JSON envelope."""

    __slots__ = ("status_code", "protocol", "headers", "body", "body_size", "set_cookies",
                 "warnings", "session", "raw")

    def __init__(self, payload: Mapping[str, Any]):
        self.raw = dict(payload)
        self.status_code: int = payload.get("status_code", 0)
        self.protocol: str = payload.get("protocol", "")
        self.headers: dict[str, list[str]] = payload.get("headers", {})
        self.set_cookies: list[str] = payload.get("set_cookies", [])
        self.warnings: list[str] = payload.get("warnings", [])
        self.session: int = payload.get("session", 0)
        self.body_size: int = payload.get("body_size", 0)

        if payload.get("body_base64"):
            self.body: bytes = base64.b64decode(payload["body_base64"])
        else:
            self.body = payload.get("body", "").encode("utf-8")

    # -- header access -------------------------------------------------------

    def header(self, name: str, default: str | None = None) -> str | None:
        """First value of ``name``, case-insensitive."""
        wanted = name.lower()

        for key, values in self.headers.items():
            if key.lower() == wanted:
                return values[0] if values else default

        return default

    # -- body access ---------------------------------------------------------

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content(self) -> bytes:
        return self.body

    def json(self) -> Any:
        return json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def raise_for_status(self) -> "Response":
        if not self.ok:
            raise Ja3Error(f"HTTP {self.status_code}", error_code=5, payload=self.raw)

        return self

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Response {self.status_code} {self.protocol} {self.body_size}B>"


class Session:
    """A handle to a persistent client: connection pool + cookie jar reused."""

    def __init__(self, ja3: "Ja3", handle: int, options: Mapping[str, Any]):
        self._ja3 = ja3
        self._handle = handle
        self._options = dict(options)
        self._closed = False

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def closed(self) -> bool:
        return self._closed

    def request(self, url: str, *, method: str = "GET",
                headers: Mapping[str, Any] | None = None,
                body: Any = None, **options: Any) -> Response:
        if self._closed:
            raise Ja3Error("session is closed", error_code=4)

        payload = _build_payload(url, method, headers, body, options)
        # Client-level options were fixed at ja3_session_new; sending them again
        # would silently do nothing, so keep only the per-call fields.
        for client_key in _CLIENT_ONLY_KEYS:
            payload.pop(client_key, None)

        return self._ja3._session_request(self._handle, payload)

    def get(self, url: str, **options: Any) -> Response:
        return self.request(url, method="GET", **options)

    def post(self, url: str, body: Any = None, **options: Any) -> Response:
        return self.request(url, method="POST", body=body, **options)

    def close(self) -> None:
        if self._closed:
            return

        self._ja3._session_close(self._handle)
        self._closed = True

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass


class Ja3:
    """Loaded ``libja3-client`` with a small requests-shaped surface."""

    def __init__(self, library_path: str | os.PathLike[str] | None = None,
                 search_paths: Iterable[str] = (), check_abi: bool = True):
        self.path = self._locate(library_path, search_paths)
        self._lib = self._load(self.path)

        if check_abi:
            envelope = self._call("ja3_version", None)
            reported = envelope.get("abi")
            if reported is not None and reported != ABI_VERSION:
                raise Ja3Error(
                    f"{self.path} speaks ABI {reported}, this binding expects {ABI_VERSION}",
                    error_code=reported or 7,
                )

            self._version = envelope.get("version", "unknown")

    # -- loading -------------------------------------------------------------

    @staticmethod
    def _locate(library_path: str | os.PathLike[str] | None,
                search_paths: Iterable[str]) -> str:
        env_path = os.environ.get("JA3_CLIENT_LIB")
        candidates: list[str] = []

        for explicit in (library_path, env_path):
            if explicit:
                candidates.append(os.fspath(explicit))

        # JA3_CLIENT_LIB means "this file and nothing else" (cffi/PACKAGING.md), so a
        # path that is not there has to stop here: falling through to whatever else is on
        # disk turns a typo in CI into a fingerprint that quietly comes from another
        # version, and that is the worst kind of bug this library can have.
        if env_path and not os.path.isfile(env_path):
            raise Ja3Error(
                f"JA3_CLIENT_LIB points at {env_path}, which is not a file", error_code=1
            )

        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(os.path.dirname(here))  # bindings/python -> cffi
        build_dirs = [
            os.path.join(root, "build"),
            os.path.join(root, "build", "release"),
            os.path.join(root, "build", _sysname()),
            os.path.join(root, "dist"),
            here,
            os.getcwd(),
            os.path.join(os.getcwd(), "build"),
        ]
        build_dirs.extend(os.path.abspath(p) for p in search_paths)

        for directory in build_dirs:
            for name in _default_library_names():
                candidates.append(os.path.join(directory, name))

        seen: set[str] = set()
        tried: list[str] = []

        for candidate in candidates:
            if candidate in seen:
                continue

            seen.add(candidate)
            tried.append(candidate)

            if os.path.isfile(candidate):
                return candidate

        # Nothing on disk. Ask the installer module, which owns the shared cache
        # (~/.cache/ja3-client/<version>/<os>-<arch>/) that the npm and NuGet packages
        # fill, and can fetch this version's archive. The import is lazy and guarded:
        # the release archives ship ja3_client.py alone, and there the module really is
        # absent, so the error below is the right answer. An explicit JA3_CLIENT_LIB that
        # does not exist must not fall through to some other library (cffi/PACKAGING.md),
        # which is why this whole branch is skipped when one was set.
        if not env_path:
            found = _through_installer()

            if found:
                return found

        raise Ja3Error(
            "libja3-client not found. Build it with `make` in cffi/, then point "
            "JA3_CLIENT_LIB at the file. Looked at:\n  " + "\n  ".join(tried[:12]),
            error_code=1,
        )

    @staticmethod
    def _load(path: str) -> ctypes.CDLL:
        lib = ctypes.CDLL(path)

        cstr = ctypes.c_char_p
        u64 = ctypes.c_ulonglong
        ptr = ctypes.c_void_p

        lib.ja3_version.argtypes = []
        lib.ja3_request.argtypes = [cstr]
        lib.ja3_session_new.argtypes = [cstr]
        lib.ja3_session_request.argtypes = [u64, cstr]
        lib.ja3_session_close.argtypes = [u64]
        lib.ja3_free.argtypes = [ptr]

        # Every JSON-returning export gives back malloc'd memory the caller owns.
        # c_void_p (not c_char_p) keeps the pointer so ja3_free can release it.
        for name in ("ja3_version", "ja3_request", "ja3_session_new",
                     "ja3_session_request", "ja3_session_close"):
            getattr(lib, name).restype = ptr

        lib.ja3_free.restype = None

        return lib

    # -- calling -------------------------------------------------------------

    def _call(self, export: str, payload: Mapping[str, Any] | None,
              *extra: Any) -> dict[str, Any]:
        args: list[Any] = list(extra)

        if payload is not None:
            args.append(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

        raw = getattr(self._lib, export)(*args)

        if not raw:
            raise Ja3Error(f"{export} returned a null pointer", error_code=7)

        try:
            text = ctypes.string_at(raw).decode("utf-8")
        finally:
            self._lib.ja3_free(raw)

        envelope = json.loads(text)

        if envelope.get("error_code", 0) not in (0,):
            raise Ja3Error(envelope.get("error") or ERROR_CODES.get(envelope["error_code"], "error"),
                           error_code=envelope["error_code"], payload=envelope)

        return envelope

    # -- public API ----------------------------------------------------------

    def _session_request(self, handle: int, payload: Mapping[str, Any]) -> Response:
        envelope = self._call("ja3_session_request", payload, ctypes.c_ulonglong(handle))

        return Response(envelope)

    def _session_close(self, handle: int) -> None:
        self._call("ja3_session_close", None, ctypes.c_ulonglong(handle))

    def version(self) -> str:
        return getattr(self, "_version", "unknown")

    def request(self, url: str, *, method: str = "GET",
                 headers: Mapping[str, Any] | None = None,
                 body: Any = None, **options: Any) -> Response:
        """One-shot request: builds a client, uses it once, drops idle connections.

        Keyword arguments map onto the payload fields in cffi/README.md, e.g.
        ``impersonate="chrome_133"``, ``proxy="http://127.0.0.1:7890"``,
        ``with_http3=False``, ``timeout=20``.
        """
        payload = _build_payload(url, method, headers, body, options)

        return Response(self._call("ja3_request", payload))

    def get(self, url: str, **options: Any) -> Response:
        return self.request(url, method="GET", **options)

    def post(self, url: str, body: Any = None, **options: Any) -> Response:
        return self.request(url, method="POST", body=body, **options)

    def session(self, **options: Any) -> Session:
        """Open a persistent client and return its handle wrapper.

        Call ``session.close()`` (or use it as a context manager) - the library
        keeps the connection pool and cookie jar alive until then.
        """
        payload = {k: v for k, v in _drop_none(options).items()}
        envelope = self._call("ja3_session_new", payload)

        return Session(self, envelope["session"], payload)

    def close(self) -> None:
        """Nothing to release on the Python side; kept for symmetry."""
        return None


def _sysname() -> str:
    return {"Darwin": "darwin", "Windows": "windows", "Linux": "linux"}[platform.system()]


def _drop_none(options: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in options.items() if value is not None}


def _encode_body(body: Any) -> dict[str, str]:
    if body is None:
        return {}

    if isinstance(body, bytes):
        return {"body_base64": base64.b64encode(body).decode("ascii")}

    if isinstance(body, str):
        try:
            body.encode("utf-8")
        except UnicodeEncodeError:  # pragma: no cover - lone surrogates
            return {"body_base64": base64.b64encode(body.encode("utf-8", "surrogatepass")).decode("ascii")}

        return {"body": body}

    if isinstance(body, bool):
        return {"body": "true" if body else "false"}

    if isinstance(body, (int, float)):
        return {"body": str(body)}

    return {"body": json.dumps(body, ensure_ascii=False)}


def _build_payload(url: str, method: str, headers: Mapping[str, Any] | None,
                   body: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"url": url, "method": method.upper()}

    if headers is not None:
        payload["headers"] = dict(headers)

    payload.update(_encode_body(body))
    payload.update(_drop_none(options))

    return payload


_default: Ja3 | None = None


def _lazy_default() -> Ja3:
    global _default

    if _default is None:
        _default = Ja3()

    return _default


def request(url: str, **options: Any) -> Response:
    """Module-level shortcut using a lazily loaded, process-wide library handle."""
    return _lazy_default().request(url, **options)


def get(url: str, **options: Any) -> Response:
    return _lazy_default().get(url, **options)


def post(url: str, body: Any = None, **options: Any) -> Response:
    return _lazy_default().post(url, body=body, **options)


def session(**options: Any) -> Session:
    return _lazy_default().session(**options)


def version() -> str:
    return _lazy_default().version()

