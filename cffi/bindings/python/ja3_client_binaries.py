"""Install-time resolver for the ja3-client native library.

The PyPI distribution of ``ja3-client`` ships this module next to ``ja3_client.py``.
The binding code is portable; the Go/cgo build is not, so the library is downloaded
from the GitHub Release for the matching version and cached in a directory the Node
and C# bindings share.

    from ja3_client import Ja3          # fetches on first use
    python -m ja3_client_binaries ensure   # or fetch it explicitly

cffi/PACKAGING.md owns the contract (asset names, SHA256SUMS.txt, cache layout, the
``JA3_CLIENT_*`` variables); this module is the Python reading of it. Standard library
only - a resolver that needs a third-party package to fetch a package defeats its own
purpose.

A wheel cannot run code at install time, so unlike npm's postinstall this fetches on
first use. ``python -m ja3_client_binaries fetch`` is there for the people who want the
bytes on disk before the process starts.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Iterator, Optional

__all__ = [
    "platform_slug",
    "library_file_name",
    "cache_dir",
    "cache_library_path",
    "resolve_version",
    "asset_name",
    "asset_url",
    "sums_url",
    "ensure_library",
    "FindError",
    "main",
]

DEFAULT_REPO = "smallerqiu/ja3-client"
ABI_VERSION = 2
TIMEOUT_SECONDS = 60

#: Version of the library this package installs. CI stamps it from the release tag at
#: build time; a hand-built wheel keeps the last published number so the resolver asks
#: for an archive that actually exists.
PACKAGE_VERSION = "1.2.8"

_SUPPORTED_SLUGS = (
    "darwin-amd64", "darwin-arm64",
    "linux-amd64", "linux-arm64", "linux-armv7", "linux-386",
    "windows-amd64", "windows-386",
)


def _flag(name: str) -> bool:
    """Truthy for the env switches: 1/true/yes, in any case; 0/false/no/off are not."""
    value = os.environ.get(name)

    if value is None or value == "":
        return False

    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env(name: str) -> Optional[str]:
    value = os.environ.get(name)

    return value if value else None


def platform_slug(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    """The ``<os>-<arch>`` half of a release asset name.

    The arch table matches ``ja3_client._default_library_names`` so the file the
    binding looks for and the file the resolver downloads are the same file, and it
    matches package-release.sh, which derives the slug from the build directory plus
    the architecture in the library name.
    """
    system = system or platform.system()
    machine = (machine or platform.machine() or "").lower()

    arch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "i386": "386",
        "i686": "386",
        "x86": "386",
    }.get(machine, machine)

    if arch.startswith("arm") and arch not in {"arm64"}:
        # armv6l/armv7l: the release names the 32-bit build after its file, armv7.
        arch = "armv7"

    os_name = {"Darwin": "darwin", "Windows": "windows", "Linux": "linux"}.get(system)

    if os_name is None:
        raise FindError(
            f"ja3-client: no release archive for system {system!r}; "
            f"build the library (make -C cffi host) and set JA3_CLIENT_LIB"
        )

    slug = f"{os_name}-{arch}"

    if slug not in _SUPPORTED_SLUGS:
        raise FindError(
            f"ja3-client: no release archive for {slug}; "
            f"build the library (make -C cffi host) and set JA3_CLIENT_LIB"
        )

    return slug


def library_file_name(slug: str) -> str:
    """The library file inside ``ja3-client-<version>-<slug>.zip``."""
    arch = slug.split("-")[1]

    if slug.startswith("darwin"):
        return f"ja3_client_{arch}.dylib"

    if slug.startswith("windows"):
        return f"ja3_client_{arch}.dll"

    return f"libja3_client_{arch}.so"


def resolve_version() -> str:
    """Library version to fetch: JA3_CLIENT_VERSION, else this package's version."""
    return _env("JA3_CLIENT_VERSION") or PACKAGE_VERSION


def repo() -> str:
    return _env("JA3_CLIENT_REPO") or DEFAULT_REPO


def tag_for(version: str) -> str:
    return version if version.startswith("v") else f"v{version}"


def base_url() -> str:
    """Download root. The override exists for mirrors and for the offline installer
    test (cffi/test-installers.sh serves a local dist/); it replaces everything before
    ``/<tag>/<asset>``."""
    return _env("JA3_CLIENT_BASE_URL") or f"https://github.com/{repo()}/releases/download"


def asset_name(version: str, slug: str) -> str:
    return f"ja3-client-{version}-{slug}.zip"


def asset_url(version: str, slug: str) -> str:
    return f"{base_url()}/{tag_for(version)}/{asset_name(version, slug)}"


def sums_url(version: str) -> str:
    return f"{base_url()}/{tag_for(version)}/SHA256SUMS.txt"


def cache_dir() -> Path:
    """Cache root shared by the npm, PyPI and NuGet bindings, so one download serves
    all three on the same machine."""
    explicit = _env("JA3_CLIENT_CACHE_DIR")

    if explicit:
        return Path(explicit)

    xdg = _env("XDG_CACHE_HOME")

    if xdg:
        return Path(xdg) / "ja3-client"

    home = Path.home()
    system = platform.system()

    if system == "Windows":
        return Path(_env("LOCALAPPDATA") or home / "AppData" / "Local") / "ja3-client"

    if system == "Darwin":
        return home / "Library" / "Caches" / "ja3-client"

    return home / ".cache" / "ja3-client"


def cache_library_path(version: str, slug: str) -> Path:
    return cache_dir() / version / slug / library_file_name(slug)


class FindError(RuntimeError):
    """Nothing on disk and nothing downloadable: the caller gets the manual recipe."""


class ChecksumError(FindError):
    """The archive does not match SHA256SUMS.txt - never unpack it."""


def download(url: str, timeout: float = TIMEOUT_SECONDS, attempts: int = 2) -> bytes:
    """Fetch a URL into bytes.

    urllib follows the 302 that GitHub answers at /releases/download/ for us, and that
    redirect to a signed host is what makes the bytes tamper-evident in transit, so
    do not "harden" this by disabling redirects. One retry, because a CDN hiccup should
    not look like a broken package; an HTTP 4xx is a real answer and is not retried.
    """
    last: Optional[BaseException] = None

    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                code = getattr(response, "status", 200) or 200

                if code != 200:
                    raise FindError(f"HTTP {code} for {url}")

                return response.read()
        except urllib.error.HTTPError as err:
            if 400 <= err.code < 500:
                raise FindError(f"HTTP {err.code} for {url}") from err

            last = err
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            last = err

        if attempt + 1 < attempts:
            time.sleep(0.5)

    raise FindError(f"could not download {url}: {last}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_sha(sums_text: str, asset: str) -> str:
    """This archive's line from SHA256SUMS.txt (``<sha>  <name>``).

    Exact name match: linux-arm64 and linux-armv7 are one character apart, and a prefix
    match would report a checksum failure on a perfectly good download. A sums file
    without a line for this asset means an incomplete release, which is a different
    problem from a corrupt download and has to be said differently.
    """
    for line in sums_text.splitlines():
        if not line.strip():
            continue

        sha, name = line[:64].strip(), line[64:].strip().lstrip("*").strip()

        if name == asset:
            if len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha):
                raise ChecksumError(f"SHA256SUMS.txt has a malformed hash for {asset}")

            return sha.lower()

    raise ChecksumError(f"SHA256SUMS.txt has no line for {asset} - the release is incomplete")


def _extract_member(data: bytes, base_name: str, target: Path) -> None:
    """Write one member of the archive, by base name, into ``target``.

    Only the base name is ever used, so a member named ``../../.ssh/x`` cannot escape
    the cache directory even though the bytes came off the network.
    """
    with zipfile.ZipFile(BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir() or Path(info.filename).name != base_name:
                continue

            target.write_bytes(archive.read(info))

            return

    raise ChecksumError(f"the archive has no {base_name} inside it")


def find_cached_library(names: Optional[Iterator[str]] = None) -> Optional[str]:
    """A library already in the cache, newest version first.

    The cache outlives upgrades: picking the oldest directory would run a 1.2.5 binding
    against a 1.2.3 library and the fingerprint mismatch would be blamed on the profiles.
    """
    root = cache_dir()

    if not root.is_dir():
        return None

    wanted = list(names) if names else list(_default_names())

    for version_dir in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True):
        for slug_dir in sorted((p for p in version_dir.iterdir() if p.is_dir()), reverse=True):
            for name in wanted:
                candidate = slug_dir / name

                if candidate.is_file():
                    return str(candidate)

    return None


def _default_names() -> Iterator[str]:
    """Library file names this machine could use, matching ja3_client's own list."""
    slug = platform_slug()
    arch = slug.split("-")[1]

    yield library_file_name(slug)

    if arch == "armv7":
        yield "libja3_client_arm.so"


def _failure(slug: str, version: str, url: str, reason: str) -> FindError:
    """The three lines PACKAGING.md fixes as the shape of every fetch failure: what was
    wanted, where it was looked for, and how to do it by hand."""
    return FindError(
        f"ja3-client: could not fetch the native library for {slug} ({tag_for(version)}).\n"
        f"  tried: {url}\n"
        "  offline? build it (make -C cffi host), or unzip a release archive and "
        f"set JA3_CLIENT_LIB=/path/to/lib\n  reason: {reason}"
    )


def ensure_library(version: Optional[str] = None, slug: Optional[str] = None,
                   log=None) -> str:
    """Return the absolute path of a usable library, downloading it if needed.

    Raises FindError with the manual recipe when nothing is available; never touches the
    network when JA3_CLIENT_LIB or JA3_CLIENT_OFFLINE says not to.
    """
    explicit = _env("JA3_CLIENT_LIB")

    if explicit:
        if not os.path.isfile(explicit):
            raise FindError(f"JA3_CLIENT_LIB points at {explicit}, which is not a file")

        return os.path.abspath(explicit)

    version = version or resolve_version()
    slug = slug or platform_slug()
    target = cache_library_path(version, slug)

    if target.is_file():
        if log:
            log(f"ja3-client: cached {slug} {version}")

        return str(target)

    url = asset_url(version, slug)

    if _flag("JA3_CLIENT_OFFLINE"):
        raise _failure(slug, version, url, "JA3_CLIENT_OFFLINE is set")

    asset = asset_name(version, slug)

    # Every network step below reports through _failure(), because a bare
    # "HTTP 404 for .../SHA256SUMS.txt" is a dead end: the sums file is the one missing
    # asset that means "this release was never finished", and the user still needs the
    # recipe. A sums line that does not match the archive stays a ChecksumError, which
    # is a different problem and says so.
    def fetch(url: str) -> bytes:
        try:
            return download(url)
        except Exception as err:
            raise _failure(slug, version, url, str(err)) from err

    sums = fetch(sums_url(version)).decode("utf-8", "replace")
    want = expected_sha(sums, asset)
    archive = fetch(url)

    got = sha256_hex(archive)

    if got != want:
        raise _failure(slug, version, url,
                       f"sha256 is {got}, SHA256SUMS.txt says {want}")

    name = library_file_name(slug)

    # Extract through a temp directory and one rename: an install killed halfway must
    # not leave a truncated library that ctypes accepts and then crashes inside.
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(target.parent), prefix=".tmp-"))

    try:
        _extract_member(archive, name, staging / name)
        (staging / "install.json").write_text(
            json.dumps(
                {
                    "version": version,
                    "asset": asset,
                    "url": url,
                    "sha256": want,
                    "abi": ABI_VERSION,
                    "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "installed_by": "pip",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        for staged in (name, "install.json"):
            dest = target.parent / staged

            if dest.exists():
                dest.unlink()

            shutil.move(str(staging / staged), str(dest))

        # ctypes does not care about the mode, but smoke.py runs the file directly on
        # some systems and a 0600 library is a confusing thing to debug.
        target.chmod(0o755)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    if log:
        log(f"ja3-client: {slug} {version} -> {target}")

    return str(target)


def status() -> dict:
    version = resolve_version()

    try:
        slug = platform_slug()
        path = str(cache_library_path(version, slug))
        cached = Path(path).is_file()
    except FindError as err:
        slug, path, cached = str(err), "", False

    return {
        "version": version,
        "package_version": PACKAGE_VERSION,
        "slug": slug,
        "repo": repo(),
        "base_url": base_url(),
        "cache_dir": str(cache_dir()),
        "library_path": path,
        "cached": cached,
        "offline": _flag("JA3_CLIENT_OFFLINE"),
        "explicit_lib": _env("JA3_CLIENT_LIB") or "",
    }


_COMMANDS = ("print-url", "ensure", "fetch", "path", "status")


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "status"

    if command in ("-h", "--help"):
        print(f"usage: python -m ja3_client_binaries <{'|'.join(_COMMANDS)}>")

        return 0

    try:
        if command == "print-url":
            print(asset_url(resolve_version(), platform_slug()))

            return 0

        if command in ("ensure", "fetch"):
            print(ensure_library(log=lambda line: print(line, file=sys.stderr)))

            return 0

        if command == "path":
            found = cache_library_path(resolve_version(), platform_slug())

            if not found.is_file():
                print(f"ja3-client: no cached library at {found}", file=sys.stderr)

                return 1

            print(found)

            return 0

        if command == "status":
            for key, value in status().items():
                print(f"{key}={value}")

            return 0
    except FindError as err:
        print(err, file=sys.stderr)

        return 1

    print(f"unknown command '{command}' ({'|'.join(_COMMANDS)})", file=sys.stderr)

    return 2


if __name__ == "__main__":
    sys.exit(main())
