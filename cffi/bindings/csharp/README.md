# ja3-client (C#)

Browser TLS/H2/H3 fingerprint impersonation from .NET, through P-Invoke to the Go
shared library. The ABI contract (payload keys, response envelope, error codes) is in
[cffi/README.md](../README.md); this file covers installing the binary the binding needs.

```csharp
using Ja3Client;

using var ja3 = new Ja3();
var response = ja3.Get("https://tls.browserleaks.com/json",
    new RequestOptions { Impersonate = "chrome_153" });

Console.WriteLine(response.Json()["ja3n_hash"]);
```

## Where the library comes from

`dotnet add package ja3-client` installs the binding plus `build/ja3-client.targets`,
which MSBuild imports automatically. On the next build that target works out this
machine's `<os>-<arch>` slug, downloads `ja3-client-<version>-<slug>.zip` from this
repository's GitHub Release for the package version, checks it against the release's
`SHA256SUMS.txt`, unpacks the library into the cache the npm and PyPI packages share, and
copies it next to your executable - which is the first place `Ja3.cs` looks, so
`dotnet run` and `dotnet test` need no environment variables.

A fetch that fails is a warning, not a build error, so that a re-uploaded release cannot
break every consumer's build; set `Ja3ClientStrictFetch=true` if you would rather it did.

```sh
dotnet build -p:Ja3ClientVersion=1.2.5              # fetch a different library version
dotnet build -p:Ja3ClientOffline=true               # never touch the network
dotnet build -p:Ja3ClientSkipNativeFetch=true       # you ship your own library
dotnet publish                                        # the library goes to the publish dir too
```

## Knobs

Properties above, and the same environment variables as the other bindings
(cffi/PACKAGING.md): `JA3_CLIENT_LIB` (use this file, disables the target),
`JA3_CLIENT_CACHE_DIR`, `JA3_CLIENT_VERSION`, `JA3_CLIENT_BASE_URL`, `JA3_CLIENT_REPO`,
`JA3_CLIENT_OFFLINE=1|true`, `JA3_CLIENT_STRICT=1|true`.

At runtime the binding looks for, in order: the `libraryPath` you pass to `new Ja3()`,
`JA3_CLIENT_LIB`, the output directory and `runtimes/`, the current directory,
`cffi/build` in a checkout of this repository, and any version in the shared cache.

## Vendoring instead of packaging

`Ja3.cs` is one file with no dependencies: add it to your project and put the library
somewhere it can find it - `make -C cffi host` builds it for this machine. Linux
archives are built against glibc (Debian bookworm); on musl (Alpine) build the library
yourself, and there is no archive for 32-bit ARM Windows.
