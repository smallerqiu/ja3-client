using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Ja3Client;

/// <summary>Error codes reported in the envelope's <c>error_code</c>. Mirrors cffi/ffi.go.</summary>
public enum Ja3ErrorCode
{
    Ok = 0,
    NilArgument = 1,
    BadJson = 2,
    SessionInit = 3,
    InvalidHandle = 4,
    Request = 5,
    ReadBody = 6,
    Marshal = 7,
    Panic = 8,
}

public sealed class Ja3Exception : Exception
{
    public Ja3Exception(Ja3ErrorCode code, string message, Envelope? envelope = null)
        : base(message)
    {
        Code = code;
        Envelope = envelope;
    }

    public Ja3ErrorCode Code { get; }

    /// <summary>The raw envelope, when the library produced one.</summary>
    public Envelope? Envelope { get; }

    public override string ToString() => $"{Code}: {Message}";
}

/// <summary>The JSON envelope every exported function returns.</summary>
public sealed class Envelope
{
    [JsonPropertyName("error_code")] public int ErrorCode { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("warnings")] public string[]? Warnings { get; set; }
    [JsonPropertyName("status_code")] public int StatusCode { get; set; }
    [JsonPropertyName("protocol")] public string? Protocol { get; set; }
    [JsonPropertyName("headers")] public Dictionary<string, string[]>? Headers { get; set; }
    [JsonPropertyName("set_cookies")] public string[]? SetCookies { get; set; }
    [JsonPropertyName("body")] public string? Body { get; set; }
    [JsonPropertyName("body_base64")] public string? BodyBase64 { get; set; }
    [JsonPropertyName("body_binary")] public bool BodyBinary { get; set; }
    [JsonPropertyName("body_size")] public int BodySize { get; set; }
    [JsonPropertyName("session")] public ulong Session { get; set; }
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("abi")] public int Abi { get; set; }
    [JsonPropertyName("build_time")] public string? BuildTime { get; set; }
    [JsonPropertyName("ok")] public bool Ok { get; set; }

    internal void RaiseIfFailed()
    {
        if (ErrorCode != (int)Ja3ErrorCode.Ok)
        {
            throw new Ja3Exception((Ja3ErrorCode)ErrorCode, Error ?? "library call failed", this);
        }
    }
}

/// <summary>Options fixed when the client is built (ja3_session_new / ja3_request).
/// RequestOptions extends it, so a session's options can also be handed to a request;
/// the library ignores the client-level fields there.</summary>
public class SessionOptions
{
    [JsonPropertyName("impersonate")] public string? Impersonate { get; set; }
    [JsonPropertyName("ja3")] public string? Ja3 { get; set; }
    [JsonPropertyName("akamai")] public string? Akamai { get; set; }

    /// <summary>Hand-built fingerprint; keys are the snake_case spellings from cffi/README.md.</summary>
    [JsonPropertyName("client_data")] public JsonNode? ClientData { get; set; }

    [JsonPropertyName("proxy")] public string? Proxy { get; set; }
    [JsonPropertyName("source_ip")] public string? SourceIp { get; set; }
    [JsonPropertyName("timeout")] public int? Timeout { get; set; }
    [JsonPropertyName("force_http1")] public bool? ForceHttp1 { get; set; }

    /// <summary>Null keeps the profile default; false disables HTTP/3 entirely.</summary>
    [JsonPropertyName("with_http3")] public bool? WithHttp3 { get; set; }

    [JsonPropertyName("random_extension_order")] public bool? RandomExtensionOrder { get; set; }
    [JsonPropertyName("not_follow_redirects")] public bool? NotFollowRedirects { get; set; }
    [JsonPropertyName("with_debug")] public bool? WithDebug { get; set; }
    [JsonPropertyName("headers")] public Dictionary<string, JsonNode?>? Headers { get; set; }
}

/// <summary>Options for a one-shot ja3_request: client-level and call-level in one object.</summary>
public sealed class RequestOptions : SessionOptions
{
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("body")] public string? Body { get; set; }
    [JsonPropertyName("body_base64")] public string? BodyBase64 { get; set; }
}

/// <summary>A decoded response.</summary>
public sealed record Response
{
    public required int StatusCode { get; init; }
    public required string Protocol { get; init; }
    public required IReadOnlyDictionary<string, string[]> Headers { get; init; }
    public required IReadOnlyList<string> SetCookies { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public required byte[] Body { get; init; }
    public required int BodySize { get; init; }
    public required ulong Session { get; init; }
    public required Envelope Raw { get; init; }

    public bool IsOk => StatusCode is >= 200 and < 400;

    public string Text => Encoding.UTF8.GetString(Body);

    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    public string? Header(string name)
    {
        foreach (var (key, values) in Headers)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                return values.Length > 0 ? values[0] : null;
            }
        }

        return null;
    }

    public Response RaiseForStatus()
    {
        if (!IsOk)
        {
            throw new Ja3Exception(Ja3ErrorCode.Request, $"HTTP {StatusCode}", Raw);
        }

        return this;
    }

    internal static Response From(Envelope env)
    {
        var body = env.BodyBase64 is { Length: > 0 }
            ? Convert.FromBase64String(env.BodyBase64)
            : Encoding.UTF8.GetBytes(env.Body ?? string.Empty);

        return new Response
        {
            StatusCode = env.StatusCode,
            Protocol = env.Protocol ?? string.Empty,
            Headers = env.Headers ?? new Dictionary<string, string[]>(),
            SetCookies = env.SetCookies ?? Array.Empty<string>(),
            Warnings = env.Warnings ?? Array.Empty<string>(),
            Body = body,
            BodySize = env.BodySize,
            Session = env.Session,
            Raw = env,
        };
    }
}

/// <summary>A persistent client: one connection pool and one cookie jar, keyed by handle.</summary>
public sealed class Session : IDisposable
{
    private readonly Ja3 _ja3;
    private bool _closed;

    internal Session(Ja3 ja3, ulong handle)
    {
        _ja3 = ja3;
        Handle = handle;
    }

    public ulong Handle { get; }

    public bool IsClosed => _closed;

    public Response Request(string url, RequestOptions? options = null)
    {
        if (_closed)
        {
            throw new Ja3Exception(Ja3ErrorCode.InvalidHandle, "session is closed");
        }

        var payload = options ?? new RequestOptions();
        payload.Url = url;
        payload.Method ??= "GET";

        return _ja3.SessionRequest(Handle, payload);
    }

    public Response Get(string url, RequestOptions? options = null) =>
        Request(url, Apply(options, "GET", null));

    public Response Post(string url, string? body = null, RequestOptions? options = null) =>
        Request(url, Apply(options, "POST", body));

    private static RequestOptions Apply(RequestOptions? options, string method, string? body)
    {
        var payload = options ?? new RequestOptions();
        payload.Method = method;

        if (body is not null)
        {
            payload.Body = body;
        }

        return payload;
    }

    public void Close() => Dispose();

    public void Dispose()
    {
        if (_closed)
        {
            return;
        }

        _closed = true;
        _ja3.SessionClose(Handle);
    }
}

/// <summary>
/// P-Invoke binding for libja3-client. The ABI is one JSON string in, one JSON
/// string out; see cffi/README.md for the field list and the error-code table.
/// </summary>
public sealed class Ja3 : IDisposable
{
    public const int AbiVersion = 2;

    private const string LibraryName = "ja3-client";

    private static readonly JsonSerializerOptions WriterOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions ReaderOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static readonly object ResolveLock = new();

    private static string? _resolvedPath;

    private static bool _resolverRegistered;

    public Ja3(string? libraryPath = null)
    {
        lock (ResolveLock)
        {
            var fromEnv = Environment.GetEnvironmentVariable("JA3_CLIENT_LIB");

            // JA3_CLIENT_LIB means "this file and nothing else" (cffi/PACKAGING.md): a
            // typo must stop here rather than load some other version off disk, which
            // would surface as a fingerprint nobody can explain.
            if (!string.IsNullOrEmpty(fromEnv) && !File.Exists(fromEnv))
            {
                throw new Ja3Exception(Ja3ErrorCode.NilArgument,
                    $"JA3_CLIENT_LIB points at {fromEnv}, which is not a file");
            }

            LibraryPath = libraryPath ?? fromEnv ?? FindLibrary();

            _resolvedPath = LibraryPath;

            if (!_resolverRegistered)
            {
                // SetDllImportResolver is per-assembly and must not be called twice.
                NativeLibrary.SetDllImportResolver(typeof(Ja3).Assembly, Resolver);
                _resolverRegistered = true;
            }
        }

        var version = Call(Native.ja3_version);
        version.RaiseIfFailed();

        if (version.Abi != 0 && version.Abi != AbiVersion)
        {
            throw new Ja3Exception((Ja3ErrorCode)version.Abi,
                $"{LibraryPath} speaks ABI {version.Abi}, this binding expects {AbiVersion}", version);
        }

        SdkVersion = version.Version ?? "unknown";
        BuildTime = version.BuildTime ?? string.Empty;
    }

    public string LibraryPath { get; }

    public string SdkVersion { get; }

    public string BuildTime { get; }

    public Response Request(string url, RequestOptions? options = null)
    {
        var payload = options ?? new RequestOptions();
        payload.Url = url;
        payload.Method ??= "GET";

        var env = Call(() => Native.ja3_request(JsonSerializer.Serialize(payload, WriterOptions)));
        env.RaiseIfFailed();

        return Response.From(env);
    }

    public Response Get(string url, RequestOptions? options = null) =>
        Request(url, Clone(options, "GET", null));

    public Response Post(string url, string? body = null, RequestOptions? options = null) =>
        Request(url, Clone(options, "POST", body));

    public Session OpenSession(SessionOptions? options = null)
    {
        var env = Call(() => Native.ja3_session_new(JsonSerializer.Serialize(options ?? new SessionOptions(), WriterOptions)));
        env.RaiseIfFailed();

        if (env.Session == 0)
        {
            throw new Ja3Exception(Ja3ErrorCode.SessionInit, "ja3_session_new returned a zero handle", env);
        }

        return new Session(this, env.Session);
    }

    internal Response SessionRequest(ulong handle, RequestOptions options)
    {
        var env = Call(() => Native.ja3_session_request(handle,
            JsonSerializer.Serialize(options, WriterOptions)));
        env.RaiseIfFailed();

        return Response.From(env);
    }

    internal void SessionClose(ulong handle)
    {
        var env = Call(() => Native.ja3_session_close(handle));
        env.RaiseIfFailed();
    }

    public void Dispose()
    {
        // Sessions must be disposed individually; the library itself holds no handle here.
    }

    private static RequestOptions Clone(RequestOptions? options, string method, string? body)
    {
        var payload = options ?? new RequestOptions();
        payload.Method = method;

        if (body is not null)
        {
            payload.Body = body;
        }

        return payload;
    }

    /// <summary>Runs an export, copies the C string, and always releases the buffer.</summary>
    private static Envelope Call(Func<IntPtr> invoke)
    {
        var ptr = invoke();

        if (ptr == IntPtr.Zero)
        {
            throw new Ja3Exception(Ja3ErrorCode.Marshal, "export returned a null pointer");
        }

        try
        {
            var text = Marshal.PtrToStringUTF8(ptr)
                ?? throw new Ja3Exception(Ja3ErrorCode.Marshal, "export returned invalid UTF-8");

            return JsonSerializer.Deserialize<Envelope>(text, ReaderOptions)
                ?? throw new Ja3Exception(Ja3ErrorCode.Marshal, $"library returned malformed JSON: {text}");
        }
        finally
        {
            Native.ja3_free(ptr);
        }
    }

    private static IntPtr Resolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
        {
            return IntPtr.Zero;
        }

        var path = _resolvedPath ?? FindLibrary();

        return NativeLibrary.TryLoad(path, assembly, searchPath, out var handle) ? handle : IntPtr.Zero;
    }

    private static string FindLibrary()
    {
        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "amd64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "386",
            Architecture.Arm => "armv7",
            _ => RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
        };

        string[] names;
        string osDir;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            names = [$"ja3_client_{arch}.dll", "ja3-client.dll", "libja3-client.dll"];
            osDir = "windows";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            names = [$"ja3_client_{arch}.dylib", "libja3-client.dylib"];
            osDir = "darwin";
        }
        else
        {
            names = [$"libja3_client_{arch}.so", "libja3_client_armv7.so", "libja3_client_arm.so", "libja3-client.so"];
            osDir = "linux";
        }

        var roots = new List<string>
        {
            AppContext.BaseDirectory,
            Path.Combine(AppContext.BaseDirectory, osDir),
            Path.Combine(AppContext.BaseDirectory, "runtimes"),
            Directory.GetCurrentDirectory(),
            Path.Combine(FindCffiRoot(), "build", osDir),
            Path.Combine(FindCffiRoot(), "build", "release"),
            Path.Combine(FindCffiRoot(), "build"),
        };

        foreach (var root in roots)
        {
            foreach (var name in names)
            {
                var candidate = Path.Combine(root, name);

                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        var cached = CacheCandidates(names).FirstOrDefault();

        if (cached is not null)
        {
            return cached;
        }

        throw new Ja3Exception(Ja3ErrorCode.NilArgument,
            "libja3-client was not found. Build it with `make` in cffi/, run the NuGet " +
            "target (dotnet build fetches it), or set JA3_CLIENT_LIB to the file path. " +
            $"Searched: {string.Join(", ", roots)} and {CacheRoot()}");
    }

    /// <summary>
    /// The cache root from cffi/PACKAGING.md: JA3_CLIENT_CACHE_DIR, then
    /// XDG_CACHE_HOME, then the per-platform default. Shared with the npm and PyPI
    /// bindings so one download serves every language on the machine.
    /// </summary>
    private static string CacheRoot()
    {
        var explicitDir = Environment.GetEnvironmentVariable("JA3_CLIENT_CACHE_DIR");

        if (!string.IsNullOrEmpty(explicitDir))
        {
            return explicitDir;
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");

        if (!string.IsNullOrEmpty(xdg))
        {
            return Path.Combine(xdg, "ja3-client");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (OperatingSystem.IsWindows())
        {
            var local = Environment.GetEnvironmentVariable("LOCALAPPDATA");

            return Path.Combine(string.IsNullOrEmpty(local) ? Path.Combine(home, "AppData", "Local") : local,
                "ja3-client");
        }

        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(home, "Library", "Caches", "ja3-client");
        }

        return Path.Combine(home, ".cache", "ja3-client");
    }

    private static IEnumerable<string> CacheCandidates(string[] names)
    {
        var root = CacheRoot();

        if (!Directory.Exists(root))
        {
            yield break;
        }

        // Newest version directory first: a 1.2.5 binding that quietly loads the 1.2.3
        // library its predecessor left behind produces a mismatch nobody blames on the
        // cache. Ordinal sort is enough for the version and slug names.
        foreach (var version in Directory.EnumerateDirectories(root).OrderByDescending(d => d, StringComparer.Ordinal))
        {
            foreach (var slug in Directory.EnumerateDirectories(version).OrderByDescending(d => d, StringComparer.Ordinal))
            {
                foreach (var name in names)
                {
                    var candidate = Path.Combine(slug, name);

                    if (File.Exists(candidate))
                    {
                        yield return candidate;
                        yield break;
                    }
                }
            }
        }
    }

    private static string FindCffiRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "cffi", "go.mod")))
            {
                return Path.Combine(dir.FullName, "cffi");
            }

            dir = dir.Parent;
        }

        return AppContext.BaseDirectory;
    }

    private static class Native
    {
        [DllImport(LibraryName, EntryPoint = "ja3_version", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ja3_version();

        [DllImport(LibraryName, EntryPoint = "ja3_request", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ja3_request([MarshalAs(UnmanagedType.LPUTF8Str)] string payload);

        [DllImport(LibraryName, EntryPoint = "ja3_session_new", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ja3_session_new([MarshalAs(UnmanagedType.LPUTF8Str)] string payload);

        [DllImport(LibraryName, EntryPoint = "ja3_session_request", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ja3_session_request(ulong handle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string payload);

        [DllImport(LibraryName, EntryPoint = "ja3_session_close", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ja3_session_close(ulong handle);

        [DllImport(LibraryName, EntryPoint = "ja3_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void ja3_free(IntPtr ptr);
    }
}
