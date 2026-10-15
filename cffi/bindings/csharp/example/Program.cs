using System.Text.Json.Nodes;
using Ja3Client;

// Run: JA3_CLIENT_LIB=../../build/darwin/ja3_client_arm64.dylib dotnet run
var ja3 = new Ja3();
Console.WriteLine($"library {ja3.SdkVersion} built {ja3.BuildTime} from {ja3.LibraryPath}");

var report = ja3.Get("https://tls.browserleaks.com/json", new RequestOptions
{
    Impersonate = "chrome_133",
    Timeout = 20,
});

var fingerprints = report.Json<JsonObject>()!;
Console.WriteLine($"browserleaks {report.StatusCode} {report.Protocol} " +
                  $"ja3n={fingerprints["ja3n_hash"]} akamai={fingerprints["akamai_hash"]} " +
                  $"warnings={report.Warnings.Count}");

using (var session = ja3.OpenSession(new SessionOptions { Impersonate = "chrome_126", Timeout = 20 }))
{
    var first = session.Get("https://httpbin.org/get");
    Console.WriteLine($"session #{session.Handle} {first.StatusCode} ua=" +
                      $"{first.Json<JsonObject>()!["headers"]!["User-Agent"]!.GetValue<string>()[..25]}...");

    var posted = session.Post("https://httpbin.org/post", "{\"k\":\"中文\"}", new RequestOptions
    {
        Headers = new Dictionary<string, JsonNode?> { ["content-type"] = "application/json" },
    });
    Console.WriteLine($"post {posted.StatusCode} set-cookie={posted.SetCookies.Count} " +
                      $"echo={posted.Json<JsonObject>()!["json"]}");

    var dropped = session.Get("https://httpbin.org/headers", new RequestOptions
    {
        Headers = new Dictionary<string, JsonNode?> { ["user-agent"] = null },
    });
    Console.WriteLine($"user-agent removed -> {dropped.Json<JsonObject>()!["headers"]!["User-Agent"]}" +
                      $" warnings={string.Join("|", dropped.Warnings)}");
}

var binary = ja3.Get("https://www.google.com/favicon.ico");
Console.WriteLine($"favicon {binary.StatusCode} {binary.Body.Length} bytes " +
                  $"content-type={binary.Header("Content-Type")} first={Convert.ToHexString(binary.Body[..4])}");

// A second instance must not re-register the P-Invoke resolver.
using var another = new Ja3();
Console.WriteLine($"second instance {another.SdkVersion}");

try
{
    ja3.Request("", new RequestOptions { Impersonate = "chrome_133" });
}
catch (Ja3Exception error)
{
    Console.WriteLine($"empty url -> {error.Code} {error.Message}");
}
