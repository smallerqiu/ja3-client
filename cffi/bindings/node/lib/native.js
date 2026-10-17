/**
 * Native library resolver for the `ja3-client` npm package.
 *
 * The package ships binding code only: the Go/cgo build is per target and tens of
 * megabytes, so a bundled dylib would be wrong on every machine but one. Instead the
 * library is fetched from the GitHub Release for this package's version and cached in
 * a directory shared with the Python and C# bindings.
 *
 * cffi/PACKAGING.md owns the contract (asset names, SHA256SUMS.txt, cache layout,
 * JA3_CLIENT_* variables); this file is the Node reading of it and nothing here is
 * allowed to drift from that document.
 *
 * Drive it from a shell when a package install is not enough:
 *
 *   node lib/native.js print-url   # the asset URL for this machine
 *   node lib/native.js ensure      # download if needed, print the library path
 *   node lib/native.js path        # print an already-present library path
 *   node lib/native.js status      # what the resolver sees, one line each
 *
 * Only Node builtins: no runtime dependency besides koffi survives an install behind
 * a proxy, and a resolver that needs a package to fetch a package defeats its purpose.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const DEFAULT_REPO = 'smallerqiu/ja3-client';
const DOWNLOAD_TIMEOUT_MS = 60000;
const MAX_REDIRECTS = 5;
const ABI_VERSION = 2;

/** Truthy for the env switches: 1, true, yes - any spelling, case-insensitive. */
function flag(name) {
  const value = process.env[name];

  if (value === undefined || value === '') return false;

  return !/^(0|false|no|off)$/i.test(value.trim());
}

function env(name) {
  const value = process.env[name];

  return value === undefined || value === '' ? undefined : value;
}

/* --- platform ---------------------------------------------------------- */

/**
 * The `<os>-<arch>` half of an asset name. Kept byte-for-byte compatible with
 * package-release.sh, which derives the same slug from the build directory plus the
 * architecture in the file name.
 */
function platformSlug(platform = os.platform(), arch = os.arch()) {
  let goarch = arch;
  if (arch === 'x64') goarch = 'amd64';
  else if (arch === 'arm64') goarch = 'arm64';
  else if (arch === 'ia32') goarch = '386';
  else if (arch.startsWith('arm')) goarch = 'armv7'; // arm, armv6l, armv7l

  const osName = { darwin: 'darwin', win32: 'windows', linux: 'linux' }[platform];

  if (!osName) {
    throw new Error(`ja3-client: no release archive for platform ${platform}`);
  }

  if (!['amd64', 'arm64', 'armv7', '386'].includes(goarch)) {
    throw new Error(`ja3-client: no release archive for architecture ${arch}`);
  }

  // linux-arm/v7 does not exist: the build target is linux/arm/v7 but the archive
  // is named after the file it holds, libja3_client_armv7.so.
  return `${osName}-${goarch}`;
}

function libraryFileName(slug) {
  const arch = slug.split('-')[1];

  if (slug.startsWith('darwin')) return `ja3_client_${arch}.dylib`;
  if (slug.startsWith('windows')) return `ja3_client_${arch}.dll`;

  return `libja3_client_${arch}.so`;
}

/* --- URLs and paths ----------------------------------------------------- */

/**
 * The package version is the library version: `ja3-client@1.2.5` downloads tag
 * `v1.2.5`, so a binding can never be paired with a library from an unrelated build
 * without someone going out of their way to set JA3_CLIENT_VERSION.
 */
function packageVersion() {
  try {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
    );

    return manifest.version || 'unknown';
  } catch {
    // A hand-copied lib/native.js with no manifest still has to work.
    return 'unknown';
  }
}

function resolveVersion() {
  return env('JA3_CLIENT_VERSION') || packageVersion();
}

function repo() {
  return env('JA3_CLIENT_REPO') || DEFAULT_REPO;
}

function tagFor(version) {
  return version.startsWith('v') ? version : `v${version}`;
}

function baseUrl() {
  // The override exists for the offline installer test (cffi/test-installers.sh
  // serves a local dist/) and for a mirror; it replaces the whole download root.
  return env('JA3_CLIENT_BASE_URL') || `https://github.com/${repo()}/releases/download`;
}

function assetName(version, slug) {
  return `ja3-client-${version}-${slug}.zip`;
}

function assetUrl(version, slug) {
  return `${baseUrl()}/${tagFor(version)}/${assetName(version, slug)}`;
}

function sumsUrl(version) {
  return `${baseUrl()}/${tagFor(version)}/SHA256SUMS.txt`;
}

/**
 * Cache root shared by all three bindings, so one download serves npm, pip and
 * dotnet on the same machine.
 */
function cacheDir() {
  const explicit = env('JA3_CLIENT_CACHE_DIR');
  if (explicit) return explicit;

  const xdg = env('XDG_CACHE_HOME');
  if (xdg) return path.join(xdg, 'ja3-client');

  const home = os.homedir();

  if (process.platform === 'win32') {
    return path.join(env('LOCALAPPDATA') || path.join(home, 'AppData', 'Local'), 'ja3-client');
  }

  if (process.platform === 'darwin') return path.join(home, 'Library', 'Caches', 'ja3-client');

  return path.join(home, '.cache', 'ja3-client');
}

function cacheLibraryPath(version, slug) {
  return path.join(cacheDir(), version, slug, libraryFileName(slug));
}

/* --- HTTP --------------------------------------------------------------- */

function getOnce(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const request = url.startsWith('https:') ? https : http;
    const req = request.get(url, { timeout: timeoutMs }, (res) => {
      const chunks = [];

      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () =>
        resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) })
      );
      res.on('error', reject);
    });

    req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs}ms: ${url}`)));
    req.on('error', reject);
  });
}

/**
 * Fetch a URL into a Buffer, following redirects.
 *
 * Following them is not optional polish: GitHub answers /releases/download/ with a
 * 302 to a signed object host, and that signature is what makes the bytes
 * tamper-evident in transit. One retry because a CDN hiccup must not look like a
 * broken package.
 */
async function download(url, { timeoutMs = DOWNLOAD_TIMEOUT_MS, attempts = 2 } = {}) {
  let current = url;
  let lastError;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      let hops = 0;

      for (;;) {
        const res = await getOnce(current, timeoutMs);

        if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
          const location = res.headers.location;

          if (!location) throw new Error(`redirect ${res.statusCode} with no Location: ${current}`);

          if (++hops > MAX_REDIRECTS) throw new Error(`too many redirects from ${url}`);

          current = new URL(location, current).toString();
          continue;
        }

        if (res.statusCode !== 200) {
          throw new Error(`HTTP ${res.statusCode} for ${current}`);
        }

        return res.body;
      }
    } catch (err) {
      lastError = err;

      if (err.message.startsWith('HTTP 4') || err.message.startsWith('HTTP 5')) {
        // A 404 is a real answer (wrong version, unpublished release); only network
        // errors are worth retrying.
        if (err.message.startsWith('HTTP 4')) throw err;
      }
    }
  }

  throw lastError || new Error(`download failed: ${url}`);
}

/* --- checksums ----------------------------------------------------------- */

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Pick this archive's line out of SHA256SUMS.txt (`<sha>  <name>`).
 *
 * An exact name match, not a prefix: `linux-amd64.zip` is a prefix of nothing today
 * but `linux-arm64` and `linux-armv7` are one character apart, and reading the wrong
 * line would report a checksum mismatch on a good download.
 */
function expectedSha(sumsText, asset) {
  const wanted = asset.trim();

  for (const line of sumsText.split(/\r?\n/)) {
    if (!line.trim()) continue;

    const [sha, name] = [line.slice(0, 64).trim(), line.slice(64).trim().replace(/^\*?\s*/, '')];

    if (name === wanted) {
      if (!/^[0-9a-f]{64}$/i.test(sha)) {
        throw new Error(`SHA256SUMS.txt has a malformed hash for ${wanted}`);
      }

      return sha.toLowerCase();
    }
  }

  throw new Error(`SHA256SUMS.txt has no line for ${wanted} - the release is incomplete`);
}

/* --- zip ----------------------------------------------------------------- */

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

function findEndOfCentralDirectory(zip) {
  // The EOCD record is 22 bytes plus a comment of at most 65535 bytes, and the
  // comment cannot contain the signature in practice, so a backwards scan from the
  // end is the documented way to find it.
  const floor = Math.max(0, zip.length - 22 - 0xffff);

  for (let i = zip.length - 22; i >= floor; i -= 1) {
    if (zip.readUInt32LE(i) === EOCD_SIGNATURE) {
      const commentLength = zip.readUInt16LE(i + 20);

      if (i + 22 + commentLength <= zip.length) return i;
    }
  }

  throw new Error('not a zip archive: no end-of-central-directory record');
}

/**
 * Read the central directory: the only place sizes are guaranteed to be filled in.
 */
function listZipEntries(zip) {
  const eocd = findEndOfCentralDirectory(zip);
  const total = zip.readUInt16LE(eocd + 10);
  let offset = zip.readUInt32LE(eocd + 16);
  const entries = [];

  for (let i = 0; i < total; i += 1) {
    if (offset + 46 > zip.length || zip.readUInt32LE(offset) !== CENTRAL_SIGNATURE) {
      throw new Error('corrupt zip archive: central directory entry ' + i);
    }

    const method = zip.readUInt16LE(offset + 10);
    const compressedSize = zip.readUInt32LE(offset + 20);
    const nameLength = zip.readUInt16LE(offset + 28);
    const extraLength = zip.readUInt16LE(offset + 30);
    const commentLength = zip.readUInt16LE(offset + 32);
    const localOffset = zip.readUInt32LE(offset + 42);
    const name = zip.toString('utf8', offset + 46, offset + 46 + nameLength);

    entries.push({ name, method, compressedSize, localOffset, isDirectory: name.endsWith('/') });

    offset += 46 + nameLength + extraLength + commentLength;
  }

  return entries;
}

/**
 * Uncompress one entry. Its local header is re-read because the name and extra
 * field lengths there may differ from the central directory's, and slicing data at
 * the wrong offset is how a "valid" archive yields a truncated library.
 */
function readZipEntry(zip, entry) {
  const local = entry.localOffset;

  if (zip.readUInt32LE(local) !== LOCAL_SIGNATURE) {
    throw new Error(`corrupt zip archive: bad local header for ${entry.name}`);
  }

  const nameLength = zip.readUInt16LE(local + 26);
  const extraLength = zip.readUInt16LE(local + 28);
  const flags = zip.readUInt16LE(local + 6);
  let start = local + 30 + nameLength + extraLength;
  let size = zip.readUInt32LE(local + 18) || entry.compressedSize;

  if ((flags & 0x08) !== 0) {
    // A data descriptor follows the data, so the local sizes are zero and only the
    // central directory knows the truth.
    size = entry.compressedSize;
  }

  const raw = zip.subarray(start, start + size);

  if (entry.method === 0) return Buffer.from(raw);
  if (entry.method === 8) return zlib.inflateRawSync(raw);

  throw new Error(`zip entry ${entry.name} uses unsupported method ${entry.method}`);
}

/**
 * Return the bytes of the first member whose base name matches, or null.
 *
 * Only the requested file is ever materialised, and it is written under its base
 * name, so a member named `../../.ssh/x` cannot escape the target directory even
 * though the archive came off the network.
 */
function extractZipMember(zip, baseName) {
  for (const entry of listZipEntries(zip)) {
    if (!entry.isDirectory && path.basename(entry.name) === baseName) {
      return { name: entry.name, data: readZipEntry(zip, entry) };
    }
  }

  return null;
}

/* --- the resolver -------------------------------------------------------- */

class FetchError extends Error {
  constructor(slug, version, url, detail) {
    super(
      [
        `ja3-client: could not fetch the native library for ${slug} (${tagFor(version)}).`,
        `  tried: ${url}`,
        '  offline? build it (make -C cffi host), or unzip a release archive and set JA3_CLIENT_LIB=/path/to/lib',
      ].join('\n') + (detail ? `\n  reason: ${detail}` : '')
    );

    this.name = 'FetchError';
    this.detail = detail;
  }
}

/** Every library this binding may use without downloading, cache included. */
function findCachedLibrary(searchDirs, names) {
  const root = cacheDir();

  if (!fs.existsSync(root)) return null;

  const candidates = [];

  for (const versionDir of safeReadDir(root)) {
    for (const slugDir of safeReadDir(path.join(root, versionDir))) {
      for (const name of names) {
        candidates.push(path.join(root, versionDir, slugDir, name));
      }
    }
  }

  // Newest version first: the cache outlives upgrades, and a 1.2.5 binding must not
  // pick up the 1.2.3 library it left behind.
  candidates.sort((a, b) => (a < b ? 1 : -1));

  for (const candidate of candidates) {
    if (isFile(candidate)) return candidate;
  }

  for (const dir of searchDirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (isFile(candidate)) return candidate;
    }
  }

  return null;
}

function safeReadDir(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function isFile(candidate) {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/**
 * Download, verify and cache the library for this machine, or reuse the cache.
 * Resolves to the absolute path of the library.
 */
async function ensureLibrary({ version = resolveVersion(), slug = platformSlug(), log = () => {} } = {}) {
  const explicit = env('JA3_CLIENT_LIB');

  if (explicit) {
    if (!isFile(explicit)) throw new Error(`JA3_CLIENT_LIB points at ${explicit}, which is not a file`);

    return path.resolve(explicit);
  }

  const target = cacheLibraryPath(version, slug);

  if (isFile(target)) {
    log(`ja3-client: cached ${slug} ${version}`);

    return target;
  }

  const url = assetUrl(version, slug);

  if (flag('JA3_CLIENT_OFFLINE')) {
    throw new FetchError(slug, version, url, 'JA3_CLIENT_OFFLINE is set');
  }

  const asset = assetName(version, slug);
  const sums = (await download(sumsUrl(version)).catch((err) => {
    throw new FetchError(slug, version, sumsUrl(version), err.message);
  })).toString('utf8');

  const want = expectedSha(sums, asset);
  const zip = await download(url).catch((err) => {
    throw new FetchError(slug, version, url, err.message);
  });

  const got = sha256Hex(zip);

  if (got !== want) {
    throw new FetchError(slug, version, url, `sha256 is ${got}, SHA256SUMS.txt says ${want}`);
  }

  const name = libraryFileName(slug);
  const member = extractZipMember(zip, name);

  if (!member) {
    throw new FetchError(slug, version, url, `${asset} does not contain ${name}`);
  }

  // Write through a temp dir and os-style rename: an install killed halfway must
  // leave no half-written dylib that dlopen accepts and then crashes on.
  const dir = path.dirname(target);
  const tmp = path.join(dir, `.tmp-${process.pid}-${Date.now()}`);

  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, name), member.data, { mode: 0o755 });
  fs.writeFileSync(
    path.join(tmp, 'install.json'),
    `${JSON.stringify(
      {
        version,
        asset,
        url,
        sha256: want,
        abi: ABI_VERSION,
        installed_at: new Date().toISOString(),
        installed_by: 'npm',
      },
      null,
      2
    )}\n`
  );

  fs.mkdirSync(dir, { recursive: true });

  for (const file of [name, 'install.json']) {
    fs.renameSync(path.join(tmp, file), path.join(dir, file));
  }

  fs.rmSync(tmp, { recursive: true, force: true });

  log(`ja3-client: ${slug} ${version} -> ${target}`);

  return target;
}

/** One-line status for `node lib/native.js status` and for bug reports. */
function status() {
  const version = resolveVersion();
  const slug = platformSlug();

  return {
    version,
    slug,
    repo: repo(),
    baseUrl: baseUrl(),
    cacheDir: cacheDir(),
    libraryPath: cacheLibraryPath(version, slug),
    cached: isFile(cacheLibraryPath(version, slug)),
    offline: flag('JA3_CLIENT_OFFLINE'),
    explicitLib: env('JA3_CLIENT_LIB') || null,
    packageVersion: packageVersion(),
  };
}

async function cli(argv) {
  const command = argv[0] || 'status';

  if (command === 'print-url') {
    process.stdout.write(`${assetUrl(resolveVersion(), platformSlug())}\n`);
    return;
  }

  if (command === 'path') {
    const found = cacheLibraryPath(resolveVersion(), platformSlug());

    if (!isFile(found)) {
      process.stderr.write(`ja3-client: no cached library at ${found}\n`);
      process.exitCode = 1;
      return;
    }

    process.stdout.write(`${found}\n`);
    return;
  }

  if (command === 'ensure') {
    process.stdout.write(`${await ensureLibrary({ log: (line) => process.stderr.write(`${line}\n`) })}\n`);
    return;
  }

  if (command === 'status') {
    for (const [key, value] of Object.entries(status())) {
      process.stdout.write(`${key}=${value}\n`);
    }

    return;
  }

  process.stderr.write(`unknown command '${command}' (print-url | ensure | path | status)\n`);
  process.exitCode = 2;
}

module.exports = {
  ABI_VERSION,
  assetName,
  assetUrl,
  baseUrl,
  cacheDir,
  cacheLibraryPath,
  download,
  ensureLibrary,
  env,
  expectedSha,
  extractZipMember,
  findCachedLibrary,
  flag,
  libraryFileName,
  listZipEntries,
  packageVersion,
  platformSlug,
  repo,
  resolveVersion,
  sha256Hex,
  status,
  sumsUrl,
  tagFor,
};

// `node lib/native.js <command>` - required directly, not imported.
if (require.main === module) {
  cli(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exitCode = 1;
  });
}
