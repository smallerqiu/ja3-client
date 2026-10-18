/**
 * Node.js bindings for the ja3-client shared library, built on koffi.
 *
 *     npm install ja3-client   // or link this folder from a checkout
 *
 *     const { Ja3 } = require('ja3-client');
 *
 *     const ja3 = new Ja3();
 *     const res = ja3.request('https://tls.browserleaks.com/json', { impersonate: 'chrome_133' });
 *     console.log(res.json().ja3n_hash);
 *
 *     const session = ja3.session({ impersonate: 'chrome_133' });
 *     session.get('https://example.com/');       // same pool + cookie jar
 *     session.close();
 *
 *     const pages = await Promise.all(                            // non-blocking siblings
 *       urls.map((url) => ja3.fetch(url, { impersonate: 'chrome_133' })));
 *
 * The ABI contract (payload keys, response envelope, error codes) lives in
 * cffi/README.md. Every call returns a malloc'd C string, so the functions are
 * wrapped in a koffi disposable type that calls ja3_free after conversion; using a
 * plain 'str' return type would leak one allocation per call. The same disposable
 * serves the async path: `fn.async(...)` converts and frees on the way back, which
 * is why the binding never hands a raw pointer to JavaScript.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

let koffi;
try {
  koffi = require('koffi');
} catch (err) {
  throw new Error(
    'The Node binding needs koffi (npm install koffi). ' +
      'Alternatively load the library from Python (ctypes, zero dependencies) or C# (P-Invoke).',
    { cause: err }
  );
}

const ABI_VERSION = 2;

// Cached result of the lazy require in loadInstaller(); undefined = not tried yet.
let installer;

const ERROR_CODES = {
  0: 'OK',
  1: 'NIL_ARGUMENT',
  2: 'BAD_JSON',
  3: 'SESSION_INIT',
  4: 'INVALID_HANDLE',
  5: 'REQUEST',
  6: 'READ_BODY',
  7: 'MARSHAL',
  8: 'PANIC',
};

/**
 * Default ceiling on `fetch()` calls in flight or waiting. koffi itself runs async calls
 * on worker threads and queues the rest, but its queue is hard-capped
 * (`max_async_calls`, 256 by default, 4096 absolute maximum) and it *rejects* past that
 * with "Too many asynchronous calls are running". A binding that hands you an exception
 * because 257 promises were created is not a useful API, so `fetch` waits for a slot
 * instead of asking koffi to hold the whole set. Measured on this library: 256 issued in
 * one synchronous burst all complete; 600 return 256 responses and 344 errors.
 */
const DEFAULT_MAX_CONCURRENCY = 256;

/**
 * A counting semaphore. One instance per process (module level), because the limit it
 * protects - koffi's async queue - is process-wide too: two `Ja3` objects with private
 * gates of 256 would still overflow it together.
 */
class Gate {
  constructor(limit) {
    this.limit = limit;
    this.active = 0;
    this.waiters = [];
  }

  setLimit(value) {
    if (!Number.isInteger(value) || value < 1) {
      throw new Ja3Error(`maxConcurrency must be a positive integer, got ${value}`, 1);
    }

    this.limit = value;
    this.drain();
  }

  acquire() {
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve();
    }

    return new Promise((resolve) => this.waiters.push(resolve));
  }

  release() {
    this.active -= 1;
    this.drain();
  }

  drain() {
    while (this.active < this.limit && this.waiters.length > 0) {
      this.active += 1;
      this.waiters.shift()();
    }
  }
}

const asyncGate = new Gate(DEFAULT_MAX_CONCURRENCY);

/** Options the library only reads while building the client. */
const CLIENT_ONLY_KEYS = [
  'impersonate', 'ja3', 'akamai', 'client_data', 'proxy', 'source_ip', 'timeout',
  'force_http1', 'with_http3', 'random_extension_order', 'with_debug',
  'not_follow_redirects',
];

class Ja3Error extends Error {
  constructor(message, errorCode, payload) {
    super(message);
    this.name = 'Ja3Error';
    this.errorCode = errorCode;
    this.codeName = ERROR_CODES[errorCode] || `UNKNOWN_${errorCode}`;
    this.payload = payload || {};
  }
}

function platformArch() {
  const platform = os.platform();
  let arch = os.arch();

  if (arch === 'x64') arch = 'amd64';
  else if (arch === 'arm64') arch = 'arm64';
  else if (arch === 'ia32') arch = '386';
  else if (arch.startsWith('arm')) arch = 'armv7'; // 32-bit: arm, armv6l, armv7l

  return { platform, arch };
}

function libraryNames() {
  const { platform, arch } = platformArch();

  if (platform === 'darwin') return [`ja3_client_${arch}.dylib`, 'libja3-client.dylib'];
  if (platform === 'win32') return [`ja3_client_${arch}.dll`, 'ja3-client.dll'];

  const names = [`libja3_client_${arch}.so`];

  if (arch === 'armv7' || arch === 'arm') {
    // 32-bit ARM reports armv6l/armv7l; the release names them armv7/arm.
    names.push('libja3_client_armv7.so', 'libja3_client_arm.so');
  }

  names.push('libja3-client.so');

  return names;
}

function findLibrary(explicit) {
  const { platform } = platformArch();
  const candidates = [];

  if (explicit) candidates.push(explicit);
  if (process.env.JA3_CLIENT_LIB) candidates.push(process.env.JA3_CLIENT_LIB);

  // JA3_CLIENT_LIB means "this file and nothing else" (cffi/PACKAGING.md): a typo has
  // to stop here instead of quietly loading some other version off disk, which would
  // show up as a fingerprint nobody can explain.
  if (process.env.JA3_CLIENT_LIB && !fs.existsSync(process.env.JA3_CLIENT_LIB)) {
    throw new Ja3Error(`JA3_CLIENT_LIB points at ${process.env.JA3_CLIENT_LIB}, which is not a file`, 1);
  }

  const here = __dirname;
  const root = path.resolve(here, '..', '..'); // bindings/node -> cffi
  const dirs = [
    path.join(root, 'build', platform),
    path.join(root, 'build', 'release'),
    path.join(root, 'build'),
    path.join(root, 'dist'),
    here,
    process.cwd(),
  ];

  for (const dir of dirs) {
    for (const name of libraryNames()) candidates.push(path.join(dir, name));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }

  // Nothing local: hand over to the installer, which knows the shared cache
  // (~/.cache/ja3-client/<version>/<os>-<arch>/) filled by `npm install`, and can
  // fetch into it. Loading is synchronous, so the work happens in a child process
  // running the same resolver the postinstall script uses - one implementation, and
  // lib/native.js stays optional for anyone who vendored index.js alone.
  const native = loadInstaller();

  // JA3_CLIENT_LIB means "this file, and nothing else" (PACKAGING.md), so a missing
  // path must become an error rather than quietly resolving to a cached library.
  if (native && !process.env.JA3_CLIENT_LIB) {
    const cached = native.findCachedLibrary(dirs, libraryNames());
    if (cached) return cached;

    const fetched = fetchThroughInstaller();
    if (fetched) return fetched;
  }

  throw new Ja3Error(
    'libja3-client not found. Build it (make -C cffi), run `node lib/native.js ensure`, ' +
      'or set JA3_CLIENT_LIB. Looked at: ' +
      candidates.slice(0, 8).join(', '),
    1
  );
}

/** The installer module, or null when it is not next to this file. */
function loadInstaller() {
  if (installer === undefined) {
    try {
      // eslint-disable-next-line global-require
      installer = require('./lib/native');
    } catch {
      installer = null;
    }
  }

  return installer;
}

function fetchThroughInstaller() {
  const { execFileSync } = require('child_process');

  try {
    const out = execFileSync(process.execPath, [path.join(__dirname, 'lib', 'native.js'), 'ensure'], {
      encoding: 'utf8',
      // The download itself times out at 60s per request; this is the outer bound on
      // "npm install was interrupted by a hung resolver", and it inherits stderr so
      // the installer's own three-line message reaches the user.
      timeout: 180000,
      stdio: ['ignore', 'pipe', 'inherit'],
    });

    const file = out.trim().split('\n').pop();

    return file && fs.existsSync(file) ? file : null;
  } catch {
    return null;
  }
}

/** base64 for anything that is not a plain string, matching the Go contract. */
function encodeBody(body) {
  if (body === undefined || body === null) return {};
  if (typeof body === 'string') return { body };
  if (Buffer.isBuffer(body)) return { body_base64: body.toString('base64') };
  if (body instanceof Uint8Array) {
    return { body_base64: Buffer.from(body).toString('base64') };
  }
  if (typeof body === 'object') return { body: JSON.stringify(body) };

  return { body: String(body) };
}

function buildPayload(url, options) {
  const { method = 'GET', headers, body, ...rest } = options || {};
  const payload = { url, method: String(method).toUpperCase(), ...encodeBody(body) };

  if (headers) payload.headers = headers;

  for (const [key, value] of Object.entries(rest)) {
    if (value !== undefined && value !== null) payload[key] = value;
  }

  return payload;
}

class Response {
  constructor(envelope) {
    this.raw = envelope;
    this.statusCode = envelope.status_code || 0;
    this.status = this.statusCode;
    this.protocol = envelope.protocol || '';
    this.headers = envelope.headers || {};
    this.setCookies = envelope.set_cookies || [];
    this.warnings = envelope.warnings || [];
    this.session = envelope.session || 0;
    this.bodySize = envelope.body_size || 0;
    this.body = envelope.body_base64
      ? Buffer.from(envelope.body_base64, 'base64')
      : Buffer.from(envelope.body || '', 'utf8');
  }

  get ok() {
    return this.statusCode >= 200 && this.statusCode < 400;
  }

  text() {
    return this.body.toString('utf8');
  }

  json() {
    return JSON.parse(this.text());
  }

  header(name) {
    const wanted = String(name).toLowerCase();

    for (const [key, values] of Object.entries(this.headers)) {
      if (key.toLowerCase() === wanted) return values && values.length ? values[0] : undefined;
    }

    return undefined;
  }

  raiseForStatus() {
    if (!this.ok) throw new Ja3Error(`HTTP ${this.statusCode}`, 5, this.raw);

    return this;
  }
}

class Session {
  constructor(ja3, handle) {
    this._ja3 = ja3;
    this.handle = handle;
    this.closed = false;
  }

  request(url, options) {
    if (this.closed) throw new Ja3Error('session is closed', 4);

    return new Response(this._ja3._sessionRequest(this.handle, sessionPayload(url, options)));
  }

  // The non-blocking sibling of `request`, on the same session: same pool, same cookie
  // jar, same client-level options ignored. Concurrent calls on one session are the
  // library's problem to serialize, not yours - the Go client guards its own state.
  fetch(url, options) {
    if (this.closed) return Promise.reject(new Ja3Error('session is closed', 4));

    return this._ja3._sessionFetch(this.handle, sessionPayload(url, options))
      .then((envelope) => new Response(envelope));
  }

  get(url, options) {
    return this.request(url, { ...options, method: 'GET' });
  }

  post(url, body, options) {
    return this.request(url, { ...options, method: 'POST', body });
  }

  close() {
    if (this.closed) return;

    this._ja3._sessionClose(this.handle);
    this.closed = true;
  }
}

// A session has already built its client, so the client-level keys are dropped here - on
// the wire they would be silently ignored by the library, and the binding would be the
// only place that could tell you you wrote one by mistake.
function sessionPayload(url, options) {
  const payload = buildPayload(url, options);

  for (const key of CLIENT_ONLY_KEYS) delete payload[key];

  return payload;
}

// koffi's type registry is process-wide and a second `koffi.disposable()` under the same
// name throws `Duplicate type name`. Registering inside the constructor therefore limits
// a process to one `Ja3` object - which contradicts the gate above and the README's
// `maxConcurrency` example, both of which assume two objects coexist. One name per
// resolved library path, reused by every later instance: `close()` never unloads the
// handle, so the `ja3_free` captured by the first registration stays valid for the
// process, and it is the free of the library that allocated the string.
const heapStrings = new Map();

function heapStringType(libraryPath, free) {
  const registered = heapStrings.get(libraryPath);

  if (registered) return registered;

  const HeapStr = koffi.disposable(`HeapStr${heapStrings.size}`, 'str', free);

  heapStrings.set(libraryPath, HeapStr);

  return HeapStr;
}

class Ja3 {
  constructor(options = {}) {
    const { libraryPath, checkAbi = true, maxConcurrency = undefined } = options;

    this.path = findLibrary(libraryPath);
    this._lib = koffi.load(this.path);

    const free = this._lib.func('ja3_free', 'void', ['void *']);
    // Conversion to JS string happens first, then ja3_free releases the C buffer.
    const HeapStr = heapStringType(this.path, free);

    this._fns = {
      version: this._lib.func('ja3_version', HeapStr, []),
      request: this._lib.func('ja3_request', HeapStr, ['str']),
      sessionNew: this._lib.func('ja3_session_new', HeapStr, ['str']),
      sessionRequest: this._lib.func('ja3_session_request', HeapStr, ['uint64_t', 'str']),
      sessionClose: this._lib.func('ja3_session_close', HeapStr, ['uint64_t']),
    };

    const envelope = this._call('version', undefined);

    if (checkAbi && envelope.abi !== undefined && envelope.abi !== ABI_VERSION) {
      throw new Ja3Error(
        `${this.path} speaks ABI ${envelope.abi}, this binding expects ${ABI_VERSION}`,
        envelope.abi
      );
    }

    this.libraryVersion = envelope.version || 'unknown';
    this.buildTime = envelope.build_time || '';

    if (maxConcurrency !== undefined) asyncGate.setLimit(maxConcurrency);
  }

  // koffi's async queue is one resource for the whole process, so this is a process-wide
  // number no matter which instance you read it from - and setting it on any instance
  // moves the ceiling for every `fetch()` in the program.
  get maxConcurrency() {
    return asyncGate.limit;
  }

  set maxConcurrency(value) {
    asyncGate.setLimit(value);
  }

  // _arguments builds the native argument list. `extra` are the leading arguments (the
  // session handle); the JSON payload, when there is one, is always the last.
  static _arguments(payload, extra) {
    const args = extra.map((value) => (typeof value === 'bigint' ? value : BigInt(value)));

    if (payload !== undefined) args.push(JSON.stringify(payload));

    return args;
  }

  // _decode turns one envelope of text into an object or an exception - the same rules
  // for the sync and the async path, so a library error never changes shape by thread.
  static _decode(fnName, text) {
    if (typeof text !== 'string') {
      throw new Ja3Error(`${fnName} returned no value`, 7);
    }

    let envelope;
    try {
      envelope = JSON.parse(text);
    } catch (err) {
      throw new Ja3Error(`library returned malformed JSON: ${err.message}`, 7, { text });
    }

    if (envelope.error_code !== 0) {
      throw new Ja3Error(envelope.error || ERROR_CODES[envelope.error_code], envelope.error_code, envelope);
    }

    return envelope;
  }

  // _call runs one export synchronously: the event loop stops until the library returns.
  _call(fnName, payload, ...extra) {
    const fn = this._fns[fnName];

    return Ja3._decode(fnName, fn(...Ja3._arguments(payload, extra)));
  }

  // _fetch runs the same export on a koffi worker thread and resolves when it lands. The
  // gate is what makes "issue 10k promises" a queue instead of koffi rejecting the calls
  // past its own pool size.
  _fetch(fnName, payload, ...extra) {
    const fn = this._fns[fnName];
    const args = Ja3._arguments(payload, extra);

    return asyncGate.acquire().then(() => {
      let pending;
      try {
        pending = new Promise((resolve, reject) => {
          fn.async(...args, (err, text) => {
            if (err) reject(new Error(`${fnName}: ${err}`));
            else resolve(text);
          });
        });
      } catch (err) {
        // koffi throws here when its async queue is already full; release the slot so the
        // gate does not leak capacity on a call that never started.
        asyncGate.release();
        return Promise.reject(err);
      }

      return pending
        .then((text) => Ja3._decode(fnName, text))
        .finally(() => asyncGate.release());
    });
  }

  version() {
    return this.libraryVersion;
  }

  request(url, options = {}) {
    return new Response(this._call('request', buildPayload(url, options)));
  }

  get(url, options = {}) {
    return this.request(url, { ...options, method: 'GET' });
  }

  post(url, body, options = {}) {
    return this.request(url, { ...options, method: 'POST', body });
  }

  /**
   * The non-blocking form of `request`: one call in flight on a koffi worker thread, the
   * event loop free while it runs. Same payload, same `Response`, same `Ja3Error`; the
   * only difference is that failures arrive as a rejected promise instead of a throw.
   *
   * It is named `fetch` and not `requestAsync` on purpose - `await ja3.request(...)` would
   * resolve happily while blocking your loop for the whole request, and a name that cannot
   * be confused with the sync one is the only guard against that.
   */
  fetch(url, options = {}) {
    return this._fetch('request', buildPayload(url, options)).then((envelope) => new Response(envelope));
  }

  session(options = {}) {
    const payload = {};

    for (const [key, value] of Object.entries(options)) {
      if (value !== undefined && value !== null) payload[key] = value;
    }

    const envelope = this._call('sessionNew', payload);

    return new Session(this, envelope.session);
  }

  _sessionRequest(handle, payload) {
    return this._call('sessionRequest', payload, BigInt(handle));
  }

  _sessionFetch(handle, payload) {
    return this._fetch('sessionRequest', payload, BigInt(handle));
  }

  _sessionClose(handle) {
    return this._call('sessionClose', undefined, BigInt(handle));
  }

  close() {
    /* koffi keeps the handle alive for the process; nothing to release here. */
  }
}

module.exports = { Ja3, Session, Response, Ja3Error, ABI_VERSION, ERROR_CODES };
module.exports.default = module.exports;
