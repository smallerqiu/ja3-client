/**
 * Type definitions for the ja3-client Node binding.
 */

export declare const ABI_VERSION: number;

export declare const ERROR_CODES: Record<number, string>;

export interface ClientOptions {
  /** Profile id, e.g. `chrome_133`, `firefox_135`, `safari_170`. */
  impersonate?: string;
  /** Raw JA3 string; takes precedence over `impersonate`. */
  ja3?: string;
  /** Akamai HTTP/2 settings string, used together with `ja3`. */
  akamai?: string;
  /** Hand-built fingerprint, e.g. `{ cipher_suites: "...", http_2_setting: "..." }`. */
  client_data?: Record<string, unknown>;
  /** `http://user:pass@host:port`, `socks5://host:port`. */
  proxy?: string;
  source_ip?: string;
  /** Seconds; 0 means the library default (30). */
  timeout?: number;
  force_http1?: boolean;
  /** Tri-state: omit to keep the profile default, false to disable HTTP/3. */
  with_http3?: boolean;
  random_extension_order?: boolean;
  not_follow_redirects?: boolean;
  with_debug?: boolean;
  /**
   * Headers this client/session sends by default. A call's own `headers` are merged over
   * these rather than replacing them, which is what keeps the profile's `user-agent`
   * alive; a `null` value removes a header the session would otherwise have sent.
   */
  headers?: Record<string, string | string[] | null>;
}

export interface RequestOptions extends ClientOptions {
  method?: string;
  body?: string | Buffer | Uint8Array | Record<string, unknown> | number | boolean;
  /** Use instead of `body` when the payload is not valid UTF-8 text. */
  body_base64?: string;
}

export declare class Response {
  readonly raw: Record<string, unknown>;
  readonly statusCode: number;
  readonly status: number;
  readonly protocol: string;
  readonly headers: Record<string, string[]>;
  readonly setCookies: string[];
  readonly warnings: string[];
  readonly session: number;
  readonly bodySize: number;
  readonly body: Buffer;
  readonly ok: boolean;
  text(): string;
  json<T = unknown>(): T;
  header(name: string): string | undefined;
  raiseForStatus(): Response;
}

export declare class Session {
  readonly handle: number;
  closed: boolean;
  request(url: string, options?: RequestOptions): Response;
  /** The non-blocking `request`: same handle, same pool and cookie jar, answers a promise. */
  fetch(url: string, options?: RequestOptions): Promise<Response>;
  get(url: string, options?: Omit<RequestOptions, 'method'>): Response;
  post(url: string, body?: RequestOptions['body'], options?: Omit<RequestOptions, 'method' | 'body'>): Response;
  close(): void;
}

export declare class Ja3Error extends Error {
  /** `new Ja3Error('HTTP 404', 5, response.raw)` - the shape `raiseForStatus()` throws. */
  constructor(message: string, errorCode?: number, payload?: Record<string, unknown>);
  readonly errorCode: number;
  readonly codeName: string;
  readonly payload: Record<string, unknown>;
}

export declare class Ja3 {
  constructor(options?: {
    libraryPath?: string;
    checkAbi?: boolean;
    /**
     * Ceiling on `fetch()` calls in flight or queued, process-wide because koffi's async
     * queue is. Default 256, which is koffi's own `max_async_calls`; calls past the ceiling
     * wait instead of failing.
     */
    maxConcurrency?: number;
  });
  readonly path: string;
  readonly libraryVersion: string;
  readonly buildTime: string;
  /** Read or move the process-wide `fetch()` ceiling; a non-positive integer throws `Ja3Error` 1. */
  maxConcurrency: number;
  version(): string;
  request(url: string, options?: RequestOptions): Response;
  /**
   * The non-blocking `request`: the call runs on a koffi worker thread and the event loop
   * stays free. Same options and `Response`; failures reject with `Ja3Error` instead of
   * throwing. Named `fetch` so it cannot be confused with `request`, which blocks the loop
   * for its whole duration even when you await it.
   */
  fetch(url: string, options?: RequestOptions): Promise<Response>;
  get(url: string, options?: Omit<RequestOptions, 'method'>): Response;
  post(url: string, body?: RequestOptions['body'], options?: Omit<RequestOptions, 'method' | 'body'>): Response;
  session(options?: ClientOptions): Session;
  close(): void;
}

declare const binding: {
  Ja3: typeof Ja3;
  Session: typeof Session;
  Response: typeof Response;
  Ja3Error: typeof Ja3Error;
  ABI_VERSION: number;
  ERROR_CODES: Record<number, string>;
};

// `Ja3`, `Session`, `Response` and `Ja3Error` are exported where they are declared, so
// there is no re-export list at the bottom of this file: a second `export { Ja3, … }`
// next to `export declare class Ja3` is not a restatement, it is a duplicate name in the
// same module, and every TypeScript consumer - `require` or `import`, node16 or bundler -
// then compiles their own project into "Cannot redeclare exported variable 'Ja3'".
// `make types-check` (cffi/check-node-types.sh) typechecks a real consumer against these
// declarations, which is what catches that shape.
export default binding;
