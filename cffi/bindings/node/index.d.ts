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
}

export interface RequestOptions extends ClientOptions {
  method?: string;
  headers?: Record<string, string | string[] | null>;
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
  get(url: string, options?: Omit<RequestOptions, 'method'>): Response;
  post(url: string, body?: RequestOptions['body'], options?: Omit<RequestOptions, 'method' | 'body'>): Response;
  close(): void;
}

export declare class Ja3Error extends Error {
  readonly errorCode: number;
  readonly codeName: string;
  readonly payload: Record<string, unknown>;
}

export declare class Ja3 {
  constructor(options?: { libraryPath?: string; checkAbi?: boolean });
  readonly path: string;
  readonly libraryVersion: string;
  readonly buildTime: string;
  version(): string;
  request(url: string, options?: RequestOptions): Response;
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

export default binding;
export { Ja3, Session, Response, Ja3Error };
