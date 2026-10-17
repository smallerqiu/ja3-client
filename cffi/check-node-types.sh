#!/usr/bin/env bash
# Typecheck the Node binding's declarations the way a consumer's project compiles them.
#
# The problem this exists for: index.d.ts is the only part of the package a TypeScript
# reader sees, and nothing else in this repository parses it. `make node-smoke` loads the
# runtime, check-binding-readmes.sh reads the docs - both stayed green across two releases
# while the declarations exported every class twice, once as `export declare class Ja3` and
# again in a bottom-of-file `export { Ja3, ... }`. That second form is not a restatement, it
# is a duplicate name in the same module, so every consumer's own `tsc` answered "Cannot
# redeclare exported variable 'Ja3'" the moment they imported the package - in `require` and
# in `import`, under node16 and under bundler alike.
#
# So this compiles a small consumer against the shipped entry points, once per resolution
# mode a real project picks. skipLibCheck is off on purpose: turning it on is what lets a
# broken .d.ts through, since the file being checked *is* a .d.ts.
#
#   ./check-node-types.sh          from cffi/ or anywhere
#
# The fixtures carry @ts-expect-error lines too. Declarations that accept a wrong call are
# as broken as declarations that reject a right one, and only a fixture that is required to
# fail can tell those two apart.
#
# typescript is deliberately not a devDependency of bindings/node/package.json: the
# published manifest is what npm shows the world, and a build tool does not belong in it.
# The compiler goes to a scratch directory and is reused from there. Without node/npm, or
# without a route to the registry on the first run, this reports the skip and exits 0 the
# way the other toolchain-gated targets do - CI sets JA3_TYPES_STRICT=1 so a skip there is
# a failure instead of a quiet green.
set -euo pipefail

cd "$(dirname "$0")"

TS_VERSION=5.6
TYPES_NODE_VERSION=22

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "node/npm missing; skipping the typecheck" >&2
  [ "${JA3_TYPES_STRICT:-}" = "1" ] && exit 1
  exit 0
fi

work="${TMPDIR:-/tmp}"
work="${work%/}/ja3-client-types-check-ts${TS_VERSION}"
pkg="$work/node_modules/ja3-client"
tests="$work/types-test"

if [ ! -x "$work/node_modules/.bin/tsc" ]; then
  echo "==> installing typescript@$TS_VERSION + @types/node@$TYPES_NODE_VERSION in $work"
  mkdir -p "$work"
  printf '{"name":"ja3-client-types-check","private":true}\n' > "$work/package.json"
  if ! (cd "$work" && npm install --no-audit --no-fund --silent \
      "typescript@$TS_VERSION" "@types/node@$TYPES_NODE_VERSION") >/dev/null 2>&1; then
    echo "typescript is not installed and npm could not fetch it; skipping the typecheck" >&2
    [ "${JA3_TYPES_STRICT:-}" = "1" ] && exit 1
    exit 0
  fi
fi
tsc="$work/node_modules/.bin/tsc"

# Stage the binding the way npm delivers it: into a node_modules entry, so resolution walks
# the package's own "exports" map (require -> index.js, import -> index.mjs, types ->
# index.d.ts). Pointing a tsconfig at bindings/node/index.d.ts directly would check the
# declarations but not the entry points, and the entry points are what an ESM consumer breaks
# on. The tree is built from package.json's "files" list rather than a hard-coded copy,
# because that list is what `npm pack` honours: the usual way an entry point goes missing from
# the published package is that it still sits in the repository and never made the tarball.
rm -rf "$pkg" "$tests"
mkdir -p "$pkg" "$tests"
published="$(node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync("bindings/node/package.json", "utf8"));
  console.log([...(pkg.files || []), "package.json"].join("\n"));
')"
while IFS= read -r file; do
  if [ ! -e "bindings/node/$file" ]; then
    echo "FAIL bindings/node/package.json packs \"$file\", which the directory does not have" >&2
    exit 1
  fi
  mkdir -p "$pkg/$(dirname "$file")"
  cp -R "bindings/node/$file" "$pkg/$file"
done <<< "$published"

# The export map itself, read before any typecheck. TypeScript resolves this package's
# declarations even when "exports" carries no "import" leg - it walks back to index.js and
# finds index.d.ts beside it - so a binding that stopped mapping ESM would still typecheck
# three times over while every real `import 'ja3-client'` died on ERR_PACKAGE_PATH_NOT_EXPORTED.
# Only the shipped files can answer that question, so ask them.
fails=0
echo "==> entry points"
legs="$(JA3_PKG="$pkg" node -e '
  const fs = require("fs");
  const dir = process.env.JA3_PKG;
  const pkg = JSON.parse(fs.readFileSync(dir + "/package.json", "utf8"));
  const mapped = (pkg.exports && pkg.exports["."]) || {};
  for (const condition of ["types", "require", "import"]) {
    const target = mapped[condition];
    if (typeof target !== "string") {
      console.log(`${condition} - not-mapped`);
      continue;
    }
    console.log(`${condition} ${target} ${fs.existsSync(dir + "/" + target.replace(/^.\//, "")) ? "ok" : "missing-file"}`);
  }
  // And the two pre-exports fields, for a resolver older than "exports".
  console.log(`main ${pkg.main || "-"} ${pkg.main && fs.existsSync(dir + "/" + pkg.main.replace(/^.\//, "")) ? "ok" : "missing-file"}`);
  console.log(`types-field ${pkg.types || "-"} ${pkg.types && fs.existsSync(dir + "/" + pkg.types.replace(/^.\//, "")) ? "ok" : "missing-file"}`);
')"
while IFS=' ' read -r condition target state; do
  if [ "$state" != "ok" ]; then
    echo "FAIL $condition -> ${target} ($state)"
    fails=$((fails + 1))
  else
    echo "ok   $condition -> $target"
  fi
done <<< "$legs"

if [ "$fails" -ne 0 ]; then
  echo >&2
  echo "\"exports\" has to carry all three conditions, and each one has to name a file the" >&2
  echo "package actually ships - the \"files\" list in bindings/node/package.json decides that," >&2
  echo "not the directory on disk. Dropping \"import\" makes every ESM consumer fail to resolve" >&2
  echo "the package at all, which is the one failure mode the typecheck below cannot see: the" >&2
  echo "TypeScript resolver walks back to index.js and finds its declarations there." >&2
  exit 1
fi

# One body, three module systems: a CommonJS-flavoured .ts and an ESM .ts under node16, and
# the same ESM source under the bundler resolution Vite/esbuild-based projects use.
cat > "$tests/surface.ts" <<'FIXTURE'
import client, {
  Ja3, Session, Response, Ja3Error, ABI_VERSION, ERROR_CODES,
} from 'ja3-client';

const ja3 = new Ja3({ checkAbi: true });

const res: Response = ja3.request('https://example.com', {
  impersonate: 'chrome_133',
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-empty': null },
  body: { q: '中文', page: 1 },
  proxy: 'http://user:pass@127.0.0.1:8888',
  timeout: 10,
  with_http3: false,
  not_follow_redirects: true,
  client_data: { cipher_suites: '4865,4866' },
});

// What a Response answers with: every property the README lists, at its own type.
const statusCode: number = res.statusCode;
const status: number = res.status;
const protocol: string = res.protocol;
const headers: Record<string, string[]> = res.headers;
const setCookies: string[] = res.setCookies;
const warnings: string[] = res.warnings;
const sessionNumber: number = res.session;
const bodySize: number = res.bodySize;
const body: Buffer = res.body;
const ok: boolean = res.ok;
const raw: Record<string, unknown> = res.raw;
const text: string = res.text();
const contentType: string | undefined = res.header('content-type');
const ja4: string = res.json<{ ja4: string }>().ja4;
const same: Response = res.raiseForStatus();

const session: Session = ja3.session({ impersonate: 'chrome_153', headers: { 'x-app': 'demo' } });
const seen: Response = session.get('https://example.com', { headers: { authorization: 'Basic dTpw' } });
session.post('https://example.com', 'plain body');
session.post('https://example.com', Buffer.from([0, 1, 2]), { body_base64: 'aGk=' });
const handle: number = session.handle;
session.close();

// The async half, in the same shape a consumer writes it. Declared rather than run: this
// fixture is compiled, never executed.
async function useAsync() {
  const page: Response = await ja3.fetch('https://example.com', { impersonate: 'chrome_133', timeout: 10 });
  const pages: Response[] = await Promise.all(
    ['a', 'b'].map((part) => ja3.fetch(`https://example.com/${part}`, { method: 'POST', body: { part } })));
  const viaSession: Response = await session.fetch('https://example.com', { headers: { 'x-n': '1' } });
  const pending: Promise<Response> = session.fetch('https://example.com');
  const ceiling: number = ja3.maxConcurrency;
  ja3.maxConcurrency = 64;
  const configured = new Ja3({ maxConcurrency: 128 });
  configured.close();

  return [page, pages, viaSession, pending, ceiling];
}

const version: string = ja3.version();
const libraryVersion: string = ja3.libraryVersion;
const buildTime: string = ja3.buildTime;
const libraryPath: string = ja3.path;
ja3.close();

const abi: number = ABI_VERSION;
const badJson: string = ERROR_CODES[2];

try {
  same.raiseForStatus();
} catch (err) {
  if (err instanceof Ja3Error) {
    const errorCode: number = err.errorCode;
    const codeName: string = err.codeName;
    const payload: Record<string, unknown> = err.payload;
  }
  const thrown = new Ja3Error('HTTP 500', 5, { status_code: 500 });
}

// The default export is the same binding spelled as an object, so a consumer who copied the
// README's `require` shape in TypeScript keeps working after switching to `import`.
const fromDefault = new client.Ja3();
const fromNamed = new Ja3();
fromDefault.close();
fromNamed.close();

// @ts-expect-error get() sets the method, so it is not a caller's option
ja3.get('https://example.com', { method: 'DELETE' });
// @ts-expect-error timeout counts seconds, not a duration spelled as a string
ja3.request('https://example.com', { timeout: '10s' });
// @ts-expect-error an unknown option is a typo, not a pass-through field
ja3.request('https://example.com', { impersonate_: 'chrome_133' });
// @ts-expect-error the body is bytes; text() is the call that decodes it
const bodyAsText: string = res.body;
// Only `fetch` answers a promise. An `await ja3.request(...)` looks right and blocks the
// event loop for the whole request, so the declarations have to reject the shape.
// @ts-expect-error request() returns a Response, not something awaitable
const notAPromise: Promise<Response> = ja3.request('https://example.com');
// @ts-expect-error the ceiling counts calls, so it is not a string
ja3.maxConcurrency = '128';
FIXTURE
cp "$tests/surface.ts" "$tests/surface.mts"

# Each mode of its own: "files" keeps the run to the fixture (the scratch dir is outside the
# repository, so a bare include would sweep the staged copy of the binding in as a second
# module), and noEmit means nothing is written anywhere.
write_tsconfig() {
  cat > "$tests/tsconfig.$1.json" <<EOF
{
  "compilerOptions": {
    "target": "es2022",
    "lib": ["es2022"],
    "module": "$2",
    "moduleResolution": "$3",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": false,
    "noEmit": true
  },
  "files": ["$4"]
}
EOF
}

write_tsconfig node16-cjs    node16 node16  surface.ts
write_tsconfig node16-esm    node16 node16  surface.mts
write_tsconfig bundler       esnext bundler surface.mts

echo "==> tsc $("$tsc" --version)"

fails=0
for cfg in node16-cjs node16-esm bundler; do
  printf '%-14s ' "$cfg"
  if "$tsc" -p "$tests/tsconfig.$cfg.json"; then
    echo "ok"
  else
    echo "FAIL"
    fails=$((fails + 1))
  fi
done

if [ "$fails" -ne 0 ]; then
  cat >&2 <<'MSG'
index.d.ts does not compile against a real consumer. Read it top-down: a name declared
with `export declare class X` is already exported, and listing it again at the bottom of
the file is a duplicate, not a restatement; and a module whose entry points are mapped by
"exports" has to answer for each mode separately, because `require` and `import` resolve
different files.
MSG
  exit 1
fi

echo "==> node binding declarations typecheck in all three modes"
