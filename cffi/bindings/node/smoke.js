// Check a built libja3-client shared library without touching the network.
//
//     node smoke.js [path/to/library]        # or set JA3_CLIENT_LIB
//
// Same contract as bindings/python/smoke.py, for the binding that has the most
// fragile memory rule: every export returns a malloc'd C string, and this binding
// releases it through a koffi disposable type. If that wiring is broken you get a
// leak or a crash here, not in a user's long-running service.
//
// Needs `npm install` once (koffi). It makes no request, so it runs offline.

'use strict';

const { Ja3, Ja3Error, ABI_VERSION } = require('./index.js');

const failures = [];

function expect(label, condition, detail) {
  if (condition) {
    console.log(`  ok   ${label}`);
    return;
  }

  failures.push(label);
  console.log(`  FAIL ${label}${detail ? `: ${detail}` : ''}`);
}

let ja3;
try {
  ja3 = new Ja3({ libraryPath: process.argv[2], checkAbi: false });
} catch (err) {
  console.error(`cannot load library: ${err.message}`);
  process.exit(1);
}

console.log(`library: ${ja3.path}`);

const info = ja3._call('version', undefined);
console.log(
  `version: ${info.version}  abi: ${info.abi}  build_time: ${info.build_time}`
);

expect('abi matches this binding', info.abi === ABI_VERSION,
  `library says ${info.abi}, binding expects ${ABI_VERSION}`);
expect('version is stamped', info.version && info.version !== 'dev',
  'built without -X main.Version, so bug reports cannot name a release');
expect('ok flag set', info.ok === true, JSON.stringify(info).slice(0, 120));

// A malformed payload must come back as an envelope, not as a crash. The raw
// export is called directly because _call() would JSON.stringify the payload.
const badJson = JSON.parse(ja3._fns.request('{not json'));
expect('malformed payload -> BAD_JSON', badJson.error_code === 2,
  JSON.stringify(badJson).slice(0, 120));

try {
  ja3.get('', { impersonate: 'chrome_133' });
  expect('empty url -> NIL_ARGUMENT', false, 'no error raised');
} catch (err) {
  expect('empty url -> NIL_ARGUMENT', err instanceof Ja3Error && err.errorCode === 1,
    `${err && err.name}: ${err && err.message}`);
}

const session = ja3.session({ impersonate: 'chrome_140' });
expect('session_new returns a handle', session.handle > 0, String(session.handle));

session.close();
expect('session_close marks the binding handle closed', session.closed === true);

try {
  ja3._sessionClose(session.handle);
  expect('second close is rejected', false, 'closed handle answered again');
} catch (err) {
  expect('second close is rejected', err instanceof Ja3Error && err.errorCode === 4,
    `${err && err.name}: ${err && err.message}`);
}

if (failures.length) {
  console.log(`\n${failures.length} check(s) failed: ${failures.join(', ')}`);
  process.exit(1);
}

console.log('\nall checks passed');
