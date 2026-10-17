// Check the async half of the Node binding: fetch() really is non-blocking, the
// concurrency gate holds, errors keep the same shape as the synchronous path, and the
// teardown advice in the README is what the runtime actually needs.
//
//     node test-async.js [path/to/library]      # or set JA3_CLIENT_LIB
//
// Three layers on purpose. The gate is tested against a stubbed export, because "at most N
// calls reach koffi" is invisible from the outside and a gate that silently stopped
// counting would still return correct responses. Everything else is tested against the
// real library and a local HTTP server, because the wiring that can only break in the
// real path is the disposable type on a worker thread: get that wrong and the process
// crashes or leaks one allocation per call. And the shutdown question can only be asked
// of a child process, since the answer is about how a process ends.
//
// Needs `npm install` once (koffi). It listens on 127.0.0.1 and makes no external request.

'use strict';

const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const { Ja3, Ja3Error, Response } = require('./index.js');

const failures = [];

function expect(label, condition, detail) {
  if (condition) {
    console.log(`  ok   ${label}`);
    return;
  }

  failures.push(label);
  console.log(`  FAIL ${label}${detail ? `: ${detail}` : ''}`);
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Every burst is awaited through here. A gate that stopped releasing slots would leave a
// fetch pending forever, which hangs this file instead of failing it, so each await has a
// deadline that names the burst and the cause.
const BURST_TIMEOUT = 20000;

function withTimeout(promise, label, ms = BURST_TIMEOUT) {
  let timer;

  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: never settled in ${ms}ms - a slot was never released`)), ms);
  });

  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

// A stand-in for the native function: `.async` records how many calls are outstanding,
// which is the only way to see the gate from JavaScript.
function stub({ delay = 5, failWith = null } = {}) {
  const state = { active: 0, maxActive: 0, calls: 0 };

  state.fn = {
    async(payload, callback) {
      state.calls += 1;
      state.active += 1;
      state.maxActive = Math.max(state.maxActive, state.active);

      setTimeout(() => {
        state.active -= 1;

        if (failWith) callback(failWith);
        else callback(null, JSON.stringify({ ok: true, error_code: 0, status_code: 200, body: 'stub' }));
      }, delay);
    },
  };

  return state;
}

async function gateRunsThroughTheRealCodePath(ja3) {
  const original = ja3._fns.request;

  try {
    ja3.maxConcurrency = 3;

    let state = stub();
    ja3._fns.request = state.fn;
    await withTimeout(Promise.all(Array.from({ length: 12 }, (_, i) => ja3.fetch(`http://127.0.0.1/${i}`))),
      '12-call burst at limit 3');
    expect('gate caps a burst at maxConcurrency',
      state.maxActive === 3 && state.calls === 12,
      `peak ${state.maxActive} of ${state.calls} calls, limit 3`);

    ja3.maxConcurrency = 6;
    state = stub();
    ja3._fns.request = state.fn;
    await withTimeout(Promise.all(Array.from({ length: 12 }, (_, i) => ja3.fetch(`http://127.0.0.1/${i}`))),
      '12-call burst at limit 6');
    expect('raising the limit raises the peak',
      state.maxActive === 6 && state.calls === 12,
      `peak ${state.maxActive}, limit 6`);

    // A rejected call has to give its slot back, or the gate deadlocks the next one.
    ja3.maxConcurrency = 1;
    state = stub({ failWith: new Error('stub failure') });
    ja3._fns.request = state.fn;
    const failed = await withTimeout(
      ja3.fetch('http://127.0.0.1/x').then(() => null, (err) => err),
      'the call the stub rejects');
    expect('native failure rejects with the binding’s own message',
      failed instanceof Error && /stub failure/.test(failed.message), String(failed));

    ja3._fns.request = stub().fn;
    const after = await withTimeout(ja3.fetch('http://127.0.0.1/after'), 'call after a failure');
    expect('a failed call released its slot', after.statusCode === 200, JSON.stringify(after.raw));
  } finally {
    ja3._fns.request = original;
    ja3.maxConcurrency = 256;
  }
}

async function realLibraryIsNonBlocking(ja3, port) {
  const url = `http://127.0.0.1:${port}/probe`;
  const options = { impersonate: 'chrome_153', timeout: 15 };

  let ticks = 0;
  const timer = setInterval(() => {
    ticks += 1;
  }, 20);

  const started = Date.now();
  const four = await withTimeout(
    Promise.all([1, 2, 3, 4].map((i) => ja3.fetch(`${url}?i=${i}`, options))),
    'four concurrent fetches');
  const concurrent = Date.now() - started;
  clearInterval(timer);

  expect('four fetches overlap instead of queueing behind each other',
    concurrent < 3 * 120 && ticks >= 2,
    `${concurrent}ms for four 120ms handlers, event loop ticked ${ticks} times`);
  expect('async responses are ordinary Response objects',
    four.every((r) => r instanceof Response && r.statusCode === 200),
    four.map((r) => r.statusCode).join(','));
  expect('each call got its own body',
    new Set(four.map((r) => r.json().path)).size === 4,
    four.map((r) => r.json().path).join(','));

  const t2 = Date.now();
  for (let i = 0; i < 3; i++) {
    await withTimeout(ja3.fetch(`${url}?s=${i}`, options), `sequential fetch ${i}`);
  }
  const serial = Date.now() - t2;
  expect('sequential awaits are slower than concurrent ones',
    serial >= 3 * 120, `${serial}ms serial vs ${concurrent}ms concurrent`);

  // Same input, both paths: an error has to be a Ja3Error with the library's code,
  // whether it arrives as a throw or a rejection.
  const syncError = await new Promise((resolve) => {
    try {
      ja3.get('');
    } catch (err) {
      resolve(err);
    }
  });
  const asyncError = await withTimeout(ja3.fetch('').then(() => null, (err) => err), 'empty-url fetch');
  expect('the async path keeps the sync error shape',
    syncError instanceof Ja3Error && asyncError instanceof Ja3Error &&
      asyncError.errorCode === syncError.errorCode && asyncError.codeName === syncError.codeName,
    `sync ${syncError && syncError.codeName}, async ${asyncError && asyncError.codeName}`);

  // A session is the case people will actually write: many concurrent requests, one pool
  // and one cookie jar. Client-level keys must still be stripped on the wire.
  const session = ja3.session({ impersonate: 'chrome_153' });
  const viaSession = await withTimeout(
    Promise.all([1, 2, 3].map((i) => session.fetch(`${url}?sess=${i}`, { impersonate: 'firefox_135' }))),
    'three concurrent session.fetch calls');
  expect('session.fetch works concurrently on one handle',
    viaSession.every((r) => r.statusCode === 200) && new Set(viaSession.map((r) => r.json().path)).size === 3,
    viaSession.map((r) => r.json().path).join(','));

  const warned = await withTimeout(session.fetch(`http://127.0.0.1:${port}/warn`, { impersonate: 'chrome_153' }),
    'session.fetch with a client-level key');
  expect('a client-level key on a session call is stripped before the wire',
    warned.statusCode === 200 && warned.warnings.length === 0,
    `warnings=${JSON.stringify(warned.warnings)}`);

  session.close();
  const closed = await session.fetch(url).then(() => null, (err) => err);
  expect('fetch on a closed session rejects with INVALID_HANDLE',
    closed instanceof Ja3Error && closed.errorCode === 4, String(closed));
}

// What happens at teardown. Once a Go export has run on a worker thread, Node's own shutdown
// does not finish: the loop drains, `beforeExit` fires, and the process stays up. The same
// async call into a plain C library exits by itself, so it is the Go runtime's thread
// handover on shutdown rather than koffi's pool. A server never sees it; a script that
// reaches its last line does, which is why the README says to call process.exit() - and this
// checks that the advice works, in a child process, offline, against its own server.
const CHILD = [
  "const http = require('http');",
  'const { Ja3 } = require(process.env.JA3_TEST_INDEX);',
  '(async () => {',
  '  const server = http.createServer((req, res) => setTimeout(() => { res.writeHead(200); res.end("{}"); }, 10));',
  "  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));",
  '  const ja3 = new Ja3();',
  '  const res = await ja3.fetch(`http://127.0.0.1:${server.address().port}/x`);',
  '  console.log(`CHILD_DONE ${res.statusCode}`);',
  "  if (process.env.JA3_TEST_EXIT === '1') process.exit(0);",
  '})();',
].join('\n');

function runChild({ libraryPath, shouldExit }) {
  return new Promise((resolve) => {
    const started = Date.now();

    let printedDone = false;
    let killed = false;

    const child = spawn(process.execPath, ['-e', CHILD], {
      env: {
        ...process.env,
        JA3_TEST_INDEX: path.join(__dirname, 'index.js'),
        JA3_CLIENT_LIB: libraryPath,
        JA3_TEST_EXIT: shouldExit ? '1' : '0',
      },
      stdio: ['ignore', 'pipe', 'inherit'],
    });

    child.stdout.on('data', (chunk) => {
      if (String(chunk).includes('CHILD_DONE')) printedDone = true;
    });

    child.on('exit', (code) => {
      resolve({ code, printedDone, killed, ranFor: Date.now() - started });
    });

    // An exit this process did not ask for is the behaviour being reported, not asserted:
    // if a future Go or koffi release lets the loop drain, that is the docs getting shorter.
    const timer = setTimeout(() => {
      killed = true;
      child.kill('SIGKILL');
    }, 3000);

    timer.unref();
  });
}

async function exitBehaviour(libraryPath) {
  const told = await runChild({ libraryPath, shouldExit: true });
  expect('a script that calls process.exit() after fetch() ends with its answer intact',
    told.printedDone && told.code === 0 && !told.killed, JSON.stringify(told));

  const untold = await runChild({ libraryPath, shouldExit: false });
  console.log(`  info a child that does not call process.exit(): ${untold.killed
    ? `still running ${untold.ranFor}ms after its last response (the documented case)`
    : `exited by itself with code ${untold.code} - the runtime no longer blocks shutdown`}`);
}

async function main() {
  const ja3 = new Ja3({ libraryPath: process.argv[2] });

  console.log(`library: ${ja3.path}`);
  console.log(`version: ${ja3.version()} (async gate default ${ja3.maxConcurrency})`);

  expect('maxConcurrency defaults to koffi’s async queue', ja3.maxConcurrency === 256,
    String(ja3.maxConcurrency));

  const bad = [0, -1, 2.5, 'x'];
  const rejected = bad.filter((value) => {
    try {
      ja3.maxConcurrency = value;
      return false;
    } catch (err) {
      return err instanceof Ja3Error && err.errorCode === 1;
    }
  });
  expect('an unusable limit is refused', rejected.length === bad.length,
    `accepted: ${bad.filter((v) => !rejected.includes(v)).join(', ')}`);
  ja3.maxConcurrency = 256;

  await gateRunsThroughTheRealCodePath(ja3);

  // A handler that sleeps, so overlap is measurable rather than assumed.
  const server = http.createServer((req, res) => {
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ path: req.url }));
    }, 120);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    await realLibraryIsNonBlocking(ja3, port);
  } finally {
    // The Go client keeps its connections open, so close() alone would leave this
    // process waiting on sockets the library is done using.
    if (server.closeAllConnections) server.closeAllConnections();
    server.close();
  }

  await exitBehaviour(ja3.path);

  if (failures.length) {
    console.log(`\n${failures.length} check(s) failed: ${failures.join(', ')}`);
    process.exit(1);
  }

  console.log('\nall async checks passed');
  process.exit(0);
}

main().catch((err) => {
  console.error(`async checks aborted: ${err && err.stack}`);
  process.exit(1);
});
