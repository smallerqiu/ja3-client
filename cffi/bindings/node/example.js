// Run me after `make host` in cffi/: node example.js
//
// Mirrors the Python and C# examples so the three bindings can be compared line
// by line.

const { Ja3, Ja3Error } = require('./index.js');

const ja3 = new Ja3();
console.log(`library ${ja3.libraryVersion} (${ja3.buildTime}) from ${ja3.path}`);

const report = ja3.get('https://tls.browserleaks.com/json', { impersonate: 'chrome_133', timeout: 20 });
console.log('browserleaks', report.statusCode, report.protocol, report.json().ja3n_hash,
  'warnings=', report.warnings);

const session = ja3.session({ impersonate: 'chrome_126', timeout: 20 });
const first = session.get('https://httpbin.org/get');
console.log('session', session.handle, first.statusCode, first.json().headers['User-Agent'].slice(0, 30));

const posted = session.post('https://httpbin.org/post', { k: '中文' }, {
  headers: { 'content-type': 'application/json' },
});
console.log('post', posted.statusCode, JSON.stringify(posted.json().json));

const dropped = session.get('https://httpbin.org/headers', { headers: { 'user-agent': null } });
console.log('user-agent removed ->', dropped.json().headers, dropped.warnings);

session.close();

const binary = ja3.get('https://www.google.com/favicon.ico');
console.log('favicon', binary.statusCode, binary.body.length, 'bytes',
  binary.header('content-type'), binary.body.subarray(0, 4).toString('hex'));

const typo = ja3.get('https://httpbin.org/get', { impersonate: 'chrome_133', with_http4: true });
console.log('unknown option is reported, not dropped:', typo.warnings, typo.statusCode);

try {
  session.get('https://httpbin.org/get');
} catch (error) {
  console.log('closed session ->', error.codeName);
}
