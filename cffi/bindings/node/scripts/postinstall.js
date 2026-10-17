/**
 * npm postinstall: fetch the native library for this machine.
 *
 * This runs during `npm install`, which is the moment a user has network and has not
 * yet started the app. Failure must not break the install - an app that ships its own
 * build and pins JA3_CLIENT_LIB would be un-installable over a CDN hiccup - so the
 * default is a warning and exit 0. Set JA3_CLIENT_STRICT=1 to make it fatal; CI that
 * wants the download proven should set it.
 */

'use strict';

const { ensureLibrary, platformSlug, resolveVersion, assetUrl, flag, env } = require('../lib/native');

function explain(lines) {
  for (const line of lines) process.stderr.write(`${line}\n`);
}

async function main() {
  if (env('JA3_CLIENT_LIB')) {
    explain([`ja3-client: JA3_CLIENT_LIB is set (${env('JA3_CLIENT_LIB')}); nothing downloaded.`]);

    return;
  }

  if (flag('JA3_CLIENT_OFFLINE')) {
    explain([
      'ja3-client: JA3_CLIENT_OFFLINE is set; the native library was not downloaded.',
      '  run `node lib/native.js ensure` once you have network, or build it',
      '  (make -C cffi host) and point JA3_CLIENT_LIB at the result.',
    ]);

    return;
  }

  const version = resolveVersion();
  const slug = platformSlug();

  try {
    const path = await ensureLibrary({ log: () => {} });
    process.stdout.write(`ja3-client: ${slug} ${version} -> ${path}\n`);
  } catch (err) {
    explain([err.message || String(err)]);

    if (flag('JA3_CLIENT_STRICT')) {
      process.exitCode = 1;
    } else {
      explain([
        `ja3-client: the library will be fetched again on first use, or install it by hand`,
        `  from ${assetUrl(version, slug)} (check it against SHA256SUMS.txt).`,
      ]);
    }
  }
}

main().catch((err) => {
  explain([err.message || String(err)]);

  if (flag('JA3_CLIENT_STRICT')) process.exitCode = 1;
});
