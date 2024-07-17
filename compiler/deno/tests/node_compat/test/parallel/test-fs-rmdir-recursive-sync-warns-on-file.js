// deno-fmt-ignore-file
// deno-lint-ignore-file

// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// Taken from Node 18.12.1
// This file is automatically generated by `tests/node_compat/runner/setup.ts`. Do not modify this file manually.

'use strict';
const common = require('../common');
const tmpdir = require('../common/tmpdir');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

tmpdir.refresh();

{
  common.expectWarning(
    'DeprecationWarning',
    'In future versions of Node.js, fs.rmdir(path, { recursive: true }) ' +
      'will be removed. Use fs.rm(path, { recursive: true }) instead',
    'DEP0147'
  );
  const filePath = path.join(tmpdir.path, 'rmdir-recursive.txt');
  fs.writeFileSync(filePath, '');
  assert.throws(
    () => fs.rmdirSync(filePath, { recursive: true }),
    { code: common.isWindows ? 'ENOENT' : 'ENOTDIR' }
  );
}