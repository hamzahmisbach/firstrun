// Linux-only gate for free-form runs (section 10.1, `422 unsupported_platform`). This is a platform
// check, not a danger check: it looks at one word, the first command word of the first real line
// (and the first word after each pipe on that line), and fails open. When unsure, the run is allowed
// and the sandbox decides. Names Linux shares with Windows (iex, certutil, reg, cmd) are refused only
// in a Windows shape, read from the words after them. Curated samples never pass through here.

const WINDOWS_WORDS = new Set([
  'powershell', 'pwsh', 'cmd', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'rundll32',
  'regsvr32', 'schtasks', 'reg', 'iex', 'iwr', 'irm',
]);
// Names that Linux programs share with Windows ones; these are Windows only in a Windows shape
// (`name.exe` always is). Each takes the words after the name and whether it follows a pipe.
const AMBIGUOUS_WORDS = {
  // Elixir's shell (`iex -S mix`) vs Invoke-Expression: piped input, `(...)`, a string or `$var`.
  iex: (args, pipe) => pipe || /^[("'$]/.test(args[0] ?? ''),
  // Linux NSS tools (`certutil -d sql:... -L`) vs the Windows one with its download/decode flags.
  certutil: (args) => args.some((a) => /^-(urlcache|decode|encode|verifyctl)$/i.test(a)),
  // Registry CLIs (`reg tags alpine`) vs reg.exe subcommands and HKLM/HKCU keys.
  reg: (args) => /^(add|delete|query|export|import|save|load)$/i.test(args[0] ?? '') || args.some((a) => /^HK(LM|CU)\b/i.test(a)),
  // Any program called `cmd` (`cmd --help`) vs the Windows shell with /c or /k.
  cmd: (args) => args.some((a) => /^\/[ck]$/i.test(a)),
};
const POWERSHELL_WORDS = new Set(['powershell', 'pwsh', 'iex', 'iwr', 'irm']);
const MACOS_WORDS = new Set(['osascript', 'launchctl', 'defaults', 'security', 'open']);

const PS_VERB_NOUN = /^[A-Z][a-z]+-[A-Z][A-Za-z0-9]+$/; // Invoke-WebRequest, Start-Process
const WINDOWS_PATH = /^[A-Za-z]:[\\/]/; // C:\Users\..., D:/tools/...
const WINDOWS_SCRIPT = /\.(ps1|bat|cmd)$/i;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/; // FOO=1 make

/** First line that is not blank and not a comment (so `#!/bin/bash` is skipped). */
function firstLine(command) {
  for (const raw of String(command).split('\n')) {
    const line = raw.trim();
    if (line !== '' && !line.startsWith('#')) return line;
  }
  return '';
}

/** Split a line on unquoted single `|` (not `||`); each part is one pipeline stage. */
function pipelineStages(line) {
  const stages = [];
  let current = '';
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      if (ch === '\\' && quote === '"') current += ch + (line[++i] ?? '');
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
    } else if (ch === '\\') {
      current += ch + (line[++i] ?? '');
    } else if (ch === '|') {
      if (line[i + 1] === '|') {
        current += '||';
        i += 1;
      } else {
        stages.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  stages.push(current);
  return stages;
}

/**
 * The command word of one stage and the words after it: leading VAR=value and `sudo` (with its
 * flags) are skipped.
 */
function commandWord(stage) {
  const words = stage.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < words.length && ASSIGNMENT.test(words[i])) i += 1;
  if (words[i] === 'sudo') {
    i += 1;
    while (i < words.length && words[i].startsWith('-')) i += 1;
  }
  const word = (words[i] ?? '').replace(/^["']+|["';]+$/g, '');
  return { word, args: words.slice(i + 1) };
}

function isWindowsWord(word, args, pipe) {
  const lower = word.toLowerCase();
  const bare = lower.replace(/\.exe$/, '');
  if (!WINDOWS_WORDS.has(bare)) return PS_VERB_NOUN.test(word) || WINDOWS_PATH.test(word) || WINDOWS_SCRIPT.test(word);
  const shape = AMBIGUOUS_WORDS[bare];
  return !shape || lower !== bare || shape(args, pipe);
}

/** "windows" | "macos" | null for one command word; `pipe` limits the check to Windows names. */
function classifyWord({ word, args }, { pipe = false } = {}) {
  if (!word) return null;
  if (isWindowsWord(word, args, pipe)) return 'windows';
  if (!pipe && MACOS_WORDS.has(word.toLowerCase())) return 'macos';
  return null;
}

/**
 * @param {string} command free-form command text as pasted
 * @returns {{platform: 'windows'|'macos', word: string} | null} null means "treat as Linux"
 */
export function detectPlatform(command) {
  const stages = pipelineStages(firstLine(command));
  for (let i = 0; i < stages.length; i += 1) {
    const found = commandWord(stages[i]);
    const platform = classifyWord(found, { pipe: i > 0 });
    if (platform) return { platform, word: found.word };
  }
  return null;
}

/** One sentence for the UI, after "FirstRun only runs Linux commands." */
export function platformMessage({ platform, word }) {
  if (platform === 'macos') return 'This looks like a macOS command, so it can\'t be tested here.';
  const lower = String(word).toLowerCase().replace(/\.exe$/, '');
  const ps = POWERSHELL_WORDS.has(lower) || PS_VERB_NOUN.test(word) || /\.ps1$/i.test(word);
  return `This looks like a Windows ${ps ? 'PowerShell' : ''} command, so it can't be tested here.`.replace('  ', ' ');
}
