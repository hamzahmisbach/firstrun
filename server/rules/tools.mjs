// Tool and category constants for the rules (docs/ARCHITECTURE.md section 9, lists from 5.3/5.4).

/** Decoy categories of the 5.3 manifest (also the enum of `allowed_decoy_categories`, 8.1). */
export const DECOY_CATEGORIES = Object.freeze([
  'ssh_private_key',
  'ssh_meta',
  'cloud_credentials',
  'package_manager_token',
  'vcs_token',
  'registry_token',
  'browser_profile',
  'wallet',
  'ai_assistant_config',
  'project_secrets',
  'history',
  'phished_input',
]);

/** Plain-English label per category, for titles ("fake cloud credentials"), never the raw name. */
export const CATEGORY_LABEL = Object.freeze({
  ssh_private_key: 'SSH private key',
  ssh_meta: 'SSH settings',
  cloud_credentials: 'cloud credentials',
  package_manager_token: 'package manager token',
  vcs_token: 'Git hosting token',
  registry_token: 'container registry login',
  browser_profile: 'browser profile',
  wallet: 'crypto wallet',
  ai_assistant_config: 'AI assistant login',
  project_secrets: 'project secrets',
  history: 'shell history',
  phished_input: 'typed password',
});

export function categoryLabel(category) {
  return CATEGORY_LABEL[category] ?? 'credential';
}

/** Categories whose read is `low`/`medium` rather than a credential leak. */
export const NOT_SENSITIVE = Object.freeze(new Set(['ssh_meta', 'history', 'phished_input']));

/** No claim ever justifies touching these; the contract cannot explain them. */
export const NEVER_ALLOWED = Object.freeze(new Set(['wallet', 'browser_profile', 'phished_input']));

/** Tools that legitimately read a category; listing one in `expected_processes` explains the read. */
export const CATEGORY_OWNER = Object.freeze({
  package_manager_token: Object.freeze(['npm', 'npx', 'pnpm', 'yarn', 'corepack']),
  registry_token: Object.freeze(['docker']),
  vcs_token: Object.freeze(['git', 'gh']),
  cloud_credentials: Object.freeze(['aws', 'gcloud', 'kubectl']),
  ai_assistant_config: Object.freeze(['claude', 'gemini', 'codex']),
  ssh_private_key: Object.freeze(['ssh', 'scp', 'sftp']),
  ssh_meta: Object.freeze(['ssh', 'scp', 'sftp', 'git']),
  project_secrets: Object.freeze([]),
  history: Object.freeze([]),
  browser_profile: Object.freeze([]),
  wallet: Object.freeze([]),
  phished_input: Object.freeze([]),
});

/** Any category not in the manifest is treated as sensitive (fail safe). */
export function isSensitive(category) {
  return !NOT_SENSITIVE.has(category);
}

// Shim names (exactly the 5.4 list), grouped by what calling them means.
export const PERSIST = Object.freeze(new Set(['crontab', 'systemctl', 'launchctl', 'schtasks', 'reg']));
export const PRIV = Object.freeze(new Set(['sudo', 'su', 'doas']));
export const CRED_PROMPT = Object.freeze(new Set(['osascript', 'security']));
export const OS_EXEC = Object.freeze(
  new Set([
    'powershell',
    'powershell.exe',
    'cmd',
    'cmd.exe',
    'mshta',
    'rundll32',
    'regsvr32',
    'wscript',
    'cscript',
    'certutil',
    'bitsadmin',
  ]),
);
export const PREFS = Object.freeze(new Set(['defaults']));
export const AI_CLI = Object.freeze(new Set(['claude', 'gemini', 'codex']));
export const OPENER = Object.freeze(new Set(['open', 'xdg-open']));

// Processes.
export const SHELLS = Object.freeze(new Set(['bash', 'sh', 'dash', 'zsh']));
export const INTERPRETERS = Object.freeze(new Set(['python3', 'python', 'perl', 'ruby', 'php', 'node', 'pwsh', 'lua']));
export const INLINE_FLAGS = Object.freeze(new Set(['-c', '-e', '-Command', '-EncodedCommand', '-enc', '-ec', '-']));
export const NET_TOOLS = Object.freeze(new Set(['nc', 'netcat', 'socat']));

/** `base64 -d|--decode`, `xxd -r`, `openssl enc -d`, `gunzip`, `zcat`. */
export function isDecodeHelper(name, argv) {
  const args = Array.isArray(argv) ? argv.slice(1).map(String) : [];
  switch (name) {
    case 'gunzip':
    case 'zcat':
      return true;
    case 'base64':
      return args.some((a) => a === '-d' || a === '--decode' || /^-[a-zA-Z]*d[a-zA-Z]*$/.test(a));
    case 'xxd':
      return args.some((a) => a === '-r' || /^-[a-zA-Z]*r[a-zA-Z]*$/.test(a));
    case 'openssl':
      return args[0] === 'enc' && args.includes('-d');
    default:
      return false;
  }
}

/** Interpreter invoked with code on the command line (or on stdin) instead of a script file. */
export function hasInlineFlag(argv) {
  if (!Array.isArray(argv)) return false;
  return argv.slice(1).some((a) => INLINE_FLAGS.has(String(a)));
}
