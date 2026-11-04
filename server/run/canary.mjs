// Canary tokens and the decoy manifest (docs/ARCHITECTURE.md 5.3). One run_secret per run, one
// token per decoy file derived from it, so a hit always names the file that leaked. Nothing here
// touches the disk; run/seed.mjs renders the files and evidence/matcher.mjs looks for the values.
import { createHmac, randomBytes } from 'node:crypto';

/** RFC 4648 base32 alphabet; tokens are `FR` + 22 of these (24 chars = 18 bytes of base64 input). */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOKEN_RE = /^FR[A-Z2-7]{22}$/;
export const TOKEN_LENGTH = 24;

/** Forms the matcher derives from every value (6.6). Order matters: the first match wins. */
export const ALL_FORMS = Object.freeze(['raw', 'b64x3', 'b64b64x3', 'url', 'hex', 'base32']);

/**
 * The decoy table of 5.3. `path` is relative to HOME (`null` for the non-file canary), `token`
 * says whether the file carries a canary value; tokenless rows are decoys for the "was it read"
 * signal only.
 */
export const DECOY_TABLE = Object.freeze(
  [
    { id: 'ssh_key', path: '.ssh/id_ed25519', category: 'ssh_private_key', token: true },
    { id: 'ssh_pub', path: '.ssh/id_ed25519.pub', category: 'ssh_meta', token: false },
    { id: 'ssh_config', path: '.ssh/config', category: 'ssh_meta', token: false },
    { id: 'ssh_known_hosts', path: '.ssh/known_hosts', category: 'ssh_meta', token: false },
    { id: 'aws_secret', path: '.aws/credentials', category: 'cloud_credentials', token: true },
    { id: 'aws_config', path: '.aws/config', category: 'cloud_credentials', token: true },
    { id: 'gcloud_adc', path: '.config/gcloud/application_default_credentials.json', category: 'cloud_credentials', token: true },
    { id: 'kube_config', path: '.kube/config', category: 'cloud_credentials', token: true },
    { id: 'npmrc', path: '.npmrc', category: 'package_manager_token', token: true },
    { id: 'gh_hosts', path: '.config/gh/hosts.yml', category: 'vcs_token', token: true },
    { id: 'git_credentials', path: '.git-credentials', category: 'vcs_token', token: true },
    { id: 'docker_config', path: '.docker/config.json', category: 'registry_token', token: true },
    { id: 'chrome_login_data', path: '.config/google-chrome/Default/Login Data', category: 'browser_profile', token: true },
    { id: 'chrome_cookies', path: '.config/google-chrome/Default/Cookies', category: 'browser_profile', token: true },
    { id: 'chrome_web_data', path: '.config/google-chrome/Default/Web Data', category: 'browser_profile', token: true },
    { id: 'chrome_local_state', path: '.config/google-chrome/Local State', category: 'browser_profile', token: true },
    { id: 'firefox_logins', path: '.mozilla/firefox/k3x9q1z7.default-release/logins.json', category: 'browser_profile', token: true },
    { id: 'firefox_key4', path: '.mozilla/firefox/k3x9q1z7.default-release/key4.db', category: 'browser_profile', token: true },
    { id: 'firefox_cookies', path: '.mozilla/firefox/k3x9q1z7.default-release/cookies.sqlite', category: 'browser_profile', token: true },
    { id: 'exodus_seed', path: '.config/Exodus/exodus.wallet/seed.seco', category: 'wallet', token: true },
    { id: 'electrum_wallet', path: '.electrum/wallets/default_wallet', category: 'wallet', token: true },
    { id: 'seed_phrase', path: 'Documents/wallet-backup/seed-phrase.txt', category: 'wallet', token: true },
    { id: 'claude_credentials', path: '.claude/.credentials.json', category: 'ai_assistant_config', token: true },
    { id: 'claude_json', path: '.claude.json', category: 'ai_assistant_config', token: true },
    { id: 'gemini_oauth', path: '.gemini/oauth_creds.json', category: 'ai_assistant_config', token: true },
    { id: 'project_env', path: 'projects/acme-app/.env', category: 'project_secrets', token: true },
    { id: 'bash_history', path: '.bash_history', category: 'history', token: false },
    { id: 'zsh_history', path: '.zsh_history', category: 'history', token: false },
    { id: 'pw', path: null, category: 'phished_input', token: true },
  ].map(Object.freeze),
);

export const DECOY_CATEGORIES = Object.freeze([...new Set(DECOY_TABLE.map((d) => d.category))]);

function base32Encode(bytes, chars) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = ((acc << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5 && out.length < chars) {
      bits -= 5;
      out += BASE32[(acc >>> bits) & 31];
    }
    if (out.length === chars) break;
  }
  return out;
}

/** Token for one decoy: HMAC(run_secret, id), so the manifest is a pure function of the secret. */
export function deriveToken(runSecret, decoyId) {
  const mac = createHmac('sha256', Buffer.from(runSecret, 'hex')).update(decoyId).digest();
  return `FR${base32Encode(mac, TOKEN_LENGTH - 2)}`;
}

/** `AKIA` + 16 characters derived from the token, the shape of an AWS access key id. */
export function deriveAwsKeyId(token) {
  const mac = createHmac('sha256', 'aws-key-id').update(token).digest();
  return `AKIA${base32Encode(mac, 16)}`;
}

/** A fresh random token in the canary shape (used for tests and ad-hoc values). */
export function newToken() {
  return `FR${base32Encode(randomBytes(16), TOKEN_LENGTH - 2)}`;
}

export function isToken(value) {
  return typeof value === 'string' && TOKEN_RE.test(value);
}

/**
 * @returns {{ runSecret: string, decoys: Array<{id, path, category, value, forms}> }}
 *   `runSecret` is 32 random bytes as hex. `decoys` is the manifest of 5.3: `path` is `~/...`
 *   (null for `pw`), `value` is the token or null for tokenless rows, `forms` lists the shapes
 *   the matcher derives (empty for tokenless rows).
 */
export function createCanaries({ runSecret = randomBytes(32).toString('hex') } = {}) {
  if (!/^[0-9a-f]{64}$/.test(runSecret)) throw new Error('runSecret must be 32 bytes as hex');
  const decoys = DECOY_TABLE.map((row) => ({
    id: row.id,
    path: row.path === null ? null : `~/${row.path}`,
    category: row.category,
    value: row.token ? deriveToken(runSecret, row.id) : null,
    forms: row.token ? [...ALL_FORMS] : [],
  }));
  return { runSecret, decoys };
}
