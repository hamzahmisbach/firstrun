// What a second try may change (docs/ARCHITECTURE.md 8.7). A fixed menu: the model only picks names
// from these lists, and the host owns every value. So attacker-influenced model output can never put
// text into a Docker argument or code into the sandbox. Pure: no I/O.

export const DEFAULT_HOSTNAME = 'devbox';
export const RETRY_HOSTNAMES = Object.freeze([DEFAULT_HOSTNAME, 'macbook-pro', 'prod-web-01', 'ci-runner-7']);

const PLAIN_ENV = Object.freeze({
  CI: 'true',
  GITHUB_ACTIONS: 'true',
  DISPLAY: ':0',
  SUDO_USER: 'dev',
  SSH_CONNECTION: '10.0.0.5 50122 10.0.0.9 22',
});

// Keys a command may look for. Each value carries a per-run canary, so if the command sends one
// anywhere the matcher sees it exactly as it sees a fake credential read from a file.
const SECRET_ENV = Object.freeze({
  AWS_SECRET_ACCESS_KEY: (token) => token,
  GITHUB_TOKEN: (token) => `ghp_${token}`,
  NPM_TOKEN: (token) => `npm_${token}`,
  OPENAI_API_KEY: (token) => `sk-${token}`,
  ANTHROPIC_API_KEY: (token) => `sk-ant-${token}`,
});

export const RETRY_ENV_NAMES = Object.freeze([...Object.keys(PLAIN_ENV), ...Object.keys(SECRET_ENV)]);

/** Shorter than the first run: this try only needs to get past the condition that stopped it. */
export const RETRY_TIMEOUT_S = 30;
export const ANSWERS_FILE_TEXT = 'y\n'.repeat(200);

/**
 * Turn a verified retry request into sandbox settings.
 * @param {{set_env?: string[], hostname?: string, answer_yes?: boolean, skip_sleep?: boolean}} retry
 * @param {object[]} decoys manifest; only `env_secret`'s value is read
 * @returns {{env: [string, string][], hostname: string, answerYes: boolean, skipSleep: boolean, timeoutS: number}}
 */
export function resolveKnobs(retry, decoys) {
  const token = (Array.isArray(decoys) ? decoys : []).find((d) => d?.id === 'env_secret')?.value;
  const env = [];
  for (const name of new Set(Array.isArray(retry?.set_env) ? retry.set_env : [])) {
    if (Object.hasOwn(PLAIN_ENV, name)) env.push([name, PLAIN_ENV[name]]);
    else if (Object.hasOwn(SECRET_ENV, name) && typeof token === 'string') env.push([name, SECRET_ENV[name](token)]);
  }
  return {
    env,
    hostname: RETRY_HOSTNAMES.includes(retry?.hostname) ? retry.hostname : DEFAULT_HOSTNAME,
    answerYes: retry?.answer_yes === true,
    skipSleep: retry?.skip_sleep === true,
    timeoutS: RETRY_TIMEOUT_S,
  };
}

/** True when the knobs differ from a normal run, so a second try could behave differently. */
export function knobsChangeAnything(knobs) {
  return knobs.env.length > 0 || knobs.hostname !== DEFAULT_HOSTNAME || knobs.answerYes || knobs.skipSleep;
}

/** Names only, safe for SSE, logs and the report: secret values never leave the sandbox arguments. */
export function describeKnobs(knobs) {
  return {
    set_env: knobs.env.map(([name]) => name),
    hostname: knobs.hostname,
    answer_yes: knobs.answerYes,
    skip_sleep: knobs.skipSleep,
  };
}
