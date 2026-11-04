// Output schemas for every LLM call (docs/ARCHITECTURE.md 8.1, 8.3, 8.4). All are strictObject:
// unknown keys are rejected, every choice is an enum, every string has a maximum length. Nothing
// the model returns is used before it passes one of these.
import { z } from 'zod';

/** Decoy categories from the 5.3 manifest, in table order. */
export const DECOY_CATEGORIES = [
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
];

/** One line per category for the contract prompt (no paths, no values). */
export const DECOY_CATEGORY_MEANINGS = Object.freeze({
  ssh_private_key: 'an SSH private key',
  ssh_meta: 'SSH config, known_hosts and public keys',
  cloud_credentials: 'cloud provider credentials (AWS, GCP, Kubernetes)',
  package_manager_token: 'a package registry auth token (npm)',
  vcs_token: 'a git hosting token (GitHub CLI, git credential store)',
  registry_token: 'a container registry login (Docker)',
  browser_profile: 'browser saved passwords and cookies',
  wallet: 'cryptocurrency wallet files and seed phrases',
  ai_assistant_config: 'AI assistant CLI credentials',
  project_secrets: 'a project .env file with API keys',
  history: 'shell history files',
  phished_input: 'a password typed into a prompt',
});

/** No claim can justify reading these (8.1 salvage). */
export const NEVER_ALLOWED = Object.freeze(['wallet', 'browser_profile', 'phished_input']);

export const HARNESS_LANGUAGES = ['bash', 'pwsh', 'python3', 'node'];

export const VERDICT_LEVELS = ['CLEAN', 'SUSPICIOUS', 'MALICIOUS'];

export const Contract = z.strictObject({
  summary: z.string().trim().min(1).max(300),
  expected_hosts: z.array(z.string().max(253)).max(32),
  expected_write_paths: z.array(z.string().max(256)).max(32),
  expected_processes: z.array(z.string().max(64)).max(32),
  allowed_decoy_categories: z.array(z.enum(DECOY_CATEGORIES)).max(4),
  notes: z.string().max(500),
});

export const Harness = z.strictObject({
  language: z.enum(HARNESS_LANGUAGES),
  harness: z.string().min(1).max(32768),
  replaced: z.array(z.strictObject({ sink: z.string().max(80), with: z.string().max(80) })).max(20),
  expected_output_kind: z.enum(['script', 'data', 'unknown']),
  notes: z.string().max(300),
});

export const Explanation = z.strictObject({
  verdict_echo: z.enum(VERDICT_LEVELS),
  headline: z.string().trim().min(1).max(120),
  paragraphs: z.array(z.string().max(600)).min(1).max(3),
  finding_notes: z.array(z.strictObject({ finding_id: z.string().max(64), text: z.string().max(200) })).max(20),
  next_step: z.string().max(200),
});

export const SCHEMAS = Object.freeze({ contract: Contract, harness: Harness, explanation: Explanation });

/**
 * JSON Schema for `response_format: {type: "json_schema"}`. zod's own converter keeps
 * `additionalProperties: false` and the `required` list, which is what strict mode needs.
 */
export function toJsonSchema(schema) {
  const { $schema, ...rest } = z.toJSONSchema(schema);
  return rest;
}
