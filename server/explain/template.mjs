// Deterministic fallback explanation (docs/ARCHITECTURE.md 8.4), used when the LLM is disabled,
// times out, or its answer fails validation. Written for non-experts: plain words, no jargon,
// and it never says more than the evidence does.
import { z } from 'zod';

export const Explanation = z.strictObject({
  verdict_echo: z.enum(['CLEAN', 'SUSPICIOUS', 'MALICIOUS']),
  headline: z.string().trim().min(1).max(120),
  paragraphs: z.array(z.string().max(600)).min(1).max(3),
  finding_notes: z.array(z.strictObject({ finding_id: z.string().max(64), text: z.string().max(200) })).max(20),
  next_step: z.string().max(200),
});

export const NEXT_STEP = Object.freeze({
  MALICIOUS: 'Do not run this on your machine.',
  SUSPICIOUS: 'Read the unexplained items before deciding.',
  CLEAN: "Consistent with the claim within this run's limits.",
});

/** One plain sentence per rule: what the finding means to someone who is not a security expert. */
export const RULE_NOTES = Object.freeze({
  'exfil.canary_outbound': 'A fake credential we planted was sent out of the sandbox. A real one would now be stolen.',
  'exfil.read_then_send': 'It read a fake credential file and then sent data out. We could not see the exact contents, but the order is what theft looks like.',
  'exfil.canary_stdout': 'A fake credential showed up in the program output. Anything that reads the output could capture it.',
  'decoy.credential_read': 'It opened a file that holds a credential.',
  'decoy.write': 'It opened, deleted, moved or changed a file that holds a credential or its settings.',
  'decoy.history_read': 'It read your shell history, which often contains past commands and secrets.',
  'decoy.meta_read': 'It read SSH settings or known hosts. Low risk by itself, but worth knowing.',
  'decoy.dir_enum': 'It looked through folders where credentials are kept.',
  'shim.credential_prompt': 'It called a tool that can show a password prompt or read the keychain. The sandbox only recorded the call; on a real Mac, anything you typed would go to the script.',
  'shim.persistence': 'It called a tool that manages scheduled tasks or services. The sandbox only recorded the call; such tools can make a command run again later.',
  'shim.privilege': 'It called a tool that runs commands as administrator. The sandbox only recorded the call and cannot see what would happen with those rights.',
  'shim.os_exec': 'It called a Windows tool that can run or download more code. The sandbox only recorded the call.',
  'shim.prefs': 'It called the tool that changes macOS preferences. The sandbox only recorded the call.',
  'shim.ai_cli': 'It called an AI assistant tool, which can read your settings and act on your behalf. The sandbox only recorded the call.',
  'shim.opener': 'It called the tool that opens files and links with your desktop applications. The sandbox only recorded the call.',
  'net.unexpected_upload': 'It sent data to a server the claim does not mention. In the sandbox the data went nowhere; on your machine it would not.',
  'net.unexpected_host': 'It contacted a server the claim does not mention.',
  'net.cloud_metadata': 'It tried to reach the cloud metadata service, the address a cloud server uses to hand out its own credentials. Nothing on a laptop needs that; on a cloud machine it would get real keys.',
  'net.ip_literal': 'It connected to a numeric address directly, skipping the usual name lookup.',
  'net.raw_socket': 'It opened a low-level network connection, not a normal web request.',
  'net.dns_only': 'It looked up a name the claim does not mention, but did not connect to it.',
  'net.tls_opaque': 'It made an encrypted connection the sandbox could not read; we know where, not what.',
  'proc.exec_written_file': 'It created a file and then ran it. Installers do this; so does malware.',
  'proc.interpreter_inline': 'It ran code passed directly on the command line, which is harder to inspect.',
  'proc.interpreter': 'It ran a script with an interpreter such as Python or Node.',
  'proc.net_tool': 'It used a low-level network tool that can send anything anywhere.',
  'proc.decode_helper': 'It ran a decoding tool. Code that unpacks its own contents deserves a closer look.',
  'fs.shell_startup_write': 'It wrote to a file that runs every time you open a terminal. That is one way a command keeps running after you forget it.',
  'fs.scheduler_write': 'It wrote to a place that runs programs automatically at startup or on a schedule.',
  'fs.agent_hook_write': 'It changed a settings file of a coding tool such as Claude Code, Cursor or VS Code. Such a file can tell the tool to run a command every time it opens, so the command keeps coming back.',
  'fs.system_write_attempt': 'It tried to change a system file. In the sandbox this failed only because the sandbox user is not an administrator; run with sudo on a real machine, it would work.',
  'fs.unexpected_write': 'It wrote files in a place the claim does not cover.',
  'ai.review': 'An AI read the code and raised a concern. This comes from reading the command, not from something observed in the sandbox.',
  'fs.existing_file_changed': 'It deleted, moved or changed files that were already on this computer before it ran. A command that only sets something up has no reason to touch files it did not create.',
  'unwrap.hidden_code': 'The command contains encoded layers that hide its real contents. The decoded layers are shown above.',
  'run.timeout': 'The command was still running at the time limit, so later behaviour was not seen.',
  'run.oom': 'The command used more memory than the sandbox allows and was stopped, so the rest of it did not run.',
  'run.no_activity': 'No file, network or program activity was seen. The command may only print text, or need a real terminal or an OS feature the sandbox lacks.',
});

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function cut(text, max) {
  const chars = [...text];
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : text;
}

function stripUrls(text) {
  return text.replace(/https?:\/\//gi, '');
}

function clean(text, max) {
  return cut(stripUrls(String(text ?? '')).replace(/\s+/g, ' ').trim(), max);
}

function quote(text) {
  return `"${text.replace(/"/g, "'")}"`;
}

/**
 * @param {object} input the object from buildExplanationInput
 * @returns {object} an 8.4 Explanation (validated by the same zod schema the LLM path uses)
 */
export function renderTemplateExplanation(input) {
  const level = ['CLEAN', 'SUSPICIOUS', 'MALICIOUS'].includes(input?.verdict?.level) ? input.verdict.level : 'SUSPICIOUS';
  const findings = (Array.isArray(input?.findings) ? input.findings : []).filter((f) => f && typeof f === 'object');
  const deciding = findings.filter((f) => (SEV_RANK[f.severity] ?? 0) >= SEV_RANK.medium);
  const claim = clean(input?.claim, 300);
  const summary = clean(input?.contract?.summary, 300);
  const notes = (Array.isArray(input?.coverage_notes) ? input.coverage_notes : []).map((n) => clean(n, 400)).filter(Boolean);

  let headline;
  if (level === 'MALICIOUS') {
    const critical = findings.find((f) => f.severity === 'critical') ?? findings[0];
    headline = critical ? clean(critical.title, 120) : 'The command did something no claim can justify';
  } else if (level === 'SUSPICIOUS') {
    const n = Math.max(deciding.length, 1);
    headline = `${n} thing${n === 1 ? '' : 's'} the claim does not explain`;
  } else {
    headline = 'Nothing beyond the claim was observed in this run';
  }

  // Paragraph 1: what was claimed and what that would normally involve.
  let p1 = claim ? `You were told this command ${quote(claim)}.` : 'No description of what the command does was given.';
  if (summary && summary.toLowerCase() !== claim.toLowerCase()) p1 += ` If that were all it did, we would expect: ${summary}.`;
  else if (!summary) p1 += ' We could not work out what a command like that should normally do, so everything it did is treated as unexplained.';

  // Paragraph 2: what was actually seen, top three findings by severity.
  const top = findings.slice().sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0)).slice(0, 3);
  let p2;
  if (top.length === 0) {
    p2 = 'In the sandbox nothing suspicious was seen: no credential files were touched, no unexpected servers were contacted, and nothing was set up to run later.';
  } else {
    const items = top.map((f, i) => {
      const title = clean(f.title, 150);
      const ev = clean(f.evidence_summary, 120);
      const tag = f.classification === 'explained' ? ' (covered by the claim)' : '';
      return `${i + 1}) ${title}${tag}${ev && ev.toLowerCase() !== title.toLowerCase() ? ` — ${ev}` : ''}`;
    });
    const rest = findings.length - top.length;
    const more = rest > 0 ? ` ${rest} more item${rest === 1 ? ' is' : 's are'} listed below.` : '';
    const lead = deciding.length > 3 ? `The claim does not account for ${deciding.length} things we saw. The most serious: ` : 'What we saw in the sandbox: ';
    p2 = `${lead}${items.join('; ')}.${more}`;
  }

  // Paragraph 3: the limits of this run, always.
  const p3 = notes.length > 0 ? `Keep in mind: ${notes.join(' ')}` : 'Keep in mind: this was one short run in a Linux sandbox with no internet; it shows what the command did here, not everything it could do.';

  const findingNotes = findings.slice(0, 20).map((f) => ({
    finding_id: cut(String(f.id ?? ''), 64),
    text: clean(`${RULE_NOTES[f.rule_id] ?? 'See the evidence for this item.'}${f.classification === 'explained' ? ' The claim covers this.' : ''}`, 200),
  }));

  const explanation = {
    verdict_echo: level,
    headline: clean(headline, 120) || 'Result',
    paragraphs: [cut(p1, 600), cut(p2, 600), cut(p3, 600)],
    finding_notes: findingNotes,
    next_step: NEXT_STEP[level],
  };
  return Explanation.parse(explanation);
}
