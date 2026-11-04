// Probe Vultr Serverless Inference: list the live models, then check what each one
// actually supports for agent work (plain chat, tool calling, a full tool round-trip,
// and JSON-schema structured output).
//
// Usage:
//   node --env-file=.env scripts/probe-vultr-inference.mjs              # every model
//   node --env-file=.env scripts/probe-vultr-inference.mjs glm-5.3 ...  # only these

const BASE_URL = process.env.VULTR_INFERENCE_BASE_URL ?? "https://api.vultrinference.com/v1";
const API_KEY = process.env.VULTR_INFERENCE_API_KEY;
const TIMEOUT_MS = 90_000;

if (!API_KEY) {
  console.error("VULTR_INFERENCE_API_KEY is not set. Put it in .env (see .env.example).");
  process.exit(1);
}

async function request(path, body) {
  const started = performance.now();
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: body ? "POST" : "GET",
      headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { ok: res.ok, status: res.status, json, text, ms: Math.round(performance.now() - started) };
  } catch (err) {
    return { ok: false, status: err.name, json: undefined, text: err.message, ms: Math.round(performance.now() - started) };
  }
}

const fail = (res) => `no (${res.status}: ${res.text.slice(0, 80).replace(/\s+/g, " ")})`;

const QUOTE_TOOL = {
  type: "function",
  function: {
    name: "get_quote",
    description: "Request a price quote from a supplier.",
    parameters: {
      type: "object",
      properties: {
        vendor: { type: "string", description: "Supplier name" },
        quantity: { type: "integer", description: "Number of units" },
      },
      required: ["vendor", "quantity"],
    },
  },
};

const QUOTE_SCHEMA = {
  type: "object",
  properties: {
    vendor: { type: "string" },
    unit_price_usd: { type: "number" },
    quantity: { type: "integer" },
    lead_time_days: { type: "integer" },
  },
  required: ["vendor", "unit_price_usd", "quantity", "lead_time_days"],
  additionalProperties: false,
};

async function probeChat(model) {
  const res = await request("/chat/completions", {
    model,
    messages: [{ role: "user", content: "Reply with exactly: OK" }],
    max_completion_tokens: 1024,
  });
  if (!res.ok || !res.json?.choices?.[0]?.message) return { result: fail(res), ms: res.ms };
  return { result: "yes", ms: res.ms };
}

// Returns the tool call (if any) so the round-trip probe can reuse it.
async function probeTools(model) {
  const messages = [{ role: "user", content: "Get a quote from vendor Acme for 40 laptops." }];
  const res = await request("/chat/completions", {
    model,
    messages,
    tools: [QUOTE_TOOL],
    tool_choice: "auto",
    max_completion_tokens: 1024,
  });
  if (!res.ok) return { result: fail(res) };
  const message = res.json?.choices?.[0]?.message;
  const call = message?.tool_calls?.[0];
  if (call?.function?.name !== "get_quote") return { result: "no (answered in text)" };
  try {
    const args = JSON.parse(call.function.arguments);
    if (!args.vendor || !args.quantity) return { result: "no (bad arguments)" };
  } catch {
    return { result: "no (arguments not JSON)" };
  }
  return { result: "yes", messages, message, call };
}

async function probeToolRoundTrip(model, { messages, message, call }) {
  const res = await request("/chat/completions", {
    model,
    messages: [
      ...messages,
      { role: "assistant", content: message.content ?? "", tool_calls: message.tool_calls },
      {
        role: "tool",
        tool_call_id: call.id,
        content: JSON.stringify({ vendor: "Acme", unit_price_usd: 1350, lead_time_days: 12 }),
      },
    ],
    tools: [QUOTE_TOOL],
    max_completion_tokens: 1024,
  });
  if (!res.ok) return fail(res);
  const content = res.json?.choices?.[0]?.message?.content ?? "";
  return /1,?350/.test(content) ? "yes" : "no (ignored tool result)";
}

async function probeJsonSchema(model) {
  const res = await request("/chat/completions", {
    model,
    messages: [
      {
        role: "user",
        content: "Extract the quote: Acme offers 40 laptops at $1,350 each, delivered in 12 days.",
      },
    ],
    response_format: { type: "json_schema", json_schema: { name: "quote", strict: true, schema: QUOTE_SCHEMA } },
    max_completion_tokens: 1024,
  });
  if (!res.ok) return fail(res);
  try {
    const parsed = JSON.parse(res.json?.choices?.[0]?.message?.content ?? "");
    return parsed.unit_price_usd === 1350 && parsed.quantity === 40 ? "yes" : "no (wrong values)";
  } catch {
    return "no (not valid JSON)";
  }
}

// Section 8 "CODER" criterion: can the model write a harness that only prints, as plain JSON?
async function probeHarnessSmoke(model) {
  const marker = "FIRSTRUN_PROBE_OK";
  const res = await request("/chat/completions", {
    model,
    messages: [
      { role: "system", content: "Reply with JSON only, no prose and no code fences." },
      {
        role: "user",
        content: `Return {"language":"bash","harness":"<script>"} where the script prints exactly ${marker} to stdout and does nothing else.`,
      },
    ],
    max_completion_tokens: 1024,
  });
  if (!res.ok) return fail(res);
  const content = (res.json?.choices?.[0]?.message?.content ?? "").replace(/^```(?:json)?\s*|\s*```$/g, "");
  try {
    const harness = JSON.parse(content).harness ?? "";
    if (!harness.includes(marker)) return "no (marker missing)";
    return /\b(curl|wget)\b/.test(harness) ? "no (uses network tools)" : "yes";
  } catch {
    return "no (not valid JSON)";
  }
}

// Section 8: reasoning models should accept reasoning: {enabled: false} so tokens go to the answer.
async function probeReasoningOff(model) {
  const res = await request("/chat/completions", {
    model,
    messages: [{ role: "user", content: "Reply with exactly: OK" }],
    reasoning: { enabled: false },
    max_completion_tokens: 256,
  });
  return res.ok ? "yes" : fail(res);
}

const listed = await request("/models");
if (!listed.ok) {
  console.error(`GET /models failed: ${listed.status} ${listed.text.slice(0, 200)}`);
  process.exit(1);
}

const allModels = listed.json?.data ?? [];
console.log(`\n${allModels.length} models listed by ${BASE_URL}/models:`);
for (const { id, ...meta } of allModels) {
  console.log(`  - ${id}  ${JSON.stringify(meta).slice(0, 160)}`);
}

const wanted = process.argv.slice(2);
const targets = wanted.length ? wanted : allModels.map((m) => m.id);
const rows = [];

for (const model of targets) {
  process.stdout.write(`\nProbing ${model} ... `);
  const chat = await probeChat(model);
  const row = {
    model,
    chat: chat.result,
    latency_ms: chat.ms,
    tools: "-",
    tool_round_trip: "-",
    json_schema: "-",
    harness_smoke: "-",
    reasoning_off: "-",
  };
  if (chat.result === "yes") {
    const tools = await probeTools(model);
    row.tools = tools.result;
    if (tools.result === "yes") row.tool_round_trip = await probeToolRoundTrip(model, tools);
    row.json_schema = await probeJsonSchema(model);
    row.harness_smoke = await probeHarnessSmoke(model);
    row.reasoning_off = await probeReasoningOff(model);
  }
  rows.push(row);
  process.stdout.write("done");
}

console.log("\n");
console.table(rows);

// Candidates for server/llm/config.json (docs/ARCHITECTURE.md section 8). Tool calling is not required.
const fast = rows.filter((r) => r.chat === "yes" && r.latency_ms < 3000 && r.json_schema === "yes").map((r) => r.model);
const coder = rows.filter((r) => r.harness_smoke === "yes" && r.reasoning_off === "yes").map((r) => r.model);
console.log(`FAST candidates (contract, explanation): ${fast.join(", ") || "none: use json_object mode + zod"}`);
console.log(`CODER candidates (harness loop): ${coder.join(", ") || "none passed both checks"}`);
