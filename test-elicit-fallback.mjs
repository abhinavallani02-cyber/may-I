// Fake MCP client for the elicitation auto-decline heuristic.
// Drives mayi in-process (JSON-RPC initialize + tools/call, then the
// elicitation/create reply) and stubs askHuman, so nothing here opens
// /dev/tty. This environment has that device node and no terminal
// attached to it.
//
// Covers: a fast decline falling back to the stub, a decline at/over
// the threshold honored as a user deny, accept left unchanged, and
// threshold 0 disabling the fallback.

import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { configureForTest, handleClientLine } from "./mayi.mjs";

const AUTO_LOG = "[ASK] elicitation auto-declined by client (likely unsupported), falling back to terminal prompt";

const dir = mkdtempSync(join(tmpdir(), "mayi-elicit-"));
let failures = 0;
let caseName = "";

function fail(message) {
  failures += 1;
  console.error(`FAIL ${caseName}: ${message}`);
}

function assert(cond, message) {
  if (!cond) fail(message);
}

function clientMessages(chunks) {
  return chunks
    .join("")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

// One tools/call that policy says "ask", against a client that declared
// form elicitation. `elapsedMs` is how far the fake monotonic clock
// moves between the elicitation/create write and the reply. Pass
// useRealClock to measure with performance.now() instead.
async function drive(opts) {
  const childLines = [];
  const clientChunks = [];
  const logs = [];
  const askCalls = [];
  const auditFile = join(dir, `${caseName.replace(/[^a-z0-9]+/gi, "-")}.jsonl`);
  let t = 10_000;

  configureForTest({
    rules: [
      { tool: "write_*", action: "ask" },
      { tool: "*", action: "deny" },
    ],
    auditFile,
    autoDeclineMs: opts.threshold,
    childStdin: { write: (line) => childLines.push(String(line)) },
    now: opts.useRealClock ? null : () => t,
    askHuman(id, name, args) {
      askCalls.push({ id, name, args });
      if (opts.askThrows) throw opts.askThrows;
      return opts.askResult;
    },
  });

  const origWrite = process.stdout.write.bind(process.stdout);
  const origErr = console.error;
  process.stdout.write = (chunk, enc, cb) => {
    clientChunks.push(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk));
    const done = typeof enc === "function" ? enc : cb;
    if (typeof done === "function") done();
    return true;
  };
  console.error = (...args) => {
    logs.push(args.map((part) => String(part)).join(" "));
  };

  try {
    await handleClientLine(JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: { elicitation: { form: {} } },
        clientInfo: { name: "fake-client", version: "0" },
      },
    }));

    const callLine = JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "write_file", arguments: { path: "notes.txt", content: "hi" } },
    });
    const callPromise = handleClientLine(callLine);

    const elicit = clientMessages(clientChunks).find((msg) => msg.method === "elicitation/create");
    if (!elicit) throw new Error("client never received elicitation/create");

    if (!opts.useRealClock && opts.elapsedMs !== undefined) t = 10_000 + opts.elapsedMs;

    const response = opts.elicitError
      ? { jsonrpc: "2.0", id: elicit.id, error: { code: -32000, message: "nope" } }
      : { jsonrpc: "2.0", id: elicit.id, result: opts.result };
    await handleClientLine(JSON.stringify(response));
    await callPromise;

    const audit = readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    const forwarded = childLines.filter((line) => line.includes('"tools/call"'));
    return { askCalls, logs, audit, forwarded, client: clientMessages(clientChunks), elicit };
  } finally {
    process.stdout.write = origWrite;
    console.error = origErr;
  }
}

async function check(name, opts, expect) {
  caseName = name;
  const before = failures;
  let result;
  try {
    result = await drive(opts);
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
    return;
  }

  const verdict = result.audit.length === 1 ? result.audit[0].verdict : JSON.stringify(result.audit.map((entry) => entry.verdict));
  assert(result.audit.length === 1 && result.audit[0].verdict === expect.verdict, `verdict ${verdict}, expected ${expect.verdict}`);
  assert(result.audit.length === 1 && result.audit[0].tool === "write_file" && result.audit[0].id === 7, "audit entry should be the tools/call id and tool");

  const fellBack = result.logs.some((line) => line === AUTO_LOG);
  assert(fellBack === expect.fallback, `auto-decline log ${fellBack ? "present" : "absent"}`);

  assert(result.askCalls.length === (expect.asked ? 1 : 0), `askHuman called ${result.askCalls.length} time(s)`);
  if (expect.asked && result.askCalls.length === 1) {
    assert(result.askCalls[0].id === 7, `askHuman id ${result.askCalls[0].id}, expected the tools/call id 7`);
    assert(result.askCalls[0].name === "write_file", "askHuman should see the tool name");
  }

  assert(result.forwarded.length === (expect.forwarded ? 1 : 0), `forwarded ${result.forwarded.length} tools/call line(s)`);
  const blocked = result.client.some((msg) => msg.id === 7 && msg.error);
  assert(blocked === !expect.forwarded, expect.forwarded ? "allow path wrote an error" : "deny path did not write an error");
  assert(!result.client.some((msg) => msg.id === 7 && msg.result), "tools/call result must come from the server, not may-i");

  if (failures === before) console.log(`ok ${name}`);
}

const decline = { action: "decline" };
const cancel = { action: "cancel" };
const accept = { action: "accept", content: { approve: "approve" } };
const acceptDeny = { action: "accept", content: { approve: "deny" } };

await check(
  "fast decline falls back and uses askHuman approval",
  { threshold: 250, useRealClock: true, result: decline, askResult: "approved" },
  { verdict: "ask→approved(tty-fallback)", fallback: true, asked: true, forwarded: true },
);

await check(
  "fast decline falls back and uses askHuman denial",
  { threshold: 250, elapsedMs: 0, result: decline, askResult: "denied" },
  { verdict: "ask→denied(tty-fallback)", fallback: true, asked: true, forwarded: false },
);

await check(
  "fast decline askHuman throw fails closed",
  { threshold: 250, elapsedMs: 1, result: decline, askThrows: new Error("no tty") },
  { verdict: "ask→denied(tty-fallback)", fallback: true, asked: true, forwarded: false },
);

await check(
  "fast cancel falls back the same way",
  { threshold: 250, elapsedMs: 0, result: cancel, askResult: "approved" },
  { verdict: "ask→approved(tty-fallback)", fallback: true, asked: true, forwarded: true },
);

await check(
  "decline at the threshold is a user deny",
  { threshold: 250, elapsedMs: 250, result: decline, askResult: "approved" },
  { verdict: "ask→denied", fallback: false, asked: false, forwarded: false },
);

await check(
  "slow decline is a user deny",
  { threshold: 250, elapsedMs: 5000, result: decline, askResult: "approved" },
  { verdict: "ask→denied", fallback: false, asked: false, forwarded: false },
);

await check(
  "slow cancel stays cancelled",
  { threshold: 250, elapsedMs: 250, result: cancel, askResult: "approved" },
  { verdict: "ask→cancelled", fallback: false, asked: false, forwarded: false },
);

await check(
  "accept is unchanged even when instant",
  { threshold: 250, elapsedMs: 0, result: accept, askResult: "denied" },
  { verdict: "ask→approved", fallback: false, asked: false, forwarded: true },
);

await check(
  "accept with a deny answer stays denied",
  { threshold: 250, elapsedMs: 0, result: acceptDeny, askResult: "approved" },
  { verdict: "ask→denied", fallback: false, asked: false, forwarded: false },
);

await check(
  "threshold 0 does not fall back on a fast decline",
  { threshold: 0, elapsedMs: 0, result: decline, askResult: "approved" },
  { verdict: "ask→denied", fallback: false, asked: false, forwarded: false },
);

await check(
  "elicitation error stays denied without fallback",
  { threshold: 250, elapsedMs: 0, elicitError: true, askResult: "approved" },
  { verdict: "ask→denied", fallback: false, asked: false, forwarded: false },
);

function runMayi(args, { timeout } = {}) {
  return spawnSync(process.execPath, [resolve("mayi.mjs"), ...args], {
    encoding: "utf8",
    timeout,
    cwd: process.cwd(),
  });
}

caseName = "help lists the flag";
{
  const help = runMayi(["--help"]);
  assert(help.status === 0, `help exited ${help.status}: ${help.stderr}`);
  assert(help.stdout.includes("--elicit-autodecline-ms"), "help text missing --elicit-autodecline-ms");
  assert(help.stdout.includes("250"), "help text should mention the 250 default");
  if (help.status === 0 && help.stdout.includes("--elicit-autodecline-ms")) console.log("ok help lists the flag");
}

caseName = "symlink entry point still starts";
{
  const link = join(dir, "mayi-link.mjs");
  symlinkSync(resolve("mayi.mjs"), link);
  const help = spawnSync(process.execPath, [link, "--help"], { encoding: "utf8" });
  assert(help.status === 0, `symlink help exited ${help.status}: ${help.stderr}`);
  assert((help.stdout || "").includes("--elicit-autodecline-ms"), "symlink entry did not run may-i");
  if (help.status === 0) console.log("ok symlink entry point still starts");
}

caseName = "flag rejects values that are not non-negative integers";
for (const bad of ["-1", "1.5", "foo", "+10", "", "250ms"]) {
  const result = runMayi(["--elicit-autodecline-ms", bad, "--", process.execPath, "-e", "process.exit(0)"]);
  const stderr = result.stderr || "";
  assert(result.status === 1, `value ${JSON.stringify(bad)} exited ${result.status}, stderr=${stderr}`);
  assert(stderr.includes("requires a non-negative integer"), `value ${JSON.stringify(bad)} missing validation message`);
}
{
  const missing = runMayi(["--elicit-autodecline-ms", "--", process.execPath, "-e", "process.exit(0)"]);
  assert(missing.status === 1, `missing value exited ${missing.status}`);
  assert((missing.stderr || "").includes("requires a non-negative integer"), "missing value was not rejected");
  console.log("ok flag rejects values that are not non-negative integers");
}

caseName = "flag accepts 0 and other non-negative integers";
function configLine(ms) {
  const args = ["--elicit-autodecline-ms", String(ms), "--", process.execPath, "-e", "setInterval(() => {}, 1000000)"];
  const result = runMayi(args, { timeout: 1500 });
  return result.stderr || "";
}
{
  const off = configLine(0);
  const custom = configLine(1000);
  const omitted = runMayi(["--", process.execPath, "-e", "setInterval(() => {}, 1000000)"], { timeout: 1500 });
  assert(off.includes("[CONFIG] elicit auto-decline: off"), `0 not logged as off:\n${off}`);
  assert(!off.includes("requires a non-negative integer"), "0 was rejected");
  assert(custom.includes("[CONFIG] elicit auto-decline: 1000ms"), `1000 not logged:\n${custom}`);
  assert((omitted.stderr || "").includes("[CONFIG] elicit auto-decline: 250ms"), `default not 250:\n${omitted.stderr}`);
  if (off.includes("off") && custom.includes("1000ms")) console.log("ok flag accepts 0 and other non-negative integers");
}

rmSync(dir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall elicitation fallback checks passed");
