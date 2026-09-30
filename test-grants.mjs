// Session grants: an ask approval can be remembered for this process.
// Drives mayi in-process, same as test-elicit-fallback.mjs, so nothing
// here opens /dev/tty. The tty `a` path goes through promptOnce's test
// hook, which runs the same classifier as the real readline prompt.
// The clock is injectable; expiry tests never sleep.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import { classifyTtyAnswer, configureForTest, formatTtyPrompt, handleClientLine } from "./mayi.mjs";

const dir = mkdtempSync(join(tmpdir(), "mayi-grants-"));
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

function unexpectedTty() {
  throw new Error("unexpected tty prompt");
}

class Harness {
  constructor() {
    this.childLines = [];
    this.clientChunks = [];
    this.logs = [];
    this.t = 1_000_000;
    this.ttyReads = 0;
    this.restore = null;
    this.auditFile = "";
    this.ttyAnswer = null;
    this.askHuman = unexpectedTty;
    this.grantTtl = 1800;
    this.threshold = 250;
  }

  patch() {
    const origWrite = process.stdout.write.bind(process.stdout);
    const origErr = console.error;
    process.stdout.write = (chunk, enc, cb) => {
      this.clientChunks.push(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk));
      const done = typeof enc === "function" ? enc : cb;
      if (typeof done === "function") done();
      return true;
    };
    console.error = (...args) => {
      this.logs.push(args.map((part) => String(part)).join(" "));
    };
    this.restore = () => {
      process.stdout.write = origWrite;
      console.error = origErr;
    };
  }

  configure(rules, { resetGrants }) {
    configureForTest({
      rules,
      auditFile: this.auditFile,
      autoDeclineMs: this.threshold,
      grantTtlSeconds: this.grantTtl,
      childStdin: { write: (line) => this.childLines.push(String(line)) },
      now: () => this.t,
      askHuman: this.askHuman,
      ttyAnswer: this.ttyAnswer,
      resetGrants,
    });
  }

  async start({ rules, grantTtl = 1800, threshold = 250, elicitation = true, ttyAnswer = null, askHuman = unexpectedTty }) {
    this.auditFile = join(dir, `${caseName.replace(/[^a-z0-9]+/gi, "-")}.jsonl`);
    this.grantTtl = grantTtl;
    this.threshold = threshold;
    this.ttyAnswer = ttyAnswer;
    this.askHuman = askHuman;
    this.configure(rules, { resetGrants: true });
    this.patch();
    await this.initialize(elicitation);
  }

  // Recompile the policy without dropping remembered grants, as a
  // stand-in for a policy change in the same process. Elicitation
  // support is re-declared when the next call still needs to ask.
  async reload({ rules, elicitation = false, grantTtl = this.grantTtl }) {
    this.grantTtl = grantTtl;
    this.configure(rules, { resetGrants: false });
    if (elicitation) await this.initialize(true);
  }

  async initialize(elicitation) {
    await handleClientLine(JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: elicitation ? { elicitation: { form: {} } } : {},
        clientInfo: { name: "fake-client", version: "0" },
      },
    }));
  }

  elicitations() {
    return clientMessages(this.clientChunks).filter((msg) => msg.method === "elicitation/create");
  }

  audit() {
    const raw = readFileSync(this.auditFile, "utf8").trim();
    if (!raw) return [];
    return raw.split("\n").filter(Boolean).map((line) => JSON.parse(line));
  }

  grantLogs() {
    return this.logs.filter((line) => line.startsWith("[GRANT]"));
  }

  forwarded(id) {
    return this.childLines.filter((line) => {
      try {
        const msg = JSON.parse(line);
        return msg.method === "tools/call" && msg.id === id;
      } catch {
        return false;
      }
    });
  }

  blocked(id) {
    return clientMessages(this.clientChunks).some((msg) => msg.id === id && msg.error);
  }

  // One tools/call. `reply` is the elicitation result, sent only when
  // this call actually prompted. `advanceMs` moves the fake clock
  // before that reply (0 is a real elapsed time, not "leave it").
  async call({ id, name, args, reply = null, advanceMs }) {
    const before = this.elicitationCount;
    const beforeReads = this.ttyReads;
    const promise = handleClientLine(JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name, arguments: args },
    }));
    const created = this.elicitations().slice(before);
    if (created.length > 1) throw new Error(`call ${id} produced ${created.length} elicitations`);
    if (created.length === 1 && !reply) throw new Error(`call ${id} elicited with no reply`);
    if (created.length === 0 && reply) throw new Error(`call ${id} got a reply but did not elicit`);
    if (created.length === 1) {
      if (advanceMs !== undefined) this.t += advanceMs;
      await handleClientLine(JSON.stringify({ jsonrpc: "2.0", id: created[0].id, result: reply }));
    }
    await promise;
    return {
      elicited: created.length === 1,
      schema: created[0]?.params?.requestedSchema ?? null,
      message: created[0]?.params?.message ?? null,
      ttyReads: this.ttyReads - beforeReads,
    };
  }

  get elicitationCount() {
    return this.elicitations().length;
  }
}

function countingTty(answer) {
  return (h) => (id, name, args) => {
    h.ttyReads += 1;
    assert(id !== undefined && name && args, "tty prompt should see the call");
    return answer;
  };
}

function expectVerdict(h, { id, tool, verdict, forwarded }) {
  const entry = h.audit().find((row) => row.id === id);
  assert(entry && entry.verdict === verdict && entry.tool === tool, `id ${id} verdict ${entry ? entry.verdict : "missing"}, expected ${verdict}`);
  assert(h.forwarded(id).length === (forwarded ? 1 : 0), `id ${id} forwarded ${h.forwarded(id).length}, expected ${forwarded ? 1 : 0}`);
  assert(h.blocked(id) === !forwarded, `id ${id} blocked=${h.blocked(id)}`);
}

// The same file --rules filesystem loads, prepended the way main()
// prepends a pack before --policy. notes is not in that pack, so it
// falls through to the policy rule, but the compiled index changes.
const filesystemPack = parseYaml(
  readFileSync(new URL("./rules/filesystem.yaml", import.meta.url), "utf8"),
).rules;
const notesAsk = { tool: "notes", action: "ask" };

const sessionReply = { action: "accept", content: { approve: "approve", scope: "session" } };
const onceReply = { action: "accept", content: { approve: "approve", scope: "once" } };
const bareApprove = { action: "accept", content: { approve: "approve" } };
const denyReply = { action: "accept", content: { approve: "deny", scope: "session" } };
const decline = { action: "decline" };

async function check(name, fn) {
  caseName = name;
  const before = failures;
  const h = new Harness();
  try {
    await fn(h);
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  } finally {
    if (h.restore) h.restore();
  }
  if (failures === before) console.log(`ok ${name}`);
}

await check("elicitation session scope remembers the tool and rule, not the arguments", async (h) => {
  await h.start({
    rules: [
      { tool: "write_file", path_prefix: "sandbox/", action: "ask" },
      { tool: "*", action: "deny" },
    ],
  });
  const first = await h.call({
    id: 7,
    name: "write_file",
    args: { path: "sandbox/a.txt", content: "one" },
    reply: sessionReply,
  });
  assert(first.elicited, "first call should elicit");
  assert(first.schema.properties.scope.enum.join(",") === "once,session", "scope enum");
  assert(first.schema.properties.scope.default === "once", "scope defaults to once");
  assert(first.schema.required.includes("approve") && first.schema.required.includes("scope"), "both questions are required");
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 1, `GRANT lines: ${JSON.stringify(h.grantLogs())}`);
  assert(
    h.grantLogs()[0] === "[GRANT] tool=write_file rule=write_file (path_prefix: sandbox/) ttl=1800s",
    `GRANT line ${h.grantLogs()[0]}`,
  );

  const second = await h.call({
    id: 8,
    name: "write_file",
    args: { path: "sandbox/b.txt", content: "different body" },
  });
  assert(!second.elicited, "same rule should not ask again");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });
  assert(h.grantLogs().length === 1, "a hit must not log another GRANT");
  assert(!h.audit().some((row) => row.id === 8 && row.verdict === "allow"), "granted must not collapse into allow");
});

await check("tty a remembers, tty y does not", async (h) => {
  const tty = countingTty("a");
  await h.start({
    rules: [
      { tool: "write_*", action: "ask" },
      { tool: "*", action: "deny" },
    ],
    elicitation: false,
    askHuman: null,
    ttyAnswer: tty(h),
  });
  assert(
    formatTtyPrompt(9, "write_file", { path: "notes.txt" }).endsWith("Approve? (y/n/a, a = approve and remember for this session): "),
    "prompt should offer a",
  );
  assert(classifyTtyAnswer("a") === "approved-remember", "a remembers");
  assert(classifyTtyAnswer(" A ") === "approved-remember", "a is case-insensitive");
  assert(classifyTtyAnswer("y") === "approved", "y is once");
  assert(classifyTtyAnswer("n") === "denied", "n denies");
  assert(classifyTtyAnswer("yes") === "denied", "only the single letter y approves");

  await h.call({ id: 9, name: "write_file", args: { path: "notes.txt", content: "hi" } });
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.ttyReads === 1, `tty reads ${h.ttyReads}`);
  assert(h.grantLogs()[0] === "[GRANT] tool=write_file rule=write_* ttl=1800s", `GRANT line ${h.grantLogs()[0]}`);

  await h.call({ id: 10, name: "write_file", args: { path: "other.txt", content: "there" } });
  expectVerdict(h, { id: 10, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });
  assert(h.ttyReads === 1, "granted call must not read the tty");

  // A fresh session: y approves once and the next call still asks.
  h.restore();
  h.clientChunks = [];
  h.logs = [];
  h.childLines = [];
  h.ttyReads = 0;
  const once = countingTty("y");
  h.ttyAnswer = once(h);
  h.configure([
    { tool: "write_*", action: "ask" },
    { tool: "*", action: "deny" },
  ], { resetGrants: true });
  h.patch();
  await h.initialize(false);
  await h.call({ id: 11, name: "write_file", args: { path: "notes.txt" } });
  expectVerdict(h, { id: 11, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 0, "y must not create a grant");
  const again = await h.call({ id: 12, name: "write_file", args: { path: "notes.txt" } });
  assert(again.ttyReads === 1, "once-scope tty approval should ask the next time");
  expectVerdict(h, { id: 12, tool: "write_file", verdict: "ask→approved", forwarded: true });
});

await check("fast auto-decline does not grant; tty a after it does", async (h) => {
  const tty = countingTty("y");
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
    askHuman: null,
    ttyAnswer: tty(h),
  });
  await h.call({
    id: 7,
    name: "write_file",
    args: { path: "a.txt" },
    reply: { action: "decline", content: { approve: "approve", scope: "session" } },
    advanceMs: 0,
  });
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→approved(tty-fallback)", forwarded: true });
  assert(h.grantLogs().length === 0, "fallback y must not remember, and the decline must not either");
  const second = await h.call({ id: 8, name: "write_file", args: { path: "b.txt" }, reply: decline, advanceMs: 0 });
  assert(second.elicited, "no grant, so the next call asks");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→approved(tty-fallback)", forwarded: true });

  h.restore();
  h.clientChunks = [];
  h.logs = [];
  h.childLines = [];
  h.ttyReads = 0;
  const remember = countingTty("a");
  h.ttyAnswer = remember(h);
  h.configure([{ tool: "write_file", action: "ask" }], { resetGrants: true });
  h.patch();
  await h.initialize(true);
  await h.call({ id: 9, name: "write_file", args: { path: "a.txt" }, reply: decline, advanceMs: 0 });
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→approved(tty-fallback)", forwarded: true });
  assert(h.grantLogs().length === 1, "explicit a on the fallback creates the grant");
  const granted = await h.call({ id: 10, name: "write_file", args: { path: "b.txt" } });
  assert(!granted.elicited, "session grant should cover the next call");
  expectVerdict(h, { id: 10, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });
});

await check("a different rule for the same tool still asks", async (h) => {
  await h.start({
    rules: [
      { tool: "write_file", path_prefix: "sandbox/", action: "ask" },
      { tool: "write_file", path_prefix: "/tmp/", action: "ask" },
      { tool: "*", action: "deny" },
    ],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "sandbox/a.txt" }, reply: sessionReply });
  const otherRule = await h.call({ id: 8, name: "write_file", args: { path: "/tmp/a.txt" }, reply: denyReply });
  assert(otherRule.elicited, "a different path_prefix is a different rule");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→denied", forwarded: false });
  const sameRule = await h.call({ id: 9, name: "write_file", args: { path: "sandbox/c.txt", content: "more" } });
  assert(!sameRule.elicited, "the original rule should still be granted");
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });
});

await check("a different tool under the same glob still asks", async (h) => {
  await h.start({
    rules: [
      { tool: "write_*", action: "ask" },
      { tool: "*", action: "deny" },
    ],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: sessionReply });
  const other = await h.call({ id: 8, name: "write_notes", args: { path: "a.txt" }, reply: onceReply });
  assert(other.elicited, "tool name is part of the grant key");
  expectVerdict(h, { id: 8, tool: "write_notes", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 1, "once scope on the other tool must not add a grant");
});

await check("a deny rule is never granted, including after the policy changes", async (h) => {
  await h.start({
    rules: [
      { tool: "write_file", path_prefix: "/etc/", action: "deny" },
      { tool: "write_file", path_prefix: "sandbox/", action: "ask" },
      { tool: "*", action: "deny" },
    ],
  });
  const denied = await h.call({ id: 7, name: "write_file", args: { path: "/etc/passwd", content: "x" } });
  assert(!denied.elicited, "deny must not ask");
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "deny", forwarded: false });
  assert(h.grantLogs().length === 0, "deny must not create a grant");

  await h.call({ id: 8, name: "write_file", args: { path: "sandbox/a.txt" }, reply: sessionReply });
  const stillDenied = await h.call({ id: 9, name: "write_file", args: { path: "/etc/hosts" } });
  assert(!stillDenied.elicited, "an ask-rule grant must not cover a deny rule");
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "deny", forwarded: false });

  await h.reload({
    rules: [
      { tool: "write_file", path_prefix: "sandbox/", action: "deny" },
      { tool: "*", action: "deny" },
    ],
  });
  const after = await h.call({ id: 10, name: "write_file", args: { path: "sandbox/a.txt" } });
  assert(!after.elicited, "the rule that matches now is deny, so no prompt and no grant");
  expectVerdict(h, { id: 10, tool: "write_file", verdict: "deny", forwarded: false });
  assert(h.grantLogs().length === 1, "the old grant stays in memory but must not be applied");
});

await check("a changed rule identity does not keep the grant", async (h) => {
  await h.start({
    rules: [
      { tool: "write_file", path_prefix: "sandbox/", action: "ask" },
    ],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "sandbox/a.txt" }, reply: sessionReply });

  // Same text, new index, because a rule was inserted in front.
  await h.reload({
    rules: [
      { tool: "read_*", action: "allow" },
      { tool: "write_file", path_prefix: "sandbox/", action: "ask" },
    ],
    elicitation: true,
  });
  const reindexed = await h.call({ id: 8, name: "write_file", args: { path: "sandbox/a.txt" }, reply: sessionReply });
  assert(reindexed.elicited, "index is part of the rule identity");

  // Same index, edited prefix. "sandbox" still matches sandbox/a.txt,
  // but it is not the rule that was approved.
  await h.reload({
    rules: [
      { tool: "read_*", action: "allow" },
      { tool: "write_file", path_prefix: "sandbox", action: "ask" },
    ],
    elicitation: true,
  });
  const edited = await h.call({ id: 9, name: "write_file", args: { path: "sandbox/a.txt" }, reply: onceReply });
  assert(edited.elicited, "edited rule content must not inherit the grant");
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→approved", forwarded: true });
});

await check("ttl expiry is lazy and deletes the grant", async (h) => {
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
    grantTtl: 30,
  });
  h.t = 5_000_000;
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: sessionReply });
  assert(h.grantLogs()[0] === "[GRANT] tool=write_file rule=write_file ttl=30s", `GRANT line ${h.grantLogs()[0]}`);

  h.t = 5_000_000 + 30_000 - 1;
  const still = await h.call({ id: 8, name: "write_file", args: { path: "b.txt" } });
  assert(!still.elicited, "1ms before expiry the grant applies");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });

  h.t = 5_000_000 + 30_000;
  const expired = await h.call({ id: 9, name: "write_file", args: { path: "c.txt" }, reply: denyReply });
  assert(expired.elicited, "at the expiry instant the next check must ask");
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→denied", forwarded: false });

  // If the expired entry had only been ignored, rewinding the clock
  // would make it apply again. Deletion means it stays gone.
  h.t = 5_000_000;
  const gone = await h.call({ id: 10, name: "write_file", args: { path: "d.txt" }, reply: onceReply });
  assert(gone.elicited, "lazy removal should drop the grant, not hide it");
  expectVerdict(h, { id: 10, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 1, "the once answer after expiry must not create a grant");
});

await check("grant-ttl 0 disables grants", async (h) => {
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
    grantTtl: 0,
  });
  const first = await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: sessionReply });
  assert(first.elicited, "ttl 0 still asks");
  assert(first.schema.properties.scope === undefined, "scope is not offered when grants are off");
  assert(!first.schema.required.includes("scope"), "scope is not required when grants are off");
  assert(!first.message.includes("remember"), "message should not offer remember");
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 0, "a session scope is ignored when grants are off");
  const second = await h.call({ id: 8, name: "write_file", args: { path: "a.txt" }, reply: bareApprove });
  assert(second.elicited, "the next call still asks");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→approved", forwarded: true });

  assert(classifyTtyAnswer("a") === "denied", "a is not an approval when grants are off");
  assert(classifyTtyAnswer("y") === "approved", "y still approves once");
  assert(
    formatTtyPrompt(1, "write_file", { path: "a.txt" }) === '[ASK] id=1 tool=write_file args={"path":"a.txt"}. Approve? (y/n): ',
    "tty prompt stays y/n",
  );
});

await check("tty a is a deny when grants are disabled", async (h) => {
  const tty = countingTty("a");
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
    grantTtl: 0,
    elicitation: false,
    askHuman: null,
    ttyAnswer: tty(h),
  });
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" } });
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→denied", forwarded: false });
  assert(h.grantLogs().length === 0, "disabled grants must ignore a");
  assert(h.ttyReads === 1, "the call should still have asked");
});

await check("once scope and a missing scope create no grant", async (h) => {
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: onceReply });
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 0, "once must not log GRANT");
  const again = await h.call({ id: 8, name: "write_file", args: { path: "a.txt" }, reply: bareApprove });
  assert(again.elicited, "missing scope is once, not session");
  expectVerdict(h, { id: 8, tool: "write_file", verdict: "ask→approved", forwarded: true });
  const third = await h.call({
    id: 9,
    name: "write_file",
    args: { path: "a.txt" },
    reply: { action: "accept", content: { approve: "approve", scope: "Session" } },
  });
  assert(third.elicited, "only the exact string session remembers");
  assert(h.grantLogs().length === 0, "Session is not session");
  expectVerdict(h, { id: 9, tool: "write_file", verdict: "ask→approved", forwarded: true });
});

await check("an allow rule stays allow", async (h) => {
  await h.start({
    rules: [
      { tool: "read_*", action: "allow" },
      { tool: "write_file", action: "ask" },
    ],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: sessionReply });
  const read = await h.call({ id: 8, name: "read_file", args: { path: "a.txt" } });
  assert(!read.elicited, "allow does not ask");
  expectVerdict(h, { id: 8, tool: "read_file", verdict: "allow", forwarded: true });
});

await check("a session grant does not cover a structurally blocked allow", async (h) => {
  await h.start({
    rules: [
      { tool: "query", sql: { single: "select" }, action: "allow" },
      { tool: "query", action: "ask" },
      { tool: "write_file", path_prefix: "/tmp", action: "allow" },
      { tool: "write_file", action: "ask" },
    ],
  });

  // A single INSERT misses the select allow and does not block later
  // rules, so the ask rule can be remembered.
  await h.call({ id: 7, name: "query", args: { sql: "INSERT INTO t VALUES (1)" }, reply: sessionReply });
  expectVerdict(h, { id: 7, tool: "query", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 1, "the ask rule was remembered");

  const compound = await h.call({
    id: 8,
    name: "query",
    args: { sql: "SELECT 1; DROP TABLE users" },
    reply: denyReply,
  });
  assert(compound.elicited, "a grant must not cover a call whose allow was structurally blocked");
  expectVerdict(h, { id: 8, tool: "query", verdict: "ask→denied(blocked-allow)", forwarded: false });

  // Approving that blocked call, even with session scope, must not
  // store a grant. The next compound statement still asks.
  const approved = await h.call({ id: 9, name: "query", args: { sql: "SELECT '" }, reply: sessionReply });
  assert(approved.elicited, "unparseable SQL still asks");
  expectVerdict(h, { id: 9, tool: "query", verdict: "ask→approved(blocked-allow)", forwarded: true });
  const again = await h.call({
    id: 10,
    name: "query",
    args: { sql: "SELECT 1; DELETE FROM t" },
    reply: denyReply,
  });
  assert(again.elicited, "approving a blocked call must not create a grant");
  expectVerdict(h, { id: 10, tool: "query", verdict: "ask→denied(blocked-allow)", forwarded: false });
  assert(h.grantLogs().length === 1, "blocked approvals must not log [GRANT]");

  // The original grant still covers an ask that did not block an allow.
  const plain = await h.call({ id: 11, name: "query", args: { sql: "INSERT INTO t VALUES (2)" } });
  assert(!plain.elicited, "the ask-rule grant still applies when nothing was blocked");
  expectVerdict(h, { id: 11, tool: "query", verdict: "ask→granted(session)", forwarded: true });

  // Same shape for a path that cannot be resolved: the allow is
  // blocked, so the later ask grant does not apply and is not extended.
  await h.call({ id: 12, name: "write_file", args: { path: "sandbox/a.txt" }, reply: sessionReply });
  const uncertain = await h.call({
    id: 13,
    name: "write_file",
    args: { path: "/tmp/a\0b" },
    reply: denyReply,
  });
  assert(uncertain.elicited, "a null byte must not ride an ask grant");
  expectVerdict(h, { id: 13, tool: "write_file", verdict: "ask→denied(blocked-allow)", forwarded: false });
  const outside = await h.call({ id: 14, name: "write_file", args: { path: "sandbox/b.txt" } });
  assert(!outside.elicited, "a resolvable path outside the allow prefix still uses the grant");
  expectVerdict(h, { id: 14, tool: "write_file", verdict: "ask→granted(session)", forwarded: true });
});

await check("pack rule order is part of the grant key", async (h) => {
  const packed = [...filesystemPack, notesAsk];
  await h.start({ rules: packed });

  const read = await h.call({ id: 7, name: "read_file", args: { path: "/tmp/a.txt" } });
  assert(!read.elicited, "a pack allow is not an ask");
  expectVerdict(h, { id: 7, tool: "read_file", verdict: "allow", forwarded: true });

  await h.call({ id: 8, name: "notes", args: { text: "a" }, reply: sessionReply });
  assert(
    h.grantLogs()[0] === "[GRANT] tool=notes rule=notes ttl=1800s",
    `GRANT line ${h.grantLogs()[0]}`,
  );
  const again = await h.call({ id: 9, name: "notes", args: { text: "b" } });
  assert(!again.elicited, "the pack-first identity is what the grant stores");
  expectVerdict(h, { id: 9, tool: "notes", verdict: "ask→granted(session)", forwarded: true });

  // Same rule text, index 0 instead of the index after the pack.
  await h.reload({ rules: [notesAsk], elicitation: true });
  const unpacked = await h.call({ id: 10, name: "notes", args: { text: "c" }, reply: onceReply });
  assert(unpacked.elicited, "dropping the pack changes the rule identity");
  expectVerdict(h, { id: 10, tool: "notes", verdict: "ask→approved", forwarded: true });
});

await check("a grant recorded without a pack does not cover the pack-first rule", async (h) => {
  await h.start({ rules: [notesAsk] });
  await h.call({ id: 7, name: "notes", args: { text: "a" }, reply: sessionReply });
  expectVerdict(h, { id: 7, tool: "notes", verdict: "ask→approved", forwarded: true });

  await h.reload({ rules: [...filesystemPack, notesAsk], elicitation: true });
  const shifted = await h.call({ id: 8, name: "notes", args: { text: "b" }, reply: onceReply });
  assert(shifted.elicited, "--rules shifts the policy rule's index, so the old grant must not apply");
  expectVerdict(h, { id: 8, tool: "notes", verdict: "ask→approved", forwarded: true });
  assert(h.grantLogs().length === 1, "once scope must not add a second grant");
});

await check("a denial does not remember even with scope session", async (h) => {
  await h.start({
    rules: [{ tool: "write_file", action: "ask" }],
  });
  await h.call({ id: 7, name: "write_file", args: { path: "a.txt" }, reply: denyReply });
  expectVerdict(h, { id: 7, tool: "write_file", verdict: "ask→denied", forwarded: false });
  assert(h.grantLogs().length === 0, "deny content must not create a grant");
  const next = await h.call({ id: 8, name: "write_file", args: { path: "a.txt" }, reply: onceReply });
  assert(next.elicited, "the following call still asks");
});

function runMayi(args, { timeout } = {}) {
  return spawnSync(process.execPath, [resolve("mayi.mjs"), ...args], {
    encoding: "utf8",
    timeout,
    cwd: process.cwd(),
  });
}

caseName = "help lists --grant-ttl";
{
  const before = failures;
  const help = runMayi(["--help"]);
  assert(help.status === 0, `help exited ${help.status}: ${help.stderr}`);
  assert((help.stdout || "").includes("--grant-ttl"), "help text missing --grant-ttl");
  assert((help.stdout || "").includes("1800"), "help text should mention the 1800 default");
  if (failures === before) console.log("ok help lists --grant-ttl");
}

caseName = "grant-ttl rejects values that are not non-negative integers";
{
  const before = failures;
  for (const bad of ["-1", "1.5", "foo", "+10", "", "30s"]) {
    const result = runMayi(["--grant-ttl", bad, "--", process.execPath, "-e", "process.exit(0)"]);
    const stderr = result.stderr || "";
    assert(result.status === 1, `value ${JSON.stringify(bad)} exited ${result.status}, stderr=${stderr}`);
    assert(stderr.includes("requires a non-negative integer"), `value ${JSON.stringify(bad)} missing validation message`);
  }
  const missing = runMayi(["--grant-ttl", "--", process.execPath, "-e", "process.exit(0)"]);
  assert(missing.status === 1, `missing value exited ${missing.status}`);
  assert((missing.stderr || "").includes("requires a non-negative integer"), "missing value was not rejected");
  if (failures === before) console.log("ok grant-ttl rejects values that are not non-negative integers");
}

caseName = "grant-ttl config line";
function configLine(args) {
  const result = runMayi([...args, "--", process.execPath, "-e", "setInterval(() => {}, 1000000)"], { timeout: 1500 });
  return result.stderr || "";
}
{
  const before = failures;
  const off = configLine(["--grant-ttl", "0"]);
  const custom = configLine(["--grant-ttl", "60"]);
  const omitted = configLine([]);
  assert(off.includes("[CONFIG] session grants: off"), `0 not logged as off:\n${off}`);
  assert(!off.includes("requires a non-negative integer"), "0 was rejected");
  assert(custom.includes("[CONFIG] session grants: 60s"), `60 not logged:\n${custom}`);
  assert(omitted.includes("[CONFIG] session grants: 1800s"), `default not 1800:\n${omitted}`);
  if (failures === before) console.log("ok grant-ttl config line");
}

rmSync(dir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall session grant checks passed");
