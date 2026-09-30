// Adversarial checks for path canonicalization and SQL statement shape.
// decide() is the policy result. A few calls also go through
// handleClientLine so the audit label and the forward/block decision
// are the same ones a real tools/call would get.

import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import { classifySql, isUnderPrefix } from "./structural.mjs";
import { configureForTest, decide, handleClientLine } from "./mayi.mjs";

const dir = mkdtempSync(join(tmpdir(), "mayi-structural-"));
let failures = 0;
let caseName = "";
let auditSeq = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL ${caseName}: ${message}`);
}

function assert(cond, message) {
  if (!cond) fail(message);
}

function check(name, fn) {
  caseName = name;
  const before = failures;
  try {
    fn();
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  }
  if (failures === before) console.log(`ok ${name}`);
}

async function checkAsync(name, fn) {
  caseName = name;
  const before = failures;
  try {
    await fn();
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  }
  if (failures === before) console.log(`ok ${name}`);
}

function useRules(rules) {
  configureForTest({
    rules,
    auditFile: join(dir, "unused.jsonl"),
    childStdin: { write() {} },
  });
}

function decision(rules, tool, args) {
  useRules(rules);
  return decide(tool, args);
}

const SELECT_THEN_DENY = [
  { tool: "query", sql: { single: "select" }, action: "allow" },
  { tool: "query", action: "deny" },
];

check("segment boundary, not a string prefix", () => {
  assert(isUnderPrefix("/prod", "/prod"), "/prod is itself");
  assert(isUnderPrefix("/prod/db", "/prod"), "/prod/db is inside /prod");
  assert(!isUnderPrefix("/production", "/prod"), "/production is not inside /prod");
  assert(!isUnderPrefix("/prod-backup", "/prod"), "/prod-backup is not inside /prod");
  assert(!isUnderPrefix("/prod/../etc", "/prod"), "unnormalized .. is not a child segment");
});

check("lexical path_prefix collapses .., ./, and duplicate slashes", () => {
  const rules = [
    { tool: "write_*", path_prefix: "/prod", action: "deny" },
    { tool: "write_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "ask" },
  ];
  const cases = [
    ["/prod/secret", "deny"],
    ["/prod", "deny"],
    ["/prod/../prod/secret", "deny"],
    ["/prod//secret", "deny"],
    ["/prod/./secret", "deny"],
    ["/prod/../etc/passwd", "deny"],
    ["/PROD/secret", "ask"],
    ["/production", "ask"],
    ["/prod-backup/secret", "ask"],
    ["/tmp/notes", "ask"],
  ];
  for (const [path, action] of cases) {
    const got = decision(rules, "write_file", { path });
    assert(got.action === action, `${path} -> ${got.action}, expected ${action} (${got.matchedRule})`);
  }
  const walked = decision(rules, "write_file", { path: "/prod/../etc/passwd" });
  assert(walked.matchedRule.includes("path_prefix: /etc"), `walked path matched ${walked.matchedRule}`);

  const askRules = [
    { tool: "write_*", path_prefix: "/prod", action: "ask" },
    { tool: "*", action: "allow" },
  ];
  assert(decision(askRules, "write_file", { path: "/prod/../prod/x" }).action === "ask", "canonical /prod should ask");
  assert(decision(askRules, "write_file", { path: "/production" }).action === "allow", "/production must not ask as /prod");
});

check("glob is the first pass; a path rule does not see other tools", () => {
  const rules = [
    { tool: "write_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "allow" },
  ];
  const read = decision(rules, "read_file", { path: "/etc/passwd" });
  assert(read.action === "allow", `read_file should not hit the write_ rule, got ${read.action}`);
  const write = decision(rules, "write_file", { path: "/etc/../etc/passwd" });
  assert(write.action === "deny", `canonical /etc write should deny, got ${write.action}`);
});

check("allow needs every path argument inside the prefix; deny needs any", () => {
  const safe = "/work/safe";
  const allowRules = [
    { tool: "move_*", path_prefix: safe, action: "allow" },
    { tool: "*", action: "deny" },
  ];
  const both = decision(allowRules, "move_file", { source: `${safe}/a`, destination: `${safe}/b` });
  assert(both.action === "allow", `both inside should allow, got ${both.action} ${both.matchedRule}`);
  const escaped = decision(allowRules, "move_file", { source: `${safe}/a`, destination: "/etc/passwd" });
  assert(escaped.action === "deny", `destination outside should not match the allow, got ${escaped.action}`);

  const denyRules = [
    { tool: "move_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "allow" },
  ];
  const oneSide = decision(denyRules, "move_file", { source: `${safe}/a`, destination: "/etc/../etc/passwd" });
  assert(oneSide.action === "deny", `one side under /etc should deny, got ${oneSide.action}`);
});

check("missing path does not match a path rule; a non-string path cannot be allowed", () => {
  const rules = [
    { tool: "write_*", path_prefix: "/safe", action: "allow" },
    { tool: "*", action: "allow" },
  ];
  const missing = decision(rules, "write_file", { content: "hi" });
  assert(missing.action === "allow", `no path argument is not a path-rule failure, got ${missing.action}`);

  const poisoned = [
    { tool: "write_*", path_prefix: "/safe", action: "allow" },
    { tool: "*", action: "allow" },
  ];
  for (const path of [null, 1, ["/safe/x"], `/safe/x\0/../etc/passwd`, ""]) {
    const got = decision(poisoned, "write_file", { path });
    assert(got.action === "ask", `unusable path ${JSON.stringify(path)} -> ${got.action}, expected ask`);
  }
});

// Real directories, so realpath and symlinks are the OS's answers.
const root = join(dir, "tree");
const safe = join(root, "safe");
const secret = join(root, "secret");
const safe2 = join(root, "safe2");
mkdirSync(safe, { recursive: true });
mkdirSync(secret, { recursive: true });
mkdirSync(safe2, { recursive: true });
writeFileSync(join(safe, "ok.txt"), "ok");
writeFileSync(join(secret, "pw.txt"), "no");
writeFileSync(join(safe2, "x.txt"), "x");
symlinkSync(secret, join(safe, "link"));
symlinkSync(join(secret, "pw.txt"), join(safe, "file-link"));
symlinkSync(safe, join(root, "alias"));

function pathRules(prefix, action, rest = "ask") {
  return [
    { tool: "write_*", path_prefix: prefix, action },
    { tool: "*", action: rest },
  ];
}

check("realpath: symlink targets are not inside the allow prefix", () => {
  const rules = pathRules(safe, "allow", "deny");
  const allowed = [
    join(safe, "ok.txt"),
    `${safe}//ok.txt`,
    `${safe}/./ok.txt`,
    `${safe}/../safe/ok.txt`,
    join(safe, "new.txt"),
    join(root, "alias", "ok.txt"),
  ];
  for (const path of allowed) {
    const got = decision(rules, "write_file", { path });
    assert(got.action === "allow", `${path} -> ${got.action} ${got.matchedRule}`);
  }
  const blocked = [
    join(safe, "link", "pw.txt"),
    join(safe, "link", "new.txt"),
    join(safe, "file-link"),
    join(secret, "pw.txt"),
    `${safe}/../secret/pw.txt`,
    join(safe2, "x.txt"),
    `${safe}-backup/x.txt`,
  ];
  for (const path of blocked) {
    const got = decision(rules, "write_file", { path });
    assert(got.action === "deny", `${path} should not be allowed, got ${got.action} ${got.matchedRule}`);
  }
});

check("deny matches the path as written and the realpath target", () => {
  const viaLink = decision(pathRules(secret, "deny", "allow"), "write_file", { path: join(safe, "link", "pw.txt") });
  assert(viaLink.action === "deny", `symlink into secret should deny, got ${viaLink.action}`);
  const lexical = decision(pathRules(safe, "deny", "allow"), "write_file", { path: join(safe, "link", "pw.txt") });
  assert(lexical.action === "deny", `path written under safe should deny even though it points at secret, got ${lexical.action}`);
  const viaAlias = decision(pathRules(join(root, "alias"), "deny", "allow"), "write_file", { path: join(safe, "ok.txt") });
  assert(viaAlias.action === "deny", `prefix symlink should see the real directory, got ${viaAlias.action} ${viaAlias.matchedRule}`);
});

check("sql.single allows one select and nothing compound or unparseable", () => {
  const samples = [
    ["SELECT 1", "allow"],
    ["select 1", "allow"],
    ["  /* lead */ SELECT 1", "allow"],
    ["SELECT 1;", "allow"],
    ["SELECT 'text; still text'", "allow"],
    ["SELECT 'text; still text';", "allow"],
    ["SELECT 1 /* ; DROP TABLE users */", "allow"],
    ["SELECT $$ ; still the same statement $$", "allow"],
    ["SELECT $tag$ ; DROP TABLE users $tag$", "allow"],
    ["SELECT 1; DROP TABLE users", "deny"],
    ["SELECT 1;DROP TABLE users", "deny"],
    ["SELECT 1; /* hidden */ DROP TABLE users", "deny"],
    ["SELECT 1 -- comment\n; DROP TABLE users", "deny"],
    ["SELECT 1;--\nDROP TABLE users", "deny"],
    ["SELECT 1;\nDROP TABLE users", "deny"],
    ["SELECT 1; SELECT 2", "deny"],
    ["SELECT 1 # ; DROP TABLE users", "deny"],
    ["DROP TABLE users", "deny"],
    ["EXPLAIN DELETE FROM users", "deny"],
    ["WITH cte AS (SELECT 1) DELETE FROM users", "deny"],
    ["WITH cte AS (SELECT 1) SELECT 2", "deny"],
    ["SELECT 'unterminated", "deny"],
    ["SELECT 1 /* never closed", "deny"],
    ["SELECT $tag$ never closed", "deny"],
    ["/* comment only */", "deny"],
    ["", "deny"],
    ["SELECT 1\0; DROP TABLE users", "deny"],
    [";;", "deny"],
  ];
  for (const [sql, action] of samples) {
    const got = decision(SELECT_THEN_DENY, "query", { sql });
    assert(got.action === action, `${JSON.stringify(sql)} -> ${got.action} ${got.matchedRule}, expected ${action}`);
  }
});

check("classifySql reports statement verbs", () => {
  const one = classifySql("SELECT 1; /* ; */ ");
  assert(one.ok && one.statements.length === 1 && one.statements[0] === "select", JSON.stringify(one));
  const two = classifySql("SELECT 1; /* c */ DROP TABLE users");
  assert(two.ok && two.statements.join(",") === "select,drop", JSON.stringify(two));
  const hidden = classifySql("SELECT 1 /* ; DROP TABLE users */");
  assert(hidden.ok && hidden.statements.join(",") === "select", JSON.stringify(hidden));
  const quoted = classifySql("SELECT '; DROP TABLE users'");
  assert(quoted.ok && quoted.statements.join(",") === "select", JSON.stringify(quoted));
  const broken = classifySql("SELECT 'nope");
  assert(!broken.ok, JSON.stringify(broken));
});

check("a single-statement allow does not let a later allow accept compound SQL", () => {
  const rules = [
    { tool: "query", sql: { single: "select" }, action: "allow" },
    { tool: "query", sql: { single: "insert" }, action: "allow" },
    { tool: "*", action: "allow" },
  ];
  const select = decision(rules, "query", { sql: "SELECT 1" });
  assert(select.action === "allow" && select.matchedRule.includes("sql.single: select"), select.matchedRule);
  const insert = decision(rules, "query", { sql: "INSERT INTO t VALUES (1)" });
  assert(insert.action === "allow" && insert.matchedRule.includes("sql.single: insert"), insert.matchedRule);
  const compound = decision(rules, "query", { sql: "SELECT 1; DROP TABLE users" });
  assert(compound.action === "ask", `compound must not be allowed, got ${compound.action} ${compound.matchedRule}`);
  const broken = decision(rules, "query", { sql: "SELECT '" });
  assert(broken.action === "ask", `unparseable must not be allowed, got ${broken.action}`);
});

check("sql shape is not applied to a tool the glob did not match", () => {
  const rules = [
    { tool: "query", sql: { single: "select" }, action: "allow" },
    { tool: "query", action: "deny" },
    { tool: "*", action: "allow" },
  ];
  const other = decision(rules, "other_tool", { sql: "SELECT 1; DROP TABLE users" });
  assert(other.action === "allow" && other.matchedRule === "*", `glob should skip the query rules, got ${other.action} ${other.matchedRule}`);
});

check("sql.single accepts a list, and query/statement arguments count", () => {
  const rules = [
    { tool: "query", sql: { single: ["select", "with"] }, action: "allow" },
    { tool: "query", action: "deny" },
  ];
  const withSelect = decision(rules, "query", { query: "WITH cte AS (SELECT 1) SELECT 2" });
  assert(withSelect.action === "allow", `with should be allowlisted, got ${withSelect.action}`);
  const both = decision(rules, "query", { sql: "SELECT 1", statement: "SELECT 1; DROP TABLE t" });
  assert(both.action === "deny", `a second argument that is compound must deny, got ${both.action}`);
});

check("documented limitation: single explain matches EXPLAIN DELETE", () => {
  const rules = [
    { tool: "query", sql: { single: "explain" }, action: "allow" },
    { tool: "query", action: "deny" },
  ];
  const got = decision(rules, "query", { sql: "EXPLAIN DELETE FROM users" });
  assert(got.action === "allow", `EXPLAIN DELETE is verb explain, got ${got.action} ${got.matchedRule}`);
});

check("a bad structural rule is rejected instead of ignored", () => {
  const bad = [
    [{ tool: "query", sql: { singl: "select" }, action: "allow" }, "only supports"],
    [{ tool: "query", sql: "select", action: "allow" }, "mapping"],
    [{ tool: "query", sql: { single: [] }, action: "allow" }, "at least one"],
    [{ tool: "query", sql: { single: "select;drop" }, action: "allow" }, "statement names"],
    [{ tool: "write_*", path_prefix: "", action: "deny" }, "non-empty"],
    [{ tool: "write_*", path_prefix: 1, action: "deny" }, "non-empty"],
    [{ tool: "write_*", action: "Allow" }, "action must be"],
  ];
  for (const [rule, needle] of bad) {
    let threw = false;
    try {
      useRules([rule]);
    } catch (err) {
      threw = true;
      assert(String(err.message).includes(needle), `${JSON.stringify(rule.sql ?? rule.path_prefix ?? rule.action)} message ${err.message}`);
    }
    assert(threw, `expected rejection for ${JSON.stringify(rule)}`);
  }
});

check("shipped policy.yaml still compiles", () => {
  const parsed = parseYaml(readFileSync(resolve("policy.yaml"), "utf8"));
  useRules(parsed.rules);
  const read = decide("read_file", { path: "/tmp/x" });
  const walked = decide("write_file", { path: "/prod/../prod/secret" });
  const production = decide("write_file", { path: "/production/secret" });
  assert(read.action === "allow", `read ${read.action}`);
  assert(walked.action === "deny", `/prod/../prod should deny, got ${walked.action} ${walked.matchedRule}`);
  assert(production.action === "ask", `/production should not match /prod, got ${production.action} ${production.matchedRule}`);
});

function runMayi(args) {
  return spawnSync(process.execPath, [resolve("mayi.mjs"), ...args], {
    encoding: "utf8",
    timeout: 3000,
    cwd: process.cwd(),
  });
}

check("a bad policy file fails closed at startup", () => {
  const badPath = join(dir, "bad.yaml");
  writeFileSync(badPath, "rules:\n  - tool: query\n    sql:\n      singl: select\n    action: allow\n");
  const result = runMayi(["--policy", badPath, "--", process.execPath, "-e", "process.exit(0)"]);
  assert(result.status === 1, `bad policy exited ${result.status}\n${result.stderr}`);
  assert((result.stderr || "").includes("sql only supports"), result.stderr || "");
});

async function drive(rules, name, args, askResult = "denied") {
  const childLines = [];
  const clientChunks = [];
  const auditFile = join(dir, `audit-${auditSeq += 1}.jsonl`);
  configureForTest({
    rules,
    auditFile,
    childStdin: { write: (line) => childLines.push(String(line)) },
    askHuman: () => askResult,
  });
  const origWrite = process.stdout.write.bind(process.stdout);
  const origErr = console.error;
  process.stdout.write = (chunk, enc, cb) => {
    clientChunks.push(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk));
    const done = typeof enc === "function" ? enc : cb;
    if (typeof done === "function") done();
    return true;
  };
  console.error = () => {};
  try {
    await handleClientLine(JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name, arguments: args },
    }));
  } finally {
    process.stdout.write = origWrite;
    console.error = origErr;
  }
  const audit = readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const forwarded = childLines.some((line) => line.includes('"tools/call"'));
  return { audit, forwarded, client: clientChunks.join("") };
}

await checkAsync("audit labels stay allow, deny, and ask, and compound SQL is not forwarded", async () => {
  const allowed = await drive(SELECT_THEN_DENY, "query", { sql: "SELECT 1" });
  assert(allowed.audit.length === 1 && allowed.audit[0].verdict === "allow", JSON.stringify(allowed.audit));
  assert(allowed.forwarded, "single select should be forwarded");

  const compound = await drive(SELECT_THEN_DENY, "query", { sql: "SELECT 1; DROP TABLE users" });
  assert(compound.audit.length === 1 && compound.audit[0].verdict === "deny", JSON.stringify(compound.audit));
  assert(!compound.forwarded, "compound statement was forwarded");
  assert(compound.client.includes("Blocked by policy"), compound.client);

  const onlyAllow = [
    { tool: "query", sql: { single: "select" }, action: "allow" },
  ];
  const unparsed = await drive(onlyAllow, "query", { sql: "SELECT '" }, "approved");
  assert(unparsed.audit[0].verdict === "ask→approved", JSON.stringify(unparsed.audit));
  assert(unparsed.forwarded, "a human yes on the fallback ask is an ask approval, not a structural allow");

  const unparsedDenied = await drive(onlyAllow, "query", { sql: "SELECT '" }, "denied");
  assert(unparsedDenied.audit[0].verdict === "ask→denied", JSON.stringify(unparsedDenied.audit));
  assert(!unparsedDenied.forwarded, "default ask must be able to deny an unparseable statement");

  const walked = await drive([
    { tool: "write_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "allow" },
  ], "write_file", { path: "/prod/../etc/passwd" });
  assert(walked.audit[0].verdict === "deny", JSON.stringify(walked.audit));
  assert(!walked.forwarded, "canonical /etc write was forwarded");
  assert(walked.client.includes("path_prefix: /etc"), walked.client);
});

rmSync(dir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall structural checks passed");
