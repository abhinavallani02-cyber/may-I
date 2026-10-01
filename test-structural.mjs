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
  const repoWalk = decision([
    { tool: "git_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "allow" },
  ], "git_status", { repo_path: "/work/repo/../../etc" });
  assert(repoWalk.action === "deny", `repo_path .. should hit /etc, got ${repoWalk.action} ${repoWalk.matchedRule}`);
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

const NOTE_FORWARDED = "1.0.0 forwarded calls matching invalid rules (fail-open); 1.1.0 stops at startup instead. See CHANGELOG.md.";
const NOTE_TYPEERROR = "1.0.0 threw a TypeError while compiling this rule and printed a stack trace. It did not start the child. 1.1.0 stops at startup with this message instead. See CHANGELOG.md.";
const NOTE_EMPTY_TOOL = '1.0.0 compiled an empty tool as a pattern that matches only a tool named "". 1.1.0 stops at startup instead. See CHANGELOG.md.';
const NOTE_FALSY_PREFIX = "1.0.0 skipped the path check for this path_prefix and matched the rule on the tool name alone. Its action still ran. 1.1.0 stops at startup instead. See CHANGELOG.md.";
const NOTE_COERCED_PREFIX = "1.0.0 passed this path_prefix to String.prototype.startsWith, which turns a non-string into a string. 1.1.0 stops at startup instead. See CHANGELOG.md.";
const NOTE_SQL = "1.0.0 ignored the sql key. The rule matched on the tool name alone and its action still ran. 1.1.0 stops at startup instead. See CHANGELOG.md.";

function ruleMessage(place, detail, note) {
  return `${place} ${detail}\n${note}`;
}

check("a bad rule is rejected with the shape and what 1.0.0 did", () => {
  const bad = [
    ["not-a-mapping", ruleMessage("policy rule 1", 'is "not-a-mapping", not a mapping.', NOTE_TYPEERROR)],
    [null, ruleMessage("policy rule 1", "is null, not a mapping.", NOTE_TYPEERROR)],
    [{ action: "allow" }, ruleMessage("policy rule 1", "is missing tool. tool must be a non-empty string.", NOTE_TYPEERROR)],
    [{ tool: 1, action: "allow" }, ruleMessage("policy rule 1", "has tool 1, not a string.", NOTE_TYPEERROR)],
    [{ tool: "", action: "allow" }, ruleMessage("policy rule 1", 'has empty tool "".', NOTE_EMPTY_TOOL)],
    [{ tool: "write_*", action: "Allow" }, ruleMessage("policy rule 1", 'has unknown action "Allow". Valid actions: allow, deny, ask.', NOTE_FORWARDED)],
    [{ tool: "write_*" }, ruleMessage("policy rule 1", "is missing action. Valid actions: allow, deny, ask.", NOTE_FORWARDED)],
    [{ tool: "write_*", path_prefix: "", action: "deny" }, ruleMessage("policy rule 1", 'has empty path_prefix "".', NOTE_FALSY_PREFIX)],
    [{ tool: "write_*", path_prefix: null, action: "deny" }, ruleMessage("policy rule 1", "has path_prefix null, not a non-empty string.", NOTE_FALSY_PREFIX)],
    [{ tool: "write_*", path_prefix: 1, action: "deny" }, ruleMessage("policy rule 1", "has path_prefix 1, not a non-empty string.", NOTE_COERCED_PREFIX)],
    [{ tool: "query", sql: "select", action: "allow" }, ruleMessage("policy rule 1", 'has sql "select", not a mapping. sql must be a mapping with one key, single, whose value is a statement verb or a list of verbs. Example: { single: select }.', NOTE_SQL)],
    [{ tool: "query", sql: { singl: "select" }, action: "allow" }, ruleMessage("policy rule 1", 'has sql {"singl":"select"}. Valid key: single.', NOTE_SQL)],
    [{ tool: "query", sql: { single: [] }, action: "allow" }, ruleMessage("policy rule 1", "has sql.single [], which names no statement verb.", NOTE_SQL)],
    [{ tool: "query", sql: { single: "select;drop" }, action: "allow" }, ruleMessage("policy rule 1", 'has sql.single verb "select;drop". A verb is a statement name made of letters, digits, and underscores, and it must start with a letter or underscore.', NOTE_SQL)],
  ];
  for (const [rule, expected] of bad) {
    let message = "";
    try {
      useRules([rule]);
    } catch (err) {
      message = String(err.message);
    }
    assert(message === expected, `message:\n${message}\nexpected:\n${expected}`);
  }
});

check("a pack label keeps the rule number from that pack", () => {
  let message = "";
  try {
    configureForTest({
      rules: [
        { tool: "read_*", action: "allow" },
        { tool: "write_file", action: "alow" },
      ],
      rulePlaces: [
        { label: "rules pack filesystem", number: 1 },
        { label: "rules pack filesystem", number: 2 },
      ],
      auditFile: join(dir, "unused-pack.jsonl"),
      childStdin: { write() {} },
    });
  } catch (err) {
    message = String(err.message);
  }
  const expected = ruleMessage(
    "rules pack filesystem rule 2",
    'has unknown action "alow". Valid actions: allow, deny, ask.',
    NOTE_FORWARDED,
  );
  assert(message === expected, `message:\n${message}\nexpected:\n${expected}`);
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

function expectStartup(args, expected) {
  const childPath = join(dir, "stay.mjs");
  writeFileSync(childPath, "console.error('CHILD_RAN');\nsetInterval(() => {}, 1000);\n");
  const result = spawnSync(process.execPath, [resolve("mayi.mjs"), ...args, "--", process.execPath, childPath], {
    encoding: "utf8",
    timeout: 3000,
  });
  const stderr = result.stderr || "";
  assert(result.status === 1, `status ${result.status} error ${result.error}\n${stderr}`);
  assert(stderr === expected, `stderr:\n${stderr}\nexpected:\n${expected}`);
  assert(!stderr.includes("CHILD_RAN"), "child started");
  assert(!/^\s+at /m.test(stderr), stderr);
}

check("startup errors name the file, the rule, and what 1.0.0 did", () => {
  const file = join(dir, "policy.yaml");
  const cases = [
    ["rules:\n  - not-a-mapping\n", `is "not-a-mapping", not a mapping.`, NOTE_TYPEERROR],
    ["rules:\n  - null\n", "is null, not a mapping.", NOTE_TYPEERROR],
    ["rules:\n  - [a, b]\n", 'is ["a","b"], not a mapping.', NOTE_TYPEERROR],
    ["rules:\n  - action: allow\n", "is missing tool. tool must be a non-empty string.", NOTE_TYPEERROR],
    ["rules:\n  - tool: 1\n    action: allow\n", "has tool 1, not a string.", NOTE_TYPEERROR],
    ["rules:\n  - tool: \"\"\n    action: allow\n", 'has empty tool "".', NOTE_EMPTY_TOOL],
    ["rules:\n  - tool: write_file\n", "is missing action. Valid actions: allow, deny, ask.", NOTE_FORWARDED],
    ["rules:\n  - tool: write_file\n    path_prefix: \"\"\n    action: deny\n", 'has empty path_prefix "".', NOTE_FALSY_PREFIX],
    ["rules:\n  - tool: write_file\n    path_prefix:\n    action: deny\n", "has path_prefix null, not a non-empty string.", NOTE_FALSY_PREFIX],
    ["rules:\n  - tool: write_file\n    path_prefix: 1\n    action: deny\n", "has path_prefix 1, not a non-empty string.", NOTE_COERCED_PREFIX],
    ["rules:\n  - tool: query\n    sql: select\n    action: allow\n", 'has sql "select", not a mapping. sql must be a mapping with one key, single, whose value is a statement verb or a list of verbs. Example: { single: select }.', NOTE_SQL],
    ["rules:\n  - tool: query\n    sql:\n      singl: select\n    action: allow\n", 'has sql {"singl":"select"}. Valid key: single.', NOTE_SQL],
    ["rules:\n  - tool: query\n    sql:\n      single: []\n    action: allow\n", "has sql.single [], which names no statement verb.", NOTE_SQL],
    ["rules:\n  - tool: query\n    sql:\n      single: select;drop\n    action: allow\n", 'has sql.single verb "select;drop". A verb is a statement name made of letters, digits, and underscores, and it must start with a letter or underscore.', NOTE_SQL],
  ];
  for (const [yaml, detail, note] of cases) {
    writeFileSync(file, yaml);
    expectStartup(
      ["--policy", file],
      `mayi: ${file} rule 1 ${detail}\nmayi: ${note}\n`,
    );
  }

  const third = join(dir, "third.yaml");
  writeFileSync(third, "rules:\n  - tool: read_*\n    action: allow\n  - tool: list_*\n    action: allow\n  - tool: write_file\n    action: alow\n");
  expectStartup(
    ["--policy", third],
    `mayi: ${third} rule 3 has unknown action "alow". Valid actions: allow, deny, ask.\nmayi: ${NOTE_FORWARDED}\n`,
  );
  expectStartup(
    ["--rules", "filesystem", "--policy", third],
    `mayi: ${third} rule 3 has unknown action "alow". Valid actions: allow, deny, ask.\nmayi: ${NOTE_FORWARDED}\n`,
  );
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
  assert(compound.audit.length === 1 && compound.audit[0].verdict === "deny(blocked-allow)", JSON.stringify(compound.audit));
  assert(!compound.forwarded, "compound statement was forwarded");
  assert(compound.client.includes("Blocked by policy"), compound.client);

  const onlyAllow = [
    { tool: "query", sql: { single: "select" }, action: "allow" },
  ];
  const unparsed = await drive(onlyAllow, "query", { sql: "SELECT '" }, "approved");
  assert(unparsed.audit[0].verdict === "ask→approved(blocked-allow)", JSON.stringify(unparsed.audit));
  assert(unparsed.forwarded, "a human yes on the fallback ask is an ask approval, not a structural allow");

  const unparsedDenied = await drive(onlyAllow, "query", { sql: "SELECT '" }, "denied");
  assert(unparsedDenied.audit[0].verdict === "ask→denied(blocked-allow)", JSON.stringify(unparsedDenied.audit));
  assert(!unparsedDenied.forwarded, "default ask must be able to deny an unparseable statement");

  const unresolved = await drive([
    { tool: "write_*", path_prefix: "/safe", action: "allow" },
    { tool: "write_*", action: "deny" },
  ], "write_file", { path: "/safe/ok\0" });
  assert(unresolved.audit[0].verdict === "deny(blocked-allow)", JSON.stringify(unresolved.audit));
  assert(!unresolved.forwarded, "unresolved path was forwarded");

  const walked = await drive([
    { tool: "write_*", path_prefix: "/etc", action: "deny" },
    { tool: "*", action: "allow" },
  ], "write_file", { path: "/prod/../etc/passwd" });
  assert(walked.audit[0].verdict === "deny", JSON.stringify(walked.audit));
  assert(!walked.forwarded, "canonical /etc write was forwarded");
  assert(walked.client.includes("path_prefix: /etc"), walked.client);
});

await checkAsync("blocked allow plus a tty fallback keeps both labels", async () => {
  const childLines = [];
  const clientChunks = [];
  const auditFile = join(dir, "audit-tty-block.jsonl");
  const t = 5000;
  configureForTest({
    rules: [{ tool: "query", sql: { single: "select" }, action: "allow" }],
    auditFile,
    autoDeclineMs: 750,
    now: () => t,
    childStdin: { write: (line) => childLines.push(String(line)) },
    askHuman: () => "approved",
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
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: { elicitation: { form: {} } }, clientInfo: { name: "fake", version: "0" } },
    }));
    const call = handleClientLine(JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "query", arguments: { sql: "SELECT 1; DROP TABLE users" } },
    }));
    const elicit = clientChunks.join("").split("\n").filter(Boolean).map((line) => JSON.parse(line)).find((msg) => msg.method === "elicitation/create");
    assert(elicit, "expected an elicitation");
    await handleClientLine(JSON.stringify({ jsonrpc: "2.0", id: elicit.id, result: { action: "decline" } }));
    await call;
  } finally {
    process.stdout.write = origWrite;
    console.error = origErr;
  }
  const audit = readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert(audit.length === 1 && audit[0].verdict === "ask→approved(tty-fallback,blocked-allow)", JSON.stringify(audit));
  assert(childLines.some((line) => line.includes('"tools/call"')), "human approval after a blocked allow should forward");
});

rmSync(dir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall structural checks passed");
