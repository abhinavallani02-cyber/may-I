// Rule packs: every rule must name a tool the real server actually has.
// filesystem is spawned and tools/list is called. git, github, and
// postgres are checked against snapshots captured the same way (those
// servers are not installed with may-i). An unknown --rules name must
// exit before the child starts.

import { readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { configureForTest, decide } from "./mayi.mjs";

let failures = 0;
let caseName = "";

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
    const result = fn();
    if (result && typeof result.then === "function") {
      throw new Error("use checkAsync");
    }
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

function globToRegex(glob) {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

// A catch-all "*" is not a claim that a specific tool exists. Every
// other pattern must match at least one real tool name.
function rulesMissingTools(rules, toolNames) {
  const missing = [];
  for (const rule of rules) {
    if (rule.tool === "*") continue;
    const re = globToRegex(rule.tool);
    if (!toolNames.some((name) => re.test(name))) missing.push(rule.tool);
  }
  return missing;
}

function loadPack(name) {
  const parsed = parseYaml(readFileSync(resolve("rules", `${name}.yaml`), "utf8"));
  if (!parsed || !Array.isArray(parsed.rules)) throw new Error(`${name} has no rules list`);
  return parsed.rules;
}

function loadSnapshot(name) {
  const snap = JSON.parse(readFileSync(resolve("rules", "snapshots", `${name}.json`), "utf8"));
  if (!snap.version || snap.source !== "tools/list" || !Array.isArray(snap.tools) || snap.tools.length === 0) {
    throw new Error(`snapshot ${name} is missing version, source, or tools`);
  }
  return snap;
}

function listTools(command, args) {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
  let buf = "";
  const pending = new Map();
  let nextId = 1;
  let stderr = "";
  child.stdout.on("data", (chunk) => { buf += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  function send(method, params) {
    const id = nextId++;
    const line = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout ${method}\n${stderr.slice(0, 400)}`)), 8000);
      pending.set(id, (msg) => { clearTimeout(timer); resolvePromise(msg); });
      child.stdin.write(line);
    });
  }
  function pump() {
    let i;
    while ((i = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  }
  child.stdout.on("data", pump);
  return (async () => {
    try {
      const init = await send("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mayi-pack-test", version: "0" },
      });
      if (init.error) throw new Error(JSON.stringify(init.error));
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      const listed = await send("tools/list", {});
      if (listed.error) throw new Error(JSON.stringify(listed.error));
      return (listed.result?.tools ?? []).map((tool) => tool.name);
    } finally {
      child.kill("SIGTERM");
    }
  })();
}

check("a rule that names nothing in the tool list is rejected", () => {
  const missing = rulesMissingTools(
    [{ tool: "not_a_real_tool", action: "ask" }, { tool: "*", action: "ask" }],
    ["query"],
  );
  assert(missing.length === 1 && missing[0] === "not_a_real_tool", JSON.stringify(missing));
  assert(rulesMissingTools([{ tool: "q*", action: "allow" }], ["query"]).length === 0, "glob should match query");
});

await checkAsync("filesystem pack matches the spawned server's tools/list", async () => {
  const names = await listTools(process.execPath, [
    resolve("node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"),
    tmpdir(),
  ]);
  assert(names.includes("read_text_file") && names.includes("write_file") && names.includes("move_file"), names.join(","));
  const missing = rulesMissingTools(loadPack("filesystem"), names);
  assert(missing.length === 0, `filesystem rules with no tool: ${missing.join(", ")}`);
});

check("git, github, and postgres packs match their tools/list snapshots", () => {
  for (const name of ["git", "github", "postgres"]) {
    const snap = loadSnapshot(name);
    const missing = rulesMissingTools(loadPack(name), snap.tools);
    assert(missing.length === 0, `${name} ${snap.version} rules with no tool: ${missing.join(", ")}`);
    console.log(`  ${name} ${snap.package} ${snap.version} via ${snap.source} (${snap.tools.length} tools)`);
  }
});

check("postgres pack allows one select and denies a compound statement", () => {
  configureForTest({
    rules: loadPack("postgres"),
    auditFile: join(tmpdir(), "mayi-pack-unused.jsonl"),
    childStdin: { write() {} },
  });
  const ok = decide("query", { sql: "SELECT 1" });
  const compound = decide("query", { sql: "SELECT 1; DROP TABLE users" });
  assert(ok.action === "allow" && ok.blockedAllow === false, JSON.stringify(ok));
  assert(compound.action === "deny" && compound.blockedAllow === true, JSON.stringify(compound));
});

check("pack rules are checked before --policy rules", () => {
  const pack = loadPack("filesystem");
  const extra = [
    { tool: "read_text_file", action: "deny" },
    { tool: "custom_tool", action: "deny" },
  ];
  configureForTest({
    rules: [...pack, ...extra],
    auditFile: join(tmpdir(), "mayi-pack-unused.jsonl"),
    childStdin: { write() {} },
  });
  const read = decide("read_text_file", { path: "/tmp/notes.txt" });
  const custom = decide("custom_tool", {});
  assert(read.action === "allow", `pack allow should win over a later deny, got ${read.action}`);
  assert(custom.action === "deny", `policy rule should see tools the pack does not name, got ${custom.action}`);
});

function runMayi(args, cwd = process.cwd()) {
  return spawnSync(process.execPath, [resolve("mayi.mjs"), ...args], {
    encoding: "utf8",
    timeout: 3000,
    cwd,
  });
}

check("unknown --rules is a startup error and does not start the child", () => {
  const child = [process.execPath, "-e", "console.error('CHILD_RAN'); process.exit(0)"];
  const unknown = runMayi(["--rules", "no-such-pack", "--", ...child]);
  assert(unknown.status === 1, `unknown pack exited ${unknown.status}\n${unknown.stderr}`);
  assert((unknown.stderr || "").includes("unknown rules pack"), unknown.stderr || "");
  assert(!(unknown.stderr || "").includes("CHILD_RAN") && !(unknown.stdout || "").includes("CHILD_RAN"), "child started after an unknown pack");

  const traversal = runMayi(["--rules", "../policy", "--", ...child]);
  assert(traversal.status === 1, `traversal exited ${traversal.status}`);
  assert((traversal.stderr || "").includes("pack name"), traversal.stderr || "");
  assert(!(traversal.stderr || "").includes("CHILD_RAN"), "child started after a path-like pack name");

  const missing = runMayi(["--rules", "--", ...child]);
  assert(missing.status === 1, `missing value exited ${missing.status}`);
  assert((missing.stderr || "").includes("needs a pack name"), missing.stderr || "");
});

check("--rules loads the pack and does not silently merge ./policy.yaml", () => {
  const help = runMayi(["--help"]);
  assert(help.status === 0 && help.stdout.includes("--rules"), help.stderr || help.stdout);

  const only = runMayi(["--rules", "filesystem", "--", process.execPath, "-e", "process.exit(0)"]);
  assert(only.status === 0, `filesystem pack exited ${only.status}\n${only.stderr}`);
  assert((only.stderr || "").includes("rules pack filesystem"), only.stderr || "");
  assert(!(only.stderr || "").includes("policy.yaml"), `cwd policy.yaml was merged:\n${only.stderr}`);

  const dir = mkdtempSync(join(tmpdir(), "mayi-rules-"));
  try {
    const extra = join(dir, "extra.yaml");
    writeFileSync(extra, "rules:\n  - tool: custom_tool\n    action: deny\n");
    const both = runMayi(["--policy", extra, "--rules", "git", "--", process.execPath, "-e", "process.exit(0)"]);
    assert(both.status === 0, `combined flags exited ${both.status}\n${both.stderr}`);
    const config = (both.stderr || "").split("\n").find((line) => line.includes("[CONFIG] policy:")) || "";
    const packAt = config.indexOf("rules pack git");
    const policyAt = config.indexOf(extra);
    assert(packAt !== -1 && policyAt !== -1 && packAt < policyAt, config);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall rule pack checks passed");
