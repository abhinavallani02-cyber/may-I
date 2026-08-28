// Manually trigger diff_files through mayI so the approval prompt fires
// for real, without going through an MCP client.
//
// Usage:
//   node manual-diff.mjs <fileA> <fileB> \
//     --policy <policy.yaml> --audit <audit.jsonl> \
//     -- <command to run the diff server> [args...]
//
// Example:
//   node manual-diff.mjs a.txt b.txt \
//     --policy policy.yaml --audit audit.jsonl \
//     -- uv run --directory /path/to/diffmcp python server.py

import { spawn } from "node:child_process";
import path from "node:path";

const argv = process.argv.slice(2);
const sepIndex = argv.indexOf("--");
if (sepIndex === -1 || sepIndex === argv.length - 1) {
  console.error("manual-diff: everything after \"--\" is the diff server command to run.");
  process.exit(1);
}

const before = argv.slice(0, sepIndex);
const serverCommand = argv.slice(sepIndex + 1);

const [fileA, fileB] = before.filter((a, i) =>
  !a.startsWith("--") && before[i - 1] !== "--policy" && before[i - 1] !== "--audit"
);
if (!fileA || !fileB) {
  console.error("Usage: node manual-diff.mjs <fileA> <fileB> [--policy <file>] [--audit <file>] -- <server command>");
  process.exit(1);
}

const policyIndex = before.indexOf("--policy");
const auditIndex = before.indexOf("--audit");

const mayiArgs = [path.join(import.meta.dirname, "mayi.mjs")];
if (policyIndex !== -1) mayiArgs.push("--policy", before[policyIndex + 1]);
if (auditIndex !== -1) mayiArgs.push("--audit", before[auditIndex + 1]);
mayiArgs.push("--", ...serverCommand);

const proc = spawn("node", mayiArgs, { stdio: ["pipe", "pipe", "inherit"] });

let inBuffer = "";
const pending = new Map();
proc.stdout.on("data", (chunk) => {
  inBuffer += chunk.toString();
  let i;
  while ((i = inBuffer.indexOf("\n")) !== -1) {
    const line = inBuffer.slice(0, i);
    inBuffer = inBuffer.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

let nextId = 1;
function send(method, params) {
  const id = nextId++;
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve) => pending.set(id, resolve));
}
function sendNotification(method, params) {
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

async function main() {
  await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "manual-diff", version: "0.0.1" },
  });
  sendNotification("notifications/initialized", {});

  const result = await send("tools/call", {
    name: "diff_files",
    arguments: { file_a: fileA, file_b: fileB },
  });
  console.log(JSON.stringify(result, null, 2));

  proc.stdin.end();
  proc.kill();
  process.exit(0);
}

main();
