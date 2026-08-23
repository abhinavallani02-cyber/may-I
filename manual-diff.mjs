// Manually trigger diff_files through mayI so the [ASK] prompt fires for real.
// Usage: node manual-diff.mjs <fileA> <fileB>

import { spawn } from "node:child_process";
import path from "node:path";

const [fileA, fileB] = process.argv.slice(2);
if (!fileA || !fileB) {
  console.error("Usage: node manual-diff.mjs <fileA> <fileB>");
  process.exit(1);
}

const proc = spawn(
  "node",
  [
    path.join(import.meta.dirname, "mayi.mjs"),
    "--policy", "/path/to/your-project/policy.yaml",
    "--audit", "/path/to/your-project/audit.jsonl",
    "--",
    "uv", "run", "--directory", "/path/to/diffmcp", "python", "server.py",
  ],
  { stdio: ["pipe", "pipe", "inherit"] }
);

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
