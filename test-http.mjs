// HTTP and SSE upstream, plus a stdio regression that spawns may-i the
// same way a client would. The older suites are not modified; this file
// is additive. The local servers are the SDK's own transports.

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const mayiPath = fileURLToPath(new URL("./mayi.mjs", import.meta.url));
const node = process.execPath;

const POLICY = `rules:
  - tool: echo
    action: allow
  - tool: hold
    action: allow
  - tool: secret_tool
    action: deny
  - tool: ask_tool
    action: ask
`;

const TOOLS = [
  { name: "echo", inputSchema: { type: "object" } },
  { name: "hold", inputSchema: { type: "object" } },
  { name: "secret_tool", inputSchema: { type: "object" } },
  { name: "ask_tool", inputSchema: { type: "object" } },
];

function fail(message) {
  console.error("FAIL", message);
  process.exitCode = 1;
  throw new Error(message);
}

function assert(cond, message) {
  if (!cond) fail(message);
}

async function check(name, fn) {
  try {
    await fn();
    console.log("ok", name);
  } catch (err) {
    if (!process.exitCode) process.exitCode = 1;
    console.error("FAIL", name);
    console.error(err && err.stack ? err.stack : err);
  }
}

function collect(stream) {
  let text = "";
  let pending = "";
  const lines = [];
  const waiters = [];
  stream.on("data", (chunk) => {
    const chunkText = chunk.toString();
    text += chunkText;
    pending += chunkText;
    let newline = pending.indexOf("\n");
    while (newline !== -1) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      if (line.length > 0) {
        const waiter = waiters.shift();
        if (waiter) waiter.resolve(line);
        else lines.push(line);
      }
      newline = pending.indexOf("\n");
    }
  });
  return {
    get text() {
      return text;
    },
    nextLine(ms = 8000) {
      if (lines.length > 0) return Promise.resolve(lines.shift());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for a line\n${text}`)), ms);
        waiters.push({
          resolve(line) {
            clearTimeout(timer);
            resolve(line);
          },
        });
      });
    },
    until(needle, ms = 8000) {
      if (text.includes(needle)) return Promise.resolve(text);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for ${JSON.stringify(needle)}\n${text}`)), ms);
        const onData = () => {
          if (!text.includes(needle)) return;
          clearTimeout(timer);
          stream.off("data", onData);
          resolve(text);
        };
        stream.on("data", onData);
      });
    },
  };
}

function startProxy(args, env = {}, options = {}) {
  const child = spawn(node, [options.entry || mayiPath, ...args], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ...env },
    cwd: options.cwd,
  });
  return { child, stdout: collect(child.stdout), stderr: collect(child.stderr) };
}

function send(child, message) {
  child.stdin.write(JSON.stringify(message) + "\n");
}

async function initialize(proxy, capabilities = {}) {
  send(proxy.child, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities,
      clientInfo: { name: "http-test", version: "0" },
    },
  });
  const line = await proxy.stdout.nextLine();
  const msg = JSON.parse(line);
  assert(msg.result && msg.result.protocolVersion, `initialize failed: ${line}`);
  send(proxy.child, { jsonrpc: "2.0", method: "notifications/initialized" });
  return msg;
}

function toolCall(id, name, args = {}) {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } };
}

function makeMcp(calls, onHold) {
  const mcp = new Server({ name: "fixture", version: "1.0.0" }, { capabilities: { tools: {} } });
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
    calls.push(req.params.name);
    if (req.params.name === "hold") {
      if (onHold) onHold();
      await new Promise(() => {});
    }
    const text = req.params.arguments && req.params.arguments.text;
    return { content: [{ type: "text", text: `echo:${text ?? req.params.name}` }] };
  });
  return mcp;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

async function startStreamable(options = {}) {
  const calls = [];
  const sessions = new Map();
  let markHold;
  const holdStarted = new Promise((resolve) => {
    markHold = resolve;
  });
  const httpServer = createServer(async (req, res) => {
    try {
      if (options.bearer && req.headers.authorization !== `Bearer ${options.bearer}`) {
        res.writeHead(401).end("unauthorized");
        return;
      }
      const body = await readBody(req);
      const sessionId = req.headers["mcp-session-id"];
      let transport = typeof sessionId === "string" ? sessions.get(sessionId) : undefined;
      if (!transport) {
        const mcp = makeMcp(calls, markHold);
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized(id) {
            sessions.set(id, transport);
          },
        });
        await mcp.connect(transport);
      }
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
    }
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpServer.address();
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    calls,
    holdStarted,
    drop() {
      httpServer.closeAllConnections();
      httpServer.close();
    },
  };
}

async function startSse(options = {}) {
  const calls = [];
  const sessions = new Map();
  let sawBearer = false;
  const httpServer = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      if (options.bearer && req.headers.authorization === `Bearer ${options.bearer}`) sawBearer = true;
      if (options.bearer && req.headers.authorization !== `Bearer ${options.bearer}`) {
        res.writeHead(401).end("unauthorized");
        return;
      }
      if (req.method === "GET" && url.pathname === "/sse") {
        const transport = new SSEServerTransport("/messages", res);
        sessions.set(transport.sessionId, transport);
        await makeMcp(calls).connect(transport);
        return;
      }
      if (req.method === "POST" && url.pathname === "/messages") {
        const body = await readBody(req);
        const transport = sessions.get(url.searchParams.get("sessionId"));
        if (!transport) {
          res.writeHead(404).end("no session");
          return;
        }
        await transport.handlePostMessage(req, res, body);
        return;
      }
      res.writeHead(404).end("nope");
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
    }
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpServer.address();
  return {
    url: `http://127.0.0.1:${port}/sse`,
    calls,
    sawBearer: () => sawBearer,
    drop() {
      httpServer.closeAllConnections();
      httpServer.close();
    },
  };
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), "mayi-http-"));
}

function writePolicy(dir) {
  const policy = join(dir, "policy.yaml");
  const audit = join(dir, "audit.jsonl");
  writeFileSync(policy, POLICY);
  return { policy, audit };
}

function readAudit(audit) {
  const raw = readFileSync(audit, "utf8").trim();
  if (!raw) return [];
  return raw.split("\n").map((line) => JSON.parse(line));
}

function stop(child) {
  if (child && child.exitCode === null) child.kill("SIGTERM");
}

await check("stdio regression: allow is forwarded and deny is not", async () => {
  const dir = tempDir();
  try {
    const { policy, audit } = writePolicy(dir);
    const childPath = join(dir, "child.mjs");
    writeFileSync(childPath, `
      let buf = "";
      process.stdin.on("data", (chunk) => {
        buf += chunk.toString();
        let nl;
        while ((nl = buf.indexOf("\\n")) !== -1) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (!line) continue;
          const msg = JSON.parse(line);
          const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
          if (msg.method === "initialize") {
            reply({ protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "stdio-child", version: "0" } });
          } else if (msg.method === "tools/call") {
            reply({ content: [{ type: "text", text: "from-stdio-child:" + msg.params.name }] });
          } else if (msg.id !== undefined && msg.method) {
            reply({});
          }
        }
      });
    `);
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--", node, childPath]);
    try {
      await proxy.stderr.until("[CONFIG] policy:");
      assert(!proxy.stderr.text.includes("upstream:"), proxy.stderr.text);
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: "hi" }));
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "from-stdio-child:echo", JSON.stringify(allowed));
      send(proxy.child, toolCall(3, "secret_tool"));
      const denied = JSON.parse(await proxy.stdout.nextLine());
      assert(denied.error && denied.error.message.includes("Blocked by policy"), JSON.stringify(denied));
      const entries = readAudit(audit);
      assert(entries.map((entry) => entry.verdict).join(",") === "allow,deny", JSON.stringify(entries));
      assert(!proxy.stdout.text.includes("from-stdio-child:secret_tool"), proxy.stdout.text);
      assert(!proxy.stderr.text.includes("upstream-error"), proxy.stderr.text);
    } finally {
      stop(proxy.child);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("streamable HTTP allow is forwarded and deny never reaches the server", async () => {
  const dir = tempDir();
  const fixture = await startStreamable();
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--upstream-url", fixture.url]);
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      assert(proxy.stderr.text.includes(`upstream: http ${fixture.url}`), proxy.stderr.text);
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: "hi" }));
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "echo:hi", JSON.stringify(allowed));
      send(proxy.child, toolCall(3, "secret_tool"));
      const denied = JSON.parse(await proxy.stdout.nextLine());
      assert(denied.error?.message.includes("Blocked by policy"), JSON.stringify(denied));
      assert(!denied.result, JSON.stringify(denied));
      assert(fixture.calls.includes("echo") && !fixture.calls.includes("secret_tool"), fixture.calls.join(","));
      const entries = readAudit(audit);
      assert(entries.map((entry) => entry.verdict).join(",") === "allow,deny", JSON.stringify(entries));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("streamable HTTP ask elicitation approves and then forwards", async () => {
  const dir = tempDir();
  const fixture = await startStreamable();
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--upstream-url", fixture.url, "--transport", "http"]);
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      await initialize(proxy, { elicitation: { form: {} } });
      send(proxy.child, toolCall(2, "ask_tool", { text: "please" }));
      const elicit = JSON.parse(await proxy.stdout.nextLine());
      assert(elicit.method === "elicitation/create", JSON.stringify(elicit));
      assert(!fixture.calls.includes("ask_tool"), "ask reached the server before approval");
      send(proxy.child, {
        jsonrpc: "2.0",
        id: elicit.id,
        result: { action: "accept", content: { approve: "approve" } },
      });
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "echo:please", JSON.stringify(allowed));
      assert(fixture.calls.includes("ask_tool"), fixture.calls.join(","));
      const entries = readAudit(audit);
      assert(entries.length === 1 && entries[0].verdict === "ask→approved", JSON.stringify(entries));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

const SDK_MISSING_STDERR = "HTTP transport requires @modelcontextprotocol/sdk. Install it with npm install @modelcontextprotocol/sdk.\n";

// A copy of the runtime whose node_modules has yaml and not the SDK.
// Resolution starts at the copy, outside this repo, so the SDK installed
// for the suite is not visible.
function stageWithoutSdk() {
  const dir = tempDir();
  mkdirSync(join(dir, "node_modules"));
  for (const name of ["mayi.mjs", "upstream.mjs", "structural.mjs"]) {
    copyFileSync(fileURLToPath(new URL("./" + name, import.meta.url)), join(dir, name));
  }
  symlinkSync(
    fileURLToPath(new URL("./node_modules/yaml", import.meta.url)),
    join(dir, "node_modules", "yaml"),
  );
  return dir;
}

await check("missing SDK exits 1 with the install line and answers nothing", async () => {
  const dir = stageWithoutSdk();
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(req.url || "");
    res.writeHead(500).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const { policy, audit } = writePolicy(dir);
    const result = spawnSync(
      node,
      [join(dir, "mayi.mjs"), "--policy", policy, "--audit", audit, "--upstream-url", `http://127.0.0.1:${port}/mcp`],
      {
        encoding: "utf8",
        cwd: dir,
        input: JSON.stringify(toolCall(2, "echo", { text: "nope" })) + "\n",
        timeout: 8000,
      },
    );
    assert(result.status === 1, `status ${result.status}\n${result.stderr}`);
    assert(result.stderr === SDK_MISSING_STDERR, JSON.stringify(result.stderr));
    assert(!(result.stdout || "").trim(), result.stdout || "");
    assert(seen.length === 0, `upstream saw traffic: ${seen.join(",")}`);
    assert(!existsSync(audit), "a tool call was audited");
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("an import error that is not a missing SDK does not fail open", async () => {
  const dir = stageWithoutSdk();
  writeFileSync(
    join(dir, "upstream.mjs"),
    'import "mayi-not-the-sdk";\nexport async function openUpstream() { throw new Error("should not connect"); }\n',
  );
  try {
    const { policy, audit } = writePolicy(dir);
    const result = spawnSync(
      node,
      [join(dir, "mayi.mjs"), "--policy", policy, "--audit", audit, "--upstream-url", "http://127.0.0.1:9/mcp"],
      {
        encoding: "utf8",
        cwd: dir,
        input: JSON.stringify(toolCall(2, "echo", { text: "nope" })) + "\n",
        timeout: 8000,
      },
    );
    assert(result.status === 1, `status ${result.status}\n${result.stderr}`);
    assert(!(result.stderr || "").includes(SDK_MISSING_STDERR.trim()), result.stderr || "");
    assert(!(result.stderr || "").includes("\n    at "), result.stderr || "");
    assert((result.stderr || "").startsWith("mayi: "), result.stderr || "");
    assert(!(result.stdout || "").trim(), result.stdout || "");
    assert(!existsSync(audit), "a tool call was audited");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("stdio allow and deny still work when the SDK is not installed", async () => {
  const dir = stageWithoutSdk();
  try {
    const { policy, audit } = writePolicy(dir);
    const childPath = join(dir, "child.mjs");
    writeFileSync(childPath, `
      let buf = "";
      process.stdin.on("data", (chunk) => {
        buf += chunk.toString();
        let nl;
        while ((nl = buf.indexOf("\\n")) !== -1) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (!line) continue;
          const msg = JSON.parse(line);
          const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
          if (msg.method === "initialize") {
            reply({ protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "stdio-child", version: "0" } });
          } else if (msg.method === "tools/call") {
            reply({ content: [{ type: "text", text: "from-stdio-child:" + msg.params.name }] });
          } else if (msg.id !== undefined && msg.method) {
            reply({});
          }
        }
      });
    `);
    const proxy = startProxy(
      ["--policy", policy, "--audit", audit, "--", node, childPath],
      {},
      { entry: join(dir, "mayi.mjs"), cwd: dir },
    );
    try {
      await proxy.stderr.until("[CONFIG] policy:");
      assert(!proxy.stderr.text.includes(SDK_MISSING_STDERR.trim()), proxy.stderr.text);
      assert(!proxy.stderr.text.includes("@modelcontextprotocol/sdk"), proxy.stderr.text);
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: "hi" }));
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "from-stdio-child:echo", JSON.stringify(allowed));
      send(proxy.child, toolCall(3, "secret_tool"));
      const denied = JSON.parse(await proxy.stdout.nextLine());
      assert(denied.error && denied.error.message.includes("Blocked by policy"), JSON.stringify(denied));
      const entries = readAudit(audit);
      assert(entries.map((entry) => entry.verdict).join(",") === "allow,deny", JSON.stringify(entries));
      assert(!proxy.stdout.text.includes("from-stdio-child:secret_tool"), proxy.stdout.text);
    } finally {
      stop(proxy.child);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("unreachable upstream exits non-zero and does not allow a call", async () => {
  const dir = tempDir();
  const parked = createServer();
  await new Promise((resolve) => parked.listen(0, "127.0.0.1", resolve));
  const { port } = parked.address();
  await new Promise((resolve) => parked.close(resolve));
  const url = `http://127.0.0.1:${port}/mcp`;
  try {
    const { policy, audit } = writePolicy(dir);
    const result = spawnSync(node, [mayiPath, "--policy", policy, "--audit", audit, "--upstream-url", url], {
      encoding: "utf8",
      input: JSON.stringify(toolCall(2, "echo", { text: "nope" })) + "\n",
      timeout: 8000,
    });
    assert(result.status === 1, `status ${result.status}\n${result.stderr}`);
    assert((result.stderr || "").includes("upstream unreachable"), result.stderr || "");
    assert(!(result.stderr || "").includes("CHILD_RAN"), result.stderr || "");
    assert(!(result.stdout || "").includes("echo:"), result.stdout || "");
    assert(!(result.stdout || "").includes('"result"'), result.stdout || "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("upstream drop mid-session errors the pending call instead of allowing it", async () => {
  const dir = tempDir();
  const fixture = await startStreamable();
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--upstream-url", fixture.url]);
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: "before" }));
      const first = JSON.parse(await proxy.stdout.nextLine());
      assert(first.result?.content?.[0]?.text === "echo:before", JSON.stringify(first));
      send(proxy.child, toolCall(3, "hold"));
      await Promise.race([
        fixture.holdStarted,
        new Promise((_, reject) => setTimeout(() => reject(new Error("hold never reached the server")), 8000)),
      ]);
      fixture.drop();
      const dropped = JSON.parse(await proxy.stdout.nextLine());
      assert(dropped.error && !dropped.result, JSON.stringify(dropped));
      assert(dropped.error.message.startsWith("Upstream error:"), JSON.stringify(dropped));
      send(proxy.child, toolCall(4, "echo", { text: "after" }));
      const after = JSON.parse(await proxy.stdout.nextLine());
      assert(after.error && !after.result, JSON.stringify(after));
      const entries = readAudit(audit);
      assert(entries.map((entry) => entry.verdict).join(",") === "allow,allow(upstream-error),allow(upstream-error)", JSON.stringify(entries));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("a granted call that loses the upstream is not an allow", async () => {
  const dir = tempDir();
  const fixture = await startStreamable();
  try {
    const policy = join(dir, "policy.yaml");
    const audit = join(dir, "audit.jsonl");
    writeFileSync(policy, "rules:\n  - tool: ask_tool\n    action: ask\n");
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--upstream-url", fixture.url]);
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      await initialize(proxy, { elicitation: { form: {} } });
      send(proxy.child, toolCall(2, "ask_tool", { text: "once" }));
      const elicit = JSON.parse(await proxy.stdout.nextLine());
      assert(elicit.method === "elicitation/create", JSON.stringify(elicit));
      assert(elicit.params?.requestedSchema?.properties?.scope, "grants should ask once or session");
      send(proxy.child, {
        jsonrpc: "2.0",
        id: elicit.id,
        result: { action: "accept", content: { approve: "approve", scope: "session" } },
      });
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "echo:once", JSON.stringify(allowed));
      assert(proxy.stderr.text.includes("[GRANT] tool=ask_tool rule=ask_tool ttl="), proxy.stderr.text);
      fixture.drop();
      send(proxy.child, toolCall(3, "ask_tool", { text: "again" }));
      const dropped = JSON.parse(await proxy.stdout.nextLine());
      assert(dropped.error && !dropped.result, JSON.stringify(dropped));
      assert(dropped.method !== "elicitation/create", "the grant should apply without asking again");
      assert(dropped.error.code === -32000, JSON.stringify(dropped));
      const entries = readAudit(audit);
      assert(
        entries.map((entry) => entry.verdict).join(",") === "ask→approved,ask→granted(session,upstream-error)",
        JSON.stringify(entries),
      );
      assert(!entries.some((entry) => entry.verdict === "allow" || entry.verdict === "ask→granted(session)"), JSON.stringify(entries));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("sse transport forwards an allow", async () => {
  const dir = tempDir();
  const fixture = await startSse();
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(["--policy", policy, "--audit", audit, "--transport", "sse", "--upstream-url", fixture.url]);
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      assert(proxy.stderr.text.includes("upstream: sse "), proxy.stderr.text);
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: "sse" }));
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === "echo:sse", JSON.stringify(allowed));
      assert(readAudit(audit)[0].verdict === "allow", readFileSync(audit, "utf8"));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("bearer token is sent and is absent from stderr and the audit file", async () => {
  const dir = tempDir();
  const token = "mayi-test-bearer-7f3c9e2a";
  const fixture = await startStreamable({ bearer: token });
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(
      ["--policy", policy, "--audit", audit, "--audit-include-args", "--upstream-url", fixture.url, "--bearer-env", "MAYI_TEST_TOKEN"],
      { MAYI_TEST_TOKEN: token },
    );
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      assert(proxy.stderr.text.includes("bearer from env MAYI_TEST_TOKEN"), proxy.stderr.text);
      await initialize(proxy);
      send(proxy.child, toolCall(2, "echo", { text: token }));
      const allowed = JSON.parse(await proxy.stdout.nextLine());
      assert(allowed.result?.content?.[0]?.text === `echo:${token}`, JSON.stringify(allowed));
      const stderr = proxy.stderr.text;
      const auditText = readFileSync(audit, "utf8");
      assert(!stderr.includes(token), "token leaked to stderr");
      assert(!auditText.includes(token), `token leaked to audit: ${auditText}`);
      assert(auditText.includes("[redacted]"), auditText);
      const entries = readAudit(audit);
      assert(entries[0].verdict === "allow" && entries[0].args.text === "[redacted]", JSON.stringify(entries));
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

await check("sse bearer token is required on the opening stream", async () => {
  const dir = tempDir();
  const token = "mayi-test-sse-bearer-91ab";
  const fixture = await startSse({ bearer: token });
  try {
    const { policy, audit } = writePolicy(dir);
    const proxy = startProxy(
      ["--policy", policy, "--audit", audit, "--upstream-url", fixture.url, "--transport", "sse", "--bearer-env", "MAYI_SSE_TOKEN"],
      { MAYI_SSE_TOKEN: token },
    );
    try {
      await proxy.stderr.until("[CONFIG] upstream: connected");
      assert(fixture.sawBearer(), "SSE server never saw the bearer header");
      assert(!proxy.stderr.text.includes(token), "token leaked to stderr");
    } finally {
      stop(proxy.child);
    }
  } finally {
    fixture.drop();
    rmSync(dir, { recursive: true, force: true });
  }
});

function runMayi(args, env = {}) {
  return spawnSync(node, [mayiPath, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 8000,
  });
}

await check("bad upstream flags are startup errors and do not fail open", async () => {
  const child = [node, "-e", "console.error('CHILD_RAN')"];
  const both = runMayi(["--upstream-url", "http://127.0.0.1:9/mcp", "--", ...child]);
  assert(both.status === 1, both.stderr || "");
  assert((both.stderr || "").includes("cannot be combined"), both.stderr || "");
  assert(!(both.stderr || "").includes("CHILD_RAN") && !(both.stdout || "").includes("CHILD_RAN"), "child started");

  const transportOnly = runMayi(["--transport", "sse", "--", ...child]);
  assert(transportOnly.status === 1, transportOnly.stderr || "");
  assert((transportOnly.stderr || "").includes("require --upstream-url"), transportOnly.stderr || "");
  assert(!(transportOnly.stderr || "").includes("CHILD_RAN"), transportOnly.stderr || "");

  const badTransport = runMayi(["--upstream-url", "http://127.0.0.1:9/mcp", "--transport", "stdio"]);
  assert(badTransport.status === 1, badTransport.stderr || "");
  assert((badTransport.stderr || "").includes("must be http or sse"), badTransport.stderr || "");
  assert(!(badTransport.stderr || "").includes("upstream: connected"), badTransport.stderr || "");

  const userinfo = runMayi(["--upstream-url", "http://user:s3cret-password@127.0.0.1:9/mcp"]);
  assert(userinfo.status === 1, userinfo.stderr || "");
  assert((userinfo.stderr || "").includes("username or password"), userinfo.stderr || "");
  assert(!(userinfo.stderr || "").includes("s3cret-password"), userinfo.stderr || "");

  const emptyBearer = runMayi(["--upstream-url", "http://127.0.0.1:9/mcp", "--bearer-env", "MAYI_EMPTY_TOKEN"], { MAYI_EMPTY_TOKEN: "" });
  assert(emptyBearer.status === 1, emptyBearer.stderr || "");
  assert((emptyBearer.stderr || "").includes("unset or empty"), emptyBearer.stderr || "");

  const missing = runMayi(["--upstream-url"]);
  assert(missing.status === 1, missing.stderr || "");
  assert((missing.stderr || "").includes("needs a value"), missing.stderr || "");
});

await check("help lists --upstream-url", async () => {
  const help = runMayi(["--help"]);
  assert(help.status === 0 && (help.stdout || "").includes("--upstream-url"), help.stdout || "");
  assert((help.stdout || "").includes("--transport"), help.stdout || "");
  assert((help.stdout || "").includes("--bearer-env"), help.stdout || "");
});

if (process.exitCode) {
  console.error("HTTP transport checks failed");
  process.exit(process.exitCode);
}
console.log("all HTTP transport checks passed");
