// Remote MCP upstream. The client still talks stdio to may-i. This module
// opens one session to an HTTP server using the SDK's client transports
// and calls tools through that session. It does not speak HTTP itself.
// may-i imports this file only from the guarded loader, and only when
// --upstream-url is set. A stdio run never loads it, so it never loads
// the SDK.
//
// Streamable HTTP is StreamableHTTPClientTransport. SSE is
// SSEClientTransport, selected only when the operator asks for it.
// A failed streamable HTTP connection is not retried as SSE: switching
// protocols after an error would hide a dead endpoint. OAuth is not
// implemented here. A static bearer token, if one was passed in, is sent
// as a header and is never logged.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";

// A dropped session must surface as an error on the call that was in
// flight. The transport's default is to wait and reconnect; that would
// leave a pending tools/call hanging, or complete it later against a
// new session. Zero retries makes the failure immediate.
const NO_RECONNECT = {
  initialReconnectionDelay: 0,
  maxReconnectionDelay: 0,
  reconnectionDelayGrowFactor: 1,
  maxRetries: 0,
};

function bearerHeaders(bearerToken) {
  if (!bearerToken) return undefined;
  return { Authorization: `Bearer ${bearerToken}` };
}

function createTransport(url, transportName, bearerToken) {
  const headers = bearerHeaders(bearerToken);
  const requestInit = headers ? { headers } : undefined;
  if (transportName === "http") {
    return new StreamableHTTPClientTransport(new URL(url), {
      requestInit,
      reconnectionOptions: NO_RECONNECT,
    });
  }
  if (transportName === "sse") {
    // eventSourceInit is the opening GET. requestInit covers the POSTs.
    // Setting eventSourceInit is what attaches the bearer token to the
    // stream; the SDK does not copy requestInit onto that GET.
    const eventSourceInit = headers
      ? {
          fetch(input, init) {
            return fetch(input, {
              ...init,
              headers: { ...init?.headers, ...headers },
            });
          },
        }
      : undefined;
    return new SSEClientTransport(new URL(url), { requestInit, eventSourceInit });
  }
  throw new Error(`unknown transport ${transportName}`);
}

// Resolves once the SDK has finished its own initialize with the
// upstream. A refused connection, a 4xx/5xx, or an SSE stream that
// never opens rejects, and the caller exits. Nothing is allowed
// through before this resolves.
export async function openUpstream({ url, transport, bearerToken }) {
  const sdkTransport = createTransport(url, transport, bearerToken);
  const client = new Client({ name: "may-i", version: "1.0.0" });
  let closed = false;

  function markClosed() {
    closed = true;
  }

  client.onclose = markClosed;
  sdkTransport.onclose = markClosed;
  // The SDK calls onerror with the raw failure. Swallow it here so the
  // default is not an unhandled dump that might include request state.
  // The pending call still rejects, and that path reports the error.
  sdkTransport.onerror = () => {};
  client.onerror = () => {};

  await client.connect(sdkTransport);

  async function callOrClosed(run) {
    if (closed) {
      const err = new Error("upstream closed");
      err.upstreamClosed = true;
      throw err;
    }
    try {
      return await run();
    } catch (err) {
      // A JSON-RPC error from the server (McpError) means this call
      // failed and the session may still be up. A transport failure
      // means later calls must not be treated as delivered.
      if (!(err instanceof McpError)) markClosed();
      throw err;
    }
  }

  return {
    serverVersion: client.getServerVersion() ?? { name: "may-i", version: "1.0.0" },
    capabilities: client.getServerCapabilities() ?? { tools: {} },
    isClosed: () => closed,
    callTool(name, args) {
      return callOrClosed(() => client.callTool({ name, arguments: args }));
    },
    listTools() {
      return callOrClosed(() => client.listTools());
    },
    ping() {
      return callOrClosed(() => client.ping());
    },
    async close() {
      markClosed();
      await client.close().catch(() => {});
    },
  };
}
