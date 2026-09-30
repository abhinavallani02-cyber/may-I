# may-i

[![npm version](https://img.shields.io/npm/v/mayi-mcp.svg)](https://www.npmjs.com/package/mayi-mcp)

may-i is a proxy for [MCP](https://modelcontextprotocol.io) (Model Context
Protocol), the standard AI agents use to call external tools. It sits
between an MCP client (an AI agent) and an MCP server (a set of tools the
agent can call — read/write files, run queries, send messages, and so on),
enforcing a policy on every `tools/call` request before it reaches the
server. For each call it decides `allow`, `deny`, or `ask` — and `ask`
pauses to prompt a human before letting the call through, either through
the client's own UI (MCP elicitation) or, if the client doesn't support
that, at the terminal running may-i.
Everything else (initialization, tool listing, responses, notifications)
passes through unmodified. The goal is that a human can put real limits on
what an agent is allowed to do without needing to trust the agent, or the
server, to enforce them itself.

## Status

Early and small. It has only been tested against one server
(`@modelcontextprotocol/server-filesystem`) over stdio, which is currently
the only transport it supports — no HTTP or SSE. Policy matching is tool
name (with glob support) plus an optional path-prefix check on arguments;
there's no general condition language yet. It has not had a security
review. Treat it as a working prototype, not a hardened boundary.

**`ask` verdicts prefer MCP elicitation, with `/dev/tty` as fallback.** If
the connected client declares the `elicitation` capability at
`initialize`, may-i sends a real `elicitation/create` request toward it —
the approval prompt is meant to render in the client's own UI, not a
terminal. If the client doesn't declare that capability, may-i falls back
to the original `/dev/tty` prompt, which only appears if a human is
watching the actual terminal running `mayi.mjs`.

As of this writing, the elicitation path does not actually work end to
end with Claude Code's VS Code extension — not because of anything on
may-i's side. Verified with a hand-built test client that properly
implements the client side of elicitation: may-i's request, response
handling, and id correlation all work correctly and the call goes
through. Against the real VS Code extension, the same request is silently
auto-declined with no UI ever shown, even though the extension correctly
declares the capability at `initialize`. This is a confirmed, currently
open upstream bug —
[anthropics/claude-code#79174](https://github.com/anthropics/claude-code/issues/79174) —
where interactive VS Code sessions are internally misclassified as
non-interactive ("print mode") specifically for the elicitation path,
even though the same session correctly renders other interactive prompts
(permission dialogs, `AskUserQuestion`). Until that's fixed upstream,
may-i treats a `decline` or `cancel` that arrives faster than a person
could plausibly have answered (under 750ms by default, see
`--elicit-autodecline-ms`) as "the client cannot ask" rather than "the
user said no", and falls back to the `/dev/tty` prompt. A non-accept at
or after that threshold is still a real decision. The fallback fails
closed: no terminal, a timeout, or an error denies the call.

The first default, 250ms, was a guess. It is too low for the one
auto-decline that has actually been reported. The default is now 750ms,
set from these two data points:

- **~400ms — reported by koshak01, not measured by may-i.** On
  [anthropics/claude-code#79174](https://github.com/anthropics/claude-code/issues/79174)
  (comment, 2026-08-11), a headless Claude Code v2.1.227 session
  auto-declined every `elicitation/create` from their Rust MCP server
  (`rmcp` 3.1.2) about 400ms later, with no user interaction. The
  comment says "~400ms". may-i has not reproduced that number.
- **1.8s — measured by may-i.** A real human click in Cursor, timed
  from inspect to the audit verdict `ask→approved`, took 1.8s.

750ms is above that reported ~400ms decline and clear of the 1.8s
click, so the known fast decline still falls back to the terminal and
a person's answer stays a real decision. Still unmeasured: an elicitation
auto-decline from the Claude Code CLI, and one from the VS Code
extension itself. The extension cannot be run in the environment where
this default was set, and no authenticated Claude Code CLI was
available there to time. The ~400ms figure remains koshak01's report
of a headless session.

## Install

No install needed to try it — run it directly with `npx`:

```
npx mayi-mcp -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

Or install it globally:

```
npm install -g mayi-mcp
mayi -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

The package is published as `mayi-mcp`; the command it installs is `mayi`.

With no `--policy` flag and no `policy.yaml` in the current directory,
may-i runs with a built-in conservative default: reads are allowed,
everything else asks. So the commands above work with zero config — it'll
prompt you the first time the agent tries to write, move, or otherwise
change anything.

## Usage

```
mayi [--policy <file>] [--audit <file>] [--audit-include-args] [--elicit-autodecline-ms <n>] [--grant-ttl <seconds>] -- <command> [args...]
```

Everything after `--` is the real MCP server to spawn and front. For
example, to guard the filesystem server with your own policy:

```
mayi --policy policy.yaml --audit audit.jsonl -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

Point your MCP client at `mayi` (with its arguments) instead of at the
real server directly — may-i spawns the real server itself and speaks the
same stdio protocol on its own stdin/stdout, so from the client's
perspective nothing else changes.

Flags:

- `--policy <file>` — path to the policy YAML file. Defaults to
  `policy.yaml` in the current directory if it exists, otherwise the
  built-in default described above.
- `--audit <file>` — path to the audit log. Defaults to `audit.jsonl`.
- `--audit-include-args` — include each call's arguments in the audit log.
  Off by default; see [Audit logging](#audit-logging).
- `--elicit-autodecline-ms <n>` — if an elicitation `decline` or `cancel`
  comes back in less than `<n>` milliseconds, treat it as the client
  auto-declining without showing UI (the Claude Code bug above) and fall
  back to the `/dev/tty` prompt instead of recording a user denial.
  Default `750`. `0` disables the heuristic, so every non-accept is a
  real decision. Must be a non-negative integer. The [Status](#status)
  section records why 750ms replaced the earlier 250ms guess.
- `--grant-ttl <seconds>` — how long a remembered approval stays in
  effect. Default `1800` (30 minutes). `0` disables session grants, so
  every `ask` asks and the remember option is not offered. Must be a
  non-negative integer. See [Session grants](#session-grants).
- `-h`, `--help` — print usage and exit.

Working on may-i itself? Clone the repo and run it straight from source
instead of installing — replace `mayi` above with `node mayi.mjs`:

```
git clone https://github.com/abhinavallani02-cyber/mayI
cd mayI && npm install
node mayi.mjs -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

## Policy

A policy file is a list of rules, checked in order — the first matching
rule wins. Each rule matches on the tool name (supporting `*` as a glob)
and, optionally, a `path_prefix` checked against the call's `path`,
`source`, or `destination` argument, whichever is present.

```yaml
rules:
  - tool: read_*
    action: allow

  - tool: write_file
    path_prefix: /etc
    action: deny

  - tool: write_*
    action: ask

  - tool: "*"
    action: allow
```

The three actions:

- **`allow`** — the call is forwarded to the server immediately, no
  logging beyond the normal verdict line.
- **`deny`** — the call never reaches the server. may-i sends a JSON-RPC
  error back to the client on the same request id instead.
- **`ask`** — may-i prompts a human and waits up to 30 seconds. With
  elicitation support, the form asks whether to approve and, unless
  session grants are disabled, whether to remember that approval (see
  [Session grants](#session-grants)). Otherwise it prompts on `/dev/tty`:
  `y` approves this call, `n` denies it, and `a` approves and remembers
  (`a` is not offered when grants are disabled). Any other answer, or a
  timeout, denies the call. An approval is forwarded like `allow`; a
  denial is rejected like `deny`. If there's no controlling terminal to
  ask (e.g. may-i's own input/output are both piped, with no tty
  attached), `ask` resolves to deny — there's no human to ask, so the
  safe default applies.

If no rule matches a call, may-i defaults to `ask` rather than silently
allowing it.

## Session grants

An approval can be remembered so the same kind of call doesn't prompt
again for a while. The human chooses that at approval time.

- **Elicitation** asks two things: approve or deny, and a scope. `once`
  is the default and covers this call only. `session` remembers the
  approval. If `scope` is missing or is any value other than `session`,
  nothing is remembered.
- **`/dev/tty`** accepts `y` (approve once), `n` (deny), and `a`
  (approve and remember). Only `a` creates a grant. A fast elicitation
  auto-decline never does — if that fallback then gets an `a`, the
  grant comes from that answer, not from the decline.
- The grant key is the **tool name plus the matched policy rule**, not
  the call's arguments. A rule's `path_prefix` (when it has one) is
  already the argument scope the policy author wrote down, so
  `sandbox/a` and `sandbox/b` can share a grant while a `write_file`
  that matched a different rule cannot. The rule's identity is its
  position in the policy plus its content, so two rules that would
  otherwise look the same do not share a grant, and an edited rule
  does not inherit an old one. A different tool name asks again even
  when it matches the same glob. If there's any doubt the grant
  applies, may-i asks again.
- Grants apply only to **`ask` rules**. A `deny` is never grantable.
  If the rule that matches a later call is `deny` — including after
  the policy is changed so a previously approved call now hits a deny
  rule — the grant is not used.
- Grants live in memory for this process only. They are not written
  to disk and disappear when may-i exits. `--grant-ttl` bounds each
  one (default 30 minutes). Expired grants are removed the next time
  an `ask` is checked, not by a background timer.
- `--grant-ttl 0` turns this off, and the remember option is not
  offered. The scope question is omitted from the elicitation form; a
  `session` scope sent anyway is ignored, and that approval applies to
  the one call only. The tty prompt stays `y`/`n`, and `a` is not an
  approval in that mode. Every `ask` asks.

## Audit logging

Every verdict — `allow`, `deny`, or an `ask` outcome — is appended to
the audit log as one JSON object per line:

```json
{"timestamp":"2026-08-09T03:21:42.139Z","id":3,"tool":"write_file","verdict":"ask→approved"}
```

`ask` verdicts are `ask→approved`, `ask→denied`, or `ask→cancelled`.
A later call allowed because a human remembered an earlier approval is
`ask→granted(session)`. That is not a plain `allow`: `allow` means the
policy itself let the call through, and `ask→granted(session)` means a
human allowed this tool and rule earlier in the process. The call that
creates the grant is still `ask→approved` (or `ask→approved(tty-fallback)`
when the terminal prompt was the one that answered). When a too-fast
elicitation decline or cancel was treated as the client being unable to
ask, and the terminal prompt decided instead, the verdict is
`ask→approved(tty-fallback)` or `ask→denied(tty-fallback)`, so the log
shows that fallback apart from a normal answer. A fallback that cannot
ask (no tty, timeout, or error) is `ask→denied(tty-fallback)` — never an
allow. Creating a grant also logs a stderr line,
`[GRANT] tool=<name> rule=<rule> ttl=<seconds>s`, which is not an audit
verdict.

By default the log records only the decision: timestamp, request id, tool
name, and verdict. It does **not** include the call's arguments — file
paths, file contents, or anything else passed to the tool — because
arguments can carry sensitive data that shouldn't end up in a plaintext
log file just from running the proxy. Pass `--audit-include-args` to
include them anyway, if you want a more detailed log and understand what
that means for the log file's contents.

Response payloads (what the server actually returned) are never written
to the audit log, in either mode.
