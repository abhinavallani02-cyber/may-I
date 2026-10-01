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

Early and small. Stdio is the default. It has been tested against
`@modelcontextprotocol/server-filesystem` that way, and the suite also
stands up a local streamable-HTTP server (and a legacy SSE server) to
exercise `--upstream-url`. OAuth is not implemented. Policy matching is a
tool-name glob, then a structural check only when a rule asks for one:
a canonical `path_prefix`, or `sql.single` for one SQL statement of a
named type. There is no general condition language yet. It has not had a
security review. Treat it as a working prototype, not a hardened boundary.

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
mayi [--rules <pack>] [--policy <file>] [--audit <file>] [--audit-include-args] [--elicit-autodecline-ms <n>] [--grant-ttl <seconds>] -- <command> [args...]
mayi [--rules <pack>] [--policy <file>] [--audit <file>] [--audit-include-args] [--elicit-autodecline-ms <n>] [--grant-ttl <seconds>] --upstream-url <url> [--transport http|sse] [--bearer-env <NAME>]
```

Stdio is the default. Everything after `--` is the real MCP server to
spawn and front. `--upstream-url` is the other mode: may-i connects to
a remote MCP endpoint and the client still talks stdio to may-i. The
two are mutually exclusive. Passing both, or passing `--transport` /
`--bearer-env` without `--upstream-url`, is a startup error. may-i
exits before it spawns a child or accepts tool calls. For example, to
guard the filesystem server with your own policy:

```
mayi --policy policy.yaml --audit audit.jsonl -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

Point your MCP client at `mayi` (with its arguments) instead of at the
real server directly — may-i spawns the real server itself and speaks the
same stdio protocol on its own stdin/stdout, so from the client's
perspective nothing else changes.

Flags:

- `--rules <pack>` — load a rule pack shipped with may-i:
  `filesystem`, `git`, `github`, or `postgres` (`rules/<pack>.yaml` next
  to the program, not in the working directory). The name is not a path.
  Anything else — an unknown name, a slash, `..`, a blank — is a startup
  error. may-i exits before it spawns the server. It does not fall back
  to `./policy.yaml`, the built-in policy, or allow.
- `--policy <file>` — path to the policy YAML file. Defaults to
  `policy.yaml` in the current directory if it exists and `--rules` was
  not given, otherwise the built-in default described above.
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
- `--upstream-url <url>` — connect to a remote MCP server instead of
  spawning one. `http` or `https` only. A URL with a username or
  password is a startup error. If the endpoint is unreachable, may-i
  exits non-zero before it reads client traffic. It does not fall open
  and answer calls itself.
- `--transport http|sse` — which SDK client transport to use.
  `http` (the default) is `StreamableHTTPClientTransport`. `sse` is
  `SSEClientTransport`. There is no automatic fallback: if streamable
  HTTP fails, may-i exits. It does not try SSE on its own. Point
  `--transport sse` at an SSE endpoint when that is the server you mean.
  Requires `--upstream-url`.
- `--bearer-env <NAME>` — read a bearer token from the environment
  variable `NAME` and send `Authorization: Bearer <value>` on upstream
  requests. For SSE, the same header is sent on the opening event
  stream and on later POSTs. The value is never written to stderr or
  to the audit file (arguments that contain it are stored as
  `[redacted]`). If `NAME` is not an environment-variable name, or the
  variable is missing or empty, may-i exits before connecting. Requires
  `--upstream-url`.
- `-h`, `--help` — print usage and exit.

`--rules` and `--policy` combine by concatenation, pack first. Flag
order on the command line does not change that. First match still wins,
so a pack `deny` or `ask` is not relaxed by an `allow` later in
`--policy`. The policy file only sees calls the pack did not match.
`--rules` alone does not also read `./policy.yaml`. Packs shipped here
do not end with `tool: "*"`, so a policy file can still name a tool the
pack left out. If nothing matches, the call asks.

```
mayi --rules postgres --policy extra.yaml -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb
```

That checks `rules/postgres.yaml`, then `extra.yaml`.

## Remote servers

```
mayi --policy policy.yaml --upstream-url http://127.0.0.1:3000/mcp --bearer-env MAYI_TOKEN
mayi --policy policy.yaml --upstream-url http://127.0.0.1:3000/sse --transport sse
```

`@modelcontextprotocol/sdk` and `zod` are optional peers. npm does not
install optional peers, so a stdio install of may-i does not include
them. `zod` is only there because the SDK peers it. Install the SDK
beside may-i when you use `--upstream-url`:

```
npm install @modelcontextprotocol/sdk
```

Current SDK releases depend on `zod` and install it with that command.
If yours does not, install `zod` too. If the SDK cannot be imported,
may-i exits 1 before it reads or answers client traffic, prints no
stack trace, and writes exactly this line to stderr:

```
HTTP transport requires @modelcontextprotocol/sdk. Install it with npm install @modelcontextprotocol/sdk.
```

may-i opens the upstream with `@modelcontextprotocol/sdk`'s
`StreamableHTTPClientTransport` or `SSEClientTransport` before it
handles client traffic. The SDK performs that session's initialize.
The client's own `initialize` is answered locally from the upstream
server's advertised capabilities. `notifications/initialized` is
accepted and not forwarded. `tools/list`, `ping`, and `tools/call` are
forwarded. Any other request gets a JSON-RPC error. It is not treated
as an allow.

`tools/call` still goes through policy first. `deny`, and an `ask`
that is not approved, never reach the upstream. An approved call that
the upstream does not answer — the connection refused at startup is
already an exit; a drop mid-session is an error on that call — is
audited as `allow(upstream-error)` or
`ask→approved(upstream-error)`, and the client receives a JSON-RPC
error rather than a tool result. A tty-fallback approval that then
loses the upstream is
`ask→approved(tty-fallback,upstream-error)`.

OAuth is out of scope. may-i does not run the MCP OAuth flow, open a
browser, register a client, or refresh a token. A server that expects
a bearer token already in hand is the `--bearer-env` case above.
Any other authentication has to happen outside may-i.

Working on may-i itself? Clone the repo and run it straight from source
instead of installing — replace `mayi` above with `node mayi.mjs`:

```
git clone https://github.com/abhinavallani02-cyber/mayI
cd mayI && npm install
node mayi.mjs -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

## Policy

A policy file is a list of rules, checked in order — the first matching
rule wins. The tool name is a glob (`*` matches any run of characters)
and is always the first check. Structural checks run only after that
glob matches, and only when the rule declares them.

```yaml
rules:
  - tool: read_*
    action: allow

  - tool: write_file
    path_prefix: /etc
    action: deny

  - tool: query
    sql:
      single: select
    action: allow

  - tool: query
    action: deny

  - tool: write_*
    action: ask

  - tool: "*"
    action: ask
```

`path_prefix` is checked against `path`, `source`, `destination`, and
`repo_path` (the argument mcp-server-git uses).
The value is canonicalized before the comparison, so `..`, `.`, and
duplicate slashes cannot walk out of it: `path_prefix: /prod` matches
`/prod`, `/prod/db`, `/prod/../prod/db`, `/prod//db`, and `/prod/./db`.
The match is on path segments, so `/prod` does not match `/production`
or `/prod-backup`.

Symlinks: if the path exists, may-i uses `realpath`. If it does not,
may-i `realpath`s the longest existing ancestor and appends the rest
lexically, so a file that is not created yet still counts as living in
the directory a symlink points at. If no ancestor exists, the check
stays lexical. A deny or ask rule matches when either the path as
written or that resolved path is inside the prefix, which is how a
symlink into `/etc` still hits a `/etc` deny. An allow rule matches
only when every present path argument resolves inside the prefix, so
`source` inside `/safe` and `destination` outside it does not match an
allow for `/safe`. The prefix itself is `realpath`'d when that path
exists, so a rule written against a symlink and a call written against
its target see the same directory. Relative paths and relative prefixes
are resolved against the process's current directory. If resolution
fails for another reason (permissions, a symlink loop, a null byte, or
a path argument that is not a string), the allow rule does not match
and later allow rules are skipped for that call.

`sql.single` asks for exactly one statement whose leading verb is the
given name, or one of a list (`single: [select, with]`). The verb match
is case-insensitive. The text is read from `sql`, `query`, or
`statement` (every one of those that is present has to satisfy the
rule). Quotes, `--` and `/* */` comments, and PostgreSQL dollar quotes
are recognized, so a semicolon inside them does not start another
statement:

```sql
SELECT 1; DROP TABLE users                         -- two statements, no match
SELECT 1; /* hidden */ DROP TABLE users            -- two statements, no match
SELECT 1 -- comment
; DROP TABLE users                                 -- two statements, no match
SELECT 'text; still text';                         -- one SELECT
SELECT 1 /* ; DROP TABLE users */;                 -- one SELECT
SELECT $$ ; still the same statement $$;           -- one SELECT
```

A compound statement does not match `sql.single`. An unparseable one
does not either: an unclosed quote, an unclosed comment, an unclosed
dollar quote, no statement at all, or a null byte. In both cases the
allow rule does not match, and no later allow rule can match that call
either. The call falls through to a later deny or ask, or to the
default ask. It is never allowed by a rule that asked for a single
safe statement. A later rule with no `sql` key can still allow a
*different*, well-formed single statement (an `insert` allow placed
after a `select` allow). It cannot allow `SELECT 1; DROP TABLE users`.

This is a statement splitter, not a full SQL parser, and it does not
send the statement anywhere. It does not understand statement bodies.
`SELECT ... INTO`, `COPY`, and a function that writes can still match
`single: select`. `EXPLAIN DELETE` is an `explain`, not a `delete`.
`WITH ... SELECT` and `WITH ... DELETE` are both `with`; allowing
`with` does not look at the statement after the CTE. List `with` only
when that is acceptable.
MySQL `#` comments are not comments here; a semicolon after `#` looks
like another statement and the allow does not match. Backslash escapes
inside quotes are not honored, so some MySQL strings look unparseable
and fail closed rather than matching.

When that check blocks an allow — compound or unparseable SQL, or a
path that cannot be resolved — the audit verdict is annotated
`blocked-allow`. A later deny is `deny(blocked-allow)`. A later ask is
`ask→denied(blocked-allow)`, `ask→approved(blocked-allow)`, or
`ask→cancelled(blocked-allow)`. A tty fallback keeps its own label and
adds this one: `ask→approved(tty-fallback,blocked-allow)` or
`ask→denied(tty-fallback,blocked-allow)`. A normal deny or ask, where
no allow was blocked, stays `deny` or `ask→…` with no annotation.

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
- A grant does not cover a call whose `allow` was structurally blocked
  (compound or unparseable SQL, or a path that could not be resolved),
  and approving that call does not create one. Pack rules are compiled
  in front of `--policy`, and the grant key uses that combined position,
  so the same rule text at a different index does not share a grant.

## Rule packs

`rules/` holds a policy for each server below. Each file's header names
the package version and what the pack allows, asks, and denies.
`npm test` checks every rule against that server's tool list: a glob or
name that matches nothing is a failure. `filesystem` is checked by
spawning `@modelcontextprotocol/server-filesystem` and calling
`tools/list`. `git`, `github`, and `postgres` are checked against
`rules/snapshots/*.json`, each captured the same way from the real
package because those servers are not installed with may-i.

| Pack | Server | Tool list |
| --- | --- | --- |
| `filesystem` | `@modelcontextprotocol/server-filesystem` 2026.7.10 | live `tools/list` |
| `git` | `mcp-server-git` 2026.8.18 (PyPI) | snapshot of `tools/list` |
| `github` | `github/github-mcp-server` v1.12.2, `stdio --toolsets=all` | snapshot of `tools/list` |
| `postgres` | `@modelcontextprotocol/server-postgres` 0.6.2 | snapshot of `tools/list` |

```
mayi --rules filesystem -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow
```

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
verdict. When a structural check blocked an allow before this decision,
the same verdict carries `blocked-allow` as well: `deny(blocked-allow)`,
`ask→denied(blocked-allow)`, or
`ask→approved(tty-fallback,blocked-allow)`. A grant is not applied in
that case, so the verdict is not `ask→granted(session)`. See
[Policy](#policy). When an HTTP or SSE upstream accepts the policy
decision but does not return a result (the session dropped, or the
request failed in transit), the verdict is `allow(upstream-error)`,
`ask→approved(upstream-error)`,
`ask→approved(tty-fallback,upstream-error)`, or, when the call was
allowed by a session grant, `ask→granted(session,upstream-error)`.
That is not an allow: the client is sent an error, and the call is
not retried.

By default the log records only the decision: timestamp, request id, tool
name, and verdict. It does **not** include the call's arguments — file
paths, file contents, or anything else passed to the tool — because
arguments can carry sensitive data that shouldn't end up in a plaintext
log file just from running the proxy. Pass `--audit-include-args` to
include them anyway, if you want a more detailed log and understand what
that means for the log file's contents.

Response payloads (what the server actually returned) are never written
to the audit log, in either mode.
