# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The 1.1.0 notes are the difference between published `mayi-mcp@1.0.0` and this
release. The published tarball is byte-for-byte `fc31732` ("Publish as mayi-mcp").
How that commit was identified is in the 1.1.0 pull request.

## [1.1.0] - 2026-09-30

### Added

- `--rules <pack>` loads `rules/<pack>.yaml` shipped next to the program.
  Packs: `filesystem`, `git`, `github`, `postgres`. The name is not a path:
  a slash, `..`, a blank, or an unknown name is a startup error, before a
  child is spawned and before `./policy.yaml` or the built-in policy is
  used. Pack rules are compiled in front of `--policy`. Flag order does
  not change that. `--rules` without `--policy` does not read
  `./policy.yaml`. Packs do not end with `tool: "*"`, so an unmatched tool
  falls through to `--policy` if one was given, then to the default ask.
  (`9b3fd0d`)
- `rules/filesystem.yaml` (server `@modelcontextprotocol/server-filesystem`
  2026.7.10): allow `read_*`, `list_*`, `directory_tree`, `get_file_info`,
  `search_files`. Deny `write_*`, `edit_*`, `move_*`, and `create_*` when
  the path check lands under `/etc` or `/prod`. Ask for every other
  `write_*`, `edit_*`, `move_*`, and `create_*`. (`9b3fd0d`)
- `rules/git.yaml` (server `mcp-server-git` 2026.8.18, which has no push
  tool): allow `git_status`, `git_diff*`, `git_log`, `git_show`,
  `git_branch`. Ask for `git_add`, `git_commit`, `git_reset`,
  `git_checkout`, `git_create_branch`. This pack does not set
  `path_prefix` on `repo_path`. (`9b3fd0d`)
- `rules/github.yaml` (server `github/github-mcp-server` v1.12.2, `stdio
  --toolsets=all`): allow the read globs and named read tools listed in
  that file. Ask for the write globs and named mutating tools listed
  there. (`9b3fd0d`)
- `rules/postgres.yaml` (server `@modelcontextprotocol/server-postgres`
  0.6.2, tool `query`, argument `sql`): allow one `select` statement.
  Deny every other `query` call. (`9b3fd0d`)
- `sql.single` on a rule: one statement whose leading verb is the given
  name, or one of a list (`single: [select, with]`). The verb match is
  case-insensitive. Text is read from `sql`, `query`, and `statement`;
  every one of those that is present has to satisfy the rule. Quotes,
  `--` and `/* */` comments, and PostgreSQL dollar quotes are recognized.
  A compound statement does not match. An unparseable statement does not
  match: unclosed quote, unclosed comment, unclosed dollar quote, no
  statement, or a null byte. In both cases that allow does not match, and
  no later allow rule can match that call either. A later deny or ask
  still can. If nothing matches, the call asks. (`feff3ef`)
- `--elicit-autodecline-ms <n>`. Default `750`. `0` disables it. A
  non-negative integer. An elicitation `decline` or `cancel` that arrives
  in less than `<n>` milliseconds is treated as the client auto-declining
  with no UI, and may-i falls back to the `/dev/tty` prompt. A non-accept
  at or after `<n>` milliseconds is the decision: `decline` is
  `ask→denied`, `cancel` is `ask→cancelled`. An explicit accept is not
  timed. The fallback fails closed: no terminal, a timeout, or an error
  denies the call. (`a105cf1` added this with default `250`; `91ec0a7`
  set the default to `750`.)
- `--grant-ttl <seconds>`. Default `1800` (30 minutes). `0` disables
  session grants. A non-negative integer. Grants are in memory for this
  process only. They are not written to the audit log or anywhere else
  on disk, and they disappear when may-i exits. The key is the tool name
  plus the matched rule's index and content, not the call arguments.
  Grants apply only to `ask` rules. A `deny` is never covered. A grant is
  not applied, and approving the call does not create one, when a
  structural check blocked an allow. Pack rules sit in front of
  `--policy`, and the key uses that combined index. Creating a grant
  logs `[GRANT] tool=<name> rule=<rule> ttl=<seconds>s` on stderr. That
  line is not an audit verdict. The call that creates the grant is still
  `ask→approved` (or `ask→approved(tty-fallback)`). A later call covered
  by the grant is `ask→granted(session)`. (`e50193b`, `f02b336`)
- `--upstream-url <url>` fronts a remote MCP server instead of spawning
  a child. `http` or `https` only. A URL with a username or password is
  a startup error. Mutually exclusive with a child command. If the
  endpoint is unreachable, may-i exits non-zero before it reads client
  traffic. `--transport http|sse`: `http` is the default (streamable
  HTTP). `sse` is used only when named. A failed `http` connection does
  not switch to `sse`. `--transport` and `--bearer-env` require
  `--upstream-url`. `--bearer-env <NAME>` reads a bearer token from that
  environment variable and sends `Authorization: Bearer`. The value is
  not written to stderr or the audit file. With `--audit-include-args`,
  argument text that contains the token is stored as `[redacted]`. If
  `NAME` is not an environment-variable name, or the variable is missing
  or empty, may-i exits before connecting. OAuth is not implemented.
  (`cc09c5c`)
- `@modelcontextprotocol/sdk` and `zod` are optional peerDependencies
  (`^1.31.0` and `^4.6.5`). `npm install mayi-mcp` does not install them.
  `--upstream-url` loads the SDK only on that path. If
  `@modelcontextprotocol/sdk` itself cannot be resolved, may-i exits 1
  before client traffic and writes this line to stderr, with no stack
  trace: `HTTP transport requires @modelcontextprotocol/sdk. Install it with npm install @modelcontextprotocol/sdk.`
  Any other load failure, including a missing `zod`, also exits 1 before
  client traffic, with `mayi:` and the error message, and no stack trace.
  (`cc09c5c` added the HTTP path and depended on the SDK and `zod`;
  `3ed407d` made both optional peers and added the missing-SDK line.)
- Audit verdicts that 1.0.0 did not produce: `ask→cancelled`;
  `ask→approved(tty-fallback)` and `ask→denied(tty-fallback)`;
  `ask→granted(session)`; `blocked-allow` inside the verdict when a
  structural check blocked an allow (`deny(blocked-allow)`,
  `ask→denied(blocked-allow)`, `ask→approved(blocked-allow)`,
  `ask→cancelled(blocked-allow)`,
  `ask→approved(tty-fallback,blocked-allow)`,
  `ask→denied(tty-fallback,blocked-allow)`); `upstream-error` when an
  HTTP or SSE upstream accepts the policy decision but does not return a
  result (`allow(upstream-error)`, `ask→approved(upstream-error)`,
  `ask→approved(tty-fallback,upstream-error)`,
  `ask→granted(session,upstream-error)`). The client gets a JSON-RPC
  error in the upstream-error cases, not a tool result, and the call is
  not retried. (`42a1239`, `a105cf1`, `e50193b`, `9b3fd0d`, `cc09c5c`)
- Startup logs on stderr: `[CONFIG] elicitation: ...`,
  `[CONFIG] elicit auto-decline: 750ms` (or `off`),
  `[CONFIG] session grants: 1800s` (or `off`). (`42a1239`, `a105cf1`,
  `e50193b`, `91ec0a7`)
- Published files now include `structural.mjs` (`feff3ef`), `rules/`
  (`9b3fd0d`, including `rules/snapshots/`), `upstream.mjs` (`cc09c5c`),
  and `CHANGELOG.md`. `manual-diff.mjs` is in the repository only. It is
  not in the `files` list. It takes policy, audit, and server paths as
  arguments (`626909e`, `46927c9`).

### Changed

- `ask` when the client declares `elicitation.form` or `elicitation.url`
  on `initialize`: may-i sends `elicitation/create` (`mode: form`) and
  does not open `/dev/tty` first. The form's `approve` field is `approve`
  or `deny`. When grants are enabled, `scope` is `once` (default) or
  `session`, and a missing scope does not remember. When `--grant-ttl`
  is `0`, the scope field is omitted, and a `session` value sent anyway
  is ignored. The elicitation id is `mayi-elicit-<n>`. The reply is
  consumed by may-i and is not forwarded. The wait is still 30 seconds,
  then deny. Only `action: accept` with `content.approve === "approve"`
  approves. (`42a1239`, `e50193b`)
- `/dev/tty` when the client does not declare elicitation, and when a
  fast auto-decline falls back: the prompt is `y/n/a` while grants are
  enabled. `y` approves this call only. `a` approves and remembers for
  the grant TTL. `n`, any other answer, and the 30 second timeout deny.
  In 1.0.0 the prompt was `y/n`, and any answer other than `y`, including
  `a`, denied. With `--grant-ttl 0` the prompt is `y/n` again, and `a`
  denies. No tty still denies. (`e50193b`)
- `path_prefix` is no longer `String.prototype.startsWith` on `path`,
  `source`, and `destination`. It is a canonical, segment-bounded check.
  `repo_path` is checked the same way (`9b3fd0d`). `path_prefix: /etc`
  matches `/etc`, `/etc/hosts`, and `/etc/../etc/hosts` after
  normalization. It does not match `/etc-backup`. `path_prefix: /prod`
  does not match `/production`. In 1.0.0, `path_prefix: /etc` matched a
  `path`, `source`, or `destination` string that started with `/etc`,
  including `/etc-backup` and `/etc/../tmp`. `path_prefix: /prod` matched
  `/production` the same way. 1.0.0 did not read `repo_path`. Relative
  paths and relative prefixes resolve against the process current
  directory. If the path exists, may-i uses `realpath`. If it does not,
  the longest existing ancestor is `realpath`'d and the rest is appended
  lexically. A deny or ask matches when the path as written or the
  resolved path is inside the prefix. An allow matches only when every
  present path argument resolves inside the prefix. If resolution fails
  (permissions, a symlink loop, a null byte, or a path argument that is
  not a string), that allow does not match and later allow rules are
  skipped for that call. (`feff3ef`, `9b3fd0d`)
- A rule that is not a mapping, has no string `tool`, has an `action`
  other than `allow`, `deny`, or `ask`, has an empty `path_prefix`, or
  has a `sql` value other than `sql.single` with at least one verb, is a
  startup error. may-i exits before it spawns a server. 1.0.0 did not
  reject those shapes at startup. Only `deny` was blocked. `ask` prompted.
  Any other action was forwarded. (`feff3ef`)
- Runtime dependencies. Published 1.0.0 depended on
  `@modelcontextprotocol/server-filesystem` `^2026.7.10` and `yaml`
  `^2.9.0`. 1.1.0 depends on `yaml` `^2.9.0` only.
  `@modelcontextprotocol/server-filesystem` is a devDependency and is not
  installed for a consumer (`89ab140`). The SDK was not a 1.0.0
  dependency. It is not installed by 1.1.0 either. (`3ed407d`)
- The child-spawn failure line is `mayi: failed to start child process: ...`.
  1.0.0 printed `mayI:` on that one line. Other `mayi:` errors were
  already `mayi:`. (`202620d`)
- README: install commands name `mayi-mcp` (`c36fa5b`). Display prose says
  may-i (`202620d`). Usage documents the flags above.

### Same as 1.0.0 when the new flags are not used

- Stdio is the default. The command after `--` is the child server.
- `--policy`, `--audit` (default `audit.jsonl`), and
  `--audit-include-args` (off by default) behave as before. The audit
  line is still one JSON object: `timestamp`, `id`, `tool`, `verdict`,
  and `args` only with `--audit-include-args`. Response bodies are still
  not logged.
- With no `--policy` and no `--rules`, `./policy.yaml` is loaded when it
  exists. Otherwise the built-in default is used: allow `read_*`,
  `list_*`, `get_*`, `search_*`; ask `*`.
- No matching rule still asks. A deny still returns JSON-RPC error code
  `-32602` (`Blocked by policy: ...`) and does not forward the call.
- A client that does not declare elicitation, and a person who answers
  `y` or `n`, still gets `ask→approved` or `ask→denied`. An `allow` or
  `deny` rule that does not use `path_prefix` still audits `allow` or
  `deny`.
- `SIGINT`, `SIGTERM`, and `SIGHUP` still kill the stdio child and exit.

## [1.0.0] - 2026-08-08

### Added

- First npm release of `mayi-mcp` (command `mayi`). Stdio proxy for MCP
  `tools/call`: `allow`, `deny`, or `ask`. `ask` prompts on `/dev/tty`
  with `y`/`n`, waits 30 seconds, and denies on any other answer, on
  timeout, or when there is no terminal. Built-in default policy allows
  `read_*`, `list_*`, `get_*`, and `search_*`, and asks for everything
  else. `path_prefix` is a string prefix of `path`, `source`, or
  `destination`. Audit log defaults to `audit.jsonl`, without arguments
  unless `--audit-include-args` is set. Dependencies:
  `@modelcontextprotocol/server-filesystem` and `yaml`. Published files:
  `LICENSE`, `README.md`, `mayi.mjs`, `package.json`, `policy.yaml`.
