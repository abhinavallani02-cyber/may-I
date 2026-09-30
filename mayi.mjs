#!/usr/bin/env node
// may-i -- MCP proxy with a policy engine and human-in-the-loop approval.
// Spawns a real MCP server as a child process and forwards every line
// stdin -> child.stdin and child.stdout -> stdout unchanged, EXCEPT
// tools/call requests: those are checked against policy.yaml first.
//   allow -> forwarded to the server, like any other line
//   deny  -> never reaches the server; a JSON-RPC error goes back to
//            the client instead, on the same id
//   ask   -> a human approves or denies. If the client declared MCP
//            elicitation support at initialize, the prompt is a real
//            elicitation/create request sent to the client -- it
//            renders in the client's own UI, not a terminal. Otherwise
//            this falls back to /dev/tty (not stdin -- stdin is the
//            MCP client's channel, not a human's). A decline or cancel
//            that comes back faster than a human could have answered is
//            the same fallback: the client claimed support but did not
//            actually ask (Claude Code VS Code bug
//            anthropics/claude-code#79174). Either way: approve ->
//            forwarded like allow. deny/cancel/timeout -> denied like
//            deny. An approval can also be remembered for this process:
//            later calls that hit the same tool and the same ask rule
//            are allowed without asking again, until the grant expires
//            or may-i exits. Grants are never written to disk, and a
//            deny rule is never satisfied by one. Other in-flight lines
//            are NOT blocked while a prompt is pending -- only that one
//            request waits.
// Everything that isn't a tools/call request is still pure passthrough,
// with one exception in the client->server direction: replies to
// elicitation requests may-i itself originated. Those are addressed to
// may-i, not the server, so they're consumed here and never forwarded.

import { readFileSync, createReadStream, createWriteStream, appendFileSync, existsSync, realpathSync } from "node:fs";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { parse as parseYaml } from "yaml";
import { fileURLToPath, pathToFileURL } from "node:url";
import { compileStructural, evaluateStructural } from "./structural.mjs";

const HELP_TEXT = `mayi -- an MCP proxy that enforces allow/deny/ask policy on tool calls

Usage:
  mayi [--policy <file>] [--audit <file>] [--audit-include-args] [--elicit-autodecline-ms <n>] [--grant-ttl <seconds>] -- <command> [args...]

Everything after -- is the real MCP server to spawn and front.

Options:
  --policy <file>       Policy YAML file. Defaults to ./policy.yaml if it
                         exists, otherwise a built-in conservative default
                         (reads allowed, everything else asks).
  --audit <file>        Audit log path. Defaults to ./audit.jsonl.
  --audit-include-args  Include call arguments in the audit log. Off by
                         default -- arguments can carry file contents,
                         paths, or other sensitive data.
  --elicit-autodecline-ms <n>
                        A decline or cancel faster than <n> milliseconds
                         is treated as the client auto-declining (no UI)
                         and falls back to the /dev/tty prompt. Default
                         750. 0 disables it.
  --grant-ttl <seconds>
                        How long an approval remembered for this session
                         stays in effect. Default 1800 (30 minutes).
                         0 disables session grants: every ask asks, and
                         the remember option is not offered.
  -h, --help            Show this help and exit.

Example:
  mayi --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow`;

// Set in main() from argv, or by configureForTest(). Defaults match the
// CLI defaults so a direct run that hasn't finished parsing yet still
// fails closed if anything asks early.
let auditPath = "audit.jsonl";
let auditIncludeArgs = false;
// 750ms is above the ~400ms headless Claude Code auto-decline reported
// on anthropics/claude-code#79174 (koshak01, rmcp 3.1.2, Claude Code
// v2.1.227) and below the 1.8s human click may-i measured in Cursor
// (inspect to verdict ask→approved). The earlier 250ms default was a
// guess and would miss that ~400ms decline. A Claude Code CLI
// auto-decline has not been timed here. See the README.
let elicitAutoDeclineMs = 750;
// How long a remembered approval stays in effect, in seconds. 0 turns
// session grants off entirely (the remember option is not offered, and
// a scope/answer that asks to remember is ignored).
const DEFAULT_GRANT_TTL_SECONDS = 1800;
let grantTtlSeconds = DEFAULT_GRANT_TTL_SECONDS;

// Replaced in tests so the suite can stub the terminal prompt and the
// monotonic clock. The CLI leaves these null: askHuman reads /dev/tty,
// and timestamps come from performance.now(). ttyAnswerOverride, when
// set, skips opening /dev/tty but still runs the y/n/a classifier.
let askHumanOverride = null;
let ttyAnswerOverride = null;
let clockOverride = null;

function grantsEnabled() {
  return grantTtlSeconds > 0;
}

function monotonicNow() {
  // performance.now() is monotonic (the same clock family as
  // process.hrtime), so a wall-clock step can't make a slow reply look
  // instant or stretch a same-tick auto-decline past the threshold.
  return clockOverride ? clockOverride() : performance.now();
}

// Non-negative integer, same indexOf-and-next-arg shape as --policy
// and --audit, plus a check those flags don't need because they aren't
// numbers. 0 is valid and disables the auto-decline heuristic.
function parseNonNegativeInt(raw, flag) {
  if (typeof raw !== "string" || !/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    console.error(`mayi: ${flag} requires a non-negative integer, got ${raw === undefined ? "nothing" : JSON.stringify(raw)}`);
    process.exit(1);
  }
  return Number(raw);
}

// Zero-config fallback: if no --policy was given and there's no
// policy.yaml in the current directory, use a built-in conservative
// default rather than requiring a config file to exist before may-i can
// run at all. Reads are safe on their own; everything else asks, so a
// brand-new user gets prompted rather than silently allowed or blocked.
const BUILTIN_DEFAULT_POLICY = {
  rules: [
    { tool: "read_*", action: "allow" },
    { tool: "list_*", action: "allow" },
    { tool: "get_*", action: "allow" },
    { tool: "search_*", action: "allow" },
    { tool: "*", action: "ask" },
  ],
};

let policy = BUILTIN_DEFAULT_POLICY;

// Reads and parses a policy YAML file, exiting with a clear message
// instead of a raw stack trace on malformed YAML or a missing/invalid
// rules list -- the two ways a hand-edited policy file commonly breaks.
function loadPolicyFile(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`mayi: couldn't read policy file ${path}: ${err.message}`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    console.error(`mayi: policy file ${path} is not valid YAML: ${err.message}`);
    process.exit(1);
  }
  if (!parsed || !Array.isArray(parsed.rules)) {
    console.error(`mayi: policy file ${path} must have a top-level "rules" list.`);
    process.exit(1);
  }
  return parsed;
}

// Appends one decision to the audit log. fs.appendFileSync issues a
// single write syscall per call with the O_APPEND flag, so concurrent
// appends from this process can't interleave mid-line -- each call is
// atomic at the line level. Deliberately excludes the response payload
// always. Whether it includes the call arguments is controlled by
// --audit-include-args -- off by default, since arguments can carry
// file contents, paths, or other sensitive data that shouldn't land on
// disk in plaintext without the operator opting in explicitly.
function appendAudit(id, name, verdict, callArgs) {
  const entry = { timestamp: new Date().toISOString(), id, tool: name, verdict };
  if (auditIncludeArgs) entry.args = callArgs;
  appendFileSync(auditPath, JSON.stringify(entry) + "\n");
}

// Converts a glob like "fs.write_*" into a fully-anchored RegExp. Only
// "*" is special (matches any run of characters); every other character
// is escaped literally, so tool names containing regex metacharacters
// (e.g. a tool literally named "a+b") still match exactly as written.
function globToRegex(glob) {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}
let compiledRules = [];
function compileRules(rules) {
  if (!Array.isArray(rules)) {
    throw new Error('policy must have a top-level "rules" list');
  }
  // Build the whole list before publishing it, so a bad rule doesn't
  // leave a half-compiled policy in place for the next call.
  const compiled = rules.map((rule, index) => {
    const where = `policy rule ${index + 1}`;
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      throw new Error(`${where} must be a mapping`);
    }
    if (typeof rule.tool !== "string" || rule.tool.length === 0) {
      throw new Error(`${where} needs a string tool name`);
    }
    if (rule.action !== "allow" && rule.action !== "deny" && rule.action !== "ask") {
      throw new Error(`${where} action must be allow, deny, or ask`);
    }
    const structural = compileStructural(rule, index);
    const compiledRule = { ...rule, regex: globToRegex(rule.tool), ...structural };
    // Non-enumerable so a hand-written `index:` field in the YAML stays
    // part of the rule content, and the position we assign here can't be
    // confused with it. ruleIdentity reads this property explicitly.
    // The index is the position in the compiled list, including pack
    // rules that were placed in front of --policy.
    Object.defineProperty(compiledRule, "index", { value: index });
    return compiledRule;
  });
  compiledRules = compiled;
}

function ruleLabel(rule) {
  const notes = [];
  if (rule.hasPath) notes.push(`path_prefix: ${rule.path_prefix}`);
  if (rule.hasSql) notes.push(`sql.single: ${rule.sqlSingle.join("|")}`);
  return notes.length === 0 ? rule.tool : `${rule.tool} (${notes.join(", ")})`;
}

// Glob first. Structural checks (canonical path_prefix, sql.single)
// run only for a rule that declares them, and only after the tool name
// matches. First match wins. A compound or unparseable SQL statement,
// or a path that cannot be resolved, does not match an allow rule and
// suppresses later allow rules for this call, so the result is a later
// deny or ask, or the default ask. Never an allow from that failure.
// `rule` is the compiled rule object so a session grant can key on its
// identity. The default ask has no rule.
export function decide(toolName, callArgs) {
  let blockAllows = false;
  const cache = { paths: new Map(), prefixes: new Map() };
  for (const rule of compiledRules) {
    if (typeof toolName !== "string" || !rule.regex.test(toolName)) continue;
    if (blockAllows && rule.action === "allow") continue;
    const outcome = (rule.hasPath || rule.hasSql)
      ? evaluateStructural(rule, callArgs, cache)
      : { match: true, blockLaterAllows: false };
    if (outcome.blockLaterAllows) blockAllows = true;
    if (!outcome.match) continue;
    return { action: rule.action, matchedRule: ruleLabel(rule), blockedAllow: blockAllows, rule };
  }
  return {
    action: "ask",
    matchedRule: blockAllows ? "(structural reject, default ask)" : "(no match, default)",
    blockedAllow: blockAllows,
    rule: null,
  };
}

// Session grants. In memory only -- this Map is the whole store. Nothing
// here is written to the audit log or anywhere else on disk, and the
// entries die when the process does. There is no sweep timer: expired
// entries are dropped the next time an ask decision looks one up.
//
// Key design: exact tool name + rule identity, not the call arguments.
// A rule that matches on a path_prefix (or on a tool glob alone) already
// says which arguments count as the same kind of call. Remembering the
// rule means sandbox/a and sandbox/b don't each prompt, while a
// write_file that matched a different rule (another prefix, or a deny)
// still does. Keying on the raw arguments would barely cut down prompts
// -- content and paths change every call -- and would hide the boundary
// the policy author already drew.
//
// The tool name is the name in the tools/call, not the rule's glob, so
// approving write_file under a write_* rule does not also approve
// write_notes. On any doubt, the next call asks again.
//
// Rule identity is the rule's index plus its content (every own field
// except the compiled regex). Index keeps two rules that would otherwise
// stringify the same from sharing a grant; content keeps a grant from
// surviving an edit that leaves the index in place. A missing or
// unidentifiable rule does not match.
const sessionGrants = new Map(); // key -> { expiresAt }

function ruleIdentity(rule) {
  if (!rule) return "implicit-default-ask";
  if (typeof rule.index !== "number") return null;
  const content = { "#index": rule.index };
  for (const key of Object.keys(rule).filter((name) => name !== "regex").sort()) {
    content[key] = rule[key];
  }
  return JSON.stringify(content);
}

function grantKey(toolName, rule) {
  const identity = ruleIdentity(rule);
  if (identity == null) return null;
  return JSON.stringify([String(toolName), identity]);
}

function purgeExpiredGrants() {
  const now = monotonicNow();
  for (const [key, grant] of sessionGrants) {
    if (!grant || typeof grant.expiresAt !== "number" || now >= grant.expiresAt) {
      sessionGrants.delete(key);
    }
  }
}

// True only for an unexpired grant on this tool and this ask rule.
// Deny (and allow) rules are not consulted. A key we can't build is
// treated as "no grant" -- ask again rather than guess.
function matchingSessionGrant(toolName, rule) {
  if (!grantsEnabled()) return false;
  if (rule && rule.action !== "ask") return false;
  purgeExpiredGrants();
  const key = grantKey(toolName, rule);
  if (key == null) return false;
  return sessionGrants.has(key);
}

function rememberSessionGrant(toolName, rule, matchedRule) {
  if (!grantsEnabled()) return;
  if (rule && rule.action !== "ask") return;
  const key = grantKey(toolName, rule);
  if (key == null) return;
  sessionGrants.set(key, { expiresAt: monotonicNow() + grantTtlSeconds * 1000 });
  console.error(`[GRANT] tool=${toolName} rule=${matchedRule} ttl=${grantTtlSeconds}s`);
}

const ASK_TIMEOUT_MS = 30000;

// Whether the connected client declared elicitation support, and in which
// mode(s). Set once, from the client's own `initialize` request as it
// passes through -- may-i reads this in transit without altering it, so
// the server still sees the client's real declared capabilities. Starts
// as "not supported" and stays that way until the client's `initialize`
// line is actually seen, since nothing should be asked via elicitation
// before the client has said it can handle one.
let elicitationSupport = { form: false, url: false };

function inspectInitialize(msg) {
  const capabilities = msg.params?.capabilities?.elicitation;
  elicitationSupport = { form: !!capabilities?.form, url: !!capabilities?.url };
  const supported = elicitationSupport.form || elicitationSupport.url;
  const modes = [elicitationSupport.form && "form", elicitationSupport.url && "url"].filter(Boolean).join("+");
  console.error(`[CONFIG] elicitation: ${supported ? `supported (${modes})` : "not supported"}`);
}

// may-i's own outstanding requests toward the client -- elicitation/create
// calls it originated itself, as opposed to the client's or server's
// traffic, which it only ever relays. Kept in a separate map from
// anything proxied so the two id spaces can never be confused: a
// tools/call id from the client is never looked up here, and an id in
// here is never mistaken for one of the client's.
//
// Id scheme: every id may-i generates is the string "mayi-elicit-<n>"
// (a monotonic counter), never a bare number. This is collision-safe
// because the client and server each generate their own ids
// independently and may-i never rewrites either -- it only relays them
// verbatim in both directions. The only way a collision could happen is
// if the CLIENT itself ever generated the literal string "mayi-elicit-N"
// as one of its own ids, which no real MCP client does (ids are
// typically small sequential integers or UUIDs). A numeric id range
// (e.g. "use ids above 1e9") was considered and rejected: it's not
// actually safe against a client or server that also picks large
// numbers, and it silently breaks if a peer ever does. A string prefix
// no real peer would independently produce is a stronger guarantee than
// picking a numeric range and hoping nothing else lands in it.
let elicitCounter = 0;
const pendingElicitations = new Map(); // id -> { resolve, sentAt }

function nextElicitId() {
  elicitCounter += 1;
  return `mayi-elicit-${elicitCounter}`;
}

// Sends an elicitation/create request toward the client (on stdout, the
// same channel the server's real responses travel on -- from the
// client's perspective, may-i IS the server) and waits for the matching
// reply. The reply arrives back on process.stdin (client -> may-i), same
// as any client request, and is intercepted in handleClientLine before
// it would otherwise be forwarded to the child -- see there. Resolves to
// { outcome, remember } and never rejects. outcome is "approved",
// "denied", "cancelled", "approved(tty-fallback)", or
// "denied(tty-fallback)". remember is true only when the human picked
// session scope (or tty `a`) and grants are enabled. An elicitation
// error or timeout resolves to denied with remember false. A tty
// fallback that throws, times out, or returns anything other than an
// explicit approval resolves to "denied(tty-fallback)" with remember
// false. A fast auto-decline is not itself an approval and cannot
// remember anything -- only the fallback answer can, and only via `a`.
// A failure here can never fail open into an unapproved tools/call
// going through.
//
// callId is the client's tools/call id, used only if a too-fast
// non-accept has to fall back to askHuman. The elicitation's own id
// stays in the mayi-elicit-N space.
function askViaElicitation(callId, name, args) {
  const id = nextElicitId();
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      pendingElicitations.delete(id);
      console.error(`[ASK] id=${id} elicitation timed out after ${ASK_TIMEOUT_MS}ms, defaulting to deny`);
      resolve({ outcome: "denied", remember: false });
    }, ASK_TIMEOUT_MS);

    // Stamp the send with a monotonic clock at dispatch, before the
    // bytes go out, so the reply's elapsed time can't start late.
    const sentAt = monotonicNow();
    pendingElicitations.set(id, {
      sentAt,
      resolve(result) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        pendingElicitations.delete(id);
        if (result && result.autoDeclined) {
          console.error("[ASK] elicitation auto-declined by client (likely unsupported), falling back to terminal prompt");
          // askHuman resolves "approved", "approved-remember", or
          // "denied", or rejects if something outside promptOnce throws.
          // Anything other than an explicit approval -- including a
          // throw, a timeout, or no tty -- is a deny. Never allow on an
          // error. Remember only when that approval was an explicit `a`.
          Promise.resolve()
            .then(() => askHuman(callId, name, args))
            .then(
              (human) => resolve(outcomeFromHuman(human, { fallback: true })),
              (err) => {
                const detail = err && err.message ? err.message : err;
                console.error(`[ASK] id=${callId} tty fallback failed (${detail}), defaulting to deny`);
                resolve({ outcome: "denied(tty-fallback)", remember: false });
              }
            );
          return;
        }
        const outcome = result && typeof result.outcome === "string" ? result.outcome : "denied";
        // Scope is ignored entirely when grants are disabled, even if a
        // client sends session anyway. The call can still be approved
        // once; it just isn't remembered.
        const remember = !!(result && result.remember && grantsEnabled());
        resolve({ outcome, remember });
      },
    });

    const request = {
      jsonrpc: "2.0",
      id,
      method: "elicitation/create",
      params: {
        mode: "form",
        message: grantsEnabled()
          ? `may-i: approve tool call ${name}(${JSON.stringify(args)})? You can approve just this call, or remember it for the rest of this may-i session.`
          : `may-i: approve tool call ${name}(${JSON.stringify(args)})?`,
        requestedSchema: elicitationSchema(),
      },
    };
    process.stdout.write(JSON.stringify(request) + "\n");
  });
}

// Two questions when grants are on: approve/deny, and whether to
// remember. `once` is the default -- a missing scope does not remember.
// When --grant-ttl is 0 the scope field is left out entirely, so the
// form doesn't offer a choice that would be discarded.
function elicitationSchema() {
  const properties = {
    approve: {
      type: "string",
      enum: ["approve", "deny"],
      title: "Approve this tool call?",
    },
  };
  const required = ["approve"];
  if (grantsEnabled()) {
    properties.scope = {
      type: "string",
      enum: ["once", "session"],
      title: "Remember this approval?",
      description: "once (default): this call only. session: remember this tool and rule until may-i exits or the grant expires.",
      default: "once",
    };
    required.push("scope");
  }
  return { type: "object", properties, required };
}

// True when a decline or cancel arrived too fast to be a person
// answering the prompt. At or over the threshold it's a real decision.
// 0 disables the heuristic entirely.
function isFastAutoDecline(pending) {
  if (!(elicitAutoDeclineMs > 0)) return false;
  const elapsed = monotonicNow() - pending.sentAt;
  return elapsed < elicitAutoDeclineMs;
}

// Handles a reply on process.stdin matching one of may-i's own
// outstanding elicitation ids. Maps the client's response to an outcome:
//   action "accept" + content.approve === "approve" -> "approved"
//      (+ remember when content.scope === "session"; anything else,
//       including a missing scope, is once)
//   action "accept" + content.approve === "deny"     -> "denied"
//   action "decline"                                 -> "denied"
//      (or { autoDeclined } if it arrived under the threshold)
//   action "cancel"                                  -> "cancelled"
//      (or { autoDeclined } if it arrived under the threshold)
//   anything else (malformed, error response, unexpected content) -> "denied"
// Never resolves to "approved" except on an explicit accept+approve --
// every other shape of reply denies, so a malformed or unexpected
// response can't accidentally let a call through. remember is set only
// on that same explicit approval, and only for the exact scope string
// "session". A decline or cancel never remembers, however fast it was
// and whatever else the payload contains. The accept branch is
// intentionally not timed: a fast explicit approval is still an approval.
function handleElicitResponse(msg) {
  const pending = pendingElicitations.get(msg.id);
  if (!pending) return; // not one of ours (shouldn't happen -- caller checks first)

  if (msg.error) {
    pending.resolve({ outcome: "denied", remember: false });
    return;
  }
  const action = msg.result?.action;
  if (action === "cancel") {
    pending.resolve(isFastAutoDecline(pending) ? { autoDeclined: true } : { outcome: "cancelled", remember: false });
  } else if (action === "accept" && msg.result?.content?.approve === "approve") {
    const remember = msg.result.content.scope === "session";
    pending.resolve({ outcome: "approved", remember });
  } else if (action === "decline" && isFastAutoDecline(pending)) {
    pending.resolve({ autoDeclined: true });
  } else {
    // slow decline, or accept with any other content -- both deny, and
    // neither remembers. A scope field on a denial is ignored.
    pending.resolve({ outcome: "denied", remember: false });
  }
}

// Maps a tty answer (already classified) onto the verdict outcome.
// fallback true is the elicitation auto-decline path: any non-approval
// collapses to denied(tty-fallback), matching the pre-grant behavior.
// The direct tty path (no elicitation support) keeps the raw non-approval
// string so a stub that returns "denied" still audits as ask→denied.
// `a` remembers only when grants are enabled; with --grant-ttl 0 the
// classifier never returns approved-remember, and this function would
// drop the flag anyway.
function outcomeFromHuman(human, { fallback }) {
  if (human === "approved" || human === "approved-remember") {
    const outcome = fallback ? "approved(tty-fallback)" : "approved";
    return { outcome, remember: human === "approved-remember" && grantsEnabled() };
  }
  if (fallback) return { outcome: "denied(tty-fallback)", remember: false };
  const outcome = typeof human === "string" && human ? human : "denied";
  return { outcome, remember: false };
}

function formatTtyPrompt(id, name, args) {
  const choices = grantsEnabled()
    ? "y/n/a, a = approve and remember for this session"
    : "y/n";
  return `[ASK] id=${id} tool=${name} args=${JSON.stringify(args)}. Approve? (${choices}): `;
}

// y approves once. a approves and remembers, and only when grants are
// enabled -- otherwise the letter isn't offered, and it falls through
// to deny like any other non-y answer. n and everything else deny.
// Case and surrounding whitespace don't matter.
function classifyTtyAnswer(answer) {
  const normalized = String(answer ?? "").trim().toLowerCase();
  if (normalized === "y") return "approved";
  if (normalized === "a" && grantsEnabled()) return "approved-remember";
  return "denied";
}

// Opens /dev/tty and asks one y/n/a question (y/n when grants are off),
// then closes it immediately.
// /dev/tty is deliberately NOT held open between prompts: on macOS (and
// most Unixes) it resolves to the same underlying terminal device as
// process.stdin when stdin is a tty. Two independent readers on that
// one device race for every keystroke the OS delivers, and readline
// reliably wins that race -- so a persistent /dev/tty reader silently
// starves process.stdin for the entire life of the process, not just
// during a prompt. Opening lazily, only for the duration of a single
// question, means /dev/tty is only ever in that race for the brief
// window an answer is actually being read.
//
// Not exported directly -- see askHuman below, which serializes calls
// to this so two concurrent tools/call requests needing "ask" can never
// open two /dev/tty readers at once and reintroduce the same race.
//
// Needs BOTH a read stream and a write stream on /dev/tty: readline
// writes the prompt text to `output`, and reads the answer from
// `input`. Without an output, question() has nowhere to put the prompt
// and it's silently never shown, even though the interface is still
// correctly reading answers. Both are opened lazily and closed in
// finish(), same as the read side alone was before -- this doubles the
// fds involved but not the duration either is held open for.
function promptOnce(id, name, args) {
  // Test hook: same classifier as the real prompt, without opening
  // /dev/tty. An explicit `a` is the only tty answer that remembers.
  if (ttyAnswerOverride !== null && ttyAnswerOverride !== undefined) {
    const answer = typeof ttyAnswerOverride === "function"
      ? ttyAnswerOverride(id, name, args)
      : ttyAnswerOverride;
    return Promise.resolve(classifyTtyAnswer(answer));
  }

  return new Promise((resolve) => {
    let settled = false;
    let ttyIn, ttyOut, rl;
    let inReady = false, outReady = false;

    function finish(outcome) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (rl) rl.close();
      if (ttyIn) ttyIn.destroy();
      if (ttyOut) ttyOut.destroy();
      resolve(outcome);
    }

    function onTtyError(err) {
      // Both ttyIn and ttyOut can error independently (e.g. no
      // controlling terminal at all -- both fail with ENXIO), but
      // finish() is idempotent and only the first error is the
      // interesting one, so only log once.
      if (settled) return;
      console.error(`[ASK] id=${id} tool=${name} args=${JSON.stringify(args)} -- no tty available (${err.message}), defaulting to deny`);
      finish("denied");
    }

    // Only ask once BOTH streams are open -- question() writes the
    // prompt through `output` as soon as it's called, so if output
    // isn't ready yet the prompt would be silently dropped just like
    // the original bug, only for the write side instead of missing
    // entirely.
    function maybeAsk() {
      if (!inReady || !outReady || settled) return;
      rl = createInterface({ input: ttyIn, output: ttyOut });
      rl.question(
        formatTtyPrompt(id, name, args),
        (answer) => finish(classifyTtyAnswer(answer))
      );
    }

    const timer = setTimeout(() => {
      console.error(`\n[ASK] id=${id} timed out after ${ASK_TIMEOUT_MS}ms, defaulting to deny`);
      finish("denied");
    }, ASK_TIMEOUT_MS);

    ttyIn = createReadStream("/dev/tty");
    ttyIn.on("error", onTtyError);
    ttyIn.on("open", () => { inReady = true; maybeAsk(); });

    ttyOut = createWriteStream("/dev/tty");
    ttyOut.on("error", onTtyError);
    ttyOut.on("open", () => { outReady = true; maybeAsk(); });
  });
}

// Serializes prompts: if a second tools/call needs "ask" while a prompt
// is already pending, its question waits for the current one to finish
// (answered or timed out) before /dev/tty is opened again. This is the
// only thing that queues -- handleClientLine is still fired-and-not-
// awaited per line, so other allow/deny decisions and server traffic
// keep flowing while a prompt (or several, queued) is pending.
let askQueue = Promise.resolve();
function askHuman(id, name, args) {
  if (askHumanOverride) return askHumanOverride(id, name, args);
  const result = askQueue.then(() => promptOnce(id, name, args));
  askQueue = result.catch(() => {}); // keep the chain alive even if a link ever rejects
  return result;
}

let child = null;

// Parses a raw line from the client. Non-JSON-RPC lines are forwarded
// untouched. Two kinds of lines get special handling before the general
// tools/call check:
//   - `initialize` requests are inspected (not modified) to learn whether
//     the client supports elicitation, then forwarded like anything else.
//   - Replies to may-i's own outstanding elicitation requests are
//     recognized by id, consumed here, and NOT forwarded -- the child
//     server never sent that request and knows nothing about it.
// A tools/call line is checked against policy before forwarding; on
// deny (including an ask that gets refused, cancelled, or times out),
// the line never reaches the server and an error goes back to the
// client on stdout instead. This is async because "ask" waits on a
// human, but the caller (the stdin drain loop) does NOT await it -- so a
// slow human answering one prompt never blocks any other line already
// in flight.
async function handleClientLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    child.stdin.write(line + "\n"); // not JSON -- not ours to inspect, pass through
    return;
  }

  if (msg.method === "initialize") {
    inspectInitialize(msg);
    child.stdin.write(line + "\n");
    return;
  }

  // A response (has an id, no method) addressed to one of may-i's own
  // elicitation requests. Checked before the tools/call branch since
  // these are responses, not requests, and would otherwise just fall
  // through untouched to the child -- which must never see them, since
  // it never sent the matching request and has no id to match it to.
  if (msg.method === undefined && msg.id !== undefined && pendingElicitations.has(msg.id)) {
    handleElicitResponse(msg);
    return; // consumed -- not the server's traffic, never forwarded
  }

  if (msg.method !== "tools/call") {
    child.stdin.write(line + "\n");
    return;
  }

  const { name, arguments: args } = msg.params ?? {};
  console.error(`[INSPECT] id=${msg.id} tool=${name} args=${JSON.stringify(args)}`);

  const { action, matchedRule, rule } = decide(name, args);
  let decision = action;
  let verdictLabel = action;

  if (action === "ask") {
    // A remembered approval applies only while the rule that matches
    // NOW is still an ask. A deny rule never enters this branch, so a
    // grant cannot turn a denied call into an allow, including after
    // the policy is recompiled and a different rule matches. The audit
    // label stays ask→granted(session) so it can't be read as a plain
    // policy allow.
    if (matchingSessionGrant(name, rule)) {
      decision = "allow";
      verdictLabel = "ask→granted(session)";
    } else {
      // "approved" | "denied" | "cancelled" from elicitation, or
      // "approved" | "denied" from the tty path. A too-fast decline or
      // cancel comes back as "approved(tty-fallback)" or
      // "denied(tty-fallback)" after askHuman runs. Only an explicit
      // approval allows the call; the fallback forms are explicit too,
      // and every error shape stays a deny. remember is a separate
      // flag: the creating call is still an approval, and only later
      // calls log ask→granted(session).
      const { outcome, remember } = (elicitationSupport.form || elicitationSupport.url)
        ? await askViaElicitation(msg.id, name, args)
        : outcomeFromHuman(await askHuman(msg.id, name, args), { fallback: false });
      const approved = outcome === "approved" || outcome === "approved(tty-fallback)";
      decision = approved ? "allow" : "deny";
      verdictLabel = `ask→${outcome}`;
      if (approved && remember) rememberSessionGrant(name, rule, matchedRule);
    }
  }

  console.error(`[VERDICT] id=${msg.id} tool=${name} decision=${verdictLabel}`);
  appendAudit(msg.id, name, verdictLabel, args);

  if (decision === "deny") {
    const errorResponse = {
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32602, message: `Blocked by policy: ${matchedRule}` },
    };
    process.stdout.write(JSON.stringify(errorResponse) + "\n");
    return; // never forwarded to the server
  }

  child.stdin.write(line + "\n");
}

// Wires stdio, spawns the real server, and stays alive. Not run when
// this file is imported by the test suite -- see isDirectRun() below.
function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  const sepIndex = process.argv.indexOf("--");
  if (sepIndex === -1 || sepIndex === process.argv.length - 1) {
    console.error("mayi: no server command given -- everything after \"--\" is the command to run.");
    console.error();
    console.error(HELP_TEXT);
    process.exit(1);
  }
  const beforeSep = process.argv.slice(2, sepIndex);
  const policyFlagIndex = beforeSep.indexOf("--policy");
  const explicitPolicyPath = policyFlagIndex === -1 ? null : beforeSep[policyFlagIndex + 1];
  const auditFlagIndex = beforeSep.indexOf("--audit");
  auditPath = auditFlagIndex === -1 ? "audit.jsonl" : beforeSep[auditFlagIndex + 1];
  auditIncludeArgs = beforeSep.includes("--audit-include-args");
  const elicitFlagIndex = beforeSep.indexOf("--elicit-autodecline-ms");
  if (elicitFlagIndex !== -1) {
    elicitAutoDeclineMs = parseNonNegativeInt(beforeSep[elicitFlagIndex + 1], "--elicit-autodecline-ms");
  }
  const grantFlagIndex = beforeSep.indexOf("--grant-ttl");
  if (grantFlagIndex !== -1) {
    grantTtlSeconds = parseNonNegativeInt(beforeSep[grantFlagIndex + 1], "--grant-ttl");
  }
  sessionGrants.clear();
  const [command, ...args] = process.argv.slice(sepIndex + 1);

  // Zero-config fallback: if no --policy was given and there's no
  // policy.yaml in the current directory, use a built-in conservative
  // default rather than requiring a config file to exist before may-i can
  // run at all. Reads are safe on their own; everything else asks, so a
  // brand-new user gets prompted rather than silently allowed or blocked.
  let policyPath = explicitPolicyPath;
  let policySource;
  if (policyPath) {
    if (!existsSync(policyPath)) {
      console.error(`mayi: policy file not found: ${policyPath}`);
      process.exit(1);
    }
    policy = loadPolicyFile(policyPath);
    policySource = policyPath;
  } else if (existsSync("policy.yaml")) {
    policyPath = "policy.yaml";
    policy = loadPolicyFile(policyPath);
    policySource = policyPath;
  } else {
    policy = BUILTIN_DEFAULT_POLICY;
    policySource = "built-in default (reads allowed, everything else asks)";
  }
  try {
    compileRules(policy.rules);
  } catch (err) {
    console.error(`mayi: ${err.message}`);
    process.exit(1);
  }

  console.error(`[CONFIG] policy: ${policySource}`);
  console.error(`[CONFIG] audit mode: ${auditIncludeArgs ? "decisions + args" : "decisions only"}`);
  console.error(`[CONFIG] elicit auto-decline: ${elicitAutoDeclineMs === 0 ? "off" : elicitAutoDeclineMs + "ms"}`);
  console.error(`[CONFIG] session grants: ${grantsEnabled() ? grantTtlSeconds + "s" : "off"}`);

  child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });

  // stdin -> child.stdin, buffered and split on newlines. Every line is
  // still forwarded verbatim UNLESS it's a tools/call request that policy
  // denies -- that's the one case where the raw `line` is deliberately not
  // written to child.stdin. Buffering/splitting logic is unchanged from
  // the pure-passthrough version: preserves line boundaries regardless of
  // how bytes were chunked on the way in.
  let stdinBuffer = "";
  process.stdin.on("data", (chunk) => {
    stdinBuffer += chunk.toString();
    let newlineIndex;
    while ((newlineIndex = stdinBuffer.indexOf("\n")) !== -1) {
      const line = stdinBuffer.slice(0, newlineIndex);
      stdinBuffer = stdinBuffer.slice(newlineIndex + 1);
      handleClientLine(line);
    }
  });
  process.stdin.on("end", () => child.stdin.end());

  // child.stdout -> stdout, same buffering treatment in the other direction.
  let stdoutBuffer = "";
  child.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk.toString();
    let newlineIndex;
    while ((newlineIndex = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, newlineIndex);
      stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
      process.stdout.write(line + "\n");
    }
  });

  // child.stderr is already wired straight through via stdio: "inherit"
  // above -- no buffering needed, it's not part of the framed protocol.

  // If the child dies, we die the same way, so the client sees the same
  // failure mode as if it had spawned the real server itself.
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 0);
    }
  });

  child.on("error", (err) => {
    console.error(`mayi: failed to start child process: ${err.message}`);
    process.exit(1);
  });

  // If may-i itself is killed, kill the child too -- no orphaned processes.
  // Registering a signal listener at all disables Node's default behavior
  // of exiting on that signal, so this handler must exit explicitly --
  // otherwise may-i hangs forever after Ctrl+C, waiting on nothing.
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(sig, () => {
      child.kill(sig);
      process.exit(0);
    });
  }
}

// In-process harness for test-elicit-fallback.mjs. The CLI never calls
// this. askHuman is stubbed here so tests don't open /dev/tty.
export function configureForTest({
  rules,
  auditFile,
  includeArgs = false,
  autoDeclineMs = 750,
  grantTtlSeconds: grantTtl = DEFAULT_GRANT_TTL_SECONDS,
  childStdin,
  askHuman: askHumanFn = null,
  ttyAnswer = null,
  now = null,
  resetGrants = true,
}) {
  policy = { rules };
  compileRules(rules);
  auditPath = auditFile;
  auditIncludeArgs = includeArgs;
  elicitAutoDeclineMs = autoDeclineMs;
  grantTtlSeconds = grantTtl;
  elicitationSupport = { form: false, url: false };
  pendingElicitations.clear();
  elicitCounter = 0;
  askQueue = Promise.resolve();
  askHumanOverride = askHumanFn;
  ttyAnswerOverride = ttyAnswer;
  clockOverride = now;
  if (resetGrants) sessionGrants.clear();
  child = { stdin: childStdin };
}

// True when this file is the process entry point, including when the
// npm bin is a symlink to it. Both sides are realpath'd so a symlink
// still starts the proxy. On any uncertainty, start -- a silent no-op
// would look like a hung client. Importing from the test script does
// not match, so the suite can call handleClientLine without spawning.
function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return true;
  try {
    const entryUrl = pathToFileURL(realpathSync(entry)).href;
    const selfUrl = pathToFileURL(realpathSync(fileURLToPath(import.meta.url))).href;
    return entryUrl === selfUrl;
  } catch {
    return true;
  }
}

export { handleClientLine, formatTtyPrompt, classifyTtyAnswer };

if (isDirectRun()) main();
