// Structural checks for rules that ask for them. The tool-name glob in
// mayi.mjs is the first pass; nothing here runs unless a rule carries
// path_prefix or sql.single. No network, no model, no classes.
//
// Paths: lexical normalization always (., .., duplicate slashes). When
// the path exists, realpath resolves symlinks. When it does not, the
// longest existing ancestor is realpath'd and the remainder is appended
// lexically, so a new file under a symlinked directory is judged by
// where that directory actually is. If nothing exists, the result stays
// lexical. Any other resolution error (permissions, symlink loop, a
// null byte) is uncertain: an allow must not use it.
//
// SQL: a statement splitter, not a full parser. It understands quotes,
// comments, and PostgreSQL dollar quotes well enough to count statements
// and read the leading verb. It does not understand statement bodies.

import { realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

const PATH_ARG_KEYS = ["path", "source", "destination"];
const SQL_ARG_KEYS = ["sql", "query", "statement"];

const VERB = /^[A-Za-z_][A-Za-z0-9_]*$/;

function ruleWhere(index) {
  return `policy rule ${index + 1}`;
}

function compileSql(sql, where) {
  if (sql === null || typeof sql !== "object" || Array.isArray(sql)) {
    throw new Error(`${where}: sql must be a mapping, for example "sql: { single: select }"`);
  }
  const keys = Object.keys(sql);
  if (keys.length !== 1 || keys[0] !== "single") {
    throw new Error(`${where}: sql only supports "single" (one statement verb, or a list of them)`);
  }
  const listed = Array.isArray(sql.single) ? sql.single : [sql.single];
  if (listed.length === 0) {
    throw new Error(`${where}: sql.single must name at least one statement verb`);
  }
  return listed.map((verb) => {
    if (typeof verb !== "string" || !VERB.test(verb)) {
      throw new Error(`${where}: sql.single verbs must be statement names like "select"`);
    }
    return verb.toLowerCase();
  });
}

// Pulls path_prefix / sql.single off a rule. Throws on a shape that
// would otherwise be ignored -- a typo must not quietly become "no
// structural check", which would fail open.
export function compileStructural(rule, index) {
  const where = ruleWhere(index);
  let hasPath = false;
  if (Object.prototype.hasOwnProperty.call(rule, "path_prefix")) {
    if (typeof rule.path_prefix !== "string" || rule.path_prefix.length === 0) {
      throw new Error(`${where}: path_prefix must be a non-empty string`);
    }
    hasPath = true;
  }
  let sqlSingle = null;
  if (Object.prototype.hasOwnProperty.call(rule, "sql")) {
    sqlSingle = compileSql(rule.sql, where);
  }
  return { hasPath, hasSql: sqlSingle !== null, sqlSingle };
}

// Segment boundary, not a string prefix. "/prod" contains "/prod" and
// "/prod/db". It does not contain "/production" or "/prod-backup".
// Both arguments are already absolute and lexically normalized.
export function isUnderPrefix(candidate, prefix) {
  if (candidate === prefix) return true;
  const rel = relative(prefix, candidate);
  if (rel === "" || isAbsolute(rel)) return false;
  return rel !== ".." && !rel.startsWith(`..${sep}`);
}

function prefixForms(prefix, cache) {
  if (cache.prefixes.has(prefix)) return cache.prefixes.get(prefix);
  const lexical = normalize(resolve(prefix));
  const forms = [lexical];
  try {
    const real = normalize(realpathSync(lexical));
    if (real !== lexical) forms.push(real);
  } catch {
    // A missing or unresolvable prefix still has its lexical form.
    // Call-path uncertainty is what blocks an allow; the prefix text
    // the operator wrote remains a valid comparison target.
  }
  cache.prefixes.set(prefix, forms);
  return forms;
}

function resolutionErrorIsMissing(err) {
  return err && (err.code === "ENOENT" || err.code === "ENOTDIR");
}

// realpath when some ancestor exists; null when the whole path is
// absent; uncertain when the OS refuses to say.
function resolveReal(lexical) {
  try {
    return { real: normalize(realpathSync(lexical)), uncertain: false };
  } catch (err) {
    if (!resolutionErrorIsMissing(err)) return { real: null, uncertain: true };
  }

  const pending = [];
  let cursor = lexical;
  const root = normalize(resolve(sep));
  while (cursor !== root) {
    const parent = dirname(cursor);
    if (parent === cursor) break;
    pending.push(basename(cursor));
    try {
      const parentReal = normalize(realpathSync(parent));
      const real = normalize(join(parentReal, ...pending.slice().reverse()));
      return { real, uncertain: false };
    } catch (err) {
      if (!resolutionErrorIsMissing(err)) return { real: null, uncertain: true };
    }
    cursor = parent;
  }
  return { real: null, uncertain: false };
}

export function inspectCallPath(input) {
  if (typeof input !== "string" || input.length === 0 || input.includes("\0")) {
    return { uncertain: true, candidates: [], effective: null };
  }
  let lexical;
  try {
    lexical = normalize(resolve(input));
  } catch {
    return { uncertain: true, candidates: [], effective: null };
  }
  const resolved = resolveReal(lexical);
  if (resolved.uncertain) {
    return { uncertain: true, candidates: [lexical], effective: null };
  }
  const effective = resolved.real || lexical;
  const candidates = effective === lexical ? [lexical] : [lexical, effective];
  return { uncertain: false, candidates, effective };
}

function cachedPath(cache, input) {
  if (cache.paths.has(input)) return cache.paths.get(input);
  const inspected = inspectCallPath(input);
  cache.paths.set(input, inspected);
  return inspected;
}

function underAny(path, forms) {
  return forms.some((prefix) => isUnderPrefix(path, prefix));
}

// path arguments named by filesystem-style tools. Missing keys are
// "this rule does not apply". A present non-string, empty string, or
// unresolvable path is uncertain so a later allow cannot treat it as
// inside the prefix.
function assessPaths(prefix, callArgs, cache) {
  const forms = prefixForms(prefix, cache);
  if (!callArgs || typeof callArgs !== "object") {
    return { present: false, uncertain: false, anyCandidateUnder: false, allEffectiveUnder: false };
  }
  let present = false;
  let uncertain = false;
  let anyCandidateUnder = false;
  let sawEffective = false;
  let allEffectiveUnder = true;
  for (const key of PATH_ARG_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(callArgs, key) || callArgs[key] === undefined) continue;
    present = true;
    const info = cachedPath(cache, callArgs[key]);
    if (info.candidates.some((candidate) => underAny(candidate, forms))) anyCandidateUnder = true;
    if (info.uncertain || info.effective === null) {
      uncertain = true;
      allEffectiveUnder = false;
      continue;
    }
    sawEffective = true;
    if (!underAny(info.effective, forms)) allEffectiveUnder = false;
  }
  if (!sawEffective) allEffectiveUnder = false;
  return { present, uncertain, anyCandidateUnder, allEffectiveUnder };
}

function skipIgnorable(input, start) {
  let i = start;
  const n = input.length;
  while (i < n) {
    const c = input[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i += 1;
      continue;
    }
    if (c === "-" && input[i + 1] === "-") {
      i += 2;
      while (i < n && input[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && input[i + 1] === "*") {
      const close = input.indexOf("*/", i + 2);
      if (close === -1) return { i, unclosed: true };
      i = close + 2;
      continue;
    }
    break;
  }
  return { i, unclosed: false };
}

function scanQuoted(input, i, quote) {
  const n = input.length;
  while (i < n) {
    if (input[i] === quote) {
      if (input[i + 1] === quote) {
        i += 2;
        continue;
      }
      return { i: i + 1, closed: true };
    }
    i += 1;
  }
  return { i, closed: false };
}

function scanDollar(input, i) {
  const match = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(input.slice(i));
  if (!match) return null;
  const closer = match[0];
  const end = input.indexOf(closer, i + closer.length);
  if (end === -1) return { i, closed: false };
  return { i: end + closer.length, closed: true };
}

function leadingVerb(statement) {
  const skipped = skipIgnorable(statement, 0);
  if (skipped.unclosed) return null;
  let i = skipped.i;
  if (i >= statement.length || !/[A-Za-z_]/.test(statement[i])) return null;
  let j = i + 1;
  while (j < statement.length && /[A-Za-z0-9_]/.test(statement[j])) j += 1;
  return statement.slice(i, j).toLowerCase();
}

// { ok: true, statements: ["select", ...] } or { ok: false, reason }.
// A trailing semicolon does not create a second statement. An empty
// input, a comment with no statement, an unclosed quote, or a null
// byte is not ok -- callers must not treat that as a single SELECT.
export function classifySql(input) {
  if (typeof input !== "string" || input.includes("\0")) {
    return { ok: false, reason: "unparseable" };
  }
  let i = 0;
  if (input.charCodeAt(0) === 0xfeff) i = 1;
  const n = input.length;
  const statements = [];
  let segmentStart = i;
  let sawToken = false;

  function pushSegment(end) {
    if (sawToken) statements.push(input.slice(segmentStart, end));
    sawToken = false;
    segmentStart = end;
  }

  while (i < n) {
    const skipped = skipIgnorable(input, i);
    if (skipped.unclosed) return { ok: false, reason: "unclosed comment" };
    i = skipped.i;
    if (i >= n) break;
    const c = input[i];
    if (c === ";") {
      pushSegment(i);
      i += 1;
      segmentStart = i;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      const quoted = scanQuoted(input, i + 1, c);
      if (!quoted.closed) return { ok: false, reason: "unclosed quote" };
      sawToken = true;
      i = quoted.i;
      continue;
    }
    if (c === "$") {
      const dollar = scanDollar(input, i);
      if (dollar) {
        if (!dollar.closed) return { ok: false, reason: "unclosed dollar quote" };
        sawToken = true;
        i = dollar.i;
        continue;
      }
    }
    sawToken = true;
    i += 1;
  }
  if (sawToken) pushSegment(n);
  if (statements.length === 0) return { ok: false, reason: "empty" };

  const types = [];
  for (const statement of statements) {
    const verb = leadingVerb(statement);
    if (!verb) return { ok: false, reason: "no verb" };
    types.push(verb);
  }
  return { ok: true, statements: types };
}

function assessSql(verbs, callArgs) {
  if (!callArgs || typeof callArgs !== "object") return { status: "unparseable" };
  const texts = [];
  for (const key of SQL_ARG_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(callArgs, key) || callArgs[key] === undefined) continue;
    if (typeof callArgs[key] !== "string") return { status: "unparseable" };
    texts.push(callArgs[key]);
  }
  if (texts.length === 0) return { status: "unparseable" };
  let compound = false;
  let mismatch = false;
  for (const text of texts) {
    const parsed = classifySql(text);
    if (!parsed.ok) return { status: "unparseable" };
    if (parsed.statements.length !== 1) {
      compound = true;
      continue;
    }
    if (!verbs.includes(parsed.statements[0])) mismatch = true;
  }
  // Compound wins over a mere verb mismatch so a second statement
  // cannot be saved by another argument that happens to be a SELECT.
  if (compound) return { status: "compound" };
  if (mismatch) return { status: "mismatch" };
  return { status: "match" };
}

// match: this rule applies.
// blockLaterAllows: a compound statement, an unparseable statement, or
// an unresolvable path was seen. Later allow rules must not match; a
// later deny or ask still can. The default when nothing matches is ask,
// so this cannot fail open into an allow.
export function evaluateStructural(rule, callArgs, cache = { paths: new Map(), prefixes: new Map() }) {
  let match = true;
  let blockLaterAllows = false;

  if (rule.hasPath) {
    const path = assessPaths(rule.path_prefix, callArgs, cache);
    if (!path.present) {
      match = false;
    } else if (rule.action === "allow") {
      // Every path argument has to land inside the prefix. An
      // uncertain resolution (permissions, symlink loop, null byte)
      // is not inside, and it also poisons later allow rules.
      match = !path.uncertain && path.allEffectiveUnder;
      if (path.uncertain) blockLaterAllows = true;
    } else if (path.anyCandidateUnder) {
      // Deny and ask fire if the path as written OR the real path
      // is inside the prefix, so a symlink cannot walk out of a
      // denied directory or hide from one.
      match = true;
    } else if (path.uncertain) {
      match = false;
      blockLaterAllows = true;
    } else {
      match = false;
    }
  }

  if (rule.hasSql) {
    const sql = assessSql(rule.sqlSingle, callArgs);
    if (sql.status === "mismatch") {
      match = false;
    } else if (sql.status !== "match") {
      match = false;
      blockLaterAllows = true;
    }
  }

  return { match, blockLaterAllows };
}
