#!/usr/bin/env python3
# Copyright (c) 2026 Aisle Inc.
# SPDX-License-Identifier: Apache-2.0
# Modified from AISLE's nano-analyzer prototype for local Codex CLI /
# Claude Code backends and gitignore-aware scanning.
"""
nano-analyzer: Minimal zero-day vulnerability scanner using LLMs.

Adapted from AISLE's nano-analyzer for local CLI workflows.

Two-stage pipeline:
  1. A cheap model generates security context about the file
  2. The scanner model uses that context to find vulnerabilities

Usage:
  python3 scan.py ./path/to/folder        # scan source files recursively
  python3 scan.py ./path/to/file.c        # scan a single file
  python3 scan.py ./src --codex           # use Codex CLI, no API key
  python3 scan.py ./src --claude          # use Claude Code, no API key
  python3 scan.py ./src --backend api     # force OpenAI/OpenRouter API mode
  python3 scan.py ./src --model gpt-5.4   # use a different API/Codex model
  python3 scan.py ./src --claude-model sonnet --claude-effort high
  python3 scan.py ./src --parallel 30     # control scan concurrency
  python3 scan.py ./src --include-ignored # include gitignored files
"""

import argparse
import fnmatch
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
CODEX_MODEL_ALIASES = {"codex", "codex-cli"}
CLAUDE_MODEL_ALIASES = {"claude", "claude-code", "sonnet", "opus", "haiku"}
CODEX_JSON_OBJECT_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "crux": {"type": "string"},
        "grep": {"type": "string"},
        "verdict": {"type": "string"},
    },
    "required": ["reasoning", "crux", "grep", "verdict"],
    "additionalProperties": False,
}

VERSION = "0.1"

DEFAULT_MODEL = "gpt-5.4-nano"
DEFAULT_PARALLEL = 50
DEFAULT_TRIAGE_PARALLEL = 50
DEFAULT_CODEX_PARALLEL = 4
DEFAULT_CLAUDE_PARALLEL = 4
DEFAULT_MAX_CHARS = 200_000
DEFAULT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".java", ".py", ".pyi", ".go", ".rs",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".rb", ".swift", ".m", ".mm", ".cs", ".php", ".pl",
    ".sh", ".bash", ".zsh", ".yml", ".yaml", ".dockerfile",
    ".toml", ".ini", ".cfg",
    ".x",
}
DEFAULT_FILENAMES = {"Dockerfile", "Containerfile"}
DEFAULT_SKIP_DIRS = {
    ".agents",
    ".cache",
    ".codex",
    ".claude",
    ".firebase",
    ".git",
    ".hg",
    ".next",
    ".nuxt",
    ".pnpm-store",
    ".svn",
    ".svelte-kit",
    ".turbo",
    ".venv",
    ".vscode",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "test-results",
    "venv",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
    "clean": "🟢",
}


def terminal_file_link(path, label=None):
    """Return an OSC 8 hyperlink for local terminal output when supported."""
    label = label or path
    if not sys.stdout.isatty() or os.environ.get("TERM") == "dumb":
        return label
    if os.environ.get("NANO_ANALYZER_NO_LINKS"):
        return label
    try:
        uri = Path(path).expanduser().resolve(strict=False).as_uri()
    except (OSError, ValueError):
        return label
    return f"\033]8;;{uri}\033\\{label}\033]8;;\033\\"

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

C_SECURITY_FOCUS = """\
For C/C++, prioritize memory-safety and parser boundary bugs:
- fixed-size buffer overflows and unterminated strings
- integer overflow, signedness, truncation, and size/index confusion
- NULL dereferences only when externally reachable and security-relevant
- use-after-free, double-free, lifetime bugs, and ownership confusion
- tagged union / variant access without discriminator validation
- unchecked return values from fallible allocators, parsers, and I/O
- path traversal, command injection, and unsafe file handling where present

Focus on bugs that external attacker-controlled input can trigger. \
Deprioritize static helpers with safe call sites, platform-specific dead \
code, and crashes with no meaningful security impact.\
"""

TS_JS_SECURITY_FOCUS = """\
Trace attacker-controlled data from routes, handlers, server actions, \
query params, request bodies, cookies, headers, webhooks, job queues, \
and uploaded files.

Prioritize:
- command injection: child_process.exec, execSync, spawn with shell=true
- SQL/NoSQL injection: raw queries, string-built where clauses, Mongo operators
- SSRF: fetch/axios/got/request using attacker-controlled URLs
- path traversal: fs.readFile/writeFile/sendFile using user paths
- authz bugs: IDOR, tenant bypass, missing ownership checks
- XSS/template injection: dangerouslySetInnerHTML, template engines
- open redirect: redirect(userControlledUrl)
- prototype pollution: unsafe merge/deep assignment into objects
- unsafe deserialization/parsing: yaml, qs, JSON with dynamic behavior
- secrets leakage: logs, error responses, client bundles
- CORS/CSRF/session/JWT misconfiguration when a security boundary is clear

Do not report ordinary TypeScript type errors, null derefs, or crashes \
unless an external attacker can trigger meaningful harm.\
"""

PY_SECURITY_FOCUS = """\
Trace attacker-controlled data from Flask/Django/FastAPI routes, CLI args, \
files, queues, webhooks, environment variables, and deserialized input.

Prioritize:
- command injection: subprocess(..., shell=True), os.system, popen
- code execution: eval, exec, compile, importlib on user input
- deserialization: pickle, marshal, yaml.load, unsafe json/object hooks
- SQL injection: raw SQL, f-strings, string concatenation
- SSRF: requests/httpx/urllib using attacker-controlled URLs
- path traversal: open/send_file/Path joins/archive extraction
- template injection: Jinja/Django templates with user-controlled templates
- authz bugs: missing object ownership, tenant boundary bypass
- mass assignment: model update from request dict
- XXE/XML/parser issues
- insecure crypto/token/session handling
- secrets leakage in logs or responses

Do not report ordinary exceptions or crashes unless the attacker can \
turn them into meaningful denial of service, code execution, data access, \
or privilege boundary impact.\
"""

SH_SECURITY_FOCUS = """\
Trace attacker-controlled data from argv, env vars, filenames, CI variables, \
git branch names, PR titles, config files, and network data.

Prioritize:
- command injection via eval, sh -c, backticks, $(), unquoted variables
- option injection: user values passed before -- to tools
- path injection: PATH-controlled command lookup, relative executable names
- unsafe temp files: predictable /tmp paths, symlink races
- unsafe globbing/word splitting
- unsafe curl | sh / wget | sh flows
- archive extraction traversal
- secrets exposure in set -x, logs, artifacts
- rm/chown/chmod with attacker-controlled paths
- CI/CD privilege boundary bugs

A shell finding is VALID only if the attacker controls the variable or \
filename and the script runs in a privileged or security-sensitive context.\
"""

CI_SECURITY_FOCUS = """\
Trace attacker-controlled data through CI/CD workflows, workflow_dispatch \
inputs, pull_request contexts, branch names, tags, artifact names, cache \
keys, matrix values, environment variables, and deployment configuration.

Prioritize:
- script or expression injection in run steps
- privileged pull_request_target misuse with untrusted checkout or artifacts
- overly broad permissions, token exposure, and secret leakage
- cache/artifact poisoning across trust boundaries
- deployment steps reachable from untrusted refs
- unsafe Docker build args, ADD/COPY of untrusted content, and curl | sh
- compose/config settings that expose admin ports, credentials, or volumes

Do not report generic hardening advice unless a concrete privilege boundary \
or attacker-controlled value reaches a sensitive sink.\
"""

GENERIC_SECURITY_FOCUS = """\
Trace attacker-controlled data from public entry points to dangerous sinks. \
Prioritize injection, path traversal, SSRF, unsafe deserialization, authz \
bypass, secrets exposure, unsafe file handling, and privilege-boundary bugs. \
Do not report pure type errors, ordinary exceptions, or hardening advice \
unless there is a concrete security impact.\
"""

C_CONTEXT_CHECKLIST = """\
Identify:
1. Public API, parser, syscall, file, network, or library entry points
2. Attacker-controlled parameters and buffers, traced to their sources
3. Fixed-size buffers and named size constants; use GREP to resolve values
4. Dangerous copies, arithmetic, casts, indexes, and allocation sizes
5. NULL/lifetime ownership assumptions and unchecked fallible returns
6. Tagged unions or variants and the discriminator checks protecting them
7. Static helpers vs exported functions and whether callers are safe
8. Cross-file facts needed: constants, callers, wrappers, allocators
9. Likely bug classes for this file\
"""

TS_JS_CONTEXT_CHECKLIST = """\
Identify:
1. Framework/runtime: Express, Next.js, Nest, Remix, tRPC, serverless, CLI, worker
2. Entry points: routes, API handlers, server actions, webhooks, queue consumers
3. Attacker-controlled fields: req.params, req.query, req.body, headers, cookies
4. Validators/sanitizers: zod, joi, yup, class-validator, custom guards
5. Auth/authz checks: middleware, session checks, tenant/owner checks
6. Dangerous sinks: child_process, fs, path, fetch/axios, raw SQL, redirects, templates
7. Cross-file facts needed: callers, route registration, middleware chain, schemas
8. Likely bug classes for this file\
"""

PY_CONTEXT_CHECKLIST = """\
Identify:
1. Framework/runtime: Django, Flask, FastAPI, Celery, CLI, lambda, library
2. Entry points: routes, management commands, queue tasks, file parsers
3. Attacker-controlled fields: request args/body/files/headers/cookies, argv, env
4. Validators/sanitizers: pydantic, forms, serializers, regex checks, allowlists
5. Auth/authz checks: decorators, dependencies, permission classes, ownership checks
6. Dangerous sinks: subprocess, eval/exec, pickle/yaml, open/pathlib, requests, SQL
7. Cross-file facts needed: URL routing, dependency injection, serializers, settings
8. Likely bug classes for this file\
"""

SH_CONTEXT_CHECKLIST = """\
Identify:
1. Invocation context: local script, CI job, install script, deployment script, cron
2. Attacker-controlled variables: argv, env, filenames, branch names, config values
3. Privilege boundary: root, CI token, deploy key, production credentials
4. Quoting/word-splitting hazards
5. Command-construction hazards
6. File/path hazards
7. External tools invoked and whether -- is used before user paths
8. Likely bug classes for this script\
"""

CI_CONTEXT_CHECKLIST = """\
Identify:
1. Invocation context: GitHub Actions, CI job, Docker build, compose, deployment
2. Untrusted inputs: PR metadata, branch names, workflow inputs, artifacts, cache keys
3. Privilege boundary: secrets, write tokens, deploy keys, production credentials
4. Permission and trigger model: pull_request vs pull_request_target, workflow_dispatch
5. Command-construction hazards in run/script blocks
6. Artifact/cache poisoning and cross-job trust assumptions
7. Dockerfile hazards: root user, curl | sh, secret build args, unsafe ADD/COPY
8. Likely bug classes for this file\
"""

GENERIC_CONTEXT_CHECKLIST = """\
Identify:
1. Runtime/framework and externally reachable entry points
2. Attacker-controlled variables, fields, files, config, and environment data
3. Validators, sanitizers, authorization checks, and privilege boundaries
4. Dangerous sinks: command execution, file/path APIs, network requests, raw queries
5. Cross-file facts needed: callers, registration, settings, wrappers, schemas
6. Likely source-to-sink bug classes for this file\
"""

SCAN_SYSTEM_PROMPT_TEMPLATE = """\
You are a security researcher hunting for zero-day vulnerabilities in \
{language_name} code. Analyze the code step by step by tracing untrusted \
data from source to sink.

{focus}

After your analysis, output a JSON array of findings. Each finding must \
have severity, title, function, and description. Output ONLY the JSON \
array at the end; your reasoning goes before it.\
"""

CONTEXT_GEN_PROMPT_TEMPLATE = """\
You are preparing a security briefing for a vulnerability researcher \
reviewing {language_name} code. Write a concise (~250 word) context \
briefing. Do not find vulnerabilities; provide context.

Context checklist:
{context_checklist}

Known repository facts:
{repo_context}

Name actual variables, functions, routes, settings, validators, and \
constants from the code. Use your training knowledge of this project \
where helpful, but verify specifics.

GREP TOOL: You can search the codebase by including GREP: pattern in \
your response. Use this to look up constants, callers, route registration, \
middleware, validators, schemas, settings, wrappers, or cross-file data \
flow. The results will be appended to your briefing.\
"""

TRIAGE_PROMPT_TEMPLATE = """\
A vulnerability scanner flagged this in {project_name}. Is it real?

Be skeptical — most scanner findings are false positives.

RULES:
- VALID: the bug is real AND an external attacker can trigger it to \
  cause meaningful harm (crash, code execution, data corruption, auth \
  bypass). The attacker must control the input that triggers the bug.
- INVALID: the bug pattern does not exist, OR it is not attacker-reachable \
  (only trusted internal callers), OR a concrete defense prevents it, \
  OR it is a code quality issue not a security vulnerability (e.g. \
  data race on diagnostic state, missing NULL check on internal-only \
  API, undefined behavior only in debug builds).
- UNCERTAIN: only if you genuinely cannot determine.

ABSENCE OF DEFENSE: If the bug pattern clearly exists, the input \
comes from an untrusted source, and you searched for a defense but \
did not find one, lean toward VALID rather than UNCERTAIN. Not \
having verified every upstream caller is not a reason to mark \
UNCERTAIN — only cite a defense if you can name the specific \
function and show it is sufficient.

CRITICAL: When you cite any defense — a size limit, NULL check, type \
validation, schema, sanitizer, authorization check, path normalization, \
or quoting/argv construction — you must verify it actually works. Look \
up the actual values or code. Show your work. "There \
exists a bound" is NOT the same as "the bound is sufficient." Never \
skip the verification step.

FOLLOW CROSS-FILE FACTS: When you encounter a named constant, wrapper, \
schema, middleware, sanitizer, settings value, or helper in code or \
grep results, you MUST grep for its definition or callers before \
concluding. A name is not a verified defense. If a function receives a \
validated parameter, grep for its callers to see what they pass.

IMPORTANT: If your own analysis leads to a conclusion, do not then \
contradict it in the same response. If you verify a defense and find \
it insufficient, that is your answer — do not keep searching for \
reasons to change your mind. Trust your own reasoning.

If you believe a defense exists that you haven't verified, you must \
either name the specific function/line that implements it or grep \
for it. Vague references to "assumptions in this codebase" or \
"other code probably handles this" are not valid defenses. If you \
cannot point to it or find it, it does not exist.

GREP TOOL: Include a grep pattern in the JSON to search the codebase. \
Use this to look up values, check implementations, and verify defenses. \
GREP PATTERNS: Use function/variable/constant/schema/middleware names \
as patterns, e.g. "MAX_BUF_SIZE", "parse_input(", "requireAuth", \
"UserSchema", "subprocess", "sendFile". Do NOT prefix patterns with \
file paths like "src/foo/bar.ts:symbol" — that searches for the literal \
string inside files and will return nothing. To find callers of a \
function, grep for its name.

Language-specific triage:
{triage_rules}

Use your knowledge of {project_name} for intuition, but verify \
specifics via grep. Do not invent defenses.

Respond ONLY with JSON:
{{"reasoning": "Analyze the evidence. State your conclusion clearly.", \
"crux": "the single key fact the verdict depends on", \
"grep": "search_pattern to verify the crux", \
"verdict": "VALID/INVALID/UNCERTAIN"}}

---

**Reported vulnerability:**
{finding}

**Code from {filepath}:**
```{fence}
{code}
```\
"""

USER_PROMPT_TEMPLATE = """\
Analyze the following {language_name} source file for zero-day vulnerabilities.

File: {filepath}

```{fence}
{code}
```

Provide a detailed security analysis.\
"""

C_FEWSHOT_USER = """\
Analyze the following C/C++ source file for zero-day vulnerabilities.

File: example/net/parser.c

```c
void parse_packet(struct packet *pkt, const char *data, int len) {
    char header[64];
    memcpy(header, data, len);
    process_header(header);
}

int handle_request(struct request *req) {
    struct session *sess = lookup_session(req->session_id);
    return sess->handler(req);
}

static void log_debug(const char *msg) {
    if (msg) printf("%s\\n", msg);
}

int process_attr(struct attr_value *av) {
    return av->value.str_val->length;
}
```

Provide a detailed security analysis.\
"""

C_FEWSHOT_ASSISTANT = """\
`parse_packet`: `data` and `len` come from the network. Copies `len` \
bytes into a 64-byte stack buffer with no bounds check, so `len > 64` \
overflows. `handle_request`: `lookup_session()` can return NULL and the \
result is dereferenced. `log_debug`: safe, already checks NULL. \
`process_attr`: accesses a union member without checking the type tag.

```json
[
  {"severity": "critical", "title": "Stack buffer overflow via unchecked len", "function": "parse_packet()", "description": "memcpy copies attacker-controlled len bytes into a 64-byte stack buffer without a bounds check"},
  {"severity": "high", "title": "NULL deref on failed session lookup", "function": "handle_request()", "description": "lookup_session() may return NULL for unknown session_id but the result is dereferenced unconditionally"},
  {"severity": "high", "title": "Type confusion on union access", "function": "process_attr()", "description": "Accesses av->value.str_val without checking av->type. If av is from parsed input, the wrong union member is read"}
]
```\
"""

TS_FEWSHOT_USER = """\
Analyze the following TypeScript/JavaScript source file for zero-day vulnerabilities.

File: example/server/routes.ts

```ts
app.get("/download", async (req, res) => {
  const name = req.query.name as string;
  res.sendFile(path.join(DATA_DIR, name));
});

app.get("/avatar", async (req, res) => {
  const url = req.query.url as string;
  const r = await fetch(url);
  res.send(await r.text());
});

app.post("/users/:id", requireAuth, async (req, res) => {
  await db.user.update({
    where: { id: req.params.id },
    data: req.body,
  });
  res.send("ok");
});
```

Provide a detailed security analysis.\
"""

TS_FEWSHOT_ASSISTANT = """\
`GET /download`: `req.query.name` controls the path passed to `sendFile`; \
there is no resolve-and-prefix check keeping the result under `DATA_DIR`. \
`GET /avatar`: `req.query.url` is fetched directly, which can reach internal \
services. `POST /users/:id`: authentication exists, but no ownership check \
links the authenticated user to `req.params.id`, and the full request body \
is passed into the ORM.

```json
[
  {"severity": "high", "title": "Path traversal in download endpoint", "function": "GET /download", "description": "User-controlled name is joined with DATA_DIR and sent with sendFile without resolving and checking that the final path stays under DATA_DIR."},
  {"severity": "high", "title": "SSRF via attacker-controlled fetch URL", "function": "GET /avatar", "description": "The endpoint fetches req.query.url directly, allowing requests to internal services unless an allowlist or URL validation exists."},
  {"severity": "high", "title": "IDOR/mass assignment in user update", "function": "POST /users/:id", "description": "Authenticated users can update arbitrary user ids from params, and req.body is passed directly into the ORM without field allowlisting."}
]
```\
"""

PY_FEWSHOT_USER = """\
Analyze the following Python source file for zero-day vulnerabilities.

File: example/app/views.py

```python
@app.route("/run")
def run_job():
    name = request.args["name"]
    subprocess.check_output(f"backup --name {name}", shell=True)
    return "ok"

@app.route("/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(cfg)

@app.route("/files/<path:name>")
def download(name):
    return send_file(os.path.join(DATA_DIR, name))

@app.post("/users/<user_id>")
@login_required
def update_user(user_id):
    db.execute(f"update users set email='{request.json['email']}' where id='{user_id}'")
    return "ok"
```

Provide a detailed security analysis.\
"""

PY_FEWSHOT_ASSISTANT = """\
`run_job`: query string data reaches a shell command. `import_config`: \
`yaml.load` with the unsafe loader parses attacker-controlled bytes. \
`download`: path data is joined and served without a resolved-prefix check. \
`update_user`: authentication exists, but ownership is not checked and raw \
SQL is built from attacker-controlled fields.

```json
[
  {"severity": "critical", "title": "Command injection through shell=True backup command", "function": "run_job()", "description": "request.args['name'] is interpolated into a shell command passed to subprocess.check_output(..., shell=True)."},
  {"severity": "critical", "title": "Unsafe YAML deserialization of request body", "function": "import_config()", "description": "The route passes attacker-controlled request.data to yaml.load with yaml.Loader, which can construct unsafe Python objects."},
  {"severity": "high", "title": "Path traversal in file download", "function": "download()", "description": "The route joins attacker-controlled path data with DATA_DIR and serves it without resolving and verifying that the final path stays under DATA_DIR."},
  {"severity": "high", "title": "SQL injection and missing ownership check in user update", "function": "update_user()", "description": "The handler builds SQL with f-strings from request data and user_id, and login_required alone does not prove the caller owns the target user_id."}
]
```\
"""

SH_FEWSHOT_USER = """\
Analyze the following Shell source file for zero-day vulnerabilities.

File: example/scripts/deploy.sh

```bash
#!/usr/bin/env bash
set -e
branch="$1"
pkg="$2"
tmp="/tmp/deploy-$branch"

eval "git checkout $branch"
tar xf "$pkg" -C /opt/app
rm -rf $tmp
curl "$INSTALL_URL" | sh
```

Provide a detailed security analysis.\
"""

SH_FEWSHOT_ASSISTANT = """\
`branch` is argv-controlled and reaches `eval`, so shell metacharacters \
execute in the script context. `pkg` may be attacker-controlled and is \
extracted without traversal defenses. `tmp` includes attacker-controlled \
branch data and is later expanded unquoted in `rm -rf`. `curl | sh` runs \
network data as code if `INSTALL_URL` is not trusted.

```json
[
  {"severity": "critical", "title": "Command injection through eval on branch argument", "function": "deploy.sh", "description": "The first argv value is interpolated into eval \"git checkout $branch\", allowing shell metacharacters to run in the deployment script context."},
  {"severity": "high", "title": "Unsafe archive extraction into application directory", "function": "deploy.sh", "description": "The script extracts an attacker-supplied archive into /opt/app without checking for path traversal or unsafe ownership/permission metadata."},
  {"severity": "high", "title": "Unquoted attacker-controlled path reaches rm -rf", "function": "deploy.sh", "description": "tmp includes the branch argument and is expanded unquoted in rm -rf, enabling word splitting, globbing, and option/path confusion in a destructive command."},
  {"severity": "medium", "title": "Network script execution through curl pipe", "function": "deploy.sh", "description": "curl \"$INSTALL_URL\" | sh executes remote content in the script context unless INSTALL_URL is a trusted, pinned source."}
]
```\
"""

CI_FEWSHOT_USER = """\
Analyze the following CI/CD source file for zero-day vulnerabilities.

File: .github/workflows/deploy.yml

```yaml
name: deploy
on: pull_request_target
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
      - run: echo "${{ github.event.pull_request.title }}" | sh
      - run: ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

Provide a detailed security analysis.\
"""

CI_FEWSHOT_ASSISTANT = """\
This workflow runs on `pull_request_target`, has write-all permissions and \
secrets, checks out untrusted PR code, then executes commands. The PR title \
also reaches `sh`. That crosses the untrusted PR to privileged-token boundary.

```json
[
  {"severity": "critical", "title": "Privileged pull_request_target workflow executes untrusted PR code", "function": "deploy job", "description": "The workflow runs with pull_request_target permissions and secrets, checks out github.event.pull_request.head.sha, then runs npm install and deploy.sh from untrusted code."},
  {"severity": "critical", "title": "Shell injection from pull request title", "function": "deploy job", "description": "github.event.pull_request.title is attacker-controlled and is piped to sh in a privileged workflow context."}
]
```\
"""

GENERIC_FEWSHOT_USER = TS_FEWSHOT_USER
GENERIC_FEWSHOT_ASSISTANT = TS_FEWSHOT_ASSISTANT

C_TRIAGE_RULES = """\
- INVALID if the crash is an internal-only misuse with no untrusted caller.
- INVALID if a caller-provided size is concretely bounded below the destination size.
- VALID if attacker-controlled data reaches a memory-corrupting operation, unsafe parser state, or privileged file/command sink without a verified sufficient defense.
- If claiming a bound exists, show the numeric value and the arithmetic.\
"""

MANAGED_TRIAGE_RULES = """\
- INVALID if the issue is only a type error, ordinary exception, or crash with no meaningful security impact.
- INVALID if input is already constrained by a named schema/serializer/validator and the validator is sufficient; name the schema/function and allowed pattern.
- INVALID if the route is admin-only and the reported impact is only against the admin's own data, unless privilege escalation or tenant escape exists.
- VALID for authz bugs only when a lower-privileged user can affect another user, tenant, or resource.
- If claiming path traversal is prevented, show the normalize/resolve check and prefix comparison.
- If claiming command injection is prevented, show list-argv usage or safe quoting; do not assume.
- If claiming authz exists, show the ownership/tenant check, not just authentication.\
"""

SHELL_TRIAGE_RULES = """\
- INVALID if the variable is constant, internal-only, or not attacker-controlled.
- INVALID if the variable is always safely quoted and passed after -- where option injection matters.
- VALID if untrusted input reaches eval, sh -c, backticks, unquoted command position, destructive file operation, or a privileged CI/deploy context.
- If claiming quoting is sufficient, show the exact expansion and command invocation.\
"""

CI_TRIAGE_RULES = """\
- INVALID if the workflow only runs on trusted branches or trusted maintainers with no untrusted data crossing into a privileged sink.
- VALID if untrusted PR/input/artifact/cache data reaches shell execution, deployment, secrets, write tokens, or privileged checkout.
- For pull_request_target, verify whether untrusted code or metadata is checked out or executed before declaring it safe.
- If claiming permissions are safe, show the effective permissions and secret exposure boundary.\
"""

GENERIC_TRIAGE_RULES = """\
- INVALID if the finding is generic hardening advice without attacker reachability and concrete impact.
- INVALID if a named validator, sanitizer, wrapper, or authorization check is verified sufficient.
- VALID when untrusted input reaches a sensitive sink across a security boundary and no concrete defense is found.
- Verify defenses by naming the exact function, schema, setting, or wrapper.\
"""

LANGUAGE_PROFILES = {
    "c": {
        "id": "c",
        "name": "C/C++",
        "extensions": [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"],
        "filenames": [],
        "fence": "c",
        "grep_globs": ["*.c", "*.h", "*.cc", "*.cpp", "*.cxx", "*.hpp", "*.hxx"],
        "focus": C_SECURITY_FOCUS,
        "context_checklist": C_CONTEXT_CHECKLIST,
        "triage_rules": C_TRIAGE_RULES,
        "fewshot_user": C_FEWSHOT_USER,
        "fewshot_assistant": C_FEWSHOT_ASSISTANT,
    },
    "ts": {
        "id": "ts",
        "name": "TypeScript/JavaScript",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"],
        "filenames": [],
        "fence": "ts",
        "grep_globs": ["*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs", "*.mts", "*.cts"],
        "focus": TS_JS_SECURITY_FOCUS,
        "context_checklist": TS_JS_CONTEXT_CHECKLIST,
        "triage_rules": MANAGED_TRIAGE_RULES,
        "fewshot_user": TS_FEWSHOT_USER,
        "fewshot_assistant": TS_FEWSHOT_ASSISTANT,
    },
    "py": {
        "id": "py",
        "name": "Python",
        "extensions": [".py", ".pyi"],
        "filenames": [],
        "fence": "python",
        "grep_globs": ["*.py", "*.pyi"],
        "focus": PY_SECURITY_FOCUS,
        "context_checklist": PY_CONTEXT_CHECKLIST,
        "triage_rules": MANAGED_TRIAGE_RULES,
        "fewshot_user": PY_FEWSHOT_USER,
        "fewshot_assistant": PY_FEWSHOT_ASSISTANT,
    },
    "sh": {
        "id": "sh",
        "name": "Shell",
        "extensions": [".sh", ".bash", ".zsh"],
        "filenames": [],
        "fence": "bash",
        "grep_globs": ["*.sh", "*.bash", "*.zsh"],
        "focus": SH_SECURITY_FOCUS,
        "context_checklist": SH_CONTEXT_CHECKLIST,
        "triage_rules": SHELL_TRIAGE_RULES,
        "fewshot_user": SH_FEWSHOT_USER,
        "fewshot_assistant": SH_FEWSHOT_ASSISTANT,
    },
    "ci": {
        "id": "ci",
        "name": "CI/CD YAML",
        "extensions": [".yml", ".yaml"],
        "filenames": [],
        "fence": "yaml",
        "grep_globs": ["*.yml", "*.yaml"],
        "focus": CI_SECURITY_FOCUS,
        "context_checklist": CI_CONTEXT_CHECKLIST,
        "triage_rules": CI_TRIAGE_RULES,
        "fewshot_user": CI_FEWSHOT_USER,
        "fewshot_assistant": CI_FEWSHOT_ASSISTANT,
    },
    "docker": {
        "id": "docker",
        "name": "Dockerfile/Containerfile",
        "extensions": [".dockerfile"],
        "filenames": ["Dockerfile", "Containerfile"],
        "fence": "dockerfile",
        "grep_globs": [
            "Dockerfile", "**/Dockerfile", "Containerfile", "**/Containerfile",
            "*.dockerfile", "*.Dockerfile",
        ],
        "focus": CI_SECURITY_FOCUS,
        "context_checklist": CI_CONTEXT_CHECKLIST,
        "triage_rules": CI_TRIAGE_RULES,
        "fewshot_user": CI_FEWSHOT_USER,
        "fewshot_assistant": CI_FEWSHOT_ASSISTANT,
    },
    "generic": {
        "id": "generic",
        "name": "source",
        "extensions": [],
        "filenames": [],
        "fence": "",
        "grep_globs": ["*"],
        "focus": GENERIC_SECURITY_FOCUS,
        "context_checklist": GENERIC_CONTEXT_CHECKLIST,
        "triage_rules": GENERIC_TRIAGE_RULES,
        "fewshot_user": GENERIC_FEWSHOT_USER,
        "fewshot_assistant": GENERIC_FEWSHOT_ASSISTANT,
    },
}

_PROFILE_EXTENSIONS = {
    ext: profile
    for profile in LANGUAGE_PROFILES.values()
    for ext in profile.get("extensions", [])
}
_PROFILE_FILENAMES = {
    name.lower(): profile
    for profile in LANGUAGE_PROFILES.values()
    for name in profile.get("filenames", [])
}


def language_profile_for_path(filepath):
    """Infer the best language/security profile from a path."""
    base = os.path.basename(filepath).lower()
    if base in _PROFILE_FILENAMES:
        return _PROFILE_FILENAMES[base]

    ext = os.path.splitext(filepath)[1].lower()
    return _PROFILE_EXTENSIONS.get(ext, LANGUAGE_PROFILES["generic"])

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def load_api_keys():
    keys = {}
    for var in ("OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        val = os.environ.get(var)
        if val:
            keys[var] = val
    return keys


def resolve_backend(model, keys):
    if "/" in model:
        api_key = keys.get("OPENROUTER_API_KEY")
        if not api_key:
            print(
                f"❌ Model '{model}' uses OpenRouter (provider/model format) "
                "but OPENROUTER_API_KEY is not set.",
                file=sys.stderr,
            )
            print("   Set it with:  export OPENROUTER_API_KEY=sk-or-...", file=sys.stderr)
            sys.exit(1)
        return OPENROUTER_API_URL, api_key, model, {
            "HTTP-Referer": "https://github.com/weareaisle/nano-analyzer",
            "X-Title": "nano-analyzer",
        }

    api_key = keys.get("OPENAI_API_KEY")
    if not api_key:
        print(
            f"❌ Model '{model}' uses OpenAI but OPENAI_API_KEY is not set.",
            file=sys.stderr,
        )
        print("   Set it with:  export OPENAI_API_KEY=sk-...", file=sys.stderr)
        sys.exit(1)
    return OPENAI_API_URL, api_key, model, {}


def _resolve_codex_cli(keys):
    cli = (
        keys.get("_CODEX_CLI")
        or os.environ.get("NANO_ANALYZER_CODEX_CLI")
        or "codex"
    )
    has_path = os.path.sep in cli or (os.path.altsep and os.path.altsep in cli)
    if has_path:
        return cli if os.path.exists(cli) else None
    return shutil.which(cli)


def _resolve_claude_cli(keys):
    cli = (
        keys.get("_CLAUDE_CLI")
        or os.environ.get("NANO_ANALYZER_CLAUDE_CLI")
        or "claude"
    )
    has_path = os.path.sep in cli or (os.path.altsep and os.path.altsep in cli)
    if has_path:
        return cli if os.path.exists(cli) else None
    return shutil.which(cli)


def _clean_cli_setting(value):
    if not isinstance(value, str):
        return None
    value = re.sub(r'\x1b\[[0-9;]*m', '', value).strip()
    value = re.sub(r'\[[0-9;]*m\]$', '', value).strip()
    return value or None


def _read_simple_toml_string(path, key):
    """Best-effort parser for simple top-level `key = "value"` settings."""
    try:
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("["):
                    break
                m = re.match(
                    rf'{re.escape(key)}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^#\s]+))',
                    line,
                )
                if m:
                    return _clean_cli_setting(next(g for g in m.groups() if g is not None))
    except OSError:
        return None
    return None


def _codex_config_path():
    codex_home = os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")
    return os.path.join(codex_home, "config.toml")


def _claude_settings_path():
    claude_home = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return os.path.join(claude_home, "settings.json")


def _read_json_setting(path, key):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return _clean_cli_setting(data.get(key))


def _codex_config_model():
    return _read_simple_toml_string(_codex_config_path(), "model")


def _codex_config_effort():
    return _read_simple_toml_string(_codex_config_path(), "model_reasoning_effort")


def _claude_settings_model():
    return _read_json_setting(_claude_settings_path(), "model")


def _claude_settings_effort():
    return _read_json_setting(_claude_settings_path(), "effortLevel")


def _looks_like_claude_model(model):
    return model in CLAUDE_MODEL_ALIASES or model.startswith("claude-")


def select_llm_backend(model, keys):
    requested = keys.get("_BACKEND", "auto")
    if requested == "api":
        return "api"
    if requested == "codex" or model in CODEX_MODEL_ALIASES:
        return "codex"
    if requested == "claude" or _looks_like_claude_model(model):
        return "claude"
    if "/" in model:
        return "api"
    if keys.get("OPENAI_API_KEY"):
        return "api"
    if _resolve_codex_cli(keys):
        return "codex"
    if _resolve_claude_cli(keys):
        return "claude"
    return "api"


def configure_llm_backend(args, keys):
    keys["_BACKEND"] = args.backend
    keys["_CODEX_CLI"] = args.codex_cli
    keys["_CODEX_TIMEOUT"] = args.codex_timeout
    keys["_CLAUDE_CLI"] = args.claude_cli
    keys["_CLAUDE_TIMEOUT"] = args.claude_timeout
    keys["_CLAUDE_EFFORT"] = (
        args.claude_effort
        or os.environ.get("NANO_ANALYZER_CLAUDE_EFFORT")
    )

    backend = select_llm_backend(args.model, keys)
    keys["_RESOLVED_BACKEND"] = backend

    codex_model = args.codex_model
    if (
        backend == "codex"
        and not codex_model
        and args.model not in CODEX_MODEL_ALIASES
        and args.model != DEFAULT_MODEL
    ):
        codex_model = args.model
    if backend == "codex" and not codex_model:
        codex_model = os.environ.get("NANO_ANALYZER_CODEX_MODEL")
    keys["_CODEX_MODEL"] = codex_model
    keys["_CODEX_EFFECTIVE_MODEL"] = (
        codex_model
        if backend == "codex" and codex_model
        else _codex_config_model() if backend == "codex" else None
    )
    keys["_CODEX_REASONING_EFFORT"] = (
        _codex_config_effort() if backend == "codex" else None
    )

    claude_model = args.claude_model
    if (
        backend == "claude"
        and not claude_model
        and args.model != DEFAULT_MODEL
    ):
        claude_model = args.model
    if backend == "claude" and not claude_model:
        claude_model = os.environ.get("NANO_ANALYZER_CLAUDE_MODEL")
    keys["_CLAUDE_MODEL"] = claude_model
    keys["_CLAUDE_EFFECTIVE_MODEL"] = (
        claude_model
        if backend == "claude" and claude_model
        else _claude_settings_model() if backend == "claude" else None
    )
    keys["_CLAUDE_EFFECTIVE_EFFORT"] = (
        keys.get("_CLAUDE_EFFORT")
        if backend == "claude" and keys.get("_CLAUDE_EFFORT")
        else _claude_settings_effort() if backend == "claude" else None
    )

    if backend == "codex":
        codex_cli = _resolve_codex_cli(keys)
        if not codex_cli:
            print(
                "❌ Codex backend requested, but `codex` was not found.",
                file=sys.stderr,
            )
            print(
                "   Install/login to Codex CLI or pass --codex-cli /path/to/codex.",
                file=sys.stderr,
            )
            sys.exit(1)
        keys["_CODEX_CLI_PATH"] = codex_cli
    elif backend == "claude":
        claude_cli = _resolve_claude_cli(keys)
        if not claude_cli:
            print(
                "❌ Claude backend requested, but `claude` was not found.",
                file=sys.stderr,
            )
            print(
                "   Install/login to Claude Code or pass --claude-cli /path/to/claude.",
                file=sys.stderr,
            )
            sys.exit(1)
        keys["_CLAUDE_CLI_PATH"] = claude_cli
    else:
        resolve_backend(args.model, keys)

    return backend


def _messages_to_cli_prompt(messages, json_mode):
    prompt = [
        "You are the LLM completion backend for nano-analyzer.",
        "Follow the role-tagged conversation exactly as a chat completion.",
        "Do not modify files. Do not run shell commands. Answer only from the supplied content.",
    ]
    if json_mode:
        prompt.append("Return only one valid JSON object. Do not use Markdown fences.")
    prompt.append("\nConversation:")

    for msg in messages:
        role = msg.get("role", "user").upper()
        content = msg.get("content", "")
        prompt.append(f"\n<{role}>\n{content}\n</{role}>")

    prompt.append("\nRespond to the final USER message.")
    return "\n".join(prompt)


def _call_codex_cli(model, messages, keys, json_mode=False,
                    max_retries=3, reasoning_effort=None):
    del reasoning_effort  # Codex CLI uses its own configured reasoning settings.

    codex_cli = keys.get("_CODEX_CLI_PATH") or _resolve_codex_cli(keys)
    if not codex_cli:
        raise RuntimeError("Codex CLI not found")

    codex_model = keys.get("_CODEX_MODEL")
    if not codex_model and model not in CODEX_MODEL_ALIASES:
        codex_model = os.environ.get("NANO_ANALYZER_CODEX_MODEL")

    timeout = keys.get("_CODEX_TIMEOUT") or 600
    prompt = _messages_to_cli_prompt(messages, json_mode)
    last_error = None

    for attempt in range(max_retries):
        time.sleep(
            random.uniform(0.1, 1.0)
            if attempt == 0
            else 2 ** attempt + random.uniform(0, 2)
        )

        with tempfile.TemporaryDirectory(prefix="nano-analyzer-codex-") as tmpdir:
            out_path = os.path.join(tmpdir, "last-message.txt")
            cmd = [
                codex_cli, "exec",
                "--color", "never",
                "--sandbox", "read-only",
                "--skip-git-repo-check",
                "--ephemeral",
                "--output-last-message", out_path,
            ]

            if codex_model:
                cmd.extend(["--model", codex_model])

            if json_mode:
                schema_path = os.path.join(tmpdir, "schema.json")
                with open(schema_path, "w") as sf:
                    json.dump(CODEX_JSON_OBJECT_SCHEMA, sf)
                cmd.extend(["--output-schema", schema_path])

            cmd.append("-")

            try:
                t0 = time.time()
                semaphore = _api_semaphore or threading.Semaphore(1)
                with semaphore:
                    proc = subprocess.run(
                        cmd,
                        input=prompt,
                        text=True,
                        capture_output=True,
                        timeout=timeout,
                    )
                elapsed = time.time() - t0

                if proc.returncode != 0:
                    detail = (proc.stderr or proc.stdout or "").strip()
                    raise RuntimeError(
                        f"Codex CLI failed ({proc.returncode}): {detail[-500:]}"
                    )

                content = ""
                if os.path.exists(out_path):
                    with open(out_path) as outf:
                        content = outf.read().strip()
                if not content:
                    content = (proc.stdout or "").strip()
                if not content:
                    raise RuntimeError("Codex CLI returned an empty response")

                return content, {}, elapsed

            except (subprocess.TimeoutExpired, RuntimeError) as e:
                last_error = e
                if attempt == max_retries - 1:
                    raise RuntimeError(
                        f"Codex CLI failed after {max_retries} retries: {e}"
                    )

    raise RuntimeError(f"Codex CLI failed: {last_error}")


def _call_claude_cli(model, messages, keys, json_mode=False,
                     max_retries=3, reasoning_effort=None):
    del reasoning_effort  # Claude Code uses --effort / its own config.

    claude_cli = keys.get("_CLAUDE_CLI_PATH") or _resolve_claude_cli(keys)
    if not claude_cli:
        raise RuntimeError("Claude Code CLI not found")

    claude_model = keys.get("_CLAUDE_MODEL")
    if not claude_model and not _looks_like_claude_model(model):
        claude_model = os.environ.get("NANO_ANALYZER_CLAUDE_MODEL")

    claude_effort = (
        keys.get("_CLAUDE_EFFORT")
        or os.environ.get("NANO_ANALYZER_CLAUDE_EFFORT")
    )
    timeout = keys.get("_CLAUDE_TIMEOUT") or 600
    prompt = _messages_to_cli_prompt(messages, json_mode)
    last_error = None

    for attempt in range(max_retries):
        time.sleep(
            random.uniform(0.1, 1.0)
            if attempt == 0
            else 2 ** attempt + random.uniform(0, 2)
        )

        with tempfile.TemporaryDirectory(prefix="nano-analyzer-claude-") as tmpdir:
            cmd = [
                claude_cli,
                "--print",
                "--no-session-persistence",
                "--permission-mode", "dontAsk",
                "--tools", "",
                "--output-format", "json",
            ]

            if claude_model:
                cmd.extend(["--model", claude_model])
            if claude_effort:
                cmd.extend(["--effort", claude_effort])
            if json_mode:
                cmd.extend(["--json-schema", json.dumps(CODEX_JSON_OBJECT_SCHEMA)])

            try:
                t0 = time.time()
                semaphore = _api_semaphore or threading.Semaphore(1)
                with semaphore:
                    proc = subprocess.run(
                        cmd,
                        input=prompt,
                        text=True,
                        capture_output=True,
                        timeout=timeout,
                        cwd=tmpdir,
                    )
                elapsed = time.time() - t0

                output = (proc.stdout or "").strip()
                detail = (proc.stderr or output or "").strip()
                if proc.returncode != 0 and not output:
                    raise RuntimeError(
                        f"Claude Code failed ({proc.returncode}): {detail[-500:]}"
                    )

                try:
                    data = json.loads(output)
                except (json.JSONDecodeError, ValueError):
                    if proc.returncode != 0:
                        raise RuntimeError(
                            f"Claude Code failed ({proc.returncode}): {detail[-500:]}"
                        )
                    if not output:
                        raise RuntimeError("Claude Code returned an empty response")
                    return output, {}, elapsed

                if isinstance(data, dict) and data.get("is_error"):
                    msg = data.get("result") or data.get("message") or detail
                    status = data.get("api_error_status")
                    if status in (401, 403):
                        raise PermissionError(msg)
                    raise RuntimeError(msg)

                if isinstance(data, dict) and "result" in data:
                    content = data.get("result")
                    usage = data.get("usage") or {}
                    if data.get("duration_ms"):
                        elapsed = data["duration_ms"] / 1000
                else:
                    content = data
                    usage = {}

                if not isinstance(content, str):
                    content = json.dumps(content)
                content = content.strip()
                if not content:
                    raise RuntimeError("Claude Code returned an empty response")

                return content, usage, elapsed

            except PermissionError as e:
                raise RuntimeError(f"Claude Code authentication failed: {e}") from e
            except (subprocess.TimeoutExpired, RuntimeError) as e:
                last_error = e
                if attempt == max_retries - 1:
                    raise RuntimeError(
                        f"Claude Code failed after {max_retries} retries: {e}"
                    )

    raise RuntimeError(f"Claude Code failed: {last_error}")


_http_session = None
_http_lock = threading.Lock()
_api_semaphore = None


def _get_session():
    global _http_session
    if _http_session is None:
        with _http_lock:
            if _http_session is None:
                _http_session = urllib.request.build_opener(
                    urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(),
                )
    return _http_session


def init_api_semaphore(max_concurrent):
    global _api_semaphore
    _api_semaphore = threading.Semaphore(max_concurrent)


def call_llm(model, messages, keys, json_mode=False, max_retries=3, reasoning_effort=None):
    backend = keys.get("_RESOLVED_BACKEND") or select_llm_backend(model, keys)
    if backend == "codex":
        return _call_codex_cli(
            model, messages, keys,
            json_mode=json_mode,
            max_retries=max_retries,
            reasoning_effort=reasoning_effort,
        )
    if backend == "claude":
        return _call_claude_cli(
            model, messages, keys,
            json_mode=json_mode,
            max_retries=max_retries,
            reasoning_effort=reasoning_effort,
        )

    api_url, api_key, model_name, extra_headers = resolve_backend(model, keys)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    payload = {"model": model_name, "messages": messages}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort

    session = _get_session()

    for attempt in range(max_retries):
        time.sleep(
            random.uniform(0.1, 3.0)
            if attempt == 0
            else 2 ** attempt + random.uniform(0, 2)
        )
        try:
            t0 = time.time()
            with _api_semaphore:
                request = urllib.request.Request(
                    api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with session.open(request, timeout=120) as resp:
                    status_code = resp.status
                    response_text = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - t0

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            if status_code != 200:
                raise RuntimeError(f"API {status_code}: {response_text[:200]}")

            data = json.loads(response_text)
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")

            content = data["choices"][0]["message"]["content"]
            if content is None:
                content = data["choices"][0]["message"].get("reasoning_content") or ""
            usage = data.get("usage", {})
            return content, usage, elapsed

        except urllib.error.HTTPError as e:
            status_code = e.code
            response_text = ""
            try:
                response_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                response_text = str(e)

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            raise RuntimeError(f"API {status_code}: {response_text[:200]}")

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            ConnectionResetError,
            OSError,
        ) as e:
            if attempt == max_retries - 1:
                raise RuntimeError(f"Connection failed after {max_retries} retries: {e}")
            time.sleep(2 ** attempt + random.uniform(0, 1))

    raise RuntimeError("Max retries exceeded")
# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------

def _extract_json(text):
    """Try to extract a JSON object or array from text that might have
    markdown fences or surrounding prose."""
    text = text.strip()
    fence = re.search(r'```(?:json)?\s*\n?(.*?)```', text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Repair common nano model JSON malformations (scan output arrays only)
    if '"severity"' in text:
        repaired = text
        # `4: {` instead of `{` in arrays
        repaired = re.sub(r',?\s*\d+\s*:\s*\{', ', {', repaired)
        repaired = re.sub(r'^\[\s*,', '[', repaired.strip())
        # Invalid backslash escapes: \' \0 etc. (not valid in JSON)
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', repaired)
        if repaired != text:
            try:
                return json.loads(repaired)
            except (json.JSONDecodeError, ValueError):
                pass

        # Last resort: extract individual JSON objects from broken arrays
        objects = []
        for m in re.finditer(r'\{\s*"severity"', text):
            depth = 0
            for i in range(m.start(), len(text)):
                if text[i] == '{': depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        chunk = text[m.start():i + 1]
                        chunk = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', chunk)
                        try:
                            objects.append(json.loads(chunk))
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
        if objects:
            return objects

    for start_char, end_char in [('[', ']'), ('{', '}')]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def parse_findings(text):
    """Parse findings from JSON array, with fallback to regex."""
    # Method 1: >>> marker lines
    marker_pattern = re.compile(
        r'^>>>\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(.+)',
        re.MULTILINE | re.IGNORECASE,
    )
    marker_matches = list(marker_pattern.finditer(text))
    if marker_matches:
        findings = []
        for m in marker_matches:
            sev = m.group(1).lower()
            rest = m.group(2).strip()
            parts = rest.split("|", 2)
            title = parts[0].strip()
            body = rest
            findings.append({"severity": sev, "title": title, "body": body})
        return findings

    # Method 2: JSON
    parsed = _extract_json(text)

    if isinstance(parsed, dict) and "severity" in parsed:
        parsed = [parsed]

    if isinstance(parsed, dict) and "findings" in parsed:
        parsed = parsed["findings"]

    if isinstance(parsed, list):
        findings = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", "medium").lower()
            if sev == "none":
                continue
            findings.append({
                "severity": sev,
                "title": item.get("title", "Untitled finding"),
                "body": item.get("description", "") + ("\n\nFix: " + item["fix"] if item.get("fix") else ""),
            })
        return findings

    _BUG_KEYWORD = re.compile(
        r'(?:overflow|underflow|use.after.free|double.free|null.pointer|'
        r'null.deref|out.of.bounds|oob|buffer|race|deadlock|'
        r'injection|bypass|escalat|uncheck|missing.check|missing.bound|'
        r'missing.valid|unbounded|unchecked|integer.overflow|'
        r'uaf|memcpy|sprintf|strcpy|strcat|format.string|'
        r'denial.of.service|dos\b|crash|panic|corrupt|'
        r'leak|disclosure|uninitiali|dangling|stale|'
        r'sequence|replay|shift|xdr|length|size)',
        re.IGNORECASE,
    )
    _JUNK_TITLE = re.compile(
        r'(?:^summary|^overview|^what (?:this|to|i) |^threat model|'
        r'^overall|^conclusion|^next step|^recommend|^note|'
        r'^checklist|^audit |^action|^practical |'
        r'^.?level\b|^/info|^.?impact\b|^.?risk\b|'
        r'^.?confidence\b|exploitation path|candidates|'
        r'^concurrency consider|^other |^ssues|^oncrete )',
        re.IGNORECASE,
    )
    # Filter out function-signature headings (documentation, not findings)
    _FUNC_SIG = re.compile(r'^[`\s]*\w+[\w_]*\s*[\(/]', re.IGNORECASE)

    findings = []
    heading_pattern = re.compile(
        r'^#{1,4}\s+'
        r'(?:\d+[\.\)]\s*'                  # "## 1) Title" or "## 2. Title"
        r'|(?:critical|high|medium|low)\b'   # "## High severity: ..."
        r'|[>`\w]'                           # "## `function_name()`" or any heading
        r')'
        r'(.*)',
        re.MULTILINE | re.IGNORECASE,
    )
    matches = list(heading_pattern.finditer(text))
    if matches:
        for i, m in enumerate(matches):
            title = m.group(1).strip().strip("*").strip()
            title = re.sub(r'^severity\s*[:/]\s*', '', title, flags=re.IGNORECASE)
            title = re.sub(r'^[\(\[]?\s*(?:critical|high|medium|low|informational)\s*[\)\]]?\s*[:/]?\s*',
                           '', title, flags=re.IGNORECASE).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            section = text[start:end]
            if _JUNK_TITLE.search(title):
                continue
            if _FUNC_SIG.search(title):
                continue
            if not _BUG_KEYWORD.search(title) and not _BUG_KEYWORD.search(section[:300]):
                continue
            sev = "medium"
            for level in SEVERITY_LEVELS:
                if re.search(r'\b' + level + r'\b', section, re.IGNORECASE):
                    sev = level
                    break
            findings.append({"severity": sev, "title": title, "body": section.strip()})

    if not findings:
        for level in SEVERITY_LEVELS:
            if re.search(r'\b' + level + r'\b', text, re.IGNORECASE):
                findings.append({"severity": level, "title": "Unstructured finding", "body": text})
                break

    return findings


def count_severities(text):
    findings = parse_findings(text)
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def top_severity(sevs):
    for level in SEVERITY_LEVELS:
        if sevs.get(level, 0) > 0:
            return level
    return "clean"

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _git_root_for_path(path):
    """Return the git worktree root for path, or None outside git."""
    start = path if os.path.isdir(path) else os.path.dirname(path)
    if not start:
        start = "."

    try:
        proc = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None
    root = proc.stdout.strip()
    return os.path.abspath(root) if root else None


def _git_tracked_and_unignored_files(path):
    """List tracked plus unignored untracked files under path, if path is in git."""
    git_root = _git_root_for_path(path)
    if not git_root:
        return None

    abs_path = os.path.abspath(path)
    try:
        common = os.path.commonpath([git_root, abs_path])
    except ValueError:
        return None
    if common != git_root:
        return None

    pathspec = os.path.relpath(abs_path, git_root)
    if pathspec == ".":
        pathspec = "."

    try:
        proc = subprocess.run(
            [
                "git", "-C", git_root, "ls-files", "-z",
                "--cached", "--others", "--exclude-standard",
                "--", pathspec,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None

    files = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8", errors="surrogateescape")
        files.append(os.path.join(git_root, rel))
    return files


def _under_default_skip_dir(filepath, scan_base):
    """True when filepath is below a default skipped directory for this scan."""
    try:
        rel = os.path.relpath(os.path.abspath(filepath), scan_base)
    except ValueError:
        return False
    if rel == "." or rel.startswith(".."):
        return False

    parts = rel.split(os.sep)
    for part in parts[:-1]:
        if part in DEFAULT_SKIP_DIRS or part.endswith(".egg-info"):
            return True
    return False


def _matches_requested_file_type(filepath, extensions, filenames=None):
    """True when a file should be scanned based on extension or basename."""
    if not extensions and not filenames:
        return True

    ext = os.path.splitext(filepath)[1].lower()
    if extensions and ext in extensions:
        return True

    basename = os.path.basename(filepath)
    lower_filenames = {name.lower() for name in (filenames or set())}
    return basename.lower() in lower_filenames


def discover_files(path, extensions, max_chars, respect_gitignore=True, filenames=None):
    """Walk a path (file or dir) and return (scannable, skipped) lists."""
    scannable = []
    skipped = []
    abs_path = os.path.abspath(path)
    scan_base = abs_path if os.path.isdir(path) else os.path.dirname(abs_path)

    if os.path.isfile(path):
        candidates = (
            _git_tracked_and_unignored_files(path)
            if respect_gitignore else None
        )
        if candidates is None:
            candidates = [path]
    else:
        candidates = (
            _git_tracked_and_unignored_files(path)
            if respect_gitignore else None
        )
        if candidates is None:
            candidates = []
            for root, dirnames, fnames in os.walk(path):
                dirnames[:] = sorted(
                    d for d in dirnames
                    if d not in DEFAULT_SKIP_DIRS and not d.endswith(".egg-info")
                )
                for fn in sorted(fnames):
                    candidates.append(os.path.join(root, fn))

    for filepath in sorted(candidates):
        if _under_default_skip_dir(filepath, scan_base):
            skipped.append((filepath, "ignored directory"))
            continue

        if not os.path.isfile(filepath):
            skipped.append((filepath, "not a regular file"))
            continue

        if os.path.islink(filepath):
            skipped.append((filepath, "symlink"))
            continue

        if not _matches_requested_file_type(filepath, extensions, filenames):
            skipped.append((filepath, "extension"))
            continue

        try:
            size = os.path.getsize(filepath)
        except OSError:
            skipped.append((filepath, "unreadable"))
            continue

        if size > max_chars:
            skipped.append((filepath, f"too large ({size:,} bytes)"))
            continue

        try:
            with open(filepath, encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
            line_count = content.count("\n")
            char_count = len(content)
        except (OSError, UnicodeDecodeError):
            skipped.append((filepath, "unreadable/binary"))
            continue

        if char_count > max_chars:
            skipped.append((filepath, f"too large ({char_count:,} chars)"))
            continue

        scannable.append({
            "filepath": filepath,
            "lines": line_count,
            "chars": char_count,
        })

    return scannable, skipped


def _read_text_prefix(path, max_chars=8000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(max_chars)
    except OSError:
        return ""


def _first_existing(repo_dir, names):
    for name in names:
        path = os.path.join(repo_dir, name)
        if os.path.isfile(path):
            return path
    return None


def _summarize_package_json(repo_dir):
    path = _first_existing(repo_dir, ["package.json"])
    if not path:
        return None

    try:
        data = json.loads(_read_text_prefix(path, max_chars=80_000))
    except json.JSONDecodeError:
        return "package.json present but could not be parsed"

    scripts = data.get("scripts", {})
    deps = {}
    for key in ("dependencies", "devDependencies"):
        deps.update(data.get(key, {}) or {})

    frameworks = [
        name for name in (
            "next", "express", "@nestjs/core", "@remix-run/node", "@trpc/server",
            "fastify", "koa", "hapi", "electron", "prisma", "typeorm",
            "sequelize", "drizzle-orm", "mongoose", "zod", "joi", "yup",
            "class-validator",
        )
        if name in deps
    ]
    shown_scripts = ", ".join(list(scripts.keys())[:12]) or "none"
    shown_deps = ", ".join(frameworks[:20]) or "none detected"
    return f"package.json: scripts={shown_scripts}; notable deps={shown_deps}"


def _summarize_python_manifests(repo_dir):
    lines = []
    pyproject = _first_existing(repo_dir, ["pyproject.toml"])
    if pyproject:
        text = _read_text_prefix(pyproject, max_chars=20_000)
        interesting = []
        for line in text.splitlines():
            stripped = line.strip()
            if (
                stripped.startswith("[project]")
                or stripped.startswith("[tool.poetry")
                or stripped.startswith("[tool.uv")
                or stripped.startswith("dependencies")
                or stripped.startswith("requires-python")
                or any(name in stripped.lower() for name in (
                    "django", "flask", "fastapi", "celery", "pydantic",
                    "sqlalchemy", "requests", "httpx",
                ))
            ):
                interesting.append(stripped)
            if len(interesting) >= 12:
                break
        lines.append("pyproject.toml: " + "; ".join(interesting[:12]))

    req = _first_existing(repo_dir, ["requirements.txt", "requirements-dev.txt"])
    if req:
        pkgs = []
        for line in _read_text_prefix(req, max_chars=20_000).splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                pkgs.append(re.split(r'[<=>\[]', stripped, 1)[0])
            if len(pkgs) >= 20:
                break
        lines.append("requirements: " + ", ".join(pkgs))

    return "\n".join(lines) if lines else None


def _summarize_routes_and_settings(repo_dir):
    facts = []
    route_markers = []
    settings_markers = []
    for root, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [
            d for d in dirnames
            if d not in DEFAULT_SKIP_DIRS and not d.endswith(".egg-info")
        ]
        rel_root = os.path.relpath(root, repo_dir)
        if rel_root.count(os.sep) > 4:
            dirnames[:] = []
            continue

        for filename in filenames:
            rel = os.path.normpath(os.path.join(rel_root, filename))
            rel = filename if rel == "." else rel
            lowered = rel.lower()
            if (
                "pages/api" in lowered
                or "app/api" in lowered
                or lowered.endswith("routes.ts")
                or lowered.endswith("routes.js")
                or lowered.endswith("urls.py")
                or lowered.endswith("router.py")
                or lowered.endswith("views.py")
            ):
                route_markers.append(rel)
            if lowered.endswith("settings.py") or lowered.endswith("next.config.js") or lowered.endswith("next.config.ts"):
                settings_markers.append(rel)

        if len(route_markers) >= 20 and len(settings_markers) >= 8:
            break

    if route_markers:
        facts.append("route files: " + ", ".join(route_markers[:20]))
    if settings_markers:
        facts.append("settings/config files: " + ", ".join(settings_markers[:8]))
    return "\n".join(facts) if facts else None


def _summarize_ci_files(repo_dir):
    facts = []
    workflows_dir = os.path.join(repo_dir, ".github", "workflows")
    if os.path.isdir(workflows_dir):
        workflow_summaries = []
        for name in sorted(os.listdir(workflows_dir))[:12]:
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(workflows_dir, name)
            text = _read_text_prefix(path, max_chars=12000)
            triggers = []
            permissions = []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith(("on:", "pull_request", "pull_request_target", "workflow_dispatch")):
                    triggers.append(stripped)
                if stripped.startswith(("permissions:", "contents:", "id-token:", "actions:", "checks:")):
                    permissions.append(stripped)
                if len(triggers) >= 6 and len(permissions) >= 6:
                    break
            detail = []
            if triggers:
                detail.append("triggers=" + ", ".join(triggers[:6]))
            if permissions:
                detail.append("permissions=" + ", ".join(permissions[:6]))
            workflow_summaries.append(f"{name} ({'; '.join(detail) or 'no trigger summary'})")
        if workflow_summaries:
            facts.append("workflows: " + "; ".join(workflow_summaries))

    docker_files = []
    for root, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [
            d for d in dirnames
            if d not in DEFAULT_SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for filename in filenames:
            if filename in DEFAULT_FILENAMES or filename.lower().endswith(".dockerfile"):
                docker_files.append(os.path.relpath(os.path.join(root, filename), repo_dir))
        if len(docker_files) >= 12:
            break
    if docker_files:
        facts.append("docker/container files: " + ", ".join(docker_files[:12]))
    return "\n".join(facts) if facts else None


def collect_repo_manifest_context(repo_dir, max_chars=2500):
    """Collect compact repo-level facts relevant to managed-language scans."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return "(repo context unavailable)"

    sections = []
    for summarizer in (
        _summarize_package_json,
        _summarize_python_manifests,
        _summarize_routes_and_settings,
        _summarize_ci_files,
    ):
        summary = summarizer(repo_dir)
        if summary:
            sections.append(summary)

    if not sections:
        return "(no manifest/framework facts detected)"

    text = "\n".join(f"- {section}" for section in sections)
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "\n- (repo context truncated)"
    return text

# ---------------------------------------------------------------------------
# Core scan logic (per-file, runs in thread)
# ---------------------------------------------------------------------------

def scan_single_file(filepath, code, display_name, model, keys, repo_dir=None,
                     profile=None, repo_context=None):
    """Run the two-stage scan on a single file. Returns result dict."""
    profile = profile or language_profile_for_path(filepath)
    repo_context = repo_context or "(repo context unavailable)"
    result = {
        "file": filepath,
        "display_name": display_name,
        "model": model,
        "language_profile": profile["id"],
        "language_name": profile["name"],
    }

    try:
        # Stage 1: generate context (with optional grep)
        context_prompt = CONTEXT_GEN_PROMPT_TEMPLATE.format(
            language_name=profile["name"],
            context_checklist=profile["context_checklist"],
            repo_context=repo_context[:2500],
        )
        ctx_messages = [
            {"role": "system", "content": context_prompt},
            {"role": "user", "content": (
                f"File: {display_name}\n\n"
                f"```{profile['fence']}\n{code}\n```"
            )},
        ]
        context, ctx_usage, ctx_elapsed = call_llm(model, ctx_messages, keys)

        # Execute any grep requests from context generation
        if repo_dir:
            ctx_greps = execute_grep_requests(
                context, repo_dir, profile["grep_globs"]
            )
            if ctx_greps:
                context += f"\n\n[GREP RESULTS from codebase]:\n{ctx_greps}"

        result["context"] = context
        result["context_tokens"] = ctx_usage.get("total_tokens", 0)
        result["context_elapsed"] = round(ctx_elapsed, 1)

        # Stage 2: vulnerability scan (with few-shot example)
        scan_system_prompt = SCAN_SYSTEM_PROMPT_TEMPLATE.format(
            language_name=profile["name"],
            focus=profile["focus"],
        )
        scan_messages = [
            {"role": "system", "content": scan_system_prompt + "\n\n"
             "Security context for the file being analyzed:\n" + context},
            {"role": "user", "content": profile["fewshot_user"]},
            {"role": "assistant", "content": profile["fewshot_assistant"]},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(
                language_name=profile["name"],
                filepath=display_name,
                fence=profile["fence"],
                code=code,
            )},
        ]
        report, scan_usage, scan_elapsed = call_llm(model, scan_messages, keys)
        result["report"] = report
        result["prompt_tokens"] = scan_usage.get("prompt_tokens", 0)
        result["completion_tokens"] = scan_usage.get("completion_tokens", 0)
        result["total_tokens"] = scan_usage.get("total_tokens", 0)
        result["scan_elapsed"] = round(scan_elapsed, 1)
        result["total_elapsed"] = round(ctx_elapsed + scan_elapsed, 1)
        result["severities"] = count_severities(report)
        result["status"] = "ok"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["severities"] = {level: 0 for level in SEVERITY_LEVELS}

    return result


def extract_findings(report):
    """Extract findings as (title, text) tuples for triage."""
    parsed = parse_findings(report)
    results = []
    for f in parsed:
        fid = f.get("id", "")
        prefix = f"{fid} " if fid else ""
        results.append((
            f"{prefix}{f['title']}",
            f"[{f['severity'].upper()}] {prefix}{f['title']}\n\n{f['body']}",
        ))
    return results


MAX_GREP_REQUESTS = 3
MAX_GREP_LINES = 30
MAX_GREP_LINE_LEN = 2000


_csearch_path = None
_csearch_index = None
_rg_path = shutil.which("rg")


def init_grep_index(repo_dir):
    """Build a csearch index for the repo if csearch is available."""
    global _csearch_path, _csearch_index, _rg_path
    _csearch_path = shutil.which("csearch")
    cindex_path = shutil.which("cindex")
    _rg_path = shutil.which("rg")

    if not _csearch_path or not cindex_path:
        _csearch_path = None
        return

    _csearch_index = f"/tmp/nano_aisle_{os.path.basename(repo_dir)}.csearchindex"
    if os.path.exists(_csearch_index):
        return

    print(f"📇 Building search index for {repo_dir}...")
    try:
        subprocess.run(
            [cindex_path, repo_dir],
            capture_output=True, timeout=300,
            env={**os.environ, "CSEARCHINDEX": _csearch_index},
        )
        print(f"📇 Index ready: {_csearch_index}")
    except Exception as e:
        print(f"📇 Index failed: {e} — falling back to ripgrep")
        _csearch_path = None


def execute_grep_requests(response_text, repo_dir, grep_globs=None):
    """Parse grep requests from triage response, execute them, return results.
    Uses csearch if indexed, falls back to ripgrep."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return None
    grep_globs = grep_globs or ["*"]

    requests = []

    # Explicit GREP: lines
    for m in re.finditer(r'GREP:\s*(.+)', response_text, re.IGNORECASE):
        requests.append(m.group(1).strip().strip('`').strip())

    # Prose-style: "grep for `pattern`" or "grep for pattern"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?[`"]([^`"]+)[`"]', response_text):
        val = m.group(1).strip()
        if val and val not in requests:
            requests.append(val)

    # Without backticks: "grep for function_name(" or "GREP function_name"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?(\w[\w_:.*]+\(?)', response_text):
        val = m.group(1).strip()
        if val and len(val) > 6 and val not in requests:
            requests.append(val)

    if not requests:
        return None

    # Junk grep terms the model accidentally produces (from prose near "GREP")
    _GREP_JUNK = {"results", "call", "code", "function", "value",
                  "NULL", "null", "type", "data", "return", "void",
                  "true", "false", "the", "this", "that", "from",
                  "verification", "verifications", "verified", "verify",
                  "evidence", "confirm", "confirmed", "confirms",
                  "output", "outputs", "search", "searches",
                  "pattern", "patterns", "required", "provided",
                  "shown", "needed", "following", "whether",
                  "checked", "checking", "matched", "matches",
                  "returned", "returns", "failed", "missing"}

    def _unescape(s):
        """Strip regex escapes and stray punctuation for literal search."""
        s = re.sub(r'\\[bBdDwWsS]', '', s)
        s = re.sub(r'\\(.)', r'\1', s)
        s = s.strip().strip('"\'`')
        return s

    def _simplify_pattern(pattern):
        """Extract the core identifier from a complex code pattern."""
        identifiers = re.findall(r'[a-zA-Z_]\w*(?:->[\w]+)*', pattern)
        identifiers.sort(key=len, reverse=True)
        for ident in identifiers:
            if len(ident) > 5 and ident not in _GREP_JUNK:
                return ident
        return None

    def _path_matches_grep_globs(path):
        """Filter a relative file path by the active language profile globs."""
        path = path.replace("\\", "/").lstrip("./")
        basename = os.path.basename(path)
        return any(
            fnmatch.fnmatch(path, glob)
            or fnmatch.fnmatch(basename, glob)
            for glob in grep_globs
        )

    def _matches_grep_globs(line):
        """Filter a grep output line by the matched file path."""
        return _path_matches_grep_globs(line.split(":", 1)[0])

    def _python_grep(pattern, repo_dir, fixed=True):
        """Portable fallback when csearch/rg are unavailable."""
        try:
            regex = None if fixed else re.compile(pattern)
        except re.error:
            return ""

        matches = []
        for root, dirnames, filenames in os.walk(repo_dir):
            dirnames[:] = [
                d for d in dirnames
                if d not in DEFAULT_SKIP_DIRS and not d.endswith(".egg-info")
            ]
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, repo_dir)
                if not _path_matches_grep_globs(rel_path):
                    continue
                try:
                    if os.path.getsize(full_path) > DEFAULT_MAX_CHARS:
                        continue
                    with open(full_path, encoding="utf-8", errors="replace") as f:
                        for line_no, line in enumerate(f, 1):
                            haystack = line.rstrip("\n")
                            matched = pattern in haystack if fixed else regex.search(haystack)
                            if matched:
                                matches.append(f"{rel_path}:{line_no}:{haystack}")
                                if len(matches) >= MAX_GREP_LINES * 3:
                                    return "\n".join(matches)
                except OSError:
                    continue
        return "\n".join(matches)

    # Expand compound patterns and clean up
    expanded = []
    for raw in requests[:MAX_GREP_REQUESTS]:
        raw = raw.strip()
        # Split on | and unescape each part
        parts = raw.split("|") if "|" in raw else [raw]
        for part in parts:
            cleaned = _unescape(part)
            if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                continue
            # Strip file path prefixes (e.g. "sys/foo/bar.c:symbol" → "symbol")
            path_prefix = re.match(r'[\w/\\]+\.\w+[:\s]+(.+)', cleaned)
            if path_prefix:
                cleaned = path_prefix.group(1).strip()
                if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                    continue
            # Skip purely numeric patterns (line numbers extracted from file:line refs)
            if re.match(r'^\d+[:\s]*$', cleaned):
                continue
            # If pattern has commas/spaces (too specific), extract identifier
            if ", " in cleaned or len(cleaned) > 60:
                simplified = _simplify_pattern(cleaned)
                if simplified:
                    cleaned = simplified
            expanded.append(cleaned)

    def _run_grep(pattern, repo_dir, fixed=True):
        """Run a single grep, return raw output or empty string."""
        try:
            if _csearch_path and _csearch_index:
                # csearch uses regex — escape special chars for literal match
                escaped = re.escape(pattern) if fixed else pattern
                proc = subprocess.run(
                    [_csearch_path, "-n", escaped],
                    capture_output=True, text=True, timeout=10,
                    env={**os.environ, "CSEARCHINDEX": _csearch_index},
                    errors="replace",
                )
                raw = proc.stdout.strip()
                if raw:
                    raw = raw.replace(repo_dir.rstrip("/") + "/", "")
                    lines_filtered = [
                        l for l in raw.splitlines()
                        if _matches_grep_globs(l)
                    ]
                    return "\n".join(lines_filtered)
                return ""
            else:
                flags = ["--fixed-strings"] if fixed else []
                if _rg_path:
                    glob_args = ["--hidden"]
                    for skip_dir in sorted(DEFAULT_SKIP_DIRS):
                        glob_args.extend(["-g", f"!{skip_dir}/**"])
                        glob_args.extend(["-g", f"!**/{skip_dir}/**"])
                    for glob in grep_globs:
                        glob_args.extend(["-g", glob])
                    proc = subprocess.run(
                        [_rg_path, "--no-heading", "-n"] + flags +
                        glob_args + ["--", pattern],
                        capture_output=True, text=True, timeout=60,
                        cwd=repo_dir, errors="replace",
                    )
                    return proc.stdout.strip()
                return _python_grep(pattern, repo_dir, fixed=fixed)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    results = []
    for pattern in expanded[:MAX_GREP_REQUESTS * 2]:
        try:
            # Detect if pattern uses regex syntax
            is_regex = bool(re.search(r'(?<![\\])[.*+?{}|^$]', pattern))

            # Try search
            raw = _run_grep(pattern, repo_dir, fixed=not is_regex)

            # If no results and pattern looks complex, simplify and retry
            if not raw and any(c in pattern for c in "(),-> "):
                simplified = _simplify_pattern(pattern)
                if simplified and simplified != pattern:
                    raw = _run_grep(simplified, repo_dir, fixed=True)
                    if raw:
                        pattern = f"{pattern} (simplified to: {simplified})"

            all_lines = raw.splitlines() if raw else []
            # Prioritize likely definitions/config declarations over usage sites.
            def _line_priority(l):
                definition_markers = (
                    '#define', 'function ', 'def ', 'class ', 'const ',
                    'export ', 'permissions:', 'on:', 'schema',
                    'validator', 'middleware',
                )
                if any(marker in l for marker in definition_markers): return 0
                if any(suffix in l for suffix in ('.h:', '.hpp:', '.py:', '.ts:')): return 1
                return 2
            all_lines.sort(key=_line_priority)
            lines = all_lines[:MAX_GREP_LINES]
            truncated = []
            for line in lines:
                if len(line) > MAX_GREP_LINE_LEN:
                    truncated.append(line[:MAX_GREP_LINE_LEN] + "...")
                else:
                    truncated.append(line)
            output = "\n".join(truncated) if truncated else "(no matches in repo)"
            output = output.replace("\x00", "")
            results.append(f"GREP `{pattern}`:\n```\n{output}\n```")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results.append(f"GREP `{pattern}`: (search failed)")

    return "\n\n".join(results)


def _condense_prior_greps(reasoning_text, max_lines_per_pattern=3):
    """Replace full grep output in prior-round reasoning with a compact
    summary that preserves key evidence without context bloat."""
    match = re.search(r'\n\n\[GREP RESULTS[^\]]*\]:\n', reasoning_text)
    if not match:
        return reasoning_text

    before = reasoning_text[:match.start()]
    grep_section = reasoning_text[match.end():]

    condensed = []
    for pattern, content in re.findall(
        r'GREP `([^`]*)`:\n```\n(.*?)\n```', grep_section, re.DOTALL
    ):
        content = content.strip()
        if not content or content == '(no matches in repo)':
            condensed.append(f"  - `{pattern}`: (no matches)")
        else:
            lines = [l for l in content.split('\n') if l.strip()]
            shown = lines[:max_lines_per_pattern]
            extra = len(lines) - len(shown)
            for line in shown:
                condensed.append(f"  - {line.strip()}")
            if extra > 0:
                condensed.append(f"    (+{extra} more matches)")

    if condensed:
        return before + "\n\n[Prior grep evidence]:\n" + "\n".join(condensed)
    return before


def triage_finding(finding_title, finding_text, code, filepath,
                   project_name, model, keys, prior_reasoning=None,
                   repo_dir=None, reasoning_effort=None, file_context=None,
                   profile=None):
    """Stage 3: Skeptical triage of a single finding. Returns verdict dict."""
    profile = profile or language_profile_for_path(filepath)
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        project_name=project_name,
        finding=finding_text,
        filepath=filepath,
        fence=profile["fence"],
        triage_rules=profile["triage_rules"],
        code=code,
    )

    if file_context:
        prompt += (
            "\n\n**Security context for this file:**\n"
            + file_context[:2000]  # cap to avoid bloating
        )

    if prior_reasoning:
        prompt += (
            "\n\n---\n\n"
            "Prior reviewers have weighed in below. Their reasoning is "
            "SPECULATIVE — it may contain errors or unfounded assumptions.\n\n"
            "Your job is NOT to repeat their analysis. Instead:\n"
            "- Find arguments they MISSED — new attack paths, new \n"
            "  defenses, different code paths, different callers\n"
            "- If they all focused on one aspect, look at a DIFFERENT one\n"
            "- Verify any cited defense with actual values (use GREP)\n"
            "- Consider angles no prior reviewer raised: what about \n"
            "  error paths? race conditions? integer edge cases? caller \n"
            "  contracts? platform differences?\n"
            "- Do NOT rehash the same argument — add new information\n\n"
        )
        for i, (verdict, reasoning) in enumerate(prior_reasoning, 1):
            prompt += f"**Reviewer {i}**:\n{reasoning}\n\n"

    messages = [
        {"role": "system", "content": "You are a security engineer triaging "
         "vulnerability reports. For each finding, answer: "
         "(1) Is the bug pattern real in the code? "
         "(2) Can an attacker reach it through untrusted input? Trace "
         "the data flow backward from the bug to its origin. "
         "(3) If a defense is cited, is it actually sufficient? If you "
         "find a named constant, schema, middleware, wrapper, setting, "
         "or sanitizer, grep for its definition before concluding. "
         "(4) Even if the bug is real, is it security-relevant? A data "
         "race on diagnostic state, ordinary exception, missing NULL "
         "check on an internal API, or undefined behavior only in debug "
         "builds is a code quality issue, NOT necessarily a security "
         "vulnerability — mark it INVALID unless a concrete attacker "
         "impact exists. "
         "Use GREP to verify. Do not guess."},
        {"role": "user", "content": prompt},
    ]

    try:
        response, usage, elapsed = call_llm(model, messages, keys, json_mode=True,
                                           reasoning_effort=reasoning_effort)

        verdict = "UNCERTAIN"
        reasoning = response

        parsed = _extract_json(response)
        if isinstance(parsed, dict):
            v = parsed.get("verdict", "").upper()
            if v in ("VALID", "INVALID", "UNCERTAIN"):
                verdict = v
            reasoning = parsed.get("reasoning", response)
            crux = parsed.get("crux", "")
            if crux:
                reasoning += f"\n\nCRUX: {crux}"

            grep_req = parsed.get("grep", "")
            if grep_req:
                grep_req = re.sub(r'^GREP:\s*', '', grep_req, flags=re.IGNORECASE)
                grep_req = grep_req.strip('`"\'')
                if grep_req:
                    reasoning += f"\nGREP: {grep_req}"
        else:
            clean = re.sub(r'[*#\-\s]+', ' ', response[:300]).strip().upper()
            if "INVALID" in clean[:30]:
                verdict = "INVALID"
            elif "VALID" in clean[:30]:
                verdict = "VALID"
            elif "UNCERTAIN" in clean[:30]:
                verdict = "UNCERTAIN"

        return {
            "finding_title": finding_title,
            "verdict": verdict,
            "reasoning": reasoning,
            "elapsed": round(elapsed, 1),
            "tokens": usage.get("total_tokens", 0),
        }
    except Exception as e:
        return {
            "finding_title": finding_title,
            "verdict": "ERROR",
            "reasoning": str(e),
            "elapsed": 0,
            "tokens": 0,
        }


VERDICT_EMOJI = {
    "VALID": "✅",
    "INVALID": "❌",
    "UNCERTAIN": "❓",
    "ERROR": "💥",
}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

print_lock = threading.Lock()


def print_logo(offset_spaces: int = 5) -> str:
    logo_str = f"""\033[32m
            I   I
           AI   IA
         AA#I   I#AA
       AA##V     V##AA
     AA###V       V###AA
   AA####V         V####AA
TTT#####V           V#####TTT
III####V             V####III
III###V               V###III
III##V  \033[30mNANO-ANALYZER\033[32m  V##III
III#V    \033[90mversion \033[30m{VERSION}    \033[32mV#III
IIIV                     VIII
          \033[92mA I S L E
    \033[0m"""

    logo_str = "".join([f"{' ' * offset_spaces}{line}\n" for line in logo_str.split("\n")])

    print(logo_str)

    return logo_str


def run_scan(args):
    keys = load_api_keys()

    # Discover files
    ext_set = DEFAULT_EXTENSIONS

    scannable, skipped = discover_files(
        args.path,
        ext_set,
        args.max_chars,
        respect_gitignore=not args.include_ignored,
        filenames=DEFAULT_FILENAMES,
    )

    if not scannable:
        print("❌ No scannable files found.")
        return

    llm_backend = configure_llm_backend(args, keys)
    effective_model = args.model
    if llm_backend == "codex":
        effective_model = keys.get("_CODEX_EFFECTIVE_MODEL") or "Codex CLI default"
        effective_effort = keys.get("_CODEX_REASONING_EFFORT")
    elif llm_backend == "claude":
        effective_model = keys.get("_CLAUDE_EFFECTIVE_MODEL") or "Claude Code default"
        effective_effort = keys.get("_CLAUDE_EFFECTIVE_EFFORT")
    else:
        effective_effort = None

    if llm_backend in ("codex", "claude"):
        parallel_explicit = getattr(args, "_parallel_explicit", False)
        triage_parallel_explicit = getattr(args, "_triage_parallel_explicit", False)
        if args.parallel == DEFAULT_PARALLEL and not parallel_explicit:
            args.parallel = (
                DEFAULT_CODEX_PARALLEL
                if llm_backend == "codex"
                else DEFAULT_CLAUDE_PARALLEL
            )
        if (
            args.triage_parallel == DEFAULT_TRIAGE_PARALLEL
            and not triage_parallel_explicit
        ):
            args.triage_parallel = (
                DEFAULT_CODEX_PARALLEL
                if llm_backend == "codex"
                else DEFAULT_CLAUDE_PARALLEL
            )

    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    init_api_semaphore(max_conn)

    total_lines = sum(f["lines"] for f in scannable)
    total_chars = sum(f["chars"] for f in scannable)

    # Compute display base for relative paths
    if os.path.isdir(args.path):
        base_path = os.path.abspath(args.path)
    else:
        base_path = os.path.dirname(os.path.abspath(args.path))

    # Resolve grep/repo directory
    if args.repo_dir:
        repo_dir = args.repo_dir
    elif os.path.isfile(args.path):
        repo_dir = os.path.dirname(os.path.abspath(args.path))
    else:
        repo_dir = os.path.abspath(args.path)

    repo_context = collect_repo_manifest_context(repo_dir)

    # Timestamp for output directory
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    if args.output_dir:
        out_dir = args.output_dir
    else:
        out_dir = os.path.join(os.path.expanduser("~/nano-analyzer-results"), timestamp)
    os.makedirs(out_dir, exist_ok=True)

    # Triage config
    triage_threshold = args.triage_threshold
    triage_rounds = args.triage_rounds
    project_name = args.project or os.path.basename(os.path.abspath(args.path))
    if args.repo_dir:
        init_grep_index(repo_dir)
    do_triage = triage_threshold is not None
    verbose_triage = args.verbose_triage
    thresh_idx = SEVERITY_LEVELS.index(triage_threshold) if do_triage else -1
    triage_counter = [0]  # completed triages
    triage_total = [0]    # total triages submitted (grows as scans find findings)
    triage_semaphore = threading.Semaphore(args.triage_parallel) if do_triage else None
    active_scans = [0]
    active_triages = [0]
    triage_valid_count = [0]
    triage_invalid_count = [0]
    triage_uncertain_count = [0]

    # Pre-scan summary
    print_logo()
    print("🔍 nano-analyzer vulnerability scanner")
    print("🛠️  Modified version: misrtjakub")
    print(f"📂 Target: {terminal_file_link(os.path.abspath(args.path))}")
    print(f"🔎 Grep dir: {terminal_file_link(repo_dir)}")
    print(f"📄 {len(scannable)} files to scan ({total_lines:,} lines, {total_chars:,} chars)")
    if skipped:
        skip_ext = sum(1 for _, r in skipped if r == "extension")
        skip_size = sum(1 for _, r in skipped if "large" in r)
        skip_ignored = sum(1 for _, r in skipped if r.startswith("ignored"))
        skip_symlink = sum(1 for _, r in skipped if r == "symlink")
        skip_irregular = sum(1 for _, r in skipped if r == "not a regular file")
        skip_other = (
            len(skipped)
            - skip_ext
            - skip_size
            - skip_ignored
            - skip_symlink
            - skip_irregular
        )
        parts = []
        if skip_ext:
            parts.append(f"{skip_ext} wrong extension")
        if skip_size:
            parts.append(f"{skip_size} too large")
        if skip_ignored:
            parts.append(f"{skip_ignored} ignored dirs")
        if skip_symlink:
            parts.append(f"{skip_symlink} symlinks")
        if skip_irregular:
            parts.append(f"{skip_irregular} non-files")
        if skip_other:
            parts.append(f"{skip_other} unreadable")
        print(f"   ⏭️  {len(skipped)} skipped ({', '.join(parts)})")
    print(f"🤖 Model: {effective_model}")
    if llm_backend == "codex":
        effort_str = f", effort {effective_effort}" if effective_effort else ""
        print(f"🔌 Backend: Codex CLI ({effective_model}{effort_str}, no API key required)")
    elif llm_backend == "claude":
        effort_str = f", effort {effective_effort}" if effective_effort else ""
        print(f"🔌 Backend: Claude Code ({effective_model}{effort_str}, no API key required)")
    else:
        print("🔌 Backend: Chat Completions API")
    print(f"⚡ Parallelism: {args.parallel} scan, {args.triage_parallel} triage")
    print(f"💾 Results → {terminal_file_link(out_dir, out_dir + os.sep)}")
    if do_triage:
        rounds_str = f", {triage_rounds} rounds" if triage_rounds > 1 else ""
        print(f"🔬 Triage: {triage_threshold}+ findings → skeptical review ({rounds_str.lstrip(', ')})" if triage_rounds > 1 else f"🔬 Triage: {triage_threshold}+ findings → skeptical review")
    print()

    # Run scans (and inline triage)
    results = []
    all_triage_results = []
    completed = 0
    total = len(scannable)
    scan_start = time.time()

    def process_file(file_info):
        nonlocal completed
        filepath = file_info["filepath"]
        profile = language_profile_for_path(filepath)

        with open(filepath, encoding="utf-8-sig", errors="replace") as f:
            code = f.read()

        display_name = os.path.relpath(filepath, base_path)

        with print_lock:
            active_scans[0] += 1
        try:
            result = scan_single_file(
                filepath, code, display_name,
                args.model, keys,
                repo_dir=repo_dir,
                profile=profile,
                repo_context=repo_context,
            )
        finally:
            with print_lock:
                active_scans[0] -= 1

        result["lines"] = file_info["lines"]
        result["chars"] = file_info["chars"]
        result["timestamp"] = timestamp

        # Save individual results
        safename = display_name.replace("/", "_").replace("\\", "_")
        md_path = os.path.join(out_dir, f"{safename}.md")
        json_path = os.path.join(out_dir, f"{safename}.json")

        if result["status"] == "ok":
            with open(md_path, "w") as f:
                f.write(f"# Scan: {display_name}\n\n")
                f.write(result["report"])

            ctx_md_path = os.path.join(out_dir, f"{safename}.context.md")
            with open(ctx_md_path, "w") as f:
                f.write(f"# Context: {display_name}\n\n")
                f.write(result.get("context", "(no context generated)"))

            with open(json_path, "w") as f:
                json.dump(result, f, indent=2)

        # Live scan output
        with print_lock:
            completed += 1
            sevs = result["severities"]
            short_name = os.path.basename(filepath)
            elapsed = result.get("total_elapsed", 0)
            cw = len(str(total))

            sc = active_scans[0]
            tc = active_triages[0]
            ts = datetime.now().strftime("%H:%M:%S")
            load = f"[LLMs running S:{sc} T:{tc}]"

            if result["status"] == "error":
                print(f"  {ts} [file {completed:>{cw}}/{total}] ❌ {short_name}  ERROR: {result['error'][:50]}  {load}")
            else:
                dots = ""
                for lev, em in [("critical", "🔴"), ("high", "🟠"),
                                ("medium", "🟡"), ("low", "🔵")]:
                    dots += em * sevs.get(lev, 0)

                ctx_link = os.path.join(out_dir, f"{safename}.context.md")
                scan_link = os.path.join(out_dir, f"{safename}.md")
                if dots:
                    print(f"  {ts} [file {completed:>{cw}}/{total}] {dots} {short_name}  {elapsed:.0f}s  {load}")
                else:
                    print(f"  {ts} [file {completed:>{cw}}/{total}] ⬜ {short_name}  {elapsed:.0f}s  {load}")
                if result["status"] == "ok":
                    print(f"         📋 {terminal_file_link(ctx_link)}")
                    print(f"         📄 {terminal_file_link(scan_link)}")

        # Queue triage work (non-blocking — fires and forgets into triage executor)
        result["_triage_pending"] = []
        if do_triage and result["status"] == "ok":
            needs_triage = any(
                result["severities"].get(lev, 0) > 0
                for lev in SEVERITY_LEVELS[:thresh_idx + 1]
            )
            if needs_triage:
                findings = extract_findings(result["report"])
                to_triage = []
                for title, text in findings:
                    finding_sev = None
                    for lev in SEVERITY_LEVELS:
                        if re.search(r'\b' + lev + r'\b', text[:200], re.IGNORECASE):
                            finding_sev = lev
                            break
                    if finding_sev is None or SEVERITY_LEVELS.index(finding_sev) > thresh_idx:
                        continue
                    to_triage.append((title, text))

                file_context = result.get("context", "")

                def _triage_one_finding(t_title, t_text, t_code, t_display, t_short):
                    """Run all triage rounds for one finding, print result, append."""
                    try:
                        return _triage_one_finding_inner(t_title, t_text, t_code, t_display, t_short)
                    except Exception as e:
                        with print_lock:
                            ts = datetime.now().strftime("%H:%M:%S")
                            print(f"  {ts} ❌ TRIAGE ERROR {t_short}: {t_title[:40]}... — {e}")

                def _triage_one_finding_inner(t_title, t_text, t_code, t_display, t_short):
                    round_verdicts = []
                    prior = None
                    for rn in range(1, triage_rounds + 1):
                        with triage_semaphore:
                            with print_lock:
                                active_triages[0] += 1
                            try:
                                tv = triage_finding(
                                    t_title, t_text, t_code, t_display,
                                    project_name, args.model, keys,
                                    prior_reasoning=prior,
                                    repo_dir=repo_dir,
                                    file_context=file_context,
                                    profile=profile,
                                )
                            except Exception as e:
                                tv = {
                                    "finding_title": t_title,
                                    "verdict": "UNCERTAIN",
                                    "reasoning": f"Triage error: {e}",
                                }
                            finally:
                                with print_lock:
                                    active_triages[0] -= 1
                        tv["file"] = t_display
                        tv["round"] = rn
                        round_verdicts.append(tv)

                        # Print partial progress per round
                        if triage_rounds > 1 and verbose_triage:
                            history = "".join(VERDICT_EMOJI.get(rv["verdict"], "❓") for rv in round_verdicts)
                            with print_lock:
                                sc = active_scans[0]
                                at = active_triages[0]
                                ts = datetime.now().strftime("%H:%M:%S")
                                short_t = t_title[:35] + "..." if len(t_title) > 35 else t_title
                                print(f"  {ts}    R{rn}/{triage_rounds} {history} {t_short}: {short_t}  [LLMs running S:{sc} T:{at}]")

                        if prior is None:
                            prior = []

                        reasoning_text = tv.get("reasoning", "")

                        # Execute any GREP requests from this round
                        grep_results = execute_grep_requests(
                            reasoning_text, repo_dir, profile["grep_globs"]
                        )
                        if grep_results:
                            tv["grep_used"] = True
                            tv["grep_results"] = grep_results

                        # Condense grep results from older rounds to save
                        # context while preserving key evidence for later rounds
                        if prior:
                            prior = [(v, _condense_prior_greps(r))
                                     for v, r in prior]

                        reasoning_with_greps = reasoning_text
                        if grep_results:
                            reasoning_with_greps += (
                                f"\n\n[GREP RESULTS]:\n{grep_results}"
                            )
                        prior.append((tv["verdict"], reasoning_with_greps))

                    n_valid = sum(1 for rv in round_verdicts if rv["verdict"] == "VALID")
                    n_invalid = sum(1 for rv in round_verdicts if rv["verdict"] == "INVALID")
                    n_total = len(round_verdicts)
                    any_greps = any(rv.get("grep_used") for rv in round_verdicts)
                    confidence = n_valid / n_total if n_total > 0 else 0
                    verdicts_str = "".join(rv["verdict"][0] for rv in round_verdicts)

                    # Final arbiter: fresh call with just the key facts
                    if triage_rounds > 1:
                        # Collect reasoning summaries and grep results
                        evidence = []
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "?")
                            reasoning = rv.get("reasoning", "")
                            # Include first ~500 chars of reasoning + crux
                            summary = reasoning[:500]
                            if len(reasoning) > 500:
                                summary += "..."
                            crux_m = re.search(r'CRUX:\s*(.+?)(?:\n|$)', reasoning)
                            crux = f"\nCRUX: {crux_m.group(1).strip()}" if crux_m else ""
                            evidence.append(
                                f"**Round {rv.get('round', '?')} ({rv_emoji} {rv['verdict']}):** "
                                f"{summary}{crux}"
                            )
                            if rv.get("grep_results"):
                                evidence.append(rv["grep_results"])

                        arbiter_prompt = (
                            f"A vulnerability was reported in {project_name}:\n"
                            f"{t_title}\n\n"
                            f"The reported finding:\n{t_text}\n\n"
                            f"Key evidence from {n_total} rounds of analysis:\n"
                            + "\n".join(evidence[:10]) + "\n\n"
                            f"Verdicts so far: {verdicts_str} "
                            f"({n_valid} valid, {n_invalid} invalid)\n\n"
                            f"The relevant source code from {t_display}:\n"
                            f"```{profile['fence']}\n{t_code}\n```\n\n"
                            "Based on the code and evidence, is this a "
                            "real security vulnerability? Verify any "
                            "numeric values yourself from the code.\n\n"
                            + (f"NOTE: All {n_total} prior reviewers said "
                               "UNCERTAIN or INVALID. Only override to VALID "
                               "if the evidence is overwhelming and you can "
                               "justify it clearly.\n\n"
                               if n_valid == 0 else "") +
                            "Respond with JSON: "
                            '{"verdict": "VALID/INVALID", '
                            '"reasoning": "concise explanation"}'
                        )
                        try:
                            with triage_semaphore:
                                with print_lock:
                                    active_triages[0] += 1
                                try:
                                    arbiter_resp, _, _ = call_llm(
                                        args.model,
                                        [{"role": "system",
                                          "content": "You are an impartial judge. "
                                          "Decide based on evidence, not arguments."},
                                         {"role": "user", "content": arbiter_prompt}],
                                        keys, json_mode=True,
                                    )
                                finally:
                                    with print_lock:
                                        active_triages[0] -= 1

                            arbiter_parsed = _extract_json(arbiter_resp)
                            if isinstance(arbiter_parsed, dict):
                                arbiter_verdict = arbiter_parsed.get(
                                    "verdict", "").upper()
                                if arbiter_verdict in ("VALID", "INVALID"):
                                    round_verdicts.append({
                                        "verdict": arbiter_verdict,
                                        "reasoning": f"[ARBITER] {arbiter_parsed.get('reasoning', '')}",
                                        "round": n_total + 1,
                                        "file": t_display,
                                        "finding_title": t_title,
                                    })
                                    verdicts_str += "→" + arbiter_verdict[0]
                                    if arbiter_verdict == "VALID":
                                        n_valid += 1
                                    else:
                                        n_invalid += 1
                                    n_total += 1
                                    confidence = n_valid / n_total
                        except Exception:
                            pass  # arbiter failure is non-fatal

                    final_tv = round_verdicts[-1].copy()
                    final_tv["all_rounds"] = round_verdicts
                    final_tv["confidence"] = round(confidence, 2)
                    final_tv["verdicts_str"] = verdicts_str
                    final_tv["verdict"] = round_verdicts[-1]["verdict"]

                    short_title = final_tv["finding_title"]
                    if len(short_title) > 45:
                        short_title = short_title[:42] + "..."
                    emoji = VERDICT_EMOJI.get(final_tv["verdict"], "❓")
                    conf_pct = int(confidence * 100)

                    # Write triage detail file
                    triage_dir = os.path.join(out_dir, "triages")
                    os.makedirs(triage_dir, exist_ok=True)
                    safe_file = t_display.replace("/", "_").replace("\\", "_")
                    safe_title = re.sub(r'[^\w\-]', '_', final_tv["finding_title"][:40]).strip("_")

                    with print_lock:
                        triage_counter[0] += 1
                        tc = triage_counter[0]
                        tt = triage_total[0]

                    triage_md = os.path.join(triage_dir, f"T{tc:04d}_{safe_file}_{safe_title}.md")
                    with open(triage_md, "w") as tf:
                        tf.write(f"# Triage T{tc:04d}: {final_tv['finding_title']}\n\n")
                        tf.write(f"- **File**: `{t_display}`\n")
                        tf.write(f"- **Verdict**: {final_tv['verdict']}\n")
                        tf.write(f"- **Confidence**: {conf_pct}% [{verdicts_str}]\n\n")
                        tf.write("---\n\n## Finding\n\n")
                        tf.write(final_tv.get("finding_title", ""))
                        tf.write("\n\n---\n\n## Triage rounds\n\n")
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                            tf.write(f"### Round {rv['round']}: {rv_emoji} {rv['verdict']}\n\n")
                            reasoning = rv.get("reasoning", "")
                            # Extract and highlight crux
                            crux_match = re.search(r'CRUX:\s*(.+?)(?:\n|$)', reasoning)
                            if crux_match:
                                tf.write(f"**🎯 Crux:** {crux_match.group(1).strip()}\n\n")
                            tf.write(reasoning)
                            if rv.get("grep_results"):
                                tf.write(f"\n\n🔎 **Grep results:**\n\n{rv['grep_results']}")
                            tf.write("\n\n")

                    final_tv["triage_md"] = triage_md

                    with print_lock:
                        sc = active_scans[0]
                        at = active_triages[0]
                        ts = datetime.now().strftime("%H:%M:%S")
                        load = f"[LLMs running S:{sc} T:{at}]"
                        grep_icon = " 🔎" if any_greps else ""
                        if triage_rounds > 1:
                            print(f"  {ts} 🔬 [triage {tc}/{tt}] {emoji} {conf_pct}% [{verdicts_str}]{grep_icon} {t_short}: {short_title}  {load}")
                        else:
                            print(f"  {ts} 🔬 [triage {tc}/{tt}] {emoji}{grep_icon} {t_short}: {short_title}  {load}")
                        print(f"         📄 {terminal_file_link(triage_md)}")

                        if final_tv["verdict"] == "VALID":
                            triage_valid_count[0] += 1
                        elif final_tv["verdict"] == "INVALID":
                            triage_invalid_count[0] += 1
                        else:
                            triage_uncertain_count[0] += 1

                        _show_every = 25 if tt > 100 else 10
                        if tc > 1 and tc % _show_every == 0:
                            _el = time.time() - scan_start
                            _v = triage_valid_count[0]
                            _i = triage_invalid_count[0]
                            _u = triage_uncertain_count[0]
                            _rate = tc / _el * 60 if _el > 0 else 0
                            print(f"\n  {'─' * 58}")
                            print(f"  📊 Triage: triage {tc}/{tt} done  ⏱️ {_el:.0f}s  ({_rate:.1f}/min)")
                            print(f"     ✅ {_v} valid   ❌ {_i} rejected   ❓ {_u} uncertain")
                            print(f"  {'─' * 58}\n")

                    all_triage_results.append(final_tv)

                for fi, (title, text) in enumerate(to_triage):
                    with print_lock:
                        triage_total[0] += 1
                    triage_executor.submit(
                        _triage_one_finding, title, text, code,
                        display_name, short_name,
                    )

        return result

    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    triage_executor = ThreadPoolExecutor(max_workers=max_conn) if do_triage else None

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(process_file, fi): fi for fi in scannable}
        for future in as_completed(futures):
            results.append(future.result())

    # Scans done — release scan capacity into the triage semaphore so
    # triage can use all available connections.
    if triage_executor:
        if triage_semaphore:
            for _ in range(args.parallel):
                triage_semaphore.release()
        remaining = triage_total[0] - triage_counter[0]
        if remaining > 0:
            max_conn = args.max_connections or (args.parallel + args.triage_parallel)
            print(f"\n⏳ Scans complete. {remaining} triages remaining (full capacity: {max_conn} connections)...")
        triage_executor.shutdown(wait=True)

    wall_time = time.time() - scan_start

    # Sort results by severity for summary
    results.sort(key=lambda r: (
        -r["severities"].get("critical", 0),
        -r["severities"].get("high", 0),
        -r["severities"].get("medium", 0),
    ))

    # Summary
    crit_files = [r for r in results if r["severities"].get("critical", 0) > 0]
    high_files = [r for r in results if r["severities"].get("high", 0) > 0 and r not in crit_files]
    med_files = [r for r in results if r["severities"].get("medium", 0) > 0 and r not in crit_files and r not in high_files]
    clean_files = [r for r in results if sum(r["severities"].values()) == 0 and r["status"] == "ok"]
    error_files = [r for r in results if r["status"] == "error"]

    print()
    print("━" * 60)
    print(f"📊 Summary: {len(results)} files scanned in {wall_time:.0f}s")
    if crit_files:
        crit_total = sum(r["severities"]["critical"] for r in crit_files)
        print(f"   🔴 Critical: {len(crit_files)} files ({crit_total} findings)")
        for r in crit_files:
            print(f"      → {r['display_name']}")
    if high_files:
        high_total = sum(r["severities"]["high"] for r in high_files)
        print(f"   🟠 High:     {len(high_files)} files ({high_total} findings)")
    if med_files:
        print(f"   🟡 Medium:   {len(med_files)} files")
    print(f"   🟢 Clean:    {len(clean_files)} files")
    if error_files:
        print(f"   ❌ Errors:   {len(error_files)} files")
    print(f"💾 Results saved to: {terminal_file_link(out_dir, out_dir + os.sep)}")

    # Triage summary
    if all_triage_results:
        valid_count = sum(1 for t in all_triage_results if t["verdict"] == "VALID")
        invalid_count = sum(1 for t in all_triage_results if t["verdict"] == "INVALID")
        uncertain_count = sum(1 for t in all_triage_results if t["verdict"] == "UNCERTAIN")

        print()
        print(f"🔬 Triage: ✅ {valid_count} valid | ❌ {invalid_count} rejected | ❓ {uncertain_count} uncertain")

        if valid_count > 0:
            print()
            survivors = sorted(
                [t for t in all_triage_results if t["verdict"] == "VALID"],
                key=lambda t: -t.get("confidence", 1),
            )
            min_conf = args.min_confidence
            if min_conf > 0:
                survivors = [t for t in survivors if t.get("confidence", 1) >= min_conf]

            if survivors:
                print("   🚨 Findings that survived triage:")
            else:
                print("   🟢 No findings above confidence threshold.")

            findings_dir = os.path.join(out_dir, "findings")
            os.makedirs(findings_dir, exist_ok=True)

            for idx, t in enumerate(survivors, 1):
                safename = t["file"].replace("/", "_").replace("\\", "_")
                conf = t.get("confidence", 1)
                conf_pct = int(conf * 100)

                if conf >= 0.9:
                    bar = "🔥"
                elif conf >= 0.7:
                    bar = "✅"
                elif conf >= 0.5:
                    bar = "🤔"
                else:
                    bar = "❓"

                finding_filename = f"VULN-{idx:03d}_{safename}.md"
                finding_path = os.path.join(findings_dir, finding_filename)

                with open(finding_path, "w") as ff:
                    ff.write(f"# VULN-{idx:03d}: {t['finding_title']}\n\n")
                    ff.write(f"- **File**: `{t['file']}`\n")
                    ff.write(f"- **Confidence**: {conf_pct}%")
                    vs = t.get("verdicts_str", "")
                    if vs:
                        ff.write(f" [{vs}]")
                    ff.write("\n")
                    ff.write(f"- **Project**: {project_name}\n")
                    ff.write(f"- **Date**: {timestamp}\n\n")
                    ff.write("---\n\n")
                    ff.write("## Scanner finding\n\n")
                    all_rounds = t.get("all_rounds", [])
                    if all_rounds:
                        ff.write(all_rounds[0].get("finding_title", ""))
                        ff.write("\n\n")
                        body = next(
                            (f["body"] for f in parse_findings(
                                next((r["report"] for r in results
                                      if r.get("display_name") == t["file"]),
                                     ""))
                             if f["title"] in t["finding_title"]
                             or t["finding_title"] in f["title"]),
                            None,
                        )
                        if body:
                            ff.write(body)
                            ff.write("\n\n")
                    ff.write("---\n\n")
                    ff.write("## Triage reasoning\n\n")
                    for ri, rv in enumerate(all_rounds, 1):
                        emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                        ff.write(f"### Round {ri}: {emoji} {rv['verdict']}\n\n")
                        ff.write(rv.get("reasoning", ""))
                        ff.write("\n\n")

                vs = t.get("verdicts_str", "")
                arbiter_str = ""
                if "→" in vs:
                    arbiter_v = vs.split("→")[-1]
                    arbiter_emoji = {"V": "✅", "I": "❌"}.get(arbiter_v, "❓")
                    arbiter_str = f" (arbiter: {arbiter_emoji})"
                print(f"      {bar} {conf_pct}% [{vs}]{arbiter_str} {t['file']}: {t['finding_title']}")
                print(f"         📄 {terminal_file_link(finding_path)}")

        with open(os.path.join(out_dir, "triage.json"), "w") as f:
            json.dump(all_triage_results, f, indent=2)

        triage_md_path = os.path.join(out_dir, "triage_survivors.md")
        with open(triage_md_path, "w") as f:
            f.write(f"# nano-analyzer triage survivors\n\n")
            f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
            f.write(f"- **Date**: {timestamp}\n")
            f.write(f"- **Model**: {effective_model}\n")
            if effective_effort:
                f.write(f"- **Effort**: {effective_effort}\n")
            f.write(f"- **Threshold**: {triage_threshold}+\n")
            f.write(f"- **Results**: ✅ {valid_count} valid | "
                    f"❌ {invalid_count} rejected | "
                    f"❓ {uncertain_count} uncertain\n\n")
            f.write("---\n\n")
            for t in all_triage_results:
                if t["verdict"] != "VALID":
                    continue
                f.write(f"## ✅ {t['file']}: {t['finding_title']}\n\n")
                f.write(f"**Verdict**: VALID\n\n")
                f.write(f"### Triage reasoning\n\n")
                f.write(t["reasoning"])
                f.write("\n\n---\n\n")

        print(f"\n   📄 Triage writeup: {terminal_file_link(triage_md_path)}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "target": os.path.abspath(args.path),
        "model": args.model,
        "effective_model": effective_model,
        "effective_effort": effective_effort,
        "backend": llm_backend,
        "codex_model": keys.get("_CODEX_MODEL") if llm_backend == "codex" else None,
        "codex_reasoning_effort": (
            keys.get("_CODEX_REASONING_EFFORT") if llm_backend == "codex" else None
        ),
        "claude_model": keys.get("_CLAUDE_MODEL") if llm_backend == "claude" else None,
        "claude_effort": (
            keys.get("_CLAUDE_EFFECTIVE_EFFORT") if llm_backend == "claude" else None
        ),
        "respect_gitignore": not args.include_ignored,
        "files_scanned": len(results),
        "total_lines": total_lines,
        "wall_time_seconds": round(wall_time, 1),
        "files_skipped": len(skipped),
        "critical_files": len(crit_files),
        "high_files": len(high_files),
        "clean_files": len(clean_files),
        "error_files": len(error_files),
        "per_file": [
            {
                "file": r["display_name"],
                "language_profile": r.get("language_profile"),
                "lines": r.get("lines", 0),
                "severities": r["severities"],
                "status": r["status"],
                "elapsed": r.get("total_elapsed", 0),
            }
            for r in results
        ],
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Human-readable summary
    with open(os.path.join(out_dir, "summary.md"), "w") as f:
        f.write(f"# nano-analyzer scan results\n\n")
        f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
        f.write(f"- **Date**: {timestamp}\n")
        f.write(f"- **Model**: {effective_model}\n")
        if effective_effort:
            f.write(f"- **Effort**: {effective_effort}\n")
        f.write(f"- **Backend**: {llm_backend}\n")
        f.write(f"- **Respect gitignore**: {str(not args.include_ignored).lower()}\n")
        f.write(f"- **Files scanned**: {len(results)} ({total_lines:,} lines)\n")
        f.write(f"- **Wall time**: {wall_time:.0f}s\n\n")
        f.write("| File | Profile | Lines | Critical | High | Medium | Low |\n")
        f.write("|------|---------|-------|----------|------|--------|-----|\n")
        for r in results:
            s = r["severities"]
            f.write(f"| {r['display_name']} | {r.get('language_profile', '')} "
                    f"| {r.get('lines',0)} "
                    f"| {s.get('critical',0)} | {s.get('high',0)} "
                    f"| {s.get('medium',0)} | {s.get('low',0)} |\n")

    print()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    argv = sys.argv[1:]

    def flag_present(name):
        return any(arg == name or arg.startswith(name + "=") for arg in argv)

    parser = argparse.ArgumentParser(
        prog="nano-analyzer",
        description="🔍 nano-analyzer: Minimal LLM-powered zero-day vulnerability scanner by AISLE",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Model for all stages (default: {DEFAULT_MODEL})")
    parser.add_argument("--backend", choices=("auto", "api", "codex", "claude"),
                        default="auto",
                        help="LLM backend: auto, api, codex, or claude (default: auto)")
    parser.add_argument("--codex", dest="backend", action="store_const", const="codex",
                        help="Use Codex CLI as the LLM backend (no API key required)")
    parser.add_argument("--codex-cli", default="codex",
                        help="Codex CLI executable for --backend codex (default: codex)")
    parser.add_argument("--codex-model", default=None,
                        help="Model passed to Codex CLI (default: Codex config default)")
    parser.add_argument("--codex-timeout", type=int, default=600,
                        help="Timeout in seconds for each Codex CLI call (default: 600)")
    parser.add_argument("--claude", dest="backend", action="store_const", const="claude",
                        help="Use Claude Code as the LLM backend (no API key required)")
    parser.add_argument("--claude-cli", default="claude",
                        help="Claude Code executable for --backend claude (default: claude)")
    parser.add_argument("--claude-model", default=None,
                        help="Model passed to Claude Code (default: Claude Code config default)")
    parser.add_argument("--claude-effort", default=None,
                        choices=("low", "medium", "high", "xhigh", "max"),
                        help="Effort passed to Claude Code (default: Claude Code config default)")
    parser.add_argument("--claude-timeout", type=int, default=600,
                        help="Timeout in seconds for each Claude Code call (default: 600)")
    parser.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                        help=f"Max concurrent scan calls (default: {DEFAULT_PARALLEL})")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                        help=f"Skip files larger than this (default: {DEFAULT_MAX_CHARS:,})")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (default: ~/nano-analyzer-results/<timestamp>/)")
    parser.add_argument("--triage-threshold", default="medium",
                        choices=SEVERITY_LEVELS[:4],
                        help="Triage findings at or above this severity (default: medium)")
    parser.add_argument("--triage-rounds", type=int, default=5,
                        help="Triage rounds per finding (default: 5)")
    parser.add_argument("--triage-parallel", type=int, default=DEFAULT_TRIAGE_PARALLEL,
                        help="Max concurrent triage calls "
                             f"(default: {DEFAULT_TRIAGE_PARALLEL})")
    parser.add_argument("--max-connections", type=int, default=None,
                        help="Max total concurrent LLM calls "
                             "(default: parallel + triage-parallel)")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        help="Only show findings above this confidence threshold, "
                             "e.g. 0.7 for 70%% (default: 0, show all)")
    parser.add_argument("--project", default=None,
                        help="Project name for triage prompt (default: directory name)")
    parser.add_argument("--repo-dir", default=None,
                        help="Root of the full repo for triage grep lookups "
                             "(default: parent dir for files, scan dir for folders)")
    parser.add_argument("--include-ignored", action="store_true",
                        help="Scan files ignored by git/.gitignore when walking a git repo")
    parser.add_argument("--verbose-triage", action="store_true",
                        help="Show per-round triage progress")
    args = parser.parse_args()
    args._parallel_explicit = flag_present("--parallel")
    args._triage_parallel_explicit = flag_present("--triage-parallel")

    if not os.path.exists(args.path):
        print(f"❌ Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    run_scan(args)


if __name__ == "__main__":
    main()
