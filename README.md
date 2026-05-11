# Nano-analyzer

**A minimal LLM-powered zero-day vulnerability scanner by [AISLE](https://aisle.com), adapted for local Codex CLI / Claude Code workflows.**

This is a modified version of AISLE's nano-analyzer prototype. The original
scanner design, prompts, and core pipeline are credited to AISLE; this fork
keeps that foundation and adds a use case focused on running the analyzer
through locally authenticated coding CLIs without requiring API keys.

![aisle-nano-analyzer-diagram](aisle-nano-analyzer.png)

> **Research prototype for demonstration purposes.** This is a simple, single-file harness that is able to detect real zero-day vulnerabilities. It now uses language-aware profiles, but it is still a prototype and will produce false positives. We are sharing it as-is in the spirit of open research — expect sharp corners.

## What it does

Nano-analyzer is a simple single-file Python scanner that sends source code through a language-profile-driven three-stage LLM pipeline:

1. **Context generation** — a model writes a profile-specific security briefing about the file: entry points, untrusted data, validators, authz checks, dangerous sinks, and cross-file facts to verify.
2. **Vulnerability scan** — the same model, primed with the context and a language-specific few-shot example, hunts for zero-day bugs and outputs structured findings.
3. **Skeptical triage** — each finding is challenged over multiple rounds by a skeptical reviewer that can grep the relevant ecosystem files to verify (or refute) defenses. An arbiter makes the final call.

Results are saved as Markdown and JSON files for human review.

## Quick start

Run one of these from the repository you want to inspect:

```bash
# Fast first pass through local Codex CLI, without skeptical triage
python3 scan.py . --codex --no-triage

# Full Codex run with triage and visible per-round progress
python3 scan.py . --codex --verbose-triage

# Full run through an API model
OPENAI_API_KEY=sk-... python3 scan.py . --backend api --model gpt-5.4-nano
```

Full triage can be much slower than the initial scan. A file with several
medium-or-higher findings can trigger multiple extra model calls per finding:
five skeptical rounds by default plus a final arbiter call.

## Language profiles

The scanner infers a profile from the file path and tunes prompts, code fences,
few-shot examples, triage rules, and grep globs accordingly:

- **C/C++** (`.c`, `.h`, `.cc`, `.cpp`, `.hpp`, etc.) — memory safety and parser boundaries.
- **TypeScript/JavaScript** (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.mts`, `.cts`) — source-to-sink web/backend issues such as SSRF, injection, path traversal, authz, redirects, and secrets leakage.
- **Python** (`.py`, `.pyi`) — framework entry points, subprocess/code execution, deserialization, SQL injection, SSRF, path traversal, authz, and secrets leakage.
- **Shell** (`.sh`, `.bash`, `.zsh`) — command construction, quoting, option/path injection, unsafe temp files, destructive commands, and CI/deploy boundaries.
- **CI/CD and containers** (`.yml`, `.yaml`, `Dockerfile`, `Containerfile`) — privileged workflow triggers, secrets, token permissions, artifact/cache poisoning, deployment, and build hazards.
- **Generic source/config** (`.java`, `.go`, `.rs`, `.rb`, `.php`, `.toml`, `.ini`, `.cfg`, etc.) — broad source-to-sink security review.

## Scan scope

By default, nano-analyzer scans recognized source/config files and skips common
generated or dependency directories. Supported extensions include C/C++, Python,
Go, Rust, JavaScript/TypeScript, Ruby, Swift, Objective-C, C#, PHP, Perl,
shell, YAML, TOML, INI, CFG, `.dockerfile`, and `.x`. `Dockerfile` and
`Containerfile` are included by basename.

When the target path is inside a git worktree, discovery uses `git ls-files`
with `--cached --others --exclude-standard`. That means tracked files are
included, untracked files are included only when not ignored, and `.gitignore`,
`.git/info/exclude`, and global git excludes are respected. Pass
`--include-ignored` to walk the filesystem directly instead.

The scanner always skips symlinks, non-regular files, files above
`--max-chars`, unreadable files, and these directories:

```text
.agents, .cache, .codex, .claude, .firebase, .git, .hg, .next, .nuxt,
.pnpm-store, .svn, .svelte-kit, .turbo, .venv, .vscode, __pycache__,
bower_components, build, coverage, dist, node_modules, out, target,
test-results, venv, and *.egg-info
```

Files are read as UTF-8 with BOM handling (`utf-8-sig`) and invalid bytes are
replaced instead of aborting the scan.

## Credit

Original project and core scanner: [AISLE nano-analyzer](https://github.com/weareaisle/nano-analyzer).

This version keeps the original Apache-2.0 licensed code and adds local CLI
backends for Codex CLI and Claude Code, gitignore-aware file discovery, and
documentation for no-API-key workflows.

## Notable changes in this fork

- Local Codex CLI and Claude Code backends, including automatic backend
  selection when API keys are not present.
- Language-aware scanner profiles with dedicated prompts, few-shot examples,
  triage rules, code fences, and grep globs.
- Gitignore-aware file discovery, Dockerfile/Containerfile support, default
  generated-directory skips, symlink skipping, and UTF-8 BOM tolerant reads.
- Compact repository manifest context from `package.json`, Python manifests,
  route/settings files, GitHub Actions workflows, and container files.
- Effective local CLI model/effort reporting from Codex and Claude config
  files when explicit model flags are not passed.
- More useful terminal output: per-file status lines, severity markers, active
  LLM counts, clickable local file links in terminals that support OSC 8, and
  progress heartbeats for long-running CLI calls.

## Current limitations

This is a v0.1 prototype. Please keep the following in mind:

- **Profile coverage is uneven.** C/C++, TypeScript/JavaScript, Python, shell, CI/YAML, and Dockerfile paths have dedicated profiles. Other languages use a generic source-to-sink profile.
- **False positives.** Even with multi-round triage, expect findings that don't hold up on closer inspection. Always verify manually.
- **False negatives.** The scanner can miss entire vulnerability classes — logic bugs, race conditions, cryptographic issues, authentication bypasses, etc. A clean scan does not mean the code is safe.
- **Mostly single-file analysis.** Each file is scanned independently, with a compact repo manifest summary and grep-based triage for cross-file facts. Deep cross-file vulnerabilities can still be missed.
- **LLM-dependent.** Results vary with the model used. Different models will find different things and hallucinate different false positives.
- **No aggregate budget.** `--max-chars` limits each file, but there is no
  built-in cap for total files, total model calls, total output size, or total
  cost. Use targeted paths, `--no-triage`, and concurrency limits for large or
  untrusted repositories.

## Setup

### Requirements

- Python 3.8+
- Codex CLI or Claude Code logged in locally, or an OpenAI/OpenRouter API key
- Optional: [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) for faster triage grep lookups
- Optional: [Google codesearch](https://github.com/google/codesearch) (`csearch`/`cindex`) for faster grep on large repos when using `--repo-dir`

### Install

```bash
git clone https://github.com/misrtjakub/nano-analyzer.git
cd nano-analyzer
# No dependency installation needed. Run directly:
python3 scan.py --help
```

Use the repository URL for this fork. The original upstream project is credited
above and remains available at `https://github.com/weareaisle/nano-analyzer`.

### Local CLI modes (no API key)

If you have Codex CLI installed and logged in, nano-analyzer can run without
`OPENAI_API_KEY` or `OPENROUTER_API_KEY`:

```bash
python3 scan.py ./src --codex
```

This uses `codex exec` for the same context, scan, triage, and arbiter calls
that normally go through the API. The scanner runs Codex with a read-only
sandbox and writes the same Markdown/JSON outputs. In Codex mode, the default
scan and triage parallelism is capped at 4 local Codex processes unless you
pass explicit `--parallel` / `--triage-parallel` values.

Codex and Claude CLI output is captured until each model call finishes. Long
runs print a progress heartbeat every 30 seconds by default so you can see
whether the scanner is still in context generation, scanning, triage rounds, or
the final arbiter.

You can optionally select a Codex model:

```bash
python3 scan.py ./src --codex --codex-model gpt-5.4
# Equivalent for non-default model names in Codex mode:
python3 scan.py ./src --codex --model gpt-5.4
```

Claude Code is also supported:

```bash
python3 scan.py ./src --claude
python3 scan.py ./src --claude --claude-model sonnet --claude-effort high
```

Claude mode uses `claude --print --output-format json` with tools disabled
for the same scan and triage calls. Like Codex mode, the default scan and
triage parallelism is capped at 4 local CLI processes unless you pass explicit
`--parallel` / `--triage-parallel` values.

When no CLI model override is passed, nano-analyzer shows the configured local
default when it can infer it from Codex's `~/.codex/config.toml` or Claude
Code's `~/.claude/settings.json`. If no setting is found, the summary falls
back to `Codex CLI default` or `Claude Code default`.

CLI backend configuration can be provided with flags or environment variables:

| Setting | Flag | Environment variable |
|---------|------|----------------------|
| Codex executable | `--codex-cli` | `NANO_ANALYZER_CODEX_CLI` |
| Codex model | `--codex-model` | `NANO_ANALYZER_CODEX_MODEL` |
| Claude executable | `--claude-cli` | `NANO_ANALYZER_CLAUDE_CLI` |
| Claude model | `--claude-model` | `NANO_ANALYZER_CLAUDE_MODEL` |
| Claude effort | `--claude-effort` | `NANO_ANALYZER_CLAUDE_EFFORT` |

For display only, Codex defaults are inferred from `model` and
`model_reasoning_effort` in `${CODEX_HOME:-~/.codex}/config.toml`. Claude
defaults are inferred from `model` and `effortLevel` in
`${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json`.

With the default `--backend auto`, OpenAI-style model names use the API when
`OPENAI_API_KEY` is set. If no OpenAI key is present and `codex` is available,
the scanner falls back to Codex CLI automatically. If Codex is unavailable and
Claude Code is available, it falls back to Claude Code. Claude-style model
names such as `sonnet`, `opus`, `haiku`, or `claude-*` use Claude Code unless
you force `--backend api`. OpenRouter `provider/model` names still require
`OPENROUTER_API_KEY`.

Backend selection order is:

1. `--backend api`, `--backend codex`, `--backend claude`, `--codex`, or
   `--claude` wins.
2. Model aliases `codex`/`codex-cli` select Codex; `claude`, `claude-code`,
   `sonnet`, `opus`, `haiku`, and `claude-*` select Claude Code.
3. `provider/model` names select OpenRouter API mode.
4. If `OPENAI_API_KEY` is set, OpenAI-style model names use API mode.
5. Otherwise Codex CLI is used when available, then Claude Code when available.

### API keys

Set your API key as an environment variable:

```bash
# For OpenAI models (model names without a slash, e.g. "gpt-5.4-nano"):
export OPENAI_API_KEY=sk-...

# For OpenRouter models (model names with a slash, e.g. "qwen/qwen3-32b"):
export OPENROUTER_API_KEY=sk-or-...
```

The scanner determines which API key to use based on the model name: if it
contains a `/`, it routes through OpenRouter; otherwise it uses the OpenAI API
directly. Pass `--backend api` to force API mode.

## Usage

### Basic scan

```bash
# Scan a single file
python3 scan.py ./path/to/file.c

# Scan a directory recursively
python3 scan.py ./path/to/src/
```

When scanning a git worktree, nano-analyzer respects the project's ignore
rules by default (`.gitignore`, `.git/info/exclude`, and global git excludes).
Tracked files are still scanned even if they match an ignore pattern.

### Terminal progress

The startup banner prints the target path, grep/repo directory, number of files
and skipped files, effective model, backend, parallelism, output directory, and
triage settings.

During scanning, each completed file prints a timestamped status line with
severity markers and active model-call counts. Long-running jobs print a
heartbeat every `--progress-interval` seconds. With local CLI backends, this is
important because Codex/Claude process output is captured until each individual
model call finishes.

Many terminal emulators render output paths as clickable OSC 8 links. Set
`NANO_ANALYZER_NO_LINKS=1` to print plain paths only.

### Common options

```bash
# Use a different model
python3 scan.py ./src --model gpt-5.4

# Run via Codex CLI without an API key
python3 scan.py ./src --codex

# Run via Claude Code without an API key
python3 scan.py ./src --claude

# Control parallelism
python3 scan.py ./src --parallel 30

# Cap total concurrent model calls across scanning and triage
python3 scan.py ./src --parallel 8 --triage-parallel 8 --max-connections 8

# Point triage grep at the full repo root (useful when scanning a subdirectory)
python3 scan.py ./lib/crypto/ --repo-dir ./

# Include generated or ignored files anyway
python3 scan.py ./src --include-ignored

# Save results somewhere specific
python3 scan.py ./src --output-dir ./results/manual-run

# Only surface high-confidence findings
python3 scan.py ./src --min-confidence 0.7

# More triage rounds for higher accuracy (default: 5)
python3 scan.py ./src --triage-rounds 7

# Skip skeptical triage for a faster initial scan
python3 scan.py ./src --codex --no-triage

# Change or disable the progress heartbeat
python3 scan.py ./src --progress-interval 10
python3 scan.py ./src --progress-interval 0
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `path` | *(required)* | File or directory to scan |
| `--model` | `gpt-5.4-nano` | Model for all stages (context, scan, triage) |
| `--backend` | `auto` | LLM backend: `auto`, `api`, `codex`, or `claude` |
| `--codex` | off | Shortcut for `--backend codex`; uses Codex CLI without API keys |
| `--codex-cli` | `codex` | Codex CLI executable path/name |
| `--codex-model` | Codex config default | Model passed to Codex CLI |
| `--codex-timeout` | `600` | Timeout in seconds for each Codex CLI call |
| `--claude` | off | Shortcut for `--backend claude`; uses Claude Code without API keys |
| `--claude-cli` | `claude` | Claude Code executable path/name |
| `--claude-model` | Claude Code config default | Model passed to Claude Code |
| `--claude-effort` | Claude Code config default | Effort passed to Claude Code (`low`, `medium`, `high`, `xhigh`, `max`) |
| `--claude-timeout` | `600` | Timeout in seconds for each Claude Code call |
| `--parallel` | `50` | Max concurrent scan LLM calls |
| `--triage-threshold` | `medium` | Triage findings at or above this severity |
| `--no-triage` | off | Skip skeptical triage after the initial scan |
| `--triage-rounds` | `5` | Triage rounds per finding |
| `--triage-parallel` | `50` | Max concurrent triage LLM calls |
| `--max-connections` | `parallel + triage-parallel` | Total LLM call cap |
| `--min-confidence` | `0.0` | Only show findings above this confidence (0.0–1.0) |
| `--project` | directory name | Project name used in triage prompts |
| `--repo-dir` | auto | Repo root for grep lookups (auto: parent dir for files, scan dir for folders) |
| `--include-ignored` | off | Include files ignored by git/.gitignore |
| `--output-dir` | `~/nano-analyzer-results/<timestamp>/` | Where to save results |
| `--max-chars` | `200,000` | Skip files larger than this |
| `--verbose-triage` | off | Show per-round triage progress |
| `--progress-interval` | `30` | Seconds between progress heartbeats; `0` disables |

In Codex and Claude modes, `--parallel` and `--triage-parallel` are reduced to
4 by default unless you pass those flags explicitly. This avoids spawning too
many local CLI processes by accident. API mode keeps the table defaults.

### Performance and cost control

Each scanned file normally uses two model calls: one for context generation and
one for the scan. If the scan reports findings at or above
`--triage-threshold`, triage adds `--triage-rounds` calls per finding and, when
multiple rounds are enabled, one final arbiter call.

Useful controls:

- Use `--no-triage` for a fast first pass.
- Use `--triage-threshold high` or `--triage-threshold critical` to reduce
  triage volume.
- Use `--parallel`, `--triage-parallel`, and `--max-connections` to limit
  concurrent LLM/API/CLI calls.
- Use `--max-chars` and narrower target paths for large repositories.
- Use `--progress-interval 0` only when quiet output matters more than
  observability.

## Output

Results are saved to `~/nano-analyzer-results/<timestamp>/` (or `--output-dir`):

```
<timestamp>/
├── summary.json              # machine-readable scan summary
├── summary.md                # human-readable scan summary
├── <filename>.md             # raw scanner output per file
├── <filename>.context.md     # context briefing per file
├── <filename>.json           # full result data per file
├── triages/                  # detailed triage reasoning
│   └── T0001_<file>_<title>.md
├── findings/                 # findings that survived triage
│   └── VULN-001_<file>.md
├── triage.json               # all triage verdicts
└── triage_survivors.md       # summary of validated findings
```

If `--no-triage` is used or no finding reaches the triage threshold, the
`triages/`, `findings/`, `triage.json`, and `triage_survivors.md` files may be
absent. `summary.json` includes the requested model, effective model/effort,
backend, gitignore mode, skipped-file count, wall time, per-file profile, and
per-file severity counts. `summary.md` provides the same high-level scan table
for quick review.

## How triage works

When a scan finds a medium-or-above severity issue, the triage pipeline kicks in:

1. A skeptical reviewer examines the finding against the actual code and can **grep the codebase** to verify or refute claimed defenses.
2. This repeats for multiple rounds (default: 5), with each reviewer seeing prior arguments and encouraged to find *new* evidence rather than rehash old points.
3. A final **arbiter** reads all rounds and makes a VALID/INVALID call.
4. The confidence score (e.g. 80% \[VVIVV→V\]) reflects the fraction of rounds that said VALID.

Findings that survive triage are written to the `findings/` directory with full reasoning chains.

### Grep and repository context

Context generation and triage can ask for `GREP:` lookups. The scanner parses a
small number of requested patterns, cleans obvious junk, filters results through
the active language profile's file globs, and appends the results to later
prompts and Markdown/JSON output.

Search backend order:

1. If both `cindex` and `csearch` are installed and `--repo-dir` is provided,
   nano-analyzer builds a temporary csearch index under `/tmp` and uses it.
2. Otherwise it uses `rg` when available.
3. If neither is available, it falls back to a portable Python grep.

Grep results are capped to reduce context bloat: at most 3 requested grep
patterns are parsed, expanded patterns are capped, each result keeps at most 30
lines, and each line is truncated at 2000 characters.

Before scanning each file, nano-analyzer also builds a compact repo summary
from common manifests and config files: JavaScript package scripts/dependencies,
Python manifests/requirements, route and settings file names, GitHub Actions
workflow triggers/permissions, and Docker/container file names. That context is
bounded and included in the context-generation prompt.

## Operational notes

- Target source code, model output, grep results, and selected repository
  context are sent to the configured backend. Use local CLI modes or a private
  API setup when reviewing sensitive code.
- Result artifacts can contain source snippets, grep matches, and findings.
  Treat `~/nano-analyzer-results/...` as sensitive until reviewed.
- Codex is invoked in read-only sandbox mode and Claude is invoked with tools
  disabled, but scanned source is still untrusted prompt content. Prefer
  disposable worktrees for hostile repositories.
- The scanner does not delete old result directories or temporary csearch
  indexes. Clean them up according to your local retention policy.

## Disclaimer

This tool is a research prototype. It is not a replacement for professional security audits, manual code review, or established static analysis tools. Do not rely on it as your sole security assessment. Use at your own risk.

## License

Apache License 2.0
