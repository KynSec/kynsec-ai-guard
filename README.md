# AI-Guard-CLI

<div align="center">

**Security auditing for the local AI stack.**

Find dangerous MCP servers, hardcoded credentials, exposed host paths, and prompt-injection payloads before they reach production.

[![CI](https://github.com/KynSec/AI-Guard-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/KynSec/AI-Guard-CLI/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ai-guard.svg)](https://pypi.org/project/ai-guard/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![GitHub stars](https://img.shields.io/github/stars/KynSec/AI-Guard-CLI?style=social)](https://github.com/KynSec/AI-Guard-CLI/stargazers)

[Why AI-Guard?](#why-ai-guard) · [Quickstart](#quickstart) · [Usage](#usage) · [Rules](#rules-reference) · [CI integration](#github-actions--sarif) · [Architecture](#architecture) · [Contributing](#contributing)

</div>

---

AI agent configuration is executable configuration. An MCP server entry can launch a shell, mount the host filesystem, or expose an unauthenticated network listener. A system prompt can instruct an agent to hide actions from its user. A dotfile can contain a live cloud key.

AI-Guard-CLI is a fast, offline, read-only static analyzer for that entire surface:

- Claude Desktop, Claude Code, Cline, Cursor, Windsurf, OpenCode, and VS Code MCP configuration
- Model Context Protocol (MCP) server definitions
- System prompts, instruction files, and Markdown policies
- Local LLM deployment and tool configuration
- `.env` files and other credential-bearing text files

No telemetry. No network calls. No secrets in reports.

## Why AI-Guard?

| Risk | What AI-Guard does |
| --- | --- |
| MCP servers that wrap `bash`, inline interpreters, or privilege commands | Flags executable entry points and recommends fixed, allow-listed binaries |
| Remote MCP endpoints with no authentication or plaintext transport | Detects unauthenticated, cleartext, and wildcard-bound listeners |
| Blanket auto-approval of tools | Identifies auto-approval lists that include file, shell, network, or wildcard capabilities |
| Container breakout primitives | Detects privileged containers, Docker socket mounts, host mounts, and sandbox bypass flags |
| Secrets pasted into agent config | Recognizes major provider token formats plus high-entropy assignments, and redacts values |
| Agent access to `/`, `/etc`, home credentials, or Windows system directories | Reports dangerous mounts and traversal sequences with line numbers |
| Prompt-injection payloads and hidden Unicode | Runs heuristic analysis over prompts and every string value in structured configs |
| Malformed or hand-edited JSON/YAML/TOML | Keeps scanning, reports the parse failure, and still checks raw text for secrets |

## Quickstart

### Install from PyPI

AI-Guard-CLI is distributed as `ai-guard` on PyPI:

```bash
pipx install ai-guard
# or
python -m pip install ai-guard
```

### Install from source

```bash
git clone https://github.com/KynSec/AI-Guard-CLI.git
cd AI-Guard-CLI
python -m pip install .
```

Verify the installation:

```bash
ai-guard --version
ai-guard --help
```

### Run your first scan

```bash
# Audit a single Claude Desktop config
ai-guard scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Audit a project, only failing CI on HIGH and CRITICAL findings
ai-guard scan . --min-severity HIGH

# Specialized MCP audit for a config or directory
ai-guard audit-mcp ./mcp.json

# Machine-readable report for automation
ai-guard scan . --format json --output ai-guard.json
```

Example terminal output:

```text
╭──────────────────── AI-Guard scan summary ────────────────────╮
│ Target       ./mcp.json                                      │
│ Files        1 scanned                                       │
│ Findings     2                                               │
│ By severity  CRITICAL 1  HIGH 1                              │
╰──────────────────────────────────────────────────────────────╯
                    Security findings (2)
┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity  ┃ Rule     ┃ Location           ┃ Finding               ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL  │ MCP002   │ mcp.json:12        │ MCP server 'local'    │
│           │          │                    │ exposes a listener    │
│           │          │                    │ on all interfaces     │
│ HIGH      │ MCP001   │ mcp.json:4         │ MCP server 'shell'    │
│           │          │                    │ launches a raw shell  │
└───────────┴──────────┴────────────────────┴───────────────────────┘
```

## Usage

### `ai-guard scan <path>`

Scans a file or directory. Directory scans recursively discover supported configuration, prompt, and environment files while skipping dependency, virtual-environment, and VCS directories.

```bash
ai-guard scan <path> [OPTIONS]
```

| Option | Default | Description |
| --- | --- | --- |
| `--min-severity`, `-s` | `info` | Report only findings at or above `critical`, `high`, `medium`, `low`, or `info` |
| `--format`, `-f` | `table` | Output format: `table`, `json`, or `sarif` |
| `--output`, `-o` | stdout | Write the report to a file. Use `-` for stdout |
| `--verbose`, `-v` | off | Add evidence, remediation, and references to terminal output |
| `--quiet`, `-q` | off | Disable the progress bar |

### `ai-guard audit-mcp <config-path>`

Runs the MCP-focused rule set: MCP security, secrets, and path exposure. This is useful when reviewing a new server before adding it to an agent.

```bash
ai-guard audit-mcp ./claude_desktop_config.json
ai-guard audit-mcp . --format sarif --output ai-guard.sarif
```

### `ai-guard rules`

Lists every built-in rule with its identifier, severity, and category.

```bash
ai-guard rules
```

### Exit codes

AI-Guard is designed for CI/CD pipelines and shell automation.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed with no findings at or above the selected severity |
| `1` | One or more findings at or above the selected severity |
| `2` | Operational or usage error, such as a missing path or unwritable report file |

```bash
if ai-guard scan . --min-severity HIGH --quiet; then
  echo "AI configuration passed security review"
else
  echo "AI configuration requires review" >&2
  exit 1
fi
```

## Severity model

| Severity | Meaning | Typical examples |
| --- | --- | --- |
| `CRITICAL` | Immediate path to host compromise or credential theft | Filesystem root mount, Docker socket, AWS/Stripe key, private key, unauthenticated wildcard listener |
| `HIGH` | Dangerous capability that should block most deployments | Raw shell execution, remote endpoint without auth, auto-approval, SSH credential path, provider API key |
| `MEDIUM` | Requires review or hardening | Path traversal, unpinned package execution, JWT exposure, weak approval settings |
| `LOW` | Hygiene and defense-in-depth issues | Reserved for lower-confidence checks |
| `INFO` | Contextual observations | Reserved for informational checks |

Findings are sorted by severity, then file and line. The process exit code is based on the findings that survive `--min-severity`.

## Rules reference

AI-Guard ships with 27 security rules plus a parse-diagnostic rule.

### MCP server security

| Rule | Severity | Detects |
| --- | --- | --- |
| `MCP001` | High/Critical | Raw shell interpreters, inline code execution, and privilege-escalation commands in MCP servers |
| `MCP002` | High/Critical | Remote endpoints without declared authentication, plaintext HTTP/WS transport, and wildcard listeners |
| `MCP003` | High/Medium | MCP auto-approval of dangerous tools or blanket `*` approval |
| `MCP004` | Critical/High | Privileged containers, host mounts, Docker socket access, and sandbox-disabling flags |
| `MCP005` | Medium | Unpinned `npx`, `pnpx`, `bunx`, `uvx`, or `pipx` package execution |

### Secrets and credentials

| Rule | Severity | Detects |
| --- | --- | --- |
| `SEC001` | High | OpenAI API keys |
| `SEC002` | High | Anthropic API keys |
| `SEC003` | High | Hugging Face access tokens |
| `SEC004` | Critical | AWS access key IDs and secret access keys |
| `SEC005` | High | GitHub and GitLab tokens |
| `SEC006` | High | Google API keys |
| `SEC007` | High | Slack bot, app, and user tokens |
| `SEC008` | Critical | PEM and PGP private key blocks |
| `SEC009` | High/Medium | High-entropy values assigned to credential-like keys |
| `SEC010` | Medium | JSON Web Tokens |
| `SEC011` | Critical | Stripe secret and restricted keys |

Secret evidence is always redacted. Reports include a short fingerprint and metadata such as token type and entropy, never the full value.

### Filesystem and path exposure

| Rule | Severity | Detects |
| --- | --- | --- |
| `PATH001` | Critical | Filesystem root as a path, mount, workspace, or tool argument |
| `PATH002` | High/Critical | Sensitive system paths such as `/etc`, `/proc`, `/sys`, `/boot`, and `/var` data directories |
| `PATH003` | Critical | SSH, cloud, container, Kubernetes, and GPG credential directories, or an entire home directory |
| `PATH004` | Medium | Parent-directory traversal sequences |
| `PATH005` | High | Windows drive roots, `C:\Windows`, and Windows credential directories |
| `PATH006` | Critical | Docker daemon socket exposure |

### Prompt and instruction heuristics

| Rule | Severity | Detects |
| --- | --- | --- |
| `PROMPT001` | High | Instruction-override language, jailbreak personas, and system-prompt disclosure requests |
| `PROMPT002` | Critical | Secret exfiltration, remote script execution, encoded payload execution, reverse shells, and destructive commands |
| `PROMPT003` | High | Requests to hide activity, suppress warnings, disable safeguards, or avoid auditing |
| `PROMPT004` | High | Invisible and bidirectional Unicode control characters |
| `PROMPT005` | Medium | Automatic approval, confirmation bypass, privileged commands, and requests for unrestricted access |

### Diagnostics

| Rule | Severity | Detects |
| --- | --- | --- |
| `AI-GUARD-000` | Medium | Malformed, unreadable, non-UTF-8, or oversized configuration files |

```bash
# Show evidence, remediation, and references
ai-guard scan . --verbose

# List every rule from the installed version
ai-guard rules
```

## Supported files and detection scope

AI-Guard parses:

- JSON and JSON with comments/trailing commas (`.json`, `.jsonc`, `.json5`)
- YAML (`.yaml`, `.yml`)
- TOML (`.toml`)
- Markdown instructions (`.md`, `.markdown`, `.mdx`)
- Text and prompt files (`.txt`, `.prompt`, `.system`, `.instructions`)
- Dotenv files (`.env`, `.env.local`, and similar)

It recognizes common agent layout shapes, including top-level `mcpServers`, `servers`, and `mcp` maps used by Claude Desktop/Code, Cline, VS Code, OpenCode, and compatible clients. MCP servers may use string or list commands, environment blocks, headers, URLs, transports, and auto-approval lists.

Directory scans skip common irrelevant or vendored locations such as `.git`, `.hg`, `.svn`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `dist`, `build`, and `site-packages`. Agent directories such as `.claude`, `.vscode`, and `.github` are not skipped.

Explicit file targets are always scanned, even with an unfamiliar suffix. Individual files larger than 5 MiB are skipped. Scans are capped at 25,000 discovered files.

## Output formats

### Table

The default, human-readable Rich table with severity colors, summary panel, optional progress bar, and `--verbose` detail panels.

### JSON

Stable, versioned JSON with the tool version, target, timestamp, summary, findings, rule catalog, parse errors, and internal rule warnings.

```json
{
  "schema_version": "1.0",
  "tool": { "name": "AI-Guard-CLI", "version": "0.1.0" },
  "summary": {
    "files_scanned": 3,
    "findings_total": 4,
    "findings_reported": 4,
    "by_severity": { "critical": 1, "high": 2, "medium": 1 }
  },
  "findings": []
}
```

### SARIF v2.1.0

SARIF output is compatible with GitHub code scanning and other SARIF consumers. It includes rule metadata, security severities, stable fingerprints, physical locations, and parse/rule execution notifications.

```bash
ai-guard scan . --format sarif --output ai-guard.sarif
```

## GitHub Actions + SARIF

Upload findings to the repository Security tab:

```yaml
name: AI Guard

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  ai-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install AI-Guard
        run: python -m pip install git+https://github.com/KynSec/AI-Guard-CLI.git

      - name: Generate SARIF
        run: ai-guard scan . --format sarif --output ai-guard.sarif --min-severity MEDIUM
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ai-guard.sarif
```

Keep the SARIF upload step separate from the gating step so results are published even when the scan fails the build.

## Architecture

```text
                        ai-guard scan <path>
                                |
                    +-----------v------------+
                    |  core/parser.py        |
                    |  JSON / JSONC / YAML   |
                    |  TOML / dotenv / text  |
                    +-----------+------------+
                                |
                    +-----------v------------+
                    |  core/engine.py        |
                    |  discovery, orchestration,
                    |  dedupe, severity filter,
                    |  progress, diagnostics |
                    +-----------+------------+
                                |
          +---------------------+---------------------+
          |                     |                     |
+---------v---------+ +---------v---------+ +---------v---------+
| MCP security      | | Secrets + entropy | | Path exposure     |
| Prompt heuristics | | Rule registry     | | Shared finding    |
+---------+---------+ +---------+---------+ +---------+---------+
          |                     |                     |
          +---------------------+---------------------+
                                |
                    +-----------v------------+
                    |  core/reporter.py      |
                    |  Rich table            |
                    |  JSON / SARIF 2.1.0    |
                    +------------------------+
```

### Repository layout

```text
ai_guard/
├── __init__.py           # Package version
├── cli.py                # Typer + Rich CLI, exit codes, progress
├── core/
│   ├── engine.py         # Discovery, orchestration, aggregation
│   ├── parser.py         # Robust JSON/YAML/TOML/dotenv parsing
│   └── reporter.py       # Table, JSON, and SARIF reports
└── rules/
    ├── base.py           # Rule ABC, Finding and Severity models
    ├── mcp_security.py   # MCP capability and network analysis
    ├── secrets_leak.py   # Regex + Shannon entropy credential detection
    ├── path_Traversal.py # Host filesystem and credential path exposure
    └── prompt_injection.py # Prompt and instruction heuristics
tests/
├── test_parser.py
├── test_engine.py
├── test_rules.py
└── test_cli.py
.github/workflows/ci.yml
```

### Design principles

- **Read-only:** AI-Guard never modifies scanned files and never executes agent configuration.
- **Offline by default:** No telemetry, analytics, or remote API calls.
- **Fail-soft parsing:** A malformed file produces a diagnostic finding; the rest of the scan continues.
- **Redaction by default:** Credential values are masked before they reach terminal, JSON, or SARIF output.
- **Evidence with location:** Findings carry file paths and line numbers whenever the format permits.
- **Deterministic output:** Findings are sorted and deduplicated for stable CI diffs.
- **Pluggable rules:** Every rule implements a small abstract interface and declares machine-readable metadata.

## Development

```bash
git clone https://github.com/KynSec/AI-Guard-CLI.git
cd AI-Guard-CLI
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

# Run the test suite
pytest

# Coverage
pytest --cov=ai_guard --cov-report=term-missing

# Lint and formatting
ruff check .
ruff format --check .
```

CI runs the test suite on Python 3.10, 3.11, and 3.12, checks formatting, and lints with Ruff.

### Releasing

AI-Guard publishes to PyPI through GitHub Actions and PyPI Trusted Publishing. Configure a PyPI trusted publisher for `ai-guard` with workflow `release.yml` and environment `pypi`, then bump `__version__`, commit, and push a `vX.Y.Z` tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds the wheel and source distribution, validates them with `twine`, and publishes them without storing a PyPI token.

### Adding a rule

1. Create or extend a rule module in `ai_guard/rules/`.
2. Subclass `Rule` and implement `scan(document) -> list[Finding]`.
3. Declare metadata for every emitted rule ID in the rule's `catalog`.
4. Register the rule in `ai_guard/rules/__init__.py`.
5. Add positive, negative, and false-positive tests in `tests/test_rules.py`.
6. Run `pytest` and `ruff check .`.

Rules must never raise for malformed input and must not include unredacted secrets in findings, evidence, or metadata.

## Contributing

Contributions are welcome, especially new detection patterns, additional MCP client layouts, false-positive reductions, and SARIF interoperability fixes.

1. Fork the repository and create a focused branch.
2. Add tests before or alongside the implementation.
3. Keep public behavior documented in the README and rule catalog.
4. Run `pytest`, `ruff check .`, and `ruff format --check .`.
5. Open a pull request describing the threat model and verification steps.

For security issues in AI-Guard itself, please use the repository's private vulnerability reporting instead of a public issue.

## Limitations

AI-Guard is a static heuristic analyzer. It reduces risk; it does not prove an agent configuration is safe.

- Heuristics can produce false positives, especially in security documentation and test fixtures.
- Prompt analysis cannot fully model model behavior or multi-turn attacks.
- A clean scan does not replace a sandbox, least-privilege OS accounts, runtime monitoring, or secret rotation.
- MCP configuration layouts evolve quickly; please report new shapes so detection can be extended.

## Acknowledgements

AI-Guard's rule design is informed by the OWASP Top 10 for LLM Applications, MITRE CWE, SARIF, and the excellent Python open-source ecosystem: Typer, Rich, Pydantic, PyYAML, and pytest.

## License

MIT License. See [LICENSE](LICENSE).

Built by [KynSec](https://github.com/KynSec).
