# `@openai/codex-security`

TypeScript SDK and CLI for running the Codex Security plugin. The package is
ESM-only, includes TypeScript declarations, and installs the `codex-security`
executable with the aligned `@openai/codex` runtime dependency.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Install

```bash
npm install @openai/codex-security@beta
npx codex-security --version
```

Node.js 22 or later is required. Running a scan or exporting findings also requires
Python 3.10 or later for the bundled plugin; Python 3.10 additionally requires
`tomli`. Configure the interpreter with `--python`, `pythonPath`, or `PYTHON`
when automatic discovery is not appropriate.

## Authentication

For local use, sign in with ChatGPT:

```bash
npx codex-security login
npx codex-security scan .
```

On a remote or headless machine, use device authentication:

```bash
npx codex-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To store an API key or
enterprise access token instead, pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx codex-security login --with-api-key
printenv CODEX_ACCESS_TOKEN | npx codex-security login --with-access-token
```

Check or remove the stored sign-in with `npx codex-security login status` and
`npx codex-security logout`. Codex Security reuses an existing file-based Codex
sign-in. If Codex stores credentials in the system keyring, run
`npx codex-security login` once before scanning.

An environment API key takes precedence over a stored sign-in. Unset both
`OPENAI_API_KEY` and `CODEX_API_KEY` to use your ChatGPT sign-in.

## CLI

```bash
npx codex-security scan /path/to/repository
npx codex-security scan /path/to/repository --path src --path tests
npx codex-security scan /path/to/repository --diff origin/main --json
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results --archive-existing
npx codex-security scan /path/to/repository --dry-run
npx codex-security scan /path/to/repository --fail-on-severity high
npx codex-security export /path/outside/repository/results --export-format sarif --output results.sarif
npx codex-security export /path/outside/repository/results --export-format csv --output findings.csv
npx codex-security export /path/outside/repository/results --export-format json --output findings.json
npx codex-security validate findings.json "Possible SQL injection in src/query.ts:42"
npx codex-security patch findings.json "Missing authorization check in src/routes.ts:18"
```

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets. The output directory must be outside the scanned
directory and any enclosing Git worktree. When SARIF is produced, it is written
to
`<scan-dir>/exports/results.sarif`.

On macOS/Linux, an existing output directory must be private to the current
user (`chmod 700`).

If the output directory already contains results, add `--archive-existing`.
The CLI moves them to `<output-dir>.previous-<timestamp>-<id>` and starts the
scan in a new, empty directory at the original path. Add `--dry-run` to see
the destination without moving files.

Scans are report-only by default. Use `--fail-on-severity` in CI to exit 1 when
a completed scan contains a finding at or above the selected severity.
Incomplete coverage and CLI/runtime errors exit 2 so they cannot be mistaken
for a passing policy. Incomplete scans still write the available human or JSON
result to stdout and a coverage warning to stderr, including in report-only
mode.

Scans use `gpt-5.6-sol` with extra-high reasoning effort by default. Override
either setting with repeatable `--codex KEY=VALUE` options, for example
`--codex 'model="gpt-5.6-sol"' --codex 'model_reasoning_effort="high"'`.

Run `npx codex-security scan --help` for the complete CLI reference.

The CLI uses [Incur](https://github.com/wevm/incur) for agent-friendly discovery
and structured output. Inspect the command manifest with `--llms`, inspect a
command schema with `scan --schema --format json`, register the CLI as an MCP
server with `mcp add`, sync agent skills with `skills add`, or generate shell
completions with `completions bash|zsh|fish`. Scan results support
`--format toon|json|yaml|jsonl` and `--full-output`.
Use `info --json` for SDK and bundled-plugin metadata. MCP exposes only this
read-only metadata command; scans, authentication, exports, validation, and
patching remain CLI-only because the MCP transport cannot cancel active scans.

For CI, keep machine-readable output on stdout and apply a severity policy;
incomplete coverage and runtime errors still exit nonzero:

```bash
npx codex-security scan . --diff origin/main --json --fail-on-severity high > codex-security.json
```

Use `export` to create CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. JSON preserves the sealed findings
document. CSV uses the portable findings columns, marks findings as open, and
does not include local workbench triage state. The exporter validates the seal
before writing, accepts `--output -` for stdout, and can use
`--source-root /path/to/repository` with SARIF to add source-line fingerprints.
Run `npx codex-security export --help` for all export options.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. Both commands operate on the current directory.

Canonical scan documents are limited to 16 MiB for the manifest, 128 MiB for
findings, and 32 MiB for coverage. Oversized scans are rejected before sealing.

Exit codes are `0` for a completed report-only scan or a passing policy, `1`
for a completed policy violation, `2` for invalid input, incomplete coverage, or
a runtime/export error, `130` for interruption, and `143` for termination.

Use `--dry-run` or `await security.preflight(...)` to validate the repository,
target, mode, output location, and Codex overrides without initializing the
runtime or loading credentials. Dry runs do not inspect the plugin or probe its
Python interpreter.

## SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.run("/path/to/repository");
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

The SDK also supports scoped and diff targets, streaming, cancellation, API-key
and Codex sign-in flows, and typed scan results.

Product documentation is available in the
[Codex Security guide](https://developers.openai.com/codex/security). Please
report bugs using [GitHub issues](https://github.com/openai/codex-security/issues)
and vulnerabilities using the repository security policy.
