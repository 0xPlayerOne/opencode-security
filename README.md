# Codex Security

Run Codex Security scans from the command line or a TypeScript application.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Requirements

The SDK and CLI require Node.js 22 or later. Running a scan or exporting findings
also requires Python 3.10 or later for the bundled Codex Security plugin;
Python 3.10 also requires `tomli`. Python is not needed to install the package
or run `--help` and `--version`.

## Install and scan

```bash
npm install @openai/codex-security@beta
npx codex-security login
npx codex-security scan /path/to/repo
```

On a remote or headless machine, use `npx codex-security login --device-auth`.
For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`.

To store an API key or enterprise access token, pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx codex-security login --with-api-key
printenv CODEX_ACCESS_TOKEN | npx codex-security login --with-access-token
```

Use `npx codex-security login status` to check the stored sign-in and
`npx codex-security logout` to remove it. Codex Security reuses an existing
file-based Codex sign-in. If Codex stores credentials in the system keyring,
run `npx codex-security login` once before scanning.

An environment API key takes precedence over a stored sign-in. Unset both
`OPENAI_API_KEY` and `CODEX_API_KEY` to use your ChatGPT sign-in. The login
status command reports the effective credential source without printing its
value, including when no stored sign-in exists.

Scan a subset of a repository or write machine-readable results:

```bash
npx codex-security scan /path/to/repo --path src --path tests
npx codex-security scan /path/to/repo --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
npx codex-security scan /path/to/repo --diff origin/main --json
npx codex-security scan /path/to/repo --output-dir /path/outside/repo/results
npx codex-security scan /path/to/repo --output-dir /path/outside/repo/results --archive-existing
npx codex-security scan /path/to/repo --dry-run
npx codex-security scan /path/to/repo --fail-on-severity high
npx codex-security bulk-scan
npx codex-security bulk-scan repositories.csv --output-dir ./security-scans
npx codex-security scans list /path/to/repo
npx codex-security scans list --scan-root /path/outside/repo/results
npx codex-security scans show SCAN_ID
npx codex-security scans rerun SCAN_ID
npx codex-security scans compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx codex-security export /path/outside/repo/results --export-format sarif --output results.sarif
npx codex-security export /path/outside/repo/results --export-format csv --output findings.csv
npx codex-security export /path/outside/repo/results --export-format json --output findings.json
npx codex-security validate findings.json "Possible SQL injection in src/query.ts:42"
npx codex-security patch findings.json "Missing authorization check in src/routes.ts:18"
```

The output directory must be outside the scanned directory and any enclosing Git
worktree. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`. Use `npx codex-security scan --help` for all
target, output, and runtime options.

Repeat `--knowledge-base PATH` for multiple files or directories. Directories are
searched recursively for Markdown, text, PDF, and Word (`.docx`) files.

Sign in with `gh auth login`, then run `npx codex-security bulk-scan` to discover
GitHub repositories pushed in the last 90 days. Archived
repositories and forks are excluded. Optionally filter by comma-separated
repository-name keywords, review the matches, and confirm before scanning.
Private checkouts reuse your GitHub CLI sign-in without changing your global Git
configuration. For automation or an existing repository list, pass a CSV
containing `id`, `repository`, and full immutable `revision` columns and specify
`--output-dir`. Use `npx codex-security bulk-scan --help` for all options.

The CLI uses [Incur](https://github.com/wevm/incur) for agent-friendly discovery
and structured output. Use `--llms` for the command manifest,
`scan --schema --format json` for a command schema, register an MCP server with
`mcp add`, sync agent skills with `skills add`, and use
`completions bash|zsh|fish` for shell
completions. Scan results support `--format toon|json|yaml|jsonl` and
`--full-output`.
Use `info --json` for SDK and bundled-plugin metadata. MCP exposes only this
read-only metadata command; scans, authentication, exports, validation, and
patching remain CLI-only because the MCP transport cannot cancel active scans.

On macOS/Linux, an existing output directory must be private to the current
user (`chmod 700`).

If the output directory already contains results, add `--archive-existing`.
The CLI moves them to `<output-dir>.previous-<timestamp>-<id>` and starts the
scan in a new, empty directory at the original path. Add `--dry-run` to see
the destination without moving files.

Scans are report-only by default. Use `--fail-on-severity` in CI to exit 1 when
a completed scan contains a finding at or above the selected severity.
Incomplete coverage and CLI/runtime errors exit 2. Incomplete scans still write
the available human or JSON result to stdout and a coverage warning to stderr,
including in report-only mode.

For CI, keep machine-readable output on stdout and apply a severity policy;
incomplete coverage and runtime errors still exit nonzero:

```bash
npx codex-security scan . --diff origin/main --json --fail-on-severity high > codex-security.json
```

JSON scans remain noninteractive, including when stderr is a terminal. Commands
that run Codex interactively (`validate`, `patch`, `login`, and `logout`) reject
`--json`. Write CSV exports to a file when JSON output is selected.

Scans use `gpt-5.6-sol` with extra-high reasoning effort by default. To override
either setting, pass valid TOML values (including quotes for strings):

```bash
npx codex-security scan . --codex 'model="gpt-5.6-sol"' --codex 'model_reasoning_effort="high"'
```

## Scan history and reruns

`npx codex-security scans list` lists scans for the current repository. Pass a
repository path to inspect another checkout, `--scan-root DIR` to filter by
scan artifact directory. `scans show SCAN_ID` includes saved configuration,
findings, and coverage.

History is saved in the existing Codex Security workbench database under
`$CODEX_HOME/state/plugins/codex-security`. Set `CODEX_SECURITY_STATE_DIR` to
choose a different location.

`scans rerun SCAN_ID` repeats the same configuration against the current
checkout. `scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` identifies new,
persisting, reopened, and resolved findings; missing findings remain unknown
when coverage is incomplete or the original location was not reviewed.

Use `export` to create CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. JSON preserves the sealed findings
document. CSV uses the portable findings columns, marks findings as open, and
does not include local workbench triage state. The exporter validates the seal
before writing, accepts `--output -` for stdout, and can use
`--source-root /path/to/repo` with SARIF to add source-line fingerprints. Run
`npx codex-security export --help` for all export options.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. Both commands operate on the current directory.

Canonical scan documents are limited to 16 MiB for the manifest, 128 MiB for
findings, and 32 MiB for coverage. Oversized scans are rejected before sealing.

Exit codes are `0` for a completed report-only scan or a passing policy, `1`
for a completed policy violation, `2` for invalid input, incomplete coverage, or
a runtime/export error, `130` for interruption, and `143` for termination.

Use `--dry-run` or `await security.preflight(...)` to validate local scan
inputs without initializing Codex, loading credentials, or starting a scan. Dry
runs do not inspect the plugin or probe Python.

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.run("/path/to/repo", {
    knowledgeBasePaths: ["/path/to/threat-models", "/path/to/architecture.pdf"],
  });
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

Product documentation is available in the
[Codex Security guide](https://developers.openai.com/codex/security).

## Support and security

Please use [GitHub issues](https://github.com/openai/codex-security/issues) for
bugs and feature requests. Report vulnerabilities privately using the
[security policy](SECURITY.md).

This project is licensed under the [Apache-2.0 License](LICENSE).
