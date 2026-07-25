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

Use `npx codex-security --version` for the CLI version and
`npx codex-security info --json` for package, plugin, and runtime versions,
the default model and reasoning effort, and the next scan command. Add
`--dry-run` to inspect the effective model and reasoning effort without
initializing Codex or contacting the network.

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

Scans report their requested paths and actual ranking, file-review, validation,
and attack-path phases. Completion shows finding severity, coverage, elapsed
time, available token and worker counts, the results directory, and the next
useful command. Progress remains on stderr; JSON results remain on stdout.

## Run bulk scans in Docker

The customer container runs noninteractive bulk scans from a supplied CSV on a
Linux Docker host. It does not support interactive repository discovery. The
included `compose.yaml` configures the image, persistent files, and hardened
Codex command sandbox.

Create a `repositories.csv` with one full, immutable Git commit per repository:

```csv
id,repository,revision
payments,https://github.com/example/payments.git,0123456789abcdef0123456789abcdef01234567
```

Create private, persistent result and authentication directories, and let the
container write files as your current user:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
docker compose build codex-security
```

For a one-time sign-in from a remote or headless Docker host, run:

```bash
docker compose run --rm codex-security login --device-auth
```

Open the displayed verification URL in your own browser and enter the one-time
code. The login remains in `state/` after the container exits. For unattended
enterprise deployments, store an enterprise access token in the same directory
without exposing the token in command arguments:

```bash
printenv CODEX_ACCESS_TOKEN | \
  docker compose run --rm -T codex-security login --with-access-token
```

Alternatively, provide `OPENAI_API_KEY` or `CODEX_API_KEY` through your host
environment or secret manager. For private repositories, provide `GH_TOKEN` or
`GITHUB_TOKEN` the same way. Compose passes only the named, configured
credentials to the container.

Security scans remain subject to the model's cybersecurity access policies.
Depending on the account and repository contents, full-repository scans may
require enrollment in [Trusted Access for Cyber](https://chatgpt.com/cyber).
A valid Codex login and GitHub token do not grant that authorization. If access
is denied, the scan records the repository as failed and exits unsuccessfully.

Start a resumable, four-worker scan with the default command:

```bash
docker compose run --rm codex-security
```

Full-repository scans can take tens of minutes per repository at the default
extra-high reasoning setting. Run large campaigns as asynchronous batch jobs
and keep the results and authentication directories mounted throughout the run.

Completed reports, per-repository findings, and the scan manifest appear in
`results/` on the host. The workbench state for that campaign remains in
`results/.codex-security-state/`; the reusable Codex login remains separately in
`state/`. This allows a new results directory to start a separate campaign with
the same login without colliding with an earlier scan. Rerun the same command
with the original CSV and the same `results/` and `state/` directories to resume
an interrupted scan.

To choose a different number of parallel workers or retry failed repositories,
override the default scan command:

```bash
docker compose run --rm codex-security \
  bulk-scan /input/repositories.csv \
  --output-dir /output \
  --workers 8 \
  --max-attempts 2
```

Set `CODEX_SECURITY_CSV`, `CODEX_SECURITY_RESULTS`, or `CODEX_SECURITY_STATE`
to use existing files or directories outside the Compose project. Set
`CODEX_SECURITY_IMAGE` to use an approved, already-built image. Set
`CODEX_SECURITY_GIT_HOST` when accessing GitHub Enterprise Server. Keep
credentials, repository lists, and results out of the image and Git; the
included ignore files exclude them from image builds and commits.
All CSV files, including custom-named repository inventories, are excluded from
the Docker build context. Compose mounts the selected CSV at runtime instead.

The included Compose configuration drops all Linux capabilities, prevents new
privileges, runs as a nonroot user, and applies the supplied default-deny
seccomp profile. Codex Security runs each scan command in a separate
unprivileged Linux sandbox. Docker's default seccomp profile blocks the user and
mount namespaces required by that sandbox; the supplied profile permits only
the needed namespace operations. The Linux host must allow unprivileged user
namespaces. Some Docker Desktop virtual machines additionally restrict nested
mount namespaces, so use a Linux host for production scans.

For environments without Docker Compose, the equivalent lower-level invocation
is:

```bash
docker run --rm --init \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt "seccomp=$PWD/docker/codex-security-seccomp.json" \
  --env OPENAI_API_KEY \
  --env CODEX_API_KEY \
  --env GH_TOKEN \
  --env GITHUB_TOKEN \
  --env CODEX_SECURITY_GIT_HOST \
  --mount "type=bind,source=$PWD/repositories.csv,target=/input/repositories.csv,readonly" \
  --mount "type=bind,source=$PWD/results,target=/output" \
  --mount "type=bind,source=$PWD/state,target=/state" \
  codex-security:local \
  bulk-scan /input/repositories.csv \
  --output-dir /output
```

The image configures a noninteractive Git credential helper for `github.com`
when a GitHub token is supplied. The token works with both HTTPS repository
URLs and `git@github.com:` repository URLs without mounting an SSH agent. The
image never places that token in a repository URL, writes it to image layers,
or sends it to another Git host. Set `CODEX_SECURITY_GIT_HOST` to the hostname
of a GitHub Enterprise Server instance when needed.

Use `--workers` to control concurrent repository scans and `--max-attempts` to
retry failures. The command returns a nonzero status when any repository fails.

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
inputs and report the selected credential source without initializing Codex,
loading credentials, or starting a scan. Dry runs do not inspect the plugin,
probe Python, or contact the network; their authentication metadata is not
verified.

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
