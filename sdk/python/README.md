# `@openai/codex-security`

TypeScript SDK and CLI for running the Codex Security plugin. The package is ESM-only,
emits declarations, and installs the `codex-security` executable together with the exact
aligned `@openai/codex` runtime dependency.

```bash
npm install @openai/codex-security@beta
npx codex-security --help
```

```ts
import { CodexSecurity } from "@openai/codex-security";

await using security = new CodexSecurity();
const result = await security.run("/path/to/repository");
console.log(result.reportPath);
```

Node installation, SDK import, argument parsing, help, version, and local validation do
not require Python. The unchanged v0 plugin still does; configure its interpreter with
`pythonPath`, `--python`, or `PYTHON` when automatic discovery is not appropriate.

During the review sequence, this package is introduced alongside the Python implementation. See
[`compatibility/PARITY_MATRIX.md`](compatibility/PARITY_MATRIX.md) for the cutover
contract and intentional language-level differences.
