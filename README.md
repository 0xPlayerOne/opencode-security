# OpenCode Security

`opencode-security` is an opt-in CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code with OpenCode-compatible models. It preserves the upstream artifact contract while using the OpenCode runtime.

The default model is `opencode-go/deepseek-v4-flash`. Set `OPENCODE_API_KEY` before running a scan.

## Quick start

Requires Node.js 22 or later, Python 3.10 or later, and access to Codex Security.

```bash
npm install opencode-security
npx opencode-security scan . --model opencode-go/deepseek-v4-flash
```

For CI, store `OPENCODE_API_KEY` as an encrypted repository or environment
secret. The package does not run automatically; consumers must explicitly call
the reusable workflow from `.github/workflows/opencode-security.yml`.

## TypeScript SDK

```ts
import { OpenCodeSecurity } from "opencode-security";

const security = new OpenCodeSecurity({
  model: "opencode-go/deepseek-v4-flash",
  maxCostUsd: 1,
});
const result = await security.run(".");

console.log(result.reportPath);
await security.close();
```

The default reusable workflow is available at
`.github/workflows/opencode-security.yml` in this repository. Pin
`source_ref` to a release tag or commit when adopting it in another repository.
