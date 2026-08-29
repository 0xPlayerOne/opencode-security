import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";

const sdkRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(sdkRoot, "../..");

describe("package manager configuration", () => {
  test("build, release, and generated-file instructions use Bun", async () => {
    const operationalFiles = [
      resolve(sdkRoot, "package.json"),
      resolve(sdkRoot, "scripts/generate-models.cjs"),
      resolve(sdkRoot, "scripts/smoke-package.mjs"),
      resolve(repositoryRoot, "Dockerfile"),
      resolve(repositoryRoot, ".github/workflows/node-ci.yml"),
      resolve(repositoryRoot, ".github/workflows/node-release.yml"),
      resolve(repositoryRoot, ".github/workflows/opencode-security.yml"),
    ];

    for (const filePath of operationalFiles) {
      expect(await readFile(filePath, "utf8")).not.toMatch(/\bpnpm\b/i);
    }
  });

  test("runs the required node matrix for staging and main pull requests", async () => {
    const workflow = await readFile(
      resolve(repositoryRoot, ".github/workflows/node-ci.yml"),
      "utf8",
    );

    expect(workflow).toMatch(/pull_request:\n\s+branches: \[main, staging\]/);
  });
});
