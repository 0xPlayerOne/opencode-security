import { readFileSync } from "node:fs";

const PACKAGE_VERSIONS = packageVersions(
  new URL("../package.json", import.meta.url),
);

/** npm-compatible successor to the Python package version 0.1.0b3. */
export const VERSION = PACKAGE_VERSIONS.package;
export const CODEX_SDK_VERSION = PACKAGE_VERSIONS.sdk;
export const CODEX_EXECUTABLE_VERSION = PACKAGE_VERSIONS.executable;
export const BUNDLED_PLUGIN_VERSION = "0.1.14" as const;

function packageVersions(url: URL): {
  package: string;
  sdk: string;
  executable: string;
} {
  try {
    const manifest: unknown = JSON.parse(readFileSync(url, "utf8"));
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("version" in manifest) ||
      typeof manifest.version !== "string" ||
      manifest.version.length === 0
    ) {
      throw new Error("version must be a non-empty string");
    }
    const dependencies =
      "dependencies" in manifest ? manifest.dependencies : undefined;
    if (typeof dependencies !== "object" || dependencies === null) {
      throw new Error("dependencies must be an object");
    }
    const sdk =
      "@openai/codex-sdk" in dependencies
        ? dependencies["@openai/codex-sdk"]
        : undefined;
    const executable =
      "@openai/codex" in dependencies
        ? dependencies["@openai/codex"]
        : undefined;
    if (
      typeof sdk !== "string" ||
      sdk.length === 0 ||
      typeof executable !== "string" ||
      executable.length === 0
    ) {
      throw new Error("Codex dependencies must have non-empty versions");
    }
    return { package: manifest.version, sdk, executable };
  } catch (error) {
    throw new Error("Unable to read Codex Security package versions.", {
      cause: error,
    });
  }
}
