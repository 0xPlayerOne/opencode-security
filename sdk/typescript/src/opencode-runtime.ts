import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";

export interface OpenCodeRunOptions {
  readonly repository: string;
  readonly model: string;
  readonly environment: NodeJS.ProcessEnv;
  readonly prompt: string;
  readonly signal?: AbortSignal;
  readonly maxCostUsd?: number;
}

export interface OpenCodeUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

export interface OpenCodeRunResult {
  readonly sessionId: string;
  readonly finalResponse: string;
  readonly usage: OpenCodeUsage | null;
  readonly costUsd: number | null;
}

interface OpenCodeEvent {
  readonly type?: unknown;
  readonly sessionID?: unknown;
  readonly part?: unknown;
  readonly error?: unknown;
}

const require = createRequire(import.meta.url);

export function resolveOpenCodeCommand(): string {
  const packageName = platformPackageName();
  const candidates = [
    resolvePlatformBinary(packageName),
    resolvePackageBinary("opencode-ai", "bin/opencode"),
    resolvePackageBinary("opencode-ai", "bin/opencode.exe"),
  ].filter((candidate): candidate is string => candidate !== null);
  const command = candidates.find((candidate) => existsSync(candidate));
  if (command !== undefined) return command;
  throw new Error(
    "The OpenCode runtime is not installed for this platform. Install the opencode-ai package.",
  );
}

export async function runOpenCode(
  options: OpenCodeRunOptions,
): Promise<OpenCodeRunResult> {
  const command = resolveOpenCodeCommand();
  const environment = {
    ...options.environment,
    OPENCODE_DISABLE_CLAUDE_CODE: "1",
  };
  const child = spawn(
    command,
    [
      "run",
      "--model",
      options.model,
      "--format",
      "json",
      "--pure",
      "--auto",
      options.prompt,
    ],
    {
      cwd: options.repository,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const exitPromise = waitForChild(child);

  const abort = (): void => {
    if (!child.killed) child.kill("SIGTERM");
  };
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener("abort", abort, { once: true });

  let sessionId: string | null = null;
  let finalResponse = "";
  let usage: OpenCodeUsage | null = null;
  let costUsd = 0;
  let sawCost = false;
  let diagnostic = "";
  let completed = false;

  const stderr = createInterface({ input: child.stderr });
  const stderrTask = (async () => {
    for await (const line of stderr) {
      if (diagnostic.length < 8_000) diagnostic += `${line}\n`;
    }
  })();

  const stdout = createInterface({ input: child.stdout });
  try {
    for await (const line of stdout) {
      if (options.signal?.aborted) break;
      const event = parseEvent(line);
      if (event === null) continue;
      if (typeof event.sessionID === "string") sessionId = event.sessionID;
      const part = isRecord(event.part) ? event.part : null;
      const type = typeof event.type === "string" ? event.type : "";
      if (type === "text" && typeof part?.["text"] === "string") {
        finalResponse += part["text"];
      }
      if (type === "step_finish" && part !== null) {
        const stepUsage = normalizeUsage(part["tokens"]);
        if (stepUsage !== null) usage = addUsage(usage, stepUsage);
        if (
          typeof part["cost"] === "number" &&
          Number.isFinite(part["cost"])
        ) {
          costUsd += part["cost"];
          sawCost = true;
          if (
            options.maxCostUsd !== undefined &&
            costUsd > options.maxCostUsd
          ) {
            abort();
            throw new Error(
              `OpenCode scan exceeded the configured cost limit of $${options.maxCostUsd.toFixed(4)}.`,
            );
          }
        }
        if (part["reason"] === "stop") completed = true;
      }
      if (type === "error") {
        const message =
          typeof event.error === "string"
            ? event.error
              : isRecord(event.error) &&
                  typeof event.error["message"] === "string"
                ? event.error["message"]
              : "OpenCode reported an unknown error.";
        throw new Error(message);
      }
    }
  } finally {
    stdout.close();
    stderr.close();
    options.signal?.removeEventListener("abort", abort);
  }

  const exit = await exitPromise;
  await stderrTask;
  if (options.signal?.aborted) {
    throw new Error("OpenCode security scan was interrupted.");
  }
  if (exit.code !== 0) {
    const detail = diagnostic.trim();
    throw new Error(
      `OpenCode exited with status ${exit.code ?? "unknown"}.${detail ? ` ${detail}` : ""}`,
    );
  }
  if (!completed || sessionId === null) {
    throw new Error(
      "OpenCode ended without a completed security scan response.",
    );
  }
  return {
    sessionId,
    finalResponse,
    usage,
    costUsd: sawCost ? costUsd : null,
  };
}

function platformPackageName(): string {
  if (process.platform === "darwin") {
    return process.arch === "arm64"
      ? "opencode-darwin-arm64"
      : "opencode-darwin-x64";
  }
  if (process.platform === "linux") {
    return process.arch === "arm64"
      ? "opencode-linux-arm64"
      : "opencode-linux-x64";
  }
  if (process.platform === "win32") {
    return process.arch === "arm64"
      ? "opencode-windows-arm64"
      : "opencode-windows-x64-baseline";
  }
  throw new Error(`OpenCode does not support ${process.platform}.`);
}

function resolvePackageBinary(
  packageName: string,
  relativePath = "bin/opencode",
): string | null {
  try {
    const packageJson = require.resolve(`${packageName}/package.json`);
    return join(dirname(packageJson), relativePath);
  } catch {
    return null;
  }
}

function resolvePlatformBinary(packageName: string): string | null {
  const opencodePackage = resolvePackageBinary("opencode-ai", "package.json");
  if (opencodePackage === null) return null;
  return join(dirname(opencodePackage), "..", packageName, "bin", "opencode");
}

function parseEvent(line: string): OpenCodeEvent | null {
  try {
    const event = JSON.parse(line) as unknown;
    return isRecord(event) ? (event as OpenCodeEvent) : null;
  } catch {
    return null;
  }
}

function normalizeUsage(value: unknown): OpenCodeUsage | null {
  if (!isRecord(value)) return null;
  const cache = isRecord(value["cache"]) ? value["cache"] : {};
  const input = numberValue(value["input"]);
  const output = numberValue(value["output"]);
  const reasoning = numberValue(value["reasoning"]) ?? 0;
  const cached = numberValue(cache["read"]) ?? 0;
  const cacheWrite = numberValue(cache["write"]) ?? 0;
  if (input === null || output === null) return null;
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

function addUsage(
  previous: OpenCodeUsage | null,
  next: OpenCodeUsage,
): OpenCodeUsage {
  if (previous === null) return next;
  return {
    input_tokens: previous.input_tokens + next.input_tokens,
    cached_input_tokens:
      previous.cached_input_tokens + next.cached_input_tokens,
    cache_write_input_tokens:
      previous.cache_write_input_tokens + next.cache_write_input_tokens,
    output_tokens: previous.output_tokens + next.output_tokens,
    reasoning_output_tokens:
      previous.reasoning_output_tokens + next.reasoning_output_tokens,
    total_tokens: previous.total_tokens + next.total_tokens,
  };
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function waitForChild(
  child: ChildProcess,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}
