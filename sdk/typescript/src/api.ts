/// <reference lib="esnext.disposable" preserve="true" />

import { chmod, lstat, realpath, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { Codex, type CodexOptions } from "@openai/codex-sdk";
import {
  accountStatus,
  CodexLoginHandle,
  loginApiKey as persistApiKey,
  logout as codexLogout,
  type AccountStatus,
} from "./auth.js";
import {
  mergedCodexConfig,
  type CodexSecurityConfig,
  type JsonObject,
  writeCodexConfig,
} from "./config.js";
import {
  loadContract,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import {
  AuthenticationRequiredError,
  CodexSecurityError,
  IncompleteScanError,
  OutputDirectoryError,
  OutputInsideProtectedRootError,
  type ProtectedScanPathKind,
  ScanInterruptedError,
} from "./errors.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import {
  workerStatusFromEvent,
  type ScanWorkerStatus,
} from "./worker-progress.js";
import {
  bootstrapPlugin,
  cleanupSdkDirectory,
  createIsolatedHome,
  importAmbientAuth,
  pluginExecutionEnvironment,
  planOutputArchive,
  prepareOutputDir,
  requireModelSafeOutputDir,
  resolveCodexCommand,
  resolvePluginPath,
  resolvePluginPython,
  type CodexCommand,
  type PluginInstall,
  type ProcessEnvironment,
  validateOutputDir,
} from "./runtime.js";
import {
  enclosingGitWorktreeRoot,
  normalizeRepository,
  normalizeTarget,
  repositoryRevision,
  resolveRepositoryPath,
  type NormalizedTarget,
  type ScanMode,
  type ScanTarget,
  validatedGitEnvironment,
  validateMode,
} from "./targets.js";

interface CodexThreadLike {
  readonly id: string | null;
  runStreamed(
    input: string,
    options: { signal: AbortSignal },
  ): Promise<{ events: AsyncGenerator<ScanEvent> }>;
}

interface ScanEvent {
  readonly type: string;
  readonly [key: string]: unknown;
}

interface CodexClientLike {
  startThread(options: {
    workingDirectory: string;
    skipGitRepoCheck: boolean;
    approvalPolicy: "never";
  }): CodexThreadLike;
}

interface PreparedRuntime {
  codexHome: string;
  bootstrapWorkspace?: string;
  configPath?: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
}

export interface ScanOptions {
  target?: ScanTarget;
  mode?: ScanMode;
  outputDir?: string;
  archiveExisting?: boolean;
  onOutputArchived?: (archiveDir: string) => void;
  onOutputDirReady?: (scanDir: string) => void;
  onScanStarted?: () => void;
  onReconnect?: (attempt: number, maxAttempts: number) => void;
  onWorkerStatus?: (status: ScanWorkerStatus) => void;
  signal?: AbortSignal;
}

export interface ScanPreflight {
  repository: string;
  target: NormalizedTarget;
  mode: ScanMode;
  outputDir: string | null;
  archiveDir?: string;
}

interface LocalScanInputs extends ScanPreflight {
  protectedRoot: string;
}

export interface CodexSecurityMetadata {
  sdk: "@openai/codex-sdk";
  sdkVersion: "0.144.6";
  executable: "@openai/codex";
  executableVersion: "0.144.6";
}

interface ClientDependencies {
  createCodex(options: CodexOptions): CodexClientLike;
  environment: ProcessEnvironment;
  prepareRuntime?: (
    config: Readonly<CodexSecurityConfig>,
    signal?: AbortSignal,
  ) => Promise<PreparedRuntime>;
  resolvePluginPython?: typeof resolvePluginPython;
  prepareOutputDir?: typeof prepareOutputDir;
  repositoryRevision?: typeof repositoryRevision;
  resolveCodexCommand?: () => CodexCommand;
}

const DEFAULT_DEPENDENCIES: ClientDependencies = {
  createCodex: (options) => new Codex(options),
  environment: process.env,
};

const SCAN_PERMISSION_PROFILE = "codex_security_scan";

export class CodexSecurity {
  public readonly config: Readonly<CodexSecurityConfig>;
  public readonly metadata: CodexSecurityMetadata = {
    sdk: "@openai/codex-sdk",
    sdkVersion: "0.144.6",
    executable: "@openai/codex",
    executableVersion: "0.144.6",
  };

  readonly #dependencies: ClientDependencies;
  readonly #loginHandles = new Set<CodexLoginHandle>();
  readonly #abortController = new AbortController();
  #activeOperation: Promise<unknown> | null = null;
  #runtimePromise: Promise<PreparedRuntime> | null = null;
  #runtime: PreparedRuntime | null = null;
  #closed = false;
  #closePromise: Promise<void> | null = null;

  public constructor(config?: CodexSecurityConfig);
  public constructor(
    config: CodexSecurityConfig = {},
    dependencies: ClientDependencies = DEFAULT_DEPENDENCIES,
  ) {
    this.config = structuredClone(config);
    this.#dependencies = dependencies;
  }

  public async run(
    repository: string,
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    return await this.#trackOperation(() => this.#run(repository, options));
  }

  public async preflight(
    repository: string,
    options: ScanOptions = {},
  ): Promise<ScanPreflight> {
    this.#requireOpen();
    const inputs = await this.#validateLocalInputs(
      repository,
      options,
      options.signal,
    );
    requireOutputOutsideRepository(
      inputs.protectedRoot,
      await realpath(tmpdir()),
      "temporary",
    );
    await mergedCodexConfig(this.config);
    const archiveDir =
      options.archiveExisting === true
        ? await planOutputArchive(inputs.outputDir)
        : null;
    this.#requireOpen();
    return {
      repository: inputs.repository,
      target: inputs.target,
      mode: inputs.mode,
      outputDir: inputs.outputDir,
      ...(archiveDir === null ? {} : { archiveDir }),
    };
  }

  async #run(repository: string, options: ScanOptions): Promise<ScanResult> {
    this.#requireOpen();
    const signal =
      options.signal === undefined
        ? this.#abortController.signal
        : AbortSignal.any([this.#abortController.signal, options.signal]);
    let scanDir = "";
    let targetPathsFile: string | null = null;
    try {
      const checkOpen = (): void => {
        this.#requireOpen();
        throwIfAborted(signal, scanDir);
      };

      // Validate all local inputs before runtime initialization or plugin-Python discovery.
      const {
        repository: repo,
        target: normalized,
        mode,
        outputDir: requestedOutput,
        protectedRoot,
      } = await this.#validateLocalInputs(repository, options, signal);
      checkOpen();
      let temporaryRoot: string | undefined;
      if (requestedOutput === null || this.#runtime === null) {
        temporaryRoot = await realpath(tmpdir());
        requireOutputOutsideRepository(
          protectedRoot,
          temporaryRoot,
          "temporary",
        );
      }
      if (requestedOutput !== null) {
        requireOutputOutsideRepository(protectedRoot, requestedOutput);
      }
      checkOpen();

      const runtime = await this.#ensureRuntime(signal, temporaryRoot, (path) =>
        requireOutputOutsideRepository(protectedRoot, path, "runtime"),
      );
      const runtimeHome = await realpath(runtime.codexHome);
      requireOutputOutsideRepository(protectedRoot, runtimeHome, "runtime");
      checkOpen();
      const apiKey = environmentApiKey(this.#dependencies.environment);
      if (apiKey !== null) {
        const codexCommand = this.#codexCommand();
        const login = await persistApiKey(
          codexCommand,
          withoutApiKeys(runtime.environment),
          apiKey,
          signal,
        );
        if (!login.success) {
          throw new CodexSecurityError(
            `Codex API-key login failed: ${login.stderr.trim() || login.stdout.trim() || "unknown error"}`,
          );
        }
        runtime.credentialsAvailable = true;
      }
      if (!runtime.credentialsAvailable) {
        throw new AuthenticationRequiredError(
          "No credentials were found. Run 'codex-security login', use " +
            "'codex-security login --device-auth' on a remote or headless machine, or set " +
            "OPENAI_API_KEY or CODEX_API_KEY for CI.",
        );
      }
      const python = await (
        this.#dependencies.resolvePluginPython ?? resolvePluginPython
      )({
        configuredPath: this.config.pythonPath,
        environment: withoutApiKeys(this.#dependencies.environment),
        protectedRoot,
        signal,
      });
      checkOpen();
      scanDir = await (this.#dependencies.prepareOutputDir ?? prepareOutputDir)(
        requestedOutput ?? undefined,
        basename(repo),
        temporaryRoot,
        (path) => requireOutputOutsideRepository(protectedRoot, path),
        options.archiveExisting,
        options.onOutputArchived,
      );
      requireOutputOutsideRepository(protectedRoot, scanDir);
      requireModelSafeOutputDir(scanDir);
      options.onOutputDirReady?.(scanDir);
      checkOpen();

      const shellPluginRoot = runtime.plugin.pluginRoot;
      const canonicalShellPluginRoot = await realpath(shellPluginRoot);
      const pluginRelativeToHome = relative(
        runtimeHome,
        canonicalShellPluginRoot,
      );
      if (
        pluginRelativeToHome === "" ||
        (!pluginRelativeToHome.startsWith(`..${sep}`) &&
          pluginRelativeToHome !== ".." &&
          !isAbsolute(pluginRelativeToHome))
      ) {
        throw new OutputDirectoryError(
          `Shell-visible plugin root must be outside CODEX_HOME: ${canonicalShellPluginRoot}`,
        );
      }
      const prompt = await scanPrompt(
        shellPluginRoot,
        normalized,
        mode,
        runtime.configPath !== undefined,
      );
      checkOpen();
      const expectation: ScanExpectation = {
        repository: repo,
        repositoryRevision: await (
          this.#dependencies.repositoryRevision ?? repositoryRevision
        )(repo, signal),
        target: normalized,
        mode,
        pluginVersion: runtime.plugin.version,
      };
      checkOpen();

      targetPathsFile =
        normalized.kind === "paths"
          ? join(
              dirname(runtime.codexHome),
              `codex-security-target-paths-${randomUUID()}.json`,
            )
          : null;
      const runtimePaths = {
        PYTHON: python,
        CODEX_SECURITY_REPOSITORY: repo,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        CODEX_SECURITY_PLUGIN_ROOT: shellPluginRoot,
        ...(runtime.configPath === undefined
          ? {}
          : { CODEX_SECURITY_CONFIG_PATH: runtime.configPath }),
        ...(targetPathsFile === null
          ? {}
          : { CODEX_SECURITY_TARGET_PATHS_FILE: targetPathsFile }),
      };
      const configuredProfiles = this.config.codexOverrides?.["profiles"];
      const profilePolicies = isCodexConfigObject(configuredProfiles)
        ? Object.fromEntries(
            Object.entries(configuredProfiles).map(([name, profile]) =>
              isCodexConfigObject(profile) &&
              isCodexConfigObject(profile["shell_environment_policy"])
                ? [
                    name,
                    {
                      ...profile,
                      shell_environment_policy: shellEnvironmentPolicy(
                        profile["shell_environment_policy"],
                        runtimePaths,
                      ),
                    },
                  ]
                : [name, profile],
            ),
          )
        : {};
      const environment = {
        ...pluginExecutionEnvironment(
          python,
          withoutCodexHome(withoutApiKeys(runtime.environment)),
        ),
        CODEX_HOME: runtime.codexHome,
        ...runtimePaths,
      };
      const codex = this.#dependencies.createCodex({
        env: definedEnvironment(environment),
        config: {
          default_permissions: SCAN_PERMISSION_PROFILE,
          allow_login_shell: false,
          shell_environment_policy: shellEnvironmentPolicy(
            this.config.codexOverrides?.["shell_environment_policy"],
            runtimePaths,
          ),
          ...(Object.keys(profilePolicies).length > 0
            ? { profiles: profilePolicies }
            : {}),
        },
      });
      const thread = codex.startThread({
        workingDirectory: scanDir,
        skipGitRepoCheck: true,
        approvalPolicy: "never",
      });
      const serializedPaths =
        normalized.kind === "paths"
          ? JSON.stringify(normalized.paths)
              .replaceAll("\u0085", "\\u0085")
              .replaceAll("\u2028", "\\u2028")
              .replaceAll("\u2029", "\\u2029")
          : null;
      checkOpen();
      if (serializedPaths !== null && targetPathsFile !== null) {
        await writeFile(targetPathsFile, `${serializedPaths}\n`, {
          flag: "wx",
          mode: 0o400,
          signal,
        });
        await chmod(targetPathsFile, 0o400);
      }
      checkOpen();
      const { events } = await thread.runStreamed(prompt, {
        signal,
      });
      checkOpen();

      return await runScanEvents({
        thread,
        events,
        signal,
        scanDir,
        pluginRoot: runtime.plugin.installedRoot,
        expectation,
        onScanStarted: options.onScanStarted,
        onReconnect: options.onReconnect,
        onWorkerStatus: options.onWorkerStatus,
      });
    } catch (error) {
      if (this.#closed) this.#requireOpen();
      if (signal.aborted && !(error instanceof ScanInterruptedError)) {
        throwIfAborted(signal, scanDir);
      }
      throw error;
    } finally {
      await removeTargetPathsFile(targetPathsFile);
    }
  }

  public async loginApiKey(apiKey: string): Promise<void> {
    const { result, runtime } = await this.#runOperation(
      async (preparedRuntime, signal) => ({
        runtime: preparedRuntime,
        result: await persistApiKey(
          this.#codexCommand(),
          withoutApiKeys(preparedRuntime.environment),
          apiKey,
          signal,
        ),
      }),
    );
    if (!result.success) {
      throw new CodexSecurityError(
        `Codex API-key login failed: ${result.stderr.trim() || result.stdout.trim() || "unknown error"}`,
      );
    }
    runtime.credentialsAvailable = true;
  }

  public async loginChatGPT(): Promise<CodexLoginHandle> {
    const runtime = await this.#ensureRuntime();
    this.#requireOpen();
    const handle = this.#trackLoginHandle(
      new CodexLoginHandle(
        this.#codexCommand(),
        ["login"],
        runtime.environment,
        () => {
          runtime.credentialsAvailable = true;
        },
      ),
    );
    await handle.waitForInstructions();
    this.#requireOpen();
    return handle;
  }

  public async loginChatGPTDeviceCode(): Promise<CodexLoginHandle> {
    const runtime = await this.#ensureRuntime();
    this.#requireOpen();
    const handle = this.#trackLoginHandle(
      new CodexLoginHandle(
        this.#codexCommand(),
        ["login", "--device-auth"],
        runtime.environment,
        () => {
          runtime.credentialsAvailable = true;
        },
      ),
    );
    await handle.waitForInstructions({ deviceCode: true });
    this.#requireOpen();
    return handle;
  }

  public async account(): Promise<AccountStatus> {
    return await this.#runOperation(async (runtime, signal) => {
      const apiKey = environmentApiKey(this.#dependencies.environment);
      if (apiKey !== null) {
        return {
          authenticated: true,
          details: "Authenticated with an API key.",
        };
      }
      return await accountStatus(
        this.#codexCommand(),
        runtime.environment,
        signal,
      );
    });
  }

  public async logout(): Promise<void> {
    const runtime = await this.#runOperation(
      async (preparedRuntime, signal) => {
        await codexLogout(
          this.#codexCommand(),
          preparedRuntime.environment,
          signal,
        );
        return preparedRuntime;
      },
    );
    runtime.credentialsAvailable = false;
  }

  public async close(): Promise<void> {
    if (this.#closePromise !== null) return await this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#finishClose();
    await this.#closePromise;
  }

  async #finishClose(): Promise<void> {
    this.#abortController.abort();
    const loginHandles = [...this.#loginHandles];
    for (const handle of loginHandles) handle.cancel();
    await Promise.allSettled(
      [
        this.#activeOperation,
        ...loginHandles.map((handle) => handle.wait()),
      ].filter(
        (operation): operation is Promise<unknown> => operation !== null,
      ),
    );
    const runtime =
      this.#runtime ?? (await this.#runtimePromise?.catch(() => null));
    this.#runtime = null;
    this.#runtimePromise = null;
    if (runtime !== null && runtime !== undefined) {
      const cleanupResults = await Promise.allSettled(
        [runtime.codexHome, runtime.bootstrapWorkspace]
          .filter((path): path is string => path !== undefined)
          .map((path) => cleanupSdkDirectory(path)),
      );
      for (const result of cleanupResults) {
        if (result.status === "rejected") throw result.reason;
      }
    }
  }

  public async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async #runOperation<T>(
    operation: (runtime: PreparedRuntime, signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    return await this.#trackOperation(async () => {
      const signal = this.#abortController.signal;
      const runtime = await this.#ensureRuntime(signal);
      this.#requireOpen();
      const result = await operation(runtime, signal);
      this.#requireOpen();
      return result;
    });
  }

  async #trackOperation<T>(operation: () => Promise<T>): Promise<T> {
    this.#requireOpen();
    if (this.#activeOperation !== null) {
      throw new CodexSecurityError(
        "A Codex Security operation is already in progress.",
      );
    }
    const activeOperation = operation();
    this.#activeOperation = activeOperation;
    try {
      return await activeOperation;
    } finally {
      if (this.#activeOperation === activeOperation) {
        this.#activeOperation = null;
      }
    }
  }

  async #ensureRuntime(
    signal?: AbortSignal,
    temporaryRoot?: string,
    validateLocation?: (path: string) => void,
  ): Promise<PreparedRuntime> {
    this.#requireOpen();
    if (this.#runtime !== null) return this.#runtime;
    if (this.#runtimePromise === null) {
      const runtimePromise = this.#prepareRuntime(
        signal ?? this.#abortController.signal,
        temporaryRoot,
        validateLocation,
      );
      this.#runtimePromise = runtimePromise;
      void runtimePromise.catch(() => {
        if (this.#runtimePromise === runtimePromise) {
          this.#runtimePromise = null;
        }
      });
    }
    const runtime = await this.#runtimePromise;
    this.#requireOpen();
    this.#runtime = runtime;
    return this.#runtime;
  }

  #trackLoginHandle(handle: CodexLoginHandle): CodexLoginHandle {
    this.#loginHandles.add(handle);
    void handle.wait().then(
      () => this.#loginHandles.delete(handle),
      () => this.#loginHandles.delete(handle),
    );
    return handle;
  }

  #codexCommand(): CodexCommand {
    return (this.#dependencies.resolveCodexCommand ?? resolveCodexCommand)();
  }

  async #validateLocalInputs(
    repository: string,
    options: ScanOptions,
    signal?: AbortSignal,
  ): Promise<LocalScanInputs> {
    const repositoryPath = resolveRepositoryPath(repository);
    const repo = await normalizeRepository(repositoryPath, signal);
    throwIfAborted(signal);
    const requestedTarget = options.target ?? "repository";
    validatedGitEnvironment(this.#dependencies.environment);
    const normalized = await normalizeTarget(repo, requestedTarget, signal);
    throwIfAborted(signal);
    const mode = options.mode ?? "standard";
    validateMode(normalized, mode);
    const protectedRoot =
      (await enclosingGitWorktreeRoot(repo, signal)) ?? repo;
    const requestedOutput = await validateOutputDir(
      options.outputDir,
      options.archiveExisting,
    );
    if (requestedOutput !== null) {
      requireOutputOutsideRepository(protectedRoot, requestedOutput);
    }
    return {
      repository: repo,
      target: normalized,
      mode,
      outputDir: requestedOutput,
      protectedRoot,
    };
  }

  async #prepareRuntime(
    signal: AbortSignal,
    temporaryRoot?: string,
    validateLocation?: (path: string) => void,
  ): Promise<PreparedRuntime> {
    if (this.#dependencies.prepareRuntime !== undefined) {
      return await this.#dependencies.prepareRuntime(this.config, signal);
    }
    const codexHome = await createIsolatedHome(temporaryRoot, validateLocation);
    let bootstrapWorkspace: string | undefined;
    try {
      throwIfAborted(signal);
      bootstrapWorkspace = await createIsolatedHome(
        dirname(codexHome),
        validateLocation,
      );
      const pluginRoot = await resolvePluginPath(
        this.config.pluginPath,
        bootstrapWorkspace,
        signal,
      );
      const processEnvironment = this.#dependencies.environment;
      const nodeAmbientHome = join(homedir(), ".codex");
      const configuredAmbientHome = environmentValue(
        processEnvironment,
        "CODEX_HOME",
      );
      const ambientHome = configuredAmbientHome ?? nodeAmbientHome;
      const mergedConfig = await mergedCodexConfig(this.config);
      const codexConfig = scanRuntimeCodexConfig(mergedConfig);
      await writeCodexConfig(join(codexHome, "config.toml"), codexConfig);
      const configPath = join(bootstrapWorkspace, "config-preflight.toml");
      await writeCodexConfig(
        configPath,
        scanPreflightCodexConfig(mergedConfig),
      );
      throwIfAborted(signal);
      const plugin = await bootstrapPlugin(codexHome, pluginRoot, {
        environment: withoutCodexHome(processEnvironment),
        signal,
      });
      const credentialsAvailable = await initialCredentialsAvailable(
        processEnvironment,
        ambientHome,
        codexHome,
      );
      return {
        codexHome,
        bootstrapWorkspace,
        configPath,
        plugin,
        environment: {
          ...withoutCodexHome(withoutApiKeys(processEnvironment)),
          CODEX_HOME: codexHome,
        },
        credentialsAvailable,
      };
    } catch (error) {
      const cleanupResults = await Promise.allSettled(
        [bootstrapWorkspace, codexHome]
          .filter((path): path is string => path !== undefined)
          .map((path) => cleanupSdkDirectory(path)),
      );
      const cleanupFailures = cleanupResults.flatMap((result) =>
        result.status === "rejected" ? [result.reason] : [],
      );
      if (cleanupFailures.length > 0) {
        throw new AggregateError(
          [error, ...cleanupFailures],
          "Codex Security runtime preparation failed and its isolated runtime could not be cleaned up.",
          { cause: error },
        );
      }
      throw error;
    }
  }

  #requireOpen(): void {
    if (this.#closed) throw new CodexSecurityError("CodexSecurity is closed.");
  }
}

export async function initialCredentialsAvailable(
  environment: ProcessEnvironment,
  ambientHome: string,
  isolatedHome: string,
  importer: typeof importAmbientAuth = importAmbientAuth,
): Promise<boolean> {
  if (environmentApiKey(environment) !== null) return false;
  return await importer(ambientHome, isolatedHome);
}

async function removeTargetPathsFile(path: string | null): Promise<void> {
  if (path === null) return;
  try {
    await rm(path, { force: true });
  } catch (error) {
    if (process.platform !== "win32") throw error;
    await chmod(path, 0o600);
    await rm(path, { force: true });
  }
}

interface ScanEventRunOptions {
  thread: CodexThreadLike;
  events: AsyncGenerator<ScanEvent>;
  signal: AbortSignal;
  scanDir: string;
  pluginRoot: string;
  expectation: ScanExpectation;
  onScanStarted?: () => void;
  onReconnect?: (attempt: number, maxAttempts: number) => void;
  onWorkerStatus?: (status: ScanWorkerStatus) => void;
}

export async function runScanEvents(
  options: ScanEventRunOptions,
): Promise<ScanResult> {
  let threadId = options.thread.id;
  let scanStarted = false;
  let status = "in_progress";
  let finalResponse = "";
  let usage: unknown = null;
  let lastStreamError: string | null = null;
  try {
    for await (const event of options.events) {
      const workerStatus = workerStatusFromEvent(event);
      if (workerStatus !== null) options.onWorkerStatus?.(workerStatus);
      if (event.type === "thread.started") {
        const startedThreadId = event["thread_id"];
        if (typeof startedThreadId === "string") threadId = startedThreadId;
        if (!scanStarted) {
          scanStarted = true;
          options.onScanStarted?.();
        }
      } else if (
        event.type === "item.completed" &&
        isRecord(event["item"]) &&
        event["item"]["type"] === "agent_message" &&
        typeof event["item"]["text"] === "string"
      ) {
        finalResponse = event["item"]["text"];
      } else if (event.type === "turn.completed") {
        status = "completed";
        usage = event["usage"];
      } else if (
        event.type === "turn.failed" &&
        isRecord(event["error"]) &&
        typeof event["error"]["message"] === "string"
      ) {
        throw new CodexSecurityError(event["error"]["message"]);
      } else if (
        event.type === "error" &&
        typeof event["message"] === "string"
      ) {
        const message = event["message"];
        const reconnect = reconnectAttempt(message);
        if (reconnect === null) throw new CodexSecurityError(message);
        lastStreamError = message;
        options.onReconnect?.(...reconnect);
      }
    }
    if (options.signal.aborted) {
      throw new ScanInterruptedError(
        `Codex Security scan was interrupted; partial output remains at ${options.scanDir}.`,
        options.scanDir,
      );
    }
    if (status !== "completed") {
      throw new IncompleteScanError(
        lastStreamError ??
          "Codex Security event stream ended before the turn completed.",
      );
    }
    if (threadId === null) {
      throw new IncompleteScanError(
        "Codex Security did not report a thread ID.",
      );
    }
    const result = await collectResult(
      { status, finalResponse, usage },
      threadId,
      options.scanDir,
      options.pluginRoot,
      options.expectation,
      options.signal,
    );
    if (options.signal.aborted) {
      throw new ScanInterruptedError(
        `Codex Security scan was interrupted; partial output remains at ${options.scanDir}.`,
        options.scanDir,
      );
    }
    return result;
  } catch (error) {
    if (options.signal.aborted && !(error instanceof ScanInterruptedError)) {
      throw new ScanInterruptedError(
        `Codex Security scan was interrupted; partial output remains at ${options.scanDir}.`,
        options.scanDir,
        { cause: error },
      );
    }
    throw error;
  }
}

async function scanPrompt(
  pluginRoot: string,
  target: NormalizedTarget,
  mode: ScanMode,
  hasConfigPath = false,
): Promise<string> {
  const skillName = skillNameFor(target, mode);
  const skillPath = join(pluginRoot, "skills", skillName, "SKILL.md");
  const metadata = await lstat(skillPath).catch(() => null);
  if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new IncompleteScanError(
      `Installed plugin is missing scan skill: ${skillName}`,
    );
  }
  return [
    `Use the installed $codex-security:${skillName} skill at "$CODEX_SECURITY_PLUGIN_ROOT/skills/${skillName}/SKILL.md".`,
    "Run this Codex Security scan non-interactively.",
    ...(skillName === "deep-security-scan"
      ? []
      : [
          "This exhaustive scan authorizes the delegated-worker phases required by the selected skill; use available subagent tools and continue with parent-agent fallback if capacity changes.",
        ]),
    "This SDK host does not render MCP Apps; use the terminal/chat workflow.",
    'Use "$PYTHON" as <python_command> for every plugin helper; replace any literal python or python3 helper invocation with this exact interpreter.',
    'Repository root: "$CODEX_SECURITY_REPOSITORY"',
    'Use this exact scan directory for all scan output: "$CODEX_SECURITY_SCAN_DIR"',
    ...(hasConfigPath
      ? [
          'For normal config-preflight helper calls, append --config "$CODEX_SECURITY_CONFIG_PATH" so preflight reads the sanitized active runtime config. Preserve the documented runtime and --effective-config arguments for session-only values.',
        ]
      : []),
    "Runtime paths are environment-backed; keep them quoted in POSIX shells and use the corresponding $env: names in PowerShell. Do not copy or reparse their values.",
    targetInstruction(target),
    "Complete and seal the canonical JSON contract before returning.",
  ].join("\n");
}

function skillNameFor(target: NormalizedTarget, mode: ScanMode): string {
  if (target.kind === "refs" || target.kind === "working_tree")
    return "security-diff-scan";
  return mode === "deep" ? "deep-security-scan" : "security-scan";
}

function targetInstruction(target: NormalizedTarget): string {
  if (target.kind === "repository")
    return "Scan target: the entire repository.";
  if (target.kind === "paths")
    return 'Scan target paths: generate the combined inventory once with "$PYTHON" "$CODEX_SECURITY_PLUGIN_ROOT/scripts/generate_rank_input.py" make-repo-rank-input --repo "$CODEX_SECURITY_REPOSITORY" --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --out "$CODEX_SECURITY_SCAN_DIR/artifacts/02_discovery/rank_input.jsonl". Before finalization, preserve every requested scope with "$PYTHON" "$CODEX_SECURITY_PLUGIN_ROOT/scripts/generate_rank_input.py" bind-repo-scopes --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --manifest "$CODEX_SECURITY_SCAN_DIR/scan-manifest.json" --coverage "$CODEX_SECURITY_SCAN_DIR/coverage.json". Do not print, evaluate, or modify the target-paths file.';
  if (target.kind === "refs") {
    return `Scan target: Git diff from ${target.base} to ${target.head}.`;
  }
  return `Scan target: staged and unstaged working-tree changes against ${target.base}.`;
}

async function collectResult(
  turnResult: TurnResultMetadata,
  threadId: string,
  scanDir: string,
  pluginRoot: string,
  expectation: ScanExpectation,
  signal: AbortSignal,
): Promise<ScanResult> {
  const required = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const missing: string[] = [];
  for (const name of required) {
    try {
      await requireScanFile(scanDir, name, name, signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason ?? error;
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `Codex Security scan completed without required artifacts: ${missing.join(", ")}`,
    );
  }
  const { manifest, findings, coverage } = await loadContract(scanDir, {
    pluginRoot,
    expectation,
    signal,
  });
  let sarifPath: string | null = null;
  try {
    sarifPath = await requireScanFile(
      scanDir,
      "exports/results.sarif",
      "exports/results.sarif",
      signal,
    );
  } catch (error) {
    if (signal.aborted) throw signal.reason ?? error;
  }
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId,
    turnResult,
    sarifPath,
  });
}

function environmentApiKey(environment: ProcessEnvironment): string | null {
  for (const requested of ["OPENAI_API_KEY", "CODEX_API_KEY"]) {
    const canonical = environment[requested]?.trim();
    if (canonical) return canonical;
    for (const [name, value] of Object.entries(environment)) {
      if (name.toUpperCase() === requested && value?.trim())
        return value.trim();
    }
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reconnectAttempt(message: string): [number, number] | null {
  const match =
    /^Reconnecting(?:\.\.\.|…)[ \t]+([1-9]\d{0,2})\/([1-9]\d{0,2})(?=[ \t(]|$)/u.exec(
      message,
    );
  if (match === null) return null;
  const attempt = Number(match[1]);
  const maxAttempts = Number(match[2]);
  return attempt <= maxAttempts ? [attempt, maxAttempts] : null;
}

function isCodexConfigObject(
  value: unknown,
): value is NonNullable<CodexOptions["config"]> {
  return isRecord(value);
}

export function scanRuntimeCodexConfig(config: JsonObject): JsonObject {
  const hardened = structuredClone(config);
  delete hardened["sandbox_mode"];
  const configuredPermissions = isRecord(hardened["permissions"])
    ? hardened["permissions"]
    : {};
  return {
    ...hardened,
    allow_login_shell: false,
    default_permissions: SCAN_PERMISSION_PROFILE,
    permissions: {
      ...configuredPermissions,
      [SCAN_PERMISSION_PROFILE]: {
        filesystem: {
          ":root": "read",
          ":workspace_roots": "write",
        },
      },
    },
  };
}

export function scanPreflightCodexConfig(config: JsonObject): JsonObject {
  const safeString = (value: unknown, maxLength: number): value is string =>
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    !/(?:^|[^a-z0-9])(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|key|secret|token|env|mcp|set|password|passwd|credential|authorization|bearer)(?:[^a-z0-9]|$)/iu.test(
      value,
    );
  const safeProfileName = (value: unknown): value is string =>
    safeString(value, 128) && /^[A-Za-z0-9_-]+$/u.test(value);
  const safeInteger = (value: unknown): value is number =>
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 1_000_000;
  const capabilityFeatures = (value: unknown): JsonObject => {
    if (!isRecord(value)) return {};
    const result: JsonObject = {};
    if (typeof value["goals"] === "boolean") {
      result["goals"] = value["goals"];
    }
    const multiAgent = value["multi_agent_v2"];
    if (typeof multiAgent === "boolean") {
      result["multi_agent_v2"] = multiAgent;
    } else if (isRecord(multiAgent)) {
      const sanitized: JsonObject = {};
      if (typeof multiAgent["enabled"] === "boolean") {
        sanitized["enabled"] = multiAgent["enabled"];
      }
      const capacity = multiAgent["max_concurrent_threads_per_session"];
      if (safeInteger(capacity)) {
        sanitized["max_concurrent_threads_per_session"] = capacity;
      }
      if (Object.keys(sanitized).length > 0) {
        result["multi_agent_v2"] = sanitized;
      }
    }
    return result;
  };

  const result: JsonObject = {};
  const features = capabilityFeatures(config["features"]);
  if (Object.keys(features).length > 0) result["features"] = features;
  const agents = config["agents"];
  if (isRecord(agents)) {
    const sanitized: JsonObject = {};
    for (const key of ["max_threads", "max_depth"]) {
      const value = agents[key];
      if (safeInteger(value)) {
        sanitized[key] = value;
      }
    }
    if (Object.keys(sanitized).length > 0) result["agents"] = sanitized;
  }
  if (safeProfileName(config["profile"])) {
    result["profile"] = config["profile"];
  }
  const profiles = config["profiles"];
  if (isRecord(profiles)) {
    const sanitized: JsonObject = {};
    for (const [name, profile] of Object.entries(profiles).slice(0, 256)) {
      if (!safeProfileName(name) || !isRecord(profile)) continue;
      const profileFeatures = capabilityFeatures(profile["features"]);
      if (Object.keys(profileFeatures).length > 0) {
        sanitized[name] = { features: profileFeatures };
      }
    }
    if (Object.keys(sanitized).length > 0) result["profiles"] = sanitized;
  }
  const rootMarkers = config["project_root_markers"];
  if (Array.isArray(rootMarkers)) {
    result["project_root_markers"] = rootMarkers
      .filter((value): value is string => safeString(value, 256))
      .slice(0, 64);
  }
  const projects = config["projects"];
  if (isRecord(projects)) {
    const sanitized: JsonObject = {};
    for (const [path, project] of Object.entries(projects).slice(0, 256)) {
      if (!safeString(path, 4096) || !isAbsolute(path) || !isRecord(project)) {
        continue;
      }
      const trust = project["trust_level"];
      if (trust !== "trusted" && trust !== "untrusted") continue;
      sanitized[path] = { trust_level: trust };
    }
    if (Object.keys(sanitized).length > 0) result["projects"] = sanitized;
  }
  const multiagent = config["multiagent_config"];
  if (isRecord(multiagent) && safeInteger(multiagent["max_concurrency"])) {
    result["multiagent_config"] = {
      max_concurrency: multiagent["max_concurrency"],
    };
  }
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > 256 * 1024) {
    throw new CodexSecurityError(
      "The sanitized Codex Security preflight config exceeds the size limit.",
    );
  }
  return result;
}

function shellEnvironmentPolicy(
  policy: unknown,
  runtimePaths: Record<string, string>,
): NonNullable<CodexOptions["config"]> {
  const configured = isCodexConfigObject(policy) ? policy : {};
  const configuredSet = isCodexConfigObject(configured["set"])
    ? configured["set"]
    : {};
  const includeOnly = configured["include_only"];
  const exclude = configured["exclude"];
  return {
    ...configured,
    ignore_default_excludes: false,
    exclude: [
      ...new Set([
        ...(Array.isArray(exclude)
          ? exclude.filter(
              (value): value is string => typeof value === "string",
            )
          : []),
        "CODEX_HOME",
        "*KEY*",
        "*SECRET*",
        "*TOKEN*",
      ]),
    ],
    set: {
      ...Object.fromEntries(
        Object.entries(configuredSet).filter(([key]) =>
          safeShellEnvironmentName(key),
        ),
      ),
      ...runtimePaths,
    },
    include_only: [
      ...new Set([
        ...(Array.isArray(includeOnly)
          ? includeOnly.filter(
              (value): value is string =>
                typeof value === "string" && safeShellEnvironmentPattern(value),
            )
          : [
              "PATH",
              "HOME",
              "USER",
              "USERPROFILE",
              "HOMEDRIVE",
              "HOMEPATH",
              "TMP",
              "TEMP",
              "TMPDIR",
              "SYSTEMROOT",
              "WINDIR",
              "COMSPEC",
              "PATHEXT",
              "LANG",
              "LC_*",
            ]),
        ...Object.keys(runtimePaths),
      ]),
    ],
  };
}

function safeShellEnvironmentName(value: string): boolean {
  const upper = value.toUpperCase();
  return (
    upper !== "CODEX_HOME" &&
    !upper.includes("KEY") &&
    !upper.includes("SECRET") &&
    !upper.includes("TOKEN")
  );
}

function safeShellEnvironmentPattern(value: string): boolean {
  return (
    safeShellEnvironmentName(value) &&
    (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) || value === "LC_*")
  );
}

function requireOutputOutsideRepository(
  repository: string,
  outputDirectory: string,
  pathKind: ProtectedScanPathKind = "output",
): void {
  const outputRelative = relative(repository, outputDirectory);
  if (
    outputRelative === "" ||
    (outputRelative !== ".." &&
      !outputRelative.startsWith(`..${sep}`) &&
      !isAbsolute(outputRelative))
  ) {
    throw new OutputInsideProtectedRootError(
      outputDirectory,
      repository,
      pathKind,
    );
  }
}

function throwIfAborted(signal?: AbortSignal, scanDir = ""): void {
  if (!signal?.aborted) return;
  const message = scanDir
    ? `Codex Security scan was interrupted; partial output remains at ${scanDir}.`
    : "Codex Security scan was interrupted during preparation.";
  throw new ScanInterruptedError(message, scanDir, { cause: signal.reason });
}

function definedEnvironment(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

function withoutApiKeys(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(definedEnvironment(environment)).filter(
      ([name]) =>
        name.toUpperCase() !== "OPENAI_API_KEY" &&
        name.toUpperCase() !== "CODEX_API_KEY",
    ),
  );
}

function withoutCodexHome(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(definedEnvironment(environment)).filter(
      ([name]) => name.toUpperCase() !== "CODEX_HOME",
    ),
  );
}

export function environmentValue(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested];
  if (exact !== undefined && exact.trim() !== "") return exact;
  const upper = requested.toUpperCase();
  for (const [name, value] of Object.entries(environment)) {
    if (
      name.toUpperCase() === upper &&
      value !== undefined &&
      value.trim() !== ""
    ) {
      return value;
    }
  }
  return undefined;
}
