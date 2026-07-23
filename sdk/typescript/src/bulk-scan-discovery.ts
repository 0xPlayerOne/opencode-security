import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { stdin } from "node:process";
import { emitKeypressEvents } from "node:readline";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { z } from "incur";
import Papa from "papaparse";
import { inspectMultiscanInventory } from "./multiscan.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const DEFAULT_ACTIVITY_DAYS = 90;
const PREVIEW_LIMIT = 10;
const DAY_MILLISECONDS = 86_400_000;
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const GITHUB_NAME = /^[A-Za-z0-9_.-]{1,100}$/u;
const GITHUB_REPOSITORIES_QUERY = `
  query($owner: String!, $endCursor: String, $privacy: RepositoryPrivacy) {
    repositoryOwner(login: $owner) {
      repositories(
        first: 100
        after: $endCursor
        privacy: $privacy
        isArchived: false
        isFork: false
        orderBy: { field: PUSHED_AT, direction: DESC }
      ) {
        nodes {
          nameWithOwner
          url
          visibility
          isArchived
          isFork
          isEmpty
          pushedAt
          primaryLanguage { name }
          defaultBranchRef { target { oid } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
`.trim();

const githubAuthenticationSchema = z.object({
  hosts: z.record(
    z.string(),
    z.array(
      z.object({
        active: z.boolean().optional(),
        state: z.string().optional(),
      }),
    ),
  ),
});

const githubOwnerRepositoriesSchema = z.object({
  data: z.object({
    repositoryOwner: z
      .object({
        repositories: z.object({
          nodes: z.array(
            z
              .object({
                nameWithOwner: z.string(),
                url: z.string(),
                visibility: z.string(),
                isArchived: z.boolean(),
                isFork: z.boolean(),
                isEmpty: z.boolean(),
                pushedAt: z.string().nullable(),
                primaryLanguage: z.object({ name: z.string() }).nullable(),
                defaultBranchRef: z
                  .object({
                    target: z.object({
                      oid: z.string().regex(/^[0-9a-f]{40,64}$/iu),
                    }),
                  })
                  .nullable(),
              })
              .nullable(),
          ),
          pageInfo: z.object({
            hasNextPage: z.boolean(),
            endCursor: z.string().nullable(),
          }),
        }),
      })
      .nullable(),
  }),
  errors: z.array(z.object({ message: z.string() })).optional(),
});

type GitHubVisibility = "PRIVATE" | "INTERNAL" | "PUBLIC";

interface BulkScanRepositoryFilters {
  nameKeywords: readonly string[];
  activeWithinDays: number | null;
  language: string | null;
  visibility: readonly GitHubVisibility[];
}

const DEFAULT_REPOSITORY_FILTERS: BulkScanRepositoryFilters = {
  nameKeywords: [],
  activeWithinDays: DEFAULT_ACTIVITY_DAYS,
  language: null,
  visibility: ["PRIVATE", "INTERNAL"],
};

export interface BulkScanCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface BulkScanPrompt {
  isInteractive(): boolean;
  write(value: string): void;
  confirm(question: string, defaultValue?: boolean): Promise<boolean>;
  input(question: string, defaultValue?: string): Promise<string>;
  select<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value }[],
    defaultValue?: Value,
  ): Promise<Value>;
  multiSelect<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value }[],
    defaultValues?: readonly Value[],
  ): Promise<Value[]>;
}

export interface BulkScanDiscoveryDependencies {
  prompt: BulkScanPrompt;
  now(): number;
  currentDirectory(): string;
  githubHost?: string;
  runGitHub(
    args: readonly string[],
    options?: { host?: string; interactive?: boolean; signal?: AbortSignal },
  ): Promise<BulkScanCommandResult>;
}

export interface BulkScanWizardResult {
  inputPath: string;
  outputDir: string;
  githubHost?: string;
}

export class BulkScanInterruptedError extends Error {
  public constructor() {
    super("Bulk scan canceled.");
    this.name = "BulkScanInterruptedError";
  }
}

interface GitHubRepository {
  fullName: string;
  url: string;
  revision: string;
}

interface PromptOutput {
  write(value: string): unknown;
  readonly isTTY?: boolean;
}

export function createBulkScanDiscoveryDependencies(options: {
  output: PromptOutput;
  now(): number;
  currentDirectory(): string;
}): BulkScanDiscoveryDependencies {
  return {
    prompt: createTerminalPrompt(options.output),
    now: options.now,
    currentDirectory: options.currentDirectory,
    ...(process.env["GH_HOST"]?.trim()
      ? { githubHost: process.env["GH_HOST"].trim() }
      : {}),
    runGitHub: async (args, commandOptions = {}) => {
      const trusted = await resolveTrustedExecutable(
        "gh",
        process.env,
        options.currentDirectory(),
      );
      if (trusted === null) {
        throw new Error(
          "GitHub CLI is required to discover repositories. Install gh, then run 'codex-security bulk-scan' again.",
        );
      }
      const environment = {
        ...trusted.environment,
        ...(commandOptions.host === undefined
          ? {}
          : { GH_HOST: commandOptions.host }),
      };
      return await runGitHubCommand(
        trusted.executable,
        args,
        environment,
        commandOptions,
      );
    },
  };
}

export async function runBulkScanWizard(
  dependencies: BulkScanDiscoveryDependencies,
  signal?: AbortSignal,
): Promise<BulkScanWizardResult | null> {
  const { prompt } = dependencies;
  if (!prompt.isInteractive()) {
    throw new Error(
      "Interactive repository selection requires a terminal. Provide a CSV with 'codex-security bulk-scan repositories.csv --output-dir ./security-scans'.",
    );
  }
  signal?.throwIfAborted();
  const hasRepositoryList = await prompt.confirm(
    "Do you already have a list of repositories to scan?",
    false,
  );
  let providedInput: string | undefined;
  let repositories: GitHubRepository[] | undefined;
  let githubHost: string | undefined;
  let repositoryNames: string[];

  if (hasRepositoryList) {
    prompt.write(
      "\nEnter the path to a CSV containing id, repository, and revision columns.\n",
    );
    const input = await prompt.input("CSV path");
    if (!input.trim()) throw new Error("A repository CSV path is required.");
    providedInput = resolve(dependencies.currentDirectory(), input.trim());
    const inventory = await inspectMultiscanInventory(providedInput);
    repositoryNames = inventory.repositories;
  } else {
    if (
      !(await prompt.confirm("Are your repositories hosted on GitHub?", true))
    ) {
      prompt.write(
        "\nAutomatic repository discovery currently supports GitHub only. Provide a CSV with id, repository, and revision columns.\n",
      );
      return null;
    }
    const host = await selectGitHubHost(dependencies, signal);
    githubHost = host;
    const owner = await selectGitHubOwner(dependencies, host, signal);
    const selection = await prompt.select(
      "Which repositories do you want to scan?\nNo scan will start until you confirm.",
      [
        {
          label: "Private and internal repositories active in the last 90 days",
          value: "default",
        },
        { label: "Something else", value: "custom" },
      ],
    );
    const filters =
      selection === "default"
        ? DEFAULT_REPOSITORY_FILTERS
        : await selectRepositoryFilters(prompt);
    repositories = await withLoading(
      prompt,
      selection === "default"
        ? "Finding active private and internal repositories..."
        : "Finding repositories that match your filters...",
      async () =>
        await discoverGitHubRepositories(
          dependencies,
          host,
          owner,
          filters,
          signal,
        ),
    );
    if (repositories.length === 0) {
      prompt.write("\nNo repositories matched your selection.\n");
      return null;
    }
    repositoryNames = repositories.map((repository) => repository.fullName);
  }

  prompt.write(`\nFound ${repositoryNames.length} repositories:\n\n`);
  for (const repository of repositoryNames.slice(0, PREVIEW_LIMIT)) {
    prompt.write(`  ${repository}\n`);
  }
  if (repositoryNames.length > PREVIEW_LIMIT) {
    prompt.write(`\n  and ${repositoryNames.length - PREVIEW_LIMIT} more\n`);
  }

  const selectedOutput = await prompt.input(
    "\nWhere should scan results be saved?",
    "./security-scans",
  );
  const outputDir = resolve(
    dependencies.currentDirectory(),
    selectedOutput.trim() || "./security-scans",
  );
  const inputPath = providedInput ?? join(outputDir, "repositories.csv");
  await validateWizardOutput(outputDir, providedInput === undefined);
  prompt.write(
    `\nReady to scan ${repositoryNames.length} repositories?\n\n` +
      `Results will be saved to:\n\n  ${outputDir}\n\n` +
      (providedInput === undefined
        ? `The selected repositories will be saved to:\n\n  ${inputPath}\n\n`
        : `Repository list:\n\n  ${inputPath}\n\n`),
  );
  if (!(await prompt.confirm("Start scanning?", false))) {
    prompt.write("\nScan canceled.\n");
    return null;
  }
  signal?.throwIfAborted();
  if (repositories !== undefined) {
    await mkdir(outputDir, { recursive: true, mode: 0o700 });
    const rows = repositories.map((repository) => ({
      id: repositoryId(repository.fullName),
      repository: repository.url,
      revision: repository.revision,
    }));
    const identifiers = new Set(rows.map((row) => row.id.toLowerCase()));
    if (identifiers.size !== rows.length) {
      throw new Error("Discovered repositories have conflicting scan IDs.");
    }
    await writeFile(inputPath, `${Papa.unparse(rows)}\n`, {
      flag: "wx",
      mode: 0o600,
      ...(signal === undefined ? {} : { signal }),
    });
  }
  return {
    inputPath,
    outputDir,
    ...(githubHost === undefined ? {} : { githubHost }),
  };
}

async function selectRepositoryFilters(
  prompt: BulkScanPrompt,
): Promise<BulkScanRepositoryFilters> {
  const names = await prompt.input(
    "Repository name contains (comma-separated; leave blank for any)",
  );
  const nameKeywords = [...new Set(names.split(",").map((name) => name.trim()))]
    .filter(Boolean)
    .map((name) => name.toLowerCase());
  if (
    nameKeywords.length > 8 ||
    nameKeywords.some((name) => name.length > 80)
  ) {
    throw new Error(
      "Enter at most eight repository-name keywords of 80 characters or fewer.",
    );
  }

  const activity = await prompt.select(
    "Last repository activity",
    [
      { label: "Last 30 days", value: "30" },
      { label: "Last 90 days", value: "90" },
      { label: "Last 180 days", value: "180" },
      { label: "Last year", value: "365" },
      { label: "Any time", value: "all" },
    ],
    "90",
  );
  const language = await prompt.input("Primary language (leave blank for any)");
  if (language.trim().length > 80) {
    throw new Error("Enter a primary language of 80 characters or fewer.");
  }
  const visibility = await prompt.multiSelect(
    "Repository visibility",
    [
      { label: "Private", value: "PRIVATE" },
      { label: "Internal", value: "INTERNAL" },
      { label: "Public", value: "PUBLIC" },
    ],
    ["PRIVATE", "INTERNAL"],
  );
  if (visibility.length === 0) {
    throw new Error("Select at least one repository visibility.");
  }

  return {
    nameKeywords,
    activeWithinDays: activity === "all" ? null : Number(activity),
    language: language.trim() || null,
    visibility,
  };
}

async function withLoading<Value>(
  prompt: BulkScanPrompt,
  message: string,
  operation: () => Promise<Value>,
): Promise<Value> {
  let frame = 0;
  prompt.write(`\n${SPINNER_FRAMES[frame]} ${message}`);
  const interval = setInterval(() => {
    frame = (frame + 1) % SPINNER_FRAMES.length;
    prompt.write(`\r\u001b[2K${SPINNER_FRAMES[frame]} ${message}`);
  }, 100);
  interval.unref();
  try {
    return await operation();
  } finally {
    clearInterval(interval);
    prompt.write("\r\u001b[2K");
  }
}

async function selectGitHubHost(
  dependencies: BulkScanDiscoveryDependencies,
  signal?: AbortSignal,
): Promise<string> {
  const version = await dependencies.runGitHub(["--version"], { signal });
  requireGitHubSuccess(version, "GitHub CLI could not be started.");
  const authentication = await dependencies.runGitHub(
    ["auth", "status", "--json", "hosts"],
    { signal },
  );
  const hosts = parseAuthenticatedHosts(
    authentication,
    dependencies.githubHost,
  );
  if (hosts.length === 1) return hosts[0]!;
  if (hosts.length > 1) {
    return await dependencies.prompt.select(
      "Which GitHub host should we use?",
      hosts.map((host) => ({ label: host, value: host })),
    );
  }
  dependencies.prompt.write(
    "\nSign in to GitHub to find repositories you can access.\n" +
      "No scan will start until you confirm.\n",
  );
  if (
    !(await dependencies.prompt.confirm("Continue to GitHub sign-in?", false))
  ) {
    throw new Error("GitHub sign-in is required to discover repositories.");
  }
  const login = await dependencies.runGitHub(
    [
      "auth",
      "login",
      ...(dependencies.githubHost === undefined
        ? []
        : ["--hostname", dependencies.githubHost]),
    ],
    { interactive: true, signal },
  );
  requireGitHubSuccess(login, "GitHub sign-in did not complete.");
  const refreshed = await dependencies.runGitHub(
    ["auth", "status", "--json", "hosts"],
    { signal },
  );
  const refreshedHosts = parseAuthenticatedHosts(
    refreshed,
    dependencies.githubHost,
  );
  if (refreshedHosts.length === 0) {
    throw new Error("GitHub sign-in could not be confirmed.");
  }
  if (refreshedHosts.length === 1) return refreshedHosts[0]!;
  return await dependencies.prompt.select(
    "Which GitHub host should we use?",
    refreshedHosts.map((host) => ({ label: host, value: host })),
  );
}

function parseAuthenticatedHosts(
  result: BulkScanCommandResult,
  configuredHost?: string,
): string[] {
  if (result.exitCode !== 0 || !result.stdout.trim()) return [];
  let value: unknown;
  try {
    value = JSON.parse(result.stdout);
  } catch {
    return [];
  }
  const parsed = githubAuthenticationSchema.safeParse(value);
  if (!parsed.success) return [];
  return Object.entries(parsed.data.hosts)
    .filter(
      ([host, accounts]) =>
        (configuredHost === undefined || host === configuredHost) &&
        accounts.some(
          (account) => account.active === true && account.state === "success",
        ),
    )
    .map(([host]) => host)
    .sort();
}

async function selectGitHubOwner(
  dependencies: BulkScanDiscoveryDependencies,
  host: string,
  signal?: AbortSignal,
): Promise<string> {
  const organizations = await dependencies.runGitHub(
    ["api", "user/orgs", "--paginate", "--jq", ".[].login"],
    { host, signal },
  );
  requireGitHubSuccess(
    organizations,
    "GitHub organizations could not be listed. Check your organization access or SSO authorization.",
  );
  const owners = [...new Set(organizations.stdout.split(/\r?\n/u))]
    .map((owner) => owner.trim())
    .filter(Boolean)
    .sort();
  if (owners.some((owner) => !GITHUB_OWNER.test(owner))) {
    throw new Error("GitHub returned an invalid organization name.");
  }
  if (owners.length === 1) {
    dependencies.prompt.write(`\nSearching repositories in ${owners[0]}.\n`);
    return owners[0]!;
  }
  if (owners.length > 1) {
    return await dependencies.prompt.select(
      "Which account or organization should we search?",
      owners.map((owner) => ({ label: owner, value: owner })),
    );
  }
  const user = await dependencies.runGitHub(["api", "user", "--jq", ".login"], {
    host,
    signal,
  });
  requireGitHubSuccess(
    user,
    "The active GitHub account could not be determined.",
  );
  const owner = user.stdout.trim();
  if (!GITHUB_OWNER.test(owner)) {
    throw new Error("GitHub returned an invalid account name.");
  }
  dependencies.prompt.write(`\nSearching repositories in ${owner}.\n`);
  return owner;
}

async function discoverGitHubRepositories(
  dependencies: BulkScanDiscoveryDependencies,
  host: string,
  owner: string,
  filters: BulkScanRepositoryFilters,
  signal?: AbortSignal,
): Promise<GitHubRepository[]> {
  if (!GITHUB_OWNER.test(owner)) {
    throw new Error("GitHub account or organization name is invalid.");
  }
  const repositories: GitHubRepository[] = [];
  const cutoff =
    filters.activeWithinDays === null
      ? null
      : dependencies.now() - filters.activeWithinDays * DAY_MILLISECONDS;
  const privacy = filters.visibility.includes("PUBLIC")
    ? filters.visibility.length === 1
      ? "PUBLIC"
      : undefined
    : "PRIVATE";
  let cursor: string | undefined;

  while (true) {
    signal?.throwIfAborted();
    const response = await dependencies.runGitHub(
      [
        "api",
        "graphql",
        "-f",
        `query=${GITHUB_REPOSITORIES_QUERY}`,
        "-f",
        `owner=${owner}`,
        ...(privacy === undefined ? [] : ["-f", `privacy=${privacy}`]),
        ...(cursor === undefined ? [] : ["-f", `endCursor=${cursor}`]),
      ],
      { host, signal },
    );
    requireGitHubSuccess(response, "GitHub repository discovery failed.");
    const page = parseJson(
      githubOwnerRepositoriesSchema,
      response.stdout,
      "GitHub returned an invalid repository discovery response.",
    );
    if (page.errors?.length || page.data.repositoryOwner === null) {
      throw new Error("GitHub could not list repositories for this account.");
    }

    let reachedActivityCutoff = false;
    const connection = page.data.repositoryOwner.repositories;
    for (const repository of connection.nodes) {
      if (repository === null) continue;
      const pushedAt = Date.parse(repository.pushedAt ?? "");
      if (!Number.isFinite(pushedAt)) continue;
      if (cutoff !== null && pushedAt < cutoff) {
        reachedActivityCutoff = true;
        break;
      }
      const parts = repository.nameWithOwner.split("/");
      if (
        parts.length !== 2 ||
        parts[0]!.toLowerCase() !== owner.toLowerCase() ||
        !GITHUB_NAME.test(parts[1]!) ||
        !filters.visibility.some(
          (visibility) => visibility === repository.visibility,
        ) ||
        repository.isArchived ||
        repository.isFork ||
        repository.isEmpty ||
        repository.defaultBranchRef === null ||
        (filters.nameKeywords.length > 0 &&
          !filters.nameKeywords.some((keyword) =>
            parts[1]!.toLowerCase().includes(keyword),
          )) ||
        (filters.language !== null &&
          repository.primaryLanguage?.name.toLowerCase() !==
            filters.language.toLowerCase())
      ) {
        continue;
      }
      repositories.push({
        fullName: repository.nameWithOwner,
        url: validateRepositoryUrl(repository.url, host),
        revision: repository.defaultBranchRef.target.oid.toLowerCase(),
      });
    }
    if (reachedActivityCutoff || !connection.pageInfo.hasNextPage) break;
    if (connection.pageInfo.endCursor === null) {
      throw new Error(
        "GitHub returned an invalid repository pagination cursor.",
      );
    }
    cursor = connection.pageInfo.endCursor;
  }
  return repositories;
}

function validateRepositoryUrl(value: string, host: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("GitHub returned an invalid repository URL.");
  }
  if (
    url.protocol !== "https:" ||
    url.hostname.toLowerCase() !== host.toLowerCase() ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("GitHub returned an unsafe repository URL.");
  }
  url.pathname = url.pathname.replace(/\/$/u, "");
  if (!url.pathname.endsWith(".git")) url.pathname += ".git";
  return url.toString();
}

function repositoryId(fullName: string): string {
  const value = fullName.replace("/", "--");
  if (value.length <= 128) return value;
  const digest = createHash("sha256")
    .update(fullName)
    .digest("hex")
    .slice(0, 16);
  return `${value.slice(0, 111)}-${digest}`;
}

async function validateWizardOutput(
  outputDir: string,
  discovered: boolean,
): Promise<void> {
  const metadata = await lstat(outputDir).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    },
  );
  if (metadata !== undefined && !metadata.isDirectory()) {
    throw new Error("The scan output must be a real directory.");
  }
  if (!discovered || metadata === undefined) return;
  for (const name of ["repositories.csv", "manifest.json"]) {
    const existing = await lstat(join(outputDir, name)).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw error;
      },
    );
    if (existing !== undefined) {
      throw new Error(
        "The selected output directory already contains a repository list or scan. Choose a new directory or resume the existing scan.",
      );
    }
  }
}

function requireGitHubSuccess(
  result: BulkScanCommandResult,
  message: string,
): void {
  if (result.exitCode === 0) return;
  const detail = result.stderr.trim().split("\n").at(-1);
  throw new Error(detail ? `${message} ${detail}` : message);
}

function parseJson<Schema extends z.ZodType>(
  schema: Schema,
  source: string,
  message: string,
): z.output<Schema> {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(message);
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new Error(message);
  return parsed.data;
}

async function runGitHubCommand(
  executable: string,
  args: readonly string[],
  environment: Record<string, string | undefined>,
  options: { interactive?: boolean; signal?: AbortSignal },
): Promise<BulkScanCommandResult> {
  return await new Promise((resolveCommand, reject) => {
    const command = spawn(executable, [...args], {
      env: environment,
      stdio: options.interactive ? "inherit" : ["ignore", "pipe", "pipe"],
      windowsHide: true,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    let stdout = "";
    let stderr = "";
    command.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    command.stderr?.on("data", (chunk: Buffer) => {
      stderr = `${stderr}${chunk.toString("utf8")}`.slice(-64 * 1024);
    });
    command.once("error", reject);
    command.once("close", (code) => {
      resolveCommand({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

function createTerminalPrompt(output: PromptOutput): BulkScanPrompt {
  return {
    isInteractive: () => stdin.isTTY === true && output.isTTY === true,
    write: (value) => {
      output.write(value);
    },
    confirm: async (question, defaultValue = false) => {
      const suffix = defaultValue ? "[Y/n]" : "[y/N]";
      for (;;) {
        const response = (await questionInput(output, `${question} ${suffix} `))
          .trim()
          .toLowerCase();
        if (!response) return defaultValue;
        if (["y", "yes"].includes(response)) return true;
        if (["n", "no"].includes(response)) return false;
        output.write("Please answer yes or no.\n");
      }
    },
    input: async (question, defaultValue) => {
      const suffix = defaultValue === undefined ? ": " : ` [${defaultValue}]: `;
      const response = (
        await questionInput(output, `${question}${suffix}`)
      ).trim();
      return response || defaultValue || "";
    },
    select: async (question, options, defaultValue) => {
      if (options.length === 0) {
        throw new Error("No selection options are available.");
      }
      output.write(`\n${question}\n\n`);
      const defaultIndex = options.findIndex(
        (option) => option.value === defaultValue,
      );
      let selected = defaultIndex < 0 ? 0 : defaultIndex;
      const render = (): void => {
        for (let index = 0; index < options.length; index += 1) {
          output.write(
            `\u001b[2K\r${index === selected ? "❯" : " "} ${options[index]!.label}\n`,
          );
        }
      };
      render();
      emitKeypressEvents(stdin);
      const wasRaw = stdin.isRaw;
      stdin.setRawMode(true);
      stdin.resume();
      return await new Promise((resolveSelection, reject) => {
        const cleanup = (): void => {
          stdin.removeListener("keypress", onKeypress);
          stdin.setRawMode(wasRaw === true);
          stdin.pause();
        };
        const onKeypress = (
          _value: string | undefined,
          key: { name?: string; ctrl?: boolean },
        ): void => {
          if (key.ctrl && key.name === "c") {
            cleanup();
            reject(new BulkScanInterruptedError());
            return;
          }
          if (key.name === "return" || key.name === "enter") {
            cleanup();
            output.write("\n");
            resolveSelection(options[selected]!.value);
            return;
          }
          if (key.name !== "up" && key.name !== "down") return;
          selected =
            key.name === "up"
              ? (selected + options.length - 1) % options.length
              : (selected + 1) % options.length;
          output.write(`\u001b[${options.length}A`);
          render();
        };
        stdin.on("keypress", onKeypress);
      });
    },
    multiSelect: async (question, options, defaultValues = []) => {
      if (options.length === 0) {
        throw new Error("No selection options are available.");
      }
      output.write(
        `\n${question}\nUse ↑/↓ to move, Space to toggle, and Enter to confirm.\n\n`,
      );
      let focused = 0;
      const selected = new Set(defaultValues);
      const render = (): void => {
        for (let index = 0; index < options.length; index += 1) {
          const option = options[index]!;
          const cursor = index === focused ? "❯" : " ";
          const checkbox = selected.has(option.value) ? "[x]" : "[ ]";
          output.write(`\u001b[2K\r${cursor} ${checkbox} ${option.label}\n`);
        }
      };
      render();
      emitKeypressEvents(stdin);
      const wasRaw = stdin.isRaw;
      stdin.setRawMode(true);
      stdin.resume();
      return await new Promise((resolveSelection, reject) => {
        const cleanup = (): void => {
          stdin.removeListener("keypress", onKeypress);
          stdin.setRawMode(wasRaw === true);
          stdin.pause();
        };
        const onKeypress = (
          value: string | undefined,
          key: { name?: string; ctrl?: boolean },
        ): void => {
          if (key.ctrl && key.name === "c") {
            cleanup();
            reject(new BulkScanInterruptedError());
            return;
          }
          if (key.name === "return" || key.name === "enter") {
            if (selected.size === 0) {
              output.write("\u0007");
              return;
            }
            cleanup();
            output.write("\n");
            resolveSelection(
              options
                .filter((option) => selected.has(option.value))
                .map((option) => option.value),
            );
            return;
          }
          if (key.name === "space" || value === " ") {
            const option = options[focused]!;
            if (selected.has(option.value)) selected.delete(option.value);
            else selected.add(option.value);
          } else if (key.name === "up" || key.name === "down") {
            focused =
              key.name === "up"
                ? (focused + options.length - 1) % options.length
                : (focused + 1) % options.length;
          } else {
            return;
          }
          output.write(`\u001b[${options.length}A`);
          render();
        };
        stdin.on("keypress", onKeypress);
      });
    },
  };
}

async function questionInput(
  output: PromptOutput,
  question: string,
): Promise<string> {
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      try {
        output.write(chunk.toString("utf8"));
        callback();
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
      }
    },
  });
  const terminal = createInterface({
    input: stdin,
    output: destination,
    terminal: true,
  });
  try {
    return await terminal.question(question);
  } finally {
    terminal.close();
  }
}
