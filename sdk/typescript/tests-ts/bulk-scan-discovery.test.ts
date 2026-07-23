import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  runBulkScanWizard,
  type BulkScanCommandResult,
  type BulkScanDiscoveryDependencies,
  type BulkScanPrompt,
} from "../src/bulk-scan-discovery.js";

const temporaryDirectories: string[] = [];
const NOW = Date.parse("2026-07-22T12:00:00.000Z");
const REVISION = "0123456789abcdef0123456789abcdef01234567";

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-bulk-discovery-"));
  temporaryDirectories.push(root);
  return root;
}

class FakePrompt implements BulkScanPrompt {
  public readonly messages: string[] = [];
  public readonly questions: string[] = [];
  public readonly selections: string[] = [];
  public interactive = true;
  public confirms: boolean[] = [];
  public inputs: string[] = [];
  public choices: string[] = [];
  public multiChoices: string[][] = [];

  public isInteractive(): boolean {
    return this.interactive;
  }

  public write(value: string): void {
    this.messages.push(value);
  }

  public async confirm(
    question: string,
    defaultValue = false,
  ): Promise<boolean> {
    this.questions.push(question);
    return this.confirms.shift() ?? defaultValue;
  }

  public async input(question: string, defaultValue?: string): Promise<string> {
    this.questions.push(question);
    return this.inputs.shift() ?? defaultValue ?? "";
  }

  public async select<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value }[],
    defaultValue?: Value,
  ): Promise<Value> {
    this.questions.push(question);
    this.selections.push(...options.map((option) => option.label));
    const selection = this.choices.shift();
    const chosen =
      selection === undefined
        ? options.find((option) => option.value === defaultValue) ?? options[0]
        : options.find((option) => option.value === selection);
    if (chosen === undefined) throw new Error("Unexpected test selection.");
    return chosen.value;
  }

  public async multiSelect<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value }[],
    defaultValues: readonly Value[] = [],
  ): Promise<Value[]> {
    this.questions.push(question);
    this.selections.push(...options.map((option) => option.label));
    const selected = this.multiChoices.shift() ?? defaultValues;
    return options
      .filter((option) => selected.includes(option.value))
      .map((option) => option.value);
  }
}

function success(stdout: string): BulkScanCommandResult {
  return { exitCode: 0, stdout, stderr: "" };
}

function discoveryDependencies(
  root: string,
  options: {
    prompt?: FakePrompt;
    host?: string;
    organizations?: string[];
    repositories?: Array<{
      fullName: string;
      visibility?: "private" | "internal" | "public";
      archived?: boolean;
      fork?: boolean;
      empty?: boolean;
      pushedAt?: string;
      language?: string | null;
    }>;
    authenticated?: boolean;
  } = {},
): {
  dependencies: BulkScanDiscoveryDependencies;
  prompt: FakePrompt;
  commands: Array<{ args: readonly string[]; host?: string }>;
} {
  const prompt = options.prompt ?? new FakePrompt();
  const host = options.host ?? "github.com";
  const repositories = options.repositories ?? [
    { fullName: "acme/payments-api", visibility: "private" as const },
    { fullName: "acme/identity-service", visibility: "internal" as const },
  ];
  const commands: Array<{ args: readonly string[]; host?: string }> = [];
  let authenticated = options.authenticated ?? true;
  const dependencies: BulkScanDiscoveryDependencies = {
    prompt,
    now: () => NOW,
    currentDirectory: () => root,
    ...(options.host === undefined ? {} : { githubHost: host }),
    runGitHub: async (args, commandOptions) => {
      commands.push({
        args,
        ...(commandOptions?.host === undefined
          ? {}
          : { host: commandOptions.host }),
      });
      if (args[0] === "--version") return success("gh version test\n");
      if (args[0] === "auth" && args[1] === "status") {
        return success(
          JSON.stringify({
            hosts: authenticated
              ? { [host]: [{ active: true, state: "success" }] }
              : {},
          }),
        );
      }
      if (args[0] === "auth" && args[1] === "login") {
        authenticated = true;
        return success("");
      }
      if (args[0] === "api" && args[1] === "user/orgs") {
        return success((options.organizations ?? ["acme"]).join("\n"));
      }
      if (args[0] === "api" && args[1] === "user") {
        return success("personal-account\n");
      }
      if (args[0] === "api" && args[1] === "graphql") {
        const query = args.find((argument) => argument.startsWith("query="));
        if (query?.includes("repositoryOwner(login: $owner)")) {
          const cursor = args
            .find((argument) => argument.startsWith("endCursor="))
            ?.slice("endCursor=".length);
          const start = cursor === undefined ? 0 : Number(cursor);
          const page = repositories.slice(start, start + 100);
          const next = start + page.length;
          return success(
            JSON.stringify({
              data: {
                repositoryOwner: {
                  repositories: {
                    nodes: page.map((repository) => ({
                      nameWithOwner: repository.fullName,
                      url: `https://${host}/${repository.fullName}`,
                      visibility: (
                        repository.visibility ?? "private"
                      ).toUpperCase(),
                      isArchived: repository.archived ?? false,
                      isFork: repository.fork ?? false,
                      isEmpty: repository.empty ?? false,
                      pushedAt: repository.pushedAt ?? "2026-07-20T00:00:00Z",
                      primaryLanguage:
                        repository.language === undefined ||
                        repository.language === null
                          ? null
                          : { name: repository.language },
                      defaultBranchRef: repository.empty
                        ? null
                        : { target: { oid: REVISION } },
                    })),
                    pageInfo: {
                      hasNextPage: next < repositories.length,
                      endCursor:
                        next < repositories.length ? String(next) : null,
                    },
                  },
                },
              },
            }),
          );
        }
      }
      throw new Error(`Unexpected GitHub command: ${args.join(" ")}`);
    },
  };
  return { dependencies, prompt, commands };
}

describe("bulk scan repository discovery", () => {
  test("discovers active private and internal repositories without repository search", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.confirms = [false, true, true];
    prompt.inputs = ["./security-scans"];

    const result = await runBulkScanWizard(dependencies);

    expect(result).toEqual({
      inputPath: join(root, "security-scans", "repositories.csv"),
      outputDir: join(root, "security-scans"),
      githubHost: "github.com",
    });
    expect(commands.some(({ args }) => args[0] === "search")).toBe(false);
    const graphql = commands.find(
      ({ args }) => args[0] === "api" && args[1] === "graphql",
    )?.args;
    const query = graphql?.find((argument) => argument.startsWith("query="));
    expect(query).toContain("privacy: $privacy");
    expect(graphql).toContain("privacy=PRIVATE");
    expect(query).toContain("isArchived: false");
    expect(query).toContain("isFork: false");
    expect(query).toContain("field: PUSHED_AT");
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("id,repository,revision");
    expect(csv).toContain(
      `acme--payments-api,https://github.com/acme/payments-api.git,${REVISION}`,
    );
    expect(csv).toContain(
      `acme--identity-service,https://github.com/acme/identity-service.git,${REVISION}`,
    );
    expect(prompt.messages.join("")).toContain("Found 2 repositories");
    expect(prompt.messages.join("")).toContain(
      "Finding active private and internal repositories...",
    );
    expect(prompt.questions).not.toContain(
      "Which account or organization should we search?",
    );
  });

  test("discovers more than 100 active repositories across GitHub pages", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: Array.from({ length: 151 }, (_value, index) => ({
        fullName: `acme/service-${String(index).padStart(3, "0")}`,
      })),
    });
    prompt.confirms = [false, true, true];

    const result = await runBulkScanWizard(dependencies);

    expect(result).not.toBeNull();
    expect(prompt.messages.join("")).toContain("Found 151 repositories");
    expect(
      commands.filter(({ args }) => args[0] === "api" && args[1] === "graphql"),
    ).toHaveLength(2);
    expect(commands.some(({ args }) => args[0] === "search")).toBe(false);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--service-000");
    expect(csv).toContain("acme--service-150");
  });

  test("stops paginating when repositories are older than 90 days", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/active-service" },
        {
          fullName: "acme/old-service",
          pushedAt: "2026-04-22T00:00:00Z",
        },
        ...Array.from({ length: 100 }, (_value, index) => ({
          fullName: `acme/older-${index}`,
          pushedAt: "2026-04-21T00:00:00Z",
        })),
      ],
    });
    prompt.confirms = [false, true, true];

    const result = await runBulkScanWizard(dependencies);

    expect(result).not.toBeNull();
    expect(prompt.messages.join("")).toContain("Found 1 repositories");
    expect(
      commands.filter(({ args }) => args[0] === "api" && args[1] === "graphql"),
    ).toHaveLength(1);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--active-service");
    expect(csv).not.toContain("old-service");
  });

  test("matches any custom repository-name keyword without GitHub search", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/owl" },
        { fullName: "acme/openai" },
        { fullName: "acme/openai-public", visibility: "public" },
        { fullName: "acme/unrelated-service" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom"];
    prompt.inputs = [" OwL, OPENAI ", "", "./custom-results"];

    const result = await runBulkScanWizard(dependencies);

    expect(result?.outputDir).toBe(join(root, "custom-results"));
    expect(commands.some(({ args }) => args[0] === "search")).toBe(false);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--owl");
    expect(csv).toContain("acme--openai");
    expect(csv).not.toContain("openai-public");
    expect(csv).not.toContain("unrelated-service");
    expect(prompt.messages.join("")).toContain(
      "Finding repositories that match your filters...",
    );
    expect(prompt.selections).toContain("Something else");
    expect(prompt.questions).toContain(
      "Repository name contains (comma-separated; leave blank for any)",
    );
    expect(prompt.questions).toContain("Last repository activity");
    expect(prompt.questions).toContain(
      "Primary language (leave blank for any)",
    );
    expect(prompt.questions).toContain("Repository visibility");
    expect(prompt.selections).toContain("Private");
    expect(prompt.selections).toContain("Internal");
    expect(prompt.selections).toContain("Public");
    expect(prompt.questions.join(" ").toLowerCase()).not.toContain("topic");
    expect(prompt.questions.join(" ").toLowerCase()).not.toContain("archived");
    expect(prompt.questions.join(" ").toLowerCase()).not.toContain("fork");
  });

  test("filters repositories by primary language case-insensitively", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/python-service", language: "Python" },
        { fullName: "acme/typescript-service", language: "TypeScript" },
        { fullName: "acme/unknown-service" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom"];
    prompt.inputs = ["service", "python", "./python-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--python-service");
    expect(csv).not.toContain("typescript-service");
    expect(csv).not.toContain("unknown-service");
  });

  test("orders activity windows chronologically while defaulting to 90 days", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        {
          fullName: "acme/active-within-90-days",
          pushedAt: "2026-06-12T00:00:00Z",
        },
        {
          fullName: "acme/older-than-90-days",
          pushedAt: "2026-04-01T00:00:00Z",
        },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom"];
    prompt.inputs = ["", "", "./activity-results"];

    const result = await runBulkScanWizard(dependencies);

    const firstActivity = prompt.selections.indexOf("Last 30 days");
    expect(prompt.selections.slice(firstActivity, firstActivity + 5)).toEqual([
      "Last 30 days",
      "Last 90 days",
      "Last 180 days",
      "Last year",
      "Any time",
    ]);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--active-within-90-days");
    expect(csv).not.toContain("older-than-90-days");
  });

  test("filters internal repositories without including private repositories", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/private-service", visibility: "private" },
        { fullName: "acme/internal-service", visibility: "internal" },
        { fullName: "acme/public-service", visibility: "public" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom", "90"];
    prompt.multiChoices = [["INTERNAL"]];
    prompt.inputs = ["", "", "./internal-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--internal-service");
    expect(csv).not.toContain("private-service");
    expect(csv).not.toContain("public-service");
    expect(
      commands.find(({ args }) => args[0] === "api" && args[1] === "graphql")
        ?.args,
    ).toContain("privacy=PRIVATE");
  });

  test("filters public repositories and sets GitHub public privacy", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/private-service", visibility: "private" },
        { fullName: "acme/public-service", visibility: "public" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom", "90"];
    prompt.multiChoices = [["PUBLIC"]];
    prompt.inputs = ["", "", "./public-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--public-service");
    expect(csv).not.toContain("private-service");
    expect(
      commands.find(({ args }) => args[0] === "api" && args[1] === "graphql")
        ?.args,
    ).toContain("privacy=PUBLIC");
  });

  test("includes every visibility when all repositories are selected", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/private-service", visibility: "private" },
        { fullName: "acme/internal-service", visibility: "internal" },
        { fullName: "acme/public-service", visibility: "public" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom", "90"];
    prompt.multiChoices = [["PRIVATE", "INTERNAL", "PUBLIC"]];
    prompt.inputs = ["", "", "./all-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--private-service");
    expect(csv).toContain("acme--internal-service");
    expect(csv).toContain("acme--public-service");
    expect(
      commands
        .find(({ args }) => args[0] === "api" && args[1] === "graphql")
        ?.args.some((argument) => argument.startsWith("privacy=")),
    ).toBe(false);
  });

  test("allows private and public visibility to be selected together", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/private-service", visibility: "private" },
        { fullName: "acme/internal-service", visibility: "internal" },
        { fullName: "acme/public-service", visibility: "public" },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom", "90"];
    prompt.multiChoices = [["PRIVATE", "PUBLIC"]];
    prompt.inputs = ["", "", "./mixed-visibility-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--private-service");
    expect(csv).toContain("acme--public-service");
    expect(csv).not.toContain("internal-service");
    expect(
      commands
        .find(({ args }) => args[0] === "api" && args[1] === "graphql")
        ?.args.some((argument) => argument.startsWith("privacy=")),
    ).toBe(false);
  });

  test("requires at least one selected repository visibility", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.confirms = [false, true];
    prompt.choices = ["custom", "90"];
    prompt.multiChoices = [[]];
    prompt.inputs = ["", ""];

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "Select at least one repository visibility",
    );
    expect(
      commands.some(({ args }) => args[0] === "api" && args[1] === "graphql"),
    ).toBe(false);
    await expect(lstat(join(root, "security-scans"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  test("supports an all-time activity window", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/active-service" },
        {
          fullName: "acme/old-service",
          pushedAt: "2024-01-01T00:00:00Z",
        },
      ],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["custom", "all"];
    prompt.inputs = ["", "", "./all-time-results"];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--active-service");
    expect(csv).toContain("acme--old-service");
  });

  test("rejects an excessive number of name keywords before discovery", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.confirms = [false, true];
    prompt.choices = ["custom"];
    prompt.inputs = ["one,two,three,four,five,six,seven,eight,nine"];

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "at most eight repository-name keywords",
    );
    expect(
      commands.some(({ args }) => args[0] === "api" && args[1] === "graphql"),
    ).toBe(false);
  });

  test("honors a configured GitHub Enterprise host", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      host: "github.acme.example",
    });
    prompt.confirms = [false, true, true];

    const result = await runBulkScanWizard(dependencies);

    expect(result).not.toBeNull();
    expect(result?.githubHost).toBe("github.acme.example");
    expect(
      commands
        .filter(({ args }) => args[0] === "api" || args[0] === "search")
        .every((call) => call.host === "github.acme.example"),
    ).toBe(true);
    expect(await readFile(result!.inputPath, "utf8")).toContain(
      "https://github.acme.example/acme/payments-api.git",
    );
  });

  test("confirms GitHub sign-in before discovering repositories", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      authenticated: false,
    });
    prompt.confirms = [false, true, true, true];

    expect(await runBulkScanWizard(dependencies)).not.toBeNull();
    expect(prompt.questions).toContain("Continue to GitHub sign-in?");
    expect(
      commands.find(({ args }) => args[0] === "auth" && args[1] === "login")
        ?.args,
    ).toEqual(["auth", "login"]);
    expect(prompt.messages.join("")).toContain(
      "Sign in to GitHub to find repositories you can access.",
    );
  });

  test("preserves a configured enterprise hostname during GitHub sign-in", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      authenticated: false,
      host: "github.acme.example",
    });
    prompt.confirms = [false, true, true, true];

    expect(await runBulkScanWizard(dependencies)).not.toBeNull();
    expect(
      commands.find(({ args }) => args[0] === "auth" && args[1] === "login")
        ?.args,
    ).toEqual(["auth", "login", "--hostname", "github.acme.example"]);
  });

  test("does not search GitHub when sign-in is declined", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root, {
      authenticated: false,
    });
    prompt.confirms = [false, true, false];

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "GitHub sign-in is required",
    );
    expect(commands.some(({ args }) => args[0] === "search")).toBe(false);
    await expect(lstat(join(root, "security-scans"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  test("leaves non-GitHub repository discovery unsupported", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.confirms = [false, false];

    expect(await runBulkScanWizard(dependencies)).toBeNull();
    expect(prompt.messages.join("")).toContain("supports GitHub only");
    expect(commands).toEqual([]);
  });

  test("asks for an owner only when several organizations are available", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      organizations: ["acme", "acme-labs"],
    });
    prompt.confirms = [false, true, true];
    prompt.choices = ["acme", "default"];

    await runBulkScanWizard(dependencies);

    expect(prompt.questions).toContain(
      "Which account or organization should we search?",
    );
    expect(prompt.selections).toContain("acme");
    expect(prompt.selections).toContain("acme-labs");
  });

  test("always excludes archived, forked, and empty repositories", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/payments-api" },
        { fullName: "acme/archive", archived: true },
        { fullName: "acme/fork", fork: true },
        { fullName: "acme/empty", empty: true },
        { fullName: "another-owner/service" },
      ],
    });
    prompt.confirms = [false, true, true];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--payments-api");
    expect(csv).not.toContain("archive");
    expect(csv).not.toContain("fork");
    expect(csv).not.toContain("empty");
    expect(csv).not.toContain("another-owner");
  });

  test("validates an existing CSV without using GitHub discovery", async () => {
    const root = await temporaryDirectory();
    const input = join(root, "existing.csv");
    await writeFile(
      input,
      `id,repository,revision\nservice,https://github.com/acme/service.git,${REVISION}\n`,
    );
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.confirms = [true, true];
    prompt.inputs = ["existing.csv", "./existing-results"];

    expect(await runBulkScanWizard(dependencies)).toEqual({
      inputPath: input,
      outputDir: join(root, "existing-results"),
    });
    expect(commands).toEqual([]);
  });

  test("does not create a repository list when confirmation is declined", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root);
    prompt.confirms = [false, true, false];

    expect(await runBulkScanWizard(dependencies)).toBeNull();
    await expect(lstat(join(root, "security-scans"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(prompt.messages.join("")).toContain("Scan canceled.");
  });

  test("does not create a repository list when no repositories match", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [],
    });
    prompt.confirms = [false, true];

    expect(await runBulkScanWizard(dependencies)).toBeNull();
    await expect(lstat(join(root, "security-scans"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(prompt.messages.join("")).toContain("No repositories matched");
  });

  test("rejects an existing scan instead of replacing its repository list", async () => {
    const root = await temporaryDirectory();
    const output = join(root, "existing-results");
    const existing = join(output, "repositories.csv");
    await mkdir(output, { recursive: true });
    await writeFile(existing, "do not overwrite\n");
    const { dependencies, prompt } = discoveryDependencies(root);
    prompt.confirms = [false, true];
    prompt.inputs = ["./existing-results"];

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "already contains a repository list or scan",
    );
    expect(await readFile(existing, "utf8")).toBe("do not overwrite\n");
  });

  test("rejects interactive discovery without a terminal", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    prompt.interactive = false;

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "requires a terminal",
    );
    expect(commands).toEqual([]);
  });

  test("honors cancellation before prompting or starting discovery", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, commands } = discoveryDependencies(root);
    const controller = new AbortController();
    controller.abort();

    await expect(
      runBulkScanWizard(dependencies, controller.signal),
    ).rejects.toThrow();
    expect(prompt.questions).toEqual([]);
    expect(commands).toEqual([]);
  });
});
