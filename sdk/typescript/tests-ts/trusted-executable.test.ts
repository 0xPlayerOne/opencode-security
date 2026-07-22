import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "trusted-executable-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function resolveWindowsExecutable(
  candidate: string,
  path: string,
  protectedRoot: string,
): { executable: string; environment: Record<string, string> } | null {
  const script = `
    Object.defineProperty(process, "platform", { value: "win32" });
    const { resolveTrustedExecutable } = await import(process.argv[1]);
    console.log(JSON.stringify(await resolveTrustedExecutable(
      process.argv[2],
      { Path: process.argv[3], KEEP: "ok" },
      process.argv[4],
    )));
  `;
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      script,
      fileURLToPath(new URL("../src/trusted-executable.ts", import.meta.url)),
      candidate,
      path,
      protectedRoot,
    ],
    { encoding: "utf8" },
  );
  expect(result.status).toBe(0);
  return JSON.parse(result.stdout) as {
    executable: string;
    environment: Record<string, string>;
  } | null;
}

describe("trusted executable resolution", () => {
  test("selects runnable Windows executables ahead of extensionless and batch files", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const second = join(root, "second");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(second)]);
    await Promise.all([
      writeFile(join(first, "git"), "extensionless"),
      writeFile(join(first, "git.cmd"), "batch"),
      writeFile(join(first, "git.bat"), "batch"),
      writeFile(join(second, "git.exe"), "executable"),
      writeFile(join(second, "git.com"), "executable"),
    ]);

    expect(
      resolveWindowsExecutable(
        "git",
        [first, second].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(second, "git.exe"),
      environment: { KEEP: "ok", PATH: [first, second].join(delimiter) },
    });
  });

  test("accepts a Windows COM executable and rejects batch-only candidates", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const com = join(root, "com");
    const batch = join(root, "batch");
    await Promise.all([mkdir(repository), mkdir(com), mkdir(batch)]);
    await Promise.all([
      writeFile(join(com, "python3.com"), "executable"),
      writeFile(join(batch, "python3"), "extensionless"),
      writeFile(join(batch, "python3.cmd"), "batch"),
      writeFile(join(batch, "python3.bat"), "batch"),
    ]);

    expect(resolveWindowsExecutable("python3", com, repository)).toEqual({
      executable: join(com, "python3.com"),
      environment: { KEEP: "ok", PATH: com },
    });
    expect(resolveWindowsExecutable("python3", batch, repository)).toBeNull();
  });

  test("resolves already-suffixed Windows executables without adding another extension", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(first, "python.exe.exe"), "wrong executable"),
      writeFile(join(trusted, "python.exe"), "python executable"),
      writeFile(join(trusted, "git.exe"), "git executable"),
      writeFile(join(trusted, "tool.com"), "com executable"),
      writeFile(join(trusted, "script.cmd"), "batch"),
    ]);

    for (const candidate of ["python.exe", "git.exe", "tool.com"]) {
      expect(
        resolveWindowsExecutable(
          candidate,
          [first, trusted].join(delimiter),
          repository,
        ),
      ).toEqual({
        executable: join(trusted, candidate),
        environment: { KEEP: "ok", PATH: [first, trusted].join(delimiter) },
      });
    }
    expect(
      resolveWindowsExecutable("script.cmd", trusted, repository),
    ).toBeNull();
  });

  test("removes PATH entries containing repository-linked Windows shims", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const unsafe = join(repository, "node_modules", ".bin");
    const linked = join(root, "linked");
    const trusted = join(root, "trusted");
    await Promise.all([
      mkdir(unsafe, { recursive: true }),
      mkdir(linked),
      mkdir(trusted),
    ]);
    await Promise.all([
      writeFile(join(unsafe, "git.cmd"), "batch"),
      writeFile(join(unsafe, "git"), "extensionless"),
      writeFile(join(trusted, "git.exe"), "executable"),
    ]);
    await Promise.all([
      symlink(join(unsafe, "git.cmd"), join(linked, "git.cmd")),
      symlink(join(unsafe, "git"), join(linked, "git")),
    ]);

    expect(
      resolveWindowsExecutable(
        "git",
        [unsafe, linked, trusted].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(trusted, "git.exe"),
      environment: { KEEP: "ok", PATH: trusted },
    });
  });
});
