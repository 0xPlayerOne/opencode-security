import { describe, expect, test } from "bun:test";
import { workerStatusFromEvent } from "../src/worker-progress.js";

function commandEvent(
  command: string,
  output: string,
): Record<string, unknown> {
  return {
    type: "item.completed",
    item: {
      id: "command-1",
      type: "command_execution",
      command,
      aggregated_output: output,
      exit_code: 0,
      status: "completed",
    },
  };
}

function messageEvent(text: string): Record<string, unknown> {
  return {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text },
  };
}

describe("worker progress events", () => {
  test("reads configured worker capacity from a completed preflight", () => {
    const output = JSON.stringify({
      profile: "security_scan",
      status: "ready",
      results: [
        { capability: "delegated_workers", status: "pass", actual: true },
        { capability: "usable_worker_slots_6", status: "pass", actual: 8 },
      ],
    });

    expect(
      workerStatusFromEvent(
        commandEvent(
          '"/managed/python" "$CODEX_SECURITY_PLUGIN_ROOT/scripts/config_preflight.py" --profile security_scan',
          output,
        ),
      ),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: 8,
    });
  });

  test("keeps unavailable and unknown delegation distinct from capacity", () => {
    for (const [status, delegation] of [
      ["fail", "unavailable"],
      ["unknown", "unknown"],
    ] as const) {
      expect(
        workerStatusFromEvent(
          commandEvent(
            "python3 /plugin/scripts/config_preflight.py --profile security_scan",
            JSON.stringify({
              profile: "security_scan",
              status: status === "unknown" ? "incomplete" : "ready",
              results: [
                { capability: "delegated_workers", status },
                {
                  capability: "usable_worker_slots_6",
                  status: "pass",
                  actual: 8,
                },
              ],
            }),
          ),
        ),
      ).toEqual({ kind: "preflight", delegation, configuredSlots: 8 });
    }
  });

  test("accepts diff preflight without a worker-slot requirement", () => {
    expect(
      workerStatusFromEvent(
        commandEvent(
          "python3 C:\\plugin\\scripts\\config_preflight.py --profile security_diff_scan",
          JSON.stringify({
            profile: "security_diff_scan",
            status: "ready",
            results: [{ capability: "delegated_workers", status: "pass" }],
          }),
        ),
      ),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: null,
    });
  });

  test("reads a bounded dispatch marker from the agent message", () => {
    expect(
      workerStatusFromEvent(
        messageEvent(
          'Reviewing the ranked worklist.\nCODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":3}',
        ),
      ),
    ).toEqual({
      kind: "dispatch",
      phase: "file_review",
      planned: 6,
      started: 3,
    });
    expect(
      workerStatusFromEvent(
        messageEvent(
          'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":0}',
        ),
      ),
    ).toEqual({ kind: "dispatch", phase: "ranking", planned: 6, started: 0 });
  });

  test("ignores unrelated, malformed, conflicting, or oversized events", () => {
    const preflight = JSON.stringify({
      profile: "security_scan",
      results: [{ capability: "delegated_workers", status: "pass" }],
    });
    for (const event of [
      commandEvent("rg config_preflight.py /repository", preflight),
      commandEvent("python3 /plugin/scripts/config_preflight.py", "not json"),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: "deep_security_scan",
          results: [{ capability: "delegated_workers", status: "pass" }],
        }),
      ),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: ["security_scan"],
          results: [{ capability: "delegated_workers", status: "pass" }],
        }),
      ),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: "security_scan",
          results: [
            { capability: "delegated_workers", status: "pass" },
            { capability: "delegated_workers", status: "fail" },
          ],
        }),
      ),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        `${preflight}${" ".repeat(65 * 1024)}`,
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":3}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":-1,"started":0}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"discovery","planned":2,"started":1}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":1,"path":"/repository"}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":1}\nCODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":0}',
      ),
    ]) {
      expect(workerStatusFromEvent(event)).toBeNull();
    }
  });
});
