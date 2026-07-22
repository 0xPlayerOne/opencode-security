const MAX_WORKER_STATUS_BYTES = 64 * 1024;
const MAX_WORKER_COUNT = 1024;
const WORKER_STATUS_PREFIX = "CODEX_SECURITY_WORKER_STATUS ";
const PREFLIGHT_COMMAND = /(?:^|[\\/])config_preflight\.py(?=$|["'\s])/u;
const WORKER_PHASES = new Set([
  "ranking",
  "file_review",
  "validation",
  "attack_path",
]);

export type ScanWorkerPhase =
  | "ranking"
  | "file_review"
  | "validation"
  | "attack_path";

export type ScanWorkerStatus =
  | {
      kind: "preflight";
      delegation: "available" | "unavailable" | "unknown";
      configuredSlots: number | null;
    }
  | {
      kind: "dispatch";
      phase: ScanWorkerPhase;
      planned: number;
      started: number;
    };

export function workerStatusFromEvent(
  event: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (event["type"] !== "item.completed" || !isRecord(event["item"])) {
    return null;
  }
  const item = event["item"];
  if (item["type"] === "command_execution") return preflightStatus(item);
  if (item["type"] === "agent_message") return dispatchStatus(item);
  return null;
}

function preflightStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (
    typeof item["command"] !== "string" ||
    !PREFLIGHT_COMMAND.test(item["command"]) ||
    typeof item["aggregated_output"] !== "string" ||
    Buffer.byteLength(item["aggregated_output"], "utf8") >
      MAX_WORKER_STATUS_BYTES
  ) {
    return null;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(item["aggregated_output"]);
  } catch {
    return null;
  }
  if (
    !isRecord(payload) ||
    (payload["profile"] !== "security_scan" &&
      payload["profile"] !== "security_diff_scan") ||
    !Array.isArray(payload["results"])
  ) {
    return null;
  }
  const results = payload["results"];
  const delegated = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) && result["capability"] === "delegated_workers",
  );
  const delegatedResult = delegated[0];
  if (delegated.length !== 1 || delegatedResult === undefined) return null;
  const delegation =
    delegatedResult["status"] === "pass"
      ? "available"
      : delegatedResult["status"] === "fail"
        ? "unavailable"
        : delegatedResult["status"] === "unknown"
          ? "unknown"
          : null;
  if (delegation === null) return null;
  const capacity = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) &&
      typeof result["capability"] === "string" &&
      result["capability"].startsWith("usable_worker_slots_"),
  );
  if (capacity.length > 1) return null;
  const capacityResult = capacity[0];
  const configuredSlots =
    capacity.length === 1 &&
    capacityResult !== undefined &&
    isWorkerCount(capacityResult["actual"])
      ? capacityResult["actual"]
      : null;
  return { kind: "preflight", delegation, configuredSlots };
}

function dispatchStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (
    typeof item["text"] !== "string" ||
    Buffer.byteLength(item["text"], "utf8") > MAX_WORKER_STATUS_BYTES
  ) {
    return null;
  }
  const markers = item["text"]
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(WORKER_STATUS_PREFIX));
  const marker = markers[0];
  if (markers.length !== 1 || marker === undefined) return null;
  let payload: unknown;
  try {
    payload = JSON.parse(marker.slice(WORKER_STATUS_PREFIX.length));
  } catch {
    return null;
  }
  if (
    !isRecord(payload) ||
    Object.keys(payload).length !== 3 ||
    typeof payload["phase"] !== "string" ||
    !WORKER_PHASES.has(payload["phase"]) ||
    !isWorkerCount(payload["planned"]) ||
    !isWorkerCount(payload["started"]) ||
    payload["started"] > payload["planned"]
  ) {
    return null;
  }
  return {
    kind: "dispatch",
    phase: payload["phase"] as ScanWorkerPhase,
    planned: payload["planned"],
    started: payload["started"],
  };
}

function isWorkerCount(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_WORKER_COUNT
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
