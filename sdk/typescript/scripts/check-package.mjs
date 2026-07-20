import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const [archive] = args;
if (archive === undefined || args.length !== 1) {
  throw new Error("Usage: node scripts/check-package.mjs <npm-tarball>");
}

const MAX_EXPANDED_ASSET_BYTES = 32 * 1024 * 1024;
const MAX_ENCODED_CANDIDATES = 16_384;
const archiveBytes = gunzipSync(readFileSync(archive), {
  maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
});
const PUBLIC_LOGO_SHA256 =
  "9b9c2b09b2fa064611fb62307d321d5c2ea70cf0789f7ce34cdb0fc0d9190b3a";
const tarOptions = { maxBuffer: archiveBytes.byteLength + 1024 };
function tar(args, encoding = "buffer") {
  const result = spawnSync("tar", ["--ignore-zeros", ...args], {
    ...tarOptions,
    encoding,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0 || result.stderr.length !== 0) {
    const stderr = result.stderr.toString().trim();
    throw new Error(
      `npm tarball contains an invalid tar entry${stderr === "" ? "." : `: ${stderr}`}`,
    );
  }
  return result.stdout;
}

for (let offset = 0; offset + 512 <= archiveBytes.byteLength; ) {
  const header = archiveBytes.subarray(offset, offset + 512);
  if (header.every((byte) => byte === 0)) {
    offset += 512;
    continue;
  }
  const name = header.subarray(0, 100).toString("utf8").split("\0", 1)[0];
  const prefix = header.subarray(345, 500).toString("utf8").split("\0", 1)[0];
  const path = prefix === "" ? name : `${prefix}/${name}`;
  const sizeField = header
    .subarray(124, 136)
    .toString("ascii")
    .split("\0", 1)[0]
    .trim();
  if (!/^[0-7]*$/u.test(sizeField)) {
    throw new Error("npm tarball contains an invalid tar entry.");
  }
  if (path.endsWith("/") && header[156] !== 0x35) {
    throw new Error("npm tarball contains an invalid tar entry.");
  }
  const size = Number.parseInt(sizeField || "0", 8);
  offset += 512 + Math.ceil(size / 512) * 512;
}

const entries = tar(["-tzf", archive], "utf8").split(/\r?\n/u).filter(Boolean);
const files = new Set(entries);
if (files.size !== entries.length) {
  throw new Error("npm tarball contains duplicate paths.");
}
const required = [
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
  "package/bin/codex-security.mjs",
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/cli.js",
  "package/_bundled_plugin/.codex-plugin/plugin.json",
];

for (const file of required) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}

const pluginFiles = new Set([
  ".app.json",
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "assets/logo.png",
  "examples/completed-scan/coverage.json",
  "examples/completed-scan/findings.json",
  "examples/completed-scan/scan-manifest.json",
  "mcp/mcp-app.html.br",
  "mcp/server.mjs",
  "mcp/server.mjs.br.part-000",
  "mcp/server.mjs.br.part-001",
  "preflight/capability-profiles.toml",
  "references/config-preflight.md",
  "references/final-report.md",
  "references/finding-detail-fields.md",
  "references/sarif-adapter.md",
  "references/scan-artifacts.md",
  "references/scan-contract.md",
  "references/security-guidance.md",
  "references/shared-hard-rules.md",
  "references/static-finding-assessment.md",
  "schemas/coverage.schema.json",
  "schemas/findings.schema.json",
  "schemas/scan-manifest.schema.json",
  "scripts/config_preflight.py",
  "scripts/deep_scan_config.py",
  "scripts/deep_scan_workbench.py",
  "scripts/filesystem_identity.py",
  "scripts/finalize_scan_contract.py",
  "scripts/finding_preview.py",
  "scripts/generate_rank_input.py",
  "scripts/rank_preview.py",
  "scripts/report_projection.py",
  "scripts/resolve_security_md.py",
  "scripts/snapshot_sqlite.py",
  "scripts/validate_report_format.py",
  "scripts/validate_scan_contract.py",
  "scripts/validate_tracking_source.py",
  "scripts/windows_scan_local_files.py",
  "scripts/workbench/__init__.py",
  "scripts/workbench/handoff.py",
  "scripts/workbench_cli.py",
  "scripts/workbench_constants.py",
  "scripts/workbench_db.py",
  "scripts/workbench_progress.py",
  "scripts/workbench_remediation.py",
  "scripts/workbench_scan_history.py",
  "scripts/workbench_scan_start.py",
  "scripts/workbench_schema.py",
  "scripts/workbench_source_excerpt.py",
  "scripts/workbench_target.py",
  "scripts/workbench_target_state.py",
  "scripts/workbench_validation.py",
  "skills/attack-path-analysis/SKILL.md",
  "skills/attack-path-analysis/agents/openai.yaml",
  "skills/attack-path-analysis/references/attack-path-facts.md",
  "skills/attack-path-analysis/references/severity-policy.md",
  "skills/deep-security-scan/SKILL.md",
  "skills/deep-security-scan/agents/openai.yaml",
  "skills/finding-discovery/SKILL.md",
  "skills/finding-discovery/agents/openai.yaml",
  "skills/fix-finding/SKILL.md",
  "skills/fix-finding/agents/openai.yaml",
  "skills/propose-security-hardening/SKILL.md",
  "skills/propose-security-hardening/agents/openai.yaml",
  "skills/propose-security-hardening/references/proposal-format.md",
  "skills/security-diff-scan/SKILL.md",
  "skills/security-diff-scan/agents/openai.yaml",
  "skills/security-scan/SKILL.md",
  "skills/security-scan/agents/openai.yaml",
  "skills/security-scan/references/repo-wide-artifacts-and-ledger.md",
  "skills/security-scan/references/repo-wide-high-impact-families.md",
  "skills/security-scan/references/repo-wide-instance-expansion.md",
  "skills/security-scan/references/repo-wide-validation-closure.md",
  "skills/security-scan/references/repository-wide-scan.md",
  "skills/security-scan/references/scan-artifacts-and-ledger.md",
  "skills/threat-model/SKILL.md",
  "skills/threat-model/agents/openai.yaml",
  "skills/threat-model/references/threat-model-guidance.md",
  "skills/track-findings/SKILL.md",
  "skills/track-findings/agents/openai.yaml",
  "skills/track-findings/references/github-security-advisories.md",
  "skills/track-findings/references/jira.md",
  "skills/triage-finding/SKILL.md",
  "skills/triage-finding/agents/openai.yaml",
  "skills/triage-finding/references/github-rest-intake.md",
  "skills/triage-finding/references/ticket-intake.md",
  "skills/triage-finding/references/triage-result-contract.md",
  "skills/validation/SKILL.md",
  "skills/validation/agents/openai.yaml",
  "skills/validation/references/validation-guidance.md",
  "skills/vulnerability-writeup/SKILL.md",
  "skills/vulnerability-writeup/agents/openai.yaml",
  "skills/vulnerability-writeup/references/report-format.md",
]);
const pluginEntries = new Set();
const pluginDirectories = new Set(["package/_bundled_plugin"]);
for (const file of pluginFiles) {
  const archivePath = `package/_bundled_plugin/${file}`;
  pluginEntries.add(archivePath);
  if (!files.has(archivePath)) {
    throw new Error(`npm tarball is missing ${archivePath}.`);
  }
  const parts = file.split("/");
  for (let index = 1; index < parts.length; index++) {
    pluginDirectories.add(
      `package/_bundled_plugin/${parts.slice(0, index).join("/")}`,
    );
  }
}

const allowedRoot = new Set([
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
  "package/bin/codex-security.mjs",
]);
const distFiles = new Set(
  [
    "api",
    "auth",
    "cli",
    "config",
    "contract",
    "errors",
    "index",
    "models",
    "result",
    "runtime",
    "targets",
    "version",
  ].flatMap((module) =>
    ["js", "js.map", "d.ts", "d.ts.map"].map(
      (extension) => `package/dist/${module}.${extension}`,
    ),
  ),
);
for (const file of distFiles) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}
const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
for (const file of files) {
  const normalized = file.endsWith("/") ? file.slice(0, -1) : file;
  const allowed = file.endsWith("/")
    ? normalized === "package" ||
      normalized === "package/bin" ||
      normalized === "package/dist" ||
      pluginDirectories.has(normalized)
    : allowedRoot.has(normalized) ||
      distFiles.has(normalized) ||
      pluginEntries.has(normalized);
  if (!allowed || unsafePath.test(file) || file.includes("\\")) {
    throw new Error(`npm tarball contains an unexpected file: ${file}.`);
  }
}

const listing = tar(["-tvzf", archive], "utf8");
if (/^[^d-]/mu.test(listing)) {
  throw new Error(
    "npm tarball contains a non-regular entry (symbolic or hard link, device, or pipe).",
  );
}
const listingLines = listing.split(/\r?\n/u).filter(Boolean);
if (
  listingLines.length !== entries.length ||
  listingLines.some(
    (line, index) => line.startsWith("-") && entries[index].endsWith("/"),
  )
) {
  throw new Error("npm tarball contains an invalid tar entry.");
}

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket\x2dfirewall\x2dregistry|openai\.(?:enterprise\.)?slack\.com|app\.slack\.com\/client|(?:app\.notion\.com\/p|notion\.so)\/openai|linear\.app\/openai|(?:github\.com[:/]|api\.github\.com\/repos\/|raw\.githubusercontent\.com\/)openai\/openai(?:\.git)?(?:[^a-z0-9_-]|$)|LicenseRef\x2dProprietary|\/Users\/|\/home\/dev-user|flow\.apps\.openai\.org|(?:^|[^a-z0-9_-])go\/[a-z0-9_-]+)/iu;
const obsoletePythonMarker =
  /(?:sdk\/python|openai_codex_security|pip install(?: --pre)? openai-codex-security|python-(?:ci|release))/iu;

const payloads = textPayloads(archiveBytes);
const compressedFiles = [...files].filter((file) => /\.br$/iu.test(file));
const compressedParts = new Map();
for (const file of files) {
  const match = /^(.*\.br)\.part-([0-9]+)$/iu.exec(file);
  if (match === null) continue;
  const [, name, part] = match;
  const parts = compressedParts.get(name) ?? [];
  parts.push({ file, part: Number(part) });
  compressedParts.set(name, parts);
}

function textPayloads(bytes) {
  const textViews = (value) => [
    value.toString("utf8"),
    new TextDecoder("utf-16be").decode(value),
    new TextDecoder("utf-16le").decode(value),
    new TextDecoder("utf-16be").decode(value.subarray(1)),
    new TextDecoder("utf-16le").decode(value.subarray(1)),
  ];
  const views = textViews(bytes);
  const unescape = (value) =>
    value
      .replace(
        /\\+u\{([0-9a-f]{1,6})\}|\\+u([0-9a-f]{4})|\\+x([0-9a-f]{2})/giu,
        (_match, codePoint, unicode, hex) =>
          String.fromCodePoint(
            Number.parseInt(codePoint ?? unicode ?? hex, 16),
          ),
      )
      .replace(/\\+([0-3][0-7]{0,2}|[4-7][0-7]?)/gu, (_match, octal) =>
        String.fromCodePoint(Number.parseInt(octal, 8)),
      )
      .replace(/(?:%[0-9a-f]{2})+/giu, (encoded) =>
        Buffer.from(encoded.replaceAll("%", ""), "hex").toString("utf8"),
      )
      .replace(/\\+\//gu, "/");
  const payloads = new Set(views);
  let pending = views;
  let candidateCount = 0;
  let decodedBytes = 0;
  const seenCandidates = new Set();
  const boundedMatches = (value, pattern) => {
    const matches = [];
    for (const [match] of value.matchAll(pattern)) {
      const candidate = match.replaceAll(/\s/gu, "");
      if (seenCandidates.has(candidate)) continue;
      seenCandidates.add(candidate);
      candidateCount += 1;
      if (candidateCount > MAX_ENCODED_CANDIDATES) {
        throw new Error("npm tarball exceeds the encoded-content budget.");
      }
      matches.push(match);
    }
    return matches;
  };
  const decodedViews = (bytes) => {
    decodedBytes += bytes.byteLength;
    if (decodedBytes > MAX_EXPANDED_ASSET_BYTES) {
      throw new Error("npm tarball exceeds the encoded-content budget.");
    }
    return textViews(bytes);
  };
  for (let depth = 0; depth < 8 && pending.length > 0; depth += 1) {
    const decoded = pending.flatMap((value) => {
      const unescaped = unescape(value).replaceAll(
        /(?:\\+r\\+n|\\+[nrt]|[\t\r\n\f\v])+/giu,
        "\n",
      );
      const decodedPercent = boundedMatches(
        value,
        /(?:%[0-9a-f]{2})+/giu,
      ).flatMap((encoded) =>
        decodedViews(Buffer.from(encoded.replaceAll("%", ""), "hex")),
      );
      const decodedBase64 = [
        ...boundedMatches(
          unescaped,
          /(?<![a-z0-9+/_-])[a-z0-9+/_-]{6,}={0,2}(?![a-z0-9+/_=-])/giu,
        ),
        ...boundedMatches(
          unescaped,
          /(?<![a-z0-9+/_-])(?:[a-z0-9+/_-]{4,}[ \t]*\r?\n[ \t]*)+[a-z0-9+/_-]{1,}={0,2}(?![a-z0-9+/_=-])/giu,
        ),
        ...boundedMatches(
          unescaped,
          /(?<![a-z0-9+/_-])[a-z0-9+/_-]{1,3}[ \t]*\r?\n[ \t]*[a-z0-9+/_-]{3,}={0,2}(?![a-z0-9+/_=-])/giu,
        ),
        ...boundedMatches(
          unescaped,
          /(?<![a-z0-9+/_-])(?:[a-z0-9+/_-]+[ \t]*\r?\n[ \t]*){2,}[a-z0-9+/_-]+={0,2}(?![a-z0-9+/_=-])/giu,
        ),
      ]
        .map((encoded) => encoded.replaceAll(/\s/gu, ""))
        .filter((encoded) => encoded.length % 4 !== 1)
        .flatMap((encoded) => decodedViews(Buffer.from(encoded, "base64")));
      return [unescaped, ...decodedPercent, ...decodedBase64];
    });
    pending = decoded.filter((value) => {
      if (payloads.has(value)) return false;
      payloads.add(value);
      return true;
    });
  }
  if (pending.length > 0) {
    throw new Error("npm tarball contains excessively nested encoded content.");
  }
  return [...payloads];
}

function brotliPayload(bytes, file) {
  const result = brotliDecompressSync(bytes, {
    info: true,
    maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
  });
  if (result.engine.bytesWritten !== bytes.length) {
    throw new Error(`npm tarball contains trailing Brotli data: ${file}.`);
  }
  return result.buffer;
}

for (const file of compressedFiles) {
  payloads.push(
    ...textPayloads(brotliPayload(tar(["-xOf", archive, file]), file)),
  );
}
for (const parts of compressedParts.values()) {
  parts.sort((left, right) => left.part - right.part);
  const bytes = Buffer.concat(
    parts.map(({ file }) => tar(["-xOf", archive, file])),
  );
  payloads.push(...textPayloads(brotliPayload(bytes, parts[0].file)));
}
for (const file of files) {
  if (/\.png$/iu.test(file)) {
    const digest = createHash("sha256")
      .update(tar(["-xOf", archive, file]))
      .digest("hex");
    if (digest !== PUBLIC_LOGO_SHA256) {
      throw new Error(`npm tarball contains an unexpected PNG asset: ${file}.`);
    }
  }
}

for (const contents of payloads) {
  if (internalMarker.test(contents)) {
    throw new Error("npm tarball contains an internal reference.");
  }
  if (obsoletePythonMarker.test(contents)) {
    throw new Error("npm tarball contains an obsolete Python SDK reference.");
  }
}

console.log(`Validated ${archive}: ${files.size} entries.`);
