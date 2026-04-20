import { GREASE_SENTINEL, type NormalizedFingerprint } from "./normalize.js";

export interface FieldDiff {
  field: string;
  baseline: string;
  current: string;
  added: string[];
  removed: string[];
}

function formatValue(v: string | number): string {
  return Number(v) === GREASE_SENTINEL ? "GREASE" : String(v);
}

export interface DiffResult {
  hasChanges: boolean;
  diffs: FieldDiff[];
}

function diffArrayField(
  field: string,
  baseline: (string | number)[],
  current: (string | number)[],
): FieldDiff | null {
  const baseStr = baseline.map(formatValue).join("-");
  const curStr = current.map(formatValue).join("-");
  if (baseStr === curStr) return null;

  const baseSet = new Set(baseline.map((v) => formatValue(v)));
  const curSet = new Set(current.map((v) => formatValue(v)));

  return {
    field,
    baseline: baseStr,
    current: curStr,
    added: current.map((v) => formatValue(v)).filter((v) => !baseSet.has(v)),
    removed: baseline.map((v) => formatValue(v)).filter((v) => !curSet.has(v)),
  };
}

function diffScalarField(
  field: string,
  baseline: string | boolean,
  current: string | boolean,
): FieldDiff | null {
  if (String(baseline) === String(current)) return null;
  return {
    field,
    baseline: String(baseline),
    current: String(current),
    added: [],
    removed: [],
  };
}

export function diffFingerprints(
  baseline: NormalizedFingerprint,
  current: NormalizedFingerprint,
): DiffResult {
  const diffs: FieldDiff[] = [];

  const arrayFields: { field: string; key: keyof NormalizedFingerprint }[] = [
    { field: "cipher_suites", key: "cipher_suites" },
    { field: "extensions", key: "extensions" },
    { field: "supported_groups", key: "supported_groups" },
    { field: "supported_versions", key: "supported_versions" },
    { field: "key_share_groups", key: "key_share_groups" },
    { field: "signature_algorithms", key: "signature_algorithms" },
    { field: "alpn", key: "alpn" },
    { field: "ec_point_formats", key: "ec_point_formats" },
  ];

  for (const { field, key } of arrayFields) {
    const d = diffArrayField(
      field,
      baseline[key] as (string | number)[],
      current[key] as (string | number)[],
    );
    if (d) diffs.push(d);
  }

  const scalarFields: { field: string; key: keyof NormalizedFingerprint }[] = [
    { field: "psk_key_exchange_mode", key: "psk_key_exchange_mode" },
    { field: "cert_compression_algorithms", key: "cert_compression_algorithms" },
    { field: "early_data", key: "early_data" },
  ];

  for (const { field, key } of scalarFields) {
    const d = diffScalarField(
      field,
      baseline[key] as string | boolean,
      current[key] as string | boolean,
    );
    if (d) diffs.push(d);
  }

  return { hasChanges: diffs.length > 0, diffs };
}

export function formatReport(
  browserName: string,
  baseline: NormalizedFingerprint,
  current: NormalizedFingerprint,
  diffResult: DiffResult,
): string {
  if (!diffResult.hasChanges) {
    return `### ${browserName}\nNo TLS fingerprint changes detected.\n`;
  }

  let report = `### ${browserName}\n\n`;

  for (const d of diffResult.diffs) {
    report += `**${d.field}**\n`;
    if (d.added.length) report += `- Added: ${d.added.join(", ")}\n`;
    if (d.removed.length) report += `- Removed: ${d.removed.join(", ")}\n`;
    if (!d.added.length && !d.removed.length) {
      report += `- Changed: \`${d.baseline}\` → \`${d.current}\`\n`;
    }
    report += "\n";
  }

  return report;
}

export function formatUtlsComparison(
  label: string,
  realFp: NormalizedFingerprint,
  utlsFp: NormalizedFingerprint,
  diffResult: DiffResult,
): string {
  if (!diffResult.hasChanges) {
    return `### ${label}\nutls parrot matches real browser. No differences.\n`;
  }

  let report = `### ${label}\n\n`;

  for (const d of diffResult.diffs) {
    report += `**${d.field}**\n`;
    if (d.added.length) report += `- In real browser but not utls: ${d.added.join(", ")}\n`;
    if (d.removed.length) report += `- In utls but not real browser: ${d.removed.join(", ")}\n`;
    if (!d.added.length && !d.removed.length) {
      report += `- Differ: real=\`${d.current}\` utls=\`${d.baseline}\`\n`;
    }
    report += "\n";
  }

  return report;
}
