import { GREASE_SENTINEL, type NormalizedQuicFingerprint } from "./normalize-quic.js";

export interface QuicFieldDiff {
  field: string;
  baseline: string;
  current: string;
  added: string[];
  removed: string[];
}

export interface QuicDiffResult {
  hasChanges: boolean;
  diffs: QuicFieldDiff[];
}

const ARRAY_FIELDS = [
  "frame_types",
  "cipher_suites",
  "extensions",
  "supported_groups",
  "key_share_groups",
  "signature_algorithms",
  "supported_versions",
  "alpn",
  "cert_compression_algorithms",
  "psk_key_exchange_modes",
  "transport_parameter_ids",
] as const;

function fmt(v: string | number): string {
  return Number(v) === GREASE_SENTINEL ? "GREASE" : String(v);
}

function diffArray(field: string, a: (string | number)[], b: (string | number)[]): QuicFieldDiff | null {
  const as = a.map(fmt), bs = b.map(fmt);
  if (as.join("-") === bs.join("-")) return null;
  return {
    field,
    baseline: as.join("-"),
    current: bs.join("-"),
    added: bs.filter((v) => !as.includes(v)),
    removed: as.filter((v) => !bs.includes(v)),
  };
}

export function diffQuic(baseline: NormalizedQuicFingerprint, current: NormalizedQuicFingerprint): QuicDiffResult {
  const diffs: QuicFieldDiff[] = [];
  if (baseline.packet_count !== current.packet_count) {
    diffs.push({ field: "packet_count", baseline: String(baseline.packet_count), current: String(current.packet_count), added: [], removed: [] });
  }
  for (const f of ARRAY_FIELDS) {
    const d = diffArray(f, baseline[f] as (string | number)[], current[f] as (string | number)[]);
    if (d) diffs.push(d);
  }
  const keys = [...new Set([...Object.keys(baseline.transport_parameter_values), ...Object.keys(current.transport_parameter_values)])].sort();
  for (const k of keys) {
    const a = baseline.transport_parameter_values[k] ?? "", b = current.transport_parameter_values[k] ?? "";
    if (a !== b) diffs.push({ field: `tp.${k}`, baseline: a || "(absent)", current: b || "(absent)", added: [], removed: [] });
  }
  return { hasChanges: diffs.length > 0, diffs };
}

function body(diffs: QuicFieldDiff[], addedLabel: string, removedLabel: string, changed: (d: QuicFieldDiff) => string): string {
  let out = "";
  for (const d of diffs) {
    out += `**${d.field}**\n`;
    if (d.added.length) out += `- ${addedLabel}: ${d.added.join(", ")}\n`;
    if (d.removed.length) out += `- ${removedLabel}: ${d.removed.join(", ")}\n`;
    if (!d.added.length && !d.removed.length) out += `- ${changed(d)}\n`;
    out += "\n";
  }
  return out;
}

export function formatQuicReport(name: string, diff: QuicDiffResult): string {
  if (!diff.hasChanges) return `### ${name} (QUIC)\nNo QUIC fingerprint changes detected.\n`;
  return `### ${name} (QUIC)\n\n` + body(diff.diffs, "Added", "Removed", (d) => `Changed: \`${d.baseline}\` → \`${d.current}\``);
}

export function formatUquicComparison(label: string, real: NormalizedQuicFingerprint, diff: QuicDiffResult): string {
  const info =
    `_DCID lengths ${JSON.stringify(real.info.dcid_lengths)}, first packet number 0x${real.info.first_packet_number || "?"} ` +
    `and google_initial_rtt (0x3127) are not compared; Chrome only sends 0x3127 once it has an RTT estimate for the server._\n\n`;
  if (!diff.hasChanges) return `### ${label}\n${info}uquic parrot matches the real browser.\n`;
  return `### ${label}\n\n${info}` + body(diff.diffs, "In real browser but not uquic", "In uquic but not real browser", (d) => `Differ: real=\`${d.current}\` uquic=\`${d.baseline}\``);
}
