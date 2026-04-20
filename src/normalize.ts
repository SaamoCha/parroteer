/**
 * normalize.ts — strip per-run noise from raw reflector JSON,
 * producing a stable structural fingerprint.
 *
 * GREASE handling: specific values (0x0A0A..0xFAFA) are replaced with
 * a sentinel (-1) to preserve their COUNT and POSITION while removing
 * the random value.
 *
 * Supports two response formats:
 *   1. browserleaks.com root (/) — full tls object with {id, name, data}
 *      extension details including supported_versions, key_share, sig_algs
 *   2. Flat ja3_text-only responses — fallback parsing from ja3_text + ja4_r
 */

export const GREASE_SENTINEL = -1;

export interface NormalizedFingerprint {
  cipher_suites: number[];
  extensions: number[];
  supported_groups: number[];
  supported_versions: number[];
  key_share_groups: number[];
  signature_algorithms: number[];
  alpn: string[];
  ec_point_formats: string[];
  psk_key_exchange_mode: string;
  cert_compression_algorithms: string;
  early_data: boolean;
}

// GREASE values: 0x0A0A, 0x1A1A, ..., 0xFAFA
function isGrease(value: number): boolean {
  return value >= 0x0a0a && (value & 0x0f0f) === 0x0a0a;
}

function replaceGrease(values: number[]): number[] {
  return values.map((v) => (isGrease(v) ? GREASE_SENTINEL : v));
}

// Chrome randomizes extension order each connection, but GREASE slots at
// the boundaries are structural. Preserve leading/trailing GREASE sentinels,
// sort the non-GREASE interior so the result is stable across captures.
function stabilizeExtensionOrder(extIds: number[]): number[] {
  let i = 0;
  const leading: number[] = [];
  while (i < extIds.length && extIds[i] === GREASE_SENTINEL) {
    leading.push(GREASE_SENTINEL);
    i++;
  }

  let j = extIds.length - 1;
  const trailing: number[] = [];
  while (j >= i && extIds[j] === GREASE_SENTINEL) {
    trailing.push(GREASE_SENTINEL);
    j--;
  }

  const middle = extIds.slice(i, j + 1).sort((a, b) => a - b);
  return [...leading, ...middle, ...trailing];
}

// ─── ja3/ja4 fallback parsers ───────────────────────────────────────────

function parseJa3Segment(ja3: string, index: number): number[] {
  const parts = ja3.split(",");
  if (parts.length <= index || !parts[index]) return [];
  return replaceGrease(
    parts[index].split("-").map(Number).filter((n) => !isNaN(n)),
  );
}

function parseSigAlgsFromJa4r(ja4r: string): number[] {
  const segments = ja4r.split("_");
  if (segments.length < 4 || !segments[3]) return [];
  return segments[3]
    .split(",")
    .map((hex) => parseInt(hex, 16))
    .filter((n) => !isNaN(n));
}

function parseAlpnFromJa4(ja4: string): string[] {
  const prefix = ja4.split("_")[0] ?? "";
  const alpnCode = prefix.slice(-2);
  if (alpnCode === "h2") return ["h2", "http/1.1"];
  if (alpnCode === "h1") return ["http/1.1"];
  return [];
}

// ─── browserleaks root format parsers ───────────────────────────────────
// tls.cipher_suites: [{id, name}, ...]
// tls.extensions:    [{id, name, data?}, ...]
//   - ext 10 (supported_groups): data.named_group_list [{id, name}, ...]
//   - ext 13 (signature_algorithms): data.supported_signature_algorithms [{id, name}, ...]
//   - ext 16 (alpn): data.protocol_name_list [{protocol}, ...]
//   - ext 43 (supported_versions): data.versions [{id, name}, ...]
//   - ext 51 (key_share): data.client_shares [{group: {id, name}}, ...]
//   - ext 11 (ec_point_formats): data.ec_point_format_list [{id, name}, ...]
//   - ext 45 (psk_key_exchange_modes): data.ke_modes [{id, name}, ...]

interface IdName { id: number; name: string }
interface ExtObj { id: number; name: string; data?: Record<string, unknown> }

function findExt(exts: ExtObj[], id: number): ExtObj | undefined {
  return exts.find((e) => e.id === id);
}

function extractIdList(arr: unknown): number[] {
  if (!Array.isArray(arr)) return [];
  return (arr as IdName[]).map((item) => item.id).filter((n) => typeof n === "number");
}

function parseBrowserleaksTls(tls: Record<string, unknown>): {
  cipher_suites: number[];
  extensions: number[];
  supported_groups: number[];
  supported_versions: number[];
  key_share_groups: number[];
  signature_algorithms: number[];
  alpn: string[];
  ec_point_formats: string[];
  psk_key_exchange_mode: string;
} {
  const rawCiphers = (tls.cipher_suites as IdName[]) ?? [];
  const cipher_suites = replaceGrease(rawCiphers.map((c) => c.id));

  const rawExts = (tls.extensions as ExtObj[]) ?? [];
  const extIds = replaceGrease(rawExts.map((e) => e.id));
  const extensions = stabilizeExtensionOrder(extIds);

  // supported_groups from ext 10
  const groupsExt = findExt(rawExts, 10);
  const supported_groups = groupsExt?.data
    ? replaceGrease(extractIdList(groupsExt.data.named_group_list))
    : [];

  // supported_versions from ext 43
  const versionsExt = findExt(rawExts, 43);
  const supported_versions = versionsExt?.data
    ? replaceGrease(extractIdList(versionsExt.data.versions))
    : [];

  // key_share from ext 51
  const keyShareExt = findExt(rawExts, 51);
  let key_share_groups: number[] = [];
  if (keyShareExt?.data && Array.isArray(keyShareExt.data.client_shares)) {
    key_share_groups = replaceGrease(
      (keyShareExt.data.client_shares as { group: IdName }[])
        .map((s) => s.group?.id)
        .filter((n): n is number => typeof n === "number"),
    );
  }

  // signature_algorithms from ext 13
  const sigAlgExt = findExt(rawExts, 13);
  const signature_algorithms = sigAlgExt?.data
    ? extractIdList(sigAlgExt.data.supported_signature_algorithms)
    : [];

  // ALPN from ext 16 — protocol_name_list is an array of strings
  const alpnExt = findExt(rawExts, 16);
  let alpn: string[] = [];
  if (alpnExt?.data && Array.isArray(alpnExt.data.protocol_name_list)) {
    alpn = (alpnExt.data.protocol_name_list as string[]).filter(Boolean);
  }

  // ec_point_formats from ext 11
  const pointsExt = findExt(rawExts, 11);
  const ec_point_formats = pointsExt?.data
    ? extractIdList(pointsExt.data.ec_point_format_list).map(String)
    : [];

  // psk_key_exchange_modes from ext 45
  const pskExt = findExt(rawExts, 45);
  let psk_key_exchange_mode = "";
  if (pskExt?.data && Array.isArray(pskExt.data.ke_modes)) {
    psk_key_exchange_mode = (pskExt.data.ke_modes as IdName[])
      .map((m) => m.id)
      .join(",");
  }

  return {
    cipher_suites,
    extensions,
    supported_groups,
    supported_versions,
    key_share_groups,
    signature_algorithms,
    alpn,
    ec_point_formats,
    psk_key_exchange_mode,
  };
}

// ─── Main normalize function ────────────────────────────────────────────

export function normalize(raw: Record<string, unknown>): NormalizedFingerprint {
  const tls = (raw.tls ?? null) as Record<string, unknown> | null;
  const ja3 = (raw.ja3_text ?? raw.ja3 ?? "") as string;
  const ja4 = (raw.ja4 ?? "") as string;
  const ja4r = (raw.ja4_r ?? raw.ja4_ro ?? "") as string;

  // If tls object has extensions array (browserleaks root format), use full parser
  if (tls && Array.isArray(tls.extensions) && tls.extensions.length > 0) {
    const parsed = parseBrowserleaksTls(tls);
    return {
      ...parsed,
      cert_compression_algorithms: "",
      early_data: false,
    };
  }

  // Fallback: parse from ja3_text + ja4_r (flat format or /json endpoint)
  return {
    cipher_suites: parseJa3Segment(ja3, 1),
    extensions: parseJa3Segment(ja3, 2).sort((a, b) => a - b),
    supported_groups: parseJa3Segment(ja3, 3),
    supported_versions: [],
    key_share_groups: [],
    signature_algorithms: parseSigAlgsFromJa4r(ja4r),
    alpn: parseAlpnFromJa4(ja4),
    ec_point_formats: parseJa3Segment(ja3, 4).map(String),
    psk_key_exchange_mode: "",
    cert_compression_algorithms: "",
    early_data: false,
  };
}

// CLI: npx tsx src/normalize.ts <raw-json-file>
if (process.argv[1]?.endsWith("normalize.ts")) {
  const fs = require("fs") as typeof import("fs");
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: npx tsx src/normalize.ts <raw-capture.json>");
    process.exit(1);
  }

  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  const result = normalize(raw);
  console.log(JSON.stringify(result, null, 2));
}
