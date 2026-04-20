/**
 * normalize.ts — strip per-run noise from raw reflector JSON,
 * producing a stable structural fingerprint.
 *
 * GREASE handling: specific values (0x0A0A..0xFAFA) are replaced with
 * a sentinel (-1) to preserve their COUNT and POSITION while removing
 * the random value. This matters because censors can detect:
 *   - whether GREASE is present at all
 *   - how many GREASE values appear in each field
 *   - where they appear (e.g. Chrome wraps extensions with GREASE first+last)
 *
 * Parsing strategy: extract all fields from the `tls` sub-object (always
 * present in reflector responses). Does NOT depend on `ja3`, `ja3n`, or
 * `scrapfly_fp` — those may be absent for non-browser TLS clients (e.g.
 * utls-capture).
 */

// Sentinel value representing a GREASE slot in normalized output.
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

// Standard TLS cipher suite name → numeric ID mapping.
// Only includes suites commonly seen in modern browsers.
const CIPHER_NAME_TO_ID: Record<string, number> = {
  TLS_AES_128_GCM_SHA256: 0x1301,
  TLS_AES_256_GCM_SHA384: 0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca8,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xc013,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: 0xc014,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 0xc009,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: 0xc00a,
  TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009c,
  TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009d,
  TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,
  TLS_RSA_WITH_AES_256_CBC_SHA: 0x0035,
  TLS_RSA_WITH_AES_128_CBC_SHA256: 0x003c,
  TLS_RSA_WITH_AES_256_CBC_SHA256: 0x003d,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA: 0x000a,
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: 0xc012,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: 0xc024,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: 0xc023,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: 0xc027,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: 0xc028,
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: 0x009e,
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: 0x009f,
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xccaa,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA: 0x0033,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA: 0x0039,
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV: 0x00ff,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ALT: 0xc02b,
};

// Parse cipher name to numeric ID.
// Handles: "0xNNNN" (hex, usually GREASE), named suites, unknown → skip.
function parseCipherId(name: string): number | null {
  // Hex format like "0x3A3A" — GREASE or other raw values
  if (name.startsWith("0x")) {
    const val = parseInt(name, 16);
    return isNaN(val) ? null : val;
  }
  return CIPHER_NAME_TO_ID[name] ?? null;
}

// Parse numeric ID from parenthesized string like "X25519 (29)" or "TLS_GREASE (0x5A5A)"
function parseParenId(s: string): number | null {
  if (s.includes("GREASE") || s.includes("TLS_GREASE")) {
    // Extract hex GREASE value
    const hex = s.match(/0x([0-9A-Fa-f]+)/);
    if (hex) return parseInt(hex[1], 16);
    return null;
  }
  const match = s.match(/\((\d+)\)/);
  return match ? Number(match[1]) : null;
}

// Parse extension ID from reflector string like "server_name (0) (IANA)"
// or "GREASE (0xBABA)"
function parseExtensionId(ext: string): number {
  if (ext.startsWith("GREASE")) return GREASE_SENTINEL;
  const match = ext.match(/\((\d+)\)/);
  return match ? Number(match[1]) : -2;
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

export function normalize(raw: Record<string, unknown>): NormalizedFingerprint {
  const tls = raw.tls as Record<string, unknown>;

  // --- Cipher suites from tls.ciphers ---
  const rawCiphers = (tls.ciphers as string[]) ?? [];
  const cipher_suites = replaceGrease(
    rawCiphers.map(parseCipherId).filter((v): v is number => v !== null),
  );

  // --- Extensions from tls.extensions ---
  const rawExtensions = (tls.extensions as string[]) ?? [];
  const allExtIds = rawExtensions.map(parseExtensionId);
  const extensions = stabilizeExtensionOrder(allExtIds);

  // --- Supported groups from tls.curves ---
  const rawCurves = (tls.curves as string[]) ?? [];
  const supported_groups = replaceGrease(
    rawCurves.map(parseParenId).filter((v): v is number => v !== null),
  );

  // --- Supported versions (GREASE → sentinel) ---
  const supported_versions = replaceGrease(
    (tls.supported_tls_versions as number[]) ?? [],
  );

  // --- Key share groups (GREASE → sentinel) ---
  const key_share_groups = replaceGrease(
    (tls.key_shares as number[]) ?? [],
  );

  // --- Stable scalar fields ---
  const signature_algorithms = (tls.signature_algorithms as number[]) ?? [];
  const alpn = (tls.protocols as string[]) ?? [];
  const ec_point_formats = (tls.points as string[]) ?? [];
  const psk_key_exchange_mode = (tls.psk_key_exchange_mode as string) ?? "";
  const cert_compression_algorithms =
    (tls.cert_compression_algorithms as string) ?? "";
  const early_data = (tls.early_data as boolean) ?? false;

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
    cert_compression_algorithms,
    early_data,
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
