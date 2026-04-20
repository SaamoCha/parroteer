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
 * Noise removed:
 *   - GREASE specific values → replaced with GREASE_SENTINEL (-1)
 *   - handshake_duration, is_session_resumption, using_psk
 *   - selected_protocol, selected_curve_group, selected_cipher_suite
 *   - session_ticket_supported, support_secure_renegotiation
 *
 * Structural fields kept (from tls object, NOT ja3n — ja3n strips GREASE
 * and sorts extensions, losing structural info):
 *   - Cipher suites (order + GREASE positions preserved)
 *   - Extensions (original order + GREASE positions preserved)
 *   - Supported groups / curves (order + GREASE positions preserved)
 *   - Supported versions (GREASE positions preserved)
 *   - Key share groups (GREASE positions preserved)
 *   - Signature algorithms
 *   - ALPN protocols
 *   - EC point formats
 *   - PSK key exchange mode
 *   - Cert compression algorithms
 *   - Early data support
 */

// Sentinel value representing a GREASE slot in normalized output.
// The specific GREASE value (0x0A0A..0xFAFA) is noise; the position is structural.
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

// Replace GREASE values with sentinel, keep everything else
function replaceGrease(values: number[]): number[] {
  return values.map((v) => (isGrease(v) ? GREASE_SENTINEL : v));
}

// Parse extension ID from reflector string like "server_name (0) (IANA)"
// or "GREASE (0xBABA)"
function parseExtensionId(ext: string): number {
  if (ext.startsWith("GREASE")) return GREASE_SENTINEL;
  const match = ext.match(/\((\d+)\)/);
  return match ? Number(match[1]) : -2; // -2 for unparseable
}

// Chrome randomizes extension order each connection, but GREASE slots at
// the boundaries are structural. Preserve leading/trailing GREASE sentinels,
// sort the non-GREASE interior so the result is stable across captures.
function stabilizeExtensionOrder(extIds: number[]): number[] {
  // Peel off leading GREASE sentinels
  const leading: number[] = [];
  let i = 0;
  while (i < extIds.length && extIds[i] === GREASE_SENTINEL) {
    leading.push(GREASE_SENTINEL);
    i++;
  }

  // Peel off trailing GREASE sentinels
  const trailing: number[] = [];
  let j = extIds.length - 1;
  while (j >= i && extIds[j] === GREASE_SENTINEL) {
    trailing.push(GREASE_SENTINEL);
    j--;
  }

  // Sort the middle (non-GREASE) portion
  const middle = extIds.slice(i, j + 1).sort((a, b) => a - b);

  return [...leading, ...middle, ...trailing];
}

// Parse cipher: "0x3A3A" is GREASE, named ciphers need ja3 mapping
// We use the ja3 field (raw, unsorted) which has numeric IDs in original order
function parseCiphersFromJa3(ja3: string): number[] {
  const parts = ja3.split(",");
  if (parts.length < 2) return [];
  return replaceGrease(
    parts[1].split("-").map(Number).filter((n) => !isNaN(n)),
  );
}

// Parse supported groups from ja3 (4th segment, original order)
function parseSupportedGroupsFromJa3(ja3: string): number[] {
  const parts = ja3.split(",");
  if (parts.length < 4) return [];
  return replaceGrease(
    parts[3].split("-").map(Number).filter((n) => !isNaN(n)),
  );
}

export function normalize(raw: Record<string, unknown>): NormalizedFingerprint {
  const tls = raw.tls as Record<string, unknown>;
  const ja3 = raw.ja3 as string; // raw ja3 preserves original order

  // Cipher suites from ja3 (original order, GREASE → sentinel)
  const cipher_suites = parseCiphersFromJa3(ja3);

  // Extensions from tls object (GREASE → sentinel).
  // Chrome randomizes extension order each connection, but GREASE positions
  // (first and/or last) are structural. Strategy: extract GREASE bookends,
  // sort the non-GREASE middle, then re-attach bookends.
  const rawExtensions = (tls.extensions as string[]) ?? [];
  const allExtIds = rawExtensions.map(parseExtensionId);
  const extensions = stabilizeExtensionOrder(allExtIds);

  // Supported groups from ja3 (original order, GREASE → sentinel)
  const supported_groups = parseSupportedGroupsFromJa3(ja3);

  // Supported versions from tls object (GREASE → sentinel)
  const supported_versions = replaceGrease(
    (tls.supported_tls_versions as number[]) ?? [],
  );

  // Key share groups (GREASE → sentinel)
  const key_share_groups = replaceGrease(
    (tls.key_shares as number[]) ?? [],
  );

  // Fields that are already stable
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
