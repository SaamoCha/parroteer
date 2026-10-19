/**
 * normalize-quic.ts — turn a clienthellod QUIC fingerprint into a stable,
 * comparable structure.
 *
 * Input is the JSON a clienthellod reflector (or cmd/uquic-capture) returns:
 * { ClientInitials: { packets, client_hello, transport_parameters, ... } }.
 *
 * Left out on purpose, because they change between connections:
 *   - destination connection ID length and initial packet number (Firefox
 *     randomizes both); they are kept under `info` for the report only
 *   - the order of frames inside each Initial packet (Chrome splits CRYPTO
 *     differently every time); only the set of frame types is compared
 *   - google_initial_rtt (0x3127), which Chrome only sends when it already has
 *     an RTT estimate for the server
 *   - the order of extensions (Chrome permutes them); the sorted list is used
 */

export const GREASE_SENTINEL = -1;

const STATEFUL_TRANSPORT_PARAMETERS = new Set([0x3127]);

const FRAME_NAMES: Record<number, string> = { 0: "PADDING", 1: "PING", 2: "ACK", 6: "CRYPTO" };

// Transport parameters whose values are stable for a given client build.
const VALUE_FIELDS = [
  "max_idle_timeout",
  "max_udp_payload_size",
  "initial_max_data",
  "initial_max_stream_data_bidi_local",
  "initial_max_stream_data_bidi_remote",
  "initial_max_stream_data_uni",
  "initial_max_streams_bidi",
  "initial_max_streams_uni",
  "ack_delay_exponent",
  "max_ack_delay",
  "active_connection_id_limit",
  "max_datagram_frame_size",
] as const;

export interface NormalizedQuicFingerprint {
  packet_count: number;
  frame_types: string[];
  cipher_suites: number[];
  extensions: number[];
  supported_groups: number[];
  key_share_groups: number[];
  signature_algorithms: number[];
  supported_versions: number[];
  alpn: string[];
  cert_compression_algorithms: number[];
  psk_key_exchange_modes: number[];
  transport_parameter_ids: number[];
  transport_parameter_values: Record<string, string>;
  info: { dcid_lengths: number[]; first_packet_number: string };
}

function isGrease(v: number): boolean {
  return v >= 0x0a0a && (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff);
}

function nums(v: unknown): number[] {
  return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number").map((x) => (isGrease(x) ? GREASE_SENTINEL : x)) : [];
}

function hex(v: unknown): string {
  return Array.isArray(v) ? v.map((b) => Number(b).toString(16).padStart(2, "0")).join("") : "";
}

// clienthellod returns transport parameter values as big-endian bytes.
function decimal(v: unknown): string {
  return Array.isArray(v) ? v.reduce((n: bigint, b) => (n << 8n) | BigInt(Number(b)), 0n).toString() : "";
}

export function normalizeQuic(raw: Record<string, unknown>): NormalizedQuicFingerprint {
  const ci = (raw.ClientInitials ?? {}) as Record<string, any>;
  const packets = (ci.packets ?? []) as { header?: Record<string, any>; frames?: number[] }[];
  const ch = (ci.client_hello ?? {}) as Record<string, unknown>;
  const tp = (ci.transport_parameters ?? {}) as Record<string, unknown>;

  const frameTypes = new Set<string>();
  for (const p of packets) for (const f of p.frames ?? []) frameTypes.add(FRAME_NAMES[f] ?? `0x${f.toString(16)}`);

  const values: Record<string, string> = {};
  for (const field of VALUE_FIELDS) if (tp[field] !== undefined) values[field] = decimal(tp[field]);

  return {
    packet_count: packets.length,
    frame_types: [...frameTypes].sort(),
    cipher_suites: nums(ch.cipher_suites),
    extensions: nums(ch.extensions_normalized ?? ch.extensions).sort((a, b) => a - b),
    supported_groups: nums(ch.supported_groups),
    key_share_groups: nums(ch.key_share),
    signature_algorithms: nums(ch.signature_algorithms),
    supported_versions: nums(ch.supported_versions),
    alpn: Array.isArray(ch.alpn) ? (ch.alpn as string[]) : [],
    cert_compression_algorithms: nums(ch.compress_certificate),
    psk_key_exchange_modes: nums(ch.psk_key_exchange_modes),
    transport_parameter_ids: nums(tp.tpids).filter((id) => !STATEFUL_TRANSPORT_PARAMETERS.has(id)).sort((a, b) => a - b),
    transport_parameter_values: values,
    info: {
      dcid_lengths: packets.map((p) => Number(p.header?.dest_conn_id_len ?? 0)),
      first_packet_number: hex(packets[0]?.header?.packet_number),
    },
  };
}

// CLI: npx tsx src/normalize-quic.ts <capture.json>
if (process.argv[1]?.endsWith("normalize-quic.ts")) {
  const fs = require("fs") as typeof import("fs");
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: npx tsx src/normalize-quic.ts <quic-capture.json>");
    process.exit(1);
  }
  console.log(JSON.stringify(normalizeQuic(JSON.parse(fs.readFileSync(file, "utf8"))), null, 2));
}
