// Oracle for RFC 8785 canonical form and DWKP framing.
//
// Fills `canonical` (and, for DWKP, `frame_hex`) in tests/protocol/vectors/valid.json
// from each vector's `input`, using the ECMAScript reference behaviour RFC 8785
// is defined against: JSON.stringify for primitives, object keys sorted by
// UTF-16 code units (Array.prototype.sort's default order).
//
// The point is independence. The expected bytes are not produced by the Rust
// crate or the Python bindings, both of which are tested against them.
//
// Test-data tooling, not part of the build. Needs Node.js; never run in CI.
//
//     node tests/protocol/oracle/fill_canonical.mjs

import { readFileSync, writeFileSync } from "node:fs";

const path = new URL("../vectors/valid.json", import.meta.url);
const doc = JSON.parse(readFileSync(path, "utf8"));

function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

for (const vector of doc.vectors) {
  if (vector.family === "event") continue; // records are re-emitted verbatim, not canonicalised
  const canonical = canonicalize(JSON.parse(vector.input));
  vector.canonical = canonical;
  if (vector.family === "dwkp") {
    const body = Buffer.from(canonical, "utf8");
    const header = Buffer.alloc(5);
    header.writeUInt32BE(body.length, 0);
    header.writeUInt8(0x01, 4);
    vector.frame_hex = Buffer.concat([header, body]).toString("hex");
  }
}

// Match the Python writer: one-space indent, ASCII-only output (non-ASCII
// UTF-16 code units escaped), trailing newline.
const BACKSLASH = String.fromCharCode(92);
const nonAscii = new RegExp("[" + String.fromCharCode(0x7f) + "-" + String.fromCharCode(0xffff) + "]", "g");
const ascii = (s) => s.replace(nonAscii, (c) => BACKSLASH + "u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
writeFileSync(path, ascii(JSON.stringify(doc, null, 1)) + "\n");
