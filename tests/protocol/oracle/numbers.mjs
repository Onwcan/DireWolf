// Oracle for ECMAScript Number serialisation (RFC 8785 section 3.2.2.3).
//
// Regenerates tests/protocol/vectors/numbers.json using V8 itself as the
// reference implementation, as RFC 8785 Appendix B suggests ("running V8 as a
// live reference together with a program generating a substantial amount of
// random IEEE 754 values").
//
// This is a test-data generator, not part of the build. It needs Node.js and is
// never run in CI: the committed output is the test oracle, and both the Rust
// and Python suites are checked against it.
//
//     node tests/protocol/oracle/numbers.mjs > tests/protocol/vectors/numbers.json

let state = 0x9e3779b97f4a7c15n; // fixed seed: output is deterministic
const MASK = (1n << 64n) - 1n;
function next() {
  // xorshift64*
  state ^= state >> 12n; state ^= (state << 25n) & MASK; state ^= state >> 27n;
  return (state * 0x2545f4914f6cdd1dn) & MASK;
}

const buf = new DataView(new ArrayBuffer(8));
const hex = (x) => { buf.setFloat64(0, x); return buf.getBigUint64(0).toString(16).padStart(16, "0"); };
const out = new Map();
const add = (x) => { if (Number.isFinite(x)) out.set(hex(x), JSON.stringify(x)); };

// Uniform random bit patterns: every exponent, subnormals included.
for (let i = 0; i < 3000; i++) { buf.setBigUint64(0, next()); add(buf.getFloat64(0)); }
// Human-scale decimals, where shortest-digit ties actually occur.
for (let i = 0; i < 2000; i++) {
  const mant = Number(next() % 10000000000000000n);
  const scale = Number(next() % 40n) - 20;
  add(mant * Math.pow(10, scale)); add(-mant / Math.pow(10, Number(next() % 17n)));
}
// Boundaries of the layout rules and of the safe-integer range.
for (let e = -330; e <= 310; e++) { add(Math.pow(10, e)); add(5 * Math.pow(10, e)); add(Math.pow(2, e)); }
for (const x of [1e21, 1e21 - 65536, 999999999999999900000, 1e-6, 1e-7, 0.000001234, 2 ** 53, 2 ** 53 - 1,
                 2 ** 53 + 2, -(2 ** 53), Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0.1, 0.2,
                 0.30000000000000004, 1424953923781206.25, 123456789012345680000, 4.35, 0.5, 1.5, 2.5]) add(x);

const rows = [...out.entries()].sort().map(([bits, es]) => `  {"bits":"${bits}","es":${JSON.stringify(es)}}`);
process.stdout.write(`{\n "generator": "tests/protocol/oracle/numbers.mjs",\n "reference": "V8 ${process.versions.v8} (Node ${process.version}) JSON.stringify",\n "count": ${rows.length},\n "vectors": [\n${rows.join(",\n")}\n ]\n}\n`);
