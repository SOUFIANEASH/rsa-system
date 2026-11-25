const R = require("./rsa.js");
const assert = require("assert");

const k = R.generateKeys(1009n, 1013n);
assert.strictEqual(k.n, 1009n * 1013n);
assert.strictEqual((k.e * k.d) % k.phi, 1n);

const msg = "Hello, RSA! Vilnius ąčęė 😀";
const text = R.serialize(k.n, k.e, R.encrypt(msg, k.n, k.e));
const f = R.parse(text);
const atk = R.breakPublicKey(f.n, f.e);
assert.strictEqual(atk.d, k.d);
assert.strictEqual(R.decrypt(f.cipher, f.n, atk.d), msg);

const [g, x, y] = R.extGcd(240n, 46n);
assert.strictEqual(g, 2n); assert.strictEqual(240n * x + 46n * y, 2n);
assert.throws(() => R.generateKeys(10n, 13n));
assert.throws(() => R.encrypt("é", 143n, 7n));
console.log("all tests passed");
