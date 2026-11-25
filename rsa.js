// RSA from scratch (Level B) - no cryptography library. Uses BigInt only.

/** Euclidean algorithm: gcd(a, b). */
function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

/** Extended Euclidean algorithm: returns [g, x, y] with a*x + b*y = g. */
function extGcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = extGcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

/** Modular inverse of a mod m via the extended Euclidean algorithm. */
function modInverse(a, m) {
  const [g, x] = extGcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error("No modular inverse: gcd(e, Φ) ≠ 1");
  return ((x % m) + m) % m;
}

/** Square-and-multiply modular exponentiation. */
function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/** Trial-division primality test (inputs are small in this assignment). */
function isPrime(n) {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) if (n % i === 0n) return false;
  return true;
}

/** Pick public exponent e: 1 < e < Φ, gcd(e, Φ) = 1. Prefers 65537, else smallest odd. */
function chooseE(phi) {
  if (65537n < phi && gcd(65537n, phi) === 1n) return 65537n;
  for (let e = 3n; e < phi; e += 2n) if (gcd(e, phi) === 1n) return e;
  throw new Error("No valid e found; choose larger primes");
}

/** Generate all RSA parameters from p, q. */
function generateKeys(p, q, eWanted) {
  if (!isPrime(p)) throw new Error(`p = ${p} is not prime`);
  if (!isPrime(q)) throw new Error(`q = ${q} is not prime`);
  if (p === q) throw new Error("p and q must be different");
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  let e = eWanted ?? chooseE(phi);
  if (!(e > 1n && e < phi && gcd(e, phi) === 1n))
    throw new Error("e must satisfy 1 < e < Φ and gcd(e, Φ) = 1");
  const d = modInverse(e, phi);
  return { p, q, n, phi, e, d };
}

/** Encrypt text: each Unicode code point m -> m^e mod n. Requires n > every m. */
function encrypt(text, n, e) {
  const out = [];
  for (const ch of text) {
    const m = BigInt(ch.codePointAt(0));
    if (m >= n) throw new Error(`n = ${n} is too small for character "${ch}" (code ${m}); use larger primes`);
    out.push(modPow(m, e, n));
  }
  return out;
}

/** Decrypt: c -> c^d mod n -> character. */
function decrypt(cipher, n, d) {
  return cipher.map((c) => String.fromCodePoint(Number(modPow(c, d, n)))).join("");
}

/** Mathematical attack: factor n by trial division to recover p and q. */
function factorN(n) {
  if (n % 2n === 0n) return [2n, n / 2n];
  for (let i = 3n; i * i <= n; i += 2n) if (n % i === 0n) return [i, n / i];
  throw new Error("n is prime or could not be factored");
}

/** Full attack: from public key (n, e) alone, recover p, q, Φ, d. */
function breakPublicKey(n, e) {
  const [p, q] = factorN(n);
  const phi = (p - 1n) * (q - 1n);
  return { p, q, phi, d: modInverse(e, phi) };
}

/** File format for saving. */
function serialize(n, e, cipher) {
  return `RSA-PUBLIC-KEY\nn=${n}\ne=${e}\nCIPHERTEXT\n${cipher.join(" ")}\n`;
}

function parse(text) {
  const n = /^n=(\d+)$/m.exec(text), e = /^e=(\d+)$/m.exec(text);
  const c = /^CIPHERTEXT\s*\n([\d\s]+)$/m.exec(text);
  if (!n || !e || !c) throw new Error("Invalid file format");
  return { n: BigInt(n[1]), e: BigInt(e[1]), cipher: c[1].trim().split(/\s+/).map(BigInt) };
}

const RSA = { gcd, extGcd, modInverse, modPow, isPrime, chooseE, generateKeys, encrypt, decrypt, factorN, breakPublicKey, serialize, parse };
if (typeof module !== "undefined") module.exports = RSA;
