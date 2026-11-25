# RSA Encryption and Decryption System (Level B)

RSA implemented from scratch (no cryptography library), using only JavaScript `BigInt`.

## Run
Open `index.html` in a browser. Tests: `node test.js`.

## Features
- Input of primes p, q and plaintext x
- n = p·q, Φ = (p−1)(q−1), public exponent e, private exponent d
- Euclidean algorithm (`gcd`) and extended Euclidean algorithm (`extGcd`, `modInverse`)
- Per-character encryption on Unicode code points: c = m^e mod n
- Saves public key (n, e) and ciphertext to `rsa_encrypted.txt`
- Reads the file, factors n (trial division) to get p and q, computes Φ and d, decrypts: m = c^d mod n

## Notes
n must be greater than the largest character code (1,114,111 for full Unicode), so choose p, q around 1000 or larger.
