<!-- coderabbit-ai-generated:v1 -->

# Encryption engine tests and security assessment

## Conclusion

The Genetic Cipher has no established security level comparable to AES-256-GCM or ChaCha20-Poly1305. Do not use this experimental engine to protect sensitive production data on the basis of these tests. Correct round trips, visual randomness, and avalanche measurements cannot establish resistance to cryptanalysis.

## Reproduce

The header requires C++20 and threads. The optional comparison requires OpenSSL development headers and libcrypto (tested with GCC 15.2.0 and OpenSSL 3.5.5).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSECURITY_COMPARISON=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/security_comparison
```

For sanitizer coverage of the operation matrix:

```sh
cmake -S . -B build-sanitized -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-sanitized --target engine_tests -j2
./build-sanitized/engine_tests
```

## Correctness findings and repairs

- CircleTransform failed 20 of the initial 2,560 operation/width/length cases. Rasterized neighboring rings overlap, so decryption must reverse the order of rotations as well as each rotation's direction. The repair preserves forward output and reverses traversal using the original random shifts.
- Minimum padding used byte arithmetic for sub-byte elements, producing fewer bytes than requested. Padding now calculates the number of elements using their bit width. This repairs the documented minimum-size guarantee; ciphertext for affected short, narrow-mode inputs changes. No original-length metadata is added: decrypted output retains padding.
- Regression coverage includes all 62 operation tags and both built-in shapes, ten widths (1–64 bits), four element counts including partial grids, fresh decryption objects, padded compositions, repeated calls, multiple container nodes, zero/FF/incrementing byte patterns, and empty input rejection. BLOCK (128) is excluded because scalar elements are uint64_t; these results do not establish support for that mode.
- The existing demo covers archive and streaming round trips. Archive parser fuzzing, hostile extraction paths, concurrency, and exhaustive parameter combinations have not been audited here.

## Security experiments

Synthetic 4 KiB incrementing bytes; fixed test secrets; no customer data. Sixteen controlled single-bit plaintext mutations per pipeline. Re-run the executable for current measurements.

| Experiment | Genetic XOR only | Genetic README pipeline | AES-256-GCM | ChaCha20-Poly1305 |
| --- | --- | --- | --- | --- |
| Exact round trip | Pass | Pass | Pass | Pass |
| Same input and keys repeats ciphertext | Yes | Yes | Same nonce repeats; distinct nonces differ | Same nonce repeats; distinct nonces differ |
| Reject changed ciphertext | No | No | Yes | Yes |
| Reject wrong key | No | No | Yes | Yes |
| Mean payload bits changed | 0.003% | 4.635% | 0.003% | 0.003% |

The established AEAD ciphers use a distinct nonce per encryption in normal operation. The comparison deliberately holds nonce/key constant ONLY for differential measurements; never reuse those fixed synthetic fixtures in an application. The table measures payload bits, excluding authentication tags. Local bit changes are expected for counter/stream encryption and do not indicate weakness when ciphertext is authenticated. The observed Genetic diffusion percentage describes this sample, not an attack cost or a security rating.

A reproducible known-plaintext attack on GeneticCipher<BitwiseXor> recovers every byte of a second equal-length message encrypted under the same secrets: C1 XOR P1 XOR C2 = P2. This demonstrates failure of an allowed pipeline; it does not demonstrate recovery of arbitrary composed pipelines. Permutation-only and unkeyed operation choices likewise cannot be assumed to provide confidentiality merely because they are available as encryption operations.

## Design gaps found by inspection

- No per-message nonce or salt in the in-memory interface. Repeated messages leak equality; per-operation reseeding repeats key streams for the same secrets and operation positions.
- No payload authentication in the tested pipelines. Wrong keys and modifications yield bytes without an error. Adding more transforms does not supply authenticity.
- `EncryptionSettings::key_derivation_rounds` is declared but never read. PRNG seeding uses custom byte mixing with ten fixed rounds rather than an established configurable password KDF. Expansion cannot add entropy to a weak password. README claims about 4096-byte expansion and brute-force resistance are unsupported by this path.
- `TransformAES` applies substitution tables, not full AES. `TransformChaCha` applies a reversible quarter-round-like operation, not the standardized ChaCha20 AEAD construction. The PRNG also uses custom word/output handling; ChaCha-inspired source is not evidence of RFC conformance.
- Timing output is a single cold sample including setup, key derivation for Genetic, allocation, and provider initialization for OpenSSL. It is diagnostic only, not a fair throughput ranking. There is no defensible numeric claim about security bits, superiority, or brute-force time from this work.

## Next design step

Use a maintained cryptographic library's authenticated encryption interface, with per-message nonces, an established password KDF and salt when passwords are used, and a versioned envelope that authenticates metadata. Retrofitting that envelope changes the existing deterministic ciphertext format and wrong-key behavior; it requires an explicit compatibility/migration design. These tests repair reversibility and padding without silently redesigning the format.

## Primary references

- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): GCM authenticated encryption and IV requirements.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): ChaCha20-Poly1305 construction, nonce uniqueness, and authentication.

Official sources were retrieved directly; the web search service was unavailable during this task.
