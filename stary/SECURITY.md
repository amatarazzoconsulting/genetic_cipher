# Security and file format

`stary` uses a fixed experimental pipeline from `genetic_cipher.hpp`, combining
`SquareTransform`, `CircleTransform`, `TriangleTransform`, `Scatter`,
`Shuffle`, `Diffuse`, `Mix`, `TransformChaCha`, and mode-stack tags. The
pipeline is for exercising the library, not for protecting data.

## Important limitations

- The transformations do not provide authenticated encryption. Modified
  ciphertext is not reliably detected, and a wrong password or key may produce
  arbitrary output without an error.
- Output is deterministic for the same input and credentials. There is no
  per-file nonce or salt, and passwords are not processed by an established
  password-based key derivation function.
- `TransformChaCha` is not the standardized ChaCha20-Poly1305 construction.
  The header's security assessment documents a known-plaintext break for an
  allowed XOR-only pipeline and does not establish a security level for this
  pipeline. Extra shape transforms, mode widths, and push/pop masks do not
  provide a defensible security-strength ranking.
- The default electronic password is a fixed application string. An optional
  `--electronic-password-file` replaces it with the file's first line; this is
  not a password KDF or an authenticated key-management mechanism.
- The mode byte and element count in the envelope are unauthenticated metadata.
- Files and directory packages are buffered in memory by the engine; progress
  is reported around the transform, not continuously during it.
- Directory extraction validates relative paths and stages output, but these
  checks do not authenticate the encrypted package.

Do not use `stary` or `genetic_cipher.hpp` to protect sensitive production
data. Use a maintained cryptographic library with authenticated encryption and
an established password KDF instead.

## Format

The `STGC0002` envelope contains the 8-byte magic, a payload-kind byte, a bit
width, a little-endian 64-bit element count, and the transformed data. The
original length is embedded in the transformed payload so padding can be
removed on decryption. This envelope has no authentication. Files using
`STGC0001` or the previous `STARY001` OpenSSL AEAD format are not compatible
with this implementation.

Directory contents are packaged with relative paths before transformation.
Symbolic links are rejected; extraction rejects absolute paths, parent
traversal, duplicate paths, oversized path/count fields, and an existing
destination directory.
