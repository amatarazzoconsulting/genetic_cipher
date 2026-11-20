# stary

`stary` is a terminal demonstration of the experimental transformations in
[`genetic_cipher.hpp`](../genetic_cipher.hpp). It supports text, file, and
directory round trips, but it does **not** provide secure encryption. Do not
use it to protect sensitive data.

## Build

```sh
cmake -S stary -B stary/build
cmake --build stary/build
ctest --test-dir stary/build --output-on-failure
```

## Use

```sh
stary/build/stary encrypt --input notes.txt --output notes.stary
stary/build/stary decrypt --input notes.stary --output restored.txt
stary/build/stary encrypt --directory project --output project.stary
stary/build/stary decrypt --input project.stary --output restored-project
stary/build/stary encrypt --text
stary/build/stary decrypt --text
```

Without a credential option, `stary` prompts for a password. Alternatively,
use `--password-file FILE` to read the first line as the password, or
`--key-file FILE` to read a 32-byte value encoded as 64 hexadecimal characters.
`--electronic-password-file FILE` optionally supplies the engine's electronic
password from its first line; spaces in that line are preserved. Protect
credential files with restrictive filesystem permissions.

For example, prepare the optional file with a private first line, then pass it
alongside the normal password file:

```sh
printf '%s\n' 'replace this with a private phrase containing spaces' > electronic-password.txt
chmod 600 electronic-password.txt
stary/build/stary encrypt --text --bit-width 16 \
  --password-file password.txt \
  --electronic-password-file electronic-password.txt
```

Encryption accepts `--bit-width BITS` for 1, 2, 3, 4, 5, 6, 8, 16, 32, or 64.
The width is recorded in the envelope, so decryption selects it automatically.
Text mode reads a single line from standard input and prints base64 output.
File and directory operations buffer the full payload in memory. Existing
output paths are not overwritten. New `STGC0002` files are incompatible with
`STGC0001` and the previous `STARY001` format.

The demo pipeline combines square, circle, and triangle geometry with mode
push/pop tags and reversible element transforms. These combinations and bit
widths change the demonstration output; they are not security levels or a
substitute for a reviewed authenticated cipher.

See [SECURITY.md](SECURITY.md) for the format and limitations.
