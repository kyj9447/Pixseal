<p align="center">
<img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/logo/Pixseal.png" width="200px"/>
</p>

# Pixseal
### Prove what you published — and what you didn’t.
Pixseal is a Python-based **image integrity and authenticity verification tool**
designed to **detect whether an image has been modified since signing.**

Pixseal embeds a **cryptographically verifiable integrity seal** into an image in an
invisible manner. During verification, **any modification** — including editing,
filtering, cropping, resizing, re-encoding — will cause verification to **fail**.

Pixseal signs the payload and image hash with an RSA private key. Verification uses
the matching RSA public key or an X.509 certificate that contains it.

Pixseal is not a visual watermarking or branding tool.
The watermark exists solely as a **means to achieve strict, deterministic image
tamper detection**.
Pixseal prioritizes tamper sensitivity over robustness against intentional adversarial manipulation.

- GitHub: https://github.com/kyj9447/Pixseal
- Changelog: https://github.com/kyj9447/Pixseal/blob/main/CHANGELOG.md

## Features
- **Image Integrity Verification**
  - Cryptographically proves that an image remains in its original, unmodified state
  - Detects single-pixel changes with deterministic verification results

- **Tamper Detection**
  - Detects all forms of image modification, including:
    - editing
    - filters and color adjustments
    - cropping and resizing
    - re-encoding and recompression
    - pixel-level changes

- **Invisible Integrity Seal**
  - Embeds verification data without any visible watermark
  - Preserves the original visual appearance of the image

- **RSA Signatures + Certificate Support**
  - Signs payloads and image hashes with an RSA private key
  - Validates with RSA public keys or X.509 certificates (PEM/DER)

- **Flexible Key Inputs**
  - Accepts key/cert objects, PEM/DER bytes, or file paths

- **Fully Local & Offline**
  - No external servers or network dependencies
  - Pure Python implementation

- **Lossless Format Support**
  - Supports PNG and BMP (24-bit) images
  - Lossy formats (e.g., JPEG, WebP) are intentionally excluded to preserve integrity guarantees

## Installation

```bash
pip install Pixseal
# or for local development
pip install -e ./pip_package
```

Python 3.8+ is required. Wheels published to PyPI already include the compiled
Cython extension, so `pip install Pixseal` automatically selects the right build
for your operating system and CPU.

### Building the Cython extension

If you cloned the repository (or downloaded the source), run the helper script
to compile the `simpleImage_ext` extension for your environment:

```bash
git clone https://github.com/kyj9447/Pixseal.git
cd Pixseal
python3 -m pip install -r requirements.txt
./compile_extension.sh
```

This command regenerates the C source via Cython and invokes your local C
compiler (`clang` or `gcc`) to produce `pip_package/Pixseal/simpleImage_ext*.so`.
You still need a working build toolchain (`gcc`/`clang` and Python headers)
installed through your OS package manager. If you skip this step, Pixseal falls
back to the pure Python implementation, which works but is significantly slower.

## Quick start

### Sign an image

```python
from Pixseal import signImage

signed = signImage(
    imageInput="assets/original.png",
    payload="AutoTest123!",
    private_key="assets/CA/pixseal-dev-final.key",
)
signed.save("assets/signed_original.png")
```

- The payload is looped if it runs out before the image ends, so even small files carry the full sentinel/payload/end pattern.

### Validate a signed image

```python
from Pixseal import validateImage

report = validateImage(
    imageInput="assets/signed_original.png",
    publicKey="assets/CA/pixseal-dev-final.crt",  # cert or public key
)

print(report["verdict"])
```

## Key and certificate inputs

Pixseal accepts multiple input formats so you can keep the calling code minimal.

- `signImage(..., private_key=...)` accepts:
  - `RSAPrivateKey`
  - PEM/DER bytes (`bytes`, `bytearray`, `memoryview`)
  - file path (`str` or `Path`)

- `validateImage(..., publicKey=...)` accepts:
  - `RSAPublicKey`
  - `x509.Certificate`
  - PEM/DER bytes (`bytes`, `bytearray`, `memoryview`)
  - file path (`str` or `Path`)

If a certificate is provided, Pixseal extracts the embedded RSA public key and
verifies the signatures. Certificate chain validation is the responsibility of
the calling application.

## Validation output

### Success

```
[SimpleImage] Opened image: <width>x<height>, channels=<n>
[SimpleImage] Opened image: <width>x<height>, channels=<n>

Validation Report

{'lengthCheck': {'length': <int>, 'result': <bool>},
 'tailCheck': {'full': '<truncated payload preview>',
               'tail': '<truncated tail preview>',
               'result': <bool>},
 'startVerify': <bool>,
 'endtVerify': <bool>,
 'payloadVerify': <bool>,
 'imageHashVerify': <bool>,
 'imageHashCompareCheck': {'extrackedHash': '<hex>',
                           'computedHash': '<hex>',
                           'result': <bool>},
 'verdict': <bool>}
```

### Failure

```
[SimpleImage] Opened image: <width>x<height>, channels=<n>
[SimpleImage] Opened image: <width>x<height>, channels=<n>

Validation Report

{'lengthCheck': {'length': <int>, 'result': <bool>},
 'tailCheck': {'result': 'Not Required'},
 'startVerify': <bool>,
 'endtVerify': <bool>,
 'payloadVerify': <bool>,
 'imageHashVerify': <bool>,
 'imageHashCompareCheck': {'extrackedHash': '<hex>',
                           'computedHash': '<hex>',
                           'result': <bool>},
 'verdict': <bool>}
```

## CLI demo script

`python testRun.py` offers an interactive flow:

1. Choose **1** to sign an image. It reads `assets/original.png`, asks for a payload, and writes `assets/signed_original.png`.
2. Choose **2** to validate. It reads `assets/signed_original.png` and prints the validation report.
3. Choose **3** to benchmark performance.
4. Choose **4** to test signing and validation with byte-stream input.
5. Choose **5** to run the optional line-profiler demo.
6. Choose **6** to run validation multi-pass tests.

Option **5** requires the optional dependency `line_profiler` and must be run via
`kernprof -l testRun.py` so that `builtins.profile` is provided. Without
`line_profiler` installed the script will continue to work, but the profiling
option will display an informative message instead of running.

## Key and certificate management

Generate a root + intermediate + final certificate chain for development:

```bash
./gen-ca-chain.sh
```

This generates the following artifacts under `assets/CA`:
- `pixseal-dev-root.crt` / `.key` (root CA)
- `pixseal-dev-intermediate.crt` / `.key` (intermediate CA)
- `pixseal-dev-final.crt` / `.key` (leaf signer)

Use the **leaf private key** to sign and the matching **leaf certificate** (or
public key) to validate. If your application needs OS-level trust-chain checks,
perform that separately in the calling application.

## API reference

| Function | Description |
| --- | --- |
| `signImage(imageInput, payload, private_key)` | Loads a PNG/BMP from a filesystem path or raw bytes, injects `payload` plus sentinels, and signs the payload/hash using the RSA private key. Returns a `SimpleImage` that you can `save()` or `saveBmp()`. |
| `validateImage(imageInput, publicKey)` | Reads the hidden bit stream from a path or raw bytes, rebuilds the payload JSON, verifies signatures and the computed image hash, and returns a validation report. Accepts RSA public keys or X.509 certificates. |

## Examples

| Original | Signed (`AutoTest123!`) |
| --- | --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/original.png" width="400px"/> | <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/signed_original.png" width="400px"/> |

Validation output (success):

```
[SimpleImage] Opened image: 2000x1500, channels=4
[SimpleImage] Opened image: 2000x1500, channels=4

Validation Report

{'lengthCheck': {'length': 4, 'result': True},
 'tailCheck': {'full': '{"payload":"AutoTest...lgu9lUM+s7OHUZywYqYYOYIFVTWCmq...',
               'tail': '{"payload":"AutoTest...lgu9lUM+s7',
               'result': True},
 'startVerify': True,
 'endtVerify': True,
 'payloadVerify': True,
 'imageHashVerify': True,
 'imageHashCompareCheck': {'extrackedHash': '2129e43456029f39b20bbe96340dce6827c0ad2288107cb92c0b92136fec48d6',
                           'computedHash': '2129e43456029f39b20bbe96340dce6827c0ad2288107cb92c0b92136fec48d6',
                           'result': True},
 'verdict': True}
```

| Corrupted after signing |
| --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/currupted_signed_original.png" width="400px"/> |

Validation output (failure):

```
[SimpleImage] Opened image: 2000x1500, channels=4
[SimpleImage] Opened image: 2000x1500, channels=4

Validation Report

{'lengthCheck': {'length': 31, 'result': False},
 'tailCheck': {'result': 'Not Required'},
 'startVerify': True,
 'endtVerify': True,
 'payloadVerify': True,
 'imageHashVerify': True,
 'imageHashCompareCheck': {'extrackedHash': '68d500c751dfa298d55dfc1cd2ab5c9f43ec139f02f6a11027211c4d144c2870',
                           'computedHash': '43fd2108f5aa16045f4b64d70a0ce05991043cba6878f66d82abd3e7edb9d51e',
                           'result': False},
 'verdict': False}
```

## Related projects

https://github.com/kyj9447/imageSignerCamera
- Mobile camera that signs images on capture
- Server-side validator that verifies payloads
