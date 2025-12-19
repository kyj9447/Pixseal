<p align="center">
<img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/Pixseal.png" width="200px"/>
</p>

# Pixseal
### Prove what you published — and what you didn’t.
Pixseal is a Python-based **image integrity and authenticity verification tool**
designed to **detect whether an image has been modified since signing.**

Pixseal embeds a **cryptographically verifiable integrity seal** into an image in an
invisible manner. During verification, **any modification** — including editing,
filtering, cropping, resizing, re-encoding — will cause
verification to **immediately fail**.

If **even a single pixel** is altered after signing, Pixseal will detect it.

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

- **RSA-Based Encryption (Optional)**
  - Supports RSA public/private key encryption for embedded verification data
  - Allows separation of signing and verification roles

- **Verification & Extraction**
  - Payloads may be partially or fully extractable even after modification
  - Automatically fails verification when tampering is detected

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

### Building from a git clone

If you cloned the repository (or downloaded the source), run the included build
script to create a wheel/SDist tailored to your environment:

```bash
git clone https://github.com/kyj9447/Pixseal.git
cd Pixseal
python3 -m pip install -r requirements.txt
./build.sh
# Install the freshly built wheel (optional)
python3 -m pip install pip_package/dist/Pixseal-*.whl
```

Even after running `python3 -m pip install -r requirements.txt` you still need a
working C toolchain (`gcc`) and the Python development headers exposed via
`python3-config`; these come from your OS packages, not pip.

```bash
cd Pixseal
# optional: choose backend for testing (python fallback available)
./build.sh  # regenerates the C extension and runs `python -m build`
```

`build.sh` invokes Cython and `gcc` (via `python3-config`) before producing the
wheel/sdist artifacts. Ensure `cython`, `build`, and a working C toolchain are
installed. If you skip this step, Pixseal falls back to the pure Python
implementation, which works but is significantly slower.

## Usage

### Sign an image

```python
from Pixseal import signImage

result = signImage(
    imageInput="assets/original.png",  # accepts a file path or raw PNG/BMP bytes
    hiddenString="!Validation:kyj9447@mailmail.com",
    publicKeyPath="assets/RSA/public_key.pem",  # omit for plain-text embedding
)
result.save("assets/signed_original.png")
```

- The payload is looped if it runs out before the image ends, so even small files carry the full sentinel/payload/end pattern.
- When `publicKeyPath` is omitted, the payload remains plain text.

### Validate and (optionally) decrypt

```python
from Pixseal import validateImage

report = validateImage(
    imageInput="assets/signed_original.png",  # accepts a file path or raw PNG/BMP bytes
    privKeyPath="assets/RSA/private_key.pem",  # omit for plain-text payloads
)

print(report["extractedString1"])
print(report["validationReport"])
```

`validateImage` returns:

```python
{
    "extractedString1": "<payload or encrypted blob>",
    "extractedString2": "<truncated payload or encrypted blob>",
    "validationReport": {
        "arrayLength": 4,
        "lengthCheck": True,
        "startCheck": True,
        "endCheck": True,
        "isDecrypted": True,
        "tailCheckResult": True,
        "verdict": True,
        # decryptSkipMessage when a decrypt request was skipped
    }
}
```

### CLI demo script

`python testRun.py` offers an interactive flow:

1. Choose **1** to sign an image. It reads `assets/original.png`, asks for a payload (default `!Validation:kyj9447@mailmail.com`), optionally encrypts with `assets/RSA/public_key.pem`, and writes `assets/signed_<name>.png`.
2. Choose **2** to validate. It reads `assets/signed_original.png`, optionally decrypts with `assets/RSA/private_key.pem`, and prints both the extracted string and verdict.
3. Choose **3** to benchmark performance. It reads `assets/original.png`, encrypts it with `assets/RSA/public_key.pem`, and writes `assets/signed_original.png`, printing the elapsed signing time. Then it reads `assets/signed_original.png`, performs extraction/decryption/validation, and prints the elapsed validation time along with the total elapsed time.
4. Choose **4** to test signing and validation with file-path input option.
5. Choose **5** to test signing and validation with byte-stream input option.
6. Choose **6** to run the optional line-profiler demo. It benchmarks `signImage` and `validateImage`, printing per-line timings when the script is executed through `kernprof`.

Option **6** requires the optional dependency `line_profiler` and must be run via `kernprof -l testRun.py` so that `builtins.profile` is provided. Without `line_profiler` installed the script will continue to work, but the profiling option will display an informative message instead of running.
### Key management

Generate a test RSA pair (PKCS#8) with OpenSSL:

```bash
openssl genpkey -algorithm RSA -out assets/RSA/private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in assets/RSA/private_key.pem -out assets/RSA/public_key.pem
```

Point `publicKeyPath` / `privKeyPath` to these files.

## API reference

| Function | Description |
| --- | --- |
| `signImage(imageInput, hiddenString, publicKeyPath=None)` | Loads a PNG/BMP from a filesystem path or raw bytes, injects `hiddenString` plus sentinels, encrypting each chunk when `publicKeyPath` is provided. Returns a `SimpleImage` that you can `save()` or `saveBmp()`. |
| `validateImage(imageInput, privKeyPath=None)` | Reads the hidden bit stream from a path or raw bytes, splits by newlines, deduplicates, optionally decrypts each chunk (Base64 indicates ciphertext), and returns the payload plus a validation report. |


## Examples

| Original | Signed (`!Validation:kyj9447@mailmail.com`) |
| --- | --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/original.png" width="400px"/> | <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/signed_original.png" width="400px"/> |

Validation output excerpt:

```
[Validate] verdict: True
[Validate] extracted string: !Validation:kyj9447@mailmail.com
[Validate] decrypted with private key: RSA/private_key.pem

Validation Report

{'extractedString1': '!Validation:kyj9447@mailmail.com',
 'extractedString2': 'DMnWAzbd6NFycGAxcPkzzmGjL33WXovG...',
 'validationReport': {'arrayLength': 4,
                      'endCheck': True,
                      'isDecrypted': True,
                      'lengthCheck': True,
                      'startCheck': True,
                      'tailCheckResult': True,
                      'verdict': True}}
```

(When encrypted, each line appears as Base64 until decrypted with the RSA private key.)

| Corrupted after signing |
| --- |
|<img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/currupted_signed_original.png" width="400px"/>

Validation output excerpt:

```
...
string argument should contain only ASCII characters
string argument should contain only ASCII characters
string argument should contain only ASCII characters
[Validate] verdict: False
[Validate] extracted string: !Validation:kyj9447@mailmail.com
[Validate] decrypted with private key: RSA/private_key.pem

Validation Report

{'extractedString1': '!Validation:kyj9447@mailmail.com',
 'extractedString2': 'hh78IWEsRgfTWMw3Rg02hTnCdErjx0O4...',
 'validationReport': {'arrayLength': 400,
                      'decryptSkipMessage': 'Skip decrypt: payload was plain '
                                            'or corrupted text despite decrypt '
                                            'request.',
                      'endCheck': True,
                      'isDecrypted': True,
                      'lengthCheck': False,
                      'startCheck': True,
                      'tailCheckResult': 'Not Required',
                      'verdict': False}}
```
## Related projects

https://github.com/kyj9447/imageSignerCamera
- Mobile camera that signs images on capture: 
- Server-side validator that decrypts and verifies payloads.
