# Pixseal

Encrypted image watermark injector/validator that hides text (optionally RSA encrypted) inside 24-bit PNG or BMP files by modulating the parity of carefully selected color channels.
- GitHub: https://github.com/kyj9447/imageSignerCamera

## Features

- **Noise-resistant embedding**: Chooses the RGB component whose value is farthest from 127 and nudges it ±1 to match each payload bit, keeping noise visually imperceptible.
- **Sentinel-based framing**: Automatically prefixes/suffixes payloads with `START-VALIDATION` / `END-VALIDATION` markers so the validator knows where to look.
- **Optional RSA envelope**: When you pass a public key, both the sentinels and payload are encrypted with OAEP (SHA-256). Validation decrypts with the matching private key before building a verdict.
- **Pure Python image I/O**: `SimpleImage` reads/writes uncompressed BMPs as well as 8-bit RGB/RGBA PNGs without third-party imaging libraries.

## Installation

```bash
pip install Pixseal
# or for local development
pip install -e ./pip_package
```

Python 3.8+ is required. The only runtime dependency is `cryptography>=41.0.0`.

## Usage

### Sign an image

```python
from Pixseal import signImage

result = signImage(
    imagePath="original.png",
    hiddenString="!Validation:kyj9447@mailmail.com",
    publicKeyPath="SSL/public_key.pem",  # omit for plain-text embedding
)
result.save("signed_original.png")
```

- The payload is looped if it runs out before the image ends, so even small files carry the full sentinel/payload/end pattern.
- When `publicKeyPath` is omitted, the payload remains plain text.

### Validate and (optionally) decrypt

```python
from Pixseal import validateImage

report = validateImage(
    imagePath="signed_original.png",
    privKeyPath="SSL/private_key.pem",  # omit for plain-text payloads
)

print(report["extractedString"])
print(report["validationReport"])
```

`validateImage` returns:

```python
{
    "extractedString": "<payload or encrypted blob>",
    "validationReport": {
        "arrayLength": 4,
        "lengthCheck": True,
        "startCheck": True,
        "endCheck": True,
        "isDecrypted": True,
        "verdict": True,
        # decryptSkipMessage when a decrypt request was skipped
    }
}
```

### CLI demo script

`python testRun.py` offers an interactive flow:

1. Choose **1** to sign an image. It reads `original.png`, asks for a payload (default `!Validation:kyj9447@mailmail.com`), optionally encrypts with `SSL/public_key.pem`, and writes `signed_<name>.png`.
2. Choose **2** to validate. It reads `signed_original.png`, optionally decrypts with `SSL/private_key.pem`, and prints both the extracted string and verdict.

### Key management

Generate a test RSA pair (PKCS#8) with OpenSSL:

```bash
openssl genpkey -algorithm RSA -out SSL/private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in SSL/private_key.pem -out SSL/public_key.pem
```

Point `publicKeyPath` / `privKeyPath` to these files.

## API reference

| Function | Description |
| --- | --- |
| `signImage(imagePath, hiddenString, publicKeyPath=None)` | Loads a PNG/BMP, injects `hiddenString` plus sentinels, encrypting each chunk when `publicKeyPath` is provided. Returns a `SimpleImage` that you can `save()` or `saveBmp()`. |
| `validateImage(imagePath, privKeyPath=None)` | Reads the hidden bit stream back, splits by newlines, deduplicates, optionally decrypts each chunk (Base64 indicates ciphertext), and returns the payload plus a validation report. |
| `SimpleImage.open(path)` | Low-level helper that exposes `size`, `getPixel`, `putPixel`, `save`, and `saveBmp`. Useful if you need custom preprocessing before/after signing. |
| `BinaryProvider`, `addHiddenBit`, `readHiddenBit`, `buildValidationReport` | Lower-level primitives exported from `Pixseal` for advanced workflows or experimentation. |

## Examples

| Original | Signed (`!Validation:kyj9447@mailmail.com`) |
| --- | --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/original.png" width="400px"/> | <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/signed_original.png" width="400px"/> |

Validation output excerpt:

```
[Validate] verdict: True
[Validate] extracted string: !Validation:kyj9447@mailmail.com
[Validate] decrypted with private key: SSL/private_key.pem
```

(When encrypted, each line appears as Base64 until decrypted with the RSA private key.)

| Currupted after signing |
| --- |
|<img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/currupted_signed_original.png" width="400px"/>

Validation output excerpt:

```
...
string argument should contain only ASCII characters
string argument should contain only ASCII characters
string argument should contain only ASCII characters
[Validate] verdict: False
[Validate] extracted string: !Validation:kyj9447@mailmail.com
[Validate] decrypted with private key: SSL/private_key.pem
```
## Related projects

- Mobile camera that signs images on capture: https://github.com/kyj9447/imageSignerCamera
- Server-side validator that decrypts and verifies payloads.
