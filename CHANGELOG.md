## [0.1.2]

### Added
- **Byte-stream API support** – Core entry points such as `SimpleImage.open`, `signImage`, and `validateImage` now accept either file paths or raw PNG/BMP byte streams.
- **TailCheck in validation report** – `validateImage` now exposes `tailCheckResult` in the returned `validationReport`, comparing the complete ciphertext with its truncated counterpart so you can detect tampering even when decryption isn’t possible.